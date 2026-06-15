"""Schema equivalence: ``SQLModel.metadata`` vs ``alembic upgrade head``.

The 55 existing test fixtures still build their scratch DBs with
``SQLModel.metadata.create_all`` — that's the fast path and we don't want
the migration overhead on every test. This test is the *one* thing that
keeps the Alembic baseline honest: it builds two empty scratch sqlite
files (one via ``create_all``, one via ``alembic upgrade head``) and asserts
they describe the same shape (same tables, same columns, same indexes).

Why this matters
----------------
The risk model behind splitting tests away from migrations is
*"create_all could drift from head silently"*. Without an explicit diff
gate, a new column added to a model would land in every test
(``metadata.create_all`` sees it) but never trigger a new Alembic revision
— and production users on existing DBs would be missing the column
forever. This test forces every PR that touches models to also produce
the matching ``alembic revision --autogenerate`` file.

What's compared
---------------
* Table set (names).
* Per-table column set, with nullability + primary-key flag.
* Per-table index set, with column tuples and uniqueness.

What's *not* compared (intentional)
-----------------------------------
* SQLite column types — SQLite ignores most declared types, and SQLAlchemy
  renders the same Python type differently across the two paths
  (``VARCHAR`` vs ``VARCHAR(255)`` etc.). Comparing types here would
  generate noise without catching real bugs; ``compare_type=True`` in
  env.py is the right place for that signal.
* Foreign keys — sqlite's PRAGMA foreign_key_list lists FK names that
  Alembic batch-mode renames during table-rebuild; the *behavior* is
  identical but the names drift.
* Default expressions — same reason as types; ``compare_server_default``
  in env.py is the right home.
"""

from __future__ import annotations

import pytest
from sqlalchemy import inspect
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, create_engine

# conftest.py at tests/ root adds backend/ to sys.path before any test imports,
# so cybersecurity_assessor resolves without an editable install.
from cybersecurity_assessor import models  # noqa: F401  -- registers tables
from cybersecurity_assessor.migrations import upgrade_to_head


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_scratch_engine(db_file: Path):
    """Build a file-backed sqlite engine pointed at ``db_file``.

    Has to be file-backed (not ``:memory:``) so the Alembic side and the
    metadata side both walk *some* OS file — keeps the inspector behavior
    identical across the two branches.
    """
    return create_engine(
        f"sqlite:///{db_file}",
        connect_args={"check_same_thread": False, "timeout": 30},
        poolclass=StaticPool,
    )


def _snapshot_schema(engine) -> dict:
    """Return a comparable schema description for the given engine.

    Shape:
        {
            "tables": {
                "evidence": {
                    "columns": {"id": (False_nullable, True_pk), ...},
                    "indexes": {
                        ("ix_evidence_workbook_id", ("workbook_id",), False),
                        ...
                    },
                },
                ...
            }
        }

    ``alembic_version`` is filtered out because only the Alembic side
    creates it — including it would force a guaranteed mismatch.
    """
    insp = inspect(engine)
    out: dict = {"tables": {}}
    for table in sorted(insp.get_table_names()):
        if table == "alembic_version":
            continue
        cols = {}
        for c in insp.get_columns(table):
            cols[c["name"]] = (bool(c.get("nullable", True)), False)
        # Mark PK columns
        pk = insp.get_pk_constraint(table) or {}
        for pk_col in pk.get("constrained_columns") or []:
            if pk_col in cols:
                nullable, _ = cols[pk_col]
                cols[pk_col] = (nullable, True)
        indexes = set()
        for idx in insp.get_indexes(table):
            indexes.add(
                (
                    idx["name"],
                    tuple(idx.get("column_names") or ()),
                    bool(idx.get("unique", False)),
                )
            )
        out["tables"][table] = {"columns": cols, "indexes": indexes}
    return out


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


def test_alembic_head_matches_sqlmodel_metadata(tmp_path, monkeypatch):
    """Alembic head produces the same schema as ``SQLModel.metadata.create_all``.

    If this fails after a model change, run
    ``cd backend && CYBERSEC_ALEMBIC_URL=sqlite:///./_scratch.db uv run \
       alembic revision --autogenerate -m "describe the change"``
    and commit the generated file.
    """
    # --- side A: metadata.create_all ----------------------------------------
    meta_db = tmp_path / "metadata.db"
    meta_engine = _make_scratch_engine(meta_db)
    SQLModel.metadata.create_all(meta_engine)
    meta_snapshot = _snapshot_schema(meta_engine)
    meta_engine.dispose()

    # --- side B: alembic upgrade head ---------------------------------------
    alembic_db = tmp_path / "alembic.db"
    # Point env.py at this scratch file via the documented override.
    monkeypatch.setenv("CYBERSEC_ALEMBIC_URL", f"sqlite:///{alembic_db}")
    alembic_engine = _make_scratch_engine(alembic_db)
    upgrade_to_head(alembic_engine)
    alembic_snapshot = _snapshot_schema(alembic_engine)
    alembic_engine.dispose()

    # --- diff ---------------------------------------------------------------
    meta_tables = set(meta_snapshot["tables"])
    alembic_tables = set(alembic_snapshot["tables"])

    missing_in_alembic = meta_tables - alembic_tables
    extra_in_alembic = alembic_tables - meta_tables
    assert not missing_in_alembic, (
        "Tables defined in SQLModel.metadata are missing from "
        f"alembic head: {sorted(missing_in_alembic)}. Generate a new "
        "Alembic revision."
    )
    assert not extra_in_alembic, (
        "Tables exist in alembic head but not in SQLModel.metadata: "
        f"{sorted(extra_in_alembic)}. Either delete the stale model or "
        "the stale migration."
    )

    mismatches: list[str] = []
    for table in sorted(meta_tables):
        meta_t = meta_snapshot["tables"][table]
        ale_t = alembic_snapshot["tables"][table]

        meta_cols = set(meta_t["columns"])
        ale_cols = set(ale_t["columns"])
        if meta_cols != ale_cols:
            only_meta = meta_cols - ale_cols
            only_ale = ale_cols - meta_cols
            mismatches.append(
                f"  {table}: column mismatch — only-in-metadata={sorted(only_meta)}, "
                f"only-in-alembic={sorted(only_ale)}"
            )

        for col in meta_cols & ale_cols:
            if meta_t["columns"][col] != ale_t["columns"][col]:
                mismatches.append(
                    f"  {table}.{col}: nullable/pk mismatch — "
                    f"metadata={meta_t['columns'][col]} vs "
                    f"alembic={ale_t['columns'][col]}"
                )

        # Index comparison is set-vs-set; auto-named SQLite indexes
        # ``sqlite_autoindex_*`` are inspector artifacts of UNIQUE
        # constraints and align on both sides.
        if meta_t["indexes"] != ale_t["indexes"]:
            only_meta_idx = meta_t["indexes"] - ale_t["indexes"]
            only_ale_idx = ale_t["indexes"] - meta_t["indexes"]
            if only_meta_idx or only_ale_idx:
                mismatches.append(
                    f"  {table}: index mismatch — "
                    f"only-in-metadata={sorted(only_meta_idx)}, "
                    f"only-in-alembic={sorted(only_ale_idx)}"
                )

    if mismatches:
        pytest.fail(
            "Alembic head drifted from SQLModel.metadata. "
            "Add a new revision with `alembic revision --autogenerate`. "
            "Differences:\n" + "\n".join(mismatches)
        )
