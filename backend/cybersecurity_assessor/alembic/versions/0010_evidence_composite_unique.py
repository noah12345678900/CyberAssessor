"""Per-workbook composite UNIQUEs on ``Evidence`` — online-safe schema flip.

Revision ID: 0010
Revises: 0009
Create Date: 2026-06-07

Why this migration exists
-------------------------
PR 2 of the per-workbook hard-scoping sequence taught the ingest helpers
``_existing_by_uri`` / ``_existing_by_hash`` to look up evidence by
``(workbook_id, path)`` / ``(workbook_id, sha256)`` instead of by the bare
column — but the global ``UNIQUE`` on ``evidence.path`` (from 0001) still
rejects the second insert when the same file is ingested into a second
workbook. The helper change is meaningless without the schema flip.

Originally the plan put this UNIQUE swap in PR 3 alongside the
``workbook_id NOT NULL`` flip and the NULL-row quarantine pass. But:

* Dropping a UNIQUE + adding looser composite UNIQUEs is a strictly
  *additive* permission change — every row that was unique before is
  still unique now (the new constraints are a superset). No data
  validation needed, no app downtime needed.
* The NULL-row quarantine + NOT NULL flip in 0011 (PR 3) IS the offline
  step — it deletes legacy rows and tightens a column, both of which can
  race a live writer.

Separating the two keeps PR 3 small and explicit-about-downtime, and
unblocks PR 2's tests from passing the moment 0010 lands. Both PR 3
header and run-book continue to be the place that says
"REQUIRES APP STOPPED" — 0010 does not.

Schema changes
--------------
1. Drop the unique index ``ix_evidence_path`` (created in 0001 line 546
   as ``batch_op.create_index(..., 'path', unique=True)``). Recreate it
   as a non-unique index on ``path`` — we still want O(log n) lookup
   speed for the ``_existing_by_uri`` composite query and the legacy
   sweep / asset-crosscheck path scans, just without the global UNIQUE.
2. Add composite UNIQUE constraint ``uq_evidence_workbook_path`` on
   ``(workbook_id, path)``.
3. Add composite UNIQUE constraint ``uq_evidence_workbook_sha256`` on
   ``(workbook_id, sha256)``.

SQLite NULL-in-UNIQUE semantics
-------------------------------
Under SQLite (and ANSI SQL), each NULL in a UNIQUE column is treated as
*distinct* — so ``(NULL, '/x.pdf')`` and ``(NULL, '/x.pdf')`` do not
violate the composite UNIQUE. This means the legacy NULL-workbook rows
remaining at PR 2 time are not protected by these new UNIQUEs.

That is acceptable because:
* PR 2's ``ingest_source`` hardening forbids NEW NULL-workbook inserts
  (raises ValueError on missing workbook_id), so no new ambiguity gets
  created after 0010.
* 0011 (PR 3) drains every legacy NULL-workbook row into
  ``quarantinedevidence`` and flips ``workbook_id`` to NOT NULL — after
  which the NULL-distinct edge case is structurally unreachable.

Idempotency
-----------
Wrapped in ``_has_index`` / ``_has_unique_constraint`` guards, same
pattern as 0007/0008/0009. Safe to re-run against a DB already at head.

SQLite batch mechanics
----------------------
SQLite cannot drop/add UNIQUE constraints in place — ``batch_alter_table``
rebuilds the table (drop, recreate with new constraints, copy rows). We
rebuild ``evidence`` once with all three changes wrapped in a single
batch so we pay the row-copy cost exactly once.

Why not drop ``unique=True`` from the SQLModel field too?
---------------------------------------------------------
We do — ``models.py :: Evidence.path`` loses ``unique=True`` in the
same PR. Migration is the source of truth for prod; the model edit
keeps SQLModel.metadata.create_all (used by some test fixtures) in
sync. Without the model edit, a fresh test DB created via create_all
would still get the old global UNIQUE and the PR 2 ingest-scope tests
would fail in the test path even with 0010 applied in prod.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


# Constraint / index names used in both upgrade and downgrade. Keeping
# them as module constants lets the round-trip test reference the same
# strings without re-deriving them.
_PATH_UNIQUE_INDEX = "ix_evidence_path"  # the 0001 unique index we drop
_UQ_WORKBOOK_PATH = "uq_evidence_workbook_path"
_UQ_WORKBOOK_SHA256 = "uq_evidence_workbook_sha256"


def _has_table(bind: sa.engine.Connection, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def _path_index_is_unique(bind: sa.engine.Connection) -> bool | None:
    """True if ``ix_evidence_path`` exists and is unique, False if it
    exists non-unique, None if missing.

    Used by upgrade to know whether we still need to do the swap (skip
    if a previous run already converted it) and by downgrade to know
    whether the index needs flipping back.
    """
    if not _has_table(bind, "evidence"):
        return None
    for ix in sa.inspect(bind).get_indexes("evidence"):
        if ix["name"] == _PATH_UNIQUE_INDEX:
            return bool(ix.get("unique"))
    return None


def _has_unique_constraint(bind: sa.engine.Connection, name: str) -> bool:
    """True if a UNIQUE constraint with the given name exists on
    ``evidence``. SQLAlchemy reflects SQLite UNIQUEs as both unique
    indexes (the implementation) and via ``get_unique_constraints`` —
    we check both so we don't double-create on re-run.
    """
    if not _has_table(bind, "evidence"):
        return False
    insp = sa.inspect(bind)
    for uc in insp.get_unique_constraints("evidence"):
        if uc.get("name") == name:
            return True
    # Belt-and-braces — SQLite may surface a composite UNIQUE as a
    # unique index with the constraint name.
    for ix in insp.get_indexes("evidence"):
        if ix.get("name") == name and ix.get("unique"):
            return True
    return False


# ---------------------------------------------------------------------------
# upgrade
# ---------------------------------------------------------------------------


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind, "evidence"):
        return

    path_unique = _path_index_is_unique(bind)
    has_uq_path = _has_unique_constraint(bind, _UQ_WORKBOOK_PATH)
    has_uq_sha = _has_unique_constraint(bind, _UQ_WORKBOOK_SHA256)

    # Nothing to do — already at the post-0010 shape.
    if path_unique is False and has_uq_path and has_uq_sha:
        return

    # Single batch_alter_table so SQLite rebuilds the table exactly once
    # — index drop, two constraint adds, index re-create.
    with op.batch_alter_table("evidence", schema=None) as batch_op:
        if path_unique is True:
            # Drop the global UNIQUE-on-path index, recreate as a plain
            # index so lookup speed is preserved without the constraint.
            batch_op.drop_index(_PATH_UNIQUE_INDEX)
            batch_op.create_index(_PATH_UNIQUE_INDEX, ["path"], unique=False)
        elif path_unique is None:
            # The index was somehow removed entirely — recreate it
            # non-unique so the lookup-path code keeps its index.
            batch_op.create_index(_PATH_UNIQUE_INDEX, ["path"], unique=False)

        if not has_uq_path:
            batch_op.create_unique_constraint(
                _UQ_WORKBOOK_PATH, ["workbook_id", "path"]
            )
        if not has_uq_sha:
            batch_op.create_unique_constraint(
                _UQ_WORKBOOK_SHA256, ["workbook_id", "sha256"]
            )


# ---------------------------------------------------------------------------
# downgrade
# ---------------------------------------------------------------------------


def downgrade() -> None:
    """Restore the 0001/0009 shape: drop composite UNIQUEs, flip the
    ``ix_evidence_path`` index back to ``unique=True``.

    Downgrading after PR 2's helper changes have shipped means the app
    will reject the second ingest of a file already present with a
    different workbook_id (because the global UNIQUE comes back). That
    is the expected behavior of a downgrade — it's a rollback to the
    pre-PR-2 schema invariant. If the DB has accumulated cross-workbook
    duplicate paths since upgrade, this downgrade will raise an
    IntegrityError during the batch table rebuild. That is correct: the
    data violates the constraint being restored.
    """
    bind = op.get_bind()
    if not _has_table(bind, "evidence"):
        return

    has_uq_path = _has_unique_constraint(bind, _UQ_WORKBOOK_PATH)
    has_uq_sha = _has_unique_constraint(bind, _UQ_WORKBOOK_SHA256)
    path_unique = _path_index_is_unique(bind)

    # Nothing to do — already at the pre-0010 shape.
    if not has_uq_path and not has_uq_sha and path_unique is True:
        return

    with op.batch_alter_table("evidence", schema=None) as batch_op:
        if has_uq_path:
            batch_op.drop_constraint(_UQ_WORKBOOK_PATH, type_="unique")
        if has_uq_sha:
            batch_op.drop_constraint(_UQ_WORKBOOK_SHA256, type_="unique")

        if path_unique is False:
            # Flip ix_evidence_path back to unique=True to match the
            # 0001 schema. drop+recreate because SQLite has no "alter
            # index" verb.
            batch_op.drop_index(_PATH_UNIQUE_INDEX)
            batch_op.create_index(_PATH_UNIQUE_INDEX, ["path"], unique=True)
        elif path_unique is None:
            # Recreate the missing index in its 0001 unique form.
            batch_op.create_index(_PATH_UNIQUE_INDEX, ["path"], unique=True)
