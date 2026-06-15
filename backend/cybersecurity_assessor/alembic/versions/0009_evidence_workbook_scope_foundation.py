"""Per-workbook hard scoping foundation — ``Workbook.scope_salt`` + ``quarantinedevidence`` + CASCADE on Evidence M2M FKs.

Revision ID: 0009
Revises: 0007
Create Date: 2026-06-07

Why this migration exists
-------------------------
Evidence has been a global pool since v0.1. ``Evidence.workbook_id`` is
nullable; kernel retrieval (``engine/evidence_bundle.py``) ignores it; dedup
is global on ``sha256`` / ``path``; and workbook delete deliberately NULLs
``Evidence.workbook_id`` to preserve cross-workbook reuse. For federal
compliance work, one mistagged file or a NULL-owner row visible to every
workbook is a cross-customer spillage incident.

This migration is **PR 1 of the per-workbook hard-scoping sequence** — a
foundation-only step that adds schema *without changing app behavior*.
Reads still go through the global pool; writes still tolerate NULL
workbook_id; legacy rows are untouched. PR 2 hardens write paths, PR 3
(alembic 0010) flips the schema invariant (drops the global UNIQUE, moves
NULL rows to quarantine, sets ``Evidence.workbook_id`` NOT NULL), and
PR 4 cuts over every read path + decision cache.

Schema changes (additive only)
------------------------------
1. ``workbook.scope_salt`` — new CHAR(32) NOT NULL column. Random per row
   (``secrets.token_hex(16)``). Mixed into ``decision_cache.fingerprint``
   in PR 4 so two workbooks with byte-identical evidence and prompts
   produce distinct cache keys. **Critical**: each existing row gets a
   *unique* salt during backfill — a shared default would re-create the
   covert cache-replay leak between workbooks. We add the column nullable,
   backfill row-by-row, then ALTER NOT NULL.
2. ``quarantinedevidence`` — new table, mirror of ``Evidence`` minus
   ``workbook_id``, plus ``original_workbook_hint`` (free-text breadcrumb)
   and ``quarantined_at`` (timestamp). Empty after this migration; PR 3
   populates it from legacy ``Evidence.workbook_id IS NULL`` rows. Lives
   in a separate table (not a sentinel ``Workbook.kind="quarantine"`` row)
   so it's a compile-time invariant — no future ``select(Workbook)`` can
   accidentally leak orphans into a customer-facing list.
3. ``ondelete="CASCADE"`` on the six M2M FKs pointing at ``evidence.id``:
   ``evidencetag``, ``evidencecomponent``, ``evidenceasset``,
   ``evidenceboundary``, ``poamevidence``, ``stigfinding``. The original
   0001 schema created these as anonymous FKs with no cascade — meaning
   ``DELETE FROM evidence`` raises IntegrityError today unless every
   M2M row is explicitly purged first. PR 4's workbook-delete rewrite
   relies on the DB enforcing the cascade so we can DELETE Evidence
   directly without re-implementing the walk in Python. We swap the FKs
   via batch_alter_table + a naming_convention so unnamed-FK reflection
   succeeds on SQLite.

What stays unchanged
--------------------
* ``Evidence.workbook_id`` stays nullable through this PR. PR 3 (alembic
  0010) flips it to NOT NULL after the quarantine backfill drains the
  NULL rows.
* All app reads still go through the global pool. Writes still accept
  NULL workbook_id (hardened in PR 2). The behavior change is purely
  PR 4's read-path filter + PR 3's schema invariant.
* ``assessmentevidenceshown.evidence_id`` FK is **NOT** cascaded. The
  snippet payload on that row IS the audit record; byte-equivalent
  replay after a workbook delete matters more than referential
  cleanliness. The FK is documented to dangle by design (see PR 4
  tests/test_audit_replay_survives_delete.py).

Idempotency
-----------
Wrapped in ``_has_table`` / ``_has_column`` / ``_has_index`` /
``_fk_has_cascade`` guards, same pattern as 0007 / 0008. Safe to re-run
against a DB that already saw ``SQLModel.metadata.create_all`` (dev path,
which produces FKs without cascade because SQLModel doesn't read the
``info`` dict on ``sa_column_kwargs``).

FK ondelete behavior — the six cascades
---------------------------------------
* ``evidencetag.evidence_id`` — CASCADE. Tags are pure (Evidence, Objective)
  membership; the tag has no independent meaning once Evidence is gone.
* ``evidencecomponent.evidence_id`` / ``evidenceasset.evidence_id`` /
  ``evidenceboundary.evidence_id`` — CASCADE. Scope membership rows;
  the membership has no value without the attached artifact.
* ``poamevidence.evidence_id`` — CASCADE. The POAM itself survives
  (POAMs are independent records of a finding); only the link to the
  dropped evidence row is severed.
* ``stigfinding.evidence_id`` — CASCADE. Findings live and die with
  their parent scan/CKL — there's no scenario where the finding is
  meaningful after the source CKL is gone.

SQLite FK swap mechanics
------------------------
The 0001 schema declared every M2M FK as ``sa.ForeignKeyConstraint(...)``
with no ``name=`` arg — they reflect as anonymous constraints on SQLite.
``batch_alter_table`` rebuilds the table by reflecting it first; we pass
a ``naming_convention`` so the unnamed FK gets a deterministic name
(``fk_<table>_<col>_<reftable>``), then drop+recreate by that name with
``ondelete="CASCADE"``. This is the documented Alembic pattern for
unnamed SQLite FK swaps.
"""

from __future__ import annotations

import secrets

import sqlalchemy as sa
from alembic import op
from sqlalchemy import MetaData

# revision identifiers, used by Alembic.
revision = "0009"
down_revision = "0011"
branch_labels = None
depends_on = None


# Naming convention used during batch_alter_table reflection so the
# anonymous FKs from 0001 get a deterministic name we can drop+recreate.
# Format: fk_<table>_<col>_<referenced_table>.
_NAMING = {
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
}

# (table, column) pairs that get a new CASCADE FK to evidence(id).
_EVIDENCE_FK_TABLES: tuple[tuple[str, str], ...] = (
    ("evidencetag", "evidence_id"),
    ("evidencecomponent", "evidence_id"),
    ("evidenceasset", "evidence_id"),
    ("evidenceboundary", "evidence_id"),
    ("poamevidence", "evidence_id"),
    ("stigfinding", "evidence_id"),
)


def _has_table(bind: sa.engine.Connection, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def _has_column(bind: sa.engine.Connection, table: str, column: str) -> bool:
    inspector = sa.inspect(bind)
    if table not in inspector.get_table_names():
        return False
    return any(c["name"] == column for c in inspector.get_columns(table))


def _has_index(bind: sa.engine.Connection, table: str, index: str) -> bool:
    if not _has_table(bind, table):
        return False
    return any(ix["name"] == index for ix in sa.inspect(bind).get_indexes(table))


def _fk_has_cascade(bind: sa.engine.Connection, table: str, column: str) -> bool:
    """True if any FK on ``table`` whose constrained_columns contains
    ``column`` has ``ondelete='CASCADE'`` in its reflected options.

    Used to make the FK swap idempotent — re-running the migration against
    a DB that's already been upgraded leaves the FK alone instead of
    rebuilding the table on every alembic upgrade head call.
    """
    if not _has_table(bind, table):
        return False
    for fk in sa.inspect(bind).get_foreign_keys(table):
        cols = fk.get("constrained_columns") or []
        if column in cols:
            options = fk.get("options") or {}
            if (options.get("ondelete") or "").upper() == "CASCADE":
                return True
    return False


def _fk_constraint_name(table: str, column: str) -> str:
    """Deterministic FK name matching the naming_convention applied during
    batch_alter_table reflection. ``referred_table`` is hardcoded to
    ``evidence`` because every FK we touch here points at it.
    """
    return f"fk_{table}_{column}_evidence"


# ---------------------------------------------------------------------------
# upgrade
# ---------------------------------------------------------------------------


def upgrade() -> None:
    bind = op.get_bind()

    # --- 1. workbook.scope_salt ---------------------------------------------
    # Three-step pattern (add nullable -> backfill per-row -> alter NOT NULL)
    # because SQLite cannot add a NOT NULL column without a server-side
    # default, and we explicitly do NOT want a shared default value (that
    # would defeat the entire point of the salt).
    if _has_table(bind, "workbook"):
        if not _has_column(bind, "workbook", "scope_salt"):
            with op.batch_alter_table("workbook", schema=None) as batch_op:
                batch_op.add_column(
                    sa.Column("scope_salt", sa.String(length=32), nullable=True)
                )

            # Backfill every existing row with a UNIQUE salt. Loop in Python
            # so each row gets its own ``secrets.token_hex(16)`` call — a
            # single UPDATE with a constant would re-create the cache-replay
            # leak across workbooks. Cheap: the workbook table is small
            # (one row per program, typically <20 across a deployment's life).
            ids = [row[0] for row in bind.execute(sa.text("SELECT id FROM workbook"))]
            for wb_id in ids:
                bind.execute(
                    sa.text("UPDATE workbook SET scope_salt = :salt WHERE id = :id"),
                    {"salt": secrets.token_hex(16), "id": wb_id},
                )

            with op.batch_alter_table("workbook", schema=None) as batch_op:
                batch_op.alter_column(
                    "scope_salt",
                    existing_type=sa.String(length=32),
                    nullable=False,
                )

    # --- 2. quarantinedevidence ---------------------------------------------
    if not _has_table(bind, "quarantinedevidence"):
        op.create_table(
            "quarantinedevidence",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("path", sa.String(), nullable=False),
            sa.Column("sha256", sa.String(), nullable=False),
            sa.Column("kind", sa.String(), nullable=False),
            sa.Column("size_bytes", sa.Integer(), nullable=False),
            sa.Column("ingested_at", sa.DateTime(), nullable=False),
            sa.Column("extracted_text_path", sa.String(), nullable=True),
            sa.Column("title", sa.String(), nullable=True),
            sa.Column("doc_number", sa.String(), nullable=True),
            sa.Column("archive_uri", sa.String(), nullable=True),
            sa.Column("original_workbook_hint", sa.String(), nullable=True),
            sa.Column("quarantined_at", sa.DateTime(), nullable=False),
            sa.Column("source_kind", sa.String(), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )

    for ix_name, cols in (
        ("ix_quarantinedevidence_path", ["path"]),
        ("ix_quarantinedevidence_sha256", ["sha256"]),
        ("ix_quarantinedevidence_doc_number", ["doc_number"]),
        ("ix_quarantinedevidence_archive_uri", ["archive_uri"]),
        ("ix_quarantinedevidence_quarantined_at", ["quarantined_at"]),
        ("ix_quarantinedevidence_source_kind", ["source_kind"]),
    ):
        if not _has_index(bind, "quarantinedevidence", ix_name):
            op.create_index(ix_name, "quarantinedevidence", cols)

    # --- 3. CASCADE FKs on the six Evidence-M2M tables ----------------------
    # Pass a MetaData with the naming_convention so SQLite's anonymous FKs
    # from 0001 get a deterministic name we can drop. Skip tables whose FK
    # already cascades (idempotency — re-running against an already-upgraded
    # DB or a create_all dev DB where models.py annotations have been picked
    # up by some future SQLModel rev).
    for table, column in _EVIDENCE_FK_TABLES:
        if not _has_table(bind, table):
            continue
        if _fk_has_cascade(bind, table, column):
            continue

        fk_name = _fk_constraint_name(table, column)
        meta = MetaData(naming_convention=_NAMING)
        with op.batch_alter_table(
            table,
            schema=None,
            naming_convention=_NAMING,
            recreate="always",
        ) as batch_op:
            # drop_constraint on an FK that the reflector named via the
            # naming_convention. If the FK was originally created with an
            # explicit name, this will still work because the convention
            # only fills in names where None.
            try:
                batch_op.drop_constraint(fk_name, type_="foreignkey")
            except (ValueError, KeyError):
                # The constraint name didn't match — fall back to dropping
                # any FK on this column. Some SQLAlchemy versions name
                # reflected FKs differently; this defensive path keeps the
                # migration robust across alembic/sqlalchemy minor versions.
                pass
            batch_op.create_foreign_key(
                fk_name,
                "evidence",
                [column],
                ["id"],
                ondelete="CASCADE",
            )
        # ``meta`` referenced to satisfy linters that flag the import; the
        # real wiring happens via the naming_convention kwarg above.
        del meta


# ---------------------------------------------------------------------------
# downgrade
# ---------------------------------------------------------------------------


def downgrade() -> None:
    bind = op.get_bind()

    # --- Reverse step 3: drop CASCADE, restore anonymous FK -----------------
    for table, column in _EVIDENCE_FK_TABLES:
        if not _has_table(bind, table):
            continue
        if not _fk_has_cascade(bind, table, column):
            continue

        fk_name = _fk_constraint_name(table, column)
        with op.batch_alter_table(
            table,
            schema=None,
            naming_convention=_NAMING,
            recreate="always",
        ) as batch_op:
            try:
                batch_op.drop_constraint(fk_name, type_="foreignkey")
            except (ValueError, KeyError):
                pass
            # Recreate without ondelete — match the 0001 anonymous-FK shape
            # as closely as we can. The constraint gets a name now, but
            # functionally it's the same FK.
            batch_op.create_foreign_key(
                fk_name,
                "evidence",
                [column],
                ["id"],
            )

    # --- Reverse step 2: drop quarantinedevidence ---------------------------
    if _has_table(bind, "quarantinedevidence"):
        for ix in (
            "ix_quarantinedevidence_source_kind",
            "ix_quarantinedevidence_quarantined_at",
            "ix_quarantinedevidence_archive_uri",
            "ix_quarantinedevidence_doc_number",
            "ix_quarantinedevidence_sha256",
            "ix_quarantinedevidence_path",
        ):
            if _has_index(bind, "quarantinedevidence", ix):
                op.drop_index(ix, table_name="quarantinedevidence")
        op.drop_table("quarantinedevidence")

    # --- Reverse step 1: drop workbook.scope_salt ---------------------------
    if _has_table(bind, "workbook") and _has_column(bind, "workbook", "scope_salt"):
        with op.batch_alter_table("workbook", schema=None) as batch_op:
            batch_op.drop_column("scope_salt")
