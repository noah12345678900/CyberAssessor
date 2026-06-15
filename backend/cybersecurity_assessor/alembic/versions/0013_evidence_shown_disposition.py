"""Token-budget evidence audit — ``assessmentevidenceshown`` disposition columns.

Revision ID: 0013
Revises: 0012
Create Date: 2026-06-09

Why this migration exists
-------------------------
The evidence bundle used to truncate tagged evidence to a fixed
``MAX_ARTIFACTS = 6``: artifacts 7..N for an enterprise control (30-50+
tagged artifacts is normal) were silently discarded — they never reached the
model AND never reached the ``AssessmentEvidenceShown`` audit trail. A
3PAO/JAB reviewer asking "what did you examine for AC-2?" got an answer that
omitted most of the evidence with no record that anything was dropped.

The replacement (``engine.evidence_ranker.rank_artifacts``) partitions the
full tagged set into *examined* (admitted under a token budget, shown to the
model) and *deferred* (over budget, NOT shown) — and records BOTH as audit
rows. This migration adds the columns that make a deferred row distinguishable
from an examined one and explain why it was held back. "Anything not examined
must be traceable" is now enforced at the schema level.

Schema changes
--------------
* ``assessmentevidenceshown`` — three new columns:
    - ``disposition`` VARCHAR NOT NULL, ``server_default 'examined'``.
      Backfills every legacy audit row to ``examined`` (correct: before the
      ranker, every recorded chunk was one the model saw). Indexed because the
      SAR coverage join filters examined-vs-deferred per assessment.
    - ``rank_score`` FLOAT NULL — the relevance used for admission ordering,
      denormalized at capture time so a later retag doesn't rewrite history.
    - ``deferred_reason`` VARCHAR NULL — null on examined rows; set to e.g.
      ``token-budget-exceeded`` on deferred rows.

Numbering note
--------------
Head at authoring time is ``0012`` (framework.enabled), so
``down_revision = "0012"``.

Idempotency
-----------
``_has_column`` / ``_has_index`` guards mirror ``0012_framework_enabled.py``.
Adding NOT NULL columns with a constant ``server_default`` is a native
``ALTER TABLE ADD COLUMN`` on SQLite — no table rebuild, so the FK references
into ``assessmentevidenceshown`` (from ``assessmentcitation``) are untouched.
Safe to re-run against a DB that already saw ``SQLModel.metadata.create_all``.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None

_TABLE = "assessmentevidenceshown"


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


def upgrade() -> None:
    bind = op.get_bind()

    if not _has_table(bind, _TABLE):
        # Fresh DB built via create_all before any assessment ran — the table
        # (with these columns) is created directly by the model. Nothing to do.
        return

    if not _has_column(bind, _TABLE, "disposition"):
        op.add_column(
            _TABLE,
            sa.Column(
                "disposition",
                sa.String(),
                nullable=False,
                server_default="examined",
            ),
        )

    if not _has_column(bind, _TABLE, "rank_score"):
        op.add_column(_TABLE, sa.Column("rank_score", sa.Float(), nullable=True))

    if not _has_column(bind, _TABLE, "deferred_reason"):
        op.add_column(
            _TABLE, sa.Column("deferred_reason", sa.String(), nullable=True)
        )

    if not _has_index(bind, _TABLE, "ix_assessmentevidenceshown_disposition"):
        op.create_index(
            "ix_assessmentevidenceshown_disposition",
            _TABLE,
            ["disposition"],
        )


def downgrade() -> None:
    bind = op.get_bind()

    if _has_index(bind, _TABLE, "ix_assessmentevidenceshown_disposition"):
        op.drop_index(
            "ix_assessmentevidenceshown_disposition", table_name=_TABLE
        )

    # SQLite drop_column needs batch mode (table rebuild). The rebuild copies
    # the FK from assessmentcitation.evidence_shown_id forward automatically.
    with op.batch_alter_table(_TABLE, schema=None) as batch_op:
        if _has_column(bind, _TABLE, "deferred_reason"):
            batch_op.drop_column("deferred_reason")
        if _has_column(bind, _TABLE, "rank_score"):
            batch_op.drop_column("rank_score")
        if _has_column(bind, _TABLE, "disposition"):
            batch_op.drop_column("disposition")
