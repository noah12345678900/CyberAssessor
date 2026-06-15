"""Manual-override epoch for decision-cache invalidation.

Revision ID: 0015
Revises: 0014
Create Date: 2026-06-10

Why this migration exists
-------------------------
The :class:`DecisionCache` fingerprint is content-addressed: same row +
same evidence + same CRM ⇒ same fingerprint ⇒ cache hit. Re-running an
unchanged objective replays the prior LLM Decision for free — exactly the
intent. But it hides a silent revert: when a reviewer manually edits a
verdict via ``POST /api/assessments`` (clearing ``needs_review`` to record
explicit human trust), the *content* is unchanged. A later
``POST /api/controls/.../assess`` recomputes the identical fingerprint,
hits the cache, and replays the stale pre-override Decision — the persist
block then clobbers the human's correction and re-raises ``needs_review``.

This table is the tiebreaker. Each manual override bumps ``epoch`` for the
``(workbook_id, objective_id)`` pair, and the epoch participates in the
fingerprint (``engine.decision_cache.fingerprint``). After an override the
fingerprint changes, so the next re-run MISSES the cache and re-assesses
FRESH instead of replaying the superseded decision. The epoch defaults to
0, so objectives that have never been overridden compute exactly the legacy
fingerprint and keep sharing cache entries across workbooks.

Numbering note
--------------
Head at authoring time is ``0014`` (retention/automation/STIG precision),
so ``down_revision = "0014"``.

Idempotency
-----------
``_has_table`` / ``_has_index`` guards mirror
``0014_retention_automation_stig_precision.py``. The new table is created
only when absent, so a DB that already ran ``SQLModel.metadata.create_all``
is left untouched. Safe to re-run.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

_EPOCH = "overrideepoch"


def _has_table(bind: sa.engine.Connection, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def _has_index(bind: sa.engine.Connection, table: str, index: str) -> bool:
    if not _has_table(bind, table):
        return False
    return any(ix["name"] == index for ix in sa.inspect(bind).get_indexes(table))


def upgrade() -> None:
    bind = op.get_bind()

    if not _has_table(bind, _EPOCH):
        op.create_table(
            _EPOCH,
            sa.Column("workbook_id", sa.Integer(), nullable=False),
            sa.Column("objective_id", sa.Integer(), nullable=False),
            sa.Column("epoch", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint("workbook_id", "objective_id"),
            sa.ForeignKeyConstraint(["workbook_id"], ["workbook.id"]),
            sa.ForeignKeyConstraint(["objective_id"], ["objective.id"]),
        )
        op.create_index(
            "ix_overrideepoch_workbook_id", _EPOCH, ["workbook_id"]
        )
        op.create_index(
            "ix_overrideepoch_objective_id", _EPOCH, ["objective_id"]
        )


def downgrade() -> None:
    bind = op.get_bind()

    # Drop the table wholesale (indexes go with it on SQLite).
    if _has_table(bind, _EPOCH):
        op.drop_table(_EPOCH)
