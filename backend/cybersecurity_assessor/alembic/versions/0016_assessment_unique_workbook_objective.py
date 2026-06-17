"""Dedup Assessment rows and enforce UNIQUE(workbook_id, objective_id).

Revision ID: 0016
Revises: 0015
Create Date: 2026-06-17

Why this migration exists
-------------------------
A single (workbook, objective) must have exactly ONE Assessment. The
attach-time CRM backfill (``engine.crm_backfill``) runs once per CRM
overlay attach. With two CRMs attached in separate operations, each pass
built its own ``CrmContext`` snapshot and inserted a rival Assessment row
for the same objective — there was no uniqueness at the DB layer to stop
it. The live symptom: PE-3 (objective 947) had two Assessment rows, one
correct (both clouds) and one stale (single cloud); the UI rendered the
stale one.

This migration (1) deduplicates any existing duplicates, keeping the
"richest" row per (workbook_id, objective_id), and (2) adds the
``uq_assessment_workbook_objective`` UNIQUE constraint so the write path's
get-or-create upsert is enforced and a future double-insert fails loudly
instead of silently forking.

Dedup policy
------------
For each duplicate (workbook_id, objective_id) group, keep the survivor by:
  1. most AssessmentImplementation children (the multi-scope row wins over
     a single-scope partial), then
  2. highest Assessment.id (newest write) as a deterministic tiebreaker.
Delete the losers AND their orphaned AssessmentImplementation rows.

SQLite note: ``workbook_id`` is nullable (SOC engagement rows root on
engagement_id with workbook_id NULL). SQLite treats NULLs as DISTINCT in a
UNIQUE constraint, so engagement-rooted rows never collide — the constraint
only disciplines workbook-rooted assessments, which is exactly the target.

Idempotency
-----------
The constraint is added inside ``batch_alter_table`` only when absent; the
dedup step is a no-op when there are no duplicates. Safe to re-run.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None

_CONSTRAINT = "uq_assessment_workbook_objective"


def _has_table(bind: sa.engine.Connection, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def _has_unique_constraint(
    bind: sa.engine.Connection, table: str, name: str
) -> bool:
    if not _has_table(bind, table):
        return False
    insp = sa.inspect(bind)
    names = {uc.get("name") for uc in insp.get_unique_constraints(table)}
    return name in names


def _dedup_assessments(bind: sa.engine.Connection) -> None:
    """Delete duplicate Assessment rows (+ orphan impls), keep the richest."""
    if not _has_table(bind, "assessment"):
        return

    # Find duplicate (workbook_id, objective_id) groups. workbook_id IS NOT
    # NULL filter excludes engagement-rooted rows (which never collide).
    dup_groups = bind.execute(
        sa.text(
            """
            SELECT workbook_id, objective_id, COUNT(*) AS c
            FROM assessment
            WHERE workbook_id IS NOT NULL
            GROUP BY workbook_id, objective_id
            HAVING c > 1
            """
        )
    ).fetchall()

    has_impls = _has_table(bind, "assessmentimplementation")

    for wb_id, obj_id, _count in dup_groups:
        rows = bind.execute(
            sa.text(
                "SELECT id FROM assessment "
                "WHERE workbook_id = :wb AND objective_id = :obj"
            ),
            {"wb": wb_id, "obj": obj_id},
        ).fetchall()
        ids = [r[0] for r in rows]

        # Rank: most impl children first, then highest id.
        def _impl_count(aid: int) -> int:
            if not has_impls:
                return 0
            return bind.execute(
                sa.text(
                    "SELECT COUNT(*) FROM assessmentimplementation "
                    "WHERE assessment_id = :aid"
                ),
                {"aid": aid},
            ).scalar() or 0

        survivor = sorted(ids, key=lambda aid: (_impl_count(aid), aid))[-1]
        losers = [aid for aid in ids if aid != survivor]
        for aid in losers:
            if has_impls:
                bind.execute(
                    sa.text(
                        "DELETE FROM assessmentimplementation "
                        "WHERE assessment_id = :aid"
                    ),
                    {"aid": aid},
                )
            bind.execute(
                sa.text("DELETE FROM assessment WHERE id = :aid"),
                {"aid": aid},
            )


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind, "assessment"):
        return

    _dedup_assessments(bind)

    if not _has_unique_constraint(bind, "assessment", _CONSTRAINT):
        # SQLite cannot ALTER ADD CONSTRAINT; batch_alter_table rebuilds the
        # table with the new constraint (same mechanics as 0001/0010).
        with op.batch_alter_table("assessment", schema=None) as batch_op:
            batch_op.create_unique_constraint(
                _CONSTRAINT, ["workbook_id", "objective_id"]
            )


def downgrade() -> None:
    bind = op.get_bind()
    if _has_unique_constraint(bind, "assessment", _CONSTRAINT):
        with op.batch_alter_table("assessment", schema=None) as batch_op:
            batch_op.drop_constraint(_CONSTRAINT, type_="unique")
