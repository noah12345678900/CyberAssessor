"""Make ``assessmentimplementation.status`` nullable (per-scope abstain).

Revision ID: 0017
Revises: 0016
Create Date: 2026-06-18

Why this migration exists
-------------------------
``engine.assessor.plan_implementations`` deliberately emits the synthesized
On-Premises *residual* per-scope row with ``status=None``: when a cloud scope
is customer-owned but no on-prem evidence was assessed, the cloud verdict must
NOT silently extend to the on-prem footprint (precision over recall). The
narrative on that row says exactly that and flags it for reviewer follow-up.

Every consumer already tolerated a None per-scope status —
``compute_rollup_status`` types its input ``list[ComplianceStatus | None]``
and returns None for an all-abstain set; the parent ``Assessment.status`` is
only overwritten for non-abstain decisions and is itself nullable; the
``/controls`` serializer passes ``impl.status`` straight through (None -> JSON
null); the SAR reads only the impl ``narrative``. The ONE place out of sync
was this column: it shipped NOT NULL, so persisting the residual abstain slice
raised ``IntegrityError: NOT NULL constraint failed:
assessmentimplementation.status`` mid-flush, rolling back the WHOLE batch
transaction and surfacing to the UI as a 500 on ``POST
/api/controls/assess-batch``.

This migration drops the NOT NULL constraint so storage matches the engine
contract. NULL means "scope acknowledged but unassessed — reviewer
follow-up"; the narrative is always populated in that branch so the row is
never contentless.

Idempotency
-----------
``alter_column`` to ``nullable=True`` is a no-op if already nullable. Safe to
re-run.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

_TABLE = "assessmentimplementation"
_COLUMN = "status"


def _has_table(bind: sa.engine.Connection, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def _is_nullable(bind: sa.engine.Connection, table: str, column: str) -> bool:
    insp = sa.inspect(bind)
    for col in insp.get_columns(table):
        if col["name"] == column:
            return bool(col.get("nullable"))
    return False


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind, _TABLE):
        return
    if _is_nullable(bind, _TABLE, _COLUMN):
        return
    # SQLite cannot ALTER COLUMN in place; batch_alter_table rebuilds the
    # table with the relaxed constraint (same mechanics as 0010/0016).
    with op.batch_alter_table(_TABLE, schema=None) as batch_op:
        batch_op.alter_column(
            _COLUMN,
            existing_type=sa.String(),
            nullable=True,
        )


def downgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind, _TABLE):
        return
    if not _is_nullable(bind, _TABLE, _COLUMN):
        return
    # Re-imposing NOT NULL requires every existing row to have a non-null
    # status. Backfill the residual-abstain rows to NON_COMPLIANT (the
    # safest defensible verdict for an unassessed customer scope) so the
    # downgrade doesn't fail on legitimately-null rows.
    #
    # The column stores the enum NAME, not its value: SQLAlchemy's Enum
    # adapter persists ``ComplianceStatus.NON_COMPLIANT.name`` ("NON_COMPLIANT"),
    # NOT its ``.value`` ("Non-Compliant"). Writing the value here would inject
    # a string no row ever legitimately contains and trip a LookupError on the
    # next load. Use the NAME.
    bind.execute(
        sa.text(
            f"UPDATE {_TABLE} SET {_COLUMN} = 'NON_COMPLIANT' "
            f"WHERE {_COLUMN} IS NULL"
        )
    )
    with op.batch_alter_table(_TABLE, schema=None) as batch_op:
        batch_op.alter_column(
            _COLUMN,
            existing_type=sa.String(),
            nullable=False,
        )
