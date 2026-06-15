"""Evidence retention ledger, automation schedules, STIG narrative precision.

Revision ID: 0014
Revises: 0013
Create Date: 2026-06-09

Why this migration exists
-------------------------
Three independent-but-related additions, all in service of the v2.0
in-boundary autonomous assessor and the "defensibility over velocity"
north star:

1. **STIG narrative precision** (``stigfinding`` columns). A citation has to
   point at the *specific SV-rule* that failed and show the V-number a
   reviewer recognizes from STIG Viewer — not just name the CKL. The
   extractors already parse the STIG Group ID / Vuln_Num and the
   check/fix language; until now we threw it away. Four nullable columns
   capture it: ``group_id`` (V-number, indexed), ``rule_title``,
   ``check_text``, ``fix_text``.

2. **Evidence retention ledger** (``evidenceretentionevent`` table). A
   continuously-pulling connector can grow a workbook's evidence set
   without bound. We cap it per-workbook and evict the oldest
   *safe-to-evict* rows; every eviction is logged here (append-only,
   never itself evicted) so the audit trail can answer "what was deleted,
   when, and why" after the row is gone.

3. **Automation schedules** (``automationschedule`` table). The
   per-workbook autostart queue — one row per (workbook, connector
   source) describing when to pull and whether to chain a re-assessment.
   The v0.x seed of the v2.0 scheduler.

Numbering note
--------------
Head at authoring time is ``0013`` (evidence-shown disposition), so
``down_revision = "0013"``.

Idempotency
-----------
``_has_table`` / ``_has_column`` / ``_has_index`` guards mirror
``0013_evidence_shown_disposition.py``. New columns on ``stigfinding`` are
all nullable, so they are native ``ALTER TABLE ADD COLUMN`` on SQLite (no
table rebuild — the FK from ``stigfinding.evidence_id`` stays put). The two
new tables are created only when absent, so a DB that already ran
``SQLModel.metadata.create_all`` is left untouched. Safe to re-run.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

_STIG = "stigfinding"
_RETENTION = "evidenceretentionevent"
_SCHEDULE = "automationschedule"


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

    # --- 1. stigfinding precision columns --------------------------------
    # Only patch the table if it already exists; a fresh DB gets the full
    # column set from create_all and needs nothing here.
    if _has_table(bind, _STIG):
        if not _has_column(bind, _STIG, "group_id"):
            op.add_column(_STIG, sa.Column("group_id", sa.String(), nullable=True))
        if not _has_column(bind, _STIG, "rule_title"):
            op.add_column(_STIG, sa.Column("rule_title", sa.String(), nullable=True))
        if not _has_column(bind, _STIG, "check_text"):
            op.add_column(_STIG, sa.Column("check_text", sa.String(), nullable=True))
        if not _has_column(bind, _STIG, "fix_text"):
            op.add_column(_STIG, sa.Column("fix_text", sa.String(), nullable=True))
        if not _has_index(bind, _STIG, "ix_stigfinding_group_id"):
            op.create_index("ix_stigfinding_group_id", _STIG, ["group_id"])

    # --- 2. evidence retention ledger ------------------------------------
    if not _has_table(bind, _RETENTION):
        op.create_table(
            _RETENTION,
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("workbook_id", sa.Integer(), nullable=False),
            sa.Column("evicted_evidence_id", sa.Integer(), nullable=False),
            sa.Column("evicted_path", sa.String(), nullable=True),
            sa.Column("evicted_sha256", sa.String(), nullable=True),
            sa.Column("evicted_title", sa.String(), nullable=True),
            sa.Column("evicted_ingested_at", sa.DateTime(), nullable=True),
            sa.Column(
                "reason",
                sa.String(),
                nullable=False,
                server_default="cap_exceeded",
            ),
            sa.Column("detail", sa.String(), nullable=True),
            sa.Column("remaining_count", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["workbook_id"], ["workbook.id"]),
        )
        op.create_index(
            "ix_evidenceretentionevent_workbook_id", _RETENTION, ["workbook_id"]
        )
        op.create_index(
            "ix_evidenceretentionevent_evicted_evidence_id",
            _RETENTION,
            ["evicted_evidence_id"],
        )
        op.create_index(
            "ix_evidenceretentionevent_reason", _RETENTION, ["reason"]
        )
        op.create_index(
            "ix_evidenceretentionevent_created_at", _RETENTION, ["created_at"]
        )

    # --- 3. automation schedules -----------------------------------------
    if not _has_table(bind, _SCHEDULE):
        op.create_table(
            _SCHEDULE,
            sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
            sa.Column("workbook_id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(), nullable=True),
            sa.Column("source_type", sa.String(), nullable=False),
            sa.Column("source_ref", sa.String(), nullable=True),
            sa.Column(
                "interval_minutes",
                sa.Integer(),
                nullable=False,
                server_default="1440",
            ),
            sa.Column(
                "run_assessment",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
            sa.Column(
                "enabled",
                sa.Boolean(),
                nullable=False,
                server_default=sa.true(),
            ),
            sa.Column("last_run_at", sa.DateTime(), nullable=True),
            sa.Column("last_status", sa.String(), nullable=True),
            sa.Column("last_detail", sa.String(), nullable=True),
            sa.Column("next_run_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["workbook_id"], ["workbook.id"]),
        )
        op.create_index(
            "ix_automationschedule_workbook_id", _SCHEDULE, ["workbook_id"]
        )
        op.create_index(
            "ix_automationschedule_source_type", _SCHEDULE, ["source_type"]
        )
        op.create_index(
            "ix_automationschedule_enabled", _SCHEDULE, ["enabled"]
        )
        op.create_index(
            "ix_automationschedule_next_run_at", _SCHEDULE, ["next_run_at"]
        )


def downgrade() -> None:
    bind = op.get_bind()

    # Drop new tables wholesale (indexes go with them on SQLite).
    if _has_table(bind, _SCHEDULE):
        op.drop_table(_SCHEDULE)
    if _has_table(bind, _RETENTION):
        op.drop_table(_RETENTION)

    # stigfinding column removal needs batch mode on SQLite.
    if _has_table(bind, _STIG):
        if _has_index(bind, _STIG, "ix_stigfinding_group_id"):
            op.drop_index("ix_stigfinding_group_id", table_name=_STIG)
        with op.batch_alter_table(_STIG, schema=None) as batch_op:
            if _has_column(bind, _STIG, "fix_text"):
                batch_op.drop_column("fix_text")
            if _has_column(bind, _STIG, "check_text"):
                batch_op.drop_column("check_text")
            if _has_column(bind, _STIG, "rule_title"):
                batch_op.drop_column("rule_title")
            if _has_column(bind, _STIG, "group_id"):
                batch_op.drop_column("group_id")
