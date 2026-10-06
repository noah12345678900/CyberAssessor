"""Scope ODP assignments and history to a workbook.

Revision ID: 0020
Revises: 0019
Create Date: 2026-10-06
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def _has_table(bind: sa.engine.Connection, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def _has_column(bind: sa.engine.Connection, table: str, column: str) -> bool:
    if not _has_table(bind, table):
        return False
    return any(c["name"] == column for c in sa.inspect(bind).get_columns(table))


def _create_scoped_assignment_table(name: str) -> None:
    op.create_table(
        name,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("workbook_id", sa.Integer(), nullable=True),
        sa.Column("framework_version", sa.String(), nullable=False),
        sa.Column("control_id", sa.String(), nullable=False),
        sa.Column("odp_id", sa.String(), nullable=False),
        sa.Column("assigned_from", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False),
        sa.Column("source_ingest", sa.String(), nullable=False),
        sa.Column("ingested_at", sa.DateTime(), nullable=False),
        sa.Column("oscal_param_id", sa.String(), nullable=True),
        sa.Column("slot_index", sa.Integer(), nullable=True),
        sa.Column("slot_total", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["workbook_id"], ["workbook.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "workbook_id",
            "framework_version",
            "control_id",
            "odp_id",
            "assigned_from",
            name="uq_odpassignment_workbook_key",
        ),
    )


def _create_scoped_indexes() -> None:
    op.create_index("ix_odpassignment_control_id", "odpassignment", ["control_id"], unique=False)
    op.create_index(
        "ix_odpassignment_framework_version",
        "odpassignment",
        ["framework_version"],
        unique=False,
    )
    op.create_index("ix_odpassignment_workbook_id", "odpassignment", ["workbook_id"], unique=False)
    op.create_index(
        "ix_odpassignment_workbook_fw_control",
        "odpassignment",
        ["workbook_id", "framework_version", "control_id"],
        unique=False,
    )


def upgrade() -> None:
    bind = op.get_bind()
    if _has_table(bind, "odpassignment") and not _has_column(bind, "odpassignment", "workbook_id"):
        _create_scoped_assignment_table("_odpassignment_scoped")
        op.execute(
            """
            INSERT INTO _odpassignment_scoped (
                workbook_id, framework_version, control_id, odp_id,
                assigned_from, value, source_ingest, ingested_at,
                oscal_param_id, slot_index, slot_total
            )
            SELECT
                NULL, framework_version, control_id, odp_id,
                assigned_from, value, source_ingest, ingested_at,
                oscal_param_id, slot_index, slot_total
            FROM odpassignment
            """
        )
        op.drop_table("odpassignment")
        op.rename_table("_odpassignment_scoped", "odpassignment")
        _create_scoped_indexes()

    if _has_table(bind, "odpauditlog") and not _has_column(bind, "odpauditlog", "workbook_id"):
        op.add_column("odpauditlog", sa.Column("workbook_id", sa.Integer(), nullable=True))
        op.create_index(
            "ix_odpauditlog_workbook_id",
            "odpauditlog",
            ["workbook_id"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    if _has_table(bind, "odpassignment") and _has_column(bind, "odpassignment", "workbook_id"):
        op.create_table(
            "_odpassignment_global",
            sa.Column("framework_version", sa.String(), nullable=False),
            sa.Column("control_id", sa.String(), nullable=False),
            sa.Column("odp_id", sa.String(), nullable=False),
            sa.Column("assigned_from", sa.String(), nullable=False),
            sa.Column("value", sa.String(), nullable=False),
            sa.Column("source_ingest", sa.String(), nullable=False),
            sa.Column("ingested_at", sa.DateTime(), nullable=False),
            sa.Column("oscal_param_id", sa.String(), nullable=True),
            sa.Column("slot_index", sa.Integer(), nullable=True),
            sa.Column("slot_total", sa.Integer(), nullable=True),
            sa.PrimaryKeyConstraint("framework_version", "control_id", "odp_id", "assigned_from"),
        )
        op.execute(
            """
            INSERT OR REPLACE INTO _odpassignment_global (
                framework_version, control_id, odp_id, assigned_from,
                value, source_ingest, ingested_at, oscal_param_id,
                slot_index, slot_total
            )
            SELECT
                framework_version, control_id, odp_id, assigned_from,
                value, source_ingest, ingested_at, oscal_param_id,
                slot_index, slot_total
            FROM odpassignment
            ORDER BY ingested_at, id
            """
        )
        op.drop_table("odpassignment")
        op.rename_table("_odpassignment_global", "odpassignment")
        op.create_index(
            "ix_odpassignment_control_id",
            "odpassignment",
            ["control_id"],
            unique=False,
        )
        op.create_index(
            "ix_odpassignment_framework_version",
            "odpassignment",
            ["framework_version"],
            unique=False,
        )

    if _has_table(bind, "odpauditlog") and _has_column(bind, "odpauditlog", "workbook_id"):
        op.drop_index("ix_odpauditlog_workbook_id", table_name="odpauditlog")
        with op.batch_alter_table("odpauditlog", schema=None) as batch_op:
            batch_op.drop_column("workbook_id")
