"""Add ``ingestreport`` for loader-run audit trail.

Revision ID: 0005
Revises: 0004
Create Date: 2026-06-07

Why this table exists
---------------------
``load_program_controls`` makes structural decisions on every workbook load —
notably, border-aware forward-fill across unmerged tall col-A cell blocks
(T1TL's AU-2 block at col A=460 spans sub-bullets a-l; openpyxl sees those as
empty-col-A rows, and the loader must decide row-by-row whether to inherit
the parent control id or surface the row as ``(unnumbered)``).

Pre-this-table, those decisions lived only in the loader's transient
``_rows_seen`` / ``_maps_written`` / ``_unmapped_*`` attrs and surfaced once
in the HTTP response. If the operator didn't screenshot the toast, the audit
signal vanished — yet the ``RequirementMap`` rows it produced look
indistinguishable from rows that came straight from numbered workbook cells.
A 3PAO reviewing the catalog has no way to ask "was this map a forward-fill
or a literal?" without re-running the loader.

``IngestReport`` fills that gap: one row per load, structured counts plus a
JSON ``actions`` log keyed by openpyxl row index. Joining
``RequirementSource → IngestReport`` answers the audit question for every
historical load.

Idempotency
-----------
Wrapped in ``_has_table`` / ``_has_column`` guards so re-running the
migration against a DB that already saw ``SQLModel.metadata.create_all``
(dev path) is a no-op. Indexes created via ``op.create_index`` so SQLite
handles them without a batch-rebuild.

Data migration
--------------
None. Pre-0005 ``RequirementSource`` rows have no ``IngestReport`` child;
the audit endpoint returns an empty trail for those sources, which is
truthful — we don't have a forward-fill log for loads that happened before
the loader could record one.

FK ondelete behavior
--------------------
* ``IngestReport.requirement_source_id`` — CASCADE. A re-import wipes the
  prior ``RequirementSource`` + its maps + its IngestReport in one
  transaction; the audit travels with the data it describes.
* ``IngestReport.framework_id`` — RESTRICT (default). Frameworks are
  effectively immutable in this app; an attempted framework delete with a
  surviving IngestReport is operator error worth surfacing.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def _has_table(bind: sa.engine.Connection, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def _has_index(bind: sa.engine.Connection, table: str, index: str) -> bool:
    if not _has_table(bind, table):
        return False
    return any(ix["name"] == index for ix in sa.inspect(bind).get_indexes(table))


def upgrade() -> None:
    bind = op.get_bind()

    if not _has_table(bind, "ingestreport"):
        op.create_table(
            "ingestreport",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("requirement_source_id", sa.Integer(), nullable=True),
            sa.Column("framework_id", sa.Integer(), nullable=True),
            sa.Column("source_path", sa.String(), nullable=False),
            sa.Column("sheet_name", sa.String(), nullable=True),
            sa.Column("loader_version", sa.String(), nullable=False),
            sa.Column("rows_seen", sa.Integer(), nullable=False, server_default="0"),
            sa.Column(
                "maps_written", sa.Integer(), nullable=False, server_default="0"
            ),
            sa.Column(
                "rows_forward_filled",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "rows_unnumbered", sa.Integer(), nullable=False, server_default="0"
            ),
            sa.Column("unmapped_ccis", sa.JSON(), nullable=False),
            sa.Column("unmapped_control_ids", sa.JSON(), nullable=False),
            sa.Column("actions", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(
                ["requirement_source_id"],
                ["requirementsource.id"],
                ondelete="CASCADE",
            ),
            sa.ForeignKeyConstraint(
                ["framework_id"],
                ["framework.id"],
            ),
            sa.PrimaryKeyConstraint("id"),
        )
    if not _has_index(
        bind, "ingestreport", "ix_ingestreport_requirement_source_id"
    ):
        op.create_index(
            "ix_ingestreport_requirement_source_id",
            "ingestreport",
            ["requirement_source_id"],
        )
    if not _has_index(bind, "ingestreport", "ix_ingestreport_framework_id"):
        op.create_index(
            "ix_ingestreport_framework_id",
            "ingestreport",
            ["framework_id"],
        )
    if not _has_index(bind, "ingestreport", "ix_ingestreport_created_at"):
        op.create_index(
            "ix_ingestreport_created_at",
            "ingestreport",
            ["created_at"],
        )


def downgrade() -> None:
    bind = op.get_bind()

    if _has_table(bind, "ingestreport"):
        for ix in (
            "ix_ingestreport_created_at",
            "ix_ingestreport_framework_id",
            "ix_ingestreport_requirement_source_id",
        ):
            if _has_index(bind, "ingestreport", ix):
                op.drop_index(ix, table_name="ingestreport")
        op.drop_table("ingestreport")
