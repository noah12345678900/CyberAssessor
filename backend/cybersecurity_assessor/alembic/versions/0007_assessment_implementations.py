"""Multi-implementation splits — ``assessmentimplementation`` + ``baseline.scope_label``.

Revision ID: 0007
Revises: 0005
Create Date: 2026-06-07

Why this migration exists
-------------------------
A single CCI legitimately splits N ways across implementation
boundaries: a real federal system runs on AWS GovCloud + Azure
Government simultaneously AND keeps an on-prem footprint, and each
slice has its own responsibility verdict, evidence, and narrative the
3PAO needs to see independently. The v0.1 schema collapsed all three
into ``Assessment.narrative_q`` + a half-built two-column split
(``narrative_on_prem`` / ``narrative_cloud``). This migration makes
implementation splits first-class.

Schema changes
--------------
1. ``baseline.scope_label`` — new nullable string column. CRM-source
   Baselines carry the per-implementation label (``"AWS GovCloud"``);
   PROGRAM_CONTROLS / OTHER / OSCAL Baselines leave it null. The
   ``"On-Premises"`` label is reserved and NEVER stored — the assessor
   synthesizes the on-prem implementation row at assess-time.
2. ``assessmentimplementation`` — new child table of ``assessment``. One
   row per implementation slice of a CCI verdict. Unique constraint on
   ``(assessment_id, scope_label)`` so we can't accidentally double-
   write the same slice.

What stays unchanged
--------------------
* ``Assessment.narrative_q`` + ``Assessment.status`` stay as the
  canonical exporter inputs. Multi-impl rows get a worst-of rollup
  status and a ``"{scope_label}: {narrative}"`` composed narrative_q at
  write time; single-impl + pre-migration rows behave exactly as before.
* The deprecated ``narrative_on_prem`` / ``narrative_cloud`` columns
  stay in place as advisory legacy fields. v0.3 cleanup after the new
  shape proves out.

Idempotency
-----------
Wrapped in ``_has_table`` / ``_has_column`` / ``_has_index`` guards,
same pattern as 0005/0006. Safe to re-run against a DB that already
saw ``SQLModel.metadata.create_all``.

FK ondelete behavior
--------------------
* ``AssessmentImplementation.assessment_id`` — no explicit ondelete
  (default RESTRICT). Re-ingest / re-assess flows delete impl rows
  before the parent Assessment, mirroring how POAMs and Evidence are
  unlinked.
* ``AssessmentImplementation.source_baseline_id`` — SET NULL. If the
  source CRM Baseline is later deleted (overlay replace, framework
  reset), the impl row stays — its evidence chain to the SAR is still
  valuable — but its provenance back to a specific CRM degrades.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0007"
down_revision = "0005"
branch_labels = None
depends_on = None


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

    # --- 1. baseline.scope_label ---------------------------------------
    if _has_table(bind, "baseline") and not _has_column(
        bind, "baseline", "scope_label"
    ):
        with op.batch_alter_table("baseline", schema=None) as batch_op:
            batch_op.add_column(sa.Column("scope_label", sa.String(), nullable=True))
    if not _has_index(bind, "baseline", "ix_baseline_scope_label"):
        op.create_index(
            "ix_baseline_scope_label",
            "baseline",
            ["scope_label"],
        )

    # --- 2. assessmentimplementation -----------------------------------
    if not _has_table(bind, "assessmentimplementation"):
        op.create_table(
            "assessmentimplementation",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("assessment_id", sa.Integer(), nullable=False),
            sa.Column("scope_label", sa.String(), nullable=False),
            sa.Column("source_baseline_id", sa.Integer(), nullable=True),
            sa.Column("responsibility", sa.String(), nullable=True),
            sa.Column("status", sa.String(), nullable=False),
            sa.Column("narrative", sa.String(), nullable=False),
            sa.Column("evidence_refs", sa.String(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(
                ["assessment_id"],
                ["assessment.id"],
            ),
            sa.ForeignKeyConstraint(
                ["source_baseline_id"],
                ["baseline.id"],
                ondelete="SET NULL",
            ),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "assessment_id",
                "scope_label",
                name="uq_assessment_implementation_assessment_scope",
            ),
        )
    if not _has_index(
        bind, "assessmentimplementation", "ix_assessmentimplementation_assessment_id"
    ):
        op.create_index(
            "ix_assessmentimplementation_assessment_id",
            "assessmentimplementation",
            ["assessment_id"],
        )
    if not _has_index(
        bind, "assessmentimplementation", "ix_assessmentimplementation_scope_label"
    ):
        op.create_index(
            "ix_assessmentimplementation_scope_label",
            "assessmentimplementation",
            ["scope_label"],
        )
    if not _has_index(
        bind,
        "assessmentimplementation",
        "ix_assessmentimplementation_source_baseline_id",
    ):
        op.create_index(
            "ix_assessmentimplementation_source_baseline_id",
            "assessmentimplementation",
            ["source_baseline_id"],
        )


def downgrade() -> None:
    bind = op.get_bind()

    if _has_table(bind, "assessmentimplementation"):
        for ix in (
            "ix_assessmentimplementation_source_baseline_id",
            "ix_assessmentimplementation_scope_label",
            "ix_assessmentimplementation_assessment_id",
        ):
            if _has_index(bind, "assessmentimplementation", ix):
                op.drop_index(ix, table_name="assessmentimplementation")
        op.drop_table("assessmentimplementation")

    if _has_index(bind, "baseline", "ix_baseline_scope_label"):
        op.drop_index("ix_baseline_scope_label", table_name="baseline")
    if _has_column(bind, "baseline", "scope_label"):
        with op.batch_alter_table("baseline", schema=None) as batch_op:
            batch_op.drop_column("scope_label")
