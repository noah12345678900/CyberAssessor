"""POAM risk provenance — ``*_source`` / ``*_rationale`` columns + ``poamriskhistory`` table.

Revision ID: 0008
Revises: 0007
Create Date: 2026-06-07

Why this migration exists
-------------------------
POAM risk scoring v0.1 makes three previously-implicit things explicit so
a 3PAO can defend every verdict:

1. **Provenance** — every ``Poam.likelihood`` / ``impact`` / ``residual_risk``
   gains a sibling ``*_source`` (``"auto"`` | ``"manual"`` | ``"llm_suggested"``
   | NULL for legacy rows) and a free-text ``*_rationale`` so the reason the
   number is what it is travels with the number.
2. **Auditability** — an append-only ``poamriskhistory`` table (modelled on
   ``OdpAuditLog``) records every transition: prev/new value + prev/new
   rationale + prev/new source + actor + UTC timestamp. The 3PAO question
   "this POAM was HIGH in May, who changed it to MODERATE and why?" gets
   a concrete answer months later.
3. **Generator seeding** — companion code changes seed ``impact`` from the
   cluster's highest STIG CAT (CAT I → HIGH, CAT II → MODERATE, CAT III →
   LOW) with ``impact_source = "auto"`` and a rationale citing the rule_id.
   ``likelihood`` is left NULL on purpose — the repo has no CVSS / KEV /
   EPSS signal to ground a guess, and an unjustified MODERATE default
   undermines defensibility more than an empty cell does.

Schema changes
--------------
* ``poam`` — six new nullable string columns:
  ``likelihood_source``, ``likelihood_rationale``,
  ``impact_source``, ``impact_rationale``,
  ``residual_risk_source``, ``residual_risk_rationale``.
* ``poamriskhistory`` — new child table of ``poam``. Indexes match the
  ``OdpAuditLog`` pattern: per-column indexes on ``poam_id`` /
  ``field`` / ``created_at``, plus a composite
  ``(poam_id, created_at)`` index for the common "show the audit trail
  for this POAM newest-first" query.

What stays unchanged
--------------------
* ``Poam.likelihood`` / ``impact`` / ``residual_risk`` / ``raw_severity``
  columns and their semantics. The 5×5 NIST 800-30r1 matrix in
  ``poam/risk.py`` is preserved verbatim — auditors expect that exact
  shape. Only the *inputs*, *provenance*, and *residual analysis* improve.
* ``DEFAULT_LIKELIHOOD`` / ``DEFAULT_IMPACT`` still drive ``raw_severity``
  when assessor inputs are NULL so list sorting on column ``raw_severity``
  doesn't break for un-graded POAMs.

Idempotency
-----------
Wrapped in ``_has_table`` / ``_has_column`` / ``_has_index`` guards, same
pattern as 0005 / 0007. Safe to re-run against a DB that already saw
``SQLModel.metadata.create_all``.

FK ondelete behavior
--------------------
* ``PoamRiskHistory.poam_id`` — explicit CASCADE. The history is only
  meaningful as long as the POAM it describes exists; orphan rows after
  a POAM is purged would be misleading noise. ``OdpAuditLog`` uses the
  same reasoning for its parent linkage.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0008"
down_revision = "0007"
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


_NEW_POAM_COLUMNS = (
    "likelihood_source",
    "likelihood_rationale",
    "impact_source",
    "impact_rationale",
    "residual_risk_source",
    "residual_risk_rationale",
)


def upgrade() -> None:
    bind = op.get_bind()

    # --- 1. poam provenance columns ------------------------------------
    if _has_table(bind, "poam"):
        missing = [
            col for col in _NEW_POAM_COLUMNS if not _has_column(bind, "poam", col)
        ]
        if missing:
            with op.batch_alter_table("poam", schema=None) as batch_op:
                for col in missing:
                    batch_op.add_column(sa.Column(col, sa.String(), nullable=True))

    # --- 2. poamriskhistory --------------------------------------------
    if not _has_table(bind, "poamriskhistory"):
        op.create_table(
            "poamriskhistory",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("poam_id", sa.Integer(), nullable=False),
            sa.Column("field", sa.String(), nullable=False),
            sa.Column("prev_value", sa.String(), nullable=True),
            sa.Column("new_value", sa.String(), nullable=True),
            sa.Column("prev_rationale", sa.String(), nullable=True),
            sa.Column("new_rationale", sa.String(), nullable=True),
            sa.Column("prev_source", sa.String(), nullable=True),
            sa.Column("new_source", sa.String(), nullable=True),
            sa.Column("actor", sa.String(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(
                ["poam_id"],
                ["poam.id"],
                ondelete="CASCADE",
            ),
            sa.PrimaryKeyConstraint("id"),
        )

    if not _has_index(bind, "poamriskhistory", "ix_poamriskhistory_poam_id"):
        op.create_index(
            "ix_poamriskhistory_poam_id",
            "poamriskhistory",
            ["poam_id"],
        )
    if not _has_index(bind, "poamriskhistory", "ix_poamriskhistory_field"):
        op.create_index(
            "ix_poamriskhistory_field",
            "poamriskhistory",
            ["field"],
        )
    if not _has_index(bind, "poamriskhistory", "ix_poamriskhistory_created_at"):
        op.create_index(
            "ix_poamriskhistory_created_at",
            "poamriskhistory",
            ["created_at"],
        )
    if not _has_index(
        bind, "poamriskhistory", "ix_poam_risk_history_poam_id_created_at"
    ):
        op.create_index(
            "ix_poam_risk_history_poam_id_created_at",
            "poamriskhistory",
            ["poam_id", "created_at"],
        )


def downgrade() -> None:
    bind = op.get_bind()

    if _has_table(bind, "poamriskhistory"):
        for ix in (
            "ix_poam_risk_history_poam_id_created_at",
            "ix_poamriskhistory_created_at",
            "ix_poamriskhistory_field",
            "ix_poamriskhistory_poam_id",
        ):
            if _has_index(bind, "poamriskhistory", ix):
                op.drop_index(ix, table_name="poamriskhistory")
        op.drop_table("poamriskhistory")

    if _has_table(bind, "poam"):
        existing = [
            col for col in _NEW_POAM_COLUMNS if _has_column(bind, "poam", col)
        ]
        if existing:
            with op.batch_alter_table("poam", schema=None) as batch_op:
                for col in existing:
                    batch_op.drop_column(col)
