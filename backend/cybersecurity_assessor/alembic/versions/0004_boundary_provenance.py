"""Add ``boundarytokensource`` + ``sweephit`` for per-token / per-hit provenance.

Revision ID: 0004
Revises: 0003
Create Date: 2026-06-06

Why these tables exist
----------------------
Two parallel auditability gaps shipped before v0.2:

* ``SystemContext.extracted_tokens`` is a flat ``list[str]``. The aggregate
  ``source_ref`` (``"evidence:[1,2,3]"``) can tell a 3PAO which docs informed
  the context, but not which doc produced the token ``okta`` specifically.
  ``BoundaryTokenSource`` is the answer: one row per token per SC, pinned to
  the Evidence row + snippet that produced it.
* ``SweepCandidate`` is explicitly ephemeral (sweep.py:184-232). Only
  candidates the operator *ingested* leave a trail (``SweepDecision``).
  Surfaced-but-skipped candidates vanish — the question "why did this file
  even appear in the sweep tray?" has no answer for skipped rows. ``SweepHit``
  fills that hole: one row per token-match per surfaced candidate, written in
  the same transaction as the parent ``SweepRun``.

Both tables are pure additions; no existing row's behavior changes.

Idempotency
-----------
Wrapped in ``_has_table`` / ``_has_column`` guards so re-running the migration
against a DB that already ran ``SQLModel.metadata.create_all`` (dev path) is a
no-op rather than an error. Indexes created via ``op.create_index`` rather than
inside ``batch_alter_table`` so SQLite handles them cleanly without a table
rebuild — these are pure CREATE INDEX statements, no schema rewrite needed.

Data migration
--------------
None — and that is non-negotiable. Pre-v0.2 ``SystemContext`` rows have no
``BoundaryTokenSource`` children; the sweep's ``build_boundary_fingerprint``
walks those tokens through a fallback path that yields
``source_kind="unattributed"`` at read time. v0.1-ingested workbooks keep
working end-to-end with no backfill. Likewise ``SweepRun`` rows from before
this migration have no ``SweepHit`` children; the future detail-pane endpoint
returns an empty hit list for those runs.

FK ondelete behavior
--------------------
* ``BoundaryTokenSource.system_context_id`` — CASCADE. The SC upsert in
  ``boundary_docs.py`` replaces the full ``extracted_tokens`` list on each
  apply; CASCADE keeps the side table consistent with the parent without
  application-level cleanup chasing every code path that drops an SC.
* ``BoundaryTokenSource.source_evidence_id`` — SET NULL. If the source
  evidence is later deleted, the token row stays (its presence in
  ``SystemContext.extracted_tokens`` is what biases sweep) but its provenance
  degrades to unattributed.
* ``SweepHit.sweep_run_id`` — CASCADE. SweepRun deletes (rare; operator
  cleanup of an aborted run) drop the hit detail with them.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0004"
down_revision = "0003"
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

    if not _has_table(bind, "boundarytokensource"):
        op.create_table(
            "boundarytokensource",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("system_context_id", sa.Integer(), nullable=False),
            sa.Column("token", sa.String(), nullable=False),
            sa.Column("source_evidence_id", sa.Integer(), nullable=True),
            sa.Column("source_snippet", sa.String(), nullable=True),
            sa.Column("source_kind", sa.String(), nullable=False),
            sa.Column("confidence", sa.Float(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(
                ["system_context_id"],
                ["systemcontext.id"],
                ondelete="CASCADE",
            ),
            sa.ForeignKeyConstraint(
                ["source_evidence_id"],
                ["evidence.id"],
                ondelete="SET NULL",
            ),
            sa.PrimaryKeyConstraint("id"),
        )
    if not _has_index(
        bind, "boundarytokensource", "ix_boundarytokensource_system_context_id"
    ):
        op.create_index(
            "ix_boundarytokensource_system_context_id",
            "boundarytokensource",
            ["system_context_id"],
        )
    if not _has_index(bind, "boundarytokensource", "ix_boundarytokensource_token"):
        op.create_index(
            "ix_boundarytokensource_token",
            "boundarytokensource",
            ["token"],
        )
    if not _has_index(
        bind, "boundarytokensource", "ix_boundarytokensource_source_evidence_id"
    ):
        op.create_index(
            "ix_boundarytokensource_source_evidence_id",
            "boundarytokensource",
            ["source_evidence_id"],
        )
    if not _has_index(
        bind, "boundarytokensource", "ix_boundarytokensource_source_kind"
    ):
        op.create_index(
            "ix_boundarytokensource_source_kind",
            "boundarytokensource",
            ["source_kind"],
        )
    if not _has_index(bind, "boundarytokensource", "ix_boundarytokensource_sc_token"):
        op.create_index(
            "ix_boundarytokensource_sc_token",
            "boundarytokensource",
            ["system_context_id", "token"],
        )

    if not _has_table(bind, "sweephit"):
        op.create_table(
            "sweephit",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("sweep_run_id", sa.Integer(), nullable=False),
            sa.Column("candidate_key", sa.String(), nullable=False),
            sa.Column("matched_token", sa.String(), nullable=False),
            sa.Column("matched_signal", sa.String(), nullable=False),
            sa.Column("score_contribution", sa.Float(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(
                ["sweep_run_id"],
                ["sweeprun.id"],
                ondelete="CASCADE",
            ),
            sa.PrimaryKeyConstraint("id"),
        )
    if not _has_index(bind, "sweephit", "ix_sweephit_sweep_run_id"):
        op.create_index(
            "ix_sweephit_sweep_run_id", "sweephit", ["sweep_run_id"]
        )
    if not _has_index(bind, "sweephit", "ix_sweephit_candidate_key"):
        op.create_index(
            "ix_sweephit_candidate_key", "sweephit", ["candidate_key"]
        )
    if not _has_index(bind, "sweephit", "ix_sweephit_run_candidate"):
        op.create_index(
            "ix_sweephit_run_candidate",
            "sweephit",
            ["sweep_run_id", "candidate_key"],
        )


def downgrade() -> None:
    bind = op.get_bind()

    if _has_table(bind, "sweephit"):
        for ix in (
            "ix_sweephit_run_candidate",
            "ix_sweephit_candidate_key",
            "ix_sweephit_sweep_run_id",
        ):
            if _has_index(bind, "sweephit", ix):
                op.drop_index(ix, table_name="sweephit")
        op.drop_table("sweephit")

    if _has_table(bind, "boundarytokensource"):
        for ix in (
            "ix_boundarytokensource_sc_token",
            "ix_boundarytokensource_source_kind",
            "ix_boundarytokensource_source_evidence_id",
            "ix_boundarytokensource_token",
            "ix_boundarytokensource_system_context_id",
        ):
            if _has_index(bind, "boundarytokensource", ix):
                op.drop_index(ix, table_name="boundarytokensource")
        op.drop_table("boundarytokensource")
