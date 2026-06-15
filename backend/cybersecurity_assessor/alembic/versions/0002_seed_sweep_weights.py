"""Seed the v1 SweepWeights row.

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-06

Ports the body of the old ``db._seed_initial_sweep_weights`` helper into a
proper data migration. On a fresh install this fires once after the schema
is built and writes the historical hand-tuned weights as the active v1
row — the boundary-aware sweep scorer reads from the row with
``is_active=True`` and would otherwise crash on a fresh DB.

Why the constants are inlined here (not imported from
``evidence.sources.sweep``)
---------------------------------------------------------------------------
Alembic migrations are *historical artifacts* — every revision must keep
working against the state of the world at the time it was written. If we
imported ``_W_HOST`` etc. from the live module, a future weight retune in
``sweep.py`` would silently change what 0002 seeds when re-run on a fresh
DB built from scratch (e.g. a new dev box). Pinning the numbers here keeps
v1 = the same row everyone got at v0.x.0, regardless of what later sweep
recalibrations decide. Online SGD and batch recalibration write *new*
rows; this seed is never updated in place.

Idempotency: guarded by a SELECT — if any SweepWeights row already exists
(e.g. a re-run during dev or stamped-then-upgraded DB), we skip. Matches
the original helper's behavior.
"""

from __future__ import annotations

from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


# Historical v1 weights — DO NOT EDIT in this file. Recalibration writes
# new rows; never touch the seed.
_W_HOST = 0.40
_W_CONTROL_ID = 0.30
_W_FAMILY = 0.20
_W_CRM_KEYWORD = 0.15
_W_PRIORITY_LINK = 0.15
_W_DOC_PREFIX = 0.10
_INTERCEPT = 0.0
_SURFACE_THRESHOLD = 0.30
_PRECHECK_THRESHOLD = 0.60

_SEED_NOTES = (
    "Seeded at DB init from hand-tuned constants in "
    "evidence.sources.sweep. Never updated in place — "
    "recalibration writes new rows."
)


def upgrade() -> None:
    bind = op.get_bind()

    # Skip if any SweepWeights row already exists. Covers fresh installs
    # (no rows → seed), stamped legacy DBs (seed already present from the
    # old init_db helper → skip), and accidental re-runs (skip).
    existing = bind.execute(sa.text("SELECT id FROM sweepweights LIMIT 1")).first()
    if existing is not None:
        return

    bind.execute(
        sa.text(
            """
            INSERT INTO sweepweights (
                fitted_at,
                source,
                weight_host,
                weight_control_id,
                weight_family,
                weight_crm_keyword,
                weight_doc_prefix,
                weight_priority_link,
                intercept,
                surface_threshold,
                precheck_threshold,
                n_decisions_seen,
                auc,
                parent_weights_id,
                notes,
                is_active
            ) VALUES (
                :fitted_at,
                'manual',
                :w_host,
                :w_control_id,
                :w_family,
                :w_crm_keyword,
                :w_doc_prefix,
                :w_priority_link,
                :intercept,
                :surface_threshold,
                :precheck_threshold,
                0,
                NULL,
                NULL,
                :notes,
                1
            )
            """
        ),
        {
            "fitted_at": datetime.now(timezone.utc),
            "w_host": _W_HOST,
            "w_control_id": _W_CONTROL_ID,
            "w_family": _W_FAMILY,
            "w_crm_keyword": _W_CRM_KEYWORD,
            "w_doc_prefix": _W_DOC_PREFIX,
            "w_priority_link": _W_PRIORITY_LINK,
            "intercept": _INTERCEPT,
            "surface_threshold": _SURFACE_THRESHOLD,
            "precheck_threshold": _PRECHECK_THRESHOLD,
            "notes": _SEED_NOTES,
        },
    )


def downgrade() -> None:
    # Only delete the canonical seed row — leaves any sgd_online or
    # batch_lr rows alone in case a partial downgrade is being done for
    # debugging. The seed is uniquely identified by its source + notes
    # signature.
    op.get_bind().execute(
        sa.text(
            "DELETE FROM sweepweights "
            "WHERE source = 'manual' AND notes = :notes"
        ),
        {"notes": _SEED_NOTES},
    )
