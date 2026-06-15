"""POAM residual-risk suggestion cache — ``residualsuggestioncache`` table.

Revision ID: 0011
Revises: 0008
Create Date: 2026-06-07

Why this migration exists
-------------------------
The POAM residual-risk advisor (``poam/residual_advisor.py``) is an
LLM-powered, environment-aware reviewer that proposes a residual risk
level by reading the POAM, its contributing STIG findings, and the
narratives on linked controls (which carry the boundary description —
internet-facing vs airgapped, compensating controls, etc.).

Without caching every render of the residual advisor card in the UI
would trigger a fresh LLM call against the same content, which is both
slow and unnecessary. This table stores the JSON suggestion payload
keyed by a content fingerprint that includes the advisor kernel
version + prompt sha + serialized POAM + linked-narrative state.
Bumping ``ADVISOR_KERNEL_VERSION`` or editing the advisor prompt
automatically invalidates every cached row — same contract as
:class:`DecisionCache` (alembic 0001 / engine/decision_cache.py).

Schema
------
* ``residualsuggestioncache``
    - ``fingerprint`` PK  — sha256 over (advisor_version, prompt_sha,
      poam_payload, linked_objective_payload, finding_ids).
    - ``advisor_version`` indexed — semver string, lets ops compare
      cache utilization across kernel versions.
    - ``prompt_sha`` indexed — sha256 of residual_advisor.md, edits
      trigger re-evaluation.
    - ``poam_id`` indexed + FK ondelete CASCADE — deleting a POAM
      evicts its cached suggestions so future re-creations of the same
      id don't replay stale prose.
    - ``decided_at`` — UTC.
    - ``payload_json`` — serialized ``ResidualSuggestion``.
    - ``hit_count`` / ``last_hit_at`` — observability mirrors
      :class:`DecisionCache`.

Numbering note
--------------
This is migration ``0011`` rather than the next sequential ``0009``
because the parallel evidence-workbook-scope branch already used the
``0009`` / ``0010`` filenames. When this PR rebases onto a main that
contains those migrations, the ``down_revision`` below should be
updated to point at whatever revision is then current. ``0008`` is the
correct down-revision for the poam-risk-provenance branch in
isolation.

Idempotency
-----------
``_has_table`` / ``_has_index`` guards match the pattern in
``0008_poam_risk_provenance.py``. Safe to re-run.

FK ondelete behavior
--------------------
* ``ResidualSuggestionCache.poam_id`` — explicit CASCADE. Mirrors the
  reasoning in 0008 for ``PoamRiskHistory.poam_id``: stale cached
  prose tied to a long-deleted POAM is misleading noise, never useful
  signal.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0011"
down_revision = "0008"
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

    if not _has_table(bind, "residualsuggestioncache"):
        op.create_table(
            "residualsuggestioncache",
            sa.Column("fingerprint", sa.String(), nullable=False),
            sa.Column("advisor_version", sa.String(), nullable=False),
            sa.Column("prompt_sha", sa.String(), nullable=False),
            sa.Column("poam_id", sa.Integer(), nullable=False),
            sa.Column("decided_at", sa.DateTime(), nullable=False),
            sa.Column("payload_json", sa.String(), nullable=False),
            sa.Column("hit_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_hit_at", sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(
                ["poam_id"],
                ["poam.id"],
                ondelete="CASCADE",
            ),
            sa.PrimaryKeyConstraint("fingerprint"),
        )

    if not _has_index(
        bind, "residualsuggestioncache", "ix_residualsuggestioncache_advisor_version"
    ):
        op.create_index(
            "ix_residualsuggestioncache_advisor_version",
            "residualsuggestioncache",
            ["advisor_version"],
        )
    if not _has_index(
        bind, "residualsuggestioncache", "ix_residualsuggestioncache_prompt_sha"
    ):
        op.create_index(
            "ix_residualsuggestioncache_prompt_sha",
            "residualsuggestioncache",
            ["prompt_sha"],
        )
    if not _has_index(
        bind, "residualsuggestioncache", "ix_residualsuggestioncache_poam_id"
    ):
        op.create_index(
            "ix_residualsuggestioncache_poam_id",
            "residualsuggestioncache",
            ["poam_id"],
        )


def downgrade() -> None:
    bind = op.get_bind()

    if _has_table(bind, "residualsuggestioncache"):
        for ix in (
            "ix_residualsuggestioncache_poam_id",
            "ix_residualsuggestioncache_prompt_sha",
            "ix_residualsuggestioncache_advisor_version",
        ):
            if _has_index(bind, "residualsuggestioncache", ix):
                op.drop_index(ix, table_name="residualsuggestioncache")
        op.drop_table("residualsuggestioncache")
