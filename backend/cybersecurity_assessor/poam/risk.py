"""NIST SP 800-30 Rev 1 risk math.

Single source of truth for the 5-level scale, semi-quantitative scores, and
the 5x5 risk matrix. All risk-aware code paths (generator defaults, UI
tooltips, exporter validation) read from here — no ad-hoc risk schemes
anywhere else in the codebase.

References:
  Table G-2  Likelihood of threat event initiation       (adversarial)
  Table G-3  Likelihood of threat event occurrence       (non-adversarial)
  Table G-4  Likelihood of threat event resulting in adverse impact
  Table G-5  Overall likelihood (G-2/G-3 × G-4)
  Table H-3  Impact of threat events
  Table I-2  Risk = function(Likelihood, Impact)   ← the matrix below
  Table I-3  Risk descriptions
"""

from __future__ import annotations

from sqlmodel import Session

from ..models import PoamRiskHistory, RiskLevel

# Table I-2 semi-quantitative scores. Used when callers need numeric values
# (e.g. sorting POAMs by raw_severity desc in the UI list view).
SCORES: dict[RiskLevel, int] = {
    RiskLevel.VERY_LOW: 0,
    RiskLevel.LOW: 2,
    RiskLevel.MODERATE: 5,
    RiskLevel.HIGH: 8,
    RiskLevel.VERY_HIGH: 10,
}

# Inverse: 800-30 score-range → bucket. SP 800-30 buckets the
# semi-quantitative scale as: 0  | 1-3 | 4-6 | 7-9 | 10.
def score_to_level(score: int) -> RiskLevel:
    if score <= 0:
        return RiskLevel.VERY_LOW
    if score <= 3:
        return RiskLevel.LOW
    if score <= 6:
        return RiskLevel.MODERATE
    if score <= 9:
        return RiskLevel.HIGH
    return RiskLevel.VERY_HIGH


# Table I-2 — the canonical 5×5 risk matrix.
# Indexed [likelihood][impact]. Values transcribed directly from
# SP 800-30r1 Appendix I to keep this auditable against the source document.
#
#                    Impact →
#                    VL    L    M    H    VH
# Likelihood ↓
#   VL              VL    VL    VL    L    L
#   L               VL    L     L     L    M
#   M               VL    L     M     M    H
#   H               VL    L     M     H    VH
#   VH              VL    L     M     H    VH
RISK_MATRIX: dict[RiskLevel, dict[RiskLevel, RiskLevel]] = {
    RiskLevel.VERY_LOW: {
        RiskLevel.VERY_LOW: RiskLevel.VERY_LOW,
        RiskLevel.LOW: RiskLevel.VERY_LOW,
        RiskLevel.MODERATE: RiskLevel.VERY_LOW,
        RiskLevel.HIGH: RiskLevel.LOW,
        RiskLevel.VERY_HIGH: RiskLevel.LOW,
    },
    RiskLevel.LOW: {
        RiskLevel.VERY_LOW: RiskLevel.VERY_LOW,
        RiskLevel.LOW: RiskLevel.LOW,
        RiskLevel.MODERATE: RiskLevel.LOW,
        RiskLevel.HIGH: RiskLevel.LOW,
        RiskLevel.VERY_HIGH: RiskLevel.MODERATE,
    },
    RiskLevel.MODERATE: {
        RiskLevel.VERY_LOW: RiskLevel.VERY_LOW,
        RiskLevel.LOW: RiskLevel.LOW,
        RiskLevel.MODERATE: RiskLevel.MODERATE,
        RiskLevel.HIGH: RiskLevel.MODERATE,
        RiskLevel.VERY_HIGH: RiskLevel.HIGH,
    },
    RiskLevel.HIGH: {
        RiskLevel.VERY_LOW: RiskLevel.VERY_LOW,
        RiskLevel.LOW: RiskLevel.LOW,
        RiskLevel.MODERATE: RiskLevel.MODERATE,
        RiskLevel.HIGH: RiskLevel.HIGH,
        RiskLevel.VERY_HIGH: RiskLevel.VERY_HIGH,
    },
    RiskLevel.VERY_HIGH: {
        RiskLevel.VERY_LOW: RiskLevel.VERY_LOW,
        RiskLevel.LOW: RiskLevel.LOW,
        RiskLevel.MODERATE: RiskLevel.MODERATE,
        RiskLevel.HIGH: RiskLevel.HIGH,
        RiskLevel.VERY_HIGH: RiskLevel.VERY_HIGH,
    },
}


def compute_risk(likelihood: RiskLevel, impact: RiskLevel) -> RiskLevel:
    """Look up overall risk from the 800-30r1 Table I-2 matrix."""
    return RISK_MATRIX[likelihood][impact]


# Table I-3 — human-readable descriptions. Surfaced as tooltips in the UI
# Select components so the assessor doesn't have to memorize the rubric.
LEVEL_DESCRIPTIONS: dict[RiskLevel, str] = {
    RiskLevel.VERY_LOW: (
        "Threat event could have a negligible adverse effect on operations, "
        "assets, individuals, other organizations, or the Nation."
    ),
    RiskLevel.LOW: (
        "Threat event could have a limited adverse effect on operations, "
        "assets, individuals, other organizations, or the Nation."
    ),
    RiskLevel.MODERATE: (
        "Threat event could have a serious adverse effect on operations, "
        "assets, individuals, other organizations, or the Nation."
    ),
    RiskLevel.HIGH: (
        "Threat event could have a severe or catastrophic adverse effect on "
        "operations, assets, individuals, other organizations, or the Nation."
    ),
    RiskLevel.VERY_HIGH: (
        "Threat event could have multiple severe or catastrophic adverse "
        "effects on operations, assets, individuals, other organizations, or "
        "the Nation."
    ),
}


# Default likelihood/impact for newly-generated POAMs. Conservative middle
# ground; assessor adjusts before export to eMASS. These are intentionally
# Moderate/Moderate rather than guessing from CCI metadata — the assessor
# owns this judgment.
#
# Note: as of alembic 0008 these still drive ``raw_severity`` when the
# assessor inputs are NULL — list sorting on column ``raw_severity`` would
# otherwise break for un-graded POAMs. The risk card UI distinguishes
# "computed from defaults" from "computed from assessor inputs" via the
# ``*_source`` provenance badges, not by changing the numeric default.
DEFAULT_LIKELIHOOD = RiskLevel.MODERATE
DEFAULT_IMPACT = RiskLevel.MODERATE


# ─────────────────────────────────────────────────────────────────────────────
# Risk provenance helpers (alembic 0008)
#
# These are the *only* sanctioned way to write to PoamRiskHistory. Every
# code path that mutates a POAM risk field (routes/poams.py PATCH,
# generator seed, residual advisor apply endpoint) MUST funnel through
# ``record_risk_change`` so the audit trail stays complete.
# ─────────────────────────────────────────────────────────────────────────────

# Canonical list of fields the audit trail tracks. Mirrors the columns on
# ``Poam`` that hold ``RiskLevel`` values. ``raw_severity`` is included
# because it's recomputed on every likelihood/impact write and assessors
# benefit from seeing the derived value transition independently — they
# may have set MODERATE × HIGH thinking they'd get MODERATE and want to
# confirm the matrix gave them HIGH.
RISK_HISTORY_FIELDS: tuple[str, ...] = (
    "likelihood",
    "impact",
    "raw_severity",
    "residual_risk",
)


# STIG CAT severity strings map directly to impact buckets. Mirrors the
# ``_derive_remediation_severity`` output in ``poam/generator.py`` so a
# CAT I finding (= "high") seeds HIGH impact, CAT II (= "medium") seeds
# MODERATE, CAT III (= "low") seeds LOW. No fallback for unknown strings —
# the caller checks for ``None`` and leaves impact unset rather than
# guessing, per ``feedback_precision_over_recall``.
_SEVERITY_TO_IMPACT: dict[str, RiskLevel] = {
    "high": RiskLevel.HIGH,
    "medium": RiskLevel.MODERATE,
    "low": RiskLevel.LOW,
}


def seed_impact_from_stig(severity_key: str | None) -> RiskLevel | None:
    """Translate a STIG-CAT severity string into the seeded ``impact`` level.

    Returns ``None`` when the severity is unknown or NULL — the caller
    leaves ``impact_source``/``impact_rationale`` NULL too so the UI
    knows not to show an Auto badge.
    """
    if severity_key is None:
        return None
    return _SEVERITY_TO_IMPACT.get(severity_key.lower())


def _level_to_str(value: RiskLevel | None) -> str | None:
    """Coerce a RiskLevel enum to its persistence string. NULL passes through.

    Used by ``record_risk_change`` so callers can pass either form without
    the audit trail rows coming out as ``"RiskLevel.HIGH"``.
    """
    if value is None:
        return None
    if isinstance(value, RiskLevel):
        return value.value
    return str(value)


def record_risk_change(
    session: Session,
    *,
    poam_id: int,
    field: str,
    prev_value: RiskLevel | str | None,
    new_value: RiskLevel | str | None,
    actor: str | None,
    prev_rationale: str | None = None,
    new_rationale: str | None = None,
    prev_source: str | None = None,
    new_source: str | None = None,
) -> PoamRiskHistory | None:
    """Append a row to ``poamriskhistory`` capturing a single field transition.

    Returns the inserted row (already added to the session, not yet
    committed — the caller controls the transaction boundary) or ``None``
    if nothing actually changed and a noisy "X → X" row would be
    misleading. Equality compares both value AND rationale AND source so
    a rationale-only edit (assessor sharpens the wording but keeps
    MODERATE) still records.

    ``field`` MUST be in :data:`RISK_HISTORY_FIELDS`; the assertion
    catches typos that would otherwise silently land bogus rows the UI
    can't render. Mirrors how ``OdpAuditLog`` rejects unknown ``odp_id``
    values at the route layer.
    """
    if field not in RISK_HISTORY_FIELDS:
        raise ValueError(
            f"PoamRiskHistory.field must be one of {RISK_HISTORY_FIELDS}, got {field!r}"
        )

    prev_str = _level_to_str(prev_value)
    new_str = _level_to_str(new_value)

    if (
        prev_str == new_str
        and (prev_rationale or None) == (new_rationale or None)
        and (prev_source or None) == (new_source or None)
    ):
        return None

    row = PoamRiskHistory(
        poam_id=poam_id,
        field=field,
        prev_value=prev_str,
        new_value=new_str,
        prev_rationale=prev_rationale,
        new_rationale=new_rationale,
        prev_source=prev_source,
        new_source=new_source,
        actor=actor,
    )
    session.add(row)
    return row
