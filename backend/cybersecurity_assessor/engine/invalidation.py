"""Assessment freshness invalidation.

When the set of :class:`EvidenceTag` rows attached to an
:class:`Objective` changes (a new artifact is auto-tagged, an artifact
is deleted, or the whole evidence index is wiped), any
:class:`Assessment` row that was produced against the *prior* evidence
picture is stale: the kernel made its verdict from a different bundle
than the next run would see.

The most common failure mode this protects against is the
``rule_no_evidence`` short-circuit (engine/assessor.py): if the
assessment ran when zero artifacts were tagged for a CCI and an
artifact landed seconds later (real workbook ingest can interleave by
~100s), the verdict is permanently ``Non-Compliant`` until something
flips it. The decision-cache fingerprint does not include "set of
tagged evidence IDs", so a re-run replays the stale verdict from cache.

The fix is to flag those rows ``needs_review=True`` with a
free-form ``review_reason`` token so the reviewer UI surfaces them in
the triage queue. We do NOT erase the verdict — the prior assessor's
text/status stays visible for context — only set the gate that keeps
exporters (ccis_writer, POAM, SAR, bundle, workbook_control_status) from
shipping it. The reviewer either re-runs the CCI through the engine or
clears the flag manually.

Two invariants:

1. We only flip rows where ``needs_review`` is currently ``False``. If
   the reviewer has already triaged a row to a different reason
   (``low-confidence``, ``unverified-cites``, etc.), we don't clobber
   it — their reason carries more signal than ours.

2. The caller owns the transaction. Callers (tagger, evidence routes)
   commit after their own work; we just stage the UPDATE.
"""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy import or_, update
from sqlmodel import Session

from ..models import Assessment, VerdictSource

# Free-form review_reason token. Kept short and grep-friendly so the
# review-queue UI can chip-render it; matches the convention used by
# other tokens (``rule-8c-unverified``, ``low-confidence``, etc.).
EVIDENCE_CHANGED_REASON = "evidence-changed-since-assessment"

# Verdict sources whose basis is EVIDENCE-INDEPENDENT — a CRM overlay
# inheritance/provider/NA short-circuit or a workbook-intrinsic rule #8
# verdict. Uploading or deleting a local artifact does NOT change the basis
# for these (an inherited control is inherited regardless of local evidence;
# a col-N Not Applicable is scoped out regardless). Flagging them
# "evidence-changed" was the bug that flipped every CRM-inherited control to
# needs-review the moment any evidence was uploaded. They are EXEMPT from
# invalidation. Only evidence-derived verdicts (``llm*``, ``rule_no_evidence``,
# ``cache_hit``, ``abstain``, ``imported``, or a NULL legacy source) get
# flagged when their objective's evidence picture changes.
_EVIDENCE_INDEPENDENT_SOURCES = (
    VerdictSource.CRM_PROVIDER,
    VerdictSource.CRM_INHERITED,
    VerdictSource.CRM_NOT_APPLICABLE,
    VerdictSource.CRM_HYBRID_MIXED,
    VerdictSource.RULE_8A,
    VerdictSource.RULE_8B,
    VerdictSource.RULE_8C,
)


def invalidate_assessments_for_objectives(
    session: Session,
    objective_ids: Iterable[int],
    *,
    reason: str = EVIDENCE_CHANGED_REASON,
) -> int:
    """Flag stale Assessment rows for objectives whose evidence picture changed.

    Stages an UPDATE on every :class:`Assessment` row whose
    ``objective_id`` is in the supplied set AND whose ``needs_review`` is
    currently False. The caller commits.

    Returns the number of rows touched. ``0`` is a normal outcome
    (objective had no prior assessment, or every existing assessment was
    already in the review queue) — callers can ignore the return unless
    they want to log it.
    """
    ids = sorted({int(oid) for oid in objective_ids if oid is not None})
    if not ids:
        return 0

    stmt = (
        update(Assessment)
        .where(
            Assessment.objective_id.in_(ids),  # type: ignore[attr-defined]
            Assessment.needs_review == False,  # noqa: E712 — SQLAlchemy needs ==False, not `is False` or `not`
            # Exempt evidence-independent verdicts (CRM inheritance / rule #8).
            # NULL verdict_source (legacy rows) is treated as evidence-derived
            # and DOES get flagged — safe default, matches pre-column behavior.
            or_(
                Assessment.verdict_source.is_(None),  # type: ignore[attr-defined]
                Assessment.verdict_source.notin_(  # type: ignore[attr-defined]
                    _EVIDENCE_INDEPENDENT_SOURCES
                ),
            ),
        )
        .values(needs_review=True, review_reason=reason)
    )
    result = session.exec(stmt)  # type: ignore[arg-type]
    return getattr(result, "rowcount", 0) or 0
