"""Regression test for the abstain silent-drop fix.

History: in an earlier kernel revision, the bulk-assess persistence
gate read ``if decision.status is not None and decision.narrative`` and
silently dropped any ``Decision(accepted=True, status=None,
narrative=None)`` row — the hard-abstain shape emitted by the
no-llm-client / dual-pass-disagreement / cite-hallucination paths in
``engine/assessor.py``. CCI-002124 and CCI-002127 surfaced the bug:
both objectives carried four ``EvidenceTag`` rows each, were in the
workbook + baseline, and had zero ``Assessment`` rows (see
``feedback_abstain_status_none_drops.md``).

The fix routes both write sites in ``routes/controls.py`` through
``_coerce_abstain_persistence_fields``, which resolves the NOT NULL
schema columns from the abstain Decision so the row always lands with
``needs_review=True`` and the reviewer queue surfaces it. This module
pins the helper's contract so a future refactor can't silently un-fix
the bug.

Three cases:
  1. Hard abstain with a ``review_reason`` → status coerced to
     NON_COMPLIANT, narrative falls through to the review reason.
  2. Hard abstain with NO ``review_reason`` → narrative falls through
     all the way to the placeholder constant.
  3. Soft abstain (kernel emitted a status + narrative but flagged
     ``needs_review=True``) → both fields pass through untouched.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor.engine.assessor import Decision  # noqa: E402
from cybersecurity_assessor.models import ComplianceStatus, NarrativeClass  # noqa: E402
from cybersecurity_assessor.routes.controls import (  # noqa: E402
    _ABSTAIN_NARRATIVE_PLACEHOLDER,
    _coerce_abstain_persistence_fields,
)


def _hard_abstain(*, review_reason: str | None) -> Decision:
    """The shape ``Assessor._abstain`` emits on the hard-abstain paths
    (no-llm-client, dual-pass-mismatch with both passes None, etc.).

    status and narrative are both None; review_reason carries the triage
    string the kernel produced — sometimes populated, sometimes not.
    """
    return Decision(
        cci_id="CCI-002124",
        excel_row=42,
        accepted=True,
        status=None,
        narrative=None,
        narrative_class=NarrativeClass.AMBIGUOUS,
        source="abstain",
        rule=None,
        needs_review=True,
        review_reason=review_reason,
    )


def test_hard_abstain_with_review_reason_coerces_to_nc_and_uses_reason() -> None:
    decision = _hard_abstain(review_reason="dual-pass-disagreement: pass1=None, pass2=None")
    status, narrative = _coerce_abstain_persistence_fields(decision)
    assert status is ComplianceStatus.NON_COMPLIANT
    assert narrative == "dual-pass-disagreement: pass1=None, pass2=None"


def test_hard_abstain_without_review_reason_falls_through_to_placeholder() -> None:
    decision = _hard_abstain(review_reason=None)
    status, narrative = _coerce_abstain_persistence_fields(decision)
    assert status is ComplianceStatus.NON_COMPLIANT
    assert narrative == _ABSTAIN_NARRATIVE_PLACEHOLDER


def test_soft_abstain_passes_through_untouched() -> None:
    """The kernel got a usable proposal but flagged needs_review (e.g.
    low-confidence, unverified-cites). Both fields are populated; the
    coercion helper must not overwrite them."""
    decision = Decision(
        cci_id="CCI-000366",
        excel_row=99,
        accepted=True,
        status=ComplianceStatus.NON_COMPLIANT,
        narrative="LLM verdict with citation it could not verify.",
        narrative_class=NarrativeClass.GAP_DESCRIBING,
        source="llm_after_retry",
        rule=None,
        needs_review=True,
        review_reason="unverified-cites: 1 ref not found in extracted text",
        confidence=0.55,
    )
    status, narrative = _coerce_abstain_persistence_fields(decision)
    assert status is ComplianceStatus.NON_COMPLIANT
    assert narrative == "LLM verdict with citation it could not verify."
