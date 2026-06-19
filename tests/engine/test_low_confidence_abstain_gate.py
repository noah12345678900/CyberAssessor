"""Test-only proof that the low-confidence implicit-abstain gate fires.

The gate (assessor.py, "Low-confidence implicit-abstain gate", RESTORED
2026-06-19) demotes an OTHERWISE-CLEAN, validator-approved LLM verdict to
``needs_review`` whenever the model's self-reported ``confidence`` is below
``CONFIDENCE_THRESHOLD`` (0.35). It is the precision-over-recall safety net: a
near-coin-flip verdict the model itself is unsure about is held for a human
rather than shipped.

WHY THIS IS A TEST AND NOT A DEMO CONTROL. ``proposal.confidence`` comes only
from the LIVE model's self-report (llm/client.py ``_coerce_confidence``); the
demo workbook is assessed against the real Anthropic API, so no workbook column
can deterministically pin confidence below 0.35 (and the prompt actually steers
an unsure model toward ``abstain:true`` — the *self*-abstain path — instead of a
low confidence score). The only way to exercise THIS branch deterministically is
a fake LLM client that returns a clean, validator-passing proposal with a low
confidence. That is exactly what these tests do.

Contract pinned:
  * confidence < 0.35  → needs_review True, status coerced to None, the LLM's
    proposed status preserved (as the guess), review_reason names the gate.
  * confidence >= 0.35 → the SAME proposal is accepted normally (control: proves
    it's the confidence, not the narrative, that triggers the abstain).
"""

from __future__ import annotations

from cybersecurity_assessor.engine.assessor import (
    CONFIDENCE_THRESHOLD,
    Assessor,
    LlmProposal,
)
from cybersecurity_assessor.engine.evidence_bundle import EvidenceBlock
from cybersecurity_assessor.excel.ccis_reader import CcisRow
from cybersecurity_assessor.models import ComplianceStatus

# Non-empty evidence so the kernel's no-evidence short-circuit (deterministic
# Non-Compliant before the LLM is ever called) does NOT fire — we need to reach
# the LLM accept path where the confidence gate lives. The USD token is present
# literally so the cite-verifier doesn't reject the narrative for an unbacked
# reference.
_EVIDENCE = EvidenceBlock(
    text=(
        "## evidence_bundle\n"
        "- USD00050010 Example System Account Management Plan Rev - — "
        "covers account provisioning and review.\n"
    ),
    has_artifacts=True,
    has_coverage=False,
    has_findings=False,
    has_hosts=False,
    has_nonscan_artifact=True,
)

# A clean, validator-passing COMPLIANT narrative — uses the affirming phrasing
# the narrative validator's template-phrase table expects, and cites the USD
# token present in the evidence bundle so the cite-verifier is satisfied. The
# point is that NOTHING about this proposal is wrong except the low confidence.
_CLEAN_COMPLIANT_NARRATIVE = (
    "Examined the Example System Account Management Plan (USD00050010) and "
    "confirmed via the documented procedure that account provisioning, review, "
    "and removal are performed as required for this control objective."
)


def _row() -> CcisRow:
    """Single-scope (no-CRM) AC-2 row that flows to the LLM path.

    Column L blank → flex slice ASSESS; no CRM context is passed to assess(),
    so there are no cloud slices and the control is single-scope. inherited/
    status left unset so no rule-8 short-circuit pre-empts the LLM.
    """
    return CcisRow(
        excel_row=10,
        required=True,
        control_id="AC-2",
        ap_acronym="AC-2.1",
        cci_id="CCI-000015",
        implementation_status=None,
        designation=None,
        narrative=None,
        definition="Account management.",
        guidance=None,
        procedures=None,
        inherited=None,
        remote_inheritance=None,
        status=None,
        date_tested=None,
        tester=None,
        results=None,
        previous_status=None,
        previous_date=None,
        previous_tester=None,
        previous_results=None,
    )


class _FakeLlm:
    """Minimal LLM client returning one canned proposal at a fixed confidence.

    Mirrors the orchestrator's LlmClient protocol surface used on the accept
    path: ``propose`` and ``propose_twice`` (dual-pass returns the same
    proposal twice → no disagreement, so the disagreement-abstain branch can't
    pre-empt the confidence gate).
    """

    _audit_citations = False

    def __init__(self, confidence: float) -> None:
        self._confidence = confidence
        self.calls = 0

    def _proposal(self) -> LlmProposal:
        return LlmProposal(
            status=ComplianceStatus.COMPLIANT,
            narrative=_CLEAN_COMPLIANT_NARRATIVE,
            confidence=self._confidence,
            abstain=False,
        )

    def propose(self, **_kwargs) -> LlmProposal:
        self.calls += 1
        return self._proposal()

    def propose_twice(self, **_kwargs) -> tuple[LlmProposal, LlmProposal]:
        p = self.propose(**_kwargs)
        return (p, p)


def test_low_confidence_verdict_is_demoted_to_needs_review():
    """confidence 0.30 (< 0.35) → clean COMPLIANT verdict is held for review."""
    low = round(CONFIDENCE_THRESHOLD - 0.05, 2)  # 0.30
    fake = _FakeLlm(confidence=low)
    d = Assessor(llm=fake).assess(
        _row(),
        tagged_evidence=_EVIDENCE.text,
        evidence_block=_EVIDENCE,
    )

    assert fake.calls >= 1, "the LLM accept path must have been reached"
    assert d.needs_review is True, "a sub-threshold verdict must be held for review"
    # Status is coerced to None on the abstain (the verdict isn't trusted yet);
    # the LLM's proposed status is preserved separately as the guess.
    assert d.status is None
    assert d.proposed_status is ComplianceStatus.COMPLIANT
    assert d.confidence == low
    # The review reason names the gate so a triager knows WHY it abstained.
    assert d.review_reason is not None
    assert "low-confidence" in d.review_reason.lower()


def test_at_threshold_confidence_is_accepted_not_abstained():
    """confidence exactly 0.35 is NOT below threshold (strict <) → accepted.

    Control case: the identical proposal at 0.35 ships normally, proving it's
    the confidence value — not the narrative — that drove the abstain above.
    """
    fake = _FakeLlm(confidence=CONFIDENCE_THRESHOLD)  # 0.35, not < 0.35
    d = Assessor(llm=fake).assess(
        _row(),
        tagged_evidence=_EVIDENCE.text,
        evidence_block=_EVIDENCE,
    )
    assert d.needs_review is False
    assert d.status is ComplianceStatus.COMPLIANT


def test_high_confidence_clean_verdict_is_accepted():
    """confidence 0.95 → the same clean COMPLIANT verdict ships, no review."""
    fake = _FakeLlm(confidence=0.95)
    d = Assessor(llm=fake).assess(
        _row(),
        tagged_evidence=_EVIDENCE.text,
        evidence_block=_EVIDENCE,
    )
    assert d.needs_review is False
    assert d.status is ComplianceStatus.COMPLIANT
    assert d.confidence == 0.95
