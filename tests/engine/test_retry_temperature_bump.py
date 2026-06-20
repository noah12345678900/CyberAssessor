"""Regression: the assess retry loop bumps temperature on retries so a stuck
ambiguous narrative can be rewritten instead of regenerating identically.

THE GAP (user-found, AC-7a). The retry loop re-calls the LLM up to 3x AND feeds
the ambiguous-rejection back as corrective context — but every attempt ran at
temperature 0.0, so a deterministically-ambiguous narrative regenerated
identically on every retry and exhausted to a `validator-exhausted` needs-review.

The fix: attempt 0 runs at the client default (0.0 — happy path + cache
unchanged); every retry (attempt >= 1, only reached after a validator rejection)
passes `RETRY_TEMPERATURE` (0.4). These tests pin:
  * attempt 0 gets NO temperature override (the kwarg is not passed);
  * retries get temperature == RETRY_TEMPERATURE;
  * a row that's ambiguous on attempt 0 but compliant on retry RECOVERS to a
    Compliant verdict instead of exhausting to needs-review.

Collected via testpaths=["../tests"].
"""

from __future__ import annotations

from cybersecurity_assessor.engine.assessor import (
    RETRY_TEMPERATURE,
    Assessor,
    LlmProposal,
)
from cybersecurity_assessor.engine.evidence_bundle import EvidenceBlock
from cybersecurity_assessor.excel.ccis_reader import CcisRow
from cybersecurity_assessor.models import ComplianceStatus

# Non-empty evidence so the no-evidence short-circuit doesn't fire before the LLM
# (the USD token is literally present so the cite-verifier accepts the narrative).
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

_CLEAN_COMPLIANT_NARRATIVE = (
    "Examined the Example System Account Management Plan (USD00050010) and "
    "confirmed via the documented procedure that account provisioning, review, "
    "and removal are performed as required for this control objective."
)


def _row() -> CcisRow:
    """Single-scope (no-CRM) AC-2 row that flows to the LLM path."""
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

# An AMBIGUOUS narrative the validator rejects with status_narrative_mismatch:
# it pairs neither a clean compliance-affirming nor NA-justifying nor
# gap-describing classification, so classify() lands AMBIGUOUS.
_AMBIGUOUS_NARRATIVE = (
    "The control might be partially addressed; some settings appear present but "
    "it is unclear whether they fully apply, and further review may or may not "
    "be warranted depending on interpretation."
)


class _TempRecordingLlm:
    """Fake LLM that records the temperature of every call and returns an
    ambiguous proposal on attempt 0, a clean compliant proposal thereafter.

    Mirrors the orchestrator's client surface (propose / propose_twice) with the
    new optional ``temperature`` kwarg. The orchestrator passes NO temperature
    on attempt 0 (so it arrives as the default None here) and RETRY_TEMPERATURE
    on retries.
    """

    _audit_citations = False

    def __init__(self) -> None:
        self.calls = 0
        self.temperatures: list[float | None] = []

    def _proposal(self) -> LlmProposal:
        if self.calls == 1:
            # First attempt → ambiguous (validator rejects → retry).
            return LlmProposal(
                status=ComplianceStatus.COMPLIANT,
                narrative=_AMBIGUOUS_NARRATIVE,
                confidence=0.9,
            )
        # Retry → clean compliant narrative that passes the validator.
        return LlmProposal(
            status=ComplianceStatus.COMPLIANT,
            narrative=_CLEAN_COMPLIANT_NARRATIVE,
            confidence=0.9,
        )

    def propose(self, *, temperature: float | None = None, **_kwargs) -> LlmProposal:
        self.calls += 1
        self.temperatures.append(temperature)
        return self._proposal()

    def propose_twice(self, **kwargs):
        p = self.propose(**kwargs)
        return (p, p)


def test_attempt0_no_temp_override_retry_bumps_and_recovers():
    """Attempt 0 → no temp override (None); retry → RETRY_TEMPERATURE; an
    ambiguous-then-clean row recovers to Compliant instead of exhausting."""
    fake = _TempRecordingLlm()
    d = Assessor(llm=fake).assess(
        _row(),
        tagged_evidence=_EVIDENCE.text,
        evidence_block=_EVIDENCE,
    )

    # The loop retried at least once (ambiguous attempt 0 → clean retry).
    assert fake.calls >= 2, "expected a retry after the ambiguous first attempt"
    # Attempt 0 received NO temperature override (happy path unchanged).
    assert fake.temperatures[0] is None
    # Every retry received the bumped temperature.
    for t in fake.temperatures[1:]:
        assert t == RETRY_TEMPERATURE
    # The row recovered to a trusted Compliant verdict (NOT validator-exhausted).
    assert d.status is ComplianceStatus.COMPLIANT
    assert d.needs_review is False


def test_clean_first_attempt_never_bumps_temperature():
    """A row that passes on attempt 0 makes exactly one call with NO temperature
    override — clean rows behave exactly as before this change."""

    class _CleanLlm:
        _audit_citations = False

        def __init__(self) -> None:
            self.temperatures: list[float | None] = []

        def propose(self, *, temperature: float | None = None, **_kwargs):
            self.temperatures.append(temperature)
            return LlmProposal(
                status=ComplianceStatus.COMPLIANT,
                narrative=_CLEAN_COMPLIANT_NARRATIVE,
                confidence=0.9,
            )

        def propose_twice(self, **kwargs):
            p = self.propose(**kwargs)
            return (p, p)

    fake = _CleanLlm()
    d = Assessor(llm=fake).assess(
        _row(),
        tagged_evidence=_EVIDENCE.text,
        evidence_block=_EVIDENCE,
    )
    assert fake.temperatures == [None], "clean row must make one call at default temp"
    assert d.status is ComplianceStatus.COMPLIANT
