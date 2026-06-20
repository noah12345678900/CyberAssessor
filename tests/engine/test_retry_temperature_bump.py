"""Regression: the assess retry loop runs every attempt at the default
temperature (no per-retry bump) so structured JSON output stays reliable.

HISTORY. A 2026-06-19 change bumped retries to temperature 0.4 to escape a stuck
"ambiguous" narrative loop (AC-7a). But the LLM client enforces NO JSON output
mode, so the higher temperature let the model wander off the JSON envelope on
retries → "[parse_error] no JSON object" (AC-17). Reverted 2026-06-20: all
attempts run at the client default (0.0). The retry mechanism itself is
unchanged — it still re-calls the LLM with corrective context — it just no
longer perturbs the temperature.

These tests pin the reverted contract:
  * NO attempt (first or retry) receives a temperature override — the assessor
    never passes ``temperature=`` to the client, so the client uses its own
    DEFAULT_TEMPERATURE (0.0) on every call.
  * The corrective-context retry still recovers an ambiguous-then-clean row to a
    Compliant proposal (the retry loop works; only the temp bump was removed).

Collected via testpaths.
"""

from __future__ import annotations

from cybersecurity_assessor.engine.assessor import Assessor, LlmProposal
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

# An AMBIGUOUS narrative the validator rejects (status_narrative_mismatch).
_AMBIGUOUS_NARRATIVE = (
    "The control might be partially addressed; some settings appear present but "
    "it is unclear whether they fully apply, and further review may or may not "
    "be warranted depending on interpretation."
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


class _TempRecordingLlm:
    """Fake LLM that records the temperature kwarg of every call and returns an
    ambiguous proposal on attempt 0, a clean compliant proposal on retry.

    ``temperature`` defaults to None so the assertion can confirm the assessor
    passes NO override (the reverted contract). If the assessor ever re-adds a
    bump, ``temperatures`` would contain a non-None value and the test fails.
    """

    _audit_citations = False

    def __init__(self) -> None:
        self.calls = 0
        self.temperatures: list[float | None] = []

    def _proposal(self) -> LlmProposal:
        if self.calls == 1:
            return LlmProposal(
                status=ComplianceStatus.COMPLIANT,
                narrative=_AMBIGUOUS_NARRATIVE,
                confidence=0.9,
            )
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


def test_no_attempt_passes_a_temperature_override():
    """Reverted contract: neither the first attempt nor any retry passes a
    temperature override — the client always uses its DEFAULT_TEMPERATURE.

    The corrective-context retry still recovers the ambiguous-then-clean row to
    a Compliant proposal, proving the retry LOOP works without the temp bump.
    """
    fake = _TempRecordingLlm()
    d = Assessor(llm=fake).assess(
        _row(),
        tagged_evidence=_EVIDENCE.text,
        evidence_block=_EVIDENCE,
    )

    assert fake.calls >= 2, "expected a retry after the ambiguous first attempt"
    # The headline assertion: NO call received a temperature override (no bump).
    assert all(t is None for t in fake.temperatures), (
        f"no attempt may pass a temperature override; got {fake.temperatures}"
    )
    # The retry still recovered to a trusted Compliant verdict.
    assert d.status is ComplianceStatus.COMPLIANT
    assert d.needs_review is False


def test_clean_first_attempt_single_call_no_override():
    """A row that passes on attempt 0 makes exactly one call, no temp override."""

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
    assert fake.temperatures == [None]
    assert d.status is ComplianceStatus.COMPLIANT
