"""Tests for the patent-kernel orchestrator.

Stubs out the LLM client so the orchestrator's contract — rule #8 bypass,
supersession-before-validation, bounded retry, run-recorder instrumentation —
is exercised without burning tokens.

Scope note (2026-06-05): The bulk of the legacy orchestrator suite that
once lived here was duplicated by ``backend/tests/engine/test_assessor_e2e.py``
and ``backend/tests/engine/test_assessor_outcome_branches.py`` after the
v0.2 dual-pass + no-evidence short-circuit landed. The duplicates broke
in this root-level file (no ``tagged_evidence`` plumbed → v0.2 short-
circuit fires before the LLM is reached) while the backend equivalents
pass — they pre-bake ``_PLACEHOLDER_EVIDENCE``. Rather than re-fit eight
near-identical tests, the failing duplicates were dropped here. The
remaining tests pin the rule-#8 bypass surface and the
multi-rule-shape smoke contract, both of which are NOT duplicated by
the backend suite.

The unique negative-``max_retries`` clamp test (assessor.py:297) was
ported to ``backend/tests/engine/test_assessor_e2e.py`` as
``test_max_retries_clamps_negative_to_zero``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from cybersecurity_assessor.engine import assessor as assessor_mod
from cybersecurity_assessor.engine.assessor import Assessor, Decision, LlmProposal
from cybersecurity_assessor.excel.ccis_reader import CcisRow
from cybersecurity_assessor.models import ComplianceStatus


# ---------------------------------------------------------------------------
# Module-wide: disable dual-pass for the legacy-effectiveness tests
# ---------------------------------------------------------------------------
#
# These tests exercise rule #8 bypass paths and a multi-shape smoke
# contract. They were written before the v0.2 dual-pass precision-over-
# recall gate was added to the kernel. Dual-pass doubles per-attempt
# proposal consumption + token totals, which is independently covered by
# tests/engine/. We pin it off here so the legacy assertions stay 1:1
# with what they're measuring.


@pytest.fixture(autouse=True)
def _disable_dual_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(assessor_mod, "DUAL_PASS_ENABLED", False)


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


@dataclass
class StubLlm:
    """Scripted LLM client. Returns proposals in order; records every call.

    Implements both ``propose`` (single-pass) and ``propose_twice`` (dual-pass)
    so the kernel's LlmClient protocol is fully satisfied. The dual-pass
    method delegates to two ``propose`` calls — the autouse fixture above
    pins DUAL_PASS_ENABLED off in this file so the single-pass path is the
    one exercised, but having ``propose_twice`` present keeps the stub
    valid against any test that flips dual-pass back on.
    """

    proposals: list[LlmProposal]
    calls: list[dict] = field(default_factory=list)

    def propose(
        self,
        *,
        row: CcisRow,
        corrective_context: str | None = None,
        prior_attempts: list[LlmProposal] | None = None,
        tagged_evidence: str | None = None,
        **_kwargs,  # absorb temperature/crm_responsibility/boundary_brief/etc.
    ) -> LlmProposal:
        self.calls.append(
            {
                "cci_id": row.cci_id,
                "corrective_context": corrective_context,
                "prior_attempts_n": len(prior_attempts or []),
            }
        )
        if not self.proposals:
            raise AssertionError("StubLlm exhausted — orchestrator called more times than expected")
        return self.proposals.pop(0)

    def propose_twice(
        self,
        *,
        row: CcisRow,
        corrective_context: str | None = None,
        prior_attempts: list[LlmProposal] | None = None,
        tagged_evidence: str | None = None,
        **_kwargs,
    ) -> tuple[LlmProposal, LlmProposal]:
        a = self.propose(
            row=row,
            corrective_context=corrective_context,
            prior_attempts=prior_attempts,
            tagged_evidence=tagged_evidence,
        )
        b = self.propose(
            row=row,
            corrective_context=corrective_context,
            prior_attempts=prior_attempts,
            tagged_evidence=tagged_evidence,
        )
        return a, b


# ---------------------------------------------------------------------------
# Rule #8 bypass paths
# ---------------------------------------------------------------------------


def test_rule_8a_bypasses_llm_entirely(make_row):
    row = make_row(
        procedures="Automatically compliant per assessment procedures.",
    )
    llm = StubLlm(proposals=[])  # would explode if called
    assessor = Assessor(llm=llm)

    decision = assessor.assess(row)

    assert decision.accepted is True
    assert decision.source == "rule_8a"
    assert decision.status == ComplianceStatus.COMPLIANT
    assert decision.retries == 0
    assert llm.calls == []  # never called


def test_rule_8b_bypasses_llm_entirely(make_row):
    # v0.11.0: NA (8b) fires only from an explicit scope-exclusion phrase in
    # the human-authored rationale (col Q/U), never from CSP attribution in
    # the DISA template text. A documented "not applicable per SDA control"
    # in results is the canonical 8b shape.
    row = make_row(results="Not applicable per SDA control.")
    llm = StubLlm(proposals=[])
    assessor = Assessor(llm=llm)

    decision = assessor.assess(row)

    assert decision.accepted is True
    assert decision.source == "rule_8b"
    assert decision.status == ComplianceStatus.NOT_APPLICABLE
    assert llm.calls == []


def test_no_llm_configured_still_processes_rule_8(make_row):
    # Rule #8 must still fire even without an LLM client — that's the
    # whole point of the deterministic pre-filter.
    row = make_row(procedures="Automatically compliant per assessment procedures.")
    assessor = Assessor(llm=None)

    decision = assessor.assess(row)

    assert decision.accepted is True
    assert decision.source == "rule_8a"


# ---------------------------------------------------------------------------
# Multi-shape smoke
# ---------------------------------------------------------------------------


def test_decision_is_returned_for_every_row_shape(make_row):
    """Smoke test: assessor never raises on any of the four rule outcomes."""
    rows = [
        make_row(procedures="Automatically compliant per inheritance."),  # 8a
        make_row(results="Not applicable per SDA control."),  # 8b (col Q)
        make_row(procedures="Inherited from upstream.", inherited="Local"),  # 8c
        make_row(procedures="Examine docs.", inherited="Local"),  # no auto
    ]
    proposal = LlmProposal(
        status=ComplianceStatus.NON_COMPLIANT,
        narrative="No artifact found; POA&M opened.",
    )
    # Two non-8a/8b rows × up to 3 attempts each = 6 proposals to be safe.
    llm = StubLlm(proposals=[proposal] * 6)
    assessor = Assessor(llm=llm)

    decisions = [assessor.assess(r) for r in rows]

    assert all(isinstance(d, Decision) for d in decisions)
    assert decisions[0].source == "rule_8a"
    assert decisions[1].source == "rule_8b"
    # 8c and no-auto both go through LLM; with a gap narrative + Non-Compliant
    # status they're a valid match and should accept on the first try.
    assert decisions[2].accepted is True
    assert decisions[3].accepted is True
