"""Tests for ``Assessor._finalize_crm_decision`` short-circuit emission.

What we pin (plan B7/B10 — "3 short-circuits → 3 events linked to one log"):

1. **Every provider/inherited/not_applicable CRM row emits exactly one
   ``CrmShortCircuit`` dataclass.** The dataclass carries the fields the
   route handler needs to persist a ``CrmShortCircuitEvent`` row
   (``cci``, ``control_id``, ``responsibility``, ``baseline_id``) and a
   timestamp for chronology in the suspicion log.

2. **Dual access path — ``Decision.crm_short_circuit`` is the SAME
   object as ``CciOutcome.crm_short_circuit``.** The Decision is what
   the export layer reads; the outcome is what the RunRecorder persists.
   They must agree so the suspicion banner's "events" count matches the
   exports without a separate reconciliation pass.

3. **The customer/hybrid paths do NOT emit a short-circuit.** Those go
   through the LLM (or the LLM-with-hybrid-block enrichment) and are
   not part of the "LLM bypassed" accounting that drives the suspicion
   banner's trust calculus.

4. **``baseline_id`` propagates from the CRM entry untouched.** The
   route handler groups events by overlay; if baseline_id were lost or
   defaulted, multi-CRM workbooks would mis-attribute events to the
   wrong overlay row.

5. **Three short-circuits in one run → three outcomes carry
   short_circuit, one outcome (the LLM row) does not.** This is the
   load-bearing "events linked to one log" assertion from plan B10 —
   the route handler iterates ``recorder.outcomes``, filters on
   ``crm_short_circuit is not None``, and writes one row per filtered
   outcome under a single ``CrmSuspicionLog`` parent.

This file complements ``test_assessor_outcome_branches.py`` (which pins
a single CRM provider short-circuit through the recorder) by extending
to all three responsibility values plus a customer LLM row in the same
run — the route-handler scenario.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- register tables
from cybersecurity_assessor.engine.assessor import (  # noqa: E402
    Assessor,
    LlmProposal,
)
from cybersecurity_assessor.engine.crm_context import (  # noqa: E402
    CrmContext,
    CrmEntry,
)
from cybersecurity_assessor.engine.measurement import (  # noqa: E402
    CrmShortCircuit,
    RunRecorder,
)
from cybersecurity_assessor.models import ComplianceStatus, Workbook  # noqa: E402

# Reuse the canonical stub + row helpers from the e2e suite — they're the
# in-repo contract for orchestrator-level tests.
from tests.engine.test_assessor_e2e import _PLACEHOLDER_EVIDENCE, StubLlmClient, _row  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    """In-memory SQLite with StaticPool — same pattern as test_assessor_e2e."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def workbook(session: Session) -> Workbook:
    wb = Workbook(path="/tmp/test_short_circuits.xlsx", filename="test.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb


def _crm(control_id: str, responsibility: str, baseline_id: int = 1) -> CrmContext:
    """Single-entry CrmContext for one control row."""
    key = control_id.lower()
    return CrmContext(
        by_control={
            key: CrmEntry(
                control_id=key,
                responsibility=responsibility,  # type: ignore[arg-type]
                narrative=None,
                source_baseline_id=baseline_id,
            )
        }
    )


# ---------------------------------------------------------------------------
# Each responsibility type emits a CrmShortCircuit (parametrized)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("responsibility", "expected_status", "expected_source"),
    [
        ("provider", ComplianceStatus.NOT_APPLICABLE, "crm_provider"),
        ("inherited", ComplianceStatus.COMPLIANT, "crm_inherited"),
        ("not_applicable", ComplianceStatus.NOT_APPLICABLE, "crm_not_applicable"),
    ],
)
def test_each_short_circuit_responsibility_emits_event_with_expected_fields(
    session, workbook, responsibility, expected_status, expected_source
):
    """provider/inherited/not_applicable each produce one CrmShortCircuit
    whose fields match the source CrmEntry. Status/source on the Decision
    are pinned in test_assessor_e2e — we re-pin here only as a sanity
    check that the short_circuit is bound to the SAME path.
    """
    recorder = RunRecorder.start(session, workbook_id=workbook.id)
    row = _row(control_id="AC-2")
    crm = _crm("AC-2", responsibility, baseline_id=7)
    stub = StubLlmClient([])  # empty queue → any LLM call would AssertionError
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row, crm_context=crm, recorder=recorder)

    # LLM was bypassed.
    assert stub.calls == []
    # Decision matches the short-circuit path.
    assert decision.source == expected_source
    assert decision.status is expected_status
    # CrmShortCircuit is attached to the Decision.
    sc = decision.crm_short_circuit
    assert sc is not None
    assert isinstance(sc, CrmShortCircuit)
    assert sc.cci == "CCI-000001"
    assert sc.control_id == "ac-2"
    assert sc.responsibility == responsibility
    assert sc.baseline_id == 7


# ---------------------------------------------------------------------------
# Dual access path — Decision.crm_short_circuit is the recorder's outcome
# ---------------------------------------------------------------------------


def test_decision_and_outcome_carry_identical_short_circuit_object(session, workbook):
    """``Decision.crm_short_circuit is CciOutcome.crm_short_circuit``.

    Identity (not just equality) — the route handler reads the outcome
    list and the export layer reads the Decision; both must see the
    same record so the suspicion banner's "events" count cannot drift
    from what the CSV export shows.
    """
    recorder = RunRecorder.start(session, workbook_id=workbook.id)
    row = _row(control_id="AC-2")
    crm = _crm("AC-2", "inherited", baseline_id=3)
    assessor = Assessor(llm=StubLlmClient([]))

    decision = assessor.assess(row, crm_context=crm, recorder=recorder)

    outcomes = recorder.outcomes
    assert len(outcomes) == 1
    outcome_sc = outcomes[0].crm_short_circuit
    assert outcome_sc is not None
    assert decision.crm_short_circuit is outcome_sc


# ---------------------------------------------------------------------------
# Customer + hybrid rows must NOT emit a short-circuit
# ---------------------------------------------------------------------------


def test_customer_responsibility_does_not_emit_short_circuit(session, workbook):
    """Customer-owned rows go through the LLM. No short-circuit emitted —
    these rows are NOT in the "LLM bypassed" accounting.
    """
    recorder = RunRecorder.start(session, workbook_id=workbook.id)
    row = _row(control_id="AC-2", procedures="Examine local AD policy.")
    crm = _crm("AC-2", "customer")
    # Queue a clean compliant proposal so the LLM path completes.
    proposal = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "AcctMgmt-001 documents local account lifecycle. Operator review "
            "is performed monthly; observed in the 2026 audit log sample."
        ),
        confidence=0.9,
    )
    stub = StubLlmClient([proposal])
    assessor = Assessor(llm=stub)

    decision = assessor.assess(
        row, crm_context=crm, recorder=recorder, tagged_evidence=_PLACEHOLDER_EVIDENCE
    )

    # LLM was consulted (customer path).
    assert len(stub.calls) >= 1
    # No short-circuit attached.
    assert decision.crm_short_circuit is None
    assert recorder.outcomes[0].crm_short_circuit is None


def test_hybrid_responsibility_does_not_emit_short_circuit(session, workbook):
    """Hybrid rows go through the LLM with the responsibility-split block
    prepended. The plan reserves the short-circuit accounting for the
    fully-off-loaded responsibilities (provider/inherited/NA) — hybrid
    still requires a customer-side assessment, so the LLM is consulted
    and no short-circuit fires.
    """
    recorder = RunRecorder.start(session, workbook_id=workbook.id)
    row = _row(control_id="AC-2", procedures="Examine local enforcement.")
    crm = CrmContext(
        by_control={
            "ac-2": CrmEntry(
                control_id="ac-2",
                responsibility="hybrid",
                narrative="Provider handles federation; customer handles local groups.",
                source_baseline_id=2,
            )
        }
    )
    proposal = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Local group membership reviewed monthly per AcctMgmt-001; "
            "observations recorded in the 2026 audit sample."
        ),
        confidence=0.85,
    )
    # Queue several copies — the hybrid path may invoke the validator's
    # corrective-retry loop. The exact iteration count is a validator
    # internal we don't want to pin here; what we ARE pinning is that the
    # LLM is consulted (>= 1 call) and no short-circuit is emitted.
    stub = StubLlmClient([proposal] * 5)
    assessor = Assessor(llm=stub)

    decision = assessor.assess(row, crm_context=crm, recorder=recorder)

    assert len(stub.calls) >= 1, "hybrid must consult the LLM"
    assert decision.crm_short_circuit is None
    assert recorder.outcomes[0].crm_short_circuit is None


# ---------------------------------------------------------------------------
# Multi-row run — three short-circuits + one LLM row (the route handler scenario)
# ---------------------------------------------------------------------------


def test_three_short_circuits_in_one_run_are_all_recorded(session, workbook):
    """Plan B10 contract: "3 short-circuits → 3 events linked to one log".

    Run four CCIs through the assessor under one RunRecorder:
      - AC-2  provider        → short-circuit
      - AC-3  inherited       → short-circuit
      - AC-4  not_applicable  → short-circuit
      - AC-5  customer (LLM)  → no short-circuit

    After the batch, ``recorder.outcomes`` must yield 4 outcomes, of
    which exactly 3 carry ``crm_short_circuit`` populated. Each
    short-circuit must reference the correct cci/control_id/responsibility
    and the correct ``baseline_id`` (10, 11, 12 — distinct, so a
    cross-wired field would surface).
    """
    from cybersecurity_assessor.models import ComplianceStatus

    recorder = RunRecorder.start(session, workbook_id=workbook.id)

    spec = [
        ("AC-2", "CCI-000001", "provider", 10),
        ("AC-3", "CCI-000002", "inherited", 11),
        ("AC-4", "CCI-000003", "not_applicable", 12),
        ("AC-5", "CCI-000004", None, None),  # customer — LLM path, no short-circuit
    ]

    # One LLM proposal needed (only the customer row consults the LLM).
    customer_proposal = LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Local AD policy enforces 14-character passwords on OU=Workstations "
            "per AcctSec-PWLen-14; observed in the 2026 GPO export."
        ),
        confidence=0.9,
    )
    stub = StubLlmClient([customer_proposal])
    assessor = Assessor(llm=stub)

    decisions = []
    for control_id, cci_id, responsibility, baseline_id in spec:
        row = _row(
            control_id=control_id,
            cci_id=cci_id,
            procedures="Examine local enforcement.",
        )
        if responsibility is None:
            ctx = None
        else:
            ctx = CrmContext(
                by_control={
                    control_id.lower(): CrmEntry(
                        control_id=control_id.lower(),
                        responsibility=responsibility,  # type: ignore[arg-type]
                        narrative=None,
                        source_baseline_id=baseline_id,  # type: ignore[arg-type]
                    )
                }
            )
        decisions.append(
            assessor.assess(
                row,
                crm_context=ctx,
                recorder=recorder,
                tagged_evidence=_PLACEHOLDER_EVIDENCE,
            )
        )

    # The LLM was called exactly once (the customer row).
    assert len(stub.calls) == 1

    outcomes = recorder.outcomes
    assert len(outcomes) == 4

    # Filter to short-circuit outcomes (the route-handler operation).
    sc_outcomes = [o for o in outcomes if o.crm_short_circuit is not None]
    assert len(sc_outcomes) == 3, (
        "exactly 3 outcomes must carry a CrmShortCircuit — one per "
        "off-loaded responsibility"
    )

    # Map cci → short-circuit for index-free assertions.
    sc_by_cci = {o.crm_short_circuit.cci: o.crm_short_circuit for o in sc_outcomes}
    assert set(sc_by_cci.keys()) == {"CCI-000001", "CCI-000002", "CCI-000003"}

    assert sc_by_cci["CCI-000001"].responsibility == "provider"
    assert sc_by_cci["CCI-000001"].control_id == "ac-2"
    assert sc_by_cci["CCI-000001"].baseline_id == 10

    assert sc_by_cci["CCI-000002"].responsibility == "inherited"
    assert sc_by_cci["CCI-000002"].control_id == "ac-3"
    assert sc_by_cci["CCI-000002"].baseline_id == 11

    assert sc_by_cci["CCI-000003"].responsibility == "not_applicable"
    assert sc_by_cci["CCI-000003"].control_id == "ac-4"
    assert sc_by_cci["CCI-000003"].baseline_id == 12

    # The customer outcome (CCI-000004) has no short-circuit.
    customer_outcome = next(o for o in outcomes if o.cci == "CCI-000004")
    assert customer_outcome.crm_short_circuit is None


# ---------------------------------------------------------------------------
# Short-circuit fires even when no recorder is attached
# ---------------------------------------------------------------------------


def test_short_circuit_emitted_on_decision_even_when_recorder_is_none(session, workbook):
    """The Decision must carry crm_short_circuit even if the caller
    didn't pass a recorder — the export layer reads the Decision
    directly and would otherwise lose the event for ad-hoc runs (e.g.
    re-run-one-cci from the UI without re-running the whole workbook).
    """
    row = _row(control_id="AC-2")
    crm = _crm("AC-2", "provider", baseline_id=5)
    assessor = Assessor(llm=StubLlmClient([]))

    decision = assessor.assess(row, crm_context=crm)  # no recorder

    assert decision.crm_short_circuit is not None
    assert decision.crm_short_circuit.responsibility == "provider"
    assert decision.crm_short_circuit.baseline_id == 5
