"""Tests for the calibration telemetry pipeline (kernel-adjacent).

Two halves:

* **Recorder integration** — ``RunRecorder._commit_outcome`` writes a
  ``CalibrationEntry`` row for every LLM-derived Decision, and skips it
  for rule-based short-circuits (no ``stated_confidence`` to grade).
* **Scoring math** — Brier + ECE return the documented contract values
  on synthetic data, and unreviewed entries are excluded from both.

Reuses the in-memory SQLModel session pattern from
``tests/engine/test_decision_cache.py`` so the calibration table starts
clean per test and reviewer signals don't leak across cases.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

import pytest
from sqlmodel import Session, SQLModel, create_engine

from cybersecurity_assessor.engine import assessor as assessor_mod
from cybersecurity_assessor.engine import calibration as calibration_engine
from cybersecurity_assessor.engine.assessor import Assessor, LlmProposal
from cybersecurity_assessor.engine.measurement import RunRecorder
from cybersecurity_assessor.excel.ccis_reader import CcisRow
from cybersecurity_assessor.models import CalibrationEntry, ComplianceStatus


# ---------------------------------------------------------------------------
# Module-wide fixtures (mirrors test_decision_cache.py)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _disable_dual_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """Dual-pass doubles proposal consumption; the calibration contract is
    one entry per LLM-informed Decision, which is easier to assert with
    the dual-pass gate pinned off.
    """
    monkeypatch.setattr(assessor_mod, "DUAL_PASS_ENABLED", False)


@pytest.fixture
def session() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


@dataclass
class StubLlm:
    proposals: list[LlmProposal]
    calls: list[dict] = field(default_factory=list)

    def propose(
        self,
        *,
        row: CcisRow,
        corrective_context: str | None = None,
        prior_attempts: list[LlmProposal] | None = None,
        tagged_evidence: str | None = None,
        crm_responsibility: str | None = None,
        boundary_brief: str | None = None,
        **_kwargs,  # absorb temperature (retry bump) and future kwargs
    ) -> LlmProposal:
        self.calls.append({"cci_id": row.cci_id})
        if not self.proposals:
            raise AssertionError("StubLlm exhausted")
        return self.proposals.pop(0)

    def propose_twice(
        self,
        *,
        row: CcisRow,
        corrective_context: str | None = None,
        prior_attempts: list[LlmProposal] | None = None,
        tagged_evidence: str | None = None,
        crm_responsibility: str | None = None,
        boundary_brief: str | None = None,
        **_kwargs,
    ) -> tuple[LlmProposal, LlmProposal]:
        a = self.propose(
            row=row,
            corrective_context=corrective_context,
            prior_attempts=prior_attempts,
            tagged_evidence=tagged_evidence,
            crm_responsibility=crm_responsibility,
            boundary_brief=boundary_brief,
        )
        b = self.propose(
            row=row,
            corrective_context=corrective_context,
            prior_attempts=prior_attempts,
            tagged_evidence=tagged_evidence,
            crm_responsibility=crm_responsibility,
            boundary_brief=boundary_brief,
        )
        return a, b


def _good_proposal(confidence: float = 0.9) -> LlmProposal:
    """Validator-accepted proposal; mirrors test_decision_cache.py."""
    return LlmProposal(
        status=ComplianceStatus.COMPLIANT,
        narrative=(
            "Verified via USD00050010 §3.2 that automated provisioning "
            "is configured per the plan."
        ),
        input_tokens=100,
        output_tokens=50,
        confidence=confidence,
    )


def _llm_only_row(make_row) -> CcisRow:
    return make_row(
        procedures="Examine account management documentation.",
        inherited="Local",
    )


# Validator rule #11 rejects narratives citing tokens absent from the
# tagged evidence; include the proposal's USD doc token here.
_EV_BASE = "Tagged evidence excerpt: USD00050010 §3.2 — account management plan."


def _ev(suffix: str = "") -> str:
    return _EV_BASE + suffix


def _seed_reviewed(
    session: Session,
    *,
    run_id: int,
    confidence: float,
    accepted: bool,
    cci_id: str = "CCI-000015",
) -> CalibrationEntry:
    """Insert a hand-crafted reviewed CalibrationEntry directly.

    Bypasses the assessor pipeline so the scoring tests can stage exact
    confidence values + accept flags without juggling LLM stubs.
    """
    entry = CalibrationEntry(
        run_id=run_id,
        cci_id=cci_id,
        fingerprint=f"fp-{cci_id}-{confidence}-{accepted}",
        stated_confidence=confidence,
        proposed_status=ComplianceStatus.COMPLIANT.value,
        final_status=ComplianceStatus.COMPLIANT.value,
        abstained=False,
        rewrite_requested=False,
        human_accepted=accepted,
        recorded_at=datetime.now(timezone.utc),
        reviewed_at=datetime.now(timezone.utc),
    )
    session.add(entry)
    session.commit()
    session.refresh(entry)
    return entry


# ---------------------------------------------------------------------------
# Recorder integration
# ---------------------------------------------------------------------------


def test_calibration_entry_written_for_llm_decision(make_row, session):
    """An accepted LLM proposal must produce one CalibrationEntry tied
    to the run, with the LLM's stated confidence and the verdict's
    proposed/final status copied across.
    """
    row = _llm_only_row(make_row)
    llm = StubLlm(proposals=[_good_proposal(confidence=0.8)])
    assessor = Assessor(llm=llm)
    recorder = RunRecorder.start(session, workbook_id=None)

    decision = assessor.assess(row, tagged_evidence=_ev(), recorder=recorder)
    recorder.finish()

    assert decision.accepted is True
    entries = list(session.exec(__import__(
        "sqlmodel"
    ).select(CalibrationEntry)).all())  # type: ignore[attr-defined]
    assert len(entries) == 1
    e = entries[0]
    assert e.run_id == recorder.run_id
    assert e.cci_id == row.cci_id
    assert e.stated_confidence == pytest.approx(0.8)
    assert e.proposed_status == ComplianceStatus.COMPLIANT.value
    assert e.final_status == ComplianceStatus.COMPLIANT.value
    assert e.abstained is False
    # Reviewer signal starts null — flipped later via the review endpoint.
    assert e.human_accepted is None
    assert e.reviewed_at is None


def test_calibration_entry_skipped_for_rule_8a(make_row, session):
    """Rule #8a short-circuits the LLM entirely; there is no
    ``stated_confidence`` to grade, so the recorder MUST NOT write a
    CalibrationEntry.
    """
    row = make_row(
        procedures="Automatically compliant per assessment procedures.",
    )
    llm = StubLlm(proposals=[])  # would explode if called
    assessor = Assessor(llm=llm)
    recorder = RunRecorder.start(session, workbook_id=None)

    decision = assessor.assess(row, recorder=recorder)
    recorder.finish()

    assert decision.source == "rule_8a"
    from sqlmodel import select as _select

    entries = list(session.exec(_select(CalibrationEntry)).all())
    assert entries == []


# ---------------------------------------------------------------------------
# Scoring math
# ---------------------------------------------------------------------------


def test_brier_score_perfect_calibration(session):
    """confidence=1 + accepted=True → squared error 0 → Brier 0."""
    run_id = 1
    _seed_reviewed(session, run_id=run_id, confidence=1.0, accepted=True, cci_id="A")
    _seed_reviewed(session, run_id=run_id, confidence=1.0, accepted=True, cci_id="B")

    assert calibration_engine.brier_score(session, run_id=run_id) == pytest.approx(0.0)


def test_brier_score_worst_case(session):
    """confidence=1 + accepted=False → squared error 1 → Brier 1.

    This is the failure mode the patent kernel must surface: perfectly
    confident, perfectly wrong.
    """
    run_id = 1
    _seed_reviewed(session, run_id=run_id, confidence=1.0, accepted=False, cci_id="A")
    _seed_reviewed(session, run_id=run_id, confidence=1.0, accepted=False, cci_id="B")

    assert calibration_engine.brier_score(session, run_id=run_id) == pytest.approx(1.0)


def test_ece_perfectly_calibrated_bins(session):
    """Stage one bin per confidence level where the accept rate exactly
    equals the bin's mean confidence — ECE collapses to 0.

    Synthetic uniform-by-design: confidence=0.05 with 0/2 accepted (rate
    0.0), confidence=0.95 with 2/2 accepted (rate 1.0). Wait — that gives
    a gap of |0.05 - 0.0| = 0.05 in bin 0 and |0.95 - 1.0| = 0.05 in
    bin 9, weighted 0.05 each → ECE 0.05. To hit a true zero we need each
    bin's mean to equal its accept rate; e.g. confidence=0.5 with 1/2
    accepted (mean 0.5, rate 0.5) → gap 0.0 → ECE 0.0. That's the cleanest
    "perfectly calibrated" claim.
    """
    run_id = 1
    _seed_reviewed(session, run_id=run_id, confidence=0.5, accepted=True, cci_id="A")
    _seed_reviewed(session, run_id=run_id, confidence=0.5, accepted=False, cci_id="B")

    ece = calibration_engine.expected_calibration_error(
        session, run_id=run_id, bins=10
    )
    assert ece == pytest.approx(0.0)


def test_calibration_report_partitions_correctly(session):
    """Report bundles brier + ece + bin breakdown + reviewed/unreviewed
    counters. Sample: 3 reviewed, 1 unreviewed, mixed confidences across
    distinct bins so the bin_breakdown counts are checkable.
    """
    run_id = 1
    # Reviewed: low-confidence reject, mid-confidence accept, high-confidence accept
    _seed_reviewed(session, run_id=run_id, confidence=0.1, accepted=False, cci_id="A")
    _seed_reviewed(session, run_id=run_id, confidence=0.5, accepted=True, cci_id="B")
    _seed_reviewed(session, run_id=run_id, confidence=0.95, accepted=True, cci_id="C")
    # Unreviewed: a fourth entry that must NOT contribute to brier/ece
    # but MUST show up in total_unreviewed.
    unreviewed = CalibrationEntry(
        run_id=run_id,
        cci_id="D",
        fingerprint="fp-D",
        stated_confidence=0.7,
        proposed_status=ComplianceStatus.COMPLIANT.value,
        final_status=ComplianceStatus.COMPLIANT.value,
        recorded_at=datetime.now(timezone.utc),
    )
    session.add(unreviewed)
    session.commit()

    report = calibration_engine.calibration_report(
        session, run_id=run_id, bins=10
    )

    assert report["total_reviewed"] == 3
    assert report["total_unreviewed"] == 1
    assert 0.0 <= report["brier"] <= 1.0
    assert 0.0 <= report["ece"] <= 1.0
    assert len(report["bin_breakdown"]) == 10

    # Bin 1 holds 0.1 (right-open [0.1, 0.2)), bin 5 holds 0.5, bin 9
    # holds 0.95 (top bin is closed at 1.0). Empty bins keep their slot
    # with count=0 and None rate fields.
    bin1 = report["bin_breakdown"][1]
    bin5 = report["bin_breakdown"][5]
    bin9 = report["bin_breakdown"][9]
    assert bin1["count"] == 1 and bin1["accept_rate"] == pytest.approx(0.0)
    assert bin5["count"] == 1 and bin5["accept_rate"] == pytest.approx(1.0)
    assert bin9["count"] == 1 and bin9["accept_rate"] == pytest.approx(1.0)

    empty_bin = report["bin_breakdown"][0]  # 0.1 falls in bin 1, not 0
    assert empty_bin["count"] == 0
    assert empty_bin["mean_confidence"] is None
    assert empty_bin["accept_rate"] is None


def test_unreviewed_entries_excluded_from_score(session):
    """A confidence=1 + accepted=False reviewed row must drive Brier to
    1.0 even when an unreviewed confidence=1 + accept=None row exists.
    Reviewed rows are the only Brier/ECE input.
    """
    run_id = 1
    _seed_reviewed(session, run_id=run_id, confidence=1.0, accepted=False, cci_id="A")
    # Unreviewed entry with the opposite signal -- if it were counted,
    # the Brier would drop. It must NOT be counted.
    unreviewed = CalibrationEntry(
        run_id=run_id,
        cci_id="B",
        fingerprint="fp-B",
        stated_confidence=0.0,  # opposite end of the confidence range
        proposed_status=ComplianceStatus.NON_COMPLIANT.value,
        final_status=ComplianceStatus.NON_COMPLIANT.value,
        recorded_at=datetime.now(timezone.utc),
    )
    session.add(unreviewed)
    session.commit()

    assert calibration_engine.brier_score(session, run_id=run_id) == pytest.approx(1.0)
    assert calibration_engine.expected_calibration_error(
        session, run_id=run_id, bins=10
    ) == pytest.approx(1.0)

    report = calibration_engine.calibration_report(session, run_id=run_id)
    assert report["total_reviewed"] == 1
    assert report["total_unreviewed"] == 1
