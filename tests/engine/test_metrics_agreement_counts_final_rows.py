"""Regression: the agreement metric counts FINAL Assessment rows.

Two user-reported defects in the "CCI verdict agreement" card:

1. "11 of 13" on a 13-CCI workbook, persisting on a fresh DB. Root cause:
   deterministic controls (rule 8a/8b, CRM provider/inherited/NA) are written
   by the open-time backfill with outcome=None — no AssessmentRun, no
   ccis_accepted — and then skipped by a later "Assess all" (skip_existing).
   They never entered the run-sum numerator. Counting final Assessment rows
   includes them.

2. "2 rejects when there were none." validator_rejections counted every retry
   REJECTION event, so a rejected-then-accepted-on-retry CCI was counted in
   both accepted and rejected, inflating "decided." Rejections are no longer
   in the agreement denominator.

The fix derives accepted/abstained from final Assessment rows
(needs_review False/True) and uses accepted+abstained as "decided".
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from cybersecurity_assessor import models  # noqa: F401  -- register tables
from cybersecurity_assessor.models import (
    Assessment,
    AssessmentRun,
    ComplianceStatus,
    NarrativeClass,
)
from cybersecurity_assessor.routes.metrics import _aggregate


def _session():
    eng = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(eng)
    return Session(eng)


def _assessment(obj_id: int, *, needs_review: bool, status=ComplianceStatus.COMPLIANT):
    return Assessment(
        workbook_id=1,
        objective_id=obj_id,
        excel_row=obj_id,
        status=status,
        tester="t",
        date_tested=datetime.now(timezone.utc),
        narrative_q="x",
        narrative_class=NarrativeClass.COMPLIANCE_AFFIRMING,
        needs_review=needs_review,
    )


def _run(**kw):
    base = dict(
        workbook_id=1,
        started_at=datetime.now(timezone.utc),
        ccis_accepted=0,
        validator_rejections=0,
        abstained=0,
        llm_calls=0,
        retry_count=0,
        cost_usd=0.0,
        llm_input_tokens=0,
        llm_output_tokens=0,
        llm_cache_read_tokens=0,
        supersession_hits=0,
    )
    base.update(kw)
    return AssessmentRun(**base)


def test_deterministic_backfill_controls_count_as_accepted():
    """13 final trusted rows, but the run only recorded 9 (4 were backfilled
    deterministic controls + skipped). Metric must show 13, not 9."""
    with _session() as s:
        for i in range(13):
            s.add(_assessment(i + 1, needs_review=False))
        # The run that "Assess all" produced — only the 9 LLM CCIs; the 4
        # deterministic ones were backfilled (outcome=None) and skipped.
        s.add(_run(ccis_accepted=9, llm_calls=9))
        s.commit()
        rows = s.exec(select(AssessmentRun)).all()
        acc = _aggregate(rows, s)["accuracy"]
        assert acc["ccis_accepted"] == 13, "all final trusted rows must count"
        assert acc["abstained"] == 0
        assert acc["accuracy_pct"] == 100.0


def test_retry_rejections_not_in_agreement_denominator():
    """A CCI rejected-then-accepted-on-retry must not show as a 'decided'
    rejection. 13 trusted rows + a run logging 2 retry rejections → still
    100% agreement, rejections surfaced only as telemetry."""
    with _session() as s:
        for i in range(13):
            s.add(_assessment(i + 1, needs_review=False))
        s.add(_run(ccis_accepted=13, llm_calls=13, validator_rejections=2, retry_count=2))
        s.commit()
        rows = s.exec(select(AssessmentRun)).all()
        acc = _aggregate(rows, s)["accuracy"]
        assert acc["ccis_accepted"] == 13
        assert acc["accuracy_pct"] == 100.0, "retry rejections must not lower agreement"
        # Raw count still surfaced as telemetry.
        assert acc["validator_rejections"] == 2


def test_abstain_is_decided_but_not_accepted():
    """An abstain (needs_review=True) counts in 'decided' but not accepted."""
    with _session() as s:
        for i in range(12):
            s.add(_assessment(i + 1, needs_review=False))
        s.add(_assessment(13, needs_review=True, status=ComplianceStatus.NON_COMPLIANT))
        s.add(_run(ccis_accepted=12, abstained=1, llm_calls=13))
        s.commit()
        rows = s.exec(select(AssessmentRun)).all()
        acc = _aggregate(rows, s)["accuracy"]
        assert acc["ccis_accepted"] == 12
        assert acc["abstained"] == 1
        # 12 / (12 + 1) = 92.3%
        assert round(acc["accuracy_pct"], 1) == 92.3
