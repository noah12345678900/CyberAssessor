"""Regression: persist a synthesized On-Premises residual abstain slice.

The batch assess endpoint 500'd on ``IntegrityError: NOT NULL constraint
failed: assessmentimplementation.status``. Root cause: a control with a
customer-owned cloud scope but NO on-prem evidence makes
``engine.assessor.plan_implementations`` emit a synthesized On-Premises
*residual* ImplementationPlan with ``status=None`` — a per-scope abstain
("acknowledged but unassessed; flag for reviewer") that is precision-over-
recall by design. ``AssessmentImplementation.status`` shipped NOT NULL, so
persisting that plan raised mid-flush and rolled back the WHOLE batch
transaction, surfacing as a 500 on ``POST /api/controls/assess-batch``.

The column is now nullable (migration 0017). This test pins the contract:
a Decision whose plan set includes a status=None residual slice persists
cleanly, the child row lands with ``status IS NULL`` and a non-empty
narrative, and the parent keeps its own (coerced) verdict.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

# tests/conftest.py adds the backend package to sys.path.
from cybersecurity_assessor import models  # noqa: F401  -- register tables
from cybersecurity_assessor.engine.assessor import Decision
from cybersecurity_assessor.engine.crm_context import (
    CrmContext,
    ImplementationSlice,
)
from cybersecurity_assessor.engine.impl_persistence import (
    persist_assessment_with_impls,
)
from cybersecurity_assessor.models import (
    Assessment,
    AssessmentImplementation,
    ComplianceStatus,
    NarrativeClass,
)


@pytest.fixture
def session() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _decision() -> Decision:
    # A COMPLIANT cloud verdict with NO per-scope on-prem narrative — exactly
    # the shape that makes plan_implementations synthesize a status=None
    # On-Premises residual slice.
    return Decision(
        cci_id="CCI-000130",
        excel_row=42,
        accepted=True,
        status=ComplianceStatus.COMPLIANT,
        narrative="Cloud control confirmed via configuration review.",
        narrative_class=NarrativeClass.COMPLIANCE_AFFIRMING,
        source="llm",
        rule=None,
        narratives_by_scope={
            "AWS GovCloud": "AWS GovCloud confirmed via configuration review."
        },
    )


def _crm_with_synthesized_onprem() -> CrmContext:
    # One customer-owned cloud slice + the synthesized On-Premises slice
    # (source_baseline_id is None — the "residual customer work on-prem"
    # placeholder crm_context appends when any cloud scope is customer-owned).
    return CrmContext(
        by_control_impls={
            "ac-2": [
                ImplementationSlice(
                    scope_label="AWS GovCloud",
                    responsibility="customer",
                    narrative="AWS GovCloud is customer-owned.",
                    source_baseline_id=1,
                ),
                ImplementationSlice(
                    scope_label="On-Premises",
                    responsibility="customer",
                    narrative=None,
                    source_baseline_id=None,
                ),
            ]
        }
    )


def test_persist_residual_onprem_abstain_does_not_raise(session):
    """The status=None residual slice persists instead of 500ing the flush."""
    decision = _decision()
    crm = _crm_with_synthesized_onprem()
    assessment = Assessment(
        workbook_id=1,
        objective_id=10,
        excel_row=42,
        status=ComplianceStatus.COMPLIANT,
        tester="t",
        date_tested=datetime.now(timezone.utc),
        narrative_q="Cloud control confirmed via configuration review.",
        narrative_class=NarrativeClass.COMPLIANCE_AFFIRMING,
    )

    pk = persist_assessment_with_impls(
        session,
        assessment=assessment,
        decision=decision,
        crm_context=crm,
        control_id="AC-2",
        is_new=True,
    )
    session.commit()  # would IntegrityError pre-fix
    assert pk is not None

    impls = session.exec(
        select(AssessmentImplementation).where(
            AssessmentImplementation.assessment_id == pk
        )
    ).all()
    by_scope = {i.scope_label: i for i in impls}
    assert "On-Premises" in by_scope, "residual on-prem slice must persist"

    onprem = by_scope["On-Premises"]
    assert onprem.status is None, (
        "synthesized residual on-prem slice is a per-scope abstain (status=None)"
    )
    assert onprem.narrative, "abstain row must carry a non-empty narrative"
    assert "on-premises" in onprem.narrative.lower()

    # The evidenced cloud scope keeps its real verdict.
    aws = by_scope["AWS GovCloud"]
    assert aws.status is ComplianceStatus.COMPLIANT

    # Parent keeps a confident verdict (the abstain child doesn't drag it down
    # to None — compute_rollup_status worst-of ignores the None contributor).
    parent = session.get(Assessment, pk)
    assert parent.status is ComplianceStatus.COMPLIANT
