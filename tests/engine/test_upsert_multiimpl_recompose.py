"""Regression: the multi-impl upsert recomposes column-Q from per-scope rows.

AC-17 bug (user-reported): a multi-scope control's column-Q showed a stale
2-scope LLM blob — the AWS GovCloud customer scope was dropped and the text
even contradicted the per-scope rows ("Azure ... no evidence ... POA&M" while
the Azure impl row was inherited/Compliant). Root cause: the UI's per-scope
editor shipped `implementations` in the POST /api/controls/assessments body,
but `AssessmentUpsert` had NO `implementations` field, so Pydantic silently
dropped them and the server persisted the stale top-textarea narrative_q.

The fix adds the field and, when present, applies each edit to its impl row
then recomposes the parent status (worst-of) + narrative_q (labeled per-scope
join over ALL impl rows). This test drives the real endpoint and asserts the
recomposed column-Q contains EVERY scope.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from cybersecurity_assessor import models  # noqa: F401  -- register tables
from cybersecurity_assessor.db import get_session
from cybersecurity_assessor.models import (
    Assessment,
    AssessmentImplementation,
    ComplianceStatus,
    Control,
    Framework,
    NarrativeClass,
    Objective,
    Workbook,
)
from cybersecurity_assessor.server import create_app


def _setup():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    def _override():
        with Session(engine) as s:
            yield s

    app = create_app()
    app.dependency_overrides[get_session] = _override
    return engine, app


def test_multiimpl_upsert_recomposes_column_q_with_all_scopes():
    engine, app = _setup()
    with Session(engine) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5")
        s.add(fw)
        s.commit()
        s.refresh(fw)
        ctrl = Control(
            framework_id=fw.id, control_id="ac-17", title="Remote Access", family="AC"
        )
        s.add(ctrl)
        s.commit()
        s.refresh(ctrl)
        obj = Objective(
            control_id_fk=ctrl.id,
            objective_id="CCI-000063",
            source="CCI",
            text="Remote access is authorized.",
        )
        s.add(obj)
        s.commit()
        s.refresh(obj)
        wb = Workbook(id=1, path="/tmp/wb.xlsx", filename="wb.xlsx", framework_id=fw.id)
        s.add(wb)
        s.commit()
        # A parent assessment carrying a STALE 2-scope blob + 3 impl rows.
        a = Assessment(
            workbook_id=1,
            objective_id=obj.id,
            excel_row=8,
            status=ComplianceStatus.NON_COMPLIANT,
            tester="t",
            date_tested=datetime.now(timezone.utc),
            narrative_q="STALE BLOB: Azure no evidence; POA&M opened.",
            narrative_class=NarrativeClass.GAP_DESCRIBING,
        )
        s.add(a)
        s.commit()
        s.refresh(a)
        aws = AssessmentImplementation(
            assessment_id=a.id,
            scope_label="AWS GovCloud",
            responsibility="customer",
            status=ComplianceStatus.NON_COMPLIANT,
            narrative="On the AWS GovCloud enclave, verified via USD20240622 the VPN config.",
        )
        azure = AssessmentImplementation(
            assessment_id=a.id,
            scope_label="Azure Government",
            responsibility="inherited",
            status=ComplianceStatus.COMPLIANT,
            narrative="Customer fully inherits the managed Azure Bastion control.",
        )
        onprem = AssessmentImplementation(
            assessment_id=a.id,
            scope_label="On-Premises",
            responsibility="customer",
            status=ComplianceStatus.NON_COMPLIANT,
            narrative="No evidence addresses the On-Premises footprint; POA&M opened.",
        )
        s.add_all([aws, azure, onprem])
        s.commit()
        obj_id, aws_id, azure_id, onprem_id = obj.id, aws.id, azure.id, onprem.id

    client = TestClient(app)
    resp = client.post(
        "/api/controls/assessments?force=true",
        json={
            "workbook_id": 1,
            "objective_id": obj_id,
            "excel_row": 8,
            "status": "Non-Compliant",
            "tester": "Noah Jaskolski",
            "narrative_q": "STALE BLOB: Azure no evidence; POA&M opened.",
            "narrative_class": "gap-describing",
            "implementations": [
                {"id": aws_id, "status": "Non-Compliant", "narrative": "On the AWS GovCloud enclave, verified via USD20240622 the VPN config."},
                {"id": azure_id, "status": "Compliant", "narrative": "Customer fully inherits the managed Azure Bastion control."},
                {"id": onprem_id, "status": "Non-Compliant", "narrative": "No evidence addresses the On-Premises footprint; POA&M opened."},
            ],
        },
    )
    assert resp.status_code == 200, resp.text

    with Session(engine) as s:
        a = s.exec(
            select(Assessment).where(Assessment.objective_id == obj_id)
        ).one()
        # Column Q now reflects EVERY scope — not the stale blob.
        assert "AWS GovCloud" in a.narrative_q, a.narrative_q
        assert "Azure Government" in a.narrative_q
        assert "On-Premises" in a.narrative_q
        assert "STALE BLOB" not in a.narrative_q
        # Worst-of rollup: one NC scope => parent NC.
        assert a.status is ComplianceStatus.NON_COMPLIANT
