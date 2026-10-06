"""Regression coverage for workbook-scoped bulk evidence clearing."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: E402,F401
from cybersecurity_assessor.db import get_session  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Assessment,
    AssessmentEvidenceShown,
    ComplianceStatus,
    Control,
    Evidence,
    EvidenceKind,
    EvidenceTag,
    Framework,
    NarrativeClass,
    Objective,
    Workbook,
)
from cybersecurity_assessor.server import create_app  # noqa: E402


@pytest.fixture
def env(tmp_path: Path) -> dict:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    def override_session():
        with Session(engine) as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_session] = override_session

    shared_text = tmp_path / "shared.txt"
    shared_text.write_text("shared extracted text", encoding="utf-8")
    unique_text = tmp_path / "only-a.txt"
    unique_text.write_text("workbook A only", encoding="utf-8")

    with Session(engine) as session:
        framework = Framework(name="NIST", version="Rev 4")
        session.add(framework)
        session.commit()
        session.refresh(framework)
        control = Control(
            framework_id=framework.id,
            control_id="ac-2",
            title="Account Management",
            family="AC",
        )
        session.add(control)
        session.commit()
        session.refresh(control)
        objective = Objective(
            control_id_fk=control.id,
            objective_id="CCI-000015",
            text="Account management.",
        )
        session.add(objective)
        session.commit()
        session.refresh(objective)

        workbook_a = Workbook(path="a.xlsx", filename="a.xlsx", framework_id=framework.id)
        workbook_b = Workbook(path="b.xlsx", filename="b.xlsx", framework_id=framework.id)
        session.add_all([workbook_a, workbook_b])
        session.commit()
        session.refresh(workbook_a)
        session.refresh(workbook_b)

        evidence_a = Evidence(
            path="file:///a.txt",
            sha256="a" * 64,
            kind=EvidenceKind.TEXT,
            size_bytes=10,
            extracted_text_path=str(shared_text),
            workbook_id=workbook_a.id,
        )
        evidence_b = Evidence(
            path="file:///b.txt",
            sha256="b" * 64,
            kind=EvidenceKind.TEXT,
            size_bytes=10,
            extracted_text_path=str(shared_text),
            workbook_id=workbook_b.id,
        )
        evidence_a_only = Evidence(
            path="file:///a-only.txt",
            sha256="c" * 64,
            kind=EvidenceKind.TEXT,
            size_bytes=10,
            extracted_text_path=str(unique_text),
            workbook_id=workbook_a.id,
        )
        session.add_all([evidence_a, evidence_b, evidence_a_only])
        session.commit()
        session.refresh(evidence_a)
        session.refresh(evidence_b)
        session.add_all(
            [
                EvidenceTag(evidence_id=evidence_a.id, objective_id=objective.id),
                EvidenceTag(evidence_id=evidence_b.id, objective_id=objective.id),
            ]
        )
        assessments = []
        for workbook in (workbook_a, workbook_b):
            assessment = Assessment(
                workbook_id=workbook.id,
                objective_id=objective.id,
                excel_row=7,
                status=ComplianceStatus.COMPLIANT,
                tester="tester",
                date_tested=datetime.now(UTC),
                narrative_q="Implemented.",
                narrative_class=NarrativeClass.COMPLIANCE_AFFIRMING,
                needs_review=False,
            )
            session.add(assessment)
            session.commit()
            session.refresh(assessment)
            assessments.append(assessment)
        session.add_all(
            [
                AssessmentEvidenceShown(
                    assessment_id=assessments[0].id,
                    evidence_id=evidence_a.id,
                    chunk_sha="a" * 64,
                    chunk_text="A",
                    order_index=0,
                ),
                AssessmentEvidenceShown(
                    assessment_id=assessments[1].id,
                    evidence_id=evidence_b.id,
                    chunk_sha="b" * 64,
                    chunk_text="B",
                    order_index=0,
                ),
            ]
        )
        session.commit()

        ids = {
            "workbook_a": workbook_a.id,
            "workbook_b": workbook_b.id,
            "evidence_a": evidence_a.id,
            "evidence_b": evidence_b.id,
            "assessment_a": assessments[0].id,
            "assessment_b": assessments[1].id,
        }

    yield {
        "client": TestClient(app),
        "engine": engine,
        "shared_text": shared_text,
        "unique_text": unique_text,
        **ids,
    }
    app.dependency_overrides.clear()


def test_clear_evidence_removes_only_selected_workbook(env: dict) -> None:
    response = env["client"].delete(
        f"/api/evidence?workbook_id={env['workbook_a']}&purge_text=true"
    )
    assert response.status_code == 200, response.text
    assert response.json()["evidence_removed"] == 2
    assert response.json()["tags_removed"] == 1

    with Session(env["engine"]) as session:
        assert session.get(Evidence, env["evidence_a"]) is None
        assert session.get(Evidence, env["evidence_b"]) is not None
        remaining_tags = session.exec(select(EvidenceTag)).all()
        assert [tag.evidence_id for tag in remaining_tags] == [env["evidence_b"]]
        remaining_shown = session.exec(select(AssessmentEvidenceShown)).all()
        assert [row.evidence_id for row in remaining_shown] == [env["evidence_b"]]
        assert session.get(Assessment, env["assessment_a"]).needs_review is True
        assert session.get(Assessment, env["assessment_b"]).needs_review is False

    assert env["shared_text"].exists(), "shared cache text must remain for workbook B"
    assert not env["unique_text"].exists(), "unshared cache text should be removed"


def test_clear_evidence_rejects_unknown_workbook(env: dict) -> None:
    response = env["client"].delete("/api/evidence?workbook_id=999999")
    assert response.status_code == 404
