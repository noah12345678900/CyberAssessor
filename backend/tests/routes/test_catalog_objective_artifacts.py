"""Linked-artifact enrichment for the Controls CSV objective feed."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402
from cybersecurity_assessor.db import get_session  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Control,
    Evidence,
    EvidenceKind,
    EvidenceTag,
    Framework,
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

    def _override_get_session():
        with Session(engine) as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_session] = _override_get_session

    with Session(engine) as session:
        framework = Framework(name="NIST SP 800-53", version="Rev 5")
        session.add(framework)
        session.commit()
        session.refresh(framework)

        control = Control(
            framework_id=framework.id,
            control_id="AC-2",
            title="Account Management",
            family="AC",
        )
        session.add(control)
        session.commit()
        session.refresh(control)

        tagged = Objective(
            control_id_fk=control.id,
            objective_id="CCI-000015",
            source="CCI",
            text="Automate account management.",
        )
        empty = Objective(
            control_id_fk=control.id,
            objective_id="CCI-000016",
            source="CCI",
            text="Review account management.",
        )
        session.add_all([tagged, empty])
        session.commit()
        session.refresh(tagged)
        session.refresh(empty)

        workbook_a = Workbook(
            path=str(tmp_path / "a.xlsx"),
            filename="a.xlsx",
            framework_id=framework.id,
        )
        workbook_b = Workbook(
            path=str(tmp_path / "b.xlsx"),
            filename="b.xlsx",
            framework_id=framework.id,
        )
        session.add_all([workbook_a, workbook_b])
        session.commit()
        session.refresh(workbook_a)
        session.refresh(workbook_b)

        policy = Evidence(
            path="file:///C:/evidence/policy-a.pdf",
            sha256="a" * 64,
            kind=EvidenceKind.PDF,
            size_bytes=10,
            title="Access Policy",
            workbook_id=workbook_a.id,
        )
        scan = Evidence(
            path="zip:///C:/evidence/bundle.zip!/nested/scan.txt",
            sha256="b" * 64,
            kind=EvidenceKind.TEXT,
            size_bytes=10,
            workbook_id=workbook_a.id,
        )
        other_workbook = Evidence(
            path="file:///C:/evidence/other-secret.pdf",
            sha256="c" * 64,
            kind=EvidenceKind.PDF,
            size_bytes=10,
            title="Other Workbook Secret",
            workbook_id=workbook_b.id,
        )
        session.add_all([policy, scan, other_workbook])
        session.commit()
        session.refresh(policy)
        session.refresh(scan)
        session.refresh(other_workbook)

        session.add_all(
            [
                EvidenceTag(
                    evidence_id=policy.id,
                    objective_id=tagged.id,
                    source="auto",
                ),
                EvidenceTag(
                    evidence_id=policy.id,
                    objective_id=tagged.id,
                    source="manual",
                ),
                EvidenceTag(evidence_id=scan.id, objective_id=tagged.id),
                EvidenceTag(evidence_id=other_workbook.id, objective_id=tagged.id),
            ]
        )
        session.commit()

        ids = {
            "control": control.id,
            "tagged": tagged.id,
            "empty": empty.id,
            "workbook_a": workbook_a.id,
            "workbook_b": workbook_b.id,
            "policy": policy.id,
            "scan": scan.id,
            "other": other_workbook.id,
        }

    return {"client": TestClient(app), **ids}


def _by_id(rows: list[dict], objective_id: int) -> dict:
    return next(row for row in rows if row["id"] == objective_id)


def test_linked_artifacts_are_opt_in_and_require_workbook(env: dict) -> None:
    base = f"/api/catalog/controls/{env['control']}/objectives"

    response = env["client"].get(base)
    assert response.status_code == 200
    assert all("linked_artifacts" not in row for row in response.json())

    invalid = env["client"].get(f"{base}?include_evidence=true")
    assert invalid.status_code == 400
    assert invalid.json()["detail"] == ("workbook_id is required when include_evidence=true")


def test_linked_artifacts_are_deduplicated_scoped_and_stable(env: dict) -> None:
    base = f"/api/catalog/controls/{env['control']}/objectives"
    response = env["client"].get(f"{base}?include_evidence=true&workbook_id={env['workbook_a']}")
    assert response.status_code == 200, response.text

    tagged = _by_id(response.json(), env["tagged"])
    assert tagged["linked_artifacts"] == [
        {
            "evidence_id": env["policy"],
            "filename": "policy-a.pdf",
            "display_path": "C:/evidence/policy-a.pdf",
            "title": "Access Policy",
        },
        {
            "evidence_id": env["scan"],
            "filename": "scan.txt",
            "display_path": "C:/evidence/bundle.zip!/nested/scan.txt",
            "title": None,
        },
    ]
    assert _by_id(response.json(), env["empty"])["linked_artifacts"] == []
    assert env["other"] not in {artifact["evidence_id"] for artifact in tagged["linked_artifacts"]}

    other_response = env["client"].get(
        f"{base}?include_evidence=true&workbook_id={env['workbook_b']}"
    )
    other_tagged = _by_id(other_response.json(), env["tagged"])
    assert [a["evidence_id"] for a in other_tagged["linked_artifacts"]] == [env["other"]]
