"""Test fixtures for the POAM module.

Each test gets a fresh in-memory SQLite engine + session so generator runs
don't bleed across tests. The ``poam_catalog`` fixture seeds a small but
clustering-realistic catalog: SI-3, SI-3(1), SI-3(2) (one base + two
enhancements) plus AC-2 — enough to exercise base_control_id collapsing
without dragging in the full 800-53 loader.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

# Make the backend package importable regardless of pytest cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.models import (  # noqa: E402
    Assessment,
    ComplianceStatus,
    Control,
    Framework,
    NarrativeClass,
    Objective,
    Workbook,
)


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def poam_catalog(session, tmp_path):
    """Seed a workbook + clustering-realistic catalog.

    Layout:
      Framework: NIST SP 800-53 Rev 5
      Controls (with one CCI each, so each control = one objective):
        SI-3      → CCI-001240
        SI-3(1)   → CCI-001241
        SI-3(2)   → CCI-001242
        AC-2      → CCI-000015

    Returns a dict with the workbook + objective lookups so individual tests
    can build assessments against the CCIs they care about.
    """
    p = tmp_path / "poam-test.xlsx"
    p.write_bytes(b"fake-ccis-bytes")

    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)

    objectives: dict[str, Objective] = {}
    for ctl_id, family, cci in [
        ("SI-3", "SI", "CCI-001240"),
        ("SI-3(1)", "SI", "CCI-001241"),
        ("SI-3(2)", "SI", "CCI-001242"),
        ("AC-2", "AC", "CCI-000015"),
    ]:
        ctrl = Control(
            framework_id=fw.id,
            control_id=ctl_id,
            title=f"{ctl_id} title",
            family=family,
        )
        session.add(ctrl)
        session.commit()
        session.refresh(ctrl)

        obj = Objective(
            control_id_fk=ctrl.id,
            objective_id=cci,
            source="CCI",
            text=f"objective text for {cci}",
        )
        session.add(obj)
        session.commit()
        session.refresh(obj)
        objectives[ctl_id] = obj

    wb = Workbook(path=str(p), filename=p.name, framework_id=fw.id)
    session.add(wb)
    session.commit()
    session.refresh(wb)

    return {"workbook": wb, "framework": fw, "objectives": objectives, "path": p}


@pytest.fixture
def assess(session):
    """Factory: create an Assessment for an objective with a given status."""

    def _make(
        workbook_id: int,
        objective_id: int,
        status: ComplianceStatus = ComplianceStatus.NON_COMPLIANT,
        *,
        tester: str = "Noah Jaskolski",
        narrative: str = "Test narrative.",
    ) -> Assessment:
        a = Assessment(
            workbook_id=workbook_id,
            objective_id=objective_id,
            status=status,
            tester=tester,
            date_tested=datetime.now(timezone.utc),
            narrative_q=narrative,
            narrative_class=(
                NarrativeClass.GAP_DESCRIBING
                if status == ComplianceStatus.NON_COMPLIANT
                else NarrativeClass.COMPLIANCE_AFFIRMING
            ),
        )
        session.add(a)
        session.commit()
        session.refresh(a)
        return a

    return _make
