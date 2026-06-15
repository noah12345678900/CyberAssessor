"""Test fixtures for the controls export module.

Each test gets a fresh in-memory SQLite engine + session so export runs
don't bleed across tests. The ``controls_catalog`` fixture seeds a
small mixed-status / mixed-CRM baseline so the rollup logic and the
PSC bulk fetch both have something realistic to chew on.

xlwings-bound tests (template-preserving COM writes) gate behind the
``requires_excel`` marker — register it in ``pytest.ini`` if absent,
or run ``pytest -m "not requires_excel"`` in CI.
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
    Baseline,
    BaselineControl,
    BaselineObjective,
    BaselineSourceType,
    ComplianceStatus,
    Control,
    Framework,
    NarrativeClass,
    Objective,
    RequirementMap,
    RequirementSource,
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
def controls_catalog(session, tmp_path):
    """Seed a workbook + baseline with four controls covering the
    interesting rollup cases:

      AC-2  : two CCIs both Compliant            → single-bucket emit
      AC-3  : two CCIs, one Compliant + one NC   → multi-line rollup
      AC-4  : one CCI inherited via CRM          → "inherited from <src>"
      AC-5  : one CCI needs_review               → excluded from eMASS

    AC-2 and AC-3 also carry PSC mappings from two RequirementSources so
    the PSC formatter has source-prefixed lines to render.

    Returns a dict with workbook + framework + baseline + objective lookups.
    """
    p = tmp_path / "ctrls-test.xlsx"
    p.write_bytes(b"fake-ccis-bytes")

    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)

    # Two overlay sources so the PSC column has multi-source content.
    src_sda = RequirementSource(
        framework_id=fw.id, name="SDA Enterprise Services Controls"
    )
    src_t1tl = RequirementSource(
        framework_id=fw.id, name="T1TL Program Controls"
    )
    session.add_all([src_sda, src_t1tl])
    session.commit()
    session.refresh(src_sda)
    session.refresh(src_t1tl)

    catalog_layout = [
        ("AC-2", "AC", ["CCI-000015", "CCI-000016"]),
        ("AC-3", "AC", ["CCI-000213", "CCI-000214"]),
        ("AC-4", "AC", ["CCI-001548"]),
        ("AC-5", "AC", ["CCI-000038"]),
    ]
    controls: dict[str, Control] = {}
    objectives: dict[str, Objective] = {}
    for ctl_id, family, ccis in catalog_layout:
        ctrl = Control(
            framework_id=fw.id,
            control_id=ctl_id,
            title=f"{ctl_id} title",
            family=family,
            statement=f"{ctl_id} statement",
        )
        session.add(ctrl)
        session.commit()
        session.refresh(ctrl)
        controls[ctl_id] = ctrl

        for cci in ccis:
            obj = Objective(
                control_id_fk=ctrl.id,
                objective_id=cci,
                source="CCI",
                text=f"objective text for {cci}",
            )
            session.add(obj)
            session.commit()
            session.refresh(obj)
            objectives[cci] = obj

    bl = Baseline(
        framework_id=fw.id,
        name="ctrls-test-baseline",
        source_type=BaselineSourceType.CCIS_WORKBOOK,
    )
    session.add(bl)
    session.commit()
    session.refresh(bl)

    # All four controls in scope; AC-4 carries CRM inherited responsibility.
    for ctl_id, ctrl in controls.items():
        responsibility = "inherited" if ctl_id == "AC-4" else None
        responsibility_narrative = (
            "AWS GovCloud — inherited control." if ctl_id == "AC-4" else None
        )
        session.add(
            BaselineControl(
                baseline_id=bl.id,
                control_id=ctrl.id,
                in_scope=True,
                responsibility=responsibility,
                responsibility_narrative=responsibility_narrative,
            )
        )
    session.commit()

    # BaselineObjective rows so source_row lookups don't trip.
    for i, obj in enumerate(objectives.values(), start=20):
        session.add(
            BaselineObjective(
                baseline_id=bl.id,
                objective_id=obj.id,
                source_row=str(i),
            )
        )
    session.commit()

    # PSC overlays on AC-2 (two sources) and AC-3 (one source).
    psc_rows = [
        (src_sda.id, objectives["CCI-000015"].id, "SDA-127",
         "Customer shall enforce least-privilege account creation."),
        (src_t1tl.id, objectives["CCI-000016"].id, "T1TL-031",
         "Program shall document account approval chain."),
        (src_sda.id, objectives["CCI-000213"].id, "SDA-201",
         "Logical access controls shall be reviewed quarterly."),
    ]
    for source_id, obj_id, req_num, req_text in psc_rows:
        session.add(
            RequirementMap(
                requirement_source_id=source_id,
                objective_id=obj_id,
                requirement_number=req_num,
                requirement_text=req_text,
            )
        )
    session.commit()

    wb = Workbook(
        path=str(p),
        filename=p.name,
        framework_id=fw.id,
        baseline_id=bl.id,
    )
    session.add(wb)
    session.commit()
    session.refresh(wb)

    return {
        "workbook": wb,
        "framework": fw,
        "baseline": bl,
        "controls": controls,
        "objectives": objectives,
        "sources": {"sda": src_sda, "t1tl": src_t1tl},
        "path": p,
    }


@pytest.fixture
def assess(session):
    """Factory: create an Assessment for an objective with a given status.

    Mirrors the poam test fixture so the two suites stay in sync.
    """

    def _make(
        workbook_id: int,
        objective_id: int,
        status: ComplianceStatus = ComplianceStatus.COMPLIANT,
        *,
        tester: str = "Noah Jaskolski",
        narrative: str = "Test narrative.",
        needs_review: bool = False,
        review_reason: str | None = None,
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
            needs_review=needs_review,
            review_reason=review_reason,
        )
        session.add(a)
        session.commit()
        session.refresh(a)
        return a

    return _make
