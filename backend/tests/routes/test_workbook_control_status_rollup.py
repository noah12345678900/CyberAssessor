"""Regression test for the ``GET /api/workbooks/{id}/control-status`` rollup.

Pins the precision-over-recall gate at
``routes/workbooks.py:728-733`` — ``needs_review=True`` rows must be
routed into the ``needs_review`` bucket and excluded from
``compliant`` / ``non_compliant`` / ``na``, regardless of the persisted
``status`` value. This matters because the abstain-coercion fix
(``feedback_abstain_status_none_drops.md``) lands hard abstains as
``(status=NON_COMPLIANT, needs_review=True)`` so the row survives the
NOT NULL schema; without the rollup gate every such coerced row would
inflate the Non-Compliant count and silently flip a control's verdict
from ``Compliant`` to ``Non-Compliant``.

The historical TODO at ``models.py`` (now resolved) flagged the rollup
as the last consumer missing the gate. This test exists so a future
refactor can't silently un-fix the gate.

Three scenarios per control rollup:
  1. Mixed trusted + needs_review NC → rolls up to ``Needs Review``
     (NC came in via needs_review, can't trust it; trusted rows are
     all Compliant). Coerced NC must NOT promote the control.
  2. Single trusted NC + many needs_review → rolls up to
     ``Non-Compliant`` (one confirmed gap > open questions; standing
     precedence rule).
  3. All-Compliant trusted + zero needs_review → rolls up to
     ``Compliant``.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.db import get_session  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Assessment,
    ComplianceStatus,
    Control,
    Framework,
    NarrativeClass,
    Objective,
    Workbook,
)
from cybersecurity_assessor.server import create_app  # noqa: E402


def _utc() -> datetime:
    return datetime.now(timezone.utc)


def _assessment(
    *,
    workbook_id: int,
    objective_id: int,
    status: ComplianceStatus,
    needs_review: bool,
) -> Assessment:
    """Minimal Assessment with the rollup-relevant fields set.

    Everything else (narrative, tester, date_tested) gets a defensible
    default so the row passes NOT NULL constraints without distracting
    from the gate under test.
    """
    return Assessment(
        workbook_id=workbook_id,
        objective_id=objective_id,
        excel_row=1,
        status=status,
        tester="test",
        date_tested=_utc(),
        narrative_q="x",
        narrative_class=NarrativeClass.AMBIGUOUS,
        needs_review=needs_review,
    )


@pytest.fixture
def client(tmp_path: Path):
    """TestClient backed by an in-memory SQLite.

    Seeds three Controls (AC-2, AC-3, AC-4), one Objective per Control,
    and the Assessment fixture each scenario needs.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    def _override_get_session():
        with Session(engine) as s:
            yield s

    app = create_app()
    app.dependency_overrides[get_session] = _override_get_session

    wb_path = tmp_path / "demo.xlsx"
    wb_path.write_bytes(b"x")

    with Session(engine) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5")
        s.add(fw)
        s.commit()
        s.refresh(fw)

        wb = Workbook(path=str(wb_path), filename=wb_path.name, framework_id=fw.id)
        s.add(wb)

        # Each control rolls up across its OWN objectives (CCIs), one
        # Assessment per objective — the real shape now that
        # uq_assessment_workbook_objective forbids two assessments on one
        # objective. AC-2 gets 3 objectives, AC-3 gets 3, AC-4 gets 1; the
        # rollup math under test is identical to the prior (incorrectly
        # one-objective-stacked) fixture.
        controls: dict[str, Control] = {}
        objectives: dict[str, list[Objective]] = {}
        obj_counts = {"AC-2": 3, "AC-3": 3, "AC-4": 1}
        for cid in ("AC-2", "AC-3", "AC-4"):
            c = Control(framework_id=fw.id, control_id=cid, title=cid, family="AC")
            s.add(c)
            controls[cid] = c
        s.commit()
        for cid, c in controls.items():
            s.refresh(c)
            objs: list[Objective] = []
            for n in range(1, obj_counts[cid] + 1):
                o = Objective(
                    control_id_fk=c.id,
                    objective_id=f"{cid}.{n}",
                    source="CCI",
                    text=f"{cid} objective {n}",
                )
                s.add(o)
                objs.append(o)
            objectives[cid] = objs
        s.commit()
        for objs in objectives.values():
            for o in objs:
                s.refresh(o)
        s.refresh(wb)
        wb_id = wb.id

        # AC-2: two trusted-Compliant objectives + one coerced-NC needs_review.
        # Rollup must see Compliant=2, NC=0, needs_review=1 → "Needs Review".
        # If the gate regresses, NC would be 1 and the rollup would flip to
        # "Non-Compliant".
        s.add(
            _assessment(
                workbook_id=wb_id,
                objective_id=objectives["AC-2"][0].id,
                status=ComplianceStatus.COMPLIANT,
                needs_review=False,
            )
        )
        s.add(
            _assessment(
                workbook_id=wb_id,
                objective_id=objectives["AC-2"][1].id,
                status=ComplianceStatus.COMPLIANT,
                needs_review=False,
            )
        )
        s.add(
            _assessment(
                workbook_id=wb_id,
                objective_id=objectives["AC-2"][2].id,
                status=ComplianceStatus.NON_COMPLIANT,
                needs_review=True,
            )
        )

        # AC-3: one trusted NC + two needs_review (status doesn't matter,
        # they go into the needs_review bucket). NC wins.
        s.add(
            _assessment(
                workbook_id=wb_id,
                objective_id=objectives["AC-3"][0].id,
                status=ComplianceStatus.NON_COMPLIANT,
                needs_review=False,
            )
        )
        s.add(
            _assessment(
                workbook_id=wb_id,
                objective_id=objectives["AC-3"][1].id,
                status=ComplianceStatus.COMPLIANT,
                needs_review=True,
            )
        )
        s.add(
            _assessment(
                workbook_id=wb_id,
                objective_id=objectives["AC-3"][2].id,
                status=ComplianceStatus.NON_COMPLIANT,
                needs_review=True,
            )
        )

        # AC-4: single trusted Compliant objective, no needs_review.
        s.add(
            _assessment(
                workbook_id=wb_id,
                objective_id=objectives["AC-4"][0].id,
                status=ComplianceStatus.COMPLIANT,
                needs_review=False,
            )
        )

        s.commit()

    yield TestClient(app), wb_id
    app.dependency_overrides.clear()


def test_rollup_routes_needs_review_into_separate_bucket(client) -> None:
    """Coerced-NC abstain rows must not inflate the Non-Compliant count."""
    tc, wb_id = client
    r = tc.get(f"/api/workbooks/{wb_id}/control-status")
    assert r.status_code == 200, r.text
    by_control = {row["control_id"]: row for row in r.json()}

    ac2 = by_control[1]  # AC-2 is the first Control row -> id=1
    assert ac2["compliant"] == 2
    assert ac2["non_compliant"] == 0, (
        "needs_review=True NC row leaked into non_compliant bucket — "
        "rollup gate at routes/workbooks.py:728-733 has regressed"
    )
    assert ac2["needs_review"] == 1
    assert ac2["status"] == "Needs Review"


def test_rollup_trusted_nc_beats_needs_review(client) -> None:
    """NC is the strongest signal — one trusted NC wins over open triage."""
    tc, wb_id = client
    r = tc.get(f"/api/workbooks/{wb_id}/control-status")
    by_control = {row["control_id"]: row for row in r.json()}

    ac3 = by_control[2]  # AC-3 -> id=2
    assert ac3["non_compliant"] == 1
    assert ac3["needs_review"] == 2
    assert ac3["compliant"] == 0, (
        "needs_review=True Compliant row leaked into compliant bucket"
    )
    assert ac3["status"] == "Non-Compliant"


def test_rollup_clean_compliant(client) -> None:
    """Sanity: no needs_review, all Compliant -> Compliant."""
    tc, wb_id = client
    r = tc.get(f"/api/workbooks/{wb_id}/control-status")
    by_control = {row["control_id"]: row for row in r.json()}

    ac4 = by_control[3]  # AC-4 -> id=3
    assert ac4["compliant"] == 1
    assert ac4["needs_review"] == 0
    assert ac4["non_compliant"] == 0
    assert ac4["status"] == "Compliant"
