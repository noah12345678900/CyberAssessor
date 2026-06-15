"""Light model round-trip tests for AutomationSchedule.

Verifies:
  - Default field values (interval_minutes=1440, run_assessment=False, enabled=True)
  - Per-workbook isolation (querying by workbook_id returns only its rows)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401 -- registers tables
from cybersecurity_assessor.models import AutomationSchedule, Workbook


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


def _make_workbook(session: Session, path: str) -> Workbook:
    wb = Workbook(path=path, filename=Path(path).name)
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb


# ---------------------------------------------------------------------------
# Default field values
# ---------------------------------------------------------------------------


def test_automation_schedule_defaults(session):
    """Row written with only required fields gets correct defaults."""
    wb = _make_workbook(session, "/tmp/defaults_test.xlsx")
    sched = AutomationSchedule(workbook_id=wb.id, source_type="local")
    session.add(sched)
    session.commit()
    session.refresh(sched)

    assert sched.interval_minutes == 1440, "Default daily interval"
    assert sched.run_assessment is False, "run_assessment defaults to False"
    assert sched.enabled is True, "enabled defaults to True"
    assert sched.last_run_at is None
    assert sched.last_status is None
    assert sched.next_run_at is None


def test_automation_schedule_custom_values(session):
    """Explicit field values survive a round-trip."""
    wb = _make_workbook(session, "/tmp/custom_test.xlsx")
    sched = AutomationSchedule(
        workbook_id=wb.id,
        source_type="sharepoint",
        name="Nightly SP Pull",
        interval_minutes=60,
        run_assessment=True,
        enabled=False,
    )
    session.add(sched)
    session.commit()
    session.refresh(sched)

    assert sched.name == "Nightly SP Pull"
    assert sched.interval_minutes == 60
    assert sched.run_assessment is True
    assert sched.enabled is False


# ---------------------------------------------------------------------------
# Workbook isolation
# ---------------------------------------------------------------------------


def test_automation_schedule_workbook_isolation(session):
    """Querying by workbook_id returns only that workbook's schedules."""
    wb1 = _make_workbook(session, "/tmp/wb1.xlsx")
    wb2 = _make_workbook(session, "/tmp/wb2.xlsx")

    session.add(AutomationSchedule(workbook_id=wb1.id, source_type="local"))
    session.add(AutomationSchedule(workbook_id=wb1.id, source_type="sharepoint"))
    session.add(AutomationSchedule(workbook_id=wb2.id, source_type="local"))
    session.commit()

    wb1_scheds = session.exec(
        select(AutomationSchedule).where(AutomationSchedule.workbook_id == wb1.id)
    ).all()
    wb2_scheds = session.exec(
        select(AutomationSchedule).where(AutomationSchedule.workbook_id == wb2.id)
    ).all()

    assert len(wb1_scheds) == 2
    assert len(wb2_scheds) == 1
    assert all(s.workbook_id == wb1.id for s in wb1_scheds)
    assert wb2_scheds[0].workbook_id == wb2.id
