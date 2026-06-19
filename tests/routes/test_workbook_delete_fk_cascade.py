"""Regression: DELETE /api/workbooks/{id} must cascade EVERY NOT-NULL
workbook FK so the delete doesn't 500 under foreign-key enforcement.

THE BUG (user-found). Deleting a workbook in the UI silently failed: the
backend cascade (routes/workbooks.py delete_workbook) hand-walks ~20 tables but
omitted FOUR that carry a NOT-NULL ``workbook_id`` FK — Component, OverrideEpoch,
EvidenceRetentionEvent, AutomationSchedule. Production runs with
``PRAGMA foreign_keys=ON`` (db.py), so a workbook that had ANY such row raised a
FOREIGN KEY constraint failure on ``s.delete(wb)`` → HTTP 500 → the UI delete
appeared to do nothing and the workbook stayed.

WHY THE EXISTING TEST MISSED IT (backend/tests/routes/test_workbook_delete.py):
it (1) never seeds those four tables and (2) builds its engine WITHOUT
``PRAGMA foreign_keys=ON``, so even an unhandled FK wouldn't raise. This test
fixes both: it turns FK enforcement ON via a connect event (matching production)
AND seeds one row in each of the four previously-missed tables, so a regression
that drops any of the four deletes makes ``DELETE`` 500 and fails here.

Lives in the COLLECTED top-level tree (``testpaths=["../tests"]``).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import event
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select

from cybersecurity_assessor import models  # noqa: F401 -- register tables
from cybersecurity_assessor.db import get_session
from cybersecurity_assessor.models import (
    AutomationSchedule,
    Component,
    Control,
    EvidenceRetentionEvent,
    Framework,
    Objective,
    OverrideEpoch,
    Workbook,
)
from cybersecurity_assessor.server import create_app


def _utc() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def client_and_ids(tmp_path: Path):
    """TestClient with FK enforcement ON (matching production db.py) and a
    workbook seeded with a row in each of the four previously-uncascaded
    NOT-NULL-FK tables.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    # Match production: enforce foreign keys so an unhandled NOT-NULL FK raises
    # on delete instead of silently orphaning. Without this the bug is invisible.
    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _rec):  # pragma: no cover - trivial
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    SQLModel.metadata.create_all(engine)

    def _override_get_session():
        with Session(engine) as s:
            yield s

    app = create_app()
    app.dependency_overrides[get_session] = _override_get_session

    wb_path = tmp_path / "target.xlsx"
    wb_path.write_bytes(b"x")

    with Session(engine) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5")
        s.add(fw)
        s.commit()
        s.refresh(fw)

        ctrl = Control(framework_id=fw.id, control_id="ac-2", title="AC-2", family="AC")
        s.add(ctrl)
        s.commit()
        s.refresh(ctrl)

        obj = Objective(
            control_id_fk=ctrl.id,
            objective_id="CCI-000015",
            source="CCI",
            text="Account management.",
        )
        s.add(obj)
        s.commit()
        s.refresh(obj)

        wb = Workbook(path=str(wb_path), filename=wb_path.name, framework_id=fw.id)
        s.add(wb)
        s.commit()
        s.refresh(wb)

        # The FOUR previously-uncascaded NOT-NULL workbook FKs.
        s.add(Component(workbook_id=wb.id, name="web-tier"))  # kind has a default
        s.add(OverrideEpoch(workbook_id=wb.id, objective_id=obj.id, epoch=1))
        s.add(
            EvidenceRetentionEvent(
                workbook_id=wb.id,
                evicted_evidence_id=999,  # a since-evicted evidence row (no FK)
                reason="cap_exceeded",
            )
        )
        s.add(
            AutomationSchedule(
                workbook_id=wb.id,
                source_type="local",
            )
        )
        s.commit()

        wb_id = wb.id

    yield TestClient(app), wb_id, engine
    app.dependency_overrides.clear()


def test_delete_workbook_cascades_notnull_fk_tables(client_and_ids):
    """A workbook with Component/OverrideEpoch/EvidenceRetentionEvent/
    AutomationSchedule rows deletes cleanly (no FK 500) and clears all four.
    """
    tc, wb_id, engine = client_and_ids

    r = tc.delete(f"/api/workbooks/{wb_id}")
    assert r.status_code == 200, (
        f"delete must not 500 on NOT-NULL workbook FKs; got {r.status_code}: {r.text}"
    )
    cascade = r.json()["cascade"]
    # Each of the four tables had exactly one row → the route now reports them.
    assert cascade["components"] == 1
    assert cascade["override_epochs"] == 1
    assert cascade["evidence_retention_events"] == 1
    assert cascade["automation_schedules"] == 1

    with Session(engine) as s:
        assert s.get(Workbook, wb_id) is None
        for model in (
            Component,
            OverrideEpoch,
            EvidenceRetentionEvent,
            AutomationSchedule,
        ):
            remaining = s.exec(
                select(model).where(model.workbook_id == wb_id)  # type: ignore[attr-defined]
            ).all()
            assert remaining == [], f"{model.__name__} not cleared on delete"
