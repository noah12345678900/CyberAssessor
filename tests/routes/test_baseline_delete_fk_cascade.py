"""Regression: DELETE /api/baselines/{id} must satisfy every foreign key.

THE BUG (user-found). Deleting a baseline (CRM overlay) 500'd. Under
``PRAGMA foreign_keys=ON`` (db.py — production), delete_baseline deleted
CrmSuspicionLog rows (by crm_baseline_id) but never cleared the
CrmShortCircuitEvent rows whose ``suspicion_log_id`` FK points at them. The
suspicion-log delete then raised a FOREIGN KEY constraint failure → HTTP 500 →
the UI baseline delete silently failed.

This test enables FK enforcement (matching production) and seeds a CRM baseline
with a CrmSuspicionLog → CrmShortCircuitEvent chain, so a regression that drops
the short-circuit-event delete (or re-orders it after the suspicion-log delete)
makes the delete 500 and fails here.

Collected via testpaths=["../tests"].
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
    Baseline,
    BaselineControl,
    BaselineObjective,
    BaselineSourceType,
    Control,
    CrmCorpusFeatures,
    CrmShortCircuitEvent,
    CrmSuspicionLog,
    Framework,
    Objective,
    Workbook,
    WorkbookOverlay,
)
from cybersecurity_assessor.server import create_app


def _utc() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def client_and_ids():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

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
            control_id_fk=ctrl.id, objective_id="CCI-000015", source="CCI", text="t"
        )
        s.add(obj)
        s.commit()
        s.refresh(obj)

        # A workbook is needed for the CRM-telemetry rows' workbook_id FK, but it
        # must NOT pin the baseline as primary scope (that would 409). So the
        # workbook's primary baseline is a SEPARATE one; the CRM baseline is only
        # attached as an overlay.
        primary = Baseline(
            framework_id=fw.id, name="primary", source_type=BaselineSourceType.CCIS_WORKBOOK
        )
        s.add(primary)
        s.commit()
        s.refresh(primary)
        wb = Workbook(path="x.xlsx", filename="x.xlsx", baseline_id=primary.id)
        s.add(wb)
        s.commit()
        s.refresh(wb)

        crm = Baseline(
            framework_id=fw.id,
            name="CRM-AWS",
            source_type=BaselineSourceType.CRM,
            scope_label="AWS GovCloud",
        )
        s.add(crm)
        s.commit()
        s.refresh(crm)

        # Scoping rows + overlay attachment for the CRM baseline.
        s.add(BaselineControl(baseline_id=crm.id, control_id=ctrl.id, in_scope=True))
        s.add(BaselineObjective(baseline_id=crm.id, objective_id=obj.id, source_row=1))
        s.add(WorkbookOverlay(workbook_id=wb.id, baseline_id=crm.id, attached_at=_utc()))

        # The FK chain that broke the delete: CrmSuspicionLog → CrmShortCircuitEvent.
        susp = CrmSuspicionLog(
            workbook_id=wb.id,
            crm_baseline_id=crm.id,
            heuristic_score=0.3,
            overall_suspicion=0.3,
            flags_json="[]",
            per_family_json="{}",
        )
        s.add(susp)
        s.commit()
        s.refresh(susp)
        s.add(
            CrmShortCircuitEvent(
                workbook_id=wb.id,
                control_id_fk=ctrl.id,
                responsibility="inherited",
                suspicion_log_id=susp.id,
            )
        )
        s.add(
            CrmCorpusFeatures(
                workbook_id=wb.id,
                crm_baseline_id=crm.id,
                feature_schema_version=1,
                features_json="{}",
            )
        )
        s.commit()

        crm_id = crm.id
        wb_id = wb.id

    yield TestClient(app), crm_id, wb_id, engine
    app.dependency_overrides.clear()


def test_delete_baseline_with_suspicion_chain_does_not_500(client_and_ids):
    """A CRM baseline whose suspicion log has a short-circuit-event child deletes
    cleanly (no FK 500); the short-circuit event is cleared first.
    """
    tc, crm_id, wb_id, engine = client_and_ids

    # The CRM baseline is an overlay, not the workbook's primary scope, so a
    # plain (non-force) delete is allowed (no 409).
    r = tc.delete(f"/api/baselines/{crm_id}")
    assert r.status_code == 200, (
        f"baseline delete must satisfy the suspicion-log FK chain; "
        f"got {r.status_code}: {r.text}"
    )

    with Session(engine) as s:
        assert s.get(Baseline, crm_id) is None
        # The short-circuit event and suspicion log for this baseline are gone.
        assert s.exec(select(CrmShortCircuitEvent)).all() == []
        assert (
            s.exec(
                select(CrmSuspicionLog).where(CrmSuspicionLog.crm_baseline_id == crm_id)
            ).all()
            == []
        )
        # The workbook (separate primary baseline) survives.
        assert s.get(Workbook, wb_id) is not None
