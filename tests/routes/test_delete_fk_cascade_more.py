"""Regression: two more FK-cascade delete fixes (B1 + B7).

Both are the same bug class as the earlier workbook/baseline delete 500s — a
parent deleted under PRAGMA foreign_keys=ON without first clearing a NOT-NULL-FK
child. The old tests didn't enable FK enforcement, which is why these shipped.

B1 — DELETE /api/poams/{id} omitted PoamRiskHistory (poam_id FK). Deleting a
     single POAM whose risk level was ever changed → FK 500. (delete_all_poams
     and delete_workbook already cleared it; the single-delete was the outlier.)

B7 — POST /api/system-context/pending/reset deleted boundary-doc Evidence with a
     bare s.delete(d), leaving Evidence's nine FK children → FK 500. Now routes
     through delete_one_evidence which clears children first.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import event
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select

from cybersecurity_assessor import models  # noqa: F401 -- register tables
from cybersecurity_assessor.db import get_session
from cybersecurity_assessor.models import (
    Evidence,
    EvidenceKind,
    EvidenceTag,
    Framework,
    Objective,
    Control,
    Poam,
    PoamMilestone,
    PoamRiskHistory,
    RiskLevel,
    SystemContext,
    Workbook,
)
from cybersecurity_assessor.server import create_app


def _utc() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def client_engine():
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

    def _override():
        with Session(engine) as s:
            yield s

    app = create_app()
    app.dependency_overrides[get_session] = _override
    yield TestClient(app), engine
    app.dependency_overrides.clear()


def test_delete_poam_with_risk_history_does_not_500(client_engine):
    """B1: a POAM with a PoamRiskHistory row deletes cleanly (no FK 500)."""
    tc, engine = client_engine
    with Session(engine) as s:
        wb = Workbook(path="x.xlsx", filename="x.xlsx")
        s.add(wb)
        s.commit()
        s.refresh(wb)
        poam = Poam(
            workbook_id=wb.id,
            control_cluster="SI-3",
            vulnerability_description="Malware protection gap.",
        )
        s.add(poam)
        s.commit()
        s.refresh(poam)
        # A milestone (already-handled child) + a risk-history row (the missed
        # child that caused the 500).
        s.add(PoamMilestone(poam_id=poam.id, description="Patch by EOQ."))
        s.add(
            PoamRiskHistory(
                poam_id=poam.id,
                field="likelihood",
                prev_value=None,
                new_value=RiskLevel.HIGH.value,
            )
        )
        s.commit()
        poam_id = poam.id

    r = tc.delete(f"/api/poams/{poam_id}")
    assert r.status_code == 200, (
        f"delete_poam must clear PoamRiskHistory before the parent; "
        f"got {r.status_code}: {r.text}"
    )
    with Session(engine) as s:
        assert s.get(Poam, poam_id) is None
        assert s.exec(select(PoamRiskHistory)).all() == []
        assert s.exec(select(PoamMilestone)).all() == []


def test_reset_pending_context_with_boundary_doc_children_does_not_500(client_engine):
    """B7: pending reset clears boundary-doc Evidence + its FK children (no 500)."""
    tc, engine = client_engine
    with Session(engine) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5")
        s.add(fw)
        s.commit()
        s.refresh(fw)
        ctrl = Control(framework_id=fw.id, control_id="sc-7", title="SC-7", family="SC")
        s.add(ctrl)
        s.commit()
        s.refresh(ctrl)
        obj = Objective(control_id_fk=ctrl.id, objective_id="CCI-001097", source="CCI", text="t")
        s.add(obj)
        s.commit()
        s.refresh(obj)

        # Pending SystemContext singleton (workbook_id is None = pending).
        # source_type defaults to FREEFORM_MARKDOWN — irrelevant to this test.
        ctx = SystemContext(workbook_id=None, description="Pending boundary.")
        s.add(ctx)
        s.commit()

        # A pending boundary-doc Evidence (workbook_id None, is_boundary_doc) WITH
        # an EvidenceTag child — the FK child a bare delete would orphan → 500.
        ev = Evidence(
            path="boundary.pdf",
            sha256="b" * 64,
            kind=EvidenceKind.PDF,
            size_bytes=1,
            workbook_id=None,
            is_boundary_doc=True,
        )
        s.add(ev)
        s.commit()
        s.refresh(ev)
        s.add(
            EvidenceTag(
                evidence_id=ev.id,
                objective_id=obj.id,
                relevance=0.5,
                confidence=0.5,
                source="auto",
                rationale="boundary diagram",
            )
        )
        s.commit()
        ev_id = ev.id

    r = tc.post("/api/system-context/pending/reset")
    assert r.status_code == 200, (
        f"pending reset must clear boundary-doc Evidence children before delete; "
        f"got {r.status_code}: {r.text}"
    )
    with Session(engine) as s:
        assert s.get(Evidence, ev_id) is None
        assert s.exec(select(EvidenceTag)).all() == []
        # Pending context singleton gone too.
        assert (
            s.exec(select(SystemContext).where(SystemContext.workbook_id == None)).all()  # noqa: E711
            == []
        )
