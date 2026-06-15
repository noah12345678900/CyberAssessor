"""Tests for the pending-singleton SystemContext endpoints.

Exercises the workbook-decoupling slice (2026-06-05) — assessor drops
boundary docs BEFORE picking a workbook, then promotes that pending
scope onto a workbook later.

The pending-CRUD + promote endpoints are tested directly here without
mocking the LLM extractor — we seed SystemContext and boundary-doc
Evidence rows via the test session so we can exercise the
read/reset/promote/bump paths in isolation. Tests that need extraction
live in the freeform / boundary_docs adapter test modules.

Covers:
  - GET /pending returns 404 when nothing exists
  - GET /pending returns ctx + docs after seeding
  - POST /pending/reset cascades to pending boundary docs
  - POST /pending/bump-confidence is no-op without a pending row
  - POST /pending/bump-confidence clamps to 1.0
  - POST /pending/promote reparents both the SystemContext and
    pending boundary Evidence rows onto the target workbook
  - POST /pending/promote returns {promoted: False} when nothing pending
  - POST /pending/promote refuses 409 when the target already has a
    SystemContext
  - Route registration order: GET /pending does NOT shadow into the
    parametric /{workbook_id} handler (would 422 otherwise)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.db import get_session  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Evidence,
    EvidenceKind,
    Framework,
    SystemContext,
    SystemContextSourceType,
    Workbook,
)
from cybersecurity_assessor.server import create_app  # noqa: E402


@pytest.fixture
def app_client(tmp_path: Path):
    """TestClient + bound engine for direct seeding.

    Returns (TestClient, engine, workbook_id_factory) — the workbook
    factory creates a real-file-backed Workbook row in the shared
    engine since several tests need to promote into a workbook (or
    refuse to promote when one already has a SystemContext).
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

    with Session(engine) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5")
        s.add(fw)
        s.commit()
        s.refresh(fw)
        fw_id = fw.id

    def _make_workbook(name: str = "demo.xlsx") -> int:
        p = tmp_path / name
        p.write_bytes(b"x")
        with Session(engine) as s:
            wb = Workbook(path=str(p), filename=p.name, framework_id=fw_id)
            s.add(wb)
            s.commit()
            s.refresh(wb)
            return wb.id

    yield TestClient(app), engine, _make_workbook
    app.dependency_overrides.clear()


def _seed_pending_context(engine, *, tokens=("server01",), confidence=0.5) -> int:
    """Insert a pending SystemContext directly, bypassing the LLM path."""
    with Session(engine) as s:
        ctx = SystemContext(
            workbook_id=None,
            source_type=SystemContextSourceType.FREEFORM_MARKDOWN,
            source_ref="freeform",
            extracted_tokens=list(tokens),
            confidence=confidence,
        )
        s.add(ctx)
        s.commit()
        s.refresh(ctx)
        return ctx.id


def _seed_pending_boundary_doc(engine, *, sha: str, filename: str) -> int:
    """Insert an Evidence row flagged as a pending boundary doc."""
    with Session(engine) as s:
        ev = Evidence(
            path=f"file:///pending/{filename}",
            sha256=sha,
            kind=EvidenceKind.PDF,
            size_bytes=10,
            is_boundary_doc=True,
            boundary_doc_kind="SSP",
            workbook_id=None,
        )
        s.add(ev)
        s.commit()
        s.refresh(ev)
        return ev.id


# ---------------------------------------------------------------------------
# GET /pending
# ---------------------------------------------------------------------------


def test_get_pending_returns_200_null_when_empty(app_client):
    """Empty state is ``{context: null, boundary_docs: []}``, not 404 — the
    page polls this on every load and a 404 was logged as a red DevTools
    error on every fresh app launch."""
    tc, _engine, _ = app_client
    r = tc.get("/api/system-context/pending")
    assert r.status_code == 200, r.text
    assert r.json() == {"context": None, "boundary_docs": []}


def test_get_pending_returns_ctx_and_docs(app_client):
    tc, engine, _ = app_client
    ctx_id = _seed_pending_context(engine, tokens=("hostA", "hostB"))
    doc_id = _seed_pending_boundary_doc(engine, sha="aaa", filename="ssp.pdf")

    r = tc.get("/api/system-context/pending")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["context"]["id"] == ctx_id
    assert body["context"]["workbook_id"] is None
    assert sorted(body["context"]["extracted_tokens"]) == ["hostA", "hostB"]
    assert len(body["boundary_docs"]) == 1
    assert body["boundary_docs"][0]["id"] == doc_id


def test_get_pending_returns_200_when_only_docs_present(app_client):
    """User dropped docs but extraction hasn't fired yet — still not a 404."""
    tc, engine, _ = app_client
    _seed_pending_boundary_doc(engine, sha="bbb", filename="diagram.pdf")
    r = tc.get("/api/system-context/pending")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["context"] is None
    assert len(body["boundary_docs"]) == 1


def test_get_pending_does_not_shadow_into_parametric_route(app_client):
    """Regression: registration order matters — `GET /pending` must NOT
    be matched by `GET /{workbook_id}` and coerced to int."""
    tc, _engine, _ = app_client
    r = tc.get("/api/system-context/pending")
    # 200 (our "no pending" empty shape) not 422 (FastAPI int-coercion failure)
    # and not the per-workbook GET's ``null`` body shape.
    assert r.status_code == 200, r.text
    body = r.json()
    assert "context" in body and "boundary_docs" in body


# ---------------------------------------------------------------------------
# POST /pending/reset
# ---------------------------------------------------------------------------


def test_reset_pending_deletes_ctx_and_docs(app_client):
    tc, engine, _ = app_client
    _seed_pending_context(engine)
    _seed_pending_boundary_doc(engine, sha="ccc", filename="ato.pdf")
    _seed_pending_boundary_doc(engine, sha="ddd", filename="net.pdf")

    r = tc.post("/api/system-context/pending/reset")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body == {
        "reset": True,
        "context_removed": True,
        "boundary_docs_removed": 2,
    }

    # Verify everything is actually gone.
    with Session(engine) as s:
        assert (
            s.exec(
                select(SystemContext).where(SystemContext.workbook_id.is_(None))
            ).first()
            is None
        )
        remaining = s.exec(
            select(Evidence).where(
                Evidence.workbook_id.is_(None),
                Evidence.is_boundary_doc.is_(True),
            )
        ).all()
        assert remaining == []


def test_reset_pending_is_idempotent_when_empty(app_client):
    tc, _engine, _ = app_client
    r = tc.post("/api/system-context/pending/reset")
    assert r.status_code == 200
    assert r.json() == {
        "reset": True,
        "context_removed": False,
        "boundary_docs_removed": 0,
    }


# ---------------------------------------------------------------------------
# POST /pending/bump-confidence
# ---------------------------------------------------------------------------


def test_bump_pending_confidence_noop_when_no_row(app_client):
    tc, _engine, _ = app_client
    r = tc.post(
        "/api/system-context/pending/bump-confidence",
        json={"accepted_count": 3},
    )
    assert r.status_code == 200
    assert r.json() == {"bumped": False, "reason": "no pending SystemContext"}


def test_bump_pending_confidence_zero_or_negative_is_noop(app_client):
    tc, engine, _ = app_client
    _seed_pending_context(engine, confidence=0.4)
    r = tc.post(
        "/api/system-context/pending/bump-confidence",
        json={"accepted_count": 0},
    )
    assert r.status_code == 200
    assert r.json() == {"bumped": False, "reason": "accepted_count <= 0"}


def test_bump_pending_confidence_clamps_to_one(app_client):
    tc, engine, _ = app_client
    _seed_pending_context(engine, confidence=0.95)
    r = tc.post(
        "/api/system-context/pending/bump-confidence",
        json={"accepted_count": 10},  # would push past 1.0
    )
    assert r.status_code == 200
    body = r.json()
    assert body["bumped"] is True
    assert body["confidence"] == pytest.approx(1.0)


def test_bump_pending_confidence_increments_by_five_percent_per_artifact(app_client):
    tc, engine, _ = app_client
    _seed_pending_context(engine, confidence=0.3)
    r = tc.post(
        "/api/system-context/pending/bump-confidence",
        json={"accepted_count": 2},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["bumped"] is True
    assert body["confidence"] == pytest.approx(0.4)  # 0.3 + 2*0.05


# ---------------------------------------------------------------------------
# POST /pending/promote
# ---------------------------------------------------------------------------


def test_promote_pending_returns_false_when_nothing_pending(app_client):
    tc, _engine, make_wb = app_client
    wb_id = make_wb("target.xlsx")
    r = tc.post(f"/api/system-context/pending/promote?workbook_id={wb_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["promoted"] is False
    assert body["reason"] == "no pending context"
    assert body["workbook_id"] == wb_id


def test_promote_pending_404_when_workbook_unknown(app_client):
    tc, engine, _ = app_client
    _seed_pending_context(engine)
    r = tc.post("/api/system-context/pending/promote?workbook_id=999999")
    assert r.status_code == 404


def test_promote_pending_reparents_context_and_docs(app_client):
    tc, engine, make_wb = app_client
    wb_id = make_wb("promote-target.xlsx")
    ctx_id = _seed_pending_context(engine, tokens=("alpha",), confidence=0.6)
    ev_id_1 = _seed_pending_boundary_doc(engine, sha="eee", filename="ssp1.pdf")
    ev_id_2 = _seed_pending_boundary_doc(engine, sha="fff", filename="net1.pdf")

    r = tc.post(f"/api/system-context/pending/promote?workbook_id={wb_id}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["promoted"] is True
    assert body["workbook_id"] == wb_id
    assert body["context"]["id"] == ctx_id
    assert body["context"]["workbook_id"] == wb_id
    assert body["boundary_doc_count"] == 2

    # Pending GET should now return the empty shape — the singleton was
    # reparented, not duplicated.
    r2 = tc.get("/api/system-context/pending")
    assert r2.status_code == 200, r2.text
    assert r2.json() == {"context": None, "boundary_docs": []}

    # Evidence rows reparented in-place.
    with Session(engine) as s:
        for ev_id in (ev_id_1, ev_id_2):
            ev = s.get(Evidence, ev_id)
            assert ev is not None
            assert ev.workbook_id == wb_id
            assert ev.is_boundary_doc is True


def test_promote_pending_refuses_409_when_workbook_has_context(app_client):
    """Refuses to silently overwrite the assessor's prior boundary work."""
    tc, engine, make_wb = app_client
    wb_id = make_wb("conflict.xlsx")

    # Pre-seed the workbook with its own SystemContext.
    with Session(engine) as s:
        s.add(
            SystemContext(
                workbook_id=wb_id,
                source_type=SystemContextSourceType.FREEFORM_MARKDOWN,
                source_ref="freeform",
                extracted_tokens=["existing-host"],
                confidence=0.7,
            )
        )
        s.commit()

    _seed_pending_context(engine, tokens=("pending-host",))

    r = tc.post(f"/api/system-context/pending/promote?workbook_id={wb_id}")
    assert r.status_code == 409
    assert "already has a SystemContext" in r.json().get("detail", "")

    # Pending row preserved — caller can decide what to do (today: keep it
    # until the user picks a workbook without an existing SystemContext).
    with Session(engine) as s:
        pending = s.exec(
            select(SystemContext).where(SystemContext.workbook_id.is_(None))
        ).first()
        assert pending is not None
        assert pending.extracted_tokens == ["pending-host"]


def test_promote_pending_with_docs_only_reparents_docs(app_client):
    """User dropped docs but extraction hasn't run yet — promote should
    still reparent the Evidence rows so the workbook picks them up."""
    tc, engine, make_wb = app_client
    wb_id = make_wb("docs-only.xlsx")
    ev_id = _seed_pending_boundary_doc(engine, sha="ggg", filename="ssp.pdf")

    r = tc.post(f"/api/system-context/pending/promote?workbook_id={wb_id}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["promoted"] is True
    assert body["context"] is None
    assert body["boundary_doc_count"] == 1

    with Session(engine) as s:
        ev = s.get(Evidence, ev_id)
        assert ev is not None
        assert ev.workbook_id == wb_id
