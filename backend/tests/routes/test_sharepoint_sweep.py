"""Tests for POST /api/sharepoint/sweep — pending-mode + workbook-mode.

Workbook-decoupling slice (2026-06-05): the sweep route now accepts
either ``workbook_id`` or ``system_context_id`` (or both). This module
pins the wire contract for the pending-mode branch added with that
slice plus the existing workbook path so regressions either way show
up here, not in a UI smoke test.

Mock surface:
  * ``cfg.load_config``                   — saved AppConfig (site URL set,
                                            judge disabled so make_client
                                            is never invoked).
  * ``_acquire_graph_token_for_sweep``    — cache-hit silent acquisition.
  * ``build_boundary_fingerprint``        — returns a hand-built
                                            BoundaryFingerprint so we can
                                            steer the 422 vs 200 guard.
  * ``SharePointSource``                  — stub class; ``sweep_for_boundary``
                                            returns a SweepResult with zero
                                            candidates (we're asserting the
                                            route's bookkeeping, not the
                                            walker).

Covers:
  - 422 when SweepBody has neither workbook_id nor system_context_id
    (pydantic validator).
  - 404 when workbook_id points at a missing workbook.
  - 422 with pending-mode detail copy when fingerprint has no signals.
  - 200 + SweepRun(workbook_id=NULL, system_context_id=N) written for a
    pending-mode sweep with host_tokens.
  - 200 + SweepRun(workbook_id=N) written AND workbook counters bumped
    for a workbook-mode sweep.
"""

from __future__ import annotations

import sys
from dataclasses import replace
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
from cybersecurity_assessor.evidence.sources.sweep import (  # noqa: E402
    BoundaryFingerprint,
    SweepResult,
)
from cybersecurity_assessor.models import (  # noqa: E402
    SweepRun,
    SystemContext,
    SystemContextSourceType,
    Workbook,
)
from cybersecurity_assessor.routes import sharepoint as sharepoint_route  # noqa: E402
from cybersecurity_assessor.server import create_app  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """TestClient with sweep dependencies stubbed at the route module.

    Why patch at ``cybersecurity_assessor.routes.sharepoint.X`` and not at
    the source module: the route imports each helper by name at module
    load time, so binding the route-module attribute is the only way the
    handler actually sees the stub. Patching the upstream module would
    leave the route's local name pointing at the real callable.
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

    # ----- config stub -------------------------------------------------
    # Use the real AppConfig schema so any field rename surfaces here
    # immediately (rather than a silent KeyError deep in the handler).
    # Judge disabled so the cost-cap branch and make_client call are
    # both skipped — keeps the test focused on the workbook-decoupling
    # contract.
    from cybersecurity_assessor import config as cfg_mod

    cfg_stub = cfg_mod.AppConfig(
        sharepoint_site_url="https://example.sharepoint.com/sites/test",
        sharepoint_library="Documents",
        sharepoint_folder_path="",
        sharepoint_priority_links=[],
        sweep_judge_enabled=False,
        sweep_cost_cap_usd=0.0,
    )
    monkeypatch.setattr(sharepoint_route.cfg, "load_config", lambda: cfg_stub)

    # ----- Graph auth pre-flight stub ---------------------------------
    monkeypatch.setattr(
        sharepoint_route,
        "_acquire_graph_token_for_sweep",
        lambda _site_url: {"ok": True},
    )

    # ----- SharePointSource stub --------------------------------------
    class _StubSource:
        def __init__(self, *, site_url, library, folder_path):
            self.site_url = site_url
            self.library = library
            self.folder_path = folder_path

        def sweep_for_boundary(self, fingerprint, **_kwargs) -> SweepResult:
            # Return a minimal, valid SweepResult. Candidates are empty —
            # we're pinning the route's persistence + 422 branches, not
            # the scorer.
            return SweepResult(
                scan_root=self.folder_path or "/",
                workbook_id=fingerprint.workbook_id,
                system_context_id=fingerprint.system_context_id,
                candidates=tuple(),
                families_skipped_by_crm=tuple(),
                truncated=False,
                elapsed_ms=1,
                weights_version_id=None,
                fingerprint_snapshot=fingerprint.to_snapshot_dict(),
                llm_cost_usd=0.0,
                candidates_judged=0,
                judge_model=None,
                judge_used=False,
                judge_fallback_reason=None,
            )

    monkeypatch.setattr(sharepoint_route, "SharePointSource", _StubSource)

    # ----- build_boundary_fingerprint stub ----------------------------
    # Default returns an empty fingerprint; individual tests reassign
    # ``state["fingerprint"]`` to steer the 422/200 branches.
    state: dict = {
        "fingerprint": BoundaryFingerprint(workbook_id=None, system_context_id=None)
    }

    def _stub_fingerprint(*, session, workbook_id, system_context_id, priority_links):
        fp = state["fingerprint"]
        # Honor the route-supplied ids so downstream assertions see the
        # values that were actually passed in (the route layer treats
        # these as authoritative for SweepRun attribution).
        return replace(
            fp, workbook_id=workbook_id, system_context_id=system_context_id
        )

    monkeypatch.setattr(
        sharepoint_route, "build_boundary_fingerprint", _stub_fingerprint
    )

    app = create_app()
    app.dependency_overrides[get_session] = _override_get_session

    yield TestClient(app), engine, state
    app.dependency_overrides.clear()


def _make_workbook(engine, tmp_path: Path, name: str = "demo.xlsx") -> int:
    p = tmp_path / name
    p.write_bytes(b"x")
    with Session(engine) as s:
        wb = Workbook(path=str(p), filename=p.name)
        s.add(wb)
        s.commit()
        s.refresh(wb)
        return wb.id


def _make_pending_context(engine) -> int:
    with Session(engine) as s:
        ctx = SystemContext(
            workbook_id=None,
            source_type=SystemContextSourceType.FREEFORM_MARKDOWN,
            source_ref="freeform",
            extracted_tokens=["server01"],
            confidence=0.6,
        )
        s.add(ctx)
        s.commit()
        s.refresh(ctx)
        return ctx.id


# ---------------------------------------------------------------------------
# SweepBody pydantic validator
# ---------------------------------------------------------------------------


def test_sweep_rejects_missing_scope(app_client):
    """Neither workbook_id nor system_context_id → 422 from validator.

    Without the validator the route would call build_boundary_fingerprint
    with both ids None and ultimately BFS the whole library for nothing.
    """
    tc, _engine, _state = app_client
    r = tc.post("/api/sharepoint/sweep", json={})
    assert r.status_code == 422, r.text
    # FastAPI's pydantic-error envelope — message lives in detail[0]["msg"].
    detail = r.json()["detail"]
    assert any("at least one of" in d.get("msg", "") for d in detail), detail


# ---------------------------------------------------------------------------
# Workbook lookup
# ---------------------------------------------------------------------------


def test_sweep_404_when_workbook_missing(app_client):
    tc, _engine, _state = app_client
    r = tc.post("/api/sharepoint/sweep", json={"workbook_id": 999_999})
    assert r.status_code == 404, r.text
    assert "workbook not found" in r.json()["detail"]


# ---------------------------------------------------------------------------
# 422 — empty fingerprint
# ---------------------------------------------------------------------------


def test_sweep_422_when_pending_fingerprint_has_no_signals(app_client, tmp_path):
    """Pending-mode caller with no host tokens → 422 with pending-flavored copy.

    Pinning the user-visible message because it's the actionable hook the
    UI surfaces verbatim ("Add boundary documents…"). A regression here
    would silently strand the assessor with a generic 422.
    """
    tc, engine, state = app_client
    ctx_id = _make_pending_context(engine)

    # Empty fingerprint — no in_scope_control_ids, no host_tokens, no
    # doc_number_prefixes, no priority_path_prefixes.
    state["fingerprint"] = BoundaryFingerprint()

    r = tc.post("/api/sharepoint/sweep", json={"system_context_id": ctx_id})
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert "pending boundary scope" in detail
    assert "Add boundary documents" in detail


def test_sweep_422_workbook_mode_copy_differs(app_client, tmp_path):
    """Workbook-mode 422 carries the workbook-flavored copy, not pending."""
    tc, engine, state = app_client
    wb_id = _make_workbook(engine, tmp_path)
    state["fingerprint"] = BoundaryFingerprint()

    r = tc.post("/api/sharepoint/sweep", json={"workbook_id": wb_id})
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert "framework bound" in detail
    # Cross-check: must NOT use the pending-mode phrasing.
    assert "pending boundary scope" not in detail


# ---------------------------------------------------------------------------
# 200 — pending mode
# ---------------------------------------------------------------------------


def test_sweep_pending_mode_writes_sweeprun_with_null_workbook(app_client):
    """Happy path for pending mode: host tokens drive the sweep, SweepRun
    persists with workbook_id NULL and system_context_id set so a future
    promote can backfill the workbook id without losing telemetry."""
    tc, engine, state = app_client
    ctx_id = _make_pending_context(engine)

    state["fingerprint"] = BoundaryFingerprint(
        host_tokens=frozenset({"server01", "host42"}),
    )

    r = tc.post(
        "/api/sharepoint/sweep",
        json={"system_context_id": ctx_id, "max_candidates": 50},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["workbook_id"] is None
    assert body["system_context_id"] == ctx_id
    assert body["candidates"] == []

    # SweepRun row must reflect pending attribution.
    with Session(engine) as s:
        runs = s.exec(select(SweepRun)).all()
        assert len(runs) == 1
        run = runs[0]
        assert run.workbook_id is None
        assert run.system_context_id == ctx_id


# ---------------------------------------------------------------------------
# 200 — workbook mode
# ---------------------------------------------------------------------------


def test_sweep_workbook_mode_bumps_workbook_counters(app_client, tmp_path):
    """Workbook-bound sweep increments sweep_attempts and total_sweep_cost_usd.

    Pending sweeps deliberately skip this bump (workbook is None); the
    bump moves over at promote time. Pinning both branches keeps that
    asymmetry from drifting.
    """
    tc, engine, state = app_client
    wb_id = _make_workbook(engine, tmp_path)

    state["fingerprint"] = BoundaryFingerprint(
        in_scope_control_ids=frozenset({"ac-2"}),
        control_families=frozenset({"AC"}),
    )

    r = tc.post(
        "/api/sharepoint/sweep",
        json={"workbook_id": wb_id, "max_candidates": 50},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["workbook_id"] == wb_id

    with Session(engine) as s:
        runs = s.exec(select(SweepRun)).all()
        assert len(runs) == 1
        assert runs[0].workbook_id == wb_id

        wb = s.get(Workbook, wb_id)
        assert wb is not None
        # sweep_judge_enabled is False in the stub so llm_cost is 0.0
        # — assert the counter ticked even though cost is zero. That's
        # the only way the "this workbook has been swept N times"
        # display works after a cheap sweep.
        assert (wb.sweep_attempts or 0) == 1
