"""Tests for sweep pre-credit — flagging candidates already in ``Evidence``.

Pins two contracts:

1. :func:`normalize_sp_candidate_uri` produces a single canonical
   ``sharepoint://host/<server-relative-url>`` URI regardless of whether the
   caller passed the candidate path with or without leading slashes, with or
   without library/folder prefixes baked in. Pre-credit is a string-equality
   lookup against the unique-indexed ``Evidence.path`` column — drift in
   normalization silently turns "already in evidence" into "looks new" and
   re-pre-checks the row in the triage dialog.

2. The sweep route's batched ``Evidence.path IN (…)`` lookup populates
   ``already_in_evidence`` / ``existing_evidence_id`` on the response
   candidates. Empty match set leaves both fields at their dataclass
   defaults (``False`` / ``None``); the response must never claim a
   candidate is pre-credited when no Evidence row exists.

Reuses the same TestClient + monkeypatched ``SharePointSource`` /
``build_boundary_fingerprint`` pattern as
``tests/routes/test_sharepoint_sweep.py`` — the candidate fixture flows
through the real route (single source of truth for the IN-lookup logic).
"""

from __future__ import annotations

import sys
from dataclasses import replace
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
from cybersecurity_assessor.evidence.sources.sweep import (  # noqa: E402
    BoundaryFingerprint,
    SweepCandidate,
    SweepResult,
    normalize_sp_candidate_uri,
)
from cybersecurity_assessor.models import (  # noqa: E402
    Evidence,
    EvidenceKind,
    Workbook,
)
from cybersecurity_assessor.routes import sharepoint as sharepoint_route  # noqa: E402
from cybersecurity_assessor.server import create_app  # noqa: E402


_SITE_URL = "https://example.sharepoint.com/sites/test"


# ---------------------------------------------------------------------------
# normalize_sp_candidate_uri — pure unit tests
# ---------------------------------------------------------------------------


def test_uri_normalization_strips_leading_slash():
    """Candidate path with or without a leading slash → same canonical URI.

    The sweep walker hands back ``SweepCandidate.path`` already stripped,
    but defensive callers (and historical fixtures) sometimes include the
    leading slash. Both must collapse to a single Evidence.path match.
    """
    with_slash = normalize_sp_candidate_uri(
        "/Policies/SSP.docx", _SITE_URL, "Shared Documents", folder_path=""
    )
    without_slash = normalize_sp_candidate_uri(
        "Policies/SSP.docx", _SITE_URL, "Shared Documents", folder_path=""
    )
    assert with_slash == without_slash


def test_uri_normalization_collapses_folder_slashes():
    """folder_path with leading/trailing slashes collapses to the same URI."""
    bare = normalize_sp_candidate_uri(
        "SSP.docx", _SITE_URL, "Shared Documents", folder_path="Policies"
    )
    leading = normalize_sp_candidate_uri(
        "SSP.docx", _SITE_URL, "Shared Documents", folder_path="/Policies"
    )
    trailing = normalize_sp_candidate_uri(
        "SSP.docx", _SITE_URL, "Shared Documents", folder_path="Policies/"
    )
    both = normalize_sp_candidate_uri(
        "SSP.docx", _SITE_URL, "Shared Documents", folder_path="/Policies/"
    )
    assert bare == leading == trailing == both


def test_uri_normalization_default_library():
    """``library=None`` defaults to ``"Documents"`` to match SharePointSource."""
    explicit = normalize_sp_candidate_uri(
        "SSP.docx", _SITE_URL, "Documents", folder_path=""
    )
    default = normalize_sp_candidate_uri(
        "SSP.docx", _SITE_URL, None, folder_path=""
    )
    assert explicit == default


def test_uri_normalization_url_encodes_spaces():
    """Spaces in library / path must URL-encode to ``%20`` — Evidence.path
    is the URL-encoded form (per ``sharepoint._sharepoint_uri``)."""
    uri = normalize_sp_candidate_uri(
        "Boundary Diagram.pdf", _SITE_URL, "Shared Documents", folder_path=""
    )
    assert "Shared%20Documents" in uri
    assert "Boundary%20Diagram.pdf" in uri
    assert uri.startswith("sharepoint://example.sharepoint.com/")


def test_uri_normalization_empty_folder_omits_segment():
    """folder_path empty/None → URI has only library and candidate parts."""
    none_form = normalize_sp_candidate_uri(
        "SSP.docx", _SITE_URL, "Shared Documents", folder_path=None
    )
    empty_form = normalize_sp_candidate_uri(
        "SSP.docx", _SITE_URL, "Shared Documents", folder_path=""
    )
    assert none_form == empty_form
    # Sanity: no doubled slash from missing folder.
    assert "//" not in none_form.removeprefix("sharepoint://")


# ---------------------------------------------------------------------------
# Route-level pre-credit integration
# ---------------------------------------------------------------------------


@pytest.fixture
def app_client(monkeypatch: pytest.MonkeyPatch):
    """TestClient with sweep dependencies stubbed at the route module.

    Mirrors the fixture in ``tests/routes/test_sharepoint_sweep.py`` — we
    deliberately exercise the real ``normalize_sp_candidate_uri`` +
    Evidence IN-lookup inside the route, only stubbing the upstream Graph
    surface (config, token, walker, fingerprint) so the test stays
    hermetic.

    ``state["candidates"]`` is the tuple the stub source returns — each
    test overwrites it before POSTing.
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

    from cybersecurity_assessor import config as cfg_mod

    cfg_stub = cfg_mod.AppConfig(
        sharepoint_site_url=_SITE_URL,
        sharepoint_library="Shared Documents",
        sharepoint_folder_path="",
        sharepoint_priority_links=[],
        sweep_judge_enabled=False,
        sweep_cost_cap_usd=0.0,
    )
    monkeypatch.setattr(sharepoint_route.cfg, "load_config", lambda: cfg_stub)
    monkeypatch.setattr(
        sharepoint_route,
        "_acquire_graph_token_for_sweep",
        lambda _site_url: {"ok": True},
    )

    state: dict = {"candidates": tuple()}

    class _StubSource:
        def __init__(self, *, site_url, library, folder_path):
            self.site_url = site_url
            self.library = library
            self.folder_path = folder_path

        def sweep_for_boundary(self, fingerprint, **_kwargs) -> SweepResult:
            return SweepResult(
                scan_root=self.folder_path or "/",
                workbook_id=fingerprint.workbook_id,
                system_context_id=fingerprint.system_context_id,
                candidates=state["candidates"],
                families_skipped_by_crm=tuple(),
                truncated=False,
                elapsed_ms=1,
                weights_version_id=None,
                fingerprint_snapshot=fingerprint.to_snapshot_dict(),
            )

    monkeypatch.setattr(sharepoint_route, "SharePointSource", _StubSource)

    def _stub_fingerprint(*, session, workbook_id, system_context_id, priority_links):
        # Non-empty fingerprint so the route's "no signals" 422 branch
        # doesn't fire — pre-credit only runs on the 200 path.
        return BoundaryFingerprint(
            workbook_id=workbook_id,
            system_context_id=system_context_id,
            host_tokens=frozenset({"server01"}),
        )

    monkeypatch.setattr(
        sharepoint_route, "build_boundary_fingerprint", _stub_fingerprint
    )

    app = create_app()
    app.dependency_overrides[get_session] = _override_get_session

    yield TestClient(app), engine, state
    app.dependency_overrides.clear()


def _make_workbook(engine, tmp_path: Path) -> int:
    p = tmp_path / "demo.xlsx"
    p.write_bytes(b"x")
    with Session(engine) as s:
        wb = Workbook(path=str(p), filename=p.name)
        s.add(wb)
        s.commit()
        s.refresh(wb)
        return wb.id


def _candidate(name: str, path: str) -> SweepCandidate:
    return SweepCandidate(
        name=name,
        path=path,
        web_url=f"https://example.sharepoint.com/{path}",
        size=1024,
        modified="2026-06-01T00:00:00Z",
        score=0.75,
        matched_signals=("host:server01",),
        proposed_ccis=("ac-2",),
        snippet=None,
        download_url=None,
    )


def test_already_in_evidence_flagged(app_client, tmp_path):
    """Sweep candidate whose canonical URI is already in Evidence → flagged.

    Seeds an Evidence row at the exact ``sharepoint://...`` URI that
    ``normalize_sp_candidate_uri`` builds for the candidate, then asserts
    the response carries ``already_in_evidence=true`` and the matching
    ``existing_evidence_id``.
    """
    tc, engine, state = app_client
    wb_id = _make_workbook(engine, tmp_path)

    # The library + empty folder_path on the stubbed AppConfig drive the
    # URI shape — keep this in sync with the cfg_stub above.
    pre_credited_uri = normalize_sp_candidate_uri(
        "Policies/SSP.docx",
        _SITE_URL,
        "Shared Documents",
        folder_path="",
    )

    with Session(engine) as s:
        ev = Evidence(
            path=pre_credited_uri,
            sha256="cafe" * 16,
            kind=EvidenceKind.PDF,
            size_bytes=1024,
        )
        s.add(ev)
        s.commit()
        s.refresh(ev)
        ev_id = ev.id

    state["candidates"] = (
        _candidate("SSP.docx", "Policies/SSP.docx"),
        _candidate("NewDoc.docx", "Policies/NewDoc.docx"),
    )

    r = tc.post(
        "/api/sharepoint/sweep",
        json={"workbook_id": wb_id, "max_candidates": 50},
    )
    assert r.status_code == 200, r.text
    by_name = {c["name"]: c for c in r.json()["candidates"]}

    assert by_name["SSP.docx"]["already_in_evidence"] is True
    assert by_name["SSP.docx"]["existing_evidence_id"] == ev_id

    # Non-credited candidate must stay at the dataclass defaults.
    assert by_name["NewDoc.docx"]["already_in_evidence"] is False
    assert by_name["NewDoc.docx"]["existing_evidence_id"] is None


def test_uri_normalization_handles_url_variants(app_client, tmp_path):
    """Candidate path variants (with/without leading slash) still match.

    Seeds Evidence once at the canonical URI, then submits the same
    candidate path with a leading slash. The route normalizes both
    forms to the same Evidence.path so pre-credit fires either way.
    """
    tc, engine, state = app_client
    wb_id = _make_workbook(engine, tmp_path)

    canonical_uri = normalize_sp_candidate_uri(
        "Policies/SSP.docx",
        _SITE_URL,
        "Shared Documents",
        folder_path="",
    )
    with Session(engine) as s:
        ev = Evidence(
            path=canonical_uri,
            sha256="dead" * 16,
            kind=EvidenceKind.PDF,
            size_bytes=2048,
        )
        s.add(ev)
        s.commit()

    # Note the leading slash — the walker shouldn't emit this but defensive
    # normalization must collapse it to the same canonical URI.
    state["candidates"] = (_candidate("SSP.docx", "/Policies/SSP.docx"),)

    r = tc.post(
        "/api/sharepoint/sweep",
        json={"workbook_id": wb_id, "max_candidates": 50},
    )
    assert r.status_code == 200, r.text
    cand = r.json()["candidates"][0]
    assert cand["already_in_evidence"] is True, (
        "leading-slash candidate path should normalize to the same "
        "Evidence.path and surface the pre-credit flag"
    )


def test_no_match_means_false(app_client, tmp_path):
    """Fresh Evidence table → every candidate has the default flags.

    The IN-lookup short-circuits on an empty match set (the route skips
    the ``dataclasses.replace`` loop entirely). Pin the dataclass-default
    values so a future refactor that "helpfully" defaults to ``True``
    fails here.
    """
    tc, engine, state = app_client
    wb_id = _make_workbook(engine, tmp_path)

    state["candidates"] = (
        _candidate("A.docx", "Policies/A.docx"),
        _candidate("B.pdf", "Policies/B.pdf"),
    )

    r = tc.post(
        "/api/sharepoint/sweep",
        json={"workbook_id": wb_id, "max_candidates": 50},
    )
    assert r.status_code == 200, r.text
    for cand in r.json()["candidates"]:
        assert cand["already_in_evidence"] is False
        assert cand["existing_evidence_id"] is None
