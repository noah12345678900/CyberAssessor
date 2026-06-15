"""Pin POST /api/evidence/ingest-file behavior, esp. on re-add (dedup-hit).

Regression target: user reported Sweep Context drag-drop "failed" when
attaching documents already present in Evidence (file already ingested
via the Evidence folder sweep). The dedup-hit branch in
``ingest_single_local_file`` returns the existing row; the route must
stamp boundary fields on it and return success — not 4xx, not 500.

Covers:
1. First-add of a brand-new file with is_boundary_doc=True
2. Re-add of an existing Evidence row (URI-dedup hit)
3. Re-add of an existing row with different workbook_id (re-targeting)
"""

from __future__ import annotations

import sys
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
from cybersecurity_assessor.models import Workbook  # noqa: E402
from cybersecurity_assessor.server import create_app  # noqa: E402


@pytest.fixture
def client_and_session(tmp_path: Path):
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
        wb = Workbook(filename="ssp-pilot.xlsx", path=str(tmp_path / "ssp.xlsx"))
        s.add(wb)
        s.commit()
        s.refresh(wb)
        wb_id = wb.id

    client = TestClient(app)
    yield client, engine, wb_id, tmp_path


def _write_docx_stub(p: Path) -> None:
    """Minimal payload — extractor may ExtractorError; that's fine, route
    still persists an Evidence row per ``ingest_source``'s ExtractorError
    branch (empty text + error in metadata)."""
    p.write_bytes(b"PK\x03\x04stub-not-a-real-docx")


def test_ingest_file_first_add_with_boundary_flag(client_and_session):
    client, _engine, wb_id, tmp_path = client_and_session
    doc = tmp_path / "system_description.docx"
    _write_docx_stub(doc)

    res = client.post(
        "/api/evidence/ingest-file",
        json={
            "path": str(doc),
            "is_boundary_doc": True,
            "boundary_doc_kind": "SSP",
            "workbook_id": wb_id,
        },
    )
    assert res.status_code == 200, res.text
    ev = res.json()
    assert ev["is_boundary_doc"] is True
    assert ev["boundary_doc_kind"] == "SSP"
    assert ev["workbook_id"] == wb_id


def test_ingest_file_re_add_existing_evidence_succeeds(client_and_session):
    """Re-add of a file already in Evidence must return 200 with stamped flags."""
    client, _engine, wb_id, tmp_path = client_and_session
    doc = tmp_path / "ssp.docx"
    _write_docx_stub(doc)

    # First add — vanilla, no boundary flag. workbook_id is required (PR 2
    # per-workbook hard-scoping); a None here is a 400, so scope to wb_id.
    r1 = client.post(
        "/api/evidence/ingest-file",
        json={"path": str(doc), "is_boundary_doc": False, "workbook_id": wb_id},
    )
    assert r1.status_code == 200, r1.text
    first = r1.json()
    assert first["is_boundary_doc"] is False
    assert first["workbook_id"] == wb_id
    first_id = first["id"]

    # Second add — same file, now flagged as boundary doc for wb_id.
    r2 = client.post(
        "/api/evidence/ingest-file",
        json={
            "path": str(doc),
            "is_boundary_doc": True,
            "boundary_doc_kind": "SSP",
            "workbook_id": wb_id,
        },
    )
    assert r2.status_code == 200, r2.text
    second = r2.json()
    assert second["id"] == first_id, "should reuse the existing Evidence row, not create a new one"
    assert second["is_boundary_doc"] is True
    assert second["boundary_doc_kind"] == "SSP"
    assert second["workbook_id"] == wb_id


def test_ingest_file_requires_workbook_id(client_and_session):
    """Omitting (or nulling) workbook_id is a 400 — per-workbook hard-scoping.

    PR 2 made evidence strictly per-workbook: a single-file ingest with no
    open workbook is rejected up front rather than landing an orphan row.
    Pins the contract that used to be implicit in the re-add test's first
    add before it was scoped to a real workbook.
    """
    client, _engine, _wb_id, tmp_path = client_and_session
    doc = tmp_path / "orphan.docx"
    _write_docx_stub(doc)

    r = client.post(
        "/api/evidence/ingest-file",
        json={"path": str(doc), "is_boundary_doc": False, "workbook_id": None},
    )
    assert r.status_code == 400, r.text
    assert "workbook_id is required" in r.json()["detail"].lower()


def test_ingest_file_re_add_from_sweep_context_ui_payload(client_and_session):
    """Reproduce the exact UI payload from SweepContext.tsx submitPath.

    UI sends ONLY {path, is_boundary_doc:true, workbook_id}; it does NOT
    send boundary_doc_kind (Sweep Context has no kind selector per the
    minimal UX). On a dedup hit, the existing row's boundary_doc_kind
    must not get clobbered to NULL if it was previously set.
    """
    client, _engine, wb_id, tmp_path = client_and_session
    doc = tmp_path / "network-diagram.docx"
    _write_docx_stub(doc)

    # Round 1: caller stamps a kind (e.g. through a different UI surface).
    r1 = client.post(
        "/api/evidence/ingest-file",
        json={
            "path": str(doc),
            "is_boundary_doc": True,
            "boundary_doc_kind": "Network Diagram",
            "workbook_id": wb_id,
        },
    )
    assert r1.status_code == 200, r1.text
    assert r1.json()["boundary_doc_kind"] == "Network Diagram"

    # Round 2: SweepContext drag-drop — payload has no boundary_doc_kind.
    r2 = client.post(
        "/api/evidence/ingest-file",
        json={
            "path": str(doc),
            "is_boundary_doc": True,
            "workbook_id": wb_id,
        },
    )
    assert r2.status_code == 200, r2.text
    # Re-add via Sweep Context (which doesn't know the kind) must NOT
    # nuke the existing kind to NULL. The user already labeled it; we
    # preserve.
    assert r2.json()["boundary_doc_kind"] == "Network Diagram"
