"""PATCH /api/evidence/{id}/boundary — named-boundary tagging.

Tags a host-bearing artifact (scan / checklist) with a named boundary / CRN so
the asset cross-check keys its hosts by (boundary, hostname). The route writes
through the EXISTING EvidenceBoundary link table (no schema change): get-or-
create a BoundarySegment for (workbook_id, name) and replace the evidence's
boundary link. These tests pin: link creation, get-or-create dedupe, re-tag
replacement, clear-on-empty, and the end-to-end effect on /crosscheck (two
same-named hosts in different boundaries stay distinct).

Collected via testpaths=["../tests"].
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from cybersecurity_assessor import models  # noqa: F401 -- register tables
from cybersecurity_assessor.db import get_session
from cybersecurity_assessor.models import (
    BoundarySegment,
    Evidence,
    EvidenceBoundary,
    EvidenceKind,
    Workbook,
)
from cybersecurity_assessor.server import create_app


@pytest.fixture
def ctx():
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
        wb = Workbook(path="wb.xlsx", filename="wb.xlsx", baseline_id=None)
        s.add(wb)
        s.commit()
        s.refresh(wb)
        wb_id = wb.id

        def _ev(path: str, hosts: list[str], title: str) -> int:
            ev = Evidence(
                path=path,
                sha256=f"sha:{path}",
                kind=EvidenceKind.NESSUS,
                size_bytes=10,
                title=title,
                workbook_id=wb_id,
                host_inventory=json.dumps(hosts),
            )
            s.add(ev)
            s.commit()
            s.refresh(ev)
            return ev.id

        ev_a = _ev("file:///boe/a.nessus", ["192.168.1.1"], "A")
        ev_b = _ev("file:///boe/b.nessus", ["192.168.1.1"], "B")

    return TestClient(app), engine, wb_id, ev_a, ev_b


def _segments(engine, wb_id):
    with Session(engine) as s:
        return s.exec(
            select(BoundarySegment).where(BoundarySegment.workbook_id == wb_id)
        ).all()


def _links(engine, ev_id):
    with Session(engine) as s:
        return s.exec(
            select(EvidenceBoundary).where(EvidenceBoundary.evidence_id == ev_id)
        ).all()


def test_tag_creates_segment_and_link(ctx):
    client, engine, wb_id, ev_a, _ = ctx
    r = client.patch(
        f"/api/evidence/{ev_a}/boundary",
        json={"boundary_name": "CRN-A", "workbook_id": wb_id},
    )
    assert r.status_code == 200
    segs = _segments(engine, wb_id)
    assert [seg.name for seg in segs] == ["CRN-A"]
    assert len(_links(engine, ev_a)) == 1


def test_same_name_reuses_one_segment(ctx):
    client, engine, wb_id, ev_a, ev_b = ctx
    client.patch(
        f"/api/evidence/{ev_a}/boundary",
        json={"boundary_name": "CRN-A", "workbook_id": wb_id},
    )
    client.patch(
        f"/api/evidence/{ev_b}/boundary",
        json={"boundary_name": "CRN-A", "workbook_id": wb_id},
    )
    # Two artifacts, ONE shared segment row (dedupe on (workbook_id, name)).
    assert len(_segments(engine, wb_id)) == 1
    assert len(_links(engine, ev_a)) == 1
    assert len(_links(engine, ev_b)) == 1


def test_retag_replaces_link(ctx):
    client, engine, wb_id, ev_a, _ = ctx
    client.patch(
        f"/api/evidence/{ev_a}/boundary",
        json={"boundary_name": "CRN-A", "workbook_id": wb_id},
    )
    client.patch(
        f"/api/evidence/{ev_a}/boundary",
        json={"boundary_name": "CRN-B", "workbook_id": wb_id},
    )
    links = _links(engine, ev_a)
    assert len(links) == 1  # single-valued: replaced, not accumulated
    with Session(engine) as s:
        seg = s.get(BoundarySegment, links[0].boundary_segment_id)
        assert seg.name == "CRN-B"


def test_empty_name_clears_link(ctx):
    client, engine, wb_id, ev_a, _ = ctx
    client.patch(
        f"/api/evidence/{ev_a}/boundary",
        json={"boundary_name": "CRN-A", "workbook_id": wb_id},
    )
    r = client.patch(
        f"/api/evidence/{ev_a}/boundary",
        json={"boundary_name": "", "workbook_id": wb_id},
    )
    assert r.status_code == 200
    assert _links(engine, ev_a) == []


def test_404_on_missing_evidence(ctx):
    client, _, wb_id, _, _ = ctx
    r = client.patch(
        "/api/evidence/999999/boundary",
        json={"boundary_name": "CRN-A", "workbook_id": wb_id},
    )
    assert r.status_code == 404


def test_crosscheck_reflects_boundary_split(ctx):
    client, _, wb_id, ev_a, ev_b = ctx
    client.patch(
        f"/api/evidence/{ev_a}/boundary",
        json={"boundary_name": "CRN-A", "workbook_id": wb_id},
    )
    client.patch(
        f"/api/evidence/{ev_b}/boundary",
        json={"boundary_name": "CRN-B", "workbook_id": wb_id},
    )
    r = client.get(f"/api/evidence/crosscheck?workbook_id={wb_id}")
    assert r.status_code == 200
    data = r.json()
    # The shared 192.168.1.1 now renders as TWO devices, one per boundary.
    pairs = sorted((h["boundary"], h["hostname"]) for h in data["hosts"])
    assert pairs == [("CRN-A", "192.168.1.1"), ("CRN-B", "192.168.1.1")]
    assert data["source_types"]["ips"] == 2
