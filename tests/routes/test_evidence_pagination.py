"""GET /api/evidence pagination (Bug D).

The Evidence page previously showed only a truncated window. The route now
takes ``offset`` (in addition to ``limit``) and returns the pre-limit total
match count in the ``X-Total-Count`` header so the UI can render page N of M.
These tests pin: total header correctness, offset/limit windowing, and stable
``ingested_at DESC`` ordering across pages.

Collected via testpaths=["../tests"].
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from cybersecurity_assessor import models  # noqa: F401 -- register tables
from cybersecurity_assessor.db import get_session
from cybersecurity_assessor.models import Evidence, EvidenceKind, Workbook
from cybersecurity_assessor.server import create_app


@pytest.fixture
def client_and_wb():
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

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with Session(engine) as s:
        wb = Workbook(path="wb.xlsx", filename="wb.xlsx", baseline_id=None)
        s.add(wb)
        s.commit()
        s.refresh(wb)
        # 25 evidence rows, ascending ingested_at so DESC order is well-defined.
        for i in range(25):
            s.add(
                Evidence(
                    path=f"file:///ev/{i:02d}.txt",
                    sha256=f"sha{i:02d}",
                    kind=EvidenceKind.TEXT,
                    size_bytes=10,
                    title=f"ev{i:02d}",
                    workbook_id=wb.id,
                    ingested_at=base + timedelta(minutes=i),
                )
            )
        s.commit()
        wb_id = wb.id

    return TestClient(app), wb_id


def test_total_count_header_reports_full_match_set(client_and_wb):
    client, wb_id = client_and_wb
    r = client.get(f"/api/evidence?workbook_id={wb_id}&limit=10&offset=0")
    assert r.status_code == 200
    assert r.headers.get("X-Total-Count") == "25"
    assert len(r.json()) == 10  # limited page


def test_offset_windows_without_overlap(client_and_wb):
    client, wb_id = client_and_wb
    p1 = client.get(f"/api/evidence?workbook_id={wb_id}&limit=10&offset=0").json()
    p2 = client.get(f"/api/evidence?workbook_id={wb_id}&limit=10&offset=10").json()
    p3 = client.get(f"/api/evidence?workbook_id={wb_id}&limit=10&offset=20").json()
    assert len(p1) == 10 and len(p2) == 10 and len(p3) == 5  # 25 total
    ids = [e["id"] for e in (p1 + p2 + p3)]
    assert len(ids) == len(set(ids)) == 25  # no overlap, full coverage


def test_descending_order_is_stable_across_pages(client_and_wb):
    client, wb_id = client_and_wb
    p1 = client.get(f"/api/evidence?workbook_id={wb_id}&limit=10&offset=0").json()
    p2 = client.get(f"/api/evidence?workbook_id={wb_id}&limit=10&offset=10").json()
    # Newest first: ev24 ... ev00. Page 1 starts at the newest title.
    assert p1[0]["title"] == "ev24"
    # Page 2 continues strictly after page 1's last row (no gap, no repeat).
    titles = [e["title"] for e in (p1 + p2)]
    assert titles == sorted(titles, reverse=True)


def test_offset_past_end_returns_empty_but_total_intact(client_and_wb):
    client, wb_id = client_and_wb
    r = client.get(f"/api/evidence?workbook_id={wb_id}&limit=10&offset=100")
    assert r.status_code == 200
    assert r.json() == []
    assert r.headers.get("X-Total-Count") == "25"


# --- Free-text search (?q=) -------------------------------------------------
#
# The Evidence page gained a server-side search box that filters by filename
# (derived from ``path``), ``title``, and ``doc_number``. These tests pin:
# the filter narrows BOTH the returned rows AND X-Total-Count, is
# case-insensitive, matches across all three columns, tolerates NULL
# title/doc_number, and composes with offset/limit.


@pytest.fixture
def client_and_wb_search():
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

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with Session(engine) as s:
        wb = Workbook(path="wb.xlsx", filename="wb.xlsx", baseline_id=None)
        s.add(wb)
        s.commit()
        s.refresh(wb)
        # Distinct rows so each column-match assertion is unambiguous.
        rows = [
            # path-only match for "firewall"
            dict(path="file:///ev/Firewall-Config.txt", title="Network policy", doc_number=None),
            # title-only match for "firewall"
            dict(path="file:///ev/scan-001.txt", title="FIREWALL ruleset review", doc_number=None),
            # doc_number-only match for "usd00050010"
            dict(path="file:///ev/cdrl-a.txt", title="CDRL deliverable", doc_number="USD00050010"),
            # nothing matches "firewall"/"usd0005" — control row, NULL title+doc
            dict(path="file:///ev/random.txt", title=None, doc_number=None),
        ]
        for i, r in enumerate(rows):
            s.add(
                Evidence(
                    path=r["path"],
                    sha256=f"shaS{i:02d}",
                    kind=EvidenceKind.TEXT,
                    size_bytes=10,
                    title=r["title"],
                    doc_number=r["doc_number"],
                    workbook_id=wb.id,
                    ingested_at=base + timedelta(minutes=i),
                )
            )
        s.commit()
        wb_id = wb.id

    return TestClient(app), wb_id


def test_q_filters_rows_and_total_across_columns(client_and_wb_search):
    client, wb_id = client_and_wb_search
    # "firewall" hits the path row AND the title row, not the doc/NULL rows.
    r = client.get(f"/api/evidence?workbook_id={wb_id}&q=firewall")
    assert r.status_code == 200
    body = r.json()
    paths = {e["path"] for e in body}
    assert paths == {
        "file:///ev/Firewall-Config.txt",
        "file:///ev/scan-001.txt",
    }
    # X-Total-Count reflects the filtered match set, not the table size.
    assert r.headers.get("X-Total-Count") == "2"


def test_q_is_case_insensitive(client_and_wb_search):
    client, wb_id = client_and_wb_search
    lower = client.get(f"/api/evidence?workbook_id={wb_id}&q=firewall")
    upper = client.get(f"/api/evidence?workbook_id={wb_id}&q=FIREWALL")
    mixed = client.get(f"/api/evidence?workbook_id={wb_id}&q=FireWall")
    sets = [{e["id"] for e in resp.json()} for resp in (lower, upper, mixed)]
    assert sets[0] == sets[1] == sets[2]
    assert len(sets[0]) == 2


def test_q_matches_doc_number_column(client_and_wb_search):
    client, wb_id = client_and_wb_search
    r = client.get(f"/api/evidence?workbook_id={wb_id}&q=usd00050010")
    body = r.json()
    assert len(body) == 1
    assert body[0]["doc_number"] == "USD00050010"
    assert r.headers.get("X-Total-Count") == "1"


def test_q_composes_with_offset_and_limit(client_and_wb_search):
    client, wb_id = client_and_wb_search
    # Two rows match "firewall"; page them one at a time. Total stays 2 on
    # every page; the two single-row pages are disjoint and cover the match set.
    p1 = client.get(
        f"/api/evidence?workbook_id={wb_id}&q=firewall&limit=1&offset=0"
    )
    p2 = client.get(
        f"/api/evidence?workbook_id={wb_id}&q=firewall&limit=1&offset=1"
    )
    assert p1.headers.get("X-Total-Count") == "2"
    assert p2.headers.get("X-Total-Count") == "2"
    assert len(p1.json()) == 1 and len(p2.json()) == 1
    ids = {p1.json()[0]["id"], p2.json()[0]["id"]}
    assert len(ids) == 2  # no overlap


def test_q_no_match_returns_empty_with_zero_total(client_and_wb_search):
    client, wb_id = client_and_wb_search
    r = client.get(f"/api/evidence?workbook_id={wb_id}&q=zzz-nope")
    assert r.status_code == 200
    assert r.json() == []
    assert r.headers.get("X-Total-Count") == "0"
