"""Wire-shape + per-workbook isolation pins for GET /api/supersession/chains.

The endpoint surfaces auto-detected document supersessions (an older
Evidence row chained to a newer one via ``superseded_by_id``) for a single
workbook. These tests pin:

- the response shape (legacy / current / kind / *_evidence_id),
- per-workbook scoping: a chain seeded under workbook A must NOT appear
  under workbook B,
- the empty-state (a workbook with no superseded evidence returns []).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.db import get_session  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Evidence,
    EvidenceKind,
    Workbook,
)
from cybersecurity_assessor.server import create_app  # noqa: E402


@pytest.fixture
def client(tmp_path: Path) -> Iterator[tuple[TestClient, int, int]]:
    """TestClient + (workbook_a_id, workbook_b_id).

    Workbook A is seeded with a Rev A → Rev B supersession chain (same
    doc_number); workbook B has none, so it exercises the isolation +
    empty-state assertions.
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
        wb_a = Workbook(path=str(tmp_path / "a.xlsx"), filename="a.xlsx")
        wb_b = Workbook(path=str(tmp_path / "b.xlsx"), filename="b.xlsx")
        s.add_all([wb_a, wb_b])
        s.commit()
        s.refresh(wb_a)
        s.refresh(wb_b)
        wb_a_id, wb_b_id = wb_a.id, wb_b.id

        # Rev B (current) then Rev A (superseded), both scoped to workbook A.
        rev_b = Evidence(
            path="file:///a/USD20260601_rev_b.pdf",
            sha256="b" * 64,
            kind=EvidenceKind.PDF,
            size_bytes=1,
            title="Account Mgmt Procedure Manual Rev B",
            doc_number="USD20260601",
            workbook_id=wb_a_id,
        )
        s.add(rev_b)
        s.commit()
        s.refresh(rev_b)

        rev_a = Evidence(
            path="file:///a/USD20260601_rev_a.pdf",
            sha256="a" * 64,
            kind=EvidenceKind.PDF,
            size_bytes=1,
            title="Account Mgmt Procedure Manual Rev A",
            doc_number="USD20260601",
            workbook_id=wb_a_id,
            superseded_by_id=rev_b.id,
        )
        s.add(rev_a)
        s.commit()

    yield TestClient(app), wb_a_id, wb_b_id

    app.dependency_overrides.clear()


def test_chains_returns_detected_supersession_for_workbook(client) -> None:
    tc, wb_a, _ = client
    r = tc.get(f"/api/supersession/chains?workbook_id={wb_a}")
    assert r.status_code == 200, r.text
    rows = r.json()
    # The doc_number candidate is emitted (title==current-ref is skipped only
    # when identical; here doc_number is the unambiguous match).
    assert any(row["current"] == "USD20260601" for row in rows)
    row = next(row for row in rows if row["current"] == "USD20260601")
    assert row["kind"] in {"doc_number", "title"}
    assert isinstance(row["stale_evidence_id"], int)
    assert isinstance(row["current_evidence_id"], int)
    assert row["stale_evidence_id"] != row["current_evidence_id"]


def test_chains_are_scoped_per_workbook(client) -> None:
    """The chain seeded under workbook A must NOT leak into workbook B."""
    tc, _, wb_b = client
    r = tc.get(f"/api/supersession/chains?workbook_id={wb_b}")
    assert r.status_code == 200, r.text
    assert r.json() == []
