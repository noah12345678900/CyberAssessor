"""Wire-shape pins for the scope CRUD endpoints.

Covers the three resource families on :mod:`cybersecurity_assessor.routes.scope`:

- ``/api/components``           — list / create / delete
- ``/api/assets``               — list / create / delete (idempotent on
                                  (workbook_id, hostname))
- ``/api/boundary-segments``    — list / create / delete (idempotent on
                                  (workbook_id, name))

Pins both the success shapes and the dedupe / cascade behaviors so a
future schema or serialization change has to be deliberate.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterator

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
    Asset,
    BoundarySegment,
    Component,
    ComponentAsset,
    EvidenceAsset,
    EvidenceBoundary,
    EvidenceComponent,
    Framework,
    Workbook,
)
from cybersecurity_assessor.server import create_app  # noqa: E402


@pytest.fixture
def client(tmp_path: Path) -> Iterator[tuple[TestClient, int, int]]:
    """TestClient + (workbook_id, other_workbook_id) for the seeded data.

    Seeds two workbooks under one framework so per-workbook scoping
    can be exercised (a Component in wb_a must not show up under wb_b).
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

    wb_a_path = tmp_path / "wb_a.xlsx"
    wb_b_path = tmp_path / "wb_b.xlsx"
    wb_a_path.write_bytes(b"x")
    wb_b_path.write_bytes(b"x")

    with Session(engine) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5")
        s.add(fw)
        s.commit()
        s.refresh(fw)

        wb_a = Workbook(path=str(wb_a_path), filename=wb_a_path.name, framework_id=fw.id)
        wb_b = Workbook(path=str(wb_b_path), filename=wb_b_path.name, framework_id=fw.id)
        s.add_all([wb_a, wb_b])
        s.commit()
        s.refresh(wb_a)
        s.refresh(wb_b)
        wb_a_id = wb_a.id
        wb_b_id = wb_b.id

    # The fixture yields the engine implicitly via the override so tests
    # that want to peek at side-effects can use a fresh Session().
    yield TestClient(app), wb_a_id, wb_b_id

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------


def test_create_component_returns_serialized_row(client) -> None:
    tc, wb_a, _ = client
    r = tc.post(
        "/api/components",
        json={"workbook_id": wb_a, "name": "Web Tier", "kind": "tier"},
    )
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["id"] is not None
    assert payload["workbook_id"] == wb_a
    assert payload["name"] == "Web Tier"
    assert payload["kind"] == "tier"
    assert payload["parent_component_id"] is None
    assert payload["created_at"] is not None


def test_create_component_rejects_unknown_workbook(client) -> None:
    tc, _, _ = client
    r = tc.post(
        "/api/components",
        json={"workbook_id": 9999, "name": "X", "kind": "other"},
    )
    assert r.status_code == 404


def test_create_component_rejects_cross_workbook_parent(client) -> None:
    tc, wb_a, wb_b = client
    parent = tc.post(
        "/api/components",
        json={"workbook_id": wb_a, "name": "Parent", "kind": "tier"},
    ).json()
    # Try to attach a child in wb_b that references a wb_a parent.
    r = tc.post(
        "/api/components",
        json={
            "workbook_id": wb_b,
            "name": "Child",
            "kind": "service",
            "parent_component_id": parent["id"],
        },
    )
    assert r.status_code == 400


def test_list_components_filters_by_workbook(client) -> None:
    tc, wb_a, wb_b = client
    tc.post("/api/components", json={"workbook_id": wb_a, "name": "A1", "kind": "tier"})
    tc.post("/api/components", json={"workbook_id": wb_a, "name": "A2", "kind": "tier"})
    tc.post("/api/components", json={"workbook_id": wb_b, "name": "B1", "kind": "tier"})

    a = tc.get(f"/api/components?workbook_id={wb_a}").json()
    b = tc.get(f"/api/components?workbook_id={wb_b}").json()
    assert sorted(c["name"] for c in a) == ["A1", "A2"]
    assert [c["name"] for c in b] == ["B1"]


def test_delete_component_is_idempotent(client) -> None:
    tc, wb_a, _ = client
    comp = tc.post(
        "/api/components",
        json={"workbook_id": wb_a, "name": "X", "kind": "tier"},
    ).json()

    r1 = tc.delete(f"/api/components/{comp['id']}")
    assert r1.status_code == 200
    assert r1.json() == {"deleted": True, "component_id": comp["id"]}

    r2 = tc.delete(f"/api/components/{comp['id']}")
    assert r2.status_code == 200
    assert r2.json() == {"deleted": False, "component_id": comp["id"]}


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


def test_create_asset_normalizes_hostname_to_lowercase(client) -> None:
    tc, wb_a, _ = client
    r = tc.post(
        "/api/assets",
        json={"workbook_id": wb_a, "hostname": "SERVER01"},
    )
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["hostname"] == "server01"
    assert payload["source"] == "manual"
    assert payload["asset_class"] == "other"


def test_create_asset_is_idempotent_on_workbook_hostname(client) -> None:
    """Re-POSTing the same (workbook, hostname) returns the existing row."""
    tc, wb_a, _ = client
    first = tc.post(
        "/api/assets",
        json={"workbook_id": wb_a, "hostname": "server01"},
    ).json()
    second = tc.post(
        "/api/assets",
        # Different casing should still match the lowercased existing row.
        json={"workbook_id": wb_a, "hostname": "Server01"},
    ).json()
    assert second["id"] == first["id"]


def test_create_asset_allows_same_hostname_in_different_workbook(client) -> None:
    tc, wb_a, wb_b = client
    a = tc.post(
        "/api/assets", json={"workbook_id": wb_a, "hostname": "server01"}
    ).json()
    b = tc.post(
        "/api/assets", json={"workbook_id": wb_b, "hostname": "server01"}
    ).json()
    assert a["id"] != b["id"]


def test_delete_asset_idempotent(client) -> None:
    tc, wb_a, _ = client
    a = tc.post(
        "/api/assets", json={"workbook_id": wb_a, "hostname": "h1"}
    ).json()
    r1 = tc.delete(f"/api/assets/{a['id']}")
    r2 = tc.delete(f"/api/assets/{a['id']}")
    assert r1.json() == {"deleted": True, "asset_id": a["id"]}
    assert r2.json() == {"deleted": False, "asset_id": a["id"]}


# ---------------------------------------------------------------------------
# Boundary segments
# ---------------------------------------------------------------------------


def test_create_boundary_segment_returns_serialized_row(client) -> None:
    tc, wb_a, _ = client
    r = tc.post(
        "/api/boundary-segments",
        json={"workbook_id": wb_a, "name": "DMZ", "kind": "dmz"},
    )
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["name"] == "DMZ"
    assert payload["kind"] == "dmz"
    assert payload["workbook_id"] == wb_a


def test_create_boundary_segment_is_idempotent_on_workbook_name(client) -> None:
    tc, wb_a, _ = client
    first = tc.post(
        "/api/boundary-segments",
        json={"workbook_id": wb_a, "name": "DMZ", "kind": "dmz"},
    ).json()
    second = tc.post(
        "/api/boundary-segments",
        json={"workbook_id": wb_a, "name": "DMZ", "kind": "internal"},
    ).json()
    # Existing row wins — second POST does NOT overwrite kind.
    assert second["id"] == first["id"]
    assert second["kind"] == "dmz"


def test_list_boundary_segments_filters_by_workbook(client) -> None:
    tc, wb_a, wb_b = client
    tc.post("/api/boundary-segments", json={"workbook_id": wb_a, "name": "DMZ"})
    tc.post("/api/boundary-segments", json={"workbook_id": wb_b, "name": "Internal"})

    a = tc.get(f"/api/boundary-segments?workbook_id={wb_a}").json()
    b = tc.get(f"/api/boundary-segments?workbook_id={wb_b}").json()
    assert [s["name"] for s in a] == ["DMZ"]
    assert [s["name"] for s in b] == ["Internal"]


def test_delete_boundary_segment_idempotent(client) -> None:
    tc, wb_a, _ = client
    seg = tc.post(
        "/api/boundary-segments",
        json={"workbook_id": wb_a, "name": "DMZ"},
    ).json()
    r1 = tc.delete(f"/api/boundary-segments/{seg['id']}")
    r2 = tc.delete(f"/api/boundary-segments/{seg['id']}")
    assert r1.json() == {"deleted": True, "segment_id": seg["id"]}
    assert r2.json() == {"deleted": False, "segment_id": seg["id"]}
