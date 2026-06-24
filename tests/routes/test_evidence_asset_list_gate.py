"""PATCH /api/evidence/{id}/asset-list — content-gated declaration.

A spreadsheet may be flagged "declared authoritative" ONLY when the ingest
classifier actually parsed it as a host inventory (non-empty host_inventory).
This replaces the prior BLIND file-extension check that let any .xlsx — a
budget, a parts catalog — claim to be the authoritative boundary. Host-bearing
scan/checklist KINDS stay eligible regardless. These tests pin: accept an xlsx
WITH hosts, reject an xlsx WITHOUT hosts, accept a scan kind, reject a
non-inventory non-host artifact, and the host_count serialize field.

Collected via testpaths=["../tests"].
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from cybersecurity_assessor import models  # noqa: F401 -- register tables
from cybersecurity_assessor.db import get_session
from cybersecurity_assessor.models import Evidence, EvidenceKind, Workbook
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

        def _ev(
            path: str,
            kind: EvidenceKind,
            hosts: list[str] | None,
        ) -> int:
            ev = Evidence(
                path=path,
                sha256=f"sha:{path}",
                kind=kind,
                size_bytes=10,
                workbook_id=wb_id,
                host_inventory=json.dumps(hosts) if hosts is not None else None,
            )
            s.add(ev)
            s.commit()
            s.refresh(ev)
            return ev.id

        ids = {
            # spreadsheet the classifier parsed as an inventory (has hosts)
            "inv_with_hosts": _ev(
                "file:///boe/HWSW_Inventory.xlsx",
                EvidenceKind.XLSX,
                ["server01", "server02"],
            ),
            # spreadsheet with NO detectable host columns (budget/parts catalog)
            "budget_no_hosts": _ev(
                "file:///boe/Q3_Budget.xlsx", EvidenceKind.XLSX, []
            ),
            # spreadsheet with host_inventory never set (NULL)
            "sheet_null_hosts": _ev(
                "file:///boe/random.csv", EvidenceKind.TEXT, None
            ),
            # host-bearing scan kind — eligible regardless of host_inventory
            "scan": _ev("file:///boe/scan.nessus", EvidenceKind.NESSUS, []),
            # non-inventory, non-host artifact — never eligible
            "policy_pdf": _ev("file:///boe/policy.pdf", EvidenceKind.PDF, None),
        }

    return TestClient(app), wb_id, ids


def _set_asset_list(client, ev_id, on=True):
    return client.patch(
        f"/api/evidence/{ev_id}/asset-list",
        json={"is_asset_list": on},
    )


def test_inventory_xlsx_with_hosts_accepted(ctx):
    client, _, ids = ctx
    r = _set_asset_list(client, ids["inv_with_hosts"])
    assert r.status_code == 200
    assert r.json()["is_asset_list"] is True


def test_budget_xlsx_without_hosts_rejected(ctx):
    client, _, ids = ctx
    r = _set_asset_list(client, ids["budget_no_hosts"])
    assert r.status_code == 400
    assert "host" in r.json()["detail"].lower()


def test_null_host_inventory_spreadsheet_rejected(ctx):
    client, _, ids = ctx
    r = _set_asset_list(client, ids["sheet_null_hosts"])
    assert r.status_code == 400


def test_scan_kind_accepted_regardless_of_host_inventory(ctx):
    client, _, ids = ctx
    # Nessus scan with empty flat host_inventory is STILL eligible — its host
    # enumeration is intrinsic to the kind (findings carry hosts).
    r = _set_asset_list(client, ids["scan"])
    assert r.status_code == 200
    assert r.json()["is_asset_list"] is True


def test_non_inventory_non_host_artifact_rejected(ctx):
    client, _, ids = ctx
    r = _set_asset_list(client, ids["policy_pdf"])
    assert r.status_code == 400


def test_serialize_exposes_host_count(ctx):
    client, wb_id, ids = ctx
    rows = client.get(f"/api/evidence?workbook_id={wb_id}&limit=100").json()
    by_id = {e["id"]: e for e in rows}
    assert by_id[ids["inv_with_hosts"]]["host_count"] == 2
    assert by_id[ids["budget_no_hosts"]]["host_count"] == 0
    assert by_id[ids["sheet_null_hosts"]]["host_count"] == 0


def test_unset_always_allowed(ctx):
    client, _, ids = ctx
    # Clearing the flag must never be gated (only setting it is).
    r = _set_asset_list(client, ids["budget_no_hosts"], on=False)
    assert r.status_code == 200
    assert r.json()["is_asset_list"] is False
