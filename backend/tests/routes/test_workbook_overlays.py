"""Tests for the workbook-overlay attach endpoint.

Covers the positive case for attaching a sibling CCIS workbook as a
reference overlay. (The OSCAL_PROFILE rejection guard was removed when
the FedRAMP baseline loader was deleted — no current code path creates
``OSCAL_PROFILE`` baseline rows.)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

# Make the backend package importable from any pytest cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.db import get_session  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Baseline,
    BaselineSourceType,
    Framework,
    Workbook,
)
from cybersecurity_assessor.server import create_app  # noqa: E402


@pytest.fixture
def client(tmp_path: Path):
    """TestClient with an isolated in-memory SQLite via dep override.

    Avoids touching the developer's ~/.cybersecurity-assessor/app.db.
    The Workbook row needs a real file on disk for path validation
    downstream, so we drop a placeholder into tmp_path.
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

    # Seed: a framework, a workbook bound to that framework, and a sibling
    # CCIS_WORKBOOK baseline for the positive overlay-attach assertion.
    wb_path = tmp_path / "demo.xlsx"
    wb_path.write_bytes(b"x")

    with Session(engine) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5")
        s.add(fw)
        s.commit()
        s.refresh(fw)

        wb = Workbook(path=str(wb_path), filename=wb_path.name, framework_id=fw.id)
        s.add(wb)

        sibling_ccis = Baseline(
            framework_id=fw.id,
            name="Sibling system CCIS",
            source_type=BaselineSourceType.CCIS_WORKBOOK,
            source_ref=str(tmp_path / "sibling.xlsx"),
        )
        s.add(sibling_ccis)

        s.commit()
        s.refresh(wb)
        s.refresh(sibling_ccis)
        wb_id = wb.id
        sibling_id = sibling_ccis.id

    yield TestClient(app), wb_id, sibling_id

    app.dependency_overrides.clear()


def test_attach_ccis_workbook_overlay_succeeds(client) -> None:
    tc, wb_id, sibling_id = client
    r = tc.post(
        f"/api/workbooks/{wb_id}/overlays",
        json={"baseline_id": sibling_id, "note": "cross-reference"},
    )
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["workbook_id"] == wb_id
    assert payload["baseline_id"] == sibling_id
    assert payload["baseline"]["source_type"] == BaselineSourceType.CCIS_WORKBOOK.value


def test_workbook_catalog_endpoint_returns_framework_and_overlays(client) -> None:
    """``GET /api/workbooks/{id}/catalog`` returns the framework summary
    plus every attached baseline. Drives the per-workbook catalog detail
    panel on the Workbooks page (Stage 3 of the catalog-page consolidation).
    """
    tc, wb_id, sibling_id = client
    # Attach the sibling overlay first so the catalog endpoint has something
    # to enumerate.
    tc.post(
        f"/api/workbooks/{wb_id}/overlays",
        json={"baseline_id": sibling_id},
    )

    r = tc.get(f"/api/workbooks/{wb_id}/catalog")
    assert r.status_code == 200, r.text
    payload = r.json()

    assert payload["framework"] is not None
    assert payload["framework"]["name"] == "NIST SP 800-53"
    assert payload["framework"]["version"] == "Rev 5"
    # No controls or objectives seeded in this fixture — zero is fine, just
    # has to be an int.
    assert payload["framework"]["control_count"] == 0
    assert payload["framework"]["objective_count"] == 0

    attached = payload["attached_baselines"]
    assert len(attached) == 1
    assert attached[0]["baseline_id"] == sibling_id
    assert attached[0]["source_type"] == BaselineSourceType.CCIS_WORKBOOK.value
    # CCIS_WORKBOOK overlays don't have a RequirementSource — only
    # PROGRAM_CONTROLS overlays do.
    assert attached[0]["requirement_source"] is None


def test_workbook_catalog_endpoint_404_on_missing_workbook(client) -> None:
    tc, _, _ = client
    r = tc.get("/api/workbooks/9999/catalog")
    assert r.status_code == 404
