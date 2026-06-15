"""Tests for ``POST /api/baselines/crm/load`` response shape.

The route promotes two diagnostic counters out of the loader's loose
``notes`` dict — ``unknown_control_ids`` and ``unknown_responsibility_rows`` —
so the UI toast can name them separately. Before this split, the toast
labeled both failure modes with one message and silently dropped the
responsibility-miss count entirely.

These tests pin the typed response contract so a future loader refactor
or route signature change can't quietly re-bury the diagnostics.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from openpyxl import Workbook as XlsxWorkbook
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.db import get_session  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Baseline,
    BaselineControl,
    Control,
    Framework,
)
from cybersecurity_assessor.server import create_app  # noqa: E402


def _write_crm_xlsx(
    path: Path,
    rows: list[tuple[str, str, str]],
) -> None:
    """Write a minimal CRM-shaped xlsx at ``path``.

    Header row uses canonical labels that ``_locate_columns`` recognizes
    (``Control ID`` / ``Responsibility`` / ``Customer Responsibility``).
    Each row is ``(control_id, responsibility, narrative)``.
    """
    wb = XlsxWorkbook()
    ws = wb.active
    ws.append(["Control ID", "Responsibility", "Customer Responsibility"])
    for row in rows:
        ws.append(list(row))
    wb.save(path)


def _write_dual_scope_crm_xlsx(
    path: Path,
    rows: list[tuple[str, str, str, str, str]],
) -> None:
    """Write a dual-column CRM xlsx that exercises the cloud + on-prem split.

    Header uses the explicit ``Cloud Responsibility`` / ``On-Prem
    Responsibility`` synonyms the loader added for dual-scope CRMs
    (lucky-sleeping-parasol.md). Each row is
    ``(control_id, cloud_resp, cloud_narr, onprem_resp, onprem_narr)``.
    """
    wb = XlsxWorkbook()
    ws = wb.active
    ws.append(
        [
            "Control ID",
            "Cloud Responsibility",
            "Cloud Customer Responsibility",
            "On-Prem Responsibility",
            "On-Prem Customer Responsibility",
        ]
    )
    for row in rows:
        ws.append(list(row))
    wb.save(path)


@pytest.fixture
def client(tmp_path: Path):
    """TestClient + framework seeded with a single known control (AC-2)."""

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

        # One canonical OSCAL-id control. Catalog deliberately stops here so
        # the test can drive a "control not in catalog" miss against AC-99.
        s.add(
            Control(
                framework_id=fw.id,
                control_id="ac-2",
                title="Account Management",
                family="AC",
            )
        )
        s.commit()
        framework_id = fw.id

    yield TestClient(app), framework_id, tmp_path, engine

    app.dependency_overrides.clear()


def test_crm_load_response_promotes_failure_mode_counters(client) -> None:
    """The route surfaces ``unknown_control_ids`` and
    ``unknown_responsibility_rows`` as first-class fields, not buried in
    ``notes``. Catalog miss and responsibility miss are independent.
    """
    tc, framework_id, tmp, _engine = client
    crm_path = tmp / "vendor_crm.xlsx"
    _write_crm_xlsx(
        crm_path,
        rows=[
            # Happy path: in-catalog control, valid responsibility.
            ("AC-2", "Provider", "Vendor manages account lifecycle."),
            # Catalog miss: AC-99 doesn't exist in the loaded framework.
            ("AC-99", "Inherited", "Inherited from upstream platform."),
            # Responsibility miss: "Customr" is a typo, not in the map.
            ("AC-2(1)", "Customr", "Customer-owned with automation."),
        ],
    )

    r = tc.post(
        "/api/baselines/crm/load",
        json={"framework_id": framework_id, "path": str(crm_path)},
    )
    assert r.status_code == 200, r.text
    payload = r.json()

    # One row landed cleanly.
    assert payload["controls_in_scope"] == 1
    # Catalog miss bucket: AC-99 collected by OSCAL id, surfaced verbatim
    # so the user can grep their CRM and fix it.
    assert payload["controls_unknown"] == 1
    assert payload["unknown_control_ids"] == ["ac-99"]
    # Responsibility miss bucket: independent of catalog miss, must not be
    # collapsed into ``controls_unknown``.
    assert payload["unknown_responsibility_rows"] == 1
    # Legacy ``notes`` dict stays for forward-compat / debugging.
    assert isinstance(payload["notes"], dict)
    assert payload["notes"]["loader"] == "crm_xlsx"


def test_crm_load_clean_response_has_empty_diagnostic_lists(client) -> None:
    """A CRM with zero misses returns empty list / zero counter — the UI
    toast keys off these to decide whether to render diagnostic clauses,
    so the keys must be present (not omitted) on a clean upload.
    """
    tc, framework_id, tmp, _engine = client
    crm_path = tmp / "clean_crm.xlsx"
    _write_crm_xlsx(
        crm_path,
        rows=[("AC-2", "Provider", "Vendor-managed.")],
    )

    r = tc.post(
        "/api/baselines/crm/load",
        json={"framework_id": framework_id, "path": str(crm_path)},
    )
    assert r.status_code == 200, r.text
    payload = r.json()

    assert payload["controls_in_scope"] == 1
    assert payload["controls_unknown"] == 0
    assert payload["unknown_control_ids"] == []
    assert payload["unknown_responsibility_rows"] == 0


def test_crm_load_dual_column_populates_both_scopes(client) -> None:
    """End-to-end round-trip for the dual-scope CRM (lucky-sleeping-parasol.md
    verification step 3): a workbook carrying BOTH ``Cloud Responsibility``
    and ``On-Prem Responsibility`` columns must land BOTH ``responsibility``
    (cloud) and ``responsibility_onprem`` on the resulting ``BaselineControl``
    row, with the matching narratives on the *_narrative fields.

    Synthetic ``CrmEntry`` tests in ``test_assessor_dualscope_crm.py`` pin
    the engine behavior; this test pins the loader→DB path so a header-
    sniffing regression in ``_locate_columns`` (e.g. on-prem alias drift
    accidentally hitting the cloud bucket) can't silently collapse the
    two scopes back into one column.
    """
    tc, framework_id, tmp, engine = client
    crm_path = tmp / "dual_scope_crm.xlsx"
    _write_dual_scope_crm_xlsx(
        crm_path,
        rows=[
            (
                "AC-2",
                "Provider",
                "AWS manages IAM in GovCloud.",
                "Customer",
                "Local Active Directory owned by IT operations.",
            ),
        ],
    )

    r = tc.post(
        "/api/baselines/crm/load",
        json={"framework_id": framework_id, "path": str(crm_path)},
    )
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["controls_in_scope"] == 1
    assert payload["unknown_responsibility_rows"] == 0

    # Query the materialized BaselineControl row directly — the route's
    # response only returns counters, not per-control fields.
    with Session(engine) as s:
        baseline = s.exec(select(Baseline)).first()
        assert baseline is not None
        bc = s.exec(
            select(BaselineControl).where(BaselineControl.baseline_id == baseline.id)
        ).first()
        assert bc is not None, "dual-column CRM produced no BaselineControl row"

        # Cloud scope landed on the legacy field (renamed-in-spirit).
        assert bc.responsibility == "provider"
        assert bc.responsibility_narrative == "AWS manages IAM in GovCloud."
        # On-prem scope landed on the new field — the whole point of the slice.
        assert bc.responsibility_onprem == "customer"
        assert (
            bc.responsibility_onprem_narrative
            == "Local Active Directory owned by IT operations."
        )
