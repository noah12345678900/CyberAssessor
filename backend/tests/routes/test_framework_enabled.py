"""Tests for the framework display/selection gate (migration 0012).

The ``enabled`` flag is **presentation-only**. Flipping it:

  * changes what ``GET /api/catalog/frameworks`` reports (the flag is
    echoed; the row is never dropped — UI filters client-side), and
  * is idempotent, and 404s on a missing id.

The load-bearing invariant is that disabling a *parent* framework
(800-53 r5) must NOT corrupt a child framework's (FedRAMP HIGH) effective
catalog: ``list_controls`` resolves inherited rows by parent id, not by
``enabled``, so a disabled parent's Control rows still merge into the
enabled child. This file pins that with a parent/child pair plus an
inherited objective, asserting the child's control listing is unchanged
after the parent is toggled off.
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
from cybersecurity_assessor.models import (  # noqa: E402
    Control,
    Framework,
    Objective,
)
from cybersecurity_assessor.server import create_app  # noqa: E402


@pytest.fixture
def seeded(tmp_path: Path):
    """TestClient + ids for a parent (r5) and child (FedRAMP) framework.

    The parent owns one Control + one CCI objective; the child has
    ``parent_framework_id`` pointing at the parent so the inheritance
    merge in ``list_controls`` has something to surface.
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
        parent = Framework(
            name="NIST SP 800-53",
            version="Rev 5",
            oscal_uri="https://example/NIST_SP-800-53_rev5_catalog.json",
        )
        s.add(parent)
        s.commit()
        s.refresh(parent)

        control = Control(
            framework_id=parent.id, control_id="ac-2", title="AC-2", family="AC"
        )
        s.add(control)
        s.commit()
        s.refresh(control)

        s.add(
            Objective(
                control_id_fk=control.id,
                objective_id="CCI-000015",
                source="CCI",
                text="Account management automation.",
            )
        )

        child = Framework(
            name="FedRAMP",
            version="Rev 5 HIGH",
            oscal_uri="https://example/FedRAMP_rev5_HIGH-baseline.json",
            parent_framework_id=parent.id,
        )
        s.add(child)
        s.commit()
        s.refresh(child)

        parent_id = parent.id
        child_id = child.id

    yield TestClient(app), parent_id, child_id, engine
    app.dependency_overrides.clear()


def _fw_by_id(payload: list[dict], fid: int) -> dict:
    return next(f for f in payload if f["id"] == fid)


def test_frameworks_list_echoes_enabled_default_true(seeded) -> None:
    tc, parent_id, child_id, _ = seeded
    r = tc.get("/api/catalog/frameworks")
    assert r.status_code == 200, r.text
    body = r.json()
    assert _fw_by_id(body, parent_id)["enabled"] is True
    assert _fw_by_id(body, child_id)["enabled"] is True


def test_toggle_disable_then_enable_roundtrip(seeded) -> None:
    tc, parent_id, _, _ = seeded

    r = tc.post(f"/api/catalog/frameworks/{parent_id}/enabled", json={"enabled": False})
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is False

    # The row is never dropped from the list — only the flag flips.
    body = tc.get("/api/catalog/frameworks").json()
    assert _fw_by_id(body, parent_id)["enabled"] is False

    r = tc.post(f"/api/catalog/frameworks/{parent_id}/enabled", json={"enabled": True})
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is True
    body = tc.get("/api/catalog/frameworks").json()
    assert _fw_by_id(body, parent_id)["enabled"] is True


def test_toggle_is_idempotent(seeded) -> None:
    tc, parent_id, _, _ = seeded
    first = tc.post(
        f"/api/catalog/frameworks/{parent_id}/enabled", json={"enabled": False}
    )
    second = tc.post(
        f"/api/catalog/frameworks/{parent_id}/enabled", json={"enabled": False}
    )
    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["enabled"] is False


def test_toggle_missing_framework_returns_404(seeded) -> None:
    tc, *_ = seeded
    r = tc.post("/api/catalog/frameworks/99999/enabled", json={"enabled": False})
    assert r.status_code == 404


def test_disabling_parent_does_not_break_child_inheritance(seeded) -> None:
    """The load-bearing invariant: a disabled parent still feeds its
    Control rows into an enabled child's effective catalog."""
    tc, parent_id, child_id, _ = seeded

    before = tc.get(f"/api/catalog/frameworks/{child_id}/controls")
    assert before.status_code == 200, before.text
    before_ids = sorted(c["control_id"] for c in before.json())
    assert "ac-2" in before_ids  # inherited from the parent r5 catalog

    # Disable the parent.
    r = tc.post(f"/api/catalog/frameworks/{parent_id}/enabled", json={"enabled": False})
    assert r.status_code == 200, r.text

    # Child's effective catalog is unchanged — inheritance reads parent
    # rows by id, not by ``enabled``.
    after = tc.get(f"/api/catalog/frameworks/{child_id}/controls")
    assert after.status_code == 200, after.text
    after_ids = sorted(c["control_id"] for c in after.json())
    assert after_ids == before_ids
