"""Unit tests for the Framework.parent_framework_id chain + resolve_control.

v0.2 catalog refactor (FedRAMP-as-Framework). The schema gained a self-FK
on Framework so child frameworks (FedRAMP → 800-53 r5) can inherit their
parent's Control catalog. The
``resolve_control`` helper does a single-hop parent walk so a caller
asking for a control id on the child Framework still resolves rows that
physically sit on the parent.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[1]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.catalogs.fedramp_profile_loader import (  # noqa: E402
    load_fedramp_profile,
)
from cybersecurity_assessor.catalogs.oscal_loader import load_oscal_catalog  # noqa: E402
from cybersecurity_assessor.db import get_session  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Control,
    Framework,
    resolve_control,
)
from cybersecurity_assessor.server import create_app  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _seed_chain(s: Session) -> tuple[Framework, Framework, Control]:
    """Parent Framework with one Control, plus an empty child Framework."""
    parent = Framework(name="NIST SP 800-53", version="Rev 5")
    s.add(parent)
    s.commit()
    s.refresh(parent)

    parent_ctrl = Control(
        framework_id=parent.id,
        control_id="AC-1",
        title="Access Control Policy and Procedures",
        family="AC",
    )
    s.add(parent_ctrl)
    s.commit()
    s.refresh(parent_ctrl)

    child = Framework(
        name="FedRAMP",
        version="20x",
        parent_framework_id=parent.id,
    )
    s.add(child)
    s.commit()
    s.refresh(child)

    return parent, child, parent_ctrl


def test_resolve_walks_to_parent_on_miss(session):
    """Control lives on parent only — resolve via child walks one hop."""
    parent, child, parent_ctrl = _seed_chain(session)

    hit = resolve_control(session, child.id, "AC-1")
    assert hit is not None
    assert hit.id == parent_ctrl.id
    assert hit.framework_id == parent.id


def test_resolve_prefers_child_when_both_have_label(session):
    """Child-defined controls shadow the parent — FedRAMP-only overrides win."""
    parent, child, parent_ctrl = _seed_chain(session)

    child_ctrl = Control(
        framework_id=child.id,
        control_id="AC-1",
        title="FedRAMP-specific AC-1 override",
        family="AC",
    )
    session.add(child_ctrl)
    session.commit()
    session.refresh(child_ctrl)

    hit = resolve_control(session, child.id, "AC-1")
    assert hit is not None
    assert hit.id == child_ctrl.id
    assert hit.framework_id == child.id


def test_resolve_returns_none_when_neither_has_label(session):
    """Truly missing control id — no walk magic recovers it."""
    _parent, child, _parent_ctrl = _seed_chain(session)

    assert resolve_control(session, child.id, "ZZ-99") is None


def test_resolve_on_root_framework_does_not_walk(session):
    """Root Framework (parent NULL) — short-circuits with None on miss."""
    parent, _child, parent_ctrl = _seed_chain(session)

    # Hit on the parent itself succeeds.
    hit = resolve_control(session, parent.id, "AC-1")
    assert hit is not None
    assert hit.id == parent_ctrl.id

    # Miss on the parent returns None — no infinite walk.
    assert resolve_control(session, parent.id, "ZZ-99") is None


def test_resolve_on_unknown_framework_id(session):
    """Bogus framework_id — returns None, doesn't crash on the parent lookup."""
    _parent, _child, _parent_ctrl = _seed_chain(session)
    assert resolve_control(session, 99999, "AC-1") is None


# ---------------------------------------------------------------------------
# Integration: real bundled rev5 + bundled FedRAMP HIGH profile.
#
# The unit tests above use synthetic two-Framework chains. This one drives
# the *bundled* OSCAL files end-to-end through both loaders + the
# membership-aware ``GET /api/catalog/frameworks/{id}/controls`` route to
# pin the v0.2 catalog-binding contract:
#
#   - rev5 loads ~1014 base controls
#   - HIGH profile loads as a child Framework with parent_framework_id set
#   - the controls endpoint with include_inherited=true returns the 410-row
#     FedRAMP HIGH baseline (membership filter intersected with rev5 +
#     any FedRAMP-only synthesised rows from modify.alters)
#
# The 410 figure is the canonical FedRAMP Rev 5 HIGH control count
# (published by GSA). Asserting an exact range (>=400, <=425) keeps the
# test resilient to GSA shipping an off-by-one revision of the profile
# (e.g. adding a single new enhancement) without burying real regressions
# like "membership filter silently disabled, returning all 1014 rev5 rows."
# ---------------------------------------------------------------------------


@pytest.fixture
def integration_client():
    """TestClient backed by a fresh in-memory SQLite engine.

    Returns ``(client, engine)`` so tests can both POST through the route
    and read DB state directly for cross-checking.
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
    try:
        yield TestClient(app), engine
    finally:
        app.dependency_overrides.clear()


def test_bundled_rev5_plus_fedramp_high_returns_baseline_count(integration_client):
    """Load real bundled rev5 + HIGH profile, hit the controls endpoint,
    assert the returned list is the ~410-control FedRAMP HIGH baseline.
    """
    tc, engine = integration_client

    with Session(engine) as s:
        # Bundled rev5 — offline=True forces the bundled-JSON path so the
        # test never touches the network. ``path=None`` lets the loader's
        # resolution chain pick the wheel-bundled file.
        parent = load_oscal_catalog(s, path=None, rev="5", offline=True)
        assert parent.id is not None
        parent_id = parent.id

        # Parent should carry the full rev5 catalog. Exact count drifts
        # with NIST releases; the 800s floor catches "loader silently
        # truncated" regressions without pinning a brittle number.
        rev5_ctrl_count = s.exec(
            select(Control).where(Control.framework_id == parent_id)
        ).all()
        assert len(rev5_ctrl_count) >= 800, (
            f"bundled rev5 returned only {len(rev5_ctrl_count)} controls — "
            "loader truncation regression?"
        )

        result = load_fedramp_profile(
            s,
            level="HIGH",
            parent_framework_id=parent_id,
            path=None,
            offline=True,
        )
        child_id = result.framework.id
        assert child_id is not None
        assert result.framework.parent_framework_id == parent_id
        # FedRAMP HIGH ships 410 includes — allow a small drift band so a
        # GSA point-release that adds/removes one control doesn't break CI.
        assert 400 <= result.members_added <= 425, (
            f"unexpected members_added={result.members_added} — FedRAMP HIGH "
            "profile shape changed materially"
        )

    # Round-trip via the route the UI actually calls. The
    # membership-aware merge should return the same ~410 rows, NOT the
    # full 1000+ rev5 catalog.
    r = tc.get(
        f"/api/catalog/frameworks/{child_id}/controls",
        params={"include_inherited": "true"},
    )
    assert r.status_code == 200, r.text
    rows = r.json()
    assert 400 <= len(rows) <= 425, (
        f"controls endpoint returned {len(rows)} rows for FedRAMP HIGH — "
        "expected ~410. Membership filter may have been bypassed (would "
        "return all 1000+ rev5 rows) or wrongly applied (would return 0)."
    )

    # Sanity: a known HIGH control is present, a known not-in-HIGH
    # rev5-only control is absent. ac-1 is in every FedRAMP baseline;
    # pm-* family is intentionally excluded from FedRAMP profiles.
    ids = {row["control_id"] for row in rows}
    assert "ac-1" in ids
    assert not any(cid.startswith("pm-") for cid in ids), (
        "PM family controls should be filtered out of FedRAMP HIGH "
        "membership — found leakage suggests membership filter is off."
    )
