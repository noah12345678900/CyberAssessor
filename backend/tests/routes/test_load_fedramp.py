"""Tests for ``POST /api/catalog/load/fedramp`` response and gating.

The route is the UI's only entry point for projecting a FedRAMP Rev 5
profile (HIGH / MODERATE / LOW / LI-SaaS) onto the loaded 800-53 r5
catalog. Three contracts are pinned here:

1.  Without rev5 loaded, the route refuses with 400 — the UI surfaces
    the message verbatim so the user knows the next step is "Load NIST
    800-53 Rev 5 first."
2.  On the happy path, the JSON response is *flat* — Framework fields
    inline with the loader counters (``members_added``,
    ``controls_synthesized``, ``parameters_loaded``,
    ``unknown_control_ids``) so the UI can render one toast and refetch
    ``/api/catalog/frameworks`` without a second round-trip. The
    response also carries ``parent_framework_id`` so the picker can
    indent the new child under rev5 immediately.
3.  An unknown ``level`` (e.g. ``"ULTRA"``) is a 400 — surfaced as a
    typed validation error from the loader rather than a 500.

A synthetic OSCAL profile JSON is used (1 include, 1 alter w/ prose,
1 set-parameter) so the test doesn't pull from the bundled HIGH/MOD/LOW
fixtures (those live ~410+ rows deep and would obscure the contract
being pinned).
"""

from __future__ import annotations

import json
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
from cybersecurity_assessor.models import Control, Framework  # noqa: E402
from cybersecurity_assessor.server import create_app  # noqa: E402


# rev5 detection in ``_resolve_rev5_framework`` is a substring match on
# ``oscal_uri`` (must contain "rev5"). The canonical NIST URL works
# verbatim; using ``example.test`` here keeps the seed self-contained.
_REV5_OSCAL_URI = "https://example.test/NIST_SP-800-53_rev5_catalog.json"


def _make_app(engine):
    """Build a TestClient app that uses the given in-memory SQLite engine."""

    def _override_get_session():
        with Session(engine) as s:
            yield s

    app = create_app()
    app.dependency_overrides[get_session] = _override_get_session
    return app


@pytest.fixture
def engine():
    """Fresh in-memory SQLite engine per test (StaticPool → one connection
    shared between the test seeding session and the route's request-scoped
    session, otherwise tables vanish between connections).
    """
    e = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(e)
    return e


def _seed_rev5(engine, *, controls: list[str]) -> int:
    """Seed an 800-53 r5 Framework + the named controls. Returns its id."""
    with Session(engine) as s:
        fw = Framework(
            name="NIST SP 800-53",
            version="Rev 5",
            oscal_uri=_REV5_OSCAL_URI,
        )
        s.add(fw)
        s.commit()
        s.refresh(fw)
        for cid in controls:
            family = cid.split("-", 1)[0].upper()
            s.add(
                Control(
                    framework_id=fw.id,
                    control_id=cid,
                    title=f"Synthetic {cid.upper()}",
                    family=family,
                    statement=f"Parent {cid.upper()} statement.",
                )
            )
        s.commit()
        return fw.id


def _write_profile_json(
    path: Path,
    *,
    include_ids: list[str],
    alters: list[dict] | None = None,
    set_parameters: list[dict] | None = None,
) -> None:
    """Synthesize a minimal-but-loader-valid OSCAL profile JSON at ``path``."""
    doc = {
        "profile": {
            "metadata": {
                "title": "Synthetic FedRAMP Profile",
                "version": "Rev 5",
            },
            "imports": [
                {
                    "href": "#catalog",
                    "include-controls": [{"with-ids": include_ids}],
                }
            ],
            "modify": {
                "alters": alters or [],
                "set-parameters": set_parameters or [],
            },
        }
    }
    path.write_text(json.dumps(doc), encoding="utf-8")


def test_load_fedramp_without_rev5_returns_400(engine, tmp_path):
    """No rev5 → 400 with a message the UI can show verbatim. The route
    must not attempt to materialize a child Framework with no parent.
    """
    app = _make_app(engine)
    tc = TestClient(app)

    profile_path = tmp_path / "profile.json"
    _write_profile_json(profile_path, include_ids=["ac-1"])

    r = tc.post(
        "/api/catalog/load/fedramp",
        json={"level": "HIGH", "path": str(profile_path)},
    )
    assert r.status_code == 400, r.text
    detail = r.json()["detail"]
    assert "Rev 5" in detail
    assert "not loaded" in detail.lower()


def test_load_fedramp_happy_path_returns_flat_shape(engine, tmp_path):
    """End-to-end: seed rev5 with 2 controls, POST a synthetic profile,
    assert the response carries Framework fields + all loader counters
    inline (flat shape — no nested ``result`` wrapper).
    """
    parent_id = _seed_rev5(engine, controls=["ac-1", "au-3"])
    app = _make_app(engine)
    tc = TestClient(app)

    profile_path = tmp_path / "profile.json"
    _write_profile_json(
        profile_path,
        # ac-1 known, au-3 known, xx-99 unknown (surfaced not persisted).
        include_ids=["ac-1", "au-3", "xx-99"],
        alters=[
            {
                "control-id": "ac-1",
                "adds": [
                    {
                        "position": "after",
                        "parts": [
                            {
                                "name": "item",
                                "prose": "FedRAMP-specific AC-1 requirement.",
                            }
                        ],
                    }
                ],
            }
        ],
        set_parameters=[
            {
                "param-id": "au-03_odp.01",
                "constraints": [{"description": "at least annually"}],
            }
        ],
    )

    r = tc.post(
        "/api/catalog/load/fedramp",
        json={"level": "HIGH", "path": str(profile_path)},
    )
    assert r.status_code == 200, r.text
    payload = r.json()

    # Framework fields — flat, inlined alongside counters. The UI
    # reads ``id`` to auto-select the new child in the picker.
    assert isinstance(payload["id"], int)
    assert payload["id"] != parent_id
    assert payload["framework_id"] == payload["id"]
    assert payload["name"] == "FedRAMP Rev 5 HIGH"
    assert payload["parent_framework_id"] == parent_id
    # oscal_uri is the canonical FedRAMP URL — picker's per-level
    # ``hasFedramp`` substring match (``FedRAMP_rev5_HIGH-``) depends
    # on this exact filename token surviving the round-trip.
    assert "FedRAMP_rev5_HIGH-" in payload["oscal_uri"]

    # Loader counters — all four must be present so the toast can
    # compose its summary line without optional-chaining each field.
    assert payload["members_added"] == 2
    assert payload["controls_synthesized"] == 1
    assert payload["parameters_loaded"] == 1
    assert payload["unknown_control_ids"] == ["xx-99"]


def test_load_fedramp_unknown_level_returns_400(engine, tmp_path):
    """An unknown level surfaces as a typed 400 — the loader raises
    ValueError, the route translates it. Without this, a typo
    (``"MODERATE "`` with trailing space, ``"ULTRA"``) would 500 and
    the UI toast would just say "Internal server error."
    """
    _seed_rev5(engine, controls=["ac-1"])
    app = _make_app(engine)
    tc = TestClient(app)

    profile_path = tmp_path / "profile.json"
    _write_profile_json(profile_path, include_ids=["ac-1"])

    r = tc.post(
        "/api/catalog/load/fedramp",
        json={"level": "ULTRA", "path": str(profile_path)},
    )
    assert r.status_code == 400, r.text
    assert "Unsupported FedRAMP level" in r.json()["detail"]
