"""Tests for the Confluence /status and /test endpoints + Settings wiring.

Mirrors test_emass_routes.py: isolated config dir + in-memory keyring shim
so the developer's Windows Credential Manager and real config.toml are
never touched.

Covers:
- GET /api/confluence/status returns the unconfigured payload by default
- /status reports gates_satisfied=False until BOTH inner gate flags flip
- /status reports configured=True only when fields + PAT + gates all line up
- PUT /api/settings round-trips confluence_* fields
- POST/DELETE /api/settings/confluence-pat sets and clears the keyring slot
- POST /api/confluence/test refuses to probe when gates are off (400)
- /test refuses when PAT is missing (400) and when fields are missing (400)
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cybersecurity_assessor import config as cfg
from cybersecurity_assessor.server import create_app


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """TestClient with an isolated config dir + in-memory keyring shim."""

    config_root = tmp_path / "config"
    config_root.mkdir()
    monkeypatch.setattr(cfg, "config_dir", lambda: config_root)

    # Stub keyring so set_confluence_pat() etc. write to a dict instead of
    # Windows Credential Manager.
    store: dict[tuple[str, str], str] = {}

    class _Errors:
        class PasswordDeleteError(Exception):
            pass

    class _FakeKeyring:
        errors = _Errors

        @staticmethod
        def get_password(service: str, user: str) -> str | None:
            return store.get((service, user))

        @staticmethod
        def set_password(service: str, user: str, value: str) -> None:
            store[(service, user)] = value

        @staticmethod
        def delete_password(service: str, user: str) -> None:
            if (service, user) not in store:
                raise _Errors.PasswordDeleteError()
            del store[(service, user)]

    monkeypatch.setattr(cfg, "keyring", _FakeKeyring)

    return TestClient(create_app())


def test_confluence_status_unconfigured(client: TestClient) -> None:
    r = client.get("/api/confluence/status")
    assert r.status_code == 200
    payload = r.json()
    assert payload["configured"] is False
    assert payload["enabled"] is False
    assert payload["base_url"] is None
    assert payload["space_keys"] is None
    assert payload["pat_set"] is False
    # Single-pill refactor: inner gate flags default ON, so they read True
    # even on a fresh install — only the main `enable_*` pill and the
    # fields/PAT remain off, which keeps `configured`/`enabled` False above.
    assert payload["upcoming_gated"] is True
    assert payload["connectors_v04"] is True
    assert payload["gates_satisfied"] is True
    # /status never probes the network.
    assert payload["reachable"] is None


def test_settings_exposes_confluence_fields(client: TestClient) -> None:
    s = client.get("/api/settings").json()
    assert "confluence" in s
    assert s["confluence"]["base_url"] is None
    assert s["confluence"]["max_pages"] == 500
    assert "confluence" in s["features"]
    assert "confluence_upcoming_gated" in s["features"]
    assert "connectors_v04" in s["features"]


def test_settings_roundtrips_confluence_fields(client: TestClient) -> None:
    r = client.put(
        "/api/settings",
        json={
            "confluence_base_url": "https://confluence.example.com/wiki",
            "confluence_username": "alice",
            "confluence_space_keys": "PROG, DEV ,SEC",
            "confluence_max_pages": 250,
        },
    )
    assert r.status_code == 200, r.text

    s = client.get("/api/settings").json()
    assert s["confluence"]["base_url"] == "https://confluence.example.com/wiki"
    assert s["confluence"]["username"] == "alice"
    # Whitespace stripped + empty entries dropped on the way through.
    assert s["confluence"]["space_keys"] == "PROG,DEV,SEC"
    assert s["confluence"]["max_pages"] == 250


def test_settings_rejects_zero_max_pages(client: TestClient) -> None:
    r = client.put("/api/settings", json={"confluence_max_pages": 0})
    assert r.status_code == 400


def test_settings_clears_confluence_base_url(client: TestClient) -> None:
    client.put(
        "/api/settings",
        json={"confluence_base_url": "https://confluence.example.com/wiki"},
    )
    assert (
        client.get("/api/settings").json()["confluence"]["base_url"]
        == "https://confluence.example.com/wiki"
    )
    client.put("/api/settings", json={"confluence_base_url": ""})
    assert client.get("/api/settings").json()["confluence"]["base_url"] is None


def test_confluence_pat_set_and_clear(client: TestClient) -> None:
    r = client.post(
        "/api/settings/confluence-pat", json={"key": "test-pat-abcdef12345"}
    )
    assert r.status_code == 200
    status = client.get("/api/confluence/status").json()
    assert status["pat_set"] is True

    r = client.delete("/api/settings/confluence-pat")
    assert r.status_code == 200
    assert client.get("/api/confluence/status").json()["pat_set"] is False


def test_confluence_status_configured_requires_all_three(client: TestClient) -> None:
    """`configured` needs fields + PAT + both inner gates.

    Single-pill refactor: the inner gates default ON, so the missing piece on
    a fresh install is the fields + PAT — once those land, `configured` flips
    True without any explicit gate toggle. We prove each piece is load-bearing
    by turning a gate OFF and watching `configured` drop back to False.
    """
    # Just URL + space — no PAT yet → still unconfigured.
    client.put(
        "/api/settings",
        json={
            "confluence_base_url": "https://confluence.example.com/wiki",
            "confluence_space_keys": "PROG",
        },
    )
    assert client.get("/api/confluence/status").json()["configured"] is False

    # Add the PAT — gates are already on by default, so this completes the
    # trio and `configured` flips True.
    client.post("/api/settings/confluence-pat", json={"key": "pat-xxxxxxxxxxxx"})
    s = client.get("/api/confluence/status").json()
    assert s["configured"] is True
    assert s["gates_satisfied"] is True

    # Turn an inner gate OFF — `configured` drops, proving the gate is still
    # part of the configured contract.
    client.put("/api/settings", json={"confluence_upcoming_gated_enabled": False})
    s = client.get("/api/confluence/status").json()
    assert s["configured"] is False
    assert s["gates_satisfied"] is False


def test_confluence_test_blocked_when_gates_off(client: TestClient) -> None:
    # Fields + PAT in place, then explicitly turn an inner gate OFF — the gates
    # default ON post-refactor, so we must flip one off to exercise the guard.
    client.put(
        "/api/settings",
        json={
            "confluence_base_url": "https://confluence.example.com/wiki",
            "confluence_space_keys": "PROG",
            "confluence_upcoming_gated_enabled": False,
        },
    )
    client.post("/api/settings/confluence-pat", json={"key": "pat-xxxxxxxxxxxx"})

    r = client.post("/api/confluence/test", json={})
    assert r.status_code == 400
    assert "gate" in r.json()["detail"].lower()


def test_confluence_test_blocked_without_pat(client: TestClient) -> None:
    # Gates on + fields set, but no PAT in keyring.
    client.put(
        "/api/settings",
        json={
            "confluence_base_url": "https://confluence.example.com/wiki",
            "confluence_space_keys": "PROG",
            "confluence_upcoming_gated_enabled": True,
            "connectors_v04_enabled": True,
        },
    )
    r = client.post("/api/confluence/test", json={})
    assert r.status_code == 400
    assert "pat" in r.json()["detail"].lower()


def test_confluence_test_blocked_without_fields(client: TestClient) -> None:
    # Gates + PAT but no base_url / space_keys.
    client.put(
        "/api/settings",
        json={
            "confluence_upcoming_gated_enabled": True,
            "connectors_v04_enabled": True,
        },
    )
    client.post("/api/settings/confluence-pat", json={"key": "pat-xxxxxxxxxxxx"})

    r = client.post("/api/confluence/test", json={})
    assert r.status_code == 400
    # First missing field surfaced is base_url.
    assert "base_url" in r.json()["detail"].lower()
