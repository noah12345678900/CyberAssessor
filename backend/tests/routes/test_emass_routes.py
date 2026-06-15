"""Tests for the eMASS status endpoint and settings extension.

Covers:
- GET /api/emass/status is network-free and reports ``configured`` only when
  ALL of: base_url + system_id + an on-disk cert + both gate flags
  (connectors_v04_enabled AND emass_upcoming_gated_enabled) are present.
  It never embeds a test_connection payload — the real mTLS probe lives at
  POST /api/emass/test.
- A partial config (base_url + cert_path only) stays ``configured=False``.
- GET /api/settings exposes the new emass_* fields
- PUT /api/settings round-trips emass_base_url / emass_cert_path
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cybersecurity_assessor import config as cfg
from cybersecurity_assessor.server import create_app


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """TestClient with an isolated config dir + in-memory keyring shim.

    Avoids polluting the developer's Windows Credential Manager and the real
    ~/.cybersecurity-assessor/config.toml.
    """

    config_root = tmp_path / "config"
    config_root.mkdir()
    monkeypatch.setattr(cfg, "config_dir", lambda: config_root)

    # Stub keyring to a per-test dict so we don't touch Windows Credential Manager.
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


def test_emass_status_unconfigured(client: TestClient) -> None:
    r = client.get("/api/emass/status")
    assert r.status_code == 200
    payload = r.json()
    assert payload["configured"] is False
    assert payload["base_url"] is None
    assert payload["system_id"] is None
    assert payload["cert_path"] is None
    assert payload["api_key_set"] is False
    assert payload["cert_exists"] is False
    # /status is network-free: it never embeds a probe result and always
    # reports reachable=None. The real mTLS probe lives at POST /api/emass/test.
    assert "test" not in payload
    assert payload["reachable"] is None


def test_emass_status_partial_config_stays_unconfigured(client: TestClient) -> None:
    """base_url + cert_path alone is NOT enough — configured stays False.

    The full gate also needs system_id, an on-disk cert, and BOTH gate flags
    (connectors_v04_enabled AND emass_upcoming_gated_enabled). A 2-field PUT
    round-trips the values but must not flip ``configured`` on.
    """
    r = client.put(
        "/api/settings",
        json={
            "emass_base_url": "https://emass.disa.mil",
            "emass_cert_path": "C:/certs/client.pfx",
        },
    )
    assert r.status_code == 200, r.text

    status = client.get("/api/emass/status").json()
    assert status["base_url"] == "https://emass.disa.mil"
    assert status["cert_path"] == "C:/certs/client.pfx"
    # Missing system_id, no on-disk cert, gates off → not configured.
    assert status["configured"] is False
    assert status["cert_exists"] is False
    assert status["reachable"] is None


def test_emass_status_fully_configured(
    client: TestClient, tmp_path: Path
) -> None:
    """All of: base_url + system_id + an on-disk cert + both gate flags → configured.

    Drops a real file under tmp_path so ``cert_exists`` resolves True, and
    flips both halves of the double-gate via PUT /api/settings.
    """
    cert = tmp_path / "client.pfx"
    cert.write_bytes(b"not-a-real-cert")

    r = client.put(
        "/api/settings",
        json={
            "emass_base_url": "https://emass.disa.mil",
            "emass_system_id": "12345",
            "emass_cert_path": str(cert),
            "connectors_v04_enabled": True,
            "emass_upcoming_gated_enabled": True,
        },
    )
    assert r.status_code == 200, r.text

    status = client.get("/api/emass/status").json()
    assert status["base_url"] == "https://emass.disa.mil"
    assert status["system_id"] == "12345"
    assert status["cert_path"] == str(cert)
    assert status["cert_exists"] is True
    assert status["connectors_v04"] is True
    assert status["upcoming_gated"] is True
    assert status["configured"] is True
    # Still network-free — no probe was performed.
    assert status["reachable"] is None
    assert "test" not in status


def test_settings_exposes_emass_fields(client: TestClient) -> None:
    s = client.get("/api/settings").json()
    assert "emass_base_url" in s
    assert "emass_cert_path" in s
    assert "emass_api_key_set" in s
    assert s["emass_api_key_set"] is False


def test_settings_clears_emass_base_url(client: TestClient) -> None:
    # Set then clear via empty string convention (matches anthropic_base_url).
    client.put("/api/settings", json={"emass_base_url": "https://emass.disa.mil"})
    assert client.get("/api/settings").json()["emass_base_url"] == "https://emass.disa.mil"
    client.put("/api/settings", json={"emass_base_url": ""})
    assert client.get("/api/settings").json()["emass_base_url"] is None


def test_emass_api_key_set_and_clear(client: TestClient) -> None:
    # Set
    r = client.post("/api/settings/emass-key", json={"key": "test-emass-key-xyz"})
    assert r.status_code == 200
    assert client.get("/api/settings").json()["emass_api_key_set"] is True
    assert client.get("/api/emass/status").json()["api_key_set"] is True

    # Clear
    r = client.delete("/api/settings/emass-key")
    assert r.status_code == 200
    assert client.get("/api/settings").json()["emass_api_key_set"] is False


def test_emass_api_key_rejects_too_short(client: TestClient) -> None:
    r = client.post("/api/settings/emass-key", json={"key": "ab"})
    assert r.status_code == 400
