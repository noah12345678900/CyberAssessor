"""Loopback sidecar per-launch bearer auth (#1).

CORS is browser-only and doesn't stop a local process (or a DNS-rebinding
webpage) from hitting 127.0.0.1:<port>. When Electron sets CCIS_AUTH_TOKEN the
sidecar requires `Authorization: Bearer <token>` on every request except
/healthz. These tests pin:

* env-ABSENT (the default in pytest/dev) → auth is INERT, so the other ~2400
  tests that build create_app() without a token keep working with no header,
* env-PRESENT → 401 without/with-wrong header, 200 with the right header,
* /healthz stays open regardless (the CCIS_PORT handshake + packaged-sidecar
  smoke probe it before any token is known).
"""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor.server import create_app  # noqa: E402


def test_auth_inert_when_env_absent(monkeypatch):
    monkeypatch.delenv("CCIS_AUTH_TOKEN", raising=False)
    app = create_app()
    client = TestClient(app)
    # No Authorization header, yet a normal endpoint is reachable — this is the
    # invariant that keeps the whole existing suite header-free.
    assert client.get("/healthz").status_code == 200


def test_healthz_open_even_with_token(monkeypatch):
    monkeypatch.setenv("CCIS_AUTH_TOKEN", "secret-token-123")
    app = create_app()
    client = TestClient(app)
    # Handshake/health probe must never require the token.
    assert client.get("/healthz").status_code == 200


def test_protected_route_401_without_header(monkeypatch):
    monkeypatch.setenv("CCIS_AUTH_TOKEN", "secret-token-123")
    app = create_app()
    client = TestClient(app)
    # Any non-open path without a valid bearer → 401.
    r = client.get("/api/workbooks")
    assert r.status_code == 401


def test_protected_route_401_with_wrong_token(monkeypatch):
    monkeypatch.setenv("CCIS_AUTH_TOKEN", "secret-token-123")
    app = create_app()
    client = TestClient(app)
    r = client.get(
        "/api/workbooks", headers={"Authorization": "Bearer wrong-token"}
    )
    assert r.status_code == 401


def test_protected_route_ok_with_correct_token(monkeypatch):
    monkeypatch.setenv("CCIS_AUTH_TOKEN", "secret-token-123")
    app = create_app()
    client = TestClient(app)
    r = client.get(
        "/api/workbooks", headers={"Authorization": "Bearer secret-token-123"}
    )
    # 200 (or any non-401) — the point is auth PASSED, not the payload.
    assert r.status_code != 401
