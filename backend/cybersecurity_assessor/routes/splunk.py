"""Splunk connector routes — status + test probe + token slot.

Mirrors the pattern in routes/sharepoint.py and routes/jira.py: cheap
``/status`` that reads config + keyring only (NO network), ``/test`` that
does a real ``service.info()`` round-trip via ``SplunkSource``, plus a
``/token`` write/clear pair that lands the Splunk auth token in the OS
keyring.

Single-gated (unlike Jira/Confluence/eMASS which are double-gated). The
``enable_splunk`` flag is the only kill-switch — flipping it on exposes
the connector everywhere, no second ack.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import config as cfg
from ..evidence.sources.splunk import SplunkSource

router = APIRouter(prefix="/api/splunk", tags=["splunk"])


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------


class SplunkTokenBody(BaseModel):
    """POST body for storing the Splunk auth token in the OS keyring."""

    token: str


class SplunkTestBody(BaseModel):
    """POST body for ``/test`` — every field optional, falls back to stored config.

    Lets the UI probe a *candidate* configuration before saving it (the
    classic "Test connection" flow) without persisting a half-typed host or
    a typo'd port to disk. The token comes from the keyring unless the
    user is testing a fresh token before saving (in which case body.token
    overrides).
    """

    host: str | None = None
    port: int | None = None
    scheme: str | None = None
    app: str | None = None
    owner: str | None = None
    verify_tls: bool | None = None
    saved_searches: list[str] | None = None
    token: str | None = None


# ---------------------------------------------------------------------------
# /status — config + keyring only, NEVER a network call
# ---------------------------------------------------------------------------


@router.get("/status")
def splunk_status() -> dict[str, Any]:
    """Return whether Splunk is configured and ready to probe.

    Recipe gotcha #6: status probes must not hit the network. The Settings
    card calls this on every render to update its badge; a network call
    here would slow page paint AND surface transient Splunk 5xx as a
    persistent red banner. The real network probe lives at ``/test``.
    """
    c = cfg.load_config()
    token_set = cfg.get_splunk_token() is not None
    has_searches = bool(c.splunk_saved_searches)
    # "configured" semantics for the badge: every required piece is in
    # place. Missing host, token, or any saved-search means the test
    # probe would fail loudly — surface that early on the card without
    # forcing the user to click Test to find out.
    configured = bool(c.splunk_host) and token_set and has_searches
    return {
        "configured": configured,
        "host": c.splunk_host,
        "port": c.splunk_port,
        "scheme": c.splunk_scheme,
        "app": c.splunk_app,
        "owner": c.splunk_owner,
        "verify_tls": c.splunk_verify_tls,
        "saved_searches": list(c.splunk_saved_searches),
        "token_set": token_set,
        "enabled": c.enable_splunk,
    }


# ---------------------------------------------------------------------------
# /test — real service.info() round-trip (does hit the network)
# ---------------------------------------------------------------------------


@router.post("/test")
def splunk_test(body: SplunkTestBody | None = None) -> dict[str, Any]:
    """Probe Splunk auth + reachability.

    Resolves each field from the request body first, then falls back to
    saved config / keyring — lets the user click "Test connection" with a
    candidate host or token typed into the form before clicking Save.

    Returns ``{ok, message, detected: {...}}``. The route catches Splunk-
    side failures (auth, network, TLS) and surfaces them in ``message``
    rather than raising — keeps the UI on a stable shape without per-
    error HTTPException branches. Configuration errors (gate closed,
    missing host, missing token, empty saved-searches) DO raise HTTP 400
    because there's no point showing a "connector says: …" banner when
    the form isn't filled in yet.
    """
    body = body or SplunkTestBody()
    c = cfg.load_config()

    # Gate first — refuse before even touching keyring / network.
    if not c.enable_splunk:
        raise HTTPException(
            status_code=400,
            detail=(
                "Splunk connector is disabled. Flip 'enable_splunk' on the "
                "Settings card before testing."
            ),
        )

    host = (body.host or c.splunk_host or "").strip()
    if not host:
        raise HTTPException(status_code=400, detail="No Splunk host configured.")

    token = body.token or cfg.get_splunk_token()
    if not token:
        raise HTTPException(
            status_code=400,
            detail="No Splunk auth token stored. Save one from the Settings card first.",
        )

    saved_searches = (
        body.saved_searches
        if body.saved_searches is not None
        else list(c.splunk_saved_searches)
    )
    saved_searches = [s.strip() for s in saved_searches if s and s.strip()]
    if not saved_searches:
        raise HTTPException(
            status_code=400,
            detail=(
                "No saved searches configured. Add at least one saved-search "
                "name before testing — Splunk is config-bound and refuses to "
                "run raw SPL from the UI."
            ),
        )

    port = body.port if body.port is not None else c.splunk_port
    scheme = (body.scheme or c.splunk_scheme).strip()
    app = (body.app or c.splunk_app).strip() or "search"
    owner = (body.owner or c.splunk_owner).strip() or "-"
    verify_tls = body.verify_tls if body.verify_tls is not None else c.splunk_verify_tls

    try:
        src = SplunkSource(
            host=host,
            token=token,
            saved_searches=saved_searches,
            port=int(port),
            scheme=scheme,
            app=app,
            owner=owner,
            verify=bool(verify_tls),
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid Splunk config: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 — surface SDK import / construction issues
        raise HTTPException(
            status_code=500,
            detail=f"Failed to construct Splunk client: {exc}",
        ) from exc

    # SplunkSource exposes test_connection() if present; otherwise build a
    # minimal probe by asking for the service info. The connector module
    # already wraps the auth call to keep tokens out of crash logs.
    try:
        if hasattr(src, "test_connection"):
            result = src.test_connection()
        else:
            service = src._build_service()  # noqa: SLF001 — intentional, route-only probe
            info = service.info if hasattr(service, "info") else {}
            result = {
                "ok": True,
                "version": getattr(info, "get", lambda *_: None)("version"),
                "host": host,
            }
    except Exception as exc:  # noqa: BLE001 — Splunk SDK raises bare Exception too
        return {
            "ok": False,
            "message": f"Splunk test failed: {exc}",
            "detected": {"host": host},
        }

    if result.get("ok"):
        return {
            "ok": True,
            "message": "Connected to Splunk",
            "detected": {
                "host": host,
                "version": result.get("version") or "",
                "saved_searches": len(saved_searches),
            },
        }
    return {
        "ok": False,
        "message": result.get("error") or "Splunk test failed",
        "detected": {"host": host},
    }


# ---------------------------------------------------------------------------
# /token — keyring write + clear
# ---------------------------------------------------------------------------


@router.post("/token")
def set_splunk_token_route(body: SplunkTokenBody) -> dict[str, Any]:
    """Store the Splunk auth token in the OS keyring.

    Refuses laughably short tokens as a typo guard (Splunk tokens are
    long base64 blobs in practice; the 16-char floor here only catches
    "asdf" / "" / accidental empty paste). The keyring slot lives at
    ``KEYRING_KEY_SPLUNK_TOKEN`` — see config.py.
    """
    token = (body.token or "").strip()
    if len(token) < 16:
        raise HTTPException(
            status_code=400,
            detail="Splunk token looks too short to be valid (minimum 16 characters).",
        )
    cfg.set_splunk_token(token)
    return {"ok": True}


@router.delete("/token")
def clear_splunk_token_route() -> dict[str, Any]:
    cfg.clear_splunk_token()
    return {"ok": True}
