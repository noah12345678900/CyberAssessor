"""Archer (RSA Archer / GRC) connector routes — status + test probe.

Mirrors the pattern in ``routes/sharepoint.py``: a cheap ``/status`` that
reads config + keyring only, and a ``/test`` that performs a real network
login against the configured Archer instance. Also exposes
``/password`` (POST/DELETE) so the Settings card can write/clear the
keyring slot without touching the Pydantic settings body — passwords
deliberately never travel through the generic ``SettingsUpdate`` model
to keep them out of GET responses and config.toml dumps.

The connector itself lives in ``evidence/sources/archer.py``; this
router is purely the credential + probe surface so the Settings UI can
land a connector card without dragging the ingest path into the
configuration flow.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import config as cfg
from ..evidence.sources.archer import (
    ArcherApplicationQuery,
    ArcherClient,
    ArcherConfig,
    _read_password,
    clear_password,
    feature_enabled,
    store_password,
)

LOG = logging.getLogger(__name__)

router = APIRouter(prefix="/api/archer", tags=["archer"])


@router.get("/status")
def archer_status() -> dict:
    """Report Archer connector configuration + keyring state.

    Cheap — does NOT hit the network. Reads ``cfg.load_config()`` and a
    single keyring lookup (only when both instance_name + username are
    set, so an unconfigured connector doesn't probe the OS credential
    store for a guaranteed-miss).

    ``configured`` is True when instance_url, instance_name, and
    username are all set; ``password_set`` is True when the keyring
    has a slot for that pair OR the ``ARCHER_PASSWORD`` env-var
    fallback is populated (the same precedence the connector itself
    follows at login time). ``feature_env_flag`` reports the legacy
    ``ARCHER_CONNECTOR_ENABLED`` env-var state so power users on dev
    workstations can see why the connector is on/off independent of
    the persisted ``enable_archer`` toggle.
    """
    c = cfg.load_config()
    configured = bool(
        c.archer_instance_url and c.archer_instance_name and c.archer_username
    )
    password_set = False
    if c.archer_instance_name and c.archer_username:
        password_set = (
            _read_password(c.archer_instance_name, c.archer_username) is not None
        )
    return {
        "configured": configured,
        "instance_url": c.archer_instance_url,
        "instance_name": c.archer_instance_name,
        "username": c.archer_username,
        "domain": c.archer_domain,
        "password_set": password_set,
        "enabled": c.enable_archer,
        "feature_env_flag": feature_enabled(),
    }


class ArcherPasswordBody(BaseModel):
    """Body for ``POST /password`` — write a password to the keyring.

    Instance + username are optional overrides; when omitted we read
    them from the saved config so the Settings card can call this with
    just the password after the user has saved the connection details.
    """

    password: str
    instance_name: str | None = None
    username: str | None = None


@router.post("/password")
def set_archer_password(body: ArcherPasswordBody) -> dict:
    """Persist an Archer password in the OS keyring.

    Routes through :func:`evidence.sources.archer.store_password` so
    the keyring service name + slot key stay defined in one place. The
    password never lands in config.toml or in a GET response.
    """
    c = cfg.load_config()
    instance_name = (body.instance_name or c.archer_instance_name or "").strip()
    username = (body.username or c.archer_username or "").strip()
    if not instance_name or not username:
        raise HTTPException(
            status_code=400,
            detail=(
                "Archer instance_name and username must be saved (or supplied "
                "in the body) before storing a password."
            ),
        )
    if not body.password or len(body.password) < 1:
        raise HTTPException(status_code=400, detail="Password is required")
    try:
        store_password(instance_name, username, body.password)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"ok": True}


@router.delete("/password")
def clear_archer_password() -> dict:
    """Remove the stored Archer password for the configured instance/user."""
    c = cfg.load_config()
    if not c.archer_instance_name or not c.archer_username:
        # Nothing to clear — surface as success so the UI doesn't error on
        # a fresh install where the slot was never populated.
        return {"ok": True, "cleared": False}
    cleared = clear_password(c.archer_instance_name, c.archer_username)
    return {"ok": True, "cleared": cleared}


class ArcherTestBody(BaseModel):
    """Override-on-test payload for ``/test``.

    Every field is optional; anything not supplied falls back to the
    saved value via ``cfg.load_config()``. Lets the user probe a
    candidate instance without committing to ``config.toml`` first.
    Password is NOT a field — the probe always uses whatever is in
    the keyring for the (instance_name, username) pair under test, so
    a passing probe proves the persisted credential round-trips.
    """

    instance_url: str | None = None
    instance_name: str | None = None
    username: str | None = None
    domain: str | None = None


@router.post("/test")
def archer_test(body: ArcherTestBody | None = None) -> dict:
    """Authenticate against Archer and return a small probe payload.

    Builds an :class:`ArcherConfig` from the body overrides falling
    back to saved config, then runs :meth:`ArcherClient.test_connection`
    which performs a real login round-trip. The returned ``detected``
    dict surfaces instance_url / instance_name / username so the UI
    can render a "Connected as alice@PROD" badge.

    Errors:
      * 400 — required fields missing or password not stored.
      * 502 — login transport failure (network, TLS, unreachable host).

    Authentication failures (HTTP 401 from Archer) return ``ok=False``
    with a hint string rather than raising — the UI surfaces them as
    a red badge alongside the saved credentials so the user can fix
    them in place.
    """
    body = body or ArcherTestBody()
    c = cfg.load_config()
    instance_url = (body.instance_url or c.archer_instance_url or "").strip().rstrip(
        "/"
    )
    instance_name = (body.instance_name or c.archer_instance_name or "").strip()
    username = (body.username or c.archer_username or "").strip()
    if not instance_url or not instance_name or not username:
        raise HTTPException(
            status_code=400,
            detail=(
                "Archer instance_url, instance_name, and username are required "
                "(supply in the body or save them via /api/settings first)."
            ),
        )
    if _read_password(instance_name, username) is None:
        raise HTTPException(
            status_code=400,
            detail=(
                f"No password stored for {username}@{instance_name}. POST to "
                "/api/archer/password first."
            ),
        )

    config = ArcherConfig(
        instance_url=instance_url,
        instance_name=instance_name,
        username=username,
        # Empty queries tuple — test_connection only logs in, never walks
        # records, so we don't need to know the per-tenant application IDs.
        queries=(ArcherApplicationQuery(application_id=0),)[:0],
    )
    client = ArcherClient(config)
    try:
        probe = client.test_connection()
    finally:
        client.close()

    detected: dict[str, str | None] = {
        "instance_url": probe.get("instance_url"),
        "instance_name": probe.get("instance_name"),
        "username": probe.get("username"),
    }
    if probe.get("ok"):
        return {
            "ok": True,
            "message": (
                f"Authenticated as {detected['username']} against "
                f"{detected['instance_name']}."
            ),
            "detected": detected,
        }
    return {
        "ok": False,
        "message": probe.get("hint") or "Archer login failed.",
        "detected": detected,
        "disabled": bool(probe.get("disabled")),
    }
