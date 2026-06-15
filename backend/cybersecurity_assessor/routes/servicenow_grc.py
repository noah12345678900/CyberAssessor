"""ServiceNow GRC connector routes — status + test probe.

Mirrors the pattern in routes/sharepoint.py: cheap ``/status`` that reads
config + keyring only (no network), and ``/test`` that does a real probe
against the SN Table API. Secret material (OAuth client_secret, Basic
password) is set/cleared via dedicated keyring endpoints so the values
never round-trip through ``GET /api/settings``.

The walker itself is invoked from ``/api/evidence/ingest`` via the
discriminated source-spec union; this router is purely for credential
plumbing + the Settings UI card.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .. import config as cfg
from ..evidence.sources.servicenow_grc import (
    DEFAULT_TABLES,
    KEYRING_KEY_SNOW_BASIC_PASSWORD,
    KEYRING_KEY_SNOW_OAUTH_SECRET,
    FeatureDisabledError,
    ServiceNowGrcSource,
    SnowGrcConfig,
    TableSpec,
    build_source_from_config,
    clear_basic_password,
    clear_oauth_secret,
    set_basic_password,
    set_oauth_secret,
)

LOG = logging.getLogger(__name__)

router = APIRouter(prefix="/api/servicenow_grc", tags=["servicenow_grc"])


def _keyring_get(slot: str) -> bool:
    """Return True if a keyring value exists for ``slot`` (no value leaked)."""
    try:
        import keyring

        return keyring.get_password(cfg.KEYRING_SERVICE, slot) is not None
    except Exception:
        return False


@router.get("/status")
def servicenow_grc_status() -> dict:
    """Report current ServiceNow GRC configuration.

    Cheap — does NOT call SN or hit the network. Used by the Settings card
    to decide which buttons to enable. ``configured`` is True when the
    minimum required fields are set for the chosen auth method.
    """
    c = cfg.load_config()
    instance_url = c.servicenow_grc_instance_url
    auth_method = (c.servicenow_grc_auth_method or "oauth").lower()
    username = c.servicenow_grc_username
    secret_set = (
        _keyring_get(KEYRING_KEY_SNOW_OAUTH_SECRET)
        if auth_method == "oauth"
        else _keyring_get(KEYRING_KEY_SNOW_BASIC_PASSWORD)
    )
    # "Configured" = enough fields persisted that ``build_source_from_config``
    # would not blow up on construction (modulo the secret, which lives in
    # the keyring and is reported separately so the UI can show "instance +
    # username set, password missing" as its own state).
    configured = bool(instance_url and username)
    return {
        "configured": configured,
        "instance_url": instance_url,
        "auth_method": auth_method,
        "username": username,
        "allowed_tables": list(c.servicenow_grc_allowed_tables) or list(DEFAULT_TABLES),
        "secret_set": secret_set,
        "enabled": c.enable_snow_grc,
    }


class _SecretBody(BaseModel):
    """OAuth client_secret or Basic password — stored in the OS keyring."""

    secret: str = Field(..., min_length=1)


@router.post("/oauth-secret")
def set_servicenow_grc_oauth_secret(body: _SecretBody) -> dict:
    """Persist the OAuth client_secret in the OS keyring."""
    if len(body.secret) < 4:
        raise HTTPException(status_code=400, detail="Secret too short")
    set_oauth_secret(body.secret)
    return {"ok": True}


@router.delete("/oauth-secret")
def clear_servicenow_grc_oauth_secret() -> dict:
    clear_oauth_secret()
    return {"ok": True}


@router.post("/basic-password")
def set_servicenow_grc_basic_password(body: _SecretBody) -> dict:
    """Persist the Basic-auth password in the OS keyring."""
    if len(body.secret) < 4:
        raise HTTPException(status_code=400, detail="Password too short")
    set_basic_password(body.secret)
    return {"ok": True}


@router.delete("/basic-password")
def clear_servicenow_grc_basic_password() -> dict:
    clear_basic_password()
    return {"ok": True}


class TestBody(BaseModel):
    """Override-on-test payload — lets the user probe a candidate instance
    without committing to ``config.toml`` first. Every field is optional;
    anything not supplied falls back to the saved value via
    ``cfg.load_config()``.
    """

    instance_url: str | None = None
    auth_method: str | None = None
    username: str | None = None
    allowed_tables: list[str] | None = None


def _resolve(body: TestBody) -> SnowGrcConfig:
    """Build a :class:`SnowGrcConfig` from override-body + persisted config."""
    c = cfg.load_config()
    instance_url = (body.instance_url or c.servicenow_grc_instance_url or "").strip()
    if not instance_url:
        raise HTTPException(
            status_code=400,
            detail="instance_url is not set — save it first or pass it in the body.",
        )
    auth_method = (
        body.auth_method or c.servicenow_grc_auth_method or "oauth"
    ).strip().lower()
    if auth_method not in ("oauth", "basic"):
        raise HTTPException(
            status_code=400,
            detail=f"auth_method must be 'oauth' or 'basic'; got {auth_method!r}",
        )
    username = (body.username or c.servicenow_grc_username or "").strip()
    if not username:
        raise HTTPException(
            status_code=400,
            detail=(
                "username is not set. For OAuth, this is the client_id; for "
                "Basic, the service account username."
            ),
        )
    tables_in = body.allowed_tables
    if tables_in is None:
        tables_in = list(c.servicenow_grc_allowed_tables)
    table_names = [t.strip() for t in tables_in if t and t.strip()] or list(
        DEFAULT_TABLES
    )
    try:
        return SnowGrcConfig(
            instance_url=instance_url,
            auth_mode=auth_method,
            oauth_client_id=username if auth_method == "oauth" else None,
            basic_username=username if auth_method == "basic" else None,
            tables=tuple(TableSpec(name=n) for n in table_names),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/test")
def servicenow_grc_test(body: TestBody | None = None) -> dict[str, Any]:
    """Probe SN auth + table reachability without pulling rows.

    Returns ``{ok, message, detected}`` for a Settings-card-friendly shape.
    On the happy path, ``detected`` carries the probe table name + the SN
    instance's reported total row count so the user can sanity-check that
    the GRC tables are populated.
    """
    body = body or TestBody()
    snow_cfg = _resolve(body)
    try:
        # Honor the feature flag — the connector's own factory enforces it.
        source = build_source_from_config(snow_cfg)
    except FeatureDisabledError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 — surface SDK errors as 400
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    assert isinstance(source, ServiceNowGrcSource)
    result = source.test_connection()
    if not result.get("ok"):
        # Bubble the upstream error up as a 400 so the UI's onError handler
        # can render it via humanize(err); leaves the underlying error text
        # intact rather than coercing to a generic 500.
        raise HTTPException(
            status_code=400,
            detail=result.get("error") or "ServiceNow probe failed.",
        )
    return {
        "ok": True,
        "message": (
            f"Connected to {result.get('instance_url')} via "
            f"{result.get('auth_mode')} (probe table "
            f"'{result.get('probe_table')}' returned "
            f"{result.get('probe_total_count')} rows)."
        ),
        "detected": {
            "instance_url": result.get("instance_url"),
            "auth_mode": result.get("auth_mode"),
            "probe_table": result.get("probe_table"),
            "probe_total_count": result.get("probe_total_count"),
        },
    }
