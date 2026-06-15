"""Tenable connector routes — status + test probe.

Mirrors the pattern in ``routes/sharepoint.py``: a cheap ``/status`` that
reads config + keyring only (no network), and a ``/test`` that constructs
a :class:`TenableSource` and runs ``test_connection()`` against the live
SDK. The walker itself is invoked from ``/api/evidence/ingest`` via the
discriminated source-spec union; this router is purely for credential
plumbing so the Settings card can render meaningful state.

Two flavors are supported:

* ``sc`` — Tenable.sc / SecurityCenter on-prem. Requires ``host`` (FQDN).
* ``io`` — Tenable.io SaaS. Host is implicit (``cloud.tenable.com``); the
  ``host`` field on the test body is ignored when flavor is ``io``.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import config as cfg
from ..evidence.sources.tenable import TENABLE_IO_HOST, TenableSource

LOG = logging.getLogger(__name__)

router = APIRouter(prefix="/api/tenable", tags=["tenable"])


def _is_configured(c: cfg.AppConfig) -> bool:
    """True when the stored config is sufficient to build a TenableSource.

    - ``io`` only needs the keyset (host is implicit).
    - ``sc`` additionally requires a host FQDN.
    """
    if not c.tenable_flavor:
        return False
    if not (cfg.get_tenable_access_key() and cfg.get_tenable_secret_key()):
        return False
    if c.tenable_flavor == "sc" and not c.tenable_host:
        return False
    return True


@router.get("/status")
def tenable_status() -> dict:
    """Report current Tenable configuration + key-storage state.

    Cheap — does NOT hit the network. Used by the Settings card to decide
    which buttons to enable and by the Evidence source picker to gate the
    Tenable option. Raw key material is never returned; the card only sees
    ``*_key_set`` booleans.
    """
    c = cfg.load_config()
    # For .io, surface the implicit cloud host so the UI can render it as
    # a read-only badge instead of an empty field.
    effective_host: str | None
    if c.tenable_flavor == "io":
        effective_host = TENABLE_IO_HOST
    else:
        effective_host = c.tenable_host
    return {
        "configured": _is_configured(c),
        "flavor": c.tenable_flavor,
        "host": effective_host,
        "access_key_set": cfg.get_tenable_access_key() is not None,
        "secret_key_set": cfg.get_tenable_secret_key() is not None,
        "enabled": c.enable_tenable,
    }


class TestBody(BaseModel):
    """Override-on-test payload — lets the user probe a candidate flavor /
    host without committing it to ``config.toml`` first. Every field is
    optional; anything not supplied falls back to the saved value via
    ``cfg.load_config()`` (or the keyring for the secrets).

    Note: ``access_key`` / ``secret_key`` are NOT part of this body. The
    test endpoint always reads them from the keyring — they can be staged
    via ``POST /api/settings/tenable-access-key`` and the matching secret
    endpoint without round-tripping the raw values through the JSON body.
    """

    flavor: Literal["sc", "io"] | None = None
    host: str | None = None


@router.post("/test")
def tenable_test(body: TestBody | None = None) -> dict:
    """Build a TenableSource with the effective config and probe the SDK.

    Returns ``{ok, message, detected: {flavor, host, username}}`` on success,
    or raises ``HTTPException(400)`` with a human-readable detail on any
    failure. The probe hits the cheapest authenticated endpoint per flavor
    (``current.user()`` on SC, ``session.details()`` on io) — same call
    ``TenableSource.test_connection`` already implements.
    """
    body = body or TestBody()
    c = cfg.load_config()

    flavor = (body.flavor or c.tenable_flavor or "").strip().lower()
    if flavor not in ("sc", "io"):
        raise HTTPException(
            status_code=400,
            detail="Tenable flavor not configured. Pick 'sc' or 'io' first.",
        )

    if flavor == "io":
        # io always points at the SaaS host; an explicit override is ignored
        # rather than rejected so the UI can preselect "cloud.tenable.com"
        # without conditionally clearing the field.
        host: str | None = TENABLE_IO_HOST
    else:
        host = (body.host or c.tenable_host or "").strip().rstrip("/") or None
        if not host:
            raise HTTPException(
                status_code=400,
                detail="Tenable.sc requires a host (the SecurityCenter FQDN).",
            )

    access_key = cfg.get_tenable_access_key()
    secret_key = cfg.get_tenable_secret_key()
    if not access_key or not secret_key:
        raise HTTPException(
            status_code=400,
            detail="Tenable keyset not stored. Save access_key and secret_key first.",
        )

    try:
        source = TenableSource(
            flavor=flavor,  # type: ignore[arg-type]
            access_key=access_key,
            secret_key=secret_key,
            host=host,
            # /test should never start a walk; feature_enabled only gates
            # iter_files(), so leaving it False here is fine.
            feature_enabled=False,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ImportError as exc:
        # pyTenable not installed in this sidecar build. Surface the same
        # human message the source module raises so the UI doesn't need to
        # special-case it.
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    try:
        result: dict[str, Any] = source.test_connection()
    except Exception as exc:  # noqa: BLE001 — defensive; test_connection() catches its own
        LOG.exception("Tenable test_connection raised unexpectedly")
        raise HTTPException(status_code=502, detail=f"Probe failed: {exc!s}") from exc

    if result.get("ok"):
        return {
            "ok": True,
            "message": f"Connected to Tenable.{flavor} at {result.get('host', host)}",
            "detected": {
                "flavor": result.get("flavor", flavor),
                "host": result.get("host", host),
                "username": result.get("username", "(unknown)"),
            },
        }

    # ok=False — translate the source's structured error into an HTTP 400.
    err = result.get("error") or "connection_failed"
    hint = result.get("hint") or "Probe failed (no detail)."
    status_code = 401 if err == "auth_failed" else 400
    raise HTTPException(status_code=status_code, detail=hint)
