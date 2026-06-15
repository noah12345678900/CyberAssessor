"""eMASS REST connector routes — status + test probe.

Mirrors the pattern in routes/sharepoint.py: cheap /status that reads
config + filesystem only (no network), /test that does a real mTLS probe
through the EmassSource constructor + ``test_connection()`` helper.

eMASS is DOUBLE-GATED. The probe constructor will refuse to instantiate
the source unless BOTH ``connectors_v04_enabled`` AND
``emass_upcoming_gated_enabled`` are True — the route surfaces that as a
400 with a clear message rather than letting the gate exception bubble.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import config as cfg
from ..evidence.sources.emass import EmassConnectorGatedError, EmassSource

router = APIRouter(prefix="/api/emass", tags=["emass"])


@router.get("/status")
def emass_status() -> dict:
    """Cheap status: reads config + checks cert paths exist on disk.

    No network. The UI polls this to render the "configured / not
    configured" badge on the Settings card. ``configured`` is True iff
    the required fields are present AND both gate flags are flipped on
    AND the cert file actually exists.
    """
    c = cfg.load_config()
    cert_exists = bool(c.emass_cert_path and Path(c.emass_cert_path).is_file())
    key_exists = bool(c.emass_key_path and Path(c.emass_key_path).is_file())
    fields_set = bool(c.emass_base_url and c.emass_system_id and c.emass_cert_path)
    gates_on = bool(c.connectors_v04_enabled and c.emass_upcoming_gated_enabled)
    configured = fields_set and cert_exists and gates_on
    return {
        "configured": configured,
        "enabled": c.enable_emass,
        "base_url": c.emass_base_url,
        "system_id": c.emass_system_id,
        "cert_path": c.emass_cert_path,
        "key_path": c.emass_key_path,
        "api_key_set": cfg.get_emass_api_key() is not None,
        "cert_exists": cert_exists,
        "key_exists": key_exists,
        "upcoming_gated": c.emass_upcoming_gated_enabled,
        "connectors_v04": c.connectors_v04_enabled,
        "reachable": None,  # /status never probes; /test sets this
    }


class EmassTestBody(BaseModel):
    """Optional per-field overrides for the probe.

    All four connection fields fall back to the saved config when None —
    so the UI can call /test with an empty body to validate the saved
    settings, or supply unsaved-yet form values for a dry-run.
    """

    base_url: str | None = None
    system_id: str | None = None
    cert_path: str | None = None
    key_path: str | None = None


@router.post("/test")
def emass_test(body: EmassTestBody | None = None) -> dict:
    """Real mTLS probe — instantiates EmassSource and calls test_connection.

    Returns ``{ok, message, detected: {...}}``. Failures (gate off,
    missing config, network error, 401, etc.) come back as HTTP 400 with
    the upstream detail so the UI can render them in a toast.
    """
    c = cfg.load_config()
    body = body or EmassTestBody()
    base_url = (body.base_url or c.emass_base_url or "").strip().rstrip("/")
    system_id = (body.system_id or c.emass_system_id or "").strip()
    cert_path = (body.cert_path or c.emass_cert_path or "").strip()
    key_path = (body.key_path or c.emass_key_path or "").strip() or None

    if not base_url:
        raise HTTPException(status_code=400, detail="No eMASS base_url configured.")
    if not system_id:
        raise HTTPException(status_code=400, detail="No eMASS system_id configured.")
    if not cert_path:
        raise HTTPException(status_code=400, detail="No eMASS cert_path configured.")
    if not Path(cert_path).is_file():
        raise HTTPException(
            status_code=400,
            detail=f"Cert file not found on disk: {cert_path}",
        )
    if key_path and not Path(key_path).is_file():
        raise HTTPException(
            status_code=400,
            detail=f"Key file not found on disk: {key_path}",
        )

    try:
        src = EmassSource(
            base_url=base_url,
            system_id=system_id,
            cert_path=cert_path,
            key_path=key_path,
            api_key=cfg.get_emass_api_key(),
            connectors_v04_enabled=c.connectors_v04_enabled,
            emass_upcoming_gated_enabled=c.emass_upcoming_gated_enabled,
        )
    except EmassConnectorGatedError as exc:
        raise HTTPException(
            status_code=400,
            detail=(
                f"eMASS connector is gate-disabled: {exc}. Flip both "
                "'connectors_v04' and 'emass_upcoming_gated' on this Settings card."
            ),
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        result = src.test_connection()
    except Exception as exc:  # noqa: BLE001 — surface raw SDK errors to UI
        raise HTTPException(
            status_code=400,
            detail=f"eMASS probe failed: {exc}",
        ) from exc

    if not result.get("ok"):
        return {
            "ok": False,
            "message": result.get("hint") or "eMASS probe returned ok=False.",
            "detected": {},
        }
    return {
        "ok": True,
        "message": "eMASS reachable and system_id resolves.",
        "detected": {
            "system_id": result.get("system_id"),
            "system_name": result.get("system_name"),
            "base_url": result.get("base_url"),
        },
    }
