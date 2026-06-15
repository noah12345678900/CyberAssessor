"""SharePoint Boundary Sweep connector routes — status + test probe.

Mirrors the pattern in routes/sharepoint.py: cheap /status that reads
config + filesystem only, /test that does a real (read-only) Graph probe
to verify the boundary-sweep walk can resolve the configured site.

The boundary sweep is a derivative connector — it reuses the SharePoint
connector's site URL + Graph auth surface, so /status surfaces both the
boundary-sweep feature flag AND a "depends on SharePoint" health
indicator. When SharePoint isn't configured (or its enable flag is off),
this connector is functionally degraded even if its own flag is on; the
UI uses that signal to render an actionable warning instead of letting
/test fail with a confusing 400.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import config as cfg
from ..evidence.sources.sharepoint import (
    GraphAuthError,
    _resolve_site_id,
    _token_cache_path,
    acquire_token,
    cloud_for,
)
from ..evidence.sources.sp_boundary_sweep import (
    BoundarySweepCaps,
    BoundarySweepDisabledError,
    SharePointBoundarySweepSource,
)

LOG = logging.getLogger(__name__)

router = APIRouter(prefix="/api/boundary-sweep", tags=["boundary-sweep"])


@router.get("/status")
def boundary_sweep_status() -> dict:
    """Report boundary-sweep configuration + SharePoint dependency health.

    Cheap — does NOT call MSAL or hit the network. Reads cfg + filesystem
    only. ``sharepoint_configured`` / ``sharepoint_enabled`` are surfaced
    so the Settings card can render a "SharePoint not configured" warning
    instead of letting /test fail with a 400. ``configured`` is True when
    the SharePoint dependency is satisfied AND boundary-sweep itself is
    enabled — the only state from which /test is meaningful.
    """
    c = cfg.load_config()
    cloud_name: str | None = None
    if c.sharepoint_site_url:
        cloud_name = cloud_for(c.sharepoint_site_url).cloud_name
    sharepoint_configured = bool(c.sharepoint_site_url)
    sharepoint_enabled = bool(c.enable_sharepoint)
    return {
        # "Can /test do anything useful?" — true only when the underlying
        # SharePoint surface is wired AND boundary-sweep itself is enabled.
        # The card uses this to decide between "test connection" (configured)
        # and "configured, untested" (sharepoint set but no sweep flag yet).
        "configured": sharepoint_configured,
        "enabled": c.enable_boundary_sweep,
        # SharePoint dependency state — surfaced separately so the UI can
        # render an actionable "Configure SharePoint first" link rather
        # than a generic "not configured" badge.
        "sharepoint_configured": sharepoint_configured,
        "sharepoint_enabled": sharepoint_enabled,
        # Inherited site context — boundary-sweep has no site URL of its
        # own. Surfaced so the card can show "Will sweep <site>" without
        # the user toggling back to the SharePoint card to remember.
        "site_url": c.sharepoint_site_url,
        "library": c.sharepoint_library,
        "cloud_name": cloud_name,
        "token_cache_exists": _token_cache_path().exists(),
        # Boundary-sweep-specific knobs. None ⇒ BoundarySweepCaps defaults.
        "folder_path": c.boundary_sweep_folder_path,
        "max_folder_depth": c.boundary_sweep_max_folder_depth,
        "max_stale_items": c.boundary_sweep_max_stale_items,
        # Surface the dataclass defaults so the card can show the
        # effective values (and the placeholders on empty inputs)
        # without hard-coding them in the UI.
        "default_max_folder_depth": BoundarySweepCaps().max_folder_depth,
        "default_max_stale_items": BoundarySweepCaps().max_stale_title_items,
    }


class TestBody(BaseModel):
    """Override-on-test payload — lets the user probe a candidate site /
    folder without committing to config.toml first. Every field is
    optional; anything not supplied falls back to the saved value via
    ``cfg.load_config()``.

    Site URL is inherited from the SharePoint connector — there is no
    ``site_url`` override here because the boundary sweep deliberately
    reuses that surface (one auth token, one cloud, one set of priority
    links). Override the site on the SharePoint card and re-probe here.
    """

    folder_path: str | None = None
    max_folder_depth: int | None = None
    max_stale_items: int | None = None


@router.post("/test")
def test_boundary_sweep(body: TestBody | None = None) -> dict:
    """Probe boundary-sweep readiness with the saved (or override) config.

    Read-only — resolves the site via the shared Graph helpers but does
    NOT walk libraries / external shares / stale-title scan. A successful
    probe means:

    1. The boundary-sweep feature flag is on.
    2. The SharePoint dependency is configured.
    3. The cached MSAL token (or freshly-acquired one) resolves the site.
    4. The boundary-sweep source can be instantiated under the configured
       caps without raising.

    Returns ``{ok, message, detected: {site_title, cloud, caps}}``. Auth
    failures surface as HTTP 401; the UI is expected to route the user to
    the SharePoint card's device-code flow rather than spinning a second
    device-code dance here.
    """
    body = body or TestBody()
    c = cfg.load_config()

    if not c.enable_boundary_sweep:
        raise HTTPException(
            status_code=400,
            detail=(
                "Boundary sweep is disabled. Enable the connector on this "
                "card first, then test."
            ),
        )

    site_url = c.sharepoint_site_url
    if not site_url:
        raise HTTPException(
            status_code=400,
            detail=(
                "SharePoint is not configured. Paste a site URL on the "
                "SharePoint card first — boundary sweep reuses that "
                "surface for auth and site routing."
            ),
        )

    # Resolve effective caps. ``None`` on either knob ⇒ dataclass default;
    # explicit values override. ``BoundarySweepCaps`` is frozen so we
    # rebuild rather than mutate.
    defaults = BoundarySweepCaps()
    effective_caps = BoundarySweepCaps(
        max_subsites=defaults.max_subsites,
        max_libraries_per_site=defaults.max_libraries_per_site,
        max_stale_title_items=(
            body.max_stale_items
            if body.max_stale_items is not None
            else (c.boundary_sweep_max_stale_items or defaults.max_stale_title_items)
        ),
        max_folder_depth=(
            body.max_folder_depth
            if body.max_folder_depth is not None
            else (c.boundary_sweep_max_folder_depth or defaults.max_folder_depth)
        ),
        max_items_per_library=defaults.max_items_per_library,
    )

    # Boundary-sweep source carries its own feature-flag gate which
    # raises ``BoundarySweepDisabledError`` if the env var override is
    # off. The config-level ``enable_boundary_sweep`` flag is the user-
    # facing toggle; pass ``enabled=True`` here so the test doesn't
    # double-gate on a legacy env var.
    library = c.sharepoint_library or "Documents"
    try:
        src = SharePointBoundarySweepSource(
            site_url=site_url,
            library=library,
            caps=effective_caps,
            enabled=True,
        )
    except BoundarySweepDisabledError as exc:
        # Defensive — should be unreachable because we pass enabled=True.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 — surface SDK errors verbatim
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    # Resolve the site through the shared Graph helpers — same code path
    # the actual walk uses, so a green check here means iter_files()
    # would at least make it past step 1. We don't enumerate libraries
    # / external shares / stale titles in the probe; those are token-
    # expensive and would defeat the "cheap probe" contract.
    endpoint = cloud_for(site_url)
    try:
        token = acquire_token(endpoint=endpoint, site_host=src._site_host)
    except GraphAuthError as exc:
        # The shared SharePoint card owns the device-code UX. Surface a
        # 401 so the UI prompts the user to sign in over there rather
        # than spinning a duplicate dance here.
        raise HTTPException(
            status_code=401,
            detail=(
                f"SharePoint sign-in required — complete the device-code "
                f"flow on the SharePoint card, then re-test boundary sweep. "
                f"({exc})"
            ),
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    try:
        site_record = _resolve_site_id(endpoint.graph_base, token, site_url)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    detected: dict[str, Any] = {
        "site_title": site_record.get("displayName") or site_record.get("name"),
        "site_id": site_record.get("id"),
        "cloud": endpoint.cloud_name,
        "library": library,
        "folder_path": (
            body.folder_path
            if body.folder_path is not None
            else c.boundary_sweep_folder_path
        )
        or "",
        "caps": {
            "max_subsites": effective_caps.max_subsites,
            "max_libraries_per_site": effective_caps.max_libraries_per_site,
            "max_stale_title_items": effective_caps.max_stale_title_items,
            "max_folder_depth": effective_caps.max_folder_depth,
            "max_items_per_library": effective_caps.max_items_per_library,
        },
    }
    return {
        "ok": True,
        "message": (
            f"Boundary sweep ready — resolved site '{detected['site_title']}' "
            f"on {endpoint.cloud_name}."
        ),
        "detected": detected,
    }
