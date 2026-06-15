"""Confluence DC connector routes — status + test probe.

Mirrors the pattern in routes/emass.py: cheap /status that reads
config + keyring presence only (no network), /test that does a real
PAT-authenticated probe against a configured space.

Confluence DC is DOUBLE-GATED. ``ConfluenceSource`` constructs even
when the gate flags are off (so the Settings card can render
"configured but disabled"), but ``iter_files()`` refuses to walk
unless both ``connectors.v04`` AND ``connectors.confluence_upcoming_gated``
flags are True. The /test probe replicates that gate guard up front so
the UI shows the same error a real ingest would surface.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import config as cfg
from ..evidence.sources.confluence import (
    ConfluenceSource,
    _V04_FLAG,
    _UPCOMING_FLAG,
    confluence_enabled,
)

router = APIRouter(prefix="/api/confluence", tags=["confluence"])


def _build_flags(c: cfg.AppConfig) -> dict:
    """Pack the flat config flags into the nested dict the source consumes.

    ConfluenceSource accepts both nested ``{"connectors": {"v04": True}}``
    and flat ``{"connectors.v04": True}`` shapes; we emit the flat shape
    for symmetry with how the source's tests build it.
    """
    return {
        _V04_FLAG: c.connectors_v04_enabled,
        _UPCOMING_FLAG: c.confluence_upcoming_gated_enabled,
    }


@router.get("/status")
def confluence_status() -> dict:
    """Cheap status: reads config + checks PAT presence in keyring.

    No network. The UI polls this to render the "configured / not
    configured" badge on the Settings card. ``configured`` is True iff
    the required fields are present AND a PAT is stored AND both gate
    flags are flipped on.
    """
    c = cfg.load_config()
    pat_set = cfg.get_confluence_pat() is not None
    fields_set = bool(c.confluence_base_url and c.confluence_space_keys)
    gates_on = bool(c.connectors_v04_enabled and c.confluence_upcoming_gated_enabled)
    configured = fields_set and pat_set and gates_on
    return {
        "configured": configured,
        "enabled": c.enable_confluence,
        "base_url": c.confluence_base_url,
        "username": c.confluence_username,
        "space_keys": c.confluence_space_keys,
        "max_pages": c.confluence_max_pages,
        "pat_set": pat_set,
        "upcoming_gated": c.confluence_upcoming_gated_enabled,
        "connectors_v04": c.connectors_v04_enabled,
        "gates_satisfied": gates_on,
        "reachable": None,  # /status never probes; /test sets this
    }


class ConfluenceTestBody(BaseModel):
    """Optional per-field overrides for the probe.

    All connection fields fall back to the saved config when None — so
    the UI can call /test with an empty body to validate the saved
    settings, or supply unsaved-yet form values for a dry-run.
    """

    base_url: str | None = None
    space_keys: str | None = None


@router.post("/test")
def confluence_test(body: ConfluenceTestBody | None = None) -> dict:
    """Real PAT probe — constructs a ConfluenceSource and lists 1 page.

    Returns ``{ok, message, detected: {...}}``. Failures (gate off,
    missing PAT, missing fields, network error, 401, etc.) come back as
    HTTP 400 with the upstream detail so the UI can render them in a
    toast.

    The probe is intentionally tiny: ``client.get_all_pages_from_space(
    key, start=0, limit=1)`` — one HTTP call, no body fetch. It proves
    auth + scope (space key resolves) without pulling actual content.
    """
    c = cfg.load_config()
    body = body or ConfluenceTestBody()

    # Gate guard mirrors what iter_files() would do — surface the same
    # error up front rather than letting the probe network-attempt with
    # the gate off.
    flags = _build_flags(c)
    if not confluence_enabled(flags):
        raise HTTPException(
            status_code=400,
            detail=(
                "Confluence connector is gate-disabled. Flip BOTH "
                "'connectors_v04' and 'confluence_upcoming_gated' on this "
                "Settings card before running the probe."
            ),
        )

    base_url = (body.base_url or c.confluence_base_url or "").strip().rstrip("/")
    space_keys_raw = (body.space_keys or c.confluence_space_keys or "").strip()
    space_keys = [k.strip() for k in space_keys_raw.split(",") if k.strip()]

    if not base_url:
        raise HTTPException(
            status_code=400,
            detail="No Confluence base_url configured.",
        )
    if not space_keys:
        raise HTTPException(
            status_code=400,
            detail="No Confluence space_keys configured (comma-separated list).",
        )
    if cfg.get_confluence_pat() is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "No Confluence PAT stored. Paste a token under Settings → "
                "Confluence → PAT before probing."
            ),
        )

    try:
        src = ConfluenceSource(
            server_url=base_url,
            space_keys=space_keys,
            flags=flags,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Probe: list 1 page from the first space. This forces PAT auth +
    # space-key resolution without fetching any body content.
    try:
        client = src._get_client()  # noqa: SLF001 — connector route is allowed in
        probe_space = space_keys[0]
        pages = client.get_all_pages_from_space(  # type: ignore[attr-defined]
            probe_space, start=0, limit=1
        )
    except Exception as exc:  # noqa: BLE001 — surface raw SDK errors to UI
        raise HTTPException(
            status_code=400,
            detail=f"Confluence probe failed: {exc}",
        ) from exc

    sample_title = None
    if isinstance(pages, list) and pages:
        first = pages[0]
        if isinstance(first, dict):
            sample_title = first.get("title")

    return {
        "ok": True,
        "message": (
            f"Confluence reachable; space '{probe_space}' resolved "
            f"({'has pages' if pages else 'empty'})."
        ),
        "detected": {
            "base_url": base_url,
            "space_probed": probe_space,
            "page_count_sampled": len(pages) if isinstance(pages, list) else 0,
            "sample_title": sample_title,
        },
    }
