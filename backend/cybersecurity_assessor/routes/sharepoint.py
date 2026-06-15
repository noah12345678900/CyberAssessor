"""SharePoint connector endpoints.

Surface for the Settings → SharePoint card:

* ``GET  /api/sharepoint/status``    — report whether tenant/client/site are
  configured and whether a token cache exists on disk.
* ``POST /api/sharepoint/test``      — run ``SharePointSource.test_connection``.
  When MSAL falls back to device-code the response carries ``device_code`` /
  ``verification_uri`` / ``user_code`` so the UI can render the sign-in
  instructions; the background task then finishes the flow and the next call
  goes silent.
* ``POST /api/sharepoint/sign-out``  — wipe the persisted token cache.

The SharePoint walker itself is invoked from ``/api/evidence/ingest`` via the
discriminated source-spec union; this router is purely for credential plumbing.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, model_validator
from sqlmodel import Session

from .. import config as cfg
from ..db import chunked, get_session
from ..evidence.sources.sharepoint import (
    SharePointSource,
    _token_cache_path,
    acquire_token,
    clear_token_cache,
    cloud_for,
)
from ..db import session_scope
from ..engine.sweep_online import (
    MIN_DECISIONS_FOR_ONLINE_FIT,
    update_weights_online,
)
from ..evidence.sources.sweep import (
    _W_CONTROL_ID,
    _W_CRM_KEYWORD,
    _W_DOC_PREFIX,
    _W_FAMILY,
    _W_HOST,
    _W_PRIORITY_LINK,
    build_boundary_fingerprint,
    load_active_weights,
    normalize_sp_candidate_uri,
)
from ..llm.client import make_client
from ..models import (
    Evidence,
    SweepDecision,
    SweepHit,
    SweepRun,
    SweepWeights,
    SystemContext,
    Workbook,
)
from sqlmodel import select
import dataclasses
import json
from datetime import datetime, timezone

LOG = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sharepoint", tags=["sharepoint"])


@router.get("/status")
def sharepoint_status() -> dict:
    """Report current SharePoint configuration + sign-in state.

    Cheap — does NOT call MSAL or hit the network. Used by the Settings card
    to decide which buttons to enable. ``cloud_name`` is auto-detected from
    the site URL hostname so the UI can show a "Detected cloud: GovCloud"
    badge before the user signs in.
    """
    c = cfg.load_config()
    cache_path = _token_cache_path()
    cloud_name: str | None = None
    if c.sharepoint_site_url:
        cloud_name = cloud_for(c.sharepoint_site_url).cloud_name
    return {
        # With Graph + Graph PowerShell client_id, the only thing the user
        # MUST configure is a site URL. Tenant/client are no longer required.
        "configured": bool(c.sharepoint_site_url),
        "site_url": c.sharepoint_site_url,
        "library": c.sharepoint_library,
        "folder_path": c.sharepoint_folder_path,
        "cloud_name": cloud_name,
        "token_cache_exists": cache_path.exists(),
        "token_cache_path": str(cache_path),
        "enabled": c.enable_sharepoint,
    }


class TestBody(BaseModel):
    """Override-on-test payload — lets the user probe a candidate site/library
    without committing it to ``config.toml`` first. Every field is optional;
    anything not supplied falls back to the saved value via
    ``cfg.load_config()``.

    Tenant/client/authority are intentionally absent — Graph PowerShell's
    well-known client_id is hardcoded server-side and the cloud is detected
    from the site URL hostname. Pasting a URL is the whole config.
    """

    site_url: str | None = None
    library: str | None = None
    folder_path: str | None = None


# Device-code flow handoff. ``test_connection`` blocks waiting for the user to
# complete the device-code dance — too long for an HTTP request — so we kick
# the actual MSAL call off on a thread, capture the device-code dict synchronously
# via a callback, and return that to the UI on the first call. Subsequent calls
# (after the user signs in at microsoft.com/devicelogin) succeed silently using
# the cached refresh token.
_DEVICE_CODE_EVENT = threading.Event()
_DEVICE_CODE_PAYLOAD: dict[str, Any] = {}
_DEVICE_CODE_ISSUED_AT: dict[str, float] = {}  # single-key {"ts": float}
_TEST_LOCK = threading.Lock()


def _reset_device_state() -> None:
    _DEVICE_CODE_EVENT.clear()
    _DEVICE_CODE_PAYLOAD.clear()
    _DEVICE_CODE_ISSUED_AT.clear()


def _force_release_lock() -> None:
    """Best-effort lock release — swallows RuntimeError if already free."""
    try:
        _TEST_LOCK.release()
    except RuntimeError:
        pass


def _device_code_still_valid() -> bool:
    """True if the cached device-code payload has not expired yet."""
    if not _DEVICE_CODE_PAYLOAD:
        return False
    issued = _DEVICE_CODE_ISSUED_AT.get("ts", 0.0)
    expires_in = float(_DEVICE_CODE_PAYLOAD.get("expires_in", 0) or 0)
    if not issued or not expires_in:
        return False
    # 30s safety margin so we don't hand out a code that's about to die.
    return (time.time() - issued) < (expires_in - 30)


# ---------------------------------------------------------------------------
# Sweep-path device-code handoff
#
# Separate from the /test-path globals above so a stuck /test (e.g. user
# walked away from the device-code prompt) can't lock out /sweep, and so
# the two paths can each carry their own pending-payload cache without
# stomping each other. Same shape, same watchdog idiom.
# ---------------------------------------------------------------------------
_SWEEP_DEVICE_CODE_EVENT = threading.Event()
_SWEEP_DEVICE_CODE_PAYLOAD: dict[str, Any] = {}
_SWEEP_DEVICE_CODE_ISSUED_AT: dict[str, float] = {}
_SWEEP_LOCK = threading.Lock()


def _reset_sweep_device_state() -> None:
    _SWEEP_DEVICE_CODE_EVENT.clear()
    _SWEEP_DEVICE_CODE_PAYLOAD.clear()
    _SWEEP_DEVICE_CODE_ISSUED_AT.clear()


def _sweep_device_code_still_valid() -> bool:
    if not _SWEEP_DEVICE_CODE_PAYLOAD:
        return False
    issued = _SWEEP_DEVICE_CODE_ISSUED_AT.get("ts", 0.0)
    expires_in = float(_SWEEP_DEVICE_CODE_PAYLOAD.get("expires_in", 0) or 0)
    if not issued or not expires_in:
        return False
    return (time.time() - issued) < (expires_in - 30)


def _acquire_graph_token_for_sweep(site_url: str) -> dict:
    """Pre-flight: ensure we have a usable Graph token before sweep starts.

    Returns one of:
      * ``{"ok": True}``                          — silent acquisition succeeded
        (cache hit). Caller may proceed to walk Graph.
      * ``{"ok": False, "pending": True, ...}``   — MSAL is in device-code mode;
        payload carries ``user_code`` / ``verification_uri`` so the UI can
        render sign-in instructions. Caller MUST return early; subsequent
        /sweep calls succeed once the user signs in (refresh token then lives
        in the on-disk cache).
      * ``{"ok": False, "detail": "..."}``        — non-recoverable error.

    Mirrors the ``/test`` handoff (threaded MSAL + Event-gated callback) but
    uses separate globals so a stuck test sign-in can't block the sweep
    sign-in and vice versa.
    """
    parsed = urlparse(site_url)
    site_host = parsed.netloc or None
    endpoint = cloud_for(site_url)

    # Already-pending payload? Re-show it if still valid; otherwise force a
    # fresh flow so a stale code from a prior abandoned sweep doesn't haunt us.
    if not _SWEEP_LOCK.acquire(blocking=False):
        if _sweep_device_code_still_valid():
            payload = dict(_SWEEP_DEVICE_CODE_PAYLOAD)
            return {
                "ok": False,
                "pending": True,
                "device_code": payload.get("device_code"),
                "user_code": payload.get("user_code"),
                "verification_uri": payload.get("verification_uri"),
                "expires_in": payload.get("expires_in"),
                "interval": payload.get("interval"),
                "message": payload.get(
                    "message",
                    f"Go to {payload.get('verification_uri')} and enter code "
                    f"{payload.get('user_code')}. Then click Sweep again.",
                ),
            }
        # Stale lock — abandoned flow. Force-release and retry.
        try:
            _SWEEP_LOCK.release()
        except RuntimeError:
            pass
        if not _SWEEP_LOCK.acquire(blocking=False):
            return {
                "ok": False,
                "pending": True,
                "detail": (
                    "Another sweep sign-in just started. Wait a moment and "
                    "click Sweep again."
                ),
            }

    try:
        _reset_sweep_device_state()

        def _on_device_code(flow: dict) -> None:
            _SWEEP_DEVICE_CODE_PAYLOAD.update(flow)
            _SWEEP_DEVICE_CODE_ISSUED_AT["ts"] = time.time()
            _SWEEP_DEVICE_CODE_EVENT.set()

        error_holder: dict[str, BaseException] = {}

        def _runner() -> None:
            try:
                acquire_token(
                    endpoint=endpoint,
                    site_host=site_host,
                    on_device_code=_on_device_code,
                )
            except BaseException as exc:  # noqa: BLE001 — surface to foreground
                error_holder["exc"] = exc
                _SWEEP_DEVICE_CODE_EVENT.set()

        thread = threading.Thread(
            target=_runner, name="sharepoint-sweep-auth", daemon=True
        )
        thread.start()

        # Silent-path window: cached refresh token resolves in well under 5s.
        thread.join(timeout=5.0)
        if not thread.is_alive():
            if "exc" in error_holder:
                exc = error_holder["exc"]
                # Token acquisition failed cleanly — let the lock release in
                # the finally below; signal back as non-pending failure.
                return {"ok": False, "detail": str(exc)}
            return {"ok": True}

        # Still running ⇒ MSAL is in device-code mode. Wait briefly for the
        # callback payload to land, then surface it to the UI.
        if _SWEEP_DEVICE_CODE_EVENT.wait(timeout=15.0):
            if "exc" in error_holder:
                return {"ok": False, "detail": str(error_holder["exc"])}
            payload = dict(_SWEEP_DEVICE_CODE_PAYLOAD)
            return {
                "ok": False,
                "pending": True,
                "device_code": payload.get("device_code"),
                "user_code": payload.get("user_code"),
                "verification_uri": payload.get("verification_uri"),
                "expires_in": payload.get("expires_in"),
                "interval": payload.get("interval"),
                "message": payload.get(
                    "message",
                    f"Go to {payload.get('verification_uri')} and enter code "
                    f"{payload.get('user_code')}. Then click Sweep again.",
                ),
            }

        return {
            "ok": False,
            "pending": True,
            "detail": (
                "MSAL is still initializing the sign-in flow for the sweep. "
                "Try again in a few seconds."
            ),
        }
    finally:
        # Same idiom as /test: don't release the lock immediately — the
        # background MSAL thread may still be blocking in
        # ``acquire_token_by_device_flow`` waiting for the user. Watchdog
        # joins for up to 5 min (device-code TTL is ~15 min) then releases.
        def _releaser(t: threading.Thread) -> None:
            t.join(timeout=300)
            try:
                _SWEEP_LOCK.release()
            except RuntimeError:
                pass

        threading.Thread(
            target=_releaser,
            args=(thread,),
            name="sharepoint-sweep-auth-watchdog",
            daemon=True,
        ).start()


@router.post("/test")
def test_sharepoint(body: TestBody | None = None) -> dict:
    """Probe SharePoint with the saved (or override) config.

    Two-phase response so the HTTP request never blocks on the user finishing
    a device-code sign-in:

    1. First call with no token cache → spawn the MSAL device-code flow on a
       background thread, wait briefly for the device-code payload to land,
       return it to the UI. UI shows ``user_code`` + ``verification_uri`` and
       polls again.
    2. Subsequent calls (or any call where a refresh token already lives in
       the on-disk cache) → silent acquisition, immediate ``ok: true`` with
       site title + scan-root verification.
    """
    body = body or TestBody()
    c = cfg.load_config()
    site_url = body.site_url or c.sharepoint_site_url
    if not site_url:
        raise HTTPException(
            status_code=400,
            detail="SharePoint site URL is required (paste it in Settings or pass it in the test body).",
        )

    src = SharePointSource(
        site_url=site_url,
        library=body.library or c.sharepoint_library or "Documents",
        folder_path=body.folder_path or c.sharepoint_folder_path or "",
    )
    # No tenant/client gate — Graph PowerShell client_id is hardcoded and
    # the cloud (Commercial / GovCloud / DoD) is derived from the site
    # hostname in SharePointSource.__init__.

    # Only one test at a time — guards the device-code globals.
    if not _TEST_LOCK.acquire(blocking=False):
        # Lock is held by a prior /test that hasn't been released yet.
        # Two recoverable cases:
        #   (a) The cached device code is still valid → re-show it. Re-clicking
        #       "Sign in & test" should always show the live code, not a stale
        #       "in progress" message.
        #   (b) The cached device code has expired (or was never produced) →
        #       force-release the lock and fall through to spin a fresh flow.
        if _device_code_still_valid():
            payload = dict(_DEVICE_CODE_PAYLOAD)
            return {
                "ok": False,
                "pending": True,
                "device_code": payload.get("device_code"),
                "user_code": payload.get("user_code"),
                "verification_uri": payload.get("verification_uri"),
                "expires_in": payload.get("expires_in"),
                "interval": payload.get("interval"),
                "message": payload.get(
                    "message",
                    f"Go to {payload.get('verification_uri')} and enter code "
                    f"{payload.get('user_code')}. Then click Sign in & test again.",
                ),
            }
        # Stale lock — abandoned flow or expired code. Force-release so we can
        # start a fresh sign-in on this same call.
        LOG.info("Releasing stale SharePoint device-code lock to regenerate code")
        _force_release_lock()
        if not _TEST_LOCK.acquire(blocking=False):
            # Should be impossible — someone else grabbed it in the microsecond
            # we were holding nothing. Surface a clear error instead of looping.
            return {
                "ok": False,
                "pending": True,
                "detail": "Another sign-in just started. Wait a moment and click Sign in & test again.",
            }

    try:
        _reset_device_state()

        # The callback runs on whichever thread MSAL is on. We just stash the
        # payload and signal the foreground that it can return.
        def _on_device_code(flow: dict) -> None:
            _DEVICE_CODE_PAYLOAD.update(flow)
            _DEVICE_CODE_ISSUED_AT["ts"] = time.time()
            _DEVICE_CODE_EVENT.set()

        result_holder: dict[str, Any] = {}
        error_holder: dict[str, BaseException] = {}

        def _runner() -> None:
            try:
                result_holder["result"] = src.test_connection(on_device_code=_on_device_code)
            except BaseException as exc:  # noqa: BLE001 — capture for the foreground
                error_holder["exc"] = exc
                # If we crashed before the callback fired, unblock the foreground.
                _DEVICE_CODE_EVENT.set()

        thread = threading.Thread(target=_runner, name="sharepoint-test", daemon=True)
        thread.start()

        # Wait up to 5s for either the silent-acquisition path to finish OR for
        # MSAL to emit a device code.
        thread.join(timeout=5.0)
        if not thread.is_alive():
            # Silent path finished (cache hit) — return the actual result.
            if "exc" in error_holder:
                exc = error_holder["exc"]
                raise HTTPException(status_code=502, detail=str(exc)) from exc
            return {"ok": True, "pending": False, **result_holder.get("result", {})}

        # Still running — should mean MSAL is in device-code mode. Wait briefly
        # for the callback payload.
        if _DEVICE_CODE_EVENT.wait(timeout=15.0):
            if "exc" in error_holder:
                exc = error_holder["exc"]
                raise HTTPException(status_code=502, detail=str(exc)) from exc
            payload = dict(_DEVICE_CODE_PAYLOAD)
            return {
                "ok": False,
                "pending": True,
                "device_code": payload.get("device_code"),
                "user_code": payload.get("user_code"),
                "verification_uri": payload.get("verification_uri"),
                "expires_in": payload.get("expires_in"),
                "interval": payload.get("interval"),
                "message": payload.get(
                    "message",
                    f"Go to {payload.get('verification_uri')} and enter code "
                    f"{payload.get('user_code')}. Then click Test again.",
                ),
            }

        # Neither finished nor produced a device code — likely a network hang.
        return {
            "ok": False,
            "pending": True,
            "detail": "MSAL is still initializing the sign-in flow. Try again in a few seconds.",
        }
    finally:
        # Don't release the lock here — the background thread may still be
        # running. Release it on a fire-and-forget watchdog that joins the
        # thread up to 5 minutes (device-code expires in ~15min anyway).
        def _releaser(t: threading.Thread) -> None:
            t.join(timeout=300)
            try:
                _TEST_LOCK.release()
            except RuntimeError:
                pass

        threading.Thread(
            target=_releaser, args=(thread,), name="sharepoint-test-watchdog", daemon=True
        ).start()


@router.post("/sign-out")
def sharepoint_sign_out() -> dict:
    """Delete the persisted MSAL token cache.

    Forces the next ``/test`` (or ingest) call back through device-code. Used
    when the user switches Entra accounts or wants to revoke local-cache trust.

    Also force-releases the device-code lock, so this doubles as a "panic
    button" when a prior /test got stuck (crashed callback, browser
    abandoned mid-flow, watchdog hasn't fired yet). The lock release is
    best-effort — if no one holds it, the RuntimeError is swallowed.
    """
    removed = clear_token_cache()
    lock_released = False
    try:
        _TEST_LOCK.release()
        lock_released = True
    except RuntimeError:
        # Lock wasn't held — fine.
        pass
    _reset_device_state()
    return {"ok": True, "cache_removed": removed, "lock_released": lock_released}


@router.post("/cancel")
def sharepoint_cancel() -> dict:
    """Cancel an in-flight device-code sign-in without wiping the token cache.

    Use this when the device code expired (15min) or the browser was abandoned
    mid-flow and you want a fresh code without losing a previously-valid
    refresh token. The next ``/test`` call will start a brand-new device-code
    dance.
    """
    _force_release_lock()
    _reset_device_state()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Interactive browse — one folder level at a time
# ---------------------------------------------------------------------------


class BrowseBody(BaseModel):
    """Browse a single subfolder under the configured scan root.

    ``subfolder`` is relative to ``cfg.sharepoint_folder_path`` (the configured
    scan root inside the library), so the first call passes empty-string and
    drill-ins pass paths the browse response returned. site_url/library override
    the saved config when present — same pattern as ``/test`` — so callers can
    peek at a candidate site before committing it.
    """

    site_url: str | None = None
    library: str | None = None
    folder_path: str | None = None
    subfolder: str = ""


@router.post("/browse")
def sharepoint_browse(body: BrowseBody | None = None) -> dict:
    """Return one level of folders + files under ``subfolder``.

    Synchronous. Single Graph round-trip (plus pagination follow-on for huge
    folders). Cheap enough to call on every drill-in click; the UI doesn't
    cache between dialogs. Uses the same token as ingest, so an existing
    cache means no sign-in prompt here.
    """
    body = body or BrowseBody()
    c = cfg.load_config()
    site_url = body.site_url or c.sharepoint_site_url
    if not site_url:
        raise HTTPException(
            status_code=400,
            detail="SharePoint site URL is required (paste it in Settings or pass it in the browse body).",
        )

    src = SharePointSource(
        site_url=site_url,
        library=body.library or c.sharepoint_library or "Documents",
        folder_path=body.folder_path or c.sharepoint_folder_path or "",
    )
    try:
        return src.browse_folder(body.subfolder or "")
    except Exception as exc:  # noqa: BLE001 — surface Graph errors verbatim
        raise HTTPException(status_code=502, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Filename search — mirror nist-assessor's find-evidence pattern
# ---------------------------------------------------------------------------


class SearchBody(BaseModel):
    """Search filenames under the configured scan root.

    Mirrors ``BrowseBody`` but adds a free-text ``query`` that gets parsed
    into USD doc numbers, control IDs, and keywords. The walker is BFS-capped
    at ``max_depth`` so a too-broad scan root won't spin forever; ``max_matches``
    bounds the result list so we don't ship thousands of rows back to the UI.

    Filename-only matching — matches the nist-assessor plugin's find-evidence
    approach. The assessor still has to verify each hit is actually applicable
    before ingesting; that's surfaced in the UI banner above the result list.
    """

    site_url: str | None = None
    library: str | None = None
    folder_path: str | None = None
    query: str
    max_depth: int = 3
    max_matches: int = 200


@router.post("/search")
def sharepoint_search(body: SearchBody) -> dict:
    """Walk the scan root and return filenames matching ``body.query``.

    Synchronous like ``/browse`` — the BFS is depth-capped so the worst case
    is bounded. Same site/library/folder override semantics so the user can
    probe a different scope without changing config first.
    """
    c = cfg.load_config()
    site_url = body.site_url or c.sharepoint_site_url
    if not site_url:
        raise HTTPException(
            status_code=400,
            detail="SharePoint site URL is required (paste it in Settings or pass it in the search body).",
        )

    src = SharePointSource(
        site_url=site_url,
        library=body.library or c.sharepoint_library or "Documents",
        folder_path=body.folder_path or c.sharepoint_folder_path or "",
    )
    try:
        return src.search_files(
            body.query,
            max_depth=body.max_depth,
            max_matches=body.max_matches,
        )
    except Exception as exc:  # noqa: BLE001 — surface Graph errors verbatim
        raise HTTPException(status_code=502, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Boundary-aware sweep — no-download triage
# ---------------------------------------------------------------------------


class SweepBody(BaseModel):
    """Triage the configured scan root against a boundary scope.

    The route is **read-only** with respect to the Evidence table — no rows
    are created. The response is a ranked candidate list with proposed CCI
    mappings; the caller (UI) confirms a subset and then POSTs to the
    existing ``/api/sharepoint/ingest`` cherry-pick path with ``file_paths``
    set to the confirmed candidates.

    Scope contract (added 2026-06-05 — workbook decoupling):
        At least one of ``workbook_id`` or ``system_context_id`` must be
        provided. Both is fine too (sweep is attributed to the workbook;
        SystemContext supplies host tokens). When only ``system_context_id``
        is set, the sweep runs in **pending mode** — no workbook is open,
        scoring relies entirely on host_tokens / doc_prefixes / priority
        links from the pending SystemContext singleton. The resulting
        ``SweepRun`` row carries ``workbook_id IS NULL`` until the user
        promotes the pending scope onto a workbook.

    See :doc:`SHAREPOINT_SWEEP_DESIGN.md`. Site / library / folder follow
    the same override-or-config pattern as the other endpoints so a power
    user can sweep a different scope without changing Settings first.
    """

    workbook_id: int | None = None
    # Pending-mode scope (no workbook open yet). Either id works; both is
    # fine. Validator below enforces the at-least-one invariant — without
    # it the sweep has nothing to score against and would just BFS the
    # whole share for minutes.
    system_context_id: int | None = None
    site_url: str | None = None
    library: str | None = None
    folder_path: str | None = None
    max_candidates: int = 500
    max_search_queries: int = 50
    # Per-request cost ceiling. None ⇒ inherit ``cfg.sweep_cost_cap_usd``
    # (0 = unlimited). Positive value ⇒ override for this sweep only.
    # Currently config-only — exposed for CI / power-user automation.
    cost_cap_usd: float | None = None
    # Per-request wall-clock ceiling in seconds. None or <=0 ⇒ unlimited.
    # Wired to the inline "Stop after N min" toggle next to the Sweep button.
    # When tripped, in-flight LLM calls finish, pending judge slots fall back
    # to pure-keyword scoring (graceful degradation, not a failure).
    time_cap_seconds: float | None = None
    # Pseudo-relevance feedback. When set, these paths are the candidates the
    # assessor confirmed in a prior sweep round; the sweep entry point looks
    # them up during the BFS / search enrichment pass, extracts their
    # name+path+snippet, and the LLM judge sees them as "exemplar in-scope
    # artifacts" in its cached system block. Per-candidate calls on the
    # refine pass then have a richer semantic prior than the host-token list
    # alone — useful when the first pass surfaced obvious wins but missed
    # semantically-similar files with no token overlap. Empty/omitted ⇒
    # first-round behavior (no exemplars).
    seed_candidate_paths: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _require_scope(self) -> "SweepBody":
        if self.workbook_id is None and self.system_context_id is None:
            raise ValueError(
                "sweep requires at least one of workbook_id or "
                "system_context_id — neither was provided"
            )
        return self


@router.post("/sweep")
def sharepoint_sweep(
    body: SweepBody, s: Session = Depends(get_session)
) -> dict:
    """Boundary-aware triage of the scan root. Returns ranked candidates.

    Pipeline:

    1. Build a :class:`BoundaryFingerprint` from the workbook (host inventory,
       in-scope control families, CRM responsibility map, doc-number prefixes).
    2. Hand it to :meth:`SharePointSource.sweep_for_boundary` which BFS-walks
       Graph metadata + runs token searches and scores every file.
    3. Return :meth:`SweepResult.as_dict` verbatim.

    No file bytes are pulled and no Evidence rows are persisted — both are
    enforced inside the source method.
    """
    c = cfg.load_config()
    site_url = body.site_url or c.sharepoint_site_url
    if not site_url:
        raise HTTPException(
            status_code=400,
            detail="SharePoint site URL is required (paste it in Settings or pass it in the sweep body).",
        )

    # ----- Auth pre-flight -----------------------------------------------
    # Acquire (or refresh) the Graph token BEFORE we start building the
    # fingerprint or walking Graph. If the cached refresh token is missing
    # or expired, MSAL flips to device-code; we return that payload to the
    # UI immediately so the user can sign in. The next /sweep call after
    # sign-in completes silently and the pipeline continues.
    #
    # Why pre-flight (not lazy-inside-the-walk): the walk fires per-query
    # /search calls; a 401 deep inside would still surface (we raise now,
    # since GraphAuthError is fatal) but the UI would just see a 502 with
    # a stringified exception, not an actionable "click here to sign in"
    # payload. Pre-flighting keeps that payload accessible.
    auth = _acquire_graph_token_for_sweep(site_url)
    if not auth.get("ok"):
        if auth.get("pending"):
            # 200 with pending=true — UI distinguishes from real errors and
            # renders the device-code instructions inline.
            return auth
        raise HTTPException(
            status_code=401,
            detail=auth.get("detail") or "SharePoint sign-in failed.",
        )

    # Sweep attempts counter is telemetry-only as of v0.2 — the hard 2/2 cap
    # was removed in favor of the cost-cap (pre-flight HTTP 402 + in-flight
    # silent degrade in sweep_judge.py). Re-sweeping the same library is
    # already bounded by dollars, not iteration count, so the assessor can
    # iterate freely (e.g. sweep root, then re-sweep into Implementation/T2,
    # then again into Test/) without resetting anything. The counter still
    # ticks below for SweepRun telemetry / "this workbook has been swept N
    # times" displays.
    #
    # Workbook is optional as of 2026-06-05 (pending-mode sweep). When the
    # body carries only ``system_context_id`` we skip the workbook lookup
    # entirely and the resulting SweepRun is attributed by SystemContext
    # until the user promotes the pending scope onto a real workbook. The
    # SweepBody validator already guarantees at least one of the two ids
    # is present.
    wb: Workbook | None = None
    if body.workbook_id is not None:
        wb = s.get(Workbook, body.workbook_id)
        if wb is None:
            raise HTTPException(status_code=404, detail="workbook not found")

    try:
        fingerprint = build_boundary_fingerprint(
            session=s,
            workbook_id=body.workbook_id,
            system_context_id=body.system_context_id,
            priority_links=c.sharepoint_priority_links or [],
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=400,
            detail=f"failed to build boundary fingerprint: {exc}",
        ) from exc

    # Load active calibrated weights from the DB; falls back to hand-tuned
    # constants inside score_candidate when None (fresh install with no
    # SweepWeights row, or operator-disabled all rows).
    active_weights = load_active_weights(s)

    # Pre-flight: the scorer needs SOMETHING to discriminate candidates by.
    # Two acceptable signal sources (either is fine, both is better):
    #
    #   * In-scope controls / families from a workbook's baseline (+0.40
    #     control-id hit, family heuristics, CRM weights).
    #   * Host tokens / doc-number prefixes / priority links from a
    #     SystemContext (pending or workbook-bound). In pending mode this
    #     is the ONLY signal — the assessor adds boundary docs first, the
    #     extractor lifts hostnames, and the sweep scores filename matches.
    #
    # If neither set has any signal we'd BFS the whole share for minutes
    # and return an empty list. Fail fast with an actionable message that
    # names whichever scope the caller actually passed in.
    has_baseline_signal = bool(
        fingerprint.in_scope_control_ids or fingerprint.control_families
    )
    has_context_signal = bool(
        fingerprint.host_tokens
        or fingerprint.doc_number_prefixes
        or fingerprint.priority_path_prefixes
    )
    if not has_baseline_signal and not has_context_signal:
        if body.workbook_id is None:
            detail = (
                "The pending boundary scope has no host tokens, doc-number "
                "prefixes, or priority links to score against. Add boundary "
                "documents on the Sweep page (the extractor will lift "
                "hostnames automatically) or open a workbook with a "
                "framework selected, then retry."
            )
        else:
            detail = (
                "This workbook has no framework bound and no SystemContext "
                "signals — the boundary sweep needs in-scope controls OR "
                "host tokens / boundary docs to score against. Open the "
                "workbook with a framework selected (Workbooks tab → "
                "choose framework) or add boundary docs on the Sweep page, "
                "then retry. Tip: use Browse SharePoint → search if you "
                "just want to cherry-pick files by keyword."
            )
        raise HTTPException(status_code=422, detail=detail)

    # ----- Cost-cap pre-flight ------------------------------------------
    # Estimate expected spend from the rolling avg-cost-per-judged-candidate
    # over the last 5 SweepRun rows (workbook-scoped first, then global).
    # If we'd blow past the cap before we even start, refuse with HTTP 402
    # — distinct from the in-flight cap (which just degrades silently into
    # keyword-only). 402 = "you literally cannot afford this; raise the cap
    # or shrink max_candidates." Skipped entirely when cap <= 0 (the
    # default — corpora big enough to need a sweep are too big for a
    # fixed-dollar guardrail to be meaningful).
    # Effective cap: per-request override (inline UI toggle) wins; falls
    # back to the config default.
    effective_cap = (
        body.cost_cap_usd if body.cost_cap_usd is not None else c.sweep_cost_cap_usd
    )
    if c.sweep_judge_enabled and effective_cap > 0:
        # Look back by whichever scope id the caller passed in. In pending
        # mode (workbook_id None) we want the rolling avg over prior
        # pending sweeps for THIS SystemContext, not the global average,
        # so the cap is steered by the same boundary docs that will drive
        # the next sweep.
        if body.workbook_id is not None:
            scope_filter = SweepRun.workbook_id == body.workbook_id
        else:
            scope_filter = SweepRun.system_context_id == body.system_context_id
        recent = s.exec(
            select(SweepRun)
            .where(scope_filter)
            .order_by(SweepRun.id.desc())  # type: ignore[attr-defined]
            .limit(5)
        ).all()
        if not recent:
            recent = s.exec(
                select(SweepRun).order_by(SweepRun.id.desc()).limit(5)  # type: ignore[attr-defined]
            ).all()
        avg_per_call = 0.0
        if recent:
            tot_cost = sum(r.llm_cost_usd for r in recent)
            tot_calls = sum(r.candidates_judged for r in recent)
            if tot_calls > 0:
                avg_per_call = tot_cost / tot_calls
        # Rough estimate: a quarter of max_candidates survive keyword filter
        # on a typical run. We have no priors for the first sweep ever; in
        # that case avg_per_call == 0 → estimate 0 → never trips.
        estimate = avg_per_call * (body.max_candidates / 4.0)
        if estimate > effective_cap:
            raise HTTPException(
                status_code=402,
                detail=(
                    f"Estimated sweep cost ${estimate:.2f} exceeds cap "
                    f"${effective_cap:.2f}. Raise the cap (or uncheck "
                    f"\"Cap cost\") and retry."
                ),
            )

    # Build the judge client only if the kill-switch is on. make_client()
    # respects the cfg.llm_provider toggle so swapping providers in Settings
    # automatically flips the judge too.
    judge_client = make_client(c) if c.sweep_judge_enabled else None

    src = SharePointSource(
        site_url=site_url,
        library=body.library or c.sharepoint_library or "Documents",
        folder_path=body.folder_path or c.sharepoint_folder_path or "",
    )
    try:
        result = src.sweep_for_boundary(
            fingerprint,
            max_candidates=body.max_candidates,
            max_search_queries=body.max_search_queries,
            weights=active_weights,
            judge_client=judge_client,
            judge_model=c.llm_judge_model,
            judge_workers=c.sweep_judge_workers,
            judge_cost_cap_usd=effective_cap,
            judge_time_cap_seconds=(
                body.time_cap_seconds if body.time_cap_seconds is not None else 0.0
            ),
            judge_enabled=c.sweep_judge_enabled,
            seed_candidate_paths=body.seed_candidate_paths or None,
        )
    except Exception as exc:  # noqa: BLE001 — surface Graph errors verbatim
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    # ----- Pre-credit: flag candidates already attached as Evidence -----
    # Single batched IN-lookup against the unique-indexed Evidence.path so
    # the UI can render an "In Evidence" badge and default-uncheck pre-
    # credited rows. Per feedback_evidence_vs_sweep_split: sweep reads
    # Evidence, never writes; pre-credit suppresses re-tokenization noise
    # without hiding the candidate from coverage math.
    #
    # SweepCandidate is frozen — we rebuild each candidate via
    # dataclasses.replace and reconstruct the SweepResult so downstream
    # (SweepHit telemetry, response serialization) sees the populated
    # fields uniformly.
    library_name = body.library or c.sharepoint_library or "Documents"
    folder_path_used = body.folder_path or c.sharepoint_folder_path or ""
    sweep_uris: list[str] = []
    for cand in result.candidates:
        sweep_uris.append(
            normalize_sp_candidate_uri(
                cand.path, site_url, library_name, folder_path_used
            )
        )
    existing_map: dict[str, int] = {}
    if sweep_uris:
        # Chunk the path IN-clause: a full-library sweep on a large SDA
        # SharePoint can enumerate tens of thousands of candidate URIs in a
        # single run, past SQLITE_MAX_VARIABLES. Union the per-batch rows.
        for batch in chunked(sweep_uris):
            for path, ev_id in s.exec(
                select(Evidence.path, Evidence.id).where(
                    Evidence.path.in_(batch)  # type: ignore[attr-defined]
                )
            ).all():
                existing_map[path] = ev_id
    if existing_map:
        new_candidates = tuple(
            dataclasses.replace(
                cand,
                already_in_evidence=True,
                existing_evidence_id=existing_map[uri],
            )
            if uri in existing_map
            else cand
            for cand, uri in zip(result.candidates, sweep_uris)
        )
        result = dataclasses.replace(result, candidates=new_candidates)

    # ----- Persist SweepRun telemetry + bump workbook total ------------
    # Done BEFORE the attempts bump so a DB write failure doesn't burn an
    # attempt. weights_version_id is NOT NULL on the model — fall back to
    # the SweepWeights row created at db init (id=1) when active_weights
    # is None.
    weights_id_for_run = (
        active_weights.id
        if active_weights is not None and active_weights.id is not None
        else 1
    )
    # In pending mode the SweepRun is attributed to the SystemContext
    # only; once the user promotes the pending scope onto a workbook the
    # promote endpoint will backfill workbook_id on these rows so the
    # "latest sweep" footer keeps working post-promote.
    run = SweepRun(
        workbook_id=body.workbook_id,
        system_context_id=body.system_context_id,
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        total_candidates=len(result.candidates),
        candidates_surfaced=len(result.candidates),
        candidates_judged=result.candidates_judged,
        llm_cost_usd=result.llm_cost_usd,
        input_tokens=result.llm_tokens_in_total,
        output_tokens=result.llm_tokens_out_total,
        cache_read_tokens=result.cache_read_tokens_total,
        judge_model=result.judge_model,
        weights_version_id=weights_id_for_run,
        fingerprint_snapshot_json=json.dumps(
            result.fingerprint_snapshot, default=str
        ),
        fallback_reason=result.judge_fallback_reason,
    )
    s.add(run)

    # ----- SweepHit telemetry (0004 side table) -----------------------
    # Flush so ``run`` gets its PK assigned before SweepHit children hang
    # off it; commit stays below so both writes land atomically. Without
    # this the FK assignment would be NULL and the INSERT would fail
    # NOT-NULL on sweep_run_id.
    # FIXME(sweep-audit 2026-06-07): no cap on SweepHit writes per SweepRun.
    # A surface tray of N candidates each with up to 6 signal types
    # (host/control/family/crm-kw/doc-prefix/priority) writes up to 6*N rows
    # per run. crm-kw is already capped to 3 surfaced tokens per candidate
    # but other signal types can multiply further. At 200 surfaced candidates
    # this is a ~1200-row write per sweep — fine now, but consider a hard cap
    # or per-(run, candidate, signal_kind) dedupe before v0.4 connector load.
    s.flush()
    if run.id is not None:
        # Prefix → weight map. ``active_weights`` is the persisted
        # SweepWeights row honored by ``score_candidate``; falling back
        # to the module-level constants keeps detail-pane math correct
        # when the user is running on stock weights (active_weights=None).
        signal_weights = {
            "host": active_weights.weight_host
            if active_weights is not None
            else _W_HOST,
            "control": active_weights.weight_control_id
            if active_weights is not None
            else _W_CONTROL_ID,
            "family": active_weights.weight_family
            if active_weights is not None
            else _W_FAMILY,
            "crm-kw": active_weights.weight_crm_keyword
            if active_weights is not None
            else _W_CRM_KEYWORD,
            "doc-prefix": active_weights.weight_doc_prefix
            if active_weights is not None
            else _W_DOC_PREFIX,
            "priority": active_weights.weight_priority_link
            if active_weights is not None
            else _W_PRIORITY_LINK,
        }
        for cand in result.candidates:
            # web_url is stable per SP item and is what a future detail
            # pane would deep-link to. SweepCandidate doesn't surface
            # drive_id:item_id without expanding its public dataclass
            # which is out of slice scope.
            cand_key = cand.web_url or cand.path or cand.name
            if not cand_key:
                continue
            for signal in cand.matched_signals:
                # Signals are ``prefix:token`` from sweep.py:798-876.
                # Split on first ":" only — tokens (FQDNs, IPs) can
                # contain ":" themselves in theory.
                if ":" not in signal:
                    continue
                prefix, _, token = signal.partition(":")
                contribution = signal_weights.get(prefix)
                if contribution is None:
                    # Unknown signal kind — future-proof: don't drop the
                    # row, record 0.0 so the detail pane still shows the
                    # signal fired but flags it for investigation.
                    contribution = 0.0
                s.add(
                    SweepHit(
                        sweep_run_id=run.id,
                        candidate_key=cand_key,
                        matched_token=token,
                        matched_signal=signal,
                        score_contribution=float(contribution),
                    )
                )

    # Workbook counters only bump when a workbook is actually open. Pending
    # sweeps have no workbook to attribute cost to; the SweepRun row above
    # is the system of record and the promote step will roll its cost into
    # the workbook total at that point.
    if wb is not None:
        wb.total_sweep_cost_usd = (wb.total_sweep_cost_usd or 0.0) + result.llm_cost_usd
        # Sweep succeeded — burn the attempt. Done here (not before the Graph
        # call) so a transient 502 doesn't cost the user a try.
        wb.sweep_attempts = (wb.sweep_attempts or 0) + 1
        s.add(wb)
    s.commit()

    return result.as_dict()


# ---------------------------------------------------------------------------
# Manual escape hatch — ingest every file in a folder, skip scoring entirely
# ---------------------------------------------------------------------------


class SweepIngestAllBody(BaseModel):
    """Body for ``POST /api/sharepoint/sweep/ingest-all``.

    When the boundary sweep's keyword + LLM-judge scoring still misses the
    user's intended evidence (rare with B1's content-fetch fallback but
    real — e.g. a deeply renamed folder of program docs that bears no
    lexical relationship to the boundary tokens), this endpoint walks the
    folder unconditionally and ingests every file. Bypasses ``score_candidate``
    entirely. Same pipeline as ``POST /api/evidence/ingest`` with a
    SharePoint source spec — this endpoint just lives next to ``/sweep``
    so the UI can wire the button without crossing routers.

    No ``system_context_id`` field: ingest-all doesn't score, so the boundary
    fingerprint isn't relevant. ``workbook_id`` flows through so auto-tags
    land under the right framework lens.
    """

    site_url: str | None = None
    library: str | None = None
    folder_path: str | None = None
    workbook_id: int | None = None


@router.post("/sweep/ingest-all")
def sharepoint_sweep_ingest_all(body: SweepIngestAllBody) -> dict:
    """Walk the folder and ingest every supported file — no scoring.

    Returns ``{"job_id": ...}`` (same shape as ``/api/evidence/ingest``) so
    the UI's existing ingest-job poller (``/api/evidence/ingest/jobs/{id}``)
    handles progress + completion without a second polling endpoint.

    Auth pre-flight matches ``/sweep`` — a pending device-code flow returns
    ``{"ok": False, "pending": True, ...}`` for the UI to surface.
    """
    from ..evidence import jobs as ingest_jobs  # local import — avoids cycle

    c = cfg.load_config()
    site_url = body.site_url or c.sharepoint_site_url
    if not site_url:
        raise HTTPException(
            status_code=400,
            detail=(
                "SharePoint site URL is required (paste it in Settings or "
                "pass it in the request body)."
            ),
        )

    auth = _acquire_graph_token_for_sweep(site_url)
    if not auth.get("ok"):
        if auth.get("pending"):
            return auth
        raise HTTPException(
            status_code=401,
            detail=auth.get("detail") or "SharePoint sign-in failed.",
        )

    src = SharePointSource(
        site_url=site_url,
        library=body.library or c.sharepoint_library or "Documents",
        folder_path=body.folder_path or c.sharepoint_folder_path or "",
    )

    try:
        job_id = ingest_jobs.registry.start_ingest_job(
            src, workbook_id=body.workbook_id
        )
    except RuntimeError as exc:
        # Another ingest is already in flight — JobRegistry rejects concurrent
        # starts so the per-thread Session doesn't race. Surface 409 so the
        # UI shows "wait for the current run to finish" instead of swallowing.
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    LOG.info(
        "SharePoint ingest-all started: job_id=%s site=%s folder=%r workbook_id=%s",
        job_id, site_url, src.folder_path, body.workbook_id,
    )
    return {"job_id": job_id}


def _sweep_run_to_dict(run: SweepRun) -> dict:
    """Serialize a SweepRun for the "Last sweep …" footer endpoints.

    Shared by ``/sweep-runs/{workbook_id}/latest`` and the pending-mode
    twin ``/sweep-runs/by-system-context/{id}/latest`` so post-promote
    reparenting doesn't require the UI to know which key the row was
    originally written under.
    """
    return {
        "id": run.id,
        "workbook_id": run.workbook_id,
        "system_context_id": run.system_context_id,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "total_candidates": run.total_candidates,
        "candidates_surfaced": run.candidates_surfaced,
        "candidates_judged": run.candidates_judged,
        "llm_cost_usd": run.llm_cost_usd,
        "input_tokens": run.input_tokens,
        "output_tokens": run.output_tokens,
        "cache_read_tokens": run.cache_read_tokens,
        "judge_model": run.judge_model,
        "fallback_reason": run.fallback_reason,
    }


@router.get("/sweep-runs/{workbook_id}/latest")
def latest_sweep_run(workbook_id: int, s: Session = Depends(get_session)) -> dict | None:
    """Return the most recent SweepRun for a workbook, or ``None`` if none yet.

    Powers the "Last sweep: $X.XX · N judged · {model} · {minutes}m ago" footer
    on the Sweep Context page. Cheap — a single indexed lookup on
    ``sweeprun.workbook_id`` ordered by id desc. Returns ``None`` (not 404)
    when the workbook has never been swept so the UI can render nothing
    without spamming the console with errors on fresh workbooks.
    """
    run = s.exec(
        select(SweepRun)
        .where(SweepRun.workbook_id == workbook_id)
        .order_by(SweepRun.id.desc())  # type: ignore[union-attr]
        .limit(1)
    ).first()
    if run is None:
        return None
    return _sweep_run_to_dict(run)


@router.get("/sweep-runs/by-system-context/{system_context_id}/latest")
def latest_sweep_run_by_system_context(
    system_context_id: int, s: Session = Depends(get_session)
) -> dict | None:
    """Latest SweepRun for a SystemContext (pending-mode footer).

    Pending sweeps run before any workbook is open, so the workbook-keyed
    endpoint above can't surface them. The Sweep Context page falls back
    to this one when there's no active workbook but a pending SystemContext
    exists. After promote, both endpoints surface the same row (the
    workbook one via ``workbook_id`` newly backfilled, this one via the
    unchanged ``system_context_id``).
    """
    run = s.exec(
        select(SweepRun)
        .where(SweepRun.system_context_id == system_context_id)
        .order_by(SweepRun.id.desc())  # type: ignore[union-attr]
        .limit(1)
    ).first()
    if run is None:
        return None
    return _sweep_run_to_dict(run)


# ---------------------------------------------------------------------------
# Sweep decisions — labeled outcomes from SweepTriageDialog (implicit labels
# for online SGD calibration of the sweep weights)
# ---------------------------------------------------------------------------


class SweepDecisionEntry(BaseModel):
    """One row's worth of triage outcome. The UI assembles a batch of these
    at "Ingest" click and POSTs them fire-and-forget. The score and signals
    are passed back verbatim from the sweep response so the recorded
    fingerprint matches what the assessor actually saw."""

    candidate_path: str
    candidate_name: str
    score_at_decision: float
    signals: list[str]
    proposed_ccis: list[str]
    included: bool
    auto_prechecked: bool


class SweepDecisionsBody(BaseModel):
    """Batch payload for ``POST /sweep/decisions``.

    ``weights_version_id`` is the ``SweepWeights.id`` returned in the
    sweep response that produced these scores — kept verbatim so the
    online updater can recover the exact weight vector the assessor
    saw, even if a new active version landed in between.
    ``fingerprint_snapshot`` is whatever shape the sweep handler chose
    to expose (currently a dict of host_tokens / in_scope_control_ids
    / etc.); stored as JSON for batch recalibration to recompute
    features without re-walking SharePoint.
    """

    workbook_id: int
    weights_version_id: int
    fingerprint_snapshot: dict
    decisions: list[SweepDecisionEntry]


@router.post("/sweep/decisions")
def record_sweep_decisions(
    body: SweepDecisionsBody, s: Session = Depends(get_session)
) -> dict:
    """Persist a triage session's per-candidate outcomes.

    Fire-and-forget from the UI — never blocks Ingest. Each candidate
    becomes one ``SweepDecision`` row tagged with the weight version it
    was scored under; the online SGD updater (``engine.sweep_online``)
    pulls unconsumed rows on its next pass.

    Returns the inserted count rather than the row IDs — the UI has no
    use for them and exposing them risks coupling the SGD pipeline to
    a synchronous response.
    """
    if not body.decisions:
        return {"inserted": 0}

    # Resolve weights ID once. If the row was deleted in between (unlikely
    # — operators don't delete historical weights — but cheap to guard),
    # we fall back to the active row to keep the FK satisfied; the
    # mismatch is annotated in signals_json so the updater can detect.
    weights_row = s.get(SweepWeights, body.weights_version_id)
    if weights_row is None:
        active = s.exec(
            select(SweepWeights).where(SweepWeights.is_active == True)  # noqa: E712
        ).first()
        if active is None:
            raise HTTPException(
                status_code=409,
                detail=(
                    "weights_version_id is unknown and no active SweepWeights "
                    "row exists — refusing to log unanchored decisions."
                ),
            )
        resolved_weights_id = active.id
    else:
        resolved_weights_id = weights_row.id

    import json as _json

    fp_json = _json.dumps(body.fingerprint_snapshot, sort_keys=True)

    inserted = 0
    for d in body.decisions:
        s.add(
            SweepDecision(
                workbook_id=body.workbook_id,
                candidate_path=d.candidate_path,
                candidate_name=d.candidate_name,
                score_at_decision=d.score_at_decision,
                signals_json=_json.dumps(d.signals),
                proposed_ccis_json=_json.dumps(d.proposed_ccis),
                fingerprint_snapshot_json=fp_json,
                weights_version_id=resolved_weights_id,
                included=d.included,
                auto_prechecked=d.auto_prechecked,
            )
        )
        inserted += 1
    s.commit()

    # Kick the online SGD updater on a background thread. Cheap check
    # first: the updater needs >= MIN_DECISIONS_FOR_ONLINE_FIT unconsumed
    # rows to do anything, so don't even spin a thread for sub-threshold
    # writes (the common case on a partial triage session). The thread
    # opens its own Session — the request-scoped ``s`` will close on
    # response return.
    unconsumed = s.exec(
        select(SweepDecision).where(
            SweepDecision.consumed_for_training.is_(False)  # type: ignore[union-attr]
        )
    ).all()
    if len(unconsumed) >= MIN_DECISIONS_FOR_ONLINE_FIT:
        def _run_online_update() -> None:
            try:
                with session_scope() as bg_session:
                    update_weights_online(bg_session)
            except Exception:  # noqa: BLE001 — background, never break ingest
                LOG.exception("update_weights_online background task failed")

        threading.Thread(
            target=_run_online_update,
            name="sweep-online-update",
            daemon=True,
        ).start()

    return {"inserted": inserted}


# ---------------------------------------------------------------------------
# Priority links — bookmark URLs the user pastes for quick reference
# ---------------------------------------------------------------------------


class PriorityLink(BaseModel):
    """One bookmark row. ``url`` is the SharePoint deep link the user copied
    from the browser address bar; ``label`` is the human-friendly name they
    want to see in the picker."""

    label: str
    url: str


class PriorityLinksBody(BaseModel):
    """Full replacement payload — UI sends the entire list on every save."""

    links: list[PriorityLink]


@router.get("/priority-links")
def list_priority_links() -> dict:
    """Return the saved priority-link bookmarks.

    Returns shape ``{"links": [...]}`` rather than a bare array so the
    response is forward-compatible (future fields like default sort order
    can land next to ``links`` without breaking callers).
    """
    c = cfg.load_config()
    return {"links": c.sharepoint_priority_links or []}


@router.put("/priority-links")
def set_priority_links(body: PriorityLinksBody) -> dict:
    """Replace the priority-link list (PUT semantics, no diff).

    Trims label/URL and silently drops fully-empty rows so the UI's
    "add row" affordance doesn't have to grow a delete button for blank
    rows — leaving the row empty and clicking Save removes it.
    """
    c = cfg.load_config()
    cleaned: list[dict] = []
    for link in body.links:
        label = (link.label or "").strip()
        url = (link.url or "").strip()
        if not label and not url:
            continue
        cleaned.append({"label": label or url, "url": url})
    c.sharepoint_priority_links = cleaned
    cfg.save_config(c)
    return {"ok": True, "links": cleaned}
