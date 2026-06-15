"""SharePoint document-library source — Microsoft Graph edition.

Talks to SharePoint Online via **Microsoft Graph** (``/sites/{id}/drives``)
with delegated tokens minted by MSAL public-client device-code flow against
the well-known **Graph PowerShell** client ID
(``14d82eec-204b-4c2f-b7e8-296a70dab67e``). The cloud (Commercial / GovCloud
/ DoD) is auto-detected from the site URL hostname, and the multi-tenant
``organizations`` authority routes the user to whichever Entra tenant their
account lives in.

Plug-and-play across organizations
----------------------------------
Earlier revisions required each user to register their own public-client app
in Entra ID and paste the tenant/client IDs into Settings. That was a
non-starter for the "paste a site URL and click sign-in" UX, and it was
fragile in tenants whose admins lock down arbitrary first-party app
consent. Graph PowerShell is:

* Multi-cloud (Commercial, GovCloud, DoD all recognise the same client ID),
* Multi-tenant (works against any tenant the signed-in user belongs to), and
* Either already consented or able to consent itself (``Sites.Read.All``
  is a delegated scope that the user can grant on first sign-in unless the
  tenant explicitly blocks user consent).

The only thing the user pastes is the site URL. The rest is derived:

* hostname suffix ``*.sharepoint-mil.us``  → DoD Graph
* hostname suffix ``*.sharepoint.us``      → GovCloud Graph
* hostname suffix ``*.sharepoint.com``     → Commercial Graph
* anything else                            → Commercial (best-effort default)

Token cache
-----------
Persisted under ``~/.cybersecurity-assessor/graph_token_cache.json`` so the
device-code flow runs once per user, then refreshes silently. The filename
deliberately differs from the legacy ``sharepoint_token_cache.json`` so a
prior install's stale cache doesn't confuse the new flow.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import BinaryIO, Callable, Iterator
from urllib.parse import quote, urlparse

from .base import SourceFile
from ...models import SweepWeights
from .sweep import (
    SCORE_SURFACE_THRESHOLD,
    _KW_BLEND_WEIGHT,
    _LLM_BLEND_WEIGHT,
    BoundaryFingerprint,
    SweepCandidate,
    SweepResult,
    score_candidate,
)
from .sweep_judge import judge_candidates_concurrent

LOG = logging.getLogger(__name__)

# Same set the local walker uses — kept duplicated so the SharePoint
# walker doesn't depend on the local-folder module's internals.
_INGESTIBLE_SUFFIXES = {
    ".pdf",
    ".docx",
    ".pptx",
    ".xlsx",
    ".xlsm",
    ".ckl",
    ".cklb",
    ".xml",
    ".nessus",
    ".txt",
    ".md",
    ".log",
    ".csv",
}

# Well-known "Microsoft Graph PowerShell" public client. Multi-tenant,
# multi-cloud, broadly pre-consented for delegated Graph scopes. Using this
# means *no per-org Entra app registration is required* — paste the site URL,
# sign in, done. If a tenant blocks user consent entirely, the device-code
# flow surfaces that as a clean AADSTS65001 message and the user takes it to
# their IT team. We can't fix tenant-wide consent policy from the client.
GRAPH_POWERSHELL_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"

# Multi-tenant authority placeholder — only used as a fallback when we
# can't resolve the SharePoint host's tenant up front (network blocked,
# unauthenticated probe rejected, etc). The happy path resolves the
# **specific** tenant ID for the target site host before sign-in so MSAL
# routes the user to whichever tenant owns the site. Without that, signing
# in to a different tenant than the site lives in produces a token whose
# tenant claim doesn't match Graph's view of the site → 400 invalidRequest
# from /sites/{host}:/... because Graph site-by-path is single-tenant.
MSAL_TENANT = "organizations"

# Single delegated scope is enough for read-only walk + download. Scope must
# match the target cloud's Graph audience — see ``cloud_for(...).graph_resource``.
# Using ``graph.microsoft.com/.default`` on GovCloud/DoD mints a token with the
# wrong ``aud`` claim and the gov Graph endpoint rejects it with
# ``Invalid audience`` (401).
def _scopes_for(endpoint: "CloudEndpoint") -> list[str]:
    return [f"{endpoint.graph_resource}/.default"]

# Legacy export — routes/sharepoint.py still imports this. Unused by the
# new flow but kept so the import doesn't break on rollout. Safe to delete
# in a follow-up once the route is updated.
DEFAULT_GOV_AUTHORITY = "https://login.microsoftonline.us"


# ---------------------------------------------------------------------------
# Cloud routing — hostname → authority + graph endpoint
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CloudEndpoint:
    """Per-cloud Graph + login endpoints derived from the site URL.

    ``cloud_name`` is the user-facing label ("Commercial", "GovCloud", "DoD")
    that the Settings card renders as a Badge so it's obvious the URL was
    parsed correctly before sign-in.

    ``graph_resource`` is the audience the access token must be minted for.
    Entra binds the token's ``aud`` claim to the scope's resource URI — if we
    ask for ``graph.microsoft.com/.default`` and call ``graph.microsoft.us``,
    the gov Graph endpoint rejects the token with "Invalid audience" (401).
    Per-cloud scopes are mandatory; we can't share one literal across clouds.
    """

    cloud_name: str
    authority_base: str  # MSAL authority, e.g. https://login.microsoftonline.us
    graph_base: str  # Graph root, e.g. https://graph.microsoft.us/v1.0
    graph_resource: str  # Audience for token scope, e.g. https://graph.microsoft.us


def cloud_for(site_url: str) -> CloudEndpoint:
    """Map a SharePoint site URL to the right cloud's Graph + login endpoints.

    Order matters: ``*.sharepoint-mil.us`` is a strict suffix of
    ``*.sharepoint.us`` if you squint, so DoD must be checked first.
    Anything we don't recognise falls back to Commercial — the worst case
    is a clear "site not found" from Graph rather than a silent wrong-cloud.
    """
    host = (urlparse(site_url).netloc or site_url).lower()
    if host.endswith(".sharepoint-mil.us"):
        return CloudEndpoint(
            cloud_name="DoD",
            authority_base="https://login.microsoftonline.us",
            graph_base="https://dod-graph.microsoft.us/v1.0",
            graph_resource="https://dod-graph.microsoft.us",
        )
    if host.endswith(".sharepoint.us"):
        return CloudEndpoint(
            cloud_name="GovCloud",
            authority_base="https://login.microsoftonline.us",
            graph_base="https://graph.microsoft.us/v1.0",
            graph_resource="https://graph.microsoft.us",
        )
    if host.endswith(".sharepoint.com"):
        return CloudEndpoint(
            cloud_name="Commercial",
            authority_base="https://login.microsoftonline.com",
            graph_base="https://graph.microsoft.com/v1.0",
            graph_resource="https://graph.microsoft.com",
        )
    LOG.warning(
        "Unrecognised SharePoint host %r — defaulting to Commercial cloud.", host
    )
    return CloudEndpoint(
        cloud_name="Commercial",
        authority_base="https://login.microsoftonline.com",
        graph_base="https://graph.microsoft.com/v1.0",
        graph_resource="https://graph.microsoft.com",
    )


def _sharepoint_uri(site_url: str, server_relative_url: str) -> str:
    """Render a SharePoint server-relative path as a ``sharepoint://`` URI.

    The canonical Evidence/IngestSummary URI shape — kept stable across the
    REST→Graph rewrite so existing rows still resolve.
    """
    parsed = urlparse(site_url)
    host = parsed.netloc or parsed.path
    return f"sharepoint://{host}{quote(server_relative_url, safe='/')}"


# ---------------------------------------------------------------------------
# MSAL token acquisition — device-code flow with persistent cache
# ---------------------------------------------------------------------------


def _token_cache_path() -> Path:
    """Persistent MSAL token cache lives next to config.toml.

    Filename differs from the legacy ``sharepoint_token_cache.json`` so a
    stale REST-API cache from a prior install can't be mistaken for a fresh
    Graph cache. ``clear_token_cache`` only removes this new path; the old
    one becomes garbage that ``sharepoint_sign_out`` no longer touches —
    harmless, and explicit cleanup would silently delete the user's
    in-progress upgrade state.
    """
    from ... import config as cfg  # noqa: PLC0415

    return cfg.config_dir() / "graph_token_cache.json"


def _resolve_tenant_for_host(host: str) -> str | None:
    """Resolve the Entra tenant ID that owns a SharePoint host.

    Uses the standard "client.svc realm" trick: hitting any SharePoint REST
    endpoint with an empty Bearer challenge returns 401 with a
    ``WWW-Authenticate`` header whose ``realm`` value is the tenant GUID.
    This works unauthenticated and cross-cloud (Commercial / GovCloud / DoD)
    because the realm is part of the public WS-Federation handshake.

    Returning ``None`` is fine — the caller falls back to ``organizations``
    (multi-tenant) and signs the user into their home tenant. That's the old
    behaviour, and breaks for cross-tenant sites, so we only fall back when
    the realm probe itself fails (network blocked, host typo, etc).
    """
    try:
        import re  # noqa: PLC0415
        import requests  # noqa: PLC0415
    except ImportError:
        return None
    url = f"https://{host}/_vti_bin/client.svc"
    try:
        # Trailing space in the Authorization value is intentional — empty
        # Bearer triggers a realm-bearing 401 on every SharePoint tenant.
        resp = requests.get(
            url,
            headers={"Authorization": "Bearer "},
            timeout=10,
            allow_redirects=False,
        )
    except Exception as exc:  # noqa: BLE001
        LOG.debug("Tenant realm probe failed for %s: %s", host, exc)
        return None
    auth = resp.headers.get("WWW-Authenticate", "")
    m = re.search(r'realm="([0-9a-fA-F-]{36})"', auth)
    if not m:
        LOG.debug("No realm GUID in WWW-Authenticate for %s: %r", host, auth)
        return None
    return m.group(1)


def _build_msal_app(authority_base: str, tenant: str):
    """Construct an MSAL ``PublicClientApplication`` with disk-backed cache.

    ``tenant`` is either a tenant GUID (resolved from the SharePoint host via
    ``_resolve_tenant_for_host``) or the literal ``organizations`` fallback.
    Tenant-specific authority is the only thing that makes cross-tenant site
    access work: signing into the wrong tenant mints a token Graph happily
    issues, then rejects on the site lookup because tenant↔site is a 1:1
    binding on Graph's side.
    """
    try:
        import msal  # type: ignore[import-not-found]  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError(
            "msal is not installed. Install the 'sources' extras: "
            "`pip install -e .[sources]` from backend/."
        ) from exc

    cache = msal.SerializableTokenCache()
    cache_path = _token_cache_path()
    if cache_path.exists():
        try:
            cache.deserialize(cache_path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 — corrupt cache shouldn't crash login
            LOG.warning("Graph token cache unreadable, ignoring: %s", exc)

    return msal.PublicClientApplication(
        client_id=GRAPH_POWERSHELL_CLIENT_ID,
        authority=f"{authority_base}/{tenant}",
        token_cache=cache,
    )


def _persist_cache(app) -> None:
    cache = app.token_cache
    if cache.has_state_changed:
        path = _token_cache_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(cache.serialize(), encoding="utf-8")


def acquire_token(
    *,
    endpoint: CloudEndpoint,
    site_host: str | None = None,
    on_device_code: Callable[[dict], None] | None = None,
) -> str:
    """Return a Microsoft Graph access token, prompting for sign-in if needed.

    Silent-first via the on-disk refresh token cache; device-code fallback
    on miss. The callback receives the MSAL flow dict so the HTTP probe can
    push ``user_code`` / ``verification_uri`` into the response payload.

    Args:
        endpoint: Resolved cloud (authority + graph base + audience). Drives
            both the MSAL authority host *and* the scope resource so the
            issued token's ``aud`` claim matches the Graph endpoint we'll
            call. Mismatch = 401 ``Invalid audience``.
        site_host: SharePoint hostname (e.g. ``collab.example.com``) —
            used to resolve the tenant ID that owns the site so MSAL signs
            the user into THAT tenant. Falls back to multi-tenant
            ``organizations`` when omitted or unresolvable. Required for
            cross-tenant scenarios (assessor in tenant A, site in tenant B);
            without it Graph rejects /sites/{host}:/... with 400
            invalidRequest because the token's tenant doesn't match.
        on_device_code: Callback that receives the device-code flow dict.
    """
    tenant = MSAL_TENANT
    if site_host:
        resolved = _resolve_tenant_for_host(site_host)
        if resolved:
            tenant = resolved
            LOG.info("Using tenant %s for SharePoint host %s", resolved, site_host)
        else:
            LOG.info(
                "Could not resolve tenant for %s, falling back to multi-tenant",
                site_host,
            )
    app = _build_msal_app(endpoint.authority_base, tenant)
    scopes = _scopes_for(endpoint)

    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent(scopes, account=accounts[0])
        if result and "access_token" in result:
            _persist_cache(app)
            return result["access_token"]

    flow = app.initiate_device_flow(scopes=scopes)
    if "user_code" not in flow:
        raise RuntimeError(
            f"Graph device-code init failed: {flow.get('error_description') or flow}"
        )
    if on_device_code is not None:
        try:
            on_device_code(flow)
        except Exception:  # noqa: BLE001 — callback failure must not block login
            LOG.exception("on_device_code callback raised")

    result = app.acquire_token_by_device_flow(flow)
    _persist_cache(app)
    if "access_token" not in result:
        raise RuntimeError(
            f"Graph device-code auth failed: {result.get('error_description') or result}"
        )
    return result["access_token"]


# ---------------------------------------------------------------------------
# Graph HTTP helpers — thin layer over `requests`
# ---------------------------------------------------------------------------


class GraphAuthError(RuntimeError):
    """Graph rejected our bearer token (401).

    Distinct from generic ``RuntimeError`` so the sweep can treat token
    expiry as fatal (force re-auth) instead of silently skipping every
    per-query ``/search`` call and returning an empty candidate list. The
    sweep previously caught the bare ``RuntimeError``, logged "skipping",
    and finished "successfully" with zero candidates — looking like a
    SharePoint indexing problem to the user when it was actually our
    cached token having expired.
    """


# Status codes Graph documents as transient. 429 = throttled (respect
# Retry-After), 503 = service unavailable, 504 = gateway timeout. Empirically
# the sweep's /search calls eat 503s and 504s during $skiptoken pagination on
# busy tenants — without retry, one slow page poisons an entire query.
_GRAPH_RETRY_STATUS = {429, 503, 504}
_GRAPH_RETRY_MAX_ATTEMPTS = 4  # initial + 3 retries
_GRAPH_RETRY_BACKOFF_BASE = 1.5  # seconds; doubles each attempt


def _graph_get(url: str, token: str, *, stream: bool = False):
    """GET ``url`` with Bearer auth; raise on non-2xx with body in the message.

    Kept tiny on purpose. The previous SDK (Office365-REST-Python-Client)
    swallowed too many request details on failure ("internal server error"
    with no body), which made gov-cloud auth failures painful to diagnose.
    Surfacing the raw status + body upstream is a deliberate trade.

    Retries 429/503/504 with exponential backoff (honoring Retry-After when
    present). 401 → ``GraphAuthError`` (distinct type so callers can
    force-clear the MSAL cache and re-prompt). All other non-2xx → bare
    ``RuntimeError``.
    """
    try:
        import requests  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError(
            "requests is not installed. Install the 'sources' extras: "
            "`pip install -e .[sources]` from backend/."
        ) from exc

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    last_resp = None
    for attempt in range(_GRAPH_RETRY_MAX_ATTEMPTS):
        resp = requests.get(url, headers=headers, stream=stream, timeout=60)
        if resp.ok:
            return resp
        last_resp = resp
        if resp.status_code not in _GRAPH_RETRY_STATUS:
            break
        if attempt == _GRAPH_RETRY_MAX_ATTEMPTS - 1:
            break
        # Prefer server-provided Retry-After (seconds); fall back to
        # exponential backoff with mild jitter so retries don't synchronize.
        retry_after_hdr = resp.headers.get("Retry-After")
        try:
            delay = (
                float(retry_after_hdr)
                if retry_after_hdr
                else _GRAPH_RETRY_BACKOFF_BASE * (2 ** attempt)
            )
        except ValueError:
            delay = _GRAPH_RETRY_BACKOFF_BASE * (2 ** attempt)
        delay = min(delay, 30.0)  # cap so one bad page can't stall for minutes
        LOG.info(
            "Graph %s on %s — retrying in %.1fs (attempt %d/%d)",
            resp.status_code,
            url,
            delay,
            attempt + 1,
            _GRAPH_RETRY_MAX_ATTEMPTS,
        )
        time.sleep(delay)
        # Drain prior response so the connection can be reused.
        try:
            resp.close()
        except Exception:  # noqa: BLE001
            pass

    resp = last_resp
    # Truncate big error bodies so the UI doesn't get a wall of HTML.
    body = (resp.text or "")[:500] if resp is not None else ""
    status = resp.status_code if resp is not None else "?"
    if resp is not None and resp.status_code == 401:
        raise GraphAuthError(f"Graph {status} on {url}: {body}")
    raise RuntimeError(f"Graph {status} on {url}: {body}")


def _resolve_site_id(graph_base: str, token: str, site_url: str) -> dict:
    """Look up the Graph site-id for a SharePoint site URL.

    Graph addresses sites as ``{hostname}:{server-relative-path}``. The
    returned ``id`` is the comma-triple
    (``{hostname},{site-collection-guid},{web-guid}``) that every subsequent
    drives/items call needs.
    """
    parsed = urlparse(site_url)
    host = parsed.netloc
    # Strip leading + trailing slashes so we can compose the colon-slash
    # separator ourselves. urlparse keeps the leading slash; if we don't
    # strip it we end up with ``host://sites/...`` (double-slash after the
    # colon) which Graph rejects as invalidRequest.
    rel_path = parsed.path.strip("/")  # e.g. sites/PRGM-EXAMPLE
    if not host or not rel_path:
        raise RuntimeError(
            f"Site URL must include host and a /sites/... path: {site_url!r}"
        )
    # Graph site-by-path: GET /sites/{hostname}:/{server-relative-path}
    # No trailing colon — that form is only for drive-item path addressing
    # (where the colon terminates the path before ``:/children`` etc).
    url = f"{graph_base}/sites/{host}:/{quote(rel_path, safe='/')}"
    resp = _graph_get(url, token)
    return resp.json()


def _find_drive_id(graph_base: str, token: str, site_id: str, library: str) -> dict:
    """Find a drive (document library) by display name on a site.

    Returns the full drive object so callers can inspect ``webUrl`` and
    ``name``. Match is case-insensitive on ``name`` because SharePoint
    libraries are routinely renamed and capitalisation drift bites users.
    """
    url = f"{graph_base}/sites/{site_id}/drives"
    drives = _graph_get(url, token).json().get("value", [])
    target = (library or "Documents").strip().lower()
    for d in drives:
        if (d.get("name") or "").strip().lower() == target:
            return d
    # Helpful failure — list what we did see so the user can correct the name.
    seen = ", ".join(d.get("name", "?") for d in drives) or "(no drives)"
    raise RuntimeError(
        f"Library {library!r} not found on site. Available drives: {seen}"
    )


def _list_children(graph_base: str, token: str, drive_id: str, path: str) -> list[dict]:
    """List children of ``path`` inside ``drive_id``.

    Empty ``path`` → drive root. Walks ``@odata.nextLink`` to follow Graph's
    paginated responses so large libraries don't silently truncate.
    """
    if path:
        url = (
            f"{graph_base}/drives/{drive_id}/root:/"
            f"{quote(path.strip('/'), safe='/')}:/children"
        )
    else:
        url = f"{graph_base}/drives/{drive_id}/root/children"

    items: list[dict] = []
    while url:
        try:
            page = _graph_get(url, token).json()
        except GraphAuthError:
            # Auth failures are fatal regardless of how many pages we'd
            # collected — propagate so the sweep can clear the token cache.
            raise
        except Exception as exc:  # noqa: BLE001
            # Preserve whatever pages we already collected. Earlier behavior
            # discarded the whole accumulator when page N raised, which on
            # a slow tenant turned a single 504 on $skiptoken into "this
            # folder is empty" upstream.
            LOG.info(
                "Graph pagination failed on %s after %d pages — "
                "returning partial result (%s)",
                url,
                _count_pages_done(items),
                exc,
            )
            break
        items.extend(page.get("value", []))
        url = page.get("@odata.nextLink") or ""
    return items


def _count_pages_done(items: list[dict]) -> int:
    """Best-effort page count for log lines — items / 200 rounded up."""
    return max(1, (len(items) + 199) // 200) if items else 0


def _get_item_by_path(graph_base: str, token: str, drive_id: str, path: str) -> dict:
    """Fetch a single drive item by drive-relative ``path``.

    Returns the DriveItem dict (including ``@microsoft.graph.downloadUrl``).
    Used by the cherry-pick ingest path so we can fetch hand-selected files
    without walking the whole tree.
    """
    url = (
        f"{graph_base}/drives/{drive_id}/root:/"
        f"{quote(path.strip('/'), safe='/')}"
    )
    return _graph_get(url, token).json()


def _search_drive(
    graph_base: str, token: str, drive_id: str, query: str
) -> list[dict]:
    """Run Graph drive-scoped search for ``query``; return matching DriveItems.

    Used by the boundary sweep to enrich enumerated candidates with content-
    matching hints. Graph's drive search hits both name and indexed content,
    and may return a ``searchResult`` facet (sometimes with a ``summary``
    snippet — tenant-dependent). Walks ``@odata.nextLink`` so a popular
    token doesn't silently truncate to one page.

    Quoting rules layered here:
      * KQL phrase quotes around the whole query so operators inside boundary
        tokens stay literal — CIDRs like ``10.10.5.0/24`` and control IDs like
        ``AC-2(1)`` otherwise come back ``BadRequest - Error in query syntax``
        because ``/``, ``(``, ``)``, ``:`` are KQL operators. Phrase wrapping
        forces literal matching; embedded ``"`` is doubled per KQL escape.
      * Single quotes in the resulting phrase are doubled per OData rules so a
        hostname like ``user's-laptop`` doesn't break the URL wrapper.
    """
    phrase = '"' + query.replace('"', '""') + '"'
    q = phrase.replace("'", "''")
    url = (
        f"{graph_base}/drives/{drive_id}/root/search(q='{quote(q, safe='')}')"
    )
    items: list[dict] = []
    while url:
        try:
            page = _graph_get(url, token).json()
        except GraphAuthError:
            # Auth failures stay fatal so the sweep can re-prompt the user.
            raise
        except Exception as exc:  # noqa: BLE001
            # Same partial-page rescue as _list_children: a 504 on page 2
            # used to discard a perfectly good page 1, making the outer
            # sweep log "search failed for 'AC-2'" and emit zero hits even
            # though page 1 had 50 matches.
            LOG.info(
                "Graph /search pagination failed for %r after %d hits — "
                "returning partial result (%s)",
                query,
                len(items),
                exc,
            )
            break
        items.extend(page.get("value", []))
        url = page.get("@odata.nextLink") or ""
    return items


# ---------------------------------------------------------------------------
# SourceFile + Source implementations
# ---------------------------------------------------------------------------


@dataclass
class SharePointFile:
    """A single SharePoint file, downloaded on demand from a Graph pre-signed URL.

    Graph returns an ``@microsoft.graph.downloadUrl`` on every DriveItem that
    is a short-lived pre-signed download — no Authorization header required,
    and it doesn't count against per-app Graph throttling the way an authed
    ``/content`` GET does. We capture it at walk time and stream from it
    lazily inside ``open()``.
    """

    uri: str
    name: str
    size: int | None
    container_uri: str | None
    _download_url: str
    # Lazily populated on first open(). The ingest orchestrator calls open()
    # twice per artifact (hash + extract), and on SharePoint each call was a
    # fresh ~1 MB Graph download. We cache here because each SharePointFile
    # instance is single-use — the walker yields a fresh one per file and the
    # orchestrator drops the reference after iteration, so memory stays
    # bounded to one file at a time.
    _cached_bytes: bytes | None = field(default=None, repr=False)

    def open(self) -> BinaryIO:
        if self._cached_bytes is not None:
            return BytesIO(self._cached_bytes)

        try:
            import requests  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError("requests is not installed.") from exc

        # NB: no auth header — the download URL is pre-signed by Graph.
        resp = requests.get(self._download_url, timeout=120)
        if not resp.ok:
            raise RuntimeError(
                f"SharePoint download failed: HTTP {resp.status_code} for {self.name}"
            )
        self._cached_bytes = resp.content
        return BytesIO(self._cached_bytes)


class SharePointSource:
    """Walk a SharePoint library / subfolder via Graph, yielding ingestible files.

    BFS through the drive tree using ``/children`` calls. Each round-trip
    returns folders + files together so leaf enumeration is one batch per
    directory — same shape as the prior REST implementation, just over a
    different transport.

    Constructor arguments are intentionally a subset of the old one:

    * ``site_url`` — full URL ending in the site collection.
    * ``library`` — display name of the document library (empty → "Documents").
    * ``folder_path`` — optional subpath inside the library.

    Tenant/client/authority are **derived** from the URL via ``cloud_for(...)``
    — no caller plumbing required, no per-tenant Entra registration.

    Legacy keyword args (``tenant_id``, ``client_id``, ``authority_base``) are
    accepted but ignored so existing callers and old config rows don't blow up
    during the rollout. They can be deleted in a follow-up.
    """

    # Read by the ingest orchestrator (see evidence/ingest.py). Network
    # download per file already dwarfs SQLite commit cost over WAL — per-
    # file commits add no measurable overhead and let the UI's evidence
    # list refresh continuously as files land instead of jumping in
    # batches of 50.
    commit_batch_size: int = 1

    def __init__(
        self,
        site_url: str,
        library: str = "",
        folder_path: str = "",
        *,
        file_paths: list[str] | None = None,
        tenant_id: str | None = None,  # noqa: ARG002 — legacy, ignored
        client_id: str | None = None,  # noqa: ARG002 — legacy, ignored
        authority_base: str | None = None,  # noqa: ARG002 — legacy, ignored
    ) -> None:
        self.site_url = site_url.rstrip("/")
        self.library = library or "Documents"
        self.folder_path = folder_path.strip("/")
        # When set, ``iter_files`` short-circuits the BFS and fetches only
        # the listed drive-relative paths (relative to ``folder_path``). Used
        # by the cherry-pick ingest flow where the user pre-selected files
        # via /api/sharepoint/search.
        self.file_paths = list(file_paths) if file_paths else None
        self.cloud = cloud_for(self.site_url)

        parsed = urlparse(self.site_url)
        # Cached for tenant-resolution on every acquire_token call. Without
        # this, MSAL signs the user into their own home tenant (via the
        # ``organizations`` placeholder) and Graph rejects /sites/{host}:/...
        # with 400 invalidRequest when the site lives in a different tenant.
        self._site_host = parsed.netloc
        path_segment = parsed.path  # e.g. /sites/PRGM-EXAMPLE
        self._library_root = f"{path_segment}/{self.library}".replace("//", "/")
        if self.folder_path:
            self._scan_root = f"{self._library_root}/{self.folder_path}"
        else:
            self._scan_root = self._library_root
        self.uri = _sharepoint_uri(self.site_url, self._scan_root)

        self._token: str | None = None
        self._token_lock = threading.Lock()
        self._site_id: str | None = None
        self._drive_id: str | None = None

    # ------------------------------------------------------------------
    # Token + lookup plumbing (memoised per source-walk)
    # ------------------------------------------------------------------
    def _get_token(
        self, *, on_device_code: Callable[[dict], None] | None = None
    ) -> str:
        with self._token_lock:
            if self._token is None:
                self._token = acquire_token(
                    endpoint=self.cloud,
                    site_host=self._site_host,
                    on_device_code=on_device_code,
                )
            return self._token

    def _ensure_site_and_drive(
        self, *, on_device_code: Callable[[dict], None] | None = None
    ) -> tuple[str, str]:
        """Resolve site-id and drive-id once per source instance."""
        if self._site_id and self._drive_id:
            return self._site_id, self._drive_id
        token = self._get_token(on_device_code=on_device_code)
        site = _resolve_site_id(self.cloud.graph_base, token, self.site_url)
        drive = _find_drive_id(
            self.cloud.graph_base, token, site["id"], self.library
        )
        self._site_id = site["id"]
        self._drive_id = drive["id"]
        return self._site_id, self._drive_id

    # ------------------------------------------------------------------
    # Browse — one level of children, for the interactive picker UI
    # ------------------------------------------------------------------
    def browse_folder(self, subfolder: str = "") -> dict:
        """List one level of folders + ingestible files at ``subfolder``.

        Path is relative to ``self.folder_path`` (which is itself relative
        to the library root), so a fresh dialog opens at the configured
        scan root and "drill in" calls pass the child folder path back as
        ``subfolder``. Same suffix filter as ``iter_files`` so the picker
        only shows files an ingest run would actually pull.

        Returns a dict the route can JSON-encode directly:

            {
              "path": <effective path relative to the library>,
              "folders": [{"name", "path", "child_count"}],
              "files":   [{"name", "path", "size", "modified", "ingestible"}],
            }

        Forms/_catalogs system folders are filtered out, matching the walk.
        """
        token = self._get_token()
        _, drive_id = self._ensure_site_and_drive()

        # Compose the effective path. ``self.folder_path`` is the configured
        # scan root inside the library; ``subfolder`` is the user's drill-in
        # below that. Empty parts collapse cleanly so the drive root case
        # ("no scan root, no drill-in") just becomes "".
        parts = [p for p in (self.folder_path, subfolder.strip("/")) if p]
        rel = "/".join(parts)

        items = _list_children(self.cloud.graph_base, token, drive_id, rel)

        folders: list[dict] = []
        files: list[dict] = []
        for it in items:
            name = it.get("name") or ""
            if name in ("Forms", "_catalogs"):
                continue
            if name.startswith("~$") or name.startswith("."):
                continue
            child_rel = f"{rel}/{name}" if rel else name
            if it.get("folder"):
                folders.append(
                    {
                        "name": name,
                        # ``path`` is relative to the configured scan root so
                        # the UI can pass it straight back to browse_folder as
                        # ``subfolder``. Strip the scan-root prefix.
                        "path": (
                            child_rel[len(self.folder_path) + 1:]
                            if self.folder_path and child_rel.startswith(
                                self.folder_path + "/"
                            )
                            else child_rel
                        ),
                        "child_count": (it.get("folder") or {}).get("childCount", 0),
                    }
                )
                continue
            suffix = Path(name).suffix.lower()
            files.append(
                {
                    "name": name,
                    "path": (
                        child_rel[len(self.folder_path) + 1:]
                        if self.folder_path and child_rel.startswith(
                            self.folder_path + "/"
                        )
                        else child_rel
                    ),
                    "size": it.get("size"),
                    "modified": it.get("lastModifiedDateTime"),
                    "ingestible": suffix in _INGESTIBLE_SUFFIXES,
                }
            )

        folders.sort(key=lambda x: x["name"].lower())
        files.sort(key=lambda x: x["name"].lower())
        return {"path": rel, "folders": folders, "files": files}

    # ------------------------------------------------------------------
    # Filename search — for the "find evidence by control / doc number" UI
    # ------------------------------------------------------------------
    def search_files(
        self,
        query: str,
        *,
        max_depth: int = 3,
        max_matches: int = 200,
    ) -> dict:
        """BFS the scan root and return files whose names match ``query``.

        Filename matching only — content is not inspected. Mirrors the
        nist-assessor plugin's find-evidence pattern: cheap, no full-text
        Graph search dependency, scales to large libraries by capping
        depth instead of crawling everything.

        Tokens extracted from ``query``:

        * **USD doc numbers** — ``USD\\d{8,}`` (case-insensitive)
        * **Control IDs** — ``[A-Z]{2}-\\d+(?:\\(\\d+\\))?`` (e.g. ``AC-2``,
          ``SI-4(5)``)
        * **Keywords** — remaining whitespace-split tokens, case-insensitive
          substring match. Single-character tokens are dropped to avoid
          junk matches on every ``a`` or ``1`` in a filename.

        A file scores a hit when ANY token matches. Returned ``matched_terms``
        lets the UI show *why* each hit came back.

        Returns a dict the route can JSON-encode directly. ``truncated`` is
        true when we hit ``max_matches`` and stopped early.
        """
        token_value = self._get_token()
        _, drive_id = self._ensure_site_and_drive()

        q = (query or "").strip()
        usd_terms = [m.upper() for m in re.findall(r"USD\d{8,}", q, re.IGNORECASE)]
        ctl_terms = re.findall(r"\b[A-Z]{2}-\d+(?:\(\d+\))?\b", q)
        # Strip the matched USD / control tokens out of the raw query before
        # extracting keywords so the same token doesn't score twice (and so
        # control IDs don't get matched as plain substrings — "AC-2" hits
        # filenames mentioning AC-2 specifically, not anything with "ac" in it).
        residual = q
        for t in (*usd_terms, *ctl_terms):
            residual = re.sub(re.escape(t), " ", residual, flags=re.IGNORECASE)
        kw_terms = [
            t for t in re.split(r"\s+", residual) if len(t) > 1
        ]

        if not (usd_terms or ctl_terms or kw_terms):
            return {
                "query": q,
                "scanned_folders": 0,
                "truncated": False,
                "matches": [],
            }

        usd_lower = [t.lower() for t in usd_terms]
        ctl_lower = [t.lower() for t in ctl_terms]
        kw_lower = [t.lower() for t in kw_terms]

        matches: list[dict] = []
        truncated = False
        scanned_folders = 0
        # BFS as (drive-relative path, depth). Depth 0 = scan root itself.
        queue: list[tuple[str, int]] = [(self.folder_path, 0)]

        while queue and not truncated:
            rel_path, depth = queue.pop(0)
            scanned_folders += 1
            try:
                items = _list_children(
                    self.cloud.graph_base, token_value, drive_id, rel_path
                )
            except Exception as exc:  # noqa: BLE001
                LOG.warning(
                    "SharePoint search folder fetch failed for %s: %s",
                    rel_path or "/",
                    exc,
                )
                continue

            for it in items:
                name = it.get("name") or ""
                if name in ("Forms", "_catalogs"):
                    continue
                if name.startswith("~$") or name.startswith("."):
                    continue
                child_rel = f"{rel_path}/{name}" if rel_path else name

                if it.get("folder"):
                    if depth + 1 < max_depth:
                        queue.append((child_rel, depth + 1))
                    continue

                suffix = Path(name).suffix.lower()
                if suffix not in _INGESTIBLE_SUFFIXES:
                    continue

                name_lower = name.lower()
                matched: list[str] = []
                for t, t_low in zip(usd_terms, usd_lower):
                    if t_low in name_lower:
                        matched.append(t)
                for t, t_low in zip(ctl_terms, ctl_lower):
                    if t_low in name_lower:
                        matched.append(t)
                for t, t_low in zip(kw_terms, kw_lower):
                    if t_low in name_lower:
                        matched.append(t)
                if not matched:
                    continue

                # ``path`` is relative to the configured scan root so the UI
                # can hand it back to /ingest verbatim — same convention as
                # browse_folder.
                if self.folder_path and child_rel.startswith(self.folder_path + "/"):
                    rel_to_root = child_rel[len(self.folder_path) + 1:]
                elif self.folder_path and child_rel == self.folder_path:
                    rel_to_root = ""
                else:
                    rel_to_root = child_rel
                folder_disp = (
                    rel_to_root.rsplit("/", 1)[0] if "/" in rel_to_root else ""
                )
                size = it.get("size")
                try:
                    size_int: int | None = int(size) if size is not None else None
                except (TypeError, ValueError):
                    size_int = None
                matches.append(
                    {
                        "name": name,
                        "path": rel_to_root,
                        "folder": folder_disp,
                        "size": size_int,
                        "modified": it.get("lastModifiedDateTime"),
                        "ingestible": True,
                        "matched_terms": matched,
                    }
                )
                if len(matches) >= max_matches:
                    truncated = True
                    break

        matches.sort(key=lambda m: (m["folder"].lower(), m["name"].lower()))
        return {
            "query": q,
            "scanned_folders": scanned_folders,
            "truncated": truncated,
            "matches": matches,
        }

    # ------------------------------------------------------------------
    # Boundary-aware sweep (no-download triage)
    # ------------------------------------------------------------------
    def sweep_for_boundary(
        self,
        fingerprint: BoundaryFingerprint,
        *,
        max_candidates: int = 250,
        max_search_queries: int = 30,
        max_depth: int = 4,
        weights: SweepWeights | None = None,
        judge_client: object | None = None,
        judge_model: str | None = None,
        judge_workers: int = 8,
        # cost cap default: 0 = unlimited. Set to a positive dollar value
        # only when a hard ceiling is needed (e.g. CI test runs).
        judge_cost_cap_usd: float = 0.0,
        # time cap for the judge phase. User-facing knob ("stop after N min")
        # — exposed inline next to the Sweep button in the UI, which passes an
        # explicit value. The default is a non-zero safety net (4 min) so a
        # caller that omits it can't run the judge unbounded and freeze the
        # sweep; pass 0.0 explicitly to disable (e.g. an offline batch).
        judge_time_cap_seconds: float = 240.0,
        judge_enabled: bool = True,
        # Pseudo-relevance feedback: paths the assessor confirmed in a prior
        # sweep round. We resolve each to (name, path, snippet) tuples from
        # by_id and pass them as exemplar anchors to the judge so per-candidate
        # calls have richer semantic priors than the host-token list alone.
        seed_candidate_paths: list[str] | None = None,
        on_device_code: Callable[[dict], None] | None = None,
    ) -> SweepResult:
        """Metadata-only enumeration + Graph search + scoring. No file bytes pulled.

        See :doc:`SHAREPOINT_SWEEP_DESIGN.md`. The contract:

        1. BFS the scan root via ``/children`` (depth ≤ ``max_depth``), capture
           ``{name, path, size, modified, webUrl, downloadUrl}`` for every
           ingestible file. Indexed by Graph item id so the search pass can
           splice snippets back in.
        2. Run drive-scoped ``/search(q=…)`` for each token derived from the
           fingerprint, bounded by ``max_search_queries``. Snippets, when
           Graph returns them, get attached to the matching candidate.
        3. Score every candidate via :func:`sweep.score_candidate`. Drop
           below :data:`SCORE_SURFACE_THRESHOLD`, sort by ``(-score, name)``,
           truncate to ``max_candidates``.

        Never calls :meth:`SharePointFile.open` — by design, the sweep
        downloads zero bytes. The caller confirms a subset of paths and
        then runs the existing cherry-pick ingest path which does pull
        bytes. Returns an empty result with ``truncated=False`` when the
        scan root yields no ingestible files.
        """
        start = time.monotonic()

        # Fingerprint dump — answers "did the workbook give us anything to
        # match against?" in one log line. An all-empty fingerprint means
        # every candidate scores 0 and the sweep returns 0 — no point
        # blaming /search or the judge. Truncate the long lists so the line
        # stays grep-friendly.
        LOG.info(
            "SharePoint sweep fingerprint: workbook_id=%s system_context_id=%s "
            "host_tokens=%d (%s) doc_prefixes=%d (%s) in_scope_controls=%d (%s) "
            "priority_prefixes=%d crm_skip_families=%d crm_keywords_controls=%d",
            fingerprint.workbook_id,
            fingerprint.system_context_id,
            len(fingerprint.host_tokens),
            sorted(list(fingerprint.host_tokens))[:8],
            len(fingerprint.doc_number_prefixes),
            sorted(list(fingerprint.doc_number_prefixes))[:8],
            len(fingerprint.in_scope_control_ids),
            sorted(list(fingerprint.in_scope_control_ids))[:8],
            len(fingerprint.priority_path_prefixes),
            len(fingerprint.crm_skip_families),
            len(fingerprint.crm_keywords),
        )

        token_value = self._get_token(on_device_code=on_device_code)
        _, drive_id = self._ensure_site_and_drive(on_device_code=on_device_code)

        # ---- BFS enumeration ----------------------------------------------
        # candidates indexed by Graph drive-item id so the search pass can
        # find them again without re-walking. We hold raw item dicts here
        # and post-process into SweepCandidate after scoring; that lets us
        # update `snippet` from search hits before scoring runs.
        by_id: dict[str, dict] = {}
        queue: list[tuple[str, int]] = [(self.folder_path, 0)]
        bfs_folders_visited = 0
        bfs_items_seen = 0
        bfs_started = time.monotonic()

        while queue:
            rel_path, depth = queue.pop(0)
            bfs_folders_visited += 1
            try:
                items = _list_children(
                    self.cloud.graph_base, token_value, drive_id, rel_path
                )
            except GraphAuthError as exc:
                # 401 during BFS means every subsequent folder fetch is
                # going to fail. Bail out so the route can surface the
                # re-auth prompt instead of returning an empty sweep.
                LOG.warning(
                    "SharePoint sweep aborted: Graph 401 on /children for %s — "
                    "token expired or revoked. (%s)",
                    rel_path or "/",
                    exc,
                )
                try:
                    clear_token_cache()
                except Exception:  # noqa: BLE001
                    LOG.exception("Failed to clear token cache after 401")
                with self._token_lock:
                    self._token = None
                raise
            except Exception as exc:  # noqa: BLE001
                LOG.warning(
                    "SharePoint sweep folder fetch failed for %s: %s",
                    rel_path or "/",
                    exc,
                )
                continue

            for it in items:
                name = it.get("name") or ""
                if not name or name in ("Forms", "_catalogs"):
                    continue
                if name.startswith("~$") or name.startswith("."):
                    continue
                child_rel = f"{rel_path}/{name}" if rel_path else name

                if it.get("folder"):
                    if depth + 1 < max_depth:
                        queue.append((child_rel, depth + 1))
                    continue

                suffix = Path(name).suffix.lower()
                if suffix not in _INGESTIBLE_SUFFIXES:
                    continue

                item_id = it.get("id")
                if not item_id:
                    # No stable identifier — can't reconcile with search hits.
                    # Synthesize from the path so scoring still runs.
                    item_id = f"path::{child_rel}"

                # Path relative to the configured scan root — same convention
                # as search_files so the UI can hand it back to /ingest.
                if self.folder_path and child_rel.startswith(self.folder_path + "/"):
                    rel_to_root = child_rel[len(self.folder_path) + 1:]
                elif self.folder_path and child_rel == self.folder_path:
                    rel_to_root = ""
                else:
                    rel_to_root = child_rel

                size = it.get("size")
                try:
                    size_int: int | None = int(size) if size is not None else None
                except (TypeError, ValueError):
                    size_int = None

                by_id[item_id] = {
                    "name": name,
                    "path": rel_to_root,
                    "web_url": it.get("webUrl") or "",
                    "size": size_int,
                    "modified": it.get("lastModifiedDateTime"),
                    "download_url": it.get("@microsoft.graph.downloadUrl"),
                    "snippet": None,
                }
                bfs_items_seen += 1

        bfs_elapsed = time.monotonic() - bfs_started
        LOG.info(
            "SharePoint sweep BFS complete: scan_root=%r max_depth=%d "
            "folders_visited=%d ingestible_items=%d elapsed=%.1fs",
            self.folder_path or "/",
            max_depth,
            bfs_folders_visited,
            bfs_items_seen,
            bfs_elapsed,
        )

        # ---- Search-snippet enrichment ------------------------------------
        # Build query list from fingerprint signals. Skip 2-letter family
        # literals ("AC", "AU") — they over-match — and prefer specific
        # hostnames, doc-number prefixes, and full control IDs.
        seen_q: set[str] = set()
        queries: list[str] = []

        def _push(q: str) -> None:
            ql = q.strip().lower()
            if not ql or ql in seen_q:
                return
            seen_q.add(ql)
            queries.append(q.strip())

        for h in sorted(fingerprint.host_tokens):
            if len(h) >= 3:
                _push(h)
        for p in sorted(fingerprint.doc_number_prefixes):
            if len(p) >= 3:
                _push(p)
        # Top-N in-scope control IDs — keep the search matrix bounded.
        for cid in sorted(fingerprint.in_scope_control_ids)[:10]:
            _push(cid)

        queries = queries[:max_search_queries]

        # ---- /search disabled by default ----------------------------------
        # Drive-scoped /search returns tens of thousands of tenant-wide hits
        # for common tokens ('cui'=31k, 'example-system-demo'=17k, 'example-system'=8k), each
        # query taking 60-375s. A 30-query loop reliably outruns Graph token
        # TTL and aborts the entire sweep on 401 before the LLM judge ever
        # runs. The content-fetch fallback at lines 1298+ attaches snippets
        # by downloading BFS items directly — same behavior as the MCP —
        # without the tenant-wide search round-trips. /search is now opt-in
        # via the (intentionally undocumented) SWEEP_USE_SEARCH=1 env knob
        # for the rare tenant where /search is fast.
        if os.environ.get("SWEEP_USE_SEARCH") != "1":
            if queries:
                LOG.info(
                    "SharePoint sweep skipping /search phase by default: "
                    "would have run %d queries; content-fetch fallback "
                    "supplies snippets. Set SWEEP_USE_SEARCH=1 to re-enable.",
                    len(queries),
                )
            queries = []
        elif not by_id:
            # BFS produced zero candidates. Running /search would only attach
            # snippets to entries that don't exist — pure waste (this was the
            # 12-minute silent dead zone before observability landed). Skip
            # straight to the (empty) scoring pass; the route returns
            # truncated=False, candidates=[].
            LOG.info(
                "SharePoint sweep skipping /search phase: BFS produced 0 "
                "ingestible candidates (would have run %d queries). Check "
                "BFS summary above for folders_visited and scan_root.",
                len(queries),
            )
            queries = []

        search_started = time.monotonic()
        search_queries_run = 0
        search_hits_total = 0
        search_snippets_attached = 0

        if queries:
            LOG.info(
                "SharePoint sweep /search starting: %d queries (sample=%s)",
                len(queries),
                queries[:5],
            )
        for q in queries:
            search_queries_run += 1
            q_started = time.monotonic()
            try:
                hits = _search_drive(
                    self.cloud.graph_base, token_value, drive_id, q
                )
            except GraphAuthError as exc:
                # 401 is fatal — every subsequent /search will fail the same
                # way, and continuing would let the sweep "succeed" with an
                # empty candidate list, looking like a SharePoint indexing
                # problem instead of an expired token. Clear the on-disk
                # cache so the next /sweep call re-prompts the user.
                LOG.warning(
                    "SharePoint sweep aborted: Graph 401 on /search for %r — "
                    "token expired or revoked. Clearing cache so next sweep "
                    "re-prompts. (%s)",
                    q,
                    exc,
                )
                try:
                    clear_token_cache()
                except Exception:  # noqa: BLE001 — best-effort cleanup
                    LOG.exception("Failed to clear token cache after 401")
                # Also drop our in-memory copy so the same source instance
                # would re-acquire on retry.
                with self._token_lock:
                    self._token = None
                raise
            except Exception as exc:  # noqa: BLE001
                LOG.info(
                    "SharePoint sweep /search failed for %r: %s — skipping",
                    q,
                    exc,
                )
                continue

            search_hits_total += len(hits)
            LOG.info(
                "SharePoint sweep /search query=%r hits=%d elapsed=%.1fs "
                "(query %d/%d)",
                q,
                len(hits),
                time.monotonic() - q_started,
                search_queries_run,
                len(queries),
            )
            for hit in hits:
                hid = hit.get("id")
                if not hid or hid not in by_id:
                    # Search may return items outside our BFS bounds
                    # (deeper than max_depth, or in a sibling folder we
                    # didn't enumerate). Ignore — the candidate set is
                    # defined by BFS, not search.
                    continue
                # Graph snippet shape varies by tenant. Prefer
                # `searchResult.summary`; fall back to top-level `summary`.
                snippet: str | None = None
                sr = hit.get("searchResult") or {}
                if isinstance(sr, dict):
                    snippet = sr.get("summary")
                if not snippet:
                    snippet = hit.get("summary")
                if snippet and not by_id[hid].get("snippet"):
                    by_id[hid]["snippet"] = snippet
                    search_snippets_attached += 1

        if search_queries_run:
            LOG.info(
                "SharePoint sweep /search complete: queries=%d hits=%d "
                "snippets_attached=%d elapsed=%.1fs",
                search_queries_run,
                search_hits_total,
                search_snippets_attached,
                time.monotonic() - search_started,
            )

        # ---- Content-fetch snippet fallback -------------------------------
        # /search is drive-scoped and id-joins miss when SharePoint's
        # indexer lags or when the BFS subfolder doesn't intersect the
        # tenant-wide hit set. For any item still missing a snippet, pull
        # bytes through the pre-signed download URL and run the same text
        # extractor the ingest pipeline uses, then truncate to 4 KB. That
        # is enough sample text for score_candidate to find keyword hits
        # AND for the LLM judge to evaluate semantic relevance without
        # paying for full-document context.
        import requests  # noqa: PLC0415
        from ..extractors.dispatcher import (  # noqa: PLC0415
            extract_stream,
            infer_kind,
        )
        from ...models import EvidenceKind  # noqa: PLC0415

        fetch_started = time.monotonic()
        fetch_count = 0
        fetch_errors = 0
        skipped_size = 0
        skipped_ext = 0
        skipped_no_url = 0
        skipped_deadline = 0
        FETCH_CAP = 200
        SIZE_CAP = 5 * 1024 * 1024  # 5 MB
        SNIPPET_CAP = 4096  # 4 KB
        # Overall wall-clock ceiling for the serial content-fetch fallback.
        # This loop only runs when /search is off (the default), so snippets
        # are pulled one download at a time. Worst case was FETCH_CAP (200) ×
        # the per-request timeout = many minutes of a frozen "Boundary-aware
        # sweep" dialog. Cap the whole phase: once we cross the deadline, stop
        # fetching and let the remaining candidates ride on filename/path
        # signal alone (the keyword scorer + judge still see them).
        FETCH_DEADLINE_SECONDS = 90.0
        # Per-request timeout as (connect, read). The old flat 60s let a single
        # slow download eat most of the phase budget; (10, 20) fails fast on a
        # dead host while still allowing a real 5 MB doc to stream in.
        FETCH_REQUEST_TIMEOUT = (10, 20)

        for meta in by_id.values():
            if fetch_count >= FETCH_CAP:
                break
            if time.monotonic() - fetch_started > FETCH_DEADLINE_SECONDS:
                # Count what we're leaving on the table so the log line below
                # explains a short snippet set instead of looking like a bug.
                skipped_deadline += 1
                continue
            if meta.get("snippet"):
                continue
            download_url = meta.get("download_url")
            if not download_url:
                skipped_no_url += 1
                continue
            size = meta.get("size")
            if size is not None and size > SIZE_CAP:
                skipped_size += 1
                continue
            name = meta.get("name") or ""
            if infer_kind(name) is EvidenceKind.OTHER:
                skipped_ext += 1
                continue
            try:
                resp = requests.get(download_url, timeout=FETCH_REQUEST_TIMEOUT)
                resp.raise_for_status()
                doc = extract_stream(BytesIO(resp.content), name)
                text = (doc.text or "").strip()
                if text:
                    meta["snippet"] = text[:SNIPPET_CAP]
                    fetch_count += 1
            except Exception as exc:  # noqa: BLE001
                # Best-effort fallback — one failure shouldn't kill the
                # sweep. Log and move on. Extractor errors, HTTP errors,
                # transient timeouts all land here.
                fetch_errors += 1
                LOG.debug(
                    "SharePoint sweep content-fetch failed for %r: %s",
                    name,
                    exc,
                )

        LOG.info(
            "SharePoint sweep content-fetch complete: snippets_fetched=%d "
            "skipped_size=%d skipped_ext=%d skipped_no_url=%d "
            "skipped_deadline=%d errors=%d elapsed=%.1fs",
            fetch_count,
            skipped_size,
            skipped_ext,
            skipped_no_url,
            skipped_deadline,
            fetch_errors,
            time.monotonic() - fetch_started,
        )

        # ---- Pass 1: keyword score (signal only, no gate) -----------------
        # The keyword scorer used to be a hard pre-filter — items below
        # SCORE_SURFACE_THRESHOLD never reached the LLM judge. That was the
        # demo-breaker: filenames like "Network Diagram.vsdx" carry zero
        # lexical signal against host_tokens/control_ids/family_kw and
        # would silently drop. New design: keyword score is now an
        # ORDERING + SIGNAL input, and the LLM judge decides. Cost cap is
        # the only gate (judge_cost_cap_usd / judge_time_cap_seconds).
        scored_meta: list[tuple[dict, float, list, list]] = []
        for meta in by_id.values():
            kw_score, signals, proposed = score_candidate(
                meta["name"],
                meta["path"],
                meta.get("snippet"),
                fingerprint,
                weights=weights,
            )
            scored_meta.append((meta, kw_score, signals, proposed))

        # Judge the high-confidence stuff first so a cost-cap trip mid-batch
        # cuts the least-likely candidates, not the obvious winners.
        scored_meta.sort(key=lambda t: (-t[1], t[0]["name"].lower()))

        LOG.info(
            "SharePoint sweep scoring complete: total_items=%d top_scores=%s",
            len(scored_meta),
            [
                (m["name"], round(kw, 3), sig)
                for (m, kw, sig, _) in scored_meta[:10]
            ],
        )

        # ---- Pass 2: LLM judge (every candidate) --------------------------
        # User directive (2026-06-06): "best final product" — combine
        # keyword scoring (free signal, ordering) with LLM-judge-everything
        # (precision). Cost-bounded by judge_cost_cap_usd and time-bounded
        # by judge_time_cap_seconds; cap-skipped rows fall back to pure
        # keyword score so the index alignment + degradation story holds.
        judge_results = None
        judge_used_globally = False
        judge_fallback_reason: str | None = None
        llm_cost_usd = 0.0
        llm_tokens_in = 0
        llm_tokens_out = 0
        cache_read_tokens = 0
        if (
            judge_enabled
            and judge_client is not None
            and judge_model
            and scored_meta
        ):
            inputs = [
                (m["name"], m["path"], m.get("snippet"), kw, list(sig))
                for (m, kw, sig, _p) in scored_meta
            ]

            # Resolve seed paths to exemplar tuples. Paths the user selected
            # might not be in by_id (e.g. ingested in a prior session and
            # purged from the workbook scope since) — skip silently rather
            # than fail the sweep. Dedupe by path and cap at 12 so the
            # cached system block stays bounded.
            seed_exemplars: list[tuple[str, str, str | None]] = []
            if seed_candidate_paths:
                want = {p for p in seed_candidate_paths if p}
                seen_paths: set[str] = set()
                for meta in by_id.values():
                    p = meta.get("path")
                    if p in want and p not in seen_paths:
                        seen_paths.add(p)
                        seed_exemplars.append(
                            (meta["name"], p, meta.get("snippet"))
                        )
                        if len(seed_exemplars) >= 12:
                            break
                LOG.info(
                    "SharePoint sweep PRF: requested=%d resolved=%d",
                    len(want),
                    len(seed_exemplars),
                )

            batch = judge_candidates_concurrent(
                judge_client,
                fingerprint,
                inputs,
                max_workers=judge_workers,
                cost_cap_usd=judge_cost_cap_usd,
                model=judge_model,
                time_cap_seconds=judge_time_cap_seconds,
                seed_exemplars=seed_exemplars or None,
            )
            judge_results = batch.results
            judge_used_globally = True
            judge_fallback_reason = batch.fallback_reason
            llm_cost_usd = batch.estimated_cost_usd
            llm_tokens_in = batch.total_input_tokens
            llm_tokens_out = batch.total_output_tokens
            cache_read_tokens = batch.total_cache_read_tokens

            # Judge summary — pairs item names with LLM scores + first
            # 120 chars of reasoning. If the judge is silently rejecting
            # everything, this is where we'll see it. Errors are surfaced
            # separately so a transport failure doesn't look like a
            # low-score verdict.
            judge_samples = []
            judge_errors = 0
            for (m, _kw, _s, _p), jr in zip(scored_meta, batch.results):
                if jr.error is not None:
                    judge_errors += 1
                    continue
                judge_samples.append(
                    (
                        m["name"],
                        round(jr.score, 3),
                        (jr.reasoning or "")[:120],
                    )
                )
            judge_samples.sort(key=lambda r: r[1])  # lowest scores first
            LOG.info(
                "SharePoint sweep LLM judge complete: items=%d "
                "judged_ok=%d errors=%d fallback_reason=%s cost_usd=%.4f "
                "tokens_in=%d tokens_out=%d cache_read=%d lowest_5=%s",
                len(scored_meta),
                len(judge_samples),
                judge_errors,
                judge_fallback_reason,
                llm_cost_usd,
                llm_tokens_in,
                llm_tokens_out,
                cache_read_tokens,
                judge_samples[:5],
            )
        elif scored_meta:
            # No judge ran but we had items — surface why so we don't
            # waste a debug cycle wondering if the judge silently no-op'd.
            LOG.info(
                "SharePoint sweep LLM judge SKIPPED: items=%d "
                "judge_enabled=%s judge_client=%s judge_model=%s",
                len(scored_meta),
                judge_enabled,
                judge_client is not None,
                bool(judge_model),
            )

        # ---- Build SweepCandidates with blended scores --------------------
        # Surface threshold now applies to the BLENDED (LLM-informed) score,
        # not the raw keyword score. A candidate with kw=0 but llm=0.8
        # (e.g. a network diagram the judge recognized as in-boundary)
        # now lands well above SCORE_SURFACE_THRESHOLD; the demo failure
        # mode where such files were dropped pre-judge is closed.
        scored: list[SweepCandidate] = []
        candidates_judged = 0
        for idx, (meta, kw_score, signals, proposed) in enumerate(scored_meta):
            llm_score: float | None = None
            judge_reasoning: str | None = None
            row_judge_used = False
            if judge_results is not None:
                jr = judge_results[idx]
                if jr.error is None:
                    llm_score = jr.score
                    judge_reasoning = jr.reasoning or None
                    row_judge_used = True
                    candidates_judged += 1
                # else: error or cost-cap-skipped → fall back to pure keyword

            if row_judge_used and llm_score is not None:
                blended = _KW_BLEND_WEIGHT * kw_score + _LLM_BLEND_WEIGHT * llm_score
            else:
                blended = kw_score

            # Post-judge surface gate. Items the judge confidently rejected
            # (and that have no keyword signal to rescue them) drop here.
            if blended < SCORE_SURFACE_THRESHOLD:
                continue

            scored.append(
                SweepCandidate(
                    name=meta["name"],
                    path=meta["path"],
                    web_url=meta["web_url"],
                    size=meta["size"],
                    modified=meta["modified"],
                    score=blended,
                    matched_signals=tuple(signals),
                    proposed_ccis=tuple(proposed),
                    snippet=meta.get("snippet"),
                    download_url=meta.get("download_url"),
                    keyword_score=kw_score,
                    llm_score=llm_score,
                    judge_reasoning=judge_reasoning,
                    judge_used=row_judge_used,
                )
            )

        scored.sort(key=lambda c: (-c.score, c.name.lower()))
        truncated = len(scored) > max_candidates
        if truncated:
            scored = scored[:max_candidates]

        elapsed_ms = int((time.monotonic() - start) * 1000)
        return SweepResult(
            scan_root=self.uri,
            workbook_id=fingerprint.workbook_id,
            system_context_id=fingerprint.system_context_id,
            candidates=tuple(scored),
            families_skipped_by_crm=tuple(sorted(fingerprint.crm_skip_families)),
            truncated=truncated,
            elapsed_ms=elapsed_ms,
            weights_version_id=(weights.id if weights is not None else None),
            fingerprint_snapshot=fingerprint.to_snapshot_dict(),
            llm_cost_usd=llm_cost_usd,
            llm_tokens_in_total=llm_tokens_in,
            llm_tokens_out_total=llm_tokens_out,
            cache_read_tokens_total=cache_read_tokens,
            candidates_judged=candidates_judged,
            judge_model=(judge_model if judge_used_globally else None),
            judge_used=judge_used_globally,
            judge_fallback_reason=judge_fallback_reason,
        )

    # ------------------------------------------------------------------
    # Walk
    # ------------------------------------------------------------------
    def iter_files(self) -> Iterator[SourceFile]:
        token = self._get_token()
        _, drive_id = self._ensure_site_and_drive()

        container_uri = self.uri

        # Cherry-pick path — when the caller supplied an allow-list
        # (e.g. from /api/sharepoint/search), skip the BFS entirely and
        # fetch each file directly by drive-relative path. Lets the UI's
        # checkbox-based ingest run pull just the chosen artifacts instead
        # of walking the (potentially huge) scan root.
        if self.file_paths:
            for rel in self.file_paths:
                # Caller's path is relative to ``self.folder_path``; compose
                # the full drive-relative path the same way browse_folder
                # does so the suffix filter + Graph fetch line up.
                rel = rel.strip("/")
                if not rel:
                    continue
                full_rel = (
                    f"{self.folder_path}/{rel}" if self.folder_path else rel
                )
                name = full_rel.rsplit("/", 1)[-1]
                if name.startswith("~$") or name.startswith("."):
                    continue
                suffix = Path(name).suffix.lower()
                if suffix not in _INGESTIBLE_SUFFIXES:
                    continue
                try:
                    item = _get_item_by_path(
                        self.cloud.graph_base, token, drive_id, full_rel
                    )
                except Exception as exc:  # noqa: BLE001
                    LOG.warning(
                        "SharePoint cherry-pick fetch failed for %s: %s",
                        full_rel,
                        exc,
                    )
                    continue
                download_url = item.get("@microsoft.graph.downloadUrl")
                if not download_url:
                    LOG.debug("No downloadUrl for %s — skipping", full_rel)
                    continue
                size = item.get("size")
                try:
                    size_int = int(size) if size is not None else None
                except (TypeError, ValueError):
                    size_int = None
                server_rel = f"{self._library_root}/{full_rel}".replace("//", "/")
                yield SharePointFile(
                    uri=_sharepoint_uri(self.site_url, server_rel),
                    name=name,
                    size=size_int,
                    container_uri=container_uri,
                    _download_url=download_url,
                )
            return

        # BFS — paths are drive-relative (i.e. inside the library), not
        # server-relative. The library prefix lives in self._library_root
        # only for URI construction.
        queue: list[str] = [self.folder_path]  # empty string = drive root

        while queue:
            rel_path = queue.pop(0)
            try:
                items = _list_children(
                    self.cloud.graph_base, token, drive_id, rel_path
                )
            except Exception as exc:  # noqa: BLE001 — surface but don't abort walk
                LOG.warning(
                    "SharePoint folder fetch failed for %s: %s", rel_path or "/", exc
                )
                continue

            for it in items:
                name = it.get("name") or ""
                child_rel = f"{rel_path}/{name}" if rel_path else name

                if it.get("folder"):
                    # Skip SharePoint system folders that hold library
                    # views/templates, not real evidence.
                    if name in ("Forms", "_catalogs"):
                        continue
                    queue.append(child_rel)
                    continue

                # File path. Filter the same suffix set as the local walker
                # and skip Office lockfiles / dotfiles.
                if name.startswith("~$") or name.startswith("."):
                    continue
                suffix = Path(name).suffix.lower()
                if suffix not in _INGESTIBLE_SUFFIXES:
                    continue

                download_url = it.get("@microsoft.graph.downloadUrl")
                if not download_url:
                    # Defensive: Graph normally always returns this for files.
                    # If it's missing (e.g. checked-out file with no current
                    # version), skip rather than crash the whole walk.
                    LOG.debug("No downloadUrl for %s — skipping", child_rel)
                    continue

                size = it.get("size")
                try:
                    size_int = int(size) if size is not None else None
                except (TypeError, ValueError):
                    size_int = None

                server_rel = f"{self._library_root}/{child_rel}".replace("//", "/")
                yield SharePointFile(
                    uri=_sharepoint_uri(self.site_url, server_rel),
                    name=name,
                    size=size_int,
                    container_uri=container_uri,
                    _download_url=download_url,
                )

    # ------------------------------------------------------------------
    # Public probe — used by the /api/sharepoint/test route
    # ------------------------------------------------------------------
    def test_connection(
        self, on_device_code: Callable[[dict], None] | None = None
    ) -> dict:
        """Authenticate, resolve site + library, and probe the scan root.

        Signature preserved (``on_device_code=...``) so the
        ``/api/sharepoint/test`` route's two-phase device-code flow keeps
        working unchanged. Returns a dict shaped like the prior REST version
        plus a ``cloud_name`` field so the UI can confirm which cloud the
        URL routed to.
        """
        token = acquire_token(
            endpoint=self.cloud,
            site_host=self._site_host,
            on_device_code=on_device_code,
        )
        self._token = token

        site = _resolve_site_id(self.cloud.graph_base, token, self.site_url)
        site_title = site.get("displayName") or site.get("name") or ""
        self._site_id = site["id"]

        try:
            drive = _find_drive_id(
                self.cloud.graph_base, token, site["id"], self.library
            )
            self._drive_id = drive["id"]
            library_ok = True
            library_error: str | None = None
        except Exception as exc:  # noqa: BLE001
            library_ok = False
            library_error = str(exc)
            drive = None

        # Probe the scan root inside the drive so the user sees the full path
        # is reachable before they kick off a walk. Same fast-fail rationale
        # as the prior REST implementation.
        scan_ok = False
        scan_name_or_error: str
        if library_ok and drive is not None:
            try:
                items = _list_children(
                    self.cloud.graph_base, token, drive["id"], self.folder_path
                )
                scan_ok = True
                # Helpful: how many entries did we just see?
                scan_name_or_error = (
                    self.folder_path or "/"
                ) + f"  ({len(items)} item(s))"
            except Exception as exc:  # noqa: BLE001
                scan_name_or_error = str(exc)
        else:
            scan_name_or_error = library_error or "library unavailable"

        # Aggregate health — auth + site reachable is necessary but not
        # sufficient. The UI's green banner is keyed on this single boolean,
        # so a 404 on the user's folder path must surface here too. Without
        # the AND, a typo in the folder field showed "Connection OK" while
        # the actual scan path 404'd — confusing for end users who only
        # glance at the banner.
        return {
            "ok": library_ok and scan_ok,
            "site_title": site_title,
            "site_url": self.site_url,
            "library": self.library,
            "library_ok": library_ok,
            "scan_root": self._scan_root,
            "scan_root_ok": scan_ok,
            "scan_root_name_or_error": scan_name_or_error,
            "cloud_name": self.cloud.cloud_name,
        }


def clear_token_cache() -> bool:
    """Delete the persisted Graph token cache. Returns True if a file was removed."""
    path = _token_cache_path()
    if path.exists():
        path.unlink()
        return True
    return False
