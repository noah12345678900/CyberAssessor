"""SharePoint **boundary-discovery** sweep — v0.4 connector (feature-gated).

Sibling of :mod:`sharepoint` (file-byte streaming) and :mod:`sweep` (pure
candidate scoring). This module covers a different question:

    Where does the program's authorization boundary actually *live* in
    SharePoint, and which tier-mismatched documents should the assessor
    flag for supersession review before any bytes are downloaded?

A *boundary location* here is anything that materially expands the
attack surface of the program site collection:

* The **scan-root site** itself.
* **Sub-sites** reachable from the scan root (``/sites/{id}/sites``).
* **Document libraries** on the root site and on every sub-site.
* **External-share surface** — drive items whose effective permissions
  carry a ``link.scope == "anonymous"`` or a non-tenant grantee. Only the
  *summary* per library is emitted (full per-item enumeration is a v0.5
  problem) so the cost stays bounded.
* **Stale-titled documents** — files whose tier label embedded in the
  filename (e.g. ``T1`` for tier-1) disagrees with the tier label
  embedded in the containing folder (e.g. a ``T1_…`` file living under a
  ``T2`` folder is almost always an un-superseded artifact). Surfaces a
  short-circuit CM finding without paying download cost.

Each discovered location is emitted as a :class:`SourceFile`-shaped
record whose ``open()`` returns a small JSON/text payload describing the
location — enough for the downstream extractor to feed a CM finding row
into Evidence, but *never* the raw document bytes. The boundary sweep
intentionally never streams a real document; that is the existing
:class:`SharePointSource` ingest connector's job, kicked off after the
user confirms the picks in the triage UI.

Feature flag
------------
v0.4-only. Off by default. Enable by either:

* setting ``CCIS_ENABLE_BOUNDARY_SWEEP=1`` in the sidecar's environment, or
* passing ``enabled=True`` to the constructor (tests do this).

The :func:`is_enabled` helper lets the route layer (``routes/sharepoint``
in v0.4) short-circuit cleanly when the flag is off, without importing
any Graph plumbing. The module-level ``__all__`` is unconditional —
import-time side effects are deliberately absent so unit tests for *other*
sources are not penalised when the flag is off.

Reuse
-----
All Graph plumbing — auth, retry, tenant resolution, site/drive lookup —
is imported from :mod:`.sharepoint`. This module owns:

* boundary-location enumeration semantics,
* the tier-label parser (``_extract_tier_label``),
* the :class:`BoundaryLocation` SourceFile shape,
* feature-flag gating.

Anything that touches Graph headers, MSAL accounts, or token cache files
lives in ``sharepoint.py`` and is consumed via the small surface re-
exported below. If a v0.5 follow-up needs to share Graph plumbing across
yet another connector, lift it to a private ``_graph_common`` module —
do not duplicate it here.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from collections import deque
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any, BinaryIO, Callable, Iterator
from urllib.parse import quote, urlparse

from .base import Source, SourceFile

# Reuse the existing SharePoint connector's Graph plumbing — never
# reinvent the wheel for token / retry / tenant / cloud routing.
from .sharepoint import (
    GraphAuthError,
    _find_drive_id,
    _graph_get,
    _resolve_site_id,
    _sharepoint_uri,
    acquire_token,
    clear_token_cache,
    cloud_for,
)

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Feature flag — v0.4 only
# ---------------------------------------------------------------------------

#: Environment variable that unlocks the boundary sweep. Mirrors the
#: ``SWEEP_USE_SEARCH`` pattern already in ``sharepoint.py``: a single
#: env var, value ``"1"`` enables. Anything else (unset, empty,
#: ``"0"``, ``"false"``, …) keeps the connector dormant.
ENV_FLAG = "CCIS_ENABLE_BOUNDARY_SWEEP"


def is_enabled() -> bool:
    """Return ``True`` iff the v0.4 boundary sweep is operator-enabled.

    Cheap to call — re-reads the environment every time so tests can
    flip the flag with ``monkeypatch.setenv`` without restarting the
    process. The constructor still accepts an explicit ``enabled=True``
    override so unit tests don't need to touch the global env.
    """

    return os.environ.get(ENV_FLAG, "").strip() == "1"


class BoundarySweepDisabledError(RuntimeError):
    """Raised when the connector is instantiated with the feature flag off.

    Surfaced as a clean 503-shaped error in the route layer so the UI
    can hide the boundary-sweep tab in v0.1/v0.2/v0.3 builds without
    crashing on an import. Distinct from :class:`GraphAuthError` so
    callers can tell "I refused" apart from "Entra refused".
    """


# ---------------------------------------------------------------------------
# Tier-label parser — drives stale-title supersession flagging
# ---------------------------------------------------------------------------

# Match T1/T2/T3 (tier-1/2/3) labels with a word boundary on either side.
# Accept the common separator variants seen in program file names:
# ``T1_…``, ``T1-…``, ``T1 …``, ``…(T1)…``, ``…_T1.pdf``, and the
# slightly-different bare-token form embedded mid-filename. Case-
# insensitive — program teams ship a mix of ``T1`` and ``t1``.
_TIER_LABEL_RE = re.compile(
    r"(?<![A-Za-z0-9])(T[1-3])(?![A-Za-z0-9])",
    re.IGNORECASE,
)


def _extract_tier_label(text: str) -> str | None:
    """Return the uppercase tier label (``"T1"`` etc.) found in ``text``.

    Returns ``None`` when no tier marker is present *or* when the text
    carries more than one *distinct* tier (e.g. a filename like
    ``T1-vs-T2-comparison.pdf`` — ambiguous, not actionable, skip).
    Mixed-case duplicates of the same tier (``T1`` and ``t1``) are not
    treated as distinct.
    """

    if not text:
        return None
    hits = {m.group(1).upper() for m in _TIER_LABEL_RE.finditer(text)}
    if len(hits) != 1:
        return None
    return next(iter(hits))


# ---------------------------------------------------------------------------
# SourceFile-shaped record per discovered boundary location
# ---------------------------------------------------------------------------


@dataclass
class BoundaryLocation:
    """One discovered authorization-boundary location.

    Implements the :class:`SourceFile` protocol so the existing ingest
    orchestrator can consume the sweep output uniformly. The ``open()``
    payload is a small JSON descriptor of the location — never the raw
    SharePoint document bytes. The downstream extractor recognises the
    ``application/vnd.ccis.boundary-location+json`` shape by the
    ``.json`` suffix on :attr:`name` plus the ``kind`` field inside.
    """

    uri: str
    name: str
    kind: str  # "site" | "subsite" | "library" | "external_share" | "stale_title"
    container_uri: str | None = None
    size: int | None = None

    # Free-form context — serialised into the JSON payload returned by
    # ``open()``. Keep small: this is a triage hint, not a corpus.
    details: dict[str, Any] = field(default_factory=dict)

    def open(self) -> BinaryIO:
        """Return an in-memory JSON descriptor of the boundary location.

        Caller is responsible for closing. Stream is fresh each call so
        the orchestrator can re-read on retry without seek juggling.
        """

        payload = {
            "kind": self.kind,
            "uri": self.uri,
            "name": self.name,
            "container_uri": self.container_uri,
            "details": self.details,
        }
        return BytesIO(json.dumps(payload, indent=2).encode("utf-8"))


# ---------------------------------------------------------------------------
# Source — the actual boundary-discovery walk
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BoundarySweepCaps:
    """Bound the walk so a misconfigured site can't melt the sidecar.

    Defaults are conservative — picked from the design note's
    "metadata-only triage" budget. A future operator-facing knob can
    expose these in Settings; for v0.4 they live in code so we don't
    have to add config-schema migrations to a deferred connector.
    """

    max_subsites: int = 50
    max_libraries_per_site: int = 20
    max_stale_title_items: int = 100
    # Folder-recursion ceiling for the stale-title scan. Mirrors the
    # design-spec ``max_depth=4`` for the file sweep.
    max_folder_depth: int = 4
    # Per-library item cap for stale-title scan. Stops a 50k-item
    # library from chewing the whole token budget for a hint.
    max_items_per_library: int = 500


class SharePointBoundarySweepSource:
    """v0.4 connector — enumerate SharePoint authorization-boundary surface.

    Constructor mirrors :class:`SharePointSource` (URL + optional library)
    so route plumbing can swap between them without re-deriving the
    auth surface. Unlike the byte-streaming connector, ``iter_files``
    yields :class:`BoundaryLocation` records whose ``open()`` returns a
    JSON descriptor — never the raw document.

    Auth, token cache, cloud routing, retry, and tenant resolution are
    all delegated to :mod:`.sharepoint`. This class owns:

    * the enumeration order (root → subsites → libraries → externals → stale),
    * the tier-label parser,
    * the feature-flag refusal,
    * the per-walk caps.
    """

    # Boundary records are cheap to persist and there are few of them —
    # commit each so the UI's discovery list refreshes live (same logic
    # as ``SharePointSource.commit_batch_size``).
    commit_batch_size: int = 1

    def __init__(
        self,
        site_url: str,
        *,
        library: str = "",
        caps: BoundarySweepCaps | None = None,
        tenant_email_domains: tuple[str, ...] | None = None,
        enabled: bool | None = None,
    ) -> None:
        # Explicit override beats env flag so tests don't have to touch
        # global state. ``None`` (the default) means "consult env".
        flag_on = is_enabled() if enabled is None else bool(enabled)
        if not flag_on:
            raise BoundarySweepDisabledError(
                f"SharePoint boundary sweep is a v0.4 feature; set "
                f"{ENV_FLAG}=1 to enable."
            )

        self.site_url = site_url.rstrip("/")
        self.library = library or "Documents"
        self.caps = caps or BoundarySweepCaps()

        self.cloud = cloud_for(self.site_url)
        parsed = urlparse(self.site_url)
        self._site_host = parsed.netloc

        # Email-domain allow-list for external-share triage. The SharePoint
        # host (``…sharepoint.us``) is NOT a useful proxy for "internal email
        # domain" — Entra tenants routinely send email from ``@example.com``
        # while serving SharePoint from ``collab.example.com``. Caller
        # passes the real corporate domains; when unset, we conservatively
        # flag every non-anonymous grantee carrying an email so the assessor
        # eyeballs the surface manually (false-positive is safer than miss).
        self._tenant_email_domains: tuple[str, ...] = tuple(
            d.lower().lstrip("@") for d in (tenant_email_domains or ())
        )

        # The Source.uri contract — recorded on IngestSummary so the UI
        # can label "where did this boundary sweep run". Reuses the
        # shared sharepoint:// scheme so it round-trips through the same
        # provenance plumbing as a regular ingest.
        self.uri = _sharepoint_uri(self.site_url, parsed.path)

        self._token: str | None = None
        self._token_lock = threading.Lock()
        self._site: dict | None = None
        # Cache the subsite list so the libraries pass doesn't pay a second
        # Graph round-trip (reviewer P2). Initialised on first walk so we
        # never call out before iter_files() has acquired a token.
        self._cached_subsites: list[dict] | None = None
        self._on_device_code: Callable[[dict], None] | None = None

    # ------------------------------------------------------------------
    # Auth — delegated to sharepoint.acquire_token
    # ------------------------------------------------------------------
    def _get_token(
        self,
        *,
        on_device_code: Callable[[dict], None] | None = None,
        force_refresh: bool = False,
    ) -> str:
        """Return a Graph access token, refreshing on demand.

        ``force_refresh=True`` blows away the cached token AND wipes the
        on-disk MSAL cache so MSAL has to re-prompt instead of handing
        back the same expired blob. Used by :meth:`_graph_get_paged` when
        Graph returns a 401 mid-walk — without it the boundary sweep
        silently truncates whenever a long enumeration outlives the
        access token's hour-long lifetime.
        """

        with self._token_lock:
            if force_refresh:
                self._token = None
                try:
                    clear_token_cache()
                except Exception:  # noqa: BLE001
                    LOG.exception(
                        "boundary sweep: failed to clear MSAL cache before refresh"
                    )
            if self._token is None:
                self._token = acquire_token(
                    endpoint=self.cloud,
                    site_host=self._site_host,
                    on_device_code=on_device_code,
                )
            return self._token

    def _ensure_site(
        self, *, on_device_code: Callable[[dict], None] | None = None
    ) -> dict:
        if self._site is not None:
            return self._site
        token = self._get_token(on_device_code=on_device_code)
        self._site = _resolve_site_id(self.cloud.graph_base, token, self.site_url)
        return self._site

    # ------------------------------------------------------------------
    # Paginated Graph GET helper — addresses reviewer P0 (pagination)
    # and P0 (token expiry).
    # ------------------------------------------------------------------
    def _graph_get_paged(
        self,
        url: str,
        *,
        max_items: int | None = None,
        what: str = "graph call",
    ) -> Iterator[dict]:
        """Iterate every ``value`` item across ``@odata.nextLink`` pages.

        Centralises three things every boundary-sweep call needs:

        * **Pagination.** A site with 21+ libraries used to silently
          truncate at page one. Walks ``@odata.nextLink`` until exhausted
          or ``max_items`` is hit.
        * **Token refresh.** A long sweep can outlive the access token.
          On 401 we wipe the MSAL cache, re-prompt once, and retry the
          *current* page exactly once. A second 401 propagates so the
          caller (each ``_iter_*`` helper) can log + skip rather than
          spin forever.
        * **Partial-progress preservation.** Mirrors the sharepoint.py
          pattern — a 504 on page N keeps the items collected from pages
          1..N-1 instead of dropping the whole accumulator.
        """

        yielded = 0
        retried_auth = False
        while url:
            try:
                page = _graph_get(url, self._get_token()).json()
            except GraphAuthError as exc:
                if retried_auth:
                    LOG.warning(
                        "boundary sweep: %s 401 after token refresh — %s", what, exc
                    )
                    return
                LOG.info(
                    "boundary sweep: %s 401 — refreshing token and retrying once",
                    what,
                )
                retried_auth = True
                try:
                    self._get_token(force_refresh=True)
                except Exception as refresh_exc:  # noqa: BLE001
                    LOG.warning(
                        "boundary sweep: token refresh for %s failed: %s",
                        what,
                        refresh_exc,
                    )
                    return
                continue
            except Exception as exc:  # noqa: BLE001
                # 5xx / network — keep whatever pages we already got.
                LOG.info(
                    "boundary sweep: %s pagination failed (returning partial): %s",
                    what,
                    exc,
                )
                return

            # Reset auth-retry after a successful page.
            retried_auth = False
            for item in page.get("value", []):
                yield item
                yielded += 1
                if max_items is not None and yielded >= max_items:
                    return
            url = page.get("@odata.nextLink") or ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def iter_files(
        self,
        *,
        on_device_code: Callable[[dict], None] | None = None,
    ) -> Iterator[BoundaryLocation]:
        """Yield discovered boundary locations.

        Order is intentional — the UI renders the discovery list in
        walk order, so coarser-grained findings (root, subsites,
        libraries) come first and individual stale-title flags come
        last. Errors during sub-walks are logged and skipped — a single
        unreadable library should not abort the whole sweep.
        """

        # Capture the device-code callback so the paginated helper can
        # re-acquire a token mid-walk without a second `iter_files` call.
        self._on_device_code = on_device_code

        self._get_token(on_device_code=on_device_code)
        site = self._ensure_site(on_device_code=on_device_code)
        site_id = site["id"]
        base = self.cloud.graph_base

        # 1. The scan-root site itself.
        yield self._make_site_location(site, kind="site")

        # 2. Sub-sites. Single Graph round-trip cached for the libraries
        # pass below — used to do two listings, see reviewer P2.
        subsites = self._load_subsites(base, site_id)
        for sub in subsites[: self.caps.max_subsites]:
            yield self._make_site_location(sub, kind="subsite")
        if len(subsites) > self.caps.max_subsites:
            LOG.info(
                "boundary sweep: capped subsites at %d (saw %d)",
                self.caps.max_subsites,
                len(subsites),
            )

        # 3. Libraries (root + each cached subsite).
        drives_to_scan: list[tuple[str, dict]] = []
        for site_record in [site, *subsites[: self.caps.max_subsites]]:
            sid = site_record["id"]
            for drive in self._iter_libraries(base, sid):
                yield self._make_library_location(site_record, drive)
                drives_to_scan.append((sid, drive))

        # 4. External-share surface — one summary record per library.
        for sid, drive in drives_to_scan:
            ext = self._summarize_external_shares(base, drive["id"])
            if ext is None:
                continue
            yield self._make_external_share_location(sid, drive, ext)

        # 5. Stale-title supersession candidates.
        stale_yielded = 0
        for sid, drive in drives_to_scan:
            if stale_yielded >= self.caps.max_stale_title_items:
                break
            for stale in self._iter_stale_titles(base, drive):
                if stale_yielded >= self.caps.max_stale_title_items:
                    break
                yield stale
                stale_yielded += 1

    # ------------------------------------------------------------------
    # Enumeration helpers — each isolated for unit-test monkeypatching
    # ------------------------------------------------------------------
    def _load_subsites(self, graph_base: str, site_id: str) -> list[dict]:
        """Materialise the cached subsite list (paginated, cached).

        First call hits Graph and walks every ``@odata.nextLink`` page;
        subsequent calls return the in-memory list — eliminates the
        duplicate round-trip the original iter_files made (one for the
        records, one for the drives loop).
        """

        if self._cached_subsites is not None:
            return self._cached_subsites
        url = f"{graph_base}/v1.0/sites/{site_id}/sites"
        out: list[dict] = []
        # ``max_items`` is the cap + 1 so callers can detect overflow.
        for sub in self._graph_get_paged(
            url,
            max_items=self.caps.max_subsites + 1,
            what=f"subsites for {site_id}",
        ):
            out.append(sub)
        self._cached_subsites = out
        return out

    # Back-compat shim — the original test suite monkeypatched module
    # globals (``_graph_get``, ``acquire_token``, ``_resolve_site_id``)
    # and expected ``_iter_subsites`` to be a thin generator over the
    # /sites/{id}/sites payload. Keep the surface intact so the existing
    # `test_walk_*` cases (which read off a FakeResp) still drive the
    # loader, while real callers route through ``_load_subsites``.
    def _iter_subsites(
        self, graph_base: str, token: str, site_id: str
    ) -> Iterator[dict]:
        url = f"{graph_base}/v1.0/sites/{site_id}/sites"
        for sub in self._graph_get_paged(
            url, what=f"subsites for {site_id}"
        ):
            yield sub

    def _iter_libraries(
        self, graph_base: str, site_id: str
    ) -> Iterator[dict]:
        """Yield document library (drive) records on a single site."""

        url = f"{graph_base}/v1.0/sites/{site_id}/drives"
        # Pull cap + 1 so we can log overflow distinctly from "exactly cap".
        emitted = 0
        for drive in self._graph_get_paged(
            url,
            max_items=self.caps.max_libraries_per_site + 1,
            what=f"drives for {site_id}",
        ):
            if emitted >= self.caps.max_libraries_per_site:
                LOG.info(
                    "boundary sweep: capped libraries at %d for site %s",
                    self.caps.max_libraries_per_site,
                    site_id,
                )
                return
            yield drive
            emitted += 1

    def _is_external_email(self, email: str) -> bool:
        """Return True when ``email`` is outside the tenant's allow-list.

        When no allow-list was configured we conservatively treat every
        non-tenant grantee as external — false-positive surfacing is
        the safe default for a triage report. Comparing against the
        SharePoint host (the previous behaviour) was wrong: Entra
        tenants serve SharePoint under ``…sharepoint.us`` but mail under
        a different domain entirely, so the old check flagged *every*
        grantee as external.
        """

        addr = email.strip().lower()
        if not addr or "@" not in addr:
            return False
        domain = addr.rsplit("@", 1)[1]
        if not self._tenant_email_domains:
            return True
        return domain not in self._tenant_email_domains

    def _summarize_external_shares(
        self, graph_base: str, drive_id: str
    ) -> dict | None:
        """Return a small dict summarising the external-share surface.

        Calls ``/drives/{id}/root/permissions`` — drive-level only.
        Per-item unique permissions (``/items/{id}/permissions``) are a
        v0.5 follow-up; the design note flagged a full per-item walk as
        out of budget for v0.4.

        Anything with ``link.scope == "anonymous"`` or a grantee email
        outside the tenant allow-list (see :meth:`_is_external_email`)
        is treated as external. Returns ``None`` when there are zero
        such permissions so the caller can skip emitting empty records.
        """

        url = f"{graph_base}/v1.0/drives/{drive_id}/root/permissions"
        anonymous = 0
        external_grantees: list[str] = []
        for p in self._graph_get_paged(
            url, what=f"permissions for drive {drive_id}"
        ):
            link = p.get("link") or {}
            if link.get("scope") == "anonymous":
                anonymous += 1
                continue
            for grantee_field in ("grantedToV2", "grantedTo"):
                g = p.get(grantee_field) or {}
                user = g.get("user") or {}
                email = user.get("email") or ""
                if email and self._is_external_email(email):
                    external_grantees.append(email)

        if anonymous == 0 and not external_grantees:
            return None

        return {
            "anonymous_links": anonymous,
            "external_grantees": sorted(set(external_grantees))[:20],
        }

    def _iter_stale_titles(
        self, graph_base: str, drive: dict
    ) -> Iterator[BoundaryLocation]:
        """Walk the drive shallowly looking for tier-mismatched files.

        Folder-context inference covers two cases:

        * **Tier mismatch.** A ``T1_…`` filename inside a ``T2 …``
          folder — the canonical "un-superseded artifact" pattern from
          the v0.4 design note.
        * **Tiered file in untiered folder.** A ``T1_OldPolicy.pdf``
          dropped at the root of ``Working/`` (no folder tier) — equally
          interesting for CM review because it suggests an out-of-place
          baseline document. The folder-tier inference cannot decide
          which tier "should" apply, so we flag with folder_tier=None.

        Walk uses BFS via :class:`collections.deque` so a single deep
        branch can't starve sibling folders; honours
        ``caps.max_folder_depth`` and ``caps.max_items_per_library`` so
        a deep or wide library can't balloon the sweep cost. Both ``rel``
        and individual segment names are URL-encoded so files with
        spaces / ``&`` / ``#`` don't blow up the Graph URL.
        """

        drive_id = drive["id"]
        root_path = (drive.get("webUrl") or "").rstrip("/")

        # BFS — popleft instead of pop so wide trees stay balanced.
        queue: deque[tuple[str, int]] = deque([("", 0)])
        items_seen = 0

        while queue:
            rel, depth = queue.popleft()
            if depth > self.caps.max_folder_depth:
                continue

            if rel:
                encoded = quote(rel.strip("/"), safe="/")
                url = (
                    f"{graph_base}/v1.0/drives/{drive_id}/root:"
                    f"/{encoded}:/children"
                )
            else:
                url = f"{graph_base}/v1.0/drives/{drive_id}/root/children"

            for item in self._graph_get_paged(
                url, what=f"stale-title scan {rel or '<root>'}"
            ):
                items_seen += 1
                if items_seen > self.caps.max_items_per_library:
                    return

                name = item.get("name") or ""
                if item.get("folder") is not None:
                    next_rel = f"{rel}/{name}".strip("/")
                    queue.append((next_rel, depth + 1))
                    continue

                folder_tier = _extract_tier_label(rel)
                file_tier = _extract_tier_label(name)

                # Skip when the file has no tier marker — no signal to act on.
                if not file_tier:
                    continue
                # Skip when folder and file agree — that's the happy path.
                if folder_tier and folder_tier == file_tier:
                    continue
                # Either folder is untiered (folder_tier=None) or the two
                # tiers diverge. Both warrant a CM-review flag — emit one
                # BoundaryLocation describing the asymmetry.

                # Carry both tiers + the parent folder so the UI can
                # render a one-line CM finding. ``parentReference.path``
                # comes back as e.g. ``/drive/root:/Working/T2_Foo`` —
                # strip the ``/drive/root:`` artifact so the URI matches
                # what the byte-streaming connector emits.
                parent_path = (
                    (item.get("parentReference") or {}).get("path", "") or ""
                )
                if "root:" in parent_path:
                    parent_path = parent_path.split("root:", 1)[1] or "/"
                server_rel = parent_path.rstrip("/") + (f"/{name}" if name else "")

                if folder_tier is None:
                    finding = (
                        f"{file_tier} document in untiered folder — "
                        "possible misfiled baseline (CM review)."
                    )
                else:
                    finding = (
                        f"{file_tier} document in {folder_tier} folder — "
                        "possible un-superseded artifact (CM review)."
                    )

                yield BoundaryLocation(
                    uri=_sharepoint_uri(self.site_url, server_rel or f"/{name}"),
                    name=f"{name}.boundary.json",
                    kind="stale_title",
                    container_uri=_sharepoint_uri(
                        self.site_url, root_path + (f"/{rel}" if rel else "")
                    ),
                    size=None,
                    details={
                        "file_tier": file_tier,
                        "folder_tier": folder_tier,
                        "folder_path": rel,
                        "drive_id": drive_id,
                        "drive_name": drive.get("name"),
                        "web_url": item.get("webUrl"),
                        "finding": finding,
                    },
                )

    # ------------------------------------------------------------------
    # Record factories
    # ------------------------------------------------------------------
    def _make_site_location(self, site: dict, *, kind: str) -> BoundaryLocation:
        web_url = site.get("webUrl") or self.site_url
        name = site.get("displayName") or site.get("name") or "site"
        return BoundaryLocation(
            uri=f"sharepoint://{urlparse(web_url).netloc}{urlparse(web_url).path}",
            name=f"{name}.boundary.json",
            kind=kind,
            container_uri=self.uri if kind == "subsite" else None,
            size=None,
            details={
                "site_id": site.get("id"),
                "web_url": web_url,
                "description": site.get("description"),
            },
        )

    def _make_library_location(
        self, site: dict, drive: dict
    ) -> BoundaryLocation:
        site_web = site.get("webUrl") or self.site_url
        lib_name = drive.get("name") or "Documents"
        return BoundaryLocation(
            uri=(
                f"sharepoint://{urlparse(site_web).netloc}"
                f"{urlparse(site_web).path}/{lib_name}"
            ),
            name=f"{lib_name}.boundary.json",
            kind="library",
            container_uri=(
                f"sharepoint://{urlparse(site_web).netloc}"
                f"{urlparse(site_web).path}"
            ),
            size=None,
            details={
                "drive_id": drive.get("id"),
                "drive_type": drive.get("driveType"),
                "web_url": drive.get("webUrl"),
                "quota_used": (drive.get("quota") or {}).get("used"),
                "quota_total": (drive.get("quota") or {}).get("total"),
            },
        )

    def _make_external_share_location(
        self, site_id: str, drive: dict, summary: dict
    ) -> BoundaryLocation:
        drive_url = drive.get("webUrl") or ""
        return BoundaryLocation(
            uri=f"{drive_url}#external-shares",
            name=f"{drive.get('name') or 'library'}.external-shares.boundary.json",
            kind="external_share",
            container_uri=drive_url or None,
            size=None,
            details={
                "site_id": site_id,
                "drive_id": drive.get("id"),
                "summary": summary,
                "finding": (
                    "External-share surface present — boundary expansion "
                    "candidate (AC/AT review)."
                ),
            },
        )


# Protocol conformance is enforced by runtime_checkable isinstance()
# checks in the orchestrator and by the unit tests in
# ``tests/sources/test_sp_boundary_sweep.py`` — ``Source.uri`` is an
# *instance* attribute set in ``__init__``, so an import-time
# ``hasattr`` check on the class would falsely fail. The ``Source``
# protocol import below stays referenced as a hint to anyone tempted
# to drop it.
_PROTOCOL_REF: type = Source  # noqa: F841


__all__ = [
    "BoundaryLocation",
    "BoundarySweepCaps",
    "BoundarySweepDisabledError",
    "ENV_FLAG",
    "SharePointBoundarySweepSource",
    "is_enabled",
]
