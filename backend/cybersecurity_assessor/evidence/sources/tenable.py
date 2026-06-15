"""Tenable vulnerability-scan source — v0.4 evidence connector.

Pulls vulnerability-scan results from either **Tenable.sc** (on-prem
SecurityCenter) or **Tenable.io** (cloud) and emits each scan report or
finding-set as a :class:`SourceFile`. The assessor uses these payloads to
*corroborate* STIG-narrative claims — see the kernel memo
``feedback_corroborate_stig_findings.md``: a single scan finding is never
sufficient evidence on its own, but a Tenable export aligned with a
configured baseline + a policy narrative is.

Why a connector and not "drop the .nessus in Evidence"
------------------------------------------------------
The local-folder source already accepts ``.nessus`` files, and small
programs will keep dropping them in. The connector exists for the larger
programs where scans are run on a Tenable.sc cluster and exported on a
schedule — chasing the latest export across SharePoint folders is exactly
the kind of integration the assessor is meant to replace. Pulling directly
from the API also lets us record the scan's *server-side* run ID so re-
ingest is idempotent (see URI scheme below).

Authentication — API keysets only, never password
-------------------------------------------------
Both flavors of Tenable support legacy username+password auth. We
deliberately **do not**:

* Passwords trigger MFA prompts that no headless connector can answer.
* Keysets (``access_key`` / ``secret_key``) are revocable per-user without
  changing the assessor's local config — same posture as AWS IAM keys.
* Tenable.sc keysets are scoped to a single user; the user creates them
  in **My Account → API Keys** in the SC UI.
* Tenable.io keysets live under **Settings → My Account → API Keys**.

Secrets handling matches the existing connectors:

* ``access_key`` and ``secret_key`` are passed to the constructor and held
  in instance attributes only — never logged, never persisted by this
  module. The keyring slots in ``config.py`` (added in the same v0.4
  slice) own on-disk storage; this module reads them.
* On auth failure, the upstream :class:`TenableAuthError` carries the
  HTTP status only — the bad key is *not* echoed back to the caller, so
  a 401 in the sidecar log doesn't leak the secret.

URI scheme — ``tenable://<host>/scan/<scan_id>/<run_id>``
---------------------------------------------------------
Stable across re-ingest so the orchestrator's dedupe (keyed on
``Evidence.path``) works the same way it does for SharePoint and local
files. The components:

* ``host`` — SC FQDN (e.g. ``tenable.sda.mil``) or ``cloud.tenable.com``
  for Tenable.io. Disambiguates a scan ID across different Tenable
  instances when an assessor manages multiple programs.
* ``scan_id`` — the scan definition (SC: numeric id from ``/scan``; io:
  UUID from ``/scans``). Stable across runs of the same scheduled scan.
* ``run_id`` — the per-execution identifier (SC: ``history.id``; io:
  ``history_uuid``). Distinguishes today's run from yesterday's; lets
  us hold both as separate Evidence rows when both are interesting.

A scan with no completed runs yields no SourceFile — running scans aren't
evidence. The orchestrator's hash-based dedupe is a *backstop* but isn't
the primary identifier; this URI guarantees one row per (scan, run) even
if Tenable rehydrates the same bytes after a transient SQL hiccup.

Feature flag (``tenable_connector_enabled``)
-------------------------------------------
v0.4 ships gated. The connector is constructible at all times so the
Settings UI can collect inputs and run ``test_connection()``, but
``iter_files()`` short-circuits when the flag is off — same posture as
the eMASS connector while it was being staged. Flip the flag in
``config.toml`` (or the Settings card once the v0.4 UI lands) to unlock
ingest.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from io import BytesIO
from typing import Any, BinaryIO, Iterator, Literal
from urllib.parse import urlparse

from .base import SourceFile

LOG = logging.getLogger(__name__)

# Tenable.io is a fixed multi-tenant host; SC is whatever FQDN the
# customer deployed. Keeping the io host as a constant makes the URI
# scheme deterministic across assessors (no per-tenant subdomain to
# disambiguate).
TENABLE_IO_HOST = "cloud.tenable.com"

# Both products report finding severities as 0..4. Anything below this
# threshold is informational — keeping them attached to a scan export is
# fine, but the per-finding short-circuit in the assessor uses the same
# threshold to decide whether a finding rises to "actually a finding" for
# corroboration purposes. Mirrors Tenable's own definition.
SEVERITY_INFO = 0
SEVERITY_LOW = 1
SEVERITY_MEDIUM = 2
SEVERITY_HIGH = 3
SEVERITY_CRITICAL = 4


class TenableAuthError(RuntimeError):
    """Tenable rejected our keyset (401).

    Distinct from generic ``RuntimeError`` so the route layer can surface
    a clean "rotate your API key" prompt instead of bucketing the failure
    with transient network errors. We never include the secret in the
    message — only the host + scan id that triggered the rejection — so
    operators can tail the sidecar log without re-pasting credentials.
    """


class TenableRateLimitError(RuntimeError):
    """Tenable returned 429 after the SDK's internal retry budget.

    pyTenable retries throttled requests with exponential backoff
    internally; raising this only when retries are exhausted lets the
    sweep treat rate limiting as fatal-for-this-run instead of silently
    returning a partial export.
    """


# ---------------------------------------------------------------------------
# URI helpers — kept module-level so tests can import them without
# constructing a full client.
# ---------------------------------------------------------------------------


def _normalize_host(url: str) -> str:
    """Extract a stable host from a SC URL.

    Inputs vary: users paste ``https://tenable.sda.mil``,
    ``tenable.sda.mil``, ``tenable.sda.mil:443``, or ``//tenable...``. The
    URI scheme has to be the same regardless — otherwise a config-page
    edit that drops the scheme reissues every Evidence row.
    """
    if not url:
        return ""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.hostname or "").lower()
    return host


def _scan_uri(host: str, scan_id: str | int, run_id: str | int) -> str:
    """Render the canonical ``tenable://`` URI for a scan run.

    Both ID components are stringified so the URI shape stays uniform
    whether the source SDK returned ints (SC) or UUIDs (io). Letting one
    component be an int and the other a string would burn us in dedupe
    later: ``tenable://h/scan/1/abc`` is a different string than
    ``tenable://h/scan/'1'/abc``.
    """
    return f"tenable://{host}/scan/{scan_id}/{run_id}"


# ---------------------------------------------------------------------------
# Concrete SourceFile — one per scan run, payload fetched on demand
# ---------------------------------------------------------------------------


@dataclass
class TenableScanFile:
    """One completed scan run, downloaded as a ``.nessus`` XML blob on demand.

    The bytes are fetched lazily inside :meth:`open` (same pattern as
    SharePointFile) so the walk pass only touches metadata — listing every
    scan in a 4000-host SC cluster shouldn't pull 4000 export files.
    """

    uri: str
    name: str
    size: int | None
    container_uri: str | None
    # Bound late by the iterator so test fakes can swap in a synthetic
    # callable without needing the pyTenable SDK installed.
    _fetch: Any  # () -> bytes
    _cached_bytes: bytes | None = None

    def open(self) -> BinaryIO:
        if self._cached_bytes is None:
            self._cached_bytes = self._fetch()
        return BytesIO(self._cached_bytes)


# ---------------------------------------------------------------------------
# Source — Tenable.sc + Tenable.io behind one class with a flavor switch
# ---------------------------------------------------------------------------


TenableFlavor = Literal["sc", "io"]


class TenableSource:
    """Walk a Tenable instance's completed scans and yield ``.nessus`` exports.

    Constructor inputs:

    * ``flavor`` — ``"sc"`` for Tenable.sc (on-prem SecurityCenter) or
      ``"io"`` for Tenable.io (cloud). The two SDKs have nearly identical
      public surfaces but the scan / export call shapes differ enough
      that a single dispatch is cleaner than per-method branching.
    * ``host`` — SC FQDN; ignored when ``flavor="io"`` (we always hit
      ``cloud.tenable.com``).
    * ``access_key`` / ``secret_key`` — Tenable API keyset. Kept in
      instance attrs only; never logged, never persisted.
    * ``feature_enabled`` — v0.4 gate. False → ``iter_files()`` yields
      nothing and logs once. The constructor itself always succeeds so
      the Settings UI can render a card before the flag flips.
    * ``min_severity`` — stored on the source so downstream extractors
      (which DO parse per-finding severity from the .nessus XML) can
      read it without re-plumbing config. The walk itself doesn't
      filter on severity because Tenable's scan-list endpoints don't
      report severity counts — you'd have to download every export to
      decide, which defeats the lazy-fetch design. Clamped to 0..4 to
      match Tenable's own severity range.

    Walk semantics:

    1. List scans (SC: ``sc.scans.list``; io: ``tio.scans.list``).
    2. For each scan, iterate completed history rows (one row = one run).
       Skip runs with no successful completion timestamp.
    3. Emit one :class:`TenableScanFile` per (scan, run) pair. Bytes are
       NOT fetched here — the orchestrator decides whether to call
       ``open()`` based on dedupe.
    """

    # Same per-file commit cadence as SharePointSource — Tenable exports
    # can be multi-MB, network-bound downloads dwarf SQLite WAL commit
    # cost, and we want the UI's evidence list to refresh continuously
    # as runs land instead of jumping in batches.
    commit_batch_size: int = 1

    def __init__(
        self,
        *,
        flavor: TenableFlavor,
        access_key: str,
        secret_key: str,
        host: str | None = None,
        feature_enabled: bool = False,
        min_severity: int = SEVERITY_INFO,
        # Test seam: lets the unit tests inject a pre-built fake client
        # instead of standing up the real SDK. Production callers always
        # leave this None and the constructor builds the SDK lazily.
        _client: Any | None = None,
    ) -> None:
        if flavor not in ("sc", "io"):
            raise ValueError(
                f"flavor must be 'sc' or 'io', got {flavor!r}"
            )
        if flavor == "sc" and not host:
            raise ValueError("Tenable.sc requires a host (the SC FQDN)")
        if not access_key or not secret_key:
            # Reject empty strings up front. Without this, pyTenable raises
            # a confusing AuthenticationWarning *after* a network call; we
            # want a clean "not configured" error before any traffic leaves
            # the box.
            raise ValueError("Tenable access_key and secret_key are required")

        self.flavor: TenableFlavor = flavor
        self._access_key = access_key
        self._secret_key = secret_key
        self.feature_enabled = feature_enabled
        self.min_severity = max(SEVERITY_INFO, min(SEVERITY_CRITICAL, int(min_severity)))

        if flavor == "io":
            self.host = TENABLE_IO_HOST
        else:
            self.host = _normalize_host(host or "")

        self.uri = f"tenable://{self.host}/"
        self._client_override = _client
        self._client: Any | None = None

    # ------------------------------------------------------------------
    # Auth — keyset only, lazy SDK import
    # ------------------------------------------------------------------
    def _build_client(self) -> Any:
        """Construct the underlying pyTenable client.

        Lazy so importing this module doesn't drag in pyTenable on systems
        that don't have it installed (it lives in the ``sources`` extras).
        """
        if self._client_override is not None:
            return self._client_override
        try:
            if self.flavor == "sc":
                # SecurityCenter (on-prem). The SDK auto-discovers the
                # /rest endpoint suffix; we just pass the host.
                from tenable.sc import TenableSC  # noqa: PLC0415

                return TenableSC(
                    host=self.host,
                    access_key=self._access_key,
                    secret_key=self._secret_key,
                )
            else:
                from tenable.io import TenableIO  # noqa: PLC0415

                return TenableIO(
                    access_key=self._access_key,
                    secret_key=self._secret_key,
                )
        except ImportError as exc:
            raise ImportError(
                "pyTenable is not installed. Install the 'sources' extras: "
                "`pip install -e .[sources]` from backend/."
            ) from exc

    def _ensure_client(self) -> Any:
        if self._client is None:
            self._client = self._build_client()
        return self._client

    # ------------------------------------------------------------------
    # Probe — used by the Settings card to validate the keyset
    # ------------------------------------------------------------------
    def test_connection(self) -> dict[str, Any]:
        """Hit the cheapest authenticated endpoint and report status.

        Returns a small dict the UI can render directly. We never echo
        the access/secret key back — the worst case (401) returns the
        host + a hint, nothing else. Errors get truncated to 200 chars
        so a wall of HTML from a misconfigured proxy doesn't blow up
        the Settings card.
        """
        try:
            client = self._ensure_client()
            if self.flavor == "sc":
                # SC's /currentUser is the cheapest authed call.
                user = client.current.user()
                username = (user or {}).get("username") or "(unknown)"
            else:
                # Tenable.io's session endpoint is the equivalent.
                session = client.session.details()
                username = (session or {}).get("username") or "(unknown)"
            return {
                "ok": True,
                "flavor": self.flavor,
                "host": self.host,
                "username": username,
            }
        except Exception as exc:  # noqa: BLE001 — surface upstream as one shape
            status = _http_status_from_exc(exc)
            if status == 401:
                # Auth-specific path so the UI can show "rotate keys"
                # instead of "transient error".
                return {
                    "ok": False,
                    "flavor": self.flavor,
                    "host": self.host,
                    "error": "auth_failed",
                    "hint": "Access/secret key rejected (HTTP 401). Verify the keyset has not been revoked.",
                }
            return {
                "ok": False,
                "flavor": self.flavor,
                "host": self.host,
                "error": "connection_failed",
                "hint": _redacted_error_message(exc),
            }

    # ------------------------------------------------------------------
    # Walk
    # ------------------------------------------------------------------
    def iter_files(self) -> Iterator[SourceFile]:
        """Yield one :class:`TenableScanFile` per completed scan run.

        Feature-flag check first — when off, we log once at INFO and
        return immediately. The constructor having succeeded means the
        Settings card showed green; the gate is only on the actual data
        pull so the operator can verify connectivity before flipping the
        flag.
        """
        if not self.feature_enabled:
            LOG.info(
                "Tenable connector disabled (v0.4 feature flag). "
                "Set tenable_connector_enabled=true in config to ingest."
            )
            return

        client = self._ensure_client()

        try:
            scans = list(self._list_scans(client))
        except Exception as exc:  # noqa: BLE001
            status = _http_status_from_exc(exc)
            if status == 401:
                raise TenableAuthError(
                    f"Tenable {self.flavor} rejected keyset on scan list "
                    f"(host={self.host})"
                ) from exc
            if status == 429:
                raise TenableRateLimitError(
                    f"Tenable {self.flavor} rate limit exhausted on scan list "
                    f"(host={self.host})"
                ) from exc
            raise

        for scan in scans:
            scan_id = scan.get("id")
            scan_name = scan.get("name") or f"scan-{scan_id}"
            if scan_id is None:
                # SDK shouldn't hand us an id-less scan, but defensive log
                # + skip beats raising mid-walk and losing the rest.
                LOG.debug("Tenable scan with no id, skipping: %r", scan)
                continue

            try:
                history = list(self._iter_history(client, scan_id))
            except Exception as exc:  # noqa: BLE001
                LOG.warning(
                    "Tenable %s history fetch failed for scan %s: %s — skipping",
                    self.flavor,
                    scan_id,
                    _redacted_error_message(exc),
                )
                continue

            for run in history:
                run_id = run.get("id") or run.get("uuid") or run.get("history_id")
                status = (run.get("status") or "").lower()
                # Tenable uses "completed" for SC and "completed" for io.
                # Anything else (running, paused, aborted, imported) isn't
                # a finished export we can pull.
                if status != "completed" or run_id is None:
                    continue

                # File name embeds enough provenance to be recognizable in
                # the evidence list without round-tripping to the URI:
                # "<scan-name>.<run-id>.nessus". Sanitize the scan name
                # so OS path constraints don't bite if a downstream
                # extractor caches the bytes to disk.
                safe_name = _sanitize_filename(scan_name)
                file_name = f"{safe_name}.{run_id}.nessus"
                uri = _scan_uri(self.host, scan_id, run_id)

                # Bind the export call as a no-arg closure so TenableScanFile
                # doesn't need to know which flavor it came from. Defer
                # downloading until open() is called.
                fetch = self._make_fetch(client, scan_id, run_id)

                yield TenableScanFile(
                    uri=uri,
                    name=file_name,
                    size=None,  # Tenable doesn't pre-report export size
                    container_uri=self.uri,
                    _fetch=fetch,
                )

    # ------------------------------------------------------------------
    # Flavor-specific list / history / export helpers
    # ------------------------------------------------------------------
    def _list_scans(self, client: Any) -> Iterator[dict[str, Any]]:
        """Yield scan-definition dicts in a flavor-normalized shape.

        We normalize to ``{"id": ..., "name": ...}`` so the caller's loop
        doesn't have to know which product it's talking to. Extra fields
        the SDK returns are passed through untouched in case future
        callers want them.
        """
        if self.flavor == "sc":
            # SC returns {"manageable": [...], "usable": [...]}; the union
            # is the right scope for an assessor — usable covers shared
            # scans the operator can read even without ownership.
            raw = client.scans.list()
            if isinstance(raw, dict):
                items = list(raw.get("usable") or []) + list(raw.get("manageable") or [])
                # Dedupe by id, preserving order
                seen: set[Any] = set()
                for it in items:
                    sid = it.get("id")
                    if sid in seen:
                        continue
                    seen.add(sid)
                    yield {**it, "id": sid, "name": it.get("name")}
            else:
                yield from raw or []
        else:
            # Tenable.io: list() returns a generator of scan dicts. Older
            # pyTenable versions returned a {"scans": [...]} dict — handle
            # both so a version bump in the env doesn't break us silently.
            raw = client.scans.list()
            if isinstance(raw, dict):
                for it in raw.get("scans") or []:
                    yield {**it, "id": it.get("id"), "name": it.get("name")}
            else:
                for it in raw or []:
                    yield {**it, "id": it.get("id"), "name": it.get("name")}

    def _iter_history(self, client: Any, scan_id: Any) -> Iterator[dict[str, Any]]:
        """Yield completed-run dicts in a flavor-normalized shape.

        Exceptions from the underlying SDK propagate up to ``iter_files``
        so it can log + skip the offending scan (rather than silently
        treating "couldn't list history" as "no history"). That keeps a
        flaky scan from masking real coverage gaps.
        """
        if self.flavor == "sc":
            # SC: scan.results.list_history returns rows with `id` + `status`.
            rows = (
                client.scan_instances.list()
                if hasattr(client, "scan_instances")
                else []
            )
            # Filter to this scan id. SC's scan_instances is a global
            # history; per-scan filtering keeps us from yielding the
            # entire instance with every iter_files() call.
            for r in rows or []:
                if r.get("scan", {}).get("id") == scan_id:
                    yield {
                        "id": r.get("id"),
                        "status": (r.get("status") or "").lower(),
                    }
        else:
            # Tenable.io: scans.history(scan_id) returns a list of dicts
            # with `history_id` and `status`.
            hist = client.scans.history(scan_id)
            for r in hist or []:
                yield {
                    "id": r.get("history_id") or r.get("id") or r.get("uuid"),
                    "status": (r.get("status") or "").lower(),
                }

    def _make_fetch(
        self, client: Any, scan_id: Any, run_id: Any
    ) -> "Any":
        """Build a no-arg closure that downloads the .nessus export.

        Captures the SDK + ids by reference so the actual network call
        doesn't happen until the orchestrator calls ``open()``. Errors
        during fetch are raised as :class:`TenableAuthError` /
        :class:`TenableRateLimitError` so the caller can distinguish
        "your key was revoked" from "this one file failed".
        """

        def _do_fetch() -> bytes:
            buf = BytesIO()
            try:
                if self.flavor == "sc":
                    # SC: scans.download(scan_id, history_id=run_id) writes
                    # to the file-like passed in.
                    client.scans.download(scan_id, fobj=buf, history_id=run_id)
                else:
                    # Tenable.io: scans.export(scan_id, history_id=run_id,
                    # format='nessus'); export streams chunks via fobj.
                    client.scans.export(
                        scan_id, fobj=buf, history_id=run_id, format="nessus"
                    )
            except Exception as exc:  # noqa: BLE001
                status = _http_status_from_exc(exc)
                if status == 401:
                    raise TenableAuthError(
                        f"Tenable {self.flavor} rejected keyset on export "
                        f"(scan={scan_id} run={run_id})"
                    ) from exc
                if status == 429:
                    raise TenableRateLimitError(
                        f"Tenable {self.flavor} rate-limited on export "
                        f"(scan={scan_id} run={run_id})"
                    ) from exc
                raise
            return buf.getvalue()

        return _do_fetch

    # ------------------------------------------------------------------
    # Repr — never includes the secrets
    # ------------------------------------------------------------------
    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"TenableSource(flavor={self.flavor!r}, host={self.host!r}, "
            f"feature_enabled={self.feature_enabled}, "
            f"access_key=<redacted>, secret_key=<redacted>)"
        )


# ---------------------------------------------------------------------------
# Helpers — kept private to the module so tests can monkeypatch without
# leaking into the public surface.
# ---------------------------------------------------------------------------


_SANITIZE_RX = re.compile(r"[^A-Za-z0-9._-]+")


def _sanitize_filename(name: str) -> str:
    """Collapse runs of non-safe chars in a scan name to a single underscore.

    The .nessus payload is treated as a regular SourceFile downstream, so
    extractors (and any cache-to-disk paths) need a portable filename.
    Scan names routinely include slashes, colons, and quotes — characters
    that explode on Windows or get URL-escaped twice if we leave them in.
    """
    cleaned = _SANITIZE_RX.sub("_", (name or "").strip()).strip("._-")
    return cleaned or "scan"


def _http_status_from_exc(exc: BaseException) -> int | None:
    """Best-effort extraction of an HTTP status code from a pyTenable error.

    pyTenable wraps requests' HTTPError in its own ``APIError`` subclass
    whose ``code`` attribute holds the status. Different versions of the
    SDK have moved the attribute around (``code``, ``status_code``,
    ``response.status_code``); we probe each so a version bump doesn't
    silently demote 401s to "unknown error".
    """
    for attr in ("code", "status_code"):
        v = getattr(exc, attr, None)
        if isinstance(v, int):
            return v
    resp = getattr(exc, "response", None)
    if resp is not None:
        sc = getattr(resp, "status_code", None)
        if isinstance(sc, int):
            return sc
    return None


_SECRET_PATTERNS = (
    # Generic 32+-char hex / base64-ish secrets. Tenable keysets are 64-char
    # hex; this also catches anything that looks like it could be a token if
    # an SDK update changed the error shape.
    re.compile(r"[A-Fa-f0-9]{32,}"),
    re.compile(r"[A-Za-z0-9+/=]{40,}"),
)


def _redacted_error_message(exc: BaseException, max_len: int = 200) -> str:
    """Stringify an exception while scrubbing anything that looks like a key.

    Defense-in-depth — pyTenable doesn't echo keys in error messages today,
    but a future SDK version that includes the request URL or body could.
    We always strip aggressively before surfacing to the caller (UI or log).
    """
    msg = str(exc) or type(exc).__name__
    for rx in _SECRET_PATTERNS:
        msg = rx.sub("<redacted>", msg)
    if len(msg) > max_len:
        msg = msg[:max_len] + "…"
    return msg
