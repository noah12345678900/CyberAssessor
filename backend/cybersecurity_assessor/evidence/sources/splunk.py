"""Splunk saved-search evidence connector — v0.4.

Runs a configured allow-list of **saved searches** against a Splunk
instance and emits each search result-set as a :class:`SourceFile` whose
payload is the (CSV or JSON) result rows. The ingest orchestrator then
treats each result-set as a regular evidence artifact: the
CSV/JSON extractor pulls the text, the tagger maps it to AU / IR / SI
controls by filename and content, and the assessor cites the
``splunk://saved-search/<name>/<run-id>`` URI like any other evidence
URI.

Why saved searches and not raw SPL
----------------------------------
Defensibility. An assessor must be able to point at WHAT was queried —
the SPL text, the time window, who created it, what indexes it touches
— and have that be reviewable by a 3PAO / AO without trusting that the
connector configuration "looked right at runtime". Saved searches are
named, versioned (Splunk tracks history), and reviewable by anyone with
Splunk read access. A connector that accepts raw SPL is effectively a
"trust me, I queried the right thing" hand-wave — banned here on
purpose. The connector takes a list of saved-search NAMES, looks each
one up via ``splunk-sdk``'s ``SavedSearches`` collection, and runs the
search ``.dispatch()`` API; it never builds, accepts, or executes a
caller-provided SPL string.

Why a feature flag
------------------
This connector is on the v0.4 roadmap (see ``project_connectors_roadmap``
in memory: "v0.4+: one per release — SP boundary sweep → Tenable →
Splunk → eMASS (gated)"). v0.x main-branch users should not see Splunk
results land in their evidence list without opt-in. The
``enable_splunk`` AppSettings flag (default ``False``) gates the route /
ingest entry-points; constructing the source directly in a test bypasses
the flag, which is intentional so the kernel tests don't drag in a real
Splunk dependency.

Auth — token only
-----------------
Splunk supports session-key (password), basic auth, and HTTP Event
Collector tokens. We accept ONLY a bearer/auth-token string (Splunk's
``Authentication Tokens`` feature, Splunk 7.3+). Passwords are never
read, stored, or accepted by this connector — the constructor rejects
``password=`` kwargs with a clear error. The token itself is held in
memory on the source instance for the duration of the walk and is never
logged: the only place it appears is in the ``Authorization`` header of
the splunk-sdk HTTP client. ``__repr__`` redacts it explicitly.

Result pagination
-----------------
Result rows are streamed in pages (``count=<page_size>``,
``offset=<n>``) until either Splunk says there's no more or
``max_results_per_search`` is reached. We do NOT materialize the full
result set in one ``.results()`` call — that path can pull millions of
rows on a wide search and OOM the sidecar. The default ``page_size`` is
1000 and the default ``max_results_per_search`` is 50_000, which sizes
the worst-case in-memory buffer at ~50 MB of CSV — well under sidecar
limits but big enough that a chatty audit search returns useful
context. Both knobs are constructor-level.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
import threading
import time
import warnings
from dataclasses import dataclass, field
from io import BytesIO
from typing import BinaryIO, Iterator, Sequence
from urllib.parse import quote

from .base import SourceFile

LOG = logging.getLogger(__name__)

# Defensive log discipline. When the host application is set to DEBUG
# (e.g. a developer enables verbose logging in the sidecar), splunklib
# and the underlying urllib3 connection-pool will both log full request
# headers — which include ``Authorization: Splunk <token>``. We cap
# those loggers at INFO unconditionally on module import to keep tokens
# out of crash dumps even when global logging is verbose. Setting the
# level here only narrows the floor; callers can still raise it
# explicitly if they need to debug Splunk SDK behaviour, at their own
# risk and with their own redaction wrapper.
for _noisy in ("splunklib", "urllib3.connectionpool", "urllib3"):
    logging.getLogger(_noisy).setLevel(max(logging.INFO, logging.getLogger(_noisy).level))

# Conservative defaults. ``page_size`` is the per-paginate row count
# requested from Splunk; ``max_results_per_search`` is the hard cap on
# total rows we'll buffer for one saved search before truncating. Both
# are overridable via the constructor — these defaults exist so a
# default-configured connector can't OOM the sidecar on a misconfigured
# wide search.
_DEFAULT_PAGE_SIZE = 1000
_DEFAULT_MAX_RESULTS = 50_000

# Saved-search names must be reasonable identifiers. Allows letters,
# digits, spaces, hyphens, underscores, dots, and parentheses — the
# character set Splunk's UI permits. Rejects anything that looks like
# SPL (pipe, backtick, brackets, double-quote) to make it obvious in
# code review when someone tries to sneak SPL through the name list.
_SAVED_SEARCH_NAME_RE = re.compile(r"^[A-Za-z0-9 \-_.()/:&]+$")

# Output format aliases the connector emits. CSV is the default because
# the existing CSV extractor handles it without special-casing; JSON is
# available for searches whose result schemas don't flatten cleanly
# (stats with mv fields etc.). Both end up as a SourceFile with the
# right suffix on .name so the extractor dispatcher can pick the right
# extractor by extension.
_OUTPUT_FORMATS = {"csv", "json"}


def _splunk_uri(saved_search_name: str, run_id: str) -> str:
    """Render the canonical URI for a saved-search result-set.

    Stable across re-ingest runs only when the same ``run_id`` is
    re-used (which it won't be — each ``dispatch()`` gets a new Splunk
    SID). That's intentional: each run is a distinct point-in-time
    snapshot, and treating them as distinct Evidence rows is what lets
    the assessor cite WHEN the search was run, not just what it was.
    """
    return (
        f"splunk://saved-search/"
        f"{quote(saved_search_name, safe='')}/"
        f"{quote(run_id, safe='')}"
    )


def _validate_saved_search_name(name: str) -> str:
    """Reject anything that doesn't look like a Splunk saved-search name.

    Defense in depth: even though the SDK's ``SavedSearches[name]``
    lookup would fail on a junk name, we want loud, early rejection
    here so a misconfigured config file doesn't silently fall through
    to "search not found". Also blocks the most obvious SPL-injection
    attempts (pipes, backticks) at the connector boundary so reviewers
    auditing the config file can be sure no SPL is being smuggled in.
    """
    name = (name or "").strip()
    if not name:
        raise ValueError("Saved-search name cannot be empty")
    if len(name) > 200:
        raise ValueError(f"Saved-search name too long ({len(name)} chars)")
    if not _SAVED_SEARCH_NAME_RE.match(name):
        raise ValueError(
            f"Saved-search name {name!r} contains disallowed characters. "
            "Connector accepts saved-search NAMES only, not raw SPL. "
            "If you need to add a new search, define it in Splunk first."
        )
    return name


@dataclass
class SplunkResultFile:
    """A single saved-search result-set rendered as bytes.

    Behaves like any other ``SourceFile`` so the ingest orchestrator
    can treat Splunk evidence the same as a local PDF or a SharePoint
    docx. ``.open()`` returns the pre-rendered payload — no second
    network call, no streaming-from-Splunk-mid-extract.
    """

    uri: str
    name: str
    size: int | None
    container_uri: str | None
    _payload: bytes = field(repr=False)

    def open(self) -> BinaryIO:
        return BytesIO(self._payload)


class SplunkSource:
    """Run an allow-list of saved searches and yield each result-set as a file.

    Constructor arguments:

    * ``host`` — Splunk REST host (e.g. ``splunk.example-system.example.mil``).
    * ``port`` — management port (default 8089).
    * ``token`` — Splunk auth token (NEVER a password). Stored on the
      instance; redacted from ``__repr__``.
    * ``saved_searches`` — list of saved-search NAMES to run. Each is
      validated and looked up by name; raw SPL is rejected.
    * ``app`` — Splunk app namespace (default ``"search"``); needed
      because saved searches are scoped per app.
    * ``owner`` — Splunk owner namespace (default ``"-"`` = any owner).
    * ``output_format`` — ``"csv"`` (default) or ``"json"``. Drives the
      ``.name`` extension so the extractor dispatcher picks the right
      extractor.
    * ``page_size`` / ``max_results_per_search`` — pagination knobs.
      See module docstring; defaults bound worst-case memory.
    * ``scheme`` — ``"https"`` (default) or ``"http"``. http is only
      for test fixtures.
    * ``verify`` — TLS verify flag passed through to splunk-sdk; True by
      default. Set False ONLY for self-signed lab instances.

    The ``password`` kwarg is explicitly rejected with a clear error so
    a copy-paste from a stale code sample doesn't accidentally introduce
    password-based auth.
    """

    # Same hint the ingest orchestrator honours for SharePoint —
    # per-search commits so the UI's evidence list refreshes as each
    # saved search lands instead of jumping in one big batch at the
    # end. Splunk runs are small (one row per search) so any batch
    # size > 1 buys nothing.
    commit_batch_size: int = 1

    def __init__(
        self,
        host: str,
        token: str,
        saved_searches: Sequence[str],
        *,
        port: int = 8089,
        app: str = "search",
        owner: str = "-",
        output_format: str = "csv",
        page_size: int = _DEFAULT_PAGE_SIZE,
        max_results_per_search: int = _DEFAULT_MAX_RESULTS,
        scheme: str = "https",
        verify: bool = True,
        # Test-only injection hook: lets the test suite swap in a fake
        # ``splunklib.client.Service`` without monkey-patching the
        # module-level import. Production code never passes this.
        _service_factory=None,
        # Reject legacy auth styles explicitly. The kwargs are listed
        # by name so a stale config dict that includes them fails at
        # construction time, not silently mid-walk.
        password: str | None = None,
        username: str | None = None,
    ) -> None:
        if password is not None or username is not None:
            raise ValueError(
                "SplunkSource accepts token-based auth only. Remove "
                "username/password kwargs and supply a Splunk auth token. "
                "See Splunk docs: 'Authentication Tokens' (Splunk 7.3+)."
            )

        if not host or not isinstance(host, str):
            raise ValueError("Splunk host is required")
        if not token or not isinstance(token, str):
            raise ValueError("Splunk auth token is required")
        if not saved_searches:
            raise ValueError(
                "saved_searches must contain at least one saved-search name. "
                "Raw SPL is not accepted — define the search in Splunk and "
                "list its name here."
            )
        if output_format not in _OUTPUT_FORMATS:
            raise ValueError(
                f"output_format must be one of {_OUTPUT_FORMATS}, got "
                f"{output_format!r}"
            )
        if page_size <= 0:
            raise ValueError("page_size must be positive")
        if max_results_per_search <= 0:
            raise ValueError("max_results_per_search must be positive")
        if scheme not in {"http", "https"}:
            raise ValueError(f"scheme must be 'http' or 'https', got {scheme!r}")

        self.host = host
        self.port = port
        self.app = app
        self.owner = owner
        self.output_format = output_format
        self.page_size = page_size
        self.max_results_per_search = max_results_per_search
        self.scheme = scheme
        self.verify = verify
        self.saved_searches: list[str] = [
            _validate_saved_search_name(n) for n in saved_searches
        ]

        # Token is private-ish — accessible to instance methods but
        # redacted from repr to keep it out of crash logs and the
        # debug ``print(source)`` reflex.
        self._token = token
        self._service_factory = _service_factory
        self._service = None  # lazily built on first iter_files
        # Service construction is memoized via _build_service; the lock
        # makes that safe under concurrent iter_files() calls (defense
        # in depth — the sidecar serializes ingest today, but the
        # cost of the lock is negligible and the cost of duplicate
        # auth on a corp Splunk is non-trivial).
        self._service_lock = threading.Lock()

        # Canonical container URI for the connector instance. Used for
        # provenance grouping on every emitted SourceFile so the UI's
        # "ingested from" filter can collapse a run into one source.
        self.uri = f"splunk://{host}:{port}/{app}"

        # TLS verify=False is occasionally required for lab / self-
        # signed Splunk instances. We don't ban it — but we make sure
        # it's noisy. Both a Python warning (so test suites can assert
        # on it) and a WARNING log line (so operators see it in the
        # sidecar's normal log stream). Tokens are NOT included; the
        # warning is purely about TLS posture.
        if not self.verify:
            warnings.warn(
                "SplunkSource initialized with verify=False; TLS certificate "
                "verification is disabled. Acceptable only for self-signed "
                "lab instances — never for production / boundary Splunk.",
                stacklevel=2,
            )
            LOG.warning(
                "SplunkSource(host=%s) TLS verification DISABLED (verify=False)",
                self.host,
            )

    # ------------------------------------------------------------------
    # Repr / logging discipline
    # ------------------------------------------------------------------
    def __repr__(self) -> str:
        # Explicit redaction. The default dataclass-style repr would
        # dump self._token verbatim — which would land in any log line
        # that interpolated the source object.
        return (
            f"SplunkSource(host={self.host!r}, port={self.port}, "
            f"app={self.app!r}, owner={self.owner!r}, "
            f"saved_searches={self.saved_searches!r}, "
            f"output_format={self.output_format!r}, "
            f"token=<redacted>)"
        )

    # ------------------------------------------------------------------
    # Lazy splunk-sdk Service construction
    # ------------------------------------------------------------------
    def _build_service(self):
        """Construct (and memoize) the ``splunklib.client.Service``.

        Import is local so the sidecar's cold-start cost stays
        independent of whether Splunk is enabled. ``splunk-sdk`` is an
        optional ``sources`` extra (see pyproject) — when not
        installed, the ImportError surfaces with a clear install hint
        instead of an opaque ``ModuleNotFoundError``.

        Memoization is guarded by ``self._service_lock`` so concurrent
        ``iter_files()`` calls don't both pay the auth round-trip. The
        sidecar serializes ingest today, but the lock is cheap and
        prevents a class of "fixed by accident" races we'd rather not
        rely on.
        """
        # Fast path — no lock needed for a hot read.
        if self._service is not None:
            return self._service

        with self._service_lock:
            # Re-check under the lock to avoid duplicate auth.
            if self._service is not None:
                return self._service

            if self._service_factory is not None:
                # Test path — caller supplies a fake.
                self._service = self._service_factory(
                    host=self.host,
                    port=self.port,
                    token=self._token,
                    scheme=self.scheme,
                    verify=self.verify,
                    app=self.app,
                    owner=self.owner,
                )
                return self._service

            try:
                import splunklib.client as client  # type: ignore  # noqa: PLC0415
            except ImportError as exc:
                raise ImportError(
                    "splunk-sdk is not installed. Install the 'sources' extras: "
                    "`pip install -e .[sources]` from backend/, then ensure "
                    "splunk-sdk is present (added to pyproject for v0.4)."
                ) from exc

            # splunk-sdk's `connect()` ALSO accepts username/password — we
            # explicitly pass token only. The SDK then sends
            # ``Authorization: Bearer <token>`` on every request.
            #
            # Auth failures inside the SDK can include the full request
            # headers (including ``Authorization: Splunk <token>``) in
            # the exception chain depending on splunk-sdk + urllib3
            # versions. We catch + re-raise a clean RuntimeError with
            # ``from None`` so the traceback never carries the token
            # into a sidecar crash log.
            try:
                service = client.connect(
                    host=self.host,
                    port=self.port,
                    scheme=self.scheme,
                    verify=self.verify,
                    app=self.app,
                    owner=self.owner,
                    token=self._token,
                )
            except Exception as exc:  # noqa: BLE001
                # Capture only type + a brief, token-free message. We
                # use ``from None`` to drop the original __cause__ /
                # __context__ chain so the SDK's request-header
                # introspection can't bubble up.
                msg = type(exc).__name__
                raise RuntimeError(
                    f"Splunk auth/connect failed for host {self.host!r} "
                    f"(error type: {msg}). Verify the token is valid and "
                    "the host is reachable. (Token redacted from this "
                    "message; check Splunk's own access log for detail.)"
                ) from None
            self._service = service
            return self._service

    # ------------------------------------------------------------------
    # Per-saved-search dispatch + paginated result collection
    # ------------------------------------------------------------------
    def _run_saved_search(self, service, name: str) -> tuple[str, bytes, str]:
        """Dispatch one saved search and return ``(run_id, payload, suffix)``.

        ``run_id`` is the Splunk SID (search-id) — opaque, unique per
        dispatch. We surface it in the URI so an auditor can correlate
        the Evidence row to the exact Splunk job in the Splunk UI.

        Paginated via ``count=page_size`` + ``offset=n`` so a wide
        search doesn't materialize all rows in one SDK call. Stops
        when Splunk returns fewer rows than the page size (last page)
        or when ``max_results_per_search`` is hit (we mark the payload
        truncated in that case — a trailing ``# truncated`` line for
        CSV, an explicit ``"truncated": true`` field for JSON).
        """
        # Look up the saved search by name. ``SavedSearches[name]``
        # raises KeyError on miss — we wrap that into a clear
        # connector-level error so a typo in the config file produces
        # an actionable message and a single skipped search, not a
        # mid-walk crash that aborts every subsequent saved search.
        try:
            saved = service.saved_searches[name]
        except KeyError:
            raise RuntimeError(
                f"Splunk saved search {name!r} not found in app "
                f"{self.app!r}/owner {self.owner!r}. Either the name is "
                "wrong or the auth token's role lacks read access."
            )

        # Dispatch returns a Job; we wait for it to complete. The SDK
        # exposes `.is_done()` polling — bounded so a stuck job
        # doesn't hang the walk forever.
        job = saved.dispatch()
        sid = job.sid
        deadline = time.monotonic() + 600  # 10 min hard cap per search
        while not job.is_done():
            if time.monotonic() > deadline:
                # Best-effort cancel. If cancel itself fails, the job
                # is still safe to abandon — Splunk reaps stale jobs
                # automatically.
                try:
                    job.cancel()
                except Exception:  # noqa: BLE001
                    LOG.exception("Failed to cancel stuck Splunk job %s", sid)
                raise RuntimeError(
                    f"Splunk saved search {name!r} (sid={sid}) did not "
                    "complete within 10 minutes — aborted."
                )
            time.sleep(1.0)

        rows: list[dict] = []
        truncated = False
        offset = 0
        while True:
            remaining = self.max_results_per_search - len(rows)
            if remaining <= 0:
                truncated = True
                break
            this_count = min(self.page_size, remaining)
            # ``results()`` returns a stream of JSON or CSV bytes
            # depending on output_mode. We always request JSON
            # internally so pagination is uniform — output_format
            # only affects what we WRITE.
            stream = job.results(
                output_mode="json",
                count=this_count,
                offset=offset,
            )
            try:
                raw = stream.read()
            finally:
                try:
                    stream.close()
                except Exception:  # noqa: BLE001
                    pass

            if not raw:
                break
            try:
                doc = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Splunk returned non-JSON results for {name!r} "
                    f"(sid={sid}): {exc}"
                )
            page = doc.get("results", []) or []
            rows.extend(page)
            if len(page) < this_count:
                # Last page — Splunk gave us fewer rows than asked.
                break
            offset += this_count

        if self.output_format == "csv":
            payload = _rows_to_csv(rows, truncated=truncated)
            suffix = ".csv"
        else:
            payload = _rows_to_json(rows, truncated=truncated)
            suffix = ".json"

        LOG.info(
            "Splunk saved search %r returned %d rows (truncated=%s, sid=%s)",
            name,
            len(rows),
            truncated,
            sid,
        )
        return sid, payload, suffix

    # ------------------------------------------------------------------
    # Source protocol
    # ------------------------------------------------------------------
    def iter_files(self) -> Iterator[SourceFile]:
        """Run each configured saved search and yield one SourceFile per run.

        Failures on individual saved searches are logged and skipped
        rather than aborting the walk — same shape as the SharePoint
        walker's per-folder fetch handling. Aggregate failures
        (auth, connectivity) raise so the orchestrator surfaces a
        connector-level error tile rather than silently producing
        zero artifacts.
        """
        service = self._build_service()
        for name in self.saved_searches:
            try:
                sid, payload, suffix = self._run_saved_search(service, name)
            except Exception as exc:  # noqa: BLE001
                # Per-search failure — log and skip. Token is never in
                # the exception message because we only ever pass it
                # to the SDK, never interpolate it ourselves.
                LOG.warning(
                    "Splunk saved search %r failed; skipping. (%s)", name, exc
                )
                continue

            # Filename embeds the saved-search name so the tagger's
            # filename heuristics can map AU-named searches to AU
            # controls, etc. Replace path-unsafe chars with `_` so the
            # CSV extractor's filename inference doesn't choke.
            # Strip leading/trailing underscores AND dots so the
            # filename can't become a hidden dotfile (e.g. ".something")
            # on POSIX or trip Windows' trailing-dot trim heuristic.
            safe_name = re.sub(r"[^A-Za-z0-9._\-]+", "_", name).strip("_.")
            file_name = f"{safe_name}__{sid}{suffix}"
            yield SplunkResultFile(
                uri=_splunk_uri(name, sid),
                name=file_name,
                size=len(payload),
                container_uri=self.uri,
                _payload=payload,
            )


# ---------------------------------------------------------------------------
# Result rendering helpers (pure functions — easy to unit test)
# ---------------------------------------------------------------------------


def _rows_to_csv(rows: list[dict], *, truncated: bool) -> bytes:
    """Render JSON-shaped rows as CSV bytes.

    Column order is the union of keys across all rows, sorted for
    determinism (so re-runs of the same search produce byte-identical
    payloads when the result set didn't change — useful for hash-based
    dedupe upstream). Truncation is signaled by an explicit
    ``# truncated`` comment as the trailing line; the CSV extractor
    ignores comment lines, so the truncation hint is visible to humans
    inspecting the file without breaking the extractor.
    """
    if not rows:
        buf = io.StringIO()
        if truncated:
            buf.write("# truncated\n")
        return buf.getvalue().encode("utf-8")

    keys: set[str] = set()
    for r in rows:
        keys.update(r.keys())
    ordered_keys = sorted(keys)

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=ordered_keys, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        # Multi-value fields come back as lists in JSON — join with
        # newline so the CSV cell is a single string. None becomes
        # empty string for CSV-friendliness.
        flat = {}
        for k in ordered_keys:
            v = r.get(k)
            if v is None:
                flat[k] = ""
            elif isinstance(v, (list, tuple)):
                flat[k] = "\n".join(str(x) for x in v)
            else:
                flat[k] = str(v)
        writer.writerow(flat)
    if truncated:
        buf.write("# truncated\n")
    return buf.getvalue().encode("utf-8")


def _rows_to_json(rows: list[dict], *, truncated: bool) -> bytes:
    """Render rows as a JSON document with explicit ``truncated`` field."""
    doc = {"results": rows, "truncated": truncated, "count": len(rows)}
    return json.dumps(doc, ensure_ascii=False, indent=2).encode("utf-8")
