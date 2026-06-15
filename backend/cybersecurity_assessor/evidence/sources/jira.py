"""Jira issue-tracker source — gated v0.4+ connector.

Pulls Jira issues matching a **config-defined** JQL query as evidence.
Primary use cases mapped to control families:

* **IR-***  — incident-response tickets (post-mortems, on-call rotations).
* **CM-***  — change-control RFCs, deployment/CR tickets, freeze-window
  approvals.
* **CA-***  — POA&M tracking tickets, milestone evidence.
* **AU-***  — audit-finding follow-up tickets, log-review actions.

Design constraints (load-bearing for federal-defensibility):

1. **Config-bound JQL only.** The list of queries lives in
   ``config.toml`` under ``[connectors.jira]`` (or is supplied by tests).
   There is no API surface that accepts a free-form runtime JQL string —
   if a query can be edited per-request, the assessor cannot defend what
   was queried at audit time. New queries require an explicit config
   edit, which is reviewable.

2. **Double feature flag.** Activates ONLY when BOTH ``connectors.v04``
   AND ``connectors.jira_upcoming_gated`` are true. Default off. A
   user-installed v0.x build cannot turn this on by accident — both
   flags require manual config-toml edits, and the second flag is
   explicitly labelled as "upcoming-gated" so a future-build operator
   knows they are opting in to unfinished functionality.

3. **Personal Access Token (PAT) auth, OS-keyring storage.** PAT lives
   in the same Windows Credential Manager (cross-platform via
   ``keyring``) as every other secret in the app. Never persisted to
   ``config.toml``, never echoed in logs.

4. **URI carries ``updated`` timestamp** so re-ingest after an issue
   updates lands as a *new* :class:`Evidence` row (the orchestrator
   keys on ``Evidence.path``), while an unchanged re-ingest dedupes.
   Shape: ``jira://<host>/issue/<KEY>@<updated_iso8601>``.

5. **Pagination** via the chosen library's iterator so large JQL result
   sets (>1000 issues) don't silently truncate. Default upper bound is
   configurable but capped so an unbounded JQL doesn't OOM the ingest
   process.

Library choice: ``atlassian-python-api`` (``atlassian.Jira``).
Rationale:
  * Single dependency covers Jira Server (Data Center) and Jira Cloud.
  * PAT and Bearer-token auth both first-class.
  * Built-in ``jql_get_list_of_tickets`` pagination helper —
    ``jira-python`` requires hand-rolled ``startAt`` loops.
  * Mature in DoD/IC environments (same vendor as Confluence MCP we
    already lean on).
The ``jira`` (``jira-python``) library would have worked too; rejected
only because we already use ``atlassian-python-api`` for Confluence
elsewhere and a single transport library is one less version-skew risk
for the v2.0 installer bundle (see
``project_ccis_assessor_installer_prereqs.md``).

Like the eMASS connector this module is **gated stub-grade** for now:
the surface is locked, tests pin behaviour, but no production ingest
runs against a live Jira until both flags flip in a v0.4 build.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any, BinaryIO, Iterable, Iterator
from urllib.parse import quote, urlparse

from .base import SourceFile

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Feature-flag gate — double-flag, both required, default off
# ---------------------------------------------------------------------------


class JiraConnectorDisabledError(RuntimeError):
    """Raised when ``JiraSource`` is constructed without both flags enabled.

    Distinct exception type so the route layer can catch and surface a
    422 with a clear "enable feature flags X and Y" hint instead of a
    generic 500. Tests pin the exact pair of flag names so a future
    rename here doesn't silently regress the gate.
    """


def is_jira_connector_enabled(
    *,
    v04_flag: bool,
    upcoming_gated_flag: bool,
) -> bool:
    """Return True only when BOTH gating flags are on.

    Encoded as a free function (not a method) so the routes layer can
    short-circuit *before* instantiating the source, and so the test
    suite can assert truth-table behaviour without spinning up a
    ``JiraSource``.
    """
    return bool(v04_flag) and bool(upcoming_gated_flag)


# ---------------------------------------------------------------------------
# Config dataclass — what the route hands us, what tests construct directly
# ---------------------------------------------------------------------------


# Cap on issues per JQL query. The orchestrator already streams one
# SourceFile at a time so memory isn't the issue — this is a defensive
# guardrail against an operator accidentally pasting `project = FOO` as a
# query and yanking 80,000 tickets into the evidence index. Adjust in
# config if a legitimate query genuinely needs more. Defensibility note:
# the cap value is logged at iter-time so the assessor's audit trail
# captures "we asked Jira for at most N issues matching <query>".
DEFAULT_MAX_RESULTS_PER_QUERY = 1000

# Fields requested from Jira when none are explicitly configured. Kept
# narrow on purpose: the broader the field set, the more PII / unrelated
# project context lands in the evidence payload. Operators broaden this
# in config if a particular control family needs (e.g.) ``customfield_*``
# entries surfaced.
DEFAULT_FIELDS = (
    "summary",
    "status",
    "issuetype",
    "priority",
    "labels",
    "components",
    "assignee",
    "reporter",
    "created",
    "updated",
    "resolutiondate",
    "description",
    "fixVersions",
)


@dataclass(frozen=True)
class JiraConfig:
    """Frozen config snapshot for one ``JiraSource`` walk.

    ``frozen=True`` so a route handler that builds this from a route
    request can hand the same object to multiple downstream callers
    without worrying about mutation. The JQL list is forced to a tuple
    on construction so even a misbehaving caller can't reach in and
    swap queries between the flag check and the walk.
    """

    server_url: str
    # ``repr=False`` so str/repr/log-formatting of a JiraConfig never leaks
    # the PAT. Defensibility note: federal-compliance code should never
    # have a secret in any default str() — even a single LOG.info("%r",cfg)
    # at debug time would pin the token in operator logs. Reviewer GPT-5.1
    # flagged this as a concrete leak path; the regression is pinned by
    # ``test_pat_not_in_config_repr`` in the stub-test file.
    pat: str = field(repr=False)
    queries: tuple[str, ...]
    fields: tuple[str, ...] = field(default_factory=lambda: DEFAULT_FIELDS)
    max_results_per_query: int = DEFAULT_MAX_RESULTS_PER_QUERY
    verify_ssl: bool = True

    def __post_init__(self) -> None:
        """Validate on construction — direct callers (tests, routes) get the
        same non-empty-queries guarantee that ``from_dict`` enforces.

        Without this, a route handler could build ``JiraConfig(queries=())``
        and the walk would silently no-op instead of failing loud — exactly
        the kind of "we ran the assessment, found nothing, looked green"
        bug that hurts at audit time.
        """
        if not isinstance(self.queries, tuple) or not self.queries:
            raise ValueError(
                "JiraConfig.queries must be a non-empty tuple of JQL strings"
            )
        if any(not (isinstance(q, str) and q.strip()) for q in self.queries):
            raise ValueError(
                "JiraConfig.queries contained only empty strings or non-strings"
            )

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, pat: str) -> "JiraConfig":
        """Build from a parsed ``[connectors.jira]`` TOML table + injected PAT.

        PAT comes in separately (from keyring resolution) so the TOML
        layer never sees it. The dict shape we accept:

            server_url:  str        (required)
            queries:     list[str]  (required, non-empty)
            fields:      list[str]  (optional; defaults to DEFAULT_FIELDS)
            max_results_per_query: int (optional)
            verify_ssl:  bool       (optional; default True)
        """
        server = (data.get("server_url") or "").strip()
        if not server:
            raise ValueError("Jira config missing required 'server_url'")
        raw_queries = data.get("queries") or []
        if not isinstance(raw_queries, (list, tuple)) or not raw_queries:
            raise ValueError(
                "Jira config 'queries' must be a non-empty list of JQL strings"
            )
        queries = tuple(str(q).strip() for q in raw_queries if str(q).strip())
        if not queries:
            raise ValueError("Jira config 'queries' contained only empty strings")
        fields_raw = data.get("fields") or DEFAULT_FIELDS
        fields_tuple = tuple(str(f).strip() for f in fields_raw if str(f).strip())
        if not fields_tuple:
            fields_tuple = DEFAULT_FIELDS
        return cls(
            server_url=server.rstrip("/"),
            pat=pat,
            queries=queries,
            fields=fields_tuple,
            max_results_per_query=int(
                data.get("max_results_per_query") or DEFAULT_MAX_RESULTS_PER_QUERY
            ),
            verify_ssl=bool(data.get("verify_ssl", True)),
        )


# ---------------------------------------------------------------------------
# URI helpers
# ---------------------------------------------------------------------------


def _jira_host(server_url: str) -> str:
    """Extract the bare hostname from a Jira server URL.

    Used as the ``<host>`` segment of the canonical URI. We normalise so
    ``https://jira.example.mil/`` and ``http://jira.example.mil:8080``
    produce stable, comparable URIs (the port is preserved when present;
    the scheme is dropped because ``jira://`` carries no scheme info).
    """
    parsed = urlparse(server_url)
    host = parsed.netloc or parsed.path
    return host.strip("/").lower()


def jira_issue_uri(server_url: str, key: str, updated_iso: str) -> str:
    """Canonical URI for a Jira issue snapshot.

    Embedding ``updated`` in the URI makes re-ingest semantics fall out
    of the existing dedupe logic for free: orchestrator keys on
    ``Evidence.path`` (== this URI). Two ingests of the same issue with
    no update → same URI → dedupe. An update bumps ``updated`` →
    different URI → new Evidence row, old row preserved as historical
    snapshot (matches NIST evidence-of-record expectations).
    """
    host = _jira_host(server_url)
    # quote() the key+timestamp so a future Jira convention change (e.g.
    # microsecond suffixes) doesn't break URI parsing downstream.
    return f"jira://{host}/issue/{quote(key, safe='')}@{quote(updated_iso, safe='')}"


# ---------------------------------------------------------------------------
# SourceFile — one Jira issue payload
# ---------------------------------------------------------------------------


@dataclass
class JiraIssueFile:
    """One Jira issue serialised as JSON, conforming to :class:`SourceFile`.

    ``open()`` returns a fresh ``BytesIO`` over the cached payload each
    call; the orchestrator opens twice (hash + extract) and serialisation
    is the costly bit, not the bytes wrapper. Caching the bytes once
    keeps both opens cheap without holding a network handle.
    """

    uri: str
    name: str
    size: int | None
    container_uri: str | None
    _payload: bytes = field(repr=False)

    def open(self) -> BinaryIO:
        return BytesIO(self._payload)


# ---------------------------------------------------------------------------
# Source — config-bound JQL walker
# ---------------------------------------------------------------------------


class JiraSource:
    """Walk one or more JQL queries, yielding one ``JiraIssueFile`` per issue.

    Gated by ``is_jira_connector_enabled``: construction raises
    :class:`JiraConnectorDisabledError` unless BOTH feature flags are
    explicitly true. This keeps the gate at the construction boundary
    instead of relying on every caller remembering to check first.

    ``iter_files`` paginates each configured JQL until either:
      * Jira returns no more results, or
      * ``max_results_per_query`` is hit (logged as a truncation warning
        so the audit trail captures the cap).

    The connector is intentionally **read-only**: no create / update /
    transition methods exist on this surface. Mutations require a write
    connector (not in any current roadmap line item).
    """

    # The orchestrator's per-file commit batch size knob. Network round-
    # trip per issue dominates SQLite commit cost, same pattern as
    # SharePointSource — commit per file so the UI's evidence list
    # refreshes continuously.
    commit_batch_size: int = 1

    def __init__(
        self,
        config: JiraConfig,
        *,
        v04_flag: bool,
        upcoming_gated_flag: bool,
        client: Any | None = None,
    ) -> None:
        if not is_jira_connector_enabled(
            v04_flag=v04_flag, upcoming_gated_flag=upcoming_gated_flag
        ):
            raise JiraConnectorDisabledError(
                "Jira connector requires BOTH feature flags: "
                "'connectors.v04' and 'connectors.jira_upcoming_gated'. "
                "Both default to false; enable them in config.toml only when "
                "intentionally opting into upcoming-gated functionality."
            )
        self.config = config
        # Optional injected client for tests / future alternate transports.
        # When None, ``_get_client()`` lazily imports atlassian-python-api.
        self._client = client
        self.uri = f"jira://{_jira_host(config.server_url)}/"

    # ------------------------------------------------------------------
    # Client plumbing
    # ------------------------------------------------------------------
    def _get_client(self) -> Any:
        """Return an authenticated ``atlassian.Jira`` instance (or injected).

        Lazy import: keeps ``atlassian-python-api`` a soft dep — the
        module imports cleanly even when the package is missing, so the
        flag gate is the *only* thing that can refuse to construct.
        Operators who never enable the flags never need the dependency.
        """
        if self._client is not None:
            return self._client
        try:
            from atlassian import Jira  # type: ignore[import-not-found]  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "atlassian-python-api is not installed. Install the 'jira' "
                "extras: `pip install -e .[jira]` from backend/. The Jira "
                "connector requires this package for PAT auth + pagination."
            ) from exc
        # PAT auth uses the ``token`` kwarg (NOT ``password``). Server &
        # Cloud both accept Bearer-token auth via this path.
        self._client = Jira(
            url=self.config.server_url,
            token=self.config.pat,
            verify_ssl=self.config.verify_ssl,
            cloud=False,
        )
        return self._client

    # ------------------------------------------------------------------
    # Walk
    # ------------------------------------------------------------------
    def iter_files(self) -> Iterator[SourceFile]:
        """Yield one :class:`JiraIssueFile` per issue across all configured JQL.

        Dedupe: the same issue can match multiple configured queries;
        we yield it only once (keyed by issue key + updated timestamp,
        which is exactly what the URI carries).
        """
        client = self._get_client()
        seen_uris: set[str] = set()
        for jql in self.config.queries:
            LOG.info(
                "Jira walk starting: jql=%r fields=%d max_results=%d",
                jql,
                len(self.config.fields),
                self.config.max_results_per_query,
            )
            count = 0
            try:
                for issue in self._paginate(client, jql):
                    key = issue.get("key") or ""
                    fields = issue.get("fields") or {}
                    updated = fields.get("updated") or ""
                    if not key or not updated:
                        # Defensive: every Jira issue carries key + updated.
                        # If either is missing the URI can't be stable; skip.
                        LOG.debug("Skipping Jira issue with missing key/updated: %r", issue)
                        continue
                    uri = jira_issue_uri(self.config.server_url, key, updated)
                    if uri in seen_uris:
                        continue
                    seen_uris.add(uri)
                    payload = json.dumps(
                        {"key": key, "fields": fields},
                        ensure_ascii=False,
                        sort_keys=True,
                    ).encode("utf-8")
                    yield JiraIssueFile(
                        uri=uri,
                        name=f"{key}.json",
                        size=len(payload),
                        container_uri=self.uri,
                        _payload=payload,
                    )
                    count += 1
                    if count >= self.config.max_results_per_query:
                        LOG.warning(
                            "Jira walk truncated at max_results_per_query=%d for "
                            "jql=%r — increase the cap if this query legitimately "
                            "needs more, or narrow the JQL.",
                            self.config.max_results_per_query,
                            jql,
                        )
                        break
            except Exception as exc:  # noqa: BLE001
                # One bad JQL shouldn't poison the whole walk. Log + move on
                # so the assessor still gets evidence from the other queries.
                LOG.warning(
                    "Jira walk failed for jql=%r after %d issues: %s",
                    jql,
                    count,
                    exc,
                )
                continue
            LOG.info("Jira walk complete: jql=%r issues=%d", jql, count)

    # ------------------------------------------------------------------
    # Pagination helper
    # ------------------------------------------------------------------
    def _paginate(self, client: Any, jql: str) -> Iterable[dict]:
        """Yield issue dicts for ``jql`` using ``atlassian.Jira.jql`` paging.

        ``atlassian.Jira.jql`` returns a single page; we drive the
        ``startAt`` loop ourselves so the cap + truncation logging in
        ``iter_files`` stays authoritative. Page size 100 is the
        atlassian-python-api default and the Jira API hard ceiling for
        most deployments.

        We also stop requesting further pages once we've fetched at least
        ``max_results_per_query`` issues — without this, a 50k-issue JQL
        with a cap of 1000 would still hammer Jira for 50 pages even
        though the connector throws 49 of them away in ``iter_files``.
        Reviewer GPT-5.1 flagged the unbounded fetch as a polite-API +
        defensibility gap (audit log should show we asked for at most N).

        Wrapped in its own method so tests can override pagination
        without re-stubbing the whole walk.
        """
        page_size = 100
        start_at = 0
        fields = list(self.config.fields)
        cap = self.config.max_results_per_query
        fetched = 0
        while True:
            result = client.jql(
                jql,
                start=start_at,
                limit=page_size,
                fields=fields,
            )
            issues = (result or {}).get("issues") or []
            if not issues:
                return
            for issue in issues:
                yield issue
            fetched += len(issues)
            if len(issues) < page_size:
                return
            if fetched >= cap:
                # iter_files will log the truncation warning on the next
                # yield-cap check. We just stop hitting Jira.
                return
            start_at += page_size

    # ------------------------------------------------------------------
    # Probe — used by Settings UI to confirm the PAT works
    # ------------------------------------------------------------------
    def test_connection(self) -> dict[str, Any]:
        """Round-trip a lightweight ``/myself`` call to validate auth + reach.

        Returns a stable shape so the Settings card can render a green
        banner with the authenticated account name, mirroring the
        SharePoint test_connection result.
        """
        try:
            client = self._get_client()
            me = client.myself()  # type: ignore[attr-defined]
            return {
                "ok": True,
                "server_url": self.config.server_url,
                "account": (me or {}).get("displayName")
                or (me or {}).get("name")
                or "",
                "queries_configured": len(self.config.queries),
            }
        except Exception as exc:  # noqa: BLE001 — surface for UI
            return {
                "ok": False,
                "server_url": self.config.server_url,
                "error": str(exc),
            }
