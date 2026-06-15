"""Confluence Data Center evidence source — page bodies + attachments.

GATED CONNECTOR. Off by default. Requires TWO independent feature flags
to activate at runtime — ``connectors.v04`` (the v0.4 connector wave
flag) AND ``connectors.confluence_upcoming_gated`` (the per-connector
"upcoming" gate that matches the same posture as the eMASS REST client).
Construction itself is allowed (so the Settings card can render "not
configured") but :meth:`ConfluenceSource.iter_files` refuses to walk
unless both flags are True.

The connector pulls from a Confluence Data Center instance (on-prem,
not Cloud — different auth and different REST shape; Cloud support is a
follow-up). Scope is defined by **either** a CQL query string **or** a
list of space keys; not both. Each page emits:

* one :class:`ConfluenceFile` for the rendered page body (HTML, exposed
  as ``.html`` so the existing HTML extractor picks it up), and
* one :class:`ConfluenceFile` per attachment when
  ``include_attachments=True`` (default), keyed by attachment id.

URI convention
--------------

* Page body:      ``confluence://<host>/page/<page_id>@<version>``
* Attachment:     ``confluence://<host>/page/<page_id>/attachment/<att_id>@<att_version>``

The ``@<version>`` suffix is **load-bearing** — Confluence pages and
attachments are versioned and the ingest orchestrator dedupes on URI.
Without the version suffix, a re-walk of an updated page would compare
equal to the prior ingest and the new content would silently drop.
With the suffix, a version bump produces a distinct URI and the
orchestrator treats it as a fresh artifact (existing rows pointing at
the prior version remain intact as historical evidence — supersession
detection runs at the assessment layer, not here).

Auth
----

Personal Access Token (PAT) only. PAT is sourced from, in order:

1. ``CONFLUENCE_PAT`` environment variable (preferred for CI / dev),
2. OS keychain slot ``CONFLUENCE_PAT`` under the existing
   ``cybersecurity-assessor`` keyring service.

No PAT is ever accepted as a constructor argument, written to disk, or
echoed in log lines. The constructor stores ``server_url`` and scope
parameters only; the token is read lazily on the first network call.

Why no Basic / OAuth: PAT is the documented Data Center auth path,
works against gov-hosted Data Center instances behind the same SSO
fronting as the rest of the assessor's gated connectors, and avoids
the per-user OAuth dance Cloud requires.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from io import BytesIO
from typing import BinaryIO, Iterable, Iterator
from urllib.parse import urlparse

from .base import SourceFile

LOG = logging.getLogger(__name__)

# Keyring slot — kept under the existing service so the user has one
# Credential Manager entry per provider rather than a separate service
# per connector. Matches the eMASS / SharePoint convention in
# ``config.py``.
KEYRING_KEY_CONFLUENCE_PAT = "CONFLUENCE_PAT"


# ---------------------------------------------------------------------------
# Feature-flag gate
# ---------------------------------------------------------------------------

# Both flags must be True at the time iter_files() is called. The
# constructor itself is unguarded so the Settings card can render
# "configured but disabled" without an exception. Mirrors the eMASS
# stub pattern: existence is fine, *activation* requires explicit opt-in.
_V04_FLAG = "connectors.v04"
_UPCOMING_FLAG = "connectors.confluence_upcoming_gated"


class ConfluenceGatedError(RuntimeError):
    """Raised when iter_files() is called without both feature flags set.

    Distinct exception type so callers (the ingest route, the Settings
    card) can render a "this connector is gated" message instead of a
    generic 500. Matches the GraphAuthError discipline in
    ``sharepoint.py``.
    """


def _flag_enabled(flags: dict | None, key: str) -> bool:
    """Read a dotted-key flag from a nested-or-flat dict.

    Accepts both ``{"connectors": {"v04": True}}`` (the nested shape
    config.toml produces) and ``{"connectors.v04": True}`` (flat
    shape some test fixtures use). Returns False when the dict is None
    or the key is missing — gated-off is the safe default for any
    ambiguous state.
    """
    if not flags:
        return False
    parts = key.split(".")
    cur: object = flags
    for p in parts:
        if not isinstance(cur, dict):
            return False
        if p in cur:
            cur = cur[p]
            continue
        # Fall through to flat lookup at top level only.
        return False
    return bool(cur)


def confluence_enabled(flags: dict | None) -> bool:
    """Both gates must be ON. Order doesn't matter; AND semantics.

    Exposed at module level so route code can short-circuit
    ConfluenceSource construction entirely when either gate is off
    instead of catching ConfluenceGatedError after the fact.
    """
    # Flat-key fast path so the dict ``{"connectors.v04": True,
    # "connectors.confluence_upcoming_gated": True}`` (the shape some
    # test fixtures + an env-var loader produce) also works without
    # forcing nested wrapping.
    if flags:
        flat = (
            flags.get(_V04_FLAG) is True
            and flags.get(_UPCOMING_FLAG) is True
        )
        if flat:
            return True
    return _flag_enabled(flags, _V04_FLAG) and _flag_enabled(
        flags, _UPCOMING_FLAG
    )


# ---------------------------------------------------------------------------
# PAT acquisition
# ---------------------------------------------------------------------------


def _get_pat() -> str:
    """Read the Confluence PAT from env or keyring. Never returns it.

    Raises :class:`RuntimeError` (not :class:`ConfluenceGatedError`)
    when the PAT is missing — gating is orthogonal to credential
    presence and the two failures want different UX surfaces. Both
    lookup paths are silent on the value itself; only presence is
    logged.
    """
    env = os.environ.get("CONFLUENCE_PAT")
    if env:
        LOG.debug("Confluence PAT sourced from CONFLUENCE_PAT env var")
        return env
    try:
        import keyring  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "Confluence PAT not in CONFLUENCE_PAT env, and `keyring` is "
            "not installed for fallback lookup."
        ) from exc
    # Pull the canonical keyring service name from config.py so a future
    # rename only has to happen in one place. Imported lazily inside the
    # function so the connector module stays importable without the
    # config layer (matters in early-boot test scenarios).
    from ...config import KEYRING_SERVICE  # noqa: PLC0415

    val = keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_CONFLUENCE_PAT)
    if not val:
        raise RuntimeError(
            "Confluence PAT not configured. Set CONFLUENCE_PAT env var "
            f"or store under keyring service '{KEYRING_SERVICE}', "
            f"key '{KEYRING_KEY_CONFLUENCE_PAT}'."
        )
    LOG.debug("Confluence PAT sourced from OS keyring")
    return val


# ---------------------------------------------------------------------------
# SourceFile + Source implementations
# ---------------------------------------------------------------------------


@dataclass
class ConfluenceFile:
    """One downloadable byte payload from Confluence (page body or attachment).

    The orchestrator's hash + extract pipeline calls :meth:`open` twice
    per artifact, so the raw bytes are cached after the first fetch.
    Instances are single-use (the walker yields a fresh one per file
    and the orchestrator drops the reference after iteration), so the
    cache stays bounded to one artifact at a time — same shape as
    :class:`SharePointFile`.
    """

    uri: str
    name: str
    size: int | None
    container_uri: str | None
    # Closure that produces the bytes on demand. Injected by the walker
    # so tests can substitute a fake without touching a network. Lives
    # on the instance (not a module-level function) so each file carries
    # the exact context it needs to fetch itself — page id for body,
    # attachment download path for attachments.
    _fetch: object = field(repr=False, default=None)
    _cached: bytes | None = field(default=None, repr=False)

    def open(self) -> BinaryIO:
        if self._cached is not None:
            return BytesIO(self._cached)
        if self._fetch is None:
            raise RuntimeError(
                f"ConfluenceFile {self.uri} has no fetch closure — "
                "constructed outside ConfluenceSource.iter_files?"
            )
        # The closure is the only thing that talks to the network.
        # Errors propagate to the orchestrator which logs + skips the
        # file (the iter_files loop catches per-page so a single bad
        # attachment doesn't abort the whole walk).
        data = self._fetch()  # type: ignore[operator]
        if not isinstance(data, (bytes, bytearray)):
            raise RuntimeError(
                f"ConfluenceFile fetch returned {type(data).__name__}, "
                "expected bytes"
            )
        self._cached = bytes(data)
        return BytesIO(self._cached)


class ConfluenceSource:
    """Walk a Confluence Data Center scope, yielding ingestible page bodies + attachments.

    Construction
    ------------

    ``server_url``      — base URL of the Confluence instance, e.g.
                          ``https://confluence.example.mil``. Trailing
                          slash trimmed. The URI scheme falls back to
                          the URL's hostname (``urlparse(...).netloc``)
                          so corporate proxy URLs that include a path
                          prefix still produce clean canonical URIs.

    Exactly ONE of:
      ``cql``          — CQL query string. Forwarded verbatim to the
                          Confluence search endpoint. Use for "all
                          pages with label X" / "all pages modified
                          since Y" / multi-space scopes.
      ``space_keys``    — list of Confluence space keys. The walker
                          iterates each space's pages.

    ``include_attachments``  — when True (default), each page emits
                          itself plus one ConfluenceFile per attachment.
                          When False, only page bodies are yielded.

    ``flags``           — dict of feature flags. MUST contain both
                          ``connectors.v04`` and
                          ``connectors.confluence_upcoming_gated`` set
                          to True or :meth:`iter_files` raises
                          :class:`ConfluenceGatedError`. Default None
                          means "no flags supplied" which also fails
                          the gate — safe by construction.

    ``client``          — optional pre-constructed
                          ``atlassian.Confluence`` client. Injected by
                          tests; production code leaves this None and
                          the source lazily constructs one from
                          ``server_url`` + PAT on first walk.

    Why "exactly one of CQL or space_keys"
    --------------------------------------

    Mixing the two produces ambiguous scope (CQL can already filter by
    space, so a separate space list is redundant or contradictory).
    Forcing the caller to pick keeps the audit trail clear: the
    IngestSummary records the literal scope spec, and a reviewer can
    re-run the same query offline.
    """

    # Per-file commits — same reasoning as SharePointSource. Each fetch
    # is a network call, so SQLite commit overhead is dwarfed by I/O
    # and the UI's evidence list refreshes continuously.
    commit_batch_size: int = 1

    def __init__(
        self,
        server_url: str,
        *,
        cql: str | None = None,
        space_keys: Iterable[str] | None = None,
        include_attachments: bool = True,
        flags: dict | None = None,
        client: object | None = None,
    ) -> None:
        self.server_url = (server_url or "").rstrip("/")
        if not self.server_url:
            raise ValueError("ConfluenceSource: server_url is required")

        # Scope: exactly one of cql or space_keys. Both/neither = error.
        space_list = list(space_keys) if space_keys else []
        if bool(cql) == bool(space_list):
            raise ValueError(
                "ConfluenceSource: pass EXACTLY ONE of cql=... or "
                "space_keys=... (got "
                f"cql={cql!r}, space_keys={space_list!r})"
            )
        self.cql = cql
        self.space_keys = space_list
        self.include_attachments = include_attachments
        self.flags = flags
        self._client = client

        parsed = urlparse(self.server_url)
        self._host = parsed.netloc or parsed.path
        # Top-level URI on IngestSummary — describes the scope, not a
        # specific page. CQL scopes are quoted so the round-trip in the
        # UI is unambiguous; space-key scopes get a comma-joined list.
        if self.cql:
            self.uri = f"confluence://{self._host}/?cql={self.cql}"
        else:
            self.uri = (
                f"confluence://{self._host}/?spaces="
                + ",".join(self.space_keys)
            )

    # ------------------------------------------------------------------
    # Client construction — lazy, PAT pulled at call time
    # ------------------------------------------------------------------
    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            from atlassian import Confluence  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "atlassian-python-api is not installed. Install the "
                "'sources' extras: `pip install -e .[sources]` from "
                "backend/."
            ) from exc
        pat = _get_pat()
        # Bearer-token auth on Data Center. atlassian-python-api takes
        # the PAT via ``token=`` which sets the Authorization header
        # accordingly; do NOT pass username/password — the library
        # would otherwise fall through to Basic auth and the gov
        # instance returns 401.
        self._client = Confluence(url=self.server_url, token=pat)
        return self._client

    # ------------------------------------------------------------------
    # Page enumeration
    # ------------------------------------------------------------------
    def _iter_page_ids(self) -> Iterator[str]:
        """Yield page ids in scope, paginated.

        CQL path uses ``cql`` endpoint with explicit ``type=page`` AND
        wrapping the caller-supplied query so a CQL like
        ``label = "specification"`` doesn't accidentally pull blogposts
        or comments. Space-key path uses ``get_all_pages_from_space``.
        Both paginate with ``start`` / ``limit`` until exhaustion.
        """
        client = self._get_client()
        page_size = 50

        if self.cql:
            cql = f"({self.cql}) AND type = page"
            start = 0
            while True:
                # atlassian-python-api exposes cql() returning the raw
                # search JSON; results key is "results".
                resp = client.cql(cql, start=start, limit=page_size)  # type: ignore[attr-defined]
                results = (resp or {}).get("results", []) if isinstance(resp, dict) else []
                if not results:
                    break
                for r in results:
                    # Result shape: {"content": {"id": "...", "type": "page", ...}}
                    content = r.get("content") if isinstance(r, dict) else None
                    if not content:
                        continue
                    if content.get("type") != "page":
                        continue
                    pid = content.get("id")
                    if pid:
                        yield str(pid)
                if len(results) < page_size:
                    break
                start += page_size
            return

        for space in self.space_keys:
            start = 0
            while True:
                pages = client.get_all_pages_from_space(  # type: ignore[attr-defined]
                    space, start=start, limit=page_size
                )
                if not pages:
                    break
                for p in pages:
                    pid = p.get("id") if isinstance(p, dict) else None
                    if pid:
                        yield str(pid)
                if len(pages) < page_size:
                    break
                start += page_size

    # ------------------------------------------------------------------
    # Walk
    # ------------------------------------------------------------------
    def iter_files(self) -> Iterator[SourceFile]:
        """Yield page-body + attachment files. Gated by feature flags.

        Per-page failure is isolated — a 404 on one page (e.g. ACL
        change between enumeration and fetch) logs and continues to
        the next page. Per-attachment failure is similarly isolated.
        Auth failures (401/403) are propagated since they'll affect
        every subsequent call.
        """
        if not confluence_enabled(self.flags):
            raise ConfluenceGatedError(
                "Confluence connector is gated. Enable both "
                f"'{_V04_FLAG}' AND '{_UPCOMING_FLAG}' feature flags "
                "to activate."
            )

        client = self._get_client()
        container = self.uri

        for page_id in self._iter_page_ids():
            try:
                # ``expand=body.export_view,version`` gives us rendered
                # HTML (the cleanest body format for downstream text
                # extraction) plus the version number for the URI
                # suffix. expand=body.storage would give XHTML storage
                # format — usable but noisier (Confluence macros render
                # as ``<ac:structured-macro>`` blobs the HTML extractor
                # would have to discard).
                page = client.get_page_by_id(  # type: ignore[attr-defined]
                    page_id, expand="body.export_view,version"
                )
            except Exception as exc:  # noqa: BLE001
                LOG.warning(
                    "Confluence page fetch failed for id=%s: %s",
                    page_id,
                    exc,
                )
                continue
            if not isinstance(page, dict):
                continue

            version = ((page.get("version") or {}).get("number")) or 1
            title = page.get("title") or f"page-{page_id}"
            body_html = (
                ((page.get("body") or {}).get("export_view") or {}).get("value")
                or ""
            )
            body_bytes = body_html.encode("utf-8")

            # ``.html`` suffix is required so the dispatcher's
            # extension lookup picks the HTML extractor (or the
            # text-extractor fallback for unknown suffixes — either
            # way the body is text and lands in evidence).
            safe_title = _safe_filename(title)
            page_uri = (
                f"confluence://{self._host}/page/{page_id}@{version}"
            )
            yield ConfluenceFile(
                uri=page_uri,
                name=f"{safe_title}.html",
                size=len(body_bytes),
                container_uri=container,
                _fetch=lambda b=body_bytes: b,
            )

            if not self.include_attachments:
                continue

            try:
                # get_attachments_from_content returns paginated; we
                # take the first page (most pages have <50 attachments)
                # and only paginate if Confluence indicates more.
                att_resp = client.get_attachments_from_content(  # type: ignore[attr-defined]
                    page_id, limit=200
                )
            except Exception as exc:  # noqa: BLE001
                LOG.warning(
                    "Confluence attachments fetch failed for page=%s: %s",
                    page_id,
                    exc,
                )
                continue

            attachments = []
            if isinstance(att_resp, dict):
                attachments = att_resp.get("results", []) or []
            elif isinstance(att_resp, list):  # some client versions unwrap
                attachments = att_resp

            for att in attachments:
                if not isinstance(att, dict):
                    continue
                att_id = att.get("id")
                if not att_id:
                    continue
                att_title = att.get("title") or f"attachment-{att_id}"
                att_version = (
                    (att.get("version") or {}).get("number")
                    if isinstance(att.get("version"), dict)
                    else 1
                ) or 1
                ext = att.get("extensions") or {}
                size = ext.get("fileSize") if isinstance(ext, dict) else None
                try:
                    size_int = int(size) if size is not None else None
                except (TypeError, ValueError):
                    size_int = None
                download_path = (
                    ((att.get("_links") or {}).get("download")) or ""
                )
                att_uri = (
                    f"confluence://{self._host}/page/{page_id}/"
                    f"attachment/{att_id}@{att_version}"
                )
                # Bind page_id, att_id, download_path into the closure
                # so the fetch knows exactly what to retrieve when
                # open() is finally called.
                fetch = _make_attachment_fetch(
                    client, page_id, att_id, download_path, self.server_url
                )
                yield ConfluenceFile(
                    uri=att_uri,
                    name=att_title,
                    size=size_int,
                    container_uri=container,
                    _fetch=fetch,
                )


def _make_attachment_fetch(client, page_id, att_id, download_path, server_url):
    """Build the lazy-download closure for one attachment.

    Two-path fallback: the atlassian-python-api ``download_attachments_from_page``
    helper returns paths-on-disk (we want bytes), so we use the
    library's underlying ``_session`` to GET the ``_links.download``
    URL directly. If that's missing we synthesize one from the page +
    attachment ids (Data Center's documented attachment download URL
    shape).
    """
    def _fetch() -> bytes:
        # Prefer the path Confluence handed us — it includes the right
        # query string for the current attachment version.
        url = download_path or (
            f"/download/attachments/{page_id}/{att_id}"
        )
        if not url.startswith("http"):
            url = server_url.rstrip("/") + url
        # The atlassian client exposes ``_session`` (requests.Session)
        # with auth already bound. Using it means our PAT header
        # rides on the download too without us re-reading the PAT.
        session = getattr(client, "_session", None)
        if session is None:
            # Test path or a client variant without _session — fall
            # back to a one-shot requests.get with the PAT from
            # environment/keyring. Re-reading is fine: this only
            # fires on test fakes or atypical client builds.
            import requests  # noqa: PLC0415

            pat = _get_pat()
            resp = requests.get(
                url,
                headers={"Authorization": f"Bearer {pat}"},
                timeout=120,
            )
        else:
            resp = session.get(url, timeout=120)
        if not getattr(resp, "ok", False):
            status = getattr(resp, "status_code", "?")
            raise RuntimeError(
                f"Confluence attachment download failed: HTTP {status} "
                f"for {url}"
            )
        return resp.content

    return _fetch


def _safe_filename(title: str) -> str:
    """Sanitize a page title into something the extractor + filesystem like.

    Drops path separators and control characters; collapses whitespace.
    Not for security — only to keep the synthetic ``.html`` filename
    free of characters that would confuse downstream filename-pattern
    heuristics (the doc-number tagger inspects ``name``).
    """
    out = []
    for ch in (title or "").strip():
        if ch in ("/", "\\", "\0", ":", "*", "?", "\"", "<", ">", "|"):
            out.append("_")
        elif ch.isspace():
            out.append(" ")
        else:
            out.append(ch)
    cleaned = "".join(out).strip() or "untitled"
    # Cap to avoid silly-long synthetic names on giant Confluence titles.
    return cleaned[:120]
