"""RSA Archer GRC connector — v0.4 evidence source.

Pulls records from an Archer instance via its **modern REST API** (the
``/api/core/...`` surface — NOT the legacy SOAP ``/ws/`` endpoints). Each
record in a configured application is emitted as one :class:`SourceFile`
whose payload is the record's field map serialised to JSON. The ingest
pipeline treats it like any other ``.json`` artifact.

Why a connector, not a one-off importer
---------------------------------------
Programs whose compliance system of record is Archer (some DoD/IC ecosystems
still standardise on it for control inventories, POAMs, and vendor
attestations) need their assessor to pull facts straight from Archer rather
than ask the user to export-and-re-upload. Modelling Archer records as
``SourceFile`` payloads lets every existing downstream stage — JSON
extractor, tagger, sweep scorer — work without any Archer-specific code
path. Boundary: this connector reads only. POAM round-trips into Archer
stay deferred to a later milestone.

Auth model
----------
Archer rarely ships first-class API tokens — the documented public API is
**session-token-from-login**:

  ``POST /api/core/security/login`` with ``{InstanceName, Username,
  Password, UserDomain}`` returns ``{RequestedObject: {SessionToken: ...}}``.
  All subsequent calls use ``Authorization: Archer session-id="<token>"``.

Sessions expire (configurable per instance — commonly 20 min idle). We
treat any **401** mid-walk as "token died, log in again, retry once"; a
second 401 propagates. The password is read from the keyring under a
per-instance key — **never persisted to disk**, never returned in
``test_connection`` payloads, never logged.

Feature flag
------------
Gated behind ``ARCHER_CONNECTOR_ENABLED=1`` (env var, off by default).
Until v0.4 ships and the Settings UI grows an Archer card, the connector
exists purely so the abstraction lines up — calling ``iter_files`` while
the flag is unset raises ``RuntimeError`` with a clear "set the env var"
message. Same shape the eMASS stub uses for "not configured" so the UI
behaviour stays uniform.

URI scheme
----------
``archer://<instance-name>/<application-id>/<content-id>`` — instance-name
(not host) because two different Archer hosts can serve the same
``InstanceName`` (load balancer, dev/prod separation) and the InstanceName
is what users actually identify records by in the Archer UI.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any, BinaryIO, Iterator
from urllib.parse import quote, urlparse

from .base import SourceFile

LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Feature flag
# ---------------------------------------------------------------------------

# Off by default. The Settings UI will flip this on once the Archer card
# lands in v0.4. Kept as an env var (not a config-row) so dev workstations
# can opt in without touching the user's persistent config.toml — same
# pattern as SWEEP_USE_SEARCH in sharepoint.py.
_FEATURE_FLAG_ENV = "ARCHER_CONNECTOR_ENABLED"


def feature_enabled() -> bool:
    """True when the Archer connector is allowed to make network calls.

    Centralised so tests can monkeypatch ``os.environ`` and exercise both
    branches without duplicating the env-var name. Settings UI will read
    this through a small ``/api/archer/status`` route in v0.4 wiring.
    """
    return os.environ.get(_FEATURE_FLAG_ENV) == "1"


class ArcherFeatureDisabled(RuntimeError):
    """Raised when iter_files / login is called with the flag off.

    Distinct type so callers (and tests) can differentiate "Archer is
    deliberately disabled in this build" from a transport/auth failure
    that should bubble up as a generic ``RuntimeError``.
    """


# ---------------------------------------------------------------------------
# Keyring
# ---------------------------------------------------------------------------

# Keyring slot family for Archer instance passwords. One slot per
# (service, username@instance) tuple so a workstation that talks to dev +
# prod Archer doesn't clobber one password storing the other. Reads return
# None when the slot is empty — caller falls back to ARCHER_PASSWORD env
# (dev convenience) and ultimately raises if both miss.
_KEYRING_SERVICE = "cybersecurity-assessor.archer"


def _keyring_key(instance_name: str, username: str) -> str:
    """Render the keyring slot identifier for a (instance, user) pair.

    Lowercased so case drift in the instance name (Archer is
    case-insensitive on lookup) doesn't strand a previously-stored
    password.
    """
    return f"{username.lower()}@{instance_name.lower()}"


def _read_password(instance_name: str, username: str) -> str | None:
    """Look up an Archer password from the OS keyring, then the env fallback.

    Never persists. Returns ``None`` if neither source has it; the caller
    raises so the user gets a clear "store the password first" message
    instead of a misleading 401 from Archer.
    """
    try:
        import keyring  # noqa: PLC0415
    except ImportError:
        keyring = None  # type: ignore[assignment]

    if keyring is not None:
        try:
            stored = keyring.get_password(
                _KEYRING_SERVICE, _keyring_key(instance_name, username)
            )
        except Exception as exc:  # noqa: BLE001 — corrupt store shouldn't crash
            LOG.warning("Archer keyring read failed: %s", exc)
            stored = None
        if stored:
            return stored

    # Dev fallback so the test fixture and a local "I just want to poke
    # the API" run don't require Credential Manager setup. Documented in
    # the connector README so it doesn't become a surprise auth surface.
    env_pw = os.environ.get("ARCHER_PASSWORD")
    if env_pw:
        return env_pw
    return None


def store_password(instance_name: str, username: str, password: str) -> None:
    """Write an Archer password to the keyring.

    Surfaced as a module-level helper so the Settings route can call it
    without instantiating an ``ArcherSource``. Never echoes the value
    back, never writes to log lines.
    """
    try:
        import keyring  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "keyring is not installed — install the 'sources' extras"
        ) from exc
    keyring.set_password(
        _KEYRING_SERVICE, _keyring_key(instance_name, username), password
    )


def clear_password(instance_name: str, username: str) -> bool:
    """Delete a stored Archer password. Returns True if a slot was removed."""
    try:
        import keyring  # noqa: PLC0415
        import keyring.errors  # noqa: PLC0415
    except ImportError:
        return False
    try:
        keyring.delete_password(
            _KEYRING_SERVICE, _keyring_key(instance_name, username)
        )
        return True
    except Exception:  # noqa: BLE001 — "not found" surfaces as exception on some backends
        return False


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ArcherApplicationQuery:
    """One (application_id, content_search_filter) tuple to pull.

    ``application_id`` is Archer's numeric module id (e.g. 75 for the stock
    "Policies" application — varies per tenant). ``content_search_filter``
    is the optional XML/JSON search filter posted alongside
    ``/api/core/content/contentsearch``; pass ``None`` to walk every record
    in the application.

    Frozen so it can live in a tuple on :class:`ArcherSource` without
    risk of an upstream caller mutating it mid-walk.
    """

    application_id: int
    content_search_filter: str | None = None


@dataclass(frozen=True)
class ArcherConfig:
    """Connection config for an Archer instance.

    Password is intentionally **not** stored here — it's resolved on
    demand from the keyring/env via :func:`_read_password`. Keeping it
    off the dataclass means an accidental ``repr(config)`` (logs, error
    messages, test failures) can't leak it.
    """

    instance_url: str  # e.g. https://archer.example.com
    instance_name: str  # Archer's logical instance name (often != hostname)
    username: str
    queries: tuple[ArcherApplicationQuery, ...]
    verify_tls: bool = True  # Override only for on-prem self-signed (rare; logged loud).
    page_size: int = 100  # Records per /contentsearch page.
    request_timeout: float = 60.0


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------


class ArcherAuthError(RuntimeError):
    """Archer rejected our session token (401) or login (failed credentials)."""


class ArcherClient:
    """Thin httpx wrapper that owns one session-token's lifecycle.

    Login on first use, refresh once on a 401, propagate on a second.
    Thread-safe around token rotation so concurrent ``iter_files`` calls
    on the same client don't double-log-in. Construction is cheap — no
    network calls until the first request.
    """

    def __init__(self, config: ArcherConfig) -> None:
        self.config = config
        self._token: str | None = None
        self._token_lock = threading.Lock()
        # httpx client built lazily so we don't even import the dep
        # at module import time (keeps cold-start cheap).
        self._client: Any | None = None
        if not config.verify_tls:
            # Loud warning — disabling TLS verification on a connector
            # that ships passwords over the wire is a foot-gun. We allow
            # it (some on-prem Archer installs use self-signed certs and
            # the user's IT department won't fix it) but make sure the
            # decision lands in the log so security reviewers can find it.
            LOG.warning(
                "Archer client constructed with verify_tls=False — "
                "MITM risk; only use on trusted networks (instance=%s).",
                config.instance_name,
            )

    # ------------------------------------------------------------------
    # Lazy client construction
    # ------------------------------------------------------------------
    def _httpx(self):
        if self._client is None:
            try:
                import httpx  # noqa: PLC0415
            except ImportError as exc:
                raise ImportError(
                    "httpx is not installed — required by the Archer connector."
                ) from exc
            self._client = httpx.Client(
                base_url=self.config.instance_url.rstrip("/"),
                timeout=self.config.request_timeout,
                verify=self.config.verify_tls,
                headers={"Accept": "application/json"},
            )
        return self._client

    def close(self) -> None:
        """Close the underlying httpx client. Idempotent."""
        if self._client is not None:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001
                pass
            self._client = None

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------
    def _login(self) -> str:
        """Acquire a session token from Archer.

        Mints a token via ``POST /api/core/security/login``. Raises
        :class:`ArcherAuthError` on bad creds. The password is read from
        the keyring on every login so a Settings-page password change is
        picked up without restarting the sidecar.
        """
        if not feature_enabled():
            raise ArcherFeatureDisabled(
                f"Archer connector is gated behind {_FEATURE_FLAG_ENV}=1 — "
                "set the env var to enable (v0.4 feature)."
            )
        password = _read_password(
            self.config.instance_name, self.config.username
        )
        if not password:
            raise ArcherAuthError(
                f"No password stored for {self.config.username}@"
                f"{self.config.instance_name}. Use the Settings card or "
                f"set ARCHER_PASSWORD env var."
            )
        body = {
            "InstanceName": self.config.instance_name,
            "Username": self.config.username,
            "Password": password,
            # Archer accepts an empty domain for the default LDAP path.
            "UserDomain": "",
        }
        resp = self._httpx().post(
            "/api/core/security/login",
            json=body,
            # Login itself does not need a bearer header.
            headers={"Content-Type": "application/json"},
        )
        # Wipe the local reference as early as possible — the keyring still
        # has the canonical copy. Defensive against tracebacks landing in
        # logs.
        del password
        del body
        if resp.status_code == 401 or resp.status_code == 403:
            raise ArcherAuthError(
                f"Archer login rejected: HTTP {resp.status_code}"
            )
        if resp.status_code >= 400:
            raise RuntimeError(
                f"Archer login failed: HTTP {resp.status_code} — "
                f"{(resp.text or '')[:200]}"
            )
        try:
            payload = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(
                f"Archer login returned non-JSON body: {exc}"
            ) from exc
        # Archer wraps successful payloads in {IsSuccessful, RequestedObject}.
        if not payload.get("IsSuccessful", False):
            raise ArcherAuthError(
                f"Archer login failed: {payload.get('ValidationMessages') or payload}"
            )
        token = (payload.get("RequestedObject") or {}).get("SessionToken")
        if not token:
            raise ArcherAuthError("Archer login response had no SessionToken")
        return token

    def _ensure_token(self, *, force_refresh: bool = False) -> str:
        with self._token_lock:
            if self._token is None or force_refresh:
                self._token = self._login()
            return self._token

    # ------------------------------------------------------------------
    # Authed request
    # ------------------------------------------------------------------
    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any | None = None,
        params: dict | None = None,
    ):
        """One authed request with single-shot 401 → re-login → retry.

        The retry is bounded to one attempt: a second 401 after a fresh
        login means the credentials themselves are bad (or the account
        is locked), and silently looping would mask the real failure.
        """
        token = self._ensure_token()
        headers = {
            "Authorization": f'Archer session-id="{token}"',
            "Content-Type": "application/json",
        }
        client = self._httpx()
        resp = client.request(
            method, path, headers=headers, json=json_body, params=params
        )
        if resp.status_code == 401:
            # Stale token — try one re-login. A second 401 propagates.
            LOG.info(
                "Archer 401 on %s %s — refreshing session token", method, path
            )
            token = self._ensure_token(force_refresh=True)
            headers["Authorization"] = f'Archer session-id="{token}"'
            resp = client.request(
                method, path, headers=headers, json=json_body, params=params
            )
            if resp.status_code == 401:
                raise ArcherAuthError(
                    f"Archer {method} {path} still 401 after re-login — "
                    "credentials may have been revoked."
                )
        return resp

    # ------------------------------------------------------------------
    # Probe
    # ------------------------------------------------------------------
    def test_connection(self) -> dict:
        """Authenticate and return a small probe payload.

        Used by the Settings card to render a green/red badge. Never
        echoes the password or the session token. Returns ``ok=False``
        plus a short hint when login fails so the UI can surface it
        without parsing exception text.
        """
        try:
            self._ensure_token(force_refresh=True)
        except ArcherFeatureDisabled as exc:
            return {"ok": False, "hint": str(exc), "disabled": True}
        except ArcherAuthError as exc:
            return {"ok": False, "hint": str(exc)}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "hint": f"Transport error: {exc}"}
        return {
            "ok": True,
            "instance_url": self.config.instance_url,
            "instance_name": self.config.instance_name,
            "username": self.config.username,
        }

    # ------------------------------------------------------------------
    # Content search — pages through records for one application
    # ------------------------------------------------------------------
    def iter_application_records(
        self, query: ArcherApplicationQuery
    ) -> Iterator[dict]:
        """Yield raw record dicts from one application, paginated.

        Archer's ``/api/core/content/contentsearch`` accepts a JSON body
        with ``ModuleId`` + a per-tenant search filter. The response
        carries records under ``RequestedObject.Records``. Pagination is
        page-number based (``PageNumber`` + ``PageSize`` in the request
        body); we walk until the server returns an empty page or a
        clearly-terminal total. This is the modern documented surface;
        the legacy ``/api/contentapi/...`` URL is OData-shaped and not
        used here.
        """
        page = 1
        empty_page_streak = 0
        while True:
            body: dict[str, Any] = {
                "ModuleId": query.application_id,
                "PageNumber": page,
                "PageSize": self.config.page_size,
            }
            if query.content_search_filter:
                # Archer's filter is opaque to us — pass through verbatim
                # so program teams can craft tenant-specific XML/JSON
                # filters in Settings without us having to model the
                # full filter grammar.
                body["Filter"] = query.content_search_filter

            resp = self._request(
                "POST", "/api/core/content/contentsearch", json_body=body
            )
            if resp.status_code >= 400:
                raise RuntimeError(
                    f"Archer contentsearch failed on application "
                    f"{query.application_id} page {page}: "
                    f"HTTP {resp.status_code} — {(resp.text or '')[:200]}"
                )
            payload = resp.json()
            if not payload.get("IsSuccessful", True):
                # Some Archer builds return 200 with IsSuccessful=False on a
                # bad filter. Surface as a hard error so the user sees their
                # filter is rejected — silently looping would mask it.
                raise RuntimeError(
                    f"Archer contentsearch returned IsSuccessful=False on "
                    f"application {query.application_id}: "
                    f"{payload.get('ValidationMessages')}"
                )
            requested = payload.get("RequestedObject") or {}
            records = requested.get("Records") or []
            total = requested.get("TotalCount")
            if not records:
                # If the server tells us the total is zero (or we've walked
                # to it), bail immediately — no need to probe again. Without
                # a TotalCount, require two empty pages in a row before
                # giving up so a transient empty page mid-walk on a tenant
                # with a rebuilding search index doesn't truncate the walk.
                if isinstance(total, int):
                    return
                empty_page_streak += 1
                if empty_page_streak >= 2:
                    return
                page += 1
                continue
            empty_page_streak = 0
            for rec in records:
                yield rec
            # If the server told us the total and we've passed it, stop.
            if isinstance(total, int) and page * self.config.page_size >= total:
                return
            page += 1


# ---------------------------------------------------------------------------
# SourceFile + Source
# ---------------------------------------------------------------------------


def _archer_uri(instance_name: str, application_id: int, content_id: Any) -> str:
    """Render the canonical archer:// URI for one record."""
    cid = str(content_id) if content_id is not None else "unknown"
    return (
        f"archer://{quote(instance_name, safe='')}/"
        f"{application_id}/{quote(cid, safe='')}"
    )


@dataclass
class ArcherRecordFile:
    """One Archer record materialised as a JSON-payload SourceFile.

    The bytes are computed eagerly at construction time — Archer records
    are small (kilobytes, not megabytes) and the contentsearch response
    already has the full field map, so re-fetching per ``open()`` would
    waste round-trips. The cached payload also means ``open()`` is
    side-effect-free, which the ingest orchestrator relies on for its
    hash-then-extract two-pass.
    """

    uri: str
    name: str
    size: int | None
    container_uri: str | None
    _payload: bytes = field(repr=False)

    def open(self) -> BinaryIO:
        return BytesIO(self._payload)


def _extract_content_id(record: dict) -> Any:
    """Find the per-record id Archer uses for /content/{id} lookups.

    Different Archer schemas surface it under different keys; we try the
    documented field first and fall back to common aliases. None → caller
    synthesises an "unknown" placeholder so the walk doesn't crash on a
    malformed record.
    """
    for key in ("Id", "ContentId", "ContentID", "id"):
        val = record.get(key)
        if val is not None:
            return val
    return None


class ArcherSource:
    """Walk one or more Archer applications, yielding records as SourceFiles.

    One :class:`ArcherSource` corresponds to one Archer instance + a list
    of applications to pull from. ``iter_files`` runs the queries in
    order; each emitted ``SourceFile`` has its application_id encoded in
    the URI so downstream provenance can group / filter by application.

    The connector does **not** download field-level attachments at this
    milestone — the JSON record payload is enough for the JSON extractor
    + tagger to find control IDs, doc-numbers, and program tokens. File
    attachments inside Archer records become a follow-up if we see
    program teams asking for them.
    """

    # Network round-trip per record is small but adds up — same per-file
    # commit cadence as SharePoint so the evidence list updates live in
    # the UI instead of jumping in big batches.
    commit_batch_size: int = 1

    def __init__(self, config: ArcherConfig) -> None:
        self.config = config
        # Top-level URI used as the IngestSummary root — instance-scoped,
        # not per-application, so a multi-application sweep shows up as
        # one "ingested from Archer:<instance>" group in the UI.
        host = urlparse(config.instance_url).netloc or config.instance_url
        self.uri = f"archer://{config.instance_name}/?host={quote(host, safe='')}"
        self._client = ArcherClient(config)

    # Defensive: callers occasionally drop references mid-walk on errors;
    # the GC eventually closes the underlying httpx client but tests run
    # in tight loops and the orphaned sockets show up as ResourceWarnings.
    def __del__(self):  # pragma: no cover - GC timing
        try:
            self._client.close()
        except Exception:  # noqa: BLE001
            pass

    def test_connection(self) -> dict:
        """Pass-through to the client probe. Same shape as eMASS stub."""
        return self._client.test_connection()

    def iter_files(self) -> Iterator[SourceFile]:
        """Yield one :class:`ArcherRecordFile` per record across all queries."""
        if not feature_enabled():
            raise ArcherFeatureDisabled(
                f"Archer connector is gated behind {_FEATURE_FLAG_ENV}=1 — "
                "set the env var to enable (v0.4 feature)."
            )
        for query in self.config.queries:
            yield from self._iter_application(query)

    def _iter_application(
        self, query: ArcherApplicationQuery
    ) -> Iterator[SourceFile]:
        instance = self.config.instance_name
        container_uri = (
            f"archer://{quote(instance, safe='')}/{query.application_id}/"
        )
        for record in self._client.iter_application_records(query):
            content_id = _extract_content_id(record)
            uri = _archer_uri(instance, query.application_id, content_id)
            # Serialise the record verbatim so the downstream JSON
            # extractor sees the same field shape an analyst would see
            # in the Archer UI. ``ensure_ascii=False`` so unicode
            # characters in titles/descriptions survive intact; ``indent=2``
            # makes the extractor's text dump readable for the tagger.
            payload = json.dumps(record, ensure_ascii=False, indent=2).encode(
                "utf-8"
            )
            # Filename is synthesised — Archer records don't have one.
            # Embed the content id so the evidence-list "filename" column
            # still shows something distinctive per row.
            name = f"archer_app{query.application_id}_record{content_id or 'unknown'}.json"
            yield ArcherRecordFile(
                uri=uri,
                name=name,
                size=len(payload),
                container_uri=container_uri,
                _payload=payload,
            )
