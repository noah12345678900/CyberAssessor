"""eMASS REST evidence connector — v0.4+, gated.

DOUBLE-GATED. Two flags must BOTH be True for this source to load:

  1. ``connectors.v04`` (``AppConfig.connectors_v04_enabled``) — the
     version cohort gate for the v0.4 connector wave.
  2. ``connectors.emass_upcoming_gated`` (``AppConfig.emass_upcoming_gated_enabled``)
     — the per-connector authorization gate. eMASS API access requires a
     DISA-distributed mTLS client cert AND an explicit system_id allow-list
     entry; we cannot assume any user-installed build is authorized to even
     touch the endpoint. Stays default-off forever.

What this connector reads (THIS slice, read-only):

  * CCIS export — per-control compliance status as eMASS sees it. Used by
    the v0.4 cross-source reconciliation pass to flag drift between the
    local assessor's verdicts and the system of record.
  * POAM list — open POAM rows, milestone status, scheduled completion
    dates. Drives the "POAMs eMASS has but the local generator did not
    propose" gap pane.
  * Package status — top-level system metadata (name, system_id, RMF
    step, ATO date). Cheap auth probe; what ``test_connection()`` calls.

What this connector does NOT do in v0.4:

  * Push POAMs (RMF_POAM xlsx-based export remains the supported path —
    see ``poam/exporter.py`` + ``reference_emass_poam_template.md``).
  * Modify CCI statuses in eMASS.
  * Upload artifacts.

A future "Export POAM to eMASS" slice will graft a write path onto this
module; the read-only invariant in v0.4 is enforced by
``_assert_read_only_endpoint()`` which refuses any non-GET method at the
HTTP layer. See the TODO at the bottom of this file for the write-slice
contract.

URI scheme
----------

::

    emass://system/<system_id>/<artifact>/<rev>

Where ``<artifact>`` is one of:
  * ``ccis``        — CCIS-shaped per-control export (one file)
  * ``poams``       — POAM list (one file per fetch)
  * ``package``     — system header / package status (one file)

``<rev>`` is the eMASS-reported revision token (e.g. timestamp or row
hash). Including it in the URI means re-fetching the same artifact after
eMASS-side edits produces a distinct ``Evidence.path`` row — so the
provenance trail shows "we ingested eMASS POAM list at rev X on date Y"
without overwriting the prior snapshot.

mTLS credential handling
------------------------

Both ``cert_path`` and ``key_path`` are **paths only**. The connector
never reads the bytes into Python memory:

  * ``requests`` accepts the tuple ``(cert_path, key_path)`` and streams
    the file contents straight to OpenSSL via libssl's ``SSL_CTX``.
  * We do not log either path's contents.
  * We do not pass either path into the URI or into the SourceFile's
    public attributes.
  * The Settings UI shows only the path string (with a "redact in logs"
    helper); the file itself lives on disk under the user's chosen
    location.

This is deliberate. If the cert/key bytes ever land in a Python ``bytes``
object they can show up in tracebacks, in pickled fixtures, or in test
logs uploaded to a shared CI artifact bucket. Path-only handling means
the worst-case leak is the path string — and that's already non-secret
config the user pastes into the Settings card.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any, BinaryIO, Iterator
from urllib.parse import quote

from .base import SourceFile

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Gate enforcement
# ---------------------------------------------------------------------------


class EmassConnectorGatedError(RuntimeError):
    """Raised when something tries to instantiate the eMASS source while
    one or both feature flags are off.

    Distinct exception type so the routes layer can render a precise
    "your build does not have the v0.4 connector wave enabled" / "the
    eMASS upcoming-gated flag is off" message instead of a generic 500.
    """


def _assert_double_gate(
    *,
    connectors_v04_enabled: bool,
    emass_upcoming_gated_enabled: bool,
) -> None:
    """Refuse to construct the source unless BOTH flags are True.

    Called from ``EmassSource.__init__``. Raising in the constructor (not
    in ``iter_files``) means a misconfigured user can't even hold an
    instance — every code path that would touch eMASS dies at the point
    of construction, before any cert or system_id is read.
    """
    if not connectors_v04_enabled:
        raise EmassConnectorGatedError(
            "eMASS connector requires the 'connectors.v04' feature flag. "
            "This build is on the pre-v0.4 connector wave; eMASS is not "
            "available."
        )
    if not emass_upcoming_gated_enabled:
        raise EmassConnectorGatedError(
            "eMASS connector requires the 'connectors.emass_upcoming_gated' "
            "flag to be explicitly enabled in config.toml. API access "
            "requires DISA authorization (mTLS client cert + system_id "
            "allow-list entry); flip the flag only after your ISSM has "
            "confirmed authorization."
        )


# Allowed HTTP methods in v0.4. POAM push / artifact upload are NOT in
# this set on purpose; the future write slice will add them behind a
# third flag, not by relaxing this set.
_ALLOWED_METHODS: frozenset[str] = frozenset({"GET"})


def _assert_read_only_method(method: str) -> None:
    """Refuse any non-GET HTTP method.

    Read-only enforcement at the transport layer. Even if a caller passes
    an attacker-controlled method string (or a future write slice lands
    behind a flag we haven't gated yet), this raises before the request
    is sent.
    """
    if method.upper() not in _ALLOWED_METHODS:
        raise EmassConnectorGatedError(
            f"eMASS connector is read-only in v0.4; HTTP {method!r} is not "
            "permitted. Write-path (POAM push / artifact upload) is a future "
            "slice — see TODO at the bottom of evidence/sources/emass.py."
        )


# ---------------------------------------------------------------------------
# URI helper
# ---------------------------------------------------------------------------


def emass_uri(system_id: str, artifact: str, rev: str) -> str:
    """Canonical ``emass://system/<id>/<artifact>/<rev>`` URI.

    ``system_id`` and ``rev`` are quoted because eMASS package GUIDs
    historically include ``-`` (fine) but rev tokens can be ISO timestamps
    with ``:`` (not URL-safe). ``artifact`` is from a fixed enum so it
    doesn't need quoting; passing an unexpected value still produces a
    valid URI but ingest won't know what to do with it.

    Inputs are coerced to ``str`` before quoting so a numeric ``system_id``
    (eMASS returns these as ints in some response shapes) doesn't crash
    ``quote()`` with a ``TypeError``. The URI scheme is text-only.
    """
    return (
        f"emass://system/{quote(str(system_id), safe='')}"
        f"/{artifact}/{quote(str(rev), safe='')}"
    )


# ---------------------------------------------------------------------------
# SourceFile
# ---------------------------------------------------------------------------


@dataclass
class EmassFile:
    """One addressable artifact pulled from the eMASS REST API.

    Bytes are captured at construction time (the API hands us JSON, not a
    streamable blob), so ``open()`` just wraps the cached buffer. We don't
    expose ``cert_path`` / ``key_path`` on the dataclass — they live only
    on the parent ``EmassSource`` and never reach the SourceFile's public
    surface. That keeps the "path only, never bytes" rule intact even if
    someone serializes the SourceFile dict for debugging.

    ``_payload`` is excluded from the auto-generated ``__repr__`` because
    a SourceFile holding a multi-megabyte POAM blob would otherwise dump
    the entire artifact into a stack trace if it shows up in a logged
    exception. ``dataclasses.asdict()`` still walks it (that's how the
    stdlib defines the recursion), but ``repr()`` — the form that ends
    up in tracebacks, logger calls, and pytest assertion diffs — stays
    small. Callers that want the bytes call ``open()``.
    """

    uri: str
    name: str
    size: int | None
    container_uri: str | None
    _payload: bytes = field(repr=False)

    def open(self) -> BinaryIO:
        return BytesIO(self._payload)


# ---------------------------------------------------------------------------
# Source
# ---------------------------------------------------------------------------


class EmassSource:
    """Read-only eMASS REST source.

    Constructor enforces the double-flag gate. Path-only credential
    handling (the cert/key files are passed to ``requests`` as paths;
    bytes never enter the process). HTTP layer enforces GET-only.

    Args:
        base_url: eMASS REST root (e.g.
            ``https://emass.disa.mil/api``). Trailing slash stripped.
        system_id: Per-package GUID. Scopes every read.
        cert_path: Path to the client cert (.pem). Never read into memory
            by this module — handed straight to ``requests``.
        key_path: Path to the cert's private key (.pem). Same treatment.
            ``None`` when the cert is a single .pfx bundle that includes
            the key (v0.4 deferred: bundle support requires pyOpenSSL or
            a temporary file dance; the .pem + .key pair is the common
            DISA-issued shape and what we support today).
        api_key: Optional ``api-key`` header value. Most eMASS REST
            endpoints require mTLS AND an api-key header issued by the
            DISA enclave admin. Omit (``None``) only against test
            instances that disable header-auth. Stored on the instance
            (the value itself is not a long-lived secret like the cert
            key; it's a tenant-scoped token), but never logged.
        connectors_v04_enabled: Version cohort gate.
        emass_upcoming_gated_enabled: Per-connector authorization gate.
        verify: TLS server-cert verification toggle. Default True; set
            False ONLY for a local development emulator. Passed straight
            to ``requests``.
        connect_timeout_seconds: TCP-connect timeout. Default 5s — a
            firewall blackhole should fail fast, not eat the full read
            budget. eMASS frontend usually responds in < 1s.
        read_timeout_seconds: Per-request read timeout. eMASS endpoints
            have been observed to take 30+s on big POAM lists, so we
            default to 90.
    """

    # Per-source commit batch. Three reads per fetch (ccis / poams / package);
    # batching doesn't move the needle here — match SharePointSource's
    # per-file commit so the UI refreshes promptly.
    commit_batch_size: int = 1

    def __init__(
        self,
        *,
        base_url: str,
        system_id: str,
        cert_path: str,
        key_path: str | None,
        connectors_v04_enabled: bool,
        emass_upcoming_gated_enabled: bool,
        api_key: str | None = None,
        verify: bool = True,
        connect_timeout_seconds: float = 5.0,
        read_timeout_seconds: float = 90.0,
    ) -> None:
        _assert_double_gate(
            connectors_v04_enabled=connectors_v04_enabled,
            emass_upcoming_gated_enabled=emass_upcoming_gated_enabled,
        )
        if not base_url:
            raise ValueError("eMASS base_url is required")
        if not system_id:
            raise ValueError("eMASS system_id is required")
        if not cert_path:
            raise ValueError("eMASS cert_path is required")

        self.base_url = base_url.rstrip("/")
        self.system_id = system_id
        # Stored as plain strings — paths only. The cert/key bytes are
        # never read by this module; ``requests`` opens them lazily and
        # streams to OpenSSL.
        self._cert_path = cert_path
        self._key_path = key_path
        self._api_key = api_key
        self._verify = verify
        # ``requests`` accepts either a single float (applied to BOTH
        # connect and read) or a (connect, read) tuple. We use the tuple
        # so a TCP blackhole fails after ``connect_timeout`` instead of
        # the much-longer read budget. Reviewer-emass HIGH finding.
        self._timeout: tuple[float, float] = (
            connect_timeout_seconds,
            read_timeout_seconds,
        )
        self.uri = f"emass://system/{quote(str(system_id), safe='')}"

    # ------------------------------------------------------------------
    # Cert tuple — kept tiny so it's obvious where path-only handling lives
    # ------------------------------------------------------------------
    @property
    def _cert_for_requests(self) -> str | tuple[str, str]:
        """Cert argument shape ``requests`` expects.

        Single string when cert+key share a file (.pfx-style, deferred to
        a future slice); 2-tuple when they're separate .pem files (the
        common DISA shape, what we ship today). Either way, both elements
        are PATHS, not bytes.
        """
        if self._key_path:
            return (self._cert_path, self._key_path)
        return self._cert_path

    # ------------------------------------------------------------------
    # HTTP — thin wrapper that enforces GET-only and mTLS
    # ------------------------------------------------------------------
    def _request(self, method: str, path: str) -> Any:
        """Perform an authenticated REST call. GET only in v0.4.

        Returns the decoded JSON body. Raises ``RuntimeError`` on non-2xx
        with the truncated response body so callers can surface a useful
        error to the UI without leaking the entire response (which on
        eMASS can include the requested system's full POAM list).
        """
        _assert_read_only_method(method)
        try:
            import requests  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "requests is not installed. Install the 'sources' extras: "
                "`pip install -e .[sources]` from backend/."
            ) from exc

        url = f"{self.base_url}/{path.lstrip('/')}"
        headers: dict[str, str] = {"Accept": "application/json"}
        if self._api_key:
            # eMASS REST also requires an ``api-key`` header alongside the
            # mTLS client cert. Only sent when configured so dev/emulator
            # endpoints without header-auth still work.
            headers["api-key"] = self._api_key
        resp = requests.request(
            method.upper(),
            url,
            cert=self._cert_for_requests,
            verify=self._verify,
            timeout=self._timeout,
            headers=headers,
        )
        if not resp.ok:
            # Truncate the body so a multi-megabyte POAM dump doesn't
            # land in a traceback / log line if eMASS returns a partial
            # JSON error envelope.
            body = (resp.text or "")[:500]
            raise RuntimeError(
                f"eMASS {method} {url} returned HTTP {resp.status_code}: {body}"
            )
        return resp.json()

    # ------------------------------------------------------------------
    # Probe — cheap GET against the package endpoint
    # ------------------------------------------------------------------
    def test_connection(self) -> dict[str, Any]:
        """Authenticate, fetch the package header, and return a status dict.

        Same shape contract as the legacy ``EmassClient.test_connection``
        stub so the Settings UI doesn't have to branch on which client
        backed the call. ``ok=True`` plus the system name on success;
        ``ok=False`` plus a redacted error string on failure.
        """
        try:
            payload = self._request("GET", f"systems/{quote(self.system_id, safe='')}")
        except Exception as exc:  # noqa: BLE001 — UI probe; surface message
            return {"ok": False, "hint": f"eMASS probe failed: {exc}"}
        # Best-effort name extraction — eMASS returns ``{name, system_id,
        # rmf_step, ...}`` on the package endpoint. Anything else we just
        # echo back so the user can see what came over the wire.
        name = (
            payload.get("name")
            if isinstance(payload, dict)
            else None
        ) or self.system_id
        return {
            "ok": True,
            "system_id": self.system_id,
            "system_name": name,
            "base_url": self.base_url,
        }

    # ------------------------------------------------------------------
    # Read APIs — used by both iter_files() and the future Settings probe
    # ------------------------------------------------------------------
    def _fetch_ccis_export(self) -> tuple[bytes, str]:
        """Return (json bytes, rev) for the CCIS export.

        ``rev`` is taken from a top-level ``last_modified`` / ``revision``
        field if eMASS supplies one; otherwise we synthesize a hash-based
        rev so re-fetches with no content change collapse to the same URI.
        Caller wraps the bytes in an ``EmassFile``.
        """
        payload = self._request(
            "GET", f"systems/{quote(self.system_id, safe='')}/ccis"
        )
        return self._payload_to_bytes_with_rev(payload, fallback_label="ccis")

    def _fetch_poams(self) -> tuple[bytes, str]:
        """Return (json bytes, rev) for the POAM list."""
        payload = self._request(
            "GET", f"systems/{quote(self.system_id, safe='')}/poams"
        )
        return self._payload_to_bytes_with_rev(payload, fallback_label="poams")

    def _fetch_package(self) -> tuple[bytes, str]:
        """Return (json bytes, rev) for the package header."""
        payload = self._request(
            "GET", f"systems/{quote(self.system_id, safe='')}"
        )
        return self._payload_to_bytes_with_rev(payload, fallback_label="package")

    def _payload_to_bytes_with_rev(
        self, payload: Any, *, fallback_label: str
    ) -> tuple[bytes, str]:
        """Serialize the payload + extract a rev token.

        Rev token preference:
          1. ``payload["last_modified"]`` — eMASS's canonical "this is when
             this view last changed" stamp.
          2. ``payload["revision"]`` — explicit row revision on POAM/CCI
             responses.
          3. A short SHA-256 of the serialized bytes — guaranteed stable
             for a given content snapshot, so unchanged re-fetches keep
             one Evidence row.

        The fallback is deliberately weak (hash, not timestamp) so a
        manually-edited eMASS row whose ``last_modified`` we don't see
        still produces a distinct URI when the bytes differ.
        """
        # Stable JSON for hashing (sort keys) — same payload from two
        # fetches must hash identically or the URI-stability invariant
        # breaks.
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        rev: str | None = None
        if isinstance(payload, dict):
            for key in ("last_modified", "revision", "etag"):
                v = payload.get(key)
                if isinstance(v, str) and v.strip():
                    rev = v.strip()
                    break
        if rev is None:
            rev = f"{fallback_label}-sha256-{hashlib.sha256(blob).hexdigest()[:12]}"
        return blob, rev

    # ------------------------------------------------------------------
    # Walk
    # ------------------------------------------------------------------
    def iter_files(self) -> Iterator[SourceFile]:
        """Yield one EmassFile per artifact (ccis, poams, package).

        Order is fixed (package → ccis → poams) so the ingest pipeline
        sees system metadata before the per-control rows that reference
        it. Failures on one artifact don't abort the walk — the others
        still ingest, and the failed one logs a warning. This matches the
        SharePoint walker's "best-effort per folder" posture; the
        alternative (abort on first failure) made a single transient
        eMASS 503 fail the entire evidence sweep.

        BUT: if EVERY artifact fails we raise the last exception. A silent
        zero-file success on this connector almost always means total auth
        failure (expired cert, revoked api-key, wrong system_id) — surfacing
        that as a pipeline error is more useful than reporting "0 files
        ingested" and letting downstream code interpret it as "eMASS has
        nothing for this system". Reviewer-emass HIGH finding.
        """
        artifacts: list[tuple[str, str, Any]] = [
            ("package", "emass-package.json", self._fetch_package),
            ("ccis", "emass-ccis-export.json", self._fetch_ccis_export),
            ("poams", "emass-poams.json", self._fetch_poams),
        ]
        container_uri = self.uri
        yielded = 0
        last_exc: Exception | None = None
        for artifact, filename, fetcher in artifacts:
            try:
                payload_bytes, rev = fetcher()
            except Exception as exc:  # noqa: BLE001 — keep walking other artifacts
                LOG.warning(
                    "eMASS fetch failed for artifact=%s system=%s: %s",
                    artifact,
                    self.system_id,
                    exc,
                )
                last_exc = exc
                continue
            yielded += 1
            yield EmassFile(
                uri=emass_uri(self.system_id, artifact, rev),
                name=filename,
                size=len(payload_bytes),
                container_uri=container_uri,
                _payload=payload_bytes,
            )
        if yielded == 0 and last_exc is not None:
            raise RuntimeError(
                f"eMASS source produced 0 files for system={self.system_id}; "
                f"all artifact fetches failed. Last error: {last_exc}"
            ) from last_exc


# ---------------------------------------------------------------------------
# FUTURE WRITE SLICE — DO NOT IMPLEMENT IN v0.4
# ---------------------------------------------------------------------------
#
# When the "Export POAM to eMASS" button lands, this module gets a
# companion write-path. Contract sketch so the v0.x reader has the shape
# in front of them when the design call happens:
#
#   1. Third feature flag: ``connectors.emass_write_enabled``. The double
#      gate above stays in place; the write flag is a triple-gate.
#   2. _ALLOWED_METHODS expands to {"GET", "POST", "PUT"} ONLY when the
#      third flag is True. _assert_read_only_method becomes
#      _assert_method_allowed(method, write_enabled).
#   3. POAM push reads from the local generator (poam/generator.py) and
#      shapes rows per the RMF_POAM template contract documented in
#      ``reference_emass_poam_template.md``. The xlsx-based export path
#      (poam/exporter.py) stays as the fallback for environments where
#      the REST write endpoint is disabled.
#   4. Audit row written to AssessmentTrace on every push: who, what
#      system_id, which POAM IDs, request payload hash, response.
#   5. UI confirmation modal required before any push — the autonomy
#      story is "human reviews exceptions, not every CCI" but never
#      "human signs nothing".
# ---------------------------------------------------------------------------
