"""ServiceNow GRC evidence source — Now Table REST edition.

Pulls GRC records (compliance controls, attestations, risks, issues,
policies) from a ServiceNow GRC instance via the Now Table REST API at
``/api/now/table/{table}``. Used when a program's compliance system of
record is SN-GRC rather than eMASS — the assessor still wants to ingest
the GRC artifacts as evidence so its controls can cite them.

Each Table row becomes one :class:`SourceFile` whose payload is the
record's JSON serialization. The ingest pipeline's JSON extractor
handles the rest; from the assessor's point of view a SN-GRC control
attestation is just another evidence artifact with a queryable URI.

URI scheme
----------
``snow-grc://<host>/<table>/<sys_id>`` — host is the bare instance host
(e.g. ``acmecorp.service-now.com``), no scheme prefix.

Auth modes
----------
Two are supported, picked by ``SnowGrcConfig.auth_mode``:

* ``"oauth"`` — RFC 6749 client_credentials against
  ``/oauth_token.do``. Client ID is a config value (not a secret).
  Client secret is read from the OS keyring under the key
  ``SNOW_GRC_OAUTH_SECRET`` (or the ``SNOW_GRC_OAUTH_SECRET`` env var
  for CI / headless boxes). Token is cached in memory for its
  ``expires_in`` window minus 60 s safety margin.
* ``"basic"`` — HTTP Basic. Username is a config value; password is
  read from the keyring under ``SNOW_GRC_BASIC_PASSWORD`` (or the env
  var of the same name).

**No credential ever lives in config.toml or in the SnowGrcConfig
object** — only the *reference* to where it should be read from. This
matches how the Anthropic / OpenAI / eMASS keys are handled and keeps
the config file safe to commit to a backup repo.

Pagination
----------
The Now Table API caps a single response at ``sysparm_limit`` rows
(default 10000, but customer instances commonly lower it to 1000).
We page with ``sysparm_offset`` until a short page comes back. The
``X-Total-Count`` header is read on the first page for an upper-bound
log line so the user sees "pulled 4,321 of 50,000" instead of guessing.

sysparm_query sanitization
--------------------------
ServiceNow's encoded query string is positional and operator-heavy
(``^``, ``^OR``, ``=``, ``!=`` etc). We accept the user's raw string
but reject characters that could break out of the query parameter
into the path or smuggle in URL fragments: newlines, NUL bytes, and
embedded ``&``/``#``. Anything else is passed through verbatim — SN's
parser is the authority on what's legal inside the query expression
itself, and we don't want to be cleverer than it.

Feature gating
--------------
v0.4 connector. Hidden behind ``AppConfig.enable_snow_grc`` (default
False). The module imports clean even when disabled — only
:func:`build_source_from_config` enforces the flag, so the Settings UI
can probe / list tables on a configured-but-disabled instance without
crashing.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any, BinaryIO, Iterator
from urllib.parse import quote, urlparse

from .base import SourceFile

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Keyring slots & env-var fallbacks
# ---------------------------------------------------------------------------

# Match the rest of the codebase: keyring SERVICE is shared, KEY name is
# per-credential. Env-var fallback exists so headless CI / dev boxes can
# avoid touching Windows Credential Manager.
KEYRING_KEY_SNOW_OAUTH_SECRET = "SNOW_GRC_OAUTH_SECRET"
KEYRING_KEY_SNOW_BASIC_PASSWORD = "SNOW_GRC_BASIC_PASSWORD"
ENV_SNOW_OAUTH_SECRET = "SNOW_GRC_OAUTH_SECRET"
ENV_SNOW_BASIC_PASSWORD = "SNOW_GRC_BASIC_PASSWORD"

# Feature-flag env knob mirroring SWEEP_USE_SEARCH=1. Both ways to enable
# are honored — the persistent AppConfig.enable_snow_grc bool *or* this
# env var. Either ⇒ enabled.
ENV_FEATURE_FLAG = "CCIS_ENABLE_SNOW_GRC"


# Default table set — the SN-GRC tables most commonly cited as compliance
# evidence. Override per-config (one connector instance can target any
# subset / superset).
DEFAULT_TABLES: tuple[str, ...] = (
    "sn_compliance_control",
    "sn_compliance_attestation",
    "sn_risk_risk",
    "sn_risk_issue",
)

# Hard cap on rows pulled per table per run. Defensible default: a
# generous ceiling that still bounds a runaway query, configurable per
# table by passing ``max_rows`` in the per-table override dict.
DEFAULT_MAX_ROWS_PER_TABLE = 50_000

# Default page size requested from the SN Table API. SN caps this at the
# instance's ``glide.rest.batch_size`` value (commonly 1000 or 10000); a
# lower request is always honored.
DEFAULT_PAGE_SIZE = 1000

# Per-request HTTP timeout. Token-refresh + page fetch separately.
HTTP_TIMEOUT_SECONDS = 60

# OAuth token cushion — refresh ``expires_in - SAFETY_MARGIN`` seconds
# after acquisition so a long-running paginated pull doesn't 401 mid-walk.
TOKEN_SAFETY_MARGIN_SECONDS = 60

# Retry status codes: 429 throttled, 5xx transient. Same shape as the
# SharePoint Graph helper but trimmed to what SN actually emits.
_RETRY_STATUS = {429, 500, 502, 503, 504}
_RETRY_MAX_ATTEMPTS = 4
_RETRY_BACKOFF_BASE = 1.5

# Characters we refuse to forward inside a sysparm_query — they would
# break query-string framing or smuggle a URL fragment. SN's operator
# grammar uses ``^`` and ``=``, both of which are fine in a query param;
# what we have to block is anything that ends the param itself or hops
# scheme contexts.
_SYSPARM_QUERY_FORBIDDEN = ("\n", "\r", "\x00", "&", "#")


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------


@dataclass
class TableSpec:
    """Per-table configuration override.

    Attributes:
        name: Table name as the SN Table API knows it (e.g.
            ``"sn_compliance_control"``).
        sysparm_query: Optional SN encoded query string to filter rows
            on the server side. Pre-sanitization is applied — see module
            docstring for the rules.
        sysparm_fields: Optional comma-separated field allowlist. None
            means "return all fields" (SN default), which is what the
            evidence pipeline wants by default (the more provenance the
            better) but is configurable for tables with very wide rows.
        max_rows: Per-table cap. None ⇒ ``DEFAULT_MAX_ROWS_PER_TABLE``.
    """

    name: str
    sysparm_query: str | None = None
    sysparm_fields: str | None = None
    max_rows: int | None = None


@dataclass
class SnowGrcConfig:
    """Connector configuration. NO secrets — only references to keyring slots.

    Attributes:
        instance_url: Full URL of the SN instance, e.g.
            ``https://acmecorp.service-now.com``. Trailing slashes are
            stripped.
        auth_mode: ``"oauth"`` (client_credentials) or ``"basic"``.
        oauth_client_id: OAuth application ID created in
            SN → System OAuth → Application Registry. Treated as a
            non-secret label (it's not, really, but SN itself logs it).
        basic_username: Service account username for HTTP Basic.
        tables: Iterable of :class:`TableSpec` to walk. Defaults to
            :data:`DEFAULT_TABLES` with no filters.
        page_size: ``sysparm_limit`` requested per page. Capped by SN's
            instance config.
        verify_tls: TLS verification toggle. Almost always True; only
            flipped to False for internal SN dev instances with
            self-signed certs (in which case set ``ca_bundle`` instead
            if you can).
        ca_bundle: Optional path to a CA bundle PEM, passed to httpx as
            ``verify``. Use this instead of disabling TLS verification
            wherever possible.
    """

    instance_url: str
    auth_mode: str = "oauth"  # "oauth" | "basic"
    oauth_client_id: str | None = None
    basic_username: str | None = None
    tables: tuple[TableSpec, ...] = field(
        default_factory=lambda: tuple(TableSpec(name=t) for t in DEFAULT_TABLES)
    )
    page_size: int = DEFAULT_PAGE_SIZE
    verify_tls: bool = True
    ca_bundle: str | None = None

    def __post_init__(self) -> None:
        self.instance_url = (self.instance_url or "").rstrip("/")
        if not self.instance_url:
            raise ValueError("SnowGrcConfig.instance_url is required")
        parsed = urlparse(self.instance_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"SnowGrcConfig.instance_url must be http(s)://; got {self.instance_url!r}"
            )
        if not parsed.netloc:
            raise ValueError(
                f"SnowGrcConfig.instance_url must include a host; got {self.instance_url!r}"
            )
        if self.auth_mode not in ("oauth", "basic"):
            raise ValueError(
                f"SnowGrcConfig.auth_mode must be 'oauth' or 'basic'; got {self.auth_mode!r}"
            )
        if self.auth_mode == "oauth" and not self.oauth_client_id:
            raise ValueError("oauth auth_mode requires oauth_client_id")
        if self.auth_mode == "basic" and not self.basic_username:
            raise ValueError("basic auth_mode requires basic_username")
        if self.page_size <= 0 or self.page_size > 10_000:
            raise ValueError(
                f"page_size must be 1..10000; got {self.page_size}"
            )

    @property
    def host(self) -> str:
        """Bare hostname used in the snow-grc:// URI."""
        return urlparse(self.instance_url).netloc


# ---------------------------------------------------------------------------
# Feature flag
# ---------------------------------------------------------------------------


def feature_enabled() -> bool:
    """Return True when the v0.4 SN-GRC connector is enabled.

    Either the persistent ``AppConfig.enable_snow_grc`` flag or the
    ``CCIS_ENABLE_SNOW_GRC=1`` env var enables it. The env var exists
    for eval/CI runs where mutating config.toml is awkward.

    Imports config lazily so this module stays import-safe even when
    the config layer is unavailable (e.g. test harness without a TOML).
    """
    if os.environ.get(ENV_FEATURE_FLAG) == "1":
        return True
    try:
        from ... import config as cfg  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return False
    try:
        return bool(getattr(cfg.load_config(), "enable_snow_grc", False))
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Credential resolvers — keyring first, env var second, never config.toml
# ---------------------------------------------------------------------------


def _read_keyring(key: str) -> str | None:
    """Read a value from the shared keyring service. None on any failure."""
    try:
        import keyring  # noqa: PLC0415

        from ... import config as cfg  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return None
    try:
        return keyring.get_password(cfg.KEYRING_SERVICE, key)
    except Exception:  # noqa: BLE001
        return None


def get_oauth_secret() -> str | None:
    """Return the OAuth client_secret from keyring → env fallback."""
    return _read_keyring(KEYRING_KEY_SNOW_OAUTH_SECRET) or os.environ.get(
        ENV_SNOW_OAUTH_SECRET
    )


def get_basic_password() -> str | None:
    """Return the HTTP Basic password from keyring → env fallback."""
    return _read_keyring(KEYRING_KEY_SNOW_BASIC_PASSWORD) or os.environ.get(
        ENV_SNOW_BASIC_PASSWORD
    )


def set_oauth_secret(secret: str) -> None:
    """Persist the OAuth client_secret to the OS keyring."""
    import keyring  # noqa: PLC0415

    from ... import config as cfg  # noqa: PLC0415

    keyring.set_password(cfg.KEYRING_SERVICE, KEYRING_KEY_SNOW_OAUTH_SECRET, secret)


def set_basic_password(password: str) -> None:
    """Persist the HTTP Basic password to the OS keyring."""
    import keyring  # noqa: PLC0415

    from ... import config as cfg  # noqa: PLC0415

    keyring.set_password(
        cfg.KEYRING_SERVICE, KEYRING_KEY_SNOW_BASIC_PASSWORD, password
    )


def clear_oauth_secret() -> None:
    try:
        import keyring  # noqa: PLC0415

        from ... import config as cfg  # noqa: PLC0415

        keyring.delete_password(cfg.KEYRING_SERVICE, KEYRING_KEY_SNOW_OAUTH_SECRET)
    except Exception:  # noqa: BLE001
        pass


def clear_basic_password() -> None:
    try:
        import keyring  # noqa: PLC0415

        from ... import config as cfg  # noqa: PLC0415

        keyring.delete_password(cfg.KEYRING_SERVICE, KEYRING_KEY_SNOW_BASIC_PASSWORD)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# sysparm_query sanitization
# ---------------------------------------------------------------------------


class SysparmQueryError(ValueError):
    """Raised when a user-supplied sysparm_query contains forbidden chars."""


def sanitize_sysparm_query(q: str | None) -> str | None:
    """Validate a sysparm_query string; return it unchanged if safe.

    SN's encoded-query grammar is its own DSL — we deliberately do not
    try to parse it. The only rejection criterion is whether the string
    contains characters that would break out of the query-param slot or
    smuggle in a URL fragment. Empty / None ⇒ None.
    """
    if q is None:
        return None
    q = q.strip()
    if not q:
        return None
    for bad in _SYSPARM_QUERY_FORBIDDEN:
        if bad in q:
            raise SysparmQueryError(
                f"sysparm_query contains forbidden character {bad!r}; "
                "use the SN encoded-query DSL only"
            )
    return q


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _httpx_client(cfg: SnowGrcConfig):
    """Build a configured httpx.Client. Defers the import to keep this
    module import-safe even before the optional ``sources`` extras are
    installed (mirrors the SharePoint module's pattern).
    """
    try:
        import httpx  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError(
            "httpx is not installed. Install the 'sources' extras: "
            "`pip install -e .[sources]` from backend/."
        ) from exc
    verify: bool | str = cfg.verify_tls
    if cfg.ca_bundle:
        verify = cfg.ca_bundle
    return httpx.Client(timeout=HTTP_TIMEOUT_SECONDS, verify=verify)


def _request_with_retry(
    client,
    method: str,
    url: str,
    **kwargs,
):
    """HTTP request wrapper with backoff on 429/5xx and transport errors.

    Returns the final response object (caller responsible for status
    handling). Sleeps respect Retry-After when present, else exponential
    backoff with the same shape as the Graph helper.

    Transport failures (DNS, connection reset, TLS handshake, read
    timeout) from the underlying httpx client are caught and retried
    with the same backoff curve so an intermittent network blip
    doesn't kill a multi-hour table walk. After ``_RETRY_MAX_ATTEMPTS``
    transport failures the original ``httpx.HTTPError`` is re-raised
    so the caller sees the root cause.
    """
    # Defer httpx import to keep this module import-safe when the
    # optional sources extras aren't installed — same rationale as
    # _httpx_client(). The exception class hierarchy is what we need
    # for the except clause; missing httpx means there's nothing to
    # retry anyway, so we degrade to a bare Exception filter.
    try:
        import httpx  # noqa: PLC0415

        transport_errors: tuple[type[BaseException], ...] = (httpx.HTTPError,)
    except ImportError:
        transport_errors = ()

    last_resp = None
    last_exc: BaseException | None = None
    for attempt in range(_RETRY_MAX_ATTEMPTS):
        try:
            resp = client.request(method, url, **kwargs)
        except transport_errors as exc:  # type: ignore[misc]
            last_exc = exc
            if attempt == _RETRY_MAX_ATTEMPTS - 1:
                raise
            delay = min(_RETRY_BACKOFF_BASE * (2 ** attempt), 30.0)
            LOG.info(
                "SN-GRC transport error on %s — %s — retrying in %.1fs "
                "(attempt %d/%d)",
                url,
                exc,
                delay,
                attempt + 1,
                _RETRY_MAX_ATTEMPTS,
            )
            time.sleep(delay)
            continue
        if resp.status_code not in _RETRY_STATUS:
            return resp
        last_resp = resp
        if attempt == _RETRY_MAX_ATTEMPTS - 1:
            break
        retry_after_hdr = resp.headers.get("Retry-After")
        try:
            delay = (
                float(retry_after_hdr)
                if retry_after_hdr
                else _RETRY_BACKOFF_BASE * (2 ** attempt)
            )
        except ValueError:
            delay = _RETRY_BACKOFF_BASE * (2 ** attempt)
        delay = min(delay, 30.0)
        LOG.info(
            "SN-GRC %s on %s — retrying in %.1fs (attempt %d/%d)",
            resp.status_code,
            url,
            delay,
            attempt + 1,
            _RETRY_MAX_ATTEMPTS,
        )
        time.sleep(delay)
    # Exhausted retries: prefer the last response (caller will branch on
    # status_code), only fall back to re-raising the transport exception
    # if we never got *any* response. ``last_resp`` is guaranteed non-None
    # if at least one request returned, since we only loop here when the
    # status was retryable. The unreachable-None branch in _fetch_page is
    # defensive — covers the "all attempts threw transport errors" case
    # which now re-raises above.
    if last_resp is not None:
        return last_resp
    if last_exc is not None:
        raise last_exc
    return None


class SnowAuthError(RuntimeError):
    """401/403 from ServiceNow — credentials wrong, expired, or insufficient ACL."""


# ---------------------------------------------------------------------------
# Token cache (OAuth) + per-request header builder
# ---------------------------------------------------------------------------


@dataclass
class _OAuthToken:
    access_token: str
    expires_at: float  # monotonic seconds


class _Authenticator:
    """Resolves the Authorization header for each Table request.

    OAuth path caches the bearer in memory across requests within a
    single source-walk; the cache is thread-safe but per-instance, so
    creating a fresh :class:`ServiceNowGrcSource` always re-mints.
    """

    def __init__(self, cfg: SnowGrcConfig) -> None:
        self._cfg = cfg
        self._lock = threading.Lock()
        self._oauth: _OAuthToken | None = None

    def authorization_header(self, client) -> str:
        if self._cfg.auth_mode == "oauth":
            return f"Bearer {self._oauth_token(client)}"
        # basic
        import base64  # noqa: PLC0415

        username = self._cfg.basic_username or ""
        password = get_basic_password()
        if not password:
            raise SnowAuthError(
                "Basic auth selected but no password in keyring/env "
                f"({KEYRING_KEY_SNOW_BASIC_PASSWORD} / {ENV_SNOW_BASIC_PASSWORD})"
            )
        raw = f"{username}:{password}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def _oauth_token(self, client) -> str:
        with self._lock:
            now = time.monotonic()
            if self._oauth and self._oauth.expires_at - TOKEN_SAFETY_MARGIN_SECONDS > now:
                return self._oauth.access_token
            client_id = self._cfg.oauth_client_id or ""
            client_secret = get_oauth_secret()
            if not client_secret:
                raise SnowAuthError(
                    "OAuth selected but no client_secret in keyring/env "
                    f"({KEYRING_KEY_SNOW_OAUTH_SECRET} / {ENV_SNOW_OAUTH_SECRET})"
                )
            url = f"{self._cfg.instance_url}/oauth_token.do"
            data = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
            }
            resp = _request_with_retry(
                client,
                "POST",
                url,
                data=data,
                headers={"Accept": "application/json"},
            )
            if resp is None or resp.status_code != 200:
                code = resp.status_code if resp is not None else "?"
                body = (resp.text if resp is not None else "")[:300]
                raise SnowAuthError(
                    f"SN OAuth token request failed: HTTP {code} — {body}"
                )
            payload = resp.json()
            access = payload.get("access_token")
            expires_in = float(payload.get("expires_in") or 1800)
            if not access:
                raise SnowAuthError(
                    "SN OAuth response missing access_token; body keys: "
                    f"{list(payload)}"
                )
            self._oauth = _OAuthToken(
                access_token=access,
                expires_at=time.monotonic() + expires_in,
            )
            return access


# ---------------------------------------------------------------------------
# Table walk
# ---------------------------------------------------------------------------


def _table_url(cfg: SnowGrcConfig, table: str) -> str:
    # Table names are ASCII identifiers; still quote defensively so a
    # typo with a special char fails as a 404 instead of a malformed URL.
    return f"{cfg.instance_url}/api/now/table/{quote(table, safe='_')}"


def _fetch_page(
    client,
    cfg: SnowGrcConfig,
    auth: _Authenticator,
    table: str,
    *,
    offset: int,
    limit: int,
    sysparm_query: str | None,
    sysparm_fields: str | None,
):
    params: dict[str, str] = {
        "sysparm_offset": str(offset),
        "sysparm_limit": str(limit),
        # Display values OFF — we want the raw reference + dotted values
        # that downstream tools can re-resolve. Suppress reference links
        # for the same reason: cuts response size, the link URL is
        # reconstructible from (table, sys_id) anyway.
        "sysparm_display_value": "false",
        "sysparm_exclude_reference_link": "true",
    }
    if sysparm_query:
        params["sysparm_query"] = sysparm_query
    if sysparm_fields:
        params["sysparm_fields"] = sysparm_fields
    headers = {
        "Accept": "application/json",
        "Authorization": auth.authorization_header(client),
    }
    resp = _request_with_retry(
        client,
        "GET",
        _table_url(cfg, table),
        params=params,
        headers=headers,
    )
    if resp is None:
        raise RuntimeError(f"SN-GRC table {table}: no response after retries")
    if resp.status_code in (401, 403):
        raise SnowAuthError(
            f"SN-GRC table {table}: HTTP {resp.status_code} — "
            f"{(resp.text or '')[:300]}"
        )
    if resp.status_code != 200:
        raise RuntimeError(
            f"SN-GRC table {table}: HTTP {resp.status_code} — "
            f"{(resp.text or '')[:300]}"
        )
    body = resp.json()
    records = body.get("result") or []
    total_hdr = resp.headers.get("X-Total-Count")
    try:
        total_count = int(total_hdr) if total_hdr else None
    except ValueError:
        total_count = None
    return records, total_count


def _iter_table_rows(
    client,
    cfg: SnowGrcConfig,
    auth: _Authenticator,
    spec: TableSpec,
) -> Iterator[dict[str, Any]]:
    """Yield rows of ``spec.name`` in stable insertion order with paging."""
    sysparm_query = sanitize_sysparm_query(spec.sysparm_query)
    max_rows = spec.max_rows if spec.max_rows is not None else DEFAULT_MAX_ROWS_PER_TABLE
    offset = 0
    yielded = 0
    total_seen: int | None = None
    while yielded < max_rows:
        page_limit = min(cfg.page_size, max_rows - yielded)
        records, total_count = _fetch_page(
            client,
            cfg,
            auth,
            spec.name,
            offset=offset,
            limit=page_limit,
            sysparm_query=sysparm_query,
            sysparm_fields=spec.sysparm_fields,
        )
        if total_count is not None and total_seen is None:
            total_seen = total_count
            LOG.info(
                "SN-GRC table %s: server reports %d total row(s) "
                "(max_rows cap = %d, page_size = %d)",
                spec.name,
                total_count,
                max_rows,
                page_limit,
            )
        if not records:
            break
        for row in records:
            yield row
            yielded += 1
            if yielded >= max_rows:
                break
        if len(records) < page_limit:
            # Short page = end of table.
            break
        offset += len(records)
    LOG.info("SN-GRC table %s: walked %d row(s)", spec.name, yielded)


# ---------------------------------------------------------------------------
# SourceFile + Source
# ---------------------------------------------------------------------------


def _snow_uri(host: str, table: str, sys_id: str) -> str:
    return f"snow-grc://{host}/{quote(table, safe='_')}/{quote(sys_id, safe='')}"


@dataclass
class ServiceNowGrcFile:
    """One Table row materialized as a JSON-bytes SourceFile.

    The payload is the raw row dict serialized as UTF-8 JSON with
    ``ensure_ascii=False`` so non-Latin field values survive (SN supports
    non-ASCII descriptions). The orchestrator's JSON extractor will
    re-decode and ingest the keys verbatim.
    """

    uri: str
    name: str
    size: int | None
    container_uri: str | None
    _payload: bytes = field(repr=False)

    def open(self) -> BinaryIO:
        return BytesIO(self._payload)


class ServiceNowGrcSource:
    """Walk SN GRC tables, yielding one SourceFile per row.

    The orchestrator treats SourceFiles uniformly — JSON content gets
    routed to the JSON extractor, hashed, and indexed under its URI.
    Re-runs are idempotent because the URI (host + table + sys_id) is
    stable; the row payload changes only when the GRC record itself
    changes.

    Constructor args:
        cfg: :class:`SnowGrcConfig` — instance, auth mode, table list.

    Use :func:`build_source_from_config` instead of this constructor in
    production code paths — that helper enforces the v0.4 feature flag.
    Direct construction is fine in tests where the flag would just be
    monkey-patched anyway.
    """

    # The JSON payloads are small and self-contained; per-row commits
    # add no measurable overhead and let the Evidence list refresh
    # continuously during a large pull. Same rationale as SharePoint.
    commit_batch_size: int = 1

    def __init__(self, cfg: SnowGrcConfig) -> None:
        self._cfg = cfg
        self._auth = _Authenticator(cfg)
        self.uri = f"snow-grc://{cfg.host}/"

    @property
    def cfg(self) -> SnowGrcConfig:
        return self._cfg

    def test_connection(self) -> dict[str, Any]:
        """Probe auth + table reachability without pulling rows.

        Pulls one row from the first configured table. Returns a
        Settings-friendly status dict; never raises. The UI's green
        banner is keyed off ``ok`` so a 404 on a misspelled table name
        surfaces here, not at ingest time.
        """
        if not self._cfg.tables:
            return {
                "ok": False,
                "instance_url": self._cfg.instance_url,
                "auth_mode": self._cfg.auth_mode,
                "error": "No tables configured.",
            }
        first = self._cfg.tables[0]
        try:
            with _httpx_client(self._cfg) as client:
                _records, total = _fetch_page(
                    client,
                    self._cfg,
                    self._auth,
                    first.name,
                    offset=0,
                    limit=1,
                    sysparm_query=sanitize_sysparm_query(first.sysparm_query),
                    sysparm_fields=first.sysparm_fields,
                )
        except SnowAuthError as exc:
            return {
                "ok": False,
                "instance_url": self._cfg.instance_url,
                "auth_mode": self._cfg.auth_mode,
                "error": f"Authentication failed: {exc}",
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "ok": False,
                "instance_url": self._cfg.instance_url,
                "auth_mode": self._cfg.auth_mode,
                "error": str(exc),
            }
        return {
            "ok": True,
            "instance_url": self._cfg.instance_url,
            "auth_mode": self._cfg.auth_mode,
            "probe_table": first.name,
            "probe_total_count": total,
        }

    def iter_files(self) -> Iterator[SourceFile]:
        container_uri = self.uri
        with _httpx_client(self._cfg) as client:
            for spec in self._cfg.tables:
                try:
                    rows = _iter_table_rows(client, self._cfg, self._auth, spec)
                    for row in rows:
                        sys_id = row.get("sys_id")
                        if not sys_id:
                            # No primary key — can't form a stable URI.
                            # Skip rather than synthesize, which would let
                            # duplicate runs explode evidence rows.
                            LOG.warning(
                                "SN-GRC %s row missing sys_id; skipping. keys=%s",
                                spec.name,
                                list(row)[:8],
                            )
                            continue
                        payload = json.dumps(
                            row, ensure_ascii=False, sort_keys=True
                        ).encode("utf-8")
                        uri = _snow_uri(self._cfg.host, spec.name, str(sys_id))
                        # Name suffix .json so the dispatcher routes to the
                        # JSON extractor; the human-readable prefix is the
                        # table + sys_id so the Evidence list is scannable.
                        name = f"{spec.name}-{sys_id}.json"
                        yield ServiceNowGrcFile(
                            uri=uri,
                            name=name,
                            size=len(payload),
                            container_uri=container_uri,
                            _payload=payload,
                        )
                except SnowAuthError:
                    # Auth errors are fatal — every subsequent table will
                    # fail the same way; surface to the orchestrator so
                    # the run fails loudly instead of silently emitting
                    # half a corpus.
                    raise
                except Exception as exc:  # noqa: BLE001
                    # Per-table failure shouldn't kill the whole walk —
                    # one misspelled table or one ACL-restricted table
                    # would otherwise lose every later table's rows.
                    LOG.warning(
                        "SN-GRC table %s walk failed: %s — continuing",
                        spec.name,
                        exc,
                    )
                    continue


# ---------------------------------------------------------------------------
# Public factory — enforces the v0.4 feature flag
# ---------------------------------------------------------------------------


class FeatureDisabledError(RuntimeError):
    """Raised by :func:`build_source_from_config` when the flag is off."""


def build_source_from_config(cfg: SnowGrcConfig) -> ServiceNowGrcSource:
    """Construct a source, enforcing the v0.4 feature flag.

    The route layer should call this rather than :class:`ServiceNowGrcSource`
    directly so users can't accidentally start an SN-GRC ingest run when
    the connector is disabled.
    """
    if not feature_enabled():
        raise FeatureDisabledError(
            "ServiceNow GRC connector is a v0.4 feature. Enable it via "
            "AppConfig.enable_snow_grc or set CCIS_ENABLE_SNOW_GRC=1."
        )
    return ServiceNowGrcSource(cfg)
