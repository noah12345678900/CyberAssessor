"""ServiceNow GRC connector — v0.4 unit tests.

Scope: pure-Python invariants of the SN-GRC connector that don't need a
live ServiceNow instance. We monkey-patch the HTTP layer with a tiny
fake-httpx, and the keyring with a dict, so the whole file runs in <1s.

Coverage
--------
* :class:`SnowGrcConfig` validation rejects bad inputs.
* :func:`sanitize_sysparm_query` accepts SN operator grammar (``^``,
  ``=``, ``!=``, ``ORDERBY``) and rejects URL-framing chars (``\\n``,
  ``\\r``, ``\\x00``, ``&``, ``#``).
* :func:`feature_enabled` honors both the env-var override and the
  persistent AppConfig flag.
* Credential getters prefer keyring over env, return None when neither
  is set.
* OAuth token caching: minted once, reused until expiry, re-minted
  after expiry (with safety margin honored).
* Basic auth produces a correctly base64-encoded header.
* Pagination walks N pages, stops on short page, respects ``max_rows``
  cap, and skips rows without ``sys_id``.
* :class:`ServiceNowGrcFile` and :class:`ServiceNowGrcSource` satisfy
  the :class:`Source` / :class:`SourceFile` Protocols at runtime.
* :func:`build_source_from_config` raises :class:`FeatureDisabledError`
  when the flag is off.
* :meth:`ServiceNowGrcSource.test_connection` reports failures as a
  dict instead of raising.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

import pytest

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor.evidence.sources import servicenow_grc as snow  # noqa: E402
from cybersecurity_assessor.evidence.sources.base import (  # noqa: E402
    Source,
    SourceFile,
)


# ---------------------------------------------------------------------------
# Fake HTTP layer — minimal subset of httpx the connector actually uses.
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(
        self,
        status_code: int,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        text: str = "",
    ) -> None:
        self.status_code = status_code
        self._json = json_body if json_body is not None else {}
        self.headers = headers or {}
        self.text = text

    def json(self) -> Any:
        return self._json


class _FakeClient:
    """Programmable fake httpx.Client.

    The connector calls ``client.request(method, url, **kwargs)`` via
    ``_request_with_retry``. We record every call and pop a queued
    response, so a test can pre-stage exactly the page sequence it
    expects.
    """

    def __init__(self, queue: list[_FakeResponse]) -> None:
        self._queue = list(queue)
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append(
            {"method": method, "url": url, "kwargs": kwargs}
        )
        if not self._queue:
            raise AssertionError(
                f"Fake client out of responses (call: {method} {url})"
            )
        return self._queue.pop(0)

    # Context-manager protocol so the connector's `with _httpx_client()` works.
    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *_a: Any) -> None:
        return None


@pytest.fixture
def fake_httpx(monkeypatch: pytest.MonkeyPatch):
    """Replace :func:`_httpx_client` with a queue-driven fake.

    Tests interact with the per-test queue via the returned ``stage``
    callable, which patches the module's client factory to return a
    new ``_FakeClient`` pre-loaded with that queue.
    """

    holder: dict[str, _FakeClient] = {}

    def stage(responses: list[_FakeResponse]) -> _FakeClient:
        client = _FakeClient(responses)
        holder["client"] = client
        monkeypatch.setattr(snow, "_httpx_client", lambda _cfg: client)
        return client

    return stage


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch):
    """Strip env vars the connector reads so test runs aren't tainted
    by a developer's shell with real SN credentials exported."""
    for var in (
        snow.ENV_FEATURE_FLAG,
        snow.ENV_SNOW_OAUTH_SECRET,
        snow.ENV_SNOW_BASIC_PASSWORD,
    ):
        monkeypatch.delenv(var, raising=False)
    yield


@pytest.fixture
def fake_keyring(monkeypatch: pytest.MonkeyPatch):
    """Replace the keyring read helper with a dict-backed stub."""
    store: dict[str, str] = {}

    def _read(key: str) -> str | None:
        return store.get(key)

    monkeypatch.setattr(snow, "_read_keyring", _read)
    return store


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


class TestSnowGrcConfig:
    def test_oauth_happy_path(self) -> None:
        cfg = snow.SnowGrcConfig(
            instance_url="https://acme.service-now.com/",
            auth_mode="oauth",
            oauth_client_id="cid",
        )
        # Trailing slash stripped.
        assert cfg.instance_url == "https://acme.service-now.com"
        assert cfg.host == "acme.service-now.com"

    def test_basic_happy_path(self) -> None:
        cfg = snow.SnowGrcConfig(
            instance_url="https://acme.service-now.com",
            auth_mode="basic",
            basic_username="svc.assessor",
        )
        assert cfg.auth_mode == "basic"

    def test_empty_instance_url_rejected(self) -> None:
        with pytest.raises(ValueError, match="instance_url is required"):
            snow.SnowGrcConfig(instance_url="", oauth_client_id="cid")

    def test_non_http_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="http"):
            snow.SnowGrcConfig(
                instance_url="ftp://acme.service-now.com",
                oauth_client_id="cid",
            )

    def test_missing_host_rejected(self) -> None:
        with pytest.raises(ValueError, match="host"):
            snow.SnowGrcConfig(instance_url="https://", oauth_client_id="cid")

    def test_unknown_auth_mode_rejected(self) -> None:
        with pytest.raises(ValueError, match="auth_mode"):
            snow.SnowGrcConfig(
                instance_url="https://acme.service-now.com",
                auth_mode="kerberos",
            )

    def test_oauth_requires_client_id(self) -> None:
        with pytest.raises(ValueError, match="oauth_client_id"):
            snow.SnowGrcConfig(
                instance_url="https://acme.service-now.com",
                auth_mode="oauth",
            )

    def test_basic_requires_username(self) -> None:
        with pytest.raises(ValueError, match="basic_username"):
            snow.SnowGrcConfig(
                instance_url="https://acme.service-now.com",
                auth_mode="basic",
            )

    def test_page_size_bounds(self) -> None:
        with pytest.raises(ValueError, match="page_size"):
            snow.SnowGrcConfig(
                instance_url="https://acme.service-now.com",
                oauth_client_id="cid",
                page_size=0,
            )
        with pytest.raises(ValueError, match="page_size"):
            snow.SnowGrcConfig(
                instance_url="https://acme.service-now.com",
                oauth_client_id="cid",
                page_size=10_001,
            )


# ---------------------------------------------------------------------------
# sysparm_query sanitization
# ---------------------------------------------------------------------------


class TestSanitizeSysparmQuery:
    def test_none_returns_none(self) -> None:
        assert snow.sanitize_sysparm_query(None) is None

    def test_blank_returns_none(self) -> None:
        assert snow.sanitize_sysparm_query("   ") is None

    @pytest.mark.parametrize(
        "q",
        [
            "active=true",
            "active=true^state=3",
            "name!=foo^ORstate=2",
            "sys_updated_on>=javascript:gs.daysAgoStart(7)",
            "ORDERBYsys_updated_on",
            "categoryIN1,2,3",
        ],
    )
    def test_sn_operator_grammar_accepted(self, q: str) -> None:
        # Whatever SN's parser accepts, we pass through verbatim.
        assert snow.sanitize_sysparm_query(q) == q

    @pytest.mark.parametrize(
        "bad_char",
        ["\n", "\r", "\x00", "&", "#"],
    )
    def test_url_framing_chars_rejected(self, bad_char: str) -> None:
        q = f"active=true{bad_char}name=foo"
        with pytest.raises(snow.SysparmQueryError):
            snow.sanitize_sysparm_query(q)


# ---------------------------------------------------------------------------
# Feature flag
# ---------------------------------------------------------------------------


class TestFeatureFlag:
    def test_env_var_enables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(snow.ENV_FEATURE_FLAG, "1")
        assert snow.feature_enabled() is True

    def test_env_var_other_values_dont_enable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(snow.ENV_FEATURE_FLAG, "true")
        # Strict "1" — anything else falls through to config.
        # Config load fails in this test harness (no TOML), so result is False.
        # We patch load_config to make that explicit.
        from cybersecurity_assessor import config as _cfg

        monkeypatch.setattr(
            _cfg, "load_config", lambda: _cfg.AppConfig(enable_snow_grc=False)
        )
        assert snow.feature_enabled() is False

    def test_app_config_flag_enables(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cybersecurity_assessor import config as _cfg

        monkeypatch.setattr(
            _cfg, "load_config", lambda: _cfg.AppConfig(enable_snow_grc=True)
        )
        assert snow.feature_enabled() is True

    def test_disabled_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cybersecurity_assessor import config as _cfg

        monkeypatch.setattr(
            _cfg, "load_config", lambda: _cfg.AppConfig(enable_snow_grc=False)
        )
        assert snow.feature_enabled() is False


# ---------------------------------------------------------------------------
# Credential resolvers
# ---------------------------------------------------------------------------


class TestCredentialResolvers:
    def test_oauth_secret_prefers_keyring(
        self, fake_keyring: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_keyring[snow.KEYRING_KEY_SNOW_OAUTH_SECRET] = "from-keyring"
        monkeypatch.setenv(snow.ENV_SNOW_OAUTH_SECRET, "from-env")
        assert snow.get_oauth_secret() == "from-keyring"

    def test_oauth_secret_falls_back_to_env(
        self, fake_keyring: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(snow.ENV_SNOW_OAUTH_SECRET, "from-env")
        assert snow.get_oauth_secret() == "from-env"

    def test_oauth_secret_none_when_nothing_set(
        self, fake_keyring: dict[str, str]
    ) -> None:
        assert snow.get_oauth_secret() is None

    def test_basic_password_prefers_keyring(
        self, fake_keyring: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_keyring[snow.KEYRING_KEY_SNOW_BASIC_PASSWORD] = "kr"
        monkeypatch.setenv(snow.ENV_SNOW_BASIC_PASSWORD, "env")
        assert snow.get_basic_password() == "kr"

    def test_basic_password_falls_back_to_env(
        self, fake_keyring: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(snow.ENV_SNOW_BASIC_PASSWORD, "env")
        assert snow.get_basic_password() == "env"


# ---------------------------------------------------------------------------
# OAuth token caching
# ---------------------------------------------------------------------------


def _make_cfg_oauth(**over: Any) -> snow.SnowGrcConfig:
    base = {
        "instance_url": "https://acme.service-now.com",
        "auth_mode": "oauth",
        "oauth_client_id": "client-1",
    }
    base.update(over)
    return snow.SnowGrcConfig(**base)


def _make_cfg_basic(**over: Any) -> snow.SnowGrcConfig:
    base = {
        "instance_url": "https://acme.service-now.com",
        "auth_mode": "basic",
        "basic_username": "svc.tester",
    }
    base.update(over)
    return snow.SnowGrcConfig(**base)


class TestOAuthCaching:
    def test_token_minted_once_and_reused(
        self,
        fake_keyring: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fake_keyring[snow.KEYRING_KEY_SNOW_OAUTH_SECRET] = "sek"
        cfg = _make_cfg_oauth()
        auth = snow._Authenticator(cfg)
        responses = [
            _FakeResponse(
                200, json_body={"access_token": "tok-A", "expires_in": 3600}
            )
        ]
        client = _FakeClient(responses)
        first = auth.authorization_header(client)
        assert first == "Bearer tok-A"
        # Second call uses cache — no additional mint, no second response needed.
        second = auth.authorization_header(client)
        assert second == "Bearer tok-A"
        assert len(client.calls) == 1
        # Sanity: it hit the token endpoint, not the Table endpoint.
        assert client.calls[0]["url"].endswith("/oauth_token.do")

    def test_token_re_minted_after_expiry(
        self,
        fake_keyring: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        fake_keyring[snow.KEYRING_KEY_SNOW_OAUTH_SECRET] = "sek"
        cfg = _make_cfg_oauth()
        auth = snow._Authenticator(cfg)
        # First mint expires almost immediately (< safety margin).
        responses = [
            _FakeResponse(
                200, json_body={"access_token": "tok-A", "expires_in": 1}
            ),
            _FakeResponse(
                200, json_body={"access_token": "tok-B", "expires_in": 3600}
            ),
        ]
        client = _FakeClient(responses)
        assert auth.authorization_header(client) == "Bearer tok-A"
        # Force "time" past the safety-margin window by faking monotonic.
        base = snow.time.monotonic()
        monkeypatch.setattr(
            snow.time,
            "monotonic",
            lambda b=base: b + 1000,
        )
        assert auth.authorization_header(client) == "Bearer tok-B"
        assert len(client.calls) == 2

    def test_missing_secret_raises(
        self, fake_keyring: dict[str, str]
    ) -> None:
        cfg = _make_cfg_oauth()
        auth = snow._Authenticator(cfg)
        client = _FakeClient([])
        with pytest.raises(snow.SnowAuthError, match="client_secret"):
            auth.authorization_header(client)

    def test_token_endpoint_non_200_raises(
        self, fake_keyring: dict[str, str]
    ) -> None:
        fake_keyring[snow.KEYRING_KEY_SNOW_OAUTH_SECRET] = "sek"
        cfg = _make_cfg_oauth()
        auth = snow._Authenticator(cfg)
        client = _FakeClient(
            [_FakeResponse(401, text="invalid_client")]
        )
        with pytest.raises(snow.SnowAuthError, match="HTTP 401"):
            auth.authorization_header(client)

    def test_token_endpoint_missing_access_token_raises(
        self, fake_keyring: dict[str, str]
    ) -> None:
        fake_keyring[snow.KEYRING_KEY_SNOW_OAUTH_SECRET] = "sek"
        cfg = _make_cfg_oauth()
        auth = snow._Authenticator(cfg)
        client = _FakeClient(
            [_FakeResponse(200, json_body={"expires_in": 3600})]
        )
        with pytest.raises(snow.SnowAuthError, match="access_token"):
            auth.authorization_header(client)


# ---------------------------------------------------------------------------
# Basic auth header
# ---------------------------------------------------------------------------


class TestBasicAuth:
    def test_basic_header_shape(
        self, fake_keyring: dict[str, str]
    ) -> None:
        fake_keyring[snow.KEYRING_KEY_SNOW_BASIC_PASSWORD] = "p@ssword!"
        cfg = _make_cfg_basic(basic_username="alice")
        auth = snow._Authenticator(cfg)
        header = auth.authorization_header(_FakeClient([]))
        assert header.startswith("Basic ")
        decoded = base64.b64decode(header[len("Basic "):]).decode("utf-8")
        assert decoded == "alice:p@ssword!"

    def test_missing_password_raises(
        self, fake_keyring: dict[str, str]
    ) -> None:
        cfg = _make_cfg_basic()
        auth = snow._Authenticator(cfg)
        with pytest.raises(snow.SnowAuthError, match="password"):
            auth.authorization_header(_FakeClient([]))


# ---------------------------------------------------------------------------
# Pagination + row walking
# ---------------------------------------------------------------------------


def _row(sys_id: str, **extra: Any) -> dict[str, Any]:
    base = {"sys_id": sys_id, "name": f"ctl-{sys_id}"}
    base.update(extra)
    return base


class TestTableWalk:
    def test_pagination_two_full_pages_then_short(
        self,
        fake_httpx,
        fake_keyring: dict[str, str],
    ) -> None:
        fake_keyring[snow.KEYRING_KEY_SNOW_BASIC_PASSWORD] = "pw"
        cfg = _make_cfg_basic(page_size=2)
        spec = snow.TableSpec(name="sn_compliance_control")
        client = fake_httpx(
            [
                _FakeResponse(
                    200,
                    json_body={"result": [_row("a"), _row("b")]},
                    headers={"X-Total-Count": "5"},
                ),
                _FakeResponse(
                    200,
                    json_body={"result": [_row("c"), _row("d")]},
                ),
                _FakeResponse(
                    200,
                    json_body={"result": [_row("e")]},
                ),
            ]
        )
        auth = snow._Authenticator(cfg)
        rows = list(snow._iter_table_rows(client, cfg, auth, spec))
        assert [r["sys_id"] for r in rows] == ["a", "b", "c", "d", "e"]
        # Three calls — last is short, walk stops.
        assert len(client.calls) == 3
        # Offsets advance correctly.
        offsets = [
            call["kwargs"]["params"]["sysparm_offset"]
            for call in client.calls
        ]
        assert offsets == ["0", "2", "4"]

    def test_empty_result_stops_walk(
        self,
        fake_httpx,
        fake_keyring: dict[str, str],
    ) -> None:
        fake_keyring[snow.KEYRING_KEY_SNOW_BASIC_PASSWORD] = "pw"
        cfg = _make_cfg_basic(page_size=10)
        spec = snow.TableSpec(name="sn_risk_risk")
        client = fake_httpx([_FakeResponse(200, json_body={"result": []})])
        auth = snow._Authenticator(cfg)
        rows = list(snow._iter_table_rows(client, cfg, auth, spec))
        assert rows == []
        assert len(client.calls) == 1

    def test_max_rows_cap_honored(
        self,
        fake_httpx,
        fake_keyring: dict[str, str],
    ) -> None:
        fake_keyring[snow.KEYRING_KEY_SNOW_BASIC_PASSWORD] = "pw"
        cfg = _make_cfg_basic(page_size=10)
        spec = snow.TableSpec(name="sn_risk_issue", max_rows=3)
        client = fake_httpx(
            [
                _FakeResponse(
                    200,
                    json_body={
                        "result": [_row(str(i)) for i in range(10)]
                    },
                )
            ]
        )
        auth = snow._Authenticator(cfg)
        rows = list(snow._iter_table_rows(client, cfg, auth, spec))
        assert len(rows) == 3
        # Page limit should have been capped to remaining budget (3).
        assert client.calls[0]["kwargs"]["params"]["sysparm_limit"] == "3"

    def test_auth_failure_propagates(
        self,
        fake_httpx,
        fake_keyring: dict[str, str],
    ) -> None:
        fake_keyring[snow.KEYRING_KEY_SNOW_BASIC_PASSWORD] = "pw"
        cfg = _make_cfg_basic()
        spec = snow.TableSpec(name="sn_compliance_control")
        client = fake_httpx([_FakeResponse(401, text="unauthorized")])
        auth = snow._Authenticator(cfg)
        with pytest.raises(snow.SnowAuthError):
            list(snow._iter_table_rows(client, cfg, auth, spec))

    def test_other_5xx_after_retries_raises(
        self,
        fake_httpx,
        fake_keyring: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Skip sleeps in retry loop.
        monkeypatch.setattr(snow.time, "sleep", lambda _s: None)
        fake_keyring[snow.KEYRING_KEY_SNOW_BASIC_PASSWORD] = "pw"
        cfg = _make_cfg_basic()
        spec = snow.TableSpec(name="sn_compliance_control")
        # Same status repeated for every retry attempt.
        client = fake_httpx(
            [_FakeResponse(503, text="busy")] * snow._RETRY_MAX_ATTEMPTS
        )
        auth = snow._Authenticator(cfg)
        with pytest.raises(RuntimeError, match="HTTP 503"):
            list(snow._iter_table_rows(client, cfg, auth, spec))

    def test_transport_error_then_success_retries(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fake_keyring: dict[str, str],
    ) -> None:
        """A connection blip mid-walk must be retried, not killed.

        ``_request_with_retry`` catches the ``httpx.HTTPError`` family
        (DNS, conn-reset, TLS handshake, read timeout) with the same
        backoff curve as HTTP 5xx. Without this guard, a single
        intermittent network drop kills a multi-hour table walk —
        we'd rather burn N retries and recover.
        """
        import httpx

        monkeypatch.setattr(snow.time, "sleep", lambda _s: None)
        fake_keyring[snow.KEYRING_KEY_SNOW_BASIC_PASSWORD] = "pw"

        page_one = _FakeResponse(
            200,
            json_body={
                "result": [{"sys_id": "abc123", "name": "ctrl-1"}],
            },
            headers={"X-Total-Count": "1"},
        )

        class _BlippyClient(_FakeClient):
            """Raise a transport error once, then serve the queued response."""

            def __init__(self, queue):
                super().__init__(queue)
                self._raised = False

            def request(self, method, url, **kwargs):  # type: ignore[override]
                self.calls.append({"method": method, "url": url, "kwargs": kwargs})
                if not self._raised:
                    self._raised = True
                    raise httpx.ConnectError("simulated connection reset")
                return self._queue.pop(0)

        client = _BlippyClient([page_one])
        cfg = _make_cfg_basic()
        spec = snow.TableSpec(name="sn_compliance_control")
        auth = snow._Authenticator(cfg)

        rows = list(snow._iter_table_rows(client, cfg, auth, spec))

        assert len(rows) == 1
        assert rows[0]["sys_id"] == "abc123"
        # First call raised; second call succeeded → 2 attempts total.
        assert len(client.calls) == 2

    def test_transport_error_exhausts_retries_reraises(
        self,
        monkeypatch: pytest.MonkeyPatch,
        fake_keyring: dict[str, str],
    ) -> None:
        """When every attempt raises, the original httpx error escapes.

        Pins the contract that ``_request_with_retry`` doesn't swallow
        a persistent network failure — the caller (and the human reading
        the log) needs the root cause, not a silent empty result.
        """
        import httpx

        monkeypatch.setattr(snow.time, "sleep", lambda _s: None)
        fake_keyring[snow.KEYRING_KEY_SNOW_BASIC_PASSWORD] = "pw"

        class _DeadClient(_FakeClient):
            def request(self, method, url, **kwargs):  # type: ignore[override]
                self.calls.append({"method": method, "url": url, "kwargs": kwargs})
                raise httpx.ReadTimeout("simulated read timeout")

        client = _DeadClient([])
        cfg = _make_cfg_basic()
        spec = snow.TableSpec(name="sn_compliance_control")
        auth = snow._Authenticator(cfg)

        with pytest.raises(httpx.ReadTimeout):
            list(snow._iter_table_rows(client, cfg, auth, spec))
        assert len(client.calls) == snow._RETRY_MAX_ATTEMPTS


# ---------------------------------------------------------------------------
# Source-level integration: ServiceNowGrcSource.iter_files
# ---------------------------------------------------------------------------


class TestSourceIterFiles:
    def test_skips_rows_without_sys_id(
        self,
        fake_httpx,
        fake_keyring: dict[str, str],
    ) -> None:
        fake_keyring[snow.KEYRING_KEY_SNOW_BASIC_PASSWORD] = "pw"
        cfg = _make_cfg_basic(
            page_size=10,
            tables=(snow.TableSpec(name="sn_compliance_control"),),
        )
        fake_httpx(
            [
                _FakeResponse(
                    200,
                    json_body={
                        "result": [
                            _row("good-1"),
                            {"name": "no-sys-id-row"},  # skipped
                            _row("good-2"),
                        ]
                    },
                )
            ]
        )
        source = snow.ServiceNowGrcSource(cfg)
        files = list(source.iter_files())
        assert [f.name for f in files] == [
            "sn_compliance_control-good-1.json",
            "sn_compliance_control-good-2.json",
        ]

    def test_uri_shape_and_payload(
        self,
        fake_httpx,
        fake_keyring: dict[str, str],
    ) -> None:
        fake_keyring[snow.KEYRING_KEY_SNOW_BASIC_PASSWORD] = "pw"
        cfg = _make_cfg_basic(
            page_size=10,
            tables=(snow.TableSpec(name="sn_compliance_control"),),
        )
        fake_httpx(
            [
                _FakeResponse(
                    200,
                    json_body={
                        "result": [_row("abc123", state="3")]
                    },
                )
            ]
        )
        source = snow.ServiceNowGrcSource(cfg)
        files = list(source.iter_files())
        assert len(files) == 1
        f = files[0]
        assert f.uri == "snow-grc://acme.service-now.com/sn_compliance_control/abc123"
        assert f.container_uri == "snow-grc://acme.service-now.com/"
        # Payload is canonical JSON (sorted keys for stable content hash).
        payload = json.loads(f.open().read().decode("utf-8"))
        assert payload == {
            "sys_id": "abc123",
            "name": "ctl-abc123",
            "state": "3",
        }
        # size matches byte payload length.
        assert f.size == len(f.open().read())

    def test_per_table_failure_does_not_abort_walk(
        self,
        fake_httpx,
        fake_keyring: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Skip retry sleeps so test stays fast.
        monkeypatch.setattr(snow.time, "sleep", lambda _s: None)
        fake_keyring[snow.KEYRING_KEY_SNOW_BASIC_PASSWORD] = "pw"
        cfg = _make_cfg_basic(
            page_size=10,
            tables=(
                snow.TableSpec(name="bad_table"),
                snow.TableSpec(name="sn_risk_risk"),
            ),
        )
        # First table: 404 (terminal, not retriable). Second table: succeeds.
        fake_httpx(
            [
                _FakeResponse(404, text="not found"),
                _FakeResponse(
                    200,
                    json_body={"result": [_row("r1")]},
                ),
            ]
        )
        source = snow.ServiceNowGrcSource(cfg)
        files = list(source.iter_files())
        # Only the second table contributed rows.
        assert [f.name for f in files] == ["sn_risk_risk-r1.json"]

    def test_auth_failure_aborts_walk(
        self,
        fake_httpx,
        fake_keyring: dict[str, str],
    ) -> None:
        fake_keyring[snow.KEYRING_KEY_SNOW_BASIC_PASSWORD] = "pw"
        cfg = _make_cfg_basic(
            page_size=10,
            tables=(
                snow.TableSpec(name="sn_compliance_control"),
                snow.TableSpec(name="sn_risk_risk"),
            ),
        )
        fake_httpx([_FakeResponse(401, text="bad creds")])
        source = snow.ServiceNowGrcSource(cfg)
        with pytest.raises(snow.SnowAuthError):
            list(source.iter_files())


# ---------------------------------------------------------------------------
# test_connection
# ---------------------------------------------------------------------------


class TestTestConnection:
    def test_success(
        self,
        fake_httpx,
        fake_keyring: dict[str, str],
    ) -> None:
        fake_keyring[snow.KEYRING_KEY_SNOW_BASIC_PASSWORD] = "pw"
        cfg = _make_cfg_basic(
            tables=(snow.TableSpec(name="sn_compliance_control"),),
        )
        fake_httpx(
            [
                _FakeResponse(
                    200,
                    json_body={"result": [_row("a")]},
                    headers={"X-Total-Count": "42"},
                )
            ]
        )
        source = snow.ServiceNowGrcSource(cfg)
        status = source.test_connection()
        assert status["ok"] is True
        assert status["probe_table"] == "sn_compliance_control"
        assert status["probe_total_count"] == 42

    def test_auth_error_reported_not_raised(
        self,
        fake_httpx,
        fake_keyring: dict[str, str],
    ) -> None:
        fake_keyring[snow.KEYRING_KEY_SNOW_BASIC_PASSWORD] = "pw"
        cfg = _make_cfg_basic(
            tables=(snow.TableSpec(name="sn_compliance_control"),),
        )
        fake_httpx([_FakeResponse(401, text="nope")])
        source = snow.ServiceNowGrcSource(cfg)
        status = source.test_connection()
        assert status["ok"] is False
        assert "Authentication failed" in status["error"]

    def test_empty_tables_reports_error(
        self,
        fake_keyring: dict[str, str],
    ) -> None:
        cfg = _make_cfg_basic(tables=())
        source = snow.ServiceNowGrcSource(cfg)
        status = source.test_connection()
        assert status["ok"] is False
        assert "No tables" in status["error"]


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    def test_file_satisfies_protocol(self) -> None:
        f = snow.ServiceNowGrcFile(
            uri="snow-grc://h/t/sid",
            name="t-sid.json",
            size=2,
            container_uri="snow-grc://h/",
            _payload=b"{}",
        )
        assert isinstance(f, SourceFile)
        body = f.open().read()
        assert body == b"{}"

    def test_source_satisfies_protocol(
        self,
        fake_keyring: dict[str, str],
    ) -> None:
        cfg = _make_cfg_basic()
        source = snow.ServiceNowGrcSource(cfg)
        assert isinstance(source, Source)
        assert source.uri == "snow-grc://acme.service-now.com/"


# ---------------------------------------------------------------------------
# Public factory + registration
# ---------------------------------------------------------------------------


class TestBuildSourceFromConfig:
    def test_raises_when_disabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cybersecurity_assessor import config as _cfg

        monkeypatch.setattr(
            _cfg, "load_config", lambda: _cfg.AppConfig(enable_snow_grc=False)
        )
        cfg = _make_cfg_basic()
        with pytest.raises(snow.FeatureDisabledError):
            snow.build_source_from_config(cfg)

    def test_succeeds_with_env_override(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(snow.ENV_FEATURE_FLAG, "1")
        cfg = _make_cfg_basic()
        source = snow.build_source_from_config(cfg)
        assert isinstance(source, snow.ServiceNowGrcSource)

    def test_succeeds_with_app_config_flag(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cybersecurity_assessor import config as _cfg

        monkeypatch.setattr(
            _cfg, "load_config", lambda: _cfg.AppConfig(enable_snow_grc=True)
        )
        cfg = _make_cfg_basic()
        source = snow.build_source_from_config(cfg)
        assert isinstance(source, snow.ServiceNowGrcSource)


class TestRegistration:
    def test_source_exported_from_package(self) -> None:
        from cybersecurity_assessor.evidence import sources as sources_pkg

        assert "ServiceNowGrcSource" in sources_pkg.__all__
        assert sources_pkg.ServiceNowGrcSource is snow.ServiceNowGrcSource

    def test_app_config_carries_flag(self) -> None:
        from cybersecurity_assessor.config import AppConfig

        cfg = AppConfig()
        assert hasattr(cfg, "enable_snow_grc")
        assert cfg.enable_snow_grc is False
