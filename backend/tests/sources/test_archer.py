"""Tests for the v0.4 Archer (RSA / GRC) connector.

The connector is gated behind ``ARCHER_CONNECTOR_ENABLED=1`` so production
builds don't accidentally make network calls. Tests flip the flag
explicitly via monkeypatch and stub all HTTP through a fake ``httpx.Client``
so nothing actually leaves the box.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from cybersecurity_assessor.evidence.sources.archer import (
    _FEATURE_FLAG_ENV,
    ArcherApplicationQuery,
    ArcherAuthError,
    ArcherClient,
    ArcherConfig,
    ArcherFeatureDisabled,
    ArcherSource,
    _archer_uri,
    _extract_content_id,
    _keyring_key,
    _read_password,
    feature_enabled,
)


# ---------------------------------------------------------------------------
# Feature flag
# ---------------------------------------------------------------------------


def test_feature_flag_default_off(monkeypatch):
    monkeypatch.delenv(_FEATURE_FLAG_ENV, raising=False)
    assert feature_enabled() is False


def test_feature_flag_on(monkeypatch):
    monkeypatch.setenv(_FEATURE_FLAG_ENV, "1")
    assert feature_enabled() is True


def test_iter_files_raises_when_flag_off(monkeypatch):
    monkeypatch.delenv(_FEATURE_FLAG_ENV, raising=False)
    src = ArcherSource(_min_config())
    with pytest.raises(ArcherFeatureDisabled):
        next(iter(src.iter_files()))


# ---------------------------------------------------------------------------
# URI shape — pinned because it's the primary key in Evidence.path
# ---------------------------------------------------------------------------


def test_archer_uri_canonical_shape():
    assert (
        _archer_uri("ProdInstance", 75, 12345)
        == "archer://ProdInstance/75/12345"
    )


def test_archer_uri_escapes_funny_characters():
    # Instance names with spaces / unicode happen in some on-prem deployments.
    uri = _archer_uri("Prod Instance", 1, "x/y")
    assert " " not in uri
    assert uri.endswith("x%2Fy")


def test_extract_content_id_prefers_documented_key():
    assert _extract_content_id({"Id": 7, "ContentId": 8}) == 7


def test_extract_content_id_falls_back_to_aliases():
    assert _extract_content_id({"ContentID": 9}) == 9


def test_extract_content_id_returns_none_for_malformed():
    assert _extract_content_id({"Title": "no id here"}) is None


# ---------------------------------------------------------------------------
# Keyring / password resolution — must never persist to disk via the dataclass
# ---------------------------------------------------------------------------


def test_keyring_key_lowercases():
    assert _keyring_key("ProdInstance", "Alice") == "alice@prodinstance"


def test_config_repr_never_includes_password():
    # The dataclass intentionally has no password field — pin that
    # explicitly so a future "convenient" refactor doesn't reintroduce it.
    cfg = _min_config()
    assert "password" not in repr(cfg).lower()
    # And the dataclass has no such attribute at all.
    assert not hasattr(cfg, "password")


def test_read_password_env_fallback(monkeypatch):
    # Force the keyring lookup to miss so we test the env fallback in isolation.
    monkeypatch.setattr(
        "cybersecurity_assessor.evidence.sources.archer.keyring",
        None,
        raising=False,
    )
    monkeypatch.setenv("ARCHER_PASSWORD", "from-env")
    assert _read_password("InstA", "alice") == "from-env"


def test_read_password_returns_none_when_both_miss(monkeypatch):
    monkeypatch.delenv("ARCHER_PASSWORD", raising=False)

    class _NullKeyring:
        @staticmethod
        def get_password(*_a, **_k):
            return None

    monkeypatch.setitem(
        __import__("sys").modules, "keyring", _NullKeyring()
    )
    assert _read_password("InstA", "alice") is None


# ---------------------------------------------------------------------------
# Fake httpx client — captures requests, returns canned responses
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None,
                 text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or (json.dumps(payload) if payload else "")

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class _FakeHttpxClient:
    """Records every call; returns scripted responses in FIFO order per (method, path)."""

    def __init__(self):
        self.calls: list[tuple[str, str, dict | None, dict | None]] = []
        # Keyed by (method, path) → list of _FakeResponse (popped in order).
        self.scripted: dict[tuple[str, str], list[_FakeResponse]] = {}
        self.closed = False

    def queue(self, method: str, path: str, response: _FakeResponse) -> None:
        self.scripted.setdefault((method, path), []).append(response)

    # httpx.Client.request signature: (method, url, headers, json, params)
    def request(self, method, path, *, headers=None, json=None, params=None):
        self.calls.append((method, path, dict(headers or {}), json))
        key = (method, path)
        queue = self.scripted.get(key, [])
        if not queue:
            raise AssertionError(
                f"Unexpected {method} {path}; nothing queued (calls so far: {len(self.calls)})"
            )
        return queue.pop(0)

    def post(self, path, *, json=None, headers=None):
        return self.request(
            "POST", path, headers=headers, json=json, params=None
        )

    def close(self):
        self.closed = True


def _install_fake_httpx(monkeypatch, client: ArcherClient) -> _FakeHttpxClient:
    fake = _FakeHttpxClient()
    monkeypatch.setattr(client, "_httpx", lambda: fake)
    return fake


# ---------------------------------------------------------------------------
# Login flow
# ---------------------------------------------------------------------------


def _min_config(
    queries: tuple[ArcherApplicationQuery, ...] = (
        ArcherApplicationQuery(application_id=75),
    ),
) -> ArcherConfig:
    return ArcherConfig(
        instance_url="https://archer.example.com",
        instance_name="ProdInstance",
        username="alice",
        queries=queries,
    )


def _stub_password(monkeypatch, value: str | None = "the-password") -> None:
    monkeypatch.setattr(
        "cybersecurity_assessor.evidence.sources.archer._read_password",
        lambda *_a, **_k: value,
    )


def test_login_uses_session_token_header(monkeypatch):
    monkeypatch.setenv(_FEATURE_FLAG_ENV, "1")
    _stub_password(monkeypatch)
    client = ArcherClient(_min_config())
    fake = _install_fake_httpx(monkeypatch, client)
    fake.queue(
        "POST",
        "/api/core/security/login",
        _FakeResponse(
            200,
            {
                "IsSuccessful": True,
                "RequestedObject": {"SessionToken": "tok-abc"},
            },
        ),
    )
    # First authed request after login — TotalCount=0 terminates immediately.
    fake.queue(
        "POST",
        "/api/core/content/contentsearch",
        _FakeResponse(
            200,
            {
                "IsSuccessful": True,
                "RequestedObject": {"Records": [], "TotalCount": 0},
            },
        ),
    )

    list(
        client.iter_application_records(
            ArcherApplicationQuery(application_id=75)
        )
    )

    # Login was the first call.
    method, path, headers, body = fake.calls[0]
    assert (method, path) == ("POST", "/api/core/security/login")
    # Password actually went over the wire on login (sanity check).
    assert body["Password"] == "the-password"
    # Subsequent authed call carries the bearer header.
    method2, path2, headers2, _ = fake.calls[1]
    assert path2 == "/api/core/content/contentsearch"
    assert headers2["Authorization"] == 'Archer session-id="tok-abc"'


def test_login_raises_auth_error_on_401(monkeypatch):
    monkeypatch.setenv(_FEATURE_FLAG_ENV, "1")
    _stub_password(monkeypatch)
    client = ArcherClient(_min_config())
    fake = _install_fake_httpx(monkeypatch, client)
    fake.queue(
        "POST",
        "/api/core/security/login",
        _FakeResponse(401, text="bad creds"),
    )
    with pytest.raises(ArcherAuthError):
        client._ensure_token()


def test_login_raises_auth_error_on_is_successful_false(monkeypatch):
    monkeypatch.setenv(_FEATURE_FLAG_ENV, "1")
    _stub_password(monkeypatch)
    client = ArcherClient(_min_config())
    fake = _install_fake_httpx(monkeypatch, client)
    fake.queue(
        "POST",
        "/api/core/security/login",
        _FakeResponse(200, {"IsSuccessful": False, "ValidationMessages": "x"}),
    )
    with pytest.raises(ArcherAuthError):
        client._ensure_token()


def test_login_blocked_when_feature_flag_off(monkeypatch):
    monkeypatch.delenv(_FEATURE_FLAG_ENV, raising=False)
    _stub_password(monkeypatch)
    client = ArcherClient(_min_config())
    _install_fake_httpx(monkeypatch, client)
    with pytest.raises(ArcherFeatureDisabled):
        client._ensure_token()


def test_login_raises_when_no_password(monkeypatch):
    monkeypatch.setenv(_FEATURE_FLAG_ENV, "1")
    _stub_password(monkeypatch, None)
    client = ArcherClient(_min_config())
    _install_fake_httpx(monkeypatch, client)
    with pytest.raises(ArcherAuthError, match="No password stored"):
        client._ensure_token()


# ---------------------------------------------------------------------------
# 401 mid-call → refresh once → retry once
# ---------------------------------------------------------------------------


def test_401_triggers_single_refresh(monkeypatch):
    monkeypatch.setenv(_FEATURE_FLAG_ENV, "1")
    _stub_password(monkeypatch)
    client = ArcherClient(_min_config())
    fake = _install_fake_httpx(monkeypatch, client)

    # Initial login.
    fake.queue(
        "POST",
        "/api/core/security/login",
        _FakeResponse(
            200,
            {
                "IsSuccessful": True,
                "RequestedObject": {"SessionToken": "tok-1"},
            },
        ),
    )
    # First contentsearch → 401 (stale token).
    fake.queue(
        "POST",
        "/api/core/content/contentsearch",
        _FakeResponse(401, text="expired"),
    )
    # Refresh login.
    fake.queue(
        "POST",
        "/api/core/security/login",
        _FakeResponse(
            200,
            {
                "IsSuccessful": True,
                "RequestedObject": {"SessionToken": "tok-2"},
            },
        ),
    )
    # Retried contentsearch → 200, empty.
    fake.queue(
        "POST",
        "/api/core/content/contentsearch",
        _FakeResponse(
            200,
            {"IsSuccessful": True, "RequestedObject": {"Records": []}},
        ),
    )
    # Second empty page completes pagination.
    fake.queue(
        "POST",
        "/api/core/content/contentsearch",
        _FakeResponse(
            200,
            {"IsSuccessful": True, "RequestedObject": {"Records": []}},
        ),
    )

    list(
        client.iter_application_records(
            ArcherApplicationQuery(application_id=75)
        )
    )

    # Two distinct logins happened — first one, then a refresh.
    login_calls = [c for c in fake.calls if c[1] == "/api/core/security/login"]
    assert len(login_calls) == 2
    # Final retried call used the new token.
    final_search = [
        c for c in fake.calls if c[1] == "/api/core/content/contentsearch"
    ][1]
    assert final_search[2]["Authorization"] == 'Archer session-id="tok-2"'


def test_401_after_refresh_propagates(monkeypatch):
    monkeypatch.setenv(_FEATURE_FLAG_ENV, "1")
    _stub_password(monkeypatch)
    client = ArcherClient(_min_config())
    fake = _install_fake_httpx(monkeypatch, client)

    fake.queue(
        "POST",
        "/api/core/security/login",
        _FakeResponse(
            200,
            {
                "IsSuccessful": True,
                "RequestedObject": {"SessionToken": "tok-1"},
            },
        ),
    )
    fake.queue(
        "POST",
        "/api/core/content/contentsearch",
        _FakeResponse(401),
    )
    fake.queue(
        "POST",
        "/api/core/security/login",
        _FakeResponse(
            200,
            {
                "IsSuccessful": True,
                "RequestedObject": {"SessionToken": "tok-2"},
            },
        ),
    )
    fake.queue(
        "POST",
        "/api/core/content/contentsearch",
        _FakeResponse(401, text="still bad"),
    )

    with pytest.raises(ArcherAuthError, match="still 401 after re-login"):
        list(
            client.iter_application_records(
                ArcherApplicationQuery(application_id=75)
            )
        )


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


def test_pagination_walks_until_total(monkeypatch):
    monkeypatch.setenv(_FEATURE_FLAG_ENV, "1")
    _stub_password(monkeypatch)
    cfg = ArcherConfig(
        instance_url="https://archer.example.com",
        instance_name="ProdInstance",
        username="alice",
        queries=(ArcherApplicationQuery(application_id=75),),
        page_size=2,
    )
    client = ArcherClient(cfg)
    fake = _install_fake_httpx(monkeypatch, client)

    fake.queue(
        "POST",
        "/api/core/security/login",
        _FakeResponse(
            200,
            {
                "IsSuccessful": True,
                "RequestedObject": {"SessionToken": "tok"},
            },
        ),
    )
    # Three records total across two pages.
    fake.queue(
        "POST",
        "/api/core/content/contentsearch",
        _FakeResponse(
            200,
            {
                "IsSuccessful": True,
                "RequestedObject": {
                    "Records": [{"Id": 1}, {"Id": 2}],
                    "TotalCount": 3,
                },
            },
        ),
    )
    fake.queue(
        "POST",
        "/api/core/content/contentsearch",
        _FakeResponse(
            200,
            {
                "IsSuccessful": True,
                "RequestedObject": {
                    "Records": [{"Id": 3}],
                    "TotalCount": 3,
                },
            },
        ),
    )

    records = list(
        client.iter_application_records(
            ArcherApplicationQuery(application_id=75)
        )
    )
    assert [r["Id"] for r in records] == [1, 2, 3]
    # Page numbers were 1, then 2 — never re-asked beyond total.
    search_calls = [
        c for c in fake.calls if c[1] == "/api/core/content/contentsearch"
    ]
    assert [c[3]["PageNumber"] for c in search_calls] == [1, 2]


def test_pagination_stops_after_two_empty_pages(monkeypatch):
    # Tenants without TotalCount: walker bails after two consecutive
    # empty pages so a transient empty page mid-walk doesn't truncate.
    monkeypatch.setenv(_FEATURE_FLAG_ENV, "1")
    _stub_password(monkeypatch)
    client = ArcherClient(_min_config())
    fake = _install_fake_httpx(monkeypatch, client)

    fake.queue(
        "POST",
        "/api/core/security/login",
        _FakeResponse(
            200,
            {
                "IsSuccessful": True,
                "RequestedObject": {"SessionToken": "tok"},
            },
        ),
    )
    fake.queue(
        "POST",
        "/api/core/content/contentsearch",
        _FakeResponse(
            200,
            {
                "IsSuccessful": True,
                "RequestedObject": {"Records": [{"Id": 1}]},
            },
        ),
    )
    fake.queue(
        "POST",
        "/api/core/content/contentsearch",
        _FakeResponse(
            200, {"IsSuccessful": True, "RequestedObject": {"Records": []}}
        ),
    )
    fake.queue(
        "POST",
        "/api/core/content/contentsearch",
        _FakeResponse(
            200, {"IsSuccessful": True, "RequestedObject": {"Records": []}}
        ),
    )

    records = list(
        client.iter_application_records(
            ArcherApplicationQuery(application_id=75)
        )
    )
    assert [r["Id"] for r in records] == [1]


def test_pagination_propagates_filter(monkeypatch):
    monkeypatch.setenv(_FEATURE_FLAG_ENV, "1")
    _stub_password(monkeypatch)
    client = ArcherClient(_min_config())
    fake = _install_fake_httpx(monkeypatch, client)

    fake.queue(
        "POST",
        "/api/core/security/login",
        _FakeResponse(
            200,
            {
                "IsSuccessful": True,
                "RequestedObject": {"SessionToken": "tok"},
            },
        ),
    )
    fake.queue(
        "POST",
        "/api/core/content/contentsearch",
        _FakeResponse(
            200,
            {
                "IsSuccessful": True,
                "RequestedObject": {"Records": [], "TotalCount": 0},
            },
        ),
    )

    list(
        client.iter_application_records(
            ArcherApplicationQuery(
                application_id=75,
                content_search_filter="<Filter>x</Filter>",
            )
        )
    )

    search_body = [
        c[3] for c in fake.calls
        if c[1] == "/api/core/content/contentsearch"
    ][0]
    assert search_body["Filter"] == "<Filter>x</Filter>"
    assert search_body["ModuleId"] == 75


# ---------------------------------------------------------------------------
# Source / SourceFile protocol conformance
# ---------------------------------------------------------------------------


def test_source_emits_records_as_sourcefiles(monkeypatch):
    from cybersecurity_assessor.evidence.sources.base import SourceFile

    monkeypatch.setenv(_FEATURE_FLAG_ENV, "1")
    _stub_password(monkeypatch)
    src = ArcherSource(_min_config())
    fake = _install_fake_httpx(monkeypatch, src._client)

    fake.queue(
        "POST",
        "/api/core/security/login",
        _FakeResponse(
            200,
            {
                "IsSuccessful": True,
                "RequestedObject": {"SessionToken": "tok"},
            },
        ),
    )
    fake.queue(
        "POST",
        "/api/core/content/contentsearch",
        _FakeResponse(
            200,
            {
                "IsSuccessful": True,
                "RequestedObject": {
                    "Records": [{"Id": 42, "Title": "ACME Policy"}],
                    "TotalCount": 1,
                },
            },
        ),
    )

    files = list(src.iter_files())
    assert len(files) == 1
    f = files[0]
    # Protocol conformance.
    assert isinstance(f, SourceFile)
    assert f.uri == "archer://ProdInstance/75/42"
    assert f.name == "archer_app75_record42.json"
    assert f.size and f.size > 0
    # Payload is the JSON of the record.
    with f.open() as fh:
        payload = json.loads(fh.read().decode("utf-8"))
    assert payload == {"Id": 42, "Title": "ACME Policy"}


def test_source_iter_blocked_when_flag_off(monkeypatch):
    monkeypatch.delenv(_FEATURE_FLAG_ENV, raising=False)
    src = ArcherSource(_min_config())
    with pytest.raises(ArcherFeatureDisabled):
        list(src.iter_files())


# ---------------------------------------------------------------------------
# test_connection probe
# ---------------------------------------------------------------------------


def test_test_connection_ok_on_login_success(monkeypatch):
    monkeypatch.setenv(_FEATURE_FLAG_ENV, "1")
    _stub_password(monkeypatch)
    client = ArcherClient(_min_config())
    fake = _install_fake_httpx(monkeypatch, client)
    fake.queue(
        "POST",
        "/api/core/security/login",
        _FakeResponse(
            200,
            {
                "IsSuccessful": True,
                "RequestedObject": {"SessionToken": "tok"},
            },
        ),
    )
    result = client.test_connection()
    assert result["ok"] is True
    # Never leaks the password or the token.
    assert "the-password" not in json.dumps(result)
    assert "tok" not in json.dumps(result)


def test_test_connection_disabled_when_flag_off(monkeypatch):
    monkeypatch.delenv(_FEATURE_FLAG_ENV, raising=False)
    client = ArcherClient(_min_config())
    result = client.test_connection()
    # Three pinned invariants: failure, disabled flag, and a non-empty hint
    # that mentions the env var so the Settings card has something to show.
    assert result["ok"] is False
    assert result.get("disabled") is True
    assert _FEATURE_FLAG_ENV in result.get("hint", "")


def test_test_connection_returns_hint_on_auth_error(monkeypatch):
    monkeypatch.setenv(_FEATURE_FLAG_ENV, "1")
    _stub_password(monkeypatch)
    client = ArcherClient(_min_config())
    fake = _install_fake_httpx(monkeypatch, client)
    fake.queue(
        "POST",
        "/api/core/security/login",
        _FakeResponse(401, text="bad creds"),
    )
    result = client.test_connection()
    assert result["ok"] is False
    assert "hint" in result


# ---------------------------------------------------------------------------
# Re-export contract — the package __init__ exposes the public surface
# ---------------------------------------------------------------------------


def test_public_reexports():
    from cybersecurity_assessor.evidence.sources import (
        ArcherApplicationQuery as _Q,
        ArcherConfig as _C,
        ArcherSource as _S,
        archer_feature_enabled as _flag,
    )

    assert _Q is ArcherApplicationQuery
    assert _C is ArcherConfig
    assert _S is ArcherSource
    assert _flag is feature_enabled
