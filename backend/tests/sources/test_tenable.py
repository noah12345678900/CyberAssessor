"""Stub-only tests for the Tenable evidence connector.

The connector is gated behind a v0.4 feature flag and the real pyTenable
SDK is in the ``sources`` extras (not in the default install), so these
tests use a hand-rolled fake client injected via the constructor's
``_client`` seam. We're pinning the contract pieces that downstream code
relies on: URI stability for dedupe, never logging or echoing secrets,
the feature gate short-circuiting before any network call, and clean
error mapping for 401/429.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from cybersecurity_assessor.evidence.sources.tenable import (
    TENABLE_IO_HOST,
    TenableAuthError,
    TenableRateLimitError,
    TenableScanFile,
    TenableSource,
    _normalize_host,
    _redacted_error_message,
    _sanitize_filename,
    _scan_uri,
)


# ---------------------------------------------------------------------------
# Module-level helper tests — kept first so a regression here surfaces
# before the larger walk fixtures fail in confusing ways.
# ---------------------------------------------------------------------------


class TestNormalizeHost:
    def test_strips_scheme(self):
        assert _normalize_host("https://tenable.example.mil") == "tenable.example.mil"

    def test_lowercases(self):
        assert _normalize_host("https://Tenable.Example.MIL") == "tenable.example.mil"

    def test_handles_bare_hostname(self):
        # Users routinely paste just the hostname; URI must be identical
        # to the schemed form so a Settings edit doesn't reissue URIs.
        assert _normalize_host("tenable.example.mil") == "tenable.example.mil"

    def test_strips_port(self):
        assert _normalize_host("https://tenable.example.mil:8443") == "tenable.example.mil"

    def test_empty_input(self):
        assert _normalize_host("") == ""


class TestScanUri:
    def test_basic_shape(self):
        assert (
            _scan_uri("h.example.mil", 42, 7)
            == "tenable://h.example.mil/scan/42/7"
        )

    def test_int_and_uuid_components_are_stringified(self):
        # Both shapes (int from SC, UUID from io) must produce identical
        # URI form — otherwise dedupe across the two flavors would break.
        sc_uri = _scan_uri("h", 1, 2)
        io_uri = _scan_uri("h", "1", "2")
        assert sc_uri == io_uri == "tenable://h/scan/1/2"


class TestSanitizeFilename:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("Weekly Scan / Prod", "Weekly_Scan_Prod"),
            ("scan:with:colons", "scan_with_colons"),
            ("  .leading.dots.  ", "leading.dots"),
            ("", "scan"),
            ("///", "scan"),
            ("normal-name_1.0", "normal-name_1.0"),
        ],
    )
    def test_collapses_unsafe(self, raw: str, expected: str):
        assert _sanitize_filename(raw) == expected


class TestRedactedErrorMessage:
    def test_scrubs_long_hex(self):
        # 64-char hex secret should be redacted
        secret = "a" * 64
        msg = _redacted_error_message(RuntimeError(f"auth failed key={secret}"))
        assert secret not in msg
        assert "<redacted>" in msg

    def test_scrubs_base64ish(self):
        # 40+ char base64-ish blob
        token = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij0123456789+/="
        msg = _redacted_error_message(RuntimeError(f"401 token={token}"))
        assert token not in msg

    def test_truncates_long_messages(self):
        long = "x" * 1000
        msg = _redacted_error_message(RuntimeError(long))
        assert len(msg) <= 201  # max_len + ellipsis

    def test_handles_empty_exception_message(self):
        msg = _redacted_error_message(RuntimeError(""))
        # Falls back to type name so callers still get something useful.
        assert msg == "RuntimeError"


# ---------------------------------------------------------------------------
# Fake pyTenable client — injected via the constructor's _client seam so
# we never actually call the real SDK during tests.
# ---------------------------------------------------------------------------


class _FakeScans:
    """Mimics enough of pyTenable's ``scans`` surface to drive iter_files."""

    def __init__(
        self,
        list_payload: Any,
        history_map: dict[Any, list[dict[str, Any]]] | None = None,
        export_bytes: bytes = b"<NessusClientData_v2/>",
        list_exc: Exception | None = None,
        export_exc: Exception | None = None,
    ) -> None:
        self._list_payload = list_payload
        self._history_map = history_map or {}
        self._export_bytes = export_bytes
        self._list_exc = list_exc
        self._export_exc = export_exc
        self.export_calls: list[tuple[Any, Any]] = []

    def list(self) -> Any:
        if self._list_exc:
            raise self._list_exc
        return self._list_payload

    def history(self, scan_id: Any) -> list[dict[str, Any]]:
        return self._history_map.get(scan_id, [])

    def export(
        self, scan_id: Any, *, fobj: Any, history_id: Any, format: str
    ) -> None:
        self.export_calls.append((scan_id, history_id))
        if self._export_exc:
            raise self._export_exc
        fobj.write(self._export_bytes)

    def download(self, scan_id: Any, *, fobj: Any, history_id: Any) -> None:
        self.export_calls.append((scan_id, history_id))
        if self._export_exc:
            raise self._export_exc
        fobj.write(self._export_bytes)


class _FakeSession:
    @staticmethod
    def details() -> dict[str, Any]:
        return {"username": "tester@example.mil"}


class _FakeCurrent:
    @staticmethod
    def user() -> dict[str, Any]:
        return {"username": "tester"}


class _FakeIoClient:
    def __init__(self, scans: _FakeScans) -> None:
        self.scans = scans
        self.session = _FakeSession()


class _FakeScClient:
    def __init__(self, scans: _FakeScans) -> None:
        self.scans = scans
        self.current = _FakeCurrent()


def _make_io_source(**kwargs: Any) -> TenableSource:
    defaults = dict(
        flavor="io",
        access_key="ak-test",
        secret_key="sk-test",
        feature_enabled=True,
    )
    defaults.update(kwargs)
    return TenableSource(**defaults)


def _make_sc_source(**kwargs: Any) -> TenableSource:
    defaults = dict(
        flavor="sc",
        host="tenable.example.mil",
        access_key="ak-test",
        secret_key="sk-test",
        feature_enabled=True,
    )
    defaults.update(kwargs)
    return TenableSource(**defaults)


# ---------------------------------------------------------------------------
# Constructor / validation
# ---------------------------------------------------------------------------


class TestConstructorValidation:
    def test_rejects_unknown_flavor(self):
        with pytest.raises(ValueError, match="flavor"):
            TenableSource(
                flavor="invalid",  # type: ignore[arg-type]
                access_key="a",
                secret_key="b",
            )

    def test_sc_requires_host(self):
        with pytest.raises(ValueError, match="host"):
            TenableSource(flavor="sc", access_key="a", secret_key="b")

    def test_io_ignores_host_and_uses_constant(self):
        src = _make_io_source(host="ignored.example.mil")
        assert src.host == TENABLE_IO_HOST

    def test_rejects_empty_access_key(self):
        with pytest.raises(ValueError, match="required"):
            TenableSource(
                flavor="io", access_key="", secret_key="b"
            )

    def test_rejects_empty_secret_key(self):
        with pytest.raises(ValueError, match="required"):
            TenableSource(
                flavor="io", access_key="a", secret_key=""
            )

    def test_min_severity_clamped(self):
        # Out-of-range values shouldn't blow up; just clamp to the legal
        # 0..4 window so the comparison in iter_files stays sane.
        src = _make_io_source(min_severity=99)
        assert src.min_severity == 4
        src = _make_io_source(min_severity=-3)
        assert src.min_severity == 0

    def test_container_uri_is_host_prefix(self):
        src = _make_sc_source()
        assert src.uri == "tenable://tenable.example.mil/"


# ---------------------------------------------------------------------------
# Secret hygiene
# ---------------------------------------------------------------------------


class TestSecretHygiene:
    def test_repr_does_not_leak_keys(self):
        src = _make_io_source(
            access_key="REAL_ACCESS_KEY_aaaaaaaaaaaaaaaaaaaa",
            secret_key="REAL_SECRET_KEY_bbbbbbbbbbbbbbbbbbbb",
        )
        text = repr(src)
        assert "REAL_ACCESS_KEY" not in text
        assert "REAL_SECRET_KEY" not in text
        assert "<redacted>" in text

    def test_no_public_attribute_exposes_secret(self):
        src = _make_io_source(
            access_key="ak-secret", secret_key="sk-secret"
        )
        # Public attrs must not surface the keys (private _access_key /
        # _secret_key are the storage). This guards against accidental
        # later code that copies them into a public field for "convenience".
        for name in dir(src):
            if name.startswith("_"):
                continue
            val = getattr(src, name, None)
            if isinstance(val, str):
                assert "ak-secret" not in val
                assert "sk-secret" not in val


# ---------------------------------------------------------------------------
# Feature flag
# ---------------------------------------------------------------------------


class TestFeatureFlag:
    def test_disabled_yields_nothing(self, caplog):
        # The fake client would crash on list() if it were touched —
        # which guarantees the flag short-circuits BEFORE _ensure_client.
        class _ExplodingScans:
            def list(self):  # pragma: no cover - must not be called
                raise AssertionError("flag-off must not call SDK")

        src = _make_io_source(feature_enabled=False, _client=type("C", (), {"scans": _ExplodingScans()})())
        with caplog.at_level(logging.INFO):
            files = list(src.iter_files())
        assert files == []
        assert any("disabled" in r.message for r in caplog.records)

    def test_enabled_walks(self):
        scans = _FakeScans(
            list_payload=[{"id": 1, "name": "Daily"}],
            history_map={
                1: [{"history_id": "run-a", "status": "completed"}]
            },
        )
        src = _make_io_source(feature_enabled=True, _client=_FakeIoClient(scans))
        out = list(src.iter_files())
        assert len(out) == 1
        assert out[0].uri == "tenable://cloud.tenable.com/scan/1/run-a"


# ---------------------------------------------------------------------------
# URI stability for dedupe
# ---------------------------------------------------------------------------


class TestUriStability:
    def test_same_inputs_same_uri_across_walks(self):
        history = {1: [{"history_id": "run-a", "status": "completed"}]}
        list_payload = [{"id": 1, "name": "Daily"}]

        src1 = _make_io_source(
            _client=_FakeIoClient(_FakeScans(list_payload, history))
        )
        src2 = _make_io_source(
            _client=_FakeIoClient(_FakeScans(list_payload, history))
        )
        uris1 = [f.uri for f in src1.iter_files()]
        uris2 = [f.uri for f in src2.iter_files()]
        assert uris1 == uris2

    def test_sc_and_io_yield_different_uris_for_same_ids(self):
        # Host disambiguates — same scan id 1 / run id 7 on SC must NOT
        # collide with id 1 / 7 on io.
        sc = _make_sc_source(
            _client=_FakeScClient(
                _FakeScans(
                    list_payload={"usable": [{"id": 1, "name": "S"}]},
                    history_map={},
                )
            )
        )
        io = _make_io_source(
            _client=_FakeIoClient(
                _FakeScans(
                    list_payload=[{"id": 1, "name": "S"}],
                    history_map={},
                )
            )
        )
        assert sc.uri != io.uri

    def test_run_id_differentiates_history(self):
        # Two runs of the same scan = two distinct URIs (and two distinct
        # SourceFile rows in the eventual evidence table).
        scans = _FakeScans(
            list_payload=[{"id": 1, "name": "Daily"}],
            history_map={
                1: [
                    {"history_id": "run-a", "status": "completed"},
                    {"history_id": "run-b", "status": "completed"},
                ]
            },
        )
        src = _make_io_source(_client=_FakeIoClient(scans))
        uris = [f.uri for f in src.iter_files()]
        assert uris == [
            "tenable://cloud.tenable.com/scan/1/run-a",
            "tenable://cloud.tenable.com/scan/1/run-b",
        ]

    def test_incomplete_runs_skipped(self):
        # Anything that isn't "completed" must not appear — running scans
        # aren't evidence and would produce a partial export.
        scans = _FakeScans(
            list_payload=[{"id": 1, "name": "Daily"}],
            history_map={
                1: [
                    {"history_id": "run-a", "status": "running"},
                    {"history_id": "run-b", "status": "completed"},
                    {"history_id": "run-c", "status": "aborted"},
                ]
            },
        )
        src = _make_io_source(_client=_FakeIoClient(scans))
        uris = [f.uri for f in src.iter_files()]
        assert uris == ["tenable://cloud.tenable.com/scan/1/run-b"]


# ---------------------------------------------------------------------------
# Lazy fetch
# ---------------------------------------------------------------------------


class TestLazyFetch:
    def test_walk_does_not_call_export(self):
        scans = _FakeScans(
            list_payload=[{"id": 1, "name": "Daily"}],
            history_map={1: [{"history_id": "r1", "status": "completed"}]},
        )
        src = _make_io_source(_client=_FakeIoClient(scans))
        files = list(src.iter_files())
        # iter_files() yields metadata only; export must NOT be hit until
        # someone calls open() on the SourceFile.
        assert scans.export_calls == []
        assert len(files) == 1

    def test_open_triggers_download_once(self):
        scans = _FakeScans(
            list_payload=[{"id": 1, "name": "Daily"}],
            history_map={1: [{"history_id": "r1", "status": "completed"}]},
            export_bytes=b"<nessus/>",
        )
        src = _make_io_source(_client=_FakeIoClient(scans))
        sf = next(iter(src.iter_files()))
        assert sf.open().read() == b"<nessus/>"
        # Re-open should reuse the cache, not call export twice.
        assert sf.open().read() == b"<nessus/>"
        assert len(scans.export_calls) == 1


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------


class _FakeApiError(Exception):
    """Stands in for pyTenable's APIError which exposes .code."""

    def __init__(self, code: int, msg: str = ""):
        super().__init__(msg or f"HTTP {code}")
        self.code = code


class TestErrorMapping:
    def test_401_on_list_raises_auth_error(self):
        scans = _FakeScans(
            list_payload=None,
            list_exc=_FakeApiError(401, "unauthorized"),
        )
        src = _make_io_source(_client=_FakeIoClient(scans))
        with pytest.raises(TenableAuthError, match="rejected"):
            list(src.iter_files())

    def test_429_on_list_raises_rate_limit(self):
        scans = _FakeScans(
            list_payload=None,
            list_exc=_FakeApiError(429, "throttled"),
        )
        src = _make_io_source(_client=_FakeIoClient(scans))
        with pytest.raises(TenableRateLimitError):
            list(src.iter_files())

    def test_other_exception_propagates_raw(self):
        # We don't want to silently bucket unknown errors as auth/rate;
        # the orchestrator's outer try/except can decide.
        scans = _FakeScans(
            list_payload=None, list_exc=RuntimeError("network blew up")
        )
        src = _make_io_source(_client=_FakeIoClient(scans))
        with pytest.raises(RuntimeError, match="network"):
            list(src.iter_files())

    def test_history_failure_skips_scan(self, caplog):
        # A per-scan history failure shouldn't abort the whole walk.
        class _Scans(_FakeScans):
            def history(self, scan_id):
                raise _FakeApiError(500, "internal")

        scans = _Scans(list_payload=[{"id": 1, "name": "Daily"}])
        src = _make_io_source(_client=_FakeIoClient(scans))
        with caplog.at_level(logging.WARNING):
            out = list(src.iter_files())
        assert out == []
        assert any("history fetch failed" in r.message for r in caplog.records)

    def test_export_401_during_open_raises_auth_error(self):
        scans = _FakeScans(
            list_payload=[{"id": 1, "name": "Daily"}],
            history_map={1: [{"history_id": "r1", "status": "completed"}]},
            export_exc=_FakeApiError(401),
        )
        src = _make_io_source(_client=_FakeIoClient(scans))
        sf = next(iter(src.iter_files()))
        with pytest.raises(TenableAuthError):
            sf.open()


# ---------------------------------------------------------------------------
# test_connection probe
# ---------------------------------------------------------------------------


class TestConnectionProbe:
    def test_io_success_returns_username(self):
        scans = _FakeScans(list_payload=[])
        src = _make_io_source(_client=_FakeIoClient(scans))
        result = src.test_connection()
        assert result["ok"] is True
        assert result["flavor"] == "io"
        assert result["host"] == TENABLE_IO_HOST
        assert result["username"] == "tester@example.mil"

    def test_sc_success_returns_username(self):
        scans = _FakeScans(list_payload={"usable": []})
        src = _make_sc_source(_client=_FakeScClient(scans))
        result = src.test_connection()
        assert result["ok"] is True
        assert result["flavor"] == "sc"
        assert result["username"] == "tester"

    def test_auth_failure_returns_clean_payload(self):
        class _AuthFailIo:
            class session:
                @staticmethod
                def details():
                    raise _FakeApiError(401)
            scans = _FakeScans(list_payload=[])

        src = _make_io_source(_client=_AuthFailIo())
        result = src.test_connection()
        assert result["ok"] is False
        assert result["error"] == "auth_failed"
        # Hint must NOT include any echo of the keys we passed.
        assert "ak-test" not in result["hint"]
        assert "sk-test" not in result["hint"]

    def test_unknown_failure_redacts_secrets_in_hint(self):
        secret = "f" * 64

        class _BoomIo:
            class session:
                @staticmethod
                def details():
                    raise RuntimeError(f"unexpected: token={secret}")
            scans = _FakeScans(list_payload=[])

        src = _make_io_source(_client=_BoomIo())
        result = src.test_connection()
        assert result["ok"] is False
        assert result["error"] == "connection_failed"
        assert secret not in result["hint"]


# ---------------------------------------------------------------------------
# SourceFile shape — confirms TenableScanFile satisfies the Protocol
# enough that the orchestrator can drive it.
# ---------------------------------------------------------------------------


class TestSourceFileShape:
    def test_has_required_fields(self):
        sf = TenableScanFile(
            uri="tenable://h/scan/1/2",
            name="Daily.2.nessus",
            size=None,
            container_uri="tenable://h/",
            _fetch=lambda: b"x",
        )
        assert sf.uri == "tenable://h/scan/1/2"
        assert sf.name == "Daily.2.nessus"
        assert sf.container_uri == "tenable://h/"
        # size may be None for Tenable (export size isn't pre-reported)
        assert sf.size is None

    def test_open_returns_seekable_binary_stream(self):
        sf = TenableScanFile(
            uri="tenable://h/scan/1/2",
            name="x.nessus",
            size=None,
            container_uri=None,
            _fetch=lambda: b"hello",
        )
        fh = sf.open()
        assert fh.read() == b"hello"
        fh.seek(0)
        assert fh.read() == b"hello"


# ---------------------------------------------------------------------------
# Filename sanitization in walk — full path through iter_files
# ---------------------------------------------------------------------------


class TestFilenameInWalk:
    def test_unsafe_scan_name_sanitized_in_emitted_file(self):
        scans = _FakeScans(
            list_payload=[{"id": 1, "name": "Weekly / DMZ : prod"}],
            history_map={1: [{"history_id": "r1", "status": "completed"}]},
        )
        src = _make_io_source(_client=_FakeIoClient(scans))
        sf = next(iter(src.iter_files()))
        # No slashes or colons in the filename — those would explode on
        # Windows extractors and double-escape in URLs.
        assert "/" not in sf.name
        assert ":" not in sf.name
        assert sf.name.endswith(".nessus")
