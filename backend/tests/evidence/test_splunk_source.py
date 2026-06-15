"""Splunk saved-search connector — unit tests.

These tests run without a real Splunk instance. They exercise the
SplunkSource against a fake ``splunklib.client.Service`` injected via
the constructor's test hook (``_service_factory``), so the connector
contract — saved-search-only enforcement, token redaction, pagination
bounding, per-search isolation, URI shape, and CSV/JSON rendering —
is validated end-to-end without touching the network.

What we explicitly DON'T test here:

* The splunk-sdk's own HTTP behaviour (its tests, not ours).
* Real Splunk job-lifecycle edge cases — there's a separate integration
  surface for that whose runner is gated behind a live Splunk endpoint.

The fixtures below are minimal: a fake Service that exposes a
``saved_searches[name]`` dict-like mapping, a fake SavedSearch whose
``.dispatch()`` returns a fake Job, and a fake Job whose
``.results()`` returns canned JSON pages.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor.evidence.sources import (  # noqa: E402
    Source,
    SourceFile,
    SplunkResultFile,
    SplunkSource,
)
from cybersecurity_assessor.evidence.sources.splunk import (  # noqa: E402
    _rows_to_csv,
    _rows_to_json,
    _splunk_uri,
    _validate_saved_search_name,
)


# ---------------------------------------------------------------------------
# Fakes — emulate splunklib.client.Service well enough for the connector.
# ---------------------------------------------------------------------------


class _FakeStream:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def close(self) -> None:
        pass


class _FakeJob:
    """A fake Splunk Job whose results pages from a fixed row list."""

    def __init__(self, sid: str, all_rows: list[dict]) -> None:
        self.sid = sid
        self._all_rows = all_rows
        self.cancelled = False

    def is_done(self) -> bool:
        # Always done immediately — we don't want unit tests to sleep.
        return True

    def cancel(self) -> None:
        self.cancelled = True

    def results(self, *, output_mode: str, count: int, offset: int):
        assert output_mode == "json", (
            "Connector should always request JSON internally; "
            "output_format only governs what we WRITE."
        )
        page = self._all_rows[offset : offset + count]
        payload = json.dumps({"results": page}).encode("utf-8")
        return _FakeStream(payload)


class _FakeJobThatHangs(_FakeJob):
    def __init__(self, sid: str) -> None:
        super().__init__(sid, [])

    def is_done(self) -> bool:
        return False


class _FakeSavedSearch:
    def __init__(self, name: str, rows: list[dict], sid: str = "SID-1") -> None:
        self.name = name
        self._rows = rows
        self._sid = sid
        self.dispatched = 0

    def dispatch(self) -> _FakeJob:
        self.dispatched += 1
        return _FakeJob(self._sid, self._rows)


class _ExplodingSavedSearch:
    """A saved search whose dispatch raises mid-walk — used to test isolation."""

    def __init__(self, name: str, exc: Exception) -> None:
        self.name = name
        self._exc = exc

    def dispatch(self):
        raise self._exc


class _FakeSavedSearches(dict):
    """Dict that raises KeyError on miss — same shape as the SDK collection."""

    def __getitem__(self, key):  # noqa: D401
        if key not in self:
            raise KeyError(key)
        return super().__getitem__(key)


class _FakeService:
    def __init__(self, saved: dict[str, object]) -> None:
        self.saved_searches = _FakeSavedSearches(saved)
        # Capture init-style kwargs so tests can assert no leak.
        self.init_kwargs: dict = {}


def _service_factory(saved: dict[str, object]):
    def _build(**kwargs):
        svc = _FakeService(saved)
        svc.init_kwargs = kwargs
        return svc

    return _build


# ---------------------------------------------------------------------------
# Saved-search name validation — defensibility: no raw SPL.
# ---------------------------------------------------------------------------


class TestNameValidation:
    @pytest.mark.parametrize(
        "name",
        [
            "AU Audit Activity",
            "AU-2 logon_failures",
            "IR.escalation/policy.v2",
            "search_with-many.chars(123)",
        ],
    )
    def test_accepts_reasonable_names(self, name: str) -> None:
        assert _validate_saved_search_name(name) == name.strip()

    @pytest.mark.parametrize(
        "name",
        [
            "index=main | stats count by host",  # raw SPL with pipe
            "search foo | head 1",  # pipe again
            "`some_macro(1)`",  # backticks
            "[bracket]",
            "double\"quote",
            "single'quote",
            "",  # empty
            "  ",  # whitespace only
        ],
    )
    def test_rejects_spl_and_garbage(self, name: str) -> None:
        with pytest.raises(ValueError):
            _validate_saved_search_name(name)

    def test_rejects_overlong_name(self) -> None:
        with pytest.raises(ValueError, match="too long"):
            _validate_saved_search_name("a" * 201)


# ---------------------------------------------------------------------------
# Constructor rejection paths — password/username MUST NOT be accepted.
# ---------------------------------------------------------------------------


class TestConstructor:
    def test_rejects_password_kwarg(self) -> None:
        with pytest.raises(ValueError, match="token-based auth only"):
            SplunkSource(
                host="splunk.example",
                token="tok",
                saved_searches=["s1"],
                password="hunter2",
            )

    def test_rejects_username_kwarg(self) -> None:
        with pytest.raises(ValueError, match="token-based auth only"):
            SplunkSource(
                host="splunk.example",
                token="tok",
                saved_searches=["s1"],
                username="admin",
            )

    def test_rejects_empty_saved_searches(self) -> None:
        with pytest.raises(ValueError, match="at least one saved-search name"):
            SplunkSource(
                host="splunk.example",
                token="tok",
                saved_searches=[],
            )

    def test_rejects_spl_in_saved_search_list(self) -> None:
        # Defense in depth: the per-name validator runs during __init__,
        # so a config with a pipe in any one name fails fast.
        with pytest.raises(ValueError, match="disallowed characters"):
            SplunkSource(
                host="splunk.example",
                token="tok",
                saved_searches=["good_name", "index=main | stats count"],
            )

    def test_rejects_bad_output_format(self) -> None:
        with pytest.raises(ValueError, match="output_format"):
            SplunkSource(
                host="splunk.example",
                token="tok",
                saved_searches=["s1"],
                output_format="xml",
            )

    def test_rejects_bad_scheme(self) -> None:
        with pytest.raises(ValueError, match="scheme"):
            SplunkSource(
                host="splunk.example",
                token="tok",
                saved_searches=["s1"],
                scheme="ftp",
            )

    def test_rejects_nonpositive_page_size(self) -> None:
        with pytest.raises(ValueError, match="page_size"):
            SplunkSource(
                host="splunk.example",
                token="tok",
                saved_searches=["s1"],
                page_size=0,
            )

    def test_rejects_nonpositive_max_results(self) -> None:
        with pytest.raises(ValueError, match="max_results_per_search"):
            SplunkSource(
                host="splunk.example",
                token="tok",
                saved_searches=["s1"],
                max_results_per_search=-5,
            )

    def test_rejects_empty_host(self) -> None:
        with pytest.raises(ValueError, match="host"):
            SplunkSource(
                host="",
                token="tok",
                saved_searches=["s1"],
            )

    def test_rejects_empty_token(self) -> None:
        with pytest.raises(ValueError, match="token"):
            SplunkSource(
                host="splunk.example",
                token="",
                saved_searches=["s1"],
            )


# ---------------------------------------------------------------------------
# Token discipline — never in repr / never in exception text.
# ---------------------------------------------------------------------------


class TestTokenRedaction:
    def test_repr_redacts_token(self) -> None:
        src = SplunkSource(
            host="splunk.example",
            token="super-secret-token-do-not-leak",
            saved_searches=["s1"],
        )
        r = repr(src)
        assert "super-secret-token-do-not-leak" not in r
        assert "<redacted>" in r

    def test_str_redacts_token(self) -> None:
        src = SplunkSource(
            host="splunk.example",
            token="super-secret-token-do-not-leak",
            saved_searches=["s1"],
        )
        assert "super-secret-token-do-not-leak" not in str(src)

    def test_token_not_in_exception_on_missing_search(self) -> None:
        secret = "super-secret-token-do-not-leak"
        src = SplunkSource(
            host="splunk.example",
            token=secret,
            saved_searches=["missing_search"],
            _service_factory=_service_factory({}),  # empty — no saved searches
        )
        # iter_files swallows per-search errors and logs; collect what's
        # yielded — should be nothing — and assert the token never
        # shows up via the exception path (we re-run the inner method
        # directly to surface the error message).
        files = list(src.iter_files())
        assert files == []

        service = src._build_service()
        with pytest.raises(RuntimeError) as exc_info:
            src._run_saved_search(service, "missing_search")
        assert secret not in str(exc_info.value)


# ---------------------------------------------------------------------------
# Protocol compliance.
# ---------------------------------------------------------------------------


class TestProtocols:
    def test_source_protocol(self) -> None:
        src = SplunkSource(
            host="splunk.example",
            token="tok",
            saved_searches=["s1"],
        )
        assert isinstance(src, Source)
        assert hasattr(src, "uri")
        assert src.uri.startswith("splunk://splunk.example:8089/search")

    def test_sourcefile_protocol(self) -> None:
        # SplunkResultFile must satisfy SourceFile (uri/name/size/container_uri/open).
        f = SplunkResultFile(
            uri="splunk://saved-search/foo/SID-1",
            name="foo__SID-1.csv",
            size=4,
            container_uri="splunk://splunk.example:8089/search",
            _payload=b"hi\n",
        )
        assert isinstance(f, SourceFile)
        with f.open() as fh:
            assert fh.read() == b"hi\n"


# ---------------------------------------------------------------------------
# End-to-end walk through the fake service.
# ---------------------------------------------------------------------------


class TestWalk:
    def test_yields_one_sourcefile_per_search(self) -> None:
        rows_a = [{"host": f"h{i}", "count": i} for i in range(3)]
        rows_b = [{"host": f"x{i}"} for i in range(2)]
        saved = {
            "AU search": _FakeSavedSearch("AU search", rows_a, sid="SID-A"),
            "IR search": _FakeSavedSearch("IR search", rows_b, sid="SID-B"),
        }
        src = SplunkSource(
            host="splunk.example",
            token="tok",
            saved_searches=["AU search", "IR search"],
            _service_factory=_service_factory(saved),
        )
        files = list(src.iter_files())
        assert len(files) == 2
        names = [f.name for f in files]
        assert names[0].startswith("AU_search__SID-A")
        assert names[1].startswith("IR_search__SID-B")
        # URI uses the original (un-sanitized) saved-search name; spaces
        # are percent-encoded by quote(safe="").
        assert files[0].uri.startswith("splunk://saved-search/AU%20search/SID-A")
        assert files[1].uri.startswith("splunk://saved-search/IR%20search/SID-B")
        # container_uri groups them under the connector instance.
        assert files[0].container_uri == src.uri
        assert files[1].container_uri == src.uri

    def test_csv_payload_round_trips(self) -> None:
        rows = [
            {"host": "h1", "count": 1},
            {"host": "h2", "count": 2, "extra": "x"},
        ]
        saved = {"s": _FakeSavedSearch("s", rows, sid="SID-1")}
        src = SplunkSource(
            host="splunk.example",
            token="tok",
            saved_searches=["s"],
            output_format="csv",
            _service_factory=_service_factory(saved),
        )
        (file,) = list(src.iter_files())
        body = file.open().read().decode("utf-8")
        # Column union, sorted for determinism.
        first_line = body.splitlines()[0]
        assert first_line.split(",") == ["count", "extra", "host"]
        assert "h1" in body and "h2" in body
        assert "# truncated" not in body
        assert file.name.endswith(".csv")

    def test_json_payload_round_trips(self) -> None:
        rows = [{"host": "h1"}]
        saved = {"s": _FakeSavedSearch("s", rows, sid="SID-1")}
        src = SplunkSource(
            host="splunk.example",
            token="tok",
            saved_searches=["s"],
            output_format="json",
            _service_factory=_service_factory(saved),
        )
        (file,) = list(src.iter_files())
        doc = json.loads(file.open().read())
        assert doc == {"results": rows, "truncated": False, "count": 1}
        assert file.name.endswith(".json")

    def test_pagination_respects_max_results(self) -> None:
        # 250 source rows, page=50, cap=100 → truncate at 100.
        rows = [{"i": i} for i in range(250)]
        saved = {"s": _FakeSavedSearch("s", rows, sid="SID-1")}
        src = SplunkSource(
            host="splunk.example",
            token="tok",
            saved_searches=["s"],
            output_format="json",
            page_size=50,
            max_results_per_search=100,
            _service_factory=_service_factory(saved),
        )
        (file,) = list(src.iter_files())
        doc = json.loads(file.open().read())
        assert doc["count"] == 100
        assert doc["truncated"] is True

    def test_pagination_short_circuits_on_partial_page(self) -> None:
        # 7 rows, page=10, cap=1000 → one page, no truncation marker.
        rows = [{"i": i} for i in range(7)]
        saved = {"s": _FakeSavedSearch("s", rows, sid="SID-1")}
        src = SplunkSource(
            host="splunk.example",
            token="tok",
            saved_searches=["s"],
            output_format="json",
            page_size=10,
            _service_factory=_service_factory(saved),
        )
        (file,) = list(src.iter_files())
        doc = json.loads(file.open().read())
        assert doc["count"] == 7
        assert doc["truncated"] is False

    def test_one_failed_search_does_not_abort_walk(self) -> None:
        # First search raises; second one returns rows. iter_files must
        # log and continue, not abort.
        ok_rows = [{"host": "h1"}]
        saved = {
            "boom": _ExplodingSavedSearch("boom", RuntimeError("kaboom")),
            "ok": _FakeSavedSearch("ok", ok_rows, sid="SID-OK"),
        }
        src = SplunkSource(
            host="splunk.example",
            token="tok",
            saved_searches=["boom", "ok"],
            output_format="json",
            _service_factory=_service_factory(saved),
        )
        files = list(src.iter_files())
        # Only the ok one survives.
        assert len(files) == 1
        assert files[0].name.startswith("ok__SID-OK")

    def test_missing_saved_search_is_skipped(self) -> None:
        # ``missing`` isn't in the fake service's saved_searches dict —
        # the connector should treat that as a per-search skip, not a
        # walk-fatal error.
        saved = {"ok": _FakeSavedSearch("ok", [{"x": 1}], sid="SID-OK")}
        src = SplunkSource(
            host="splunk.example",
            token="tok",
            saved_searches=["missing", "ok"],
            output_format="json",
            _service_factory=_service_factory(saved),
        )
        files = list(src.iter_files())
        assert len(files) == 1
        assert "ok" in files[0].name


# ---------------------------------------------------------------------------
# URI shape — assessor needs the exact format documented in the connector
# docstring so audit links resolve back to the right Splunk job.
# ---------------------------------------------------------------------------


class TestUri:
    def test_uri_format(self) -> None:
        uri = _splunk_uri("AU search/v1", "SID-1234")
        # Spaces and slashes must be percent-encoded for path safety.
        assert uri == "splunk://saved-search/AU%20search%2Fv1/SID-1234"

    def test_uri_round_trip_in_emitted_file(self) -> None:
        saved = {"AU.v1": _FakeSavedSearch("AU.v1", [{"x": 1}], sid="SID-X")}
        src = SplunkSource(
            host="splunk.example",
            token="tok",
            saved_searches=["AU.v1"],
            _service_factory=_service_factory(saved),
        )
        (file,) = list(src.iter_files())
        assert file.uri == "splunk://saved-search/AU.v1/SID-X"


# ---------------------------------------------------------------------------
# Pure rendering helpers — independent unit coverage.
# ---------------------------------------------------------------------------


class TestRendering:
    def test_csv_empty_no_truncation(self) -> None:
        assert _rows_to_csv([], truncated=False) == b""

    def test_csv_empty_with_truncation(self) -> None:
        assert _rows_to_csv([], truncated=True) == b"# truncated\n"

    def test_csv_multivalue_joined_with_newlines(self) -> None:
        out = _rows_to_csv(
            [{"tags": ["a", "b", "c"]}], truncated=False
        ).decode("utf-8")
        # csv quotes the cell because of the embedded newlines.
        assert "a\nb\nc" in out

    def test_csv_none_becomes_empty(self) -> None:
        out = _rows_to_csv(
            [{"host": "h1", "extra": None}], truncated=False
        ).decode("utf-8")
        # extra column present, value empty.
        lines = out.splitlines()
        assert lines[0] == "extra,host"
        assert lines[1] == ",h1"

    def test_json_shape(self) -> None:
        out = _rows_to_json([{"x": 1}], truncated=True)
        doc = json.loads(out)
        assert doc == {"results": [{"x": 1}], "truncated": True, "count": 1}

    def test_csv_column_order_is_deterministic(self) -> None:
        # Same rows in different insertion order ⇒ same bytes out.
        a = _rows_to_csv([{"z": 1, "a": 2}, {"m": 3}], truncated=False)
        b = _rows_to_csv([{"m": 3}, {"a": 2, "z": 1}], truncated=False)
        # Headers will be identical (sorted union); row data differs in
        # order so we only assert the header line is stable.
        assert a.splitlines()[0] == b.splitlines()[0]
        assert a.splitlines()[0] == b"a,m,z"


# ---------------------------------------------------------------------------
# Feature flag — connector must remain inert in default config.
# ---------------------------------------------------------------------------


def test_enable_splunk_defaults_off() -> None:
    from cybersecurity_assessor.config import AppConfig

    cfg = AppConfig()
    assert cfg.enable_splunk is False, (
        "v0.4 connector must default off — opt-in only."
    )


# ---------------------------------------------------------------------------
# TLS posture — verify=False must be loud (warning + WARNING log line) so
# an operator can't silently ship a connector that's accepting any cert.
# ---------------------------------------------------------------------------


class TestTlsWarning:
    def test_verify_false_emits_warning(self) -> None:
        with pytest.warns(UserWarning, match="verify=False"):
            SplunkSource(
                host="splunk.example",
                token="tok",
                saved_searches=["s1"],
                verify=False,
            )

    def test_verify_true_does_not_warn(self, recwarn) -> None:
        SplunkSource(
            host="splunk.example",
            token="tok",
            saved_searches=["s1"],
            verify=True,
        )
        # No verify-related warning should fire on the safe default.
        assert not any("verify=False" in str(w.message) for w in recwarn.list)
