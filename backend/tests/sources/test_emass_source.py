"""Stub tests for the v0.4+ eMASS REST evidence connector.

These pin the contracts the BUILDER brief and reviewer call out:

* Double-flag gate enforcement at constructor time (both flags off,
  one flag off, both on).
* URI scheme ``emass://system/<id>/<artifact>/<rev>`` (and ``rev``
  hash-fallback when eMASS supplies no version token).
* Read-only enforcement at the HTTP layer (GET only; POST/PUT/DELETE
  raise without dispatching the request).
* mTLS credential handling — paths only, never bytes-into-memory; the
  ``EmassFile`` dataclass does not surface cert/key paths.
* ``iter_files`` yields the three artifact files (package, ccis, poams)
  in fixed order and survives per-artifact failures.

Network is never touched — we monkeypatch ``EmassSource._request`` so
the tests can run on a workstation with no eMASS cert.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from cybersecurity_assessor.evidence.sources.emass import (
    EmassConnectorGatedError,
    EmassFile,
    EmassSource,
    _assert_read_only_method,
    emass_uri,
)


# ----------------------------------------------------------------------
# Gate enforcement — both flags must be True
# ----------------------------------------------------------------------


def _kwargs(**overrides: Any) -> dict[str, Any]:
    base = dict(
        base_url="https://emass.example.invalid/api",
        system_id="sys-abc-123",
        cert_path="C:/certs/client.pem",
        key_path="C:/certs/client.key",
        connectors_v04_enabled=True,
        emass_upcoming_gated_enabled=True,
    )
    base.update(overrides)
    return base


def test_constructor_refuses_when_both_flags_off():
    with pytest.raises(EmassConnectorGatedError, match="connectors.v04"):
        EmassSource(
            **_kwargs(
                connectors_v04_enabled=False,
                emass_upcoming_gated_enabled=False,
            )
        )


def test_constructor_refuses_when_v04_off():
    with pytest.raises(EmassConnectorGatedError, match="connectors.v04"):
        EmassSource(**_kwargs(connectors_v04_enabled=False))


def test_constructor_refuses_when_upcoming_gated_off():
    with pytest.raises(EmassConnectorGatedError, match="emass_upcoming_gated"):
        EmassSource(**_kwargs(emass_upcoming_gated_enabled=False))


def test_constructor_accepts_when_both_flags_on():
    src = EmassSource(**_kwargs())
    assert src.system_id == "sys-abc-123"
    assert src.base_url == "https://emass.example.invalid/api"


def test_constructor_requires_base_url():
    with pytest.raises(ValueError, match="base_url"):
        EmassSource(**_kwargs(base_url=""))


def test_constructor_requires_system_id():
    with pytest.raises(ValueError, match="system_id"):
        EmassSource(**_kwargs(system_id=""))


def test_constructor_requires_cert_path():
    with pytest.raises(ValueError, match="cert_path"):
        EmassSource(**_kwargs(cert_path=""))


# ----------------------------------------------------------------------
# Path-only cert handling — bytes never enter memory
# ----------------------------------------------------------------------


def test_cert_for_requests_returns_path_tuple_when_key_set():
    src = EmassSource(**_kwargs())
    cert = src._cert_for_requests
    assert cert == ("C:/certs/client.pem", "C:/certs/client.key")
    # Both elements are str paths, not bytes.
    assert all(isinstance(p, str) for p in cert)


def test_cert_for_requests_returns_single_path_when_no_key():
    src = EmassSource(**_kwargs(key_path=None))
    cert = src._cert_for_requests
    assert cert == "C:/certs/client.pem"
    assert isinstance(cert, str)


def test_emass_file_does_not_expose_cert_paths():
    # The SourceFile carries the JSON payload + URI but never any cert
    # material. Confirm the public dataclass surface has no cert/key.
    f = EmassFile(
        uri="emass://system/x/ccis/r1",
        name="emass-ccis-export.json",
        size=2,
        container_uri="emass://system/x",
        _payload=b"{}",
    )
    public_names = {n for n in vars(f).keys() if not n.startswith("_")}
    assert "cert_path" not in public_names
    assert "key_path" not in public_names


def test_emass_file_repr_excludes_payload_bytes():
    # `_payload` is field(repr=False) so a multi-megabyte POAM blob
    # doesn't land in tracebacks or pytest assertion diffs.
    huge = b"x" * 4096
    f = EmassFile(
        uri="emass://system/x/poams/r1",
        name="emass-poams.json",
        size=len(huge),
        container_uri="emass://system/x",
        _payload=huge,
    )
    r = repr(f)
    assert "xxxx" not in r
    assert "_payload" not in r
    # The size and URI are still visible — those are the useful debug bits.
    assert "emass://system/x/poams/r1" in r


def test_api_key_header_sent_only_when_configured(monkeypatch):
    """When api_key is set, the api-key header reaches requests; absent it,
    only Accept is sent. Reviewer-emass HIGH finding."""
    import sys

    captured: list[dict] = []

    class _Recorder:
        def request(self, method, url, **kw):
            captured.append({"method": method, "headers": dict(kw["headers"])})

            class _Resp:
                ok = True
                text = ""
                status_code = 200

                def json(self):
                    return {"name": "demo"}

            return _Resp()

    monkeypatch.setitem(sys.modules, "requests", _Recorder())

    src_no_key = EmassSource(**_kwargs())
    src_no_key._request("GET", "systems/x")
    assert "api-key" not in captured[-1]["headers"]
    assert captured[-1]["headers"]["Accept"] == "application/json"

    src_with_key = EmassSource(**_kwargs(api_key="tenant-token"))
    src_with_key._request("GET", "systems/x")
    assert captured[-1]["headers"]["api-key"] == "tenant-token"


def test_timeout_is_connect_read_tuple():
    # Single-float timeouts let a TCP blackhole eat the full read budget.
    # Verify we pass a (connect, read) tuple to requests.
    src = EmassSource(**_kwargs())
    assert isinstance(src._timeout, tuple)
    assert len(src._timeout) == 2
    connect, read = src._timeout
    assert connect < read  # connect should fail fast


# ----------------------------------------------------------------------
# Read-only enforcement at the transport layer
# ----------------------------------------------------------------------


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "post"])
def test_read_only_method_rejects_writes(method: str):
    with pytest.raises(EmassConnectorGatedError, match="read-only"):
        _assert_read_only_method(method)


def test_read_only_method_accepts_get():
    # Both casings should be accepted.
    _assert_read_only_method("GET")
    _assert_read_only_method("get")


def test_request_refuses_post_before_dispatch(monkeypatch):
    # If anyone ever calls ._request("POST", ...) directly, the gate must
    # fire BEFORE the requests library is even imported. Sentinel: patch
    # requests to crash if touched.
    import sys

    class _Boom:
        def request(self, *a, **kw):  # pragma: no cover — must not run
            raise AssertionError("requests.request must not be called")

    monkeypatch.setitem(sys.modules, "requests", _Boom())
    src = EmassSource(**_kwargs())
    with pytest.raises(EmassConnectorGatedError, match="read-only"):
        src._request("POST", "systems/x/poams")


# ----------------------------------------------------------------------
# URI shape
# ----------------------------------------------------------------------


def test_emass_uri_canonical_shape():
    assert emass_uri("sys-1", "ccis", "rev-7") == "emass://system/sys-1/ccis/rev-7"


def test_emass_uri_quotes_unsafe_chars():
    # ISO timestamp has colons that aren't URL-safe in a path segment.
    uri = emass_uri("sys-1", "poams", "2026-01-02T03:04:05Z")
    assert ":" not in uri.split("/")[-1]  # rev got percent-encoded
    assert uri.startswith("emass://system/sys-1/poams/")


def test_emass_uri_coerces_non_str_inputs():
    # eMASS sometimes returns numeric system IDs; quote() would TypeError
    # without the str() cast. Reviewer-emass MEDIUM finding.
    uri = emass_uri(12345, "ccis", 7)  # type: ignore[arg-type]
    assert uri == "emass://system/12345/ccis/7"


def test_source_uri_matches_container_root():
    src = EmassSource(**_kwargs())
    assert src.uri == "emass://system/sys-abc-123"


# ----------------------------------------------------------------------
# Payload → bytes + rev token
# ----------------------------------------------------------------------


def test_payload_rev_prefers_last_modified():
    src = EmassSource(**_kwargs())
    payload = {"last_modified": "2026-05-01T00:00:00Z", "rows": [1, 2]}
    blob, rev = src._payload_to_bytes_with_rev(payload, fallback_label="ccis")
    assert rev == "2026-05-01T00:00:00Z"
    assert json.loads(blob)["rows"] == [1, 2]


def test_payload_rev_falls_back_to_revision_then_etag():
    src = EmassSource(**_kwargs())
    _, rev = src._payload_to_bytes_with_rev({"revision": "r-42"}, fallback_label="x")
    assert rev == "r-42"
    _, rev2 = src._payload_to_bytes_with_rev({"etag": "abc"}, fallback_label="x")
    assert rev2 == "abc"


def test_payload_rev_hash_fallback_is_stable_for_same_payload():
    src = EmassSource(**_kwargs())
    p = {"data": [1, 2, 3]}
    _, r1 = src._payload_to_bytes_with_rev(p, fallback_label="ccis")
    _, r2 = src._payload_to_bytes_with_rev(p, fallback_label="ccis")
    assert r1 == r2
    assert r1.startswith("ccis-sha256-")


def test_payload_rev_hash_fallback_differs_for_different_payloads():
    src = EmassSource(**_kwargs())
    _, r1 = src._payload_to_bytes_with_rev({"a": 1}, fallback_label="x")
    _, r2 = src._payload_to_bytes_with_rev({"a": 2}, fallback_label="x")
    assert r1 != r2


def test_payload_rev_ignores_blank_version_fields():
    # Stub eMASS responses sometimes echo back "" for last_modified — we
    # must NOT treat empty string as a valid rev or every fetch collapses
    # to the same URI.
    src = EmassSource(**_kwargs())
    _, rev = src._payload_to_bytes_with_rev(
        {"last_modified": "  ", "rows": [1]}, fallback_label="ccis"
    )
    assert rev.startswith("ccis-sha256-")


# ----------------------------------------------------------------------
# iter_files — yields the three artifacts, survives partial failure
# ----------------------------------------------------------------------


def test_iter_files_yields_three_artifacts(monkeypatch):
    src = EmassSource(**_kwargs())
    calls: list[str] = []

    def fake_request(method: str, path: str) -> Any:
        calls.append(path)
        # The package endpoint has no /ccis or /poams suffix.
        if path.endswith("/ccis"):
            return {"last_modified": "2026-01-01", "controls": []}
        if path.endswith("/poams"):
            return {"last_modified": "2026-01-02", "poams": []}
        return {"name": "Demo System", "system_id": "sys-abc-123"}

    monkeypatch.setattr(src, "_request", fake_request)
    files = list(src.iter_files())
    assert len(files) == 3
    names = [f.name for f in files]
    assert names == [
        "emass-package.json",
        "emass-ccis-export.json",
        "emass-poams.json",
    ]
    # URIs are well-formed and carry the system_id + artifact + rev.
    for f in files:
        assert f.uri.startswith("emass://system/sys-abc-123/")
        assert f.container_uri == "emass://system/sys-abc-123"
        assert f.size is not None and f.size > 0


def test_iter_files_skips_failed_artifact(monkeypatch):
    src = EmassSource(**_kwargs())

    def fake_request(method: str, path: str) -> Any:
        if path.endswith("/ccis"):
            raise RuntimeError("transient 503 from eMASS")
        if path.endswith("/poams"):
            return {"last_modified": "p", "poams": []}
        return {"name": "Demo", "system_id": "sys-abc-123"}

    monkeypatch.setattr(src, "_request", fake_request)
    files = list(src.iter_files())
    names = [f.name for f in files]
    # package + poams survive; ccis is dropped (and a warning logged).
    assert "emass-package.json" in names
    assert "emass-poams.json" in names
    assert "emass-ccis-export.json" not in names


def test_iter_files_raises_when_all_artifacts_fail(monkeypatch):
    """Total auth failure (expired cert, revoked api-key, wrong system_id)
    must surface as an error, not a silent zero-file success. Reviewer-
    emass HIGH finding."""
    src = EmassSource(**_kwargs())

    def always_fail(method: str, path: str) -> Any:
        raise RuntimeError("401 Unauthorized")

    monkeypatch.setattr(src, "_request", always_fail)
    with pytest.raises(RuntimeError, match="0 files"):
        list(src.iter_files())


def test_iter_files_payload_round_trips_through_open(monkeypatch):
    src = EmassSource(**_kwargs())

    def fake_request(method: str, path: str) -> Any:
        return {"name": "X"} if path.endswith("sys-abc-123") else {"rows": []}

    monkeypatch.setattr(src, "_request", fake_request)
    files = list(src.iter_files())
    # open() returns a BinaryIO that yields the canonical JSON bytes.
    for f in files:
        with f.open() as fh:
            data = fh.read()
        # Round-trips as JSON.
        json.loads(data)


# ----------------------------------------------------------------------
# Probe — test_connection wraps _request and never raises
# ----------------------------------------------------------------------


def test_test_connection_happy_path(monkeypatch):
    src = EmassSource(**_kwargs())
    monkeypatch.setattr(
        src, "_request", lambda m, p: {"name": "Demo System", "system_id": "sys-abc-123"}
    )
    result = src.test_connection()
    assert result["ok"] is True
    assert result["system_name"] == "Demo System"
    assert result["system_id"] == "sys-abc-123"


def test_test_connection_returns_ok_false_on_error(monkeypatch):
    src = EmassSource(**_kwargs())

    def boom(method: str, path: str):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(src, "_request", boom)
    result = src.test_connection()
    assert result["ok"] is False
    assert "connection refused" in result["hint"]


# ----------------------------------------------------------------------
# Registration — import path resolves through the package __init__
# ----------------------------------------------------------------------


def test_emass_source_importable_from_package_root():
    from cybersecurity_assessor.evidence.sources import (  # noqa: PLC0415
        EmassConnectorGatedError as ReexportErr,
    )
    from cybersecurity_assessor.evidence.sources import (
        EmassSource as ReexportSrc,
    )
    from cybersecurity_assessor.evidence.sources import (
        emass_uri as reexport_uri,
    )

    assert ReexportSrc is EmassSource
    assert ReexportErr is EmassConnectorGatedError
    assert reexport_uri is emass_uri
