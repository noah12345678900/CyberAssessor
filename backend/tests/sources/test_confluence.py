"""Stub-only tests for the gated Confluence connector surface.

The Confluence Data Center connector is a v0.4 deliverable, double-
gated (``connectors.v04`` AND ``connectors.confluence_upcoming_gated``).
These tests pin:

* the gate posture — construction is unguarded, but iter_files raises
  unless both flags are True,
* the scope-XOR contract — exactly one of ``cql`` or ``space_keys``,
* the URI shape — page-body and attachment URIs both carry an
  ``@<version>`` suffix so a re-walk after an edit produces distinct
  primary keys,
* PAT acquisition order — env var preferred, keyring fallback, neither
  present is a RuntimeError (not a ConfluenceGatedError — credential
  presence is orthogonal to feature gating),
* the lazy fetch closure — open() calls the closure exactly once and
  caches bytes for a second open().

No network is touched — the constructor accepts a ``client`` kwarg for
test injection.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from cybersecurity_assessor.evidence.sources.confluence import (
    ConfluenceFile,
    ConfluenceGatedError,
    ConfluenceSource,
    _get_pat,
    confluence_enabled,
)


# ---------------------------------------------------------------------------
# Feature-flag gate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "flags,expected",
    [
        (None, False),
        ({}, False),
        ({"connectors": {"v04": True}}, False),  # only v04
        ({"connectors": {"confluence_upcoming_gated": True}}, False),  # only upcoming
        (
            {"connectors": {"v04": True, "confluence_upcoming_gated": True}},
            True,
        ),
        # Flat-key shape — some test fixtures and env loaders produce this.
        (
            {
                "connectors.v04": True,
                "connectors.confluence_upcoming_gated": True,
            },
            True,
        ),
        # Half-flat is still off.
        ({"connectors.v04": True}, False),
        # Explicit False beats accidental truthy.
        (
            {"connectors": {"v04": False, "confluence_upcoming_gated": True}},
            False,
        ),
    ],
)
def test_confluence_enabled_requires_both_flags(flags, expected):
    assert confluence_enabled(flags) is expected


def test_iter_files_raises_gated_error_when_flags_off():
    src = ConfluenceSource(
        server_url="https://confluence.example.invalid",
        space_keys=["TEST"],
        flags=None,
        client=object(),  # never reached
    )
    with pytest.raises(ConfluenceGatedError, match="connectors.v04"):
        next(iter(src.iter_files()))


def test_iter_files_raises_when_only_one_flag_set():
    src = ConfluenceSource(
        server_url="https://confluence.example.invalid",
        space_keys=["TEST"],
        flags={"connectors": {"v04": True}},
        client=object(),
    )
    with pytest.raises(ConfluenceGatedError):
        next(iter(src.iter_files()))


def test_construction_is_unguarded_so_settings_card_renders():
    # Constructing with no flags must NOT raise — the Settings UI needs
    # to be able to instantiate the source to render the "not enabled"
    # card. Only iter_files() enforces the gate.
    src = ConfluenceSource(
        server_url="https://confluence.example.invalid",
        space_keys=["TEST"],
        flags=None,
    )
    assert src.server_url == "https://confluence.example.invalid"


# ---------------------------------------------------------------------------
# Scope XOR (cql vs space_keys)
# ---------------------------------------------------------------------------


def test_requires_either_cql_or_space_keys():
    with pytest.raises(ValueError, match="EXACTLY ONE"):
        ConfluenceSource(server_url="https://x.example", flags=None)


def test_rejects_both_cql_and_space_keys():
    with pytest.raises(ValueError, match="EXACTLY ONE"):
        ConfluenceSource(
            server_url="https://x.example",
            cql='label = "foo"',
            space_keys=["BAR"],
            flags=None,
        )


def test_requires_server_url():
    with pytest.raises(ValueError, match="server_url is required"):
        ConfluenceSource(server_url="", space_keys=["TEST"])


# ---------------------------------------------------------------------------
# URI shape
# ---------------------------------------------------------------------------


def test_top_level_uri_for_cql_scope():
    src = ConfluenceSource(
        server_url="https://confluence.example.invalid/",  # trailing slash trimmed
        cql='label = "specification"',
        flags=None,
    )
    assert src.uri == (
        'confluence://confluence.example.invalid/?cql=label = "specification"'
    )


def test_top_level_uri_for_space_scope():
    src = ConfluenceSource(
        server_url="https://confluence.example.invalid",
        space_keys=["ENG", "SEC"],
        flags=None,
    )
    assert src.uri == "confluence://confluence.example.invalid/?spaces=ENG,SEC"


class _FakeClient:
    """Minimal stand-in for atlassian.Confluence — no network."""

    def __init__(self, page=None, attachments=None):
        self._page = page or {}
        self._attachments = attachments or []
        # iter_files reaches into _session for attachment downloads; a
        # stub object suffices because the tests don't actually fetch
        # an attachment body.
        self._session = object()

    def get_all_pages_from_space(self, space, start=0, limit=50):
        if start == 0:
            return [{"id": self._page.get("id", "100")}]
        return []

    def get_page_by_id(self, page_id, expand=None):
        return self._page

    def get_attachments_from_content(self, page_id, limit=200):
        return {"results": self._attachments}


def test_page_uri_carries_version_suffix():
    page = {
        "id": "12345",
        "title": "Hardening Standard",
        "version": {"number": 7},
        "body": {"export_view": {"value": "<p>body</p>"}},
    }
    src = ConfluenceSource(
        server_url="https://confluence.example.invalid",
        space_keys=["ENG"],
        include_attachments=False,
        flags={"connectors": {"v04": True, "confluence_upcoming_gated": True}},
        client=_FakeClient(page=page),
    )
    files = list(src.iter_files())
    assert len(files) == 1
    f = files[0]
    assert f.uri == "confluence://confluence.example.invalid/page/12345@7"
    assert f.name == "Hardening Standard.html"
    # container_uri points at the top-level scope so the orchestrator
    # can group children for provenance.
    assert (
        f.container_uri
        == "confluence://confluence.example.invalid/?spaces=ENG"
    )


def test_attachment_uri_carries_attachment_version_not_page_version():
    page = {
        "id": "12345",
        "title": "Page",
        "version": {"number": 7},
        "body": {"export_view": {"value": ""}},
    }
    attachments = [
        {
            "id": "att-99",
            "title": "diagram.png",
            "version": {"number": 3},
            "extensions": {"fileSize": 4096},
            "_links": {"download": "/download/attachments/12345/att-99?version=3"},
        }
    ]
    src = ConfluenceSource(
        server_url="https://confluence.example.invalid",
        space_keys=["ENG"],
        flags={"connectors": {"v04": True, "confluence_upcoming_gated": True}},
        client=_FakeClient(page=page, attachments=attachments),
    )
    files = list(src.iter_files())
    # body + one attachment
    assert len(files) == 2
    body, att = files
    assert body.uri.endswith("@7")
    # Attachment URI must use the attachment's own version (3), NOT the
    # page version (7) — they bump independently in Confluence.
    assert (
        att.uri
        == "confluence://confluence.example.invalid/page/12345/attachment/att-99@3"
    )
    assert att.name == "diagram.png"
    assert att.size == 4096


def test_version_bump_changes_uri_so_dedupe_treats_it_as_new():
    """Pin the dedupe contract — same page, different version = different URI."""

    def _src_for(version: int) -> ConfluenceSource:
        page = {
            "id": "12345",
            "title": "Hardening Standard",
            "version": {"number": version},
            "body": {"export_view": {"value": ""}},
        }
        return ConfluenceSource(
            server_url="https://confluence.example.invalid",
            space_keys=["ENG"],
            include_attachments=False,
            flags={"connectors": {"v04": True, "confluence_upcoming_gated": True}},
            client=_FakeClient(page=page),
        )

    v1 = list(_src_for(1).iter_files())[0].uri
    v2 = list(_src_for(2).iter_files())[0].uri
    assert v1 != v2
    assert v1.endswith("@1")
    assert v2.endswith("@2")


# ---------------------------------------------------------------------------
# PAT acquisition
# ---------------------------------------------------------------------------


def test_pat_prefers_env_var(monkeypatch):
    monkeypatch.setenv("CONFLUENCE_PAT", "env-token-xyz")
    # Even with a keyring value sitting around, env wins — and the
    # keyring import should never even be attempted.
    with patch(
        "keyring.get_password",
        side_effect=AssertionError("keyring must not be called"),
    ):
        assert _get_pat() == "env-token-xyz"


def test_pat_falls_back_to_keyring(monkeypatch):
    monkeypatch.delenv("CONFLUENCE_PAT", raising=False)
    with patch("keyring.get_password", return_value="kr-token-abc") as kr:
        assert _get_pat() == "kr-token-abc"
    # Service name must come from the canonical config constant, not a
    # hardcoded literal — keeps a future rename to one place.
    from cybersecurity_assessor.config import KEYRING_SERVICE

    kr.assert_called_once_with(KEYRING_SERVICE, "CONFLUENCE_PAT")


def test_pat_missing_raises_runtime_not_gated(monkeypatch):
    monkeypatch.delenv("CONFLUENCE_PAT", raising=False)
    with patch("keyring.get_password", return_value=None):
        with pytest.raises(RuntimeError, match="not configured"):
            _get_pat()


# ---------------------------------------------------------------------------
# ConfluenceFile lazy fetch
# ---------------------------------------------------------------------------


def test_open_calls_fetch_once_and_caches():
    calls = {"n": 0}

    def fetch():
        calls["n"] += 1
        return b"hello"

    f = ConfluenceFile(
        uri="confluence://h/page/1@1",
        name="x.html",
        size=5,
        container_uri="confluence://h/?spaces=X",
        _fetch=fetch,
    )
    assert f.open().read() == b"hello"
    assert f.open().read() == b"hello"
    assert calls["n"] == 1  # second open() served from cache


def test_open_raises_when_no_fetch_closure():
    f = ConfluenceFile(
        uri="confluence://h/page/1@1",
        name="x.html",
        size=0,
        container_uri=None,
        _fetch=None,
    )
    with pytest.raises(RuntimeError, match="no fetch closure"):
        f.open()


def test_open_rejects_non_bytes_fetch():
    f = ConfluenceFile(
        uri="confluence://h/page/1@1",
        name="x.html",
        size=0,
        container_uri=None,
        _fetch=lambda: "not bytes",
    )
    with pytest.raises(RuntimeError, match="expected bytes"):
        f.open()


# ---------------------------------------------------------------------------
# Per-page error isolation + include_attachments toggle
# ---------------------------------------------------------------------------


class _MultiPageFakeClient:
    """Fake that yields 3 page ids but blows up on the second's fetch.

    Pins the contract that a bad page (ACL change between enumeration
    and fetch, missing body, transient 5xx) does not abort the whole
    walk — the iterator skips it and continues to the next id.
    """

    def __init__(self):
        self._session = object()

    def get_all_pages_from_space(self, space, start=0, limit=50):
        if start == 0:
            return [{"id": "1"}, {"id": "2"}, {"id": "3"}]
        return []

    def get_page_by_id(self, page_id, expand=None):
        if page_id == "2":
            raise RuntimeError("simulated 404 / permission change mid-walk")
        return {
            "id": page_id,
            "title": f"page-{page_id}",
            "version": {"number": 1},
            "body": {"export_view": {"value": f"<p>{page_id}</p>"}},
        }

    def get_attachments_from_content(self, page_id, limit=200):
        return {"results": []}


def test_per_page_error_isolation_continues_walk():
    src = ConfluenceSource(
        server_url="https://confluence.example.invalid",
        space_keys=["ENG"],
        include_attachments=False,
        flags={"connectors": {"v04": True, "confluence_upcoming_gated": True}},
        client=_MultiPageFakeClient(),
    )
    files = list(src.iter_files())
    # 3 pages enumerated, page 2 raises and is skipped → 2 surviving files.
    assert len(files) == 2
    uris = [f.uri for f in files]
    assert any(u.endswith("/page/1@1") for u in uris)
    assert any(u.endswith("/page/3@1") for u in uris)
    assert not any(u.endswith("/page/2@1") for u in uris)


def test_include_attachments_false_suppresses_attachment_files():
    """include_attachments=False must skip the attachment fetch entirely,
    even when attachments exist on the page."""
    page = {
        "id": "12345",
        "title": "Page",
        "version": {"number": 1},
        "body": {"export_view": {"value": ""}},
    }
    attachments = [
        {
            "id": "att-1",
            "title": "should-not-appear.png",
            "version": {"number": 1},
            "extensions": {"fileSize": 100},
            "_links": {"download": "/x"},
        }
    ]
    client = _FakeClient(page=page, attachments=attachments)

    # Sanity: with the toggle ON, attachments do appear.
    src_on = ConfluenceSource(
        server_url="https://confluence.example.invalid",
        space_keys=["ENG"],
        include_attachments=True,
        flags={"connectors": {"v04": True, "confluence_upcoming_gated": True}},
        client=client,
    )
    assert len(list(src_on.iter_files())) == 2

    # With the toggle OFF, only the page body.
    src_off = ConfluenceSource(
        server_url="https://confluence.example.invalid",
        space_keys=["ENG"],
        include_attachments=False,
        flags={"connectors": {"v04": True, "confluence_upcoming_gated": True}},
        client=client,
    )
    files = list(src_off.iter_files())
    assert len(files) == 1
    assert "/attachment/" not in files[0].uri
