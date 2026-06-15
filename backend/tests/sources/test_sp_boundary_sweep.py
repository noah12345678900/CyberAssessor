"""Stub tests for the v0.4 SharePoint boundary-sweep connector.

The connector is feature-gated. These tests pin:

* the gating contract (off by default, env-flag enables, ``enabled=`` overrides),
* Source / SourceFile protocol conformance for the public types,
* tier-label parser edge cases (the unit of work behind stale-title detection),
* the external-share summariser's anonymous-link and external-grantee math,
* that the orchestration walk never reaches for *file bytes* — the connector
  is a metadata-only triage path.

Network is never touched: all Graph callers are monkeypatched at
``cybersecurity_assessor.evidence.sources.sp_boundary_sweep`` because that
module re-imports them from ``.sharepoint`` and references them via module
globals.
"""

from __future__ import annotations

import json
import sys
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor.evidence.sources import (  # noqa: E402
    Source,
    SourceFile,
)
from cybersecurity_assessor.evidence.sources import sp_boundary_sweep  # noqa: E402
from cybersecurity_assessor.evidence.sources.sp_boundary_sweep import (  # noqa: E402
    ENV_FLAG,
    BoundaryLocation,
    BoundarySweepCaps,
    BoundarySweepDisabledError,
    SharePointBoundarySweepSource,
    _extract_tier_label,
    is_enabled,
)


# ---------------------------------------------------------------------------
# Feature-flag gating
# ---------------------------------------------------------------------------


def test_is_enabled_default_false(monkeypatch):
    monkeypatch.delenv(ENV_FLAG, raising=False)
    assert is_enabled() is False


@pytest.mark.parametrize("val", ["", "0", "false", "FALSE", "no"])
def test_is_enabled_false_for_non_one_values(monkeypatch, val):
    monkeypatch.setenv(ENV_FLAG, val)
    assert is_enabled() is False


def test_is_enabled_true_for_one(monkeypatch):
    monkeypatch.setenv(ENV_FLAG, "1")
    assert is_enabled() is True


def test_constructor_raises_when_flag_off(monkeypatch):
    monkeypatch.delenv(ENV_FLAG, raising=False)
    with pytest.raises(BoundarySweepDisabledError, match="v0.4"):
        SharePointBoundarySweepSource("https://collab.example.com/sites/x")


def test_constructor_env_flag_enables(monkeypatch):
    monkeypatch.setenv(ENV_FLAG, "1")
    src = SharePointBoundarySweepSource(
        "https://collab.example.com/sites/x"
    )
    assert src.site_url.endswith("/sites/x")
    assert src.library == "Documents"


def test_constructor_explicit_enabled_overrides_env(monkeypatch):
    monkeypatch.delenv(ENV_FLAG, raising=False)
    src = SharePointBoundarySweepSource(
        "https://collab.example.com/sites/x", enabled=True
    )
    assert src.uri.startswith("sharepoint://")


# ---------------------------------------------------------------------------
# Tier-label parser
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        ("T1_some_doc.pdf", "T1"),
        ("Working/T2 Folder", "T2"),
        ("Doc-t3-final.docx", "T3"),
        ("(T1)overview.pdf", "T1"),
        ("plain.pdf", None),  # no tier label
        ("t1_vs_T2_comparison.pdf", None),  # ambiguous — two distinct
        ("StatementT10.docx", None),  # T10 — not a real tier, word-boundary
        ("", None),
    ],
)
def test_extract_tier_label(text, expected):
    assert _extract_tier_label(text) == expected


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


def test_boundary_location_is_sourcefile():
    loc = BoundaryLocation(
        uri="sharepoint://host/sites/x",
        name="x.boundary.json",
        kind="site",
    )
    assert isinstance(loc, SourceFile)


def test_boundary_location_open_yields_json_descriptor():
    loc = BoundaryLocation(
        uri="sharepoint://host/sites/x",
        name="x.boundary.json",
        kind="library",
        container_uri="sharepoint://host/sites/x",
        details={"drive_id": "abc", "drive_type": "documentLibrary"},
    )
    payload = json.loads(loc.open().read().decode("utf-8"))
    assert payload["kind"] == "library"
    assert payload["details"]["drive_id"] == "abc"
    assert payload["uri"].startswith("sharepoint://")


def test_boundary_location_open_is_freshly_seekable():
    """``open()`` returns a new stream each call so retries can re-read."""

    loc = BoundaryLocation(
        uri="sharepoint://host/sites/x",
        name="x.boundary.json",
        kind="site",
    )
    s1 = loc.open()
    s2 = loc.open()
    assert s1 is not s2
    assert s1.read() == s2.read()


def test_source_class_satisfies_source_protocol(monkeypatch):
    monkeypatch.setenv(ENV_FLAG, "1")
    src = SharePointBoundarySweepSource(
        "https://collab.example.com/sites/x"
    )
    # runtime_checkable Protocol — structural conformance.
    assert isinstance(src, Source)


# ---------------------------------------------------------------------------
# Walk semantics — no file bytes ever pulled
# ---------------------------------------------------------------------------


class _FakeResp:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def json(self) -> dict:
        return self._payload


def _wire_fake_graph(monkeypatch, *, responses: dict[str, dict]) -> list[str]:
    """Stand up a recorded fake for the module-level Graph helpers.

    ``responses`` maps a substring of the request URL to the JSON
    payload to return. Returns the list of URLs that were called so
    tests can assert call counts / shapes.
    """

    calls: list[str] = []

    def fake_graph_get(url: str, token: str, *, stream: bool = False):  # noqa: ARG001
        calls.append(url)
        for needle, payload in responses.items():
            if needle in url:
                return _FakeResp(payload)
        return _FakeResp({"value": []})

    def fake_acquire_token(*, endpoint, site_host, on_device_code=None):  # noqa: ARG001
        return "fake-token"

    def fake_resolve_site(graph_base, token, site_url):  # noqa: ARG001
        return {
            "id": "root-site-id",
            "displayName": "Root Site",
            "webUrl": site_url,
        }

    monkeypatch.setattr(sp_boundary_sweep, "_graph_get", fake_graph_get)
    monkeypatch.setattr(sp_boundary_sweep, "acquire_token", fake_acquire_token)
    monkeypatch.setattr(sp_boundary_sweep, "_resolve_site_id", fake_resolve_site)
    return calls


def test_walk_emits_root_site_at_minimum(monkeypatch):
    monkeypatch.setenv(ENV_FLAG, "1")
    calls = _wire_fake_graph(monkeypatch, responses={})
    src = SharePointBoundarySweepSource(
        "https://collab.example.com/sites/x"
    )
    items = list(src.iter_files())
    assert items, "expected at least the root-site BoundaryLocation"
    kinds = {i.kind for i in items}
    assert "site" in kinds
    # No /content URLs — boundary sweep never pulls bytes.
    assert not any("/content" in c for c in calls), calls


def test_walk_emits_library_records(monkeypatch):
    monkeypatch.setenv(ENV_FLAG, "1")
    _wire_fake_graph(
        monkeypatch,
        responses={
            "/sites/root-site-id/sites": {"value": []},
            "/sites/root-site-id/drives": {
                "value": [
                    {
                        "id": "drive-abc",
                        "name": "Documents",
                        "driveType": "documentLibrary",
                        "webUrl": "https://collab.example.com/sites/x/Documents",
                    }
                ]
            },
            "/drives/drive-abc/root/permissions": {"value": []},
            "/drives/drive-abc/root/children": {"value": []},
        },
    )
    src = SharePointBoundarySweepSource(
        "https://collab.example.com/sites/x"
    )
    items = list(src.iter_files())
    libs = [i for i in items if i.kind == "library"]
    assert len(libs) == 1
    assert libs[0].details["drive_id"] == "drive-abc"


def test_walk_emits_external_share_summary_when_anonymous(monkeypatch):
    monkeypatch.setenv(ENV_FLAG, "1")
    _wire_fake_graph(
        monkeypatch,
        responses={
            "/sites/root-site-id/sites": {"value": []},
            "/sites/root-site-id/drives": {
                "value": [
                    {
                        "id": "drive-abc",
                        "name": "Documents",
                        "driveType": "documentLibrary",
                        "webUrl": "https://collab.example.com/sites/x/Documents",
                    }
                ]
            },
            "/drives/drive-abc/root/permissions": {
                "value": [
                    {"link": {"scope": "anonymous"}},
                    {
                        "grantedToV2": {
                            "user": {"email": "outsider@example.com"}
                        }
                    },
                ]
            },
            "/drives/drive-abc/root/children": {"value": []},
        },
    )
    src = SharePointBoundarySweepSource(
        "https://collab.example.com/sites/x"
    )
    items = list(src.iter_files())
    ext = [i for i in items if i.kind == "external_share"]
    assert len(ext) == 1
    summary = ext[0].details["summary"]
    assert summary["anonymous_links"] == 1
    assert "outsider@example.com" in summary["external_grantees"]


def test_walk_detects_stale_tier_titles(monkeypatch):
    monkeypatch.setenv(ENV_FLAG, "1")
    # Folder T2_Working contains a T1_OldPolicy.pdf — mismatch flag.
    _wire_fake_graph(
        monkeypatch,
        responses={
            "/sites/root-site-id/sites": {"value": []},
            "/sites/root-site-id/drives": {
                "value": [
                    {
                        "id": "drive-abc",
                        "name": "Documents",
                        "driveType": "documentLibrary",
                        "webUrl": "https://collab.example.com/sites/x/Documents",
                    }
                ]
            },
            "/drives/drive-abc/root/permissions": {"value": []},
            "/drives/drive-abc/root/children": {
                "value": [
                    {
                        "name": "T2_Working",
                        "folder": {"childCount": 1},
                    }
                ]
            },
            "/drives/drive-abc/root:/T2_Working:/children": {
                "value": [
                    {
                        "name": "T1_OldPolicy.pdf",
                        "webUrl": "https://collab.example.com/sites/x/Documents/T2_Working/T1_OldPolicy.pdf",
                        "parentReference": {
                            "path": "/drive/root:/T2_Working"
                        },
                    },
                    {
                        "name": "T2_NewPolicy.pdf",
                        "webUrl": "https://example/",
                        "parentReference": {
                            "path": "/drive/root:/T2_Working"
                        },
                    },
                ]
            },
        },
    )
    src = SharePointBoundarySweepSource(
        "https://collab.example.com/sites/x"
    )
    items = list(src.iter_files())
    stale = [i for i in items if i.kind == "stale_title"]
    assert len(stale) == 1
    assert stale[0].details["file_tier"] == "T1"
    assert stale[0].details["folder_tier"] == "T2"
    assert "supersed" in stale[0].details["finding"].lower()


def test_walk_honours_subsite_cap(monkeypatch):
    monkeypatch.setenv(ENV_FLAG, "1")
    _wire_fake_graph(
        monkeypatch,
        responses={
            "/sites/root-site-id/sites": {
                "value": [
                    {
                        "id": f"sub-{i}",
                        "displayName": f"Sub {i}",
                        "webUrl": f"https://collab.example.com/sites/x/sub{i}",
                    }
                    for i in range(10)
                ]
            },
            "/drives": {"value": []},
        },
    )
    src = SharePointBoundarySweepSource(
        "https://collab.example.com/sites/x",
        caps=BoundarySweepCaps(max_subsites=3),
    )
    items = list(src.iter_files())
    subs = [i for i in items if i.kind == "subsite"]
    assert len(subs) == 3


def test_walk_survives_graph_auth_error_on_subsites(monkeypatch):
    """A 401 on the subsite listing must not abort the whole walk."""

    monkeypatch.setenv(ENV_FLAG, "1")

    def fake_graph_get(url: str, token: str, *, stream: bool = False):  # noqa: ARG001
        if "/sites/root-site-id/sites" in url:
            raise sp_boundary_sweep.GraphAuthError("401 on subsites")
        return _FakeResp({"value": []})

    monkeypatch.setattr(sp_boundary_sweep, "_graph_get", fake_graph_get)
    monkeypatch.setattr(
        sp_boundary_sweep,
        "acquire_token",
        lambda **_: "fake-token",
    )
    monkeypatch.setattr(
        sp_boundary_sweep,
        "_resolve_site_id",
        lambda *a, **k: {
            "id": "root-site-id",
            "displayName": "Root",
            "webUrl": "https://collab.example.com/sites/x",
        },
    )

    src = SharePointBoundarySweepSource(
        "https://collab.example.com/sites/x"
    )
    items = list(src.iter_files())
    # Root site still surfaces; no subsites; no crash.
    assert any(i.kind == "site" for i in items)
    assert not any(i.kind == "subsite" for i in items)


# ---------------------------------------------------------------------------
# Reviewer-driven hardening — pagination, BFS, URL encoding, allow-list,
# token refresh.
# ---------------------------------------------------------------------------


def test_walk_follows_odata_nextlink_on_subsites(monkeypatch):
    """A multi-page subsite response must surface every page, not just one."""

    monkeypatch.setenv(ENV_FLAG, "1")

    pages = [
        {
            "value": [
                {
                    "id": "sub-1",
                    "displayName": "Sub 1",
                    "webUrl": "https://collab.example.com/sites/x/sub1",
                }
            ],
            "@odata.nextLink": "https://graph.microsoft.us/v1.0/PAGE2",
        },
        {
            "value": [
                {
                    "id": "sub-2",
                    "displayName": "Sub 2",
                    "webUrl": "https://collab.example.com/sites/x/sub2",
                }
            ],
        },
    ]

    state = {"i": 0}

    def fake_graph_get(url: str, token: str, *, stream: bool = False):  # noqa: ARG001
        if "/sites/root-site-id/sites" in url or "PAGE2" in url:
            payload = pages[state["i"]]
            state["i"] = min(state["i"] + 1, len(pages) - 1)
            return _FakeResp(payload)
        return _FakeResp({"value": []})

    monkeypatch.setattr(sp_boundary_sweep, "_graph_get", fake_graph_get)
    monkeypatch.setattr(sp_boundary_sweep, "acquire_token", lambda **_: "tok")
    monkeypatch.setattr(
        sp_boundary_sweep,
        "_resolve_site_id",
        lambda *a, **k: {
            "id": "root-site-id",
            "displayName": "Root",
            "webUrl": "https://collab.example.com/sites/x",
        },
    )

    src = SharePointBoundarySweepSource(
        "https://collab.example.com/sites/x"
    )
    items = list(src.iter_files())
    subs = [i for i in items if i.kind == "subsite"]
    assert {i.details["site_id"] for i in subs} == {"sub-1", "sub-2"}


def test_walk_emits_stale_title_in_untiered_folder(monkeypatch):
    """A T1_ file dropped at the drive root (no folder tier) must flag."""

    monkeypatch.setenv(ENV_FLAG, "1")
    _wire_fake_graph(
        monkeypatch,
        responses={
            "/sites/root-site-id/sites": {"value": []},
            "/sites/root-site-id/drives": {
                "value": [
                    {
                        "id": "drive-abc",
                        "name": "Documents",
                        "driveType": "documentLibrary",
                        "webUrl": "https://collab.example.com/sites/x/Documents",
                    }
                ]
            },
            "/drives/drive-abc/root/permissions": {"value": []},
            # Root has a tiered file but no tiered folder above it.
            "/drives/drive-abc/root/children": {
                "value": [
                    {
                        "name": "T1_OldPolicy.pdf",
                        "webUrl": "https://example/",
                        "parentReference": {"path": "/drive/root:"},
                    },
                ]
            },
        },
    )
    src = SharePointBoundarySweepSource(
        "https://collab.example.com/sites/x"
    )
    items = list(src.iter_files())
    stale = [i for i in items if i.kind == "stale_title"]
    assert len(stale) == 1
    assert stale[0].details["file_tier"] == "T1"
    assert stale[0].details["folder_tier"] is None
    assert "untiered" in stale[0].details["finding"].lower()


def test_stale_title_uri_strips_root_artifact(monkeypatch):
    """parentReference.path starts with ``/drive/root:`` — the URI we emit
    must drop that scheme artifact so it matches the byte-streaming
    connector's canonical ``sharepoint://host/serverRelativeUrl`` shape."""

    monkeypatch.setenv(ENV_FLAG, "1")
    _wire_fake_graph(
        monkeypatch,
        responses={
            "/sites/root-site-id/sites": {"value": []},
            "/sites/root-site-id/drives": {
                "value": [
                    {
                        "id": "drive-abc",
                        "name": "Documents",
                        "driveType": "documentLibrary",
                        "webUrl": "https://collab.example.com/sites/x/Documents",
                    }
                ]
            },
            "/drives/drive-abc/root/permissions": {"value": []},
            "/drives/drive-abc/root/children": {
                "value": [
                    {
                        "name": "T2_Working",
                        "folder": {"childCount": 1},
                    }
                ]
            },
            "/drives/drive-abc/root:/T2_Working:/children": {
                "value": [
                    {
                        "name": "T1_OldPolicy.pdf",
                        "webUrl": "https://example/",
                        "parentReference": {
                            "path": "/drive/root:/T2_Working"
                        },
                    },
                ]
            },
        },
    )
    src = SharePointBoundarySweepSource(
        "https://collab.example.com/sites/x"
    )
    items = list(src.iter_files())
    stale = [i for i in items if i.kind == "stale_title"]
    assert len(stale) == 1
    # No bare "root:" artifact bleeding into the URI.
    assert "root:" not in stale[0].uri


def test_url_encodes_folder_segments_with_spaces_and_amp(monkeypatch):
    """Folder names containing spaces / & / # must be URL-encoded before
    being interpolated into the Graph ``/root:/path:/children`` URL —
    otherwise Graph rejects the request and the whole stale-title pass
    silently emits zero hits."""

    monkeypatch.setenv(ENV_FLAG, "1")
    captured: list[str] = []

    def fake_graph_get(url: str, token: str, *, stream: bool = False):  # noqa: ARG001
        captured.append(url)
        if "/sites/root-site-id/drives" in url:
            return _FakeResp(
                {
                    "value": [
                        {
                            "id": "drive-abc",
                            "name": "Documents",
                            "driveType": "documentLibrary",
                            "webUrl": "https://collab.example.com/sites/x/Documents",
                        }
                    ]
                }
            )
        if "/drives/drive-abc/root/children" in url:
            return _FakeResp(
                {
                    "value": [
                        {
                            "name": "T2 Working & Drafts",
                            "folder": {"childCount": 0},
                        }
                    ]
                }
            )
        return _FakeResp({"value": []})

    monkeypatch.setattr(sp_boundary_sweep, "_graph_get", fake_graph_get)
    monkeypatch.setattr(sp_boundary_sweep, "acquire_token", lambda **_: "tok")
    monkeypatch.setattr(
        sp_boundary_sweep,
        "_resolve_site_id",
        lambda *a, **k: {
            "id": "root-site-id",
            "displayName": "Root",
            "webUrl": "https://collab.example.com/sites/x",
        },
    )

    src = SharePointBoundarySweepSource(
        "https://collab.example.com/sites/x"
    )
    list(src.iter_files())
    # The recursive descent into the spacey folder must show up with a
    # %20 / %26 encoded segment, never a raw space or &.
    sub_urls = [u for u in captured if "T2" in u and ":/children" in u]
    assert sub_urls, captured
    assert all(" " not in u for u in sub_urls), sub_urls
    assert any("%20" in u or "%26" in u for u in sub_urls), sub_urls


def test_external_share_allow_list_filters_internal_emails(monkeypatch):
    """When tenant_email_domains is set, grantees inside the allow-list
    must NOT be counted as external — only outside-domain hits + anon."""

    monkeypatch.setenv(ENV_FLAG, "1")
    _wire_fake_graph(
        monkeypatch,
        responses={
            "/sites/root-site-id/sites": {"value": []},
            "/sites/root-site-id/drives": {
                "value": [
                    {
                        "id": "drive-abc",
                        "name": "Documents",
                        "driveType": "documentLibrary",
                        "webUrl": "https://collab.example.com/sites/x/Documents",
                    }
                ]
            },
            "/drives/drive-abc/root/permissions": {
                "value": [
                    {
                        "grantedToV2": {
                            "user": {"email": "alice@example.com"}
                        }
                    },
                    {
                        "grantedToV2": {
                            "user": {"email": "bob@vendor.example"}
                        }
                    },
                ]
            },
            "/drives/drive-abc/root/children": {"value": []},
        },
    )
    src = SharePointBoundarySweepSource(
        "https://collab.example.com/sites/x",
        tenant_email_domains=("example.com",),
    )
    items = list(src.iter_files())
    ext = [i for i in items if i.kind == "external_share"]
    assert len(ext) == 1
    grantees = ext[0].details["summary"]["external_grantees"]
    assert grantees == ["bob@vendor.example"]
    assert "alice@example.com" not in grantees


def test_token_refresh_retries_once_on_mid_walk_401(monkeypatch):
    """A 401 mid-walk must trigger a single token refresh + retry of the
    failing page. Without this, long sweeps silently truncate when the
    access token expires."""

    monkeypatch.setenv(ENV_FLAG, "1")

    state = {"acquire_calls": 0, "first_perm_call": True}

    def fake_acquire_token(**_kwargs):
        state["acquire_calls"] += 1
        return f"tok-{state['acquire_calls']}"

    def fake_graph_get(url: str, token: str, *, stream: bool = False):  # noqa: ARG001
        if "/sites/root-site-id/sites" in url:
            return _FakeResp({"value": []})
        if "/sites/root-site-id/drives" in url:
            return _FakeResp(
                {
                    "value": [
                        {
                            "id": "drive-abc",
                            "name": "Documents",
                            "driveType": "documentLibrary",
                            "webUrl": "https://collab.example.com/sites/x/Documents",
                        }
                    ]
                }
            )
        if "/drives/drive-abc/root/permissions" in url and state["first_perm_call"]:
            state["first_perm_call"] = False
            raise sp_boundary_sweep.GraphAuthError("401 expired")
        if "/drives/drive-abc/root/permissions" in url:
            return _FakeResp({"value": [{"link": {"scope": "anonymous"}}]})
        return _FakeResp({"value": []})

    monkeypatch.setattr(sp_boundary_sweep, "_graph_get", fake_graph_get)
    monkeypatch.setattr(sp_boundary_sweep, "acquire_token", fake_acquire_token)
    monkeypatch.setattr(sp_boundary_sweep, "_resolve_site_id", lambda *a, **k: {
        "id": "root-site-id",
        "displayName": "Root",
        "webUrl": "https://collab.example.com/sites/x",
    })
    monkeypatch.setattr(sp_boundary_sweep, "clear_token_cache", lambda: True)

    src = SharePointBoundarySweepSource(
        "https://collab.example.com/sites/x"
    )
    items = list(src.iter_files())
    # The retry happened: we got the external-share record despite the
    # initial 401 on permissions.
    ext = [i for i in items if i.kind == "external_share"]
    assert len(ext) == 1
    assert ext[0].details["summary"]["anonymous_links"] == 1
    # Token was re-acquired exactly once (initial + refresh = 2 calls).
    assert state["acquire_calls"] == 2


def test_subsite_listing_cached_no_duplicate_round_trip(monkeypatch):
    """The libraries pass used to re-list subsites — that's a duplicate
    Graph call per walk. Verify the cached path only hits the /sites
    endpoint once even though the subsite list is consumed twice."""

    monkeypatch.setenv(ENV_FLAG, "1")
    calls = _wire_fake_graph(
        monkeypatch,
        responses={
            "/sites/root-site-id/sites": {
                "value": [
                    {
                        "id": "sub-1",
                        "displayName": "Sub 1",
                        "webUrl": "https://collab.example.com/sites/x/sub1",
                    }
                ]
            },
            "/drives": {"value": []},
        },
    )
    src = SharePointBoundarySweepSource(
        "https://collab.example.com/sites/x"
    )
    list(src.iter_files())
    subsite_calls = [c for c in calls if c.endswith("/sites/root-site-id/sites")]
    assert len(subsite_calls) == 1, subsite_calls
