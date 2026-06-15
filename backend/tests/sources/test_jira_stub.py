"""Stub-grade tests for the Jira connector (gated v0.4+ feature).

These tests pin the **public contract** of the Jira connector so a
future v0.4 implementation that wires this up to a live Jira can't
accidentally regress:

* Double-flag gate must refuse construction unless BOTH flags are true.
* JQL is config-bound, not runtime-injectable.
* URI shape encodes ``updated`` so dedupe + update semantics work via
  the existing ``Evidence.path`` key.
* Pagination drains all pages without hand-rolled startAt loops in
  callers.
* ``iter_files`` honours ``max_results_per_query`` so a runaway JQL
  can't dump 80k tickets into the evidence index.
* ``Source`` / ``SourceFile`` Protocol compliance — orchestrator can
  consume ``JiraSource`` uniformly with every other backend.

No network calls — an injected fake client supplies canned issue
dicts in the same shape ``atlassian-python-api`` returns.
"""

from __future__ import annotations

import json

import pytest

from cybersecurity_assessor.evidence.sources import (
    JiraConfig,
    JiraConnectorDisabledError,
    JiraIssueFile,
    JiraSource,
    is_jira_connector_enabled,
    jira_issue_uri,
)
from cybersecurity_assessor.evidence.sources.base import Source, SourceFile


# ---------------------------------------------------------------------------
# Fake client — mimics atlassian.Jira's .jql() pagination shape
# ---------------------------------------------------------------------------


class _FakeJiraClient:
    """Minimal stand-in for ``atlassian.Jira``.

    ``jql_results`` maps a JQL string to the full list of issues to
    return; ``.jql(...)`` slices by ``start``/``limit`` so pagination
    tests run against a realistic-looking transport.
    """

    def __init__(self, jql_results: dict[str, list[dict]]):
        self._results = jql_results
        self.calls: list[dict] = []

    def jql(self, jql: str, *, start: int = 0, limit: int = 50, fields=None):
        self.calls.append({"jql": jql, "start": start, "limit": limit, "fields": fields})
        issues = self._results.get(jql, [])
        page = issues[start : start + limit]
        return {"issues": page, "total": len(issues)}

    def myself(self):
        return {"displayName": "Noah Jaskolski", "name": "njaskolski"}


def _make_issue(key: str, updated: str, **extra) -> dict:
    fields = {"summary": f"Summary for {key}", "updated": updated, "status": {"name": "Done"}}
    fields.update(extra)
    return {"key": key, "fields": fields}


def _enabled_config(queries=None) -> JiraConfig:
    return JiraConfig(
        server_url="https://jira.example.mil",
        pat="fake-pat-xyz",
        queries=tuple(queries or ("project = INC AND type = Incident",)),
    )


# ---------------------------------------------------------------------------
# Double-flag gate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "v04,upcoming,expected",
    [
        (False, False, False),
        (True, False, False),
        (False, True, False),
        (True, True, True),
    ],
)
def test_is_jira_connector_enabled_truth_table(v04, upcoming, expected):
    assert (
        is_jira_connector_enabled(v04_flag=v04, upcoming_gated_flag=upcoming)
        is expected
    )


@pytest.mark.parametrize(
    "v04,upcoming",
    [(False, False), (True, False), (False, True)],
)
def test_constructor_refuses_without_both_flags(v04, upcoming):
    cfg = _enabled_config()
    with pytest.raises(JiraConnectorDisabledError, match="BOTH feature flags"):
        JiraSource(
            cfg,
            v04_flag=v04,
            upcoming_gated_flag=upcoming,
            client=_FakeJiraClient({}),
        )


def test_constructor_succeeds_with_both_flags():
    cfg = _enabled_config()
    src = JiraSource(
        cfg,
        v04_flag=True,
        upcoming_gated_flag=True,
        client=_FakeJiraClient({}),
    )
    assert src.uri.startswith("jira://jira.example.mil/")


# ---------------------------------------------------------------------------
# Config-bound JQL — runtime construction can't smuggle free-form queries
# ---------------------------------------------------------------------------


def test_jql_must_be_supplied_at_config_time():
    # Empty queries list = invalid; route layer cannot supply "" to mean
    # "run anything" — config validation forbids it.
    with pytest.raises(ValueError, match="non-empty"):
        JiraConfig(
            server_url="https://jira.example.mil",
            pat="x",
            queries=(),
        )


def test_from_dict_rejects_missing_queries():
    with pytest.raises(ValueError, match="non-empty"):
        JiraConfig.from_dict({"server_url": "https://jira.example.mil"}, pat="x")


def test_from_dict_rejects_only_empty_strings():
    with pytest.raises(ValueError, match="only empty strings"):
        JiraConfig.from_dict(
            {"server_url": "https://jira.example.mil", "queries": ["", "  "]},
            pat="x",
        )


def test_from_dict_rejects_missing_server_url():
    with pytest.raises(ValueError, match="server_url"):
        JiraConfig.from_dict({"queries": ["project = X"]}, pat="x")


def test_config_queries_are_immutable_tuple():
    cfg = _enabled_config(queries=["a", "b"])
    assert isinstance(cfg.queries, tuple)
    # Frozen dataclass — direct field assignment refused
    with pytest.raises(Exception):
        cfg.queries = ("hacked",)  # type: ignore[misc]


# ---------------------------------------------------------------------------
# URI shape — embeds updated timestamp for dedupe + update semantics
# ---------------------------------------------------------------------------


def test_uri_embeds_updated_timestamp():
    uri = jira_issue_uri("https://jira.example.mil", "INC-42", "2026-06-07T12:00:00.000+0000")
    assert uri.startswith("jira://jira.example.mil/issue/INC-42@")
    assert "2026-06-07T12" in uri


def test_uri_changes_when_updated_changes():
    a = jira_issue_uri("https://jira.example.mil", "INC-42", "2026-06-01T00:00:00.000+0000")
    b = jira_issue_uri("https://jira.example.mil", "INC-42", "2026-06-07T00:00:00.000+0000")
    assert a != b, "URI must differ when updated changes — drives Evidence dedupe vs new-row"


def test_uri_stable_when_updated_unchanged():
    a = jira_issue_uri("https://jira.example.mil", "INC-42", "2026-06-07T00:00:00.000+0000")
    b = jira_issue_uri("https://JIRA.EXAMPLE.MIL/", "INC-42", "2026-06-07T00:00:00.000+0000")
    # Host normalised lower-case + trailing slash stripped → same URI.
    assert a == b


# ---------------------------------------------------------------------------
# iter_files — yields one JiraIssueFile per issue, JSON payload
# ---------------------------------------------------------------------------


def test_iter_files_emits_one_file_per_issue():
    issues = [
        _make_issue("INC-1", "2026-06-01T00:00:00.000+0000"),
        _make_issue("INC-2", "2026-06-02T00:00:00.000+0000"),
        _make_issue("INC-3", "2026-06-03T00:00:00.000+0000"),
    ]
    cfg = _enabled_config(queries=["project = INC"])
    fake = _FakeJiraClient({"project = INC": issues})
    src = JiraSource(cfg, v04_flag=True, upcoming_gated_flag=True, client=fake)

    files = list(src.iter_files())
    assert len(files) == 3
    assert [f.name for f in files] == ["INC-1.json", "INC-2.json", "INC-3.json"]
    for f in files:
        assert f.uri.startswith("jira://jira.example.mil/issue/")
        # Payload round-trips as JSON with key + fields preserved
        decoded = json.loads(f.open().read())
        assert "key" in decoded and "fields" in decoded


def test_iter_files_dedupes_across_queries():
    """Same issue matching two queries should only yield once."""
    shared = _make_issue("INC-1", "2026-06-01T00:00:00.000+0000")
    cfg = _enabled_config(queries=["a", "b"])
    fake = _FakeJiraClient({"a": [shared], "b": [shared]})
    src = JiraSource(cfg, v04_flag=True, upcoming_gated_flag=True, client=fake)
    files = list(src.iter_files())
    assert len(files) == 1


def test_iter_files_skips_issues_with_no_updated():
    bad = {"key": "INC-99", "fields": {"summary": "no updated"}}
    good = _make_issue("INC-1", "2026-06-01T00:00:00.000+0000")
    cfg = _enabled_config(queries=["x"])
    fake = _FakeJiraClient({"x": [bad, good]})
    src = JiraSource(cfg, v04_flag=True, upcoming_gated_flag=True, client=fake)
    files = list(src.iter_files())
    assert [f.name for f in files] == ["INC-1.json"]


# ---------------------------------------------------------------------------
# Pagination — multi-page JQL is fully drained
# ---------------------------------------------------------------------------


def test_pagination_drains_all_pages():
    # 250 issues across 3 pages of 100 (last page short → terminates).
    issues = [
        _make_issue(f"INC-{i}", f"2026-06-01T00:00:0{i % 10}.000+0000")
        for i in range(250)
    ]
    cfg = _enabled_config(queries=["big"])
    fake = _FakeJiraClient({"big": issues})
    src = JiraSource(cfg, v04_flag=True, upcoming_gated_flag=True, client=fake)
    files = list(src.iter_files())
    assert len(files) == 250
    # Caller drove startAt — first call at 0, second at 100, third at 200.
    starts = [c["start"] for c in fake.calls]
    assert starts == [0, 100, 200]


def test_max_results_per_query_caps_walk():
    issues = [
        _make_issue(f"INC-{i}", f"2026-06-01T00:00:0{i % 10}.000+0000")
        for i in range(500)
    ]
    cfg = JiraConfig(
        server_url="https://jira.example.mil",
        pat="x",
        queries=("big",),
        max_results_per_query=42,
    )
    fake = _FakeJiraClient({"big": issues})
    src = JiraSource(cfg, v04_flag=True, upcoming_gated_flag=True, client=fake)
    files = list(src.iter_files())
    assert len(files) == 42


def test_pagination_stops_fetching_when_cap_reached():
    """Don't keep hitting Jira past the cap.

    Reviewer-flagged: with cap=150 and 1000 total issues, the connector
    must stop after page 2 (200 fetched ≥ 150 cap), not slog through 10
    pages. Defensibility: the audit trail's 'we asked Jira for at most
    N issues' claim has to be literally true at the wire level.
    """
    issues = [
        _make_issue(f"INC-{i}", f"2026-06-01T00:00:0{i % 10}.000+0000")
        for i in range(1000)
    ]
    cfg = JiraConfig(
        server_url="https://jira.example.mil",
        pat="x",
        queries=("big",),
        max_results_per_query=150,
    )
    fake = _FakeJiraClient({"big": issues})
    src = JiraSource(cfg, v04_flag=True, upcoming_gated_flag=True, client=fake)
    list(src.iter_files())
    # First two pages requested (startAt 0 + 100); third (startAt 200) MUST NOT fire.
    starts = [c["start"] for c in fake.calls]
    assert starts == [0, 100], (
        f"Pagination kept fetching past cap=150 — actual startAt sequence: {starts}"
    )


# ---------------------------------------------------------------------------
# Protocol compliance — orchestrator can treat JiraSource like any other
# ---------------------------------------------------------------------------


def test_jira_source_is_a_source_protocol():
    cfg = _enabled_config()
    src = JiraSource(cfg, v04_flag=True, upcoming_gated_flag=True, client=_FakeJiraClient({}))
    assert isinstance(src, Source)


def test_jira_issue_file_is_a_source_file_protocol():
    f = JiraIssueFile(
        uri="jira://h/issue/X-1@t",
        name="X-1.json",
        size=10,
        container_uri="jira://h/",
        _payload=b'{"key":"X-1"}',
    )
    assert isinstance(f, SourceFile)
    assert f.open().read() == b'{"key":"X-1"}'


# ---------------------------------------------------------------------------
# Secret hygiene — PAT must not leak into logs / repr
# ---------------------------------------------------------------------------


def test_pat_not_in_default_repr():
    cfg = _enabled_config()
    src = JiraSource(cfg, v04_flag=True, upcoming_gated_flag=True, client=_FakeJiraClient({}))
    # The Source's *uri* must never contain the PAT.
    assert "fake-pat" not in src.uri


def test_pat_not_in_config_repr():
    """JiraConfig.__repr__ MUST NOT include the PAT.

    Reviewer-flagged leak path: a single LOG.info("%r", cfg) or an
    exception that includes ``repr(cfg)`` would otherwise pin the PAT
    into operator logs forever. Pinning here so the ``repr=False``
    field marker can't be silently removed later.
    """
    cfg = _enabled_config()
    rendered = repr(cfg)
    assert "fake-pat" not in rendered, (
        f"PAT leaked through JiraConfig.__repr__: {rendered!r}"
    )
    # Sanity: other fields ARE in the repr so we didn't accidentally
    # disable the whole repr.
    assert "server_url" in rendered
    assert "queries" in rendered


def test_walk_does_not_log_pat(caplog):
    cfg = _enabled_config(queries=["project = X"])
    fake = _FakeJiraClient({"project = X": [_make_issue("X-1", "2026-06-01T00:00:00.000+0000")]})
    src = JiraSource(cfg, v04_flag=True, upcoming_gated_flag=True, client=fake)
    with caplog.at_level("INFO"):
        list(src.iter_files())
    assert "fake-pat" not in caplog.text


# ---------------------------------------------------------------------------
# test_connection — Settings UI probe
# ---------------------------------------------------------------------------


def test_test_connection_ok_when_client_responds():
    cfg = _enabled_config()
    fake = _FakeJiraClient({})
    src = JiraSource(cfg, v04_flag=True, upcoming_gated_flag=True, client=fake)
    result = src.test_connection()
    assert result["ok"] is True
    assert result["account"] == "Noah Jaskolski"
    assert result["queries_configured"] == 1


def test_test_connection_surfaces_error():
    cfg = _enabled_config()

    class _Broken:
        def myself(self):
            raise RuntimeError("401 Unauthorized")

    src = JiraSource(cfg, v04_flag=True, upcoming_gated_flag=True, client=_Broken())
    result = src.test_connection()
    assert result["ok"] is False
    assert "401" in result["error"]
