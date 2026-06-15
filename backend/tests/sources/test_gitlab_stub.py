"""Stub tests for the GitLab evidence connector (v0.4, feature-gated).

The real connector talks to a self-hosted GitLab instance and uses the
``python-gitlab`` package. These tests pin the *contracts* that the rest
of the app relies on (Source / SourceFile protocol shape, URI encoding,
glob filter, token resolution precedence, retry / error surfaces) using
mocked python-gitlab handles so the suite runs offline.

Anything that requires a live GitLab is out of scope here; the live
matrix lives in ``pytest -m live_gitlab`` (planned alongside the v0.4
release once a sandbox project URL is available in CI).
"""

from __future__ import annotations

import os
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from cybersecurity_assessor.evidence.sources import GitLabSource
from cybersecurity_assessor.evidence.sources.base import Source, SourceFile
from cybersecurity_assessor.evidence.sources.gitlab import (
    _FILE_SIZE_CAP_BYTES,
    _RETRY_AFTER_CAP_SECONDS,
    GitLabFile,
    _delay_for_attempt,
    _glob_match,
    _gitlab_uri,
    _keyring_key_for_host,
    get_gitlab_token,
)


# ----------------------------------------------------------------------
# Constructor — input validation
# ----------------------------------------------------------------------


def test_constructor_requires_server_url():
    with pytest.raises(ValueError, match="server_url"):
        GitLabSource(server_url="", project_paths=["g/p"])


def test_constructor_requires_at_least_one_project():
    with pytest.raises(ValueError, match="project_path"):
        GitLabSource(server_url="https://gitlab.example", project_paths=[])


def test_constructor_strips_trailing_slash_and_derives_host():
    src = GitLabSource(
        server_url="https://gitlab.example.com/",
        project_paths=["group/repo"],
    )
    assert src.server_url == "https://gitlab.example.com"
    assert src._host == "gitlab.example.com"


def test_constructor_defaults_ref_to_head():
    src = GitLabSource(server_url="https://gl.x", project_paths=["g/p"])
    assert src.ref == "HEAD"


def test_constructor_accepts_custom_globs():
    src = GitLabSource(
        server_url="https://gl.x",
        project_paths=["g/p"],
        include_globs=("*.ini",),
    )
    assert src.include_globs == ("*.ini",)


def test_constructor_top_level_uri_describes_source():
    src = GitLabSource(
        server_url="https://gitlab.sda-oi.example",
        project_paths=["a/b", "c/d"],
    )
    assert src.uri == "gitlab://gitlab.sda-oi.example/?projects=2"


# ----------------------------------------------------------------------
# Protocol compliance — duck typing via runtime-checkable Protocol
# ----------------------------------------------------------------------


def test_gitlab_source_satisfies_source_protocol():
    src = GitLabSource(server_url="https://gl.x", project_paths=["g/p"])
    # runtime_checkable Source only inspects ``uri`` + ``iter_files``;
    # our class supplies both.
    assert isinstance(src, Source)


def test_gitlab_file_satisfies_sourcefile_protocol():
    f = GitLabFile(
        uri="gitlab://x/g/p@abc/foo.ckl",
        name="foo.ckl",
        size=None,
        container_uri="gitlab://x/g/p@abc",
        _project=MagicMock(),
        _file_path="foo.ckl",
        _commit_sha="abc",
    )
    assert isinstance(f, SourceFile)


# ----------------------------------------------------------------------
# URI rendering — re-ingest semantics depend on this exact shape
# ----------------------------------------------------------------------


def test_uri_pins_commit_sha_between_project_and_path():
    uri = _gitlab_uri(
        host="gitlab.example",
        project_path="group/subgroup/repo",
        commit_sha="abc1234deadbeef",
        file_path="evidence/foo.ckl",
    )
    assert uri == "gitlab://gitlab.example/group/subgroup/repo@abc1234deadbeef/evidence/foo.ckl"


def test_uri_keeps_slashes_in_project_and_file_paths():
    uri = _gitlab_uri("h", "a/b/c", "sha", "x/y/z.txt")
    assert "/a/b/c@" in uri
    assert "@sha/x/y/z.txt" in uri


def test_uri_encodes_spaces_in_file_path():
    uri = _gitlab_uri("h", "g/p", "sha", "my dir/firewall config.conf")
    assert "my%20dir/firewall%20config.conf" in uri


def test_same_sha_same_uri_means_dedupe_works():
    # Re-ingest at unchanged SHA must yield byte-identical URI so the
    # orchestrator's hash short-circuit fires.
    u1 = _gitlab_uri("h", "g/p", "abc1234", "foo.ckl")
    u2 = _gitlab_uri("h", "g/p", "abc1234", "foo.ckl")
    assert u1 == u2


def test_new_sha_new_uri_means_new_evidence_row():
    u1 = _gitlab_uri("h", "g/p", "abc1234", "foo.ckl")
    u2 = _gitlab_uri("h", "g/p", "def5678", "foo.ckl")
    assert u1 != u2


# ----------------------------------------------------------------------
# Glob filter
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("U_Win10_STIG_V2R5.ckl", True),
        ("nessus_scan.cklb", True),
        ("firewall.conf", True),
        ("baseline.cfg", True),
        ("clamav.log", True),
        ("inventory.json", True),
        ("playbook.yaml", True),
        ("README.md", True),
        ("policy.pdf", True),
        ("source.py", False),  # not in default set — would flood ingest
        ("Dockerfile", False),
        ("image.png", False),
    ],
)
def test_default_globs_match_evidence_types_not_source_code(name: str, expected: bool):
    from cybersecurity_assessor.evidence.sources.gitlab import _DEFAULT_INCLUDE_GLOBS

    assert _glob_match(name, _DEFAULT_INCLUDE_GLOBS) is expected


def test_glob_match_is_case_insensitive():
    assert _glob_match("Foo.CKL", ("*.ckl",))
    assert _glob_match("BASELINE.Conf", ("*.conf",))


# ----------------------------------------------------------------------
# Token resolution — env first, keyring second, None if neither
# ----------------------------------------------------------------------


def test_env_var_token_takes_precedence(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "env-token-xyz")
    assert get_gitlab_token("https://gitlab.example") == "env-token-xyz"


def test_falls_back_to_keyring_when_env_unset(monkeypatch):
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    fake_keyring = MagicMock()
    fake_keyring.get_password.return_value = "keyring-token-abc"
    with patch.dict("sys.modules", {"keyring": fake_keyring}):
        token = get_gitlab_token("https://gitlab.example")
    assert token == "keyring-token-abc"
    fake_keyring.get_password.assert_called_once_with(
        "cybersecurity-assessor", _keyring_key_for_host("gitlab.example")
    )


def test_returns_none_when_neither_env_nor_keyring(monkeypatch):
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    fake_keyring = MagicMock()
    fake_keyring.get_password.return_value = None
    with patch.dict("sys.modules", {"keyring": fake_keyring}):
        assert get_gitlab_token("https://gitlab.example") is None


def test_keyring_exception_does_not_crash(monkeypatch):
    """Locked-down workstations may raise on keyring access. We must
    swallow the exception and return None so the Settings probe can
    report 'not configured' rather than 500."""
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    fake_keyring = MagicMock()
    fake_keyring.get_password.side_effect = RuntimeError("DBus refused")
    with patch.dict("sys.modules", {"keyring": fake_keyring}):
        assert get_gitlab_token("https://gitlab.example") is None


def test_per_host_keyring_slot_sanitizes_host():
    # Multiple GitLab instances should map to distinct slots.
    a = _keyring_key_for_host("gitlab.sda-oi.example")
    b = _keyring_key_for_host("gitlab.corp.example")
    assert a != b
    assert a.startswith("GITLAB_TOKEN__")
    # No path-traversal-ish chars survive sanitization.
    weird = _keyring_key_for_host("evil/../host:8080")
    assert "/" not in weird
    assert ":" not in weird
    assert ".." not in weird or "_" in weird  # dots collapse fine, slashes do not


# ----------------------------------------------------------------------
# Token contract — never persisted in plain config / returned
# ----------------------------------------------------------------------


def test_source_does_not_accept_raw_token_argument():
    # Constructor signature deliberately omits a `token=` kwarg so callers
    # can't smuggle plaintext tokens through the source instance.
    import inspect

    sig = inspect.signature(GitLabSource.__init__)
    assert "token" not in sig.parameters
    assert "private_token" not in sig.parameters


# ----------------------------------------------------------------------
# Lazy client init — constructor must not touch the network
# ----------------------------------------------------------------------


def test_constructor_does_not_create_client():
    src = GitLabSource(server_url="https://gl.x", project_paths=["g/p"])
    assert src._gl is None
    assert src._token_acquired is False


def test_client_raises_clearly_when_no_token(monkeypatch):
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    fake_keyring = MagicMock()
    fake_keyring.get_password.return_value = None
    src = GitLabSource(server_url="https://gl.x", project_paths=["g/p"])
    fake_gitlab = MagicMock()
    with (
        patch.dict("sys.modules", {"keyring": fake_keyring, "gitlab": fake_gitlab}),
        pytest.raises(RuntimeError, match="No GitLab token found"),
    ):
        src._client()


def test_iter_files_raises_with_helpful_error_when_python_gitlab_missing(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "tok")
    src = GitLabSource(server_url="https://gl.x", project_paths=["g/p"])
    # Force the import inside _client to fail.
    with patch.dict("sys.modules", {"gitlab": None}):
        with pytest.raises(ImportError, match="python-gitlab"):
            src._client()


# ----------------------------------------------------------------------
# test_connection — UI-shaped error path
# ----------------------------------------------------------------------


def test_test_connection_returns_error_dict_when_no_token(monkeypatch):
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    fake_keyring = MagicMock()
    fake_keyring.get_password.return_value = None
    src = GitLabSource(server_url="https://gl.x", project_paths=["g/p"])
    with patch.dict("sys.modules", {"keyring": fake_keyring, "gitlab": MagicMock()}):
        result = src.test_connection()
    assert result["ok"] is False
    assert "error" in result
    assert result["server_url"] == "https://gl.x"


def test_test_connection_happy_path(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "tok")
    fake_gl_module = MagicMock()
    fake_client = MagicMock()
    fake_gl_module.Gitlab.return_value = fake_client
    fake_project = MagicMock()
    fake_project.default_branch = "main"
    fake_commit = MagicMock()
    fake_commit.id = "deadbeef" * 5
    fake_project.commits.get.return_value = fake_commit
    fake_client.projects.get.return_value = fake_project
    fake_client.user.username = "noah"
    # Make exceptions importable from the mock module too — _retryable
    # imports `gitlab` to type-check auth errors.
    fake_gl_module.exceptions.GitlabAuthenticationError = type(
        "GitlabAuthenticationError", (Exception,), {}
    )

    src = GitLabSource(server_url="https://gl.x", project_paths=["g/p"])
    with patch.dict("sys.modules", {"gitlab": fake_gl_module}):
        result = src.test_connection()

    assert result["ok"] is True
    assert result["user"] == "noah"
    assert result["projects"][0]["ok"] is True
    assert result["projects"][0]["commit_sha"] == "deadbeef" * 5


# ----------------------------------------------------------------------
# iter_files — happy path with mocked python-gitlab
# ----------------------------------------------------------------------


def test_iter_files_yields_only_glob_matches_at_pinned_sha(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "tok")
    fake_gl_module = MagicMock()
    fake_client = MagicMock()
    fake_gl_module.Gitlab.return_value = fake_client
    fake_gl_module.exceptions.GitlabAuthenticationError = type(
        "GitlabAuthenticationError", (Exception,), {}
    )

    fake_project = MagicMock()
    fake_project.default_branch = "main"
    fake_commit = MagicMock()
    fake_commit.id = "abc1234" + "0" * 33
    fake_project.commits.get.return_value = fake_commit
    fake_project.repository_tree.return_value = iter(
        [
            {"type": "blob", "path": "stigs/win.ckl"},
            {"type": "blob", "path": "src/main.py"},  # filtered out
            {"type": "blob", "path": "fw/edge.conf"},
            {"type": "tree", "path": "fw"},  # not a blob
            {"type": "blob", "path": ".hidden"},  # dotfile
        ]
    )
    fake_project.files.raw.return_value = b"data"
    fake_client.projects.get.return_value = fake_project

    src = GitLabSource(
        server_url="https://gitlab.example",
        project_paths=["group/repo"],
    )
    with patch.dict("sys.modules", {"gitlab": fake_gl_module}):
        files = list(src.iter_files())

    names = sorted(f.name for f in files)
    assert names == ["edge.conf", "win.ckl"]
    # URI pin contract
    assert all(f._commit_sha == "abc1234" + "0" * 33 for f in files)
    assert all(f.container_uri.endswith("@" + "abc1234" + "0" * 33) for f in files)
    # Top-level URI scheme
    assert all(f.uri.startswith("gitlab://gitlab.example/group/repo@") for f in files)


def test_iter_files_tolerates_one_bad_project(monkeypatch):
    """One bad project doesn't sink the whole walk."""
    monkeypatch.setenv("GITLAB_TOKEN", "tok")
    fake_gl_module = MagicMock()
    fake_client = MagicMock()
    fake_gl_module.Gitlab.return_value = fake_client
    fake_gl_module.exceptions.GitlabAuthenticationError = type(
        "GitlabAuthenticationError", (Exception,), {}
    )

    good_project = MagicMock()
    good_project.default_branch = "main"
    good_commit = MagicMock()
    good_commit.id = "g" * 40
    good_project.commits.get.return_value = good_commit
    good_project.repository_tree.return_value = iter(
        [{"type": "blob", "path": "ok.ckl"}]
    )

    def projects_get(path: str):
        if path == "bad/repo":
            raise RuntimeError("404 project not found")
        return good_project

    fake_client.projects.get.side_effect = projects_get

    src = GitLabSource(
        server_url="https://gl.x", project_paths=["bad/repo", "good/repo"]
    )
    with patch.dict("sys.modules", {"gitlab": fake_gl_module}):
        files = list(src.iter_files())
    assert [f.name for f in files] == ["ok.ckl"]


def test_iter_files_respects_max_files_per_project(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "tok")
    fake_gl_module = MagicMock()
    fake_client = MagicMock()
    fake_gl_module.Gitlab.return_value = fake_client
    fake_gl_module.exceptions.GitlabAuthenticationError = type(
        "GitlabAuthenticationError", (Exception,), {}
    )

    fake_project = MagicMock()
    fake_project.default_branch = "main"
    fake_commit = MagicMock()
    fake_commit.id = "s" * 40
    fake_project.commits.get.return_value = fake_commit
    # 10 matching files in the tree, cap to 3.
    fake_project.repository_tree.return_value = iter(
        [{"type": "blob", "path": f"f{i}.ckl"} for i in range(10)]
    )
    fake_client.projects.get.return_value = fake_project

    src = GitLabSource(
        server_url="https://gl.x",
        project_paths=["g/p"],
        max_files_per_project=3,
    )
    with patch.dict("sys.modules", {"gitlab": fake_gl_module}):
        files = list(src.iter_files())
    assert len(files) == 3


# ----------------------------------------------------------------------
# File.open() — caching + retry
# ----------------------------------------------------------------------


def test_open_caches_bytes_across_calls():
    proj = MagicMock()
    proj.files.raw.return_value = b"hello"
    f = GitLabFile(
        uri="gitlab://x/g/p@s/foo.ckl",
        name="foo.ckl",
        size=None,
        container_uri="gitlab://x/g/p@s",
        _project=proj,
        _file_path="foo.ckl",
        _commit_sha="s",
    )
    a = f.open().read()
    b = f.open().read()
    assert a == b == b"hello"
    # Network only hit once — second open() served from cache.
    assert proj.files.raw.call_count == 1


def test_open_retries_on_transient_then_raises():
    proj = MagicMock()
    err = RuntimeError("transient")
    err.response_code = 503  # noqa: PLE0237 — duck-typed for our retry policy
    proj.files.raw.side_effect = err
    f = GitLabFile(
        uri="gitlab://x/g/p@s/foo.ckl",
        name="foo.ckl",
        size=None,
        container_uri="gitlab://x/g/p@s",
        _project=proj,
        _file_path="foo.ckl",
        _commit_sha="s",
    )
    # Cut sleep so the test doesn't take ~12 seconds for the backoff
    with patch("cybersecurity_assessor.evidence.sources.gitlab.time.sleep"):
        with pytest.raises(RuntimeError, match="GitLab download failed"):
            f.open()
    # Burned all retry attempts (4 by policy).
    assert proj.files.raw.call_count == 4


def test_open_does_not_retry_on_non_transient_status():
    proj = MagicMock()
    err = RuntimeError("not found")
    err.response_code = 404  # noqa: PLE0237
    proj.files.raw.side_effect = err
    f = GitLabFile(
        uri="gitlab://x/g/p@s/foo.ckl",
        name="foo.ckl",
        size=None,
        container_uri="gitlab://x/g/p@s",
        _project=proj,
        _file_path="foo.ckl",
        _commit_sha="s",
    )
    with patch("cybersecurity_assessor.evidence.sources.gitlab.time.sleep"):
        with pytest.raises(RuntimeError):
            f.open()
    # No retry — 404 fails fast.
    assert proj.files.raw.call_count == 1


# ----------------------------------------------------------------------
# Retry-After honoring — 429 responses must respect server-supplied
# backoff instead of plowing through with exponential alone
# ----------------------------------------------------------------------


def test_delay_for_attempt_honors_retry_after_header():
    err = RuntimeError("rate limited")
    err.response_headers = {"Retry-After": "7"}
    # First attempt — exponential would say 1.5s, but the server asked for 7s.
    assert _delay_for_attempt(0, err) == 7.0


def test_delay_for_attempt_caps_outrageous_retry_after():
    err = RuntimeError("rate limited")
    err.response_headers = {"Retry-After": "600"}  # 10-minute stall would freeze ingest
    assert _delay_for_attempt(0, err) == _RETRY_AFTER_CAP_SECONDS


def test_delay_for_attempt_falls_back_to_exponential_when_no_header():
    err = RuntimeError("transient")
    err.response_headers = {}
    # _RETRY_BACKOFF_BASE_SECONDS * (2 ** attempt) → 1.5, 3, 6, 12
    assert _delay_for_attempt(0, err) == 1.5
    assert _delay_for_attempt(1, err) == 3.0
    assert _delay_for_attempt(2, err) == 6.0


def test_delay_for_attempt_falls_back_when_header_unparseable():
    err = RuntimeError("rate limited")
    err.response_headers = {"Retry-After": "next-tuesday"}  # malformed
    # Falls through to exponential silently.
    assert _delay_for_attempt(0, err) == 1.5


def test_delay_for_attempt_handles_exception_without_headers_attribute():
    # Plain RuntimeError has no response_headers — must not blow up.
    assert _delay_for_attempt(1, RuntimeError("plain")) == 3.0


def test_open_retry_uses_retry_after_when_available():
    proj = MagicMock()
    err = RuntimeError("rate limited")
    err.response_code = 429  # noqa: PLE0237
    err.response_headers = {"Retry-After": "2"}
    proj.files.raw.side_effect = err
    f = GitLabFile(
        uri="gitlab://x/g/p@s/foo.ckl",
        name="foo.ckl",
        size=None,
        container_uri="gitlab://x/g/p@s",
        _project=proj,
        _file_path="foo.ckl",
        _commit_sha="s",
    )
    with patch("cybersecurity_assessor.evidence.sources.gitlab.time.sleep") as sleep:
        with pytest.raises(RuntimeError, match="GitLab download failed"):
            f.open()
    # Every backoff between attempts must honor the server's "wait 2s".
    delays = [call.args[0] for call in sleep.call_args_list]
    assert all(d == 2.0 for d in delays), delays
    assert len(delays) == 3  # 4 attempts → 3 sleeps


# ----------------------------------------------------------------------
# File-size cap — must reject multi-GB files BEFORE buffering into RAM
# ----------------------------------------------------------------------


def test_open_rejects_files_over_size_cap_via_head():
    proj = MagicMock()
    proj.files.head.return_value = {"x-gitlab-size": str(_FILE_SIZE_CAP_BYTES + 1)}
    f = GitLabFile(
        uri="gitlab://x/g/p@s/big.log",
        name="big.log",
        size=None,
        container_uri="gitlab://x/g/p@s",
        _project=proj,
        _file_path="big.log",
        _commit_sha="s",
    )
    with pytest.raises(RuntimeError, match="exceeds size cap"):
        f.open()
    # raw() never called — bytes never buffered.
    proj.files.raw.assert_not_called()


def test_open_proceeds_when_head_size_under_cap():
    proj = MagicMock()
    proj.files.head.return_value = {"x-gitlab-size": "1000"}
    proj.files.raw.return_value = b"x" * 1000
    f = GitLabFile(
        uri="gitlab://x/g/p@s/ok.conf",
        name="ok.conf",
        size=None,
        container_uri="gitlab://x/g/p@s",
        _project=proj,
        _file_path="ok.conf",
        _commit_sha="s",
    )
    assert f.open().read() == b"x" * 1000


def test_open_proceeds_when_head_unsupported():
    """Older python-gitlab releases don't expose files.head()."""
    proj = MagicMock()
    # Configure the head attribute to raise AttributeError on access:
    type(proj.files).head = property(
        lambda self: (_ for _ in ()).throw(AttributeError("no head method"))
    )
    proj.files.raw.return_value = b"hello"
    f = GitLabFile(
        uri="gitlab://x/g/p@s/foo.ckl",
        name="foo.ckl",
        size=None,
        container_uri="gitlab://x/g/p@s",
        _project=proj,
        _file_path="foo.ckl",
        _commit_sha="s",
    )
    # Should NOT raise — gracefully degrades to post-download len() check.
    assert f.open().read() == b"hello"


def test_open_post_download_size_check_when_head_returns_no_size():
    """If HEAD succeeds but the server didn't include x-gitlab-size, the
    belt-and-suspenders len() check after raw() still rejects oversize
    blobs. (HEAD raising is treated as transient — fall through to raw
    and let raw's retry policy handle it; that's why the post-download
    check is the last line of defense.)"""
    proj = MagicMock()
    proj.files.head.return_value = {}  # no size header at all
    proj.files.raw.return_value = b"x" * (_FILE_SIZE_CAP_BYTES + 1)
    f = GitLabFile(
        uri="gitlab://x/g/p@s/leaked.bin",
        name="leaked.bin",
        size=None,
        container_uri="gitlab://x/g/p@s",
        _project=proj,
        _file_path="leaked.bin",
        _commit_sha="s",
    )
    with pytest.raises(RuntimeError, match="exceeds"):
        f.open()


# ----------------------------------------------------------------------
# Auth-error propagation — iter_files must NOT swallow 401/403; that
# would silently emit zero files and leave the user wondering why
# nothing ingested.
# ----------------------------------------------------------------------


def test_iter_files_propagates_auth_error(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "tok")
    fake_gl_module = MagicMock()
    fake_client = MagicMock()
    fake_gl_module.Gitlab.return_value = fake_client

    class FakeAuthError(Exception):
        pass

    fake_gl_module.exceptions.GitlabAuthenticationError = FakeAuthError

    def projects_get(path: str):
        raise FakeAuthError("401 token expired")

    fake_client.projects.get.side_effect = projects_get

    src = GitLabSource(
        server_url="https://gl.x", project_paths=["a/b", "c/d"]
    )
    with patch.dict("sys.modules", {"gitlab": fake_gl_module}):
        with pytest.raises(FakeAuthError, match="401"):
            list(src.iter_files())
    # Critical: auth failure stops the walk on the first project rather
    # than burning through the rest with the same bad token.
    assert fake_client.projects.get.call_count == 1


def test_iter_files_still_tolerates_non_auth_errors(monkeypatch):
    """Sanity: the auth-propagation fix didn't accidentally widen the
    catch into "stop on any error". Non-auth errors still log-and-continue."""
    monkeypatch.setenv("GITLAB_TOKEN", "tok")
    fake_gl_module = MagicMock()
    fake_client = MagicMock()
    fake_gl_module.Gitlab.return_value = fake_client

    class FakeAuthError(Exception):
        pass

    fake_gl_module.exceptions.GitlabAuthenticationError = FakeAuthError

    good_project = MagicMock()
    good_project.default_branch = "main"
    good_commit = MagicMock()
    good_commit.id = "g" * 40
    good_project.commits.get.return_value = good_commit
    good_project.repository_tree.return_value = iter(
        [{"type": "blob", "path": "ok.ckl"}]
    )

    def projects_get(path: str):
        if path == "missing/repo":
            raise RuntimeError("404 not found")  # NOT an auth error
        return good_project

    fake_client.projects.get.side_effect = projects_get

    src = GitLabSource(
        server_url="https://gl.x", project_paths=["missing/repo", "good/repo"]
    )
    with patch.dict("sys.modules", {"gitlab": fake_gl_module}):
        files = list(src.iter_files())
    assert [f.name for f in files] == ["ok.ckl"]
