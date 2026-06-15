"""GitLab repository source — v0.4 connector (feature-flagged).

Pulls evidence artifacts (STIG checklists, firewall configs, ClamAV scan
logs, CI pipeline outputs) directly from a self-hosted GitLab instance —
primarily the sda-oi tenant today, but the server URL is config so the
same connector works against any GitLab Enterprise / self-managed host.

Token storage policy
--------------------
The personal access token (PAT) is **never** written to ``config.toml``.
Two acceptable supply paths, in precedence order:

1. ``GITLAB_TOKEN`` environment variable (Claude Code / CI convention) —
   useful for batch / scripted ingest runs that don't have an interactive
   keyring unlock.
2. OS keyring (Windows Credential Manager on Windows / Keychain on macOS)
   under service ``cybersecurity-assessor`` with a per-server key
   ``GITLAB_TOKEN__<host>`` so a user with multiple GitLab instances
   (sda-oi.gitlab.com + corporate self-managed) can store tokens for
   each without one clobbering the other.

If neither is present, ``iter_files()`` raises a clear configuration
error before touching the network. The token is **read at walk start**
and held in memory for the duration of the iterator — never returned,
never logged, never persisted alongside other source state.

URI scheme
----------
``gitlab://<host>/<project_path>@<commit_sha>/<file_path>``

The commit SHA pin is load-bearing for re-ingest semantics: the same
file at the same SHA produces the same URI, so the orchestrator's
hash-based dedupe short-circuits. A new commit produces a new URI
(distinct evidence row), which is the desired audit behavior — "this
firewall config at commit ``abc1234`` was the active artifact when the
assessor verified the rule".

Feature flag
------------
Gated behind ``AppConfig.enable_gitlab`` (default False). The Settings
UI surfaces the toggle alongside SharePoint / Tenable; the ingest route
refuses to instantiate ``GitLabSource`` until the flag is on, matching
the existing connector-gating pattern.

Dependencies
------------
Uses ``python-gitlab`` (installed via the ``sources`` extra). The
library wraps the v4 REST API, handles pagination, and surfaces
``GitlabHttpError`` / ``GitlabAuthenticationError`` we can branch on
for rate-limit / auth error handling.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
import time
from dataclasses import dataclass
from io import BytesIO
from pathlib import PurePosixPath
from typing import BinaryIO, Iterator
from urllib.parse import quote, urlparse

from .base import SourceFile

LOG = logging.getLogger(__name__)

# Same conservative set every other walker uses, plus the file types
# GitLab repos uniquely carry as evidence artifacts. ``.conf`` and
# ``.cfg`` cover Cisco / Palo Alto / iptables firewall dumps; ``.json``
# catches CI report exports; ``.yaml/.yml`` catches Ansible role files
# and GitLab CI definitions (CM evidence). Keep this list pruned —
# adding ``.py`` etc. would flood ingest with source code that doesn't
# function as control evidence.
_DEFAULT_INCLUDE_GLOBS: tuple[str, ...] = (
    "*.ckl",
    "*.cklb",
    "*.conf",
    "*.cfg",
    "*.log",
    "*.xml",
    "*.json",
    "*.yaml",
    "*.yml",
    "*.txt",
    "*.md",
    "*.pdf",
)

# Maximum bytes we'll pull for a single repo file. STIG checklists run
# to ~10 MB and firewall configs ~1 MB; 25 MB cap rejects accidental
# large-binary commits (database dumps, ISOs) that bloat ingest and
# rarely carry control-relevant text.
_FILE_SIZE_CAP_BYTES = 25 * 1024 * 1024

# Transient HTTP status codes — same retry policy as the SharePoint
# connector. 429 is GitLab's rate-limit signal (respects RateLimit-*
# headers); 502/503/504 cover load-balancer hiccups during long crawls.
_RETRY_STATUS = {429, 502, 503, 504}
_RETRY_MAX_ATTEMPTS = 4
_RETRY_BACKOFF_BASE_SECONDS = 1.5
# Cap a server-supplied Retry-After at this many seconds. GitLab's
# rate-limiter occasionally returns multi-minute backoffs during DDoS
# defense or burst smoothing; honouring those literally would stall the
# whole ingest. The cap keeps walks bounded while still respecting the
# intent of the header.
_RETRY_AFTER_CAP_SECONDS = 30.0

KEYRING_SERVICE = "cybersecurity-assessor"


def _delay_for_attempt(attempt: int, exc: Exception) -> float:
    """Choose the sleep duration before the next retry attempt.

    GitLab returns ``Retry-After`` on 429 responses (RFC 6585). Honour
    it when present — exponential-only backoff can hammer a rate-limited
    server faster than it asked us to. Fall back to capped exponential
    (1.5, 3, 6, 12 s) when the header is absent or unparseable.

    ``exc`` is duck-typed: python-gitlab's ``GitlabHttpError`` exposes
    ``response_headers`` (a CaseInsensitiveDict). Other exception types
    just fall through to the exponential branch.
    """
    headers = getattr(exc, "response_headers", None)
    if headers:
        try:
            raw = headers.get("Retry-After") or headers.get("retry-after")
            if raw is not None:
                # Retry-After is "seconds" (integer or float as string).
                # HTTP-date form is also valid per RFC 7231 but GitLab
                # never uses it; if we ever see one, the int() parse
                # raises and we fall through to exponential.
                secs = float(raw)
                return max(0.0, min(secs, _RETRY_AFTER_CAP_SECONDS))
        except (AttributeError, ValueError, TypeError):
            pass
    return _RETRY_BACKOFF_BASE_SECONDS * (2 ** attempt)


def _keyring_key_for_host(host: str) -> str:
    """Per-host keyring slot so multiple GitLab instances coexist.

    ``host`` is the lowercased netloc of the server URL. Sanitise so
    weird hostnames (IPv6 brackets, ports) don't break the keyring
    key — keep only alnum, dot, dash, underscore.
    """
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", host.lower())
    return f"GITLAB_TOKEN__{safe}"


def get_gitlab_token(server_url: str) -> str | None:
    """Read PAT for ``server_url`` from env or keyring. Never persists.

    Env var is the override path; keyring is the steady-state. Returns
    None if neither is set — caller decides whether that's fatal
    (``iter_files``) or "not configured" UI text (Settings probe).
    """
    env = os.environ.get("GITLAB_TOKEN")
    if env:
        return env
    host = (urlparse(server_url).netloc or server_url).lower()
    try:
        import keyring  # noqa: PLC0415

        return keyring.get_password(KEYRING_SERVICE, _keyring_key_for_host(host))
    except Exception:  # noqa: BLE001 — keyring unavailable on locked-down boxes
        LOG.debug("Keyring read failed for GitLab host %s", host, exc_info=True)
        return None


def set_gitlab_token(server_url: str, token: str) -> None:
    """Write PAT to OS keyring under a per-host slot.

    Plain-config callers (e.g. config.toml roundtrip) MUST NOT call this
    — the token belongs in the OS credential store, not on disk in a
    user-readable TOML.
    """
    import keyring  # noqa: PLC0415

    host = (urlparse(server_url).netloc or server_url).lower()
    keyring.set_password(KEYRING_SERVICE, _keyring_key_for_host(host), token)


def clear_gitlab_token(server_url: str) -> None:
    """Delete a stored PAT. Best-effort; absence is not an error."""
    try:
        import keyring  # noqa: PLC0415

        host = (urlparse(server_url).netloc or server_url).lower()
        keyring.delete_password(KEYRING_SERVICE, _keyring_key_for_host(host))
    except Exception:  # noqa: BLE001 — keyring or "no such entry"
        pass


def _gitlab_uri(host: str, project_path: str, commit_sha: str, file_path: str) -> str:
    """Render the canonical GitLab URI.

    The commit SHA between project and file is the dedupe pivot:
    re-ingest at the same SHA → same URI → orchestrator's hash check
    short-circuits. New SHA → new URI → fresh evidence row.

    Encoding rules: project path keeps slashes (``group/subgroup/repo``
    reads naturally); commit SHA is hex, no encoding needed; file path
    keeps slashes but encodes spaces / unicode.
    """
    return (
        f"gitlab://{host}/{quote(project_path, safe='/')}"
        f"@{commit_sha}/{quote(file_path, safe='/')}"
    )


def _glob_match(name: str, globs: tuple[str, ...]) -> bool:
    """Case-insensitive glob match against any of ``globs``."""
    nl = name.lower()
    return any(fnmatch.fnmatchcase(nl, g.lower()) for g in globs)


@dataclass
class GitLabFile:
    """One file from a GitLab project tree, downloaded lazily.

    ``_project`` is the python-gitlab Project handle (cached on the
    source so per-file fetches reuse the same auth header pool); the
    actual bytes are fetched on first ``open()`` and cached because the
    ingest orchestrator opens each SourceFile twice (hash + extract).
    """

    uri: str
    name: str
    size: int | None
    container_uri: str | None
    _project: object  # gitlab.v4.objects.Project — typed Any to avoid hard dep
    _file_path: str
    _commit_sha: str
    _cached_bytes: bytes | None = None

    def open(self) -> BinaryIO:
        if self._cached_bytes is not None:
            return BytesIO(self._cached_bytes)

        # Enforce the file-size cap BEFORE pulling bytes. A 2 GB log file
        # matching ``*.log`` would otherwise OOM the sidecar — the python-
        # gitlab files.raw() call buffers the entire response into memory.
        # files.head() costs one HEAD request and returns the byte length
        # in the x-gitlab-size header; cheap insurance.
        try:
            headers = self._project.files.head(  # type: ignore[attr-defined]
                file_path=self._file_path, ref=self._commit_sha
            )
            # python-gitlab returns a dict-like CaseInsensitiveDict; the
            # canonical header name is x-gitlab-size.
            raw_size = headers.get("x-gitlab-size") or headers.get("X-Gitlab-Size")
            if raw_size is not None:
                size_int = int(raw_size)
                if size_int > _FILE_SIZE_CAP_BYTES:
                    raise RuntimeError(
                        f"GitLab file {self._file_path}@{self._commit_sha[:8]} "
                        f"exceeds size cap "
                        f"({size_int} > {_FILE_SIZE_CAP_BYTES} bytes); skipped "
                        "to protect sidecar memory. Adjust _FILE_SIZE_CAP_BYTES "
                        "if larger evidence artifacts are legitimately needed."
                    )
        except AttributeError:
            # Older python-gitlab without .head() — fall through; the
            # cap-defense degrades to "trust the server" on those.
            LOG.debug("python-gitlab files.head() unavailable; size cap unenforced")
        except RuntimeError:
            raise  # the size-cap rejection above
        except Exception:  # noqa: BLE001
            # HEAD failed for some other reason (network / 404). Don't
            # block the download attempt — let the raw() call surface the
            # real error with its own retry policy below.
            LOG.debug(
                "HEAD failed for %s@%s; proceeding to raw fetch",
                self._file_path,
                self._commit_sha[:8],
                exc_info=True,
            )

        last_exc: Exception | None = None
        for attempt in range(_RETRY_MAX_ATTEMPTS):
            try:
                # python-gitlab returns raw bytes for files.raw(...).
                # We pin to commit_sha so re-fetches at the same URI
                # are reproducible even if the branch tip moved.
                data = self._project.files.raw(  # type: ignore[attr-defined]
                    file_path=self._file_path, ref=self._commit_sha
                )
                # Belt-and-suspenders: if HEAD wasn't available, still
                # reject after-the-fact (memory has already taken the hit,
                # but the orchestrator won't get the bytes downstream).
                if len(data) > _FILE_SIZE_CAP_BYTES:
                    raise RuntimeError(
                        f"GitLab file {self._file_path}@{self._commit_sha[:8]} "
                        f"({len(data)} bytes) exceeds {_FILE_SIZE_CAP_BYTES} "
                        "byte cap"
                    )
                self._cached_bytes = bytes(data)
                return BytesIO(self._cached_bytes)
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                status = getattr(exc, "response_code", None)
                if status not in _RETRY_STATUS or attempt == _RETRY_MAX_ATTEMPTS - 1:
                    break
                delay = _delay_for_attempt(attempt, exc)
                LOG.info(
                    "GitLab download %s on %s — retrying in %.1fs (%d/%d)",
                    status,
                    self._file_path,
                    delay,
                    attempt + 1,
                    _RETRY_MAX_ATTEMPTS,
                )
                time.sleep(delay)
        raise RuntimeError(
            f"GitLab download failed for {self._file_path}@{self._commit_sha[:8]}: "
            f"{last_exc}"
        )


class GitLabSource:
    """Walk one or more GitLab projects, yielding ingestible files at a pinned ref.

    Each project is resolved to a concrete commit SHA at walk start so
    every file emitted from a single walk shares the same SHA per
    project — pagination across a long crawl doesn't risk mixing
    pre/post-commit states.

    Constructor arguments:

    * ``server_url`` — e.g. ``https://gitlab.sda-oi.example``. No
      trailing slash required.
    * ``project_paths`` — list of full project paths
      (``group/subgroup/repo``). Each is fetched independently; one
      missing project doesn't poison the others.
    * ``ref`` — branch / tag / SHA to resolve. Defaults to ``HEAD``
      (the default branch). Resolution happens once per project at
      walk start so the URI commit SHA is stable for the run.
    * ``include_globs`` — case-insensitive filename globs. Defaults to
      the evidence-relevant set (CKL/conf/log/etc).
    * ``max_files_per_project`` — safety cap so a misconfigured
      monorepo doesn't pull tens of thousands of files.

    Token comes from env/keyring via ``get_gitlab_token(server_url)``.
    The constructor itself never accepts a raw token argument — that
    would invite callers to plumb tokens through other code paths.
    """

    # Same as SharePoint: per-file commits keep the UI evidence list
    # refreshing continuously as network-fetched files land.
    commit_batch_size: int = 1

    def __init__(
        self,
        server_url: str,
        project_paths: list[str],
        *,
        ref: str = "HEAD",
        include_globs: tuple[str, ...] | None = None,
        max_files_per_project: int = 5000,
    ) -> None:
        if not server_url:
            raise ValueError("server_url is required for GitLabSource")
        if not project_paths:
            raise ValueError(
                "At least one project_path is required for GitLabSource"
            )
        self.server_url = server_url.rstrip("/")
        self.project_paths = list(project_paths)
        self.ref = ref or "HEAD"
        self.include_globs = include_globs or _DEFAULT_INCLUDE_GLOBS
        self.max_files_per_project = max_files_per_project

        parsed = urlparse(self.server_url)
        self._host = parsed.netloc.lower()
        # Top-level URI describes the source as "GitLab @ host with N
        # projects". Doesn't try to encode the full project list (URIs
        # have practical length limits); IngestSummary records the
        # per-project URIs as it goes.
        self.uri = f"gitlab://{self._host}/?projects={len(self.project_paths)}"

        self._gl = None  # python-gitlab client, lazy-init
        self._token_acquired = False

    # ------------------------------------------------------------------
    # Client init — lazy so constructor is cheap (Settings UI builds
    # one to call test_connection() without paying the import cost
    # twice).
    # ------------------------------------------------------------------
    def _client(self):
        if self._gl is not None:
            return self._gl
        try:
            import gitlab  # type: ignore[import-not-found]  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "python-gitlab is not installed. Install the 'sources' extras: "
                "`pip install -e .[sources]` from backend/."
            ) from exc

        token = get_gitlab_token(self.server_url)
        if not token:
            raise RuntimeError(
                f"No GitLab token found for {self._host}. Set GITLAB_TOKEN env "
                f"var or store via Settings (keyring slot "
                f"{_keyring_key_for_host(self._host)})."
            )
        self._token_acquired = True
        # ssl_verify defaults to True; corporate roots are picked up
        # automatically via the truststore package the sidecar already
        # depends on (see pyproject.toml). User PAT scope must be at
        # least ``read_api + read_repository``.
        self._gl = gitlab.Gitlab(
            url=self.server_url, private_token=token, ssl_verify=True, timeout=60
        )
        return self._gl

    def _retryable(self, func, *, label: str):
        """Run ``func`` with the standard retry policy.

        Centralizes the 429/5xx backoff so every GitLab call (project
        get, tree list, file fetch, commit resolve) shares one code
        path. Auth failures (401/403) bypass retry — they're not going
        to clear on their own.
        """
        try:
            import gitlab  # noqa: PLC0415
        except ImportError:
            gitlab = None  # type: ignore[assignment]

        last_exc: Exception | None = None
        for attempt in range(_RETRY_MAX_ATTEMPTS):
            try:
                return func()
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                status = getattr(exc, "response_code", None)
                if gitlab is not None and isinstance(
                    exc, gitlab.exceptions.GitlabAuthenticationError
                ):
                    # 401/403 — fatal, propagate immediately.
                    raise
                if status not in _RETRY_STATUS or attempt == _RETRY_MAX_ATTEMPTS - 1:
                    break
                delay = _delay_for_attempt(attempt, exc)
                LOG.info(
                    "GitLab %s on %s — retrying in %.1fs (%d/%d)",
                    status,
                    label,
                    delay,
                    attempt + 1,
                    _RETRY_MAX_ATTEMPTS,
                )
                time.sleep(delay)
        raise RuntimeError(f"GitLab call failed for {label}: {last_exc}")

    def _resolve_commit_sha(self, project, ref: str) -> str:
        """Resolve a ref (branch/tag/SHA) to a concrete 40-char commit SHA.

        Pinning every URI to a SHA is what makes ``gitlab://host/proj@sha/path``
        deduplicate correctly across re-ingests: same SHA → same URI
        → orchestrator's hash short-circuit fires. If we left the ref
        as ``main``, every walk would mint fresh evidence rows even
        though the file content was unchanged.
        """
        # ``HEAD`` is not a real Git ref on the server side — translate
        # to the project's default branch up front.
        if ref.upper() == "HEAD":
            ref = project.default_branch or "main"
        commit = self._retryable(
            lambda: project.commits.get(ref), label=f"resolve_commit:{ref}"
        )
        return commit.id

    # ------------------------------------------------------------------
    # Public probe — Settings UI calls this before saving
    # ------------------------------------------------------------------
    def test_connection(self) -> dict:
        """Authenticate + resolve every project. Returns a UI-shaped dict.

        Never throws on the happy "config wrong, surface error" path —
        the route renders these dicts directly. Hard errors (import
        missing, network down) propagate as exceptions.
        """
        try:
            gl = self._client()
        except RuntimeError as exc:
            return {
                "ok": False,
                "server_url": self.server_url,
                "host": self._host,
                "error": str(exc),
            }

        try:
            gl.auth()
        except Exception as exc:  # noqa: BLE001
            return {
                "ok": False,
                "server_url": self.server_url,
                "host": self._host,
                "error": f"GitLab auth failed: {exc}",
            }

        projects_status: list[dict] = []
        all_ok = True
        for path in self.project_paths:
            try:
                proj = self._retryable(
                    lambda p=path: gl.projects.get(p), label=f"projects.get:{path}"
                )
                sha = self._resolve_commit_sha(proj, self.ref)
                projects_status.append(
                    {"project_path": path, "ok": True, "commit_sha": sha}
                )
            except Exception as exc:  # noqa: BLE001
                all_ok = False
                projects_status.append(
                    {"project_path": path, "ok": False, "error": str(exc)}
                )
        return {
            "ok": all_ok,
            "server_url": self.server_url,
            "host": self._host,
            "user": getattr(gl.user, "username", None),
            "projects": projects_status,
        }

    # ------------------------------------------------------------------
    # Walk
    # ------------------------------------------------------------------
    def iter_files(self) -> Iterator[SourceFile]:
        gl = self._client()
        # Resolve the auth-error type once so we can re-raise it from the
        # per-project loop. python-gitlab may not be installed (test
        # paths mock the module); fall back to a never-matching sentinel
        # so the isinstance() check is safe either way.
        try:
            import gitlab  # noqa: PLC0415

            auth_error_cls: type = gitlab.exceptions.GitlabAuthenticationError
        except (ImportError, AttributeError):
            class _NeverMatches(Exception):
                pass

            auth_error_cls = _NeverMatches

        for project_path in self.project_paths:
            try:
                yield from self._iter_project(gl, project_path)
            except auth_error_cls:
                # 401/403 is a credential problem — it WILL repeat for
                # every remaining project. Propagate so the orchestrator
                # surfaces "fix your token" instead of silently emitting
                # zero files and confusing the user with empty ingest.
                raise
            except Exception as exc:  # noqa: BLE001
                # One bad project (404, 500, transient) shouldn't sink
                # the whole walk — surface in logs and move on.
                LOG.warning(
                    "GitLab project %s failed to walk: %s", project_path, exc
                )
                continue

    def _iter_project(self, gl, project_path: str) -> Iterator[SourceFile]:
        proj = self._retryable(
            lambda: gl.projects.get(project_path),
            label=f"projects.get:{project_path}",
        )
        commit_sha = self._resolve_commit_sha(proj, self.ref)
        # Container URI = the project at the pinned commit. Lets the
        # evidence list group "all files ingested from repo X @ SHA".
        container_uri = f"gitlab://{self._host}/{quote(project_path, safe='/')}@{commit_sha}"

        # ``repository_tree`` with recursive=True walks all paths;
        # python-gitlab handles pagination via iterator=True. Cap
        # iteration so a giant monorepo doesn't OOM the sidecar.
        try:
            tree_iter = proj.repository_tree(
                ref=commit_sha, recursive=True, all=True, iterator=True
            )
        except Exception as exc:  # noqa: BLE001
            LOG.warning(
                "GitLab tree listing failed for %s@%s: %s",
                project_path,
                commit_sha[:8],
                exc,
            )
            return

        emitted = 0
        for entry in tree_iter:
            if emitted >= self.max_files_per_project:
                LOG.info(
                    "GitLab project %s hit max_files cap (%d) — truncating walk",
                    project_path,
                    self.max_files_per_project,
                )
                break
            if entry.get("type") != "blob":
                continue
            path = entry.get("path") or ""
            name = PurePosixPath(path).name
            if not name or name.startswith(".") or name.startswith("~$"):
                continue
            if not _glob_match(name, self.include_globs):
                continue

            # Size lookup requires a per-file metadata call; the tree
            # entry doesn't carry size. Defer to download time for
            # cheap walk; if a caller needs metadata-only listing, we
            # add a head_file() helper later.
            yield GitLabFile(
                uri=_gitlab_uri(self._host, project_path, commit_sha, path),
                name=name,
                size=None,
                container_uri=container_uri,
                _project=proj,
                _file_path=path,
                _commit_sha=commit_sha,
            )
            emitted += 1
