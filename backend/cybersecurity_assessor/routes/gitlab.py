"""GitLab connector routes — status + test probe.

Mirrors the pattern in ``routes/sharepoint.py``: cheap ``/status`` that reads
config + keyring only (no network), ``/test`` that runs ``GitLabSource.test_connection()``
against the saved-or-override config.

The walker itself is invoked from ``/api/evidence/ingest`` via the discriminated
source-spec union; this router is purely for credential plumbing + the Settings
card.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import config as cfg
from ..evidence.sources.gitlab import GitLabSource, get_gitlab_token

LOG = logging.getLogger(__name__)

router = APIRouter(prefix="/api/gitlab", tags=["gitlab"])


@router.get("/status")
def gitlab_status() -> dict:
    """Report current GitLab configuration + token-present state.

    Cheap — reads ``cfg.load_config()`` and the per-host keyring slot only.
    No GitLab API call. Used by the Settings card to decide whether the
    "Test connection" button should be enabled. ``token_set`` reflects only
    whether a token is stored for the configured host; it does NOT validate
    that the token actually works (that's the job of ``/test``).
    """
    c = cfg.load_config()
    token_set = (
        get_gitlab_token(c.gitlab_server_url) is not None
        if c.gitlab_server_url
        else False
    )
    configured = (
        bool(c.gitlab_server_url)
        and bool(c.gitlab_project_paths)
        and token_set
    )
    return {
        "configured": configured,
        "server_url": c.gitlab_server_url,
        "project_paths": list(c.gitlab_project_paths),
        "ref": c.gitlab_ref,
        "include_globs": list(c.gitlab_include_globs),
        "token_set": token_set,
        "enabled": c.enable_gitlab,
    }


class TestBody(BaseModel):
    """Override-on-test payload — lets the user probe a candidate server /
    project list / ref without committing it to ``config.toml`` first.

    Every field is optional; anything not supplied falls back to the saved
    value via ``cfg.load_config()``. The token always comes from the keyring
    / env var — never accepted over HTTP.
    """

    server_url: str | None = None
    project_paths: list[str] | None = None
    ref: str | None = None
    include_globs: list[str] | None = None


@router.post("/test")
def test_gitlab(body: TestBody | None = None) -> dict:
    """Probe GitLab with the saved (or override) config.

    Authenticates against the server, then resolves each project path to a
    concrete commit SHA on the configured ref. Returns the verbatim
    ``GitLabSource.test_connection()`` dict so the UI can render per-project
    status (a typo in a project path surfaces here as ``ok: False`` for that
    row without poisoning the others).

    Raises HTTP 400 when required config is missing (no server URL or no
    project paths). Wraps the python-gitlab import error (extras not
    installed) as HTTP 400 with an actionable message so raw ImportError
    text doesn't bubble to the user.
    """
    body = body or TestBody()
    c = cfg.load_config()
    server_url = body.server_url or c.gitlab_server_url
    if not server_url:
        raise HTTPException(
            status_code=400,
            detail=(
                "GitLab server URL is required (paste it in Settings or "
                "pass it in the test body)."
            ),
        )

    project_paths = body.project_paths if body.project_paths is not None else list(
        c.gitlab_project_paths
    )
    project_paths = [p for p in project_paths if p and p.strip()]
    if not project_paths:
        raise HTTPException(
            status_code=400,
            detail=(
                "At least one GitLab project path is required (e.g. "
                "'sda-oi/example/mdp/tracking-handler')."
            ),
        )

    ref = (body.ref or c.gitlab_ref or "HEAD").strip() or "HEAD"
    include_globs = (
        tuple(body.include_globs)
        if body.include_globs is not None
        else (tuple(c.gitlab_include_globs) if c.gitlab_include_globs else None)
    )

    try:
        src = GitLabSource(
            server_url=server_url,
            project_paths=project_paths,
            ref=ref,
            include_globs=include_globs,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        result = src.test_connection()
    except ImportError as exc:
        # python-gitlab extras not installed — make the remediation explicit.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 — never let raw SDK errors bubble
        LOG.exception("GitLab test_connection raised an unexpected error")
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    # Shape the response to match the recipe contract (ok / message / detected)
    # while still surfacing the per-project rows the source returns. The UI
    # cares about ``ok`` for the badge and ``detected`` for the metadata
    # display; legacy callers reading server_url/host/user/projects still work.
    detected = {
        "server_url": result.get("server_url"),
        "host": result.get("host"),
        "user": result.get("user"),
        "projects": result.get("projects", []),
    }
    if result.get("ok"):
        user = result.get("user") or "(unknown user)"
        message = f"Authenticated as {user} against {result.get('host')}."
    else:
        message = result.get("error") or "GitLab test failed."

    return {
        "ok": bool(result.get("ok")),
        "message": message,
        "detected": detected,
        # Pass-through for backward compat / detailed UI rendering.
        **result,
    }
