"""Jira connector routes — double-gated v0.4+ status + test probe + PAT slot.

Mirrors the pattern in routes/sharepoint.py and routes/emass.py: cheap
``/status`` that reads config + keyring only (NO network), ``/test`` that
does a real ``/rest/api/2/myself`` round-trip through the underlying
``JiraSource.test_connection()`` helper, plus a ``/pat`` write/clear pair
that lands the Personal Access Token in the OS keyring.

Double-gate: every code path that would construct a real ``JiraSource``
must verify BOTH ``enable_jira`` and ``jira_upcoming_gated`` are true.
Failing the gate returns ``HTTP 400`` with a message that distinguishes
which flag is off — the Settings UI uses that distinction to decide
whether the main pill or the inner ack needs to flip.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import config as cfg
from ..evidence.sources.jira import (
    JiraConfig,
    JiraConnectorDisabledError,
    JiraSource,
    is_jira_connector_enabled,
)

router = APIRouter(prefix="/api/jira", tags=["jira"])


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------


class JiraPatBody(BaseModel):
    """POST body for storing the PAT in the OS keyring."""

    pat: str


class JiraQueryItem(BaseModel):
    """One entry in the allowed-queries list — name + JQL pair.

    The Settings card edits a list of these; the route layer flattens the
    JQL values into a tuple when constructing ``JiraConfig`` (the connector
    itself doesn't care about names — names exist purely so the Sweep UI
    can render human labels next to result counts).
    """

    name: str
    jql: str


class JiraTestBody(BaseModel):
    """POST body for ``/test`` — every field optional, falls back to stored config.

    Lets the UI probe a *candidate* configuration before saving it (the
    classic "Test connection" flow) without persisting a half-typed URL or
    a typo'd PAT to disk.
    """

    server_url: str | None = None
    pat: str | None = None
    allowed_jql_queries: list[JiraQueryItem] | None = None
    verify_ssl: bool | None = None


# ---------------------------------------------------------------------------
# /status — config + keyring only, NEVER a network call
# ---------------------------------------------------------------------------


@router.get("/status")
def jira_status() -> dict[str, Any]:
    """Return whether Jira is configured, gated, and ready to probe.

    Recipe gotcha #6: status probes must not hit the network. The Settings
    card calls this on every render to update its badge; a network call
    here would slow page paint AND surface transient Jira 5xx as a
    persistent red banner. The real network probe lives at ``/test``.
    """
    c = cfg.load_config()
    pat_set = cfg.get_jira_pat() is not None
    has_queries = bool(c.jira_allowed_jql_queries)
    # "configured" semantics for the badge: every required piece is in
    # place. Missing any one means the test probe would fail loudly, so
    # surface that early on the card without forcing the user to click
    # Test to find out.
    configured = bool(c.jira_server_url) and pat_set and has_queries
    return {
        "configured": configured,
        "server_url": c.jira_server_url,
        "allowed_jql_queries": c.jira_allowed_jql_queries,
        "max_results_per_query": c.jira_max_results_per_query,
        "verify_ssl": c.jira_verify_ssl,
        "pat_set": pat_set,
        # Double-gated state — UI uses these to decide whether to render the
        # main pill (enabled) or the inner ack (upcoming_gated) as the
        # bottleneck. Both must be true for the connector to actually run.
        "enabled": c.enable_jira,
        "upcoming_gated": c.jira_upcoming_gated,
        "gate_open": is_jira_connector_enabled(
            v04_flag=c.enable_jira,
            upcoming_gated_flag=c.jira_upcoming_gated,
        ),
    }


# ---------------------------------------------------------------------------
# /test — real /myself round-trip (does hit the network)
# ---------------------------------------------------------------------------


@router.post("/test")
def jira_test(body: JiraTestBody | None = None) -> dict[str, Any]:
    """Probe Jira auth + reachability.

    Resolves each field from the request body first, then falls back to
    saved config / keyring — lets the user click "Test connection" with
    a candidate URL or PAT typed into the form before clicking Save.

    Returns the shape ``JiraSource.test_connection()`` produces:
    ``{ok, server_url, account, queries_configured}`` on success or
    ``{ok: False, server_url, error}`` on failure. The route never raises
    on a Jira-side failure (401, 5xx, network) — it surfaces the message
    in ``error`` so the UI can render it without a special-case
    HTTPException handler. Configuration errors (no URL, no PAT, empty
    queries, gate closed) DO raise as HTTP 400 because there's no point
    rendering a "connector says: connection error" banner when the user
    just hasn't filled in the form.
    """
    body = body or JiraTestBody()
    c = cfg.load_config()

    # Gate first — refuse before even touching keyring / network.
    if not is_jira_connector_enabled(
        v04_flag=c.enable_jira, upcoming_gated_flag=c.jira_upcoming_gated
    ):
        detail = (
            "Jira connector is double-gated. Both 'enable_jira' AND "
            "'jira_upcoming_gated' must be true before any test or ingest "
            f"will run. Currently: enable_jira={c.enable_jira}, "
            f"jira_upcoming_gated={c.jira_upcoming_gated}."
        )
        raise HTTPException(status_code=400, detail=detail)

    server_url = (body.server_url or c.jira_server_url or "").strip().rstrip("/")
    if not server_url:
        raise HTTPException(status_code=400, detail="No Jira server URL configured.")

    pat = body.pat or cfg.get_jira_pat()
    if not pat:
        raise HTTPException(
            status_code=400,
            detail="No Jira PAT stored. Save one from the Settings card first.",
        )

    # Resolve allowed queries: body override > saved config. Strip empties.
    if body.allowed_jql_queries is not None:
        raw_queries = [
            (item.name.strip(), item.jql.strip())
            for item in body.allowed_jql_queries
        ]
    else:
        raw_queries = [
            (str(item.get("name", "")).strip(), str(item.get("jql", "")).strip())
            for item in (c.jira_allowed_jql_queries or [])
        ]
    jql_values = tuple(jql for _name, jql in raw_queries if jql)
    if not jql_values:
        raise HTTPException(
            status_code=400,
            detail=(
                "No allowed JQL queries configured. Add at least one named "
                "query before testing — Jira is config-bound and refuses to "
                "run free-form queries from the UI."
            ),
        )

    verify_ssl = body.verify_ssl if body.verify_ssl is not None else c.jira_verify_ssl
    max_results = c.jira_max_results_per_query

    try:
        kwargs: dict[str, Any] = {
            "server_url": server_url,
            "pat": pat,
            "queries": jql_values,
            "verify_ssl": bool(verify_ssl),
        }
        if max_results is not None and max_results > 0:
            kwargs["max_results_per_query"] = int(max_results)
        jira_cfg = JiraConfig(**kwargs)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid Jira config: {exc}") from exc

    try:
        src = JiraSource(
            jira_cfg,
            v04_flag=c.enable_jira,
            upcoming_gated_flag=c.jira_upcoming_gated,
        )
    except JiraConnectorDisabledError as exc:  # belt + suspenders; gate already checked
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 — surface SDK import / construction issues
        raise HTTPException(
            status_code=500,
            detail=f"Failed to construct Jira client: {exc}",
        ) from exc

    # ``test_connection`` itself never raises — it catches and returns
    # ``{ok: False, error}`` so the UI gets a stable shape.
    result = src.test_connection()
    # ``detected`` mirrors the SharePoint /test shape so the UI can render
    # a uniform "detected metadata" badge on the card title without per-
    # connector branching.
    if result.get("ok"):
        return {
            "ok": True,
            "message": "Connected to Jira",
            "detected": {
                "account": result.get("account") or "",
                "server_url": result.get("server_url"),
                "queries_configured": result.get("queries_configured", 0),
            },
        }
    return {
        "ok": False,
        "message": result.get("error") or "Jira test failed",
        "detected": {"server_url": result.get("server_url")},
    }


# ---------------------------------------------------------------------------
# /pat — keyring write + clear
# ---------------------------------------------------------------------------


@router.post("/pat")
def set_jira_pat(body: JiraPatBody) -> dict[str, Any]:
    """Store the Jira PAT in the OS keyring.

    Refuses laughably short tokens as a typo guard (Jira PATs are 24+
    chars in practice; the 8-char floor here only catches "asdf" / "" /
    accidental empty paste). The keyring slot lives at
    ``KEYRING_KEY_JIRA_PAT`` — see config.py.
    """
    pat = (body.pat or "").strip()
    if len(pat) < 8:
        raise HTTPException(
            status_code=400,
            detail="Jira PAT looks too short to be valid (minimum 8 characters).",
        )
    cfg.set_jira_pat(pat)
    return {"ok": True}


@router.delete("/pat")
def clear_jira_pat() -> dict[str, Any]:
    cfg.clear_jira_pat()
    return {"ok": True}
