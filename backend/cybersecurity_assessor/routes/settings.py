"""Settings endpoints: API key (via OS keyring), tester defaults, feature flags."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .. import config as cfg
from ..evidence.sources.archer import _read_password as _archer_read_password
from ..evidence.sources.gitlab import get_gitlab_token
from ..evidence.sources.sharepoint import cloud_for

router = APIRouter(prefix="/api/settings", tags=["settings"])


class ApiKeyBody(BaseModel):
    key: str


class GatewayTokenBody(BaseModel):
    token: str


@router.get("")
def get_settings() -> dict:
    c = cfg.load_config()
    import os as _os

    return {
        "default_tester": c.default_tester,
        # Active provider toggle (drives /assess + /assess-batch dispatch).
        "llm_provider": c.llm_provider,
        # Anthropic
        "anthropic_model": c.anthropic_model,
        "anthropic_key_set": cfg.get_anthropic_key() is not None,
        "anthropic_base_url": c.anthropic_base_url,  # None ⇒ real Anthropic
        "anthropic_default_base_url": cfg.DEFAULT_ANTHROPIC_BASE_URL,
        "anthropic_api_key_env_set": bool(_os.environ.get("ANTHROPIC_API_KEY")),
        "anthropic_auth_token_env_set": bool(_os.environ.get("ANTHROPIC_AUTH_TOKEN")),
        "anthropic_gateway_token_set": cfg.get_gateway_token() is not None,
        # OpenAI
        "openai_model": c.openai_model,
        "openai_key_set": cfg.get_openai_key() is not None,
        "openai_base_url": c.openai_base_url,  # None ⇒ real OpenAI
        "openai_default_base_url": cfg.DEFAULT_OPENAI_BASE_URL,
        "openai_api_key_env_set": bool(_os.environ.get("OPENAI_API_KEY")),
        "openai_auth_token_env_set": bool(_os.environ.get("OPENAI_AUTH_TOKEN")),
        "openai_gateway_token_set": cfg.get_openai_gateway_token() is not None,
        # eMASS (v0.2+ feature — stored only so the Settings card has a place
        # to render). None ⇒ "not configured".
        "emass_base_url": c.emass_base_url,
        "emass_cert_path": c.emass_cert_path,
        "emass_api_key_set": cfg.get_emass_api_key() is not None,
        # eMASS REST connector — DOUBLE-GATED. Nested block mirrors the
        # SharePoint shape so the Settings card has one source of truth for
        # all four connection fields. ``upcoming_gated`` is the per-connector
        # authorization gate (ISSM sign-off); ``enable`` is the main pill.
        "emass": {
            "base_url": c.emass_base_url,
            "system_id": c.emass_system_id,
            "cert_path": c.emass_cert_path,
            "key_path": c.emass_key_path,
            "api_key_set": cfg.get_emass_api_key() is not None,
            "upcoming_gated": c.emass_upcoming_gated_enabled,
            "connectors_v04": c.connectors_v04_enabled,
        },
        # SharePoint connector. Plug-and-play via Microsoft Graph + the
        # Graph PowerShell client_id (well-known, pre-consented for
        # Sites.Read.All across all clouds). The user pastes a site URL,
        # we detect the cloud (Commercial / GovCloud / DoD) from the
        # hostname, and a device-code sign-in does the rest. Token-cache
        # state lives at ~/.cybersecurity-assessor/graph_token_cache.json
        # (presence reported by /api/sharepoint/status).
        "sharepoint": {
            "site_url": c.sharepoint_site_url,
            "library": c.sharepoint_library,
            "folder_path": c.sharepoint_folder_path,
            "cloud_name": (
                cloud_for(c.sharepoint_site_url).cloud_name
                if c.sharepoint_site_url
                else None
            ),
        },
        # Tenable connector (v0.4). Two flavors:
        # - "sc"  (Tenable.sc / SecurityCenter on-prem; requires host FQDN)
        # - "io"  (Tenable.io SaaS; host is implicit cloud.tenable.com)
        # Secrets (access_key + secret_key) live in the OS keyring; here we
        # only report whether each slot is set, never the raw value.
        "tenable": {
            "flavor": c.tenable_flavor,
            "host": c.tenable_host,
            "access_key_set": cfg.get_tenable_access_key() is not None,
            "secret_key_set": cfg.get_tenable_secret_key() is not None,
        },
        # ServiceNow GRC connector (v0.4). Username + auth_method are
        # persisted in config so the Settings card can render what's
        # configured without round-tripping to the keyring. The OAuth
        # client_secret / Basic password live in the OS keyring under
        # KEYRING_KEY_SNOW_OAUTH_SECRET / KEYRING_KEY_SNOW_BASIC_PASSWORD;
        # only the "set?" flags are exposed via this dict so the UI can
        # show a "secret stored" badge without ever shipping the value.
        "servicenow_grc": {
            "instance_url": c.servicenow_grc_instance_url,
            "auth_method": c.servicenow_grc_auth_method,
            "username": c.servicenow_grc_username,
            "allowed_tables": list(c.servicenow_grc_allowed_tables),
            "oauth_secret_set": _keyring_has(
                "snow_grc_oauth_secret_set",
            ),
            "basic_password_set": _keyring_has(
                "snow_grc_basic_password_set",
            ),
        },
        # Archer (RSA Archer / GRC) connector. ``password_set`` is True only
        # when both instance_name + username are configured AND the keyring
        # has a slot for that pair — the UI uses it to gate the "Test
        # connection" button so users don't fire a guaranteed-401 probe.
        "archer": {
            "instance_url": c.archer_instance_url,
            "instance_name": c.archer_instance_name,
            "username": c.archer_username,
            "domain": c.archer_domain,
            "password_set": (
                _archer_read_password(c.archer_instance_name, c.archer_username)
                is not None
                if c.archer_instance_name and c.archer_username
                else False
            ),
        },
        # Splunk connector. Token-only auth; the saved-search allow-list
        # is the run-time scope knob (raw SPL is rejected at SplunkSource
        # construction). Token presence reported via /api/splunk/status —
        # the token itself never round-trips through this surface.
        "splunk": {
            "host": c.splunk_host,
            "port": c.splunk_port,
            "scheme": c.splunk_scheme,
            "app": c.splunk_app,
            "owner": c.splunk_owner,
            "verify_tls": c.splunk_verify_tls,
            "saved_searches": list(c.splunk_saved_searches),
            "token_set": cfg.get_splunk_token() is not None,
        },
        # SharePoint Boundary Sweep — v0.4 connector. Reuses the SharePoint
        # connector's site URL + Graph auth so it has almost no connection
        # state of its own. None values ⇒ use BoundarySweepCaps dataclass
        # defaults (max_folder_depth=4, max_stale_title_items=100).
        "boundary_sweep": {
            "folder_path": c.boundary_sweep_folder_path,
            "max_folder_depth": c.boundary_sweep_max_folder_depth,
            "max_stale_items": c.boundary_sweep_max_stale_items,
        },
        # GitLab connector — v0.4 evidence source. Token lives in the OS
        # keyring per-host (KEYRING_KEY_GITLAB_PREFIX + sanitized host) and
        # NEVER on disk; we only surface `token_set` so the UI can render a
        # "configured" badge without leaking the value. `server_url` is the
        # only required field; project paths / ref / globs are optional
        # walker tuning. Lists round-trip as JSON arrays.
        "gitlab": {
            "server_url": c.gitlab_server_url,
            "project_paths": list(c.gitlab_project_paths),
            "ref": c.gitlab_ref,
            "include_globs": list(c.gitlab_include_globs),
            "token_set": (
                get_gitlab_token(c.gitlab_server_url) is not None
                if c.gitlab_server_url
                else False
            ),
        },
        # Confluence DC connector — v0.4+ gated. Persisted address fields
        # so the Settings card can render "configured but disabled" before
        # the user opts into both gate flags. The PAT itself lives in the
        # keyring (status surfaced via /api/confluence/status, not here).
        "confluence": {
            "base_url": c.confluence_base_url,
            "username": c.confluence_username,
            "space_keys": c.confluence_space_keys,
            "max_pages": c.confluence_max_pages,
        },
        # Jira connector — double-gated v0.4+. ``allowed_jql_queries`` is
        # the source of truth for what the connector can run; the route
        # layer extracts ``jql`` values when constructing JiraConfig so
        # the UI never opens a free-form-JQL surface.
        "jira": {
            "server_url": c.jira_server_url,
            "allowed_jql_queries": c.jira_allowed_jql_queries,
            "max_results_per_query": c.jira_max_results_per_query,
            "verify_ssl": c.jira_verify_ssl,
            "pat_set": cfg.get_jira_pat() is not None,
        },
        "features": {
            "sharepoint": c.enable_sharepoint,
            "tenable": c.enable_tenable,
            # ServiceNow GRC. Backend flag is ``enable_snow_grc`` for
            # backward compat with evidence/sources/servicenow_grc.py's
            # feature_enabled() check; the UI sees it under the slug
            # ``servicenow_grc``.
            "servicenow_grc": c.enable_snow_grc,
            "archer": c.enable_archer,
            "splunk": c.enable_splunk,
            "boundary_sweep": c.enable_boundary_sweep,
            "gitlab": c.enable_gitlab,
            # Confluence DC — DOUBLE-GATED. Both must be True for the
            # source to iterate. ``confluence`` is the main pill (per-
            # connector enable); ``confluence_upcoming_gated`` is the
            # ISSM-ack inner panel toggle (same shape as the eMASS card
            # in sibling worktrees). ``connectors_v04`` is the shared
            # v0.4 cohort gate.
            "confluence": c.enable_confluence,
            "confluence_upcoming_gated": c.confluence_upcoming_gated_enabled,
            "connectors_v04": c.connectors_v04_enabled,
            # Jira double-gated pair: the main pill is ``jira`` (UI's
            # ``enable_jira``); the inner ack is ``jira_upcoming_gated``.
            # BOTH must be true before any /test or ingest path touches
            # a real Jira instance.
            "jira": c.enable_jira,
            "jira_upcoming_gated": c.jira_upcoming_gated,
            # eMASS main-pill flag. The connector ALSO requires the per-tenant
            # ``emass_upcoming_gated`` flag below before it will actually load
            # (see EmassSource constructor); this one is just the "is the card
            # body visible?" toggle.
            "emass": c.enable_emass,
            "emass_upcoming_gated": c.emass_upcoming_gated_enabled,
            "connectors_v04": c.connectors_v04_enabled,
            # Audit v1 — when ON, the LLM is asked to emit a structured
            # citations array alongside its narrative. Trace + evidence-shown
            # capture is unconditional; only the citation parse/persist is
            # flag-gated. Default OFF until the eval harness can measure
            # verdict regression from the longer prompt.
            "audit_citations": c.audit_citations_enabled,
        },
    }


def _keyring_has(slot_hint: str) -> bool:
    """Best-effort keyring lookup for ServiceNow GRC secrets.

    Returns ``True`` when a value is stored, ``False`` on any error /
    missing slot. We never surface the actual secret — only the boolean —
    so the UI can render a "secret stored" badge.
    """
    try:
        import keyring  # local import to avoid top-level cost on cold start

        from ..evidence.sources.servicenow_grc import (
            KEYRING_KEY_SNOW_BASIC_PASSWORD,
            KEYRING_KEY_SNOW_OAUTH_SECRET,
        )

        key = (
            KEYRING_KEY_SNOW_OAUTH_SECRET
            if "oauth" in slot_hint
            else KEYRING_KEY_SNOW_BASIC_PASSWORD
        )
        return keyring.get_password(cfg.KEYRING_SERVICE, key) is not None
    except Exception:
        return False


class SettingsUpdate(BaseModel):
    default_tester: str | None = None
    # "anthropic" | "openai"
    llm_provider: str | None = None
    anthropic_model: str | None = None
    # Pass "" to clear and revert to the default (real Anthropic API).
    anthropic_base_url: str | None = None
    openai_model: str | None = None
    # Pass "" to clear and revert to the default (api.openai.com/v1).
    openai_base_url: str | None = None
    # eMASS v0.2+ surface — empty string clears the value (same convention as
    # ``anthropic_base_url``).
    emass_base_url: str | None = None
    emass_cert_path: str | None = None
    # eMASS additional connection fields (v0.4+ wiring). Empty string clears.
    emass_key_path: str | None = None
    emass_system_id: str | None = None
    # eMASS feature flags. None ⇒ leave alone; explicit true/false flips.
    # The connector is DOUBLE-GATED: both ``enable_emass`` (main pill) and
    # ``emass_upcoming_gated_enabled`` (ISSM authorization) must be True for
    # the source to load. ``connectors_v04_enabled`` is the cohort gate that
    # will flip default-on when v0.4 ships.
    enable_emass: bool | None = None
    emass_upcoming_gated_enabled: bool | None = None
    connectors_v04_enabled: bool | None = None
    # SharePoint connector — same empty-string-clears convention. Tenant /
    # client / authority deliberately absent: Graph PowerShell client_id is
    # hardcoded server-side and the authority is derived from the site URL
    # hostname (see routes/sharepoint.py and evidence/sources/sharepoint.py).
    sharepoint_site_url: str | None = None
    sharepoint_library: str | None = None
    sharepoint_folder_path: str | None = None
    # Optional feature-flag toggle for the SharePoint connector. None ⇒ leave
    # whatever's already saved; explicit true/false flips it.
    enable_sharepoint: bool | None = None
    # Tenable connector — empty-string clears, None leaves alone. Flavor
    # must be one of "sc" | "io" (validated in the PUT handler). Host is a
    # bare FQDN for .sc; ignored / overridden to cloud.tenable.com for .io.
    tenable_flavor: str | None = None
    tenable_host: str | None = None
    enable_tenable: bool | None = None
    # ServiceNow GRC connector — empty string clears the value (same as
    # other connectors). ``servicenow_grc_allowed_tables`` is a list; pass
    # an empty list to revert to the connector defaults (DEFAULT_TABLES).
    # ``enable_servicenow_grc`` is the UI-visible alias for the backend
    # ``enable_snow_grc`` flag — see GET handler note.
    servicenow_grc_instance_url: str | None = None
    servicenow_grc_auth_method: str | None = None
    servicenow_grc_username: str | None = None
    servicenow_grc_allowed_tables: list[str] | None = None
    enable_servicenow_grc: bool | None = None
    # Archer connector — empty string clears. URL is rstripped of trailing
    # slash so the form-friendly "https://archer.example.com/" matches a
    # later-saved bare "https://archer.example.com".
    archer_instance_url: str | None = None
    archer_instance_name: str | None = None
    archer_username: str | None = None
    archer_domain: str | None = None
    enable_archer: bool | None = None
    # Splunk connector — same empty-string-clears convention. Token lives in
    # the OS keyring; never round-trips through this surface. Saved-search
    # list replaces in full on each PUT (None ⇒ leave alone, [] ⇒ clear).
    splunk_host: str | None = None
    splunk_port: int | None = None
    splunk_scheme: str | None = None
    splunk_app: str | None = None
    splunk_owner: str | None = None
    splunk_verify_tls: bool | None = None
    splunk_saved_searches: list[str] | None = None
    enable_splunk: bool | None = None
    # SharePoint Boundary Sweep (v0.4) — same empty-string-clears convention.
    # Integer caps accept null to revert to BoundarySweepCaps defaults.
    boundary_sweep_folder_path: str | None = None
    boundary_sweep_max_folder_depth: int | None = None
    boundary_sweep_max_stale_items: int | None = None
    enable_boundary_sweep: bool | None = None
    # GitLab connector — same empty-string-clears convention for scalars.
    # ``project_paths`` / ``include_globs`` are full-replacement lists when
    # provided (empty list ⇒ clear all). ``ref`` defaults to "HEAD" in
    # config; empty string here resets it back to "HEAD".
    gitlab_server_url: str | None = None
    gitlab_project_paths: list[str] | None = None
    gitlab_ref: str | None = None
    gitlab_include_globs: list[str] | None = None
    enable_gitlab: bool | None = None
    # Confluence DC connector — empty-string-clears convention. None ⇒ leave
    # alone; "" ⇒ clear; any other string ⇒ save (trim + strip trailing /
    # on the base URL).
    confluence_base_url: str | None = None
    confluence_username: str | None = None
    confluence_space_keys: str | None = None
    # max_pages is an int (positive); None ⇒ leave alone; explicit 0/negative
    # is rejected by the PUT handler. UI default surfaced by GET is 500.
    confluence_max_pages: int | None = None
    # DOUBLE-GATED toggles. None ⇒ leave alone. ``enable_confluence`` is the
    # main pill (per-connector); ``confluence_upcoming_gated_enabled`` is the
    # ISSM-ack inner panel toggle. ``connectors_v04_enabled`` is shared with
    # any other v0.4+ gated connector card and is the cohort half of the gate.
    enable_confluence: bool | None = None
    confluence_upcoming_gated_enabled: bool | None = None
    connectors_v04_enabled: bool | None = None
    # Jira connector — same empty-string-clears convention for the URL.
    # ``jira_allowed_jql_queries`` is the named list of {name, jql} pairs the
    # connector is allowed to run; None leaves the saved list intact, an empty
    # list explicitly clears it. ``jira_max_results_per_query`` accepts None
    # (use connector default) or a positive int.
    jira_server_url: str | None = None
    jira_allowed_jql_queries: list[dict] | None = None
    jira_max_results_per_query: int | None = None
    jira_verify_ssl: bool | None = None
    # Jira double-gated flags. ``enable_jira`` is the main pill; the
    # ``jira_upcoming_gated`` ack lives inside the card body. Both default to
    # leaving the saved value alone; the UI sends explicit true/false to flip.
    enable_jira: bool | None = None
    jira_upcoming_gated: bool | None = None
    # Audit v1 — citation co-emission flag. None ⇒ leave existing value;
    # explicit true/false flips it. Default value lives in config.py.
    audit_citations_enabled: bool | None = None
    # NOTE: sweep-judge knobs (sweep_judge_enabled / llm_judge_model /
    # sweep_cost_cap_usd / sweep_judge_workers) were intentionally removed from
    # the HTTP surface — defaults in ``Config`` are sized for a strong first
    # sweep and the UI no longer renders a tuning card. Power users who need
    # to override edit ``~/.cybersecurity-assessor/config.toml`` directly; the
    # values are still consumed by the sweep code path, just not settable here.


@router.put("")
def update_settings(body: SettingsUpdate) -> dict:
    c = cfg.load_config()
    if body.default_tester is not None:
        c.default_tester = body.default_tester
    if body.llm_provider is not None:
        if body.llm_provider not in ("anthropic", "openai"):
            raise HTTPException(
                status_code=400,
                detail=f"llm_provider must be 'anthropic' or 'openai', got {body.llm_provider!r}",
            )
        c.llm_provider = body.llm_provider  # type: ignore[assignment]
    if body.anthropic_model is not None:
        c.anthropic_model = body.anthropic_model
    if body.anthropic_base_url is not None:
        c.anthropic_base_url = body.anthropic_base_url.strip() or None
    if body.openai_model is not None:
        c.openai_model = body.openai_model
    if body.openai_base_url is not None:
        c.openai_base_url = body.openai_base_url.strip() or None
    if body.emass_base_url is not None:
        c.emass_base_url = body.emass_base_url.strip().rstrip("/") or None
    if body.emass_cert_path is not None:
        c.emass_cert_path = body.emass_cert_path.strip() or None
    if body.emass_key_path is not None:
        c.emass_key_path = body.emass_key_path.strip() or None
    if body.emass_system_id is not None:
        c.emass_system_id = body.emass_system_id.strip() or None
    if body.enable_emass is not None:
        c.enable_emass = body.enable_emass
    if body.emass_upcoming_gated_enabled is not None:
        c.emass_upcoming_gated_enabled = body.emass_upcoming_gated_enabled
    if body.connectors_v04_enabled is not None:
        c.connectors_v04_enabled = body.connectors_v04_enabled
    if body.sharepoint_site_url is not None:
        c.sharepoint_site_url = body.sharepoint_site_url.strip().rstrip("/") or None
    if body.sharepoint_library is not None:
        c.sharepoint_library = body.sharepoint_library.strip() or None
    if body.sharepoint_folder_path is not None:
        c.sharepoint_folder_path = body.sharepoint_folder_path.strip().strip("/") or None
    if body.enable_sharepoint is not None:
        c.enable_sharepoint = body.enable_sharepoint
    if body.tenable_flavor is not None:
        flavor = body.tenable_flavor.strip().lower() or None
        if flavor is not None and flavor not in ("sc", "io"):
            raise HTTPException(
                status_code=400,
                detail=f"tenable_flavor must be 'sc' or 'io', got {body.tenable_flavor!r}",
            )
        c.tenable_flavor = flavor  # type: ignore[assignment]
    if body.tenable_host is not None:
        c.tenable_host = body.tenable_host.strip().rstrip("/") or None
    if body.enable_tenable is not None:
        c.enable_tenable = body.enable_tenable
    if body.servicenow_grc_instance_url is not None:
        c.servicenow_grc_instance_url = (
            body.servicenow_grc_instance_url.strip().rstrip("/") or None
        )
    if body.servicenow_grc_auth_method is not None:
        v = body.servicenow_grc_auth_method.strip().lower() or None
        if v is not None and v not in ("oauth", "basic"):
            raise HTTPException(
                status_code=400,
                detail=(
                    "servicenow_grc_auth_method must be 'oauth' or 'basic', "
                    f"got {v!r}"
                ),
            )
        c.servicenow_grc_auth_method = v
    if body.servicenow_grc_username is not None:
        c.servicenow_grc_username = body.servicenow_grc_username.strip() or None
    if body.servicenow_grc_allowed_tables is not None:
        # Empty list ⇒ revert to connector defaults; otherwise normalize
        # by stripping each entry and dropping empties so the persisted
        # list never holds a "" sentinel.
        c.servicenow_grc_allowed_tables = [
            t.strip() for t in body.servicenow_grc_allowed_tables if t and t.strip()
        ]
    if body.enable_servicenow_grc is not None:
        c.enable_snow_grc = body.enable_servicenow_grc
    if body.archer_instance_url is not None:
        c.archer_instance_url = body.archer_instance_url.strip().rstrip("/") or None
    if body.archer_instance_name is not None:
        c.archer_instance_name = body.archer_instance_name.strip() or None
    if body.archer_username is not None:
        c.archer_username = body.archer_username.strip() or None
    if body.archer_domain is not None:
        c.archer_domain = body.archer_domain.strip() or None
    if body.enable_archer is not None:
        c.enable_archer = body.enable_archer
    if body.splunk_host is not None:
        c.splunk_host = body.splunk_host.strip() or None
    if body.splunk_port is not None:
        # Port is non-secret connection metadata; the field default (8089) is
        # never None on the AppConfig side, so we clamp to a sane fallback if
        # the UI sends 0/negative rather than letting Splunk SDK choke later.
        c.splunk_port = int(body.splunk_port) if body.splunk_port > 0 else 8089
    if body.splunk_scheme is not None:
        scheme = body.splunk_scheme.strip().lower() or "https"
        if scheme not in ("https", "http"):
            raise HTTPException(
                status_code=400,
                detail=f"splunk_scheme must be 'https' or 'http', got {scheme!r}",
            )
        c.splunk_scheme = scheme
    if body.splunk_app is not None:
        c.splunk_app = body.splunk_app.strip() or "search"
    if body.splunk_owner is not None:
        c.splunk_owner = body.splunk_owner.strip() or "-"
    if body.splunk_verify_tls is not None:
        c.splunk_verify_tls = body.splunk_verify_tls
    if body.splunk_saved_searches is not None:
        # Strip + drop empties so a stray blank row in the UI doesn't trip the
        # SplunkSource allow-list check later.
        c.splunk_saved_searches = [
            s.strip() for s in body.splunk_saved_searches if s and s.strip()
        ]
    if body.enable_splunk is not None:
        c.enable_splunk = body.enable_splunk
    if body.boundary_sweep_folder_path is not None:
        c.boundary_sweep_folder_path = (
            body.boundary_sweep_folder_path.strip().strip("/") or None
        )
    if body.boundary_sweep_max_folder_depth is not None:
        # Treat 0 / negative as "clear" so the UI can revert to defaults by
        # sending 0; non-positive caps would otherwise produce an empty walk.
        c.boundary_sweep_max_folder_depth = (
            body.boundary_sweep_max_folder_depth
            if body.boundary_sweep_max_folder_depth > 0
            else None
        )
    if body.boundary_sweep_max_stale_items is not None:
        c.boundary_sweep_max_stale_items = (
            body.boundary_sweep_max_stale_items
            if body.boundary_sweep_max_stale_items > 0
            else None
        )
    if body.enable_boundary_sweep is not None:
        c.enable_boundary_sweep = body.enable_boundary_sweep
    if body.gitlab_server_url is not None:
        c.gitlab_server_url = body.gitlab_server_url.strip().rstrip("/") or None
    if body.gitlab_project_paths is not None:
        # Full-replacement list. Trim each entry, strip leading/trailing
        # slashes (project paths are stored sans slash), and drop empties so
        # the UI sending `[""]` doesn't materialize a junk row.
        c.gitlab_project_paths = [
            p.strip().strip("/") for p in body.gitlab_project_paths if p and p.strip()
        ]
    if body.gitlab_ref is not None:
        # Empty string resets to the "HEAD" default rather than None — the
        # walker uses gitlab_ref unconditionally and expects a string.
        c.gitlab_ref = body.gitlab_ref.strip() or "HEAD"
    if body.gitlab_include_globs is not None:
        c.gitlab_include_globs = [
            g.strip() for g in body.gitlab_include_globs if g and g.strip()
        ]
    if body.enable_gitlab is not None:
        c.enable_gitlab = body.enable_gitlab
    if body.confluence_base_url is not None:
        c.confluence_base_url = body.confluence_base_url.strip().rstrip("/") or None
    if body.confluence_username is not None:
        c.confluence_username = body.confluence_username.strip() or None
    if body.confluence_space_keys is not None:
        # Normalise comma-separated list: strip whitespace around each key
        # and drop empties. "PROG, DEV ," ⇒ "PROG,DEV". "" or all-blank ⇒
        # None (clear).
        keys = [k.strip() for k in body.confluence_space_keys.split(",") if k.strip()]
        c.confluence_space_keys = ",".join(keys) if keys else None
    if body.confluence_max_pages is not None:
        if body.confluence_max_pages < 1:
            raise HTTPException(
                status_code=400,
                detail="confluence_max_pages must be >= 1",
            )
        c.confluence_max_pages = body.confluence_max_pages
    if body.enable_confluence is not None:
        c.enable_confluence = body.enable_confluence
    if body.confluence_upcoming_gated_enabled is not None:
        c.confluence_upcoming_gated_enabled = body.confluence_upcoming_gated_enabled
    if body.connectors_v04_enabled is not None:
        c.connectors_v04_enabled = body.connectors_v04_enabled
    if body.jira_server_url is not None:
        c.jira_server_url = body.jira_server_url.strip().rstrip("/") or None
    if body.jira_allowed_jql_queries is not None:
        # Drop entries missing either name or jql; trim whitespace on both
        # so a leading space in the textarea doesn't break the lookup. The
        # underlying field is plain ``list[dict]`` so we re-pack as dicts
        # rather than mutate in place.
        cleaned: list[dict] = []
        for item in body.jira_allowed_jql_queries:
            name = str(item.get("name", "")).strip()
            jql = str(item.get("jql", "")).strip()
            if name and jql:
                cleaned.append({"name": name, "jql": jql})
        c.jira_allowed_jql_queries = cleaned
    if body.jira_max_results_per_query is not None:
        # Treat 0 / negative as "use the connector default" (None) rather
        # than persisting nonsense. The UI surfaces the int directly.
        c.jira_max_results_per_query = (
            body.jira_max_results_per_query if body.jira_max_results_per_query > 0 else None
        )
    if body.jira_verify_ssl is not None:
        c.jira_verify_ssl = body.jira_verify_ssl
    if body.enable_jira is not None:
        c.enable_jira = body.enable_jira
    if body.jira_upcoming_gated is not None:
        c.jira_upcoming_gated = body.jira_upcoming_gated
    if body.audit_citations_enabled is not None:
        c.audit_citations_enabled = body.audit_citations_enabled
    cfg.save_config(c)
    return {"ok": True}


@router.post("/anthropic-key")
def set_anthropic_key(body: ApiKeyBody) -> dict:
    if not body.key or len(body.key) < 10:
        raise HTTPException(status_code=400, detail="Invalid API key")
    cfg.set_anthropic_key(body.key)
    return {"ok": True}


@router.delete("/anthropic-key")
def clear_anthropic_key() -> dict:
    cfg.clear_anthropic_key()
    return {"ok": True}


@router.post("/anthropic-gateway-token")
def set_anthropic_gateway_token(body: GatewayTokenBody) -> dict:
    """Persist a corporate / high-side gateway auth token in the OS keyring.

    Stored under a separate keyring slot from the personal sk-ant key so users
    on dev workstations that talk to both endpoints don't have to overwrite one
    to use the other. ``resolve_anthropic_endpoint()`` prefers this token over
    the env var and the sk-ant key when ``anthropic_base_url`` is set.
    """
    if not body.token or len(body.token) < 4:
        raise HTTPException(status_code=400, detail="Token too short")
    cfg.set_gateway_token(body.token)
    return {"ok": True}


@router.delete("/anthropic-gateway-token")
def clear_anthropic_gateway_token() -> dict:
    cfg.clear_gateway_token()
    return {"ok": True}


@router.post("/anthropic-key/test")
def test_anthropic_key() -> dict:
    """Round-trip a tiny Anthropic call to prove the stored key works.

    Uses Haiku for a near-free probe (~50 input + ~10 output tokens).
    Returns the model echo + token usage so the UI can show real success
    rather than just a 200 OK. Surfaces 401 (bad key) / 429 / 5xx as
    HTTPExceptions with the upstream message intact.
    """
    base_url, key = cfg.resolve_anthropic_endpoint()
    if not key:
        raise HTTPException(
            status_code=400,
            detail="No API key stored (and no ANTHROPIC_AUTH_TOKEN env var set).",
        )
    try:
        from anthropic import Anthropic  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover
        raise HTTPException(
            status_code=500,
            detail="`anthropic` SDK is not installed in the sidecar env.",
        ) from exc

    # base_url is pinned explicitly so the SDK ignores any ambient
    # ANTHROPIC_BASE_URL env var. Defaults to https://api.anthropic.com;
    # users opt into a corporate AI gateway by setting anthropic_base_url
    # in config.toml.
    client = Anthropic(api_key=key, base_url=base_url)
    probe_model = "claude-haiku-4-5-20251001"
    try:
        resp = client.messages.create(
            model=probe_model,
            max_tokens=16,
            temperature=0.0,
            messages=[{"role": "user", "content": "Reply with the single word OK."}],
        )
    except Exception as exc:  # noqa: BLE001 — surface ANY upstream failure verbatim
        status = getattr(exc, "status_code", None) or 502
        msg = str(exc)
        hint = ""
        # Distinguish corporate-proxy TLS failures from real auth/billing errors.
        # The anthropic SDK wraps httpx errors into APIConnectionError → "Connection error."
        # On a corporate workstation, that's almost always the proxy MITM cert not being
        # in Python's trust store.
        lowered = msg.lower()
        if "connection error" in lowered or "ssl" in lowered or "certificate" in lowered:
            hint = (
                " (Likely cause on a corporate workstation: Python doesn't trust the "
                "corporate proxy's TLS cert. Set SSL_CERT_FILE and REQUESTS_CA_BUNDLE to "
                "the corporate root CA — same file NODE_EXTRA_CA_CERTS points at — and "
                "restart the sidecar.)"
            )
        elif "credit balance" in lowered or "billing" in lowered:
            hint = " (Account has no API credits — add a payment method at console.anthropic.com.)"
        elif int(status) == 401:
            hint = " (HTTP 401 — the stored key was rejected. Re-save a valid key from console.anthropic.com.)"
        raise HTTPException(status_code=int(status), detail=msg + hint) from exc

    # Pull the first text block
    text = ""
    for block in getattr(resp, "content", []) or []:
        if getattr(block, "type", None) == "text":
            text = (getattr(block, "text", "") or "").strip()
            break

    usage = getattr(resp, "usage", None)
    return {
        "ok": True,
        "model": probe_model,
        "base_url": base_url,
        "reply": text,
        "input_tokens": getattr(usage, "input_tokens", 0) if usage else 0,
        "output_tokens": getattr(usage, "output_tokens", 0) if usage else 0,
    }


@router.post("/anthropic-gateway/test")
def test_anthropic_gateway() -> dict:
    """Round-trip a tiny Anthropic call using ONLY the gateway URL + gateway token.

    Distinct from ``/anthropic-key/test``, which goes through
    ``resolve_anthropic_endpoint()`` and silently falls back to the personal
    sk-ant key when no gateway token is present. This endpoint refuses to fall
    back — it's the "did my corporate gateway setup actually work" probe — so
    a 400 here means the gateway URL or token slot is empty.
    """
    c = cfg.load_config()
    base_url = (c.anthropic_base_url or "").strip()
    if not base_url:
        raise HTTPException(
            status_code=400,
            detail="No gateway base URL set. Save one above first.",
        )
    import os as _os

    # Prefer the keyring slot; allow ANTHROPIC_AUTH_TOKEN env var as a fallback
    # because that's the convention the resolver also honors, and on locked-down
    # corp boxes the token sometimes lives only in the env.
    token = cfg.get_gateway_token() or _os.environ.get("ANTHROPIC_AUTH_TOKEN")
    if not token:
        raise HTTPException(
            status_code=400,
            detail=(
                "No gateway auth token stored (and ANTHROPIC_AUTH_TOKEN env var "
                "is not set). Save a token above first."
            ),
        )
    try:
        from anthropic import Anthropic  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover
        raise HTTPException(
            status_code=500,
            detail="`anthropic` SDK is not installed in the sidecar env.",
        ) from exc

    client = Anthropic(api_key=token, base_url=base_url)
    probe_model = "claude-haiku-4-5-20251001"
    try:
        resp = client.messages.create(
            model=probe_model,
            max_tokens=16,
            temperature=0.0,
            messages=[{"role": "user", "content": "Reply with the single word OK."}],
        )
    except Exception as exc:  # noqa: BLE001
        status = getattr(exc, "status_code", None) or 502
        msg = str(exc)
        hint = ""
        lowered = msg.lower()
        if "connection error" in lowered or "ssl" in lowered or "certificate" in lowered:
            hint = (
                " (Likely cause on a corporate workstation: Python doesn't trust the "
                "corporate proxy's TLS cert. Set SSL_CERT_FILE and REQUESTS_CA_BUNDLE to "
                "the corporate root CA — same file NODE_EXTRA_CA_CERTS points at — and "
                "restart the sidecar.)"
            )
        elif int(status) == 401:
            hint = " (HTTP 401 — the gateway rejected the token. Check the stored token.)"
        elif int(status) == 404:
            # Gateways often serve a different model id than api.anthropic.com.
            # The probe model is locked to Haiku 4.5; if the gateway only proxies
            # a single named model the probe will 404.
            hint = (
                f" (HTTP 404 — gateway '{base_url}' doesn't expose the probe model "
                f"'{probe_model}'. The gateway likely proxies only a fixed model id "
                "(e.g. claude-4-7-opus); set that as your default model under Defaults "
                "and the assessor flow will work even if this probe fails.)"
            )
        raise HTTPException(status_code=int(status), detail=msg + hint) from exc

    text = ""
    for block in getattr(resp, "content", []) or []:
        if getattr(block, "type", None) == "text":
            text = (getattr(block, "text", "") or "").strip()
            break

    usage = getattr(resp, "usage", None)
    return {
        "ok": True,
        "model": probe_model,
        "base_url": base_url,
        "reply": text,
        "input_tokens": getattr(usage, "input_tokens", 0) if usage else 0,
        "output_tokens": getattr(usage, "output_tokens", 0) if usage else 0,
    }


@router.get("/anthropic-models")
def list_anthropic_models() -> dict:
    """Proxy Anthropic's /v1/models so the UI dropdown stays fresh.

    Returns the live model list keyed off the user's stored API key + base_url.
    Surfaces the same corporate-proxy / 401 / billing hints as /anthropic-key/test
    so the UI can show why the dropdown is empty (key not set, proxy blocked,
    etc.) and fall back to a free-text input.
    """
    base_url, key = cfg.resolve_anthropic_endpoint()
    if not key:
        raise HTTPException(
            status_code=400,
            detail="No API key stored (and no ANTHROPIC_AUTH_TOKEN env var set).",
        )
    try:
        from anthropic import Anthropic  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover
        raise HTTPException(
            status_code=500,
            detail="`anthropic` SDK is not installed in the sidecar env.",
        ) from exc

    client = Anthropic(api_key=key, base_url=base_url)
    try:
        page = client.models.list(limit=100)
    except Exception as exc:  # noqa: BLE001 — surface ANY upstream failure verbatim
        status = getattr(exc, "status_code", None) or 502
        msg = str(exc)
        hint = ""
        lowered = msg.lower()
        if "connection error" in lowered or "ssl" in lowered or "certificate" in lowered:
            hint = (
                " (Likely cause on a corporate workstation: Python doesn't trust the "
                "corporate proxy's TLS cert. Set SSL_CERT_FILE and REQUESTS_CA_BUNDLE to "
                "the corporate root CA — same file NODE_EXTRA_CA_CERTS points at — and "
                "restart the sidecar.)"
            )
        elif int(status) == 401:
            hint = " (HTTP 401 — the stored key was rejected. Re-save a valid key from console.anthropic.com.)"
        elif int(status) == 404:
            # Corporate AI gateways (and some proxies) commonly expose /v1/messages
            # but not /v1/models. Surface that as the most likely cause rather than
            # the bare 404 text.
            hint = (
                f" (HTTP 404 — the configured base_url '{base_url}' doesn't expose "
                "/v1/models. Common on corporate AI gateways that only proxy "
                "/v1/messages. Type your model id by hand instead — the dropdown is "
                "a convenience, not a requirement.)"
            )
        raise HTTPException(status_code=int(status), detail=msg + hint) from exc

    models = []
    for m in getattr(page, "data", []) or []:
        models.append(
            {
                "id": getattr(m, "id", None),
                "display_name": getattr(m, "display_name", None) or getattr(m, "id", None),
                "created_at": (
                    getattr(m, "created_at", None).isoformat()
                    if getattr(m, "created_at", None) is not None
                    and hasattr(getattr(m, "created_at"), "isoformat")
                    else getattr(m, "created_at", None)
                ),
            }
        )
    return {"base_url": base_url, "models": models}


# ---------------------------------------------------------------------------
# OpenAI endpoints — mirror the Anthropic shape so the UI cards stay symmetric
# ---------------------------------------------------------------------------


@router.post("/openai-key")
def set_openai_key(body: ApiKeyBody) -> dict:
    if not body.key or len(body.key) < 10:
        raise HTTPException(status_code=400, detail="Invalid API key")
    cfg.set_openai_key(body.key)
    return {"ok": True}


@router.delete("/openai-key")
def clear_openai_key() -> dict:
    cfg.clear_openai_key()
    return {"ok": True}


@router.post("/openai-gateway-token")
def set_openai_gateway_token(body: GatewayTokenBody) -> dict:
    """Persist a corporate / high-side OpenAI gateway auth token in the OS keyring.

    Mirrors the Anthropic gateway-token flow. Stored under a separate keyring
    slot from the personal OpenAI key so users on dev workstations that talk
    to both endpoints don't have to overwrite one to use the other.
    ``resolve_openai_endpoint()`` prefers this token over env vars and the
    personal key when ``openai_base_url`` is set.
    """
    if not body.token or len(body.token) < 4:
        raise HTTPException(status_code=400, detail="Token too short")
    cfg.set_openai_gateway_token(body.token)
    return {"ok": True}


@router.delete("/openai-gateway-token")
def clear_openai_gateway_token() -> dict:
    cfg.clear_openai_gateway_token()
    return {"ok": True}


@router.post("/openai-key/test")
def test_openai_key() -> dict:
    """Round-trip a tiny OpenAI call to prove the stored key works.

    Uses gpt-4o-mini for a near-free probe. Returns the model echo + token
    usage so the UI can show real success. Same corporate-proxy / 401 / 404
    hint logic as the Anthropic probe.
    """
    base_url, key = cfg.resolve_openai_endpoint()
    if not key:
        raise HTTPException(
            status_code=400,
            detail="No OpenAI key stored (and no OPENAI_API_KEY env var set).",
        )
    try:
        from openai import OpenAI  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover
        raise HTTPException(
            status_code=500,
            detail="`openai` SDK is not installed in the sidecar env.",
        ) from exc

    client = OpenAI(api_key=key, base_url=base_url)
    probe_model = "gpt-4o-mini"
    try:
        resp = client.chat.completions.create(
            model=probe_model,
            max_tokens=16,
            temperature=0.0,
            messages=[{"role": "user", "content": "Reply with the single word OK."}],
        )
    except Exception as exc:  # noqa: BLE001
        status = getattr(exc, "status_code", None) or 502
        msg = str(exc)
        hint = ""
        lowered = msg.lower()
        if "connection error" in lowered or "ssl" in lowered or "certificate" in lowered:
            hint = (
                " (Likely cause on a corporate workstation: Python doesn't trust the "
                "corporate proxy's TLS cert. Set SSL_CERT_FILE and REQUESTS_CA_BUNDLE to "
                "the corporate root CA — same file NODE_EXTRA_CA_CERTS points at — and "
                "restart the sidecar.)"
            )
        elif "insufficient_quota" in lowered or "billing" in lowered:
            hint = " (Account has no API credits — add a payment method at platform.openai.com.)"
        elif int(status) == 401:
            hint = " (HTTP 401 — the stored key was rejected. Re-save a valid key from platform.openai.com.)"
        raise HTTPException(status_code=int(status), detail=msg + hint) from exc

    text = ""
    choices = getattr(resp, "choices", None) or []
    if choices:
        msg_obj = getattr(choices[0], "message", None)
        if msg_obj is not None:
            text = (getattr(msg_obj, "content", "") or "").strip()

    usage = getattr(resp, "usage", None)
    return {
        "ok": True,
        "model": probe_model,
        "base_url": base_url,
        "reply": text,
        "input_tokens": getattr(usage, "prompt_tokens", 0) if usage else 0,
        "output_tokens": getattr(usage, "completion_tokens", 0) if usage else 0,
    }


@router.post("/openai-gateway/test")
def test_openai_gateway() -> dict:
    """Round-trip a tiny OpenAI call using ONLY the gateway URL + gateway token.

    Symmetric to ``/anthropic-gateway/test``. Refuses to fall back to the
    personal OpenAI key — a 400 here means the gateway URL or token slot is
    empty.
    """
    c = cfg.load_config()
    base_url = (c.openai_base_url or "").strip()
    if not base_url:
        raise HTTPException(
            status_code=400,
            detail="No gateway base URL set. Save one above first.",
        )
    import os as _os

    token = (
        cfg.get_openai_gateway_token()
        or _os.environ.get("OPENAI_AUTH_TOKEN")
    )
    if not token:
        raise HTTPException(
            status_code=400,
            detail=(
                "No gateway auth token stored (and OPENAI_AUTH_TOKEN env var "
                "is not set). Save a token above first."
            ),
        )
    try:
        from openai import OpenAI  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover
        raise HTTPException(
            status_code=500,
            detail="`openai` SDK is not installed in the sidecar env.",
        ) from exc

    client = OpenAI(api_key=token, base_url=base_url)
    probe_model = "gpt-4o-mini"
    try:
        resp = client.chat.completions.create(
            model=probe_model,
            max_tokens=16,
            temperature=0.0,
            messages=[{"role": "user", "content": "Reply with the single word OK."}],
        )
    except Exception as exc:  # noqa: BLE001
        status = getattr(exc, "status_code", None) or 502
        msg = str(exc)
        hint = ""
        lowered = msg.lower()
        if "connection error" in lowered or "ssl" in lowered or "certificate" in lowered:
            hint = (
                " (Likely cause on a corporate workstation: Python doesn't trust the "
                "corporate proxy's TLS cert. Set SSL_CERT_FILE and REQUESTS_CA_BUNDLE to "
                "the corporate root CA and restart the sidecar.)"
            )
        elif int(status) == 401:
            hint = " (HTTP 401 — the gateway rejected the token.)"
        elif int(status) == 404:
            hint = (
                f" (HTTP 404 — gateway '{base_url}' doesn't expose '{probe_model}'. "
                "Set the gateway's actual model id under Defaults and the assessor "
                "flow will still work even if this probe fails.)"
            )
        raise HTTPException(status_code=int(status), detail=msg + hint) from exc

    text = ""
    choices = getattr(resp, "choices", None) or []
    if choices:
        msg_obj = getattr(choices[0], "message", None)
        if msg_obj is not None:
            text = (getattr(msg_obj, "content", "") or "").strip()

    usage = getattr(resp, "usage", None)
    return {
        "ok": True,
        "model": probe_model,
        "base_url": base_url,
        "reply": text,
        "input_tokens": getattr(usage, "prompt_tokens", 0) if usage else 0,
        "output_tokens": getattr(usage, "completion_tokens", 0) if usage else 0,
    }


@router.get("/openai-models")
def list_openai_models() -> dict:
    """Proxy OpenAI's /v1/models so the UI dropdown stays fresh.

    OpenAI returns hundreds of models (embeddings, tts, dalle, etc.) — we
    filter to the chat-completions-capable families the assessor actually
    uses (gpt-* and o*). The UI can still fall back to a free-text input
    if the filter rejects something the user wants.
    """
    base_url, key = cfg.resolve_openai_endpoint()
    if not key:
        raise HTTPException(
            status_code=400,
            detail="No OpenAI key stored (and no OPENAI_API_KEY env var set).",
        )
    try:
        from openai import OpenAI  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover
        raise HTTPException(
            status_code=500,
            detail="`openai` SDK is not installed in the sidecar env.",
        ) from exc

    client = OpenAI(api_key=key, base_url=base_url)
    try:
        page = client.models.list()
    except Exception as exc:  # noqa: BLE001
        status = getattr(exc, "status_code", None) or 502
        msg = str(exc)
        hint = ""
        lowered = msg.lower()
        if "connection error" in lowered or "ssl" in lowered or "certificate" in lowered:
            hint = (
                " (Likely cause on a corporate workstation: Python doesn't trust the "
                "corporate proxy's TLS cert. Set SSL_CERT_FILE and REQUESTS_CA_BUNDLE to "
                "the corporate root CA and restart the sidecar.)"
            )
        elif int(status) == 401:
            hint = " (HTTP 401 — the stored key was rejected.)"
        raise HTTPException(status_code=int(status), detail=msg + hint) from exc

    models = []
    for m in getattr(page, "data", []) or []:
        mid = getattr(m, "id", "") or ""
        # Filter to chat-completion families. "o1"/"o3" reasoning models
        # included; embeddings / tts / dalle / whisper excluded.
        if not (mid.startswith("gpt-") or mid.startswith("o1") or mid.startswith("o3")):
            continue
        models.append(
            {
                "id": mid,
                "display_name": mid,
                "created_at": getattr(m, "created", None),
            }
        )
    # Newest first by created timestamp when present
    models.sort(key=lambda r: r.get("created_at") or 0, reverse=True)
    return {"base_url": base_url, "models": models}


# ---------------------------------------------------------------------------
# eMASS — v0.2+ stub. Persist the bearer today so the v0.2 client can read
# it back unchanged; status / probe lives under /api/emass/status.
# ---------------------------------------------------------------------------


@router.post("/emass-key")
def set_emass_key(body: ApiKeyBody) -> dict:
    if not body.key or len(body.key) < 4:
        raise HTTPException(status_code=400, detail="API key too short")
    cfg.set_emass_api_key(body.key)
    return {"ok": True}


@router.delete("/emass-key")
def clear_emass_key() -> dict:
    cfg.clear_emass_api_key()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Tenable — v0.4 connector. Both flavors (sc / io) authenticate with an
# access_key + secret_key pair stored in separate keyring slots so the
# Settings card can render two independent "key set" indicators without
# ever exposing the raw values.
# ---------------------------------------------------------------------------


@router.post("/tenable-access-key")
def set_tenable_access_key(body: ApiKeyBody) -> dict:
    if not body.key or len(body.key) < 8:
        raise HTTPException(status_code=400, detail="Access key too short")
    cfg.set_tenable_access_key(body.key)
    return {"ok": True}


@router.delete("/tenable-access-key")
def clear_tenable_access_key() -> dict:
    cfg.clear_tenable_access_key()
    return {"ok": True}


@router.post("/tenable-secret-key")
def set_tenable_secret_key(body: ApiKeyBody) -> dict:
    if not body.key or len(body.key) < 8:
        raise HTTPException(status_code=400, detail="Secret key too short")
    cfg.set_tenable_secret_key(body.key)
    return {"ok": True}


@router.delete("/tenable-secret-key")
def clear_tenable_secret_key() -> dict:
    cfg.clear_tenable_secret_key()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Confluence DC PAT — v0.4+ gated connector. Persist the bearer in the OS
# keyring so evidence/sources/confluence.py::_get_pat() can read it back
# unchanged at iter_files()-time. Status / probe lives under
# /api/confluence/status + /api/confluence/test.
# ---------------------------------------------------------------------------


@router.post("/confluence-pat")
def set_confluence_pat(body: ApiKeyBody) -> dict:
    if not body.key or len(body.key) < 4:
        raise HTTPException(status_code=400, detail="PAT too short")
    cfg.set_confluence_pat(body.key)
    return {"ok": True}


@router.delete("/confluence-pat")
def clear_confluence_pat() -> dict:
    cfg.clear_confluence_pat()
    return {"ok": True}
