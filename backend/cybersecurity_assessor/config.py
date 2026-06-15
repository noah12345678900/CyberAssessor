"""User-level configuration.

Lives at ``~/.cybersecurity-assessor/config.toml``. The ``ANTHROPIC_API_KEY`` is
stored in the OS keyring (Windows Credential Manager on Windows), not in the TOML
file.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any, Literal

import keyring
import tomli_w
from pydantic import BaseModel, Field

DEFAULT_ANTHROPIC_BASE_URL = "https://api.anthropic.com"
DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"

KEYRING_SERVICE = "cybersecurity-assessor"
KEYRING_KEY_ANTHROPIC = "ANTHROPIC_API_KEY"
# Separate slot for the corporate / high-side gateway auth token so it doesn't
# clobber a user's personal sk-ant key when both are configured (e.g. dev
# machine that talks to both endpoints). Stored alongside the sk-ant key in
# Windows Credential Manager.
KEYRING_KEY_ANTHROPIC_GATEWAY = "ANTHROPIC_GATEWAY_TOKEN"
# OpenAI key lives in its own slot so a user can have both providers configured
# and flip between them in Settings without re-pasting keys.
KEYRING_KEY_OPENAI = "OPENAI_API_KEY"
# Corporate / high-side OpenAI gateway token — same rationale as the Anthropic
# gateway slot. Kept separate from the personal OpenAI key so dev workstations
# that talk to both endpoints don't need to overwrite one to use the other.
KEYRING_KEY_OPENAI_GATEWAY = "OPENAI_GATEWAY_TOKEN"
# eMASS API key — v0.2+ feature. v0.1 stores it so the Settings card has a
# place to land; nothing reads it yet (sources/emass.py is a stub).
KEYRING_KEY_EMASS = "EMASS_API_KEY"
# SharePoint Entra app-registration client secret — only needed if the user
# opts into confidential-client flow. The default device-code public-client
# flow doesn't use a secret; this slot exists for completeness so the Settings
# card can offer "I have a client secret" as an advanced option later.
KEYRING_KEY_SHAREPOINT_SECRET = "SHAREPOINT_CLIENT_SECRET"
# Tenable connector (v0.4) — both .sc and .io use API key pairs
# (access_key + secret_key). They live in two separate keyring slots so a
# user who flips between Tenable.sc on-prem and Tenable.io cloud doesn't
# have to re-paste both halves. The Settings card reports only
# *_key_set booleans — raw values never leave the keyring.
KEYRING_KEY_TENABLE_ACCESS = "TENABLE_ACCESS_KEY"
KEYRING_KEY_TENABLE_SECRET = "TENABLE_SECRET_KEY"
# Splunk auth token (bearer). Token-only auth per evidence/sources/splunk.py —
# password / session-key flows are explicitly rejected at SplunkSource construction.
KEYRING_KEY_SPLUNK_TOKEN = "SPLUNK_AUTH_TOKEN"
# GitLab personal access tokens are stored per-host so users with multiple
# instances (e.g. internal SDA + dev GitLab) don't have to overwrite one to
# use the other. The actual keyring slot is
#   f"{KEYRING_KEY_GITLAB_PREFIX}{sanitized_host}"
# where the sanitization lives in evidence/sources/gitlab.py
# (_keyring_key_for_host). The token resolver also consults the GITLAB_TOKEN
# env var first so CI / shared dev boxes can skip the keyring entirely.
KEYRING_KEY_GITLAB_PREFIX = "GITLAB_TOKEN__"
# Confluence Data Center personal access token (PAT) — v0.4+ gated connector.
# Bearer-token auth via atlassian-python-api ``token=`` kwarg. The PAT is
# read by evidence/sources/confluence.py::_get_pat() in this precedence:
# CONFLUENCE_PAT env var first, then this keyring slot. NEVER persisted to
# config.toml; NEVER accepted as a constructor argument.
KEYRING_KEY_CONFLUENCE_PAT = "CONFLUENCE_PAT"
# Jira PAT (Personal Access Token) — double-gated v0.4+ connector. Stored in
# the OS keyring rather than config.toml so a stolen TOML doesn't leak the
# token. The Settings card writes via POST /api/jira/pat; clearing is an
# explicit DELETE.
KEYRING_KEY_JIRA_PAT = "JIRA_PAT"


def config_dir() -> Path:
    p = Path.home() / ".cybersecurity-assessor"
    p.mkdir(parents=True, exist_ok=True)
    return p


def config_path() -> Path:
    return config_dir() / "config.toml"


def db_path() -> Path:
    return config_dir() / "assessor.sqlite"


def working_copies_dir() -> Path:
    """Per-workbook editable copies live under Downloads, not the config dir.

    The user wants the assessed workbooks where they'd naturally look for
    outputs from a desktop app — ``~/Downloads/CyberAssessor/`` — instead
    of buried in a dotfile config tree. Downloads is the user's *local*
    Downloads folder (not the OneDrive sync target), so the original
    rationale for hiding under ``~/.cybersecurity-assessor/`` (avoiding
    sync-engine races) doesn't apply here.

    The per-workbook-id subdirectory is created lazily by
    ``working_copy.derive_working_path``; this function only owns the
    top-level program folder.
    """
    p = Path.home() / "Downloads" / "CyberAssessor"
    p.mkdir(parents=True, exist_ok=True)
    return p


def extracted_text_dir() -> Path:
    p = config_dir() / "extracted_text"
    p.mkdir(parents=True, exist_ok=True)
    return p


class AppConfig(BaseModel):
    """Persistent user config (everything except secrets)."""

    default_tester: str = Field(default="Noah Jaskolski")
    onedrive_root: str | None = Field(default=None)
    evidence_roots: list[str] = Field(default_factory=list)
    last_workbook: str | None = Field(default=None)
    anthropic_model: str = Field(default="claude-opus-4-6")
    llm_max_tokens: int = Field(default=4096)
    # Per-file text-extraction byte budget. Huge logs are less valuable than a
    # Splunk insight query result, but truncated text beats nothing — so we
    # truncate rather than reject. None ⇒ fall back to ingest.MAX_FILE_BYTES
    # (25 MB). Override here to tighten (e.g. 5_000_000 for a shallow walk) or
    # loosen (0 for unlimited — not recommended on large log files). Positive
    # values only; a value of 0 or negative is treated as unlimited by ingest.py.
    max_file_bytes: int | None = Field(default=None)
    # Per-workbook evidence retention cap. When a workbook's Evidence row count
    # exceeds this value, the oldest safe-to-evict rows are deleted to bring the
    # count back to the cap. "Safe to evict" excludes anything referenced by
    # tags, STIG findings, POAMs, assessments, or marked as asset-list /
    # boundary-doc. None ⇒ fall back to evidence_retention.DEFAULT_RETENTION_CAP
    # (30_000). Set to 0 to disable retention enforcement entirely.
    evidence_retention_cap: int | None = Field(default=None)
    # Optional override of the Anthropic API endpoint. Leave None to talk to
    # https://api.anthropic.com with your personal sk-ant key (default).
    # Set to a corporate AI-gateway URL (e.g. https://api.ai.corp.example) to
    # use that endpoint instead — auth token will be read from the
    # ANTHROPIC_AUTH_TOKEN environment variable in that mode (Claude Code's
    # convention), falling back to the keyring key if the env var is unset.
    anthropic_base_url: str | None = Field(default=None)
    # LLM provider toggle. Anthropic is the default because of prompt-caching
    # economics on our ~3-4k cached system prompt; OpenAI is offered as a
    # user-selectable alternate (Settings → Defaults) so the assessor can flip
    # providers without a redeploy when one is rate-limited / down / blocked
    # by corporate egress. The Protocol-based LlmClient in engine/assessor.py
    # is the abstraction boundary — both clients implement it.
    llm_provider: Literal["anthropic", "openai"] = Field(default="anthropic")
    openai_model: str = Field(default="gpt-5.1")
    openai_base_url: str | None = Field(default=None)
    # ------------------------------------------------------------------
    # SharePoint sweep LLM-judge knobs (v0.2)
    #
    # The sweep ranks candidate evidence files. v0.1 was pure keyword
    # scoring (sweep.py). v0.2 layers an LLM judge on top — a short-
    # rubric classifier that scores each survivor against the cached
    # boundary brief, then blends 0.30*keyword + 0.70*llm into the
    # surfaced score.
    #
    # Defaults sized for a strong first sweep with no tuning: Haiku judge
    # (short-rubric classification sweet spot), 16 concurrent workers
    # (doubles throughput vs the conservative 8; occasional 429s are
    # absorbed by the shared global retry path in
    # llm/_rate_limit.py::run_with_rate_limit_retry, gated below
    # ``llm_max_concurrency`` so bursts rarely trip the limit in the first
    # place — sweep_judge.py no longer carries its own per-call backoff),
    # no cost cap. A real
    # SharePoint corpus (210k+ files) makes a fixed-dollar cap meaningless
    # — Haiku judge cost at scale is bounded by the keyword pre-filter
    # survivor count, not by a budget. ``sweep_cost_cap_usd <= 0`` ⇒
    # unlimited (default).
    #
    # No Settings UI for these — power users override via
    # ~/.cybersecurity-assessor/config.toml directly. The kill-switch
    # (sweep_judge_enabled=False) falls back to pure keyword scoring.
    # ------------------------------------------------------------------
    llm_judge_model: str = Field(default="claude-haiku-4-5-20251001")
    sweep_cost_cap_usd: float = Field(default=0.0)
    sweep_judge_workers: int = Field(default=16)
    sweep_judge_enabled: bool = Field(default=True)
    # Tier 5-LLM "smart backstop" in the evidence tagger. When True (default),
    # an under-tagged artifact (fewer than _TIER5_MIN_EXISTING deterministic
    # tags) is judged by ``llm_judge_model`` against TF-IDF-pre-selected
    # candidate controls instead of the blunt TF-IDF cosine — the judge accepts
    # only confident matches (source="llm") and abstains otherwise. Kill-switch:
    # set False to fall back to the deterministic TF-IDF Tier 5 (offline / no
    # API key). Mirrors sweep_judge_enabled; no Settings UI, config.toml only.
    tagger_llm_enabled: bool = Field(default=True)
    # Global ceiling on *in-flight* LLM calls across the whole process, enforced
    # by a single semaphore in llm/_rate_limit.py that every call funnels
    # through (judge, tagger, sweep, assess — all of them). This is admission
    # control, not a worker count: the tagger may have 16 judge threads and the
    # sweep another 16, but only ``llm_max_concurrency`` of them hold a slot at
    # once; the rest block at the gate. Sizing the gate below the sum of the
    # per-stage worker pools is what keeps a burst from tripping the gateway's
    # "Too many calls" 429 in the first place, so the retry budget in
    # _rate_limit.py becomes a backstop instead of the primary throttle.
    # Default 10 matches the Example gateway's comfortable sustained rate observed
    # during assess-batch runs. ``<= 0`` ⇒ no global cap (each pool self-limits).
    # config.toml only — no Settings UI.
    llm_max_concurrency: int = Field(default=10)
    # Feature flags for optional connectors
    enable_sharepoint: bool = False
    enable_tenable: bool = False
    # ServiceNow GRC connector (v0.4). When False, evidence.sources.servicenow_grc
    # refuses to construct a Source. Override at runtime with the
    # ``CCIS_ENABLE_SNOW_GRC=1`` env var (mirrors the SWEEP_USE_SEARCH=1 escape
    # hatch in sharepoint.py) so a power-user can light up the connector
    # without touching the persisted config.
    enable_snow_grc: bool = False
    enable_archer: bool = False
    # Splunk saved-search connector — v0.4. Gated off by default; flipping
    # this on exposes the connector in the Settings UI and lets the
    # ingest route construct a SplunkSource from configured saved-search
    # names. See evidence/sources/splunk.py for the defensibility
    # rationale (saved-search names only, never raw SPL).
    enable_splunk: bool = False
    # v0.4 boundary-discovery sweep (sp_boundary_sweep.py). Off by default —
    # it depends on the SharePoint connector being configured first since
    # it reuses the same Graph auth + site routing. When True, the route
    # layer exposes /api/boundary-sweep/status + /test and the Settings card
    # is interactive. When False, the card collapses to a one-sentence
    # "off" body and the connector is dormant (mirrors the existing
    # CCIS_ENABLE_BOUNDARY_SWEEP env-flag semantics inside the source).
    enable_boundary_sweep: bool = False
    # v0.4 GitLab evidence connector (evidence/sources/gitlab.py). Disabled by
    # default; flip True in Settings once server URL + project list + token are
    # configured. Token lives in OS keyring per-host (KEYRING_KEY_GITLAB_PREFIX
    # + sanitized host), never in this TOML.
    enable_gitlab: bool = False
    # GitLab server URL (e.g. https://gitlab.sda-oi.example). None ⇒ "not
    # configured"; the source raises a clear error when the orchestrator tries
    # to walk a GitLabSource without a server set.
    gitlab_server_url: str | None = Field(default=None)
    # Project paths to crawl, e.g. ["sda-oi/example/mdp/tracking-handler"]. Empty
    # list ⇒ nothing to walk (the source iterates zero files cleanly).
    gitlab_project_paths: list[str] = Field(default_factory=list)
    # Git ref to pin URIs to. "HEAD" (the default) resolves to the project's
    # default branch at walk start; users can pin to a tag / branch / SHA per
    # project group via Settings.
    gitlab_ref: str = Field(default="HEAD")
    # Optional file-glob filter. Empty list ⇒ use the source's default
    # ingestible set (*.ckl, *.cklb, *.conf, *.cfg, *.log, *.xml, *.json,
    # *.yaml/.yml, *.txt, *.md, *.pdf). Match is fnmatch-style on the
    # repository-relative path.
    gitlab_include_globs: list[str] = Field(default_factory=list)
    enable_confluence: bool = False
    # ------------------------------------------------------------------
    # Confluence Data Center connector — DOUBLE-GATED (v0.4+ AND
    # upcoming-gated). Parallel to the eMASS pattern.
    #
    # Confluence DC content frequently includes export-controlled or
    # otherwise sensitive program documentation; pulling pages without
    # an explicit per-instance authorization is a non-starter on
    # locked-down tenants. Both flags must be True for the source to
    # iterate.
    #
    # ``connectors_v04_enabled`` is the version cohort gate ("am I on a
    # v0.4+ build that has the post-v0.3 connector wave?"). Shared with
    # the eMASS card — flipping it on enables both connectors' cohort
    # half of the gate.
    #
    # ``confluence_upcoming_gated_enabled`` is the per-connector
    # authorization gate. Even on a v0.4+ build, the Confluence source
    # stays off until the user pastes a real base URL + PAT AND flips
    # this flag. This is the "ISSM has signed off on pulling pages
    # from this instance" switch. As of the single-pill connector
    # refactor these inner gates default ON; the main ``enable_confluence``
    # pill is the only switch the Settings card exposes.
    # ------------------------------------------------------------------
    connectors_v04_enabled: bool = True
    confluence_upcoming_gated_enabled: bool = True
    # Jira connector main pill — the user opts in by flipping this on the
    # Settings card. Double-gated: the second flag (jira_upcoming_gated)
    # also has to be true before any /test or ingest path will construct a
    # JiraSource. Both default False so a fresh install never speaks to
    # Jira until the user opts in twice.
    enable_jira: bool = False
    # Jira upcoming-gated second flag — surfaced INSIDE the Settings card
    # body (not the main pill) per the recipe gotcha #15. Required ack
    # that the program has authorized Jira Data Center API access; refusal
    # to flip this leaves the connector permanently disabled even with
    # enable_jira=True. As of the single-pill connector refactor this
    # inner ack defaults ON; the main ``enable_jira`` pill is the only
    # switch the Settings card exposes.
    jira_upcoming_gated: bool = True
    enable_emass: bool = False
    # ------------------------------------------------------------------
    # eMASS REST connector — DOUBLE-GATED (v0.4+ AND upcoming-gated).
    #
    # eMASS API access requires special tenant-level authorization from the
    # DISA enclave admin (cert distribution + system-id allow-list); we
    # cannot assume any user-installed build is authorized to even touch
    # the endpoint. Both flags must be True for the source to load.
    #
    # ``connectors_v04_enabled`` is the version cohort gate ("am I on a
    # v0.4+ build that has the post-v0.3 connector wave?"). It will flip
    # default-on when v0.4 ships; today it's the release-gate switch.
    #
    # ``emass_upcoming_gated_enabled`` is the per-connector authorization
    # gate. Even on a v0.4+ build, the eMASS source stays off until the
    # user pastes a real cert path + system_id AND flips this flag in
    # config.toml. This is the "you have written confirmation from your
    # ISSM that you may use the API" switch. As of the single-pill
    # connector refactor these inner gates default ON; the main
    # ``enable_emass`` pill is the only switch the Settings card exposes.
    # ------------------------------------------------------------------
    connectors_v04_enabled: bool = True
    emass_upcoming_gated_enabled: bool = True
    # ------------------------------------------------------------------
    # Audit v1 — flag-gated per-claim citation co-emission.
    #
    # When True, the assess prompt asks the LLM to emit a structured
    # ``citations`` array linking each substantive claim in the narrative
    # to a specific evidence chunk and source quote. Persisted into the
    # AssessmentCitation table; surfaced in the ControlDetail Audit trail
    # section.
    #
    # Default ON as of fix #1 (2026-06-10). The citation payload is no
    # longer advisory metadata: the validator now hard-gates each
    # ``source_quote`` against the tagged evidence (UNSUPPORTED_QUOTE), so a
    # fabricated quote is rejected and retried rather than persisted. That
    # turns citations into a precision mechanism — the central
    # defensibility win for a 3PAO/JAB SAR — which outweighs the modeled
    # verdict-regression risk from the extra LLM instruction. Schema +
    # AssessmentTrace + AssessmentEvidenceShown persistence was already
    # unconditional; flipping this default additionally turns on the
    # citation request + parse + source_quote verification. The eval
    # harness still measures regression, but the gate is the safety net
    # that makes default-on defensible. Set False to disable end-to-end.
    # ------------------------------------------------------------------
    audit_citations_enabled: bool = True
    # eMASS connector (v0.2+). Persisted in config.toml so the Settings UI can
    # show the address even before the implementation lands. ``base_url`` None
    # means "not configured" — the /api/emass/status probe reports that.
    emass_base_url: str | None = Field(default=None)
    # Path to a client cert (.pfx / .pem) for mTLS to the eMASS REST API.
    # Persisted (not a secret) so the UI can show the configured path; the
    # cert file itself stays on disk and is loaded lazily by the v0.2 client.
    emass_cert_path: str | None = Field(default=None)
    # Path to the client cert's private key (.pem / .key). Required by
    # ``requests`` mTLS when the cert + key are split across two files
    # (the typical DISA-issued format). When the cert is a single .pfx
    # bundle the key lives inside the bundle and this field is left None.
    # Persisted as a PATH ONLY — the key bytes are NEVER read into config
    # memory or logged; the connector opens the file lazily and hands the
    # path straight to ``requests`` which streams it to OpenSSL.
    emass_key_path: str | None = Field(default=None)
    # eMASS system_id — the per-package GUID that scopes all reads (CCIS
    # exports, POAM list, package status). Required for any non-stub call;
    # persisted because it's a stable identifier, not a credential.
    emass_system_id: str | None = Field(default=None)
    # ------------------------------------------------------------------
    # SharePoint — populated by Settings → SharePoint card. None ⇒ "not
    # configured"; the ingest route surfaces a clear error when the user
    # picks SharePoint as a source without a site URL.
    #
    # Plug-and-play via Microsoft Graph: we use the well-known Graph
    # PowerShell client_id (14d82eec-204b-4c2f-b7e8-296a70dab67e), the
    # `organizations` multi-tenant authority, and the cloud (Commercial /
    # GovCloud / DoD) is derived from the site URL hostname suffix in
    # evidence/sources/sharepoint.py::cloud_for(). So tenant_id /
    # client_id / authority_base are no longer config — pasting a URL is
    # the whole setup. Old config.toml files that still carry those keys
    # are silently dropped on load (pydantic v2 default extra='ignore').
    # ------------------------------------------------------------------
    # Default site to scan, e.g.
    # https://collab.example.com/sites/PRGM-EXAMPLE. The ingest UI
    # can override this per-run but we pre-fill from here.
    sharepoint_site_url: str | None = Field(default=None)
    # Document library display name. Empty ⇒ "Documents" (the default
    # library every site collection ships with).
    sharepoint_library: str | None = Field(default=None)
    # Optional sub-folder inside the library to limit the scan.
    sharepoint_folder_path: str | None = Field(default=None)
    # Quick-access bookmarks the user pastes from the SharePoint browser
    # address bar. Plain {label, url} dicts — no per-link presets, no
    # auto-ingest config. Surfaces in the Browse SharePoint dialog on the
    # Evidence tab as a sidebar "Jump to…" list. Empty by default.
    sharepoint_priority_links: list[dict] = Field(default_factory=list)
    # ------------------------------------------------------------------
    # Tenable — populated by Settings → Tenable card. None ⇒ "not
    # configured"; /api/tenable/status reports that and the Evidence
    # source picker disables the Tenable option with a hint.
    #
    # ``tenable_flavor`` discriminates between Tenable.sc (on-prem
    # SecurityCenter, requires ``tenable_host`` FQDN) and Tenable.io
    # (SaaS, host is implicitly cloud.tenable.com so ``tenable_host``
    # may be None when flavor == "io"). Secrets (access_key /
    # secret_key) are stored in the OS keyring slots above — never
    # in config.toml.
    # ------------------------------------------------------------------
    tenable_flavor: Literal["sc", "io"] | None = Field(default=None)
    tenable_host: str | None = Field(default=None)
    # ServiceNow GRC — populated by Settings → ServiceNow GRC card.
    # None ⇒ "not configured"; /api/servicenow_grc/status reports that
    # and /api/evidence/ingest will refuse a snow-grc source spec.
    #
    # The connector itself lives at evidence/sources/servicenow_grc.py
    # and reads these fields via SnowGrcConfig at construct time. Auth
    # secrets (OAuth client_secret, Basic password) are stored in the
    # OS keyring under KEYRING_KEY_SNOW_OAUTH_SECRET /
    # KEYRING_KEY_SNOW_BASIC_PASSWORD — never persisted here.
    #
    # ``enable_snow_grc`` above is the feature flag (kept under that name
    # for backward compat with the connector module's feature_enabled()
    # check); the UI surfaces it as ``features.servicenow_grc``.
    # ------------------------------------------------------------------
    # Instance host, e.g. https://acme.service-now.com (no trailing
    # slash). The connector strips the trailing slash on save.
    servicenow_grc_instance_url: str | None = Field(default=None)
    # Auth flow — "oauth" (client_credentials grant, default & preferred)
    # or "basic" (HTTP Basic; legacy / dev only).
    servicenow_grc_auth_method: str | None = Field(default=None)
    # Username for Basic auth, or OAuth client_id for the oauth flow.
    # Stored here (not a secret) so the Settings card can show what
    # account is configured without round-tripping to the keyring.
    servicenow_grc_username: str | None = Field(default=None)
    # Tables to sweep. Empty list ⇒ connector defaults
    # (sn_compliance_control, sn_compliance_attestation,
    # sn_risk_risk, sn_risk_issue — see DEFAULT_TABLES in
    # evidence/sources/servicenow_grc.py).
    servicenow_grc_allowed_tables: list[str] = Field(default_factory=list)
    # Archer (RSA Archer / GRC) — populated by Settings → Archer card.
    # None ⇒ "not configured"; /api/archer/status reports unconfigured
    # when any required field is missing. Password is NOT stored here —
    # it lives in the OS keyring under service
    # "cybersecurity-assessor.archer" keyed by username@instance_name
    # (see evidence/sources/archer.py::store_password). Domain is the
    # optional Active-Directory domain string sent on session login;
    # most Archer deployments leave it empty.
    # ------------------------------------------------------------------
    archer_instance_url: str | None = Field(default=None)
    archer_instance_name: str | None = Field(default=None)
    archer_username: str | None = Field(default=None)
    archer_domain: str | None = Field(default=None)
    # Splunk — populated by Settings → Splunk card. None ⇒ "not configured".
    # Token lives in the OS keyring (KEYRING_KEY_SPLUNK_TOKEN); these
    # fields are non-secret connection metadata. Saved-search names are
    # the only run-time scope knob — raw SPL is rejected by SplunkSource.
    # ------------------------------------------------------------------
    # Splunk REST host (e.g. "splunk.example-system.example.mil"). No scheme, no port.
    splunk_host: str | None = Field(default=None)
    # Splunk management port. 8089 is the documented default; persisted
    # explicitly so air-gapped sites that remap can override without
    # touching code.
    splunk_port: int = Field(default=8089)
    # "https" or "http". https is the only sane value in prod; http exists
    # purely so dev/loopback testing doesn't need a cert. Validated by
    # SplunkSource.__init__.
    splunk_scheme: str = Field(default="https")
    # Splunk app namespace for the saved searches. "search" is the default
    # global app; programs that house their searches in a custom app
    # (e.g. "example-system_security") set it here.
    splunk_app: str = Field(default="search")
    # Splunk owner namespace. "-" means "any owner" — the right default
    # for shared saved searches. Set to a specific username only if the
    # saved searches are private to one operator.
    splunk_owner: str = Field(default="-")
    # TLS cert verification. Default True. False is loud (UserWarning at
    # SplunkSource construction) and should only be flipped for lab Splunk
    # instances behind a self-signed cert.
    splunk_verify_tls: bool = Field(default=True)
    # Saved-search allow-list. Each entry is a Splunk saved-search NAME
    # already defined on the Splunk side; the connector refuses anything
    # else. Empty ⇒ no ingestible searches yet ⇒ /status reports not
    # configured. List of plain strings; ordering preserved for the
    # Sweep UI's checkbox list.
    splunk_saved_searches: list[str] = Field(default_factory=list)
    # SharePoint Boundary Sweep — v0.4 connector
    #
    # Reuses the SharePoint connector's site URL + Graph auth, so it has
    # almost no connection state of its own. The two knobs below override
    # the conservative defaults baked into ``BoundarySweepCaps`` for power
    # users who want a deeper walk on a specific site. None ⇒ use the
    # dataclass default (max_folder_depth=4, max_stale_title_items=100).
    #
    # An optional starting folder lets the user scope the boundary walk
    # to a sub-tree of the SharePoint library (e.g. /Authorization/), so
    # the sweep doesn't enumerate libraries irrelevant to the ATO package.
    # Empty / None ⇒ walk from the library root.
    # ------------------------------------------------------------------
    boundary_sweep_folder_path: str | None = Field(default=None)
    boundary_sweep_max_folder_depth: int | None = Field(default=None)
    boundary_sweep_max_stale_items: int | None = Field(default=None)
    # Confluence Data Center — populated by Settings → Confluence card.
    # None ⇒ "not configured"; the /api/confluence/status probe surfaces
    # that to the UI. The PAT itself lives in the keyring (slot
    # ``CONFLUENCE_PAT``) — never in config.toml.
    #
    # Scope is exclusive-OR at the source layer (cql XOR space_keys);
    # the Settings card only exposes space_keys (the common case). Users
    # who want a CQL-scoped sweep can override at ingest-time.
    # ------------------------------------------------------------------
    # Base URL of the Confluence DC instance, e.g.
    # https://confluence.example.com/wiki. Trailing slash stripped on
    # save. The source appends ``/rest/api/...`` paths itself.
    confluence_base_url: str | None = Field(default=None)
    # Username associated with the PAT — Confluence DC expects the
    # username alongside the bearer token for audit log attribution.
    # Stored in cleartext (it's the same login the user already types
    # into the web UI; not a credential on its own without the PAT).
    confluence_username: str | None = Field(default=None)
    # Comma-separated list of space keys to walk, e.g. "PROG,DEV,SEC".
    # Empty ⇒ "no scope configured" (the source will refuse to iterate
    # without either a CQL query or non-empty space_keys). Persisted
    # as a string to keep the Settings round-trip simple; the source
    # splits on commas itself.
    confluence_space_keys: str | None = Field(default=None)
    # Max pages per space to fetch in a single ingest run. Defaults to
    # 500 — enough to capture a typical program space without blowing
    # out the LLM judge cost on the inevitable noise pages. Users can
    # bump this for completeness sweeps via Settings; the source itself
    # imposes no hard cap (it'll walk until the iterator runs out).
    confluence_max_pages: int = Field(default=500)
    # Jira — double-gated v0.4+ connector. Populated by Settings → Jira
    # card. None ⇒ "not configured"; the /api/jira/status probe surfaces
    # that state. The PAT itself lives in the OS keyring (slot
    # KEYRING_KEY_JIRA_PAT); only the server URL + named JQL list + tuning
    # knobs are persisted in config.toml.
    #
    # ``jira_allowed_jql_queries`` is a list of ``{name, jql}`` dicts. The
    # connector is config-bound — the UI never lets the user run a
    # free-form runtime query, so a leaked Settings page can't be turned
    # into an arbitrary-JQL execution surface. The route layer extracts
    # the ``jql`` values when constructing the underlying JiraConfig.
    # ------------------------------------------------------------------
    jira_server_url: str | None = Field(default=None)
    jira_allowed_jql_queries: list[dict] = Field(default_factory=list)
    # Per-query result cap — defends against a runaway JQL dumping 80k
    # tickets into the evidence index. None ⇒ use the JiraConfig default
    # (1000) at construction time.
    jira_max_results_per_query: int | None = Field(default=None)
    # TLS verification — defaults True. Power users with a private CA on
    # an internal Jira Data Center instance can flip this to False from
    # config.toml; the Settings card does NOT expose it (would be a
    # foot-gun on the main UI).
    jira_verify_ssl: bool = Field(default=True)
    # ------------------------------------------------------------------
    # Automation scheduler (v2.0 seed)
    #
    # ``automation_enabled`` is the master switch; False (default) keeps
    # the scheduler dormant so existing deployments are unaffected until
    # the user opts in via config.toml.  ``automation_tick_seconds`` is
    # how often the tick loop wakes to check for due schedules — 60 s
    # is fine-grained enough for minute-level scheduling while burning
    # negligible CPU.
    # ------------------------------------------------------------------
    automation_enabled: bool = Field(default=False)
    automation_tick_seconds: int = Field(default=60)


def load_config() -> AppConfig:
    p = config_path()
    if not p.exists():
        cfg = AppConfig()
        save_config(cfg)
        return cfg
    with p.open("rb") as f:
        raw: dict[str, Any] = tomllib.load(f)
    return AppConfig.model_validate(raw)


def save_config(cfg: AppConfig) -> None:
    p = config_path()
    with p.open("wb") as f:
        tomli_w.dump(cfg.model_dump(exclude_none=True), f)


def get_anthropic_key() -> str | None:
    try:
        return keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_ANTHROPIC)
    except Exception:
        return None


def set_anthropic_key(key: str) -> None:
    keyring.set_password(KEYRING_SERVICE, KEYRING_KEY_ANTHROPIC, key)


def clear_anthropic_key() -> None:
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_KEY_ANTHROPIC)
    except keyring.errors.PasswordDeleteError:
        pass


def get_gateway_token() -> str | None:
    try:
        return keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_ANTHROPIC_GATEWAY)
    except Exception:
        return None


def set_gateway_token(token: str) -> None:
    keyring.set_password(KEYRING_SERVICE, KEYRING_KEY_ANTHROPIC_GATEWAY, token)


def clear_gateway_token() -> None:
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_KEY_ANTHROPIC_GATEWAY)
    except keyring.errors.PasswordDeleteError:
        pass


def get_openai_key() -> str | None:
    try:
        return keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_OPENAI)
    except Exception:
        return None


def set_openai_key(key: str) -> None:
    keyring.set_password(KEYRING_SERVICE, KEYRING_KEY_OPENAI, key)


def clear_openai_key() -> None:
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_KEY_OPENAI)
    except keyring.errors.PasswordDeleteError:
        pass


def get_openai_gateway_token() -> str | None:
    try:
        return keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_OPENAI_GATEWAY)
    except Exception:
        return None


def set_openai_gateway_token(token: str) -> None:
    keyring.set_password(KEYRING_SERVICE, KEYRING_KEY_OPENAI_GATEWAY, token)


def clear_openai_gateway_token() -> None:
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_KEY_OPENAI_GATEWAY)
    except keyring.errors.PasswordDeleteError:
        pass


# ----------------------------------------------------------------------
# eMASS — v0.2+ feature; helpers exist so the Settings UI can persist the
# bearer today and the v0.2 client only has to read it back.
# ----------------------------------------------------------------------


def get_emass_api_key() -> str | None:
    try:
        return keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_EMASS)
    except Exception:
        return None


def set_emass_api_key(key: str) -> None:
    keyring.set_password(KEYRING_SERVICE, KEYRING_KEY_EMASS, key)


def clear_emass_api_key() -> None:
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_KEY_EMASS)
    except keyring.errors.PasswordDeleteError:
        pass


# ----------------------------------------------------------------------
# Tenable — v0.4 connector. Both flavors (sc / io) authenticate with an
# access_key + secret_key pair. Stored in two separate keyring slots so
# the Settings card can show two independent "set / not set" indicators
# without ever exposing the raw values.
# ----------------------------------------------------------------------


def get_tenable_access_key() -> str | None:
    try:
        return keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_TENABLE_ACCESS)
    except Exception:
        return None


# ----------------------------------------------------------------------
# Jira — double-gated v0.4+ connector. PAT lives in OS keyring; the
# Settings card POSTs to /api/jira/pat to set, DELETEs to clear.
# ----------------------------------------------------------------------


def get_jira_pat() -> str | None:
    try:
        return keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_JIRA_PAT)
    except Exception:
        return None


# ----------------------------------------------------------------------
# Confluence DC PAT — v0.4+ gated connector. Helpers mirror the eMASS
# slot pattern so the Settings card can persist the token today without
# touching the source-layer ``_get_pat()`` precedence (env first, then
# this keyring slot). The PAT NEVER lands in config.toml.
# ----------------------------------------------------------------------


def get_confluence_pat() -> str | None:
    try:
        return keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_CONFLUENCE_PAT)
    except Exception:
        return None


# ----------------------------------------------------------------------
# Splunk — v0.4 feature; helpers mirror the eMASS pattern so the Settings
# UI persists the bearer token via /api/splunk/token and the ingest path
# reads it back without ever having to round-trip the token through
# config.toml or the REST surface.
# ----------------------------------------------------------------------


def get_splunk_token() -> str | None:
    try:
        return keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_SPLUNK_TOKEN)
    except Exception:
        return None


def set_tenable_access_key(key: str) -> None:
    keyring.set_password(KEYRING_SERVICE, KEYRING_KEY_TENABLE_ACCESS, key)


def clear_tenable_access_key() -> None:
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_KEY_TENABLE_ACCESS)
    except keyring.errors.PasswordDeleteError:
        pass


def get_tenable_secret_key() -> str | None:
    try:
        return keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_TENABLE_SECRET)
    except Exception:
        return None


def set_tenable_secret_key(key: str) -> None:
    keyring.set_password(KEYRING_SERVICE, KEYRING_KEY_TENABLE_SECRET, key)


def clear_tenable_secret_key() -> None:
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_KEY_TENABLE_SECRET)
    except keyring.errors.PasswordDeleteError:
        pass


def set_splunk_token(token: str) -> None:
    keyring.set_password(KEYRING_SERVICE, KEYRING_KEY_SPLUNK_TOKEN, token)


def clear_splunk_token() -> None:
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_KEY_SPLUNK_TOKEN)
    except keyring.errors.PasswordDeleteError:
        pass


def set_confluence_pat(token: str) -> None:
    keyring.set_password(KEYRING_SERVICE, KEYRING_KEY_CONFLUENCE_PAT, token)


def clear_confluence_pat() -> None:
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_KEY_CONFLUENCE_PAT)
    except keyring.errors.PasswordDeleteError:
        pass


def set_jira_pat(pat: str) -> None:
    keyring.set_password(KEYRING_SERVICE, KEYRING_KEY_JIRA_PAT, pat)


def clear_jira_pat() -> None:
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_KEY_JIRA_PAT)
    except keyring.errors.PasswordDeleteError:
        pass


def resolve_openai_endpoint() -> tuple[str, str | None]:
    """Return (base_url, auth_token) for constructing the OpenAI SDK.

    Symmetric with ``resolve_anthropic_endpoint``:

    - No ``openai_base_url`` set → real OpenAI API, auth = keyring sk-... key
      (falling back to ``OPENAI_API_KEY`` env var so CI / shared dev boxes
      can skip the keyring).
    - ``openai_base_url`` set (corporate / high-side gateway) → that URL,
      auth picked in this order:
        1. Dedicated gateway token in the keyring (preferred — survives
           reboots, no env var fiddling on locked-down workstations).
        2. ``OPENAI_AUTH_TOKEN`` environment variable (mirrors Claude Code's
           ANTHROPIC_AUTH_TOKEN convention; handy for CI / shared dev boxes).
        3. ``OPENAI_API_KEY`` environment variable (legacy fallback).
        4. The personal OpenAI key as a last-resort fallback.

    The second element is None only when no token is stored anywhere; callers
    should raise their own "no key configured" error in that case.
    """
    cfg = load_config()
    base_url = cfg.openai_base_url or DEFAULT_OPENAI_BASE_URL
    if cfg.openai_base_url:
        token = (
            get_openai_gateway_token()
            or os.environ.get("OPENAI_AUTH_TOKEN")
            or os.environ.get("OPENAI_API_KEY")
            or get_openai_key()
        )
    else:
        token = get_openai_key() or os.environ.get("OPENAI_API_KEY")
    return base_url, token


def resolve_anthropic_endpoint() -> tuple[str, str | None]:
    """Return (base_url, auth_token) for constructing the Anthropic SDK.

    Precedence:

    - No ``anthropic_base_url`` set → real Anthropic API, auth = keyring sk-ant
      key.
    - ``anthropic_base_url`` set (corporate / high-side gateway) → that URL,
      auth picked in this order:
        1. Dedicated gateway token in the keyring (preferred — survives
           reboots, no env var fiddling on locked-down workstations).
        2. ``ANTHROPIC_AUTH_TOKEN`` environment variable (Claude Code's
           convention; handy for CI / shared dev boxes).
        3. The personal sk-ant key as a last-resort fallback.

    The second element is None only when no token is stored anywhere; callers
    should raise their own "no key configured" error in that case.
    """
    cfg = load_config()
    base_url = cfg.anthropic_base_url or DEFAULT_ANTHROPIC_BASE_URL
    if cfg.anthropic_base_url:
        token = (
            get_gateway_token()
            or os.environ.get("ANTHROPIC_AUTH_TOKEN")
            or get_anthropic_key()
        )
    else:
        token = get_anthropic_key()
    return base_url, token
