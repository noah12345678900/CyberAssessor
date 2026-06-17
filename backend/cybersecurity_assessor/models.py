"""Normalized data model.

Designed so v0.2+ frameworks (800-171, FedRAMP, CSF, ISO) slot in without
schema migration. ``Framework`` is the root; ``Control`` and ``Objective`` are
generic. CCI is just the ``objective_id`` for 800-53 — AO would be the same
field for 800-171.
"""

import secrets
from datetime import datetime, timezone
from enum import Enum
from typing import List

from sqlalchemy import JSON, Column, Index, UniqueConstraint, text
from sqlmodel import Field, Relationship, Session, SQLModel, select


def _utcnow() -> datetime:
    """Timezone-aware UTC now (replaces deprecated datetime.utcnow)."""
    return datetime.now(timezone.utc)


def iso_utc(dt: datetime | None) -> str | None:
    """Serialize a datetime as a UTC ISO 8601 string the UI can trust.

    SQLite drops ``tzinfo`` on round-trip, so a datetime that was originally
    written by ``_utcnow()`` (tz-aware UTC) comes back naive. Calling
    ``.isoformat()`` on a naive datetime emits ``2026-06-04T15:23:00`` with
    no zone marker, and the JavaScript ``new Date(...)`` parser then
    interprets that as **local time** — producing a 4-5 hour skew for an ET
    user on every Run/Decision/Workbook timestamp.

    This helper attaches UTC tzinfo to naive inputs (we know the writer side
    is always UTC) so the emitted string carries a ``+00:00`` suffix and
    the UI's ``new Date(...).toLocaleString()`` converts to local correctly.
    Already-aware datetimes are passed through.

    ``None`` in, ``None`` out so callers can keep their ``if x else None``
    guards.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ComplianceStatus(str, Enum):
    COMPLIANT = "Compliant"
    NON_COMPLIANT = "Non-Compliant"
    NOT_APPLICABLE = "Not Applicable"


class NarrativeClass(str, Enum):
    """Classification of a draft Q narrative (per SKILL.md rule #11)."""

    COMPLIANCE_AFFIRMING = "compliance-affirming"
    NA_JUSTIFYING = "NA-justifying"
    GAP_DESCRIBING = "gap-describing"
    AMBIGUOUS = "ambiguous"


class EvidenceKind(str, Enum):
    PDF = "pdf"
    DOCX = "docx"
    PPTX = "pptx"
    XLSX = "xlsx"
    STIG_CKL = "stig_ckl"
    STIG_CKLB = "stig_cklb"
    STIG_XCCDF = "stig_xccdf"
    NESSUS = "nessus"
    TEXT = "text"
    # Raster images (PNG/JPG/etc.) — ingested for completeness + filename/kind
    # tagging; no OCR (Tesseract needs an admin install; easyocr pulls ~3GB of
    # torch). Pixel content isn't read — these map by filename signal + metadata.
    IMAGE = "image"
    # Vector/structured diagrams (Visio .vsdx, .svg) — shape/label text IS
    # extracted (stdlib zip+XML), so network/boundary diagrams reach the tagger
    # and the boundary-control kind rule.
    DIAGRAM = "diagram"
    OTHER = "other"


class FindingStatus(str, Enum):
    OPEN = "Open"
    NOT_A_FINDING = "Not_A_Finding"
    NOT_APPLICABLE = "Not_Applicable"
    NOT_REVIEWED = "Not_Reviewed"


class VerdictSource(str, Enum):
    """Provenance tag for a persisted Assessment row.

    v0.2 patent-supporting field. The orchestrator (``engine/assessor.py``)
    already mints a ``Decision.source`` string at every verdict-emission
    site, but that string is flattened across several Assessment columns
    (``inheritance_rule``, ``needs_review``, ``confidence``) when the row
    is persisted, which makes "what fraction of verdicts were
    LLM-independent?" require a multi-column WHERE-clause spaghetti query.

    This enum collapses that into a single indexed column so the patent
    claim "kernel-driven verdicts are one SQL query away" is literal:

        SELECT verdict_source, count(*) FROM assessment GROUP BY 1;

    Mapping from ``Decision.source`` / ``cache_source`` / ``needs_review``
    to enum value is owned by ``routes/controls.py::_decision_to_verdict_source``
    so the helper is the single source of truth and both persistence sites
    (single-control + batch) stay in sync.

    Values:
      * ``RULE_8A`` / ``RULE_8B`` — col-J/K/L deterministic short-circuit
        (rules.classify_row → ``Decision.source == "rule_8a"|"rule_8b"``).
      * ``RULE_8C`` — verified SDA-controls mapping (``source == "rule-8c"``).
      * ``RULE_NO_EVIDENCE`` — deterministic NC after empty evidence bundle
        (``source == "rule_no_evidence"``).
      * ``CRM_PROVIDER`` / ``CRM_INHERITED`` / ``CRM_NOT_APPLICABLE`` /
        ``CRM_HYBRID_MIXED`` — CRM overlay short-circuit (``source``
        starts with ``"crm_"``); the hybrid variant is set when a per-side
        suffix (``+onprem_*``) is present on the source string.
      * ``CACHE_HIT`` — Decision was replayed from DecisionCache
        (``cache_source == "cache_hit"``); the original source is
        preserved on Decision but the persisted row records the cache
        provenance so cost / re-use telemetry is one query away.
      * ``LLM_ACCEPT`` — first-attempt LLM proposal accepted by validator
        (``source == "llm"``).
      * ``LLM_AFTER_RETRY`` — LLM proposal accepted only after one or
        more corrective-context retries (``source == "llm_after_retry"``).
      * ``ABSTAIN`` — ``Decision.needs_review`` is True; verdict is NOT
        trusted, exporters gate it out, but the row is written so the
        reviewer queue sees it.
    """

    RULE_8A = "rule_8a"
    RULE_8B = "rule_8b"
    RULE_8C = "rule_8c"
    RULE_NO_EVIDENCE = "rule_no_evidence"
    CRM_PROVIDER = "crm_provider"
    CRM_INHERITED = "crm_inherited"
    CRM_NOT_APPLICABLE = "crm_not_applicable"
    CRM_HYBRID_MIXED = "crm_hybrid_mixed"
    CACHE_HIT = "cache_hit"
    LLM_ACCEPT = "llm_accept"
    LLM_AFTER_RETRY = "llm_after_retry"
    ABSTAIN = "abstain"
    # Verdict + narrative came from an operator-supplied eMASS Test Result
    # template (no LLM, no kernel), ingested via excel/narrative_importer.py.
    # Trusted (needs_review stays False) so imported NCs flow into POAMs.
    IMPORTED = "imported"


class EvidenceSourceKind(str, Enum):
    """Where an Evidence row came from — connector telemetry column.

    Mirrors the URI scheme of ``Evidence.path`` plus the named connectors
    on the v0.4+ roadmap (Tenable, Splunk, GitLab, SN-GRC). v0.1 ingest
    paths only populate ``LOCAL_FILE`` and ``SHAREPOINT``; the remaining
    values are pre-declared so future connectors don't need a schema bump.

    Stored as plain TEXT (not a CHECK constraint) so a new connector
    landing mid-release can write a new value without an ALTER pass; the
    enum exists for type-safety on the writer side, not DB-level
    validation. NULL on rows ingested before this column existed.
    """

    LOCAL_FILE = "local_file"
    SHAREPOINT = "sharepoint"
    S3 = "s3"
    AZBLOB = "azblob"
    SCAN_IMPORT = "scan_import"  # generic Nessus/CKL upload route
    TENABLE = "tenable"
    SPLUNK = "splunk"
    GITLAB = "gitlab"
    SN_GRC = "sn_grc"
    MANUAL = "manual"  # user-typed text or assessor-uploaded one-off


class ComponentKind(str, Enum):
    """Architectural role a Component plays in a system boundary.

    A program may model its boundary as a hierarchy: a ``tier`` (Web,
    App, DB) decomposes into ``service``s (a microservice, a vendor
    appliance), which deploy onto Assets. ``segment`` is for
    network-style decomposition (DMZ, mgmt VLAN) when the program
    doesn't think in tiers/services. ``other`` is the escape hatch —
    new programs frequently invent their own grouping vocabulary and
    we don't want the picker to forbid it.
    """

    TIER = "tier"
    SERVICE = "service"
    SEGMENT = "segment"
    OTHER = "other"


class AssetClass(str, Enum):
    """Coarse asset taxonomy used by the CM-8 inventory cross-check.

    Granular enough to let the LLM say "missing scan coverage on the
    network appliances" without forcing a CMDB-grade taxonomy. Programs
    that need finer granularity can store the precise label in
    ``Asset.os_family`` or ``cpe``.
    """

    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK = "network"
    APPLIANCE = "appliance"
    CLOUD = "cloud"
    OTHER = "other"


class AssetSource(str, Enum):
    """How an Asset row was discovered.

    Drives the CM-8 ghost/orphan logic in asset_crosscheck — an asset
    that exists *only* with ``source=ASSET_LIST`` is a declared host
    nothing has scanned (potential ghost); an asset with ``source=SCAN``
    only is observed-but-not-declared. ``MANUAL`` means the assessor
    typed it in directly — treat as authoritative.
    """

    SCAN = "scan"
    ASSET_LIST = "asset_list"
    MANUAL = "manual"


class ScopeLinkSource(str, Enum):
    """Provenance of an Evidence ↔ scope-entity link.

    The three M2M tables (EvidenceComponent / EvidenceAsset /
    EvidenceBoundary) all carry a ``source`` column with this enum.
    ``BACKFILL`` is the one-shot migration path from the legacy
    ``Evidence.host_inventory`` JSON and ``Evidence.is_boundary_doc``
    flag — distinguishable from ``AUTO`` so the v0.2 deprecation
    sweep can find every legacy-derived link to re-verify.
    """

    AUTO = "auto"  # tagger / extractor inference at ingest
    MANUAL = "manual"  # assessor clicked attach
    BACKFILL = "backfill"  # one-shot legacy migration


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------


class Framework(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True)  # "NIST SP 800-53"
    version: str  # "Rev 5"
    # Canonical short identifier used as the framework-scope key on
    # framework-version-keyed tables (e.g. ``OdpAssignment.framework_version``,
    # ``FrameworkEquivalence.source_framework``/``target_framework``). Stable,
    # workbook-friendly value such as ``"NIST-800-53r4"``, ``"NIST-800-53r5"``,
    # ``"FedRAMP-r5-HIGH"``. Matches the CCIS workbook col C "Control Set"
    # string so ingest paths don't have to translate. Nullable for legacy rows
    # loaded before this column existed; the additive migration backfills the
    # two well-known NIST rows. New rows must set it (see ``oscal_loader.py``
    # and ``fedramp_profile_loader.py``). Indexed: render-time ODP lookups
    # filter on this column heavily.
    framework_id: str | None = Field(default=None, index=True)
    oscal_uri: str | None = None
    loaded_at: datetime = Field(default_factory=_utcnow)
    # Single-hop parent — NULL = root catalog (e.g. NIST 800-53 r5). FedRAMP
    # Framework rows point at the 800-53 r5 Framework row so the OSCAL
    # profile's `add` directives have a home and `modify` directives can
    # override inherited control params. Future sub-overlays follow the same
    # pattern. ALTER TABLE ADD COLUMN can't carry
    # REFERENCES in SQLite — same caveat as evidence.superseded_by_id —
    # so the DB-level FK is omitted; SQLAlchemy uses the ORM-level
    # foreign_key= arg below for joins.
    parent_framework_id: int | None = Field(
        default=None, foreign_key="framework.id", index=True
    )
    # Display/selection gate. True = framework appears in the active Catalog
    # section and in the assess/baseline pickers; False = hidden from those
    # surfaces but still managed (toggle row) in Settings and still readable
    # by relationship merges. Disabling is presentation-only: it never tears
    # down the parent→child inheritance that ``list_controls`` /
    # ``catalog_status`` rely on (a disabled parent's Control rows are still
    # merged into an enabled child). Default True so every framework — legacy
    # rows and freshly loaded ones — is visible until explicitly toggled off.
    enabled: bool = Field(default=True, index=True)

    controls: List["Control"] = Relationship(back_populates="framework")


class Control(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    framework_id: int = Field(foreign_key="framework.id", index=True)
    control_id: str = Field(index=True)  # "AC-2", "AC-2(1)"
    title: str
    family: str = Field(index=True)  # "AC", "AU", ...
    statement: str | None = None
    # OSCAL set-parameter values projected from a profile (FedRAMP HIGH/MOD/
    # LOW/LI-SaaS overrides). Populated on shadow Control rows that live on
    # a child Framework -- e.g. an "AC-2" shadow row under "FedRAMP Rev 5
    # HIGH" carries the HIGH-prescribed ODP values for AC-2's parameters.
    # Parent (catalog) rows leave this NULL. JSON-encoded
    # ``dict[param_id, value]`` -- value is the constraint description or
    # the literal value string from the profile. Catalog-layer override:
    # per-workbook tailoring overrides live on BaselineControl.
    parameter_overrides_json: str | None = None

    framework: Framework | None = Relationship(back_populates="controls")
    objectives: List["Objective"] = Relationship(back_populates="control")


class Objective(SQLModel, table=True):
    """A CCI (for 800-53) or assessment objective (for 800-171, etc.)."""

    id: int | None = Field(default=None, primary_key=True)
    control_id_fk: int = Field(foreign_key="control.id", index=True)
    objective_id: str = Field(index=True)  # "CCI-000213" / "AC-2.1"
    source: str = Field(default="CCI")  # "CCI", "AO", "Practice"
    text: str
    implementation_guidance: str | None = None
    assessment_procedures: str | None = None

    control: Control | None = Relationship(back_populates="objectives")


class Crosswalk(SQLModel, table=True):
    """Maps an objective in one framework to its counterpart in another."""

    id: int | None = Field(default=None, primary_key=True)
    from_objective_id: int = Field(foreign_key="objective.id", index=True)
    to_objective_id: int = Field(foreign_key="objective.id", index=True)
    confidence: float = 1.0
    source: str = "manual"  # "NIST-mapping", "manual", "generated"


class ControlCrosswalk(SQLModel, table=True):
    """Maps a control in one framework to its counterpart in another.

    Used for cross-revision mappings (800-53 rev4 ↔ rev5) and cross-framework
    mappings published as control-level lookups (e.g. CIS-to-800-53, ISO-to-
    800-53). The lower-level :class:`Crosswalk` is for objective/CCI-level
    pairs where the per-statement granularity matters.
    """

    id: int | None = Field(default=None, primary_key=True)
    from_control_id: int = Field(foreign_key="control.id", index=True)
    to_control_id: int = Field(foreign_key="control.id", index=True)
    confidence: float = 1.0
    # "NIST-rev-mapping", "auto-id-match", "manual", "CIS-mapping", "ISO-mapping"
    source: str = "manual"
    notes: str | None = None


class BaselineMembership(SQLModel, table=True):
    """Which OSCAL control_ids belong to a baseline-style Framework.

    Populated from OSCAL ``profile.imports[].include-controls[].with-ids[]`` —
    e.g. FedRAMP HIGH = 410 of the 1014 NIST 800-53 rev5 controls. Per the
    "one Framework = most restrictive baseline" architecture, a child
    Framework (FedRAMP, …) names exactly one impact level worth of
    controls; further overlay-driven scope reduction (CRM / customer-vs-
    provider / workbook-resident in-scope flags) happens at assessment time
    against this base set.

    The catalog endpoint (``/api/catalog/frameworks/{id}/controls``) uses
    this table to filter inherited parent rows so a FedRAMP query returns
    the 410 baseline controls (merged with the ~97 shadow rows carrying
    FedRAMP-specific Requirement/Guidance prose), not all 1014 rev5 rows.

    When a child Framework has zero membership rows, the endpoint falls
    back to returning every inherited parent row — keeps the table optional
    so non-baseline overlays (e.g. a pure renaming overlay) work without
    being forced to declare membership.

    Stored as a composite-key join table because membership is set
    semantics, not row identity — no surrogate id, no relationships. The
    ``control_id`` column holds the OSCAL string ("ac-2", "ac-2.1") rather
    than a ``Control.id`` FK so membership survives a Control row swap
    (parent catalog reload) without re-derivation.
    """

    framework_id: int = Field(
        foreign_key="framework.id", primary_key=True, index=True
    )
    control_id: str = Field(primary_key=True, index=True)


# ---------------------------------------------------------------------------
# Program-specific requirements (e.g. a program-specific controls overlay tab)
# ---------------------------------------------------------------------------


class RequirementSource(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    framework_id: int = Field(foreign_key="framework.id", index=True)
    name: str  # e.g. "<Program> Enterprise Services Controls"
    path: str | None = None  # path to source workbook on disk
    loaded_at: datetime = Field(default_factory=_utcnow)


class RequirementMap(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    requirement_source_id: int = Field(foreign_key="requirementsource.id", index=True)
    objective_id: int = Field(foreign_key="objective.id", index=True)
    requirement_number: str  # SDA Req #
    requirement_text: str  # verbatim shall statement


class IngestReport(SQLModel, table=True):
    """Audit trail for a single ``load_program_controls`` invocation.

    One row per loader run. Persists the structural decisions the loader made
    (forward-fills across unmerged cell blocks, rows that survived as
    ``(unnumbered)`` sentinels, CCIs/control IDs the workbook references but
    the catalog couldn't resolve) so a 3PAO can audit *why* a given
    ``RequirementMap`` exists — not just that it does.

    Why this exists
    ---------------
    Pre-this-table, the loader's transient ``_rows_seen`` / ``_maps_written``
    / ``_unmapped_*`` attrs survived only as a one-shot HTTP response. If the
    operator didn't screenshot the toast, the audit signal vanished. eMASS
    workbooks regularly ship with unmerged tall col-A cell blocks (e.g.
    T1TL's AU-2 block at col-A=460 spanning sub-bullets a-l, where openpyxl
    sees rows 461-472 with empty col A); the loader's border-aware forward-
    fill rescues those rows, but the fix is invisible without this audit
    record.

    ``actions`` is a structured per-row log: each entry is a dict like
    ``{"row": 472, "action": "forward_fill", "from_value": "AU-2"}`` or
    ``{"row": 530, "action": "unnumbered_block_start", "reason":
    "top_border_thin"}``. Bounded by per-run loader output; JSON for v1
    simplicity (a child table buys nothing until we need cross-run row-action
    queries, which we don't).

    ``loader_version`` is the loader code version (string, owned by
    ``program_controls_loader.LOADER_VERSION``) so replay knows whether a
    historical bundle was produced by a known-buggy or known-good loader.

    Lifecycle
    ---------
    Inserted at the end of ``load_program_controls``. Never updated. Cascades
    on ``RequirementSource`` delete (a re-import wipes the prior
    ``RequirementSource`` + its maps + its IngestReport in one transaction —
    the audit travels with the data it describes).
    """

    id: int | None = Field(default=None, primary_key=True)
    requirement_source_id: int | None = Field(
        default=None, foreign_key="requirementsource.id", index=True
    )
    framework_id: int | None = Field(
        default=None, foreign_key="framework.id", index=True
    )
    source_path: str  # workbook path on disk (or URI) at load time
    sheet_name: str | None = None  # e.g. "Ground Security Controls"
    loader_version: str  # e.g. "program_controls_loader@2"
    rows_seen: int = 0
    maps_written: int = 0
    rows_forward_filled: int = 0
    rows_unnumbered: int = 0  # surviving "(unnumbered)" sentinels
    # nullable=False matches migration 0005 — default_factory guarantees a
    # value is always written, so the column is never NULL in practice; the
    # schema-equivalence test ([test_alembic_schema_equivalence.py]) checks
    # both sides agree on nullability.
    unmapped_ccis: list[str] = Field(
        default_factory=list, sa_column=Column(JSON, nullable=False)
    )
    unmapped_control_ids: list[str] = Field(
        default_factory=list, sa_column=Column(JSON, nullable=False)
    )
    actions: list[dict] = Field(
        default_factory=list, sa_column=Column(JSON, nullable=False)
    )
    created_at: datetime = Field(default_factory=_utcnow, index=True)


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


class Evidence(SQLModel, table=True):
    """A single ingested artifact, identified by a canonical URI.

    The ``path`` column is a URI string — not necessarily a filesystem path.
    Schemes the codebase produces today:
      - ``file:///abs/path/foo.pdf``                            (local + NFS, no scheme = legacy)
      - ``zip:///abs/path/archive.zip!/dir/inner.pdf``          (zip member)
      - ``s3://bucket/key`` / ``azblob://container/key``        (cloud, future)
      - ``sharepoint://host/sites/.../path/file.pdf``           (SharePoint, future)

    Legacy rows written before the URI migration store bare absolute paths;
    those remain unique and lookup-compatible without rewrite (a bare path
    is a valid ``file://`` URI in everything-but-name).

    ``archive_uri`` groups all members extracted from the same container
    archive — null for top-level files. Used by the UI to collapse a 200-
    file zip into one row with a disclosure triangle.

    ``superseded_by_id`` chains a legacy-doc evidence row to the USD-
    numbered current-tier row that supersedes it (see ``engine.supersession``).
    Null means this row is current (or its supersession state is unknown).
    The chain is shallow in practice — one or two hops — but the column is
    a self-FK so deeper chains resolve without re-scanning narrative text.
    """

    id: int | None = Field(default=None, primary_key=True)
    # ``path`` is intentionally NOT globally UNIQUE. Per-workbook hard
    # scoping (PR 2 of evidence-workbook-scope) replaces the global
    # uniqueness with composite UNIQUEs ``(workbook_id, path)`` and
    # ``(workbook_id, sha256)`` -- see alembic 0010 and
    # ``evidence/ingest.py :: _existing_by_uri/_existing_by_hash``.
    # SQLModel.metadata.create_all (used by some test fixtures) honors
    # this attribute, so keeping it ``unique=True`` would silently
    # reintroduce the global constraint in the test path even after the
    # migration drops it in prod.
    path: str = Field(index=True)  # canonical URI
    sha256: str = Field(index=True)
    kind: EvidenceKind
    size_bytes: int
    ingested_at: datetime = Field(default_factory=_utcnow)
    extracted_text_path: str | None = None
    title: str | None = None
    doc_number: str | None = Field(default=None, index=True)  # e.g. USD00050010
    archive_uri: str | None = Field(default=None, index=True)  # parent zip URI, if any
    superseded_by_id: int | None = Field(
        default=None, foreign_key="evidence.id", index=True
    )
    # Populated alongside ``superseded_by_id`` by the supersession tracker.
    # All three are null on rows where ``superseded_by_id`` is null (the row is
    # still current). Together they answer "why was this row retired, by which
    # policy, and when?" without re-deriving from tracker code — the patent
    # claim's "every rewrite is one SQL query away" needs the why-fields here
    # so a reviewer can audit any chain link without reading auto-link code.
    superseded_at: datetime | None = Field(default=None)
    # One of {"same_doc_number", "legacy_title_rewrite", "manual"} — constrained
    # at the application layer (tracker policies + future manual-supersede route).
    superseded_policy: str | None = Field(default=None)
    # Short human-readable explanation surfaced in the UI chip tooltip.
    superseded_reason: str | None = Field(default=None)
    # Manually flipped by the assessor in the Evidence UI when an artifact is
    # an authoritative component/asset list (HW/SW inventory, ACAS target
    # list, etc.). Drives the asset-inventory cross-check that gets injected
    # into CM-8 / CA-3 / PM-5 prompts. No auto-detection — a vendor parts
    # catalog and an HW/SW spreadsheet look identical by column shape and we
    # don't want silent misclassification to drive a CM-8 narrative.
    is_asset_list: bool = Field(default=False, index=True)
    # Short human label shown in the cross-check diff ("Approved HW/SW",
    # "ACAS scan targets", "DISA network diagram extract"). Optional — falls
    # back to title/filename when None — but strongly recommended when more
    # than one list is tagged so the diff lines are self-describing.
    asset_list_label: str | None = None
    # JSON-encoded list of normalized hostnames captured at ingest time.
    # Populated for CKL / CKLB / XCCDF / Nessus (via extractor metadata.hosts)
    # and for XLSX / CSV with a recognizable hostname column. Reading from
    # here lets the asset cross-check work for SharePoint / S3 / Azure URIs
    # where the source file isn't locally resolvable at assess time, AND
    # makes per-prompt build cost ~0 instead of re-parsing the artifact on
    # every CM-8 / CA-3 / PM-5 assess. NULL on rows ingested before this
    # column existed — asset_crosscheck falls back to the re-parse path for
    # those when the file is locally resolvable.
    host_inventory: str | None = None
    # Sweep Context (v0.2): the assessor flags an Evidence row as a
    # boundary-defining artifact (SSP, SSPP, ATO letter, network diagram).
    # The BoundaryDocsContextSource adapter pulls every row where
    # is_boundary_doc=True scoped to a workbook and feeds the extracted text
    # to the token extractor. Same is_asset_list precedent: manual flag, no
    # auto-detection — too easy to misclassify a stray vendor whitepaper as
    # an SSP from shape alone.
    is_boundary_doc: bool = Field(default=False, index=True)
    # Free-text label shown in the Sweep Context doc table ("SSP",
    # "SSPP", "ATO Letter", "Network Diagram", "Other"). Intentionally not
    # an enum — programs use a wider variety of doc names than we can
    # enumerate, and the value is display-only.
    boundary_doc_kind: str | None = None
    # Per-workbook scoping for boundary docs. NULL for any pre-existing
    # Evidence row (workbook-agnostic). The Sweep Context page filters
    # on (workbook_id == active_wb AND is_boundary_doc) to render its table
    # without re-deriving from Objectives. Self-FK pattern (see
    # superseded_by_id) — ALTER TABLE in db.py omits the FK clause because
    # SQLite doesn't accept it post-creation, but the ORM relationship is
    # what reads use.
    workbook_id: int | None = Field(
        default=None, foreign_key="workbook.id", index=True
    )
    # v0.3-ready: connector telemetry column. Mirrors :class:`EvidenceSourceKind`
    # but stored as raw TEXT so a new connector landing mid-release doesn't
    # need an ALTER pass. NULL on legacy rows; the v0.4 connector audit
    # surfaces "% of evidence with unknown provenance" using this column.
    source_kind: str | None = Field(default=None, index=True)

    # Per-workbook hard scoping (PR 2 of evidence-workbook-scope). Mirrors
    # alembic 0010's composite UNIQUEs so SQLModel.metadata.create_all
    # (some test fixtures) enforces the same shape the migration does in
    # prod. Names match the migration so a reflected schema and a
    # create_all schema compare equal in round-trip tests.
    #
    # SQLite NULL-in-UNIQUE: each NULL is distinct, so legacy
    # ``workbook_id IS NULL`` rows are NOT protected by these -- PR 3
    # (alembic 0011) drains them into ``quarantinedevidence`` and flips
    # ``workbook_id`` to NOT NULL. Until then, ``ingest.ingest_source``
    # rejects any new NULL-workbook insert at the application layer.
    __table_args__ = (
        UniqueConstraint(
            "workbook_id", "path", name="uq_evidence_workbook_path"
        ),
        UniqueConstraint(
            "workbook_id", "sha256", name="uq_evidence_workbook_sha256"
        ),
    )


class QuarantinedEvidence(SQLModel, table=True):
    """Orphaned Evidence rows lifted out of the global pool.

    Mirror of :class:`Evidence` minus ``workbook_id`` (these rows have no
    owner) plus ``original_workbook_hint`` (free-text breadcrumb from
    whatever pre-PR-3 metadata we could salvage) and ``quarantined_at``
    (the timestamp at which the row was moved here).

    Lives in its OWN table -- not a sentinel ``Workbook.kind="quarantine"``
    row -- so it's a compile-time invariant: no future ``select(Workbook)``
    can accidentally surface orphans in a customer-facing list. PR 3
    populates this table from legacy ``Evidence.workbook_id IS NULL`` rows;
    the assessor's Quarantine Review UI is the only customer-facing surface
    that reads from it. Rows leave only via promote-to-workbook or explicit
    delete.

    Migration source of truth: ``alembic/versions/0009_evidence_workbook_scope_foundation.py``.
    Column shape MUST stay in lockstep with that migration so the schema-
    equivalence round-trip test (``test_alembic_schema_equivalence``)
    stays green.
    """

    id: int | None = Field(default=None, primary_key=True)
    path: str = Field(index=True)
    sha256: str = Field(index=True)
    kind: EvidenceKind
    size_bytes: int
    ingested_at: datetime = Field(default_factory=_utcnow)
    extracted_text_path: str | None = None
    title: str | None = None
    doc_number: str | None = Field(default=None, index=True)
    archive_uri: str | None = Field(default=None, index=True)
    # Free-text breadcrumb. PR 3's NULL-quarantine drain has no
    # workbook_id to record (that's why the row is here), but any hint
    # we can scavenge from path / SharePoint URL / sweep metadata goes
    # here so the Quarantine Review UI can suggest a target.
    original_workbook_hint: str | None = None
    quarantined_at: datetime = Field(default_factory=_utcnow, index=True)
    # Mirrors Evidence.source_kind verbatim -- the connector that
    # originally produced the row remains useful provenance even after
    # ownership is lost.
    source_kind: str | None = Field(default=None, index=True)


class EvidenceTag(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    evidence_id: int = Field(foreign_key="evidence.id", index=True)
    objective_id: int = Field(foreign_key="objective.id", index=True)
    relevance: float = 1.0
    confidence: float = 0.5
    source: str = "auto"  # "auto", "manual", "llm"
    rationale: str | None = None
    # v0.3-ready: which framework lens was active when this tag was created.
    # NULL = framework-agnostic (the historical default — tagger ran with no
    # workbook context). Populated when ingest is invoked under a workbook
    # whose ``framework_id`` is set, so cross-framework audit / UI can answer
    # "which lens did the assessor see this artifact through?". Logical FK to
    # ``framework.id``; SQLite ALTER TABLE ADD COLUMN can't carry REFERENCES
    # so the constraint lives in the ORM only (same pattern as
    # ``Evidence.superseded_by_id`` / ``Framework.parent_framework_id``).
    framework_id: int | None = Field(
        default=None, foreign_key="framework.id", index=True
    )


class StigFinding(SQLModel, table=True):
    """Normalized STIG finding from .ckl / .cklb / XCCDF / Nessus.

    Narrative precision (per feedback_corroborate_stig_findings.md): a
    citation must point at the *specific SV-rule* that failed, not just
    name the CKL. ``rule_id`` carries the SV-rule (the audit-stable
    identifier the validator's ``_CITE_STIG_RE`` matches); ``group_id``
    carries the human-facing V-number (e.g. ``V-220706``) that scanners
    and STIG Viewer show side-by-side with the SV-rule. ``check_text`` /
    ``fix_text`` let the POAM generator quote verbatim remediation
    language instead of a hand-rolled summary, and ``rule_title`` gives
    the SAR a one-line label per finding.

    All new columns are nullable — older extractors (and Nessus, which
    has no V-number) populate only what the source carries; absence is a
    gap to surface, never an error.
    """

    id: int | None = Field(default=None, primary_key=True)
    evidence_id: int = Field(foreign_key="evidence.id", index=True)
    rule_id: str = Field(index=True)  # SV-... / Plugin ID
    rule_version: str | None = None
    # Human-facing vulnerability id (STIG "Group ID" / Vuln_Num, e.g.
    # "V-220706"). Carried alongside rule_id so narratives, POAMs, and the
    # SAR can show the V-number a reviewer recognizes from STIG Viewer.
    # Indexed because corroboration/where-used queries key on it.
    group_id: str | None = Field(default=None, index=True)
    rule_title: str | None = None  # one-line STIG rule title for SAR labels
    cci_refs: str | None = None  # comma-joined CCI numbers
    severity: str | None = None
    status: FindingStatus
    finding_details: str | None = None
    comments: str | None = None
    # Verbatim STIG check / fix language, captured so the POAM generator can
    # quote authoritative remediation text rather than synthesize it.
    check_text: str | None = None
    fix_text: str | None = None


# ---------------------------------------------------------------------------
# Scope: Components, Assets, Boundary segments (v0.3-ready)
#
# First-class scope entities. The pre-v0.3 model expressed scope only as
# per-Evidence flags (``is_boundary_doc``, ``host_inventory`` JSON), which
# couldn't answer "show me every artifact for the DMZ" or "which assets are
# in the Web tier" without a re-scan of free-text fields. This block adds
# the structural pieces eMASS / SN-GRC / Xacta all model the same way:
# Components decompose a system, Assets are the hosts those components run
# on, BoundarySegments are network-style enclaves, and three M2M tables
# tie Evidence to all three at attach time.
#
# Backfilled from the legacy ``Evidence.host_inventory`` JSON and
# ``Evidence.is_boundary_doc`` flag by :mod:`evidence.scope_backfill` at
# sidecar startup, so existing workbooks light up the new filter chips
# without re-ingest. The legacy fields stay populated through v0.2 as a
# fallback for any row the backfill couldn't classify.
# ---------------------------------------------------------------------------


class Component(SQLModel, table=True):
    """A logical component within a workbook's system boundary.

    Components decompose a system into addressable pieces — a tier
    (Web/App/DB), a service (a microservice, a vendor appliance), or
    a network segment when the program thinks that way. Nested via
    ``parent_component_id`` for programs that need tier→service
    hierarchies, but the depth is unlimited; the UI just renders
    whatever tree the data describes.

    ``workbook_id`` scopes Components per-workbook so two workbooks
    can have a "Web Tier" Component without colliding. SQLite ALTER
    TABLE ADD COLUMN can't carry REFERENCES post-creation, but
    Component is a new table created by ``create_all()`` so the FK
    is enforced at DB level here.
    """

    id: int | None = Field(default=None, primary_key=True)
    workbook_id: int = Field(foreign_key="workbook.id", index=True)
    name: str = Field(index=True)
    kind: ComponentKind = Field(default=ComponentKind.OTHER, index=True)
    # Self-FK for tier→service nesting. Optional; flat lists are fine.
    parent_component_id: int | None = Field(
        default=None, foreign_key="component.id", index=True
    )
    description: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)


class Asset(SQLModel, table=True):
    """A host / device discovered or declared within a workbook's boundary.

    Keyed by ``(workbook_id, hostname)`` for dedupe — the backfill and
    the manual-add route both upsert on that pair. ``hostname`` is the
    bare lowercase short form (``server01``); the full FQDN, IP, and
    CPE live in dedicated columns so a future connector that only knows
    one of the three can fill in what it knows without losing the rest.

    ``source`` records how this row was first discovered: a Nessus scan
    (``scan``), an authoritative HW/SW spreadsheet (``asset_list``), or
    typed in by the assessor (``manual``). The CM-8 ghost/orphan logic
    in asset_crosscheck joins on this column to compute the
    declared-not-observed / observed-not-declared buckets.
    """

    id: int | None = Field(default=None, primary_key=True)
    workbook_id: int = Field(foreign_key="workbook.id", index=True)
    hostname: str = Field(index=True)
    fqdn: str | None = None
    ip_address: str | None = None
    cpe: str | None = None
    os_family: str | None = None
    asset_class: AssetClass = Field(default=AssetClass.OTHER, index=True)
    source: AssetSource = Field(default=AssetSource.MANUAL, index=True)
    created_at: datetime = Field(default_factory=_utcnow)


class BoundarySegment(SQLModel, table=True):
    """A named network/security enclave inside the system boundary.

    Distinct from :class:`Component` because boundary segments are about
    network reachability and security zones (DMZ, internal, mgmt, B2B),
    not functional decomposition. The two intersect — a "Web tier"
    Component might live in the "DMZ" BoundarySegment — but conflating
    them forces every program to pick one taxonomy, and federal
    customers want both.

    ``kind`` is intentionally free-text rather than an enum because the
    vocabulary varies wildly across programs (dmz/internal/mgmt vs
    untrust/trust/dmz vs corp/lab/prod). The picker offers a short
    suggestion list but accepts any string.
    """

    id: int | None = Field(default=None, primary_key=True)
    workbook_id: int = Field(foreign_key="workbook.id", index=True)
    name: str = Field(index=True)
    kind: str | None = None  # "dmz" | "internal" | "mgmt" | etc.
    description: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)


class ComponentAsset(SQLModel, table=True):
    """M2M: which Assets host a Component.

    Composite PK (component_id, asset_id) — same pattern as
    :class:`BaselineMembership` and :class:`PoamEvidence`. No surrogate
    id, no created_at — membership is set semantics, not row identity.
    """

    component_id: int = Field(foreign_key="component.id", primary_key=True)
    asset_id: int = Field(foreign_key="asset.id", primary_key=True)


class EvidenceComponent(SQLModel, table=True):
    """M2M: which Components an Evidence row applies to.

    ``confidence`` is 0..1 — used so an LLM tagger can express "I'm
    only 60% sure this SSP excerpt talks about the Web tier" without
    polluting the manual-attach path. ``source`` records who created
    the link (auto vs manual vs backfill); the v0.2 deprecation sweep
    queries on ``source = 'backfill'`` to re-verify legacy-derived
    links.
    """

    evidence_id: int = Field(foreign_key="evidence.id", primary_key=True)
    component_id: int = Field(foreign_key="component.id", primary_key=True)
    confidence: float = 1.0
    source: ScopeLinkSource = Field(default=ScopeLinkSource.MANUAL)
    created_at: datetime = Field(default_factory=_utcnow)


class EvidenceAsset(SQLModel, table=True):
    """M2M: which Assets an Evidence row pertains to.

    Backfilled from ``Evidence.host_inventory`` JSON by
    :mod:`evidence.scope_backfill`. The asset cross-check
    (:mod:`evidence.asset_crosscheck`) reads from this table preferentially
    and falls back to the JSON cache only for rows the backfill couldn't
    process (e.g. evidence with no resolvable workbook). See
    :class:`EvidenceComponent` for column semantics.
    """

    evidence_id: int = Field(foreign_key="evidence.id", primary_key=True)
    asset_id: int = Field(foreign_key="asset.id", primary_key=True)
    confidence: float = 1.0
    source: ScopeLinkSource = Field(default=ScopeLinkSource.MANUAL)
    created_at: datetime = Field(default_factory=_utcnow)


class EvidenceBoundary(SQLModel, table=True):
    """M2M: which BoundarySegments an Evidence row applies to.

    Backfilled from the legacy ``Evidence.is_boundary_doc`` flag — each
    boundary-doc evidence row gets a link to a per-workbook
    BoundarySegment named after its ``boundary_doc_kind`` (or "boundary"
    when null). See :class:`EvidenceComponent` for column semantics.
    """

    evidence_id: int = Field(foreign_key="evidence.id", primary_key=True)
    boundary_segment_id: int = Field(foreign_key="boundarysegment.id", primary_key=True)
    confidence: float = 1.0
    source: ScopeLinkSource = Field(default=ScopeLinkSource.MANUAL)
    created_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------


class System(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    description: str | None = None


class Workbook(SQLModel, table=True):
    """A specific CCIS workbook that has been opened in the app."""

    id: int | None = Field(default=None, primary_key=True)
    path: str = Field(index=True, unique=True)
    filename: str
    system_id: int | None = Field(default=None, foreign_key="system.id")
    framework_id: int | None = Field(default=None, foreign_key="framework.id")
    baseline_id: int | None = Field(default=None, foreign_key="baseline.id", index=True)
    last_opened: datetime = Field(default_factory=_utcnow)
    # When a fresh eMASS POAM workbook was last imported for this CCIS. Null
    # means we've never reconciled against the authoritative eMASS list — used
    # by the UI to warn before Generate / Export that locally-created Draft
    # POAMs may collide with rows eMASS already has on file.
    last_emass_import_at: datetime | None = None
    # Absolute path to the per-workbook "working copy" we write assessments
    # into instead of mutating the original. Null until the first Apply
    # creates it. Lives under
    # ``~/.cybersecurity-assessor/working_copies/<wb_id>/<stem>_edited<ext>``
    # so the original (typically in Downloads / a OneDrive drop) is never
    # touched. See ``excel/working_copy.py`` for the lazy-create semantics —
    # Apply-to-workbook must never open ``path`` for writes; that's the
    # whole point.
    working_path: str | None = None
    # Soft cap counter for /api/sharepoint/sweep. Each successful sweep
    # increments this; the third call returns HTTP 409 until the user calls
    # /api/workbooks/{id}/sweep-attempts/reset. The cap forces the assessor
    # to update SystemContext tokens (or accept that the library is exhausted)
    # before re-sweeping, instead of treating sweep as an infinite "did I miss
    # anything?" loop. The reset endpoint exists for the legitimate case of
    # "I just dropped 200 new artifacts in SharePoint."
    sweep_attempts: int = 0
    # Running tally of LLM-judge spend across every sweep for this workbook.
    # Each SweepRun insert increments this in the same transaction so the
    # Workbooks list can render per-workbook cost without joining SweepRun.
    # Resets are intentional only — there's no "reset on attempts reset"
    # behaviour; cost is an audit fact, not a soft limit like sweep_attempts.
    total_sweep_cost_usd: float = 0.0
    # Last successful write to the eMASS controls export template
    # (controls/exporter.py::export_controls_to_emass). Stamped only on the
    # eMASS-strict path; working-view exports are ephemeral and never set this.
    # Drives the "Exported <timestamp>" badge on the Controls list header.
    exported_at: datetime | None = None
    # Per-workbook hard scoping (alembic 0009). Random 32-char hex salt
    # mixed into ``decision_cache.fingerprint`` so two workbooks with
    # byte-identical evidence and prompts produce distinct cache keys.
    # Each row gets a UNIQUE salt (``secrets.token_hex(16)``) — a shared
    # default would re-create a covert cache-replay leak between workbooks.
    # ``default_factory`` is evaluated per-instance, so every Workbook (route
    # construction, ingest, tests) gets its own random salt without each call
    # site having to remember to set it — and crucially NOT a shared constant.
    scope_salt: str = Field(
        default_factory=lambda: secrets.token_hex(16),
        sa_column_kwargs={"nullable": False},
        max_length=32,
    )


class WorkbookSyncEvent(SQLModel, table=True):
    """One row-level change detected during a workbook re-read sync.

    Emitted by ``engine.workbook_sync.sync_workbook`` whenever the diff
    between the prior snapshot and the freshly parsed workbook yields an
    add/remove/move/edit. Stored as an append-only audit log so the UI
    (and downstream review flows) can show "what changed since you last
    looked" without having to recompute the diff.

    For ``added`` events ``old_value_json`` is None; for ``removed`` events
    ``new_value_json`` is None. For ``moved`` and ``edited`` both columns
    hold the full snapshot dict so callers can diff arbitrary subsets.
    """

    id: int | None = Field(default=None, primary_key=True)
    workbook_id: int = Field(foreign_key="workbook.id", index=True)
    control_id: str = Field(index=True)  # e.g. "AC-2"
    cci_id: str | None = Field(default=None, index=True)  # e.g. "CCI-000015"
    occurred_at: datetime = Field(default_factory=_utcnow, index=True)
    # "added" | "removed" | "moved" | "edited"
    event_type: str = Field(index=True)
    old_value_json: str | None = None
    new_value_json: str | None = None
    source: str = Field(default="reread", index=True)


class WorkbookOverlay(SQLModel, table=True):
    """Many-to-many: reference baselines attached to a workbook for gap analysis.

    The workbook keeps its single *primary* baseline at ``Workbook.baseline_id``
    — that's the CCIS-derived (column A) assessment scope that owns status
    writes. Rows here are *reference overlays*: typically sibling CCIS
    baselines from related systems, or any ``CCIS_WORKBOOK`` / ``MANUAL``
    baseline the user wants to display alongside the primary scope.

    Reference overlays are read-only annotation. ``assess_batch`` never
    writes to them — they're consulted by the Controls grid (to render
    per-overlay membership badges) and the SAR appendix to compute gap
    counts. A baseline can be the primary on one workbook and a reference
    overlay on another.
    """

    workbook_id: int = Field(foreign_key="workbook.id", primary_key=True)
    baseline_id: int = Field(foreign_key="baseline.id", primary_key=True)
    attached_at: datetime = Field(default_factory=_utcnow)
    note: str | None = None


# ---------------------------------------------------------------------------
# SystemContext — per-workbook seed metadata for boundary-aware sweeps
# ---------------------------------------------------------------------------


class SystemContextSourceType(str, Enum):
    """Where the SystemContext came from. Drives which adapter ran.

    Framework-agnostic: the same SystemContext seeds FedRAMP, SDA Example System, and
    future CSF sweeps without code changes. New format = new adapter behind
    the SystemContextSource Protocol; no schema change.
    """

    FREEFORM_MARKDOWN = "freeform_markdown"  # Tier 1 (v0.2 ships this)
    EMASS_SSP_XLSX = "emass_ssp_xlsx"  # Tier 2 (roadmap)
    DOCX_NARRATIVE = "docx_narrative"  # Tier 3 (roadmap)
    OSCAL_SSP_JSON = "oscal_ssp_json"  # Tier 4 (roadmap)


class SystemContext(SQLModel, table=True):
    """Per-workbook (or pending) seed metadata used to bias boundary-aware sweeps.

    1:1 with Workbook when ``workbook_id`` is set; uniqueness is enforced
    by a partial unique index on ``workbook_id WHERE workbook_id IS NOT NULL``
    (see ``db._relax_systemcontext_sweeprun_workbook_id_nullability``).

    **Pending-scope singleton**: at most one row may have
    ``workbook_id IS NULL`` at any time. This is the "user is dropping
    boundary docs before opening a workbook" state — the Sweep page can
    write SystemContext + BoundaryDoc rows immediately, and the user
    promotes the pending row onto a Workbook when one is opened via
    ``POST /api/system-context/pending/promote?workbook_id=X``. The
    singleton is enforced by a partial unique index on
    ``workbook_id WHERE workbook_id IS NULL``.

    Created/updated through ``/api/system-context`` (per-workbook) or
    ``/api/system-context/pending`` (pre-workbook) routes. The
    ``extracted_tokens`` field is the machine-readable distillation of the
    freeform text — the sweep fingerprint reads this; the freeform text
    is for human reference.

    NOT a scope picker: SystemContext is descriptive metadata about the
    system the workbook describes (per ``feedback_scoping_out_of_assessor``).
    It influences sweep scoring only, never which CCIs are in scope.
    """

    # Two SQLite-specific partial unique indexes encode the
    # "one-row-per-workbook AND at-most-one-pending" rule. Both live on
    # ``metadata`` so ``create_all`` (test scratch DBs) and Alembic head
    # (prod migrations) produce the same schema — the equivalence test
    # in ``tests/test_alembic_schema_equivalence.py`` enforces that.
    #
    # 1) per-workbook uniqueness when workbook_id IS NOT NULL — a plain
    #    UNIQUE column won't work because multiple NULLs (pending rows)
    #    must coexist with the per-workbook constraint.
    # 2) pending-singleton: at most one row with workbook_id IS NULL.
    #    Expressed as a unique index on a constant expression ``1`` with
    #    a WHERE clause — SQLAlchemy's inspector can't reflect this kind
    #    of expression index, so the equivalence test skips it on both
    #    sides (the SAWarning is expected and harmless).
    __table_args__ = (
        Index(
            "ix_systemcontext_workbook_id_notnull",
            "workbook_id",
            unique=True,
            sqlite_where=text("workbook_id IS NOT NULL"),
        ),
        Index(
            "ix_systemcontext_pending_singleton",
            text("1"),
            unique=True,
            sqlite_where=text("workbook_id IS NULL"),
        ),
    )

    id: int | None = Field(default=None, primary_key=True)
    # Nullable: NULL means "pending boundary scope" (see class docstring).
    # The single-row-per-workbook constraint is enforced by a partial
    # unique index, not a column-level UNIQUE, so the pending singleton
    # and per-workbook uniqueness can coexist.
    workbook_id: int | None = Field(
        default=None, foreign_key="workbook.id", index=True
    )

    # Source provenance.
    source_type: SystemContextSourceType = Field(
        default=SystemContextSourceType.FREEFORM_MARKDOWN
    )
    source_ref: str | None = None  # path / URL / "freeform"; nullable for inline

    # Freeform inputs (markdown, never parsed by anything but the LLM).
    boundary: str | None = None  # "what's in the system"
    stakeholders: str | None = None  # "who runs / approves / consumes"
    tech_inventory: str | None = None  # "what runs on it"
    requirement_hints: str | None = None  # "what it must do / standards it claims"

    # LLM-extracted tokens — flat list the sweep merges into host_tokens.
    extracted_tokens: list[str] = Field(default_factory=list, sa_column=Column(JSON))

    # Outcome confidence — starts at extraction estimate, bumps +0.05 per
    # accepted sweep artifact, clamped at 1.0. Drives the UI progress bar.
    confidence: float = 0.5

    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Baselines — framework-agnostic "which Objectives apply to this system"
# ---------------------------------------------------------------------------


class BaselineSourceType(str, Enum):
    """How a Baseline was populated. Each value has a matching adapter
    in ``backend/cybersecurity_assessor/baselines/``.
    """

    CCIS_WORKBOOK = "ccis_workbook"  # DoD eMASS CCIS .xlsx (column A "Required")
    OSCAL_SSP = "oscal_ssp"  # OSCAL System Security Plan JSON
    # Legacy value, retained only so existing DB rows from older builds
    # decode cleanly at startup. Current code does not produce new
    # OSCAL_PROFILE baselines — the FedRAMP loader was removed when the
    # app's input contract narrowed to "user uploads a program workbook"
    # (RMF step 4+). Users with orphaned oscal_profile rows can drop them
    # via DELETE /api/baselines/{id}.
    OSCAL_PROFILE = "oscal_profile"
    MANUAL = "manual"  # picked via UI, no source file
    ISO_SOA = "iso_soa"  # ISO 27001 Statement of Applicability
    CIS_CSAT = "cis_csat"  # CIS Controls Self-Assessment Tool export
    CRM = "crm"  # FedRAMP-style Customer Responsibility Matrix overlay
    # Program-controls overlay (e.g. "SDA Enterprise Services Controls",
    # "T1TL Ground Security Controls"). Materialized by
    # catalogs/program_controls_loader.py as a synthetic Baseline so the
    # WorkbookOverlay surface (and the Workbooks page Overlays column)
    # treats program reqs uniformly with FedRAMP/CRM-style overlays. The
    # source-of-truth row->CCI mapping still lives in RequirementSource +
    # RequirementMap; this baseline is the join handle the UI uses.
    # User-facing label is "PSC" (Program Security Controls); storage
    # value stays "program_controls" so no data migration is needed.
    PROGRAM_CONTROLS = "program_controls"
    # Inert overlay — a spreadsheet the user dropped in that doesn't match
    # the CRM or PSC header vocabularies. Registered as a Baseline so it
    # shows up in the Workbooks attach UI, but emits zero BaselineControl
    # rows and no resolver runs against it during assessment. Lets users
    # import arbitrary overlay files without erroring out; a real resolver
    # can be programmed later if a recognizable shape emerges. See
    # baselines/other_xlsx.py and baselines/overlay_classifier.py.
    OTHER = "other"


class Baseline(SQLModel, table=True):
    """A specific system's in-scope set of Objectives + tailoring metadata.

    The catalog (Framework → Control → Objective) is the *full* set of
    possible objectives for a framework. A Baseline narrows that down for
    one system. ``source_type`` records how this baseline was populated
    so the matching adapter can refresh it; ``source_ref`` is a back-
    reference (workbook path, OSCAL URI, null for manual) the adapter
    needs to re-read the source.
    """

    id: int | None = Field(default=None, primary_key=True)
    framework_id: int = Field(foreign_key="framework.id", index=True)
    system_id: int | None = Field(default=None, foreign_key="system.id", index=True)
    name: str
    source_type: BaselineSourceType
    source_ref: str | None = None
    # v0.2 multi-implementation: a Baseline tagged with a scope_label
    # represents one implementation slice (e.g. ``"AWS GovCloud"``,
    # ``"Azure Government"``). Only CRM-source Baselines are required to
    # carry a label — PROGRAM_CONTROLS / OTHER / OSCAL Baselines stay
    # nullable. Soft-dedupe in the upload route uses
    # ``(framework_id, source_type, scope_label)`` as the replace key.
    # The implicit ``"On-Premises"`` label is reserved — it is NEVER
    # stored on a Baseline; the assessor synthesizes the on-prem
    # implementation row at assess-time. See
    # :mod:`cybersecurity_assessor.baselines.scope_labels` for the
    # canonical vocabulary.
    scope_label: str | None = Field(default=None, index=True)
    created_at: datetime = Field(default_factory=_utcnow)
    refreshed_at: datetime = Field(default_factory=_utcnow)


class BaselineControl(SQLModel, table=True):
    """Per-Control (base + enhancement) tailoring decision within a baseline.

    **Scope lives here, not on CCIs.** A tailoring decision is "AC-2(1)
    does/doesn't apply to this system" — never "CCI-001548 applies but
    CCI-001549 doesn't." The CCIS workbook serializes the decision per-CCI
    row, but the adapter rolls it up: a Control is in-scope when *any* of
    its CCIs are marked required in column A.

    Enhancements are first-class :class:`Control` rows (control_id like
    ``AC-2(1)``), so this table covers both bases and enhancements with
    one shape — no separate Enhancement table needed.

    Rows exist for every Control the source mentioned (in-scope or not)
    so the UI can show NA reasons. Controls never mentioned by the source
    are *absent* — render them as "no decision".

    ``parameter_overrides_json`` carries ODP (organization-defined
    parameter) values. They're keyed by the control because ODP language
    in the catalog lives on the Control statement, not on individual CCIs.
    """

    id: int | None = Field(default=None, primary_key=True)
    baseline_id: int = Field(foreign_key="baseline.id", index=True)
    control_id: int = Field(foreign_key="control.id", index=True)
    in_scope: bool = Field(default=True, index=True)
    tailoring_reason: str | None = None
    # DEPRECATED (v0.1). ODP (organization-defined parameter) values now live
    # in :class:`OdpAssignment` — framework-scoped, provenance-tagged, resolved
    # at render time. This column is no longer written by any ingest path and
    # remains only because the routes/baselines.py response and the
    # ControlDetail.tsx UI still null-guard a read off it. Strip in v0.2
    # alongside the synchronized API + UI cutover. See
    # memory/project_odp_architecture.md for the locked design.
    parameter_overrides_json: str | None = None
    # Responsibility assignment from a CRM (or future SSP/SSPP) overlay.
    # One of:
    #   "customer"       -- customer fully owns; same as no CRM row (full assessment)
    #   "provider"       -- CSP/provider implements; short-circuit with NOT_APPLICABLE
    #                       + Decision.source="crm_provider"
    #   "hybrid"         -- shared; inject ## responsibility_split into LLM prompt
    #   "inherited"      -- inherited from authorizing system; short-circuit with
    #                       COMPLIANT + Decision.source="crm_inherited"
    #   "not_applicable" -- CSP marked NA in their CRM (e.g. control type
    #                       doesn't apply to their service model)
    # Loader-agnostic: a future SspBaselineSource populates the same column.
    responsibility: str | None = None
    # Customer-side narrative text from the CRM's "Customer Responsibility"
    # column (or equivalent SSP/SSPP field). Surfaced into the prompt for
    # hybrid controls and into the SAR CRM appendix for all responsibility
    # types. Kept separate from ``tailoring_reason`` (which feeds the SAR
    # tailored-out table) so the two never collide in reports.
    responsibility_narrative: str | None = None
    # On-prem scope split. The two ``responsibility`` / ``responsibility_narrative``
    # fields above carry the CLOUD-scope verdict from the CRM (matches how every
    # CSP-issued CRM template is structured — AWS GovCloud, Azure, GCP). These
    # two on-prem fields carry the separately-tracked verdict for the same
    # control's on-prem footprint, for systems that mix cloud + on-prem assets.
    # Nullable: legacy single-column CRMs leave these null and the assessor
    # falls back to the cloud verdict alone (backward-compatible).
    responsibility_onprem: str | None = None
    responsibility_onprem_narrative: str | None = None


class OdpAssignment(SQLModel, table=True):
    """Organization-Defined Parameter value, framework-scoped and provenance-tagged.

    ODPs (e.g. ``{$37$}`` in Rev 4 or ``ac-02_odp.03`` in Rev 5) are stored
    as first-class rows here and resolved at *render time* — never baked
    into ``Control.statement`` at ingest. This separates storage (rows)
    from presentation (render), which is what lets v0.2 (CRM overlays)
    and v0.3 (multi-framework crosswalks) slot in without schema
    migration. See ``memory/project_odp_architecture.md`` for the locked
    design and the three principles that govern this table.

    **Composite PK** = ``(framework_version, control_id, odp_id, assigned_from)``.
    Including ``assigned_from`` in the PK is deliberate: it lets multiple
    overlays (workbook + CRM-provider + SSP-doc) coexist for the same ODP
    without one collapsing the other. The assessor — not an inference
    rule — chooses which row applies per SSP at render time.

    ``framework_version`` is the canonical ``Framework.framework_id``
    string (e.g. ``"NIST-800-53r4"``) so a single column joins to both
    base and shadow Frameworks. Stored as a string (not an FK to
    ``framework.id``) so cross-framework JOINs through
    :class:`FrameworkEquivalence` work without forcing every overlay to
    materialize as a Framework row.

    Indexed on ``(framework_version, control_id)`` because
    ``resolve_odps()`` pulls every ODP for one control in a single query
    on the hot render path.
    """

    framework_version: str = Field(primary_key=True, index=True)
    control_id: str = Field(primary_key=True, index=True)
    odp_id: str = Field(primary_key=True)
    assigned_from: str = Field(primary_key=True)
    value: str
    # Where this row came from. One of:
    #   "CCIS-workbook" -- ingested from the Assignment Values tab
    #   "SSP-doc"       -- extracted from an SSP document
    #   "user-edit"     -- assessor override in the UI
    #   "CRM-tab"       -- v0.2 CRM overlay ingest
    source_ingest: str
    ingested_at: datetime = Field(default_factory=_utcnow)
    # Bridge to OSCAL parameter ID space (e.g. "ac-2_prm_1" Rev 4 or
    # "ac-02_odp.01" Rev 5). Populated at ingest by positional alignment
    # of OSCAL param declaration order vs. eMASS workbook ODP order
    # within a control. NULL when alignment cannot be computed (param
    # count mismatch, control absent from OSCAL catalog, etc.) — render
    # falls back to odp_id lookup. See ccis_workbook.apply() Step 6b.
    oscal_param_id: str | None = None
    # Workbook slot position (0-based) within the control. This is the
    # canonical, catalog-agnostic anchor for the OSCAL bridge: stamped
    # purely from the position of ``odp_id`` in the workbook's declared
    # slot list (``slot_orders[ctl_id].index(odp_id)``) — no catalog
    # involvement at ingest. The render layer (``odp_render.py``) uses
    # ``slot_index`` to *re-derive* the OSCAL param id at lookup time
    # against the catalog's CURRENT statement, which makes the bridge
    # survive: catalog reload (which overwrites ``Control.statement``),
    # FedRAMP shadow synthesis (which re-emits the parent's params
    # verbatim), and Rev 4/Rev 5 naming-convention swaps (the position
    # is invariant; the param id is not). When workbook slot count and
    # catalog param count still differ at render time (Rev 4 workbook
    # against Rev 5 catalog, etc.), the row stays unresolved — that
    # genuine cross-revision case is what ``FrameworkEquivalence`` (v0.3)
    # will cure. ``oscal_param_id`` remains the fast-path cache for the
    # matched case so existing queries don't slow down.
    slot_index: int | None = None
    # Total number of slots the workbook *declared* for this control
    # (``len(slot_orders[ctl_id])``), regardless of how many are filled.
    # Stored on every row so the render layer can answer "does the
    # workbook's slot count match the catalog's param count?" without an
    # extra round-trip — all rows for the same control share this value.
    # The check that matters at render time is
    # ``row.slot_total == len(template_oscal_params)``; using ``len(by_slot)``
    # would mis-reject the sparse case where the workbook declared 4 slots
    # but only filled 2, leaving ``by_slot`` short. NULL on rows ingested
    # before this column existed (backfilled on the next re-ingest of the
    # originating workbook).
    slot_total: int | None = None


class FrameworkEquivalence(SQLModel, table=True):
    """Curated cross-framework ODP mapping (parameter-level crosswalk).

    Empty in v0.1. Populated in v0.3 from NIST/FedRAMP transition maps
    (and similar published crosswalks). ``resolve_odps()`` JOINs through
    this table when asked for a target framework that differs from the
    ODP's source framework — unmapped target ODPs render blank with a
    "no cross-framework mapping" reason, using the same render path.

    Mirrors the existing :class:`ControlCrosswalk` pattern but at the
    parameter level so we never need an algorithmic "translation"
    function — translation is data, not code.
    """

    id: int | None = Field(default=None, primary_key=True)
    source_framework: str = Field(index=True)
    source_odp_id: str = Field(index=True)
    target_framework: str = Field(index=True)
    target_odp_id: str
    # 0.0-1.0; curated confidence. Below ~0.8 the render layer surfaces
    # the mapping as advisory rather than substituting silently.
    confidence: float = 1.0


class OdpAuditLog(SQLModel, table=True):
    """Append-only diff trail for every :class:`OdpAssignment` overwrite.

    Inserted by ``ccis_workbook.apply()`` (and future overlay ingests)
    whenever an existing ``OdpAssignment`` value changes. ``who``
    identifies the ingest channel (e.g.
    ``"CCIS-workbook-ingest:<filename>"``), not an end user; user-edit
    rows carry the assessor identity instead. ``when`` indexed DESC for
    SAR history lookups ("what did the ODP say at the time of
    assessment?").

    Never updated, never deleted — this is the audit trail the SAR
    references and the assessor relies on to defend a verdict months
    later when a workbook has been regenerated.
    """

    id: int | None = Field(default=None, primary_key=True)
    framework_version: str = Field(index=True)
    control_id: str = Field(index=True)
    odp_id: str
    assigned_from: str
    prev_value: str
    new_value: str
    who: str
    when: datetime = Field(default_factory=_utcnow, index=True)


class BaselineObjective(SQLModel, table=True):
    """Per-CCI metadata within a baseline (NOT a scoping decision).

    Scoping has moved to :class:`BaselineControl` because tailoring is a
    Control/Enhancement decision, not a per-CCI one. This table now only
    carries CCI-level back-references the adapter needs to round-trip:
    notably ``source_row`` (the workbook row a CCI came from) so that
    when we write assessment results back, we know which row to write to.

    Rows here exist for every CCI the source surfaced, regardless of
    whether the parent Control is in-scope. To get the in-scope CCI set,
    join through :class:`Control` to :class:`BaselineControl`.
    """

    id: int | None = Field(default=None, primary_key=True)
    baseline_id: int = Field(foreign_key="baseline.id", index=True)
    objective_id: int = Field(foreign_key="objective.id", index=True)
    tailoring_reason: str | None = None
    # Adapter-defined back-reference (CCIS = excel row, OSCAL = impl-req id).
    source_row: str | None = None
    # Soft-delete flag. The ingest path (baselines/ccis_workbook.py::apply)
    # used to hard-delete rows the workbook no longer surfaces, which broke
    # save flows when the DISA CCI catalog deprecated an Objective the user
    # was actively assessing — the BaselineObjective row vanished and
    # routes/controls.py::_resolve_excel_row started raising 422 with no
    # in-app recovery path. Soft-delete preserves source_row so the resolver
    # still finds the excel_row mapping; the boolean lets baseline-detail
    # views render a deprecation badge instead of silently dropping the row.
    # Existing rows surface as NULL (treated as False) — read sites must
    # coerce, fresh inserts always write a concrete bool.
    is_deprecated: bool = Field(default=False, index=True)


class Assessment(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    workbook_id: int | None = Field(default=None, foreign_key="workbook.id", index=True)
    # SOC 1/2/3 assessments roll up under an Engagement instead of a Workbook.
    # Exactly one of (workbook_id, engagement_id) is set for any given row.
    engagement_id: int | None = Field(
        default=None, foreign_key="engagement.id", index=True
    )
    objective_id: int = Field(foreign_key="objective.id", index=True)
    # Excel row in the source workbook. Null for engagement-rooted assessments.
    excel_row: int | None = None
    # Status remains NOT NULL. v0.2 abstain rows record the LLM's *proposed*
    # status (or NON_COMPLIANT for parse errors) with needs_review=True
    # marking the verdict as untrusted. Preserving the proposal gives the
    # reviewer triage signal (e.g. "model thought Compliant but pass2 said
    # Non-Compliant"); needs_review keeps the row out of exports. Every
    # Assessment consumer — controls/exporter.py, poam/generator.py,
    # reports/sar.py, ccis_writer, and the workbook_control_status rollup
    # at routes/workbooks.py:728-733 — gates on needs_review at the
    # SELECT layer so coerced statuses never inflate Compliant/NC counts.
    status: ComplianceStatus
    tester: str
    date_tested: datetime
    narrative_q: str
    # v0.2 dual-narrative split (hybrid systems). ``narrative_q`` stays as
    # the canonical exporter narrative — it's what ``ccis_writer`` lands in
    # CCIS column Q, what POAMs/SAR read from, and what the single-scope
    # codepath has always written. The two fields below carry the per-side
    # text used when the CRM (or operator) marks the control as having a
    # split cloud/on-prem footprint; the UI detail page renders both columns
    # side-by-side so the reviewer can see each scope's reasoning without
    # them being mashed together in ``narrative_q``. Both nullable: legacy
    # rows + every single-scope control leave them null, and the renderer
    # falls back to ``narrative_q``.
    narrative_on_prem: str | None = None
    narrative_cloud: str | None = None
    narrative_class: NarrativeClass
    inheritance_rule: str | None = None  # "8a", "8b", "8c", or None
    # PCI DSS v4 — compensating-control narrative when the standard requirement
    # cannot be met directly. Null for all non-PCI frameworks.
    compensating_control: str | None = None
    # v0.2 precision-over-recall gates. needs_review=True means: row was
    # written so the reviewer can see what happened, but the verdict is NOT
    # trusted. Exporters (ccis_writer, poam) must skip
    # or coerce-to-"Not Assessed" these rows; UI "Apply to workbook" is
    # hard-disabled until the assessor clears the flag manually. See
    # feedback_precision_over_recall.md for the contract.
    needs_review: bool = Field(default=False, index=True)
    # Human-readable triage signal: "unverified-cites: USD12345678",
    # "dual-pass-disagreement: pass1=Compliant, pass2=Non-Compliant",
    # "stale-reference: USD00001111", "boundary-conflict: ...",
    # "validator-exhausted: <last rejection>", "llm-parse-error".
    review_reason: str | None = None
    # LLM-self-reported confidence (0.0-1.0). None for deterministic
    # short-circuits (rule 8a/8b/8c) — those are 1.0 by construction but we
    # leave the field null to mean "not LLM-derived" rather than overload
    # 1.0. Uncalibrated in v0.2; calibration pass deferred to v0.3 once
    # there's a labeled reviewer-corrected corpus to fit on.
    confidence: float | None = None
    # v0.2 — citation-hygiene flag, NOT an abstain. Retained as a column for
    # downstream POAM/SAR/CCIS exporters. The manual stale-reference and
    # NA-reconsideration signals that used to set it were removed with the
    # manual supersession registry, so it now stays False (evidence-chain
    # rewrites correct narratives in place during assessment instead). The
    # verdict is always trusted — NA is determined by CRM + workbook scope.
    rewrite_requested: bool = Field(default=False, index=True)
    # JSON-encoded list of [legacy, current] pairs. Format:
    # '[["Legacy Doc Title", "USD00012345 Current Doc Rev -"], ...]'. Null
    # when rewrite_requested is False (the steady state now). JSON-as-string
    # mirrors the rejection_log serialization in AssessmentRun.notes — keeps
    # the SQLite schema flat.
    rewrite_requested_refs: str | None = None
    # v0.2 patent-supporting provenance tag. Single indexed enum column
    # that collapses ``Decision.source`` + ``cache_source`` + ``needs_review``
    # into one filterable verdict-origin signal. Nullable for legacy rows
    # (pre-migration); every row written after the migration MUST set it.
    # Mapping lives in ``routes/controls.py::_decision_to_verdict_source``
    # so both persistence sites stay in sync. See ``VerdictSource`` above.
    verdict_source: VerdictSource | None = Field(default=None, index=True)
    # v0.2 dual-narrative advisory provenance. Always advisory (column Q
    # already passed ``validate()``); the flag records that the on-prem /
    # cloud halves tripped ``validate_dual_narratives`` for leak language
    # ("inherited from AWS" in the on-prem half) or CRM-responsibility
    # mismatch (customer-owned row with a populated cloud half, etc.).
    # ``dual_narrative_flagged`` is the indexed boolean so the UI / SQL
    # can filter the review queue with one predicate; ``dual_narrative_flag_reasons``
    # is the JSON-encoded list of RejectionReason string values (e.g.
    # ``'["dual_narrative_mislabel"]'``) for triage detail. False / null
    # for short-circuit rows (rules, CRM, abstain) and for clean LLM rows.
    # Single source of truth: routes/controls.py persistence sites read
    # ``Decision.dual_narrative_flags`` (populated in the LLM-accept path
    # of engine/assessor.py).
    dual_narrative_flagged: bool = Field(default=False, index=True)
    dual_narrative_flag_reasons: str | None = None
    # Audit v1 — ties this Assessment to the AssessmentRun that produced it.
    # Currently only timestamp correlation exists; auditors need to replay a
    # whole run as a unit (e.g. "show me every CCI verdict from the 2026-06
    # AC-family run"). FK declared at the ORM level only — SQLite ALTER TABLE
    # can't carry REFERENCES, and the additive migration in db.py adds the
    # raw INTEGER column.
    run_id: int | None = Field(
        default=None, foreign_key="assessmentrun.id", index=True
    )
    created_at: datetime = Field(default_factory=_utcnow)
    written_to_workbook_at: datetime | None = None


class AssessmentImplementation(SQLModel, table=True):
    """Per-implementation slice of an :class:`Assessment`.

    A single CCI legitimately splits N ways across implementation
    boundaries: a system may run on AWS GovCloud + Azure Government +
    on-prem simultaneously, and each slice has its own responsibility
    verdict, evidence, and narrative. The parent :class:`Assessment`
    carries the rolled-up worst-of status and composed narrative_q for
    legacy exporters; the rows below carry the per-slice detail used by
    the SAR sub-table, the POAM clustering key, and the ControlDetail
    N-impl editor.

    ``scope_label``
        Implementation identity. CRM-derived rows mirror the parent
        :class:`Baseline.scope_label` (e.g. ``"AWS GovCloud"``); the
        on-prem residual carries ``ON_PREM_LABEL`` from
        :mod:`baselines.scope_labels`.

    ``source_baseline_id``
        FK to the CRM Baseline that produced this slice. Null for the
        synthesized on-prem residual row (no Baseline corresponds to
        on-prem in the v0.2 model).

    ``responsibility``
        Mirrors :class:`BaselineControl.responsibility` for this CCI's
        Control under this Baseline. Drives the SAR sub-table's
        "responsibility" column and informs the worst-of rollup.

    ``status`` / ``narrative`` / ``evidence_refs``
        Per-slice verdict + reasoning. ``narrative`` is unprefixed;
        :func:`engine.assessor.compose_rolled_narrative` is the only
        function that prepends ``"{scope_label}: "`` when composing the
        parent :attr:`Assessment.narrative_q`.

    Backward compatibility
    ----------------------
    Pre-migration Assessment rows have zero children here. Readers
    (ccis_writer, sar.py, poam/generator.py, ControlDetail.tsx) fall
    back to the parent's ``status`` + ``narrative_q`` when this
    relationship is empty.
    """

    __table_args__ = (
        UniqueConstraint(
            "assessment_id",
            "scope_label",
            name="uq_assessment_implementation_assessment_scope",
        ),
    )

    id: int | None = Field(default=None, primary_key=True)
    assessment_id: int = Field(foreign_key="assessment.id", index=True)
    scope_label: str = Field(index=True)
    source_baseline_id: int | None = Field(
        default=None, foreign_key="baseline.id", index=True
    )
    # Mirrors BaselineControl.responsibility. Stored as the string value
    # to keep the table self-contained (the canonical enum lives on
    # BaselineControl and may be NULL there for catalog-only rows).
    responsibility: str | None = None
    status: ComplianceStatus
    narrative: str
    # JSON-encoded list of evidence-citation tags / doc refs. Same shape
    # as the per-CCI tag list the LLM emits.
    evidence_refs: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Attestation engagements (SOC 1 / 2 / 3 — AICPA SSAE 18/21)
# ---------------------------------------------------------------------------
#
# SOC engagements differ from rule-based frameworks (800-53, ISO, CIS) in two
# load-bearing ways:
#   1. Scope is a *service organization* over a *period*, not a system snapshot.
#      Type 1 = design at a point in time; Type 2 = design + operating
#      effectiveness across the period (sample-based testing).
#   2. SOC 1 uses control objectives the service org *defines itself* (ICFR-
#      relevant), so we need a writeable ControlObjective table. SOC 2/3 use
#      the AICPA Trust Services Criteria (Common Criteria + 4 optional
#      categories) — seeded once into TrustServicesCriterion and reused.
#
# AICPA does not publish OSCAL; the TSC seed ships as JSON loaded by
# ``backend/cybersecurity_assessor/catalogs/aicpa_tsc_loader.py`` (v0.8).


class EngagementType(str, Enum):
    SOC1_TYPE_1 = "SOC1_TYPE_1"
    SOC1_TYPE_2 = "SOC1_TYPE_2"
    SOC2_TYPE_1 = "SOC2_TYPE_1"
    SOC2_TYPE_2 = "SOC2_TYPE_2"
    SOC3 = "SOC3"  # public summary derived from a SOC 2 Type 2


class TrustServicesCriterion(SQLModel, table=True):
    """AICPA TSC 2017 (revised 2022). Seeded once per install.

    Common Criteria CC1.1–CC9.2 (~33 criteria, mandatory for every SOC 2) plus
    the four optional categories: Availability, Processing Integrity,
    Confidentiality, Privacy. ``category`` is "CC" for Common Criteria or one
    of the optional category names.
    """

    id: int | None = Field(default=None, primary_key=True)
    criterion_id: str = Field(index=True, unique=True)  # "CC1.1", "A1.2", "P3.1"
    category: str = Field(index=True)  # "CC", "Availability", "Privacy", ...
    title: str
    text: str  # verbatim criterion text from AICPA TSC
    # Optional crosswalk to 800-53 — populated from AICPA TSP Section 100A.
    nist_800_53_refs: str | None = None  # comma-joined control IDs


class ControlObjective(SQLModel, table=True):
    """SOC 1 control objectives — defined per-engagement by the service org.

    Unlike SOC 2 (which uses the fixed TSC catalog), SOC 1 control objectives
    are bespoke to each engagement and describe ICFR-relevant assertions
    (e.g. "Cash receipts are recorded completely and accurately").
    """

    id: int | None = Field(default=None, primary_key=True)
    engagement_id: int = Field(foreign_key="engagement.id", index=True)
    objective_number: str  # service-org assigned, e.g. "CO-04"
    text: str
    process_area: str | None = None  # "Revenue", "IT General Controls", ...


class Engagement(SQLModel, table=True):
    """A single SOC attestation engagement.

    For SOC 2/3, Assessment rows reference TrustServicesCriterion (via
    Objective rows created during TSC catalog load) through Assessment.
    objective_id. For SOC 1, Assessment rows reference ControlObjective —
    represented via a parallel Objective row created when the ControlObjective
    is added so the existing Assessment→Objective FK still resolves.
    """

    id: int | None = Field(default=None, primary_key=True)
    engagement_type: EngagementType = Field(index=True)
    service_org: str = Field(index=True)
    period_start: datetime  # ignored for Type 1 (point-in-time)
    period_end: datetime  # the "as-of" date for Type 1
    auditor: str | None = None
    system_id: int | None = Field(default=None, foreign_key="system.id")
    framework_id: int | None = Field(default=None, foreign_key="framework.id")
    created_at: datetime = Field(default_factory=_utcnow)


class TestOfControl(SQLModel, table=True):
    """Type 2 operating-effectiveness test for one Assessment.

    Type 1 engagements skip this table — design-only assessments record the
    conclusion in Assessment.narrative_q. Type 2 requires sample-based
    testing: pick N occurrences from the period, document exceptions, and
    explain why any deviation does or does not undermine the control.
    """

    id: int | None = Field(default=None, primary_key=True)
    assessment_id: int = Field(foreign_key="assessment.id", index=True)
    test_procedure: str
    sample_size: int
    exception_count: int = 0
    deviation_rationale: str | None = None
    tested_at: datetime = Field(default_factory=_utcnow)


class AssessmentRun(SQLModel, table=True):
    """A bulk run (e.g. /assess-control AC-2). Groups individual Assessments.

    Accuracy fields (retry_count, validator_rejections, supersession_hits,
    ccis_accepted, rule_8a_short_circuits, rule_8b_short_circuits,
    crm_short_circuit_count) are the load-bearing patent-supporting
    measurements -- they prove the deterministic-post-validator +
    supersession-mapper kernel improves LLM compliance-assessment accuracy.
    Token / cost fields are operational telemetry only.
    """

    id: int | None = Field(default=None, primary_key=True)
    workbook_id: int | None = Field(default=None, foreign_key="workbook.id", index=True)
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: datetime | None = None
    command: str | None = None  # "assess-control AC-2"
    # Operational telemetry
    llm_calls: int = 0
    llm_input_tokens: int = 0
    llm_output_tokens: int = 0
    llm_cache_read_tokens: int = 0
    cost_usd: float = 0.0
    # Accuracy measurements (patent-supporting)
    retry_count: int = 0
    validator_rejections: int = 0
    supersession_hits: int = 0
    ccis_accepted: int = 0
    # v0.2 precision-over-recall telemetry: how many CCIs the run abstained
    # on (any reason — validator-exhausted, unverified cites, dual-pass
    # disagreement, stale-reference, boundary-conflict, LLM parse error),
    # and the subset of those that were specifically dual-pass disagreements.
    # Both counters are decision-critical for tuning the abstain thresholds.
    abstained: int = 0
    dual_pass_disagreements: int = 0
    # v0.2 — citation-hygiene counter (NOT an abstain). Number of CCIs in
    # this run that landed on a trusted verdict but flagged stale doc cites
    # or NA-with-retired-citation. These rows ship to POAM/SAR with a
    # "Cite refresh requested" note attached. Tracked separately from
    # abstained because reviewer workflow is different — abstain = re-verify,
    # rewrite-requested = update the narrative citation in next pass.
    rewrites_requested: int = 0
    # v0.2 — decision-cache effectiveness counter. Number of CCIs in this
    # run served from ``DecisionCache`` instead of burning a fresh LLM
    # call. Mutually exclusive with retries/rejections (cache hits return
    # before the LLM path runs). The patent-kernel determinism + cost
    # claim is "re-runs over unchanged inputs are free" — this counter is
    # the operator-visible proof on the Runs page.
    cache_hits: int = 0
    # v0.2 — Rule #8a/#8b deterministic short-circuit counters. Number of
    # CCIs in this run that bypassed the LLM because the rules engine
    # produced an auto-Compliant (8a) or auto-NA (8b) verdict from
    # col J/K/L text alone. The patent's "deterministic pre-filter
    # avoids LLM cost AND removes a known LLM failure mode (parroting
    # the requirement text the LLM was supposed to validate)" claim is
    # one SQL query away: rule_8a_short_circuits + rule_8b_short_circuits
    # is the count of CCIs whose verdict was provably model-independent.
    rule_8a_short_circuits: int = 0
    rule_8b_short_circuits: int = 0
    # v0.2 — CRM short-circuit counter. Number of CCIs in this run that
    # bypassed the LLM because the attached CRM declared the parent control
    # as provider, inherited, or not_applicable (the three buckets where
    # the inheritance/non-applicability IS the assessment). The third
    # member of the "kernel skipped the LLM" cohort alongside Rule #8a/#8b
    # — together those three counters quantify the deterministic kernel's
    # LLM-cost-and-failure-mode avoidance per run. The per-event ledger
    # lives on ``CrmShortCircuitEvent`` (with suspicion-log provenance)
    # and surfaces in SAR Appendix G; this counter is the per-run aggregate.
    crm_short_circuit_count: int = 0
    # v0.2 — Per-class validator-rejection breakdown. The aggregate
    # `validator_rejections` counter answers "how many bad LLM outputs did
    # the validator catch?" but not "what KIND of bad output?" — which is
    # the operator-actionable signal (tune the prompt for the dominant
    # failure mode). Stored as a {RejectionClass: count} JSON dict so the
    # set of classes can evolve without a schema migration; the keys are
    # validated against ``measurement.RejectionClass`` at write time. By
    # contract, `sum(validator_rejections_by_class.values()) ==
    # validator_rejections` for any single run — enforced by
    # ``test_measurement_properties.py``.
    validator_rejections_by_class: dict[str, int] = Field(
        default_factory=dict, sa_column=Column(JSON)
    )
    # Audit v1 — run-level model fingerprint. Denormalized from per-Assessment
    # AssessmentTrace rows so the Runs page can show "this run was Opus @ 0.0
    # against system prompt sha 7f3a…" without a per-row scan. Nullable for
    # rows written before Audit v1 landed. ``system_prompt_sha`` is the
    # dominant prompt sha across the run's assessments (effectively constant
    # within a run — prompt only changes between deploys).
    model_id: str | None = None
    model_temperature: float | None = None
    system_prompt_sha: str | None = None
    notes: str | None = None


# ────────────────────────────────────────────────────────────────────────────
# POAM (Plan of Action & Milestones)
#
# A POAM is the eMASS-facing remediation record for one or more failing CCIs.
# Grouping policy is encoded in poam/generator.py — clusters at the natural
# remediation boundary (base control + (N) enhancements by default; whole
# family when one fix covers all failures within it). The generator's output
# is a draft; the UI must allow split/merge.
#
# Risk fields (likelihood / impact / residual_risk) follow NIST SP 800-30 Rev 1
# Appendix G/H/I — 5-level scale with the canonical risk matrix applied in
# poam/risk.py. No ad-hoc risk schemes.
# ────────────────────────────────────────────────────────────────────────────


class PoamStatus(str, Enum):
    """eMASS POAM status field values."""

    DRAFT = "Draft"          # local-only; not yet exported to eMASS
    ONGOING = "Ongoing"      # active remediation
    RISK_ACCEPTED = "Risk Accepted"
    COMPLETED = "Completed"


class RiskLevel(str, Enum):
    """NIST SP 800-30r1 Appendix G/H/I — 5-level qualitative scale.

    Semi-quantitative scores (Table I-2): Very Low=0, Low=2, Moderate=5,
    High=8, Very High=10. Stored as enum; numeric mapping lives in poam/risk.py.
    """

    VERY_LOW = "Very Low"
    LOW = "Low"
    MODERATE = "Moderate"
    HIGH = "High"
    VERY_HIGH = "Very High"


class Poam(SQLModel, table=True):
    """One POAM entry — round-trips into the eMASS RMF POAM workbook.

    Scoping (per feedback_poam_scoping.md): defaults to one POAM per base
    control + its (N) enhancements, but whole-family clustering is fine when
    a single remediation/milestone set genuinely covers all failures.

    `emass_poam_id` is populated on import; null until eMASS assigns one.
    `vulnerability_description` is the human-readable failure summary that
    appears in column D of the eMASS template.
    """

    id: int | None = Field(default=None, primary_key=True)
    workbook_id: int = Field(foreign_key="workbook.id", index=True)

    # Cluster identity
    control_cluster: str  # e.g. "SI-3", "AU-*" — base control or family wildcard
    vulnerability_description: str  # what's failing, in plain English
    security_control_number: str | None = None  # e.g. "SI-3, SI-3(1), SI-3(2)"

    # eMASS round-trip
    emass_poam_id: str | None = Field(default=None, index=True)
    source_identifying_control_vulnerability: str | None = None  # eMASS col E
    office_org: str | None = None  # eMASS col F (responsible org)

    # Lifecycle
    status: PoamStatus = PoamStatus.DRAFT
    scheduled_completion_date: datetime | None = None
    actual_completion_date: datetime | None = None

    # NIST SP 800-30r1 risk fields (all optional until assessor fills them)
    likelihood: RiskLevel | None = None
    impact: RiskLevel | None = None
    raw_severity: RiskLevel | None = None  # pre-mitigation risk from matrix
    relevance_of_threat: RiskLevel | None = None
    residual_risk: RiskLevel | None = None  # post-existing-controls

    # ── Risk provenance (alembic 0008) ────────────────────────────────────
    # Each scalar above gains a sibling ``*_source`` + ``*_rationale`` so a
    # 3PAO can answer "why is this MODERATE?" without spelunking the audit
    # trail. Source values are constrained server-side to:
    #   * ``"auto"``           — system-seeded (e.g. impact from STIG CAT)
    #   * ``"manual"``         — assessor edited the field via PATCH
    #   * ``"llm_suggested"``  — residual advisor proposal that the
    #                            assessor accepted via the apply endpoint
    #   * NULL                 — legacy row OR field never set
    # Rationale is free text — for ``"auto"`` rows the generator writes a
    # one-line explanation ("Seeded from highest-severity contributing
    # finding (V-67890, severity=high)"); manual / llm rows carry the
    # assessor's or model's free-form prose.
    likelihood_source: str | None = None
    likelihood_rationale: str | None = None
    impact_source: str | None = None
    impact_rationale: str | None = None
    residual_risk_source: str | None = None
    residual_risk_rationale: str | None = None

    # Remediation narrative
    resources_required: str | None = None
    mitigations: str | None = None  # existing compensating controls
    comments: str | None = None

    # Audit
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    exported_at: datetime | None = None  # last write to eMASS template

    # True once the assessor has manually edited vulnerability_description via
    # the UI. Set by the PATCH endpoint whenever the field appears in the
    # update payload. The generator's regeneration pass (which rewrites the
    # enriched narrative onto existing DRAFT POAMs on each run) checks this
    # flag and skips locked rows so an assessor's wording is never clobbered.
    narrative_locked: bool = Field(default=False, index=True)


class PoamObjective(SQLModel, table=True):
    """Many-to-many: which CCIs/objectives a POAM covers.

    A POAM clustering SI-3 + SI-3(1) + SI-3(2) will have one row per CCI
    rolled up under those controls. Used by the generator to detect overlaps
    and by the UI to show "this POAM covers N CCIs across M controls".
    """

    poam_id: int = Field(foreign_key="poam.id", primary_key=True)
    objective_id: int = Field(foreign_key="objective.id", primary_key=True)
    # Snapshot of the assessment status at POAM creation time. Lets us detect
    # later if a CCI was reassessed compliant without removing it from the POAM.
    status_at_creation: ComplianceStatus | None = None


class PoamEvidence(SQLModel, table=True):
    """Many-to-many: which evidence artifacts back a POAM.

    Distinct from ``EvidenceTag`` (which links evidence to *objectives* during
    assessment): a POAM-level link captures artifacts that justify the POAM
    itself — the scan report that exposed the finding, a remediation plan
    document, a vendor patch advisory, a CRM extract proving inheritance, etc.
    Keeping POAM evidence separate from objective evidence lets reviewers see
    "what's behind this POAM" without trawling N child CCIs and de-duping.

    ``note`` is a free-text rationale ("ACAS scan 2026-05-12, host exsys-app-01"
    or "Vendor advisory CVE-2026-1234, ETA 2026-Q3"). Optional — many links
    are self-evident from the artifact title.
    """

    poam_id: int = Field(foreign_key="poam.id", primary_key=True)
    evidence_id: int = Field(foreign_key="evidence.id", primary_key=True)
    note: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)


class PoamMilestone(SQLModel, table=True):
    """A scheduled remediation step under a POAM.

    eMASS expects at least one milestone per POAM with a description and
    target date. Order is by scheduled_date asc, then id asc.
    """

    id: int | None = Field(default=None, primary_key=True)
    poam_id: int = Field(foreign_key="poam.id", index=True)
    description: str
    scheduled_date: datetime | None = None
    completion_date: datetime | None = None  # null = open
    changes_history: str | None = None  # eMASS "Milestone Changes" column
    created_at: datetime = Field(default_factory=_utcnow)


class PoamRiskHistory(SQLModel, table=True):
    """Append-only audit trail for every POAM risk-field transition.

    Modelled on :class:`OdpAuditLog`. Inserted by ``routes/poams.py`` on
    every create/update that touches ``likelihood`` / ``impact`` /
    ``raw_severity`` / ``residual_risk`` (or their ``*_source`` /
    ``*_rationale`` siblings) AND by the generator when it seeds an
    ``impact`` from a STIG CAT. Never updated, never deleted.

    The 3PAO question "this POAM was HIGH in May, who changed it to
    MODERATE and why?" gets a concrete answer here months later. Each row
    captures both the verdict transition (``prev_value`` → ``new_value``)
    AND the supporting context (rationale + source) so the audit trail
    is self-contained — reviewers do not need to cross-reference a
    separate notes field to learn why a number moved.

    ``actor`` mirrors ``OdpAuditLog.who``: ``"assessor:<name>"`` for
    UI-driven edits, ``"system:generator"`` for generator seeds, and
    ``"system:residual-advisor"`` when the LLM suggestion is applied.

    ``__tablename__`` is pinned to ``"poamriskhistory"`` to match alembic
    0008. The composite ``(poam_id, created_at)`` index serves the
    common "show this POAM's history newest-first" query without a
    full table scan.
    """

    __tablename__ = "poamriskhistory"
    __table_args__ = (
        Index(
            "ix_poam_risk_history_poam_id_created_at",
            "poam_id",
            "created_at",
        ),
    )

    id: int | None = Field(default=None, primary_key=True)
    poam_id: int = Field(foreign_key="poam.id", index=True)
    # One of: "likelihood" | "impact" | "raw_severity" | "residual_risk".
    # Free string instead of an enum so the audit trail survives schema
    # tweaks that add/rename risk fields — old rows keep their literal.
    field: str = Field(index=True)
    prev_value: str | None = None
    new_value: str | None = None
    prev_rationale: str | None = None
    new_rationale: str | None = None
    prev_source: str | None = None
    new_source: str | None = None
    # Free-text actor identifier (see class docstring).
    actor: str | None = None
    created_at: datetime = Field(default_factory=_utcnow, index=True)


# ────────────────────────────────────────────────────────────────────────────
# ML calibration — sweep weight learning + CRM adversarial guard
#
# These tables back the v0.2 ML-first upgrade:
#
#   * SweepDecision / SweepWeights  — online SGD calibration of the
#     boundary-aware sweep scorer using assessor triage decisions as
#     implicit labels (1 = included at Ingest, 0 = unchecked).
#
#   * CrmSuspicionLog / CrmShortCircuitEvent — adversarial CRM guard
#     scoring per workbook + per-CCI evidence of every short-circuit
#     decision so a suspicious CRM can be retroactively audited.
#
#   * CrmCorpusFeatures / CrmAnomalyModel — feature corpus and trained
#     IsolationForest blob used to score how anomalous a CRM looks
#     compared to the population of historically-uploaded CRMs.
#
#   * CrmNarrativeEmbedding — content-addressed cache for narrative
#     embeddings so suspicion recompute doesn't re-hit the embeddings
#     API for unchanged text.
#
# sklearn is a *runtime* dep (SGDClassifier.partial_fit + IsolationForest.
# score_samples run inside the sidecar on demand). The trained model is
# always persisted as a pickle blob in a DB column — no on-disk model
# directory, so DB backup == full state.
#
# See engine/ML_ARCHITECTURE.md for the train/serve split, schema-version
# strategy, and operator promotion workflow.
# ────────────────────────────────────────────────────────────────────────────


class SweepDecision(SQLModel, table=True):
    """One row per candidate shown in SweepTriageDialog at Ingest click.

    ``included`` reflects the assessor's final check state — the implicit
    label for online SGD. ``fingerprint_snapshot_json`` freezes the
    boundary fingerprint that produced ``score_at_decision`` so batch
    recalibration can recompute features even if the workbook later
    changes (controls added/removed, CRM swapped, evidence retagged).

    ``consumed_for_training`` is set by ``engine.sweep_online`` after the
    row contributes to a ``SweepWeights`` partial_fit batch. Keeps the
    online updater idempotent against retried route invocations.
    """

    id: int | None = Field(default=None, primary_key=True)
    workbook_id: int = Field(foreign_key="workbook.id", index=True)
    candidate_path: str
    candidate_name: str
    score_at_decision: float
    signals_json: str  # JSON list[str] — e.g. ["host:server01","control:ac-2"]
    proposed_ccis_json: str  # JSON list[str] — OSCAL-canonical CCI ids
    fingerprint_snapshot_json: str
    weights_version_id: int = Field(foreign_key="sweepweights.id", index=True)
    included: bool
    auto_prechecked: bool
    consumed_for_training: bool = Field(default=False, index=True)
    created_at: datetime = Field(default_factory=_utcnow)


class SweepWeights(SQLModel, table=True):
    """Versioned weight config for the boundary-aware sweep scorer.

    v1 is seeded at DB init with the historical hand-tuned constants and
    ``source="manual"`` so existing tests and first-run users see no
    behavior change. Subsequent rows are written by:

      * ``engine.sweep_online`` — ``source="sgd_online"``, after each
        triage batch, parented to the currently-active weights.
      * ``scripts/recalibrate_sweep_weights.py`` — ``source="batch_lr"``,
        full-corpus batch fit, also parented to active.

    Neither updater auto-activates. ``is_active`` is flipped by an
    operator after spot-checking the proposed weights against held-out
    decisions (see the recalibration UI / script output).
    """

    id: int | None = Field(default=None, primary_key=True)
    fitted_at: datetime = Field(default_factory=_utcnow)
    source: str  # "manual" | "sgd_online" | "batch_lr"
    weight_host: float
    weight_control_id: float
    weight_family: float
    weight_crm_keyword: float
    weight_doc_prefix: float
    # 6th tier added 2026-06-04: boost for candidates whose path lies under a
    # folder the user explicitly bookmarked in Settings → SharePoint priority
    # links. Surfaces the assessor's *manual* prioritization as a first-class
    # signal alongside automated boundary heuristics. Default 0.15 (same
    # weight as CRM keyword — strong enough to lift a borderline match over
    # the surface threshold but not enough to pre-check a junk file on its
    # own). Defaults to 0.15 in additive migration for backfilled rows.
    weight_priority_link: float = 0.15
    intercept: float = 0.0
    surface_threshold: float = 0.30
    precheck_threshold: float = 0.60
    n_decisions_seen: int = 0
    auc: float | None = None  # 5-fold CV AUC; null for source="manual"
    parent_weights_id: int | None = Field(
        default=None, foreign_key="sweepweights.id", index=True
    )
    notes: str | None = None
    is_active: bool = Field(default=False, index=True)


class SweepRun(SQLModel, table=True):
    """One row per /api/sharepoint/sweep invocation. Cost + token telemetry.

    Written by the sweep route after ``sweep_for_boundary`` returns, before
    the existing attempts counter is bumped — that way a DB write failure
    here doesn't burn a soft-cap attempt.

    Distinct from SweepDecision (one-per-candidate label log feeding the
    online weight recalibrator); SweepRun is one-per-invocation aggregate
    telemetry: how many BFS'd, how many surfaced past the keyword
    threshold, how many we actually called the LLM judge on, total LLM
    spend, cache hit-rate proxy via ``cache_read_tokens``, which judge
    model was used, and whether a fallback fired (cost cap or API error).

    ``fingerprint_snapshot_json`` and ``weights_version_id`` mirror the
    SweepDecision pattern so a recalibration run can recompute features
    against the exact inputs that drove the surfaced ranking.

    Workbook decoupling (2026-06-05): both ``workbook_id`` and
    ``system_context_id`` are nullable, but the route layer enforces
    "at least one must be set" — a sweep is always attributable to
    either an open workbook or a pending SystemContext (boundary docs
    ingested before any workbook was opened). After a pending
    SystemContext is promoted onto a workbook, the original SweepRun
    rows stay keyed on ``system_context_id`` and become reachable via
    the workbook's now-set SystemContext join.
    """

    id: int | None = Field(default=None, primary_key=True)
    workbook_id: int | None = Field(
        default=None, foreign_key="workbook.id", index=True
    )
    # Set when the sweep ran against a pending SystemContext (no workbook
    # yet) — or alongside ``workbook_id`` once promote happens. Always
    # populated if the sweep had any SystemContext at all; the route layer
    # rejects sweeps where neither id is present.
    system_context_id: int | None = Field(
        default=None, foreign_key="systemcontext.id", index=True
    )
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: datetime = Field(default_factory=_utcnow)
    # Everything BFS'd from SharePoint, before any scoring filter.
    total_candidates: int = 0
    # Passed the keyword surface threshold and reached the judge eligibility
    # cut. Equals ``candidates_judged`` unless the LLM judge is disabled or
    # an early-skip kicked in.
    candidates_surfaced: int = 0
    # How many surviving candidates we actually called the LLM judge on —
    # may be less than ``candidates_surfaced`` if the cost cap fired mid-
    # batch and the tail was silently demoted to keyword-only.
    candidates_judged: int = 0
    llm_cost_usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    judge_model: str | None = None
    weights_version_id: int = Field(foreign_key="sweepweights.id", index=True)
    fingerprint_snapshot_json: str
    # None when the judge completed within the cap. Set to
    # "cost_cap_exceeded" for in-flight cap, or "api_error: ClassName: msg"
    # when every per-candidate call failed (the route shows one toast
    # instead of N). Pre-flight 402s never write a SweepRun — they refuse
    # before any spend happens.
    fallback_reason: str | None = None


class BoundaryTokenSource(SQLModel, table=True):
    """Per-token provenance for ``SystemContext.extracted_tokens``.

    The aggregate ``SystemContext.source_ref`` string (``"evidence:[1,2,3]"``)
    answers "what docs informed this context" but cannot answer the 3PAO-grade
    follow-up "where did the token ``okta`` come from?" This side table is the
    answer key: one row per token per SC, optionally pinned to the specific
    Evidence row + snippet that produced it.

    Lifecycle is tied to the parent SystemContext via CASCADE — re-running
    ``BoundaryDocsContextSource.apply`` overwrites the SC row and replaces
    the full ``extracted_tokens`` list, so the entire side-table row set for
    that SC is dropped and rewritten in the same transaction. The composite
    ``(system_context_id, token)`` index keeps the sweep's
    ``build_boundary_fingerprint`` walk cheap.

    ``source_kind`` drives 3PAO defensibility tiering:

      * ``doc_extracted`` — cheap-substring or normalized match against the
        exact section text the LLM saw; ``source_evidence_id`` set.
      * ``inferred`` — LLM emitted a token not found verbatim in source text
        (e.g. canonicalized form or expanded acronym); reserved for future
        use, currently unused by the v0.2 attribution path.
      * ``unattributed`` — neither match fired; token still lands in
        ``SystemContext.extracted_tokens`` so sweep bias degrades, never
        drops. ``source_evidence_id`` is NULL.

    Pre-v0.2 SystemContext rows have no children here; readers
    (``build_boundary_fingerprint``) treat absence as ``unattributed``.
    """

    id: int | None = Field(default=None, primary_key=True)
    system_context_id: int = Field(
        foreign_key="systemcontext.id",
        index=True,
        sa_column_kwargs={"info": {"ondelete": "CASCADE"}},
    )
    token: str = Field(index=True)
    source_evidence_id: int | None = Field(
        default=None,
        foreign_key="evidence.id",
        index=True,
        sa_column_kwargs={"info": {"ondelete": "SET NULL"}},
    )
    # Excerpt of the source text that contained the token. Truncated to 512
    # chars at write time so a re-extraction over a 40k-char section doesn't
    # bloat the table. NULL when source_kind is ``unattributed`` or
    # ``inferred``.
    source_snippet: str | None = None
    source_kind: str = Field(index=True)
    # Per-token confidence if the LLM surfaced one; falls back to the
    # SC-level ``confidence`` at read time when NULL.
    confidence: float | None = None
    created_at: datetime = Field(default_factory=_utcnow)

    __table_args__ = (
        Index("ix_boundarytokensource_sc_token", "system_context_id", "token"),
    )


class SweepHit(SQLModel, table=True):
    """Per-candidate per-token sweep telemetry — surfaced AND skipped.

    Today only candidates the operator *ingested* leave a trail
    (``SweepDecision``). Candidates that were surfaced past the keyword
    threshold but never ingested vanish — the 3PAO question "why did the
    sweep surface this file?" has no answer for skipped rows.

    Written at sweep surface time inside the same DB transaction as the
    parent ``SweepRun`` so the forensic snapshot is atomic: either both
    the run-level aggregate AND every signal that drove it land, or
    neither does. Volume is bounded: ~50 surfaced candidates × ~5 token
    matches each ≈ 250 rows per run. The composite
    ``(sweep_run_id, candidate_key)`` index supports the future detail-
    pane query ("which signals fired for this candidate in this run?").

    Cascades on the parent run delete so a clean-slate ``DELETE FROM
    sweeprun`` doesn't leave orphans.
    """

    id: int | None = Field(default=None, primary_key=True)
    sweep_run_id: int = Field(
        foreign_key="sweeprun.id",
        index=True,
        sa_column_kwargs={"info": {"ondelete": "CASCADE"}},
    )
    # ``{drive_id}:{item_id}`` — the same key the existing sweep candidate
    # dict serializer emits, so detail-pane joins are a string-equality match.
    candidate_key: str = Field(index=True)
    # The fingerprint token that fired this match (after normalization).
    matched_token: str
    # Raw signal string from ``score_candidate``: ``host:server01``,
    # ``path-segment:auth``, ``family:AC``, etc. Stored verbatim so a future
    # signal-kind change doesn't require a backfill — readers re-parse on
    # demand.
    matched_signal: str
    # Per-signal numeric contribution to the candidate's surfaced score.
    score_contribution: float
    created_at: datetime = Field(default_factory=_utcnow)

    __table_args__ = (
        Index("ix_sweephit_run_candidate", "sweep_run_id", "candidate_key"),
    )


class CrmSuspicionLog(SQLModel, table=True):
    """One row per ``score_crm_suspicion`` invocation.

    Persists the full hybrid score breakdown so the UI banner can render
    historical suspicion deltas after a CRM is re-uploaded. Also captures
    the assessor's after-the-fact verdict — ``assessor_marked_false_positive
    = True`` builds the labeled corpus for the v0.3+ supervised "this CRM
    lied" classifier.

    ``n_corpus`` is snapshotted so UI can explain "ML anomaly score
    computed against 14 historical CRMs" — cold-start runs (n < 10) write
    ``ml_anomaly_score = None``.
    """

    id: int | None = Field(default=None, primary_key=True)
    workbook_id: int = Field(foreign_key="workbook.id", index=True)
    crm_baseline_id: int = Field(foreign_key="baseline.id", index=True)
    computed_at: datetime = Field(default_factory=_utcnow)
    heuristic_score: float  # always present
    ml_anomaly_score: float | None = None  # IsolationForest, None when corpus < 10
    narrative_quality_score: float | None = None  # embedding-based, None w/o provider
    overall_suspicion: float  # blended; capped at 1.0
    flags_json: str  # JSON list[CrmSuspicionFlag dicts]
    per_family_json: str  # JSON {family: {...}}
    n_corpus: int = 0  # CrmCorpusFeatures count at compute time
    # Assessor verdict — None until the assessor responds to the banner.
    # True = "CRM is fine, dismiss"; False = "CRM is actually suspicious".
    # Drives the future supervised classifier.
    assessor_marked_false_positive: bool | None = Field(default=None, index=True)
    assessor_review_notes: str | None = None


class CrmShortCircuitEvent(SQLModel, table=True):
    """One row per CCI assessment that took the CRM short-circuit path.

    Lets a retroactive audit answer "which controls would the LLM have
    re-examined if we'd known the CRM was lying?" Linked to a
    ``CrmSuspicionLog`` row when one existed at decision time so the UI
    can group short-circuits by the suspicion verdict that allowed them.
    """

    id: int | None = Field(default=None, primary_key=True)
    workbook_id: int = Field(foreign_key="workbook.id", index=True)
    control_id_fk: int = Field(foreign_key="control.id", index=True)
    responsibility: str  # "provider" | "inherited" | "not_applicable"
    suspicion_log_id: int | None = Field(
        default=None, foreign_key="crmsuspicionlog.id", index=True
    )
    created_at: datetime = Field(default_factory=_utcnow)


class CrmCorpusFeatures(SQLModel, table=True):
    """One row per (CRM upload, schema version) — IsolationForest corpus.

    ``feature_schema_version`` is the load-bearing piece: when
    ``crm_ml.CURRENT_FEATURE_SCHEMA_VERSION`` bumps (new feature added,
    existing feature redefined), old rows stop matching and the corpus
    effectively resets for the new schema. Refit script ignores
    out-of-version rows; they're kept for diagnostics, not deleted.
    """

    id: int | None = Field(default=None, primary_key=True)
    crm_baseline_id: int = Field(foreign_key="baseline.id", index=True)
    workbook_id: int = Field(foreign_key="workbook.id", index=True)
    feature_schema_version: int = Field(index=True)
    features_json: str  # JSON serialization of CrmFeatureVector
    extracted_at: datetime = Field(default_factory=_utcnow)


class CrmAnomalyModel(SQLModel, table=True):
    """Persisted IsolationForest blob.

    ``model_blob`` is a joblib pickle (sklearn's recommended format —
    handles numpy arrays + tree structure efficiently). One row is
    ``is_active=True`` at a time; ``scripts/refit_crm_anomaly_model.py``
    writes new rows ``is_active=False`` for operator promotion.

    ``feature_schema_version`` must match the schema version of the
    incoming feature vector at score time — mismatches return None and
    the suspicion report falls back to heuristics + embeddings.
    """

    id: int | None = Field(default=None, primary_key=True)
    fitted_at: datetime = Field(default_factory=_utcnow)
    n_samples: int  # corpus size at fit time
    feature_schema_version: int = Field(index=True)
    model_blob: bytes
    notes: str | None = None
    is_active: bool = Field(default=False, index=True)


class CrmNarrativeEmbedding(SQLModel, table=True):
    """Content-addressed cache for narrative embeddings.

    Keyed by sha256(narrative_text) so identical narratives across CRMs
    share one row — the boilerplate problem the embeddings exist to
    detect collapses cache size naturally. ``provider`` + ``model_name``
    let us run multiple embedding backends side-by-side (OpenAI's
    text-embedding-3-small vs. local sentence-transformers vs. TF-IDF
    fallback) without collisions.
    """

    id: int | None = Field(default=None, primary_key=True)
    narrative_sha256: str = Field(index=True, unique=True)
    provider: str  # "openai" | "sentence_transformers" | "tfidf"
    model_name: str  # "text-embedding-3-small" | "all-MiniLM-L6-v2" | "tfidf-v1"
    embedding_json: str  # JSON list[float] — vector
    created_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Decision cache + calibration telemetry (v0.2 kernel hardening)
#
# Two thin tables that together carry the kernel's determinism + honesty
# story. ``DecisionCache`` is the content-addressed replay store — a
# re-run over an unchanged (row + evidence + CRM + prompt + kernel
# version) tuple returns the prior Decision without an LLM call. The
# fingerprint string is the PK, which gives us INSERT-OR-IGNORE semantics
# under concurrent writers (the parallel assess-batch fan-out can have
# two workers racing on the same fingerprint — both writes carry the
# same Decision payload by construction, so the second one no-ops
# cleanly).
#
# ``CalibrationEntry`` is the per-Decision audit row that lets the
# operator panel compute Brier + ECE against reviewer accept/reject. One
# row per LLM-informed Decision (rule-based short-circuits skip — they
# have no ``stated_confidence`` to grade); the reviewer fills in
# ``human_accepted`` / ``human_status`` / ``reviewed_at`` later via the
# ``POST /api/calibration/review/{id}`` endpoint. See
# ``engine/calibration.py`` for the scoring contract.
# ---------------------------------------------------------------------------


class DecisionCache(SQLModel, table=True):
    """Fingerprint → serialized Decision payload.

    The fingerprint is computed by ``engine.decision_cache.fingerprint``
    and is a sha256 over (kernel_version, prompt_sha, row payload,
    evidence sha, CRM payload). Bumping ``KERNEL_VERSION`` or editing the
    system prompt automatically invalidates every cached row without
    touching this table.
    """

    fingerprint: str = Field(primary_key=True)
    kernel_version: str = Field(index=True)
    prompt_sha: str = Field(index=True)
    decided_at: datetime = Field(default_factory=_utcnow)
    payload_json: str  # serialized engine.assessor.Decision
    hit_count: int = 0
    last_hit_at: datetime | None = None


class OverrideEpoch(SQLModel, table=True):
    """Per-objective counter that invalidates the decision cache on manual override.

    The :class:`DecisionCache` fingerprint is content-addressed: same row +
    same evidence + same CRM ⇒ same fingerprint ⇒ cache hit. That is the
    point — re-running an unchanged objective replays the prior Decision for
    free. But it has a silent failure mode: when a reviewer manually edits a
    verdict via ``POST /api/assessments`` (which clears ``needs_review`` to
    record explicit human trust), the *content* is unchanged, so a later
    ``POST /api/controls/.../assess`` produces the identical fingerprint,
    hits the cache, and replays the stale pre-override LLM Decision —
    clobbering the human's correction and re-raising ``needs_review``.

    This table breaks that tie. Each manual override bumps ``epoch`` for the
    ``(workbook_id, objective_id)`` pair, and the epoch participates in the
    fingerprint. After an override the fingerprint changes, so the next
    re-run MISSES the cache and re-assesses FRESH instead of replaying the
    superseded decision. The epoch defaults to 0, so objectives that have
    never been overridden compute exactly the legacy fingerprint and keep
    sharing cache entries across workbooks.
    """

    workbook_id: int = Field(foreign_key="workbook.id", primary_key=True, index=True)
    objective_id: int = Field(foreign_key="objective.id", primary_key=True, index=True)
    epoch: int = Field(default=0)
    updated_at: datetime = Field(default_factory=_utcnow)


class ResidualSuggestionCache(SQLModel, table=True):
    """Fingerprint → serialized residual-risk suggestion payload.

    Sibling table to :class:`DecisionCache`, scoped to the POAM residual
    advisor (``poam/residual_advisor.py``). The advisor is LLM-powered and
    environment-aware — it reads the POAM, the contributing STIG findings,
    and the linked control narratives to suggest a residual risk level
    while abstaining when boundary context is insufficient. Caching by
    content fingerprint keeps re-renders of the advisor card cheap and
    deterministic.

    The fingerprint is computed by
    ``poam.residual_advisor.fingerprint`` and is a sha256 over
    (advisor_version, prompt_sha, poam content, linked-objective
    narratives, contributing-finding identifiers). Bumping
    ``ADVISOR_KERNEL_VERSION`` or editing the residual-advisor prompt
    automatically invalidates every cached row without touching this
    table — same contract as :class:`DecisionCache`.

    ``poam_id`` is denormalized onto the cache row (and FK'd with
    CASCADE) so deleting a POAM evicts its cached suggestions
    automatically; without the FK, orphan rows would survive a POAM
    purge and pollute future re-creations of the same POAM id.
    """

    fingerprint: str = Field(primary_key=True)
    advisor_version: str = Field(index=True)
    prompt_sha: str = Field(index=True)
    poam_id: int = Field(foreign_key="poam.id", index=True)
    decided_at: datetime = Field(default_factory=_utcnow)
    payload_json: str  # serialized ResidualSuggestion
    hit_count: int = 0
    last_hit_at: datetime | None = None


class CalibrationEntry(SQLModel, table=True):
    """One LLM-informed Decision's confidence + reviewer signal.

    Written by ``RunRecorder._commit_outcome`` whenever the CCI outcome
    carries a ``stated_confidence`` (LLM-derived rows only — rule 8a/8b/
    SDA 8c/CRM provider/inherited/NA/no-llm-client abstains leave that
    field as None and don't get an entry).

    ``human_accepted`` / ``human_status`` / ``reviewed_at`` start null
    and get filled in by the reviewer via the calibration review
    endpoint. The Brier and ECE math in ``engine/calibration.py`` reads
    only entries where ``human_accepted is not None``; unreviewed rows
    are surfaced in the report's ``total_unreviewed`` counter so
    operators can see the sample size before reading the score.

    ``fingerprint`` ties the entry back to the ``DecisionCache`` row
    that produced (or would have produced) the verdict, so a future
    cache replay can project the reviewer signal onto the replayed row.
    """

    id: int | None = Field(default=None, primary_key=True)
    run_id: int = Field(foreign_key="assessmentrun.id", index=True)
    cci_id: str = Field(index=True)
    fingerprint: str = Field(index=True)
    stated_confidence: float  # what the LLM emitted at decision time
    proposed_status: str  # ComplianceStatus.value the LLM proposed
    final_status: str  # post-supersession / post-rewrite verdict
    abstained: bool = False
    rewrite_requested: bool = False
    human_accepted: bool | None = None  # reviewer fills later
    human_status: str | None = None  # reviewer's corrected status
    recorded_at: datetime = Field(default_factory=_utcnow)
    reviewed_at: datetime | None = None


# ---------------------------------------------------------------------------
# Audit v1 — verdict-to-evidence traceability for 3PAO / JAB review
#
# Defensibility IS the product for federal compliance. Every CCI verdict must
# be traceable back to (1) the literal prompt sent, (2) the literal evidence
# chunks the model saw, (3) the model + version + temp + raw response, and
# when the audit_citations_enabled flag is on, (4) per-claim citations linking
# narrative text to the specific evidence chunk and span that justified it.
#
# Tables here are write-on-decision, read-on-audit. They're never read during
# the assess loop (decision cache replays the Decision blob directly), so no
# join cost ever lands on hot-path persistence.
# ---------------------------------------------------------------------------


class PromptSnapshot(SQLModel, table=True):
    """Deduplicated store of system-prompt text, keyed by sha256.

    The same system prompt is shared across thousands of assessments per run
    (it only changes between deploys), so storing it once and referencing by
    sha keeps AssessmentTrace compact. ``prompt_kind`` distinguishes the
    canonical assess-control prompt from future variants (e.g. CRM-aware
    prompt, dual-narrative prompt) without forcing a schema split.
    """

    sha256: str = Field(primary_key=True)
    text: str
    prompt_kind: str = Field(default="assess_control", index=True)
    created_at: datetime = Field(default_factory=_utcnow)


class AssessmentTrace(SQLModel, table=True):
    """1:N with Assessment — one row per LLM call that produced the verdict.

    Single-pass writes one row (pass_index=0). Dual-pass writes two
    (pass_index=0/1) so an auditor can see both samples and the disagreement
    that drove the abstain. Deterministic short-circuits (rule 8a/8b/8c, CRM,
    no-llm-client) write zero rows — no LLM call to trace.

    ``user_message`` is stored verbatim because reconstruction-on-demand
    breaks every time the prompt builder, row schema, or evidence renderer
    changes — and that defeats the auditability goal. ~4-8KB × ~3000 CCIs
    is trivial against a SQLite-IS-the-bundle file already in tens of MB.

    ``raw_response_json`` is the full parsed Anthropic response payload (TEXT
    of a JSON dump). Combined with ``request_id`` it gives the auditor a
    deterministic replay handle — Opus @ temp 0 is byte-identical on re-run,
    diffs are concrete proof of model/prompt drift.
    """

    id: int | None = Field(default=None, primary_key=True)
    assessment_id: int = Field(foreign_key="assessment.id", index=True)
    system_prompt_sha: str = Field(foreign_key="promptsnapshot.sha256")
    user_message: str
    model: str  # what we requested, e.g. "claude-opus-4-6"
    anthropic_model_version: str  # what Anthropic actually served (alias resolution)
    temperature: float
    max_tokens: int
    request_id: str  # Anthropic response.id — replay correlation
    raw_response_json: str  # full parsed response, JSON-dumped
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    pass_index: int = 0  # 0 single-pass, 0/1 dual-pass
    created_at: datetime = Field(default_factory=_utcnow)


class AssessmentEvidenceShown(SQLModel, table=True):
    """What evidence the model literally saw, in the order it saw it.

    Distinct from ``EvidenceTag`` (which is objective-scoped — what evidence
    is relevant to a Control objective overall) and from ``Evidence.sha256``
    (which is the *file* hash). The model never sees the whole file — it sees
    a head+tail-truncated snippet rendered into the prompt. That snippet
    gets its own ``chunk_sha`` so an auditor can verify "the model saw THIS
    EXACT TEXT" not "the file contained this text somewhere."

    ``relevance`` and ``tag_source`` are denormalized from EvidenceTag at
    capture time because EvidenceTag is mutable (relevance can change as
    later assessments retag evidence). Freezing the values here preserves
    the audit truth: "at the time this verdict was made, this chunk was
    relevance=0.87 from a STIG-mapper rule."

    Token-budget audit (evidence_ranker). ``disposition`` records whether the
    model actually SAW this chunk (``"examined"``) or whether it was ranked,
    snippet-hashed, and recorded but held back over the token budget
    (``"deferred"``). This is the column that makes "anything not examined
    must be traceable" true: a deferred row carries the exact snippet bytes +
    sha the model would have seen, plus a ``deferred_reason``, so a 3PAO/JAB
    reviewer can enumerate everything that exceeded the budget for a control —
    the old fixed-N cap left no such record. ``rank_score`` is the relevance
    used for the admission ordering (denormalized like ``relevance`` so a
    later retag doesn't rewrite history). ``deferred_reason`` is null on
    examined rows.
    """

    id: int | None = Field(default=None, primary_key=True)
    assessment_id: int = Field(foreign_key="assessment.id", index=True)
    evidence_id: int = Field(foreign_key="evidence.id", index=True)
    chunk_sha: str = Field(index=True)
    chunk_text: str  # the exact snippet as shown, including head+tail truncation
    order_index: int  # position in the prompt evidence block
    relevance: float | None = None
    tag_source: str | None = None
    # Token-budget partition audit. Defaults keep pre-migration code paths and
    # the no-overflow common case ("examined") working without an explicit
    # value at every construction site. ``disposition`` is indexed so the SAR
    # coverage join can cheaply filter examined-vs-deferred per assessment.
    disposition: str = Field(default="examined", index=True)
    rank_score: float | None = None
    deferred_reason: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)


class AssessmentCitation(SQLModel, table=True):
    """Per-claim spans linking narrative text to evidence-chunk text.

    Populated only when ``audit_citations_enabled`` is on (default OFF until
    the eval harness lands and verdict regression can be measured). Offsets
    are best-effort: ``narrative.find(claim_text)`` and
    ``chunk_text.find(source_quote)`` — if the LLM paraphrased the quote,
    the offset fields stay null and the row still carries the claim ↔
    chunk link with the verbatim ``source_quote``.

    ``extraction_method`` distinguishes LLM-self-citation (v1) from future
    regex-driven post-extraction or human-curated citations — same table,
    different provenance.
    """

    id: int | None = Field(default=None, primary_key=True)
    assessment_id: int = Field(foreign_key="assessment.id", index=True)
    # Which narrative field the claim came from. Free-form string so adding
    # narrative fields later (e.g. PCI compensating_control) is a no-migration
    # change. Validated at write time against a known set in the route.
    narrative_field: str  # "narrative_q" | "narrative_on_prem" | "narrative_cloud" | "narrative_class"
    claim_text: str
    claim_start_char: int | None = None
    claim_end_char: int | None = None
    evidence_shown_id: int = Field(foreign_key="assessmentevidenceshown.id")
    source_quote: str
    source_start_char: int | None = None
    source_end_char: int | None = None
    extraction_method: str = Field(default="llm_self_cite", index=True)
    created_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Evidence retention (capped, per-workbook rolling eviction)
#
# A continuously-pulling connector (the v2.0 in-boundary vision) can
# accumulate artifacts without bound. To keep a single workbook's evidence
# set from growing forever we cap it (default 30_000, see
# :mod:`evidence.evidence_retention`) and evict the OLDEST *safe-to-evict*
# rows when the cap is exceeded. "Safe to evict" is deliberately narrow:
# only artifacts that nothing load-bearing references. Every eviction is
# logged here so the audit trail can answer "what did the assessor delete,
# when, and why" long after the row itself is gone — defensibility over
# velocity. This table is append-only; it is NEVER itself evicted.
# ---------------------------------------------------------------------------


class EvidenceRetentionEvent(SQLModel, table=True):
    """Append-only ledger of evidence rows evicted by the retention cap.

    The evidence row is gone by the time anyone reads this, so we
    snapshot the identifying fields (path, sha256, title, ingested_at)
    rather than FK to a row that no longer exists. ``reason`` is a
    machine code (``"cap_exceeded"``) and ``detail`` a human sentence
    so a reviewer doesn't have to reverse-engineer the policy.
    """

    id: int | None = Field(default=None, primary_key=True)
    workbook_id: int = Field(foreign_key="workbook.id", index=True)
    # Snapshot of the evicted Evidence — intentionally NOT a FK (the target
    # row is deleted in the same transaction that writes this ledger entry).
    evicted_evidence_id: int = Field(index=True)
    evicted_path: str | None = None
    evicted_sha256: str | None = None
    evicted_title: str | None = None
    evicted_ingested_at: datetime | None = None
    reason: str = Field(default="cap_exceeded", index=True)
    detail: str | None = None
    # Workbook artifact count AFTER this eviction — lets the audit trail
    # reconstruct how close to the cap the set was at each step.
    remaining_count: int | None = None
    created_at: datetime = Field(default_factory=_utcnow, index=True)


# ---------------------------------------------------------------------------
# Automation schedules (per-workbook autostart queue, v2.0 seed)
#
# The v2.0 in-boundary assessor re-fires assessments on a schedule and on
# evidence change. This table is the v0.x seed of that: one row per
# (workbook, connector source) describing WHEN to pull/ingest and WHETHER
# the pull should chain into a batch re-assessment. The desktop sidecar's
# scheduler reads enabled rows on a tick; the same rows drive the
# Settings -> Automation UI. Kept deliberately small — interval + last-run
# bookkeeping — so the schema doesn't have to predict the full cron grammar
# v2.0 will eventually want.
# ---------------------------------------------------------------------------


class AutomationSchedule(SQLModel, table=True):
    """A per-workbook scheduled ingest/assess job (autostart queue entry).

    One row = "for workbook W, every ``interval_minutes`` pull from
    ``source_type`` (optionally one ``source_ref``) and, if
    ``run_assessment`` is set, kick a batch re-assessment afterward."
    ``source_type`` mirrors the connector enum used by the Sweep page
    (``"local"``, ``"sharepoint"``, ...). A null ``source_ref`` means
    "all configured roots for that connector".

    Scheduling state (``last_run_at`` / ``last_status`` / ``next_run_at``)
    lives on the row so the scheduler is stateless between ticks and the
    UI can render "last ran 12m ago, next in 48m" without a side table.
    """

    id: int | None = Field(default=None, primary_key=True)
    workbook_id: int = Field(foreign_key="workbook.id", index=True)
    name: str | None = None  # optional human label for the queue entry
    source_type: str = Field(index=True)  # connector enum: local|sharepoint|...
    source_ref: str | None = None  # path/site/library; null = all roots
    interval_minutes: int = Field(default=1440)  # default daily
    run_assessment: bool = Field(default=False)  # chain a batch re-assess?
    enabled: bool = Field(default=True, index=True)
    last_run_at: datetime | None = None
    last_status: str | None = None  # "ok" | "error" | "skipped" | running
    last_detail: str | None = None  # summary / error message of last run
    next_run_at: datetime | None = Field(default=None, index=True)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Catalog lookup helpers
# ---------------------------------------------------------------------------


def resolve_control(
    session: Session, framework_id: int, control_label: str
) -> "Control | None":
    """Find a Control by label within a framework, walking parent once on miss.

    FedRAMP-as-Framework (v0.2) inherits the bulk of its catalog from NIST
    800-53 r5 and only defines a handful of FedRAMP-specific control rows
    on its own Framework. Callers asking ``resolve_control(fedramp_id,
    "AC-2")`` need to fall through to the rev5 parent rather than 404 on a
    label that lives one hop up.

    Single-hop walk is enough for v0.2 — no framework on the roadmap chains
    deeper than overlay → catalog. If a future framework needs deeper
    chaining (overlay → overlay → catalog), recurse with a depth cap.

    Returns ``None`` when neither the child nor (if present) the parent has
    a matching Control. Callers that previously did a direct
    ``select(Control).where(framework_id == ..., control_id == ...)`` should
    swap to this helper so FedRAMP loads don't drop inherited rows.

    Note: ``control_label`` matches against :attr:`Control.control_id`
    (e.g. ``"AC-2"``, ``"AC-2(1)"``) — that's the field the OSCAL profile
    loader and the Baseline grader both key on. Renamed in the signature to
    avoid the confusing-but-correct ``Control.control_id`` (the string label)
    vs. ``Control.id`` (the PK) collision.
    """
    hit = session.exec(
        select(Control).where(
            Control.framework_id == framework_id,
            Control.control_id == control_label,
        )
    ).first()
    if hit is not None:
        return hit
    fw = session.get(Framework, framework_id)
    if fw is None or fw.parent_framework_id is None:
        return None
    return session.exec(
        select(Control).where(
            Control.framework_id == fw.parent_framework_id,
            Control.control_id == control_label,
        )
    ).first()
