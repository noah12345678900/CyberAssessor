/**
 * Typed client for the FastAPI sidecar.
 *
 * The Electron main process spawns the Python sidecar on a random port and
 * pushes the URL onto `window.ccis.sidecarUrl` via the preload bridge. In
 * Vite dev mode we fall back to the well-known port from `pnpm dev:backend`.
 */

declare global {
  interface Window {
    ccis?: {
      sidecarUrl: string;
      openFolder: () => Promise<string | null>;
      openFile: (filters?: { name: string; extensions: string[] }[]) => Promise<string | null>;
      /**
       * Resolves an absolute path for a File dragged into the renderer.
       * Electron 32 deprecated `File.path`; this is the supported replacement
       * (preload-side `webUtils.getPathForFile`). Used by the System
       * Description drop zone to convert HTML5 File objects from a drag-drop
       * event into paths the sidecar's path-based ingest accepts.
       */
      getDroppedFilePath: (file: File) => string;
      /**
       * Custom window controls (min / max / close) — wired in preload.ts and
       * consumed by WindowControls.tsx. Absent in browser mode (no Electron
       * preload bridge); WindowControls renders nothing in that case.
       */
      windowControls: {
        minimize: () => void;
        toggleMaximize: () => void;
        close: () => void;
        isMaximized: () => boolean;
        /** Returns an unsubscribe function. */
        onMaximizedChange: (cb: (maximized: boolean) => void) => () => void;
      };
    };
  }
}

const DEV_FALLBACK = "http://127.0.0.1:8765";

export function baseUrl(): string {
  return window.ccis?.sidecarUrl ?? DEV_FALLBACK;
}

/**
 * True only when running inside Electron with the preload bridge wired up.
 * Native file/folder dialogs are unavailable outside Electron (plain
 * browser at http://localhost:5173) — UI must fall back gracefully.
 */
export function hasNativeBridge(): boolean {
  return typeof window !== "undefined" && !!window.ccis;
}

/** Thrown for non-2xx responses; carries parsed JSON body when available. */
export class ApiError extends Error {
  constructor(
    public status: number,
    public statusText: string,
    public body: unknown,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${baseUrl()}${path}`, {
    headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
    ...init,
  });
  if (!res.ok) {
    let body: unknown = null;
    let detail = res.statusText;
    try {
      const text = await res.text();
      try {
        body = JSON.parse(text);
        const d = (body as { detail?: unknown }).detail;
        if (typeof d === "string") {
          detail = d;
        } else if (d && typeof d === "object") {
          // FastAPI lets routes raise HTTPException with a structured detail
          // dict (e.g. /assess-batch 412 → {error, message, hint}). Prefer
          // the human-readable message field so error toasts don't show raw
          // JSON. Fall back to a short summary if no message is present.
          const obj = d as Record<string, unknown>;
          const msg = typeof obj.message === "string" ? obj.message : null;
          const hint = typeof obj.hint === "string" ? obj.hint : null;
          if (msg) detail = hint ? `${msg} — ${hint}` : msg;
          else detail = text;
        } else {
          detail = text;
        }
      } catch {
        detail = text;
      }
    } catch {
      // keep statusText
    }
    throw new ApiError(res.status, res.statusText, body, `${res.status} ${detail}`);
  }
  // 204 No Content
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// ---------------------------------------------------------------------------
// Types — kept in sync with backend/cybersecurity_assessor/models.py + routes/*.py
// ---------------------------------------------------------------------------

export type ComplianceStatus = "Compliant" | "Non-Compliant" | "Not Applicable";

export type NarrativeClass =
  | "compliance-affirming"
  | "NA-justifying"
  | "gap-describing"
  | "ambiguous";

export type EvidenceKind =
  | "pdf"
  | "docx"
  | "pptx"
  | "xlsx"
  | "stig_ckl"
  | "stig_cklb"
  | "stig_xccdf"
  | "nessus"
  | "text"
  | "other";

export interface Framework {
  id: number;
  name: string;
  version: string;
  oscal_uri?: string | null;
  /**
   * Self-FK — non-null when this Framework extends another's catalog
   * (e.g. FedRAMP → NIST 800-53 r5). NULL for root catalogs. The
   * ComplianceTargetPicker uses this to indent child frameworks under
   * their parent with a "(extends …)" tag.
   */
  parent_framework_id?: number | null;
  /**
   * Display/selection gate (backend migration 0012). When false the
   * framework is hidden from the active Catalog list and from the
   * assess/baseline pickers, but still appears in Settings as a toggle
   * row so it can be re-enabled. Optional for back-compat with any cached
   * response predating the column; treat missing as enabled.
   */
  enabled?: boolean;
}

export interface Control {
  id: number;
  control_id: string;
  title: string;
  family: string;
  /**
   * Framework that owns this Control row. Each Framework gets its own
   * Control + Objective rows even for the same control_id string (catalog
   * isolation), so the UI must use this to constrain the workbook picker
   * to workbooks from the same framework — otherwise Save sends an
   * Objective PK from one framework against a Baseline from another and
   * the server rejects with 409 cross-framework. Optional because legacy
   * endpoints may not populate it.
   */
  framework_id?: number;
}

export interface Objective {
  id: number;
  objective_id: string;
  source: string;
  text: string;
  /**
   * True when this CCI was surfaced by the workbook's source (via
   * BaselineObjective for the workbook's baseline). False means the row
   * is a catalog-only stub for the same control — useful context, but
   * the workbook didn't list it. When the caller doesn't pass
   * ``workbook_id`` (or the workbook has no baseline), the backend
   * returns true for every row so old callers behave unchanged.
   */
  in_workbook?: boolean;
  /**
   * Program-specific requirements (e.g. SDA Controls "shall" statements)
   * that crosswalk to this CCI. Only populated when the caller passes
   * include_mappings=true; older endpoints leave it undefined.
   */
  mappings?: RequirementMapping[];
  /**
   * Workbook Column L (inherited) value for this CCI — e.g. "Local",
   * "DoW Enterprise", "Yes", "No". This is the authority for the flex
   * (On-Premises/workbook) slice's status under the pie-slice model.
   * Only populated when get_control is called with a workbook_id and the
   * workbook row is readable; null/undefined otherwise (chip omitted).
   */
  inherited?: string | null;
}

export interface RequirementMapping {
  source_name: string;
  requirement_number: string;
  requirement_text: string;
}

/**
 * Single program-specific requirement (shall statement) crosswalked to one
 * Objective under the current control. Used by the Control detail PSC card.
 *
 * `objective_code` is the human CCI (e.g. "CCI-000007"); `objective_id` is
 * the DB primary key so the UI can deep-link to that objective if needed.
 */
export interface ProgramControlRow {
  id: number;
  requirement_number: string;
  requirement_text: string;
  objective_id: number;
  objective_code: string;
}

/**
 * One overlay's worth of PSC rows for a single base control —
 * `GET /api/controls/{control_id}/program-controls` returns one of these
 * per RequirementSource.
 */
export interface ProgramControlSourceGroup {
  source: { id: number; name: string; framework_id: number };
  rows: ProgramControlRow[];
}

export interface ControlDetail extends Control {
  statement: string | null;
  /**
   * ODP placeholders that remain unresolved in the rendered statement —
   * either no OdpAssignment row exists for that odp_id, or the matching
   * row's value is empty (workbook encodes "slot exists but unassigned"
   * as an empty cell). Surfaced to the UI as a "needs review" badge so
   * the assessor knows the program hasn't picked a value yet.
   */
  unresolved_odps?: string[];
  objectives: Objective[];
}

/**
 * One overwrite event from the OdpAuditLog, as emitted by
 * `GET /api/controls/{control_id}/odp-history`. The `who` string is the
 * ingest channel (e.g. `"CCIS-workbook-ingest:<filename>"`) — for v0.1
 * workbooks that is always the only writer; CRM/user-edit channels land
 * in later slices and re-use the same shape.
 */
export interface OdpHistoryEvent {
  /** UTC ISO 8601 with `Z` suffix. */
  when: string;
  who: string;
  /** PK fragment — control_id of the OdpAssignment row that was overwritten. */
  assigned_from: string;
  prev_value: string;
  new_value: string;
}

/**
 * All OdpAuditLog rows for one control, grouped per ODP id. Returned
 * empty when no ODP has ever been overwritten on the control (the
 * typical first-ingest case); UI hides the card and SAR omits its
 * Appendix H on empty.
 */
export interface OdpHistoryGroup {
  odp_id: string;
  events: OdpHistoryEvent[];
}

/** Result of POST /api/catalog/load/disa-cci. */
export interface DisaCciLoadResult {
  total_ccis: number;
  inserted: number;
  updated: number;
  skipped: number;
  deprecated: number;
}

/**
 * Result of POST /api/catalog/load/program-controls.
 *
 * Program-specific controls are stored in the same `RequirementSource` table
 * as any other program overlay — keyed globally by (framework_id, name) — so this loader
 * only needs to be run once per source xlsx. Baselines reference the loaded
 * source by id, not by re-importing the file.
 *
 * `unmapped_ccis` lists requirements that reference CCIs the catalog hasn't
 * seen yet (i.e. DISA CCI hasn't been loaded). Re-running this after DISA CCI
 * load picks them up — not an error.
 *
 * `unmapped_control_ids` is the control-grain analogue: when the overlay
 * encodes its mapping as `Associated CNSSI 1253 Control Tag: AC-2(13)`
 * prose (T1TL-style), this lists control IDs the target framework's catalog
 * doesn't have. Empty for pure CCI-grain overlays.
 */
export interface ProgramControlsLoadResult {
  requirement_source_id: number;
  name: string;
  rows_seen: number;
  maps_written: number;
  unmapped_ccis: string[];
  unmapped_control_ids: string[];
}

/** Aggregate counts — GET /api/catalog/status. Drives the Workbooks status card. */
export interface CatalogStatus {
  frameworks: {
    id: number;
    name: string;
    version: string;
    /** Self-FK — non-null when this framework extends another (FedRAMP → r5). */
    parent_framework_id?: number | null;
    /** Display/selection gate (migration 0012). Missing = treat as enabled. */
    enabled?: boolean;
    control_count: number;
    objective_count: number;
  }[];
  objectives_total: number;
  requirement_sources: {
    id: number;
    name: string;
    framework_id: number;
    loaded_at: string | null;
  }[];
}

export interface Workbook {
  id: number;
  path: string;
  filename: string;
  framework_id: number | null;
  baseline_id: number | null;
  last_opened: string;
  /**
   * When the assessor last reconciled this workbook against the eMASS POAM
   * export. `null` until the first POST /api/poams/import succeeds. The
   * Generate/Export dialogs show a yellow warning banner while this is null
   * — running Generate before importing can produce drafts that collide
   * with rows eMASS already has.
   */
  last_emass_import_at: string | null;
  /**
   * Absolute path of the "working copy" the app writes assessments into.
   * Lives under `~/.cybersecurity-assessor/working_copies/<wb_id>/<stem>_edited<ext>`
   * (NOT next to the original — the source in Downloads / OneDrive is never
   * touched). `null` until the first Apply creates it. This is where the
   * user should look for their saved work.
   */
  working_path: string | null;
  /**
   * Reference baselines attached for read-only annotation — typically
   * CCIS-derived baselines from sibling systems used for cross-reference
   * scoping. The workbook's *primary* assessment scope is `baseline_id`
   * above — overlays never receive Assessment writes; they surface as
   * badges/columns and as the SAR overlay-gap appendix. Note: FedRAMP /
   * Li-SaaS `oscal_profile` baselines are first-class assessment targets,
   * not overlay annotations — they're filtered out of overlay-attach flows.
   */
  overlay_baseline_ids: number[];
  /**
   * v0.2 sweep cap counter. Each successful `/api/sharepoint/sweep` against
   * this workbook increments this; at 2 the next sweep returns HTTP 409
   * until `/api/workbooks/{id}/sweep-attempts/reset` is called. The
   * SystemContext page renders "Sweep attempts: N of 2" off this and turns
   * the banner amber + surfaces the Reset button at 2/2.
   */
  sweep_attempts: number;
  /**
   * Cumulative dollar cost of every LLM-judge sweep run against this
   * workbook (v0.2 — see plans/cuddly-twirling-planet.md). The Workbooks
   * list shows this as a small `$X.XX total` chip; SweepRun rows hold the
   * per-sweep breakdown. Defaults to 0.0 for pre-v0.2 rows.
   */
  total_sweep_cost_usd: number;
}

/** Per-workbook reference overlay — GET /api/workbooks/{id}/overlays. */
export interface WorkbookOverlay {
  workbook_id: number;
  baseline_id: number;
  attached_at: string;
  note: string | null;
  baseline: {
    id: number;
    name: string;
    framework_id: number;
    source_type: string;
  };
  /**
   * Present (non-null) only on the POST response when a CRM overlay
   * was just attached and the backend ran the attach-time backfill.
   * `applied` is the number of Assessment rows written from the CRM's
   * deterministic (provider / inherited / not_applicable) entries.
   * GET responses always omit this field.
   */
  backfill?: {
    applied: number;
    skipped_existing: number;
    skipped_no_crm_entry: number;
    skipped_non_deterministic: number;
    skipped_no_workbook_row: number;
  } | null;
}

/**
 * Merged overlay scoping for the Controls grid — GET
 * /api/workbooks/{id}/overlay-membership. `by_control[control_id]` is keyed
 * by baseline_id; absence in that inner map means "unmentioned" for that
 * overlay (rendered as no badge).
 *
 * `by_control_requirements` carries program-requirement numbers (e.g.
 * "SDA-127") for `program_controls`-type overlays only. CRM / FedRAMP
 * overlays are absent from this map and continue to render as in/out badges.
 */
export interface OverlayMembership {
  overlays: {
    baseline_id: number;
    name: string;
    framework_id: number;
    source_type: string;
    // scope_label distinguishes sibling CRM overlays (one per cloud). May be
    // null for CRMs imported before the scope-label picker was restored.
    scope_label?: string | null;
  }[];
  by_control: Record<number, Record<number, "in" | "out">>;
  by_control_requirements: Record<number, Record<number, string[]>>;
}

export interface WorkbookSummary {
  filename?: string;
  rows?: number;
  // populated by backend/excel/ccis_reader.py — left open for now
  [k: string]: unknown;
}

/**
 * Per-workbook SystemContext — GET /api/system-context/{workbook_id}.
 *
 * Freeform metadata the assessor authors at the start of an engagement so
 * the boundary-aware sweep can bias scoring toward in-boundary evidence on
 * the first pass. `extracted_tokens` is the LLM-distilled list (lowercased,
 * de-duped) that gets merged into the sweep fingerprint's host_tokens at
 * the existing _W_HOST=0.40 weight. The four freeform fields are stored
 * verbatim for human reference / re-extraction.
 */
export type SystemContextSourceType =
  | "freeform_markdown"
  | "emass_ssp_xlsx"
  | "docx_narrative"
  | "oscal_ssp_json";

export interface SystemContext {
  id: number;
  // Null = the pre-workbook "pending singleton" — the assessor dropped boundary
  // docs on the Sweep Context page before opening a workbook. The DB enforces
  // at-most-one such row via the partial unique index
  // `ix_systemcontext_pending_singleton`. Promoted onto a Workbook either
  // explicitly via /api/system-context/pending/promote or automatically when
  // open_workbook commits.
  workbook_id: number | null;
  source_type: SystemContextSourceType;
  source_ref: string | null;
  boundary: string | null;
  stakeholders: string | null;
  tech_inventory: string | null;
  requirement_hints: string | null;
  extracted_tokens: string[];
  /**
   * Outcome confidence. Starts at the LLM's extraction estimate (0.0-1.0);
   * bumps +0.05 per accepted sweep artifact (clamped at 1.0). Drives the
   * UI progress bar.
   */
  confidence: number;
  created_at: string;
  updated_at: string;
}

/**
 * POST /api/system-context/{workbook_id} response. The row is saved even
 * on LLM extraction failure — `notes.extraction_error` is populated and
 * confidence drops to 0.2 so the UI can surface a toast without losing
 * the assessor's freeform narrative.
 */
export interface SystemContextUpsertResult {
  context: SystemContext;
  tokens_extracted: number;
  confidence: number;
  notes: Record<string, unknown>;
}

export interface SystemContextFreeformInput {
  /**
   * Adapter discriminator. Omit (or "freeform_markdown") to use the legacy
   * four-prose path. Set to "docx_narrative" to dispatch to the boundary-doc
   * adapter, which ignores the four markdown fields and pulls extracted text
   * from Evidence rows flagged `is_boundary_doc=true` for this workbook.
   */
  source_type?: SystemContextSourceType;
  boundary?: string | null;
  stakeholders?: string | null;
  tech_inventory?: string | null;
  requirement_hints?: string | null;
}

/**
 * GET /api/baselines/scope-labels response — the canonical scope-label
 * vocabulary for CRM uploads. `canonical` is the ordered selectable list;
 * `on_prem` is the reserved label the server rejects on upload; `other`
 * is the sentinel the UI uses to switch to a free-text input.
 */
export interface ScopeLabelsResponse {
  canonical: string[];
  on_prem: string;
  other: string;
}

/**
 * GET /api/system-context/pending response — the pre-workbook singleton +
 * its attached boundary docs. Either field can be null/empty independently:
 * an assessor may have dropped docs but not yet triggered extraction (ctx
 * null, docs populated), or vice versa. Backend returns 404 only when BOTH
 * are absent; this is then mapped to `null` by the client.
 */
export interface PendingSystemContextResponse {
  context: SystemContext | null;
  boundary_docs: Evidence[];
}

/**
 * POST /api/system-context/pending/promote response. `promoted` is false
 * when no pending row existed (caller can treat as a clean no-op); the
 * 409-conflict case (target workbook already has a SystemContext) surfaces
 * as ApiError from the request helper rather than as a flag here.
 */
export interface PromotePendingResult {
  promoted: boolean;
  workbook_id: number;
  context?: SystemContext | null;
  boundary_doc_count?: number;
  reason?: string;
}

/** Per-control rollup for the Controls grid — GET /api/workbooks/{id}/control-status.
 *
 * v0.2 precision-over-recall: ``needs_review`` counts abstain rows separately
 * from the trusted ``compliant`` / ``non_compliant`` / ``na`` buckets. When
 * ``needs_review > 0`` and no Non-Compliant exists, the backend rolls the
 * control up as ``"Needs Review"`` so the operator can find pending-triage
 * controls in the grid. See backend/routes/workbooks.py::workbook_control_status.
 */
export interface ControlStatusRollup {
  control_id: number;
  status: "Compliant" | "Non-Compliant" | "Not Applicable" | "Mixed" | "Needs Review";
  compliant: number;
  non_compliant: number;
  na: number;
  needs_review: number;
  /**
   * v0.2 citation-hygiene count -- number of TRUSTED-verdict rows on this
   * control that carry `rewrite_requested=true`. Orthogonal to the verdict
   * rollup (these rows still count toward compliant/non_compliant/na); the
   * UI uses this for a compact "Cite refresh" pill so the assessor sees
   * pending narrative-cite swaps without expanding the row.
   */
  rewrites_requested: number;
  total_assessed: number;
}

/** Per-control Column-L (flex/on-prem inheritance) rollup for the Controls grid
 * — GET /api/workbooks/{id}/col-l-status. Column L is per-CCI; the backend
 * aggregates each control's CCIs worst-of (assess > escalate > inherited).
 * `control_id` is the OSCAL canonical id matching Control.control_id.
 */
export interface ColLStatusRollup {
  control_id: string;
  outcome: "inherited" | "assess" | "escalate";
  /** Representative raw col-L cell that drove the rollup (for the chip label). */
  value: string;
}

/**
 * Summary block returned alongside a freshly-opened workbook.
 *
 * Scope is reported at the Control/Enhancement level now — that's where
 * tailoring decisions live. The objectives_* fields are CCI-level book-
 * keeping (rows seen by the adapter, rows whose CCI is unknown to the
 * catalog), not a scoping signal.
 */
/**
 * Per-tab counters returned by the CCIS workbook ingest. Lives inside
 * `WorkbookBaselineSummary.notes.odp_assignments`. All counters default
 * to 0 when the workbook has no Assignment Values tab. UI surfaces only
 * the fields that are nonzero so clean workbooks stay quiet.
 */
export interface OdpAssignmentNotes {
  /** New OdpAssignment rows created on this ingest. */
  inserted: number;
  /** Existing rows whose value changed — each emits one OdpAuditLog row. */
  updated: number;
  /** Total value-bearing rows parsed from the Assignment Values tab. */
  rows_parsed: number;
  /** Rows whose odp_id aligned positionally to an OSCAL param. */
  oscal_mapped: number;
  /** Rows where the positional bridge abstained (slot/param count mismatch). */
  oscal_mapping_abstained: number;
  /**
   * Value-bearing rows whose odp_id is absent from the parameterized
   * statement column's slot list — the row still lands but stays
   * `oscal_param_id=NULL`. Nonzero count flags workbook drift to the
   * assessor.
   */
  value_rows_without_slot: number;
  /** Control ids (canonical OSCAL form) carrying at least one orphan row. */
  controls_with_orphan_values: string[];
}

/**
 * Catalog enrichment counters from `populate_objectives` — Objective
 * (CCI) rows created/updated and any control / CCI ids the workbook
 * referenced that the catalog didn't already know about.
 */
export interface CatalogEnrichmentNotes {
  created: number;
  updated: number;
  missing_controls: number;
  missing_cci: number;
}

export interface WorkbookBaselineSummary {
  id: number;
  name: string;
  source_type: string;
  controls_in_scope: number;
  controls_out_of_scope: number;
  controls_unknown: number;
  objectives_seen: number;
  objectives_unknown: number;
  /**
   * Per-ingest counters keyed by phase. The CCIS workbook adapter emits
   * `catalog_enrichment` and `odp_assignments`; other adapters (OSCAL,
   * manual) may emit different keys or none at all — fields are optional.
   */
  notes: {
    catalog_enrichment?: CatalogEnrichmentNotes;
    odp_assignments?: OdpAssignmentNotes;
    [key: string]: unknown;
  };
}

/** Top-level baseline row from GET /api/baselines. */
export interface Baseline {
  id: number;
  name: string;
  framework_id: number;
  system_id: number | null;
  source_type: string;
  source_ref: string | null;
  /**
   * Scope discriminator for multi-implementation overlays (migration 0007,
   * `baseline.scope_label`). Null for single-scope/legacy baselines; CRM
   * imports carry the normalized scope (e.g. "cloud", "on-premises").
   */
  scope_label?: string | null;
  created_at: string;
  refreshed_at: string;
}

/**
 * Baseline detail — GET /api/baselines/{id}.
 *
 * `counts.in_scope` / `counts.out_of_scope` are legacy aliases for the
 * control-level fields, kept so older UI screens keep rendering during
 * the scope-on-Controls migration.
 */
export interface BaselineDetail extends Omit<Baseline, "system_id"> {
  counts: {
    in_scope: number;
    out_of_scope: number;
    controls_in_scope: number;
    controls_out_of_scope: number;
    objectives_in_scope: number;
    objectives_total: number;
  };
  /**
   * Workbooks that have attached this baseline as an overlay. Ordered
   * most-recently-attached first. Populated for CRM-source baselines so
   * the suspicion banner knows which workbook(s) to compute against;
   * almost always empty for non-CRM baselines (primary scopes don't go
   * through the overlay table).
   */
  attached_workbook_ids: number[];
}

/**
 * Per-Control tailoring row — GET /api/baselines/{id}/controls.
 *
 * **Authoritative scoping surface.** A CCI is in-scope iff its parent
 * Control is — never tailored on its own.
 */
export interface BaselineControlRow {
  baseline_control_id: number;
  control_id: number;
  control_code: string;
  title: string;
  family: string;
  in_scope: boolean;
  tailoring_reason: string | null;
  parameter_overrides_json: string | null;
  /**
   * Cloud-scope responsibility from a CRM (Customer Responsibility Matrix)
   * overlay. One of "customer", "provider", "hybrid", "inherited",
   * "not_applicable", or null when no CRM overlay supplied a cloud value.
   * Matches CSP-issued CRM templates (AWS GovCloud, Azure, GCP). Drives
   * the engine's provider/inherited/NA short-circuit alongside the on-prem
   * scope — short-circuit fires only when EVERY specified scope is
   * inheritable.
   */
  responsibility: string | null;
  /**
   * Free-form cloud-scope customer-side narrative from the CRM's
   * "Customer Responsibility" / "Cloud Customer Responsibility" column.
   * Surfaced into the LLM prompt for hybrid controls and into the SAR
   * CRM appendix.
   */
  responsibility_narrative: string | null;
  /**
   * On-prem scope responsibility — same enum as `responsibility`, but for
   * the on-premise footprint of the same control in mixed cloud + on-prem
   * systems. Null when the CRM only carries cloud-scope data (legacy
   * single-column templates).
   */
  responsibility_onprem: string | null;
  /**
   * On-prem scope customer-side narrative from the CRM's "On-Prem
   * Responsibility" / "On-Prem Customer Responsibility" column. Paired
   * with `responsibility_onprem`; null when the CRM doesn't carry an
   * on-prem column.
   */
  responsibility_onprem_narrative: string | null;
}

/**
 * Per-objective row — GET /api/baselines/{id}/objectives.
 *
 * `in_scope` is **inherited** from the parent Control's BaselineControl
 * row — there is no per-CCI scoping decision. `tailoring_reason` is the
 * Objective's own field falling back to the parent's.
 */
export interface BaselineObjective {
  baseline_objective_id: number;
  objective_id: number;
  objective_code: string;
  source: string;
  control_id: number;
  control_code: string;
  in_scope: boolean;
  tailoring_reason: string | null;
  source_row: number | null;
  text: string;
}

/** Refresh result — POST /api/baselines/{id}/refresh. */
export interface BaselineRefreshResult {
  baseline_id: number;
  refreshed_at: string;
  controls_in_scope: number;
  controls_out_of_scope: number;
  controls_unknown: number;
  objectives_seen: number;
  objectives_unknown: number;
  /** Same shape as `WorkbookBaselineSummary.notes` — see that type. */
  notes: WorkbookBaselineSummary["notes"];
}

/**
 * Result body — POST /api/baselines/crm/load.
 *
 * `controls_in_scope` is the count of CRM rows successfully ingested as
 * `BaselineControl` records. The loader can drop rows for two distinct
 * reasons and the UI surfaces them separately so a typo'd CRM doesn't
 * silently lose data:
 *   - `controls_unknown` / `unknown_control_ids` — CRM references a
 *     control the loaded framework catalog doesn't have (wrong rev, typo,
 *     withdrawn). The IDs let the user fix their CRM rather than guess.
 *   - `unknown_responsibility_rows` — the responsibility cell value
 *     (e.g. "Customr", "shred") didn't match any normalized bucket
 *     in `_RESPONSIBILITY_MAP`.
 *
 * `notes` is a loose adapter-specific dict (path, loader name, etc.)
 * kept for forward-compat; the typed counters above are what the toast
 * reads. Backend ships it as `Record<string, unknown>` not `string[]`.
 */
export interface CrmLoadResult {
  baseline_id: number;
  name: string;
  source_type: string;
  controls_in_scope: number;
  controls_unknown: number;
  unknown_control_ids: string[];
  unknown_responsibility_rows: number;
  notes: Record<string, unknown>;
}

/**
 * What the unified overlay-import front door (`POST /api/catalog/overlays/import`)
 * detected and dispatched to.
 *
 * - `crm` — control-id + responsibility headers → CRM loader. Returns a
 *   Baseline row with CRM source_type.
 * - `psc` — CCI + threshold/shall headers → program-specific-controls
 *   loader. Returns a RequirementSource row (not a Baseline) plus the
 *   matched sheet name so the toast can show which tab was parsed.
 * - `other` — neither vocab hit. Returns an inert Baseline row so the
 *   file is visible in the Workbooks attach UI, but no resolver runs
 *   against it during assessment until one is programmed for the file's
 *   shape. Always carries a "no resolver registered" warning.
 */
export type OverlayKind = "crm" | "psc" | "other";

/**
 * Flat response from `POST /api/catalog/overlays/import`. Only the
 * fields relevant to the dispatched loader are present:
 *
 * - **CRM** — `baseline_id`, `controls_in_scope`, `controls_unknown`,
 *   `unknown_control_ids`, `unknown_responsibility_rows`.
 * - **PSC** — `requirement_source_id`, `sheet_name`, `rows_seen`,
 *   `maps_written`, `unmapped_ccis`, `unmapped_control_ids`.
 * - **OTHER** — `baseline_id` only (no per-row counters; OTHER is inert).
 *
 * `warnings` is always present and always safe to render. For OTHER it
 * carries the "no resolver registered" line — surface it as the toast
 * subtitle so the assessor understands the file is metadata-only.
 */
export interface OverlayImportResult {
  kind: OverlayKind;
  name: string;
  warnings: string[];
  baseline_id?: number;
  requirement_source_id?: number;
  sheet_name?: string;
  // CRM-only counters
  controls_in_scope?: number;
  controls_unknown?: number;
  unknown_control_ids?: string[];
  unknown_responsibility_rows?: number;
  // PSC-only counters
  rows_seen?: number;
  maps_written?: number;
  unmapped_ccis?: string[];
  unmapped_control_ids?: string[];
}

/**
 * Per-sheet classification preview returned by
 * `GET /api/catalog/overlays/sheets`. Feeds the Settings → Import overlay
 * sheet-picker dropdown so the user can target Ground vs SV on the T1TL
 * workbook (the classifier always picks the first PSC-shaped sheet —
 * without per-sheet info there's no way to nominate the second one).
 *
 * `candidate_kind` is null for sheets whose headers match no known
 * vocabulary — the dropdown still lists them so the user can force one
 * via `kind_hint`, but they're flagged as non-candidates in the UI.
 */
export interface OverlaySheetsResult {
  auto_pick: {
    kind: OverlayKind;
    sheet_name: string | null;
  };
  sheets: Array<{
    name: string;
    candidate_kind: OverlayKind | null;
  }>;
}

/**
 * One row of the three-tier CRM suspicion breakdown — a named heuristic
 * verdict with severity-based UI styling. ``details`` is intentionally
 * loose so the backend can attach domain-specific evidence (e.g. the
 * list of contradicting families, boilerplate excerpts) without a
 * schema change.
 */
export interface CrmSuspicionFlag {
  name: string;
  severity: "info" | "warn" | "alert";
  summary: string;
  details: Record<string, unknown>;
}

/**
 * Full hybrid-tier CRM suspicion report — returned by
 * ``GET /api/baselines/{workbook_id}/crm-suspicion``.
 *
 * The three tier scores are independent:
 *   * ``heuristic_score`` always present (the floor — works on the
 *     very first CRM ever uploaded).
 *   * ``ml_anomaly_score`` null until the IsolationForest corpus
 *     reaches ``MIN_CORPUS_SIZE`` (10) at the current feature schema.
 *   * ``narrative_quality_score`` null when no embeddings provider
 *     resolved (no API key + no offline extra installed).
 *
 * The UI hides ML rows whose score is null instead of greying them out;
 * the cold-start banner stays clean.
 *
 * ``suspicion_log_id`` ties back to the ``CrmSuspicionLog`` row so the
 * "mark as false positive" action knows which verdict to patch.
 */
export interface CrmSuspicionReport {
  workbook_id: number;
  crm_baseline_id: number;
  computed_at: string;
  heuristic_score: number;
  ml_anomaly_score: number | null;
  narrative_quality_score: number | null;
  overall_suspicion: number;
  severity: "info" | "warn" | "alert";
  flags: CrmSuspicionFlag[];
  per_family: Record<string, Record<string, unknown>>;
  n_corpus: number;
  suspicion_log_id: number;
}

/**
 * Subset of suspicion fields the cached ``/crm-suspicion/latest``
 * endpoint returns. Distinct from ``CrmSuspicionReport`` because:
 *   * No ``severity`` / ``per_family`` — those are computed at score
 *     time and aren't persisted on ``CrmSuspicionLog``.
 *   * Adds ``assessor_marked_false_positive`` so the post-attach toast
 *     can suppress the re-warning when the verdict was already cleared.
 */
export interface CrmSuspicionLatest {
  suspicion_log_id: number;
  workbook_id: number;
  crm_baseline_id: number;
  computed_at: string;
  heuristic_score: number;
  ml_anomaly_score: number | null;
  narrative_quality_score: number | null;
  overall_suspicion: number;
  flags: CrmSuspicionFlag[];
  n_corpus: number;
  assessor_marked_false_positive: string | null;
}

/** Body for marking a CrmSuspicionLog as a false positive. */
export interface MarkSuspicionFalsePositiveBody {
  notes?: string | null;
}

export interface Assessment {
  id: number;
  objective_id: number;
  workbook_id: number;
  excel_row: number;
  status: ComplianceStatus;
  tester: string;
  date_tested: string | null;
  narrative_q: string;
  /**
   * v0.2 dual-narrative fields for hybrid systems. Populated per the
   * CRM responsibility on the row:
   *   - customer       → on_prem only
   *   - hybrid         → both
   *   - provider/inh.  → cloud only
   *   - n/a            → on_prem only
   * The detail page renders whichever side(s) are non-null; the
   * canonical column-Q text lives in `narrative_q`.
   */
  narrative_on_prem: string | null;
  narrative_cloud: string | null;
  narrative_class: NarrativeClass;
  inheritance_rule: string | null;
  written_to_workbook_at: string | null;
  /**
   * v0.2 precision-over-recall gate. True when the assessor abstained
   * (validator exhausted, parse error, cite hallucination, dual-pass
   * disagreement, supersession-stale or boundary-conflict narrative).
   * Rows with `needs_review=true` are excluded from CCIS writes and
   * POAM clusters; the UI hard-gates the per-row Apply button and
   * renders an amber "Review" pill in the Controls grid.
   */
  needs_review: boolean;
  /**
   * Short machine-tagged reason for the abstain — prefixes like
   * `validator-exhausted:`, `llm-parse-error`, `unverified-cites:`,
   * `dual-pass-disagreement:`, `stale-reference:`, `boundary-conflict:`.
   * Null for trusted verdicts (`needs_review=false`).
   */
  review_reason: string | null;
  /**
   * LLM-self-reported confidence (0.0-1.0). Null for deterministic
   * short-circuits (rule 8a / 8b / 8c) which are 1.0 by construction
   * but don't bother round-tripping a score.
   */
  confidence: number | null;
  /**
   * v0.2 citation-hygiene flag. True when supersession or
   * NA-reconsideration detected a stale doc reference but the verdict
   * itself is trusted. **NOT an abstain** — the row exports normally
   * (CCIS writer / POAM generator both attach a "Cite refresh
   * requested" footer); the flag tells the assessor to swap the
   * legacy doc name on the next narrative pass.
   */
  rewrite_requested: boolean;
  /**
   * v0.2 multi-implementation children — one row per scope_label
   * (e.g. "AWS GovCloud", "Azure Government", "On-Premises"). Empty
   * array for pre-migration assessments; UI gates on `length > 0` to
   * render the N-impl editor and falls back to the legacy single
   * `narrative_q` editor otherwise. Parent `status` is the worst-of
   * rollup; parent `narrative_q` is `"{scope_label}: {narrative}"`
   * joined.
   */
  implementations: AssessmentImplementation[];
  /**
   * JSON-encoded `[[legacy, current], ...]` pair list — exactly what
   * the supersession engine reconstructed. Null when the flag was set
   * but the legacy/current pair couldn't be paired (older rows).
   * Render as a bulleted list in the info callout.
   */
  rewrite_requested_refs: string | null;
}

/**
 * v0.2 per-scope implementation row. One ``AssessmentImplementation``
 * exists for every scope_label the assessor recognized on the parent
 * Assessment — e.g. an AWS GovCloud CRM + an Azure Government CRM +
 * an implicit On-Premises residual = 3 implementations.
 *
 * Status/narrative live here; the parent Assessment row carries the
 * worst-of rollup and the composed "{scope_label}: {narrative}"
 * concatenation in `narrative_q` so legacy exporters keep working.
 *
 * `source_baseline_id` is null for the synthesized On-Premises row
 * (no CRM backs it); otherwise it points at the CRM Baseline that
 * supplied the scope.
 */
export interface AssessmentImplementation {
  id: number;
  scope_label: string;
  source_baseline_id: number | null;
  responsibility: string | null;
  status: ComplianceStatus;
  narrative: string;
  evidence_refs: string | null;
}

/**
 * One row in the v0.2 Review Queue — every Assessment with
 * `needs_review=true` for a workbook, joined to its Objective + Control so
 * the queue page can group/link without a second round-trip per row.
 *
 * Backend sorts by `review_reason` prefix (everything before the first
 * colon) then by `control_label`, so consumers can rely on that order
 * to slice into category sections without re-sorting client-side.
 */
export interface ReviewQueueItem {
  assessment_id: number;
  /** Objective.id (numeric PK) — pass to upsertAssessment. */
  objective_id: number;
  workbook_id: number;
  /** The status the LLM proposed, kept for display even though we don't trust it. */
  proposed_status: ComplianceStatus;
  narrative_q: string;
  review_reason: string | null;
  confidence: number | null;
  inheritance_rule: string | null;
  date_tested: string | null;
  /** Objective.objective_id — the CCI string like "CCI-000213". */
  cci_id: string;
  objective_text: string;
  /** Control.id (numeric PK) — link target for ControlDetail. */
  control_id: number;
  /** Control.control_id — display label like "AC-2". */
  control_label: string;
  control_title: string;
  family: string;
}

/**
 * One per-scope edit posted from the ControlDetail N-impl editor. Only
 * carries the user-editable fields — ``id`` identifies an existing
 * ``AssessmentImplementation`` row. Impls are NEVER inserted via the
 * upsert endpoint; they're created by the kernel-driven ``/assess`` path
 * via ``persist_assessment_with_impls``. When the parent ``Assessment``
 * carries no implementations (legacy single-narrative row), the editor
 * falls back to the existing form and ``implementations`` stays absent.
 *
 * Server-side: each edit's (status, narrative) pair is validated
 * independently, then the parent's ``status`` (worst-of rollup) and
 * ``narrative_q`` ("{scope_label}: …" join) are composed from the full
 * post-edit impl set — overriding whatever the client sent for those two
 * fields. The single-document parent validator is SKIPPED in that case
 * because the composed text legitimately contains both affirming and gap
 * phrases (one per scope).
 */
export interface ImplementationEdit {
  id: number;
  status: ComplianceStatus;
  narrative: string;
}

export interface AssessmentUpsert {
  workbook_id: number;
  objective_id: number;
  // Omit to let the backend resolve from BaselineObjective.source_row —
  // only set when overriding for an out-of-band edited workbook.
  excel_row?: number;
  status: ComplianceStatus;
  tester: string;
  narrative_q: string;
  /**
   * Optional dual-narrative fields. Omit on a pure-narrative_q edit to
   * leave existing values alone; pass explicit null to clear them.
   */
  narrative_on_prem?: string | null;
  narrative_cloud?: string | null;
  narrative_class: NarrativeClass;
  inheritance_rule?: string | null;
  date_tested?: string | null;
  /**
   * Manual edits clear the abstain — saving an assessor-edited
   * row sets `needs_review=false` so the export gates re-open.
   * Omit to leave the existing flag untouched (e.g. assessor is
   * patching only the narrative, not resolving the review).
   */
  needs_review?: boolean;
  review_reason?: string | null;
  confidence?: number | null;
  /**
   * Citation-hygiene flag — assessor can manually clear it when a
   * narrative pass refreshes the legacy doc cite. The backend never
   * sets this from a user edit (only supersession/NA-reconsideration
   * write it), so omitting the field on upsert preserves it.
   */
  rewrite_requested?: boolean;
  rewrite_requested_refs?: string | null;
  /**
   * v0.2 multi-implementation edits. Omit (or send empty) on a legacy
   * single-narrative save. When non-empty, the server validates each
   * impl independently, then derives the parent ``status`` +
   * ``narrative_q`` server-side from the rolled-up impl set.
   */
  implementations?: ImplementationEdit[];
}

/**
 * Response from POST /api/controls/assessments.
 *
 * ``auto_applied`` is a client-side annotation populated by
 * ``useUpsertAssessment`` after it chains the apply-batch call so the saved
 * row lands in the Excel working copy without a second click. Not on the
 * wire — the backend only returns id/status/validation. ``null`` means the
 * auto-apply step errored or wasn't run; ``applied: 0`` means the row was
 * silently skipped server-side (still needs_review, already_written, no
 * excel_row mapping).
 */
export interface UpsertAssessmentResult {
  id: number;
  status: ComplianceStatus;
  validation: {
    ok: boolean;
    classified_as: NarrativeClass;
    forced: boolean;
    notes: string[];
  };
  auto_applied?: {
    applied: number;
    skipped_needs_review: number;
    skipped_already_written: number;
  } | null;
}

export interface Evidence {
  id: number;
  /** Canonical URI — file:///, zip:///, s3://, azblob://, sharepoint://. */
  path: string;
  /** Human-readable rendering of `path` (scheme stripped, percent-decoded). */
  display_path: string;
  /** Leaf filename, derived from `path`. */
  filename: string;
  /** URI of the holding archive/folder/bucket. Null for top-level files. */
  archive_uri: string | null;
  title: string | null;
  doc_number: string | null;
  kind: EvidenceKind;
  sha256: string;
  size_bytes: number;
  ingested_at: string | null;
  extracted_text_path: string | null;
  /**
   * User-flipped flag marking this artifact as an authoritative component
   * list (HW/SW inventory, ACAS scan-target roster, network-diagram extract).
   * Drives the hostname-set cross-check that's injected into CM-8 / CA-3 /
   * PM-5 prompts.
   */
  is_asset_list: boolean;
  /**
   * Human label distinguishing overlapping asset lists in the diff
   * ("Approved HW/SW" vs "ACAS scan targets"). Null when no label is set —
   * the UI falls back to title/filename.
   */
  asset_list_label: string | null;
  /**
   * User-flipped flag marking this artifact as a boundary-defining document
   * (SSP, SSPP, ATO letter, network diagram). Drives the
   * BoundaryDocsContextSource adapter — the Sweep Context page
   * concatenates the extracted text of every flagged doc and feeds it to
   * the same token extractor that used to chew the four prose fields.
   */
  is_boundary_doc: boolean;
  /**
   * Free-text kind label ("SSP", "SSPP", "ATO Letter", "Network Diagram",
   * "Other"). Open-ended on purpose — site-specific doc names exist and
   * an enum would just block the assessor.
   */
  boundary_doc_kind: string | null;
  /**
   * Workbook this evidence is scoped to. Set when the assessor uploads a
   * boundary doc through the Sweep Context page; null for evidence
   * ingested through the generic Evidence folder-sweep (those rows are
   * shared across all workbooks via the tag join).
   */
  workbook_id: number | null;
  /**
   * v0.3-ready connector telemetry. Mirrors URI scheme + connector name:
   * `local_file` / `sharepoint` / `s3` / `azblob` / `scan_import` /
   * `tenable` / `splunk` / `gitlab` / `manual`. Null on pre-migration rows
   * — UI renders "unknown" then.
   */
  source_kind: string | null;
}

/** Component / Asset / BoundarySegment — v0.3 scope entities. */
export type ComponentKind = "tier" | "service" | "segment" | "other";
export type AssetClass =
  | "server"
  | "workstation"
  | "network"
  | "appliance"
  | "cloud"
  | "other";
export type AssetSource = "scan" | "asset_list" | "manual";
export type ScopeLinkSource = "manual" | "auto" | "backfill";

export interface Component {
  id: number;
  workbook_id: number;
  name: string;
  kind: ComponentKind;
  parent_component_id: number | null;
  description: string | null;
  created_at: string | null;
}

export interface Asset {
  id: number;
  workbook_id: number;
  hostname: string;
  fqdn: string | null;
  ip_address: string | null;
  cpe: string | null;
  os_family: string | null;
  asset_class: AssetClass;
  source: AssetSource;
  created_at: string | null;
}

export interface BoundarySegment {
  id: number;
  workbook_id: number;
  name: string;
  kind: string | null;
  description: string | null;
  created_at: string | null;
}

/** Per-Evidence component link row — GET /api/evidence/{id}/components. */
export interface EvidenceComponentLink {
  component_id: number;
  name: string;
  kind: ComponentKind;
  confidence: number | null;
  source: ScopeLinkSource;
}

export interface EvidenceAssetLink {
  asset_id: number;
  hostname: string;
  fqdn: string | null;
  ip_address: string | null;
  asset_class: AssetClass;
  asset_source: AssetSource;
  confidence: number | null;
  link_source: ScopeLinkSource;
}

export interface EvidenceBoundaryLink {
  boundary_segment_id: number;
  name: string;
  kind: string | null;
  confidence: number | null;
  source: ScopeLinkSource;
}

/** One source artifact in the coverage report — GET /api/evidence/crosscheck. */
export interface CoverageSource {
  evidence_id: number;
  label: string;
  /** Backend EvidenceKind value (NESSUS, STIG_CKL, STIG_CKLB, STIG_XCCDF, XLSX, CSV…). */
  kind: string;
  /** "scanned" | "checklisted" | "declared". */
  category: "scanned" | "checklisted" | "declared";
  host_count: number;
}

/** One source reference attached to a host's per-source attribution. */
export interface CoverageSourceRef {
  evidence_id: number;
  label: string;
  kind: string;
}

/**
 * Coverage tag describing a host's source mix.
 * Mirrors HostRecord.coverage in evidence/asset_crosscheck.py.
 */
export type HostCoverage =
  | "complete"
  | "observed_not_declared"
  | "scanned_not_checklisted"
  | "scanned_only"
  | "checklisted_not_scanned"
  | "checklisted_only"
  | "declared_not_observed"
  | "unknown";

/** Per-host roll-up across scans / checklists / declared inventory. */
export interface CoverageHost {
  hostname: string;
  coverage: HostCoverage;
  scanned_in: CoverageSourceRef[];
  checklisted_in: CoverageSourceRef[];
  declared_in: CoverageSourceRef[];
  /** STIG titles applied to this host (Evidence.title of each CKL), deduped + sorted. */
  stigs_applied: string[];
}

/**
 * Auto-derived asset-coverage report — GET /api/evidence/crosscheck.
 *
 * Asset universe is computed from every ACAS scan + STIG checklist +
 * assessor-declared inventory. The manual is_asset_list flag is now
 * just an override for "this spreadsheet IS the authoritative inventory."
 */
export interface CrossCheckResult {
  sources: CoverageSource[];
  hosts: CoverageHost[];
  /**
   * Hostnames bucketed by gap class — keys mirror HostCoverage so the UI
   * can render one tab per class. Plus the synthetic
   * "checklisted_but_stig_unknown" key for hosts whose checklist had no
   * extractable STIG title.
   */
  gaps: Partial<Record<HostCoverage | "checklisted_but_stig_unknown", string[]>>;
  totals: {
    scanned: number;
    checklisted: number;
    declared: number;
    /** Cardinality of scanned ∪ checklisted ∪ declared. */
    union: number;
  };
}

export interface EvidenceTag {
  objective_id: number;
  relevance: number;
  confidence: number;
  source: string;
  rationale: string;
}

export interface EvidenceForObjective {
  evidence_id: number;
  filename: string;
  display_path: string;
  title: string | null;
  kind: EvidenceKind;
  relevance: number;
  confidence: number;
  source: string;
  rationale: string;
}

// ---------------------------------------------------------------------------
// Ingest source discriminated union
// ---------------------------------------------------------------------------
//
// Mirrors backend/cybersecurity_assessor/routes/evidence.py. The orchestrator walks
// whichever source is selected via the shared Source protocol; only `folder`
// is wired up in v0.1, cloud + SharePoint surface as NotImplementedError in
// the ingest summary.

export interface FolderSourceSpec {
  type: "folder";
  /** Local FS path. UNC paths and NFS mounts work transparently. */
  path: string;
  recursive?: boolean;
}

export interface S3SourceSpec {
  type: "s3";
  bucket: string;
  prefix?: string;
}

export interface AzureBlobSourceSpec {
  type: "azblob";
  account: string;
  container: string;
  prefix?: string;
}

export interface SharePointSourceSpec {
  type: "sharepoint";
  site_url: string;
  library?: string;
  folder_path?: string;
  /**
   * Cherry-pick mode: when set, the backend skips the folder walk and
   * fetches exactly these scan-root-relative paths. Used by the Browse
   * dialog's filename-search to ingest only the assessor-selected hits.
   */
  file_paths?: string[];
}

/**
 * Tenable scan-ingest source spec (v0.4). One of two flavors:
 * - `sc` — on-prem Tenable.sc / SecurityCenter; `host` is the SC FQDN.
 * - `io` — Tenable.io SaaS; `host` is implicit (cloud.tenable.com) and
 *   ignored if supplied.
 *
 * Secrets (access_key / secret_key) are NOT sent in this spec — the
 * backend reads them from the OS keyring slots populated via
 * `/api/settings/tenable-access-key` and the matching secret endpoint.
 */
export interface TenableSourceSpec {
  type: "tenable";
  flavor: "sc" | "io";
  host?: string;
  /** Lower bound on severity (0=info, 4=critical). Backend clamps. */
  min_severity?: number;
}

export interface GitlabSourceSpec {
  type: "gitlab";
  /** GitLab server base URL, e.g. https://gitlab.sda-oi.example. */
  server_url: string;
  /** Project paths to walk, e.g. ["sda-oi/example/mdp/tracking-handler"]. */
  project_paths: string[];
  /** Git ref to pin URIs to. "HEAD" resolves to each project's default branch. */
  ref?: string;
  /** Optional fnmatch globs to filter ingestible files; empty ⇒ source defaults. */
  include_globs?: string[];
}

export type IngestSourceSpec =
  | FolderSourceSpec
  | S3SourceSpec
  | AzureBlobSourceSpec
  | SharePointSourceSpec
  | TenableSourceSpec
  | GitlabSourceSpec;

export interface IngestSummary {
  /** Canonical URI of the source that was walked. */
  source_uri: string;
  /** Legacy alias for source_uri — kept so older callers keep rendering. */
  folder: string;
  scanned: number;
  ingested: number;
  skipped_existing: number;
  skipped_unsupported: number;
  tags_created: number;
  findings_created: number;
  /**
   * Artifacts that ingested OK but mapped to ZERO controls (no tag from any
   * tier). Surfaced so evidence never silently vanishes from control pages —
   * the user can tag these manually or add a control reference.
   */
  untagged?: { path: string; reason: string }[];
  errors: { path: string; error: string }[];
}

/** Returned by POST /api/evidence/ingest — the run is fire-and-poll. */
export interface IngestJobStart {
  job_id: string;
}

/** Returned by GET /api/evidence/ingest/jobs/{id} and /active. */
export interface IngestJob {
  job_id: string;
  source_uri: string;
  status: "running" | "done" | "error";
  started_at: string;
  finished_at: string | null;
  /**
   * Best-effort file count known up front (local folders pre-count cheaply).
   * `null` for streaming sources that can't pre-count without a second walk
   * — the UI falls back to an indeterminate bar / "estimating…" when null.
   */
  estimated_total: number | null;
  scanned: number;
  ingested: number;
  skipped_existing: number;
  skipped_unsupported: number;
  tags_created: number;
  findings_created: number;
  error_count: number;
  /** Final summary; null while running. */
  summary: IngestSummary | null;
  /** Fatal thread-level error; per-file errors live in summary.errors. */
  error: string | null;
}

export interface AssessmentDecision {
  accepted: boolean;
  status: ComplianceStatus | null;
  narrative: string | null;
  /**
   * Presentation-only labeled multi-scope block, e.g.
   * `AWS GovCloud:\n\n<text>\n\nOn-Premises:\n\n<text>`. Built by the
   * backend's `stitch_scope_narrative` from `narratives_by_scope` and is
   * `null` whenever fewer than two scopes have text (single-boundary
   * controls — nothing to stitch). This is the SAME text that gets written
   * to column Q on save; it does NOT affect classification/validation,
   * which run on the single `narrative` above. Render this when present,
   * else fall back to `narrative`.
   */
  narrative_stitched: string | null;
  narrative_class: NarrativeClass;
  /**
   * `rule_8c` is the verified-SDA-mapping short-circuit (assessor.py
   * Rule 8c) — same shape as 8a/8b but populated from
   * `lookup_verified_sda_mapping`. Deterministic and LLM-free.
   */
  source:
    | "rule_8a"
    | "rule_8b"
    | "rule_8c"
    | "llm"
    | "llm_after_retry"
    | "unresolved";
  rule: string | null;
  retries: number;
  excel_row: number;
  rejections: { reason: string; context: string; original_output: string }[];
  supersession_hits: { stale: string; current: string; source: string }[];
  notes: string[];
  decided_at: string;
  /**
   * v0.2 precision-over-recall fields — mirror Assessment. When `accepted`
   * is true and `needs_review` is also true, the row WAS persisted (as
   * an abstain) but downstream exports skip it. See Assessment for full
   * field semantics.
   */
  needs_review: boolean;
  review_reason: string | null;
  confidence: number | null;
  /**
   * v0.2 citation-hygiene — mirror Assessment. Trusted verdict with an
   * attached cite-refresh flag; downstream exports include the row with
   * a "Cite refresh requested" footer. See Assessment for full semantics.
   */
  rewrite_requested: boolean;
  rewrite_requested_refs: string | null;
  /**
   * True when the sidecar had to auto-insert a missing CCI row into the
   * workbook before assessing (catalog knows the CCI; eMASS workbook
   * variant omitted it). The UI surfaces this as a toast so the assessor
   * knows the workbook was modified beyond just the assessment cells.
   */
  workbook_row_inserted?: boolean;
  /**
   * Operational telemetry — the AssessmentRun row this single-CCI call
   * landed on, the dollar cost of the LLM call(s) it made, and the raw
   * token totals. Surfaced in the decision trace so the assessor can see
   * per-CCI spend without having to cross-reference the Runs tab.
   *
   * Optional because rules 8a/8b/8c short-circuit before the LLM is hit —
   * those cost $0 with zero tokens. The route still ships the fields
   * (cost=0, tokens all 0) but the type stays optional so older clients
   * tolerate either shape.
   */
  run_id?: number;
  cost_usd?: number;
  tokens?: { input: number; output: number; cache_read: number };
  /**
   * v0.2 — id of the Assessment row that ``/api/controls/assess`` upserted
   * when ``persist=true`` (the default). The row is written with
   * ``needs_review=true`` and ``review_reason="pending-human-review"`` so
   * the proposal survives the user navigating away from the detail page —
   * the Save action on ControlDetail is what clears the flag. ``null`` when
   * the route was called with ``persist=false`` or the decision wasn't
   * accepted (no narrative to persist).
   */
  assessment_id?: number | null;
}

// ---------------------------------------------------------------------------
// Audit v1 — verdict→evidence traceability (GET /api/controls/assessments/{id}/audit)
// ---------------------------------------------------------------------------

/** One trace row — single-pass has one, dual-pass has two (pass_index 0 + 1). */
export interface AssessmentAuditTrace {
  id: number;
  pass_index: number;
  system_prompt_sha: string;
  user_message: string;
  model: string;
  /** Actual served model version from the API response (may differ from
   *  requested model when an alias resolves to a dated snapshot). */
  anthropic_model_version: string | null;
  temperature: number | null;
  max_tokens: number | null;
  request_id: string | null;
  /** Full raw response payload as JSON-encoded string — pre-parse blob the
   *  auditor can diff against a replay. */
  raw_response_json: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
  cache_read_tokens: number | null;
  created_at: string;
}

/** One system-prompt snapshot — deduped by sha across the trace rows. */
export interface AssessmentAuditPromptSnapshot {
  sha256: string;
  text: string;
  prompt_kind: string;
}

/** One evidence chunk the model literally saw (head+tail-truncated). */
export interface AssessmentAuditEvidenceShown {
  id: number;
  evidence_id: number;
  /** Evidence.title at audit-read time — null when the Evidence row was
   *  hard-deleted after the assessment ran. The chunk_text snapshot still
   *  proves what the model saw; the title is just a display nicety. */
  evidence_title: string | null;
  /** Evidence.path (canonical URI: file://, zip://, sharepoint://, etc.)
   *  at audit-read time. Same null caveat as evidence_title. */
  evidence_path: string | null;
  /** sha256 of `chunk_text` — proves the model saw THIS text, not just
   *  "this file contained the text somewhere". */
  chunk_sha: string;
  chunk_text: string;
  order_index: number;
  relevance: number | null;
  tag_source: string | null;
}

/** One per-claim citation (only populated when `audit_citations_enabled`
 *  was on at decision time). Offsets are best-effort `.find()` results;
 *  null when the claim/quote couldn't be located in the field/chunk. */
export interface AssessmentAuditCitation {
  id: number;
  /** Which narrative field the claim came from — `narrative_class` carries
   *  null offsets because it's the verdict-kind enum, not free text. */
  narrative_field: string;
  claim_text: string;
  claim_start_char: number | null;
  claim_end_char: number | null;
  /** FK → AssessmentAuditEvidenceShown.id. Use to look up which chunk the
   *  source_quote came from for click-to-jump highlighting. */
  evidence_shown_id: number;
  source_quote: string;
  source_start_char: number | null;
  source_end_char: number | null;
  extraction_method: string;
}

/**
 * Full audit payload — returned by GET /api/controls/assessments/{id}/audit.
 *
 * Short-circuit verdicts (rule_8a/8b/8c, CRM, deterministic abstain)
 * legitimately return empty `trace` and `evidence_shown` — no LLM call
 * was made. UI should render a "no LLM trace — deterministic verdict"
 * banner in that case rather than treating it as an error.
 */
export interface AssessmentAudit {
  assessment_id: number;
  run_id: number | null;
  trace: AssessmentAuditTrace[];
  system_prompts: AssessmentAuditPromptSnapshot[];
  evidence_shown: AssessmentAuditEvidenceShown[];
  citations: AssessmentAuditCitation[];
}

/**
 * Request body for POST /api/controls/assess-batch.
 *
 * Defaults match the server: skip CCIs that already have an Assessment row,
 * persist accepted decisions for review-then-apply. Override `tester` to
 * stamp the run with a non-default name, or set `family` for partial reruns.
 */
export interface AssessBatchRequest {
  workbook_id: number;
  family?: string;
  /** Explicit Control PK list — when supplied, the server uses this as the
   * authoritative scope and skips its own `BaselineControl.in_scope` filter.
   * Send `rows.map(r => r.id)` from the Controls grid so the in-scope toggle,
   * overlay-covered toggle, family filter, and status filter all compose into
   * the batch. Omit to fall back to "every in-scope CCI in the baseline". */
  control_ids?: number[];
  limit?: number;
  skip_existing?: boolean;
  persist?: boolean;
  tester?: string;
}

/** One decision row in the AssessBatchResult. Trimmed vs AssessmentDecision —
 * the batch endpoint omits the raw original_output blobs to keep the payload
 * small on a 319-row workbook. */
export interface BatchDecision {
  objective_id: string;
  excel_row: number;
  accepted: boolean;
  status: ComplianceStatus | null;
  narrative: string | null;
  /** Presentation-only stitched multi-scope block; see AssessmentDecision. */
  narrative_stitched: string | null;
  narrative_class: NarrativeClass;
  source: AssessmentDecision["source"];
  rule: string | null;
  retries: number;
  rejections: { reason: string; context: string }[];
  supersession_hits: { stale: string; current: string }[];
  /** v0.2 precision-over-recall — see AssessmentDecision for semantics. */
  needs_review: boolean;
  review_reason: string | null;
  confidence: number | null;
  /** v0.2 citation-hygiene — see AssessmentDecision for semantics. */
  rewrite_requested: boolean;
  rewrite_requested_refs: string | null;
  /** Set by the batch endpoint when a worker raised — populated alongside
   * accepted=false, status=null, narrative=null. The CCI has no Assessment
   * row and won't appear in /review-queue; surface it directly in the
   * post-batch modal so the user can re-run it. */
  error?: string | null;
}

export interface AssessBatchResult {
  run_id: number;
  workbook_id: number;
  baseline_id: number;
  assessed: number;
  accepted: number;
  unresolved: number;
  persisted: number;
  skipped: { objective_id: string; reason: string }[];
  cost_usd: number;
  tokens: { input: number; output: number; cache_read: number };
  decisions: BatchDecision[];
  /**
   * Client-side annotation populated by ``useAssessBatch`` after the auto-
   * apply chain runs. Not on the wire — the backend doesn't know that the
   * UI chases assess-batch with apply-batch. Lets the toast distinguish
   * "nothing to do" from "nothing newly assessed but old decisions written
   * to column N". ``null`` means the auto-apply step errored or wasn't run.
   */
  auto_applied?: {
    applied: number;
    skipped_needs_review: number;
    skipped_already_written: number;
  } | null;
}

/**
 * Snapshot of an in-flight ``/assess-batch`` run for one workbook.
 *
 * Polled by the UI on a short interval while the assess mutation is
 * pending so the Controls grid can show a determinate progress bar with
 * per-CCI granularity rather than an indeterminate "Assessing…" spinner.
 *
 * ``active: false`` is returned when no batch is registered (either the
 * batch hasn't started yet, has already finished, or this workbook
 * never started one) so the polling hook can collapse the bar without
 * special-casing 404s. All other fields are present iff ``active`` is
 * true; the union below makes that contract explicit at the type layer.
 */
export type AssessBatchProgress =
  | { active: false }
  | {
      active: true;
      workbook_id: number;
      /** Total CCIs the worker pool will attempt. Fixed at the start of
       * Phase 2 — does NOT include CCIs that failed Phase 1 evidence
       * build (those are surfaced separately in the final result). */
      total: number;
      /** CCIs the worker has handed off — accepted, unresolved, or
       * raised. Bumps once per CCI regardless of outcome so the bar
       * reaches 100% even when individual CCIs error out. */
      completed: number;
      /** Subset of ``completed`` where the worker caught an exception.
       * Surfaced so the UI can switch the bar to an amber tint when
       * failures accumulate before the final response lands. */
      errored: number;
      /** ``time.time()`` epoch from the backend — used to render elapsed
       * time and estimate ETA from the current rate. */
      started_at: number;
      /** Most recent CCI id a worker reported, or null if no worker has
       * finished yet. Lets the UI show "currently assessing CCI-001234"
       * so the user knows something is actively happening even when the
       * count moves slowly mid-LLM-call. */
      last_objective: string | null;
    };

/**
 * Telemetry row from POST-assessment runs — GET /api/runs.
 *
 * Accuracy fields (`ccis_accepted`, `retry_count`, `validator_rejections`,
 * `supersession_hits`, `crm_short_circuit_count`) back the patent claim
 * and deserve prominent display. Token / cost fields are operational
 * telemetry only.
 */
export interface Run {
  id: number;
  workbook_id: number | null;
  command: string;
  started_at: string | null;
  finished_at: string | null;
  // Derived on the server: "in_progress" while finished_at is null,
  // "complete" once finish() has flushed. Lets the UI render a spinner
  // for live runs instead of conflating them with truly stopped runs.
  status: "in_progress" | "complete";
  // Operational
  llm_calls: number;
  llm_input_tokens: number;
  llm_output_tokens: number;
  llm_cache_read_tokens: number;
  cost_usd: number;
  // Accuracy (patent-supporting)
  ccis_accepted: number;
  retry_count: number;
  validator_rejections: number;
  supersession_hits: number;
  // v0.2 — CRM short-circuit aggregate. Per-run count of CCIs whose
  // parent control was declared provider/inherited/not_applicable by
  // the attached CRM (the kernel skipped the LLM entirely). Third
  // member of the kernel-skip cohort with rule_8a/8b. Per-event ledger
  // lives on CrmShortCircuitEvent + SAR Appendix G.
  crm_short_circuit_count: number;
  notes: string | null;
}

// ---------------------------------------------------------------------------
// Metrics — cross-run rollups (Accuracy / Cost / Time) + reference benchmarks.
// Backed by /api/metrics (in-app) and /api/metrics/public (Nuon-safe).
// Mirrors the JSON shape produced by backend/cybersecurity_assessor/routes/metrics.py.
// ---------------------------------------------------------------------------

export interface MetricsReferenceSource {
  citation: string;
  url: string;
  as_of: string;
}

export interface MetricsReferenceEntry {
  key: string;
  family: "accuracy" | "cost" | "time";
  label: string;
  // null when the user has not yet sourced a real value — UI renders "Awaiting source".
  value: number | null;
  unit: string;
  source: MetricsReferenceSource;
  sublabel?: string | null;
}

export interface MetricsReference {
  accuracy: MetricsReferenceEntry[];
  cost: MetricsReferenceEntry[];
  time: MetricsReferenceEntry[];
}

export interface MetricsActivityCounters {
  /** Rule-#11 complaint EVENTS (a single retry can log several) — NOT failed
   * controls. Most recover on retry. Renamed from validator_rejections. */
  validator_complaints: number;
  /** LLM re-ask rounds (one per bounced attempt). */
  retries: number;
  dual_pass_disagreements: number;
  supersession_hits: number;
  llm_calls: number;
}

export interface MetricsActivity {
  /** The most recent assessment run only. */
  latest: MetricsActivityCounters;
  /** Summed across every run ever (adds `runs`). */
  cumulative: MetricsActivityCounters & { runs: number };
}

export interface MetricsAccuracyLive {
  ccis_accepted: number;
  /** Deprecated alias of activity.cumulative.validator_complaints — kept for
   * back-compat. These are complaint events, not failed controls. */
  validator_rejections: number;
  abstained: number;
  /** Authoritative "decided" denominator = accepted + abstained. Render this
   * directly; do NOT recompute it by adding validator_rejections (those are
   * retry events, not terminal per-CCI outcomes — the "13 of 17" bug). */
  decided: number;
  retries: number;
  dual_pass_disagreements: number;
  accuracy_pct: number | null;
  dual_pass_agreement_pct: number | null;
  rejection_rate_pct: number | null;
  abstention_rate_pct: number | null;
  /** Run-history activity split into latest-run vs cumulative. Current
   * verdict counts (accepted/abstained/decided) live above; this block is
   * "what the assessor did", not "where the workbook stands". */
  activity: MetricsActivity;
}

export interface MetricsCostLive {
  total_usd: number;
  median_per_run_usd: number | null;
  median_per_cci_usd: number | null;
  total_input_tokens: number;
  total_output_tokens: number;
  total_cache_read_tokens: number;
  llm_calls: number;
}

export interface MetricsTimeLive {
  total_seconds: number;
  median_per_run_seconds: number | null;
  median_per_cci_seconds: number | null;
  ccis_per_hour: number | null;
}

export interface MetricsLive {
  n_runs: number;
  accuracy: MetricsAccuracyLive;
  cost: MetricsCostLive;
  time: MetricsTimeLive;
}

/**
 * One auto-detected document supersession for a workbook. Derived from the
 * evidence chain (an older artifact superseded by a newer one at ingest),
 * NOT a hand-edited registry. Served per-workbook by
 * `GET /api/supersession/chains`.
 */
export interface SupersessionChain {
  legacy: string;
  current: string;
  /** "doc_number" | "title" — which field matched. */
  kind: string;
  stale_evidence_id: number;
  current_evidence_id: number;
}

export interface MetricsMechanisms {
  supersession: {
    /** Cumulative rewrite count across all runs (per-workbook entries are
     *  fetched separately via listSupersessionChains). */
    total_hits: number;
  };
  validator: {
    total_rejections: number;
    rejection_rate_pct: number | null;
  };
  crm_overlay: {
    /** False when no Baseline has any CRM data — render a stable placeholder. */
    available: boolean;
    in_scope_total: number;
    tagged_total: number;
    /** tagged / in_scope as a percent — null if denominator is 0. */
    coverage_pct: number | null;
    responsibility_breakdown: {
      customer: number;
      provider: number;
      hybrid: number;
      inherited: number;
      not_applicable: number;
      untagged: number;
    };
    /** All-time CrmShortCircuitEvent rows (provider + inherited + not_applicable). */
    total_short_circuits: number;
    short_circuits_by_responsibility: {
      provider: number;
      inherited: number;
      not_applicable: number;
    };
  };
}

export interface ModelRate {
  model: string;
  input_per_mtok: number;
  output_per_mtok: number;
  cache_read_per_mtok: number;
  cache_write_per_mtok: number;
}

export interface MetricsRateCard {
  rates_revised: string;
  models: ModelRate[];
}

/**
 * ROI headline — manual A&A baseline × accepted CCIs minus live spend/time.
 * Each field is null when the underlying reference value (in references.json)
 * isn't sourced yet. Conservative: only `ccis_accepted` counts as credit
 * earned — abstentions and validator rejects bounced back to a human and
 * don't get to claim savings.
 */
export interface MetricsSavings {
  ccis_credited: number;
  reference_cost_per_cci_usd: number | null;
  reference_time_per_cci_minutes: number | null;
  manual_baseline_cost_usd: number | null;
  manual_baseline_minutes: number | null;
  live_cost_usd: number;
  live_minutes: number;
  dollars_saved_usd: number | null;
  minutes_saved: number | null;
  /** Convenience flag — true if at least one reference value is filled. */
  reference_filled: boolean;
}

export interface MetricsPayload {
  live: MetricsLive;
  mechanisms: MetricsMechanisms;
  reference: MetricsReference;
  savings: MetricsSavings;
  rate_card: MetricsRateCard;
  references_revised: string;
}

/** Active LLM provider — drives /assess + /assess-batch dispatch server-side. */
export type LlmProvider = "anthropic" | "openai";

export interface AppSettings {
  default_tester: string;
  /** Which provider the orchestrator actually dispatches to. */
  llm_provider: LlmProvider;
  // Anthropic
  anthropic_model: string;
  anthropic_key_set: boolean;
  /** null ⇒ talking to the real Anthropic API (default). Set to a corporate / high-side gateway URL otherwise. */
  anthropic_base_url: string | null;
  anthropic_default_base_url: string;
  /** True when ANTHROPIC_API_KEY is exported in the sidecar's process env. */
  anthropic_api_key_env_set: boolean;
  /** True when ANTHROPIC_AUTH_TOKEN is exported in the sidecar's process env. */
  anthropic_auth_token_env_set: boolean;
  /** True when a corporate Anthropic gateway token is stored in the OS keyring. */
  anthropic_gateway_token_set: boolean;
  // OpenAI
  openai_model: string;
  openai_key_set: boolean;
  /** null ⇒ talking to the real OpenAI API (default). Set to a corporate proxy URL otherwise. */
  openai_base_url: string | null;
  openai_default_base_url: string;
  /** True when OPENAI_API_KEY is exported in the sidecar's process env. */
  openai_api_key_env_set: boolean;
  /** True when OPENAI_AUTH_TOKEN is exported in the sidecar's process env. */
  openai_auth_token_env_set: boolean;
  /** True when a corporate OpenAI gateway token is stored in the OS keyring. */
  openai_gateway_token_set: boolean;
  // eMASS (v0.2+ stub — fields persist but no connector ships in v0.1)
  emass_base_url: string | null;
  emass_cert_path: string | null;
  emass_api_key_set: boolean;
  /** eMASS REST connector — DOUBLE-GATED. ``upcoming_gated`` is the
   *  per-tenant authorization gate (ISSM sign-off); ``features.emass`` is
   *  the main pill that controls card body visibility. The connector
   *  refuses to load unless BOTH are True. */
  emass: {
    base_url: string | null;
    system_id: string | null;
    cert_path: string | null;
    key_path: string | null;
    api_key_set: boolean;
    upcoming_gated: boolean;
    connectors_v04: boolean;
  };
  // SharePoint connector — Microsoft Graph + Graph PowerShell client_id.
  // Plug-and-play across Commercial / GovCloud / DoD. Paste a site URL, sign
  // in with device code, done. `cloud_name` is auto-detected from the URL
  // hostname so the UI can show a "Detected cloud: GovCloud" badge.
  sharepoint: {
    site_url: string | null;
    library: string | null;
    folder_path: string | null;
    cloud_name: string | null;
  };
  /** Tenable connector (v0.4). Two flavors share one card; raw keys never
   *  leave the OS keyring — only the *_set booleans surface here. */
  tenable: {
    flavor: "sc" | "io" | null;
    host: string | null;
    access_key_set: boolean;
    secret_key_set: boolean;
  };
  /** ServiceNow GRC connector — secrets (OAuth client_secret, Basic password)
   *  live in the OS keyring; only `*_set` booleans surface so the card can
   *  render a "secret stored" badge without ever shipping the value. */
  servicenow_grc: {
    instance_url: string | null;
    auth_method: string | null;
    username: string | null;
    allowed_tables: string[];
    oauth_secret_set: boolean;
    basic_password_set: boolean;
  };
  /** Archer (RSA Archer / GRC) connector — populated from Settings → Archer
   *  card. `password_set` reflects whether the OS keyring has a slot for
   *  (instance_name, username); the password itself never travels through
   *  this GET response. `domain` is the optional Active-Directory domain
   *  string sent on session login (most deployments leave it empty). */
  archer: {
    instance_url: string | null;
    instance_name: string | null;
    username: string | null;
    domain: string | null;
    password_set: boolean;
  };
  /** Splunk connector — REST host + saved-search allow-list. Token presence
   *  is reported separately as `token_set`; the token itself never round-trips
   *  through this surface (lives in the OS keyring). */
  splunk: {
    host: string | null;
    port: number;
    scheme: string;
    app: string;
    owner: string;
    verify_tls: boolean;
    saved_searches: string[];
    token_set: boolean;
  };
  /** SharePoint Boundary Sweep — v0.4 connector that reuses the SharePoint
   *  connector's site URL + Graph auth. The two cap knobs override the
   *  conservative defaults in `BoundarySweepCaps` for power users who want
   *  a deeper walk; null ⇒ use the dataclass default. */
  boundary_sweep: {
    folder_path: string | null;
    max_folder_depth: number | null;
    max_stale_items: number | null;
  };
  // GitLab connector — per-host PAT in OS keyring (never returned over
  // HTTP). `token_set` is the only signal the UI gets that a credential
  // exists for the configured host.
  gitlab: {
    server_url: string | null;
    project_paths: string[];
    ref: string;
    include_globs: string[];
    token_set: boolean;
  };
  /** Confluence DC connector — DOUBLE-GATED. ``upcoming_gated`` is the
   *  per-instance authorization gate (ISSM sign-off); ``features.confluence``
   *  is the main pill that controls card body visibility. The connector
   *  refuses to iterate unless BOTH are True. */
  confluence: {
    base_url: string | null;
    username: string | null;
    space_keys: string | null;
    max_pages: number;
  };
  // Jira connector — double-gated v0.4+. ``allowed_jql_queries`` is the
  // named list of {name, jql} pairs the connector is allowed to run; the
  // route layer extracts ``jql`` values when constructing JiraConfig so
  // the UI never has a free-form-JQL surface. PAT lives in the OS
  // keyring; only the ``pat_set`` boolean is exposed here.
  jira: {
    server_url: string | null;
    allowed_jql_queries: JiraAllowedQuery[];
    max_results_per_query: number | null;
    verify_ssl: boolean;
    pat_set: boolean;
  };
  features: {
    sharepoint: boolean;
    tenable: boolean;
    /** ServiceNow GRC v0.4 connector — backend flag is `enable_snow_grc`
     *  (kept for the connector module's feature_enabled() check); UI sees
     *  it under the slug `servicenow_grc`. */
    servicenow_grc: boolean;
    archer: boolean;
    splunk: boolean;
    /** v0.4 boundary-discovery sweep — depends on the SharePoint connector
     *  being configured first since it reuses the same Graph auth + site
     *  routing. When false, the route layer's /status still responds but
     *  /test refuses. */
    boundary_sweep: boolean;
    gitlab: boolean;
    /** Confluence main-pill flag. The connector ALSO requires
     *  ``confluence_upcoming_gated`` before it will actually iterate. */
    confluence: boolean;
    /** Confluence per-instance authorization gate (ISSM sign-off). */
    confluence_upcoming_gated: boolean;
    /** Jira main pill — flipped from the Settings card. Double-gated: ALSO
     *  requires `features.jira_upcoming_gated` true before any /test or
     *  ingest path will touch a real Jira instance. */
    jira: boolean;
    /** Jira upcoming-gated ack — second flag, surfaced INSIDE the card
     *  body (not the main pill). Required acknowledgement that the
     *  program has authorized Jira Data Center API access. */
    jira_upcoming_gated: boolean;
    /** eMASS main-pill flag. The connector ALSO requires
     *  ``emass_upcoming_gated`` before it will actually load. */
    emass: boolean;
    /** eMASS per-tenant authorization gate (ISSM sign-off). */
    emass_upcoming_gated: boolean;
    /** Version-cohort gate that will flip default-on when v0.4 ships. */
    connectors_v04: boolean;
    /** Audit v1 — when true, the LLM is asked to co-emit a structured
     *  citations array linking each substantive claim in its narrative to
     *  a specific evidence chunk. Trace + evidence-shown capture is
     *  unconditional; only the citation parse/persist is gated by this
     *  flag. Default OFF until the eval harness can measure verdict
     *  regression from the longer prompt. */
    audit_citations: boolean;
  };
}

/** One entry in the Jira allowed-queries list — name + JQL pair. The name
 *  is human-facing (shown in the Sweep UI / Settings card list); the JQL
 *  is what actually goes to the wire. Empty entries are dropped server-
 *  side on save. */
export interface JiraAllowedQuery {
  name: string;
  jql: string;
}

export interface SettingsUpdate {
  default_tester?: string;
  /** Switch the active provider — must be one of "anthropic" | "openai". */
  llm_provider?: LlmProvider;
  anthropic_model?: string;
  /** Pass "" (empty string) to clear the override and revert to the real Anthropic API. */
  anthropic_base_url?: string;
  openai_model?: string;
  /** Pass "" (empty string) to clear the override and revert to api.openai.com/v1. */
  openai_base_url?: string;
  /** eMASS v0.2+ surface — pass "" to clear. */
  emass_base_url?: string;
  emass_cert_path?: string;
  /** Additional eMASS connection fields. Pass "" to clear. */
  emass_key_path?: string;
  emass_system_id?: string;
  /** eMASS feature flags. Connector is DOUBLE-GATED — both must be true. */
  enable_emass?: boolean;
  emass_upcoming_gated_enabled?: boolean;
  connectors_v04_enabled?: boolean;
  /** SharePoint connector — empty string clears the field. Tenant/client/
   *  authority intentionally absent: the Graph PowerShell client_id is
   *  hardcoded server-side and the cloud is auto-detected from the site
   *  URL hostname. */
  sharepoint_site_url?: string;
  sharepoint_library?: string;
  sharepoint_folder_path?: string;
  enable_sharepoint?: boolean;
  /** ServiceNow GRC connector — empty string clears string fields. Pass
   *  an empty list for `servicenow_grc_allowed_tables` to revert to the
   *  connector defaults (DEFAULT_TABLES). Secret fields are POSTed via
   *  the dedicated /api/servicenow_grc/oauth-secret and /basic-password
   *  endpoints — never via this PUT. */
  servicenow_grc_instance_url?: string;
  servicenow_grc_auth_method?: string;
  servicenow_grc_username?: string;
  servicenow_grc_allowed_tables?: string[];
  enable_servicenow_grc?: boolean;
  /** Archer connector — empty string clears the field. The password lives
   *  in the OS keyring and is written/cleared via the dedicated
   *  /api/archer/password endpoints, NOT through this settings model, to
   *  keep credentials out of GET responses and config.toml dumps. */
  archer_instance_url?: string;
  archer_instance_name?: string;
  archer_username?: string;
  archer_domain?: string;
  enable_archer?: boolean;
  /** Splunk connector — empty string clears string fields; pass `splunk_port=0`
   *  to reset to the documented default (8089). `splunk_saved_searches=[]`
   *  clears the allow-list; omit the key entirely to leave it unchanged.
   *  Token is set/cleared via dedicated /api/splunk/token routes. */
  splunk_host?: string;
  splunk_port?: number;
  splunk_scheme?: string;
  splunk_app?: string;
  splunk_owner?: string;
  splunk_verify_tls?: boolean;
  splunk_saved_searches?: string[];
  enable_splunk?: boolean;
  /** SharePoint Boundary Sweep — empty string / 0 / negative clears the
   *  field and reverts to the dataclass default on the next read. */
  boundary_sweep_folder_path?: string;
  boundary_sweep_max_folder_depth?: number;
  boundary_sweep_max_stale_items?: number;
  enable_boundary_sweep?: boolean;
  /** GitLab connector — empty string clears scalar fields; URL-trailing-slash
   *  and project-leading/trailing-slash stripping happens server-side. The
   *  PAT itself is never sent over HTTP — it lives in the OS keyring under
   *  KEYRING_KEY_GITLAB_PREFIX + sanitized host. */
  gitlab_server_url?: string;
  gitlab_project_paths?: string[];
  gitlab_ref?: string;
  gitlab_include_globs?: string[];
  enable_gitlab?: boolean;
  /** Confluence DC connector — empty string clears the field. */
  confluence_base_url?: string;
  confluence_username?: string;
  /** Comma-separated list of Confluence space keys, e.g. "PROG,DEV". */
  confluence_space_keys?: string;
  /** Max pages per space to fetch in a single ingest run (>= 1). */
  confluence_max_pages?: number;
  /** Confluence feature flags. Connector is DOUBLE-GATED — both must be true. */
  enable_confluence?: boolean;
  confluence_upcoming_gated_enabled?: boolean;
  /** Jira connector — same empty-string-clears convention for the URL.
   *  ``jira_allowed_jql_queries`` is the named list of {name, jql} pairs
   *  the connector is allowed to run; pass an empty array to explicitly
   *  clear it (omit the field to leave the saved list intact).
   *  ``jira_max_results_per_query`` accepts 0/negative to mean "use the
   *  connector default" (None server-side). */
  jira_server_url?: string;
  jira_allowed_jql_queries?: JiraAllowedQuery[];
  jira_max_results_per_query?: number;
  jira_verify_ssl?: boolean;
  /** Jira main pill — ON only persists; the connector still won't run
   *  unless `jira_upcoming_gated` is also true. */
  enable_jira?: boolean;
  /** Jira upcoming-gated ack — required second flag. UI surfaces this
   *  inside the Settings card body, NOT as the main pill. */
  jira_upcoming_gated?: boolean;
  /** Tenable connector — empty string clears. Flavor must be "sc" | "io".
   *  Host is the SecurityCenter FQDN for `sc`; ignored for `io` (the SaaS
   *  host is always cloud.tenable.com). */
  tenable_flavor?: "sc" | "io" | "";
  tenable_host?: string;
  enable_tenable?: boolean;
  /** Audit v1 — citation co-emission flag. Asks the model to emit per-claim
   *  citations linking narrative to evidence. Increases response length.
   *  Enable for audit-prep runs; disable for production until verdict
   *  regression is measured. */
  audit_citations_enabled?: boolean;
  // Sweep-judge knobs (enabled / model / cost cap / workers) were removed
  // from the HTTP surface — the backend defaults are sized for a strong
  // first sweep, and the UI no longer renders a tuning card. Edit
  // ~/.cybersecurity-assessor/config.toml directly for the power-user case.
}

/** Live SharePoint connector status (cheap — no MSAL or network calls).
 *  `configured` is true once a site URL is saved — that's the whole config
 *  surface now that we use the Graph PowerShell client_id. */
export interface SharePointStatus {
  configured: boolean;
  site_url: string | null;
  library: string | null;
  folder_path: string | null;
  /** Auto-detected from site URL hostname: "Commercial" | "GovCloud" | "DoD".
   *  Null when no site URL is saved. */
  cloud_name: string | null;
  token_cache_exists: boolean;
  token_cache_path: string;
  enabled: boolean;
}

/**
 * Two-phase test response:
 * - `ok=true, pending=false` → silent acquisition succeeded; site/library probe results follow.
 * - `ok=false, pending=true` → MSAL is in device-code mode; surface `user_code` + `verification_uri`.
 * - HTTP error → `detail` carries the upstream message.
 */
export interface SharePointTestResponse {
  ok: boolean;
  pending: boolean;
  // Success path
  site_title?: string;
  site_url?: string;
  library?: string;
  scan_root?: string;
  scan_root_ok?: boolean;
  scan_root_name_or_error?: string;
  // Device-code path
  user_code?: string;
  verification_uri?: string;
  device_code?: string;
  expires_in?: number;
  interval?: number;
  message?: string;
  detail?: string;
}

export interface SharePointTestBody {
  site_url?: string;
  library?: string;
  folder_path?: string;
}

/** Live ServiceNow GRC connector status (cheap — no network calls).
 *  `configured` requires instance_url + username; `secret_set` reports
 *  whether a keyring slot is populated for the chosen `auth_method`. */
export interface ServicenowGrcStatus {
  configured: boolean;
  instance_url: string | null;
  auth_method: string;
  username: string | null;
  allowed_tables: string[];
  secret_set: boolean;
  enabled: boolean;
}

/** Override-on-test payload. Every field is optional; anything not supplied
 *  falls back to the persisted config server-side. */
export interface ServicenowGrcTestBody {
  instance_url?: string;
  auth_method?: string;
  username?: string;
  allowed_tables?: string[];
}

/** Result of a live SN probe. `detected` echoes the instance + table the
 *  probe hit, plus the row count SN reported so the user can sanity-check
 *  that the GRC tables are populated. */
export interface ServicenowGrcTestResponse {
  ok: boolean;
  message: string;
  detected: {
    instance_url: string | null;
    auth_mode: string | null;
    probe_table: string | null;
    probe_total_count: number | null;
  };
}

/** Body for POST /api/servicenow_grc/oauth-secret and /basic-password. */
export interface ServicenowGrcSecretBody {
  secret: string;
}

/** Live GitLab connector status. Cheap — reads config + the per-host keyring
 *  slot only (no network). `configured` is true when server URL, project list,
 *  and a token are all present; the Settings card uses this to gate the
 *  "Test connection" button. `token_set` reflects only presence, not validity
 *  (validation is `/test`'s job). */
export interface GitlabStatus {
  configured: boolean;
  server_url: string | null;
  project_paths: string[];
  ref: string;
  include_globs: string[];
  token_set: boolean;
  enabled: boolean;
}

/** Override-on-test payload — every field optional, falls back to saved
 *  config server-side. The PAT always comes from the keyring; never accepted
 *  over HTTP. */
export interface GitlabTestBody {
  server_url?: string;
  project_paths?: string[];
  ref?: string;
  include_globs?: string[];
}

/** Per-project resolution result returned by GitLabSource.test_connection.
 *  A typo in one project surfaces as `ok: false` for that row without
 *  poisoning the others. */
export interface GitlabProjectStatus {
  project_path: string;
  ok: boolean;
  commit_sha?: string;
  error?: string;
}

/** Response from /api/gitlab/test. `ok` reflects all-projects-resolved;
 *  `message` is a one-line summary for the toast; `detected` carries the
 *  server/host/user/projects fields the card renders inline. */
export interface GitlabTestResponse {
  ok: boolean;
  message: string;
  detected: {
    server_url?: string | null;
    host?: string | null;
    user?: string | null;
    projects: GitlabProjectStatus[];
  };
  // Pass-throughs from the underlying source dict (kept for backward
  // compatibility / direct rendering when desired).
  server_url?: string | null;
  host?: string | null;
  user?: string | null;
  projects?: GitlabProjectStatus[];
  error?: string;
}

/** Live Confluence DC connector status (cheap — no network). `configured` is
 *  true when base_url + space_keys are saved, a PAT is stored in the keyring,
 *  AND both gate flags are flipped on. `reachable` is always null from
 *  /status — it gets set by /test. */
export interface ConfluenceStatus {
  configured: boolean;
  enabled: boolean;
  base_url: string | null;
  username: string | null;
  space_keys: string | null;
  max_pages: number;
  pat_set: boolean;
  upcoming_gated: boolean;
  connectors_v04: boolean;
  gates_satisfied: boolean;
  reachable: boolean | null;
}

/** Optional per-field overrides for the /test probe. All fields fall back
 *  to the saved config when omitted, so passing `{}` validates whatever's
 *  saved today. */
export interface ConfluenceTestBody {
  base_url?: string;
  /** Comma-separated; the probe walks the first key in the list. */
  space_keys?: string;
}

/** Confluence probe result. `detected` carries the space metadata the probe
 *  resolved from the Confluence REST API (which space was hit, sample title
 *  of the first page, etc.). */
export interface ConfluenceTestResponse {
  ok: boolean;
  message: string;
  detected: {
    base_url?: string;
    space_probed?: string;
    page_count_sampled?: number;
    sample_title?: string | null;
  };
}

/** Live Jira connector status (cheap — config + keyring only, no /myself).
 *  `configured` is true once a server URL + PAT + at least one allowed
 *  JQL query are all in place. `gate_open` is true only when BOTH
 *  `enabled` (main pill) AND `upcoming_gated` (inner ack) are true —
 *  the UI uses that to decide which flag is the bottleneck for the
 *  status badge. */
export interface JiraStatus {
  configured: boolean;
  server_url: string | null;
  allowed_jql_queries: JiraAllowedQuery[];
  max_results_per_query: number | null;
  verify_ssl: boolean;
  pat_set: boolean;
  enabled: boolean;
  upcoming_gated: boolean;
  gate_open: boolean;
}

/** Override any subset of the saved config for a candidate probe. The
 *  Settings card calls /test with an empty body to probe stored values;
 *  callers can pass partial overrides to validate a typed-in URL / PAT /
 *  query list before clicking Save. */
export interface JiraTestBody {
  server_url?: string;
  pat?: string;
  allowed_jql_queries?: JiraAllowedQuery[];
  verify_ssl?: boolean;
}

/** Stable test-response shape. Connection failures (401, 5xx, network)
 *  surface as `ok=false` with the message in `message`; only true config
 *  errors (no URL, gate closed, etc.) come back as HTTP 400. */
export interface JiraTestResponse {
  ok: boolean;
  message: string;
  detected: {
    account?: string;
    server_url?: string | null;
    queries_configured?: number;
  };
}

/** Live eMASS connector status (cheap — no network). `configured` is true
 *  when base_url + system_id + cert_path are saved, the cert file exists
 *  on disk, AND both gate flags are flipped on. `reachable` is always
 *  null from /status — it gets set by /test. */
export interface EmassStatus {
  configured: boolean;
  enabled: boolean;
  base_url: string | null;
  system_id: string | null;
  cert_path: string | null;
  key_path: string | null;
  api_key_set: boolean;
  cert_exists: boolean;
  key_exists: boolean;
  upcoming_gated: boolean;
  connectors_v04: boolean;
  reachable: boolean | null;
}

/** Optional per-field overrides for the /test probe. All fields fall back
 *  to the saved config when omitted, so passing `{}` validates whatever's
 *  saved today. */
export interface EmassTestBody {
  base_url?: string;
  system_id?: string;
  cert_path?: string;
  key_path?: string;
}

/** eMASS probe result. `detected` carries the system metadata the probe
 *  resolved from the eMASS REST API (system_id, system_name, base_url). */
export interface EmassTestResponse {
  ok: boolean;
  message: string;
  detected: {
    system_id?: string;
    system_name?: string;
    base_url?: string;
  };
}

/** One drill-in level of the configured library. Paths are relative to the
 *  configured scan root so the dialog can pass them straight back to /browse
 *  as `subfolder`. `ingestible` lets the UI render non-ingestible files
 *  (e.g. .vsd, .mp4) dimmed so the user knows clicking won't ingest them. */
export interface SharePointBrowseResponse {
  path: string;
  folders: { name: string; path: string; child_count: number }[];
  files: {
    name: string;
    path: string;
    size: number | null;
    modified: string | null;
    ingestible: boolean;
  }[];
}

export interface SharePointBrowseBody {
  site_url?: string;
  library?: string;
  folder_path?: string;
  subfolder?: string;
}

// ---------------------------------------------------------------------------
// Archer connector — status + test + password management
// ---------------------------------------------------------------------------

/** Cheap status read — no network. `configured` is true when instance_url,
 *  instance_name, and username are all set. `password_set` reflects whether
 *  the OS keyring has a slot for (instance_name, username) OR the legacy
 *  ARCHER_PASSWORD env-var fallback is populated. `feature_env_flag`
 *  surfaces the legacy ARCHER_CONNECTOR_ENABLED env-var so power users on
 *  dev workstations can see why the connector is on/off independent of the
 *  persisted `enabled` toggle. */
export interface ArcherStatus {
  configured: boolean;
  instance_url: string | null;
  instance_name: string | null;
  username: string | null;
  domain: string | null;
  password_set: boolean;
  enabled: boolean;
  feature_env_flag: boolean;
}

/** Body for POST /api/archer/test — every field is optional and falls back
 *  to the saved config server-side. Password is NOT a field; the probe
 *  always reads the keyring slot for the (instance_name, username) pair
 *  under test, so a passing probe proves the persisted credential
 *  round-trips. */
export interface ArcherTestBody {
  instance_url?: string;
  instance_name?: string;
  username?: string;
  domain?: string;
}

export interface ArcherTestResponse {
  ok: boolean;
  message: string;
  detected: {
    instance_url: string | null;
    instance_name: string | null;
    username: string | null;
  };
  disabled?: boolean;
}

export interface ArcherPasswordBody {
  password: string;
  instance_name?: string;
  username?: string;
}

/** One filename-search hit. `path` is scan-root-relative so the UI can hand
 *  it straight back as an ingest `file_paths` entry. `matched_terms` lists
 *  the parsed tokens (USD doc numbers, control IDs, or keywords) that the
 *  filename hit, so the UI can show small "why this matched" badges. */
export interface SharePointSearchHit {
  name: string;
  path: string;
  folder: string;
  size: number | null;
  modified: string | null;
  ingestible: boolean;
  matched_terms: string[];
}

export interface SharePointSearchBody {
  site_url?: string;
  library?: string;
  folder_path?: string;
  query: string;
  max_depth?: number;
  max_matches?: number;
}

export interface SharePointSearchResponse {
  query: string;
  scanned_folders: number;
  truncated: boolean;
  matches: SharePointSearchHit[];
}

/** One ranked candidate from the boundary-aware sweep. Ephemeral — the
 *  backend does NOT persist sweep results; the UI checkbox flow hands the
 *  selected `path` values back to /api/sharepoint/ingest via `file_paths`.
 *  `score` is 0..1; `matched_signals` is human-readable like
 *  `["host:server01","family:AC","crm-kw:gitlab"]`; `proposed_ccis` are
 *  OSCAL-canonical (e.g. "ac-2.1"). `download_url` is captured at walk
 *  time but the UI never uses it for sweep — only for the "open in
 *  SharePoint" link we rely on `web_url`. */
export interface SharePointSweepCandidate {
  name: string;
  path: string;
  web_url: string;
  size: number | null;
  modified: string | null;
  /**
   * Blended combined score that drives the surface/precheck thresholds.
   * v0.2 widened the semantics: when the LLM judge ran, this is
   * `0.30 * keyword_score + 0.70 * llm_score`. When the judge was skipped
   * (kill-switch off, cost-cap fallback, or per-call API error), this
   * equals `keyword_score`. Pre-v0.2 sidecars send the raw keyword score
   * here too — same numeric range so the UI can sort unconditionally.
   */
  score: number;
  matched_signals: string[];
  proposed_ccis: string[];
  snippet: string | null;
  download_url: string | null;
  /**
   * v0.2 LLM-judge per-candidate breakdown — all four are present on
   * fresh sidecars and absent (undefined) on pre-v0.2 responses.
   *
   * - `keyword_score` — pure keyword-scorer output (0..1).
   * - `llm_score` — judge rubric output (0..1), null when the judge was
   *   not consulted for this row (kill-switch off, cost-cap skip, error).
   * - `judge_reasoning` — <=200 char judge rationale; null when no judge
   *   call happened.
   * - `judge_used` — true iff the LLM score actually contributed to
   *   `score` above. Lets the UI render a small "AI" chip per row.
   */
  keyword_score?: number;
  llm_score?: number | null;
  judge_reasoning?: string | null;
  judge_used?: boolean;
  /**
   * Pre-credit dedup (v0.2): true when this candidate's web_url already
   * resolves to an Evidence row in the store. The triage dialog hides these
   * by default ("what's new" mental model) and never auto-prechecks them —
   * re-picking a credited row is a no-op at ingest (the orchestrator dedupes
   * by path). Absent on pre-v0.2 sidecars; treat undefined as false.
   */
  already_in_evidence?: boolean;
  /**
   * Evidence id of the existing row when `already_in_evidence` is true; null
   * (or absent) otherwise. Lets the UI deep-link the credited row to its
   * prior Evidence entry.
   */
  existing_evidence_id?: number | null;
}

/**
 * Sweep body — backend enforces at-least-one of `workbook_id` /
 * `system_context_id` (pydantic model_validator on `SweepBody`). The
 * pending-mode path (no workbook open yet) sets only `system_context_id`;
 * the workbook-mode path sets `workbook_id`; both may be set when a
 * workbook is open and the assessor opts to also key the sweep off the
 * promoted SystemContext explicitly. Sending neither → 422.
 */
export interface SharePointSweepBody {
  workbook_id?: number;
  system_context_id?: number;
  site_url?: string;
  library?: string;
  folder_path?: string;
  max_candidates?: number;
  max_search_queries?: number;
  /** Per-run cost ceiling in dollars. Omit (or 0) ⇒ fall back to the saved
   *  default in config.toml (which itself defaults to 0 = unlimited). Wired
   *  to the inline "Stop at $N" toggle next to the Sweep button in
   *  BrowseSharePointDialog. */
  cost_cap_usd?: number;
  /** Per-run wall-clock ceiling in seconds. Omit (or 0) ⇒ no cap. When the
   *  judge's wall-clock crosses this, in-flight LLM calls finish and
   *  remaining candidates fall back to pure-keyword scoring (graceful
   *  degradation, not a failure). Wired to the inline "Stop after N min"
   *  toggle next to the Sweep button in BrowseSharePointDialog. */
  time_cap_seconds?: number;
  /** Pseudo-relevance-feedback exemplars: scan-root-relative paths the
   *  assessor pre-checked, fed back into the LLM judge's cached system block
   *  so a "refine with selection" pass has a richer semantic prior than the
   *  host-token list alone. Empty/omitted on the first pass — maps to the
   *  backend SweepBody.seed_candidate_paths list. */
  seed_candidate_paths?: string[];
}

export interface SharePointSweepResponse {
  scan_root: string;
  /** Null in pending mode (no workbook bound yet); set in workbook mode.
   *  Pair with `system_context_id` to attribute the sweep — the SweepRun
   *  row written by the backend uses both nullable fields. */
  workbook_id: number | null;
  system_context_id: number | null;
  candidates: SharePointSweepCandidate[];
  /** Family letters (e.g. ["AU","AT","CP"]) where the CRM marked every
   *  in-scope CCI as provider/inherited/NA — those candidates are hidden
   *  entirely (see design memo "What NOT to do"). The UI shows this as a
   *  collapsible "we skipped …" banner so users understand the filtering. */
  families_skipped_by_crm: string[];
  truncated: boolean;
  elapsed_ms: number;
  /** Active SweepWeights row id used to score this sweep. Echoed back into
   *  /sweep/decisions so each logged decision is tied to the exact weights
   *  that produced its score — recalibration can reproduce features later
   *  even if the active weights have rolled forward. Null only on legacy
   *  responses from a pre-v0.2 sidecar. */
  weights_version_id: number | null;
  /** Snapshot of the BoundaryFingerprint used at sweep time (hosts,
   *  control IDs, families, CRM keywords, doc prefixes, priority-link
   *  folder URIs). Opaque to the UI — round-tripped verbatim into
   *  /sweep/decisions so retraining sees the same feature inputs. */
  fingerprint_snapshot: Record<string, unknown> | null;
  /**
   * v0.2 LLM-judge per-sweep telemetry. All eight fields default to
   * zero / null on pre-v0.2 sidecars or when `judge_used == false`, so
   * older clients keep working unchanged.
   *
   * - `llm_cost_usd` — total dollar cost of this sweep's judge calls
   *   (already factored in `Workbook.total_sweep_cost_usd`).
   * - `llm_tokens_in_total` / `llm_tokens_out_total` — raw token counts
   *   summed across every judge call in the batch.
   * - `cache_read_tokens_total` — Anthropic ephemeral-cache hits on the
   *   boundary brief. Should dominate `llm_tokens_in_total` from the
   *   second candidate onward — proves the brief is cache-served.
   * - `candidates_judged` — count of candidates that actually reached
   *   the LLM (after skip-family veto, before cost-cap cancellation).
   * - `judge_model` — model id used for this sweep, e.g.
   *   `claude-haiku-4-5-20251001`. Null when the judge was disabled.
   * - `judge_used` — true iff the judge ran for at least one candidate.
   * - `judge_fallback_reason` — null on clean runs; otherwise a short
   *   tag like `cost_cap_exceeded` or `api_error: <type>: <msg>` that
   *   the UI surfaces as a single banner instead of N per-row toasts.
   */
  llm_cost_usd?: number;
  llm_tokens_in_total?: number;
  llm_tokens_out_total?: number;
  cache_read_tokens_total?: number;
  candidates_judged?: number;
  judge_model?: string | null;
  judge_used?: boolean;
  judge_fallback_reason?: string | null;
}

/**
 * Body for POST /api/sharepoint/sweep/ingest-all — the manual escape hatch
 * that walks a folder and ingests every supported file with no scoring.
 * Mirrors the backend `SweepIngestAllBody`. No `system_context_id`: ingest-
 * all doesn't score, so the boundary fingerprint is irrelevant; `workbook_id`
 * flows through only so auto-tags land under the right framework lens.
 */
export interface SweepIngestAllBody {
  site_url?: string;
  library?: string;
  folder_path?: string;
  workbook_id?: number;
}

/**
 * Response from /sweep/ingest-all. Two shapes, discriminated on `job_id`:
 * - success → `IngestJobStart` (`{ job_id }`); poll via the existing
 *   /api/evidence/ingest/jobs/{id} poller.
 * - pending auth → `SharePointTestResponse` with `pending=true` + device-code
 *   fields (same prompt shape the Settings card already handles).
 */
export type SweepIngestAllResponse = IngestJobStart | SharePointTestResponse;

/** One per-candidate decision recorded when the assessor clicks Ingest in
 *  the SweepTriageDialog. `included` is the final check state; everything
 *  else is captured at decision time so retraining doesn't depend on
 *  the workbook's later state. */
export interface SweepDecisionEntry {
  candidate_path: string;
  candidate_name: string;
  score_at_decision: number;
  signals: string[];
  proposed_ccis: string[];
  included: boolean;
  auto_prechecked: boolean;
}

export interface SweepDecisionsBody {
  workbook_id: number;
  weights_version_id: number;
  fingerprint_snapshot: Record<string, unknown>;
  decisions: SweepDecisionEntry[];
}

export interface SweepDecisionsResult {
  inserted: number;
}

/** Most recent SweepRun row for a workbook, fetched by the Sweep Context
 *  page to render the "Last sweep: $X.XX · N judged · {model} · {minutes}m ago"
 *  footer. Returns `null` (not 404) when the workbook has never been swept. */
export interface LatestSweepRun {
  id: number;
  workbook_id: number;
  started_at: string | null;
  finished_at: string | null;
  total_candidates: number;
  candidates_surfaced: number;
  candidates_judged: number;
  llm_cost_usd: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  judge_model: string | null;
  fallback_reason: string | null;
}

/** Quick-access bookmark — pasted from the SharePoint browser address bar.
 *  No per-link presets, no auto-ingest config; this is just a labeled URL
 *  the user wants to find again later. */
export interface SharePointPriorityLink {
  label: string;
  url: string;
}

/** Live status of the Splunk connector — config + keyring only, never a
 *  network call. The Settings card reads this on every render to update its
 *  badge. `configured` is true when host, token, and at least one saved-
 *  search name are all in place — anything less and the test probe would
 *  fail loudly, so surface that on the card without forcing a click. */
export interface SplunkStatus {
  configured: boolean;
  host: string | null;
  port: number;
  scheme: string;
  app: string;
  owner: string;
  verify_tls: boolean;
  saved_searches: string[];
  token_set: boolean;
  enabled: boolean;
}

/** Body for "Test connection" — every field optional, falls back to stored
 *  config + keyring. Lets the user probe a candidate host/token typed into
 *  the form before clicking Save. */
export interface SplunkTestBody {
  host?: string;
  port?: number;
  scheme?: string;
  app?: string;
  owner?: string;
  verify_tls?: boolean;
  saved_searches?: string[];
  /** Optional override — usually omitted so the keyring token is used. */
  token?: string;
}

/** Response from /api/splunk/test. `ok=false` is reported as a 200 with a
 *  message rather than a 500 so the UI stays on a stable shape; only
 *  configuration errors (gate closed, missing host/token/saved-searches)
 *  surface as HTTP 400. */
export interface SplunkTestResponse {
  ok: boolean;
  message: string;
  detected: {
    host?: string;
    version?: string;
    saved_searches?: number;
  };
}

/** Live Tenable connector status (cheap — no network calls).
 *
 *  `configured` reflects whether `TenableSource` can be constructed from
 *  the stored config + keyring:
 *  - `io`: needs only the keyset (host is implicit).
 *  - `sc`: additionally needs a host FQDN.
 *
 *  Raw key material never appears here — only the `*_key_set` booleans.
 *  For `io`, `host` is reported as `cloud.tenable.com` so the UI can render
 *  it as a read-only badge rather than an empty field. */
export interface TenableStatus {
  configured: boolean;
  flavor: "sc" | "io" | null;
  host: string | null;
  access_key_set: boolean;
  secret_key_set: boolean;
  enabled: boolean;
}

/** Override-on-test payload for the Tenable probe. Every field is optional;
 *  anything not supplied falls back to the saved config (or the keyring for
 *  the secrets). Keys are never sent here — `/test` always reads them from
 *  the keyring. */
export interface TenableTestBody {
  flavor?: "sc" | "io";
  host?: string;
}

/** Tenable probe response. On success: `ok=true` + `detected` carries the
 *  whoami result from the SDK. On failure the backend raises HTTP 400/401
 *  with the redacted hint as `detail` — this shape only describes the
 *  success path. */
export interface TenableTestResponse {
  ok: boolean;
  message: string;
  detected: {
    flavor: "sc" | "io";
    host: string;
    username: string;
  };
}

// ---- POAMs -----------------------------------------------------------------
// Mirrors backend/cybersecurity_assessor/models.py PoamStatus + RiskLevel
// (both `(str, Enum)`, so JSON payloads serialize as the human label, not
// the Python attribute name — keep these strings byte-exact).
export type PoamStatus = "Draft" | "Ongoing" | "Risk Accepted" | "Completed";
export type RiskLevel =
  | "Very Low"
  | "Low"
  | "Moderate"
  | "High"
  | "Very High";

export interface RiskLevelInfo {
  value: RiskLevel;
  score: number;
  description: string;
}

/**
 * One row of the POAM risk-field audit trail. Returned by
 * GET /api/poams/{id}/risk-history newest-first. Free-form ``actor`` strings
 * are stamped by the backend (``"system:generator"``,
 * ``"assessor:manual-create"``, ``"assessor:update"``,
 * ``"system:residual-advisor"``); the UI just renders them verbatim.
 */
export interface PoamRiskHistoryEntry {
  id: number;
  poam_id: number;
  field: "likelihood" | "impact" | "raw_severity" | "residual_risk";
  prev_value: string | null;
  new_value: string | null;
  prev_rationale: string | null;
  new_rationale: string | null;
  prev_source: "auto" | "manual" | "llm_suggested" | null;
  new_source: "auto" | "manual" | "llm_suggested" | null;
  actor: string | null;
  created_at: string;
}

/**
 * LLM advisor response. ``suggested`` is null when the model abstains for
 * insufficient boundary context — per ``feedback_precision_over_recall`` the
 * UI surfaces the rationale rather than guessing a level.
 */
export interface PoamResidualSuggestion {
  suggested: RiskLevel | null;
  rationale: string;
  confidence: "low" | "medium" | "high";
  key_factors: string[];
  decided_at: string;
  /** ``null`` = fresh model call; ``"cache_hit"`` = decision-cache replay.
   * (Backend stamps exactly these — residual_advisor.py replay()/store_cache.) */
  cache_source: "cache_hit" | null;
}

export interface PoamMilestone {
  id: number;
  poam_id: number;
  description: string;
  scheduled_date: string | null;
  completion_date: string | null;
  changes_history: string | null;
  created_at: string;
}

export interface PoamObjectiveLink {
  /** Numeric FK into Objective.id — use this for unlink. */
  objective_id: number;
  /** Human CCI code (e.g. "CCI-000015"). */
  objective_code: string;
  objective_text: string;
  control_id: string;
  control_title: string;
  status_at_creation: ComplianceStatus | null;
}

export interface PoamEvidenceLink {
  /** Numeric FK into Evidence.id — use this for unlink. */
  evidence_id: number;
  title: string | null;
  /** Absolute path on disk; the UI falls back to this if title is null. */
  path: string;
  kind: EvidenceKind;
  /** USD/doc number parsed at ingest, when present. */
  doc_number: string | null;
  /** Free-form note attached to the link (not the evidence itself). */
  note: string | null;
  /** ISO timestamp the link row was created. */
  linked_at: string;
}

export interface PoamSummary {
  id: number;
  workbook_id: number;
  control_cluster: string;
  vulnerability_description: string;
  security_control_number: string | null;
  emass_poam_id: string | null;
  status: PoamStatus;
  scheduled_completion_date: string | null;
  actual_completion_date: string | null;
  likelihood: RiskLevel | null;
  impact: RiskLevel | null;
  raw_severity: RiskLevel | null;
  residual_risk: RiskLevel | null;
  /** Risk-input provenance. ``"auto"`` = seeded by generator from STIG CAT;
   * ``"default"`` = generator seeded the documented MODERATE baseline with
   * no STIG/CVSS signal to ground it (un-owned, pending assessor review);
   * ``"manual"`` = assessor edited via PATCH; ``"llm_suggested"`` = applied
   * via POST /apply-residual-suggestion. NULL on legacy rows. Drives the
   * source badges in the PoamDetail Risk card. */
  likelihood_source: "auto" | "default" | "manual" | "llm_suggested" | null;
  likelihood_rationale: string | null;
  impact_source: "auto" | "default" | "manual" | "llm_suggested" | null;
  impact_rationale: string | null;
  residual_risk_source: "auto" | "default" | "manual" | "llm_suggested" | null;
  residual_risk_rationale: string | null;
  /** Numeric score so the UI can sort highest-risk-first without
   * re-shipping the enum→int mapping. Null when raw_severity is null. */
  raw_severity_score: number | null;
  milestone_count: number;
  objective_count: number;
  evidence_count: number;
  created_at: string;
  updated_at: string;
  exported_at: string | null;
  narrative_locked: boolean;
}

export interface PoamDetail extends PoamSummary {
  source_identifying_control_vulnerability: string | null;
  office_org: string | null;
  relevance_of_threat: RiskLevel | null;
  resources_required: string | null;
  mitigations: string | null;
  comments: string | null;
  milestones: PoamMilestone[];
  objectives: PoamObjectiveLink[];
  evidence: PoamEvidenceLink[];
}

export interface GeneratePoamsResult {
  workbook_id: number;
  // Back-compat shape from v0.1 — count + ids of NEWLY created POAMs only.
  // New code should consume `counts`/`ids` for the full picture (created vs
  // rewritten vs locked etc).
  created: number;
  poam_ids: number[];
  counts: {
    created: number;
    rewritten: number;
    unchanged: number;
    locked_skipped: number;
    non_draft_skipped: number;
  };
  ids: {
    created: number[];
    rewritten: number[];
    unchanged: number[];
    locked_skipped: number[];
    non_draft_skipped: number[];
  };
}

export interface ExportPoamsResult {
  workbook_id: number;
  output_path: string;
  written: number;
  skipped: number;
  warnings: string[];
}

export interface ImportPoamsResult {
  workbook_id: number;
  read: number;
  matched: number;
  created: number;
  warnings: string[];
}

/** Wire-format mirror of backend ``ControlExportResultDto``.
 *
 * Returned by both ``/api/controls/export/emass`` and
 * ``/api/controls/export/working``. ``skipped`` is a list of
 * ``[control_acronym, reason]`` pairs (the backend widens tuples to
 * lists for JSON; we model them as fixed-length string arrays here).
 * ``template_warnings`` is informational — e.g. "Status column not
 * found in template; rolled-up status not written." */
export interface ControlExportResultDto {
  output_path: string;
  rows_written: number;
  controls_with_psc: number;
  skipped: string[][];
  template_warnings: string[];
}

export interface ExportControlsEmassRequest {
  workbook_id: number;
  template_path: string;
  output_path: string;
}

export interface ExportControlsWorkingRequest {
  workbook_id: number;
  output_path: string;
  /** Null/omitted = "no filter" — matches the Controls list page "All" sentinel. */
  family?: string | null;
  status?: string | null;
  search?: string | null;
}

/** Wire-format mirror of backend ``NarrativeImportResultDto``.
 *
 * Returned by ``/api/controls/import/narratives``. ``imported``/``updated``
 * count Assessment rows written; the three buckets list the CCI ids of
 * input rows that did NOT produce a write so the operator can reconcile
 * the file against the workbook's in-scope set. */
export interface NarrativeImportResultDto {
  output_path: string;
  total_rows: number;
  imported: number;
  updated: number;
  unmatched: string[];
  skipped_no_status: string[];
  skipped_no_narrative: string[];
}

export interface ImportControlsNarrativesRequest {
  workbook_id: number;
  file_path: string;
}

export interface CreatePoamRequest {
  workbook_id: number;
  control_cluster: string;
  vulnerability_description: string;
  security_control_number?: string | null;
  status?: PoamStatus;
  likelihood?: RiskLevel | null;
  likelihood_rationale?: string | null;
  impact?: RiskLevel | null;
  impact_rationale?: string | null;
  relevance_of_threat?: RiskLevel | null;
  scheduled_completion_date?: string | null;
  resources_required?: string | null;
  mitigations?: string | null;
  comments?: string | null;
  office_org?: string | null;
  objective_ids?: number[];
}

/** All-optional patch. Absence = "don't change"; explicit `null` clears the
 * field server-side (Pydantic distinguishes via __fields_set__). */
export interface UpdatePoamRequest {
  vulnerability_description?: string | null;
  security_control_number?: string | null;
  emass_poam_id?: string | null;
  source_identifying_control_vulnerability?: string | null;
  office_org?: string | null;
  status?: PoamStatus;
  scheduled_completion_date?: string | null;
  actual_completion_date?: string | null;
  likelihood?: RiskLevel | null;
  likelihood_rationale?: string | null;
  impact?: RiskLevel | null;
  impact_rationale?: string | null;
  relevance_of_threat?: RiskLevel | null;
  residual_risk?: RiskLevel | null;
  residual_risk_rationale?: string | null;
  resources_required?: string | null;
  mitigations?: string | null;
  comments?: string | null;
}

export interface MilestoneCreateRequest {
  description: string;
  scheduled_date?: string | null;
  completion_date?: string | null;
  changes_history?: string | null;
}

export interface MilestoneUpdateRequest {
  description?: string;
  scheduled_date?: string | null;
  completion_date?: string | null;
  changes_history?: string | null;
}

// ---------------------------------------------------------------------------
// Automation — per-workbook evidence-pull schedule types
// ---------------------------------------------------------------------------

/**
 * One automated evidence-pull schedule attached to a workbook.
 * Mirrors backend AutomationSchedule model (routes/automation.py).
 */
export interface AutomationSchedule {
  id: number;
  workbook_id: number;
  name: string | null;
  /** Connector discriminator — "local" | "sharepoint" | … */
  source_type: string;
  /** Null means pull from all configured roots for this connector. */
  source_ref: string | null;
  /** Pull cadence in minutes. Default 1440 (24 h). */
  interval_minutes: number;
  /** When true, a re-assessment job chains after every successful pull. */
  run_assessment: boolean;
  enabled: boolean;
  last_run_at: string | null;
  last_status: string | null;
  last_detail: string | null;
  next_run_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AutomationScheduleCreate {
  workbook_id: number;
  source_type: string;
  name?: string | null;
  source_ref?: string | null;
  interval_minutes?: number;
  run_assessment?: boolean;
  enabled?: boolean;
}

export type AutomationSchedulePatch = Partial<
  Pick<
    AutomationScheduleCreate,
    "name" | "source_type" | "source_ref" | "interval_minutes" | "run_assessment" | "enabled"
  >
>;

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

export const api = {
  health: () => request<{ status: string; version: string }>("/healthz"),

  // Catalog
  listFrameworks: () => request<Framework[]>("/api/catalog/frameworks"),
  catalogStatus: () => request<CatalogStatus>("/api/catalog/status"),
  /**
   * Toggle a framework's display/selection gate. Presentation-only on the
   * backend — never tears down catalog rows or parent→child inheritance.
   */
  setFrameworkEnabled: (frameworkId: number, enabled: boolean) =>
    request<{ id: number; name: string; version: string; enabled: boolean }>(
      `/api/catalog/frameworks/${frameworkId}/enabled`,
      { method: "POST", body: JSON.stringify({ enabled }) },
    ),
  listControls: (frameworkId: number) =>
    request<Control[]>(`/api/catalog/frameworks/${frameworkId}/controls`),
  listObjectives: (
    controlId: number,
    includeMappings = false,
    workbookId?: number,
  ) => {
    const params = new URLSearchParams();
    if (includeMappings) params.set("include_mappings", "true");
    if (workbookId !== undefined) params.set("workbook_id", String(workbookId));
    const qs = params.toString();
    return request<Objective[]>(
      `/api/catalog/controls/${controlId}/objectives${qs ? `?${qs}` : ""}`,
    );
  },
  /**
   * Program-specific overlay rows that crosswalk to one base control —
   * grouped by RequirementSource. Pass `frameworkId` to scope to the
   * workbook's active framework so an r4 overlay doesn't bleed onto an r5
   * control (or vice-versa) when both are loaded.
   */
  listProgramControlsForControl: (controlId: number, frameworkId?: number) =>
    request<ProgramControlSourceGroup[]>(
      `/api/controls/${controlId}/program-controls${frameworkId ? `?framework_id=${frameworkId}` : ""}`,
    ),
  loadNist80053r5: (path?: string) =>
    request<Framework>(`/api/catalog/load/nist-800-53r5${path ? `?path=${encodeURIComponent(path)}` : ""}`, {
      method: "POST",
    }),
  loadNist80053r4: (path?: string) =>
    request<Framework>(`/api/catalog/load/nist-800-53r4${path ? `?path=${encodeURIComponent(path)}` : ""}`, {
      method: "POST",
    }),
  /**
   * Load the NIST Cybersecurity Framework (CSF) 2.0 OSCAL catalog. Public-
   * domain content, so this is a download-style loader: with no `path` the
   * official NIST catalog is fetched into the local cache, falling back to the
   * wheel-bundled copy when the network is down. Root catalog — no parent.
   */
  loadNistCsf: (path?: string) =>
    request<Framework>(
      `/api/catalog/load/nist-csf${path ? `?path=${encodeURIComponent(path)}` : ""}`,
      { method: "POST" },
    ),
  /**
   * Load the NIST SP 800-171 Rev 3 OSCAL catalog. Public-domain; download-
   * style with bundled fallback.
   */
  loadNist800171: (path?: string) =>
    request<Framework>(
      `/api/catalog/load/nist-800-171${path ? `?path=${encodeURIComponent(path)}` : ""}`,
      { method: "POST" },
    ),
  /**
   * Load ISO/IEC 27001:2022 from a user-supplied licensed export. The control
   * text is copyrighted, so `path` is REQUIRED — point it at the org's own
   * `.csv`/`.json` export. With no path the backend returns the supply-your-
   * licensed-export error (surfaced as a 400).
   */
  loadIso27001: (opts: { path: string; offline?: boolean }) =>
    request<Framework>("/api/catalog/load/iso-27001", {
      method: "POST",
      body: JSON.stringify({ path: opts.path, offline: opts.offline ?? false }),
    }),
  /**
   * Load CIS Controls v8 Safeguards from a user-supplied licensed export.
   * Copyrighted — `path` REQUIRED (see `loadIso27001`).
   */
  loadCisV8: (opts: { path: string; offline?: boolean }) =>
    request<Framework>("/api/catalog/load/cis-v8", {
      method: "POST",
      body: JSON.stringify({ path: opts.path, offline: opts.offline ?? false }),
    }),
  /**
   * Load PCI DSS 4.0 requirements from a user-supplied licensed export.
   * Copyrighted — `path` REQUIRED (see `loadIso27001`).
   */
  loadPciDss: (opts: { path: string; offline?: boolean }) =>
    request<Framework>("/api/catalog/load/pci-dss", {
      method: "POST",
      body: JSON.stringify({ path: opts.path, offline: opts.offline ?? false }),
    }),
  /**
   * Load the SOC 2 Trust Services Criteria from a user-supplied licensed
   * export. AICPA-copyrighted — `path` REQUIRED (see `loadIso27001`).
   */
  loadSoc2: (opts: { path: string; offline?: boolean }) =>
    request<Framework>("/api/catalog/load/soc2", {
      method: "POST",
      body: JSON.stringify({ path: opts.path, offline: opts.offline ?? false }),
    }),
  /**
   * Load a FedRAMP Rev 5 baseline profile (HIGH / MODERATE / LOW / LI-SAAS)
   * as a *child* of the already-loaded 800-53 r5 Framework. The picker
   * gates these items on `hasR5 && !hasFedramp(level)`, so this call only
   * runs when both conditions are true.
   *
   * Returns the Framework with FedRAMP-specific load counts appended:
   *  - `members_added` — controls included in the profile baseline
   *  - `controls_synthesized` — shadow rows carrying merged FedRAMP-Additions prose
   *  - `parameters_loaded` — shadow rows whose ODP overrides were projected from `set-parameters[]`
   *  - `unknown_control_ids` — ids the profile referenced that the parent catalog doesn't carry
   *
   * `offline: true` skips the network and falls straight back to the
   * wheel-bundled copy (offline-first install path); `path` lets an
   * operator point at a local pre-release profile JSON for testing.
   */
  loadFedramp: (
    level: "HIGH" | "MODERATE" | "LOW" | "LI-SAAS",
    opts?: { path?: string; offline?: boolean },
  ) =>
    request<
      Framework & {
        members_added: number;
        controls_synthesized: number;
        parameters_loaded: number;
        unknown_control_ids: string[];
      }
    >("/api/catalog/load/fedramp", {
      method: "POST",
      body: JSON.stringify({
        level,
        path: opts?.path ?? null,
        offline: opts?.offline ?? false,
      }),
    }),
  loadDisaCciCatalog: (args: {
    /**
     * Path to the CCI source file. Accepts:
     *  - NIST CSRC `stig-mapping-to-nist-800-53.xlsx` (preferred — current
     *    authoritative source as of mid-2026; DISA stopped publishing the
     *    standalone XML)
     *  - Archived DISA `U_CCI_List.xml` (still parses if you have an old
     *    download)
     */
    source_path?: string;
    /** Legacy alias for `source_path`. Backend coalesces. */
    xml_path?: string;
    framework_id: number;
  }) =>
    request<DisaCciLoadResult>("/api/catalog/load/disa-cci", {
      method: "POST",
      body: JSON.stringify(args),
    }),
  /**
   * Unified overlay import — auto-classifies the xlsx as CRM / PSC / OTHER
   * by sniffing header vocab and dispatches to the right loader. This is
   * the single front door that replaces the old two-button affordance
   * (`loadCrm` + `loadProgramControlsCatalog`); both remain available for
   * the deprecated typed-loader path but new UI should prefer this.
   *
   * `kind_hint` is an escape hatch — when supplied it forces a specific
   * loader regardless of header detection. Useful when the user knows
   * the file is e.g. a CRM with hand-edited headers the classifier
   * doesn't yet recognize. The backend still surfaces a warning when the
   * hint disagrees with the auto-detected kind.
   *
   * Files with no recognizable headers import as OTHER — they get a
   * Baseline row so they're visible in the Workbooks attach UI but no
   * resolver runs against them during assessment until one is programmed.
   */
  importOverlay: (args: {
    framework_id: number;
    path: string;
    name?: string | null;
    kind_hint?: OverlayKind | null;
    /**
     * Explicit PSC sheet selector. Only honored when the dispatched loader
     * is PSC (auto-detected or via `kind_hint=psc`); ignored with a
     * warning otherwise. The T1TL workbook ships with both "Ground
     * Security Controls" and "SV Security Controls" — the classifier
     * picks the first PSC-shaped sheet (Ground), so without this field
     * there's no way to target SV. Pair with the Settings sheet-picker
     * dropdown (`listOverlaySheets`).
     */
    sheet_name?: string | null;
    system_id?: number | null;
    /**
     * Implementation slice this CRM covers (e.g. "AWS GovCloud",
     * "Azure Government"). Required by the backend when the dispatched
     * loader is CRM; null for PSC/OTHER. Free-text allowed via the
     * Settings "Other…" path — the backend normalizes/canonicalizes it.
     */
    scope_label?: string | null;
  }) =>
    request<OverlayImportResult>("/api/catalog/overlays/import", {
      method: "POST",
      body: JSON.stringify(args),
    }),
  /**
   * Preview an overlay xlsx — list every sheet labeled with its candidate
   * kind, plus the classifier's auto-pick. Feeds the Settings → Import
   * overlay sheet-picker dropdown so the user can explicitly target a tab
   * before clicking Import.
   *
   * Read-only — never mutates the file.
   */
  listOverlaySheets: (path: string) =>
    request<OverlaySheetsResult>(
      `/api/catalog/overlays/sheets?path=${encodeURIComponent(path)}`,
    ),
  /**
   * Auto-detected document supersessions for one workbook — the legacy →
   * current rewrites the assessor would apply, derived from the evidence
   * chain (Rev A superseded by Rev B at ingest). Read-only; per workbook.
   */
  listSupersessionChains: (workbookId: number) =>
    request<SupersessionChain[]>(
      `/api/supersession/chains?workbook_id=${workbookId}`,
    ),
  /**
   * Load a program-specific controls overlay into the global RequirementSource
   * table. `source_name` is the human-readable label that distinguishes one
   * overlay from another (e.g. "SDA Enterprise Services Controls"); it acts
   * as the upsert key with `framework_id`.
   *
   * `workbook_path` is any xlsx containing the overlay tab. `sheet_name` is
   * required — overlay sheet names vary across programs so we don't guess.
   *
   * @deprecated Prefer `importOverlay` — the unified front door auto-
   * classifies and dispatches to this loader for PSC-shaped files.
   */
  loadProgramControlsCatalog: (args: {
    source_name: string;
    workbook_path: string;
    framework_id: number;
    sheet_name: string;
  }) =>
    request<ProgramControlsLoadResult>("/api/catalog/load/program-controls", {
      method: "POST",
      body: JSON.stringify(args),
    }),
  /**
   * List program-controls overlays currently loaded in the catalog. Mirrors
   * the GET /api/catalog/requirement-sources response shape — adds
   * `map_count` and `loaded_at` so the Settings card can show how many
   * requirements are wired up and when the overlay was last (re)loaded.
   */
  listRequirementSources: () =>
    request<
      Array<{
        id: number;
        name: string;
        path: string | null;
        framework_id: number;
        loaded_at: string | null;
        map_count: number;
      }>
    >("/api/catalog/requirement-sources"),
  /**
   * Destructive — removes a program-controls overlay AND every
   * RequirementMap row pointing at it. Underlying 800-53 Objective rows
   * stay (framework-owned). Re-loading the same `source_name` later
   * rebuilds the maps from scratch.
   */
  deleteRequirementSource: (id: number) =>
    request<{ deleted_source_id: number; name: string; maps_removed: number }>(
      `/api/catalog/requirement-sources/${id}`,
      { method: "DELETE" },
    ),

  // Workbooks
  listWorkbooks: () => request<Workbook[]>("/api/workbooks"),
  /**
   * Open (or re-open) a CCIS workbook.
   *
   * `frameworkId` is optional but strongly recommended — supplying it
   * triggers the baseline-apply step server-side, which is what populates
   * the in-scope/out-of-scope CCI tailoring. Without it the workbook
   * indexes but no baseline is materialized.
   */
  openWorkbook: (path: string, frameworkId?: number) =>
    request<
      Workbook & {
        summary: WorkbookSummary;
        baseline: WorkbookBaselineSummary | null;
        // Auto-promote outcome from the pending pre-workbook SystemContext.
        // Null when nothing was pending (the common case). When populated,
        // the backend has already reparented the pending SystemContext +
        // boundary docs onto this workbook; the UI uses this to invalidate
        // system-context + boundary-docs caches and toast the user.
        pending_promotion: PromotePendingResult | null;
      }
    >("/api/workbooks", {
      method: "POST",
      body: JSON.stringify(
        frameworkId !== undefined ? { path, framework_id: frameworkId } : { path },
      ),
    }),
  workbookSummary: (id: number) =>
    request<WorkbookSummary>(`/api/workbooks/${id}/summary`),
  workbookControlStatus: (id: number) =>
    request<ControlStatusRollup[]>(`/api/workbooks/${id}/control-status`),
  workbookColLStatus: (id: number) =>
    request<ColLStatusRollup[]>(`/api/workbooks/${id}/col-l-status`),
  /**
   * v0.2 Review Queue — every abstained Assessment in the workbook joined to
   * Control + Objective metadata, pre-sorted by `review_reason` category.
   */
  workbookReviewQueue: (id: number) =>
    request<ReviewQueueItem[]>(`/api/workbooks/${id}/review-queue`),
  /**
   * Clear the v0.2 sweep cap counter so the next sweep is callable again.
   * Surfaced in the UI once the counter hits 2/2 — used when the assessor
   * has just added new artifacts to SharePoint and wants a fresh budget.
   */
  resetSweepAttempts: (workbookId: number) =>
    request<{ sweep_attempts: number }>(
      `/api/workbooks/${workbookId}/sweep-attempts/reset`,
      { method: "POST" },
    ),

  // Workbook overlays — reference baselines (FedRAMP, Li-SaaS, …) attached
  // for gap-display only. Never assessment-write targets.
  listWorkbookOverlays: (id: number) =>
    request<WorkbookOverlay[]>(`/api/workbooks/${id}/overlays`),
  attachWorkbookOverlay: (id: number, baseline_id: number, note?: string) =>
    request<WorkbookOverlay>(`/api/workbooks/${id}/overlays`, {
      method: "POST",
      body: JSON.stringify({ baseline_id, note }),
    }),
  detachWorkbookOverlay: (id: number, baseline_id: number) =>
    request<{ detached: boolean; workbook_id: number; baseline_id: number }>(
      `/api/workbooks/${id}/overlays/${baseline_id}`,
      { method: "DELETE" },
    ),
  /**
   * Per-control overlay membership for the Controls grid. One round-trip
   * per workbook (regardless of overlay count) — the UI merges this with
   * the primary `listBaselineControls` response client-side.
   */
  workbookOverlayMembership: (id: number) =>
    request<OverlayMembership>(`/api/workbooks/${id}/overlay-membership`),

  // System Context — per-workbook freeform seed that biases boundary-aware
  // sweep scoring. 1:1 with Workbook (unique FK). The four markdown blobs
  // are distilled into `extracted_tokens` by an LLM call inside the upsert.
  /**
   * Fetch the SystemContext for a workbook. The backend returns ``null`` (200)
   * when no row exists yet, so this is a straight passthrough — no 404 catch
   * needed. Non-2xx still propagates as ApiError.
   */
  getSystemContext: (workbookId: number) =>
    request<SystemContext | null>(`/api/system-context/${workbookId}`),
  /**
   * Upsert the SystemContext freeform inputs and run LLM extraction. On
   * LLM failure the row still saves (with confidence=0.2 and
   * notes.extraction_error populated) so the assessor's narrative isn't
   * lost — caller surfaces the error as a toast but keeps the form data.
   */
  upsertSystemContext: (
    workbookId: number,
    body: SystemContextFreeformInput,
  ) =>
    request<SystemContextUpsertResult>(`/api/system-context/${workbookId}`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  /** Delete the SystemContext row (idempotent — 200 even if no row). */
  resetSystemContext: (workbookId: number) =>
    request<{ reset: boolean; workbook_id: number }>(
      `/api/system-context/${workbookId}/reset`,
      { method: "POST" },
    ),
  /**
   * Outcome-tied confidence bump — called from SweepTriageDialog after a
   * successful ingest start. +0.05 per accepted artifact (clamped at 1.0).
   * No-op if the workbook has no SystemContext row (response `bumped:false`).
   * See routes/system_context.py docstring for why this lives outside
   * /api/evidence/ingest (async job has no workbook_id awareness).
   */
  bumpSystemContextConfidence: (workbookId: number, accepted_count: number) =>
    request<{ bumped: boolean; confidence?: number; reason?: string }>(
      `/api/system-context/${workbookId}/bump-confidence`,
      {
        method: "POST",
        body: JSON.stringify({ accepted_count }),
      },
    ),

  // Pending pre-workbook SystemContext — assessors drop SSP/diagram/ATO docs
  // on the Sweep Context page BEFORE picking a workbook (the natural reflex,
  // since those docs exist independent of any specific assessment). The
  // partial unique index `ix_systemcontext_pending_singleton` enforces
  // at-most-one such row at the schema level. Promotion onto a workbook fires
  // automatically inside open_workbook (response carries `pending_promotion`)
  // and is also exposed here for the mid-session "open another workbook" path.
  /**
   * Fetch the pending SystemContext singleton + its attached boundary docs.
   * The backend always returns 200 — the empty state is
   * ``{context: null, boundary_docs: []}`` rather than a 404. A user who has
   * dropped docs but not yet triggered extraction sees ``context: null`` with
   * a populated ``boundary_docs`` array.
   */
  getPendingSystemContext: () =>
    request<PendingSystemContextResponse>("/api/system-context/pending"),
  /**
   * Upsert the pending SystemContext and run LLM extraction. Same body shape
   * as the per-workbook upsert (the backend dispatches on `source_type`); the
   * Sweep Context page uses `source_type: "docx_narrative"` once boundary
   * docs are attached.
   */
  upsertPendingSystemContext: (body: SystemContextFreeformInput) =>
    request<SystemContextUpsertResult>("/api/system-context/pending", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  /**
   * Attach the pending SystemContext + boundary docs to `workbookId`. The
   * backend refuses with 409 when the target workbook already has its own
   * SystemContext (don't silently clobber prior boundary work) — that
   * surfaces here as ApiError, not as `promoted: false`. The `promoted:
   * false` shape only fires for the clean "nothing pending" case.
   */
  promotePendingSystemContext: (workbookId: number) =>
    request<PromotePendingResult>(
      `/api/system-context/pending/promote?workbook_id=${workbookId}`,
      { method: "POST" },
    ),
  /**
   * Drop the pending SystemContext singleton AND any pending boundary-doc
   * Evidence rows (workbook_id IS NULL, is_boundary_doc=True). Idempotent
   * — returns `context_removed: false, boundary_docs_removed: 0` when there
   * was nothing to clear. Used by the "Discard pending scope" affordance
   * in the promote banner, and as a recovery action when extraction lands
   * in a bad state.
   */
  resetPendingSystemContext: () =>
    request<{
      reset: boolean;
      context_removed: boolean;
      boundary_docs_removed: number;
    }>("/api/system-context/pending/reset", { method: "POST" }),
  /**
   * Pending-mode mirror of bumpSystemContextConfidence — fires from the
   * pending-flavored SweepTriageDialog after the assessor accepts judge-
   * surfaced artifacts. Same +0.05 per accepted artifact, clamped at 1.0.
   * No-op (bumped:false) when no pending SystemContext exists.
   */
  bumpPendingSystemContextConfidence: (accepted_count: number) =>
    request<{ bumped: boolean; confidence?: number; reason?: string }>(
      "/api/system-context/pending/bump-confidence",
      {
        method: "POST",
        body: JSON.stringify({ accepted_count }),
      },
    ),

  // Baselines
  listBaselines: () => request<Baseline[]>("/api/baselines"),
  getScopeLabels: () =>
    request<ScopeLabelsResponse>("/api/baselines/scope-labels"),
  getBaseline: (id: number) => request<BaselineDetail>(`/api/baselines/${id}`),
  /**
   * Authoritative scoping surface — one row per Control/Enhancement in
   * the baseline. The Controls grid and tailoring UI should fetch from
   * here, not derive in-scope state by OR-ing CCIs.
   */
  listBaselineControls: (id: number, inScopeOnly = false) =>
    request<BaselineControlRow[]>(
      `/api/baselines/${id}/controls${inScopeOnly ? "?in_scope_only=true" : ""}`,
    ),
  listBaselineObjectives: (id: number, inScopeOnly = false) =>
    request<BaselineObjective[]>(
      `/api/baselines/${id}/objectives${inScopeOnly ? "?in_scope_only=true" : ""}`,
    ),
  refreshBaseline: (id: number) =>
    request<BaselineRefreshResult>(`/api/baselines/${id}/refresh`, { method: "POST" }),
  /**
   * Delete a baseline and its scoping rows. Backend rejects with 409 when
   * any workbook still points at this baseline as its primary scope —
   * surface the detail message so the user knows which workbook to fix.
   */
  deleteBaseline: (id: number, force = false) =>
    request<{
      ok: true;
      baseline_id: number;
      name: string;
      controls_removed: number;
      objectives_removed: number;
      overlay_attachments_removed: number;
      workbooks_removed: string[];
    }>(`/api/baselines/${id}${force ? "?force=true" : ""}`, { method: "DELETE" }),
  /**
   * Delete a workbook and every workbook-owned row that hangs off it.
   * Hard-deletes assessments / POAMs / sweep state / CRM telemetry; NULLs
   * the workbook_id on shared rows (Evidence, SystemContext). Returns
   * per-table counts so the UI can show what was removed.
   */
  deleteWorkbook: (id: number) =>
    request<{
      ok: true;
      workbook_id: number;
      filename: string;
      cascade: Record<string, number>;
    }>(`/api/workbooks/${id}`, { method: "DELETE" }),
  /**
   * Load (or refresh) a CRM (Customer Responsibility Matrix) baseline
   * from a local xlsx. The result is a CRM-source ``Baseline`` that
   * callers should attach to a workbook via
   * ``POST /api/workbooks/{id}/overlays`` — CRMs are overlays, not
   * primary assessment targets.
   *
   * @deprecated Prefer `importOverlay` — the unified front door auto-
   * classifies and dispatches to this loader for CRM-shaped files.
   */
  loadCrm: (args: {
    framework_id: number;
    path: string;
    system_id?: number | null;
    name?: string | null;
  }) =>
    request<CrmLoadResult>("/api/baselines/crm/load", {
      method: "POST",
      body: JSON.stringify(args),
    }),
  /**
   * Compute (and persist) the three-tier CRM suspicion report for a
   * workbook's attached CRM overlay. 404 when no CRM is attached — the
   * UI treats that as the silent path (banner hidden), not an error.
   *
   * Side effect: each call grows the IsolationForest training corpus
   * by one row. That's intentional — the suspicion compute is the
   * natural place to capture features.
   */
  getCrmSuspicion: (workbookId: number) =>
    request<CrmSuspicionReport>(`/api/baselines/${workbookId}/crm-suspicion`),
  /**
   * Pure-read fetch of the most recently persisted suspicion log for a
   * workbook. Distinct from ``getCrmSuspicion`` — no embedder calls, no
   * IsolationForest scoring, no corpus growth. Used by the post-attach
   * toast in ``Workbooks.tsx`` to re-surface a prior verdict on every
   * CRM re-upload without paying the compute cost. 404 = never computed,
   * which the toast handles silently.
   */
  getLatestCrmSuspicion: (workbookId: number) =>
    request<CrmSuspicionLatest>(
      `/api/baselines/${workbookId}/crm-suspicion/latest`,
    ),
  /**
   * Mark a previously-computed suspicion log as a false positive (i.e.
   * the assessor reviewed the flagged CRM and decided the heuristics
   * over-fired). The flag becomes a label for the v0.3+ supervised
   * "CRM lied" classifier, so capture review notes when available.
   */
  markSuspicionFalsePositive: (logId: number, body: MarkSuspicionFalsePositiveBody = {}) =>
    request<{ ok: true; suspicion_log_id: number; marked_at: string }>(
      `/api/baselines/crm-suspicion/${logId}/mark`,
      { method: "PATCH", body: JSON.stringify(body) },
    ),

  // Controls + assessments
  getControl: (id: number, workbookId?: number) =>
    request<ControlDetail>(
      `/api/controls/${id}${workbookId !== undefined ? `?workbook_id=${workbookId}` : ""}`,
    ),
  /**
   * Append-only audit trail of every OdpAssignment value overwrite for
   * this control, grouped per ODP id. Empty when no overwrites have
   * occurred — the UI's OdpHistoryCard hides itself in that case.
   */
  getOdpHistory: (controlId: number) =>
    request<OdpHistoryGroup[]>(`/api/controls/${controlId}/odp-history`),
  listAssessments: (controlId: number, workbookId?: number) =>
    request<Assessment[]>(
      `/api/controls/${controlId}/assessments${workbookId ? `?workbook_id=${workbookId}` : ""}`,
    ),
  upsertAssessment: (body: AssessmentUpsert, force = false) =>
    request<UpsertAssessmentResult>(
      `/api/controls/assessments${force ? "?force=true" : ""}`,
      {
        method: "POST",
        body: JSON.stringify(body),
      },
    ),
  assessObjective: (workbookId: number, objectiveId: number) =>
    request<AssessmentDecision>("/api/controls/assess", {
      method: "POST",
      body: JSON.stringify({ workbook_id: workbookId, objective_id: objectiveId }),
    }),
  /**
   * Audit v1 — full verdict→evidence trace for a single Assessment.
   * Returns empty trace + evidence_shown arrays for deterministic
   * short-circuits (rule_8a/8b/8c, CRM, abstain). Citations are populated
   * only when `audit_citations_enabled` was on at decision time.
   */
  getAssessmentAudit: (assessmentId: number) =>
    request<AssessmentAudit>(
      `/api/controls/assessments/${assessmentId}/audit`,
    ),
  /**
   * Auto-assess every in-scope CCI in the workbook in one server-side run.
   * One shared LLM client (stable cache key) + one RunRecorder (single
   * AssessmentRun row). See backend route docstring for the full pipeline.
   */
  assessBatch: (body: AssessBatchRequest) =>
    request<AssessBatchResult>("/api/controls/assess-batch", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  /**
   * Polled while ``assessBatch`` is in flight so the UI can render a
   * determinate progress bar instead of an indeterminate spinner. Returns
   * ``{ active: false }`` when no batch is running for the workbook so the
   * polling hook can collapse the bar without special-casing 404s.
   */
  getAssessBatchProgress: (workbookId: number) =>
    request<AssessBatchProgress>(
      `/api/controls/assess-batch/progress?workbook_id=${workbookId}`,
    ),
  applyAssessmentToWorkbook: (assessmentId: number, close = false) =>
    request<{
      ok: boolean;
      assessment_id: number;
      written_to_workbook_at: string;
      summary: {
        rows_written: number;
        cells_changed: number;
        workbook: string;
        sheet: string;
        changes: Record<string, string>;
      };
    }>("/api/controls/assessments/apply", {
      method: "POST",
      body: JSON.stringify({ assessment_id: assessmentId, close }),
    }),

  /**
   * Bulk-apply every writable assessment for a workbook in one xlwings session.
   *
   * Optional ``family`` / ``assessmentIds`` mirror the Controls grid filter
   * state so the user's "Apply N to workbook" click writes exactly the rows
   * they're looking at. ``needs_review`` and already-written rows are
   * SILENTLY SKIPPED server-side — the response counters explain the gap
   * between "candidates considered" and "rows actually written".
   */
  applyAssessmentsBatchToWorkbook: (params: {
    workbookId: number;
    family?: string | null;
    assessmentIds?: number[];
    skipWritten?: boolean;
    close?: boolean;
  }) =>
    request<{
      ok: boolean;
      workbook_id: number;
      applied: number;
      skipped_needs_review: number;
      skipped_already_written: number;
      skipped_no_excel_row: number;
      summary: {
        rows_written: number;
        cells_changed: number;
        skipped_needs_review: number;
        workbook: string;
        sheet: string;
        changes: Record<string, string>;
      } | null;
    }>("/api/controls/assessments/apply-batch", {
      method: "POST",
      body: JSON.stringify({
        workbook_id: params.workbookId,
        family: params.family ?? null,
        assessment_ids: params.assessmentIds ?? null,
        skip_written: params.skipWritten ?? true,
        close: params.close ?? false,
      }),
    }),

  // Evidence
  /**
   * Walk any registered source (folder, NFS, zip, cloud, SharePoint).
   *
   * Now fire-and-poll: the route returns a job id immediately and the
   * UI polls ``getIngestJob`` for live counters. Use ``getActiveIngestJob``
   * on page load to reattach if the user refreshes mid-run.
   */
  ingestSource: (source: IngestSourceSpec, workbookId: number) =>
    request<IngestJobStart>("/api/evidence/ingest", {
      method: "POST",
      // workbook_id is mandatory under per-workbook hard-scoping (PR 2):
      // the backend refuses to create global-pool Evidence rows. Always
      // the currently-open workbook — the UI never lets the user ingest
      // without one open.
      body: JSON.stringify({ source, workbook_id: workbookId }),
    }),
  /** Convenience wrapper for the most common case — a local folder. */
  ingestFolder: (folder: string, workbookId: number, recursive = true) =>
    request<IngestJobStart>("/api/evidence/ingest", {
      method: "POST",
      body: JSON.stringify({
        source: { type: "folder", path: folder, recursive },
        workbook_id: workbookId,
      }),
    }),
  /** Poll one ingest job by id; returns live counters or final summary. */
  getIngestJob: (jobId: string) =>
    request<IngestJob>(`/api/evidence/ingest/jobs/${jobId}`),
  /**
   * The currently-running ingest job, if any. Returns null when idle —
   * the UI uses that signal to hide the progress strip on page load.
   */
  getActiveIngestJob: () =>
    request<IngestJob | null>("/api/evidence/ingest/jobs/active"),
  /**
   * Wipe the entire evidence index (Evidence + EvidenceTag + StigFinding).
   * Workbooks/assessments/catalog are NOT touched. Re-ingest to repopulate.
   */
  clearEvidence: (purgeText = true) =>
    request<{
      ok: boolean;
      evidence_removed: number;
      tags_removed: number;
      findings_removed: number;
      text_files_removed: number;
    }>(`/api/evidence?purge_text=${purgeText}`, { method: "DELETE" }),
  /**
   * Delete one Evidence row + its dependent rows (tags / STIG findings /
   * POAM links) + the supersession back-pointer. Cached extracted text
   * is unlinked on disk by default. Mirrors clearEvidence for a single id.
   */
  deleteEvidence: (id: number, purgeText = true) =>
    request<{
      ok: boolean;
      evidence_id: number;
      tags_removed: number;
      findings_removed: number;
      poam_links_removed: number;
      text_file_removed: boolean;
    }>(`/api/evidence/${id}?purge_text=${purgeText}`, { method: "DELETE" }),
  listEvidence: (
    opts: {
      kind?: string;
      archive_uri?: string;
      workbook_id?: number;
      framework_id?: number;
      control_id?: number;
      component_id?: number;
      asset_id?: number;
      boundary_id?: number;
      limit?: number;
    } = {},
  ) => {
    const q = new URLSearchParams();
    if (opts.kind) q.set("kind", opts.kind);
    if (opts.archive_uri) q.set("archive_uri", opts.archive_uri);
    if (opts.workbook_id != null) q.set("workbook_id", String(opts.workbook_id));
    if (opts.framework_id != null) q.set("framework_id", String(opts.framework_id));
    if (opts.control_id != null) q.set("control_id", String(opts.control_id));
    if (opts.component_id != null) q.set("component_id", String(opts.component_id));
    if (opts.asset_id != null) q.set("asset_id", String(opts.asset_id));
    if (opts.boundary_id != null) q.set("boundary_id", String(opts.boundary_id));
    q.set("limit", String(opts.limit ?? 200));
    return request<Evidence[]>(`/api/evidence?${q.toString()}`);
  },
  getEvidence: (id: number) =>
    request<Evidence & { tags: EvidenceTag[] }>(`/api/evidence/${id}`),
  evidenceForObjective: (objectiveId: number) =>
    request<EvidenceForObjective[]>(`/api/evidence/by-objective/${objectiveId}`),
  // Flip the manual asset-list flag (and optional label) on one artifact.
  // Server clears the label when is_asset_list is unset, so a re-flag
  // starts blank — the UI doesn't need to send null explicitly.
  setAssetList: (
    id: number,
    body: { is_asset_list: boolean; asset_list_label?: string | null },
  ) =>
    request<Evidence>(`/api/evidence/${id}/asset-list`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  // Hostname-set cross-check across user-flagged asset lists. Returns
  // empty arrays when fewer than two lists are flagged; the UI panel
  // uses that as the cue to collapse itself.
  getCrosscheck: (workbookId: number) =>
    request<CrossCheckResult>(
      `/api/evidence/crosscheck?workbook_id=${workbookId}`,
    ),

  // ---- Boundary docs (Sweep Context page) ------------------------
  //
  // Companion to setAssetList — mirror the pattern. Server clears the
  // kind label and the workbook scope when is_boundary_doc is unset.
  setBoundaryDoc: (
    id: number,
    body: {
      is_boundary_doc: boolean;
      boundary_doc_kind?: string | null;
      workbook_id?: number | null;
    },
  ) =>
    request<Evidence>(`/api/evidence/${id}/boundary-doc`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  // List boundary-flagged Evidence rows for a workbook — drives the
  // attached-docs table on the Sweep Context page.
  listBoundaryDocs: (workbookId: number) =>
    request<Evidence[]>(`/api/workbooks/${workbookId}/boundary-docs`),
  // Sync single-file ingest used by the Sweep Context drop-zone.
  // Returns the new Evidence row immediately (no fire-and-poll job) so
  // the table can update inline. The boundary-doc flags are stamped on
  // the row in the same write so a refresh isn't needed.
  ingestFile: (body: {
    path: string;
    is_boundary_doc?: boolean;
    boundary_doc_kind?: string | null;
    workbook_id?: number | null;
  }) =>
    request<Evidence>(`/api/evidence/ingest-file`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // ---- Scope: Components / Assets / BoundarySegments (v0.3) ------
  //
  // Per-workbook CRUD backing the Evidence-tab filter chips. POST is
  // idempotent — a key collision returns the existing row rather than
  // 4xx, so the UI can post blindly. DELETE cascades link rows.
  listComponents: (workbookId: number) =>
    request<Component[]>(`/api/components?workbook_id=${workbookId}`),
  createComponent: (body: {
    workbook_id: number;
    name: string;
    kind?: ComponentKind;
    parent_component_id?: number | null;
    description?: string | null;
  }) =>
    request<Component>(`/api/components`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  deleteComponent: (id: number) =>
    request<{ deleted: boolean; component_id: number }>(
      `/api/components/${id}`,
      { method: "DELETE" },
    ),

  listAssets: (workbookId: number) =>
    request<Asset[]>(`/api/assets?workbook_id=${workbookId}`),
  createAsset: (body: {
    workbook_id: number;
    hostname: string;
    fqdn?: string | null;
    ip_address?: string | null;
    cpe?: string | null;
    os_family?: string | null;
    asset_class?: AssetClass;
    source?: AssetSource;
  }) =>
    request<Asset>(`/api/assets`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  deleteAsset: (id: number) =>
    request<{ deleted: boolean; asset_id: number }>(
      `/api/assets/${id}`,
      { method: "DELETE" },
    ),

  listBoundarySegments: (workbookId: number) =>
    request<BoundarySegment[]>(
      `/api/boundary-segments?workbook_id=${workbookId}`,
    ),
  createBoundarySegment: (body: {
    workbook_id: number;
    name: string;
    kind?: string | null;
    description?: string | null;
  }) =>
    request<BoundarySegment>(`/api/boundary-segments`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  deleteBoundarySegment: (id: number) =>
    request<{ deleted: boolean; segment_id: number }>(
      `/api/boundary-segments/${id}`,
      { method: "DELETE" },
    ),

  // ---- Per-Evidence M2M scope link management --------------------
  listEvidenceComponents: (evidenceId: number) =>
    request<EvidenceComponentLink[]>(
      `/api/evidence/${evidenceId}/components`,
    ),
  attachEvidenceComponents: (evidenceId: number, ids: number[]) =>
    request<{ ok: boolean; created: number }>(
      `/api/evidence/${evidenceId}/components`,
      { method: "POST", body: JSON.stringify({ ids }) },
    ),
  detachEvidenceComponent: (evidenceId: number, componentId: number) =>
    request<{ ok: boolean }>(
      `/api/evidence/${evidenceId}/components/${componentId}`,
      { method: "DELETE" },
    ),

  listEvidenceAssets: (evidenceId: number) =>
    request<EvidenceAssetLink[]>(`/api/evidence/${evidenceId}/assets`),
  attachEvidenceAssets: (evidenceId: number, ids: number[]) =>
    request<{ ok: boolean; created: number }>(
      `/api/evidence/${evidenceId}/assets`,
      { method: "POST", body: JSON.stringify({ ids }) },
    ),
  detachEvidenceAsset: (evidenceId: number, assetId: number) =>
    request<{ ok: boolean }>(
      `/api/evidence/${evidenceId}/assets/${assetId}`,
      { method: "DELETE" },
    ),

  listEvidenceBoundarySegments: (evidenceId: number) =>
    request<EvidenceBoundaryLink[]>(
      `/api/evidence/${evidenceId}/boundary-segments`,
    ),
  attachEvidenceBoundarySegments: (evidenceId: number, ids: number[]) =>
    request<{ ok: boolean; created: number }>(
      `/api/evidence/${evidenceId}/boundary-segments`,
      { method: "POST", body: JSON.stringify({ ids }) },
    ),
  detachEvidenceBoundarySegment: (
    evidenceId: number,
    boundarySegmentId: number,
  ) =>
    request<{ ok: boolean }>(
      `/api/evidence/${evidenceId}/boundary-segments/${boundarySegmentId}`,
      { method: "DELETE" },
    ),

  // Runs
  listRuns: (limit = 50) => request<Run[]>(`/api/runs?limit=${limit}`),
  getRun: (id: number) => request<Run>(`/api/runs/${id}`),

  // Metrics — cross-run Accuracy/Cost/Time rollups + reference benchmarks.
  // /api/metrics includes the full payload (live + mechanisms + reference +
  // rate card); /api/metrics/public is the Nuon-safe variant (same shape,
  // no per-run records). The UI always hits /api/metrics.
  getMetrics: () => request<MetricsPayload>(`/api/metrics`),

  // Reports
  downloadWorkbookSar: async (workbookId: number): Promise<{ blob: Blob; filename: string }> => {
    const res = await fetch(`${baseUrl()}/api/reports/workbook/${workbookId}/sar.pdf`);
    if (!res.ok) {
      let detail = res.statusText;
      try {
        const text = await res.text();
        try {
          const body = JSON.parse(text) as { detail?: unknown };
          if (typeof body.detail === "string") detail = body.detail;
        } catch {
          detail = text || detail;
        }
      } catch {
        // keep statusText
      }
      throw new ApiError(res.status, res.statusText, null, `${res.status} ${detail}`);
    }
    const blob = await res.blob();
    const disp = res.headers.get("content-disposition") ?? "";
    const match = disp.match(/filename="?([^";]+)"?/i);
    const filename = match?.[1] ?? `sar-${workbookId}.pdf`;
    return { blob, filename };
  },

  // Settings
  getSettings: () => request<AppSettings>("/api/settings"),
  updateSettings: (body: SettingsUpdate) =>
    request<{ ok: boolean }>("/api/settings", {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  setAnthropicKey: (key: string) =>
    request<{ ok: boolean }>("/api/settings/anthropic-key", {
      method: "POST",
      body: JSON.stringify({ key }),
    }),
  clearAnthropicKey: () =>
    request<{ ok: boolean }>("/api/settings/anthropic-key", { method: "DELETE" }),
  setAnthropicGatewayToken: (token: string) =>
    request<{ ok: boolean }>("/api/settings/anthropic-gateway-token", {
      method: "POST",
      body: JSON.stringify({ token }),
    }),
  clearAnthropicGatewayToken: () =>
    request<{ ok: boolean }>("/api/settings/anthropic-gateway-token", { method: "DELETE" }),
  testAnthropicKey: () =>
    request<{
      ok: boolean;
      model: string;
      reply: string;
      input_tokens: number;
      output_tokens: number;
    }>("/api/settings/anthropic-key/test", { method: "POST" }),
  // Probes the gateway path EXPLICITLY — no resolver fallback to the personal
  // key. 400 means the gateway URL or token slot is empty; 404 with a
  // model-not-found hint is common against gateways that only proxy one
  // pinned model id (e.g. the GD gateway → claude-4-7-opus).
  testAnthropicGateway: () =>
    request<{
      ok: boolean;
      model: string;
      base_url: string;
      reply: string;
      input_tokens: number;
      output_tokens: number;
    }>("/api/settings/anthropic-gateway/test", { method: "POST" }),
  listAnthropicModels: () =>
    request<{
      base_url: string;
      models: { id: string; display_name: string | null; created_at: string | null }[];
    }>("/api/settings/anthropic-models"),
  // ---- OpenAI ----------------------------------------------------------
  // Symmetric to the Anthropic helpers above, including the corporate /
  // high-side gateway-token slot (separate from the personal sk-... key so
  // dev workstations that talk to both endpoints don't have to overwrite
  // one to use the other).
  setOpenAIKey: (key: string) =>
    request<{ ok: boolean }>("/api/settings/openai-key", {
      method: "POST",
      body: JSON.stringify({ key }),
    }),
  clearOpenAIKey: () =>
    request<{ ok: boolean }>("/api/settings/openai-key", { method: "DELETE" }),
  setOpenAIGatewayToken: (token: string) =>
    request<{ ok: boolean }>("/api/settings/openai-gateway-token", {
      method: "POST",
      body: JSON.stringify({ token }),
    }),
  clearOpenAIGatewayToken: () =>
    request<{ ok: boolean }>("/api/settings/openai-gateway-token", { method: "DELETE" }),
  testOpenAIKey: () =>
    request<{
      ok: boolean;
      model: string;
      base_url: string;
      reply: string;
      input_tokens: number;
      output_tokens: number;
    }>("/api/settings/openai-key/test", { method: "POST" }),
  // Probes the gateway path EXPLICITLY — symmetric to testAnthropicGateway.
  testOpenAIGateway: () =>
    request<{
      ok: boolean;
      model: string;
      base_url: string;
      reply: string;
      input_tokens: number;
      output_tokens: number;
    }>("/api/settings/openai-gateway/test", { method: "POST" }),
  listOpenAIModels: () =>
    request<{
      base_url: string;
      models: {
        id: string;
        display_name: string | null;
        created_at: string | number | null;
      }[];
    }>("/api/settings/openai-models"),
  // ---- eMASS connector (REST + mTLS, DOUBLE-GATED) --------------------
  emassStatus: () => request<EmassStatus>("/api/emass/status"),
  testEmass: (body?: EmassTestBody) =>
    request<EmassTestResponse>("/api/emass/test", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  setEmassKey: (key: string) =>
    request<{ ok: boolean }>("/api/settings/emass-key", {
      method: "POST",
      body: JSON.stringify({ key }),
    }),
  clearEmassKey: () =>
    request<{ ok: boolean }>("/api/settings/emass-key", { method: "DELETE" }),

  // ---- Confluence DC connector (PAT, DOUBLE-GATED) --------------------
  // v0.4+ gated. /status reads config + keyring presence only; /test does
  // a real probe with the saved PAT against the first configured space key.
  confluenceStatus: () => request<ConfluenceStatus>("/api/confluence/status"),
  testConfluence: (body?: ConfluenceTestBody) =>
    request<ConfluenceTestResponse>("/api/confluence/test", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  setConfluencePat: (key: string) =>
    request<{ ok: boolean }>("/api/settings/confluence-pat", {
      method: "POST",
      body: JSON.stringify({ key }),
    }),
  clearConfluencePat: () =>
    request<{ ok: boolean }>("/api/settings/confluence-pat", { method: "DELETE" }),

  // ---- SharePoint connector -------------------------------------------
  // Two-phase device-code: first call usually returns {pending:true,
  // user_code, verification_uri}; user signs in at microsoft.com/devicelogin;
  // next call returns {ok:true, ...}. Subsequent calls go silent (cached
  // refresh token).
  sharepointStatus: () => request<SharePointStatus>("/api/sharepoint/status"),
  testSharePoint: (body?: SharePointTestBody) =>
    request<SharePointTestResponse>("/api/sharepoint/test", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  signOutSharePoint: () =>
    request<{ ok: boolean; cache_removed: boolean }>("/api/sharepoint/sign-out", {
      method: "POST",
    }),
  // Cancel an in-flight device-code sign-in WITHOUT wiping the token cache.
  // Use this when the device code expired (15min) or the browser was abandoned
  // mid-flow and you want a fresh code without losing a prior refresh token.
  cancelSharePointSignIn: () =>
    request<{ ok: boolean }>("/api/sharepoint/cancel", {
      method: "POST",
    }),
  // One-level peek into a SharePoint folder. Cheap (single Graph round-trip
  // plus pagination); call freely on every drill-in click. ``subfolder`` is
  // relative to the configured scan root, so the first call passes "" and
  // drill-ins pass whatever path the previous response returned.
  browseSharePoint: (body?: SharePointBrowseBody) =>
    request<SharePointBrowseResponse>("/api/sharepoint/browse", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  // Filename search across the scan root. Mirrors nist-assessor's
  // find-evidence pattern — parses the query into USD doc numbers, control
  // IDs, and keywords, BFS-walks the scan root (depth-capped), and returns
  // hits annotated with which token matched. Cheap enough to call on every
  // Enter press; the assessor cherry-picks files to ingest from the result.
  searchSharePoint: (body: SharePointSearchBody) =>
    request<SharePointSearchResponse>("/api/sharepoint/search", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  // Boundary-aware triage — no-download enumeration + Graph search +
  // per-candidate scoring against the workbook's host inventory, in-scope
  // control families, CRM responsibility table, and doc-number prefixes.
  // Returns ranked candidates with proposed CCI mappings; the caller hands
  // the confirmed subset to `/api/sharepoint/ingest` via `file_paths`.
  // Synchronous — bounded by max_search_queries (default 30) × Graph round-
  // trip (~200ms) ≈ 6s worst case; OK to call on a button click.
  sweepSharePoint: (body: SharePointSweepBody, signal?: AbortSignal) =>
    request<SharePointSweepResponse>("/api/sharepoint/sweep", {
      method: "POST",
      body: JSON.stringify(body),
      signal,
    }),
  // Bulk-ingest every candidate under a swept folder, bypassing per-row
  // triage. Returns {job_id} once the ingest job is queued, or a pending
  // device-code dict when auth must be (re)established first.
  ingestAllFromFolder: (body: SweepIngestAllBody) =>
    request<SweepIngestAllResponse>("/api/sharepoint/sweep/ingest-all", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  // Latest SweepRun for a workbook — powers the Sweep Context footer.
  // Returns `null` (not 404) when the workbook has never been swept.
  getLatestSweepRun: (workbookId: number) =>
    request<LatestSweepRun | null>(
      `/api/sharepoint/sweep-runs/${workbookId}/latest`,
    ),
  // Write-only audit endpoint — assessor's check/uncheck decisions in
  // SweepTriageDialog at Ingest click. Used by the online-SGD recalibrator
  // to drift sweep weights toward observed behavior. Fire-and-forget from
  // the UI; failures don't block the ingest.
  recordSweepDecisions: (body: SweepDecisionsBody) =>
    request<SweepDecisionsResult>("/api/sharepoint/sweep/decisions", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  // Priority-link bookmarks the user pastes from the SharePoint browser
  // address bar — surfaces as a "Jump to…" sidebar in the Browse dialog.
  // PUT semantics: full replacement on save.
  listSharePointPriorityLinks: () =>
    request<{ links: SharePointPriorityLink[] }>("/api/sharepoint/priority-links"),
  setSharePointPriorityLinks: (links: SharePointPriorityLink[]) =>
    request<{ ok: boolean; links: SharePointPriorityLink[] }>(
      "/api/sharepoint/priority-links",
      { method: "PUT", body: JSON.stringify({ links }) },
    ),

  // ---- ServiceNow GRC connector --------------------------------------------
  // Cheap status (config + keyring only); /test does a real probe of the SN
  // Table API. Secret material flows through dedicated keyring endpoints so
  // OAuth client_secret / Basic password never round-trip through GET
  // /api/settings.
  servicenowGrcStatus: () =>
    request<ServicenowGrcStatus>("/api/servicenow_grc/status"),
  testServicenowGrc: (body?: ServicenowGrcTestBody) =>
    request<ServicenowGrcTestResponse>("/api/servicenow_grc/test", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  setServicenowGrcOauthSecret: (body: ServicenowGrcSecretBody) =>
    request<{ ok: boolean }>("/api/servicenow_grc/oauth-secret", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  clearServicenowGrcOauthSecret: () =>
    request<{ ok: boolean }>("/api/servicenow_grc/oauth-secret", {
      method: "DELETE",
    }),
  setServicenowGrcBasicPassword: (body: ServicenowGrcSecretBody) =>
    request<{ ok: boolean }>("/api/servicenow_grc/basic-password", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  clearServicenowGrcBasicPassword: () =>
    request<{ ok: boolean }>("/api/servicenow_grc/basic-password", {
      method: "DELETE",
    }),

  // ---- Archer (RSA Archer / GRC) connector ----------------------------
  // /status is cheap (config + single keyring lookup, no network); /test
  // does a real session-login round-trip against the configured instance.
  // Password is written/cleared through the dedicated /password endpoints
  // so credentials never travel through the generic SettingsUpdate model.
  archerStatus: () => request<ArcherStatus>("/api/archer/status"),
  testArcher: (body?: ArcherTestBody) =>
    request<ArcherTestResponse>("/api/archer/test", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  setArcherPassword: (body: ArcherPasswordBody) =>
    request<{ ok: boolean }>("/api/archer/password", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  clearArcherPassword: () =>
    request<{ ok: boolean; cleared?: boolean }>("/api/archer/password", {
      method: "DELETE",
    }),

  // ---- Splunk connector ----------------------------------------------------
  // Cheap status probe — reads config + keyring only, NEVER a network call.
  // Settings card calls this on every render to update its badge, so a
  // network round-trip here would slow page paint and surface transient
  // Splunk 5xx as a persistent red banner. Real reachability check is /test.
  splunkStatus: () => request<SplunkStatus>("/api/splunk/status"),
  // Real service.info() round-trip. Body fields override saved config so the
  // user can probe a candidate host/token before clicking Save.
  testSplunk: (body?: SplunkTestBody) =>
    request<SplunkTestResponse>("/api/splunk/test", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  // Token lives in the OS keyring; never round-trips through /settings.
  setSplunkToken: (token: string) =>
    request<{ ok: boolean }>("/api/splunk/token", {
      method: "POST",
      body: JSON.stringify({ token }),
    }),
  clearSplunkToken: () =>
    request<{ ok: boolean }>("/api/splunk/token", { method: "DELETE" }),

  // ---- GitLab connector -----------------------------------------------
  // No device-code dance — GitLab uses a personal access token stored in
  // the OS keyring per-host (KEYRING_KEY_GITLAB_PREFIX + sanitized host)
  // or the GITLAB_TOKEN env var. Status reads config + keyring only;
  // /test does a real network probe and resolves every project to a
  // commit SHA so the UI can show per-project health.
  gitlabStatus: () => request<GitlabStatus>("/api/gitlab/status"),
  testGitlab: (body?: GitlabTestBody) =>
    request<GitlabTestResponse>("/api/gitlab/test", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),

  // ---- Jira connector -------------------------------------------------
  // Double-gated v0.4+. /status reads config + keyring only (no network);
  // /test rounds-trips /rest/api/2/myself through the underlying
  // JiraSource.test_connection() helper. PAT lives in the OS keyring;
  // set via POST /api/jira/pat, clear via DELETE.
  jiraStatus: () => request<JiraStatus>("/api/jira/status"),
  testJira: (body?: JiraTestBody) =>
    request<JiraTestResponse>("/api/jira/test", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  setJiraPat: (pat: string) =>
    request<{ ok: boolean }>("/api/jira/pat", {
      method: "POST",
      body: JSON.stringify({ pat }),
    }),
  clearJiraPat: () =>
    request<{ ok: boolean }>("/api/jira/pat", { method: "DELETE" }),

  // ---- Tenable connector --------------------------------------------------
  // Cheap status read — no network. The card uses it to gate "Test" / "Save"
  // buttons and to render the two `*_key_set` indicators without exposing
  // raw values. The Evidence source picker uses `configured && enabled` to
  // decide whether to enable the Tenable option.
  tenableStatus: () => request<TenableStatus>("/api/tenable/status"),
  // Live probe — constructs a TenableSource with the effective config +
  // keyring secrets and calls `test_connection()` (cheapest authenticated
  // endpoint per flavor). Returns whoami on success; raises HTTP 400/401
  // with a redacted hint otherwise.
  testTenable: (body?: TenableTestBody) =>
    request<TenableTestResponse>("/api/tenable/test", {
      method: "POST",
      body: JSON.stringify(body ?? {}),
    }),
  // Keyring CRUD for the two halves of the API keyset. Both follow the
  // same pattern as `setEmassKey` — the Settings card never reads back the
  // raw value, only the `*_key_set` booleans from `/status` change.
  setTenableAccessKey: (key: string) =>
    request<{ ok: boolean }>("/api/settings/tenable-access-key", {
      method: "POST",
      body: JSON.stringify({ key }),
    }),
  clearTenableAccessKey: () =>
    request<{ ok: boolean }>("/api/settings/tenable-access-key", {
      method: "DELETE",
    }),
  setTenableSecretKey: (key: string) =>
    request<{ ok: boolean }>("/api/settings/tenable-secret-key", {
      method: "POST",
      body: JSON.stringify({ key }),
    }),
  clearTenableSecretKey: () =>
    request<{ ok: boolean }>("/api/settings/tenable-secret-key", {
      method: "DELETE",
    }),

  // ---- POAMs ---------------------------------------------------------------
  // Backend already sorts highest-risk-first, so the UI can render the array
  // verbatim. Both filters are optional; omitting workbook_id returns POAMs
  // across every workbook in the DB.
  listPoams: (opts?: { workbook_id?: number; status?: PoamStatus }) => {
    const qs = new URLSearchParams();
    if (opts?.workbook_id !== undefined) qs.set("workbook_id", String(opts.workbook_id));
    if (opts?.status !== undefined) qs.set("status", opts.status);
    const query = qs.toString();
    return request<PoamSummary[]>(`/api/poams${query ? `?${query}` : ""}`);
  },
  listPoamRiskLevels: () => request<RiskLevelInfo[]>("/api/poams/risk-levels"),
  getPoam: (id: number) => request<PoamDetail>(`/api/poams/${id}`),
  listPoamRiskHistory: (id: number) =>
    request<PoamRiskHistoryEntry[]>(`/api/poams/${id}/risk-history`),
  /** Force-refresh bypasses the LLM decision cache and overwrites any
   * prior entry — used by the "Refresh suggestion" button. */
  getPoamResidualSuggestion: (id: number, opts?: { force_refresh?: boolean }) =>
    request<PoamResidualSuggestion>(
      `/api/poams/${id}/residual-suggestion${
        opts?.force_refresh ? "?force_refresh=true" : ""
      }`,
    ),
  applyPoamResidualSuggestion: (
    id: number,
    body: { residual_risk: RiskLevel; residual_risk_rationale: string },
  ) =>
    request<PoamDetail>(`/api/poams/${id}/apply-residual-suggestion`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  generatePoams: (workbook_id: number) =>
    request<GeneratePoamsResult>("/api/poams/generate", {
      method: "POST",
      body: JSON.stringify({ workbook_id }),
    }),
  exportPoams: (args: {
    workbook_id: number;
    output_path: string;
    system_name?: string | null;
  }) =>
    request<ExportPoamsResult>("/api/poams/export", {
      method: "POST",
      body: JSON.stringify(args),
    }),
  importPoams: (args: { workbook_id: number; poam_file_path: string }) =>
    request<ImportPoamsResult>("/api/poams/import", {
      method: "POST",
      body: JSON.stringify(args),
    }),
  /** Write in-scope controls into a copy of the user's eMASS template via
   * xlwings. Requires Excel desktop app on the operator's machine. */
  exportControlsEmass: (args: ExportControlsEmassRequest) =>
    request<ControlExportResultDto>("/api/controls/export/emass", {
      method: "POST",
      body: JSON.stringify(args),
    }),
  /** Emit a fresh xlsx mirroring the current Controls list view (one row per
   * objective, needs_review rows included). No template; openpyxl path. */
  exportControlsWorking: (args: ExportControlsWorkingRequest) =>
    request<ControlExportResultDto>("/api/controls/export/working", {
      method: "POST",
      body: JSON.stringify(args),
    }),
  /** Upsert Assessments from an operator-filled eMASS Test Result template
   * (column N status / P tester / O date / Q narrative). Import only — NCs
   * land needs_review=False so they flow into the Generate POAMs step. */
  importControlsNarratives: (args: ImportControlsNarrativesRequest) =>
    request<NarrativeImportResultDto>("/api/controls/import/narratives", {
      method: "POST",
      body: JSON.stringify(args),
    }),
  createPoam: (body: CreatePoamRequest) =>
    request<PoamDetail>("/api/poams", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updatePoam: (id: number, body: UpdatePoamRequest) =>
    request<PoamDetail>(`/api/poams/${id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deletePoam: (id: number) =>
    request<{ ok: boolean; id: number }>(`/api/poams/${id}`, { method: "DELETE" }),
  deleteAllPoams: (opts?: { workbook_id?: number; status?: PoamStatus }) => {
    const qs = new URLSearchParams();
    if (opts?.workbook_id !== undefined) qs.set("workbook_id", String(opts.workbook_id));
    if (opts?.status !== undefined) qs.set("status", opts.status);
    const query = qs.toString();
    return request<{ ok: boolean; deleted: number }>(
      `/api/poams${query ? `?${query}` : ""}`,
      { method: "DELETE" },
    );
  },
  linkPoamObjective: (poam_id: number, objective_id: number) =>
    request<{ ok: boolean; added: boolean }>(`/api/poams/${poam_id}/objectives`, {
      method: "POST",
      body: JSON.stringify({ objective_id }),
    }),
  unlinkPoamObjective: (poam_id: number, objective_id: number) =>
    request<{ ok: boolean }>(`/api/poams/${poam_id}/objectives/${objective_id}`, {
      method: "DELETE",
    }),
  /**
   * Link an Evidence row to a POAM. Calling this with an evidence_id that's
   * already linked is treated as a note-edit (backend behavior — same endpoint
   * doubles as PATCH so the UI doesn't need a separate "edit note" affordance).
   * Hence the optional `note_updated` flag on the response.
   */
  linkPoamEvidence: (poam_id: number, evidence_id: number, note?: string | null) =>
    request<{ ok: boolean; added: boolean; note_updated?: boolean }>(
      `/api/poams/${poam_id}/evidence`,
      {
        method: "POST",
        body: JSON.stringify({ evidence_id, note: note ?? null }),
      },
    ),
  unlinkPoamEvidence: (poam_id: number, evidence_id: number) =>
    request<{ ok: boolean }>(`/api/poams/${poam_id}/evidence/${evidence_id}`, {
      method: "DELETE",
    }),
  createPoamMilestone: (poam_id: number, body: MilestoneCreateRequest) =>
    request<PoamMilestone>(`/api/poams/${poam_id}/milestones`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updatePoamMilestone: (
    poam_id: number,
    milestone_id: number,
    body: MilestoneUpdateRequest,
  ) =>
    request<PoamMilestone>(`/api/poams/${poam_id}/milestones/${milestone_id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deletePoamMilestone: (poam_id: number, milestone_id: number) =>
    request<{ ok: boolean; id: number }>(
      `/api/poams/${poam_id}/milestones/${milestone_id}`,
      { method: "DELETE" },
    ),

  // ---------------------------------------------------------------------------
  // Automation — per-workbook evidence-pull schedules
  // ---------------------------------------------------------------------------

  listAutomationSchedules: (workbookId?: number) =>
    request<AutomationSchedule[]>(
      workbookId !== undefined
        ? `/api/automation?workbook_id=${workbookId}`
        : "/api/automation",
    ),
  getAutomationSchedule: (id: number) =>
    request<AutomationSchedule>(`/api/automation/${id}`),
  createAutomationSchedule: (body: AutomationScheduleCreate) =>
    request<AutomationSchedule>("/api/automation", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateAutomationSchedule: (id: number, patch: AutomationSchedulePatch) =>
    request<AutomationSchedule>(`/api/automation/${id}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    }),
  deleteAutomationSchedule: (id: number) =>
    request<void>(`/api/automation/${id}`, {
      method: "DELETE",
    }),
  runAutomationScheduleNow: (id: number) =>
    request<AutomationSchedule>(`/api/automation/${id}/run-now`, {
      method: "POST",
    }),
};
