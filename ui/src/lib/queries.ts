/**
 * TanStack Query hooks — thin wrappers around `api.*` so screens stay
 * declarative and we get caching/refetching for free.
 */

import { useRef } from "react";

import {
  useMutation,
  useQuery,
  useQueryClient,
  type UseMutationOptions,
} from "@tanstack/react-query";

import { toast } from "@/components/ui/toaster";
import { humanize } from "./errors";

import {
  api,
  type AppSettings,
  type AssessBatchProgress,
  type AssessBatchRequest,
  type AssessBatchResult,
  type Assessment,
  type AssessmentAudit,
  type AssessmentDecision,
  type AssessmentUpsert,
  type Baseline,
  type BaselineControlRow,
  type BaselineDetail,
  type BaselineObjective,
  type BaselineRefreshResult,
  type CatalogStatus,
  type Control,
  type ControlDetail,
  type ControlStatusRollup,
  type ColLStatusRollup,
  type CreatePoamRequest,
  type CrmLoadResult,
  type CrossCheckResult,
  type MarkSuspicionFalsePositiveBody,
  type MetricsPayload,
  type SupersessionChain,
  type DisaCciLoadResult,
  type OverlayImportResult,
  type OverlayKind,
  type ProgramControlsLoadResult,
  type Evidence,
  type EvidenceForObjective,
  type Framework,
  type IngestJob,
  type IngestJobStart,
  type Objective,
  type MilestoneCreateRequest,
  type MilestoneUpdateRequest,
  type PoamDetail,
  type PoamMilestone,
  type PoamResidualSuggestion,
  type PoamRiskHistoryEntry,
  type PoamStatus,
  type PoamSummary,
  type RiskLevel,
  type ReviewQueueItem,
  type RiskLevelInfo,
  type Run,
  type ScopeLabelsResponse,
  type SettingsUpdate,
  type SharePointBrowseBody,
  type SharePointBrowseResponse,
  type SharePointSearchBody,
  type SharePointSearchResponse,
  type SharePointSweepBody,
  type SharePointSweepResponse,
  type SweepIngestAllBody,
  type SweepIngestAllResponse,
  type SweepDecisionsBody,
  type SweepDecisionsResult,
  type SharePointPriorityLink,
  type SharePointStatus,
  type SharePointTestBody,
  type SharePointTestResponse,
  type ServicenowGrcSecretBody,
  type ServicenowGrcStatus,
  type ServicenowGrcTestBody,
  type ServicenowGrcTestResponse,
  type ArcherStatus,
  type ArcherTestBody,
  type ArcherTestResponse,
  type ArcherPasswordBody,
  type SplunkStatus,
  type SplunkTestBody,
  type SplunkTestResponse,
  type GitlabStatus,
  type GitlabTestBody,
  type GitlabTestResponse,
  type JiraStatus,
  type JiraTestBody,
  type JiraTestResponse,
  type TenableStatus,
  type TenableTestBody,
  type TenableTestResponse,
  type PendingSystemContextResponse,
  type PromotePendingResult,
  type SystemContext,
  type SystemContextFreeformInput,
  type SystemContextUpsertResult,
  type UpdatePoamRequest,
  type Workbook,
  type WorkbookBaselineSummary,
  type WorkbookOverlay,
  type WorkbookSummary,
  type OverlayMembership,
  type ProgramControlSourceGroup,
  type OdpHistoryGroup,
  type Asset,
  type BoundarySegment,
  type Component,
  type EvidenceAssetLink,
  type EvidenceBoundaryLink,
  type EvidenceComponentLink,
  type AutomationSchedule,
  type AutomationScheduleCreate,
  type AutomationSchedulePatch,
} from "./api";

export const qk = {
  health: ["health"] as const,
  frameworks: ["frameworks"] as const,
  // server reads from a static registry, so this is `staleTime: Infinity`
  // and never invalidates within a session.
  scopeLabels: ["scope-labels"] as const,
  catalogStatus: ["catalog", "status"] as const,
  requirementSources: ["catalog", "requirement-sources"] as const,
  /**
   * Per-path overlay sheet preview. The path is part of the key so
   * switching the xlsx in the Settings card invalidates the dropdown
   * naturally — no manual invalidation needed.
   */
  overlaySheets: (path: string) => ["catalog", "overlay-sheets", path] as const,
  supersessionChains: (workbookId: number) =>
    ["supersession", "chains", workbookId] as const,
  controls: (frameworkId: number) => ["controls", frameworkId] as const,
  control: (controlId: number) => ["control", controlId] as const,
  objectives: (controlId: number) => ["control", controlId, "objectives"] as const,
  // Separate cache key for the heavier objectives+mappings payload so the
  // lightweight drill-down view and the CSV export don't fight over the same
  // cache entry (Mappings would be undefined for one consumer and present for
  // the other, causing flicker on tab switches).
  objectivesWithMappings: (controlId: number) =>
    ["control", controlId, "objectives", "with-mappings"] as const,
  // Program-specific controls (overlay "shall" statements like SDA-127)
  // grouped by RequirementSource for one base control. Framework filter
  // participates in the key so multi-framework DBs don't cross-cache.
  programControlsForControl: (controlId: number, frameworkId: number | undefined) =>
    ["control", controlId, "program-controls", frameworkId ?? "any"] as const,
  // Append-only OdpAuditLog rows for one control, grouped per ODP. Shares the
  // `["control", id, ...]` prefix so a future workbook re-ingest mutation can
  // wildcard-invalidate all per-control caches in one shot.
  odpHistory: (controlId: number) =>
    ["control", controlId, "odp-history"] as const,
  workbooks: ["workbooks"] as const,
  workbookSummary: (id: number) => ["workbook", id, "summary"] as const,
  workbookControlStatus: (id: number) => ["workbook", id, "control-status"] as const,
  workbookColLStatus: (id: number) => ["workbook", id, "col-l-status"] as const,
  workbookReviewQueue: (id: number) => ["workbook", id, "review-queue"] as const,
  workbookOverlays: (id: number) => ["workbook", id, "overlays"] as const,
  workbookOverlayMembership: (id: number) =>
    ["workbook", id, "overlay-membership"] as const,
  systemContext: (workbookId: number) =>
    ["system-context", workbookId] as const,
  // Pending pre-workbook SystemContext singleton — at most one row exists
  // (enforced by ix_systemcontext_pending_singleton). Same prefix as the
  // per-workbook key so a wildcard ["system-context"] invalidation hits both.
  pendingSystemContext: ["system-context", "pending"] as const,
  // Boundary docs attached to a workbook — drives the Sweep Context
  // page's attached-docs table. Keyed on workbook so flipping is_boundary_doc
  // on or off invalidates the panel for just that workbook.
  boundaryDocs: (workbookId: number) =>
    ["workbook", workbookId, "boundary-docs"] as const,
  assessments: (controlId: number, workbookId?: number) =>
    ["assessments", controlId, workbookId ?? null] as const,
  // Audit v1 — per-Assessment verdict→evidence trace. Keyed only on the
  // assessment_id because the payload is fully derived from the persisted
  // trace/evidence-shown/citation rows on that specific Assessment; no
  // workbook/control scoping needed.
  assessmentAudit: (assessmentId: number) =>
    ["assessment", assessmentId, "audit"] as const,
  // v0.3 catalog-aware key. Order is (workbookId, frameworkId, kind, controlId,
  // componentId, assetId, boundaryId) so existing bare `["evidence"]` prefix
  // invalidations still match — the prefix is the literal string, not the full
  // tuple. All args are optional; absent = "all". The chip-driven scope filters
  // (component/asset/boundary) participate in the cache key so flipping a chip
  // doesn't share data with the un-filtered view.
  evidence: (
    opts: {
      workbookId?: number;
      frameworkId?: number;
      kind?: string;
      controlId?: number;
      componentId?: number;
      assetId?: number;
      boundaryId?: number;
    } = {},
  ) =>
    [
      "evidence",
      opts.workbookId ?? "all",
      opts.frameworkId ?? "all",
      opts.kind ?? "all",
      opts.controlId ?? "all",
      opts.componentId ?? "all",
      opts.assetId ?? "all",
      opts.boundaryId ?? "all",
    ] as const,
  evidenceById: (id: number) => ["evidence", id] as const,
  evidencePaged: (
    opts: {
      workbookId?: number;
      kind?: string;
      pageSize?: number;
      page?: number;
    } = {},
  ) =>
    [
      "evidence-paged",
      opts.workbookId ?? "all",
      opts.kind ?? "all",
      opts.pageSize ?? 100,
      opts.page ?? 0,
    ] as const,
  // Per-evidence M2M scope link lists (chip rows on the Evidence card).
  evidenceComponents: (evidenceId: number) =>
    ["evidence", evidenceId, "components"] as const,
  evidenceAssets: (evidenceId: number) =>
    ["evidence", evidenceId, "assets"] as const,
  evidenceBoundarySegments: (evidenceId: number) =>
    ["evidence", evidenceId, "boundary-segments"] as const,
  // Scope-entity lists backing the Evidence-tab filter chips. Keyed on
  // workbook so the chip menu only shows entities for the active workbook.
  components: (workbookId: number) =>
    ["components", workbookId] as const,
  assets: (workbookId: number) => ["assets", workbookId] as const,
  boundarySegments: (workbookId: number) =>
    ["boundary-segments", workbookId] as const,
  evidenceForObjective: (objectiveId: number, workbookId?: number) =>
    ["evidence-for-objective", objectiveId, workbookId ?? null] as const,
  // Workbook-scoped cross-check; v0.1 backend ignores workbookId but we
  // still key on it so multi-workbook isolation lands without a refactor.
  crosscheck: (workbookId: number) =>
    ["evidence", "crosscheck", workbookId] as const,
  settings: ["settings"] as const,
  baselines: ["baselines"] as const,
  baseline: (id: number) => ["baseline", id] as const,
  baselineObjectives: (id: number, inScopeOnly: boolean) =>
    ["baseline", id, "objectives", inScopeOnly] as const,
  baselineControls: (id: number, inScopeOnly: boolean) =>
    ["baseline", id, "controls", inScopeOnly] as const,
  // Workbook-scoped (not baseline-scoped) — the suspicion compute walks
  // every CRM overlay attached to a workbook and the route handler picks
  // the most-recent. Keying on workbook_id matches that scope so attaching
  // a new CRM invalidates cleanly.
  crmSuspicion: (workbookId: number) =>
    ["crm-suspicion", workbookId] as const,
  runs: (limit: number) => ["runs", limit] as const,
  run: (id: number) => ["run", id] as const,
  // Metrics — single global key (the route aggregates ALL AssessmentRun rows,
  // no per-workbook scoping today). Mutations that complete a /assess-batch
  // invalidate this so the tab refreshes without a manual reload.
  metrics: ["metrics"] as const,
  // POAMs — filter args participate in the cache key so changing the
  // workbook/status filter doesn't bleed into other views.
  poams: (workbookId?: number, status?: PoamStatus) =>
    ["poams", workbookId ?? null, status ?? null] as const,
  poam: (id: number) => ["poam", id] as const,
  poamRiskLevels: ["poam", "risk-levels"] as const,
  poamRiskHistory: (id: number) => ["poam", id, "risk-history"] as const,
  poamResidualSuggestion: (id: number) =>
    ["poam", id, "residual-suggestion"] as const,
  // Automation schedules — keyed on workbookId (or null for the global list)
  // so switching workbooks never leaks one workbook's schedules into another.
  automationSchedules: (workbookId?: number) =>
    ["automation", "schedules", workbookId ?? null] as const,
  automationSchedule: (id: number) => ["automation", "schedule", id] as const,
};

export const useHealth = () => useQuery({ queryKey: qk.health, queryFn: api.health });

export const useFrameworks = () =>
  useQuery<Framework[]>({ queryKey: qk.frameworks, queryFn: api.listFrameworks });

/**
 * Canonical scope-label vocabulary for CRM uploads. Served from a static
 * registry, so `staleTime: Infinity` — it loads once per session and only
 * refetches on a full app reload.
 */
export const useScopeLabels = () =>
  useQuery<ScopeLabelsResponse>({
    queryKey: qk.scopeLabels,
    queryFn: api.getScopeLabels,
    staleTime: Infinity,
  });

export const useCatalogStatus = () =>
  useQuery<CatalogStatus>({ queryKey: qk.catalogStatus, queryFn: api.catalogStatus });

/**
 * Toggle a framework's display/selection gate. Presentation-only on the
 * backend, but several read surfaces derive from the framework set, so we
 * invalidate all of them:
 *   - qk.frameworks      — the Settings catalog list + every picker
 *   - qk.catalogStatus   — the Workbooks status card (framework counts)
 *   - qk.workbooks       — workbook rows badge their framework name
 */
export const useSetFrameworkEnabled = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      frameworkId,
      enabled,
    }: {
      frameworkId: number;
      enabled: boolean;
    }) => api.setFrameworkEnabled(frameworkId, enabled),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.frameworks });
      qc.invalidateQueries({ queryKey: qk.catalogStatus });
      qc.invalidateQueries({ queryKey: qk.workbooks });
    },
  });
};

export const useControls = (frameworkId: number | undefined) =>
  useQuery<Control[]>({
    queryKey: frameworkId ? qk.controls(frameworkId) : ["controls", "none"],
    queryFn: () => api.listControls(frameworkId!),
    enabled: !!frameworkId,
  });

export const useControl = (
  controlId: number | undefined,
  workbookId?: number,
) =>
  useQuery<ControlDetail>({
    queryKey: controlId
      ? [...qk.control(controlId), { workbook: workbookId ?? null }]
      : ["control", "none"],
    queryFn: () => api.getControl(controlId!, workbookId),
    enabled: !!controlId,
  });

/**
 * CCIs / assessment objectives for a single control. Lazy — only fires when
 * a controlId is given, so it's safe to use behind a row-level expander.
 */
export const useObjectives = (
  controlId: number | undefined,
  includeMappings = false,
  workbookId?: number,
) =>
  useQuery<Objective[]>({
    queryKey: controlId
      ? [
          ...qk.objectives(controlId),
          { mappings: includeMappings, workbook: workbookId ?? null },
        ]
      : ["control", "none", "objectives"],
    queryFn: () => api.listObjectives(controlId!, includeMappings, workbookId),
    enabled: !!controlId,
  });

/**
 * Program-Specific Controls for a base control — overlay "shall" statements
 * (e.g. SDA-127) grouped by RequirementSource. Pass the active workbook's
 * framework_id so a multi-framework DB doesn't bleed (an r4 SDA overlay
 * onto an r5 control). Empty array when the control has no overlay coverage.
 */
export const useProgramControlsForControl = (
  controlId: number | undefined,
  frameworkId: number | undefined,
) =>
  useQuery<ProgramControlSourceGroup[]>({
    queryKey: controlId
      ? qk.programControlsForControl(controlId, frameworkId)
      : ["control", "none", "program-controls"],
    queryFn: () => api.listProgramControlsForControl(controlId!, frameworkId),
    enabled: !!controlId,
  });

/**
 * ODP value-overwrite audit history for one control, grouped per ODP. The
 * backend returns []` when no rows exist (typical for first-ingest workbooks
 * and overlays that haven't yet been overwritten) — the consuming card hides
 * itself on empty rather than rendering a "(none)" placeholder.
 */
export const useOdpHistory = (controlId: number | undefined) =>
  useQuery<OdpHistoryGroup[]>({
    queryKey: controlId ? qk.odpHistory(controlId) : ["control", "none", "odp-history"],
    queryFn: () => api.getOdpHistory(controlId!),
    enabled: !!controlId,
  });

export const useWorkbooks = () =>
  useQuery<Workbook[]>({ queryKey: qk.workbooks, queryFn: api.listWorkbooks });

export const useWorkbookSummary = (id: number | undefined) =>
  useQuery<WorkbookSummary>({
    queryKey: id ? qk.workbookSummary(id) : ["workbook", "none", "summary"],
    queryFn: () => api.workbookSummary(id!),
    enabled: !!id,
  });

export const useWorkbookControlStatus = (id: number | undefined) =>
  useQuery<ControlStatusRollup[]>({
    queryKey: id ? qk.workbookControlStatus(id) : ["workbook", "none", "control-status"],
    queryFn: () => api.workbookControlStatus(id!),
    enabled: !!id,
  });

export const useWorkbookColLStatus = (id: number | undefined) =>
  useQuery<ColLStatusRollup[]>({
    queryKey: id ? qk.workbookColLStatus(id) : ["workbook", "none", "col-l-status"],
    queryFn: () => api.workbookColLStatus(id!),
    enabled: !!id,
  });

/**
 * v0.2 Review Queue — list of every abstained Assessment in the workbook,
 * pre-sorted by review_reason category. Invalidated by useAssessBatch and
 * useUpsertAssessment (both already invalidate `["assessments"]`, but the
 * review queue is keyed under `["workbook", id, "review-queue"]` so it
 * needs its own invalidation hooks — wired below in those mutations).
 */
export const useWorkbookReviewQueue = (id: number | undefined) =>
  useQuery<ReviewQueueItem[]>({
    queryKey: id ? qk.workbookReviewQueue(id) : ["workbook", "none", "review-queue"],
    queryFn: () => api.workbookReviewQueue(id!),
    enabled: !!id,
  });

export const useWorkbookOverlays = (id: number | undefined) =>
  useQuery<WorkbookOverlay[]>({
    queryKey: id ? qk.workbookOverlays(id) : ["workbook", "none", "overlays"],
    queryFn: () => api.listWorkbookOverlays(id!),
    enabled: !!id,
  });

export const useWorkbookOverlayMembership = (id: number | undefined) =>
  useQuery<OverlayMembership>({
    queryKey: id
      ? qk.workbookOverlayMembership(id)
      : ["workbook", "none", "overlay-membership"],
    queryFn: () => api.workbookOverlayMembership(id!),
    enabled: !!id,
  });

export const useAttachOverlay = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      workbookId,
      baselineId,
      note,
    }: {
      workbookId: number;
      baselineId: number;
      note?: string;
    }) => api.attachWorkbookOverlay(workbookId, baselineId, note),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: qk.workbookOverlays(vars.workbookId) });
      qc.invalidateQueries({
        queryKey: qk.workbookOverlayMembership(vars.workbookId),
      });
      // List response carries overlay_baseline_ids — refresh so chips appear.
      qc.invalidateQueries({ queryKey: qk.workbooks });
      // CRM attaches backfill Assessment rows on the server (provider /
      // inherited / N-A short-circuits). Drop the rollup + per-control
      // assessments cache so the Controls grid renders the new verdicts
      // without a page refresh.
      qc.invalidateQueries({
        queryKey: qk.workbookControlStatus(vars.workbookId),
      });
      // Attach can flip a control's flex-slice picture (col-L chip), same as
      // detach — keep the On-Prem (Col L) column fresh.
      qc.invalidateQueries({
        queryKey: qk.workbookColLStatus(vars.workbookId),
      });
      qc.invalidateQueries({ queryKey: ["assessments"] });
      // Server-side attach auto-fires compute_and_persist_crm_suspicion on
      // CRM overlays (Gap B). Drop the cached suspicion log so the banner
      // refetches the freshly-persisted score instead of showing the stale
      // (or null) prior log.
      qc.invalidateQueries({
        queryKey: qk.crmSuspicion(vars.workbookId),
      });
    },
  });
};

export const useDetachOverlay = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      workbookId,
      baselineId,
    }: {
      workbookId: number;
      baselineId: number;
    }) => api.detachWorkbookOverlay(workbookId, baselineId),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: qk.workbookOverlays(vars.workbookId) });
      qc.invalidateQueries({
        queryKey: qk.workbookOverlayMembership(vars.workbookId),
      });
      qc.invalidateQueries({ queryKey: qk.workbooks });
      // Detach now PURGES the CRM's contribution server-side (its
      // AssessmentImplementation slices + telemetry, recomputing/removing
      // affected parents). Mirror attach's invalidations so the UI reflects the
      // reverted verdicts instead of showing phantom rows: control-status +
      // col-L chips, the assessments cache, and the CRM-suspicion banner.
      qc.invalidateQueries({
        queryKey: qk.workbookControlStatus(vars.workbookId),
      });
      qc.invalidateQueries({
        queryKey: qk.workbookColLStatus(vars.workbookId),
      });
      qc.invalidateQueries({ queryKey: ["assessments"] });
      qc.invalidateQueries({ queryKey: qk.crmSuspicion(vars.workbookId) });
    },
  });
};

// ---------------------------------------------------------------------------
// SystemContext — per-workbook freeform seed for boundary-aware sweeps.
// ---------------------------------------------------------------------------

export const useSystemContext = (workbookId: number | undefined) =>
  useQuery<SystemContext | null>({
    queryKey: workbookId
      ? qk.systemContext(workbookId)
      : ["system-context", "none"],
    queryFn: () => api.getSystemContext(workbookId!),
    enabled: !!workbookId,
  });

export const useUpsertSystemContext = (
  opts?: UseMutationOptions<
    SystemContextUpsertResult,
    Error,
    { workbookId: number; body: SystemContextFreeformInput }
  >,
) => {
  const qc = useQueryClient();
  // Destructure caller's onSuccess BEFORE spreading so our invalidation
  // composes instead of being silently clobbered (see feedback_mutation_opts_spread_order).
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ workbookId, body }) =>
      api.upsertSystemContext(workbookId, body),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({ queryKey: qk.systemContext(vars.workbookId) });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

export const useResetSystemContext = (
  opts?: UseMutationOptions<
    { reset: boolean; workbook_id: number },
    Error,
    { workbookId: number }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ workbookId }) => api.resetSystemContext(workbookId),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({ queryKey: qk.systemContext(vars.workbookId) });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

/**
 * Clear the v0.2 sweep cap counter on a workbook. Invalidates the workbook
 * list so the SystemContext banner re-reads `sweep_attempts` and the amber
 * 2/2 styling drops back to "0 of 2" without a manual refetch.
 */
export const useResetSweepAttempts = (
  opts?: UseMutationOptions<
    { sweep_attempts: number },
    Error,
    { workbookId: number }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ workbookId }) => api.resetSweepAttempts(workbookId),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({ queryKey: qk.workbooks });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

/**
 * Outcome-tied confidence bump (+0.05 per accepted artifact, clamped at 1.0).
 * Called from SweepTriageDialog after a successful ingest start. Invalidates
 * the SystemContext query so the confidence bar advances without a refetch.
 */
export const useBumpSystemContextConfidence = (
  opts?: UseMutationOptions<
    { bumped: boolean; confidence?: number; reason?: string },
    Error,
    { workbookId: number; accepted_count: number }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ workbookId, accepted_count }) =>
      api.bumpSystemContextConfidence(workbookId, accepted_count),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({ queryKey: qk.systemContext(vars.workbookId) });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

// ---------------------------------------------------------------------------
// Pending pre-workbook SystemContext — singleton (workbook_id IS NULL).
// Drives the Sweep Context page when no workbook is open yet, so an
// assessor can drop SSP/diagram/ATO docs before picking a workbook.
// Promoted onto a Workbook automatically when one opens (see useOpenWorkbook
// below) or explicitly via usePromotePendingSystemContext.
// ---------------------------------------------------------------------------

export const usePendingSystemContext = () =>
  useQuery<PendingSystemContextResponse>({
    queryKey: qk.pendingSystemContext,
    queryFn: () => api.getPendingSystemContext(),
  });

export const useUpsertPendingSystemContext = (
  opts?: UseMutationOptions<
    SystemContextUpsertResult,
    Error,
    { body: SystemContextFreeformInput }
  >,
) => {
  const qc = useQueryClient();
  // Destructure caller's onSuccess BEFORE spreading so our invalidation
  // composes instead of being silently clobbered (see feedback_mutation_opts_spread_order).
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ body }) => api.upsertPendingSystemContext(body),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({ queryKey: qk.pendingSystemContext });
      // Pending boundary docs are Evidence rows with workbook_id IS NULL;
      // invalidate the broad evidence key so any list that filters on them
      // refetches. Mirrors the per-workbook upsert hook's behavior.
      qc.invalidateQueries({ queryKey: ["evidence"] });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

/**
 * Explicit promote — fired from the Sweep Context page banner when an
 * assessor opens a workbook mid-session and wants pending docs reparented.
 * Auto-promote inside useOpenWorkbook covers the natural "open workbook
 * first" flow; this hook is the belt-and-suspenders for everything else.
 */
export const usePromotePendingSystemContext = (
  opts?: UseMutationOptions<
    PromotePendingResult,
    Error,
    { workbookId: number }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ workbookId }) => api.promotePendingSystemContext(workbookId),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({ queryKey: qk.pendingSystemContext });
      qc.invalidateQueries({ queryKey: qk.systemContext(vars.workbookId) });
      qc.invalidateQueries({ queryKey: qk.boundaryDocs(vars.workbookId) });
      // Prefix invalidation — hits workbookSummary/controlStatus/etc. for
      // this workbook in one shot.
      qc.invalidateQueries({ queryKey: ["workbook", vars.workbookId] });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

/**
 * Discard the pending SystemContext and any pending boundary-doc Evidence
 * rows. Fired from the "Discard pending scope" affordance in the promote
 * banner. Invalidates the pending singleton and the broad evidence key
 * (pending boundary docs are workbook_id IS NULL Evidence rows).
 */
export const useResetPendingSystemContext = (
  opts?: UseMutationOptions<
    { reset: boolean; context_removed: boolean; boundary_docs_removed: number },
    Error,
    void
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: () => api.resetPendingSystemContext(),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({ queryKey: qk.pendingSystemContext });
      qc.invalidateQueries({ queryKey: ["evidence"] });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

/**
 * Pending-mode mirror of useBumpSystemContextConfidence — fired from the
 * pending-flavored SweepTriageDialog after the assessor accepts judge-
 * surfaced artifacts. +0.05 per accepted artifact, clamped at 1.0.
 */
export const useBumpPendingSystemContextConfidence = (
  opts?: UseMutationOptions<
    { bumped: boolean; confidence?: number; reason?: string },
    Error,
    { accepted_count: number }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ accepted_count }) =>
      api.bumpPendingSystemContextConfidence(accepted_count),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({ queryKey: qk.pendingSystemContext });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

export const useAssessments = (controlId: number | undefined, workbookId?: number) =>
  useQuery<Assessment[]>({
    queryKey: controlId
      ? qk.assessments(controlId, workbookId)
      : ["assessments", "none", workbookId ?? null],
    queryFn: () => api.listAssessments(controlId!, workbookId),
    enabled: !!controlId,
  });

/**
 * Audit v1 — fetch the full verdict→evidence trace for a single Assessment.
 *
 * Disabled when `assessmentId` is null/undefined so the Audit trail accordion
 * can be mounted lazily on ControlDetail without firing a request until the
 * user actually expands it. Stays cached after first fetch — the underlying
 * trace/evidence-shown/citation rows are immutable per assessment_id (a
 * re-assess writes a new Assessment row with a new id).
 */
export const useAssessmentAudit = (assessmentId: number | null | undefined) =>
  useQuery<AssessmentAudit>({
    queryKey:
      assessmentId != null
        ? qk.assessmentAudit(assessmentId)
        : ["assessment", "none", "audit"],
    queryFn: () => api.getAssessmentAudit(assessmentId!),
    enabled: assessmentId != null,
  });

/**
 * v0.3 catalog-aware evidence list. All filters are optional; absent =
 * "all" in the cache key (see qk.evidence). Backend filter chain:
 * workbook_id → framework_id → control_id → component/asset/boundary M2M.
 * Pass `frameworkId` to enable the Evidence tab's default "Mapped to active
 * catalog" view; drop it for the "Show all" toggle. The component/asset/
 * boundary filters back the per-chip narrowing on the Evidence card.
 */
export const useEvidence = (
  opts: {
    workbookId?: number;
    frameworkId?: number;
    kind?: string;
    controlId?: number;
    componentId?: number;
    assetId?: number;
    boundaryId?: number;
  } = {},
) =>
  useQuery<Evidence[]>({
    queryKey: qk.evidence(opts),
    queryFn: () =>
      api.listEvidence({
        workbook_id: opts.workbookId,
        framework_id: opts.frameworkId,
        kind: opts.kind,
        control_id: opts.controlId,
        component_id: opts.componentId,
        asset_id: opts.assetId,
        boundary_id: opts.boundaryId,
      }),
    // Gate on an active workbook. Without this the query fires with
    // workbook_id undefined, and the backend returns evidence across ALL
    // workbooks ("not mapping to current workbook"). The Evidence route
    // passes the open workbook's id; once it resolves the query runs.
    enabled: opts.workbookId != null,
  });

/**
 * Paginated evidence list for the Evidence page. Returns the current page of
 * rows PLUS the pre-limit total (from the X-Total-Count header) so the UI can
 * render "page N of M". ``page`` is 0-based. ``keepPreviousData`` keeps the
 * old page visible while the next loads, so paging doesn't flash empty.
 */
export const useEvidencePaged = (
  opts: {
    workbookId?: number;
    kind?: string;
    page?: number;
    pageSize?: number;
  } = {},
) => {
  const pageSize = opts.pageSize ?? 100;
  const page = opts.page ?? 0;
  return useQuery<{ items: Evidence[]; total: number }>({
    queryKey: qk.evidencePaged({
      workbookId: opts.workbookId,
      kind: opts.kind,
      pageSize,
      page,
    }),
    queryFn: () =>
      api.listEvidencePaged({
        workbook_id: opts.workbookId,
        kind: opts.kind,
        limit: pageSize,
        offset: page * pageSize,
      }),
    enabled: opts.workbookId != null,
    placeholderData: (prev) => prev,
  });
};

export const useEvidenceForObjective = (
  objectiveId: number | undefined,
  workbookId?: number,
) =>
  useQuery<EvidenceForObjective[]>({
    queryKey: objectiveId
      ? qk.evidenceForObjective(objectiveId, workbookId)
      : ["evidence-for-objective", "none"],
    queryFn: () => api.evidenceForObjective(objectiveId!, workbookId),
    enabled: !!objectiveId,
  });

// Asset-list cross-check for the inventory-family controls. Returns
// empty arrays when fewer than two artifacts are flagged; the UI uses
// that as the cue to collapse the panel.
export const useCrosscheck = (workbookId: number | undefined) =>
  useQuery<CrossCheckResult>({
    queryKey: workbookId ? qk.crosscheck(workbookId) : ["evidence", "crosscheck", "none"],
    queryFn: () => api.getCrosscheck(workbookId!),
    enabled: !!workbookId,
  });

// Flip the manual asset-list flag (and optional label) on one artifact.
// Invalidates evidence list AND the cross-check so the toggle's effect
// shows up immediately in both places.
export const useSetAssetList = (
  opts?: UseMutationOptions<
    Evidence,
    Error,
    { id: number; is_asset_list: boolean; asset_list_label?: string | null }
  >,
) => {
  const qc = useQueryClient();
  // Destructure `onSuccess` out of opts so it composes with our invalidation
  // instead of clobbering it. Spreading `...opts` *after* our `onSuccess`
  // would overwrite the cache-invalidation hook entirely — that bug silently
  // ate every refetch when callers passed their own `onSuccess` for toasts.
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ id, is_asset_list, asset_list_label }) =>
      api.setAssetList(id, { is_asset_list, asset_list_label }),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["evidence"] });
      callerOnSuccess?.(...args);
    },
  });
};

// ---------------------------------------------------------------------------
// Boundary docs (Sweep Context page)
// ---------------------------------------------------------------------------

/**
 * Evidence rows flagged as boundary docs for a workbook. Drives the attached-
 * docs table on the Sweep Context page. Same Evidence shape as the rest
 * of the app — just pre-filtered server-side.
 */
export const useBoundaryDocs = (workbookId: number | undefined) =>
  useQuery<Evidence[]>({
    queryKey: workbookId
      ? qk.boundaryDocs(workbookId)
      : ["workbook", "none", "boundary-docs"],
    queryFn: () => api.listBoundaryDocs(workbookId!),
    enabled: !!workbookId,
  });

/**
 * Flip the is_boundary_doc flag (and optional kind / workbook) on an existing
 * Evidence row. Mirrors useSetAssetList — same destructure-before-spread rule
 * so caller-supplied toasts don't clobber the cache invalidation.
 */
export const usePatchBoundaryDoc = (
  opts?: UseMutationOptions<
    Evidence,
    Error,
    {
      id: number;
      is_boundary_doc: boolean;
      boundary_doc_kind?: string | null;
      workbook_id?: number | null;
    }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ id, is_boundary_doc, boundary_doc_kind, workbook_id }) =>
      api.setBoundaryDoc(id, { is_boundary_doc, boundary_doc_kind, workbook_id }),
    ...restOpts,
    onSuccess: (...args) => {
      // Invalidate the whole evidence cache (any kind filter) plus every
      // workbook's boundary-docs panel — we don't know which workbook the
      // row belonged to before the flip, so the broad invalidation is safer
      // than trying to thread the id through. Also bust the pending
      // singleton: flipping a doc on/off boundary can move it into or out
      // of the pending payload, and SweepContext reads boundary_docs from
      // that payload when no workbook is open.
      qc.invalidateQueries({ queryKey: ["evidence"] });
      qc.invalidateQueries({ queryKey: ["workbook"] });
      qc.invalidateQueries({ queryKey: qk.pendingSystemContext });
      callerOnSuccess?.(...args);
    },
  });
};

/**
 * Sync single-file ingest. Used by the Sweep Context page's drop-zone
 * to land a boundary doc and immediately get an Evidence row back (the
 * folder-walk path is async/fire-and-poll, which is wrong for "I just
 * picked one file"). Invalidates evidence + boundary-docs so the table
 * re-renders with the new row.
 */
export const useIngestFile = (
  opts?: UseMutationOptions<
    Evidence,
    Error,
    {
      path: string;
      is_boundary_doc?: boolean;
      boundary_doc_kind?: string | null;
      workbook_id?: number | null;
    }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body) => api.ingestFile(body),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["evidence"] });
      qc.invalidateQueries({ queryKey: ["workbook"] });
      // Pending-mode ingest: workbook_id=null + is_boundary_doc=true rows
      // land in the pending payload. SweepContext reads docs straight from
      // that payload (not a separate evidence query) when no workbook is
      // open, so without this invalidation the drop appears stuck — the
      // backend row exists but the UI never refetches and the debounced
      // auto-extract never fires (it gates on docs.length).
      qc.invalidateQueries({ queryKey: qk.pendingSystemContext });
      callerOnSuccess?.(...args);
    },
  });
};

// ---------------------------------------------------------------------------
// Scope entities — Component, Asset, BoundarySegment + per-evidence M2M links.
// Back the Evidence tab's filter chips and (eventually) dedicated management
// UIs. CRUD-only for v0.1 per the v0.3-Ready Evidence Model plan; richer
// editors land in v0.2 alongside the CRM ingestion overlay.
// ---------------------------------------------------------------------------

export const useComponents = (workbookId: number | undefined) =>
  useQuery<Component[]>({
    queryKey: workbookId ? qk.components(workbookId) : ["components", "none"],
    queryFn: () => api.listComponents(workbookId!),
    enabled: !!workbookId,
  });

export const useAssets = (workbookId: number | undefined) =>
  useQuery<Asset[]>({
    queryKey: workbookId ? qk.assets(workbookId) : ["assets", "none"],
    queryFn: () => api.listAssets(workbookId!),
    enabled: !!workbookId,
  });

export const useBoundarySegments = (workbookId: number | undefined) =>
  useQuery<BoundarySegment[]>({
    queryKey: workbookId
      ? qk.boundarySegments(workbookId)
      : ["boundary-segments", "none"],
    queryFn: () => api.listBoundarySegments(workbookId!),
    enabled: !!workbookId,
  });

/**
 * Per-evidence M2M link lists. Drive the scope chip rows on the Evidence
 * card. Always keyed on evidence_id — same Evidence row can carry different
 * link sets across workbooks if it gets reattached, but for v0.1 each row
 * lives in one workbook so the cache identity is stable.
 */
export const useEvidenceComponents = (evidenceId: number | undefined) =>
  useQuery<EvidenceComponentLink[]>({
    queryKey: evidenceId
      ? qk.evidenceComponents(evidenceId)
      : ["evidence", "none", "components"],
    queryFn: () => api.listEvidenceComponents(evidenceId!),
    enabled: !!evidenceId,
  });

export const useEvidenceAssets = (evidenceId: number | undefined) =>
  useQuery<EvidenceAssetLink[]>({
    queryKey: evidenceId
      ? qk.evidenceAssets(evidenceId)
      : ["evidence", "none", "assets"],
    queryFn: () => api.listEvidenceAssets(evidenceId!),
    enabled: !!evidenceId,
  });

export const useEvidenceBoundarySegments = (evidenceId: number | undefined) =>
  useQuery<EvidenceBoundaryLink[]>({
    queryKey: evidenceId
      ? qk.evidenceBoundarySegments(evidenceId)
      : ["evidence", "none", "boundary-segments"],
    queryFn: () => api.listEvidenceBoundarySegments(evidenceId!),
    enabled: !!evidenceId,
  });

// --- Scope-entity mutations (create / delete) -----------------------------

export const useCreateComponent = (
  opts?: UseMutationOptions<Component, Error, Parameters<typeof api.createComponent>[0]>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body) => api.createComponent(body),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({ queryKey: qk.components(vars.workbook_id) });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

export const useDeleteComponent = (
  opts?: UseMutationOptions<
    { deleted: boolean; component_id: number },
    Error,
    { id: number; workbookId: number }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ id }) => api.deleteComponent(id),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({ queryKey: qk.components(vars.workbookId) });
      // Component delete also cascades EvidenceComponent rows, so any
      // per-evidence chip list could go stale. Prefix-invalidate.
      qc.invalidateQueries({ queryKey: ["evidence"] });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

export const useCreateAsset = (
  opts?: UseMutationOptions<Asset, Error, Parameters<typeof api.createAsset>[0]>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body) => api.createAsset(body),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({ queryKey: qk.assets(vars.workbook_id) });
      // Cross-check report derives from EvidenceAsset joins; create itself
      // doesn't add links, but keep the invalidation so a follow-up attach
      // mutation chained from the same UI flow stays consistent.
      qc.invalidateQueries({ queryKey: ["evidence", "crosscheck", vars.workbook_id] });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

export const useDeleteAsset = (
  opts?: UseMutationOptions<
    { deleted: boolean; asset_id: number },
    Error,
    { id: number; workbookId: number }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ id }) => api.deleteAsset(id),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({ queryKey: qk.assets(vars.workbookId) });
      qc.invalidateQueries({ queryKey: ["evidence"] });
      qc.invalidateQueries({ queryKey: ["evidence", "crosscheck", vars.workbookId] });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

export const useCreateBoundarySegment = (
  opts?: UseMutationOptions<
    BoundarySegment,
    Error,
    Parameters<typeof api.createBoundarySegment>[0]
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body) => api.createBoundarySegment(body),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({ queryKey: qk.boundarySegments(vars.workbook_id) });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

export const useDeleteBoundarySegment = (
  opts?: UseMutationOptions<
    { deleted: boolean; segment_id: number },
    Error,
    { id: number; workbookId: number }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ id }) => api.deleteBoundarySegment(id),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({ queryKey: qk.boundarySegments(vars.workbookId) });
      qc.invalidateQueries({ queryKey: ["evidence"] });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

// --- Per-evidence M2M attach/detach mutations -----------------------------
// Attach takes a list of ids (idempotent on the backend); detach is per-id.
// Every variant invalidates the matching per-evidence link list AND the
// broad ["evidence"] prefix so any filter-chip-driven list refetches.

export const useAttachEvidenceComponents = (
  opts?: UseMutationOptions<
    { ok: boolean; created: number },
    Error,
    { evidenceId: number; componentIds: number[] }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ evidenceId, componentIds }) =>
      api.attachEvidenceComponents(evidenceId, componentIds),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({ queryKey: qk.evidenceComponents(vars.evidenceId) });
      qc.invalidateQueries({ queryKey: ["evidence"] });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

export const useDetachEvidenceComponent = (
  opts?: UseMutationOptions<
    { ok: boolean },
    Error,
    { evidenceId: number; componentId: number }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ evidenceId, componentId }) =>
      api.detachEvidenceComponent(evidenceId, componentId),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({ queryKey: qk.evidenceComponents(vars.evidenceId) });
      qc.invalidateQueries({ queryKey: ["evidence"] });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

export const useAttachEvidenceAssets = (
  opts?: UseMutationOptions<
    { ok: boolean; created: number },
    Error,
    { evidenceId: number; assetIds: number[] }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ evidenceId, assetIds }) =>
      api.attachEvidenceAssets(evidenceId, assetIds),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({ queryKey: qk.evidenceAssets(vars.evidenceId) });
      qc.invalidateQueries({ queryKey: ["evidence"] });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

export const useDetachEvidenceAsset = (
  opts?: UseMutationOptions<
    { ok: boolean },
    Error,
    { evidenceId: number; assetId: number }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ evidenceId, assetId }) =>
      api.detachEvidenceAsset(evidenceId, assetId),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({ queryKey: qk.evidenceAssets(vars.evidenceId) });
      qc.invalidateQueries({ queryKey: ["evidence"] });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

export const useAttachEvidenceBoundarySegments = (
  opts?: UseMutationOptions<
    { ok: boolean; created: number },
    Error,
    { evidenceId: number; boundarySegmentIds: number[] }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ evidenceId, boundarySegmentIds }) =>
      api.attachEvidenceBoundarySegments(evidenceId, boundarySegmentIds),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({
        queryKey: qk.evidenceBoundarySegments(vars.evidenceId),
      });
      qc.invalidateQueries({ queryKey: ["evidence"] });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

export const useDetachEvidenceBoundarySegment = (
  opts?: UseMutationOptions<
    { ok: boolean },
    Error,
    { evidenceId: number; boundarySegmentId: number }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ evidenceId, boundarySegmentId }) =>
      api.detachEvidenceBoundarySegment(evidenceId, boundarySegmentId),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({
        queryKey: qk.evidenceBoundarySegments(vars.evidenceId),
      });
      qc.invalidateQueries({ queryKey: ["evidence"] });
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

// ---------------------------------------------------------------------------
// Runs
// ---------------------------------------------------------------------------

export const useRuns = (limit = 50) =>
  useQuery<Run[]>({
    queryKey: qk.runs(limit),
    queryFn: () => api.listRuns(limit),
    // Poll while the page is open so incremental flushes from RunRecorder
    // (token counts, ccis_accepted, retry_count) tick up live. Cheap query
    // — LIMIT 100 over a tiny table.
    refetchInterval: 5000,
  });

export const useRun = (id: number | undefined) =>
  useQuery<Run>({
    queryKey: id ? qk.run(id) : ["run", "none"],
    queryFn: () => api.getRun(id!),
    enabled: !!id,
  });

// ---------------------------------------------------------------------------
// Metrics — cross-run rollups (Accuracy / Cost / Time) + reference benchmarks.
// Backed by /api/metrics (in-app) and /api/metrics/public (Nuon-safe).
// ---------------------------------------------------------------------------

export const useMetrics = () =>
  useQuery<MetricsPayload>({ queryKey: qk.metrics, queryFn: () => api.getMetrics() });

/**
 * Auto-detected document supersession chains for one workbook. Enabled only
 * when a workbook is selected (workbookId > 0).
 */
export const useSupersessionChains = (workbookId: number | null) =>
  useQuery<SupersessionChain[]>({
    queryKey: qk.supersessionChains(workbookId ?? 0),
    queryFn: () => api.listSupersessionChains(workbookId as number),
    enabled: workbookId != null && workbookId > 0,
  });

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

type OpenWorkbookResult = Workbook & {
  summary: WorkbookSummary;
  baseline: WorkbookBaselineSummary | null;
  // Populated by the backend's inline auto-promote of any pending
  // pre-workbook SystemContext. Null when nothing was pending.
  pending_promotion: PromotePendingResult | null;
};

export const useOpenWorkbook = (
  opts?: UseMutationOptions<
    OpenWorkbookResult,
    Error,
    { path: string; frameworkId?: number }
  >,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: ({ path, frameworkId }: { path: string; frameworkId?: number }) =>
      api.openWorkbook(path, frameworkId),
    ...restOpts,
    onSuccess: (data, vars, onMutateResult, context) => {
      qc.invalidateQueries({ queryKey: qk.workbooks });
      qc.invalidateQueries({ queryKey: qk.baselines });
      // Reopen reuses the same Workbook row (PK on path) AND the same
      // Baseline row (PK on source_type+source_ref) — see
      // routes/workbooks.py:101-105 and baselines/ccis_workbook.py:117-143.
      // Same IDs means React Query's per-workbook and per-baseline caches
      // survive across reopens, but the underlying rows have just been
      // re-materialized: BaselineControl in_scope flags, ODP assignments,
      // overlay-membership rollups can all have changed. Prefix-invalidate
      // every ["workbook", id, …] and ["baseline", id, …] entry so the
      // Controls grid, overlay-covered filter, PSC column, and ODP badges
      // refetch instead of rendering yesterday's snapshot.
      qc.invalidateQueries({ queryKey: ["workbook", data.id] });
      if (data.baseline?.id) {
        qc.invalidateQueries({ queryKey: ["baseline", data.baseline.id] });
      }
      // Backend may have just auto-promoted a pending pre-workbook
      // SystemContext onto this workbook. When it did, invalidate the
      // pending cache (the singleton is gone) and the newly-populated
      // system-context + boundary-docs caches for this workbook so the
      // Sweep Context page reflects the move on next render.
      if (data.pending_promotion) {
        qc.invalidateQueries({ queryKey: qk.pendingSystemContext });
        qc.invalidateQueries({ queryKey: qk.systemContext(data.id) });
        qc.invalidateQueries({ queryKey: qk.boundaryDocs(data.id) });
      }
      callerOnSuccess?.(data, vars, onMutateResult, context);
    },
  });
};

// ---------------------------------------------------------------------------
// Baselines
// ---------------------------------------------------------------------------

export const useBaselines = () =>
  useQuery<Baseline[]>({ queryKey: qk.baselines, queryFn: api.listBaselines });

export const useBaseline = (id: number | undefined) =>
  useQuery<BaselineDetail>({
    queryKey: id ? qk.baseline(id) : ["baseline", "none"],
    queryFn: () => api.getBaseline(id!),
    enabled: !!id,
  });

export const useBaselineObjectives = (id: number | undefined, inScopeOnly = false) =>
  useQuery<BaselineObjective[]>({
    queryKey: id
      ? qk.baselineObjectives(id, inScopeOnly)
      : ["baseline", "none", "objectives", inScopeOnly],
    queryFn: () => api.listBaselineObjectives(id!, inScopeOnly),
    enabled: !!id,
  });

/**
 * Control-level scoping rows for a baseline. This is the authoritative surface
 * for "which Controls / Control Enhancements are in scope" — the per-objective
 * `in_scope` flag is now inherited from the parent Control, so the Controls
 * grid should fetch this instead of OR-aggregating across CCIs client-side.
 */
export const useBaselineControls = (id: number | undefined, inScopeOnly = false) =>
  useQuery<BaselineControlRow[]>({
    queryKey: id
      ? qk.baselineControls(id, inScopeOnly)
      : ["baseline", "none", "controls", inScopeOnly],
    queryFn: () => api.listBaselineControls(id!, inScopeOnly),
    enabled: !!id,
  });

export const useRefreshBaseline = (
  opts?: UseMutationOptions<BaselineRefreshResult, Error, number>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (id: number) => api.refreshBaseline(id),
    ...restOpts,
    onSuccess: (result, ...rest) => {
      qc.invalidateQueries({ queryKey: qk.baselines });
      qc.invalidateQueries({ queryKey: qk.baseline(result.baseline_id) });
      qc.invalidateQueries({
        queryKey: ["baseline", result.baseline_id, "objectives"],
      });
      qc.invalidateQueries({
        queryKey: ["baseline", result.baseline_id, "controls"],
      });
      callerOnSuccess?.(result, ...rest);
    },
  });
};

type DeleteBaselineResult = {
  ok: true;
  baseline_id: number;
  name: string;
  controls_removed: number;
  objectives_removed: number;
  overlay_attachments_removed: number;
  workbooks_removed: string[];
};

type DeleteWorkbookResult = {
  ok: true;
  workbook_id: number;
  filename: string;
  cascade: Record<string, number>;
};

/**
 * Delete an ingested workbook and every workbook-owned row that hangs off
 * it (assessments, POAMs, sweep state, CRM telemetry, etc.). Evidence and
 * SystemContext rows are kept and just unlinked — those are global pool
 * artifacts the user uploaded and may want to re-use under another workbook.
 *
 * Invalidates workbooks list + baselines (overlay attachments are removed
 * as part of the cascade, so any baseline showing usage counts is stale).
 */
export const useDeleteWorkbook = (
  opts?: UseMutationOptions<DeleteWorkbookResult, Error, number>,
) => {
  const qc = useQueryClient();
  // Destructure onSuccess out BEFORE spreading restOpts so our invalidation
  // wrapper survives — spreading opts after our onSuccess silently clobbers
  // it (memory: mutation_opts_spread_order).
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (id: number) => api.deleteWorkbook(id),
    ...restOpts,
    onSuccess: (result, ...rest) => {
      qc.invalidateQueries({ queryKey: qk.workbooks });
      qc.invalidateQueries({ queryKey: ["workbook"] });
      qc.invalidateQueries({ queryKey: qk.baselines });
      qc.invalidateQueries({ queryKey: ["evidence"] });
      callerOnSuccess?.(result, ...rest);
    },
  });
};

/**
 * Delete a baseline. Backend rejects with 409 if any workbook still points
 * at it as its primary scope — caller's onError gets the detail message
 * verbatim so the toast can name the workbook to fix.
 *
 * Invalidates baselines list + workbooks (a workbook might have had this
 * baseline attached as a reference overlay).
 */
export const useDeleteBaseline = (
  opts?: UseMutationOptions<
    DeleteBaselineResult,
    Error,
    { id: number; force?: boolean }
  >,
) => {
  const qc = useQueryClient();
  // Destructure onSuccess out BEFORE spreading restOpts so our invalidation
  // wrapper survives — spreading opts after our onSuccess silently clobbers
  // it (memory: mutation_opts_spread_order).
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ id, force }: { id: number; force?: boolean }) =>
      api.deleteBaseline(id, force),
    ...restOpts,
    onSuccess: (result, ...rest) => {
      qc.invalidateQueries({ queryKey: qk.baselines });
      qc.invalidateQueries({ queryKey: ["workbooks"] });
      // A workbook bound to (or overlaid by) the deleted baseline keeps the
      // dangling baseline in its per-workbook + overlay-membership caches, and
      // delete_baseline now purges CRM-derived assessments server-side. Drop
      // the ["workbook"] prefix (control-status, col-l-status, overlays,
      // membership) + assessments so dependent views recompute instead of
      // pointing at a baselineId that no longer exists.
      qc.invalidateQueries({ queryKey: ["workbook"] });
      qc.invalidateQueries({ queryKey: ["assessments"] });
      callerOnSuccess?.(result, ...rest);
    },
  });
};

/**
 * Load (or refresh) a CRM (Customer Responsibility Matrix) baseline from
 * a local xlsx. Result is a CRM-source ``Baseline`` that the caller is
 * expected to attach to a workbook via ``useAttachOverlay`` — CRMs are
 * overlays, not primary assessment targets, so we don't pre-attach here
 * (the caller knows which workbook it's working on).
 *
 * onSuccess is destructured before the opts spread so the baselines-list
 * invalidation can't be silently clobbered by a caller-supplied callback
 * (per feedback_mutation_opts_spread_order.md).
 *
 * @deprecated Prefer `useImportOverlay` — the unified front door auto-
 * classifies and dispatches to this loader for CRM-shaped files.
 */
export const useLoadCrm = (
  opts?: UseMutationOptions<
    CrmLoadResult,
    Error,
    {
      framework_id: number;
      path: string;
      system_id?: number | null;
      name?: string | null;
    }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (args) => api.loadCrm(args),
    ...restOpts,
    onSuccess: (result, ...rest) => {
      qc.invalidateQueries({ queryKey: qk.baselines });
      qc.invalidateQueries({ queryKey: qk.baseline(result.baseline_id) });
      callerOnSuccess?.(result, ...rest);
    },
  });
};

/**
 * Three-tier CRM suspicion report for a workbook's attached CRM overlay.
 *
 * Lazy on purpose — the compute walks every in-scope control and may
 * call the embeddings API, so the banner waits for an explicit refetch
 * (button click) rather than firing on mount. The 404 case (no CRM
 * overlay attached) returns ``undefined``; the banner is hidden when
 * the data is falsy, which matches the route's "silent path" contract.
 */
export const useCrmSuspicion = (workbookId: number | null | undefined) =>
  useQuery({
    queryKey: qk.crmSuspicion(workbookId ?? -1),
    queryFn: () => api.getCrmSuspicion(workbookId as number),
    enabled: false, // operator-triggered via refetch
    retry: false, // 404 is the silent path; don't burn retries on it
    staleTime: 60_000,
  });

/**
 * Mark a CrmSuspicionLog as a false positive. The flag becomes a label
 * for the v0.3+ supervised "CRM lied" classifier, so we capture optional
 * review notes alongside the boolean.
 *
 * onSuccess destructured before the spread per feedback_mutation_opts_spread_order.
 */
export const useMarkSuspicionFalsePositive = (
  opts?: UseMutationOptions<
    { ok: true; suspicion_log_id: number; marked_at: string },
    Error,
    { logId: number; workbookId: number; body?: MarkSuspicionFalsePositiveBody }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ logId, body }) => api.markSuspicionFalsePositive(logId, body),
    ...restOpts,
    onSuccess: (result, vars, ...rest) => {
      // Invalidate the workbook's suspicion banner so the next open
      // shows the marked state. (The compute endpoint re-reads the
      // latest log, so a recompute will reflect the false-positive
      // flag in the persisted history.)
      qc.invalidateQueries({ queryKey: qk.crmSuspicion(vars.workbookId) });
      callerOnSuccess?.(result, vars, ...rest);
    },
  });
};

export const useIngestFolder = (
  opts?: UseMutationOptions<
    IngestJobStart,
    Error,
    { folder: string; workbookId: number; recursive?: boolean }
  >,
) => {
  // Ingest is now fire-and-poll — the mutation only kicks off the job
  // and returns its id. ``useIngestJobStatus`` does the polling and the
  // ["evidence"] invalidation runs when that hook sees status="done",
  // so this onSuccess just forwards the job_id to the caller.
  //
  // ``workbookId`` is required: per-workbook hard-scoping (PR 2) forbids
  // global-pool Evidence, so the backend raises if it's missing. Callers
  // pass the currently-open workbook id.
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ folder, workbookId, recursive = true }) =>
      api.ingestFolder(folder, workbookId, recursive),
    ...restOpts,
    onSuccess: (...args) => {
      callerOnSuccess?.(...args);
    },
  });
};

/**
 * Walk a SharePoint document library / subfolder as an evidence source.
 * The site_url / library / folder_path come from Settings → SharePoint;
 * MSAL token cache must already be populated (sign in via the Settings
 * card first). Reuses the same /api/evidence/ingest endpoint as folders
 * — just a different source-spec discriminator.
 */
export const useIngestSharePoint = (
  opts?: UseMutationOptions<
    IngestJobStart,
    Error,
    {
      site_url: string;
      workbookId: number;
      library?: string;
      folder_path?: string;
      /** Cherry-pick: scan-root-relative paths from filename search. */
      file_paths?: string[];
    }
  >,
) => {
  // Fire-and-poll: see ``useIngestFolder`` — invalidation moves to
  // ``useIngestJobStatus`` so the table only refetches once the job
  // actually completes, not on the kick-off (when the index is still empty).
  // ``workbookId`` is required (per-workbook hard-scoping, PR 2).
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ site_url, workbookId, library, folder_path, file_paths }) =>
      api.ingestSource(
        {
          type: "sharepoint",
          site_url,
          library: library ?? "",
          folder_path: folder_path ?? "",
          // Pass through only when populated so the backend keeps the existing
          // walk-this-folder behaviour for the (default) browse-mode caller.
          ...(file_paths && file_paths.length > 0 ? { file_paths } : {}),
        },
        workbookId,
      ),
    ...restOpts,
    onSuccess: (...args) => {
      callerOnSuccess?.(...args);
    },
  });
};

/**
 * Poll an in-flight ingest job. Returns ``IngestJob`` when the id is
 * truthy, ``null`` (placeholder) otherwise — pass ``null``/``undefined``
 * to disable polling between runs.
 *
 * Refetch cadence: 1s while running, off once status flips to done/error.
 *
 * Mid-run invalidation: each poll tick where ``ingested`` actually
 * increased busts the lightweight evidence list caches so newly-landed
 * rows show up continuously instead of jumping in at terminal state.
 * Heavier caches (workbook rollups, stats, pending system context)
 * stay deferred to completion — they're expensive to recompute and
 * not useful per-file. On terminal state we invalidate the full tree,
 * matching what ``useClearEvidence`` does after a wipe.
 *
 * The ``ingested`` count is tracked across renders via a ref keyed by
 * job-id; resetting on id change handles back-to-back ingests cleanly.
 */
export const useIngestJobStatus = (jobId: string | null | undefined) => {
  const qc = useQueryClient();
  // Per-job-id tracker: skip evidence-list refetch on ticks where no
  // new row landed. The QC-only check (e.g. React Query's structural
  // sharing) isn't enough — invalidateQueries always fires a network
  // request when the query is mounted.
  const lastIngestedRef = useRef<{ jobId: string | null; count: number }>({
    jobId: null,
    count: 0,
  });
  return useQuery<IngestJob | null>({
    queryKey: ["ingest-job", jobId] as const,
    queryFn: async () => {
      if (!jobId) return null;
      const job = await api.getIngestJob(jobId);

      // Reset tracker when the job-id changes (a new ingest started).
      if (lastIngestedRef.current.jobId !== jobId) {
        lastIngestedRef.current = { jobId, count: 0 };
      }

      if (job.status === "running") {
        if (job.ingested > lastIngestedRef.current.count) {
          // Only the evidence-row queries are cheap enough to refire
          // mid-run. ``evidence-for-objective`` repaints the assessor
          // wizard's per-objective evidence panel as files trickle in.
          qc.invalidateQueries({ queryKey: ["evidence"] });
          qc.invalidateQueries({ queryKey: ["evidence-for-objective"] });
          lastIngestedRef.current.count = job.ingested;
        }
      } else if (job.status === "done" || job.status === "error") {
        // Same invalidation tree as useClearEvidence — evidence rows,
        // per-objective evidence lists, workbook rollups and stats all
        // become stale the instant the job lands new rows.
        qc.invalidateQueries({ queryKey: ["evidence"] });
        qc.invalidateQueries({ queryKey: ["evidence-for-objective"] });
        qc.invalidateQueries({ queryKey: ["evidence-stats"] });
        qc.invalidateQueries({ queryKey: ["workbook"] });
        // Pending boundary scope GET returns {context, boundary_docs} as
        // one payload — when a SharePoint/folder ingest lands boundary
        // docs with workbook_id=null + is_boundary_doc=true, the pending
        // SweepContext page won't see them until this cache is busted.
        // Same fix pattern as useIngestFile / usePatchBoundaryDoc.
        qc.invalidateQueries({ queryKey: qk.pendingSystemContext });
      }
      return job;
    },
    enabled: !!jobId,
    refetchInterval: (query) => {
      const data = query.state.data;
      return data && data.status === "running" ? 1000 : false;
    },
  });
};

/**
 * Discover an already-running ingest on page load so a tab refresh in
 * the middle of an ingest reattaches the progress strip. Returns null
 * (not undefined) when the sidecar reports no active job — distinguishes
 * "loaded, idle" from "still loading".
 */
export const useActiveIngestJob = () =>
  useQuery<IngestJob | null>({
    queryKey: ["ingest-job", "active"] as const,
    queryFn: api.getActiveIngestJob,
    // One-shot on mount — once a job_id is in hand, ``useIngestJobStatus``
    // takes over with its 1s polling cadence.
    refetchOnWindowFocus: false,
    staleTime: 30_000,
  });

type ClearEvidenceResult = Awaited<ReturnType<typeof api.clearEvidence>>;

export const useClearEvidence = (
  opts?: UseMutationOptions<ClearEvidenceResult, Error, { purgeText?: boolean } | void>,
) => {
  const qc = useQueryClient();
  // Pull `onSuccess` out before spreading so the caller's handler (toast,
  // dialog close, mutation reset) composes with our invalidation instead
  // of overwriting it. Spreading `...opts` after our onSuccess was the bug
  // that ate every refetch — clear and ingest both reported success but
  // the Evidence table sat on stale data until the user reloaded.
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (vars) => api.clearEvidence(vars?.purgeText ?? true),
    ...restOpts,
    onSuccess: (...args) => {
      // Clear wipes Evidence + EvidenceTag + StigFinding in one shot, so every
      // query that joins to those tables now serves stale counts/labels until
      // refetch. Invalidate the full derivation tree so the UI updates the
      // moment the mutation lands — not when the user happens to reload.
      //
      // Why each key:
      //   evidence — the table on the Evidence page and the crosscheck card
      //              (key prefix matches ["evidence", "crosscheck", id])
      //   evidence-for-objective — the per-objective evidence list in
      //              ControlDetail
      //   workbook — workbookControlStatus drives the Controls grid badges
      //              (evidence count per control); workbookSummary may show
      //              aggregate counts in the header
      //   assessments — assessment rows reference evidence via tags; clearing
      //              orphans those references and the count derivations
      //   poams — POAM cards show evidence_count joined off EvidenceTag;
      //              that number must drop to 0 on clear
      qc.invalidateQueries({ queryKey: ["evidence"] });
      // EVICT inactive per-objective caches (see useDeleteEvidence) so a wiped
      // artifact can't linger on a Control detail opened within the staleTime
      // window. invalidate alone doesn't refetch an unmounted query.
      qc.removeQueries({ queryKey: ["evidence-for-objective"] });
      qc.invalidateQueries({ queryKey: ["workbook"] });
      qc.invalidateQueries({ queryKey: ["assessments"] });
      qc.invalidateQueries({ queryKey: ["poams"] });
      callerOnSuccess?.(...args);
    },
  });
};

type DeleteEvidenceResult = Awaited<ReturnType<typeof api.deleteEvidence>>;

/**
 * Surgical single-row evidence delete. Same downstream invalidation tree
 * as ``useClearEvidence`` (and same destructure-before-spread guard on
 * the caller's onSuccess) — anything that joined to this row is now
 * stale, so the full derivation tree refetches the moment the mutation
 * lands.
 */
export const useDeleteEvidence = (
  opts?: UseMutationOptions<
    DeleteEvidenceResult,
    Error,
    { id: number; purgeText?: boolean }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ id, purgeText }) => api.deleteEvidence(id, purgeText ?? true),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["evidence"] });
      // EVICT (not just invalidate) the per-objective evidence caches. The
      // delete usually happens on the Evidence page while the Control detail's
      // useEvidenceForObjective query is INACTIVE (unmounted). React Query
      // marks inactive queries stale but does not refetch them, and with the
      // global staleTime=30s a remount within the window can render the cached
      // pre-delete rows — so the deleted artifact "stays" on the control.
      // removeQueries drops the cached data outright, forcing a fresh fetch
      // the next time the control is opened.
      qc.removeQueries({ queryKey: ["evidence-for-objective"] });
      qc.invalidateQueries({ queryKey: ["workbook"] });
      qc.invalidateQueries({ queryKey: ["assessments"] });
      qc.invalidateQueries({ queryKey: ["poams"] });
      // Deleting evidence cascades to its sweep tokens (BoundaryTokenSource)
      // and can flip system-context derivation, so refresh those panels too.
      // ["workbook"] already covers boundaryDocs (["workbook", id, ...]).
      qc.invalidateQueries({ queryKey: ["system-context"] });
      qc.invalidateQueries({ queryKey: ["sharepoint", "sweep-runs"] });
      callerOnSuccess?.(...args);
    },
  });
};

type UpsertResult = Awaited<ReturnType<typeof api.upsertAssessment>>;

/**
 * Save one CCI's assessment, then auto-apply it to the workbook.
 *
 * Mirrors :func:`useAssessBatch` — the user clicks Save and expects the row
 * to land in the Excel working copy without a second "Apply to workbook"
 * click. We chain ``apply-batch`` with ``assessment_ids: [result.id]`` so
 * the server-side gating (needs_review → skip, already_written → skip,
 * no excel_row → skip, see :func:`routes.controls.apply_assessments_batch`)
 * is consistent with the bulk path. The apply result is annotated onto the
 * upsert response as ``auto_applied`` so the caller's toast can mention the
 * workbook write when one happened.
 *
 * Apply errors are surfaced as toast.error here (not swallowed) because the
 * working-copy file is the user-visible artifact — silent failure is what
 * led to the empty ``~/.cybersecurity-assessor/working_copies/`` directory
 * the user noticed. The DB save itself stands either way; the caller's
 * onSuccess still fires so the drawer and review queue update.
 */
export const useUpsertAssessment = (
  opts?: UseMutationOptions<
    UpsertResult,
    Error,
    { body: AssessmentUpsert; force?: boolean }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ body, force }: { body: AssessmentUpsert; force?: boolean }) =>
      api.upsertAssessment(body, force),
    ...restOpts,
    onSuccess: async (...args) => {
      const [result, vars] = args;
      qc.invalidateQueries({ queryKey: ["assessments"] });
      // Rollup includes this assessment now — refresh the Controls grid status.
      qc.invalidateQueries({
        queryKey: ["workbook", vars.body.workbook_id, "control-status"],
      });
      // Manual save may clear needs_review (or set it) — refresh the queue.
      qc.invalidateQueries({
        queryKey: qk.workbookReviewQueue(vars.body.workbook_id),
      });

      // Chase the save with a targeted apply-batch so the working copy gets
      // the row immediately. ``assessment_ids: [result.id]`` scopes the
      // write to just this CCI; ``skip_written: true`` is a defense against
      // re-writing the same cells if the user clicks Save twice. Server-
      // side gating (needs_review etc.) means ``applied`` may be 0 even
      // on a successful HTTP call — that's expected and not an error.
      try {
        const applyResult = await api.applyAssessmentsBatchToWorkbook({
          workbookId: vars.body.workbook_id,
          assessmentIds: [result.id],
          skipWritten: true,
        });
        result.auto_applied = {
          applied: applyResult.applied,
          skipped_needs_review: applyResult.skipped_needs_review,
          skipped_already_written: applyResult.skipped_already_written,
        };
        qc.invalidateQueries({
          queryKey: qk.workbookControlStatus(vars.body.workbook_id),
        });
        // The On-Prem (Col L) grid column derives its "N/A" outcome from the
        // workbook's Column-N status, which this save just changed — refresh it
        // so the chip doesn't show stale until a manual refetch.
        qc.invalidateQueries({
          queryKey: qk.workbookColLStatus(vars.body.workbook_id),
        });
      } catch (err) {
        // Save succeeded; the workbook write didn't. Surface it so the user
        // knows the Excel artifact is out of sync with the DB — otherwise
        // they'll wonder why the working copy never changes. The caller's
        // onSuccess (drawer close, success toast) still fires below.
        result.auto_applied = null;
        toast.error(
          "Saved, but workbook write failed",
          humanize(err),
        );
      }

      callerOnSuccess?.(...args);
    },
  });
};

/**
 * Single-CCI assess. Since v0.2 the ``/api/controls/assess`` route persists
 * accepted decisions as ``needs_review=true`` rows (so navigating away from
 * the detail page no longer loses the proposal), invalidate the same caches
 * the batch hook does — per-objective + per-control assessment lists, the
 * workbook control-status rollup that drives the Controls grid pills, and
 * the workbook review queue so the new pending-human-review entry surfaces.
 *
 * Mutation-opts spread order: destructure ``onSuccess`` BEFORE spread so a
 * caller-supplied success handler doesn't clobber our invalidation. See
 * memory ``feedback_mutation_opts_spread_order``.
 */
export const useAssessObjective = (
  opts?: UseMutationOptions<
    AssessmentDecision,
    Error,
    { workbookId: number; objectiveId: number }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ workbookId, objectiveId }) =>
      api.assessObjective(workbookId, objectiveId),
    ...restOpts,
    onSuccess: (decision, vars, onMutateResult, context) => {
      // Per-objective and per-control assessment caches — ControlDetail
      // reads both depending on whether it has the objective_id in scope.
      qc.invalidateQueries({ queryKey: ["assessments"] });
      // Controls grid pills derive from the rollup; without this the grid
      // still shows "Not Assessed" after the user clicks Assess on the
      // detail page until something else refetches.
      qc.invalidateQueries({
        queryKey: qk.workbookControlStatus(vars.workbookId),
      });
      // Col-L "N/A" chip derives from Column-N status this assess may change.
      qc.invalidateQueries({
        queryKey: qk.workbookColLStatus(vars.workbookId),
      });
      // The persisted row lands as needs_review=true; surface it in the
      // queue immediately so a reviewer can find it without a manual
      // refresh.
      qc.invalidateQueries({
        queryKey: qk.workbookReviewQueue(vars.workbookId),
      });
      callerOnSuccess?.(decision, vars, onMutateResult, context);
    },
  });
};

/**
 * Auto-assess every in-scope CCI in the workbook in one server-side run.
 *
 * After the batch lands, we *immediately* chain a bulk-apply call so the
 * Controls grid status pills populate without the user clicking through a
 * separate "Apply to workbook" step. The bulk-apply endpoint silently
 * skips ``needs_review`` and already-written rows server-side (precision
 * guardrail — see memory ``feedback_precision_over_recall``), so only
 * confident verdicts land in column N. Needs-review rows continue to
 * surface in the review queue for one-click reviewer acceptance.
 *
 * The apply call is awaited inside onSuccess so the workbook-control-status
 * rollup is refreshed in the *same* tick the assess result returns — the
 * caller's onSuccess (toasts, drawer close) fires after the full chain is
 * done, not in the middle of it.
 *
 * Invalidates: per-control assessments cache, workbook control-status
 * rollup, review queue, recent runs list — driven by the assess result and
 * (transitively) the apply result.
 */
export const useAssessBatch = (
  opts?: UseMutationOptions<AssessBatchResult, Error, AssessBatchRequest>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body: AssessBatchRequest) => api.assessBatch(body),
    ...restOpts,
    onSuccess: async (...args) => {
      const [result, vars] = args;
      qc.invalidateQueries({ queryKey: ["assessments"] });
      qc.invalidateQueries({
        queryKey: ["workbook", result.workbook_id, "control-status"],
      });
      // v0.2 — batch run produces fresh abstains; refresh the queue page.
      qc.invalidateQueries({ queryKey: qk.workbookReviewQueue(result.workbook_id) });
      qc.invalidateQueries({ queryKey: qk.runs(50) });
      // Metrics tab live spend (live_cost_usd / savings ROI) is summed
      // from completed runs — without this invalidation the cost panel
      // stays frozen at the pre-batch number until the user navigates
      // away and back. qk.workbooks is invalidated too because the
      // Workbooks-list row reads from a query that other batch ops
      // also refresh, keeping the cost-related surface area consistent.
      qc.invalidateQueries({ queryKey: qk.metrics });
      qc.invalidateQueries({ queryKey: qk.workbooks });

      // Auto-apply confident rows so the Controls grid populates without a
      // second user click. Scoped to the same family the user just
      // assessed (null = whole workbook). Errors are swallowed: if the
      // workbook is locked or the working copy missing, the assess result
      // still stands and the user can retry Apply manually from the grid.
      //
      // The applied count is folded back onto the result via the
      // `auto_applied` client-only annotation so the caller's toast can
      // distinguish "0 newly assessed, but old decisions just wrote to
      // column N" from "0 newly assessed and nothing to write either".
      try {
        const applyResult = await api.applyAssessmentsBatchToWorkbook({
          workbookId: result.workbook_id,
          family: vars.family ?? null,
          skipWritten: true,
        });
        result.auto_applied = {
          applied: applyResult.applied,
          skipped_needs_review: applyResult.skipped_needs_review,
          skipped_already_written: applyResult.skipped_already_written,
        };
        qc.invalidateQueries({ queryKey: ["assessments"] });
        qc.invalidateQueries({
          queryKey: qk.workbookControlStatus(result.workbook_id),
        });
        qc.invalidateQueries({
          queryKey: qk.workbookColLStatus(result.workbook_id),
        });
      } catch (err) {
        // Assess succeeded; the workbook write didn't. Surface as a toast —
        // a silent console.warn here was hiding the case where the working
        // copy never materialized (empty ~/.cybersecurity-assessor/
        // working_copies/ dir), making the "0 written" pill look like
        // expected behavior. The caller's onSuccess still fires below so
        // the per-call success toast (assess result + token spend) renders.
        result.auto_applied = null;
        toast.error(
          "Assessed rows saved, but workbook write failed",
          humanize(err),
        );
      }

      callerOnSuccess?.(...args);
    },
  });
};

/**
 * Poll the in-flight assess-batch for a workbook.
 *
 * Fires every 750 ms while ``enabled`` is true so the Controls page can
 * render a determinate progress bar with per-CCI granularity while the
 * (multi-minute, especially on Opus) ``/assess-batch`` mutation is in
 * flight. Off-mount and off-window-focus refetching are disabled so the
 * tracker doesn't spin once the bar is hidden.
 *
 * ``enabled`` should be tied to ``assessBatch.isPending`` at the call
 * site — that gates polling to exactly the lifetime of the parent
 * mutation, with no extra round-trips when the page is idle.
 *
 * Returns the union from api.ts:
 *   ``{ active: false }`` — no batch is running (poll continues until
 *   ``enabled`` flips false; callers should hide the bar on inactive).
 *   ``{ active: true, total, completed, errored, started_at,
 *      last_objective }`` — render the bar from these fields.
 */
export const useAssessBatchProgress = (
  workbookId: number | null | undefined,
  enabled: boolean,
) =>
  useQuery<AssessBatchProgress>({
    queryKey: ["assess-batch-progress", workbookId] as const,
    queryFn: () => api.getAssessBatchProgress(workbookId as number),
    enabled: enabled && typeof workbookId === "number",
    // 750 ms feels live (a CCI assessment averages ~5-15s, so on a
    // 200-CCI batch a 1s poll would jitter visibly while individual
    // workers complete) without hammering the sidecar — 80 polls/min
    // worst-case, each returning a sub-KB JSON snapshot.
    refetchInterval: enabled ? 750 : false,
    refetchIntervalInBackground: false,
    // The tracker has no useful "stale" semantics — every poll already
    // hits the in-memory dict, and we never want a cached snapshot to
    // freeze the UI at a stale completed-count. Disable structural
    // staleness so refetchInterval drives 100% of the cadence.
    staleTime: 0,
    refetchOnWindowFocus: false,
  });

type ApplyResult = Awaited<ReturnType<typeof api.applyAssessmentToWorkbook>>;

export const useApplyToWorkbook = (
  opts?: UseMutationOptions<ApplyResult, Error, { assessmentId: number; close?: boolean }>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: ({ assessmentId, close }: { assessmentId: number; close?: boolean }) =>
      api.applyAssessmentToWorkbook(assessmentId, close),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["assessments"] });
      // Applying a row writes Column N, which the Controls grid status pill and
      // the On-Prem (Col L) "N/A" chip both derive from. The single-apply
      // result carries only assessment_id (no workbook_id), so invalidate the
      // ["workbook"] prefix — covers control-status + col-l-status for the
      // active workbook. (The bulk apply below targets by id; this one can't.)
      qc.invalidateQueries({ queryKey: ["workbook"] });
      callerOnSuccess?.(...args);
    },
  });
};

type ApplyBatchResult = Awaited<
  ReturnType<typeof api.applyAssessmentsBatchToWorkbook>
>;
type ApplyBatchVars = {
  workbookId: number;
  family?: string | null;
  assessmentIds?: number[];
  skipWritten?: boolean;
  close?: boolean;
};

/**
 * Bulk "Apply N to workbook" — writes every writable assessment for a
 * workbook (optionally narrowed by family/ids) in ONE xlwings session.
 *
 * Same invalidation surface as single-row apply (the `["assessments"]`
 * key feeds the Controls grid status pills, the per-CCI Apply button
 * label, and the per-workbook control-status rollup). Spread order
 * follows the project convention: pull caller's onSuccess out BEFORE
 * spreading restOpts so our invalidation can't be silently clobbered —
 * see memory: feedback_mutation_opts_spread_order.
 */
export const useApplyAllToWorkbook = (
  opts?: UseMutationOptions<ApplyBatchResult, Error, ApplyBatchVars>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (vars: ApplyBatchVars) =>
      api.applyAssessmentsBatchToWorkbook(vars),
    ...restOpts,
    onSuccess: (...args) => {
      const [result] = args;
      qc.invalidateQueries({ queryKey: ["assessments"] });
      // Per-workbook control-status rollup drives the "X of Y written"
      // chip on the Workbooks list and the Controls grid status pills;
      // refresh so the user sees the new totals without a page reload.
      qc.invalidateQueries({
        queryKey: qk.workbookControlStatus(result.workbook_id),
      });
      // Col-L "N/A" chip derives from Column-N status the bulk apply writes.
      qc.invalidateQueries({
        queryKey: qk.workbookColLStatus(result.workbook_id),
      });
      callerOnSuccess?.(...args);
    },
  });
};

/** Trigger a browser save for a PDF blob via a transient <a> element. */
function triggerBlobDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Defer revoke so the download has time to start.
  setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

type DownloadSarResult = Awaited<ReturnType<typeof api.downloadWorkbookSar>>;

/** Download the NIST SP 800-53A Security Assessment Report PDF. */
export const useDownloadWorkbookSar = (
  opts?: UseMutationOptions<DownloadSarResult, Error, number>,
) =>
  useMutation({
    mutationFn: async (workbookId: number) => {
      const result = await api.downloadWorkbookSar(workbookId);
      triggerBlobDownload(result.blob, result.filename);
      return result;
    },
    ...opts,
  });

export const useLoadNist = (opts?: UseMutationOptions<Framework, Error, string | undefined>) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (path?: string) => api.loadNist80053r5(path),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.frameworks });
      qc.invalidateQueries({ queryKey: qk.catalogStatus });
      callerOnSuccess?.(...args);
    },
  });
};

export const useLoadNistR4 = (
  opts?: UseMutationOptions<Framework, Error, string | undefined>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (path?: string) => api.loadNist80053r4(path),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.frameworks });
      qc.invalidateQueries({ queryKey: qk.catalogStatus });
      callerOnSuccess?.(...args);
    },
  });
};

/**
 * Result shape for `useLoadFedramp`. Matches `POST /api/catalog/load/fedramp`
 * — the Framework fields plus per-load counts the toast renders.
 */
export type FedrampLoadResult = Framework & {
  members_added: number;
  controls_synthesized: number;
  parameters_loaded: number;
  unknown_control_ids: string[];
};

/**
 * Load a FedRAMP Rev 5 profile as a child of the loaded 800-53 r5 catalog.
 *
 * Invalidates frameworks + catalogStatus so the Workbooks picker redraws
 * with the new child indented under "NIST SP 800-53 Rev 5" and the status
 * card picks up the new control/membership counts.
 *
 * Follows the mutation-opts spread order rule (destructure
 * `onSuccess` out of opts BEFORE the `...restOpts` spread) so a caller-
 * supplied `onSuccess` runs alongside the invalidation rather than
 * silently clobbering it.
 */
export const useLoadFedramp = (
  opts?: UseMutationOptions<
    FedrampLoadResult,
    Error,
    {
      level: "HIGH" | "MODERATE" | "LOW" | "LI-SAAS";
      path?: string;
      offline?: boolean;
    }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ level, path, offline }) =>
      api.loadFedramp(level, { path, offline }),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.frameworks });
      qc.invalidateQueries({ queryKey: qk.catalogStatus });
      qc.invalidateQueries({ queryKey: qk.baselines });
      callerOnSuccess?.(...args);
    },
  });
};

/**
 * Load the NIST CSF 2.0 OSCAL catalog (download-style, public domain).
 * Root catalog — invalidates frameworks + catalogStatus so the picker and
 * Settings status card pick up the new framework row.
 */
export const useLoadNistCsf = (
  opts?: UseMutationOptions<Framework, Error, string | undefined>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (path?: string) => api.loadNistCsf(path),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.frameworks });
      qc.invalidateQueries({ queryKey: qk.catalogStatus });
      callerOnSuccess?.(...args);
    },
  });
};

/**
 * Load the NIST SP 800-171 Rev 3 OSCAL catalog (download-style, public
 * domain).
 */
export const useLoadNist800171 = (
  opts?: UseMutationOptions<Framework, Error, string | undefined>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (path?: string) => api.loadNist800171(path),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.frameworks });
      qc.invalidateQueries({ queryKey: qk.catalogStatus });
      callerOnSuccess?.(...args);
    },
  });
};

/**
 * Shared factory for the four license-aware root-catalog loaders (ISO 27001,
 * CIS v8, PCI DSS, SOC 2). All take a REQUIRED `path` to the org's licensed
 * export and return a plain Framework; invalidation is identical (frameworks
 * + catalogStatus). The `loader` arg is the matching `api.*` method.
 */
const makeLicensedCatalogHook =
  (loader: (opts: { path: string; offline?: boolean }) => Promise<Framework>) =>
  (
    opts?: UseMutationOptions<
      Framework,
      Error,
      { path: string; offline?: boolean }
    >,
  ) => {
    // eslint-disable-next-line react-hooks/rules-of-hooks
    const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
    // eslint-disable-next-line react-hooks/rules-of-hooks
    return useMutation({
      mutationFn: (args: { path: string; offline?: boolean }) => loader(args),
      ...restOpts,
      onSuccess: (...args) => {
        qc.invalidateQueries({ queryKey: qk.frameworks });
        qc.invalidateQueries({ queryKey: qk.catalogStatus });
        callerOnSuccess?.(...args);
      },
    });
  };

/** Load ISO/IEC 27001:2022 from a user-supplied licensed export. */
export const useLoadIso27001 = makeLicensedCatalogHook(api.loadIso27001);
/** Load CIS Controls v8 Safeguards from a user-supplied licensed export. */
export const useLoadCisV8 = makeLicensedCatalogHook(api.loadCisV8);
/** Load PCI DSS 4.0 requirements from a user-supplied licensed export. */
export const useLoadPciDss = makeLicensedCatalogHook(api.loadPciDss);
/** Load SOC 2 Trust Services Criteria from a user-supplied licensed export. */
export const useLoadSoc2 = makeLicensedCatalogHook(api.loadSoc2);

export const useLoadDisaCci = (
  opts?: UseMutationOptions<
    DisaCciLoadResult,
    Error,
    { source_path?: string; xml_path?: string; framework_id: number }
  >,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (args: {
      source_path?: string;
      xml_path?: string;
      framework_id: number;
    }) => api.loadDisaCciCatalog(args),
    ...restOpts,
    onSuccess: (...args) => {
      // CCI metadata enriches objectives — invalidate frameworks and any
      // cached controls / control detail so the UI re-fetches the new fields.
      qc.invalidateQueries({ queryKey: qk.frameworks });
      qc.invalidateQueries({ queryKey: ["controls"] });
      qc.invalidateQueries({ queryKey: ["control"] });
      // Catalog status panel surfaces CCI counts in Settings.
      qc.invalidateQueries({ queryKey: qk.catalogStatus });
      // Baseline detail joins on Objective and renders deprecation badges;
      // baselines list shows objective counts. Sweep all baseline-prefixed
      // queries so per-id detail views also refresh.
      qc.invalidateQueries({ queryKey: qk.baselines });
      qc.invalidateQueries({ queryKey: ["baseline"] });
      // Evidence panels keyed on objective_id may render stale objective.source.
      qc.invalidateQueries({ queryKey: ["evidence-for-objective"] });
      callerOnSuccess?.(...args);
    },
  });
};

/**
 * Per-path overlay sheet preview — powers the Settings → Import overlay
 * sheet picker. Returns the auto-pick (what `classify_overlay` would
 * choose) plus every sheet with its individual candidate kind so the
 * user can target a specific tab (e.g. T1TL's "SV Security Controls"
 * instead of the default "Ground Security Controls" first-match-wins).
 *
 * Disabled when `path` is empty so the hook doesn't fire on the initial
 * card render. Per-path query key means switching the xlsx in the
 * picker naturally invalidates the dropdown — no manual invalidation.
 */
export const useOverlaySheets = (path: string) =>
  useQuery({
    queryKey: qk.overlaySheets(path),
    queryFn: () => api.listOverlaySheets(path),
    enabled: path.length > 0,
  });

/**
 * Unified overlay import — the single front door that auto-classifies an
 * xlsx as CRM / PSC / OTHER and dispatches to the right loader. Replaces
 * the old `useLoadCrm` + `useLoadProgramControls` two-button affordance.
 *
 * Invalidation covers every cache any of the three loaders can mutate:
 *   * baselines list + catalog status (CRM and OTHER write Baseline rows)
 *   * requirement sources + catalog status (PSC writes a RequirementSource)
 *   * controls / control detail (PSC's per-CCI rows show up next to
 *     objectives in the Controls grid)
 *
 * onSuccess is destructured BEFORE the opts spread so the invalidation
 * can't be silently clobbered by a caller-supplied callback (per
 * feedback_mutation_opts_spread_order.md).
 */
export const useImportOverlay = (
  opts?: UseMutationOptions<
    OverlayImportResult,
    Error,
    {
      framework_id: number;
      path: string;
      name?: string | null;
      kind_hint?: OverlayKind | null;
      sheet_name?: string | null;
      system_id?: number | null;
      // CRM-only implementation slice (e.g. "AWS GovCloud"). Required by the
      // backend when the dispatched loader is CRM; null for PSC/OTHER.
      scope_label?: string | null;
    }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (args) => api.importOverlay(args),
    ...restOpts,
    onSuccess: (result, ...rest) => {
      qc.invalidateQueries({ queryKey: qk.baselines });
      qc.invalidateQueries({ queryKey: qk.catalogStatus });
      qc.invalidateQueries({ queryKey: qk.requirementSources });
      // PSC overlays add per-CCI rows next to objectives; CRM overlays
      // change responsibility chips. Both surfaces hang off the controls
      // queries.
      qc.invalidateQueries({ queryKey: ["controls"] });
      qc.invalidateQueries({ queryKey: ["control"] });
      if (result.baseline_id !== undefined) {
        qc.invalidateQueries({ queryKey: qk.baseline(result.baseline_id) });
      }
      // Import is a pure catalog operation — no WorkbookOverlay rows are
      // written here. Workbook-scoped invalidations stay anyway so any
      // follow-up explicit attach call sees fresh data.
      qc.invalidateQueries({ queryKey: ["workbook"] });
      qc.invalidateQueries({ queryKey: qk.workbooks });
      callerOnSuccess?.(result, ...rest);
    },
  });
};

/**
 * Load a program-specific controls overlay into the global RequirementSource
 * table. Once loaded, every baseline for the chosen framework can reference
 * the source by id — no need to re-import the xlsx per workbook.
 *
 * Invalidates catalog status (the Workbooks "Requirement sources" footer
 * line reads from there) plus any cached control / control-detail queries
 * since overlay rows show up next to each objective.
 *
 * @deprecated Prefer `useImportOverlay` — the unified front door auto-
 * classifies and dispatches to this loader for PSC-shaped files.
 */
export const useLoadProgramControls = (
  opts?: UseMutationOptions<
    ProgramControlsLoadResult,
    Error,
    {
      source_name: string;
      workbook_path: string;
      framework_id: number;
      sheet_name: string;
    }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (args: {
      source_name: string;
      workbook_path: string;
      framework_id: number;
      sheet_name: string;
    }) => api.loadProgramControlsCatalog(args),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.catalogStatus });
      qc.invalidateQueries({ queryKey: qk.requirementSources });
      qc.invalidateQueries({ queryKey: ["controls"] });
      qc.invalidateQueries({ queryKey: ["control"] });
      // Pure catalog load — no auto-attach. Workbook caches are still
      // bumped so any follow-up explicit attach from the caller sees
      // fresh state.
      qc.invalidateQueries({ queryKey: ["workbook"] });
      qc.invalidateQueries({ queryKey: qk.workbooks });
      callerOnSuccess?.(...args);
    },
  });
};

/**
 * Loaded program-controls overlays — drives the delete list on the Settings
 * page. Cheap query (one row per overlay, plus a count(*) join), so we leave
 * the default staleTime — refetches on window focus pick up overlays loaded
 * from another window or after a delete.
 */
export const useRequirementSources = () =>
  useQuery({
    queryKey: qk.requirementSources,
    queryFn: api.listRequirementSources,
  });

/**
 * Destructive — wipes a program-controls overlay and every RequirementMap
 * pointing at it. Underlying Objective rows survive (framework-owned).
 * Invalidates catalog status (the overlay-count badge reads from there),
 * the requirement-sources list itself, and any cached control/control-detail
 * queries since per-CCI overlay rows disappear.
 */
export const useDeleteRequirementSource = (
  opts?: UseMutationOptions<
    { deleted_source_id: number; name: string; maps_removed: number },
    Error,
    number
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (id: number) => api.deleteRequirementSource(id),
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.requirementSources });
      qc.invalidateQueries({ queryKey: qk.catalogStatus });
      qc.invalidateQueries({ queryKey: ["controls"] });
      qc.invalidateQueries({ queryKey: ["control"] });
      callerOnSuccess?.(...args);
    },
    ...restOpts,
  });
};

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

export const useSettings = () =>
  useQuery<AppSettings>({ queryKey: qk.settings, queryFn: api.getSettings });

export const useUpdateSettings = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, SettingsUpdate>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (body: SettingsUpdate) => api.updateSettings(body),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      callerOnSuccess?.(...args);
    },
  });
};

export const useSetAnthropicKey = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, string>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (key: string) => api.setAnthropicKey(key),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      callerOnSuccess?.(...args);
    },
  });
};

export const useClearAnthropicKey = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, void>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: () => api.clearAnthropicKey(),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      callerOnSuccess?.(...args);
    },
  });
};

export const useSetAnthropicGatewayToken = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, string>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (token: string) => api.setAnthropicGatewayToken(token),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      qc.invalidateQueries({ queryKey: ["settings", "anthropic-models"] });
      callerOnSuccess?.(...args);
    },
  });
};

export const useClearAnthropicGatewayToken = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, void>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: () => api.clearAnthropicGatewayToken(),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      qc.invalidateQueries({ queryKey: ["settings", "anthropic-models"] });
      callerOnSuccess?.(...args);
    },
  });
};

type TestAnthropicKeyResult = Awaited<ReturnType<typeof api.testAnthropicKey>>;

/** Round-trip a tiny Haiku call to prove the stored key actually works. */
export const useTestAnthropicKey = (
  opts?: UseMutationOptions<TestAnthropicKeyResult, Error, void>,
) =>
  useMutation({
    mutationFn: () => api.testAnthropicKey(),
    ...opts,
  });

type TestAnthropicGatewayResult = Awaited<ReturnType<typeof api.testAnthropicGateway>>;

/**
 * Probe the corporate-gateway path explicitly (gateway URL + gateway token),
 * with no fallback to the personal sk-ant key. Use this on the gateway card
 * so the user knows the gateway itself works, not just "something works".
 */
export const useTestAnthropicGateway = (
  opts?: UseMutationOptions<TestAnthropicGatewayResult, Error, void>,
) =>
  useMutation({
    mutationFn: () => api.testAnthropicGateway(),
    ...opts,
  });

type AnthropicModelsResult = Awaited<ReturnType<typeof api.listAnthropicModels>>;

/**
 * Live model list from Anthropic /v1/models. Enabled only when an API key is
 * stored, so the dropdown stays empty (and falls back to free-text input)
 * until the key is set. Cached for an hour — the model catalog rarely changes
 * mid-session and we don't want to spam the upstream.
 */
export const useAnthropicModels = (keySet: boolean) =>
  useQuery<AnthropicModelsResult>({
    queryKey: ["settings", "anthropic-models"],
    queryFn: api.listAnthropicModels,
    enabled: keySet,
    staleTime: 60 * 60 * 1_000,
    retry: false,
  });

// ---------------------------------------------------------------------------
// OpenAI — symmetric to the Anthropic hooks above, including the corporate /
// high-side gateway-token slot. The optional ``openai_base_url`` override
// lives in the generic SettingsUpdate mutation, mirroring how
// ``anthropic_base_url`` is handled.
// ---------------------------------------------------------------------------

export const useSetOpenAIKey = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, string>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (key: string) => api.setOpenAIKey(key),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      qc.invalidateQueries({ queryKey: ["settings", "openai-models"] });
      callerOnSuccess?.(...args);
    },
  });
};

export const useClearOpenAIKey = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, void>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: () => api.clearOpenAIKey(),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      qc.invalidateQueries({ queryKey: ["settings", "openai-models"] });
      callerOnSuccess?.(...args);
    },
  });
};

export const useSetOpenAIGatewayToken = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, string>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (token: string) => api.setOpenAIGatewayToken(token),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      qc.invalidateQueries({ queryKey: ["settings", "openai-models"] });
      callerOnSuccess?.(...args);
    },
  });
};

export const useClearOpenAIGatewayToken = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, void>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: () => api.clearOpenAIGatewayToken(),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      qc.invalidateQueries({ queryKey: ["settings", "openai-models"] });
      callerOnSuccess?.(...args);
    },
  });
};

type TestOpenAIKeyResult = Awaited<ReturnType<typeof api.testOpenAIKey>>;

/** Round-trip a tiny gpt-4o-mini call to prove the stored key actually works. */
export const useTestOpenAIKey = (
  opts?: UseMutationOptions<TestOpenAIKeyResult, Error, void>,
) =>
  useMutation({
    mutationFn: () => api.testOpenAIKey(),
    ...opts,
  });

type TestOpenAIGatewayResult = Awaited<ReturnType<typeof api.testOpenAIGateway>>;

/** Symmetric to useTestAnthropicGateway — probes only the OpenAI gateway path. */
export const useTestOpenAIGateway = (
  opts?: UseMutationOptions<TestOpenAIGatewayResult, Error, void>,
) =>
  useMutation({
    mutationFn: () => api.testOpenAIGateway(),
    ...opts,
  });

type OpenAIModelsResult = Awaited<ReturnType<typeof api.listOpenAIModels>>;

/**
 * Live model list from OpenAI /v1/models (filtered server-side to chat-
 * capable gpt-* / o1* / o3* families). Same enabled/staleTime/retry posture
 * as ``useAnthropicModels`` — only fires once a key is stored, cached for an
 * hour, no auto-retry on failure (corp gateways often 404 /v1/models).
 */
export const useOpenAIModels = (keySet: boolean) =>
  useQuery<OpenAIModelsResult>({
    queryKey: ["settings", "openai-models"],
    queryFn: api.listOpenAIModels,
    enabled: keySet,
    staleTime: 60 * 60 * 1_000,
    retry: false,
  });

// ---------------------------------------------------------------------------
// eMASS — v0.2+ stub. status hook backs the Settings card; key set/clear
// mirrors the Anthropic helpers.
// ---------------------------------------------------------------------------

type EmassStatusResult = Awaited<ReturnType<typeof api.emassStatus>>;
type EmassTestResult = Awaited<ReturnType<typeof api.testEmass>>;
type EmassTestArg = Parameters<typeof api.testEmass>[0];

/** Live status of the eMASS connector. Cheap — reads config + checks cert
 *  path exists on disk; no network. The DOUBLE-GATED behaviour is reflected
 *  in `configured` (both flags must be on for it to be true). */
export const useEmassStatus = (pollMs: number = 0) =>
  useQuery<EmassStatusResult>({
    queryKey: ["emass", "status"],
    queryFn: api.emassStatus,
    staleTime: 30 * 1_000,
    retry: false,
    refetchInterval: pollMs > 0 ? pollMs : false,
    refetchIntervalInBackground: pollMs > 0,
  });

/** Real mTLS probe — instantiates EmassSource server-side and calls
 *  test_connection(). Invalidates the status query so the configured/
 *  reachable badge updates as soon as the test resolves. */
export const useTestEmass = (
  opts?: UseMutationOptions<EmassTestResult, Error, EmassTestArg>,
) => {
  const qc = useQueryClient();
  // CRITICAL: destructure caller's onSuccess BEFORE spreading restOpts,
  // otherwise spreading after our onSuccess silently clobbers it.
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body?: EmassTestArg) => api.testEmass(body ?? undefined),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["emass", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

export const useSetEmassKey = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, string>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (key: string) => api.setEmassKey(key),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      qc.invalidateQueries({ queryKey: ["emass", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

export const useClearEmassKey = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, void>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: () => api.clearEmassKey(),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      qc.invalidateQueries({ queryKey: ["emass", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

// ---------------------------------------------------------------------------
// Confluence DC — v0.4+ gated connector. Mirrors eMASS pattern: cheap status
// (config + keyring probe — no network) and a real /test PAT probe.
// ---------------------------------------------------------------------------

type ConfluenceStatusResult = Awaited<ReturnType<typeof api.confluenceStatus>>;
type ConfluenceTestResult = Awaited<ReturnType<typeof api.testConfluence>>;
type ConfluenceTestArg = Parameters<typeof api.testConfluence>[0];

/** Live status of the Confluence connector (gates + PAT presence + config). */
export const useConfluenceStatus = () =>
  useQuery<ConfluenceStatusResult>({
    queryKey: ["confluence", "status"],
    queryFn: api.confluenceStatus,
    staleTime: 30 * 1_000,
    retry: false,
  });

export const useTestConfluence = (
  opts?: UseMutationOptions<ConfluenceTestResult, Error, ConfluenceTestArg | undefined>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body?: ConfluenceTestArg) => api.testConfluence(body ?? undefined),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["confluence", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

export const useSetConfluencePat = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, string>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (key: string) => api.setConfluencePat(key),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      qc.invalidateQueries({ queryKey: ["confluence", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

export const useClearConfluencePat = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, void>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: () => api.clearConfluencePat(),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      qc.invalidateQueries({ queryKey: ["confluence", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

// ---------------------------------------------------------------------------
// Jira — double-gated v0.4+ connector. Status is config + keyring only (NO
// network); /test rounds-trips /rest/api/2/myself through the underlying
// JiraSource.test_connection() helper. PAT lives in OS keyring; set/clear
// hooks mirror the eMASS pair so the Settings card stays uniform.
// ---------------------------------------------------------------------------

/**
 * Cheap config + keyring probe — no network. Drives the Settings card badge
 * (configured / pat_set / enabled / upcoming_gated / gate_open). Polling is
 * not needed here — the card's other mutations (Save settings, Set PAT, Clear
 * PAT, Test) all invalidate `["jira", "status"]` so the badge tracks state
 * without a refetch interval.
 */
export const useJiraStatus = () =>
  useQuery<JiraStatus>({
    queryKey: ["jira", "status"],
    queryFn: api.jiraStatus,
    staleTime: 30 * 1_000,
    retry: false,
  });

/**
 * Test the Jira connection. Returns `{ok, message, detected}` — same shape
 * as the SharePoint /test response so the card renders a uniform "detected
 * metadata" badge. HTTP 400 surfaces via the standard ApiError path when
 * the double-gate is closed or required config is missing.
 *
 * Destructure-before-spread (see feedback_mutation_opts_spread_order) so the
 * caller's onSuccess isn't silently clobbered by our cache invalidation.
 */
export const useTestJira = (
  opts?: UseMutationOptions<JiraTestResponse, Error, JiraTestBody | void>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body?: JiraTestBody | void) => api.testJira(body ?? undefined),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["jira", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

/** Store PAT in the OS keyring; flips status.pat_set true on success. */
export const useSetJiraPat = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, string>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (pat: string) => api.setJiraPat(pat),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      qc.invalidateQueries({ queryKey: ["jira", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

/** Wipe the stored PAT from the OS keyring. */
export const useClearJiraPat = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, void>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: () => api.clearJiraPat(),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      qc.invalidateQueries({ queryKey: ["jira", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

// ---------------------------------------------------------------------------
// SharePoint connector. Status is cheap (config + cache file probe — no MSAL
// roundtrip); the Test mutation drives the two-phase device-code dance.
// ---------------------------------------------------------------------------

/**
 * Cheap config + token-cache probe — no MSAL/network calls.
 *
 * Pass `pollMs` while a device-code sign-in is in flight so the card flips to
 * "signed in" the moment the background MSAL thread writes the token cache to
 * disk, without the user having to come back and click anything. Default `0`
 * disables polling and falls back to React Query's standard staleTime caching.
 */
export const useSharePointStatus = (pollMs: number = 0) =>
  useQuery<SharePointStatus>({
    queryKey: ["sharepoint", "status"],
    queryFn: api.sharepointStatus,
    staleTime: 30 * 1_000,
    retry: false,
    refetchInterval: pollMs > 0 ? pollMs : false,
    refetchIntervalInBackground: pollMs > 0,
  });

/**
 * Test SharePoint connection. May return `pending: true` with
 * `user_code` / `verification_uri` on first call — UI shows the device-code
 * instructions and the user re-clicks Test after signing in.
 */
export const useTestSharePoint = (
  opts?: UseMutationOptions<SharePointTestResponse, Error, SharePointTestBody | void>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (body?: SharePointTestBody | void) =>
      api.testSharePoint(body ?? undefined),
    ...restOpts,
    onSuccess: (...args) => {
      // Status reflects token_cache_exists once the device-code flow finishes.
      qc.invalidateQueries({ queryKey: ["sharepoint", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

/**
 * Live GitLab connector status — cheap (config + keyring only, no network).
 * No device-code dance, so polling isn't typically needed; the optional
 * `pollMs` is kept for API symmetry with `useSharePointStatus`.
 */
export const useGitlabStatus = (pollMs: number = 0) =>
  useQuery<GitlabStatus>({
    queryKey: ["gitlab", "status"],
    queryFn: api.gitlabStatus,
    staleTime: 30 * 1_000,
    retry: false,
    refetchInterval: pollMs > 0 ? pollMs : false,
    refetchIntervalInBackground: pollMs > 0,
  });

/**
 * Probe GitLab with the saved (or override) config. Always synchronous —
 * no two-phase pending state. A successful test resolves every configured
 * project to a concrete commit SHA so the card can render per-project
 * health alongside the auth check.
 */
export const useTestGitlab = (
  opts?: UseMutationOptions<GitlabTestResponse, Error, GitlabTestBody | void>,
) => {
  const qc = useQueryClient();
  // Caller's onSuccess must come last so our invalidate always fires —
  // see feedback_mutation_opts_spread_order memory.
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body?: GitlabTestBody | void) =>
      api.testGitlab(body ?? undefined),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["gitlab", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

/** Wipe the persisted MSAL token cache — forces device-code on next test. */
export const useSignOutSharePoint = (
  opts?: UseMutationOptions<{ ok: boolean; cache_removed: boolean }, Error, void>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: () => api.signOutSharePoint(),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["sharepoint", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

// ---------------------------------------------------------------------------
// Splunk — saved-search connector (v0.4). Single-gated (enable_splunk only —
// no second ISSM ack like eMASS/Confluence/Jira). The status hook is cheap
// (config + keyring, no network); the Test hook does a real service.info()
// round-trip. Token set/clear hits the OS keyring via dedicated routes —
// it never round-trips through /settings.
// ---------------------------------------------------------------------------

/** Cheap config + keyring probe — NEVER hits the network. */
export const useSplunkStatus = () =>
  useQuery<SplunkStatus>({
    queryKey: ["splunk", "status"],
    queryFn: api.splunkStatus,
    staleTime: 30 * 1_000,
    retry: false,
  });

/** Real service.info() round-trip. Body fields override saved config so the
 *  user can probe a candidate host/token before clicking Save. */
export const useTestSplunk = (
  opts?: UseMutationOptions<SplunkTestResponse, Error, SplunkTestBody | void>,
) => {
  const qc = useQueryClient();
  // Destructure caller onSuccess BEFORE spreading — spreading after our
  // onSuccess would silently clobber it (see feedback_mutation_opts_spread_order).
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body?: SplunkTestBody | void) =>
      api.testSplunk(body ?? undefined),
    ...restOpts,
    onSuccess: (...args) => {
      // A successful test doesn't change config, but it does confirm token+host
      // are still in sync — invalidate so the status badge re-fetches.
      qc.invalidateQueries({ queryKey: ["splunk", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

/** Store the Splunk auth token in the OS keyring. */
export const useSetSplunkToken = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, string>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (token: string) => api.setSplunkToken(token),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["splunk", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

/** Wipe the Splunk auth token from the OS keyring. */
export const useClearSplunkToken = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, void>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: () => api.clearSplunkToken(),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["splunk", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

/**
 * Cancel an in-flight device-code sign-in WITHOUT wiping the token cache.
 * Use this when the device code expired or the browser was abandoned mid-flow
 * and the user wants a fresh code. The next `useTestSharePoint` call will spin
 * a brand-new device-code dance.
 */
export const useCancelSharePointSignIn = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, void>,
) => {
  return useMutation({
    mutationFn: () => api.cancelSharePointSignIn(),
    ...opts,
  });
};

// ---------------------------------------------------------------------------
// Archer (RSA Archer / GRC) connector hooks
// ---------------------------------------------------------------------------
//
// Mirrors the SharePoint pattern but simpler — Archer is single-shot
// password auth, no device-code two-phase dance. `useArcherStatus` is a
// cheap config + keyring probe; `useTestArcher` does a real session-login
// round-trip. Inline tuple keys ["archer", "status"] follow the
// per-recipe convention of NOT bloating the shared qk object for
// connector hooks.
// ---------------------------------------------------------------------------

export const useArcherStatus = (pollMs: number = 0) =>
  useQuery<ArcherStatus>({
    queryKey: ["archer", "status"],
    queryFn: api.archerStatus,
    staleTime: 30 * 1_000,
    retry: false,
    refetchInterval: pollMs > 0 ? pollMs : false,
    refetchIntervalInBackground: pollMs > 0,
  });

export const useTestArcher = (
  opts?: UseMutationOptions<ArcherTestResponse, Error, ArcherTestBody | void>,
) => {
  const qc = useQueryClient();
  // CRITICAL: destructure caller's onSuccess BEFORE spreading restOpts —
  // spreading after our own onSuccess would silently clobber the
  // invalidation (see feedback memory: React Query useMutation opts
  // spread order).
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body?: ArcherTestBody | void) =>
      api.testArcher(body ?? undefined),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["archer", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

/** Persist an Archer password in the OS keyring. Body must include
 *  `password`; instance_name/username default to the saved config. */
export const useSetArcherPassword = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, ArcherPasswordBody>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body: ArcherPasswordBody) => api.setArcherPassword(body),
    ...restOpts,
    onSuccess: (...args) => {
      // password_set is part of /status → refetch so the card flips to
      // "configured, untested" the moment the keyring write returns.
      qc.invalidateQueries({ queryKey: ["archer", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

export const useClearArcherPassword = (
  opts?: UseMutationOptions<{ ok: boolean; cleared?: boolean }, Error, void>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: () => api.clearArcherPassword(),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["archer", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

/**
 * One-level peek into a SharePoint folder for the Evidence-tab browse dialog.
 *
 * Modeled as a mutation rather than a query because the input (subfolder path)
 * changes on every drill-in click — caching by queryKey would either over-cache
 * (stale folder contents when the user re-opens the dialog) or thrash the cache
 * with one entry per visited subfolder. A mutation surfaces the same
 * isPending / data / error fields with no caching nonsense; the dialog just
 * tracks the current path in local state and re-runs `mutateAsync` on each
 * drill-in or breadcrumb click.
 */
export const useBrowseSharePoint = (
  opts?: UseMutationOptions<SharePointBrowseResponse, Error, SharePointBrowseBody | void>,
) => {
  return useMutation({
    mutationFn: (body?: SharePointBrowseBody | void) =>
      api.browseSharePoint(body ?? undefined),
    ...opts,
  });
};

/**
 * Filename-search hook for the Browse dialog. Same rationale as
 * ``useBrowseSharePoint`` — modeled as a mutation because the query string
 * changes per Enter press; caching would either go stale or thrash. Returns
 * the same isPending / data / error surface.
 *
 * The destructure-before-spread order is deliberate (see feedback memory):
 * spreading caller opts AFTER our own onSuccess would silently clobber it.
 */
export const useSearchSharePoint = (
  opts?: UseMutationOptions<SharePointSearchResponse, Error, SharePointSearchBody>,
) => {
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body: SharePointSearchBody) => api.searchSharePoint(body),
    ...restOpts,
    onSuccess: (...args) => {
      callerOnSuccess?.(...args);
    },
  });
};

/**
 * Boundary-aware sweep. Same shape as useSearchSharePoint — kept as a
 * mutation because the query depends on the workbook_id plus optional
 * folder overrides and the user explicitly triggers it from a button.
 *
 * On success we invalidate the workbooks list because v0.2 bumps
 * `Workbook.total_sweep_cost_usd` on every sweep (LLM-judge spend rolls
 * up there for the Workbooks-page "$X.XX total" chip) and ticks
 * `sweep_attempts`. Without the invalidation those numbers go stale
 * until the next manual refresh.
 *
 * Destructure-before-spread (see feedback_mutation_opts_spread_order).
 */
export const useSweepSharePoint = (
  opts?: UseMutationOptions<
    SharePointSweepResponse,
    Error,
    { body: SharePointSweepBody; signal?: AbortSignal }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ body, signal }: { body: SharePointSweepBody; signal?: AbortSignal }) =>
      api.sweepSharePoint(body, signal),
    ...restOpts,
    onSuccess: (...args) => {
      const [, vars] = args;
      qc.invalidateQueries({ queryKey: ["workbooks"] });
      // Refresh the Sweep Context "Last sweep" footer for this workbook.
      qc.invalidateQueries({
        queryKey: ["sharepoint", "sweep-runs", "latest", vars.body.workbook_id],
      });
      callerOnSuccess?.(...args);
    },
  });
};

/**
 * Bulk-ingest every candidate under a swept folder, skipping per-row triage.
 * Returns `{job_id}` once the ingest job is queued, or a pending device-code
 * dict when auth must be (re)established first — the caller discriminates on
 * `"job_id" in res`.
 *
 * Invalidation is deferred to `useIngestJobStatus` (the job runs async), so
 * we only forward the caller's onSuccess here.
 *
 * Destructure-before-spread (see feedback_mutation_opts_spread_order).
 */
export const useIngestAllFromFolder = (
  opts?: UseMutationOptions<SweepIngestAllResponse, Error, SweepIngestAllBody>,
) => {
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body: SweepIngestAllBody) => api.ingestAllFromFolder(body),
    ...restOpts,
    onSuccess: (...args) => {
      callerOnSuccess?.(...args);
    },
  });
};

/**
 * Most recent SweepRun for a workbook — drives the Sweep Context page
 * footer ("Last sweep: $X.XX · N judged · {model} · {minutes}m ago"). Returns
 * `null` (not 404) when the workbook has never been swept, so the UI just
 * renders nothing instead of error-toasting on every fresh workbook.
 *
 * Invalidated by `useSweepSharePoint.onSuccess` so the footer updates the
 * instant a sweep finishes without a manual refetch.
 */
export const useLatestSweepRun = (workbookId: number | null | undefined) =>
  useQuery({
    queryKey: ["sharepoint", "sweep-runs", "latest", workbookId],
    queryFn: () => api.getLatestSweepRun(workbookId as number),
    enabled: workbookId != null,
    staleTime: 30_000,
  });

/**
 * Fire-and-forget audit log of the assessor's check/uncheck decisions when
 * they click Ingest in the SweepTriageDialog. Powers the online-SGD weight
 * recalibrator (Part A of the v0.2 ML plan).
 *
 * No cache to invalidate — the SweepWeights row this writes against is
 * referenced by id from the next sweep response, and recalibration runs
 * out of band in the sidecar. The UI never reads decisions directly.
 *
 * Destructure-before-spread (see feedback_mutation_opts_spread_order).
 */
export const useRecordSweepDecisions = (
  opts?: UseMutationOptions<SweepDecisionsResult, Error, SweepDecisionsBody>,
) => {
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body: SweepDecisionsBody) => api.recordSweepDecisions(body),
    ...restOpts,
    onSuccess: (...args) => {
      callerOnSuccess?.(...args);
    },
  });
};

/** Priority-link bookmarks the user maintains on Settings → SharePoint. */
export const useSharePointPriorityLinks = () =>
  useQuery<{ links: SharePointPriorityLink[] }>({
    queryKey: ["sharepoint", "priority-links"],
    queryFn: api.listSharePointPriorityLinks,
    staleTime: 60 * 1_000,
  });

export const useSetSharePointPriorityLinks = (
  opts?: UseMutationOptions<
    { ok: boolean; links: SharePointPriorityLink[] },
    Error,
    SharePointPriorityLink[]
  >,
) => {
  const qc = useQueryClient();
  // Destructure onSuccess out BEFORE spreading — if we spread after our inline
  // onSuccess, the caller's onSuccess silently clobbers ours and the
  // invalidation never fires (see feedback_mutation_opts_spread_order memory).
  const { onSuccess: userOnSuccess, ...rest } = opts ?? {};
  return useMutation({
    ...rest,
    mutationFn: (links: SharePointPriorityLink[]) =>
      api.setSharePointPriorityLinks(links),
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["sharepoint", "priority-links"] });
      userOnSuccess?.(...args);
    },
  });
};

// ---------------------------------------------------------------------------
// Tenable connector. Two flavors: 'sc' (SecurityCenter on-prem, FQDN host)
// and 'io' (Tenable.io SaaS, implicit cloud.tenable.com host). Secrets live
// in the OS keyring, so the keyset CRUD hooks just bump status + settings.
// ---------------------------------------------------------------------------

/**
 * Live status of the Tenable connector — config + key-storage probe only,
 * no SDK roundtrip. Polling is optional; pass `pollMs > 0` if the Settings
 * card needs to react to a background mutation (currently unused — there's
 * no async sign-in flow like SharePoint's device code).
 */
export const useTenableStatus = (pollMs: number = 0) =>
  useQuery<TenableStatus>({
    queryKey: ["tenable", "status"],
    queryFn: api.tenableStatus,
    staleTime: 30 * 1_000,
    retry: false,
    refetchInterval: pollMs > 0 ? pollMs : false,
    refetchIntervalInBackground: pollMs > 0,
  });

/**
 * Run the live SDK probe. Body is optional — when absent the saved flavor +
 * host are used. The destructure-before-spread order is deliberate (see
 * feedback memory): spreading caller opts AFTER our own onSuccess would
 * silently clobber the invalidation.
 */
export const useTestTenable = (
  opts?: UseMutationOptions<TenableTestResponse, Error, TenableTestBody | void>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body?: TenableTestBody | void) =>
      api.testTenable(body ?? undefined),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["tenable", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

export const useSetTenableAccessKey = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, string>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (key: string) => api.setTenableAccessKey(key),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      qc.invalidateQueries({ queryKey: ["tenable", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

export const useClearTenableAccessKey = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, void>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: () => api.clearTenableAccessKey(),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      qc.invalidateQueries({ queryKey: ["tenable", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

export const useSetTenableSecretKey = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, string>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (key: string) => api.setTenableSecretKey(key),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      qc.invalidateQueries({ queryKey: ["tenable", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

export const useClearTenableSecretKey = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, void>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: () => api.clearTenableSecretKey(),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      qc.invalidateQueries({ queryKey: ["tenable", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

// ---------------------------------------------------------------------------
// ServiceNow GRC connector — status read + connection probe + keyring secret
// mutations. Mirrors the SharePoint pattern: status is a 30s-cached query, the
// /test mutation invalidates the status cache on completion so the card flips
// from "configured, untested" to "connected" without a manual refresh.
// ---------------------------------------------------------------------------

export const useServicenowGrcStatus = (pollMs: number = 0) =>
  useQuery<ServicenowGrcStatus>({
    queryKey: ["servicenow_grc", "status"],
    queryFn: api.servicenowGrcStatus,
    staleTime: 30 * 1_000,
    retry: false,
    refetchInterval: pollMs > 0 ? pollMs : false,
    refetchIntervalInBackground: pollMs > 0,
  });

export const useTestServicenowGrc = (
  opts?: UseMutationOptions<
    ServicenowGrcTestResponse,
    Error,
    ServicenowGrcTestBody | void
  >,
) => {
  const qc = useQueryClient();
  // Destructure caller's onSuccess BEFORE spreading — see
  // feedback_mutation_opts_spread_order memory. Otherwise the caller's
  // onSuccess wipes our invalidate.
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body?: ServicenowGrcTestBody | void) =>
      api.testServicenowGrc(body ?? undefined),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["servicenow_grc", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

export const useSetServicenowGrcOauthSecret = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, ServicenowGrcSecretBody>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body: ServicenowGrcSecretBody) =>
      api.setServicenowGrcOauthSecret(body),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["servicenow_grc", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

export const useClearServicenowGrcOauthSecret = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, void>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: () => api.clearServicenowGrcOauthSecret(),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["servicenow_grc", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

export const useSetServicenowGrcBasicPassword = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, ServicenowGrcSecretBody>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body: ServicenowGrcSecretBody) =>
      api.setServicenowGrcBasicPassword(body),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["servicenow_grc", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

export const useClearServicenowGrcBasicPassword = (
  opts?: UseMutationOptions<{ ok: boolean }, Error, void>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: () => api.clearServicenowGrcBasicPassword(),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["servicenow_grc", "status"] });
      callerOnSuccess?.(...args);
    },
  });
};

// ---------------------------------------------------------------------------
// POAMs — list/detail reads + generate/export/import + CRUD on POAMs,
// milestones, and objective links. Every mutation invalidates the relevant
// list and detail query keys so the UI never serves stale risk scores.
// ---------------------------------------------------------------------------

export const usePoams = (workbookId?: number, status?: PoamStatus) =>
  useQuery<PoamSummary[]>({
    queryKey: qk.poams(workbookId, status),
    queryFn: () =>
      api.listPoams({
        workbook_id: workbookId,
        status,
      }),
  });

export const usePoam = (id: number | undefined) =>
  useQuery<PoamDetail>({
    queryKey: id ? qk.poam(id) : ["poam", "none"],
    queryFn: () => api.getPoam(id!),
    enabled: !!id,
  });

/**
 * 800-30r1 5-level scale + descriptions for risk dropdowns. Static for the
 * life of the app — cache aggressively. Backend re-derives from the same
 * source-of-truth module, so we never hard-code the strings client-side.
 */
export const usePoamRiskLevels = () =>
  useQuery<RiskLevelInfo[]>({
    queryKey: qk.poamRiskLevels,
    queryFn: api.listPoamRiskLevels,
    staleTime: Infinity,
  });

/**
 * Append-only risk-field audit trail for a POAM. ``useUpdatePoam`` already
 * invalidates the ``["poam", id]`` prefix on success, so any field edit
 * triggers an automatic refetch without needing an extra invalidation
 * branch — same pattern as ``ControlDetail`` + ``useOdpHistory``.
 */
export const usePoamRiskHistory = (id: number | undefined) =>
  useQuery<PoamRiskHistoryEntry[]>({
    queryKey: id ? qk.poamRiskHistory(id) : ["poam", "none", "risk-history"],
    queryFn: () => api.listPoamRiskHistory(id!),
    enabled: !!id,
  });

/**
 * Lazy LLM-advisor suggestion fetch. Only mounts inside ResidualAdvisorCard,
 * so a normal POAM detail render doesn't burn an API key. The hook itself
 * stays disabled until a numeric POAM id is in hand; the card flips the
 * outer ``enabled`` once the assessor opens it (deferred mount).
 *
 * Cache is server-side (KERNEL_VERSION + PROMPT_SHA per
 * ``reference_ccis_assessor_decision_cache``); a React-Query refetch with
 * ``force_refresh=true`` from the Refresh button bypasses the cache.
 */
export const usePoamResidualSuggestion = (
  id: number | undefined,
  opts?: { enabled?: boolean; forceRefresh?: boolean },
) =>
  useQuery<PoamResidualSuggestion>({
    queryKey: id
      ? qk.poamResidualSuggestion(id)
      : ["poam", "none", "residual-suggestion"],
    queryFn: () =>
      api.getPoamResidualSuggestion(id!, {
        force_refresh: opts?.forceRefresh,
      }),
    enabled: !!id && (opts?.enabled ?? true),
    // Decision-cache hits are cheap; misses fire the LLM. Don't auto-refetch
    // on focus or reconnect — the assessor refreshes on demand.
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });

type ApplyResidualArgs = {
  poamId: number;
  residual_risk: RiskLevel;
  residual_risk_rationale: string;
};

/**
 * Accept an LLM-suggested residual risk. Stamps
 * ``residual_risk_source = "llm_suggested"`` server-side (the only codepath
 * that does — PATCH /{id} always stamps ``"manual"``) and writes one row
 * into ``poam_risk_history`` with ``actor="system:residual-advisor"``.
 *
 * Invalidates the POAM detail prefix so risk badges + history card
 * refresh immediately.
 */
export const useApplyPoamResidualSuggestion = (
  opts?: UseMutationOptions<PoamDetail, Error, ApplyResidualArgs>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ poamId, residual_risk, residual_risk_rationale }) =>
      api.applyPoamResidualSuggestion(poamId, {
        residual_risk,
        residual_risk_rationale,
      }),
    ...restOpts,
    onSuccess: (...args) => {
      const [poam] = args;
      qc.setQueryData(qk.poam(poam.id), poam);
      qc.invalidateQueries({ queryKey: qk.poamRiskHistory(poam.id) });
      qc.invalidateQueries({ queryKey: ["poams"] });
      callerOnSuccess?.(...args);
    },
  });
};

type GeneratePoamsResult = Awaited<ReturnType<typeof api.generatePoams>>;

/**
 * Cluster NC assessments into draft POAMs. Idempotent server-side — running
 * twice won't create duplicates. We invalidate every poams() variant so any
 * filtered list view picks up the new rows.
 */
export const useGeneratePoams = (
  opts?: UseMutationOptions<GeneratePoamsResult, Error, number>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (workbook_id: number) => api.generatePoams(workbook_id),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["poams"] });
      callerOnSuccess?.(...args);
    },
  });
};

type ExportPoamsArgs = Parameters<typeof api.exportPoams>[0];
type ExportPoamsResult = Awaited<ReturnType<typeof api.exportPoams>>;

/**
 * Write workbook POAMs to a copy of the eMASS template. Bumps every POAM's
 * `exported_at`, so we invalidate poams() lists *and* the individual detail
 * cache for the workbook's rows.
 */
export const useExportPoams = (
  opts?: UseMutationOptions<ExportPoamsResult, Error, ExportPoamsArgs>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (body: ExportPoamsArgs) => api.exportPoams(body),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["poams"] });
      qc.invalidateQueries({ queryKey: ["poam"] });
      callerOnSuccess?.(...args);
    },
  });
};

type ImportPoamsArgs = Parameters<typeof api.importPoams>[0];
type ImportPoamsResult = Awaited<ReturnType<typeof api.importPoams>>;

/** Read an eMASS POAM workbook back into the DB (merge by emass_poam_id). */
export const useImportPoams = (
  opts?: UseMutationOptions<ImportPoamsResult, Error, ImportPoamsArgs>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (body: ImportPoamsArgs) => api.importPoams(body),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["poams"] });
      qc.invalidateQueries({ queryKey: ["poam"] });
      callerOnSuccess?.(...args);
    },
  });
};

type ExportControlsEmassArgs = Parameters<typeof api.exportControlsEmass>[0];
type ExportControlsEmassResult = Awaited<
  ReturnType<typeof api.exportControlsEmass>
>;

/**
 * Write in-scope controls into a copy of the user's eMASS template via
 * xlwings. The export stamps ``Workbook.exported_at`` so the workbook
 * summary needs to refetch; we invalidate the broad ``["workbook"]``
 * prefix to catch both the summary and detail caches.
 */
export const useExportControlsEmass = (
  opts?: UseMutationOptions<
    ExportControlsEmassResult,
    Error,
    ExportControlsEmassArgs
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body: ExportControlsEmassArgs) =>
      api.exportControlsEmass(body),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["workbook"] });
      qc.invalidateQueries({ queryKey: ["workbooks"] });
      callerOnSuccess?.(...args);
    },
  });
};

type ExportControlsWorkingArgs = Parameters<typeof api.exportControlsWorking>[0];
type ExportControlsWorkingResult = Awaited<
  ReturnType<typeof api.exportControlsWorking>
>;

/**
 * Emit a fresh xlsx mirroring the current Controls list filter state. Does
 * NOT stamp ``exported_at`` (working artifact, not a deliverable), so no
 * cache invalidation is required.
 */
export const useExportControlsWorking = (
  opts?: UseMutationOptions<
    ExportControlsWorkingResult,
    Error,
    ExportControlsWorkingArgs
  >,
) => {
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body: ExportControlsWorkingArgs) =>
      api.exportControlsWorking(body),
    ...restOpts,
    onSuccess: (...args) => {
      callerOnSuccess?.(...args);
    },
  });
};

type ImportControlsNarrativesArgs = Parameters<
  typeof api.importControlsNarratives
>[0];
type ImportControlsNarrativesResult = Awaited<
  ReturnType<typeof api.importControlsNarratives>
>;

/**
 * Upsert Assessments from an operator-filled eMASS Test Result template.
 * The import writes assessment rows (status + narrative), which flips
 * control grid badges, workbook summary counts, and POAM eligibility, so
 * sweep the broad assessment / controls / workbook / poams prefixes.
 */
export const useImportControlsNarratives = (
  opts?: UseMutationOptions<
    ImportControlsNarrativesResult,
    Error,
    ImportControlsNarrativesArgs
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body: ImportControlsNarrativesArgs) =>
      api.importControlsNarratives(body),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["assessments"] });
      qc.invalidateQueries({ queryKey: ["controls"] });
      qc.invalidateQueries({ queryKey: ["control"] });
      qc.invalidateQueries({ queryKey: ["workbook"] });
      qc.invalidateQueries({ queryKey: ["workbooks"] });
      qc.invalidateQueries({ queryKey: ["poams"] });
      callerOnSuccess?.(...args);
    },
  });
};

export const useCreatePoam = (
  opts?: UseMutationOptions<PoamDetail, Error, CreatePoamRequest>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (body: CreatePoamRequest) => api.createPoam(body),
    ...restOpts,
    onSuccess: (poam, ...rest) => {
      qc.invalidateQueries({ queryKey: ["poams"] });
      // Seed the detail cache so navigating straight to the new POAM after
      // create is instant.
      qc.setQueryData(qk.poam(poam.id), poam);
      callerOnSuccess?.(poam, ...rest);
    },
  });
};

export const useUpdatePoam = (
  poamId: number,
  opts?: UseMutationOptions<PoamDetail, Error, UpdatePoamRequest>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (body: UpdatePoamRequest) => api.updatePoam(poamId, body),
    ...restOpts,
    onSuccess: (poam, ...rest) => {
      qc.setQueryData(qk.poam(poamId), poam);
      qc.invalidateQueries({ queryKey: ["poams"] });
      callerOnSuccess?.(poam, ...rest);
    },
  });
};

export const useDeletePoam = (
  opts?: UseMutationOptions<{ ok: boolean; id: number }, Error, number>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (id: number) => api.deletePoam(id),
    ...restOpts,
    onSuccess: (res, id, ...rest) => {
      qc.removeQueries({ queryKey: qk.poam(id) });
      qc.invalidateQueries({ queryKey: ["poams"] });
      callerOnSuccess?.(res, id, ...rest);
    },
  });
};

type DeleteAllPoamsArgs = Parameters<typeof api.deleteAllPoams>[0];
type DeleteAllPoamsResult = Awaited<ReturnType<typeof api.deleteAllPoams>>;

/**
 * Bulk-delete POAMs matching the current list filter (workbook_id + status).
 * Mirrors the scoping of `usePoams` so "delete all" removes exactly what the
 * user sees — pass the same filter args as the list query.
 *
 * Invalidates every `["poams"]` variant and the `["poam"]` prefix (covers
 * all per-id detail/history/suggestion caches) so nothing stale lingers.
 */
export const useDeleteAllPoams = (
  opts?: UseMutationOptions<DeleteAllPoamsResult, Error, DeleteAllPoamsArgs>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (args: DeleteAllPoamsArgs) => api.deleteAllPoams(args),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: ["poams"] });
      qc.invalidateQueries({ queryKey: ["poam"] });
      callerOnSuccess?.(...args);
    },
  });
};

// ---- Objective links --------------------------------------------------------

type LinkResult = Awaited<ReturnType<typeof api.linkPoamObjective>>;

export const useLinkPoamObjective = (
  poamId: number,
  opts?: UseMutationOptions<LinkResult, Error, number>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (objective_id: number) => api.linkPoamObjective(poamId, objective_id),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.poam(poamId) });
      qc.invalidateQueries({ queryKey: ["poams"] }); // objective_count moved
      callerOnSuccess?.(...args);
    },
  });
};

export const useUnlinkPoamObjective = (
  poamId: number,
  opts?: UseMutationOptions<{ ok: boolean }, Error, number>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (objective_id: number) => api.unlinkPoamObjective(poamId, objective_id),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.poam(poamId) });
      qc.invalidateQueries({ queryKey: ["poams"] });
      callerOnSuccess?.(...args);
    },
  });
};

// ---- Evidence links ---------------------------------------------------------
//
// Same shape as the objective hooks above — POST/DELETE against the join
// table, invalidate the POAM detail (which carries evidence[]) plus the list
// (which carries evidence_count for the card badge).

type EvidenceLinkResult = Awaited<ReturnType<typeof api.linkPoamEvidence>>;

/** Variables for useLinkPoamEvidence — note is optional and may be null to clear. */
export interface LinkPoamEvidenceVars {
  evidence_id: number;
  note?: string | null;
}

export const useLinkPoamEvidence = (
  poamId: number,
  opts?: UseMutationOptions<EvidenceLinkResult, Error, LinkPoamEvidenceVars>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: ({ evidence_id, note }: LinkPoamEvidenceVars) =>
      api.linkPoamEvidence(poamId, evidence_id, note),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.poam(poamId) });
      qc.invalidateQueries({ queryKey: ["poams"] }); // evidence_count moved
      callerOnSuccess?.(...args);
    },
  });
};

export const useUnlinkPoamEvidence = (
  poamId: number,
  opts?: UseMutationOptions<{ ok: boolean }, Error, number>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (evidence_id: number) => api.unlinkPoamEvidence(poamId, evidence_id),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.poam(poamId) });
      qc.invalidateQueries({ queryKey: ["poams"] });
      callerOnSuccess?.(...args);
    },
  });
};

// ---- Milestones -------------------------------------------------------------

export const useCreatePoamMilestone = (
  poamId: number,
  opts?: UseMutationOptions<PoamMilestone, Error, MilestoneCreateRequest>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (body: MilestoneCreateRequest) =>
      api.createPoamMilestone(poamId, body),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.poam(poamId) });
      qc.invalidateQueries({ queryKey: ["poams"] }); // milestone_count moved
      callerOnSuccess?.(...args);
    },
  });
};

export const useUpdatePoamMilestone = (
  poamId: number,
  milestoneId: number,
  opts?: UseMutationOptions<PoamMilestone, Error, MilestoneUpdateRequest>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (body: MilestoneUpdateRequest) =>
      api.updatePoamMilestone(poamId, milestoneId, body),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.poam(poamId) });
      callerOnSuccess?.(...args);
    },
  });
};

export const useDeletePoamMilestone = (
  poamId: number,
  opts?: UseMutationOptions<{ ok: boolean; id: number }, Error, number>,
) => {
  const qc = useQueryClient();
    const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
return useMutation({
    mutationFn: (milestone_id: number) =>
      api.deletePoamMilestone(poamId, milestone_id),
    ...restOpts,
    onSuccess: (...args) => {
      qc.invalidateQueries({ queryKey: qk.poam(poamId) });
      qc.invalidateQueries({ queryKey: ["poams"] });
      callerOnSuccess?.(...args);
    },
  });
};

// ---------------------------------------------------------------------------
// Automation — per-workbook evidence-pull schedules
// ---------------------------------------------------------------------------

/**
 * List automation schedules, optionally filtered to a single workbook.
 */
export const useAutomationSchedules = (workbookId?: number) =>
  useQuery<AutomationSchedule[]>({
    queryKey: qk.automationSchedules(workbookId),
    queryFn: () => api.listAutomationSchedules(workbookId),
  });

export const useCreateAutomationSchedule = (
  opts?: UseMutationOptions<AutomationSchedule, Error, AutomationScheduleCreate>,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: (body: AutomationScheduleCreate) =>
      api.createAutomationSchedule(body),
    ...restOpts,
    onSuccess: (...args) => {
      const [, vars] = args;
      // Invalidate the list for the specific workbook + the global unscoped list
      qc.invalidateQueries({ queryKey: qk.automationSchedules(vars.workbook_id) });
      qc.invalidateQueries({ queryKey: qk.automationSchedules() });
      callerOnSuccess?.(...args);
    },
  });
};

export const useUpdateAutomationSchedule = (
  opts?: UseMutationOptions<
    AutomationSchedule,
    Error,
    { id: number; patch: AutomationSchedulePatch; workbookId?: number }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ id, patch }) => api.updateAutomationSchedule(id, patch),
    ...restOpts,
    onSuccess: (...args) => {
      const [, vars] = args;
      qc.invalidateQueries({ queryKey: qk.automationSchedules(vars.workbookId) });
      qc.invalidateQueries({ queryKey: qk.automationSchedules() });
      qc.invalidateQueries({ queryKey: qk.automationSchedule(vars.id) });
      callerOnSuccess?.(...args);
    },
  });
};

export const useDeleteAutomationSchedule = (
  opts?: UseMutationOptions<
    void,
    Error,
    { id: number; workbookId?: number }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: async ({ id }) => { await api.deleteAutomationSchedule(id); },
    ...restOpts,
    onSuccess: (...args) => {
      const [, vars] = args;
      qc.invalidateQueries({ queryKey: qk.automationSchedules(vars.workbookId) });
      qc.invalidateQueries({ queryKey: qk.automationSchedules() });
      qc.removeQueries({ queryKey: qk.automationSchedule(vars.id) });
      callerOnSuccess?.(...args);
    },
  });
};

export const useRunAutomationScheduleNow = (
  opts?: UseMutationOptions<
    AutomationSchedule,
    Error,
    { id: number; workbookId?: number }
  >,
) => {
  const qc = useQueryClient();
  const { onSuccess: callerOnSuccess, ...restOpts } = opts ?? {};
  return useMutation({
    mutationFn: ({ id }) => api.runAutomationScheduleNow(id),
    ...restOpts,
    onSuccess: (...args) => {
      const [, vars] = args;
      qc.invalidateQueries({ queryKey: qk.automationSchedules(vars.workbookId) });
      qc.invalidateQueries({ queryKey: qk.automationSchedules() });
      qc.invalidateQueries({ queryKey: qk.automationSchedule(vars.id) });
      callerOnSuccess?.(...args);
    },
  });
};
