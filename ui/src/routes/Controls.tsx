import { Fragment, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
} from "@tanstack/react-table";
import { useQueries, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Download,
  FileSpreadsheet,
  FileUp,
  Loader2,
  Save,
  Search,
  Sparkles,
} from "lucide-react";

import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { toast } from "@/components/ui/toaster";
import { humanize } from "@/lib/errors";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from "@/components/ui/dropdown-menu";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  ComplianceTargetPicker,
  type ComplianceTarget,
} from "@/components/ComplianceTargetPicker";
import {
  qk,
  useApplyAllToWorkbook,
  useBaselineControls,
  useControls,
  useExportControlsEmass,
  useExportControlsWorking,
  useImportControlsNarratives,
  useFrameworks,
  useObjectives,
  useWorkbookControlStatus,
  useWorkbookOverlayMembership,
  useWorkbooks,
} from "@/lib/queries";
import { api, hasNativeBridge } from "@/lib/api";
import type {
  Assessment,
  BaselineControlRow,
  Control,
  ControlStatusRollup,
  Objective,
} from "@/lib/api";
import { useAssessBatchContext } from "@/contexts/AssessBatchContext";

type RollupStatus = ControlStatusRollup["status"];

interface ControlRow extends Control {
  status?: RollupStatus;
  status_counts?: {
    compliant: number;
    non_compliant: number;
    na: number;
    needs_review: number;
    // v0.2 citation-hygiene: count of TRUSTED-verdict rows on this
    // control whose narrative still cites a superseded doc name. The row
    // exports normally; this count only powers a compact "Cite refresh"
    // pill so the assessor can spot pending narrative swaps without
    // expanding the row.
    rewrites_requested: number;
  };
  in_scope?: boolean;
  // CRM overlay responsibility for this control, keyed by the CRM overlay's
  // baseline_id. Each attached CRM (one per scope_label — e.g. one for AWS
  // GovCloud, one for Azure Government) gets its own entry so the grid can
  // render one column per CRM instead of collapsing them. Each value carries
  // the cloud + on-prem responsibility pair (provider / inherited / hybrid /
  // not_applicable / customer) for that CRM. Empty when no CRM is attached or
  // the CRM doesn't carry a row for this control. Powers both the per-CRM
  // grid columns and the CSV export's per-CRM columns; the per-control detail
  // view renders the actual pills + narratives.
  crm?: Record<number, CrmResp>;
}

// Per-CRM responsibility values for a single control, both deployment scopes.
interface CrmResp {
  responsibility: string | null;
  responsibility_narrative: string | null;
  responsibility_onprem: string | null;
  responsibility_onprem_narrative: string | null;
}

export function Controls() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const frameworks = useFrameworks();
  const workbooks = useWorkbooks();
  // Tracks the in-progress CSV export so the button can show a spinner and
  // disable itself — the export fans out to N×2 lazy fetches (objectives +
  // assessments per visible control), which can take a second or two on a
  // large baseline. Without this the user has no signal anything's happening.
  const [exporting, setExporting] = useState(false);

  const fws = frameworks.data ?? [];
  const [target, setTarget] = useState<ComplianceTarget | undefined>();
  const [workbookId, setWorkbookId] = useState<number | undefined>();
  const [inScopeOnly, setInScopeOnly] = useState(true);
  // Overlay-covered filter — orthogonal to baseline in_scope. Overlay coverage
  // is the program-overlay layer's scope signal: a control cited by ANY loaded
  // overlay (SDA, T1TL, future) is in scope for the assessment. Baseline
  // in_scope (above) is the baseline workbook's own scope flag. Both can be
  // toggled together to intersect, or independently.
  const [overlayCoveredOnly, setOverlayCoveredOnly] = useState(false);
  const [familyFilter, setFamilyFilter] = useState<string>("__all__");
  const [statusFilter, setStatusFilter] = useState<string>("__all__");
  const [globalFilter, setGlobalFilter] = useState("");
  // Open when user clicks "Assess all in-scope" and there are CCIs that already
  // have a persisted Assessment row in the current scope — lets them choose
  // skip vs re-assess instead of us silently doing one or the other.
  const [reassessOpen, setReassessOpen] = useState(false);
  // eMASS-strict export dialog — copies the user's controls template via
  // xlwings, inserts a Program-Specific Controls column, writes one row per
  // in-scope control. Distinct from the working-view export below.
  const [emassExportOpen, setEmassExportOpen] = useState(false);
  const [emassTemplatePath, setEmassTemplatePath] = useState("");
  const [emassOutputPath, setEmassOutputPath] = useState("");
  // Working-view export dialog — fresh openpyxl xlsx mirroring the current
  // page filter (family/status/search), one row per OBJECTIVE so needs_review
  // rows surface for triage. Never an eMASS deliverable.
  const [workingExportOpen, setWorkingExportOpen] = useState(false);
  const [workingOutputPath, setWorkingOutputPath] = useState("");
  // Narrative import dialog — reads an operator-filled eMASS Test Result
  // template (column N status / P tester / O date / Q narrative), upserts
  // one Assessment per in-scope CCI. Import only: NC rows land
  // needs_review=False so they feed the existing Generate POAMs step.
  const [importNarrativesOpen, setImportNarrativesOpen] = useState(false);
  const [importNarrativesPath, setImportNarrativesPath] = useState("");
  // Post-batch triage modal — opens after Assess all completes when one or
  // more rows landed in needs_review. Per the precision-over-recall contract
  // those rows are blocked from CCIS / POAM export until a human clears the
  // flag, so we push the user straight to /review-queue rather than letting
  // them assume the batch is "done". Counters are snapshot from the result
  // so the modal copy survives subsequent batches.
  const [reviewModalOpen, setReviewModalOpen] = useState(false);
  const [reviewModalCounts, setReviewModalCounts] = useState<{
    accepted: number;
    unresolved: number;
    applied: number;
    // CCIs the worker raised on — already in result.decisions[] with error
    // set but accepted=false and no Assessment row, so /review-queue won't
    // show them. Snapshot here for the modal table so the user knows which
    // specific CCIs to re-run.
    errored: { objective_id: string; excel_row: number; error: string }[];
    // CCIs the validator rejected after all retries — accepted=false, no
    // exception (so no `error`), but decision.rejections carries the reason.
    // Same boat as `errored` — no Assessment row, won't appear in
    // /review-queue, must be re-run from Controls — but the remediation copy
    // differs (rule-11 retry exhaustion is usually an evidence-quality issue,
    // not a worker bug).
    rejected: { objective_id: string; excel_row: number; reason: string }[];
    // CCIs the baseline references but the workbook doesn't list (manual
    // col-A edit, framework mismatch). Same shape as the wire payload.
    skipped: { objective_id: string; reason: string }[];
    // CCIs that *did* produce a decision but landed in needs_review — these
    // DO have an Assessment row and /review-queue will surface them; we
    // count them for the modal copy but don't list them per-row.
    needsReview: number;
    // Auto-apply step skipped these for needs_review — separate signal from
    // freshly-assessed needs_review since these came from prior runs.
    skippedNeedsReview: number;
  }>({
    accepted: 0,
    unresolved: 0,
    applied: 0,
    errored: [],
    rejected: [],
    skipped: [],
    needsReview: 0,
    skippedNeedsReview: 0,
  });
  const nativeBridge = hasNativeBridge();
  // Per-row CCI expansion. Set of Control.id values that are currently open.
  // Each expanded row lazy-fetches its objectives via useObjectives(id).
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const toggleExpanded = (id: number) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // Controls grid scopes by framework only — baseline scope flows from the
  // selected workbook (BaselineControl rows materialized at workbook open),
  // so we ignore target.baselineId here and just propagate frameworkId.
  const frameworkId = target?.frameworkId;

  // Default workbook: most recent. The workbook drives the framework, because
  // ODP assignments are framework-scoped — resolving a control's ODPs requires
  // querying the SAME framework the workbook was ingested under. Defaulting the
  // framework independently (e.g. to fws[0] = the r5 catalog) while the workbook
  // lives under r4 makes resolve_odps query a framework with zero OdpAssignment
  // rows, so `{{ insert: param, ... }}` placeholders render as literal brackets.
  useEffect(() => {
    if (!workbooks.data || workbooks.data.length === 0) return;
    // Track the active (most-recently-opened) workbook. There is no picker:
    // opening a workbook on the Workbooks page bumps last_opened, reorders this
    // list, and this effect re-points scope at it. Realign the framework too so
    // ODP resolution targets the framework the workbook was ingested under.
    const wb = workbooks.data[0];
    if (workbookId !== wb.id) {
      setWorkbookId(wb.id);
      if (wb.framework_id != null) {
        setTarget({ frameworkId: wb.framework_id });
      }
    }
  }, [workbookId, workbooks.data, target]);
  // Fallback: only default the framework to the first catalog when there is no
  // workbook to take it from (empty install / workbook-less browsing). Default
  // to the first ENABLED framework (migration 0012 display gate) so we never
  // auto-land on a disabled catalog; fall back to fws[0] only if every
  // framework is disabled (degenerate, but keeps the page usable).
  useEffect(() => {
    if (!target && (!workbooks.data || workbooks.data.length === 0) && fws.length > 0) {
      const firstEnabled = fws.find((f) => f.enabled !== false) ?? fws[0];
      setTarget({ frameworkId: firstEnabled.id });
    }
  }, [target, fws, workbooks.data]);

  const controls = useControls(frameworkId);
  const selectedWorkbook = workbooks.data?.find((w) => w.id === workbookId);
  const baselineId = selectedWorkbook?.baseline_id ?? undefined;
  const baselineControls = useBaselineControls(baselineId, false);
  const controlStatus = useWorkbookControlStatus(workbookId);
  const overlayMembership = useWorkbookOverlayMembership(workbookId);

  // CRM overlay baselines attached to this workbook. The CRM loader writes
  // responsibility/responsibility_onprem onto its OWN baseline's
  // BaselineControl rows (under baseline_id = CRM PK), not onto the
  // workbook's primary baseline. So to surface inheritance + cloud/on-prem
  // chips in the grid we have to fetch those overlay rows in parallel and
  // merge by control_code. The primary baselineControls fetch above stays
  // the source of truth for in_scope and tailoring.
  const crmOverlayBaselineIds = useMemo(
    () =>
      (overlayMembership.data?.overlays ?? [])
        .filter((o) => o.source_type === "crm")
        .map((o) => o.baseline_id),
    [overlayMembership.data],
  );
  // BaselineControl rows grouped BY CRM overlay so each CRM keeps its own
  // identity in the grid. The combine results array is index-aligned with
  // the queries array (and therefore with crmOverlayBaselineIds), so we zip
  // them back together to recover which baseline each row set came from —
  // the rows themselves don't carry baseline_id. `combine` runs inside
  // useQueries and returns a stable reference that only changes when
  // underlying query data changes, sidestepping the variable-length useMemo
  // dep array pitfall (React doesn't reliably handle deps arrays whose
  // length changes between renders).
  const crmRowsByBaseline = useQueries({
    queries: crmOverlayBaselineIds.map((id) => ({
      queryKey: qk.baselineControls(id, false),
      queryFn: () => api.listBaselineControls(id, false),
    })),
    combine: (results) =>
      results.map((r, i) => ({
        baseline_id: crmOverlayBaselineIds[i],
        rows: (r.data ?? []) as BaselineControlRow[],
      })),
  });

  // The batch mutation + polling + global toasts live in
  // ``<AssessBatchProvider>`` mounted above ``<Routes>``. Hoisting it
  // there keeps the progress strip visible and the auto-apply chain
  // running when the user navigates away from this route mid-batch —
  // see ``contexts/AssessBatchContext.tsx`` for the why. The page-local
  // useEffect below watches ``lastResult`` so the post-batch triage
  // modal still pops when a completed batch lands for the workbook
  // currently being viewed.
  const {
    runBatch,
    isPending: assessIsPending,
    lastResult,
    acknowledgeResult,
  } = useAssessBatchContext();

  // Pop the post-batch triage modal when a completed batch lands for
  // the workbook on screen. Only reacts when ``lastResult.vars.workbook_id``
  // matches — if the user kicked off a batch on workbook A and then
  // switched to workbook B before it finished, popping A's modal on
  // B's Controls page would be confusing. Result stays stashed in the
  // provider until consumed; navigating back to A's Controls will
  // surface it then.
  useEffect(() => {
    if (!lastResult) return;
    if (lastResult.vars.workbook_id !== workbookId) return;

    const { result: r } = lastResult;
    const auto = r.auto_applied;
    const errored = r.decisions.filter((d) => !d.accepted && d.error);
    // Validator rejected all retries: accepted=false, no exception (so no
    // `error`), reason lives in decision.rejections[]. Same fate as
    // `errored` — no Assessment row, must be re-run — but the remediation
    // hint is different (evidence quality, not worker bug). Filtering on
    // rejections.length>0 keeps this disjoint from the `errored` bucket
    // (exceptions never populate rejections).
    const rejected = r.decisions.filter(
      (d) => !d.accepted && !d.error && d.rejections.length > 0,
    );
    const needsReview = r.decisions.filter((d) => d.needs_review).length;
    const skippedNeedsReview = auto?.skipped_needs_review ?? 0;
    const anyTroubleSignal =
      errored.length > 0 ||
      rejected.length > 0 ||
      needsReview > 0 ||
      r.skipped.length > 0 ||
      skippedNeedsReview > 0;

    if (anyTroubleSignal) {
      setReviewModalCounts({
        accepted: r.accepted,
        unresolved: r.unresolved,
        applied: auto?.applied ?? 0,
        errored: errored.map((d) => ({
          objective_id: d.objective_id,
          excel_row: d.excel_row,
          error: d.error ?? "no_decision",
        })),
        // Last rejection wins — it's the one the validator settled on
        // after the retry loop exhausted itself, so it's the most
        // actionable single line to show in a compact list.
        rejected: rejected.map((d) => ({
          objective_id: d.objective_id,
          excel_row: d.excel_row,
          reason:
            d.rejections[d.rejections.length - 1]?.reason ?? "rejected",
        })),
        skipped: r.skipped,
        needsReview,
        skippedNeedsReview,
      });
      setReviewModalOpen(true);
    }

    // Clear so the effect doesn't re-fire on every render until the
    // next batch lands. Idempotent in the provider.
    acknowledgeResult();
  }, [lastResult, workbookId, acknowledgeResult]);

  // eMASS-strict controls export — drives the user's enterprise-services
  // controls.xlsx template through xlwings, inserts a PSC column after
  // Control Acronym, writes one row per in-scope control (skipping
  // needs_review per the precision-over-recall contract).
  const exportEmassMut = useExportControlsEmass({
    onSuccess: (r) => {
      setEmassExportOpen(false);
      const pscTail =
        r.controls_with_psc > 0
          ? ` · ${r.controls_with_psc} with PSC mappings`
          : "";
      const skipTail =
        r.skipped.length > 0
          ? ` · ${r.skipped.length} skipped (needs_review or no objectives)`
          : "";
      const warnTail =
        r.template_warnings.length > 0
          ? ` · ${r.template_warnings.length} template warning${r.template_warnings.length === 1 ? "" : "s"}`
          : "";
      toast.success(
        "eMASS controls export complete",
        `${r.rows_written} rows written → ${r.output_path}${pscTail}${skipTail}${warnTail}`,
      );
    },
    onError: (err) => toast.error("eMASS export failed", humanize(err)),
  });

  // Working-view export — fresh openpyxl xlsx mirroring the current
  // page filter, one row per OBJECTIVE so needs_review surfaces for
  // triage. Never an eMASS deliverable; does not stamp exported_at.
  const exportWorkingMut = useExportControlsWorking({
    onSuccess: (r) => {
      setWorkingExportOpen(false);
      toast.success(
        "Working-view export complete",
        `${r.rows_written} row${r.rows_written === 1 ? "" : "s"} written → ${r.output_path}`,
      );
    },
    onError: (err) => toast.error("Working-view export failed", humanize(err)),
  });

  // Bulk "Apply all to workbook" — one xlwings session for every writable
  // assessment that's still pending writeback. Backend silently skips
  // needs_review rows (precision-over-recall) and already-written rows
  // (idempotent rerun), surfacing both counters in the success toast so
  // the user can spot the gap between "N assessed" and "M written".
  // Respects the current family filter so the button matches what the
  // user can see in the grid.
  const applyAllMut = useApplyAllToWorkbook({
    onSuccess: (r) => {
      const skipBits: string[] = [];
      if (r.skipped_needs_review > 0)
        skipBits.push(`${r.skipped_needs_review} needs_review`);
      if (r.skipped_already_written > 0)
        skipBits.push(`${r.skipped_already_written} already written`);
      if (r.skipped_no_excel_row > 0)
        skipBits.push(`${r.skipped_no_excel_row} no excel row`);
      const skipTail = skipBits.length > 0 ? ` · skipped ${skipBits.join(", ")}` : "";
      const target = r.summary?.workbook ?? "";
      toast.success(
        "Workbook updated",
        `${r.applied} row${r.applied === 1 ? "" : "s"} written${target ? ` → ${target}` : ""}${skipTail}`,
      );
    },
    onError: (err) => toast.error("Apply to workbook failed", humanize(err)),
  });

  // Narrative import — upserts Assessments from an operator-filled eMASS
  // Test Result template. Import only (no LLM, no POAM gen); the success
  // toast reports the write counts plus the three reconciliation buckets so
  // the user can spot CCIs the file didn't land.
  const importNarrativesMut = useImportControlsNarratives({
    onSuccess: (r) => {
      setImportNarrativesOpen(false);
      const skipBits: string[] = [];
      if (r.unmatched.length > 0)
        skipBits.push(`${r.unmatched.length} not in scope`);
      if (r.skipped_no_status.length > 0)
        skipBits.push(`${r.skipped_no_status.length} no status`);
      if (r.skipped_no_narrative.length > 0)
        skipBits.push(`${r.skipped_no_narrative.length} no narrative`);
      const skipTail = skipBits.length > 0 ? ` · skipped ${skipBits.join(", ")}` : "";
      toast.success(
        "Narrative import complete",
        `${r.imported} new · ${r.updated} updated (of ${r.total_rows} file rows)${skipTail}`,
      );
    },
    onError: (err) => toast.error("Narrative import failed", humanize(err)),
  });

  async function pickEmassTemplate() {
    if (!nativeBridge) return;
    const p = await window.ccis!.openFile([
      { name: "eMASS Controls template", extensions: ["xlsx", "xlsm"] },
    ]);
    if (p) setEmassTemplatePath(p);
  }

  async function pickImportNarrativesFile() {
    if (!nativeBridge) return;
    const p = await window.ccis!.openFile([
      { name: "eMASS Test Result template", extensions: ["xlsx", "xlsm"] },
    ]);
    if (p) setImportNarrativesPath(p);
  }

  function submitImportNarratives() {
    if (!workbookId) return;
    importNarrativesMut.mutate({
      workbook_id: workbookId,
      file_path: importNarrativesPath.trim(),
    });
  }

  function submitEmassExport() {
    if (!workbookId) return;
    exportEmassMut.mutate({
      workbook_id: workbookId,
      template_path: emassTemplatePath.trim(),
      output_path: emassOutputPath.trim(),
    });
  }

  function submitWorkingExport() {
    if (!workbookId) return;
    exportWorkingMut.mutate({
      workbook_id: workbookId,
      output_path: workingOutputPath.trim(),
      // Backend treats null/missing as "no filter". The UI uses "__all__"
      // sentinels in the picker; translate them out before posting.
      family: familyFilter !== "__all__" ? familyFilter : undefined,
      status: statusFilter !== "__all__" ? statusFilter : undefined,
      search: globalFilter.trim() || undefined,
    });
  }

  // control_id -> rollup row, for O(1) lookup while building grid rows.
  const statusByControl = useMemo(() => {
    const m = new Map<number, ControlStatusRollup>();
    for (const s of controlStatus.data ?? []) m.set(s.control_id, s);
    return m;
  }, [controlStatus.data]);

  // Map control_code (e.g. AC-2 or AC-2(1)) -> in_scope. The backend now holds
  // scope on BaselineControl directly, so we read it 1:1 instead of OR-aggregating
  // across CCIs client-side. Falls back to false for controls the baseline never
  // saw — the in-scope filter and Scope badge both treat that as "out".
  const inScopeByControl = useMemo(() => {
    const m = new Map<string, boolean>();
    for (const bc of baselineControls.data ?? []) {
      m.set(bc.control_code, bc.in_scope);
    }
    return m;
  }, [baselineControls.data]);

  // baseline_id -> (control_code -> CRM responsibility + narrative per
  // deployment scope). One inner map per attached CRM overlay so each CRM
  // (one per scope_label) keeps its own per-control values instead of being
  // collapsed last-write-wins into a single column. An entry is created when
  // EITHER scope is set so cloud-only and on-prem-only CRMs both surface.
  // Empty outer map when the workbook has no CRM, so the grid renders no CRM
  // columns and the CSV export omits them for non-CRM workflows.
  const responsibilityByBaseline = useMemo(() => {
    const byBaseline = new Map<number, Map<string, CrmResp>>();
    for (const { baseline_id, rows } of crmRowsByBaseline) {
      const inner = new Map<string, CrmResp>();
      for (const bc of rows) {
        if (bc.responsibility || bc.responsibility_onprem) {
          inner.set(bc.control_code, {
            responsibility: bc.responsibility ?? null,
            responsibility_narrative: bc.responsibility_narrative ?? null,
            responsibility_onprem: bc.responsibility_onprem ?? null,
            responsibility_onprem_narrative:
              bc.responsibility_onprem_narrative ?? null,
          });
        }
      }
      if (inner.size > 0) byBaseline.set(baseline_id, inner);
    }
    return byBaseline;
  }, [crmRowsByBaseline]);

  // Set of Control.id values that are cited "in" by at least one loaded overlay.
  // Per the overlay resolver pattern, overlay coverage IS the assessment's
  // in-scope set; an oscal_profile (FedRAMP) entry is excluded because it's a
  // primary baseline, not an annotation overlay.
  const overlayCoveredControlIds = useMemo(() => {
    const covered = new Set<number>();
    const byControl = overlayMembership.data?.by_control ?? {};
    const overlayBaselineIds = new Set(
      (overlayMembership.data?.overlays ?? [])
        .filter((o) => o.source_type !== "oscal_profile")
        .map((o) => o.baseline_id),
    );
    for (const [controlId, perBaseline] of Object.entries(byControl)) {
      for (const [bid, state] of Object.entries(perBaseline)) {
        if (state === "in" && overlayBaselineIds.has(Number(bid))) {
          covered.add(Number(controlId));
          break;
        }
      }
    }
    return covered;
  }, [overlayMembership.data]);

  const hasOverlays = useMemo(
    () =>
      (overlayMembership.data?.overlays ?? []).some(
        (o) => o.source_type !== "oscal_profile",
      ),
    [overlayMembership.data],
  );

  const families = useMemo(() => {
    const s = new Set<string>();
    for (const c of controls.data ?? []) s.add(c.family);
    return Array.from(s).sort();
  }, [controls.data]);

  // Upper-bound estimate of assessments that the bulk-apply button could
  // push to the workbook: total_assessed minus needs_review across the
  // current family/in-scope filter. This is an UPPER BOUND because we
  // can't distinguish already-written rows here (ControlStatusRollup
  // doesn't carry written_to_workbook_at). The backend silently skips
  // already-written rows on the apply call, so the user sees the real
  // count in the success toast — this just makes the button label
  // useful instead of a bare "Apply to workbook".
  const writableUpperBound = useMemo(() => {
    if (!controlStatus.data) return 0;
    let n = 0;
    for (const c of controls.data ?? []) {
      if (familyFilter !== "__all__" && c.family !== familyFilter) continue;
      if (inScopeOnly && baselineId && inScopeByControl.get(c.control_id) !== true) continue;
      if (overlayCoveredOnly && hasOverlays && !overlayCoveredControlIds.has(c.id)) continue;
      const rollup = statusByControl.get(c.id);
      if (!rollup) continue;
      if (statusFilter !== "__all__") {
        if (statusFilter === "__unassessed__") {
          if (rollup.status) continue;
        } else if (rollup.status !== statusFilter) continue;
      }
      const writable = rollup.total_assessed - rollup.needs_review;
      if (writable > 0) n += writable;
    }
    return n;
  }, [
    controls.data,
    controlStatus.data,
    familyFilter,
    inScopeOnly,
    overlayCoveredOnly,
    hasOverlays,
    statusFilter,
    baselineId,
    inScopeByControl,
    overlayCoveredControlIds,
    statusByControl,
  ]);

  function fireBatch(skipExisting: boolean) {
    if (!workbookId) return;
    // Send the currently-visible control IDs so every active grid filter
    // (in-scope toggle, overlay-covered toggle, family filter, status
    // filter) composes into the batch. Without this the server would
    // re-derive scope from BaselineControl.in_scope alone and the user's
    // "Assess all in-scope" click would steamroll over a tighter UI
    // filter — exactly the bug reported when the in-scope toggle was on
    // but the batch still hit all 312 rows.
    //
    // ``family`` is still sent as a defense-in-depth cheap filter, but
    // the control_ids list is now the authoritative scope on the server.
    runBatch({
      workbook_id: workbookId,
      family: familyFilter !== "__all__" ? familyFilter : undefined,
      control_ids: rows.map((r) => r.id),
      skip_existing: skipExisting,
      persist: true,
    });
  }

  function startBatch() {
    // Gate on EITHER the in-scope count OR the workbook-wide count.
    // See assessedInWorkbook for the failure modes the wider count
    // covers (loading state, framework mismatch, narrow filters).
    if (assessedInScope > 0 || assessedInWorkbook > 0) {
      setReassessOpen(true);
    } else {
      fireBatch(true);
    }
  }

  // CSV export of the currently-filtered grid, flattened to ONE ROW PER CCI.
  //
  // Why one row per CCI and not one per control? Earlier versions of this
  // export wrote a single row per control with aggregated counts
  // (compliant/non_compliant/na/total_assessed), which left the actual CCI
  // identifiers, text, and per-CCI status out entirely — the user reported
  // them as missing. Auditors and program leads want to slice/sort by CCI in
  // Excel, so a control row gets repeated once per CCI under it; control-level
  // metadata (title, family, scope, overlays, rollup status, rollup counts)
  // is duplicated on every CCI row to keep the file useful with a single
  // filter or pivot.
  //
  // CCIs and per-CCI assessments are fetched lazily on the click — most users
  // don't open every row, so the grid doesn't preload them. We fan out the
  // requests with Promise.all and reuse anything React Query already cached
  // (expanded rows in this session, or assessments fetched from the detail
  // page). RFC-4180-ish quoting: double any embedded quote, wrap any cell
  // containing comma/quote/newline.
  async function exportCsv() {
    if (exporting) return;
    setExporting(true);
    try {
      const fwName = fws.find((f) => f.id === frameworkId)?.name ?? "controls";
      const wbName =
        selectedWorkbook?.filename?.replace(/\.[^.]+$/, "") ?? "no-workbook";
      // Hide oscal_profile (FedRAMP) entries even if a prior session attached
      // one — under the current model FedRAMP is a first-class primary
      // baseline, not an annotation overlay, so it shouldn't appear in the
      // Overlays column. Same filter is applied to the on-screen Overlays
      // column below.
      const overlays = (overlayMembership.data?.overlays ?? []).filter(
        (o) => o.source_type !== "oscal_profile",
      );
      const includeOverlays = !!workbookId && overlays.length > 0;
      const includeScope = !!baselineId;

      const esc = (v: unknown): string => {
        if (v === null || v === undefined) return "";
        const s = String(v);
        if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
        return s;
      };

      // Fan out: for every visible control, grab its objectives (with
      // program-requirement mappings — e.g. SDA Controls "shall" statements
      // — so each CCI row carries the overlay reqs that cite it) and (if a
      // workbook is selected) its assessments. Both go through React Query's
      // cache so previously-fetched data is reused.
      const perControl = await Promise.all(
        rows.map(async (r) => {
          const objectives = await queryClient.fetchQuery<Objective[]>({
            queryKey: qk.objectivesWithMappings(r.id),
            queryFn: () => api.listObjectives(r.id, true),
          });
          const assessments = workbookId
            ? await queryClient.fetchQuery<Assessment[]>({
                queryKey: qk.assessments(r.id, workbookId),
                queryFn: () => api.listAssessments(r.id, workbookId),
              })
            : [];
          // Index assessments by objective_id for O(1) join below. There can
          // only be one Assessment per (workbook, objective), so a single-
          // value map is sufficient.
          const byObj = new Map<number, Assessment>();
          for (const a of assessments) byObj.set(a.objective_id, a);
          return { row: r, objectives, assessments: byObj };
        }),
      );

      // Discover which RequirementSource overlays are present across the
      // fetched objectives — used only for the toast summary now. The CSV
      // itself emits flat `req_source`/`req_number`/`req_text` columns so a
      // reviewer asking "what's SDA-127's status?" can AutoFilter on the
      // number column instantly. Sorted for deterministic toast text.
      const reqSourceNames = Array.from(
        new Set(
          perControl.flatMap(({ objectives }) =>
            objectives.flatMap((o) =>
              (o.mappings ?? []).map((m) => m.source_name),
            ),
          ),
        ),
      ).sort();

      // CSV shape: one row per (control × CCI × overlay-requirement). The
      // multiplier is intentional — a CCI cited by 5 SDA "shall" statements
      // becomes 5 rows, all sharing CCI metadata + status, but each with a
      // distinct req_number. That's the only shape where Excel AutoFilter
      // on `req_number = "SDA-127"` gives a usable review experience.
      // CCIs with no overlay mappings still get one row each (with empty
      // req columns) so no data is lost. Controls with no CCIs still get
      // a placeholder row.
      // CRM columns ride along when at least one CRM overlay is attached and
      // carries data. One CRM contributes FOUR columns (cloud responsibility
      // + narrative, on-prem responsibility + narrative), prefixed with the
      // CRM's label, so two CRMs no longer overwrite each other and an Excel
      // AutoFilter on any single CRM's scope works without packed cells.
      const includeCrm =
        crmOverlays.length > 0 &&
        rows.some((r) => r.crm && Object.keys(r.crm).length > 0);
      const crmHeaderSlug = (label: string) => label.replace(/\s+/g, "_");
      const headers = [
        "control_id",
        "control_title",
        "family",
        ...(includeScope ? ["in_scope"] : []),
        ...(includeCrm
          ? crmOverlays.flatMap((ov) => {
              const slug = crmHeaderSlug(ov.label);
              return [
                `crm:${slug}:cloud`,
                `crm:${slug}:cloud_narrative`,
                `crm:${slug}:onprem`,
                `crm:${slug}:onprem_narrative`,
              ];
            })
          : []),
        ...overlays.map((o) => `overlay:${o.name}`),
        "control_status",
        "control_compliant",
        "control_non_compliant",
        "control_na",
        "control_total_assessed",
        "cci_id",
        "cci_source",
        "cci_text",
        "req_source",
        "req_number",
        "req_text",
        "cci_status",
        "cci_tester",
        "cci_date_tested",
        "cci_excel_row",
      ];

      const lines: string[] = [headers.join(",")];
      let cciRowsWritten = 0;
      let controlsWithNoCcis = 0;

      for (const { row: r, objectives, assessments } of perControl) {
        const counts =
          r.status_counts ?? {
            compliant: 0,
            non_compliant: 0,
            na: 0,
            needs_review: 0,
          };
        // CSV total mirrors the grid's "Trusted verdicts" tally — abstain
        // rows aren't a verdict yet, so don't roll them into total_assessed
        // for export purposes (matches the backend's exclusion of
        // needs_review from compliant/non_compliant/na buckets).
        const total = counts.compliant + counts.non_compliant + counts.na;
        const overlayCells = includeOverlays
          ? overlays.map((o) => {
              const m = overlayMembership.data!.by_control[r.id]?.[o.baseline_id];
              return m ?? "";
            })
          : [];
        const controlPrefix = [
          r.control_id,
          r.title,
          r.family,
          ...(includeScope
            ? [r.in_scope === undefined ? "" : r.in_scope ? "in" : "out"]
            : []),
          ...(includeCrm
            ? crmOverlays.flatMap((ov) => {
                const resp = r.crm?.[ov.baseline_id];
                return [
                  resp?.responsibility ?? "",
                  resp?.responsibility_narrative ?? "",
                  resp?.responsibility_onprem ?? "",
                  resp?.responsibility_onprem_narrative ?? "",
                ];
              })
            : []),
          ...overlayCells,
          r.status ?? "",
          counts.compliant,
          counts.non_compliant,
          counts.na,
          total,
        ];

        if (objectives.length === 0) {
          // Control has no CCIs mapped (DISA CCI overlay not loaded, or a
          // bespoke framework). Still emit the control row so the export
          // doesn't silently drop it — CCI + req + assessment columns stay
          // blank (3 req cols + 4 assessment cols = 7 trailing empties).
          controlsWithNoCcis += 1;
          lines.push(
            [
              ...controlPrefix,
              "", // cci_id
              "", // cci_source
              "", // cci_text
              "", // req_source
              "", // req_number
              "", // req_text
              "", // cci_status
              "", // cci_tester
              "", // cci_date_tested
              "", // cci_excel_row
            ]
              .map(esc)
              .join(","),
          );
          continue;
        }

        for (const o of objectives) {
          const a = assessments.get(o.id);
          const mappings = o.mappings ?? [];
          // Row-explode: one CSV row per (control × CCI × overlay req).
          // A CCI cited by 5 SDA shall statements becomes 5 rows, each
          // with the same CCI/status/tester but a distinct req_number —
          // so a reviewer asking "what's SDA-127's status?" can
          // AutoFilter the req_number column in Excel and see it
          // immediately. CCIs with no mappings still get one row (empty
          // req_* cells) so no assessment data is lost.
          if (mappings.length === 0) {
            lines.push(
              [
                ...controlPrefix,
                o.objective_id,
                o.source,
                o.text,
                "", // req_source
                "", // req_number
                "", // req_text
                a?.status ?? "",
                a?.tester ?? "",
                a?.date_tested ?? "",
                a?.excel_row ?? "",
              ]
                .map(esc)
                .join(","),
            );
            cciRowsWritten += 1;
          } else {
            for (const m of mappings) {
              lines.push(
                [
                  ...controlPrefix,
                  o.objective_id,
                  o.source,
                  o.text,
                  m.source_name,
                  m.requirement_number,
                  m.requirement_text,
                  a?.status ?? "",
                  a?.tester ?? "",
                  a?.date_tested ?? "",
                  a?.excel_row ?? "",
                ]
                  .map(esc)
                  .join(","),
              );
              cciRowsWritten += 1;
            }
          }
        }
      }

      // Excel needs a UTF-8 BOM to open CSVs as UTF-8 instead of cp1252.
      const blob = new Blob(["\ufeff" + lines.join("\r\n")], {
        type: "text/csv;charset=utf-8",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      const stamp = new Date().toISOString().slice(0, 10);
      a.href = url;
      a.download = `controls-${fwName}-${wbName}-${stamp}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast.success(
        "Exported",
        `${cciRowsWritten} CCI row${cciRowsWritten === 1 ? "" : "s"} across ${rows.length} control${rows.length === 1 ? "" : "s"}${reqSourceNames.length > 0 ? ` · overlay reqs: ${reqSourceNames.join(", ")}` : " · no overlay reqs loaded"}${controlsWithNoCcis > 0 ? ` · ${controlsWithNoCcis} control${controlsWithNoCcis === 1 ? "" : "s"} had no CCIs mapped` : ""} → ${a.download}`,
      );
    } catch (e) {
      toast.error("Export failed", humanize(e));
    } finally {
      setExporting(false);
    }
  }

  const rows = useMemo<ControlRow[]>(() => {
    let list = (controls.data ?? []).map<ControlRow>((c) => {
      const rollup = statusByControl.get(c.id);
      // Collect this control's responsibility from every attached CRM,
      // keyed by the CRM's baseline_id so each renders in its own column.
      let crm: Record<number, CrmResp> | undefined;
      for (const [baselineId, inner] of responsibilityByBaseline) {
        const resp = inner.get(c.control_id);
        if (resp) {
          (crm ??= {})[baselineId] = resp;
        }
      }
      return {
        ...c,
        in_scope: inScopeByControl.get(c.control_id),
        status: rollup?.status,
        status_counts: rollup
          ? {
              compliant: rollup.compliant,
              non_compliant: rollup.non_compliant,
              na: rollup.na,
              needs_review: rollup.needs_review,
              rewrites_requested: rollup.rewrites_requested,
            }
          : undefined,
        crm,
      };
    });
    if (familyFilter !== "__all__") list = list.filter((c) => c.family === familyFilter);
    if (inScopeOnly && baselineId) {
      list = list.filter((c) => c.in_scope === true);
    }
    if (overlayCoveredOnly && hasOverlays) {
      list = list.filter((c) => overlayCoveredControlIds.has(c.id));
    }
    if (statusFilter !== "__all__") {
      list = list.filter((c) =>
        statusFilter === "__unassessed__" ? !c.status : c.status === statusFilter,
      );
    }
    return list;
  }, [
    controls.data,
    familyFilter,
    inScopeOnly,
    overlayCoveredOnly,
    hasOverlays,
    statusFilter,
    baselineId,
    inScopeByControl,
    overlayCoveredControlIds,
    statusByControl,
    responsibilityByBaseline,
  ]);

  // How many CCIs already have at least one Assessment row within the exact
  // set the batch will operate on? Walk `rows` (which composes every active
  // filter — family, in-scope toggle, overlay-covered, status, search) so the
  // "reassess existing?" dialog's trigger matches what fireBatch actually
  // sends as control_ids. Earlier this gate filtered by baseline in_scope
  // unconditionally (regardless of the inScopeOnly toggle), which silently
  // swallowed the dialog whenever the user had the toggle off but assessed
  // rows were still visible in the grid — startBatch fell through to
  // fireBatch(true) and skip_existing made the batch look like a no-op.
  const assessedInScope = useMemo(() => {
    if (!controlStatus.data) return 0;
    let n = 0;
    for (const r of rows) {
      const rollup = statusByControl.get(r.id);
      if (rollup && rollup.total_assessed > 0) n += rollup.total_assessed;
    }
    return n;
  }, [rows, controlStatus.data, statusByControl]);

  // Workbook-wide count of prior assessments — wider safety net than
  // assessedInScope. Three real ways the narrower count collapses to 0
  // even though the workbook has priors:
  //   1. controlStatus.data is still loading at click time — the gate
  //      silently fires skip_existing and the user sees a "Nothing to do
  //      — all already assessed" toast with no choice to re-run.
  //   2. The framework picker is on a different framework than the
  //      workbook's assessments (Control.id values don't intersect
  //      between rows and statusByControl).
  //   3. The user filtered the grid to a family/status with no priors,
  //      but the workbook overall has priors — skip_existing then makes
  //      the batch look like a no-op for the user's whole "Assess
  //      visible" intent.
  // startBatch below uses the OR of both counts so the user always gets
  // the Skip / Re-assess all dialog when there are *any* priors on this
  // workbook.
  const assessedInWorkbook = useMemo(() => {
    if (!controlStatus.data) return 0;
    let n = 0;
    for (const s of controlStatus.data) n += s.total_assessed;
    return n;
  }, [controlStatus.data]);

  // v0.2 precision-over-recall: aggregate count of CCIs the assessor
  // abstained on across this workbook. Surfaced as an amber pill in the
  // page header so the reviewer can jump straight to the abstained pile
  // without remembering to apply the Status filter. Sums the per-control
  // needs_review buckets from the existing rollup (which is workbook-wide,
  // not filter-scoped — the pill reflects the whole workbook so it stays
  // accurate even when other filters narrow the visible row set).
  const reviewQueueCount = useMemo(() => {
    let total = 0;
    for (const r of statusByControl.values()) {
      total += r.needs_review ?? 0;
    }
    return total;
  }, [statusByControl]);

  // Hide oscal_profile (FedRAMP) entries even if a workbook still has one
  // historically attached — under the current model FedRAMP is a first-class
  // primary baseline (picked from the compliance target dropdown), not an
  // annotation overlay. Same filter is applied to the CSV export in
  // exportCsv() above.
  const visibleOverlays = useMemo(
    () =>
      (overlayMembership.data?.overlays ?? []).filter(
        (o) => o.source_type !== "oscal_profile",
      ),
    [overlayMembership.data],
  );

  // One entry per attached CRM overlay, in attach order, each with a human
  // column label. Prefer the scope_label the assessor picked at import
  // (e.g. "AWS GovCloud"); fall back to a cleaned overlay name for CRMs
  // imported before the scope-label picker was restored (strips a leading
  // "demo_crm_"/"crm_" token, swaps separators for spaces, title-cases, and
  // upper-cases the common cloud abbreviations). This is what splits the two
  // CRMs into two columns instead of collapsing them.
  const crmOverlays = useMemo(() => {
    const prettify = (name: string): string => {
      const cleaned = name
        .replace(/^crm[:_\s-]*/i, "")
        .replace(/^demo[_\s-]*/i, "")
        .replace(/^crm[_\s-]*/i, "")
        .replace(/[_-]+/g, " ")
        .trim();
      return cleaned
        .split(/\s+/)
        .map((w) =>
          /^(aws|gov|us|fed|azure|gcc)$/i.test(w)
            ? w.toUpperCase()
            : w.charAt(0).toUpperCase() + w.slice(1),
        )
        .join(" ");
    };
    return visibleOverlays
      .filter((o) => o.source_type === "crm")
      .map((o) => ({
        baseline_id: o.baseline_id,
        label: o.scope_label?.trim() || prettify(o.name) || o.name,
      }));
  }, [visibleOverlays]);

  const columns = useMemo<ColumnDef<ControlRow>[]>(
    () => [
      {
        id: "expander",
        header: () => <span className="sr-only">Expand CCIs</span>,
        cell: (ctx) => {
          const open = expanded.has(ctx.row.original.id);
          return (
            <button
              type="button"
              aria-label={open ? "Collapse CCIs" : "Expand CCIs"}
              aria-expanded={open}
              className="inline-flex items-center justify-center rounded p-0.5 text-muted-foreground hover:bg-accent hover:text-foreground"
              onClick={(e) => {
                e.stopPropagation();
                toggleExpanded(ctx.row.original.id);
              }}
            >
              {open ? (
                <ChevronDown className="h-4 w-4" />
              ) : (
                <ChevronRight className="h-4 w-4" />
              )}
            </button>
          );
        },
      },
      {
        accessorKey: "control_id",
        header: "Control",
        cell: (ctx) => (
          <span className="font-mono text-xs text-primary hover:underline">
            {ctx.row.original.control_id}
          </span>
        ),
      },
      {
        accessorKey: "title",
        header: "Title",
        cell: (ctx) => <span className="text-sm">{ctx.row.original.title}</span>,
      },
      {
        accessorKey: "family",
        header: "Family",
        cell: (ctx) => <Badge variant="outline">{ctx.row.original.family}</Badge>,
      },
      ...(baselineId
        ? [
            {
              accessorKey: "in_scope",
              header: "Scope",
              cell: (ctx) => {
                const v = ctx.row.original.in_scope;
                if (v === undefined)
                  return <span className="text-xs text-muted-foreground">—</span>;
                return (
                  <Badge variant={v ? "success" : "outline"}>
                    {v ? "in" : "out"}
                  </Badge>
                );
              },
            } as ColumnDef<ControlRow>,
          ]
        : []),
      // One CRM responsibility column PER attached CRM overlay (one per
      // scope_label — e.g. AWS GovCloud, Azure Government). Each column reads
      // only its own CRM's values out of r.crm[baseline_id] so the two CRMs
      // no longer collapse into a single last-write-wins column. Within a
      // column, the cell renders one chip in the common case (single scope
      // set, or cloud/on-prem agree) and stacks Cloud / On-prem chips only
      // when the two scopes disagree. Full narratives live on the per-control
      // page; chip tooltips surface them inline.
      ...(workbookId
        ? crmOverlays.map(
            (ov) =>
              ({
                id: `crm_responsibility_${ov.baseline_id}`,
                header: ov.label,
                cell: (ctx) => {
                  const resp = ctx.row.original.crm?.[ov.baseline_id];
                  const cloud = resp?.responsibility ?? null;
                  const onprem = resp?.responsibility_onprem ?? null;
                  if (!cloud && !onprem)
                    return (
                      <span className="text-xs text-muted-foreground">—</span>
                    );
                  const labelMap: Record<string, string> = {
                    inherited: "Inherited",
                    // "provider" is engine-equivalent to "inherited" (both
                    // short-circuit COMPLIANT and are owned upstream), so it
                    // reads "Inherited" to the assessor rather than exposing
                    // the internal taxonomy split.
                    provider: "Inherited",
                    hybrid: "Hybrid",
                    customer: "Customer",
                    // Customer-configured is a distinct state: customer owns
                    // it, but satisfies it by configuring a provided
                    // capability. Fully assessed (NOT short-circuited).
                    customer_configured: "Customer Configured",
                    not_applicable: "N/A",
                  };
                  const chipClass = (v: string | null | undefined) =>
                    // provider shares the emerald "inherited" style — both are
                    // upstream-owned / auto-compliant in the engine.
                    v === "inherited" || v === "provider"
                      ? "border-emerald-300 bg-emerald-50 text-emerald-800 dark:border-emerald-700 dark:bg-emerald-950 dark:text-emerald-300"
                      : v === "hybrid"
                        ? "border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-300"
                        : v === "customer_configured"
                          ? "border-indigo-300 bg-indigo-50 text-indigo-800 dark:border-indigo-700 dark:bg-indigo-950 dark:text-indigo-300"
                          : v === "customer"
                            ? "border-slate-300 bg-slate-50 text-slate-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300"
                            : "border-muted bg-muted text-muted-foreground";
                  // Always a single inferred chip — the cloud/on-prem split is
                  // never surfaced in the table. Inference rule:
                  //   • only one scope set, or both agree → that value
                  //   • an explicit hybrid on either scope → "hybrid"
                  //   • cloud ≠ on-prem (e.g. provider cloud + customer
                  //     on-prem) → inferred "hybrid" (shared responsibility)
                  // Per-scope narratives still live on the per-control page;
                  // the tooltip surfaces both here.
                  const v: string =
                    !cloud || !onprem
                      ? (cloud ?? onprem!)
                      : cloud === onprem
                        ? cloud
                        : "hybrid";
                  const tooltipParts: string[] = [];
                  if (resp?.responsibility_narrative)
                    tooltipParts.push(`Cloud: ${resp.responsibility_narrative}`);
                  if (
                    resp?.responsibility_onprem_narrative &&
                    resp.responsibility_onprem_narrative !==
                      resp.responsibility_narrative
                  )
                    tooltipParts.push(
                      `On-prem: ${resp.responsibility_onprem_narrative}`,
                    );
                  return (
                    <Badge
                      variant="outline"
                      className={chipClass(v)}
                      title={
                        tooltipParts.join("\n\n") ||
                        `${ov.label}: ${labelMap[v] ?? v}`
                      }
                    >
                      {labelMap[v] ?? v}
                    </Badge>
                  );
                },
              }) as ColumnDef<ControlRow>,
          )
        : []),
      ...(workbookId &&
      visibleOverlays.some((o) => o.source_type === "program_controls")
        ? [
            {
              id: "psc",
              header: "PSC",
              cell: (ctx) => {
                const controlId = ctx.row.original.id;
                const membership =
                  overlayMembership.data?.by_control[controlId] ?? {};
                const reqs =
                  overlayMembership.data?.by_control_requirements[controlId] ??
                  {};
                // PSC column is dedicated to Program Security Control numbers
                // (e.g. SDA-127). Only program_controls overlays produce those —
                // other overlay types (FedRAMP profile, CRM, etc.) belong on
                // the detail page, not in this grid cell.
                const programOverlays = visibleOverlays.filter(
                  (o) => o.source_type === "program_controls",
                );
                return (
                  <div className="flex flex-wrap gap-1">
                    {programOverlays.map((o) => {
                      const m = membership[o.baseline_id];
                      if (m === undefined) return null;
                      const requirementNumbers = reqs[o.baseline_id] ?? [];
                      if (requirementNumbers.length === 0) return null;
                      return requirementNumbers.map((num) => (
                        <Badge
                          key={`${o.baseline_id}:${num}`}
                          variant="secondary"
                          title={`${o.name} — ${num}`}
                        >
                          {num}
                        </Badge>
                      ));
                    })}
                  </div>
                );
              },
            } as ColumnDef<ControlRow>,
          ]
        : []),
      {
        accessorKey: "status",
        header: "Status",
        cell: (ctx) => {
          const s = ctx.row.original.status;
          if (!s) return <span className="text-xs text-muted-foreground">—</span>;
          const counts = ctx.row.original.status_counts;
          // v0.2: needs_review rows roll up into a "Needs Review" bucket
          // (see backend/routes/workbooks.py::workbook_control_status). The
          // count surfaces in the tooltip so reviewers can see abstain
          // pressure at a glance without expanding the row.
          const needsReview = counts?.needs_review ?? 0;
          // v0.2 citation-hygiene: TRUSTED-verdict rows that still cite a
          // superseded doc name. Orthogonal to the verdict — the row
          // exports normally — but worth flagging so the next narrative
          // pass can swap the cite. Distinct from needs_review: blue/info,
          // not amber/blocking.
          const rewritesRequested = counts?.rewrites_requested ?? 0;
          const baseTooltip = counts
            ? `Compliant ${counts.compliant} · Non-Compliant ${counts.non_compliant} · N/A ${counts.na}`
            : s;
          const tooltipParts = [baseTooltip];
          if (needsReview > 0) tooltipParts.push(`Needs Review ${needsReview}`);
          if (rewritesRequested > 0)
            tooltipParts.push(`Cite refresh ${rewritesRequested}`);
          const tooltip = tooltipParts.join(" · ");
          const variant: "success" | "destructive" | "outline" | "warning" =
            s === "Compliant"
              ? "success"
              : s === "Non-Compliant"
                ? "destructive"
                : s === "Mixed" || s === "Needs Review"
                  ? "warning"
                  : "outline";
          return (
            <div className="flex flex-wrap items-center gap-1">
              <Badge variant={variant} title={tooltip}>
                {s}
              </Badge>
              {rewritesRequested > 0 ? (
                <Badge
                  variant="outline"
                  className="border-sky-300 bg-sky-50 text-sky-700 dark:border-sky-700 dark:bg-sky-950 dark:text-sky-300"
                  title={`${rewritesRequested} narrative${
                    rewritesRequested === 1 ? "" : "s"
                  } on this control cite a superseded doc name. Verdict stands; refresh the cite on the next pass.`}
                >
                  Cite refresh {rewritesRequested}
                </Badge>
              ) : null}
            </div>
          );
        },
      },
    ],
    [
      baselineId,
      expanded,
      workbookId,
      overlayMembership.data,
      visibleOverlays,
      crmOverlays,
    ],
  );

  const table = useReactTable({
    data: rows,
    columns,
    state: { globalFilter },
    onGlobalFilterChange: setGlobalFilter,
    globalFilterFn: (row, _id, value) => {
      const v = String(value).toLowerCase();
      const o = row.original;
      return (
        o.control_id.toLowerCase().includes(v) ||
        o.title.toLowerCase().includes(v) ||
        o.family.toLowerCase().includes(v)
      );
    },
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  return (
    <div className="p-8 space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight">Controls</h1>
            {workbookId && reviewQueueCount > 0 && (
              <Link
                to="/review-queue"
                className="inline-flex items-center gap-1.5 rounded-full border border-amber-400 bg-amber-50 px-2.5 py-0.5 text-xs font-medium text-amber-900 hover:bg-amber-100 dark:border-amber-500 dark:bg-amber-950/40 dark:text-amber-200 dark:hover:bg-amber-950/70"
                title="Open the Review Queue — abstained CCIs grouped by failure mode (dual-pass disagreement, unverified citations, validator exhaustion, etc.). Per the precision-over-recall contract, the assessor refused to set a status on these rows; they are blocked from POAM/SAR/workbook export until you resolve them."
              >
                <span aria-hidden="true">●</span>
                {reviewQueueCount} need{reviewQueueCount === 1 ? "s" : ""} review
              </Link>
            )}
          </div>
          <p className="text-sm text-muted-foreground">
            {frameworkId
              ? `${fws.find((f) => f.id === frameworkId)?.name ?? ""} ${fws.find((f) => f.id === frameworkId)?.version ?? ""} — ${controls.data?.length ?? 0} controls`
              : "No framework loaded"}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            onClick={() => setImportNarrativesOpen(true)}
            disabled={!workbookId || importNarrativesMut.isPending}
            title={
              !workbookId
                ? "Pick a workbook in the Workbook dropdown below — the import upserts that workbook's assessments."
                : "Import narratives from an operator-filled eMASS Test Result template (column N status / P tester / O date / Q narrative). Upserts one Assessment per in-scope CCI. Non-Compliant rows become POAM-ready."
            }
          >
            {importNarrativesMut.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <FileUp className="h-4 w-4" />
            )}
            {importNarrativesMut.isPending ? "Importing…" : "Import narratives"}
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="outline"
                disabled={exporting || (rows.length === 0 && !workbookId)}
                title="Export the filtered grid as CSV or working-view XLSX."
              >
                {exporting ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Download className="h-4 w-4" />
                )}
                {exporting ? "Exporting…" : "Export"}
                <ChevronDown className="h-4 w-4 opacity-70" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem
                onSelect={(e) => {
                  e.preventDefault();
                  exportCsv();
                }}
                disabled={rows.length === 0 || exporting}
                title={
                  rows.length === 0
                    ? "Nothing to export — adjust filters first."
                    : `Download one row per CCI across ${rows.length} filtered control${rows.length === 1 ? "" : "s"} (UTF-8 CSV). Each row carries control metadata, rollup status/counts, and the CCI's own status, tester, and date-tested.`
                }
              >
                <Download className="h-4 w-4" />
                CSV (filtered grid)
              </DropdownMenuItem>
              <DropdownMenuItem
                onSelect={(e) => {
                  e.preventDefault();
                  setWorkingExportOpen(true);
                }}
                disabled={!workbookId}
                title={
                  !workbookId
                    ? "Pick a workbook in the Workbook dropdown below — the export targets that workbook's assessments."
                    : "Working-view xlsx — one row per CCI with the current filter applied (family, status, search). Includes needs_review rows for triage. Not for eMASS upload."
                }
              >
                <FileSpreadsheet className="h-4 w-4" />
                XLSX (working view)
              </DropdownMenuItem>
              <DropdownMenuItem
                onSelect={(e) => {
                  e.preventDefault();
                  setEmassExportOpen(true);
                }}
                disabled={!workbookId}
                title={
                  !workbookId
                    ? "Pick a workbook in the Workbook dropdown below — the export targets that workbook's assessments."
                    : "eMASS-strict xlsx — copies your enterprise-services controls template, inserts a Program-Specific Controls column after Control Acronym, writes one row per in-scope control with the multi-line status rollup. Skips needs_review rows."
                }
              >
                <FileSpreadsheet className="h-4 w-4" />
                XLSX (eMASS upload)
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          <Button
            onClick={startBatch}
            disabled={
              assessIsPending ||
              !workbookId ||
              !baselineId ||
              rows.length === 0 ||
              controlStatus.isLoading
            }
            title={
              !workbookId
                ? "Pick a workbook in the Workbook dropdown below — that's the target of the batch."
                : !baselineId
                  ? "Selected workbook has no baseline. Re-open it from the Workbooks tab with a framework bound — that materializes which CCIs are in-scope."
                  : rows.length === 0
                    ? "No controls match the current filters — nothing to assess."
                    : controlStatus.isLoading
                      ? "Loading existing assessment counts — the re-assess prompt needs these to know whether priors exist."
                      : `Assess every CCI under the ${rows.length} control${rows.length === 1 ? "" : "s"} currently visible in the grid (all active filters apply: in-scope toggle, family, overlay-covered, status). You'll be asked whether to re-assess rows that already have results.`
            }
          >
            {assessIsPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Sparkles className="h-4 w-4" />
            )}
            {assessIsPending
              ? "Assessing…"
              : `Assess visible (${rows.length})`}
          </Button>
          <Button
            variant="outline"
            onClick={() => {
              if (!workbookId) return;
              applyAllMut.mutate({
                workbookId,
                family: familyFilter !== "__all__" ? familyFilter : undefined,
              });
            }}
            disabled={
              applyAllMut.isPending || !workbookId || writableUpperBound === 0
            }
            title={
              !workbookId
                ? "Pick a workbook in the Workbook dropdown below — bulk apply targets that workbook."
                : writableUpperBound === 0
                  ? "No assessed rows are ready to write. Run Assess all first, or clear the family filter to widen the scope."
                  : familyFilter !== "__all__"
                    ? `Write every assessed ${familyFilter} CCI to the workbook in one pass. Silently skips needs_review and already-written rows.`
                    : "Write every assessed CCI to the workbook in one pass. Silently skips needs_review and already-written rows."
            }
          >
            {applyAllMut.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Save className="h-4 w-4" />
            )}
            {applyAllMut.isPending
              ? "Applying…"
              : writableUpperBound > 0
                ? `Apply ${writableUpperBound} CCI${writableUpperBound === 1 ? "" : "s"} to workbook`
                : "Apply to workbook"}
          </Button>
        </div>
      </header>

      {/*
        Live progress strip for ``/assess-batch`` lives in
        ``<AssessBatchProgressStrip />`` mounted in App.tsx above
        ``<Routes>``. It renders as a sticky banner at the top of the
        main scroll area so it stays visible across route changes while
        a batch is in flight. See contexts/AssessBatchContext.tsx.
      */}

      <Card>
        <CardHeader>
          <CardTitle>Catalog</CardTitle>
          <CardDescription>
            Filter by control ID, title, family, or baseline scope
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-end gap-3">
            <div className="space-y-1 flex-1 max-w-md">
              <label className="text-xs font-medium text-muted-foreground block">
                Search
              </label>
              <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="AC-2, account management, AU…"
                  value={globalFilter}
                  onChange={(e) => setGlobalFilter(e.target.value)}
                  className="pl-8"
                />
              </div>
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground block">
                Framework
              </label>
              <ComplianceTargetPicker
                value={target}
                onChange={setTarget}
                includeBaselines={false}
                triggerClassName="w-[220px]"
                placeholder="Pick framework"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground block">
                Workbook open
              </label>
              {/* No selector: scope is hard-bound to the workbook that is open
                  (most-recently-opened). This is a read-only indicator, not a
                  picker — switching systems happens by opening a workbook on the
                  Workbooks page, which bumps last_opened and re-drives this. */}
              <div className="flex h-9 w-[220px] items-center rounded-md border border-input bg-muted/40 px-3 text-sm">
                <span className="truncate">
                  {workbooks.data?.find((w) => w.id === workbookId)?.filename ??
                    "No workbook open"}
                </span>
              </div>
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground block">
                Family
              </label>
              <Select value={familyFilter} onValueChange={setFamilyFilter}>
                <SelectTrigger className="w-[140px]">
                  <SelectValue placeholder="All families" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__all__">All families</SelectItem>
                  {families.map((f) => (
                    <SelectItem key={f} value={f}>
                      {f}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground block">
                Status
              </label>
              <Select
                value={statusFilter}
                onValueChange={setStatusFilter}
                disabled={!workbookId}
              >
                <SelectTrigger className="w-[170px]">
                  <SelectValue placeholder="All statuses" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__all__">All statuses</SelectItem>
                  <SelectItem value="Compliant">Compliant</SelectItem>
                  <SelectItem value="Non-Compliant">Non-Compliant</SelectItem>
                  <SelectItem value="Mixed">Mixed</SelectItem>
                  <SelectItem value="Needs Review">Needs Review</SelectItem>
                  <SelectItem value="N/A">N/A</SelectItem>
                  <SelectItem value="__unassessed__">Not assessed</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {baselineId && (
              <label className="flex items-center gap-2 text-sm text-muted-foreground pb-2">
                <input
                  type="checkbox"
                  checked={inScopeOnly}
                  onChange={(e) => setInScopeOnly(e.target.checked)}
                  className="h-4 w-4 rounded border-input"
                />
                In-scope only
              </label>
            )}
            {hasOverlays && (
              <label
                className="flex items-center gap-2 text-sm text-muted-foreground pb-2"
                title="Show only controls cited by at least one loaded program overlay (SDA, T1TL, etc.). Overlay coverage defines what's in scope for the assessment."
              >
                <input
                  type="checkbox"
                  checked={overlayCoveredOnly}
                  onChange={(e) => setOverlayCoveredOnly(e.target.checked)}
                  className="h-4 w-4 rounded border-input"
                />
                Overlay-covered only
              </label>
            )}
          </div>

          <div className="rounded-md border overflow-hidden">
            <Table>
              <TableHeader>
                {table.getHeaderGroups().map((hg) => (
                  <TableRow key={hg.id}>
                    {hg.headers.map((h) => (
                      <TableHead
                        key={h.id}
                        className={h.column.id === "control_id" ? "sticky left-0 bg-card" : ""}
                      >
                        {h.isPlaceholder
                          ? null
                          : flexRender(h.column.columnDef.header, h.getContext())}
                      </TableHead>
                    ))}
                  </TableRow>
                ))}
              </TableHeader>
              <TableBody>
                {table.getRowModel().rows.map((row) => {
                  const isOpen = expanded.has(row.original.id);
                  return (
                    <Fragment key={row.id}>
                      <TableRow
                        className="cursor-pointer hover:bg-accent/40"
                        onClick={() => navigate(`/controls/${row.original.id}`)}
                      >
                        {row.getVisibleCells().map((cell) => (
                          <TableCell
                            key={cell.id}
                            className={
                              cell.column.id === "control_id" ? "sticky left-0 bg-card" : ""
                            }
                          >
                            {flexRender(cell.column.columnDef.cell, cell.getContext())}
                          </TableCell>
                        ))}
                      </TableRow>
                      {isOpen && (
                        <TableRow className="bg-muted/30 hover:bg-muted/30">
                          <TableCell colSpan={columns.length} className="p-0">
                            <CciList
                              controlId={row.original.id}
                              workbookId={workbookId}
                            />
                          </TableCell>
                        </TableRow>
                      )}
                    </Fragment>
                  );
                })}
                {controls.isLoading && table.getRowModel().rows.length === 0 && (
                  <TableRow>
                    <TableCell
                      colSpan={columns.length}
                      className="text-center text-sm text-muted-foreground py-8"
                    >
                      <Loader2 className="inline h-4 w-4 animate-spin mr-2" />
                      Loading controls…
                    </TableCell>
                  </TableRow>
                )}
                {/* Bug #4: a failed controls/status read used to fall straight
                    through to the "No controls match" empty-state below,
                    masking a backend error as a benign empty filter. Surface
                    the real error (with a retry) so the operator doesn't chase
                    a phantom filtering problem. */}
                {!controls.isLoading &&
                  (controls.isError || controlStatus.isError) &&
                  table.getRowModel().rows.length === 0 && (
                    <TableRow>
                      <TableCell
                        colSpan={columns.length}
                        className="text-center text-sm py-8"
                      >
                        <div className="text-destructive">
                          Failed to load controls:{" "}
                          {humanize(controls.error ?? controlStatus.error)}
                        </div>
                        <Button
                          variant="outline"
                          size="sm"
                          className="mt-3"
                          onClick={() => {
                            controls.refetch();
                            controlStatus.refetch();
                          }}
                        >
                          Retry
                        </Button>
                      </TableCell>
                    </TableRow>
                  )}
                {!controls.isLoading &&
                  !controls.isError &&
                  !controlStatus.isError &&
                  table.getRowModel().rows.length === 0 && (
                    <TableRow>
                      <TableCell
                        colSpan={columns.length}
                        className="text-center text-sm text-muted-foreground py-8"
                      >
                        No controls match the current filters.
                      </TableCell>
                    </TableRow>
                  )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* CciList component lives at module scope below the export. */}

      <Dialog open={emassExportOpen} onOpenChange={setEmassExportOpen}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>Export controls to eMASS template</DialogTitle>
            <DialogDescription>
              Copies your enterprise-services controls.xlsx template via
              xlwings (preserves all 29 tabs, validation, and formatting)
              and fills the Controls tab. Inserts a Program-Specific
              Controls column right after Control Acronym so overlay
              mappings land in one filterable column. Skips needs_review
              rows per the precision-over-recall contract.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Workbook</label>
              <div className="text-sm text-muted-foreground font-mono">
                {selectedWorkbook?.filename ?? "(none selected)"}
              </div>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Template path</label>
              <div className="flex gap-2">
                <Input
                  value={emassTemplatePath}
                  onChange={(e) => setEmassTemplatePath(e.target.value)}
                  placeholder="C:\path\to\enterprise services controls.xlsx"
                  className="font-mono text-xs"
                />
                {nativeBridge && (
                  <Button variant="outline" onClick={pickEmassTemplate}>
                    <FileUp className="h-4 w-4" />
                    Browse
                  </Button>
                )}
              </div>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Output path</label>
              <Input
                value={emassOutputPath}
                onChange={(e) => setEmassOutputPath(e.target.value)}
                placeholder="C:\path\to\Example System-T2-controls-2026-06-05.xlsx"
                className="font-mono text-xs"
              />
            </div>
            <p className="text-xs text-muted-foreground">
              Caveat: inserting the PSC column shifts every column right
              by one. If a downstream batch importer keys off ordinal
              position rather than header text, strip the PSC column
              before upload.
            </p>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setEmassExportOpen(false)}
              disabled={exportEmassMut.isPending}
            >
              Cancel
            </Button>
            <Button
              onClick={submitEmassExport}
              disabled={
                exportEmassMut.isPending ||
                !workbookId ||
                !emassTemplatePath.trim() ||
                !emassOutputPath.trim()
              }
              autoFocus
            >
              {exportEmassMut.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <FileSpreadsheet className="h-4 w-4" />
              )}
              Export
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={workingExportOpen} onOpenChange={setWorkingExportOpen}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>Export working view</DialogTitle>
            <DialogDescription>
              Fresh xlsx mirroring the current filter — one row per CCI
              (not per control), including needs_review rows for triage.
              Includes the PSC column, abstain reasons, and confidence.
              Owned by the assessor for working/review; not an eMASS
              deliverable.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Workbook</label>
              <div className="text-sm text-muted-foreground font-mono">
                {selectedWorkbook?.filename ?? "(none selected)"}
              </div>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Filters applied</label>
              <div className="text-xs text-muted-foreground space-y-1">
                <div>
                  Family:{" "}
                  <span className="font-mono">
                    {familyFilter !== "__all__" ? familyFilter : "(all)"}
                  </span>
                </div>
                <div>
                  Status:{" "}
                  <span className="font-mono">
                    {statusFilter !== "__all__" ? statusFilter : "(all)"}
                  </span>
                </div>
                <div>
                  Search:{" "}
                  <span className="font-mono">
                    {globalFilter.trim() || "(none)"}
                  </span>
                </div>
              </div>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Output path</label>
              <Input
                value={workingOutputPath}
                onChange={(e) => setWorkingOutputPath(e.target.value)}
                placeholder="C:\path\to\controls-working-view.xlsx"
                className="font-mono text-xs"
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setWorkingExportOpen(false)}
              disabled={exportWorkingMut.isPending}
            >
              Cancel
            </Button>
            <Button
              onClick={submitWorkingExport}
              disabled={
                exportWorkingMut.isPending ||
                !workbookId ||
                !workingOutputPath.trim()
              }
              autoFocus
            >
              {exportWorkingMut.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Download className="h-4 w-4" />
              )}
              Export
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={importNarrativesOpen}
        onOpenChange={setImportNarrativesOpen}
      >
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>Import narratives</DialogTitle>
            <DialogDescription>
              Reads an operator-filled eMASS Test Result template and
              upserts one Assessment per in-scope CCI — column N becomes the
              status, P the tester, O the date tested, and Q the narrative.
              Import only: no AI runs here. Non-Compliant rows land ready
              for the Generate POAMs step on the POAMs tab. Rows whose CCI
              isn't in scope, or that have no status or no narrative, are
              skipped and reported.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Workbook</label>
              <div className="text-sm text-muted-foreground font-mono">
                {selectedWorkbook?.filename ?? "(none selected)"}
              </div>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">
                Test Result template path
              </label>
              <div className="flex gap-2">
                <Input
                  value={importNarrativesPath}
                  onChange={(e) => setImportNarrativesPath(e.target.value)}
                  placeholder="C:\path\to\eMASS-test-results.xlsx"
                  className="font-mono text-xs"
                />
                {nativeBridge && (
                  <Button
                    variant="outline"
                    onClick={pickImportNarrativesFile}
                  >
                    <FileUp className="h-4 w-4" />
                    Browse
                  </Button>
                )}
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              Imported verdicts overwrite any existing assessment for the
              same CCI in this workbook and are marked needs_review=False so
              they flow straight into POAM generation. Re-running is
              idempotent — the same file produces the same result.
            </p>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setImportNarrativesOpen(false)}
              disabled={importNarrativesMut.isPending}
            >
              Cancel
            </Button>
            <Button
              onClick={submitImportNarratives}
              disabled={
                importNarrativesMut.isPending ||
                !workbookId ||
                !importNarrativesPath.trim()
              }
              autoFocus
            >
              {importNarrativesMut.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <FileUp className="h-4 w-4" />
              )}
              Import
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={reassessOpen} onOpenChange={setReassessOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Some CCIs already have assessments</DialogTitle>
            <DialogDescription>
              {assessedInScope > 0
                ? familyFilter !== "__all__"
                  ? `${assessedInScope} assessment${assessedInScope === 1 ? "" : "s"} already exist for in-scope CCIs in the ${familyFilter} family. `
                  : `${assessedInScope} assessment${assessedInScope === 1 ? "" : "s"} already exist for in-scope CCIs in this workbook. `
                : `${assessedInWorkbook} assessment${assessedInWorkbook === 1 ? "" : "s"} already exist in this workbook outside the current view. `}
              How should the batch handle them?
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setReassessOpen(false);
                fireBatch(true);
              }}
              disabled={assessIsPending}
            >
              Skip already-assessed
            </Button>
            <Button
              onClick={() => {
                setReassessOpen(false);
                fireBatch(false);
              }}
              disabled={assessIsPending}
              autoFocus
              title="Re-runs the engine for every in-scope CCI — overwrites the draft assessment row with the new decision."
            >
              Re-assess all
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Post-batch triage modal — fires automatically when assess-batch +
          apply-batch finishes with anything that didn't reach Excel.
          Splits the three failure modes with different remediation paths:
            - errored CCIs: re-run from Controls (no /review-queue row exists)
            - skipped CCIs: workbook/baseline mismatch — fix upstream
            - needs_review: routes to /review-queue for human triage
          Only shows "Review now" when /review-queue is the right answer. */}
      <Dialog open={reviewModalOpen} onOpenChange={setReviewModalOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              {reviewModalCounts.needsReview > 0 ||
              reviewModalCounts.skippedNeedsReview > 0
                ? "Assessment complete — review needed"
                : "Assessment complete — some CCIs need attention"}
            </DialogTitle>
            <DialogDescription>
              {(() => {
                const parts: string[] = [];
                parts.push(`${reviewModalCounts.accepted} accepted`);
                if (reviewModalCounts.applied > 0)
                  parts.push(`${reviewModalCounts.applied} written to Excel`);
                if (reviewModalCounts.errored.length > 0)
                  parts.push(`${reviewModalCounts.errored.length} errored`);
                if (reviewModalCounts.rejected.length > 0)
                  parts.push(`${reviewModalCounts.rejected.length} rejected`);
                if (reviewModalCounts.skipped.length > 0)
                  parts.push(`${reviewModalCounts.skipped.length} skipped`);
                if (reviewModalCounts.needsReview > 0)
                  parts.push(`${reviewModalCounts.needsReview} need review`);
                if (reviewModalCounts.skippedNeedsReview > 0)
                  parts.push(
                    `${reviewModalCounts.skippedNeedsReview} prior abstains pending`,
                  );
                return parts.join(" · ");
              })()}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            {reviewModalCounts.errored.length > 0 && (
              <div className="space-y-2">
                <div className="text-sm font-semibold">
                  Worker errored ({reviewModalCounts.errored.length})
                </div>
                <div className="max-h-44 overflow-y-auto rounded border border-border bg-muted/30 p-2 text-xs">
                  {reviewModalCounts.errored.map((e) => (
                    <div
                      key={e.objective_id}
                      className="flex items-baseline gap-2 py-1"
                    >
                      <span className="font-mono text-foreground">
                        {e.objective_id}
                      </span>
                      <span className="text-muted-foreground">
                        row {e.excel_row}
                      </span>
                      <span className="truncate text-muted-foreground">
                        {e.error}
                      </span>
                    </div>
                  ))}
                </div>
                <div className="text-xs text-muted-foreground">
                  These have no Assessment row and don't appear in the Review
                  Queue. Click <em>Assess all in-scope</em> again with
                  "skip already-assessed" enabled to retry just these.
                </div>
              </div>
            )}
            {reviewModalCounts.rejected.length > 0 && (
              <div className="space-y-2">
                <div className="text-sm font-semibold">
                  Validator rejected ({reviewModalCounts.rejected.length})
                </div>
                <div className="max-h-44 overflow-y-auto rounded border border-border bg-muted/30 p-2 text-xs">
                  {reviewModalCounts.rejected.map((d) => (
                    <div
                      key={d.objective_id}
                      className="flex items-baseline gap-2 py-1"
                    >
                      <span className="font-mono text-foreground">
                        {d.objective_id}
                      </span>
                      <span className="text-muted-foreground">
                        row {d.excel_row}
                      </span>
                      <span className="truncate text-muted-foreground">
                        {d.reason}
                      </span>
                    </div>
                  ))}
                </div>
                <div className="text-xs text-muted-foreground">
                  Rule #11 retries exhausted — usually an evidence-quality
                  issue (citation hygiene, missing references). No Assessment
                  row exists; re-run after fixing the evidence bundle or
                  inspect the run log for the rejection trail.
                </div>
              </div>
            )}
            {reviewModalCounts.skipped.length > 0 && (
              <div className="space-y-2">
                <div className="text-sm font-semibold">
                  Not in workbook ({reviewModalCounts.skipped.length})
                </div>
                <div className="max-h-44 overflow-y-auto rounded border border-border bg-muted/30 p-2 text-xs">
                  {reviewModalCounts.skipped.map((s) => (
                    <div
                      key={s.objective_id}
                      className="flex items-baseline gap-2 py-1"
                    >
                      <span className="font-mono text-foreground">
                        {s.objective_id}
                      </span>
                      <span className="text-muted-foreground">{s.reason}</span>
                    </div>
                  ))}
                </div>
                <div className="text-xs text-muted-foreground">
                  The baseline references these CCIs but the current workbook
                  doesn't list them. Reload the workbook with the correct
                  framework, or update the baseline if the workbook is right.
                </div>
              </div>
            )}
            {(reviewModalCounts.needsReview > 0 ||
              reviewModalCounts.skippedNeedsReview > 0) && (
              <div className="space-y-1">
                <div className="text-sm font-semibold">
                  Needs review (
                  {reviewModalCounts.needsReview +
                    reviewModalCounts.skippedNeedsReview}
                  )
                </div>
                <div className="text-xs text-muted-foreground">
                  Abstained rows are blocked from CCIS and POAM export until a
                  reviewer sets a trusted status. Open the Review Queue to
                  triage by failure mode.
                </div>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setReviewModalOpen(false)}
              title="Stay on the Controls grid. You can return to the Review Queue from the sidebar at any time."
            >
              Close
            </Button>
            {(reviewModalCounts.needsReview > 0 ||
              reviewModalCounts.skippedNeedsReview > 0) && (
              <Button
                autoFocus
                onClick={() => {
                  setReviewModalOpen(false);
                  navigate("/review-queue");
                }}
              >
                Review now
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

/**
 * Inline CCI list rendered in the expanded row beneath a control. Lazy-fetches
 * objectives only when the row is opened, so an unexpanded grid doesn't fire
 * one request per row. Kept text-only — full per-CCI status + assess UI lives
 * on the control detail page; this section is for "what CCIs are under this
 * control?" at a glance.
 */
function CciList({
  controlId,
  workbookId,
}: {
  controlId: number;
  workbookId?: number;
}) {
  // include_mappings=true pulls RequirementMap rows alongside each CCI — that's
  // how program-overlay shall statements (e.g. SDA-AC-01, T1TL row numbers)
  // surface inline beneath each CCI. Without this the program overlays the
  // user just loaded are invisible in the on-screen Controls grid.
  //
  // workbookId scopes the in_workbook flag on each row so we can sort the
  // CCIs the workbook actually surfaced ahead of the catalog-only stubs
  // (e.g. AC-2 has ~32 catalog CCIs but a given workbook may only list 2 —
  // the other 30 are still shown, just marked and pushed to the bottom).
  const objectives = useObjectives(controlId, true, workbookId);
  // Per-CCI program-overlay mapping text is collapsed by default — the rollup
  // badges at the top of the expanded row already tell the user WHICH overlays
  // touch this control. The full "shall" text is only useful when the assessor
  // is actively reasoning about one of those overlays, so it stays hidden behind
  // a toggle. Mirrors ProgramControlsCard on the Control Detail page.
  const [showMappings, setShowMappings] = useState(false);

  if (objectives.isLoading) {
    return (
      <div className="flex items-center gap-2 px-6 py-3 text-xs text-muted-foreground">
        <Loader2 className="h-3 w-3 animate-spin" />
        Loading CCIs…
      </div>
    );
  }
  if (objectives.error) {
    return (
      <div className="px-6 py-3 text-xs text-destructive">
        Couldn't load CCIs: {(objectives.error as Error).message}
      </div>
    );
  }
  const rawObjs = objectives.data ?? [];
  // Workbook CCIs first, catalog stubs after — and within each bucket sort
  // by CCI number ascending so the user sees the natural CCI-000008 →
  // CCI-002115 order rather than whatever insertion order the catalog
  // loader happened to produce. ``cciNum`` strips the "CCI-" prefix and
  // parses the rest as an integer; anything that doesn't match falls back
  // to string comparison.
  const cciNum = (o: Objective): number => {
    const m = /^CCI-(\d+)$/i.exec(o.objective_id);
    return m ? parseInt(m[1], 10) : Number.MAX_SAFE_INTEGER;
  };
  const objs = [...rawObjs]
    // Hide the "not in workbook" catalog stubs (Rev3-only, inherited-from-CCP,
    // tailored-out, or soft-deleted) — they cluttered the list with CCIs the
    // assessor isn't evaluating. KEEP the deprecated ancestors, though: those
    // explain that coverage moved to newer atomized CCIs, which is signal the
    // assessor needs when reconciling old prior-assessment references.
    .filter((o) => o.in_workbook !== false || o.source === "CCI-deprecated")
    .sort((a, b) => {
      const aIn = a.in_workbook !== false; // undefined ⇒ in
      const bIn = b.in_workbook !== false;
      if (aIn !== bIn) return aIn ? -1 : 1;
      const na = cciNum(a);
      const nb = cciNum(b);
      if (na !== nb) return na - nb;
      return a.objective_id.localeCompare(b.objective_id);
    });
  const stubCount = objs.filter((o) => o.in_workbook === false).length;
  // Split the catalog-only rows two ways so the rollup count and the
  // per-row badge can explain WHY each CCI is catalog-only:
  //   • CCI-deprecated → DISA marked it deprecated; it was atomized into
  //     newer CCIs in a later revision (e.g. AC-2 CCI-002114 → -002125..2129).
  //   • otherwise → genuine "workbook didn't surface this catalog CCI":
  //     Rev3-only (no Rev4 reference, so eMASS doesn't export it), inherited
  //     from a CCP, tailored out, or soft-deleted.
  // The badge + tooltip downstream branch on this; the rollup count surfaces
  // each subset so the user isn't left wondering why a chunk of CCIs are
  // flagged.
  const deprecatedCount = objs.filter(
    (o) => o.in_workbook === false && o.source === "CCI-deprecated",
  ).length;
  const otherStubCount = stubCount - deprecatedCount;
  if (objs.length === 0) {
    return (
      <div className="px-6 py-3 text-xs text-muted-foreground italic">
        No CCIs / assessment objectives are mapped to this control. Load the DISA
        CCI overlay from <strong>Settings</strong> to enrich 800-53 controls with
        CCIs.
      </div>
    );
  }

  // Per-control rollup of program-overlay coverage — distinct overlay source
  // names that cite ANY CCI under this control, with the total req count per
  // source. Shown as a header strip so the user sees "this control is touched
  // by SDA Enterprise Services Controls × 7, T1TL Ground × 4" at a glance,
  // before they scan individual CCIs.
  const overlayCounts = new Map<string, number>();
  let totalMappings = 0;
  for (const o of objs) {
    for (const m of o.mappings ?? []) {
      overlayCounts.set(m.source_name, (overlayCounts.get(m.source_name) ?? 0) + 1);
      totalMappings += 1;
    }
  }

  return (
    <div className="px-6 py-3">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground mb-2">
        <span>
          {stubCount > 0 && workbookId !== undefined ? (
            <>
              <span className="font-medium text-foreground">
                {objs.length - stubCount} of {objs.length - stubCount} required
                CCI{objs.length - stubCount === 1 ? "" : "s"} in workbook
              </span>
              <span className="ml-1 text-foreground/70">
                · {stubCount} catalog-only (
                {[
                  deprecatedCount > 0 && `${deprecatedCount} deprecated`,
                  otherStubCount > 0 && `${otherStubCount} not surfaced`,
                ]
                  .filter(Boolean)
                  .join(", ")}
                )
              </span>
            </>
          ) : (
            <>
              {objs.length} CCI{objs.length === 1 ? "" : "s"} / assessment
              objective{objs.length === 1 ? "" : "s"}
            </>
          )}
        </span>
        {overlayCounts.size > 0 && (
          <span className="flex flex-wrap items-center gap-1">
            <span>·</span>
            {Array.from(overlayCounts.entries())
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([name, n]) => (
                <Badge
                  key={name}
                  variant="secondary"
                  title={`${name}: ${n} program requirement${n === 1 ? "" : "s"} cite a CCI under this control`}
                >
                  {name} × {n}
                </Badge>
              ))}
            <button
              type="button"
              onClick={() => setShowMappings((v) => !v)}
              aria-expanded={showMappings}
              className="ml-1 text-[11px] underline-offset-2 hover:underline hover:text-foreground"
              title={
                showMappings
                  ? "Hide the per-CCI program requirement text"
                  : "Show the per-CCI program requirement text"
              }
            >
              {showMappings
                ? `Hide program reqs (${totalMappings})`
                : `Show program reqs (${totalMappings})`}
            </button>
          </span>
        )}
      </div>
      <ul className="space-y-2">
        {objs.map((o) => {
          const mappings = o.mappings ?? [];
          const isStub = o.in_workbook === false;
          // DISA periodically atomizes compound CCIs into multiple
          // single-assertion CCIs across revisions (e.g. the old AC-2
          // CCI-000014 "grant access based on auth; intended usage; other
          // attributes" was split into CCI-002126/002127/002128). The
          // deprecated ancestors stay in the catalog with status=deprecated
          // (loader maps that to source="CCI-deprecated") but eMASS exports
          // only the current-revision CCIs — which is why they show up here
          // as not-in-workbook. Surface that distinction so the assessor
          // doesn't read "not in workbook" as a coverage gap.
          const isDeprecated = isStub && o.source === "CCI-deprecated";
          return (
            <li
              key={o.id}
              className={`text-sm leading-snug ${isStub ? "opacity-60" : ""}`}
            >
              <div className="flex items-start gap-3">
                <Badge
                  variant="outline"
                  className="font-mono text-[10px] shrink-0 mt-0.5"
                >
                  {o.objective_id}
                </Badge>
                <span className="text-foreground/85">{o.text}</span>
                {isDeprecated ? (
                  <Badge
                    variant="secondary"
                    className="text-[10px] shrink-0 mt-0.5 border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300"
                    title="DISA marked this CCI deprecated — it was atomized into one or more newer CCIs in a later CCI list revision. eMASS exports only current-revision CCIs, so this ancestor is shown for catalog completeness but is not assessed. Coverage is delivered by the replacement CCIs in the workbook above."
                  >
                    deprecated
                  </Badge>
                ) : (
                  isStub && (
                    <Badge
                      variant="secondary"
                      className="text-[10px] shrink-0 mt-0.5"
                      title="DISA maps this CCI to the control but the active workbook did not surface it. Common causes: inherited from a common control provider, tailored out in pre-assessment, or removed from the workbook. Coverage may live elsewhere — verify against the SDA / enterprise controls workbook before treating as a gap."
                    >
                      not in workbook
                    </Badge>
                  )
                )}
              </div>
              {showMappings && mappings.length > 0 && (
                <ul className="mt-1 ml-[4.5rem] space-y-0.5">
                  {mappings.map((m, i) => (
                    <li
                      key={`${m.source_name}-${m.requirement_number}-${i}`}
                      className="flex items-start gap-2 text-xs text-muted-foreground"
                    >
                      <Badge
                        variant="secondary"
                        className="font-mono text-[10px] shrink-0 mt-0.5"
                        title={m.source_name}
                      >
                        {m.requirement_number}
                      </Badge>
                      <span className="line-clamp-2" title={m.requirement_text}>
                        {m.requirement_text}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
