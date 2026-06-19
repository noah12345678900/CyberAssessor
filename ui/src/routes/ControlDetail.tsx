import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import Editor, { DiffEditor } from "@monaco-editor/react";
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Check,
  FileSearch,
  FileSpreadsheet,
  History,
  Info,
  ListChecks,
  Loader2,
  Save,
  Sparkles,
  X,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "@/components/ui/toaster";
import { humanize } from "@/lib/errors";
import {
  useApplyToWorkbook,
  useAssessmentAudit,
  useAssessObjective,
  useAssessments,
  useBaseline,
  useBaselineControls,
  useControl,
  useEvidenceForObjective,
  useOdpHistory,
  useProgramControlsForControl,
  useSettings,
  useUpsertAssessment,
  useWorkbooks,
} from "@/lib/queries";
import {
  ApiError,
  type AssessmentAudit,
  type AssessmentAuditCitation,
  type AssessmentAuditEvidenceShown,
  type AssessmentAuditPromptSnapshot,
  type AssessmentAuditTrace,
  type AssessmentDecision,
  type AssessmentImplementation,
  type ComplianceStatus,
  type NarrativeClass,
  type Objective,
  type OdpHistoryGroup,
  type ProgramControlSourceGroup,
} from "@/lib/api";

const STATUSES: ComplianceStatus[] = ["Compliant", "Non-Compliant", "Not Applicable"];
const CLASSES: NarrativeClass[] = [
  "compliance-affirming",
  "NA-justifying",
  "gap-describing",
  "ambiguous",
];

/**
 * Render a control statement that the backend has marked up with
 * ``**...**`` around substituted ODP values (see
 * controls/odp_render.py, bold_format="markdown"). We split on the
 * pattern and wrap matches in <strong> so the program's answers are
 * visually distinguishable from the catalog template prose.
 *
 * Kept deliberately minimal — only `**...**` is interpreted. No nested
 * markdown, no escapes; the substituted values are short strings the
 * assessor wrote into the workbook so an asterisk inside one is not a
 * realistic case to defend against.
 */
function renderStatementWithBoldOdps(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  // Non-greedy so adjacent **A** **B** stay as two separate spans.
  const pattern = /\*\*(.+?)\*\*/g;
  let last = 0;
  let key = 0;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(text)) !== null) {
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push(<strong key={key++}>{m[1]}</strong>);
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

export function ControlDetail() {
  const { controlId } = useParams<{ controlId: string }>();
  const id = controlId ? Number(controlId) : undefined;
  const workbooks = useWorkbooks();

  const [workbookId, setWorkbookId] = useState<number | undefined>();
  // Scope the control's objectives to the active workbook so legacy
  // cross-revision catalog stubs (Rev-3-only CCIs on a Rev-4 control) drop
  // from the count + list — see get_control in routes/controls.py. The first
  // render fetches unscoped (workbookId undefined) which still returns
  // framework_id to hydrate the picker below; once a workbook is selected the
  // query refetches scoped. framework_id is workbook-independent, so the
  // matching logic stays stable across the refetch.
  const control = useControl(id, workbookId);
  const [objectiveId, setObjectiveId] = useState<number | undefined>();

  // Filter the workbook picker to workbooks whose framework matches this
  // Control's framework. Each Framework owns its own Control/Objective rows
  // (catalog isolation) — saving a Rev-5 Objective PK against a Rev-4
  // baseline 422s on the missing BaselineObjective row. The server now
  // returns 409 as a backstop, but constraining the picker is the right
  // UX. See memory/project_odp_architecture.md.
  const matchingWorkbooks = useMemo(
    () =>
      (workbooks.data ?? []).filter(
        (w) =>
          control.data?.framework_id === undefined ||
          w.framework_id === control.data.framework_id,
      ),
    [workbooks.data, control.data?.framework_id],
  );

  // Hydrate defaults once data lands. Prefer the first IN-SCOPE objective
  // (in_workbook !== false) over catalog-only stubs that sort ahead of it.
  // For AC-7 the catalog puts out-of-scope CCI-000043 at objectives[0],
  // ahead of in-scope CCI-000044; defaulting to [0] blindly auto-selected
  // the wrong CCI and let "Assess (kernel)" run against an out-of-scope row
  // with thin evidence, yielding the empty-narrative Compliant glitch. The
  // `!== false` keeps legacy/unscoped rows (field undefined) treated as
  // in-scope, matching the backend contract.
  useEffect(() => {
    if (objectiveId === undefined && control.data?.objectives.length) {
      const objs = control.data.objectives;
      const firstInScope =
        objs.find((o) => o.in_workbook !== false) ?? objs[0];
      setObjectiveId(firstInScope.id);
    }
  }, [objectiveId, control.data]);
  useEffect(() => {
    // Default to a workbook from this Control's framework. If the current
    // selection is from a different framework (e.g. user navigated from a
    // Rev-4 control to a Rev-5 control), drop it so we don't post a
    // cross-framework save.
    if (workbookId === undefined && matchingWorkbooks.length) {
      setWorkbookId(matchingWorkbooks[0].id);
    } else if (
      workbookId !== undefined &&
      matchingWorkbooks.length &&
      !matchingWorkbooks.some((w) => w.id === workbookId)
    ) {
      setWorkbookId(matchingWorkbooks[0].id);
    } else if (
      workbookId !== undefined &&
      matchingWorkbooks.length === 0
    ) {
      setWorkbookId(undefined);
    }
  }, [workbookId, matchingWorkbooks]);

  const assessments = useAssessments(id, workbookId);

  // Index existing assessments by objective_id for the status pills.
  // v0.2 precision-over-recall: carry needs_review + confidence so the
  // objectives list can paint an amber Review pill (instead of the LLM's
  // proposed status badge) for abstained CCIs.
  const statusByObjective = useMemo(() => {
    const m = new Map<
      number,
      { status: ComplianceStatus; needsReview: boolean; confidence: number | null }
    >();
    for (const a of assessments.data ?? []) {
      m.set(a.objective_id, {
        status: a.status,
        needsReview: !!a.needs_review,
        confidence: a.confidence ?? null,
      });
    }
    return m;
  }, [assessments.data]);

  // Look up the selected workbook's baseline so the Context card can show
  // tailoring state (in-scope, ODP overrides, reason). null when no workbook
  // is picked or the workbook has no baseline applied yet.
  const selectedWorkbook = useMemo(
    () => workbooks.data?.find((w) => w.id === workbookId),
    [workbooks.data, workbookId],
  );
  const baselineId = selectedWorkbook?.baseline_id ?? undefined;
  const baseline = useBaseline(baselineId);
  const baselineControls = useBaselineControls(baselineId, false);
  const baselineRow = useMemo(
    () => baselineControls.data?.find((r) => r.control_id === id),
    [baselineControls.data, id],
  );

  if (control.isLoading || !control.data) {
    return (
      <div className="p-8 space-y-4">
        <Button asChild variant="ghost" size="sm">
          <Link to="/controls">
            <ArrowLeft className="h-4 w-4" />
            Back to controls
          </Link>
        </Button>
        <div className="text-sm text-muted-foreground">
          {control.isLoading ? (
            <>
              <Loader2 className="inline h-4 w-4 animate-spin mr-2" />
              Loading control…
            </>
          ) : (
            "Control not found."
          )}
        </div>
      </div>
    );
  }

  const c = control.data;
  const currentAssessment = assessments.data?.find((a) => a.objective_id === objectiveId);
  // Scope of the selected objective. A catalog-only stub (in_workbook===false)
  // is out of scope: assessing it produces the empty-narrative Compliant
  // glitch, so the Assess (kernel) button is gated on this. undefined field
  // (legacy / no baseline) is treated as in-scope.
  const selectedObjective = c?.objectives.find((o) => o.id === objectiveId);
  const selectedObjectiveInScope = selectedObjective?.in_workbook !== false;
  // Workbook Column L (inherited) for the selected CCI — the authority for the
  // flex (On-Premises/workbook) slice's status. Trimmed; empty/blank reads as
  // "assess" and we still show the chip so the assessor sees the workbook said
  // nothing. null/undefined (no workbook in play) omits the chip entirely.
  const colLInherited =
    selectedObjective?.inherited === undefined || selectedObjective?.inherited === null
      ? null
      : selectedObjective.inherited;
  // Column M (Remote Inheritance Instance) — the inheritance source name,
  // paired with col L so the flex chip resolves Remote/Yes correctly.
  const colMRemote = selectedObjective?.remote_inheritance ?? null;

  return (
    <div className="p-8 space-y-6">
      <Button asChild variant="ghost" size="sm">
        <Link to="/controls">
          <ArrowLeft className="h-4 w-4" />
          Back to controls
        </Link>
      </Button>

      <header className="flex flex-wrap items-baseline justify-between gap-3">
        <div className="flex items-baseline gap-3">
          <h1 className="text-2xl font-semibold tracking-tight font-mono">{c.control_id}</h1>
          <Badge variant="outline">{c.family}</Badge>
          <span className="text-lg text-muted-foreground">{c.title}</span>
        </div>
        <div className="flex items-end gap-2">
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground block">
              Workbook
            </label>
            <Select
              value={workbookId !== undefined ? String(workbookId) : "__none__"}
              onValueChange={(v) =>
                setWorkbookId(v === "__none__" ? undefined : Number(v))
              }
            >
              <SelectTrigger className="w-[260px]">
                <SelectValue placeholder="None" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="__none__">None</SelectItem>
                {matchingWorkbooks.map((w) => (
                  <SelectItem key={w.id} value={String(w.id)}>
                    {w.filename}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {matchingWorkbooks.length === 0 && (workbooks.data?.length ?? 0) > 0 && (
              <p className="text-xs text-muted-foreground max-w-[260px]">
                No workbook open for this framework.{" "}
                <Link to="/workbooks" className="underline">
                  Open or rebind one on the Workbooks page
                </Link>
                .
              </p>
            )}
          </div>
        </div>
      </header>

      {c.statement && (
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <CardTitle>Statement</CardTitle>
              {c.unresolved_odps && c.unresolved_odps.length > 0 && (
                <Badge
                  variant="outline"
                  className="border-amber-300 bg-amber-50 text-amber-800 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
                  title={`Unresolved placeholders:\n${c.unresolved_odps.join("\n")}`}
                >
                  {c.unresolved_odps.length} unresolved ODP
                  {c.unresolved_odps.length === 1 ? "" : "s"}
                </Badge>
              )}
            </div>
          </CardHeader>
          <CardContent className="text-sm whitespace-pre-wrap leading-relaxed">
            {renderStatementWithBoldOdps(c.statement)}
          </CardContent>
        </Card>
      )}

      <ContextCard
        controlId={c.control_id}
        family={c.family}
        objectivesTotal={c.objectives.length}
        statusByObjective={statusByObjective}
        baseline={baseline.data}
        baselineRow={baselineRow}
        workbookSelected={workbookId !== undefined}
        colLInherited={colLInherited}
        colMRemote={colMRemote}
      />

      <ProgramControlsCard
        controlId={id}
        frameworkId={selectedWorkbook?.framework_id ?? undefined}
      />

      {/* ODP value-overwrite audit history. Renders nothing when no rows
          exist (typical for first-ingest workbooks); collapsed by default
          with a per-ODP / per-event count badge. Per-Control scope, so it
          sits at the top level alongside ProgramControlsCard, not inside
          the per-CCI center column. */}
      {/* id is narrowed past the early-return on control.data (line ~187); TS can't see it. */}
      <OdpHistoryCard controlId={id!} />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left column: objectives list */}
        <ObjectivesList
          objectives={c.objectives}
          statusByObjective={statusByObjective}
          objectiveId={objectiveId}
          setObjectiveId={setObjectiveId}
        />


        {/* Center column: narrative editor + actions */}
        <div className="lg:col-span-6 space-y-6">
          <AssessmentPanel
            objectiveId={objectiveId}
            objectiveInScope={selectedObjectiveInScope}
            workbookId={workbookId}
            existingNarrative={currentAssessment?.narrative_q ?? ""}
            existingStatus={currentAssessment?.status}
            existingClass={currentAssessment?.narrative_class}
            existingNeedsReview={currentAssessment?.needs_review ?? false}
            existingReviewReason={currentAssessment?.review_reason ?? null}
            existingConfidence={currentAssessment?.confidence ?? null}
            existingRewriteRequested={currentAssessment?.rewrite_requested ?? false}
            existingRewriteRequestedRefs={
              currentAssessment?.rewrite_requested_refs ?? null
            }
            implementations={currentAssessment?.implementations ?? []}
          />
          {/* Audit v1 — verdict→evidence trace for 3PAO/JAB defensibility.
              Renders nothing until the CCI has an Assessment row; once one
              exists, the section is collapsed by default and fetches the
              audit payload only when the tester expands it. */}
          <AuditTrailSection assessmentId={currentAssessment?.id ?? null} />
        </div>

        {/* Right column: evidence */}
        <div className="lg:col-span-3">
          <EvidencePanel objectiveId={objectiveId} />
        </div>
      </div>
    </div>
  );
}

/**
 * Left-rail CCI picker for the Control Detail page.
 *
 * Splits the control's CCIs into two stacked sections:
 *   - **Assessed** — rows that already have an Assessment in the active
 *     workbook (i.e. `statusByObjective.has(o.id)`). Shown first so the
 *     tester sees what's done and can jump to revise.
 *   - **Unassessed** — rows the workbook surfaced but that haven't been
 *     assessed yet (no Assessment row, status pill would otherwise show
 *     the catalog `source` badge). Rendered in a second section with a
 *     section header and a toggle to hide them — useful when the tester
 *     wants to focus on the assessed bucket without losing the "what's
 *     left" count.
 *
 * Sort order within each bucket: by CCI number ascending
 * (CCI-000008 before CCI-002121), matching the Controls grid CciList.
 *
 * The "show stubs not in workbook" toggle is intentionally NOT here —
 * the catalog-only stub set (CCIs the DISA catalog lists under this
 * control but the workbook didn't surface) isn't in `c.objectives` for
 * this page; that filter lives at the API layer for the Controls grid.
 */
function ObjectivesList({
  objectives,
  statusByObjective,
  objectiveId,
  setObjectiveId,
}: {
  objectives: Objective[];
  statusByObjective: Map<
    number,
    { status: ComplianceStatus; needsReview: boolean; confidence: number | null }
  >;
  objectiveId: number | undefined;
  setObjectiveId: (id: number) => void;
}) {
  // Unassessed CCIs are visible by default — hiding them is opt-in. The
  // assessor still needs to SEE that there are 8 unassessed rows; the
  // toggle is for when they want to focus on the assessed bucket and
  // scroll less.
  const [hideUnassessed, setHideUnassessed] = useState(false);

  const cciNum = (id: string): number => {
    const m = /^CCI-(\d+)$/i.exec(id);
    return m ? parseInt(m[1], 10) : Number.MAX_SAFE_INTEGER;
  };
  const sortByCci = (a: Objective, b: Objective) => {
    const na = cciNum(a.objective_id);
    const nb = cciNum(b.objective_id);
    if (na !== nb) return na - nb;
    return a.objective_id.localeCompare(b.objective_id);
  };
  const assessed = objectives
    .filter((o) => statusByObjective.has(o.id))
    .sort(sortByCci);
  const unassessed = objectives
    .filter((o) => !statusByObjective.has(o.id))
    .sort(sortByCci);

  const renderButton = (o: Objective) => {
    const entry = statusByObjective.get(o.id);
    return (
      <button
        key={o.id}
        onClick={() => setObjectiveId(o.id)}
        className={`w-full text-left rounded-md border p-3 text-sm hover:bg-accent transition-colors ${
          objectiveId === o.id ? "border-primary bg-accent" : ""
        }`}
      >
        <div className="flex items-center justify-between mb-1">
          <span className="font-mono text-xs">{o.objective_id}</span>
          {entry ? (
            <StatusPill
              status={entry.status}
              needsReview={entry.needsReview}
              confidence={entry.confidence}
            />
          ) : (
            <Badge variant="outline" className="text-[10px]">
              {o.source}
            </Badge>
          )}
        </div>
        <div className="text-xs text-muted-foreground line-clamp-2">{o.text}</div>
      </button>
    );
  };

  return (
    <Card className="lg:col-span-3">
      <CardHeader>
        <CardTitle>Objectives ({objectives.length})</CardTitle>
        <CardDescription>Select to assess</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 max-h-[60vh] overflow-auto">
        {assessed.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                Assessed ({assessed.length})
              </div>
            </div>
            {assessed.map(renderButton)}
          </div>
        )}
        {unassessed.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center justify-between pt-1 border-t border-dashed">
              <div className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground mt-2">
                Unassessed ({unassessed.length})
              </div>
              <button
                type="button"
                onClick={() => setHideUnassessed((v) => !v)}
                aria-expanded={!hideUnassessed}
                className="text-[11px] mt-2 text-muted-foreground hover:text-foreground underline-offset-2 hover:underline"
                title={
                  hideUnassessed
                    ? "Show CCIs in this workbook that haven't been assessed yet"
                    : "Hide the unassessed CCIs to focus on what's already been assessed"
                }
              >
                {hideUnassessed ? "Show" : "Hide"}
              </button>
            </div>
            {!hideUnassessed && unassessed.map(renderButton)}
          </div>
        )}
        {assessed.length === 0 && unassessed.length === 0 && (
          <div className="text-xs text-muted-foreground italic py-4 text-center">
            No CCIs / assessment objectives are mapped to this control.
          </div>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * Compact context strip shown above the three-column working area.
 *
 * Surfaces the bits a tester normally has to leave the page to find:
 *   - Where this control sits in the framework family
 *   - Whether the selected workbook's baseline tailored this control
 *     in or out, and any ODP parameter overrides applied
 *   - Live assessment progress for this control in the selected workbook
 *
 * The card is intentionally read-only — tailoring lives on the Baselines
 * screen, and assessments are edited in the panel below. This is a
 * heads-up display, not another place to fight for the source of truth.
 */
function ContextCard({
  controlId,
  family,
  objectivesTotal,
  statusByObjective,
  baseline,
  baselineRow,
  workbookSelected,
  colLInherited,
  colMRemote,
}: {
  controlId: string;
  family: string;
  objectivesTotal: number;
  statusByObjective: Map<
    number,
    { status: ComplianceStatus; needsReview: boolean; confidence: number | null }
  >;
  baseline?: { name: string; source_type: string } | null;
  baselineRow?: {
    in_scope: boolean;
    tailoring_reason: string | null;
    parameter_overrides_json: string | null;
    responsibility: string | null;
    responsibility_narrative: string | null;
    responsibility_onprem: string | null;
    responsibility_onprem_narrative: string | null;
  };
  workbookSelected: boolean;
  // Workbook Column L (inherited) for the SELECTED CCI — drives the flex-slice
  // chip. null when no workbook is in play or the row couldn't be re-read.
  colLInherited: string | null;
  // Workbook Column M (Remote Inheritance Instance) — the source name; pairs
  // with col L so the chip resolves Remote/Yes correctly.
  colMRemote: string | null;
}) {
  // Tally CCI statuses for this control in the selected workbook so the
  // tester can see "5/8 CCIs assessed — 3C / 1NC / 1NA" at a glance,
  // without scanning the objectives column.
  const progress = useMemo(() => {
    let compliant = 0;
    let nc = 0;
    let na = 0;
    let review = 0;
    for (const entry of statusByObjective.values()) {
      // v0.2: abstained rows count toward "assessed" (work was done) but
      // NOT toward C/NC/NA — their proposed status isn't trusted yet. The
      // review counter is what the operator works through to clear the queue.
      if (entry.needsReview) review++;
      else if (entry.status === "Compliant") compliant++;
      else if (entry.status === "Non-Compliant") nc++;
      else if (entry.status === "Not Applicable") na++;
    }
    const assessed = compliant + nc + na + review;
    return { compliant, nc, na, review, assessed };
  }, [statusByObjective]);

  // ODP overrides ship as a JSON string blob (`{"ac-2_odp.01": "30 days", ...}`)
  // so they round-trip cleanly through OSCAL. Parse defensively — a malformed
  // override shouldn't blank the whole card.
  const odpEntries = useMemo(() => {
    if (!baselineRow?.parameter_overrides_json) return [];
    try {
      const parsed = JSON.parse(baselineRow.parameter_overrides_json) as Record<
        string,
        unknown
      >;
      return Object.entries(parsed).map(([key, val]) => [key, String(val)] as const);
    } catch {
      return [];
    }
  }, [baselineRow?.parameter_overrides_json]);

  // Scope badge tri-state: in / out / no-baseline. We deliberately don't
  // collapse "no baseline" into "in scope" — an unbaselined workbook is
  // a setup gap the tester should notice.
  const scopeBadge: { label: string; variant: "success" | "warning" | "outline" } =
    !workbookSelected
      ? { label: "No workbook selected", variant: "outline" }
      : !baseline
        ? { label: "Workbook has no baseline", variant: "warning" }
        : !baselineRow
          ? { label: "Control not in baseline", variant: "warning" }
          : baselineRow.in_scope
            ? { label: "In scope", variant: "success" }
            : { label: "Tailored out", variant: "warning" };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Info className="h-4 w-4 text-muted-foreground" />
          Context
        </CardTitle>
        <CardDescription>
          Where <span className="font-mono">{controlId}</span> sits and how it&apos;s
          tailored for the selected workbook
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline" className="font-mono text-[10px]">
            Family · {family}
          </Badge>
          <span className="text-muted-foreground">·</span>
          <Badge variant="outline" className="text-[10px]">
            {objectivesTotal} CCI{objectivesTotal === 1 ? "" : "s"}
          </Badge>
          <span className="text-muted-foreground">·</span>
          <Badge variant={scopeBadge.variant} className="text-[10px]">
            {scopeBadge.label}
          </Badge>
          {baseline && (
            <span className="text-xs text-muted-foreground truncate">
              Baseline: <span className="font-medium">{baseline.name}</span>{" "}
              <span className="font-mono">({baseline.source_type})</span>
            </span>
          )}
        </div>

        {baselineRow?.tailoring_reason && (
          <div className="rounded-md bg-muted/40 p-2 text-xs">
            <span className="text-muted-foreground">Tailoring reason: </span>
            <span>{baselineRow.tailoring_reason}</span>
          </div>
        )}

        {(baselineRow?.responsibility || baselineRow?.responsibility_onprem) && (
          <ResponsibilityChip
            responsibility={baselineRow.responsibility ?? null}
            narrative={baselineRow.responsibility_narrative ?? null}
            responsibilityOnprem={baselineRow.responsibility_onprem ?? null}
            narrativeOnprem={baselineRow.responsibility_onprem_narrative ?? null}
          />
        )}

        {colLInherited !== null && (
          <FlexInheritanceChip colL={colLInherited} colM={colMRemote} />
        )}

        {odpEntries.length > 0 && (
          <div className="text-xs space-y-1">
            <div className="text-muted-foreground">
              ODP overrides ({odpEntries.length})
            </div>
            <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-0.5">
              {odpEntries.map(([k, v]) => (
                <li key={k} className="flex gap-2">
                  <span className="font-mono text-[11px] text-muted-foreground">
                    {k}
                  </span>
                  <span className="truncate">{v}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {workbookSelected && (
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-muted-foreground">Assessment progress:</span>
            <span className="font-medium">
              {progress.assessed}/{objectivesTotal} CCI
              {objectivesTotal === 1 ? "" : "s"} assessed
            </span>
            {progress.assessed > 0 && (
              <span className="flex items-center gap-1.5">
                <Badge variant="success" className="text-[10px]">
                  {progress.compliant} C
                </Badge>
                <Badge variant="destructive" className="text-[10px]">
                  {progress.nc} NC
                </Badge>
                <Badge variant="outline" className="text-[10px]">
                  {progress.na} N/A
                </Badge>
                {progress.review > 0 && (
                  <Badge
                    variant="warning"
                    className="text-[10px]"
                    title="Needs review — assessor abstained; resolve before exporting"
                  >
                    {progress.review} Review
                  </Badge>
                )}
              </span>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * Program-Specific Controls rollup — overlay "shall" statements (e.g.
 * SDA-127) that crosswalk to one or more of this control's CCIs, grouped
 * by RequirementSource so a single overlay's rows appear together.
 *
 * Surfaces the program-level requirements driving the CCIs the assessor is
 * about to assess WITHOUT having to expand every objective row. The card
 * is hidden entirely when no overlay maps to this control — overlay-free
 * controls shouldn't show an empty section.
 *
 * Framework filter is passed in so a multi-framework DB doesn't bleed
 * (an r4 SDA overlay onto an r5 control). The hook treats undefined as
 * "any framework" so the card still renders something useful when the
 * user hasn't picked a workbook yet.
 */
function ProgramControlsCard({
  controlId,
  frameworkId,
}: {
  controlId: number | undefined;
  frameworkId: number | undefined;
}) {
  const q = useProgramControlsForControl(controlId, frameworkId);
  const groups = q.data ?? [];
  // Collapsed by default so the dense context strip stays scannable —
  // the assessor opens it only when they care which program overlay
  // requirements (SDA-127, T1TL, etc.) are driving the CCIs. Mirrors
  // the CRM responsibility card pattern (narrative hidden until toggled).
  const [open, setOpen] = useState(false);
  // Match peer cards: render nothing while loading and nothing when empty.
  // An empty heading would mislead testers into hunting for missing overlays.
  if (q.isLoading || groups.length === 0) return null;
  // Total overlay-row count across all groups — surfaced in the collapsed
  // header so the assessor knows how much is hiding before they expand.
  const totalRows = groups.reduce((sum, g) => sum + g.rows.length, 0);
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-2">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2 text-base">
              <ListChecks className="h-4 w-4 text-muted-foreground" />
              Program-specific controls
              <Badge variant="secondary" className="text-[10px]">
                {groups.length} overlay{groups.length === 1 ? "" : "s"} · {totalRows} req
                {totalRows === 1 ? "" : "s"}
              </Badge>
            </CardTitle>
            <CardDescription>
              Overlay &quot;shall&quot; statements that crosswalk to this control&apos;s CCIs
            </CardDescription>
          </div>
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            className="shrink-0 text-xs text-muted-foreground hover:text-foreground underline-offset-2 hover:underline"
          >
            {open ? "Hide" : "Show"}
          </button>
        </div>
      </CardHeader>
      {open && (
        <CardContent className="space-y-4">
          {groups.map((g) => (
            <ProgramControlsGroup key={g.source.id} group={g} />
          ))}
        </CardContent>
      )}
    </Card>
  );
}

function ProgramControlsGroup({ group }: { group: ProgramControlSourceGroup }) {
  // Control-grain overlays (e.g. T1TL) carry no per-row number — the loader
  // writes "(unnumbered)" as a sentinel. When every row in this group is
  // unnumbered, hide the Number column entirely instead of rendering a wall
  // of identical sentinel text.
  const hasNumbers = group.rows.some(
    (r) => r.requirement_number && r.requirement_number !== "(unnumbered)",
  );
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <h3 className="text-sm font-medium">{group.source.name}</h3>
        <Badge variant="outline" className="text-[10px]">
          {group.rows.length}
        </Badge>
      </div>
      <div className="rounded-md border overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-muted/40 text-muted-foreground">
            <tr>
              {hasNumbers && (
                <th className="text-left font-medium px-3 py-2 w-[140px]">Number</th>
              )}
              <th className="text-left font-medium px-3 py-2">Requirement</th>
              <th className="text-left font-medium px-3 py-2 w-[140px]">Maps to CCI</th>
            </tr>
          </thead>
          <tbody>
            {group.rows.map((r) => (
              <tr key={r.id} className="border-t align-top">
                {hasNumbers && (
                  <td className="px-3 py-2 font-mono">
                    {r.requirement_number === "(unnumbered)" ? "" : r.requirement_number}
                  </td>
                )}
                <td className="px-3 py-2 leading-relaxed whitespace-pre-wrap">
                  {r.requirement_text}
                </td>
                <td className="px-3 py-2">
                  <Badge variant="secondary" className="font-mono text-[10px]">
                    {r.objective_code}
                  </Badge>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/**
 * CRM responsibility chip + collapsible narrative panel.
 *
 * Surfaces what a Customer Responsibility Matrix overlay said about this
 * control. Color matches the engine's short-circuit behavior so the tester
 * can predict what an assessment will do without reading the prompt:
 *   - provider / inherited (brand-blue) — engine auto-finalizes; tester
 *     normally won't run the LLM at all.
 *   - not_applicable (outline-grey) — engine auto-finalizes to N/A.
 *   - hybrid (amber) — engine injects the customer narrative into the
 *     prompt so the LLM only assesses the customer-side share.
 *   - customer (subtle-neutral) — full local assessment, no short-circuit.
 *
 * Narrative is hidden by default and expanded by a click so the chip stays
 * compact in the dense Context strip but the verbatim CRM text is one tap
 * away when the tester wants to audit what the overlay actually said.
 */
function responsibilityMeta(responsibility: string): {
  label: string;
  variant: "brand" | "warning" | "outline" | "subtle";
  blurb: string;
} {
  const r = responsibility.trim().toLowerCase();
  if (r === "provider")
    return {
      label: "Provider",
      variant: "brand",
      blurb: "Cloud/service provider owns this control.",
    };
  if (r === "inherited")
    return {
      label: "Inherited",
      variant: "brand",
      blurb: "Fully inherited from a provider — no local action required.",
    };
  if (r === "hybrid")
    return {
      label: "Hybrid",
      variant: "warning",
      blurb:
        "Shared between customer and provider. LLM assesses customer-side only.",
    };
  if (r === "not_applicable" || r === "not applicable" || r === "na")
    return {
      label: "Not Applicable",
      variant: "outline",
      blurb: "Excluded by the CRM — engine auto-marks N/A.",
    };
  return {
    label: "Customer",
    variant: "subtle",
    blurb: "Customer owns this control — full local assessment.",
  };
}

/**
 * One scope row inside ResponsibilityChip. Cloud and on-prem share the same
 * layout (label badge + blurb + optional expandable narrative) so the dual
 * pane stays visually balanced when both scopes are present. Local state
 * for the open/closed narrative is per-scope — opening cloud doesn't
 * spring on-prem and vice versa.
 */
function ResponsibilityScopeRow({
  scope,
  scopeIcon,
  scopeLabel,
  responsibility,
  narrative,
}: {
  scope: "cloud" | "onprem";
  scopeIcon: string;
  scopeLabel: string;
  responsibility: string;
  narrative: string | null;
}) {
  const [open, setOpen] = useState(false);
  const meta = responsibilityMeta(responsibility);
  return (
    <div className="space-y-1.5">
      <div className="flex flex-wrap items-center gap-2">
        <span
          className="text-muted-foreground"
          aria-label={`${scopeLabel} scope`}
        >
          <span aria-hidden="true">{scopeIcon}</span> {scopeLabel}:
        </span>
        <Badge variant={meta.variant} className="text-[10px]">
          {meta.label}
        </Badge>
        <span className="text-muted-foreground">{meta.blurb}</span>
        {narrative && (
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="ml-auto text-[11px] text-muted-foreground hover:text-foreground underline-offset-2 hover:underline"
          >
            {open
              ? `Hide ${scope === "cloud" ? "cloud" : "on-prem"} narrative`
              : `Show ${scope === "cloud" ? "cloud" : "on-prem"} narrative`}
          </button>
        )}
      </div>
      {open && narrative && (
        <div className="whitespace-pre-wrap rounded-sm border bg-background/60 p-2 text-[11px] leading-relaxed">
          {narrative}
        </div>
      )}
    </div>
  );
}

/**
 * Dual-scope CRM responsibility panel. Renders up to two scope rows
 * (cloud + on-prem) so mixed cloud+on-prem systems see both verdicts
 * side-by-side instead of one collapsed verdict. Single-scope CRMs
 * (legacy cloud-only CSP templates) render just the populated row —
 * the absent scope is silently dropped, not shown as "Customer" by
 * default, because absence in the CRM means "no entry," not "customer."
 * Matches the engine's short-circuit semantics: a row with one
 * inheritable scope and no entry for the other still short-circuits.
 */
function ResponsibilityChip({
  responsibility,
  narrative,
  responsibilityOnprem,
  narrativeOnprem,
}: {
  responsibility: string | null;
  narrative: string | null;
  responsibilityOnprem: string | null;
  narrativeOnprem: string | null;
}) {
  // Defensive — the caller is expected to skip this component when both
  // scopes are null, but be safe in case it doesn't.
  if (!responsibility && !responsibilityOnprem) return null;

  return (
    <div className="rounded-md bg-muted/40 p-2 text-xs space-y-2">
      <div className="text-muted-foreground">Responsibility (CRM)</div>
      {responsibility && (
        <ResponsibilityScopeRow
          scope="cloud"
          scopeIcon="☁"
          scopeLabel="Cloud"
          responsibility={responsibility}
          narrative={narrative}
        />
      )}
      {responsibilityOnprem && (
        <ResponsibilityScopeRow
          scope="onprem"
          scopeIcon="🏢"
          scopeLabel="On-prem"
          responsibility={responsibilityOnprem}
          narrative={narrativeOnprem}
        />
      )}
    </div>
  );
}

/**
 * Mirror of the backend ``rules.resolve_col_l_flex_status``: classify the
 * workbook's inheritance columns into the flex (On-Premises/workbook) slice
 * outcome. Owner convention: Column L is a FLAG only (Local/No/blank →
 * locally owned; Remote/Yes → inherited), and the inheritance SOURCE is named
 * in Column M (Remote Inheritance Instance). Display-only — the authoritative
 * resolution happens server-side (the grid chip passes both columns).
 */
function flexInheritanceMeta(
  colL: string,
  colM?: string | null,
): {
  label: string;
  variant: "brand" | "warning" | "outline" | "subtle";
  blurb: string;
} {
  const v = colL.trim().toLowerCase();
  const REMOTE = new Set(["remote", "yes", "y", "true", "inherited"]);
  const m = (colM ?? "").trim();
  if (REMOTE.has(v)) {
    // Inherited flag — the source must be named in Column M.
    if (m)
      return {
        label: "Inherited",
        variant: "brand",
        blurb: `Inherited per the workbook (source: ${m}) — flex slice is Compliant-by-inheritance.`,
      };
    return {
      label: "Escalate",
      variant: "warning",
      blurb:
        "Column L marks this inherited but Column M names no source — escalated for reviewer (8c).",
    };
  }
  // Local / No / blank → locally owned → assess.
  return {
    label: "Assess (local)",
    variant: "subtle",
    blurb:
      "Workbook Column L says locally owned — flex slice is assessed (Non-Compliant if no evidence).",
  };
}

/**
 * Third "pie-slice" chip: the flex (On-Premises / workbook) slice status, taken
 * from the eMASS workbook's Column L (the single authority for that slice).
 * Sits next to the two CRM cloud-responsibility chips. Renders only when the
 * selected CCI's Column L value is known (workbook in play + row readable).
 */
function FlexInheritanceChip({
  colL,
  colM,
}: {
  colL: string;
  colM?: string | null;
}) {
  const meta = flexInheritanceMeta(colL, colM);
  const shown = colL.trim() === "" ? "(blank)" : colL.trim();
  return (
    <div className="rounded-md bg-muted/40 p-2 text-xs space-y-1.5">
      <div className="text-muted-foreground">
        Inheritance (Workbook Col L)
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-muted-foreground" aria-label="On-premises / workbook scope">
          Flex:
        </span>
        <Badge variant={meta.variant} className="text-[10px]">
          {meta.label}
        </Badge>
        <span className="font-mono text-[10px] text-muted-foreground">
          {shown}
        </span>
        <span className="text-muted-foreground">{meta.blurb}</span>
      </div>
    </div>
  );
}

function StatusPill({
  status,
  needsReview = false,
  confidence = null,
}: {
  status: ComplianceStatus;
  // v0.2 precision-over-recall: when the row is an abstain, the pill should
  // make that visible even though the LLM proposed a status — the proposed
  // status isn't trusted yet (exports filter the row out), so showing a
  // green "Compliant" badge would actively mislead reviewers.
  needsReview?: boolean;
  confidence?: number | null;
}) {
  if (needsReview) {
    // Amber "Review" pill takes precedence over the LLM-proposed status.
    // Confidence rendered as a parenthetical when available so a calibrated
    // 0.41 self-rating shows up next to the badge.
    const pctLabel =
      confidence != null && Number.isFinite(confidence)
        ? ` (${Math.round(confidence * 100)}%)`
        : "";
    return (
      <Badge
        variant="warning"
        className="text-[10px]"
        title={`Needs review — LLM proposed ${status}${pctLabel}`}
      >
        Review{pctLabel}
      </Badge>
    );
  }
  const variant =
    status === "Compliant"
      ? "success"
      : status === "Non-Compliant"
        ? "destructive"
        : "warning";
  const label =
    status === "Compliant"
      ? "Compliant"
      : status === "Non-Compliant"
        ? "Non-Compliant"
        : "N/A";
  return (
    <Badge variant={variant} className="text-[10px]" title={status}>
      {label}
    </Badge>
  );
}

/**
 * Yellow callout shown above the assessment editor when the persisted row
 * is a v0.2 abstain. Surfaces the structured review_reason so the operator
 * working the queue can decide *how* to resolve without re-running the
 * assessor — most reasons (validator-exhausted, unverified-cites, dual-pass-
 * disagreement, stale-reference, boundary-conflict) point at a specific
 * narrative fix rather than an evidence-collection task.
 *
 * Reason strings come from the assessor as ``"category: detail"`` (e.g.
 * ``"unverified-cites: USD99999999"`` / ``"boundary-conflict: …"``). We
 * split for emphasis but render the whole string verbatim so nothing the
 * assessor flagged gets hidden.
 */
function ReviewCallout({
  reason,
  confidence,
  proposedStatus,
}: {
  reason: string | null;
  confidence: number | null;
  proposedStatus?: ComplianceStatus;
}) {
  const pct =
    confidence != null && Number.isFinite(confidence)
      ? `${Math.round(confidence * 100)}%`
      : null;
  // The "evidence-changed" reason is an INVALIDATION flag, not a kernel
  // abstain: the row still carries a real verdict (e.g. Compliant), it's just
  // marked stale because the evidence set changed since it was assessed.
  // Labeling it "assessor abstained" was misleading — relabel it neutrally and
  // suppress the "LLM proposed" badge (no proposal was made).
  const isEvidenceChanged = reason === "evidence-changed-since-assessment";
  const headline = isEvidenceChanged
    ? "Needs review — evidence changed since assessment"
    : "Needs review — assessor abstained";
  // Split the "category: detail" form so the chip-style category badge gets
  // visual weight. Fall back to a single-line render when no colon is present.
  const colonAt = reason?.indexOf(":") ?? -1;
  const category = reason && colonAt > 0 ? reason.slice(0, colonAt).trim() : null;
  const detail = reason && colonAt > 0 ? reason.slice(colonAt + 1).trim() : reason;

  return (
    <div className="rounded-md border border-amber-500/60 bg-amber-50 dark:bg-amber-950/30 p-3 space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-amber-800 dark:text-amber-300">
        <AlertTriangle className="h-4 w-4" />
        <span className="text-sm font-medium">{headline}</span>
        {proposedStatus && !isEvidenceChanged && (
          <Badge variant="outline" className="text-[10px]">
            LLM proposed: {proposedStatus}
          </Badge>
        )}
        {pct && (
          <Badge variant="outline" className="text-[10px]" title="Self-reported confidence">
            confidence {pct}
          </Badge>
        )}
      </div>
      {reason ? (
        <div className="text-xs space-y-1">
          {category && (
            <Badge
              variant="warning"
              className="text-[10px] font-mono"
              title={isEvidenceChanged ? "Review category" : "Abstain category"}
            >
              {category}
            </Badge>
          )}
          <p className="whitespace-pre-wrap leading-relaxed text-amber-900 dark:text-amber-200">
            {isEvidenceChanged
              ? "The evidence set for this control changed after it was assessed. " +
                "The verdict above is the prior result — re-assess to refresh it " +
                "against the current evidence, or save to confirm it as-is."
              : detail}
          </p>
        </div>
      ) : (
        <p className="text-xs text-amber-900 dark:text-amber-200">
          No reason recorded. Review the narrative and save to clear the flag.
        </p>
      )}
      <p className="text-[11px] text-muted-foreground">
        {isEvidenceChanged
          ? "Re-assess to refresh this verdict against the current evidence, or " +
            "Save to confirm the existing verdict and clear the flag."
          : "Save clears the abstain and (when cleared) writes the row to the " +
            "workbook working copy in the same step. Use Apply to workbook only " +
            "if you want to re-write an already-saved row."}
      </p>
    </div>
  );
}

/**
 * Blue/info callout shown above the assessment editor when the persisted row
 * carries a v0.2 ``rewrite_requested=true`` flag — supersession or
 * NA-reconsideration flagged the narrative for a citation refresh, but the
 * verdict stands and the row exports normally (no abstain). Distinct from
 * :func:`ReviewCallout`: rewrite_requested rows are TRUSTED verdicts; this
 * banner is workflow nudge, not a blocker. The "Apply to workbook" button
 * stays enabled.
 *
 * ``refs`` is the raw JSON-encoded list on
 * ``Assessment.rewrite_requested_refs`` — ``[[legacy, current], ...]``.
 * Older rows (flagged before the refs column was populated) come through
 * as null; we fall back to a generic body in that case, mirroring the
 * POAM/CCIS writer fallback in :func:`poam.generator._render_cite_refresh_block`.
 */
function CiteRefreshCallout({ refs }: { refs: string | null }) {
  let pairs: Array<[string, string]> = [];
  if (refs) {
    try {
      const decoded = JSON.parse(refs);
      if (Array.isArray(decoded)) {
        for (const entry of decoded) {
          if (
            Array.isArray(entry) &&
            entry.length >= 2 &&
            typeof entry[0] === "string" &&
            typeof entry[1] === "string" &&
            entry[0] &&
            entry[1]
          ) {
            pairs.push([entry[0], entry[1]]);
          }
        }
      }
    } catch {
      // Malformed JSON — fall through to generic message.
    }
  }

  return (
    <div className="rounded-md border border-sky-300 bg-sky-50 dark:bg-sky-950/30 p-3 space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-sky-800 dark:text-sky-300">
        <Sparkles className="h-4 w-4" />
        <span className="text-sm font-medium">Cite refresh requested</span>
        <Badge variant="outline" className="text-[10px]">
          verdict stands
        </Badge>
      </div>
      {pairs.length > 0 ? (
        <div className="text-xs space-y-1 text-sky-900 dark:text-sky-200">
          <p className="leading-relaxed">
            The narrative cites a legacy document name that has been superseded.
            Update the citation on the next narrative pass — the assessed status
            does not change.
          </p>
          <ul className="list-disc pl-5 space-y-0.5">
            {pairs.map(([legacy, current], i) => (
              <li key={i} className="font-mono text-[11px]">
                <span className="line-through opacity-70">{legacy}</span>
                {" → "}
                <span>{current}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <p className="text-xs text-sky-900 dark:text-sky-200">
          A citation in this narrative was flagged for refresh, but the specific
          legacy/current pair could not be reconstructed. Re-run assess after
          updating the narrative to clear the flag.
        </p>
      )}
      <p className="text-[11px] text-muted-foreground">
        This row exports normally — Apply to workbook is not gated on cite
        refresh.
      </p>
    </div>
  );
}

type ValidationRejection = { reason: string; message: string };
type ValidationErrorBody = {
  ok: false;
  classified_as: NarrativeClass;
  rejections: ValidationRejection[];
  notes: string[];
};

function isValidationError(
  err: unknown,
): err is ApiError & { body: { detail: ValidationErrorBody } } {
  return (
    err instanceof ApiError &&
    err.status === 422 &&
    typeof err.body === "object" &&
    err.body !== null &&
    "detail" in err.body &&
    typeof (err.body as { detail: unknown }).detail === "object" &&
    (err.body as { detail: { rejections?: unknown } }).detail?.rejections !== undefined
  );
}

function AssessmentPanel({
  objectiveId,
  objectiveInScope = true,
  workbookId,
  existingNarrative,
  existingStatus,
  existingClass,
  existingNeedsReview,
  existingReviewReason,
  existingConfidence,
  existingRewriteRequested,
  existingRewriteRequestedRefs,
  implementations,
}: {
  objectiveId?: number;
  objectiveInScope?: boolean;
  workbookId?: number;
  existingNarrative: string;
  existingStatus?: ComplianceStatus;
  existingClass?: NarrativeClass;
  // v0.2 precision-over-recall: when the persisted row is an abstain, the
  // panel renders a yellow callout above the editor explaining *why* the
  // assessor punted (validator-exhausted, unverified-cites, dual-pass-
  // disagreement, …) and hard-gates the "Apply to workbook" button. A
  // manual save clears needs_review (the act of a human reviewer touching
  // the row is the resolution event).
  existingNeedsReview: boolean;
  existingReviewReason: string | null;
  existingConfidence: number | null;
  // v0.2 citation-hygiene: TRUSTED-verdict rows whose narrative cites a
  // superseded doc name. Renders a blue/info callout (CiteRefreshCallout)
  // but does NOT gate Apply — the row exports normally with a footer note.
  // Cleared on Save the same way needs_review is.
  existingRewriteRequested: boolean;
  existingRewriteRequestedRefs: string | null;
  // v0.2 multi-implementation: when non-empty the panel swaps the single
  // narrative editor for an N-row impl table — one row per scope (AWS
  // GovCloud / Azure Government / On-Premises / …). Pre-migration rows
  // and freshly-assessed CCIs that resolved single-impl have an empty
  // array and fall back to the legacy single-narrative form.
  implementations: AssessmentImplementation[];
}) {
  const upsert = useUpsertAssessment({
    onSuccess: (res) => {
      // Save chains apply-batch in the hook (see useUpsertAssessment); the
      // ``auto_applied`` annotation is the UI-only field the hook drops onto
      // the result. ``applied > 0`` means the working copy was written;
      // ``applied === 0`` typically means the row is still flagged
      // needs_review (server-side gate — Save alone doesn't clear that
      // unless the user also edited the row to satisfy the validator).
      if (res.auto_applied && res.auto_applied.applied > 0) {
        toast.success(
          `Assessment #${res.id} saved`,
          "Wrote to workbook working copy.",
        );
      } else if (res.auto_applied) {
        toast.success(
          `Assessment #${res.id} saved`,
          "Row not written to workbook (still flagged needs_review or already up to date).",
        );
      } else {
        // auto_applied === null → the apply step itself threw and the hook
        // already showed an error toast. Don't double-fire; just confirm
        // the DB save landed.
        toast.success(`Assessment #${res.id} saved`);
      }
    },
    onError: (err) => {
      if (!isValidationError(err)) toast.error("Save failed", humanize(err));
    },
  });
  const apply = useApplyToWorkbook({
    onSuccess: (r) =>
      toast.success(
        "Wrote to workbook",
        `${r.summary.cells_changed} cell(s) — ${r.summary.workbook} / ${r.summary.sheet}`,
      ),
    onError: (err) => toast.error("Apply failed", humanize(err)),
  });
  const propose = useAssessObjective({
    onSuccess: (data) => {
      // Sidecar auto-inserted a missing CCI row before assessing (catalog
      // knows the CCI; the eMASS Export variant omitted it). Surface a
      // toast so the assessor knows the workbook was modified beyond just
      // the assessment cells — they may want to confirm the inserted row's
      // formatting on the WORKING SHEET.
      if (data.workbook_row_inserted) {
        toast.info(
          "Added missing CCI row to workbook",
          `Excel row ${data.excel_row}`,
        );
      }
    },
  });
  const settings = useSettings();

  const [status, setStatus] = useState<ComplianceStatus>("Compliant");
  const [narrativeClass, setNarrativeClass] = useState<NarrativeClass>("compliance-affirming");
  const [tester, setTester] = useState("");
  const [narrativeQ, setNarrativeQ] = useState("");
  const [pendingForce, setPendingForce] = useState(false);
  // v0.2 multi-impl edits — Map<implementation.id, {status, narrative}>.
  // Hydrated from `implementations` whenever the prop changes (objective
  // switch, post-save refetch, kernel re-run). Pre-migration rows have
  // implementations=[], leaving this map empty and the editor in legacy
  // single-narrative mode.
  const isMultiImpl = implementations.length > 0;
  const [implEdits, setImplEdits] = useState<
    Map<number, { status: ComplianceStatus; narrative: string }>
  >(() => new Map());
  useEffect(() => {
    const next = new Map<number, { status: ComplianceStatus; narrative: string }>();
    for (const i of implementations) {
      // A null per-scope status means the control abstained and this scope is
      // awaiting reviewer adjudication. Seed the Select with a concrete default
      // ("Non-Compliant" — the conservative triage default, since every NC is
      // reviewed) so the dropdown is controlled and the reviewer explicitly
      // confirms or changes it before Save.
      next.set(i.id, {
        status: i.status ?? "Non-Compliant",
        narrative: i.narrative,
      });
    }
    setImplEdits(next);
  }, [implementations, objectiveId]);
  const updateImplEdit = (
    implId: number,
    patch: Partial<{ status: ComplianceStatus; narrative: string }>,
  ) => {
    setImplEdits((prev) => {
      const next = new Map(prev);
      const cur = next.get(implId) ?? { status: "Compliant", narrative: "" };
      next.set(implId, { ...cur, ...patch });
      return next;
    });
  };

  // Hydrate from settings (tester) and from any existing assessment
  useEffect(() => {
    if (!tester && settings.data?.default_tester) {
      setTester(settings.data.default_tester);
    }
  }, [settings.data?.default_tester, tester]);

  // Reset all four fields when switching objectives — never carry the previous
  // objective's status/class/row over to a fresh one (would silently write to
  // the wrong workbook row on Apply). Also clear any stale kernel proposal so
  // it can't be applied against a different CCI than it was generated for.
  useEffect(() => {
    setNarrativeQ(existingNarrative);
    propose.reset();
    upsert.reset();
  }, [existingNarrative, objectiveId, propose.reset, upsert.reset]);
  useEffect(() => {
    setStatus(existingStatus ?? "Compliant");
  }, [existingStatus, objectiveId]);
  useEffect(() => {
    setNarrativeClass(existingClass ?? "compliance-affirming");
  }, [existingClass, objectiveId]);

  // excel_row is no longer entered in the form — the backend resolves it
  // from BaselineObjective.source_row using (workbook_id, objective_id).
  // Legacy mode requires the column-Q narrative; multi-impl mode hides that
  // editor (column Q is derived server-side), so instead require at least one
  // per-scope implementation carrying a non-empty narrative.
  const canSave =
    !!objectiveId &&
    !!workbookId &&
    (isMultiImpl
      ? Array.from(implEdits.values()).some((e) => e.narrative.trim())
      : !!narrativeQ.trim());
  const savedId = upsert.data?.id;
  const validationError = isValidationError(upsert.error) ? upsert.error.body.detail : null;

  async function save(force = false) {
    if (!canSave) return;
    setPendingForce(force);
    try {
      await upsert.mutateAsync({
        body: {
          workbook_id: workbookId!,
          objective_id: objectiveId!,
          // excel_row omitted — backend derives from BaselineObjective.source_row
          status,
          tester,
          narrative_q: narrativeQ,
          narrative_class: narrativeClass,
          // v0.2 precision-over-recall: a human reviewer pressing Save IS
          // the resolution event. Clear the abstain flag (and the diagnostic
          // fields the assessor wrote) so the export gates re-open. If the
          // row was never an abstain, this is a no-op.
          needs_review: false,
          review_reason: null,
          confidence: null,
          // v0.2 citation-hygiene: ditto for the cite-refresh flag — the
          // human edit IS the refresh. Clear so the next exporter run
          // omits the "Cite refresh requested" footer. If the assessor
          // didn't actually touch the legacy cite, supersession will
          // re-flag it on the next assess run.
          rewrite_requested: false,
          rewrite_requested_refs: null,
          // v0.2 multi-impl: when the parent carries per-scope CRM rows,
          // ship each edited (status, narrative) pair. The server derives
          // the parent status (worst-of) + narrative_q ("{scope}: …" join)
          // from this set, overriding the parent fields sent above. Omitted
          // entirely on legacy single-narrative rows (empty map).
          ...(isMultiImpl
            ? {
                implementations: Array.from(implEdits, ([id, e]) => ({
                  id,
                  status: e.status,
                  narrative: e.narrative,
                })),
              }
            : {}),
        },
        force,
      });
    } catch {
      // toast handled
    }
  }

  async function applyToWorkbook() {
    if (!savedId) return;
    await apply.mutateAsync({ assessmentId: savedId });
  }

  async function proposeFromKernel() {
    if (!objectiveId || !workbookId) return;
    if (!objectiveInScope) {
      // Out-of-scope (catalog-only) CCI: assessing it yields the
      // empty-narrative Compliant glitch. The button is disabled for this,
      // but guard the handler too in case it's invoked another way.
      toast.error(
        "Out-of-scope CCI",
        "This objective isn't in the workbook scope; select an in-scope CCI to assess.",
      );
      return;
    }
    try {
      const decision = await propose.mutateAsync({ workbookId, objectiveId });
      // Don't auto-apply — surface the proposal as a reviewable preview the
      // user accepts field-by-field (or wholesale). Silent overwrite of the
      // form is the single biggest reason testers lost trust in v0.0.
      toast.success(
        decision.accepted ? "Kernel proposal ready" : "Kernel unresolved — review below",
        `source=${decision.source}${decision.rule ? ` rule=${decision.rule}` : ""}`,
      );
    } catch (e) {
      toast.error("Kernel failed", humanize(e));
    }
  }

  /** Cherry-pick fields from a kernel proposal into the form. */
  function applyProposal(fields: {
    status?: ComplianceStatus | null;
    narrativeClass?: NarrativeClass;
    narrative?: string | null;
  }) {
    if (fields.status) setStatus(fields.status);
    if (fields.narrativeClass) setNarrativeClass(fields.narrativeClass);
    if (fields.narrative !== undefined && fields.narrative !== null) {
      setNarrativeQ(fields.narrative);
    }
  }

  const proposal = propose.data;
  const proposeError =
    propose.isError && propose.error instanceof ApiError ? propose.error : null;
  const missingApiKey =
    proposeError?.status === 412 &&
    typeof proposeError.body === "object" &&
    proposeError.body !== null &&
    "detail" in proposeError.body &&
    typeof (proposeError.body as { detail: unknown }).detail === "object" &&
    (proposeError.body as { detail: { error?: string } }).detail?.error === "missing_api_key";
  // Backend ships a provider-aware hint string ("Set the OpenAI API key…" /
  // "Set the Anthropic API key…") in detail.hint — use it instead of
  // hardcoding "Anthropic" so the warning matches whichever provider the
  // user currently has selected in Settings → Defaults.
  const missingApiKeyHint =
    missingApiKey
      ? (proposeError!.body as { detail: { hint?: string } }).detail?.hint ??
        "API key not set. Add it in Settings."
      : null;

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>Assessment</CardTitle>
        <CardDescription>
          Edit the column-Q narrative, stage a result, then write to Excel
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {existingNeedsReview && (
          <ReviewCallout
            reason={existingReviewReason}
            confidence={existingConfidence}
            proposedStatus={existingStatus}
          />
        )}
        {/* v0.2 citation-hygiene: render alongside (not instead of) the review
            callout — a row can in principle carry both flags, though in
            practice supersession/NA-reconsideration only set
            rewrite_requested. Distinct color (sky vs amber) keeps the
            blocking vs informational distinction visually obvious. */}
        {existingRewriteRequested && (
          <CiteRefreshCallout refs={existingRewriteRequestedRefs} />
        )}
        <div className="grid grid-cols-2 gap-3">
          {/* v0.2 multi-impl: the parent status is derived server-side
              (worst-of across implementations), so hide the manual Status
              selector when per-scope CRM rows are present — each scope owns
              its own status below. Legacy single-narrative rows keep it. */}
          {!isMultiImpl && (
            <Field label="Status">
              <Select
                value={status}
                onValueChange={(v) => setStatus(v as ComplianceStatus)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {STATUSES.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
          )}
          <Field label="Narrative class">
            <Select
              value={narrativeClass}
              onValueChange={(v) => setNarrativeClass(v as NarrativeClass)}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {CLASSES.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          <Field label="Tester">
            <Input value={tester} onChange={(e) => setTester(e.target.value)} />
          </Field>
        </div>

        {/* Legacy single-narrative editor — canonical column Q. Hidden when
            per-scope CRM implementations exist; in that mode column Q is a
            derived "{scope}: {narrative}" join the server builds from the
            per-scope editors below. */}
        {!isMultiImpl && (
          <Field label="Narrative (column Q)">
            <div className="rounded-md border overflow-hidden">
              <Editor
                height="280px"
                language="markdown"
                value={narrativeQ}
                onChange={(v) => setNarrativeQ(v ?? "")}
                theme="light"
                options={{
                  fontSize: 13,
                  minimap: { enabled: false },
                  wordWrap: "on",
                  lineNumbers: "off",
                  scrollBeyondLastLine: false,
                  folding: false,
                  renderLineHighlight: "none",
                }}
              />
            </div>
          </Field>
        )}

        {/* v0.2 multi-impl per-scope CRM editor. One card per implementation
            (CRM scope_label — "AWS GovCloud", "Azure Government",
            "On-Premises", …). Each scope owns its own status + narrative; the
            server rolls these up into the parent (worst-of status, joined
            narrative_q) on save. Edits are staged in `implEdits` and shipped
            via the save() payload's `implementations` array. */}
        {isMultiImpl && (
          <div className="space-y-3">
            <div className="text-xs text-muted-foreground">
              Per-scope implementations — each scope is assessed independently;
              the parent status (worst-of) and column-Q narrative are derived
              from these on save.
            </div>
            {implementations.map((impl) => {
              const edit = implEdits.get(impl.id) ?? {
                status: impl.status ?? "Non-Compliant",
                narrative: impl.narrative,
              };
              return (
                <div
                  key={impl.id}
                  className="rounded-md border bg-muted/30 p-3 space-y-2"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium">{impl.scope_label}</span>
                    {impl.responsibility && (
                      <Badge variant="subtle" className="text-[10px]">
                        {impl.responsibility}
                      </Badge>
                    )}
                    <div className="ml-auto w-[180px]">
                      <Select
                        value={edit.status}
                        onValueChange={(v) =>
                          updateImplEdit(impl.id, { status: v as ComplianceStatus })
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {STATUSES.map((s) => (
                            <SelectItem key={s} value={s}>
                              {s}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <Textarea
                    value={edit.narrative}
                    onChange={(e) =>
                      updateImplEdit(impl.id, { narrative: e.target.value })
                    }
                    rows={6}
                    placeholder={`Narrative for ${impl.scope_label}…`}
                    className="text-xs font-mono"
                  />
                  {impl.evidence_refs && (
                    <div className="text-[11px] text-muted-foreground">
                      Evidence: {impl.evidence_refs}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        <div className="flex flex-wrap gap-2 pt-1">
          <Button
            variant="secondary"
            onClick={proposeFromKernel}
            disabled={
              !objectiveId ||
              !workbookId ||
              !objectiveInScope ||
              propose.isPending
            }
            title={
              !objectiveInScope
                ? "This CCI is out of the workbook scope — select an in-scope CCI to assess."
                : undefined
            }
            className="flex-1 min-w-[200px]"
          >
            <Sparkles className="h-4 w-4" />
            {propose.isPending ? "Running kernel…" : "Assess (kernel)"}
          </Button>
          <Button
            onClick={() => save(false)}
            disabled={!canSave || upsert.isPending}
            className="flex-1 min-w-[160px]"
          >
            <Save className="h-4 w-4" />
            {upsert.isPending && !pendingForce ? "Validating…" : "Save"}
          </Button>
          <Button
            onClick={applyToWorkbook}
            // v0.2 precision-over-recall: a row whose persisted state is still
            // an abstain cannot be written to the workbook even after the user
            // has typed in the form — they must first Save (which clears
            // needs_review) before Apply unlocks. Mirrors the bulk-export gate
            // in ccis_writer.py::_write_row.
            disabled={!savedId || apply.isPending || existingNeedsReview}
            variant="default"
            className="flex-1 min-w-[180px]"
            title={
              existingNeedsReview
                ? "Resolve review first — Save the edited row to clear the abstain."
                : undefined
            }
          >
            <FileSpreadsheet className="h-4 w-4" />
            {apply.isPending ? "Writing…" : "Apply to workbook"}
          </Button>
        </div>

        {/* Kernel proposal — reviewable preview, never auto-applied */}
        {proposal && (
          <ProposalPreview
            decision={proposal}
            current={{
              status,
              narrativeClass,
              narrative: narrativeQ,
            }}
            onApply={applyProposal}
            onDismiss={() => propose.reset()}
          />
        )}

        {/* Decision trace — kept separate from the preview so the trace stays
            available even after the proposal has been applied/dismissed. */}
        {proposal && <DecisionTrace decision={proposal} />}

        {missingApiKey && (
          <p className="text-xs text-amber-700 dark:text-amber-400">
            {missingApiKeyHint}
          </p>
        )}
        {propose.isError && !missingApiKey && (
          <p className="text-xs text-destructive">{(propose.error as Error).message}</p>
        )}

        {validationError && (
          <div className="rounded-md border border-amber-500/50 bg-amber-50 dark:bg-amber-950/30 p-3 space-y-2">
            <div className="flex items-center gap-2 text-amber-700 dark:text-amber-400">
              <AlertTriangle className="h-4 w-4" />
              <span className="text-sm font-medium">
                Validator (rule #11) rejected this write
              </span>
            </div>
            <p className="text-xs text-muted-foreground">
              Classified as <span className="font-mono">{validationError.classified_as}</span>
            </p>
            <ul className="text-xs space-y-1 list-disc pl-5">
              {validationError.rejections.map((r, i) => (
                <li key={i}>
                  <span className="font-mono text-amber-700 dark:text-amber-400">{r.reason}</span>
                  {": "}
                  {r.message}
                </li>
              ))}
            </ul>
            <Button
              size="sm"
              variant="outline"
              onClick={() => save(true)}
              disabled={upsert.isPending}
              className="w-full"
            >
              Override and save anyway
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

/**
 * Reviewable kernel proposal. Replaces the v0.0 behavior of silently
 * overwriting form state — testers couldn't tell what came from the LLM vs
 * what they'd typed. Per-field "Use" buttons let the user cherry-pick;
 * "Apply all" is the bulk-accept escape hatch.
 */
function ProposalPreview({
  decision,
  current,
  onApply,
  onDismiss,
}: {
  decision: AssessmentDecision;
  current: {
    status: ComplianceStatus;
    narrativeClass: NarrativeClass;
    narrative: string;
  };
  onApply: (fields: {
    status?: ComplianceStatus | null;
    narrativeClass?: NarrativeClass;
    narrative?: string | null;
  }) => void;
  onDismiss: () => void;
}) {
  const [showDiff, setShowDiff] = useState(false);

  // Presentation-only: when the kernel produced per-scope narratives across
  // two+ boundaries, prefer the labeled stitched block for BOTH the diff the
  // reviewer sees and the value applied to column Q on save. Single-boundary
  // controls have `narrative_stitched === null`, so this collapses to the
  // plain narrative — no behavior change. Classification still ran on
  // `decision.narrative` upstream ("visually and for when you save, not
  // logically").
  const proposedNarrative = decision.narrative_stitched ?? decision.narrative;

  const statusChanged = !!decision.status && decision.status !== current.status;
  const classChanged = decision.narrative_class !== current.narrativeClass;
  const narrativeChanged =
    !!proposedNarrative &&
    proposedNarrative.trim() !== current.narrative.trim();

  // excel_row is now derived from BaselineObjective.source_row — no longer
  // a user-editable field and no longer surfaced as a diff row.
  const anyChange = statusChanged || classChanged || narrativeChanged;

  return (
    <div className="rounded-md border-2 border-primary/30 bg-primary/5 p-3 space-y-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-sm font-medium">
          <Sparkles className="h-4 w-4 text-primary" />
          <span>Kernel proposal</span>
          <Badge variant={decision.accepted ? "success" : "warning"} className="text-[10px]">
            {decision.accepted ? "accepted" : "unresolved"}
          </Badge>
          <span className="text-xs text-muted-foreground font-mono">
            {decision.source}
            {decision.rule ? ` · ${decision.rule}` : ""}
          </span>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={onDismiss}
          className="h-7 text-xs"
        >
          <X className="h-3 w-3" />
          Dismiss
        </Button>
      </div>

      {!anyChange && (
        <p className="text-xs text-muted-foreground italic">
          Proposal matches the current form — nothing to apply.
        </p>
      )}

      {statusChanged && (
        <DiffRow
          label="Status"
          current={current.status}
          proposed={decision.status!}
          onUse={() => onApply({ status: decision.status })}
        />
      )}

      {classChanged && (
        <DiffRow
          label="Narrative class"
          current={current.narrativeClass}
          proposed={decision.narrative_class}
          onUse={() => onApply({ narrativeClass: decision.narrative_class })}
        />
      )}

      {narrativeChanged && (
        <div className="space-y-2">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-medium text-muted-foreground">
              Narrative (column Q)
            </span>
            <div className="flex items-center gap-1">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowDiff((v) => !v)}
                className="h-7 text-xs"
              >
                {showDiff ? "Hide diff" : "Show diff"}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => onApply({ narrative: proposedNarrative })}
                className="h-7 text-xs"
              >
                <ArrowRight className="h-3 w-3" />
                Use proposed
              </Button>
            </div>
          </div>
          {showDiff && (
            <div className="rounded-md border overflow-hidden">
              <DiffEditor
                height="240px"
                language="markdown"
                original={current.narrative}
                modified={proposedNarrative ?? ""}
                theme="light"
                options={{
                  fontSize: 12,
                  readOnly: true,
                  renderSideBySide: true,
                  minimap: { enabled: false },
                  wordWrap: "on",
                  lineNumbers: "off",
                  scrollBeyondLastLine: false,
                  folding: false,
                  renderLineHighlight: "none",
                }}
              />
            </div>
          )}
        </div>
      )}

      {anyChange && (
        <Button
          size="sm"
          onClick={() =>
            onApply({
              status: statusChanged ? decision.status : undefined,
              narrativeClass: classChanged ? decision.narrative_class : undefined,
              narrative: narrativeChanged ? proposedNarrative : undefined,
            })
          }
          className="w-full"
        >
          <Check className="h-4 w-4" />
          Apply all changes ({[statusChanged, classChanged, narrativeChanged].filter(Boolean).length})
        </Button>
      )}
    </div>
  );
}

function DiffRow({
  label,
  current,
  proposed,
  onUse,
}: {
  label: string;
  current: string;
  proposed: string;
  onUse: () => void;
}) {
  return (
    <div className="flex items-center justify-between gap-2 text-xs">
      <span className="text-muted-foreground w-32 shrink-0">{label}</span>
      <div className="flex items-center gap-2 flex-1 min-w-0">
        <span className="line-through text-muted-foreground truncate">{current}</span>
        <ArrowRight className="h-3 w-3 text-muted-foreground shrink-0" />
        <span className="text-primary font-medium truncate">{proposed}</span>
      </div>
      <Button variant="outline" size="sm" onClick={onUse} className="h-7 text-xs shrink-0">
        Use
      </Button>
    </div>
  );
}

// Human-readable labels for the supersession-hit chip. Mirrors the
// `SupersessionHit.source` Literal in backend/cybersecurity_assessor/engine/
// measurement.py — keep these in sync. Unknown sources fall through to the
// raw key so a backend addition that hasn't been mapped yet still renders
// (just with the snake_case identifier) instead of going blank.
const SUPERSESSION_SOURCE_LABELS: Record<string, string> = {
  llm: "LLM",
  col_u_carryover: "Col-U carryover",
  user_input: "User input",
  crm_overlay: "CRM overlay",
  sda_verified_mapping: "SDA verified mapping",
  evidence_chain: "Evidence chain",
};

function DecisionTrace({ decision }: { decision: AssessmentDecision }) {
  const [open, setOpen] = useState(true);
  return (
    <div className="rounded-md border bg-muted/40 p-3 text-xs space-y-2">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center justify-between w-full font-medium"
      >
        <span>Decision trace</span>
        <Badge variant={decision.accepted ? "success" : "warning"}>
          {decision.accepted ? "accepted" : "unresolved"}
        </Badge>
      </button>
      {open && (
        <div className="space-y-1.5">
          <Row label="Source" value={<span className="font-mono">{decision.source}</span>} />
          {decision.rule && (
            <Row label="Rule" value={<span className="font-mono">{decision.rule}</span>} />
          )}
          <Row label="Retries" value={decision.retries} />
          <Row label="Status" value={decision.status ?? "—"} />
          {/* Per-CCI cost + tokens. Surfaced here (not just in the Runs tab)
              so a tester can immediately see what their single-shot Assess
              click spent without context-switching. Rules 8a/8b/8c
              short-circuit before any LLM call so cost is $0.0000 and all
              token totals are 0 — that's a real signal, not missing data. */}
          {(decision.cost_usd !== undefined || decision.tokens) && (
            <Row
              label="Cost"
              value={
                <span className="font-mono">
                  ${(decision.cost_usd ?? 0).toFixed(4)}
                  {decision.tokens && (
                    <span className="ml-2 text-muted-foreground">
                      ({decision.tokens.input.toLocaleString()} in
                      {" / "}
                      {decision.tokens.output.toLocaleString()} out
                      {decision.tokens.cache_read > 0 && (
                        <>
                          {" / "}
                          {decision.tokens.cache_read.toLocaleString()} cached
                        </>
                      )}
                      )
                    </span>
                  )}
                </span>
              }
            />
          )}
          {decision.run_id !== undefined && (
            <Row
              label="Run"
              value={
                <Link
                  to="/runs"
                  className="font-mono text-primary hover:underline"
                  title="Open Runs telemetry"
                >
                  #{decision.run_id}
                </Link>
              }
            />
          )}
          {decision.supersession_hits.length > 0 && (
            <div>
              <div className="text-muted-foreground">
                Supersession hits ({decision.supersession_hits.length})
              </div>
              <ul className="mt-1 list-disc pl-5 space-y-0.5">
                {decision.supersession_hits.map((h, i) => (
                  <li key={i}>
                    <span className="font-mono">{h.stale}</span> →{" "}
                    <span className="font-mono">{h.current}</span>{" "}
                    <span className="text-muted-foreground">
                      ({SUPERSESSION_SOURCE_LABELS[h.source] ?? h.source})
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {decision.rejections.length > 0 && (
            <details>
              <summary className="cursor-pointer text-muted-foreground">
                Rejections ({decision.rejections.length})
              </summary>
              <ul className="mt-1 list-disc pl-5 space-y-0.5">
                {decision.rejections.map((r, i) => (
                  <li key={i}>
                    <span className="font-mono">{r.reason}</span>: {r.context}
                  </li>
                ))}
              </ul>
            </details>
          )}
          {decision.notes.length > 0 && (
            <details>
              <summary className="cursor-pointer text-muted-foreground">
                Notes ({decision.notes.length})
              </summary>
              <ul className="mt-1 list-disc pl-5 space-y-0.5">
                {decision.notes.map((n, i) => (
                  <li key={i}>{n}</li>
                ))}
              </ul>
            </details>
          )}
        </div>
      )}
    </div>
  );
}

function EvidencePanel({ objectiveId }: { objectiveId?: number }) {
  const ev = useEvidenceForObjective(objectiveId);
  const sorted = useMemo(
    () => [...(ev.data ?? [])].sort((a, b) => b.relevance - a.relevance),
    [ev.data],
  );
  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <FileSearch className="h-4 w-4" />
          Evidence
        </CardTitle>
        <CardDescription>{sorted.length} tagged artifacts</CardDescription>
      </CardHeader>
      <CardContent className="max-h-[60vh] overflow-auto">
        {!objectiveId && (
          <p className="text-sm text-muted-foreground">Select an objective.</p>
        )}
        {objectiveId && sorted.length === 0 && (
          <p className="text-sm text-muted-foreground">No evidence tagged.</p>
        )}
        <ul className="space-y-2">
          {sorted.map((e) => (
            <li key={e.evidence_id} className="rounded-md border p-2 text-xs">
              <div className="flex items-center justify-between gap-2">
                <span className="font-medium truncate">{e.title ?? e.filename}</span>
                <Badge variant="secondary" className="text-[10px] shrink-0">
                  rel {e.relevance.toFixed(2)}
                </Badge>
              </div>
              <div className="flex items-center gap-1 mt-1">
                <Badge variant="outline" className="text-[10px]">
                  {e.kind}
                </Badge>
                <span className="text-[10px] text-muted-foreground truncate">
                  {e.source}
                </span>
              </div>
              {e.rationale && (
                <p className="text-[11px] text-muted-foreground mt-1 line-clamp-3">
                  {e.rationale}
                </p>
              )}
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block space-y-1.5">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      {children}
    </label>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-muted-foreground">{label}</span>
      <span>{value}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Audit v1 — verdict → evidence trace (3PAO / JAB defensibility)
// ---------------------------------------------------------------------------

/**
 * Audit trail card mounted under the AssessmentPanel on ControlDetail.
 *
 * Collapsed by default; the underlying TanStack Query only fires when the
 * user opens the section (we pass null while closed, which trips the hook's
 * `enabled: assessmentId != null` guard). That keeps page-load fan-out flat
 * across pages with many CCIs while still giving every assessed CCI an
 * auditable read surface.
 *
 * Renders nothing when the CCI hasn't been assessed yet — surfacing an
 * empty card on every page would just be noise.
 */
function AuditTrailSection({ assessmentId }: { assessmentId: number | null }) {
  const [open, setOpen] = useState(false);
  // Pass null while closed so the hook's enabled gate keeps the network
  // request from firing until the auditor actually wants to inspect.
  const audit = useAssessmentAudit(open ? assessmentId : null);

  if (assessmentId == null) {
    return null;
  }

  return (
    <Card>
      <CardHeader
        className="cursor-pointer select-none"
        onClick={() => setOpen((v) => !v)}
      >
        <CardTitle className="flex items-center gap-2 text-base">
          <FileSearch className="h-4 w-4" />
          Audit trail
          <Badge variant="outline" className="text-[10px]">
            v1
          </Badge>
          <span className="ml-auto text-xs text-muted-foreground">
            {open ? "Hide" : "Show"}
          </span>
        </CardTitle>
        <CardDescription>
          Verdict → evidence trace for 3PAO / JAB defensibility. Replays the
          model, prompt, evidence chunks, and (when enabled) per-claim
          citations exactly as the assessor saw them.
        </CardDescription>
      </CardHeader>
      {open && (
        <CardContent className="space-y-4">
          {audit.isLoading && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Loader2 className="h-3 w-3 animate-spin" />
              Loading audit payload…
            </div>
          )}
          {audit.isError && (
            <p className="text-xs text-destructive">
              {(audit.error as Error).message}
            </p>
          )}
          {audit.data && <AuditTrailBody audit={audit.data} />}
        </CardContent>
      )}
    </Card>
  );
}

/**
 * Per-Control ODP value-overwrite audit history. Reads the append-only
 * `OdpAuditLog` rows for this control, grouped per `odp_id`. Every workbook
 * re-ingest that overwrites an existing `OdpAssignment.value` writes one
 * row here (see `ccis_workbook.apply()`), so this card is the
 * 3PAO-defensible answer to *"what did this ODP say when you decided
 * Compliant?"* after a workbook regeneration.
 *
 * UX:
 *   - Collapsed by default with a count badge ("3 ODPs, 7 changes").
 *   - Renders nothing on empty (no "(none)" placeholder — workbooks
 *     ingested clean against a fresh DB have no audit rows and we don't
 *     want a visual "missing data" implication for that case).
 *   - Each ODP group shows the placeholder token as a sub-heading, then
 *     a small table: When (UTC) | Who | Was → Is, most-recent first.
 */
function OdpHistoryCard({ controlId }: { controlId: number }) {
  const [open, setOpen] = useState(false);
  // Fetch eagerly so the count badge is accurate before expand — the
  // endpoint is a single indexed SELECT on (framework_version, control_id)
  // and returns [] cheaply when nothing has been overwritten.
  const history = useOdpHistory(controlId);
  const groups = history.data ?? [];

  // Plan: "Renders nothing when data.length === 0 — no empty card, no
  // '(none)' text." Also hide during initial load to avoid layout flicker.
  if (groups.length === 0) {
    return null;
  }

  const totalEvents = groups.reduce((n, g) => n + g.events.length, 0);

  return (
    <Card>
      <CardHeader
        className="cursor-pointer select-none"
        onClick={() => setOpen((v) => !v)}
      >
        <CardTitle className="flex items-center gap-2 text-base">
          <History className="h-4 w-4" />
          ODP value history
          <Badge variant="secondary" className="text-[10px]">
            {groups.length} ODP{groups.length === 1 ? "" : "s"}, {totalEvents}{" "}
            change{totalEvents === 1 ? "" : "s"}
          </Badge>
          <span className="ml-auto text-xs text-muted-foreground">
            {open ? "Hide" : "Show"}
          </span>
        </CardTitle>
        <CardDescription>
          Append-only trail of every ODP value overwrite recorded during
          re-ingest. Defensible answer to "what did this ODP say when the
          verdict was made?" after a workbook regeneration.
        </CardDescription>
      </CardHeader>
      {open && (
        <CardContent className="space-y-4">
          {groups.map((g) => (
            <OdpHistoryGroupBlock key={g.odp_id} group={g} />
          ))}
        </CardContent>
      )}
    </Card>
  );
}

/**
 * One ODP group: placeholder token as sub-heading + a small table of every
 * overwrite event for that token. Events arrive from the backend pre-sorted
 * most-recent-first (see fetch_odp_history in controls/odp_render.py).
 */
function OdpHistoryGroupBlock({ group }: { group: OdpHistoryGroup }) {
  return (
    <div className="rounded-md border bg-muted/30 p-3 space-y-2 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono font-medium">{group.odp_id}</span>
        <Badge variant="outline" className="text-[10px]">
          {group.events.length} change{group.events.length === 1 ? "" : "s"}
        </Badge>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left">
          <thead className="text-[10px] uppercase text-muted-foreground">
            <tr>
              <th className="py-1 pr-3 font-medium">When (UTC)</th>
              <th className="py-1 pr-3 font-medium">Who</th>
              <th className="py-1 pr-3 font-medium">Was → Is</th>
            </tr>
          </thead>
          <tbody>
            {group.events.map((e, i) => (
              <tr key={i} className="border-t border-border/50">
                <td className="py-1 pr-3 font-mono whitespace-nowrap">
                  {e.when}
                </td>
                <td className="py-1 pr-3 font-mono break-all">{e.who}</td>
                <td className="py-1 pr-3">
                  <span className="font-mono">
                    {e.prev_value || <em className="text-muted-foreground">∅</em>}
                  </span>
                  <span className="mx-1 text-muted-foreground">→</span>
                  <span className="font-mono">{e.new_value}</span>
                  {e.assigned_from && (
                    <span
                      className="ml-2 text-[10px] text-muted-foreground"
                      title="Source control the ODP value was assigned from"
                    >
                      via {e.assigned_from}
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/**
 * Audit payload body. Split from AuditTrailSection so the loading / error /
 * empty-state branches at the section level stay clean, and so hooks can be
 * declared unconditionally (the empty-trace early-return below comes AFTER
 * all useState calls per React rules).
 */
function AuditTrailBody({ audit }: { audit: AssessmentAudit }) {
  // Click-to-jump state: when an auditor clicks a citation row, the linked
  // evidence chunk auto-expands and the source quote is highlighted in
  // place. Keyed on the citation id rather than the chunk id so multiple
  // citations against the same chunk each highlight their own span.
  const [activeCitationId, setActiveCitationId] = useState<number | null>(null);

  // Build prompt lookup before any conditional returns — the auditor opens
  // a single assessment, this map is at most 1-2 entries.
  const promptBySha = useMemo(() => {
    const m = new Map<string, AssessmentAuditPromptSnapshot>();
    for (const p of audit.system_prompts) m.set(p.sha256, p);
    return m;
  }, [audit.system_prompts]);

  const evShownById = useMemo(() => {
    const m = new Map<number, AssessmentAuditEvidenceShown>();
    for (const e of audit.evidence_shown) m.set(e.id, e);
    return m;
  }, [audit.evidence_shown]);

  // Short-circuit verdicts (rule_8a / 8b / 8c, CRM inherited/provider,
  // hard abstain) legitimately produce no LLM call — therefore no trace
  // rows and no evidence_shown rows. Surface as info, not error: the
  // verdict is still fully reproducible from the deterministic inputs.
  if (audit.trace.length === 0 && audit.evidence_shown.length === 0) {
    return (
      <div className="rounded-md border border-amber-300/60 bg-amber-50 dark:border-amber-700 dark:bg-amber-950/30 p-3 text-xs text-amber-800 dark:text-amber-200 flex gap-2">
        <Info className="h-4 w-4 shrink-0 mt-0.5" />
        <div>
          <p className="font-medium">
            No LLM trace — deterministic verdict.
          </p>
          <p className="mt-1 text-amber-700 dark:text-amber-300">
            This Assessment short-circuited (e.g. rule 8a / 8b / 8c, CRM
            inherited or provider, hard abstain) and no model call was made.
            The verdict is fully reproducible from the inputs.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Trace rows — single-pass renders one, dual-pass renders two:
          pass_index 0 is the initial verdict (canonical narrative + citations
          live here per the persister contract), pass_index 1 is the challenger
          review at temp 0.0 that confirms or challenges pass 0. A CHALLENGE
          (status mismatch) abstains; a CONFIRM keeps pass 0 as-is. */}
      {audit.trace.map((t) => (
        <TraceBlock
          key={t.id}
          trace={t}
          prompt={promptBySha.get(t.system_prompt_sha) ?? null}
        />
      ))}

      <EvidenceShownList
        evidenceShown={audit.evidence_shown}
        activeCitationId={activeCitationId}
        citationsByShownId={groupCitationsByShownId(audit.citations)}
      />

      <CitationsList
        citations={audit.citations}
        evShownById={evShownById}
        activeCitationId={activeCitationId}
        setActiveCitationId={setActiveCitationId}
      />
    </div>
  );
}

/**
 * Index citations by the AssessmentEvidenceShown.id they reference so the
 * chunk list can render its own citation badges + highlight the active
 * source span without re-scanning the full citations array per chunk.
 */
function groupCitationsByShownId(
  citations: AssessmentAuditCitation[],
): Map<number, AssessmentAuditCitation[]> {
  const m = new Map<number, AssessmentAuditCitation[]>();
  for (const c of citations) {
    const arr = m.get(c.evidence_shown_id);
    if (arr) arr.push(c);
    else m.set(c.evidence_shown_id, [c]);
  }
  return m;
}

/**
 * One LLM call's replay header + prompt body. The replay header carries the
 * model identity tuple an auditor needs to reproduce the call (model alias
 * + dated snapshot resolved by the API + temperature + max_tokens), plus
 * the Anthropic request_id which is the durable handle for cross-checking
 * against Anthropic-side logs.
 *
 * Prompt body is a two-button tab — system prompt (deduped per sha) and
 * the literal user_message that was sent. Both rendered in monospace with
 * line wrap so multi-KB blobs stay legible without horizontal scroll.
 */
function TraceBlock({
  trace,
  prompt,
}: {
  trace: AssessmentAuditTrace;
  prompt: AssessmentAuditPromptSnapshot | null;
}) {
  const [tab, setTab] = useState<"system" | "user" | "response">("user");
  return (
    <div className="rounded-md border bg-muted/30 p-3 space-y-2 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        <Badge
          variant="secondary"
          className="text-[10px]"
          title={
            trace.pass_index === 0
              ? "Initial verdict at temp 0.0 — canonical narrative and citations are sourced from this pass."
              : "Challenger review at temp 0.0 — sees pass 0's verdict + narrative + citations and is asked to CONFIRM or CHALLENGE."
          }
        >
          {trace.pass_index === 0
            ? "Pass 0 (initial verdict)"
            : "Pass 1 (challenger review)"}
        </Badge>
        <span className="font-mono">{trace.model}</span>
        {trace.anthropic_model_version &&
          trace.anthropic_model_version !== trace.model && (
            <span
              className="font-mono text-muted-foreground"
              title="Served model version returned by the API (may differ from requested alias)"
            >
              → {trace.anthropic_model_version}
            </span>
          )}
        {trace.temperature != null && (
          <Badge variant="outline" className="text-[10px]">
            temp {trace.temperature}
          </Badge>
        )}
        {trace.max_tokens != null && (
          <Badge variant="outline" className="text-[10px]">
            max {trace.max_tokens}
          </Badge>
        )}
        <span className="ml-auto text-muted-foreground">
          {formatAuditTimestamp(trace.created_at)}
        </span>
      </div>
      <div className="flex flex-wrap gap-2 text-[11px] text-muted-foreground">
        {trace.request_id && (
          <span title="Anthropic request_id — durable handle for cross-checking against vendor logs">
            request_id: <span className="font-mono">{trace.request_id}</span>
          </span>
        )}
        {(trace.input_tokens != null || trace.output_tokens != null) && (
          <span>
            tokens:{" "}
            <span className="font-mono">
              {trace.input_tokens ?? "?"}↓ / {trace.output_tokens ?? "?"}↑
            </span>
            {trace.cache_read_tokens != null && trace.cache_read_tokens > 0 && (
              <span className="font-mono">
                {" "}
                (cache: {trace.cache_read_tokens})
              </span>
            )}
          </span>
        )}
      </div>
      <div className="flex gap-1 border-b">
        <PromptTab active={tab === "system"} onClick={() => setTab("system")}>
          System prompt
          {prompt && (
            <span className="ml-1 font-mono text-[10px] text-muted-foreground">
              {prompt.sha256.slice(0, 8)}
            </span>
          )}
        </PromptTab>
        <PromptTab active={tab === "user"} onClick={() => setTab("user")}>
          User message
        </PromptTab>
        {trace.raw_response_json && (
          <PromptTab
            active={tab === "response"}
            onClick={() => setTab("response")}
          >
            Raw response
          </PromptTab>
        )}
      </div>
      <pre className="max-h-[400px] overflow-auto whitespace-pre-wrap break-words font-mono text-[11px] leading-relaxed rounded-sm bg-background/60 p-2 border">
        {tab === "system" &&
          (prompt
            ? prompt.text
            : `(system prompt sha=${trace.system_prompt_sha} — snapshot row missing from payload)`)}
        {tab === "user" && trace.user_message}
        {tab === "response" && (trace.raw_response_json ?? "")}
      </pre>
    </div>
  );
}

function PromptTab({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={
        "px-2 py-1 text-[11px] -mb-px border-b-2 " +
        (active
          ? "border-primary text-foreground font-medium"
          : "border-transparent text-muted-foreground hover:text-foreground")
      }
    >
      {children}
    </button>
  );
}

/**
 * The list of evidence chunks the model literally saw, ordered by their
 * prompt position (order_index). Each chunk is collapsed by default — the
 * head/tail truncation lands them in the 1-3 KB range each which would
 * dominate the page if expanded en masse.
 *
 * When a citation is "active" (the auditor clicked it in the Citations
 * section below) the matching chunk auto-expands and highlights the
 * source quote span in place.
 */
function EvidenceShownList({
  evidenceShown,
  activeCitationId,
  citationsByShownId,
}: {
  evidenceShown: AssessmentAuditEvidenceShown[];
  activeCitationId: number | null;
  citationsByShownId: Map<number, AssessmentAuditCitation[]>;
}) {
  if (evidenceShown.length === 0) {
    // Trace existed but no chunks — rare but possible when build_tagged_
    // evidence returned None (no tags) and the LLM was called against
    // context-only material. Skip the section header entirely.
    return null;
  }
  const sorted = [...evidenceShown].sort((a, b) => a.order_index - b.order_index);
  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
        Evidence shown ({sorted.length})
      </h4>
      <ul className="space-y-1.5">
        {sorted.map((e) => {
          const activeCitations = citationsByShownId.get(e.id) ?? [];
          const activeCitation =
            activeCitationId != null
              ? activeCitations.find((c) => c.id === activeCitationId) ?? null
              : null;
          return (
            <EvidenceShownItem
              key={e.id}
              evidenceShown={e}
              citationCount={activeCitations.length}
              activeCitation={activeCitation}
            />
          );
        })}
      </ul>
    </div>
  );
}

function EvidenceShownItem({
  evidenceShown,
  citationCount,
  activeCitation,
}: {
  evidenceShown: AssessmentAuditEvidenceShown;
  citationCount: number;
  activeCitation: AssessmentAuditCitation | null;
}) {
  const [open, setOpen] = useState(false);
  // Auto-expand when a citation against this chunk goes active — saves the
  // auditor a second click after clicking the citation row.
  const expanded = open || activeCitation != null;
  return (
    <li className="rounded-md border p-2 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="outline" className="text-[10px]">
          #{evidenceShown.order_index}
        </Badge>
        <span
          className="font-medium truncate max-w-[28rem]"
          title={
            evidenceShown.evidence_path ??
            `evidence_id=${evidenceShown.evidence_id}`
          }
        >
          {evidenceShown.evidence_title ??
            evidencePathBasename(evidenceShown.evidence_path) ??
            `evidence_id=${evidenceShown.evidence_id}`}
        </span>
        {evidenceShown.relevance != null && (
          <Badge variant="secondary" className="text-[10px]">
            rel {evidenceShown.relevance.toFixed(2)}
          </Badge>
        )}
        {evidenceShown.tag_source && (
          <span className="text-[10px] text-muted-foreground">
            ({evidenceShown.tag_source})
          </span>
        )}
        <span
          className="font-mono text-[10px] text-muted-foreground"
          title={`Chunk sha256 (sha of the truncated snippet, NOT the source file): ${evidenceShown.chunk_sha}`}
        >
          sha {evidenceShown.chunk_sha.slice(0, 8)}
        </span>
        {citationCount > 0 && (
          <Badge variant="subtle" className="text-[10px]">
            {citationCount} citation{citationCount === 1 ? "" : "s"}
          </Badge>
        )}
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="ml-auto text-[11px] text-muted-foreground hover:text-foreground underline-offset-2 hover:underline"
        >
          {expanded ? "Hide" : "Show"} chunk
        </button>
      </div>
      {expanded && (
        <pre className="mt-2 max-h-[300px] overflow-auto whitespace-pre-wrap break-words font-mono text-[11px] leading-relaxed rounded-sm bg-muted/40 p-2">
          {activeCitation
            ? renderHighlightedChunk(evidenceShown.chunk_text, activeCitation)
            : evidenceShown.chunk_text}
        </pre>
      )}
    </li>
  );
}

/**
 * Render the chunk text with the active citation's source_quote span
 * highlighted. Falls back to plain text when the offsets are null (the
 * LLM emitted a quote we couldn't locate in the chunk) — still useful
 * because the chunk content is visible in full so the auditor can scan
 * for the quote manually.
 */
function renderHighlightedChunk(
  chunkText: string,
  citation: AssessmentAuditCitation,
): React.ReactNode {
  const { source_start_char, source_end_char } = citation;
  if (
    source_start_char == null ||
    source_end_char == null ||
    source_start_char < 0 ||
    source_end_char <= source_start_char ||
    source_end_char > chunkText.length
  ) {
    return chunkText;
  }
  return (
    <>
      {chunkText.slice(0, source_start_char)}
      <mark className="bg-amber-200 dark:bg-amber-700/60 text-foreground rounded-sm px-0.5">
        {chunkText.slice(source_start_char, source_end_char)}
      </mark>
      {chunkText.slice(source_end_char)}
    </>
  );
}

/**
 * Per-claim citation list. Only populated when audit_citations_enabled was
 * on at decision time. Each row reads `claim → quote [field]` with a
 * click-to-jump that highlights the source span up in the EvidenceShown
 * list. extraction_method == "llm_self_cite" today; future regex / human
 * sources would render the same way.
 */
function CitationsList({
  citations,
  evShownById,
  activeCitationId,
  setActiveCitationId,
}: {
  citations: AssessmentAuditCitation[];
  evShownById: Map<number, AssessmentAuditEvidenceShown>;
  activeCitationId: number | null;
  setActiveCitationId: (id: number | null) => void;
}) {
  if (citations.length === 0) {
    return (
      <div className="text-[11px] text-muted-foreground italic">
        No citations recorded — enable{" "}
        <span className="font-mono">audit_citations_enabled</span> in Settings
        and re-assess to capture per-claim source quotes.
      </div>
    );
  }
  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
        Citations ({citations.length})
      </h4>
      <ul className="space-y-1.5">
        {citations.map((c) => {
          const chunk = evShownById.get(c.evidence_shown_id);
          const active = c.id === activeCitationId;
          return (
            <li
              key={c.id}
              className={
                "rounded-md border p-2 text-xs cursor-pointer transition-colors " +
                (active
                  ? "border-primary bg-primary/5"
                  : "hover:bg-muted/40")
              }
              onClick={() => setActiveCitationId(active ? null : c.id)}
            >
              <div className="flex flex-wrap items-center gap-2 mb-1">
                <Badge variant="outline" className="text-[10px]">
                  {c.narrative_field}
                </Badge>
                {chunk && (
                  <span className="text-[10px] text-muted-foreground">
                    → chunk #{chunk.order_index} (evidence_id={chunk.evidence_id})
                  </span>
                )}
                <span className="ml-auto text-[10px] text-muted-foreground italic">
                  {c.extraction_method}
                </span>
              </div>
              <p className="text-[11px]">
                <span className="font-medium">Claim:</span> {c.claim_text}
              </p>
              <p className="mt-1 text-[11px] text-muted-foreground">
                <span className="font-medium">Quote:</span>{" "}
                <span className="italic">&ldquo;{c.source_quote}&rdquo;</span>
              </p>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/**
 * Cosmetic helper — the backend stamps ``created_at`` as ISO 8601. Render
 * as the user's locale string so the audit trail reads naturally without
 * surfacing the timezone-suffix noise auditors don't need.
 */
function formatAuditTimestamp(iso: string): string {
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  } catch {
    return iso;
  }
}

/**
 * Last path segment of an Evidence URI, used as a display fallback when
 * Evidence.title is null. Handles file://, zip://!/inner, sharepoint://
 * URIs, and the legacy bare-path rows. Returns null when input is null/
 * empty so the caller can fall back to evidence_id.
 */
function evidencePathBasename(path: string | null): string | null {
  if (!path) return null;
  // zip:///abs/archive.zip!/inner/foo.pdf → inner/foo.pdf, then basename of that
  const afterBang = path.includes("!/") ? path.split("!/").pop()! : path;
  const segs = afterBang.split(/[\\/]/).filter(Boolean);
  return segs.length > 0 ? segs[segs.length - 1] : null;
}
