import { useMemo } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  CircleSlash,
  DollarSign,
  History,
  Loader2,
  RotateCcw,
} from "lucide-react";

import { StatCard } from "@/components/StatCard";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { Run, Workbook } from "@/lib/api";
import { useRuns, useWorkbooks } from "@/lib/queries";

/**
 * Per-run telemetry. The accepted/retries/rejects columns back the patent
 * claim — the cost columns are operational. Supersession (a deterministic
 * accuracy mechanism, not runtime telemetry) now lives in Metrics →
 * Accuracy → Mechanisms alongside CRM overlay and validator rejections.
 */
export function Runs() {
  const runs = useRuns(100);
  const workbooks = useWorkbooks();

  const wbById = useMemo(() => {
    const m = new Map<number, Workbook>();
    for (const w of workbooks.data ?? []) m.set(w.id, w);
    return m;
  }, [workbooks.data]);

  const rollup = useMemo(() => summarize(runs.data ?? []), [runs.data]);

  return (
    <div className="p-8 space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
          <History className="h-6 w-6 text-primary" />
          Runs
        </h1>
        <p className="text-sm text-muted-foreground">
          Per-assessment telemetry — cost is operational, retry / rejection
          counts are the accuracy signals that back the patent claim. See
          Metrics for cross-run rollups and the deterministic accuracy
          mechanisms (supersession, CRM overlay).
        </p>
      </header>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <StatCard
          label="Runs"
          value={rollup.runs.toLocaleString()}
          icon={History}
          sublabel={
            rollup.stoppedRuns > 0
              ? `${rollup.stoppedRuns.toLocaleString()} stopped`
              : undefined
          }
        />
        <StatCard
          label="Completed cost"
          value={formatCostTotal(rollup.costUsd)}
          icon={DollarSign}
        />
        <StatCard
          label="Stopped cost"
          value={formatCostTotal(rollup.costUsdStopped)}
          icon={CircleSlash}
          tone={rollup.costUsdStopped > 0 ? "warning" : undefined}
          sublabel={
            rollup.stoppedRuns > 0
              ? rollup.ccisAcceptedStopped > 0
                ? `${rollup.ccisAcceptedStopped.toLocaleString()} CCIs salvaged · ${formatCostTotal(rollup.costUsdStopped / rollup.stoppedRuns)} avg`
                : `no CCIs accepted · ${formatCostTotal(rollup.costUsdStopped / rollup.stoppedRuns)} avg`
              : undefined
          }
        />
        <StatCard
          label="CCIs accepted"
          value={rollup.ccisAccepted.toLocaleString()}
          icon={CheckCircle2}
          tone="success"
          sublabel={
            rollup.ccisAcceptedStopped > 0
              ? `${rollup.ccisAcceptedStopped.toLocaleString()} from stopped runs`
              : undefined
          }
        />
        <StatCard
          label="Validator rejects"
          value={rollup.rejections.toLocaleString()}
          icon={AlertTriangle}
          tone={rollup.rejections > 0 ? "warning" : undefined}
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent runs</CardTitle>
          <CardDescription>
            Newest first. Workbook column links runs back to the file under
            assessment; a missing workbook means the run was a standalone
            assess-objective call.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Command</TableHead>
                <TableHead>Workbook</TableHead>
                <TableHead>Started</TableHead>
                <TableHead className="text-right">LLM calls</TableHead>
                <TableHead className="text-right">Cost</TableHead>
                <TableHead className="text-right">Accepted</TableHead>
                <TableHead className="text-right">Retries</TableHead>
                <TableHead className="text-right">Rejects</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {runs.isLoading && (
                <TableRow>
                  <TableCell
                    colSpan={8}
                    className="text-center text-sm text-muted-foreground py-8"
                  >
                    Loading…
                  </TableCell>
                </TableRow>
              )}
              {runs.error && !runs.isLoading && (
                <TableRow>
                  <TableCell
                    colSpan={8}
                    className="text-center text-sm text-destructive py-8"
                  >
                    Couldn't reach the sidecar — is the backend running?
                  </TableCell>
                </TableRow>
              )}
              {!runs.isLoading &&
                !runs.error &&
                (runs.data?.length ?? 0) === 0 && (
                  <TableRow>
                    <TableCell
                      colSpan={8}
                      className="text-center text-sm text-muted-foreground py-8"
                    >
                      No runs yet — assess a control from the Controls grid to
                      generate the first telemetry row.
                    </TableCell>
                  </TableRow>
                )}
              {runs.data?.map((r) => {
                const wb = r.workbook_id ? wbById.get(r.workbook_id) : undefined;
                const live = r.status === "in_progress" && !isLikelyStopped(r);
                return (
                  <TableRow key={r.id}>
                    <TableCell className="font-mono text-xs">
                      <span className="inline-flex items-center gap-2">
                        {r.command}
                        {live ? (
                          <Badge
                            variant="secondary"
                            className="gap-1 text-[10px] uppercase tracking-wide"
                          >
                            <Loader2 className="h-3 w-3 animate-spin" />
                            Running
                          </Badge>
                        ) : null}
                      </span>
                    </TableCell>
                    <TableCell className="text-sm">
                      {wb ? (
                        <span title={wb.path}>{wb.filename}</span>
                      ) : r.workbook_id ? (
                        <span className="text-muted-foreground">
                          #{r.workbook_id}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {r.started_at
                        ? new Date(r.started_at).toLocaleString()
                        : "—"}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {r.llm_calls}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {formatCost(r.cost_usd)}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {r.ccis_accepted > 0 ? (
                        <Badge variant="success" className="tabular-nums">
                          {r.ccis_accepted}
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground">0</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {r.retry_count > 0 ? (
                        <span className="inline-flex items-center gap-1 text-amber-600 dark:text-amber-400">
                          <RotateCcw className="h-3 w-3" />
                          {r.retry_count}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">0</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {r.validator_rejections > 0 ? (
                        <Badge variant="warning" className="tabular-nums">
                          {r.validator_rejections}
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground">0</span>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

// A run that hasn't reported finished_at AND hasn't started_at in the last
// 30 minutes is presumed dead (sidecar killed mid-run). Live in-progress runs
// also have status="in_progress" but show recent activity. The 30-min cutoff
// is a heuristic — a real "is sidecar still owning this run" signal would
// require a heartbeat column on AssessmentRun, deferred.
const STOPPED_THRESHOLD_MS = 30 * 60 * 1000;

function isLikelyStopped(r: Run): boolean {
  if (r.status !== "in_progress") return false;
  if (!r.started_at) return true;
  const startedMs = new Date(r.started_at).getTime();
  if (Number.isNaN(startedMs)) return true;
  return Date.now() - startedMs > STOPPED_THRESHOLD_MS;
}

function summarize(rows: Run[]) {
  // Live in-progress runs are excluded from the "stopped" bucket — token
  // counts on those rows are accumulating live via RunRecorder's per-CCI
  // flush, so lumping them in would double-count cost as both pending and
  // wasted. Stopped runs (sidecar killed) still accumulate real cost but
  // never finalize, and we surface them separately so the user sees the waste.
  return rows.reduce(
    (acc, r) => {
      const stopped = isLikelyStopped(r);
      const complete = r.status === "complete";
      return {
        runs: acc.runs + 1,
        stoppedRuns: acc.stoppedRuns + (stopped ? 1 : 0),
        // Only count cost from completed runs in the headline total; live
        // in-flight runs are still moving, so their cost belongs in the
        // (implicit) "pending" pool — not the user-facing total yet.
        costUsd: acc.costUsd + (complete ? r.cost_usd : 0),
        costUsdStopped: acc.costUsdStopped + (stopped ? r.cost_usd : 0),
        ccisAccepted: acc.ccisAccepted + r.ccis_accepted,
        // Track salvaged work from stopped runs separately so the Stopped-cost
        // tile can report "money spent + CCIs we actually got back" instead of
        // just a sunk-cost number.
        ccisAcceptedStopped:
          acc.ccisAcceptedStopped + (stopped ? r.ccis_accepted : 0),
        rejections: acc.rejections + r.validator_rejections,
      };
    },
    {
      runs: 0,
      stoppedRuns: 0,
      costUsd: 0,
      costUsdStopped: 0,
      ccisAccepted: 0,
      ccisAcceptedStopped: 0,
      rejections: 0,
    },
  );
}

function formatCost(usd: number): string {
  if (usd === 0) return "—";
  if (usd < 0.01) return "<$0.01";
  return `$${usd.toFixed(2)}`;
}

// Totals tile uses full precision — "—" / "<$0.01" hide real spend at the
// aggregate level. Show $0.00 when there's been no spend yet.
function formatCostTotal(usd: number): string {
  if (usd >= 1000) return `$${usd.toLocaleString(undefined, { maximumFractionDigits: 2, minimumFractionDigits: 2 })}`;
  return `$${usd.toFixed(2)}`;
}

