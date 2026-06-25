/**
 * Cross-route owner for the in-flight ``/assess-batch`` run.
 *
 * Before this lived here, ``useAssessBatch`` / ``useAssessBatchProgress``
 * and the inline progress strip JSX were declared inside ``Controls.tsx``.
 * That meant clicking any other sidebar item mid-batch unmounted the
 * Controls route, which tore down the mutation observer, the 750 ms
 * polling query, and the progress UI in one go — the user saw the bar
 * vanish and (worse) the ``onSuccess`` auto-apply-to-workbook chain that
 * normally writes column N never fired because its caller was gone.
 *
 * The backend batch kept running regardless (it's a synchronous POST
 * with no abort signal threaded through), but client-side feedback and
 * the auto-apply / review-modal trigger were lost. Hoisting both hooks
 * here, above ``<Routes>``, keeps:
 *
 *   - the determinate progress strip visible on every route while a
 *     batch is in flight (rendered as a sticky banner at the top of
 *     the main scroll container)
 *   - the auto-apply chain in ``useAssessBatch.onSuccess`` running to
 *     completion irrespective of which route is mounted
 *   - the post-batch toast (cost, accepted/unresolved counts, family)
 *     firing globally
 *
 * Routes that need to react to a completed batch (today: Controls, for
 * the post-batch triage modal) read ``lastResult`` via
 * ``useAssessBatchContext()`` and call ``acknowledgeResult()`` after
 * consuming. If the user is on another route when the batch finishes,
 * the result sits in context until they navigate back to a consumer
 * — so the review modal still pops at next visit instead of being
 * silently dropped.
 */

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { Activity } from "lucide-react";

import { toast } from "@/components/ui/toaster";
import { humanize } from "@/lib/errors";
import {
  useAssessBatch,
  useAssessBatchProgress,
} from "@/lib/queries";
import type {
  AssessBatchProgress,
  AssessBatchRequest,
  AssessBatchResult,
} from "@/lib/api";

/**
 * The provider preserves both the result and the request that produced
 * it. Consumers (today: Controls) need ``vars.family`` to build the
 * post-batch modal copy with the same family scope the user just ran.
 */
export interface AssessBatchOutcome {
  result: AssessBatchResult;
  vars: AssessBatchRequest;
}

interface AssessBatchContextValue {
  /** Kick off a batch. Thin wrapper over the underlying mutation's
   *  ``mutate`` — the provider's own onSuccess handles toasts and the
   *  ``lastResult`` stash, so callers don't pass onSuccess here. */
  runBatch: (req: AssessBatchRequest) => void;
  /** True while the mutation is in flight. Drives the progress strip
   *  visibility and the Controls page's "Assessing…" button state. */
  isPending: boolean;
  /** ID of the workbook whose batch is currently running, or null when
   *  idle. Lets routes that aren't the originator (e.g. Workbooks) know
   *  not to mutate the same workbook out from under the batch. */
  activeWorkbookId: number | null;
  /** Latest poll snapshot. Either ``{active:false}`` or the populated
   *  branch — see api.ts AssessBatchProgress. */
  progressSnapshot: AssessBatchProgress | undefined;
  /** Most recent completed batch + its request, or null if no batch has
   *  finished this session (or the last one was already acknowledged).
   *  Routes useEffect on this to pop modals / surface follow-ups. */
  lastResult: AssessBatchOutcome | null;
  /** Mark the most recent result as consumed so the route's useEffect
   *  doesn't re-fire on every render. Idempotent — safe to call when
   *  ``lastResult`` is already null. */
  acknowledgeResult: () => void;
}

const AssessBatchContext = createContext<AssessBatchContextValue | null>(null);

export function AssessBatchProvider({ children }: { children: ReactNode }) {
  // Stashed completed-batch state. Survives route unmounts so the post-
  // batch review modal pops the next time Controls mounts, even if the
  // user navigated away while the batch was running.
  const [lastResult, setLastResult] = useState<AssessBatchOutcome | null>(null);
  // Workbook ID of the in-flight batch. Tracked separately from the
  // mutation's vars because the mutation tears down its variables once
  // it settles — the polling hook still needs a workbook id to poll
  // until ``isPending`` flips false, but that's already the same value
  // the call site passed in, so we capture it on ``runBatch`` and clear
  // on settle.
  const [activeWorkbookId, setActiveWorkbookId] = useState<number | null>(null);

  const assessBatch = useAssessBatch({
    onSuccess: (result, vars) => {
      // Global toast — fires from any route. Mirrors the copy the
      // Controls page used to build inline, but sources ``family`` from
      // ``vars`` (the request) rather than the page's filter state so
      // it reads correctly even when the user navigated away mid-batch.
      const cost = result.cost_usd.toFixed(2);
      const family = vars.family ? ` (family ${vars.family})` : "";
      // "$0.00" alone reads like a broken cost tracker. When every
      // in-scope CCI hit a deterministic short-circuit (rule_8a/b/c,
      // CRM inherited), no LLM call is ever made — tokens are zero
      // and cost is legitimately $0. Friendlier copy for that case.
      const allDeterministic =
        result.cost_usd === 0 &&
        result.tokens.input === 0 &&
        result.tokens.output === 0;
      const costSegment = allDeterministic
        ? "no LLM (all deterministic)"
        : `$${cost}`;
      const skippedTail =
        result.skipped.length > 0
          ? ` · ${result.skipped.length} skipped (not in workbook)`
          : "";

      const auto = result.auto_applied;
      const nothingAssessed =
        result.accepted === 0 &&
        result.unresolved === 0 &&
        result.persisted === 0;

      if (nothingAssessed && auto && auto.applied === 0) {
        toast.success(
          `Nothing to do${family}`,
          "All in-scope CCIs already assessed and written to Excel. Use 'Re-assess all' to re-run.",
        );
      } else if (nothingAssessed && auto && auto.applied > 0) {
        toast.success(
          `Applied existing assessments${family}`,
          `0 newly assessed · ${auto.applied} written to Excel (from prior runs) · ${costSegment}`,
        );
      } else {
        const appliedTail =
          auto && auto.applied > 0
            ? ` · ${auto.applied} auto-applied to Excel`
            : "";
        toast.success(
          `Batch assessed${family}`,
          `${result.accepted} accepted / ${result.unresolved} unresolved · ${result.persisted} written${appliedTail} · ${costSegment}${skippedTail}`,
        );
      }

      // Stash for route-level consumers. Controls reads this in a
      // useEffect to populate + open its post-batch triage modal.
      setLastResult({ result, vars });
      setActiveWorkbookId(null);
    },
    onError: (err) => {
      toast.error("Batch assessment failed", humanize(err));
      setActiveWorkbookId(null);
    },
  });

  const assessBatchProgress = useAssessBatchProgress(
    activeWorkbookId,
    assessBatch.isPending,
  );

  const runBatch = useCallback(
    (req: AssessBatchRequest) => {
      setActiveWorkbookId(req.workbook_id);
      assessBatch.mutate(req);
    },
    [assessBatch],
  );

  const acknowledgeResult = useCallback(() => {
    setLastResult(null);
  }, []);

  const value = useMemo<AssessBatchContextValue>(
    () => ({
      runBatch,
      isPending: assessBatch.isPending,
      activeWorkbookId,
      progressSnapshot: assessBatchProgress.data,
      lastResult,
      acknowledgeResult,
    }),
    [
      runBatch,
      assessBatch.isPending,
      activeWorkbookId,
      assessBatchProgress.data,
      lastResult,
      acknowledgeResult,
    ],
  );

  return (
    <AssessBatchContext.Provider value={value}>
      {children}
    </AssessBatchContext.Provider>
  );
}

/**
 * Read the cross-route assess-batch state.
 *
 * Throws if called outside ``<AssessBatchProvider>`` — provider is
 * mounted at App level above ``<Routes>``, so any route can call
 * this safely.
 */
export function useAssessBatchContext(): AssessBatchContextValue {
  const ctx = useContext(AssessBatchContext);
  if (!ctx) {
    throw new Error(
      "useAssessBatchContext must be used inside <AssessBatchProvider>",
    );
  }
  return ctx;
}

/**
 * Format a seconds count as a compact "1m 20s" / "45s" ETA label.
 *
 * Local to this file by design: a near-identical helper lives in
 * IngestJobContext.tsx, but the two strips own independent progress
 * shapes (numeric epoch ``started_at`` here vs. ISO string there) and
 * keeping them decoupled means neither file imports the other — a small
 * duplication that avoids a cross-context dependency.
 */
function formatEta(sec: number): string {
  if (!Number.isFinite(sec) || sec < 0) return "—";
  const total = Math.round(sec);
  if (total < 60) return `${total}s`;
  const mm = Math.floor(total / 60);
  const ss = total % 60;
  return `${mm}m ${String(ss).padStart(2, "0")}s`;
}

/**
 * Persistent progress strip rendered above ``<Routes>``.
 *
 * Survives route changes because it lives in the App shell, not inside
 * the Controls page. Visibility is gated on ``isPending`` AND the
 * backend tracker snapshot — same compound gate the old inline strip
 * used (see prior Controls.tsx comments) so the bar doesn't flicker
 * off-on-off across the settling tick where the backend ``finish()``
 * races the mutation completion. Hidden entirely when no batch is in
 * flight — consumes zero layout space at rest.
 */
export function AssessBatchProgressStrip() {
  const { isPending, progressSnapshot } = useAssessBatchContext();
  if (!isPending) return null;

  // Narrow the discriminated union so optional chaining below reads on
  // the data-bearing branch only.
  const active =
    progressSnapshot && progressSnapshot.active === true
      ? progressSnapshot
      : null;
  const total = active?.total ?? 0;
  const completed = active?.completed ?? 0;
  const errored = active?.errored ?? 0;
  // Clamp 0–100 so a stale snapshot where completed somehow exceeds
  // total (race during start() replacement of a stale slot) can't
  // push the bar past the track. Divide-by-zero on total=0 falls
  // through to the indeterminate "starting…" branch below.
  const pct =
    total > 0 ? Math.min(100, Math.round((completed / total) * 100)) : 0;
  const isStarting = !active || total === 0;
  // Elapsed seconds since the backend recorded started_at. The 750 ms
  // poll re-runs queryFn often enough that this stays current without
  // a separate setInterval — keeps unmount semantics dead simple.
  const elapsedSec = active
    ? Math.max(0, Math.round(Date.now() / 1000 - active.started_at))
    : 0;
  const mm = Math.floor(elapsedSec / 60);
  const ss = elapsedSec % 60;
  const elapsedLabel = `${mm}:${String(ss).padStart(2, "0")}`;
  // ETA: remaining CCIs / observed throughput. Only meaningful once the
  // batch has left the "starting" phase (so ``total`` is known) and at
  // least one CCI has completed to establish a rate. The 750 ms poll
  // refreshes ``completed``/``elapsedSec`` often enough that the estimate
  // tightens as the run proceeds — no separate timer needed. CCIs vary in
  // cost (deterministic short-circuits finish instantly, Tier-5 LLM
  // judgings take seconds), so this is a rolling average, hence "~".
  let etaLabel: string | null = null;
  if (!isStarting && completed > 0 && elapsedSec > 0) {
    const rate = completed / elapsedSec; // CCIs/sec
    if (rate > 0) {
      const remaining = Math.max(0, total - completed);
      etaLabel = formatEta(remaining / rate);
    }
  }
  // Bar tint — amber when any worker has raised so the user sees that
  // they should expect rejected/errored rows in the post-batch modal
  // even before it opens.
  const barColor = errored > 0 ? "bg-amber-500" : "bg-emerald-500";

  return (
    <div className="sticky top-0 z-30 border-b border-border bg-card/95 backdrop-blur supports-[backdrop-filter]:bg-card/80 px-4 py-2 shadow-nuon-sm">
      <div className="space-y-1.5">
        {/* pr-[160px] keeps the right-aligned (ml-auto) percent/elapsed/ETA clear
            of the custom WindowControls cluster fixed at the top-right. Measured:
            3 × w-9 buttons (108px) + 2 × gap-1 (8px) + right-2 (8px) ≈ 124px, so
            160px clears it with margin. Without it the ETA renders UNDER the
            min/max/close buttons and is invisible — mirrors the ingest strip. */}
        <div className="flex items-center gap-2 text-sm pr-[160px]">
          <Activity className="h-4 w-4 text-emerald-500 animate-pulse" />
          <span className="font-medium">
            {isStarting
              ? "Starting batch assessment…"
              : `Assessing ${completed} of ${total} CCI${total === 1 ? "" : "s"}`}
          </span>
          {active && active.last_objective && (
            <span className="text-muted-foreground text-xs">
              · last: {active.last_objective}
            </span>
          )}
          <span className="ml-auto text-xs text-muted-foreground tabular-nums">
            {pct}% · {elapsedLabel}
            {etaLabel ? ` · ~${etaLabel} left` : ""}
          </span>
        </div>
        <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
          {isStarting ? (
            <div className="h-full w-1/3 animate-pulse rounded-full bg-emerald-500/60" />
          ) : (
            <div
              className={`h-full rounded-full transition-[width] duration-500 ease-out ${barColor}`}
              style={{ width: `${pct}%` }}
            />
          )}
        </div>
        {errored > 0 && (
          <div className="text-xs text-amber-600 dark:text-amber-400">
            {errored} CCI{errored === 1 ? "" : "s"} errored — full list in the
            post-batch review modal.
          </div>
        )}
      </div>
    </div>
  );
}
