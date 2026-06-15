/**
 * Ingest-job context — cross-route persistence for evidence ingestion.
 *
 * Mirrors AssessBatchContext: the provider is mounted once in the App shell
 * (above <Routes>), so the in-flight ingest job — its 1s status poll, the
 * mount re-adoption, and the done/error toasts — survives navigating away
 * from the Evidence page. A global sticky <IngestProgressStrip /> renders the
 * live counter + ETA on every route while a job runs.
 *
 * Why a context and not Evidence-local state (as before): the assessor kicks
 * off a folder/SharePoint ingest, then navigates to Baselines/Controls to keep
 * working while the walk runs. Before this hoist the progress card unmounted on
 * route change and the user lost all feedback until they came back. Lifting the
 * state here matches the Controls assess-batch UX exactly.
 *
 * ETA: driven by the backend ``estimated_total`` pre-count (LocalFolderSource
 * reuses its rglob filter). Streaming sources (SharePoint) omit the pre-count
 * → ``estimated_total`` is null → the strip falls back to an indeterminate
 * sweep with no ETA. Refresh is piggy-backed on the existing 1s status poll's
 * re-render — no separate setInterval.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { Loader2 } from "lucide-react";

import { toast } from "@/components/ui/toaster";
import { humanize } from "@/lib/errors";
import {
  useActiveIngestJob,
  useIngestFolder,
  useIngestJobStatus,
} from "@/lib/queries";
import type { IngestJob, IngestSummary } from "@/lib/api";

interface IngestFolderArgs {
  folder: string;
  workbookId: number;
  recursive?: boolean;
}

interface IngestJobContextValue {
  /** Live job snapshot from the status poll (null when idle). */
  job: IngestJob | null;
  /** Source URI / folder label of the active or most-recent ingest. */
  lastFolder: string | null;
  /** Completed-run summary, kept after the job finishes for the "Last ingest" card. */
  lastSummary: IngestSummary | null;
  /** True while a job is starting or running. */
  isIngesting: boolean;
  /**
   * Kick off a local folder ingest. Returns the underlying mutateAsync promise
   * so callers keep their own try/catch → setError handling.
   */
  ingestFolder: (args: IngestFolderArgs) => Promise<unknown>;
  /** Adopt a job started elsewhere (e.g. the SharePoint browse dialog). */
  adoptJob: (jobId: string, label: string) => void;
  /** Clear ingest state (used by the clear-evidence flow). */
  reset: () => void;
}

const IngestJobContext = createContext<IngestJobContextValue | null>(null);

export function IngestJobProvider({ children }: { children: ReactNode }) {
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [lastSummary, setLastSummary] = useState<IngestSummary | null>(null);
  const [lastFolder, setLastFolder] = useState<string | null>(null);

  const ingest = useIngestFolder({
    onSuccess: (res) => setActiveJobId(res.job_id),
    onError: (err) => toast.error("Ingest failed to start", humanize(err)),
  });

  // Mount re-adoption: if a job was already running when the app (re)loaded —
  // e.g. a tab refresh mid-ingest, or first paint after navigating back — pick
  // it up exactly once so the strip reattaches without losing context. Guarded
  // by a ref so we don't re-adopt (and re-toast) on every poll tick.
  const activeJobQuery = useActiveIngestJob();
  const hasAdoptedRef = useRef(false);
  useEffect(() => {
    if (hasAdoptedRef.current) return;
    if (activeJobId) {
      hasAdoptedRef.current = true;
      return;
    }
    const adopted = activeJobQuery.data;
    if (adopted && adopted.status === "running") {
      hasAdoptedRef.current = true;
      setActiveJobId(adopted.job_id);
      setLastFolder(adopted.source_uri || null);
    }
  }, [activeJobId, activeJobQuery.data]);

  // Status poll — 1s while running, stops on done/error (see useIngestJobStatus).
  const jobStatus = useIngestJobStatus(activeJobId);
  const job = jobStatus.data ?? null;

  useEffect(() => {
    if (!job || job.status === "running") return;

    if (job.status === "done" && job.summary) {
      const s = job.summary;
      setLastSummary(s);
      const errCount = s.errors.length;
      toast.success(
        "Ingest complete",
        `Scanned ${s.scanned} · ingested ${s.ingested} · skipped ${s.skipped_existing}` +
          (errCount ? ` · ${errCount} error${errCount === 1 ? "" : "s"}` : ""),
      );
    } else if (job.status === "error") {
      toast.error(
        "Ingest failed",
        job.error ?? "Unknown error in ingest thread.",
      );
    }
    setActiveJobId(null);
  }, [job]);

  const ingestFolder = useCallback(
    ({ folder, workbookId, recursive = true }: IngestFolderArgs) => {
      setLastFolder(folder);
      return ingest.mutateAsync({ folder, workbookId, recursive });
    },
    [ingest],
  );

  const adoptJob = useCallback((jobId: string, label: string) => {
    setLastFolder(label);
    setActiveJobId(jobId);
  }, []);

  const reset = useCallback(() => {
    ingest.reset();
    setActiveJobId(null);
    setLastFolder(null);
    setLastSummary(null);
  }, [ingest]);

  const isIngesting = !!activeJobId || ingest.isPending;

  const value = useMemo<IngestJobContextValue>(
    () => ({
      job,
      lastFolder,
      lastSummary,
      isIngesting,
      ingestFolder,
      adoptJob,
      reset,
    }),
    [job, lastFolder, lastSummary, isIngesting, ingestFolder, adoptJob, reset],
  );

  return (
    <IngestJobContext.Provider value={value}>
      {children}
    </IngestJobContext.Provider>
  );
}

export function useIngestJobContext(): IngestJobContextValue {
  const ctx = useContext(IngestJobContext);
  if (ctx === null) {
    throw new Error(
      "useIngestJobContext must be used inside <IngestJobProvider>",
    );
  }
  return ctx;
}

/**
 * Format a seconds count as a compact "1m 20s" / "45s" ETA label.
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
 * Global sticky progress strip — rendered in the App shell so it shows on
 * every route while an ingest runs. Returns null at rest (zero layout cost).
 *
 * Two display modes:
 *   • Determinate — backend gave an ``estimated_total`` (local folder). Show a
 *     real bar, percent, and an ETA derived from the live scan rate.
 *   • Indeterminate — ``estimated_total`` is null (SharePoint / streaming).
 *     Show the sweep animation and a raw scanned counter, no ETA.
 */
export function IngestProgressStrip() {
  const { job, lastFolder, isIngesting } = useIngestJobContext();

  // Only render while a job is actually in flight. ``isIngesting`` also covers
  // the brief window between mutate() and the first status poll landing.
  if (!isIngesting) return null;

  const running = job && job.status === "running" ? job : null;
  const scanned = running?.scanned ?? 0;
  const ingested = running?.ingested ?? 0;
  const total = running?.estimated_total ?? null;
  const isStarting = !running;

  // started_at is an ISO string on IngestJob (unlike the numeric epoch on
  // AssessBatchProgress) — parse it before any elapsed math.
  const startedMs = running ? Date.parse(running.started_at) : NaN;
  const elapsedSec = Number.isFinite(startedMs)
    ? Math.max(0, (Date.now() - startedMs) / 1000)
    : 0;

  const hasTotal = typeof total === "number" && total > 0;
  const pct = hasTotal ? Math.min(100, Math.round((scanned / total) * 100)) : 0;

  // ETA: remaining / observed rate. Only meaningful once we have a denominator
  // and at least one scanned file to establish a rate.
  let etaLabel: string | null = null;
  if (hasTotal && scanned > 0 && elapsedSec > 0) {
    const rate = scanned / elapsedSec; // files/sec
    if (rate > 0) {
      const remaining = Math.max(0, total - scanned);
      etaLabel = formatEta(remaining / rate);
    }
  }

  return (
    <div className="sticky top-0 z-30 border-b border-border bg-card/95 px-4 py-2 shadow-nuon-sm backdrop-blur supports-[backdrop-filter]:bg-card/80">
      <div className="flex items-center gap-2">
        <Loader2 className="h-4 w-4 shrink-0 animate-spin text-primary" />
        <span className="text-sm font-medium">
          {isStarting
            ? "Starting ingest…"
            : hasTotal
              ? `Ingesting ${scanned} of ${total} file${total === 1 ? "" : "s"}`
              : `Ingesting — ${scanned} scanned`}
        </span>
        {!isStarting && ingested > 0 && (
          <span className="text-xs text-muted-foreground">
            · {ingested} ingested
          </span>
        )}
        <span className="ml-auto text-xs tabular-nums text-muted-foreground">
          {hasTotal ? `${pct}%` : "estimating…"}
          {etaLabel ? ` · ~${etaLabel} left` : ""}
        </span>
      </div>

      {lastFolder && (
        <div className="mt-1 truncate font-mono text-[11px] text-muted-foreground">
          {lastFolder}
        </div>
      )}

      <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-muted">
        {hasTotal ? (
          <div
            className="h-full rounded-full bg-primary transition-[width] duration-500 ease-out"
            style={{ width: `${pct}%` }}
          />
        ) : (
          <div className="h-full w-1/3 animate-[ingest-sweep_1.4s_ease-in-out_infinite] rounded-full bg-primary" />
        )}
      </div>
    </div>
  );
}
