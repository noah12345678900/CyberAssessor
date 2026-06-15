/**
 * SweepContext page — drop boundary docs, that's it.
 *
 * Minimal UX (per user feedback 2026-06-04): one drag-drop zone with a
 * fallback "pick files" button. Anything dropped lands in Evidence with
 * `is_boundary_doc=true` scoped to the active workbook, and the SharePoint
 * sweep biases toward it. No kind selector, no separate extract button,
 * no sweep-attempts UI. Token extraction fires automatically once the last
 * drop in a batch settles (500 ms debounce), so the assessor never has to
 * think about it.
 *
 * Name note (2026-06-05): renamed from "System Description" → "Sweep Context"
 * because the page is *not* a place to author an SSP-style system description.
 * It's the assessor's hint sheet for the sweep — boundary tokens extracted
 * from whatever the user drops here bias which SharePoint candidates surface.
 * "Sweep Context" reads as "context for the sweep", which is the actual job.
 *
 * Downstream contract is unchanged: SystemContext.extracted_tokens still
 * lands in BoundaryFingerprint.host_tokens at _W_HOST=0.40 in
 * evidence/sources/sweep.py. Only the input adapter changed.
 *
 * IA: lives under Tools (utility), not Workflow — boundary docs are
 * optional sweep tuning. See feedback_scoping_out_of_assessor.md.
 *
 * Drag-drop note: Electron 32 deprecated `File.path`. We resolve absolute
 * paths via `window.ccis.getDroppedFilePath(file)`, which calls
 * `webUtils.getPathForFile` in the preload bridge.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { Upload, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { toast } from "@/components/ui/toaster";
import { humanize } from "@/lib/errors";
import { cn } from "@/lib/utils";
import { usePendingModeOverride } from "@/lib/usePendingModeOverride";
import {
  useBoundaryDocs,
  useIngestFile,
  useLatestSweepRun,
  usePatchBoundaryDoc,
  usePendingSystemContext,
  useSystemContext,
  useUpsertPendingSystemContext,
  useUpsertSystemContext,
  useWorkbooks,
} from "@/lib/queries";

/** Path-based ingest filters — same as Evidence single-file picker. */
const ACCEPTED_EXTENSIONS = ["pdf", "docx", "pptx", "xlsx", "txt", "md"];

/** Compact "Xm ago" / "Xh ago" / "Xd ago" formatter for the sweep footer.
 *  Avoids pulling in a date library for one line of UI. */
function formatRelativeMinutes(iso: string | null): string {
  if (!iso) return "just now";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "just now";
  const diffMin = Math.max(0, Math.round((Date.now() - then) / 60_000));
  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.round(diffHr / 24);
  return `${diffDay}d ago`;
}

export function SweepContext() {
  // Auto-pick the most-recently-opened workbook — same pattern as Evidence.tsx.
  const workbooks = useWorkbooks();
  const activeWorkbookId = useMemo(() => {
    const list = workbooks.data;
    if (!list || list.length === 0) return undefined;
    const sorted = [...list].sort((a, b) =>
      (b.last_opened ?? "").localeCompare(a.last_opened ?? ""),
    );
    return sorted[0]?.id;
  }, [workbooks.data]);
  const activeWorkbook = useMemo(() => {
    if (!activeWorkbookId) return undefined;
    return workbooks.data?.find((w) => w.id === activeWorkbookId);
  }, [workbooks.data, activeWorkbookId]);

  // Manual override — when ON, force pending mode even if a workbook is open.
  // See usePendingModeOverride.ts for the rationale (lets the pending path be
  // exercised before we ship a real "close workbook" affordance).
  const [pendingOverride, setPendingOverride] = usePendingModeOverride();

  // Two parallel data sources: per-workbook (real workbook is open) and pending
  // (no workbook open — boundary docs land in the singleton pending row defined
  // by the partial unique index ix_systemcontext_pending_singleton). We pick one
  // based on whether a workbook is active. The pending GET returns
  // {context, boundary_docs} as a single payload — no separate evidence query.
  // `effectiveWorkbookId` is the id used for every downstream call — undefined
  // means "go pending".
  const effectiveWorkbookId = pendingOverride ? undefined : activeWorkbookId;
  const ctxQuery = useSystemContext(effectiveWorkbookId);
  const pendingQuery = usePendingSystemContext();
  const isPending = !effectiveWorkbookId;
  const ctx = isPending ? pendingQuery.data?.context ?? null : ctxQuery.data;
  const docsQuery = useBoundaryDocs(effectiveWorkbookId);
  const docs = isPending
    ? pendingQuery.data?.boundary_docs ?? []
    : docsQuery.data ?? [];
  // Footer telemetry — most recent SweepRun for this workbook. null when the
  // workbook has never been swept (footer simply doesn't render).
  const latestSweep = useLatestSweepRun(effectiveWorkbookId);

  const [isDragging, setIsDragging] = useState(false);
  // Track in-flight uploads so the drop zone can show progress and we know
  // when to fire the debounced auto-extract.
  const [inFlight, setInFlight] = useState(0);
  const extractTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Remember the docs.length we last triggered an extract for (or seeded from
  // the initial settled load). Lets us fire when the count changes — INCLUDING
  // the N → 0 transition that the prior `if (docs.length === 0) return;` bail
  // silently swallowed, leaving stale tokens parked in extracted_tokens after
  // the assessor removed every boundary doc. Keyed by mode (workbook id /
  // pending) so toggling Close/Reopen workbook doesn't misread the other
  // mode's docs as "the user just removed N items".
  const lastUpsertRef = useRef<{ key: string; count: number } | null>(null);

  const ingest = useIngestFile({
    onSuccess: (ev) => {
      // size_bytes can be null on legacy Evidence rows ingested before the
      // column was non-nullable. Guard so the toast doesn't throw and trip
      // the "Couldn't ingest file" error path on what was actually a 200.
      const size =
        typeof ev.size_bytes === "number"
          ? `${ev.size_bytes.toLocaleString()} bytes`
          : "size unknown";
      toast.success("Boundary doc attached", `${ev.filename} — ${size}`);
    },
    onError: (err) => toast.error("Couldn't ingest file", humanize(err)),
    onSettled: () => setInFlight((n) => Math.max(0, n - 1)),
  });

  const patchDoc = usePatchBoundaryDoc({
    onSuccess: () =>
      toast.success(
        "Removed from boundary",
        "Evidence row kept — only the boundary flag was cleared.",
      ),
    onError: (err) => toast.error("Couldn't update boundary flag", humanize(err)),
  });

  // Shared success/error handlers — both per-workbook and pending upserts return
  // the same SystemContextUpsertResult shape, so the toasts are identical.
  const onUpsertSuccess = (res: {
    tokens_extracted: number;
    notes: { extraction_error?: string } | null;
  }) => {
    const extracted = res.tokens_extracted;
    const err = (res.notes as { extraction_error?: string } | null)
      ?.extraction_error;
    if (err) {
      toast.error("Auto-extract failed", err);
    } else {
      toast.success(
        "Sweep tokens updated",
        `Pulled ${extracted} token${extracted === 1 ? "" : "s"} from your boundary docs.`,
      );
    }
  };
  const onUpsertError = (err: unknown) =>
    toast.error("Auto-extract failed", humanize(err));

  const upsert = useUpsertSystemContext({
    onSuccess: onUpsertSuccess,
    onError: onUpsertError,
  });
  const upsertPending = useUpsertPendingSystemContext({
    onSuccess: onUpsertSuccess,
    onError: onUpsertError,
  });

  // Auto-extract: 500ms after the docs list settles at a new count, regenerate
  // the sweep tokens. Multi-file drops collapse to one extract call at the
  // tail of the quiet period. In pending mode the call routes through
  // /api/system-context/pending instead of the per-workbook path.
  //
  // We deliberately also fire when docs.length transitions to 0 — the
  // boundary-docs adapter handles empty input by writing tokens=[] and
  // confidence=0.0 (boundary_docs.py:136-154), which is exactly what clears
  // the displayed token cloud after the assessor removes the last doc.
  //
  // Initial-mount guard: snapshot the count on the first settled render of
  // each mode WITHOUT firing, so opening the page with N pre-existing docs
  // doesn't trigger a redundant extract + "Sweep tokens updated" toast.
  const docsLoading = isPending
    ? pendingQuery.isLoading
    : effectiveWorkbookId
      ? docsQuery.isLoading
      : false;
  useEffect(() => {
    if (docsLoading) return;
    if (inFlight > 0) return;

    const currentKey = effectiveWorkbookId
      ? `w:${effectiveWorkbookId}`
      : "pending";
    const prev = lastUpsertRef.current;

    // First settled render for this mode — seed the ref, no upsert.
    if (prev === null || prev.key !== currentKey) {
      lastUpsertRef.current = { key: currentKey, count: docs.length };
      return;
    }
    if (prev.count === docs.length) return;

    if (extractTimer.current) clearTimeout(extractTimer.current);
    extractTimer.current = setTimeout(() => {
      lastUpsertRef.current = { key: currentKey, count: docs.length };
      if (effectiveWorkbookId) {
        upsert.mutate({
          workbookId: effectiveWorkbookId,
          body: { source_type: "docx_narrative" },
        });
      } else {
        upsertPending.mutate({ body: { source_type: "docx_narrative" } });
      }
    }, 500);

    return () => {
      if (extractTimer.current) {
        clearTimeout(extractTimer.current);
        extractTimer.current = null;
      }
    };
  }, [
    effectiveWorkbookId,
    isPending,
    docsLoading,
    inFlight,
    docs.length,
    upsert.mutate,
    upsertPending.mutate,
  ]);

  function submitPath(path: string) {
    setInFlight((n) => n + 1);
    // workbook_id=null is the pending-singleton path; the ingest endpoint
    // already accepts null and the pending /promote handler reparents the
    // row when the user opens a workbook.
    ingest.mutate({
      path,
      is_boundary_doc: true,
      workbook_id: effectiveWorkbookId ?? null,
    });
  }

  async function handlePickFiles() {
    if (!window.ccis?.openFile) {
      toast.error(
        "File dialog unavailable",
        "Drag and drop a file, or run the desktop app for the picker.",
      );
      return;
    }
    const path = await window.ccis.openFile([
      { name: "Boundary docs", extensions: ACCEPTED_EXTENSIONS },
    ]);
    if (!path) return; // user cancelled
    submitPath(path);
  }

  function handleDrop(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setIsDragging(false);
    const getPath = window.ccis?.getDroppedFilePath;
    if (!getPath) {
      toast.error(
        "Drag-drop unavailable",
        "Use the picker button — drag and drop requires the desktop app.",
      );
      return;
    }
    const files = Array.from(e.dataTransfer.files);
    if (files.length === 0) return;
    for (const f of files) {
      const path = getPath(f);
      if (path) submitPath(path);
    }
  }

  if (workbooks.isLoading) {
    return (
      <div className="p-6 text-sm text-muted-foreground">Loading workbooks…</div>
    );
  }

  // No hard bail when activeWorkbookId is undefined — pending mode lets the
  // assessor drop boundary docs before opening a workbook. The DB pins them to
  // a NULL-workbook singleton row; opening a workbook auto-promotes via
  // open_workbook's pending_promotion path. See plan
  // C:\Users\Noah.Jaskolski\.claude\plans\moonlit-marinating-octopus.md.

  const tokens = ctx?.extracted_tokens ?? [];
  const busy =
    inFlight > 0 ||
    ingest.isPending ||
    upsert.isPending ||
    upsertPending.isPending;

  return (
    <div className="space-y-6 p-6">
      <header className="space-y-1">
        <div className="flex items-start justify-between gap-3">
          <h1 className="text-2xl font-semibold tracking-tight">
            Sweep Context
          </h1>
          {/* Close/Reopen workbook toggle. We don't have a real "active
              workbook" setting yet — the page picks the most-recently-opened
              workbook automatically. This button lets the assessor force the
              pending-scope path so it can be exercised without erasing
              workbook state. Reopening just clears the override. */}
          {activeWorkbook && !pendingOverride ? (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPendingOverride(true)}
              title="Stop targeting this workbook and use a pending boundary scope instead. Reopen any time."
            >
              Close workbook
            </Button>
          ) : null}
          {pendingOverride && activeWorkbook ? (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPendingOverride(false)}
              title={`Resume targeting ${activeWorkbook.filename}.`}
            >
              Reopen {activeWorkbook.filename}
            </Button>
          ) : null}
        </div>
        <p className="text-sm text-muted-foreground">
          Drop the docs that define your boundary (SSP, network diagram, ATO
          letter, etc). They land in Evidence flagged as boundary, and the
          SharePoint sweep biases toward in-boundary artifacts.{" "}
          {!isPending && activeWorkbook ? (
            <span className="font-medium">
              Workbook: {activeWorkbook.filename}
            </span>
          ) : (
            <span className="font-medium">
              Pending scope{" "}
              {activeWorkbook
                ? `(workbook ${activeWorkbook.filename} closed)`
                : "(no workbook open yet)"}
            </span>
          )}
        </p>
      </header>

      {/* Pending-mode banner — both flavors of pending (no workbook AND
          override) show this so the assessor knows where drops are landing. */}
      {isPending ? (
        <Card className="border-amber-200 bg-amber-50 dark:border-amber-900/50 dark:bg-amber-950/20">
          <CardHeader className="py-4">
            <CardTitle className="text-sm">Pending scope</CardTitle>
            <CardDescription>
              {activeWorkbook
                ? `Workbook ${activeWorkbook.filename} is closed for this session. Documents you drop here are staged on a pending boundary record. Reopen the workbook (button above) to resume targeting it — pending docs will attach automatically.`
                : "No workbook is open. Documents you drop here are staged on a pending boundary record — when you open a CCIS workbook on the Workbooks tab, these docs and any extracted sweep tokens will attach to it automatically."}
            </CardDescription>
          </CardHeader>
        </Card>
      ) : null}

      {/* Drop zone — primary affordance */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        className={cn(
          "flex flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed px-6 py-12 text-center transition-colors",
          isDragging
            ? "border-primary bg-primary/5"
            : "border-muted-foreground/25 bg-muted/20 hover:border-muted-foreground/40",
        )}
      >
        <Upload className="h-8 w-8 text-muted-foreground" strokeWidth={1.5} />
        <div className="space-y-1">
          <p className="text-sm font-medium">
            {busy ? "Working…" : "Drop boundary documents here"}
          </p>
          <p className="text-xs text-muted-foreground">
            Accepts {ACCEPTED_EXTENSIONS.join(", ")}. Sweep tokens regenerate
            automatically.
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={handlePickFiles}
          disabled={ingest.isPending}
        >
          Or pick a file
        </Button>
      </div>

      {/* Last sweep telemetry — renders only when the workbook has been swept
          at least once. Single line so it stays subordinate to the drop zone. */}
      {latestSweep.data ? (
        <p className="text-center text-xs text-muted-foreground tabular-nums">
          Last sweep: ${latestSweep.data.llm_cost_usd.toFixed(2)} ·{" "}
          {latestSweep.data.candidates_judged} judged ·{" "}
          {latestSweep.data.judge_model ?? "keyword-only"} ·{" "}
          {formatRelativeMinutes(latestSweep.data.finished_at)}
          {latestSweep.data.fallback_reason ? (
            <span className="ml-2 text-amber-600 dark:text-amber-400">
              ({latestSweep.data.fallback_reason})
            </span>
          ) : null}
        </p>
      ) : null}

      {/* Attached docs — flat list, one-click remove */}
      <Card>
        <CardHeader>
          <CardTitle>Attached boundary documents</CardTitle>
          <CardDescription>
            Removing a doc here only clears its boundary flag — the Evidence
            row is kept.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {docsQuery.isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : docs.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No boundary docs attached yet.
            </p>
          ) : (
            <ul className="divide-y rounded-md border">
              {docs.map((d) => (
                <li
                  key={d.id}
                  className="flex items-center justify-between gap-3 px-3 py-2"
                >
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono text-xs">
                      {d.filename}
                    </div>
                    <div className="text-[11px] text-muted-foreground tabular-nums">
                      {d.ingested_at
                        ? new Date(d.ingested_at).toLocaleString()
                        : "—"}
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() =>
                      patchDoc.mutate({
                        id: d.id,
                        is_boundary_doc: false,
                        boundary_doc_kind: null,
                        workbook_id: null,
                      })
                    }
                    disabled={patchDoc.isPending}
                    title="Remove from boundary"
                  >
                    <X className="h-4 w-4" />
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      {/* Extracted tokens — collapsible, secondary. Showing them up front is
          noise; the assessor only cares when sweep results look off. */}
      {tokens.length > 0 && (
        <details className="rounded-md border bg-muted/20 px-4 py-3 text-sm">
          <summary className="cursor-pointer text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Sweep tokens ({tokens.length})
          </summary>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {tokens.map((t) => (
              <Badge key={t} variant="secondary" className="font-mono">
                {t}
              </Badge>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}
