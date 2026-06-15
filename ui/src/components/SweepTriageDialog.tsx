/**
 * Boundary-aware sweep triage dialog.
 *
 * The middle step between "browse SharePoint" and "ingest". The sweep is a
 * no-download scoring pass: SharePointSource walks Graph metadata, scores
 * every candidate against the workbook's boundary fingerprint (host
 * inventory + in-scope control families + CRM responsibility map + doc-
 * number prefixes), and returns a ranked list. This dialog renders that
 * list, lets the assessor uncheck noise (or check additional rows), and
 * triggers the *existing* /api/sharepoint/ingest with the confirmed
 * subset — no new ingest path.
 *
 * The point: instead of dumping an entire share into the evidence store
 * and letting the tagger sort it out, the assessor pre-filters with a
 * full view of *why* each row scored what it did. Rows from CRM-skipped
 * families never appear; they're surfaced once in the collapsible header
 * with a count, per the design memo ("don't re-introduce the noise CRM
 * was supposed to eliminate").
 *
 * See backend/cybersecurity_assessor/evidence/sources/SHAREPOINT_SWEEP_DESIGN.md
 * for the contract.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  Cloud,
  ExternalLink,
  FolderDown,
  Loader2,
  Search,
  Sparkles,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  useBumpPendingSystemContextConfidence,
  useBumpSystemContextConfidence,
  useIngestAllFromFolder,
  useIngestSharePoint,
  useRecordSweepDecisions,
  useSharePointStatus,
  useSweepSharePoint,
} from "@/lib/queries";
import type { SharePointSweepCandidate, SweepDecisionEntry } from "@/lib/api";
import { toast } from "@/components/ui/toaster";
import { humanize } from "@/lib/errors";

// Mirror the backend constant. Rows scoring at-or-above this are pre-
// checked so the common path is "skim, uncheck noise, click ingest".
// Keep in lockstep with sweep.SCORE_PRECHECK_THRESHOLD.
const PRECHECK_THRESHOLD = 0.6;

/**
 * Discriminated scope union — the sweep route accepts either a workbook id
 * (post-workbook-open, normal path) OR a pending SystemContext id (the
 * assessor dropped boundary docs before opening any workbook). The route
 * layer enforces "at-least-one" via a pydantic validator; we pre-encode it
 * in the type so the caller can't construct an undecidable dialog state.
 */
export type SweepScope =
  | { kind: "workbook"; workbookId: number }
  | { kind: "pending"; systemContextId: number };

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /**
   * Which boundary the sweep scores against. Workbook mode uses the
   * workbook's SystemContext + baseline + CRM; pending mode uses only the
   * pending SystemContext's extracted_tokens (no baseline/CRM context yet,
   * since no workbook is bound).
   */
  scope: SweepScope;
  /** Optional override of the saved scan root (e.g. via priority link). */
  folderPath?: string;
  /** Per-run wall-clock cap in seconds from the inline toggle next to the
   *  Sweep button. undefined ⇒ no cap (server default — unlimited). When
   *  tripped, in-flight LLM calls finish and remaining candidates fall back
   *  to pure-keyword scoring. */
  timeCapSeconds?: number;
  /** Per-run dollar cap on the LLM judge for this sweep. undefined ⇒ fall
   *  back to the saved default in config.toml (which itself defaults to 0
   *  = unlimited). Overshoot is graceful: pre-flight 402 or tail falls back
   *  to keyword-only. */
  costCapUsd?: number;
  /** Same notifier as BrowseSharePointDialog so the parent's stats card
   *  updates. The second arg is the daemon-thread job_id the sidecar just
   *  registered; the parent hands it straight to ``setActiveJobId`` so the
   *  progress strip lights up on the same tick instead of waiting for the
   *  next ``useActiveIngestJob`` refetch (which is staleTime-gated to 30s). */
  onIngestStart?: (label: string, jobId: string) => void;
}

type SortKey = "score" | "name" | "modified";

export function SweepTriageDialog({
  open,
  onOpenChange,
  scope,
  folderPath,
  timeCapSeconds,
  costCapUsd,
  onIngestStart,
}: Props) {
  const spStatus = useSharePointStatus();
  const sweep = useSweepSharePoint();
  // Write-only audit log feeding the online-SGD weight recalibrator. Failures
  // are swallowed at the call site — the assessor's ingest must not block on
  // a training-pipeline write.
  const recordDecisions = useRecordSweepDecisions();
  // Outcome-tied confidence bump for the SystemContext: every artifact the
  // assessor accepts through this dialog is signal that the SystemContext
  // tokens are pointing at real evidence. Both server endpoints clamp at 1.0
  // and no-op when their target row is absent. Silent failure on error —
  // confidence is a UX hint, not a correctness invariant; don't block ingest
  // if the bump POST fails. We hold both hooks because React requires stable
  // hook order — the dispatch happens in onSuccess by reading `scope.kind`.
  const bumpWorkbookConfidence = useBumpSystemContextConfidence();
  const bumpPendingConfidence = useBumpPendingSystemContextConfidence();
  const ingest = useIngestSharePoint({
    onSuccess: () => {
      if (selectedPaths.size > 0) {
        if (scope.kind === "workbook") {
          bumpWorkbookConfidence.mutate({
            workbookId: scope.workbookId,
            accepted_count: selectedPaths.size,
          });
        } else {
          bumpPendingConfidence.mutate({
            accepted_count: selectedPaths.size,
          });
        }
      }
      toast.success(
        "SharePoint ingest started",
        "Progress shows on the Evidence tab.",
      );
      onOpenChange(false);
    },
    onError: (err) => toast.error("SharePoint ingest failed to start", humanize(err)),
  });
  // Manual escape hatch — POST /api/sharepoint/sweep/ingest-all. Bypasses
  // sweep scoring entirely; lands the whole folder so the assessor can
  // recover when keyword + LLM judge still misses the demo evidence.
  // Toasts on error; success path is handled inline in ``startIngestAll``
  // (we need access to the response shape to branch pending-auth vs
  // job_id, which is awkward in a hook-level onSuccess).
  const ingestAll = useIngestAllFromFolder({
    onError: (err) =>
      toast.error("Ingest entire folder failed to start", humanize(err)),
  });

  // Selection keyed by path so the user's check state survives sort/filter.
  const [selectedPaths, setSelectedPaths] = useState<Set<string>>(new Set());
  const [skippedExpanded, setSkippedExpanded] = useState(false);
  const [sortKey, setSortKey] = useState<SortKey>("score");
  // Filter out already-credited rows by default — the dishonesty fix.
  // The assessor's mental model is "what's new"; surfacing rows they
  // already ingested re-trains them to ignore the list. Toggle to OFF
  // when reviewing the full history (e.g. confirming a prior decision
  // was correct, or pulling an etag-refreshed copy in a future revision).
  const [hideCredited, setHideCredited] = useState(true);
  // Elapsed seconds while the sweep is in flight. Backend BFS + per-token
  // Graph /search calls can take anywhere from a few seconds (small share,
  // tight fingerprint) to ~3 minutes (full scan root, generic fingerprint).
  // Without a running counter the static spinner reads as "stuck" — see
  // the prior 422 pre-flight fix; this is the rest of that UX repair.
  const [elapsedSec, setElapsedSec] = useState(0);

  // Extract spStatus primitives so the sweep effect can list them as deps
  // without dragging in the whole spStatus.data object (which churns identity
  // on every status refetch and would cause spurious re-fires). sweep.mutate
  // is stable in React Query v5.
  const spSiteUrl = spStatus.data?.site_url ?? "";
  const spLibrary = spStatus.data?.library ?? undefined;
  const spFolderPath = spStatus.data?.folder_path ?? undefined;

  // Auto-fire the sweep when the dialog opens with a known scope. We use
  // mutation rather than query because the inputs are dialog-session-scoped
  // (scope + override folder) and we want a fresh pass each time the
  // assessor reopens it — caches between sessions would hide newly added
  // SharePoint files. Guard against missing site config: the parent disables
  // the trigger button in that case, but a defensive check here keeps a
  // flicker of a dead state out of the UI.
  //
  // Destructure scope discriminants into stable deps so the effect doesn't
  // re-fire on parent re-renders that produce a fresh `scope` object identity.
  const scopeKind = scope.kind;
  const scopeWorkbookId = scope.kind === "workbook" ? scope.workbookId : undefined;
  const scopeSystemContextId =
    scope.kind === "pending" ? scope.systemContextId : undefined;

  // Owns the AbortController for the currently-firing sweep so closing the
  // dialog (or re-firing with different inputs) cancels the fetch instead
  // of letting it run to completion in the background. Without this, the
  // "Close to cancel" affordance in the long-running spinner was cosmetic
  // only — the backend kept burning Graph BFS + /search calls for minutes.
  const sweepAbortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (!open || !spSiteUrl) return;
    // Abort any prior in-flight sweep from this dialog session before
    // starting a new one (e.g. when the time-cap toggle flips mid-flight).
    sweepAbortRef.current?.abort();
    const controller = new AbortController();
    sweepAbortRef.current = controller;
    sweep.mutate(
      {
        body: {
          // At-least-one of these is set per the SweepScope union; the route
          // layer enforces the same invariant via a pydantic validator.
          workbook_id: scopeWorkbookId,
          system_context_id: scopeSystemContextId,
          site_url: spSiteUrl,
          library: spLibrary,
          folder_path: folderPath ?? spFolderPath,
          // Per-run override from the inline toggle. Omit when undefined so
          // the backend falls back to unlimited.
          time_cap_seconds: timeCapSeconds,
          // Per-run dollar override; undefined ⇒ backend uses config default.
          cost_cap_usd: costCapUsd,
        },
        signal: controller.signal,
      },
      {
        onSuccess: (res) => {
          // Pre-check rows ≥ PRECHECK_THRESHOLD by default, but EXCLUDE rows
          // that are already in Evidence — re-picking them only confuses the
          // user, since the orchestrator dedupes by path and the row is a
          // no-op at ingest time. The "Hide already in Evidence" filter is
          // on by default so these rows aren't visible to be re-checked
          // either; this filter is the belt to the toggle's suspenders.
          const initial = new Set<string>();
          for (const c of res.candidates) {
            if (c.score >= PRECHECK_THRESHOLD && !c.already_in_evidence) {
              initial.add(c.path);
            }
          }
          setSelectedPaths(initial);
        },
      },
    );
  }, [
    open,
    scopeKind,
    scopeWorkbookId,
    scopeSystemContextId,
    folderPath,
    spSiteUrl,
    spLibrary,
    spFolderPath,
    timeCapSeconds,
    costCapUsd,
    sweep.mutate,
  ]);

  // Reset everything on close so the next open re-fetches and re-presents.
  // Also abort any in-flight sweep — closing the dialog is the user telling
  // us "I don't want this anymore", so we stop the underlying fetch instead
  // of letting it finish and waste Graph quota.
  useEffect(() => {
    if (!open) {
      sweepAbortRef.current?.abort();
      sweepAbortRef.current = null;
      setSelectedPaths(new Set());
      setSkippedExpanded(false);
      setSortKey("score");
      setHideCredited(true);
    }
  }, [open]);

  // Belt-and-suspenders: ensure unmount also cancels. Strict-mode double-
  // mounts cancel themselves before re-mounting, which is fine — the next
  // open re-fires.
  useEffect(() => {
    return () => {
      sweepAbortRef.current?.abort();
      sweepAbortRef.current = null;
    };
  }, []);

  // Run a 1-Hz counter only while a sweep is in flight. Reset to 0 on
  // each new sweep so consecutive runs don't accumulate. setInterval is
  // cheap enough at 1Hz to skip rAF gymnastics.
  useEffect(() => {
    if (!sweep.isPending) {
      setElapsedSec(0);
      return;
    }
    setElapsedSec(0);
    const startedAt = Date.now();
    const id = window.setInterval(() => {
      setElapsedSec(Math.floor((Date.now() - startedAt) / 1000));
    }, 1000);
    return () => window.clearInterval(id);
  }, [sweep.isPending]);

  const candidates: SharePointSweepCandidate[] = sweep.data?.candidates ?? [];
  const skipped: string[] = sweep.data?.families_skipped_by_crm ?? [];

  // Count of pre-credited rows in the raw sweep response — drives the
  // filter toggle label and the selection-counter "skipped on ingest" line.
  // Counted off `candidates` (not `sortedCandidates`) so the number stays
  // stable when the user flips the filter.
  const creditedCount = useMemo(
    () => candidates.filter((c) => c.already_in_evidence).length,
    [candidates],
  );

  const sortedCandidates = useMemo(() => {
    // Filter first (cheaper than sorting then filtering), then sort.
    // hideCredited drops pre-credited rows; user can flip it to see them.
    const arr = hideCredited
      ? candidates.filter((c) => !c.already_in_evidence)
      : [...candidates];
    if (sortKey === "score") {
      arr.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
    } else if (sortKey === "name") {
      arr.sort((a, b) => a.name.localeCompare(b.name));
    } else {
      // modified: nulls last
      arr.sort((a, b) => {
        if (!a.modified && !b.modified) return 0;
        if (!a.modified) return 1;
        if (!b.modified) return -1;
        return b.modified.localeCompare(a.modified);
      });
    }
    return arr;
  }, [candidates, sortKey, hideCredited]);

  // Visible rows excluding already-credited (regardless of `hideCredited`
  // toggle state) — what "Ingest all visible" should actually ingest.
  // When the filter is ON these match sortedCandidates; when OFF we still
  // exclude credited rows from the "all" action so the click never quietly
  // re-picks files the orchestrator will skip.
  const ingestableVisible = useMemo(
    () => sortedCandidates.filter((c) => !c.already_in_evidence),
    [sortedCandidates],
  );

  function toggleSelected(path: string) {
    setSelectedPaths((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  }

  function toggleAll() {
    if (selectedPaths.size === sortedCandidates.length) {
      setSelectedPaths(new Set());
    } else {
      setSelectedPaths(new Set(sortedCandidates.map((c) => c.path)));
    }
  }

  function startIngest() {
    if (!spStatus.data?.site_url || selectedPaths.size === 0) return;
    // Per-workbook hard-scoping (PR 2): a pending-scope sweep has no workbook
    // to bind Evidence rows to. Block ingest until the user promotes/opens one.
    if (scopeWorkbookId == null) {
      toast.error(
        "No workbook open",
        "Promote this sweep to a workbook (or open one from Catalogs) before ingesting evidence.",
      );
      return;
    }
    const paths = Array.from(selectedPaths);
    const label = `SharePoint sweep: ${paths.length} file${
      paths.length === 1 ? "" : "s"
    } from boundary triage`;

    // Fire-and-forget audit log BEFORE kicking ingest. The sweep response
    // carries the weights id and fingerprint snapshot used to score the
    // candidates — we round-trip both so recalibration sees identical
    // features later even if the active weights have rolled forward or
    // the workbook fingerprint has drifted.
    //
    // Wrapped in a try/catch (and the mutation has no onError that surfaces
    // to the user) because a training-pipeline write must never block the
    // assessor's primary action. Older sidecars without v0.2 may return
    // null for either field; we skip the log in that case rather than
    // posting garbage that breaks the SGD trainer.
    //
    // Pending-mode is intentionally skipped: the recorder is keyed on
    // workbook_id and the recalibrator joins back through Workbook → CRM
    // for negative-class weighting. A pending sweep has no CRM yet; logging
    // it would teach the trainer noisy features. Once the user promotes,
    // future sweeps log normally.
    if (
      scope.kind === "workbook" &&
      sweep.data?.weights_version_id != null &&
      sweep.data?.fingerprint_snapshot != null
    ) {
      try {
        const decisions: SweepDecisionEntry[] = sortedCandidates.map((c) => ({
          candidate_path: c.path,
          candidate_name: c.name,
          score_at_decision: c.score,
          signals: c.matched_signals,
          proposed_ccis: c.proposed_ccis,
          included: selectedPaths.has(c.path),
          auto_prechecked: c.score >= PRECHECK_THRESHOLD,
        }));
        recordDecisions.mutate({
          workbook_id: scope.workbookId,
          weights_version_id: sweep.data.weights_version_id,
          fingerprint_snapshot: sweep.data.fingerprint_snapshot,
          decisions,
        });
      } catch {
        // Swallow — the audit log is best-effort.
      }
    }

    // Pass label + job_id to the parent inside the mutation's per-call
    // onSuccess so the Evidence tab's progress strip appears on the same
    // tick the sidecar registers the job — not whenever
    // ``useActiveIngestJob`` next refetches.
    ingest.mutate(
      {
        site_url: spStatus.data.site_url,
        library: spStatus.data.library ?? undefined,
        folder_path: folderPath ?? spStatus.data.folder_path ?? undefined,
        file_paths: paths,
        workbookId: scopeWorkbookId,
      },
      { onSuccess: (res) => onIngestStart?.(label, res.job_id) },
    );
  }

  /**
   * One-click power-user path: ingest every visible non-credited candidate
   * the sweep surfaced, no checkbox dance. Distinct from "Ingest entire
   * folder" — that bypasses scoring entirely; this respects the sweep's
   * surface threshold (≥ 0.05) and the CRM family skip-list.
   *
   * Confirmation gate at N > 100 because the user can also flip
   * `hideCredited` OFF and accidentally trigger a giant ingest including
   * (already-skipped) credited rows — the count makes the blast radius
   * obvious before the click commits.
   */
  function startIngestAllVisible() {
    if (!spStatus.data?.site_url || ingest.isPending) return;
    if (scopeWorkbookId == null) {
      toast.error(
        "No workbook open",
        "Promote this sweep to a workbook (or open one from Catalogs) before ingesting evidence.",
      );
      return;
    }
    const paths = ingestableVisible.map((c) => c.path);
    if (paths.length === 0) return;
    if (paths.length > 100) {
      const skipMsg =
        creditedCount > 0
          ? `\n\n${creditedCount} already-in-Evidence row${creditedCount === 1 ? " is" : "s are"} excluded automatically.`
          : "";
      const ok = window.confirm(
        `Ingest ${paths.length} candidates from this sweep?${skipMsg}`,
      );
      if (!ok) return;
    }
    // Reuse startIngest by populating selectedPaths first so the audit log
    // sees the same shape as a click-by-click ingest. The mutation runs on
    // the next render after setSelectedPaths, but startIngest reads paths
    // directly from its closure copy — so we just call the same fetch
    // inline here to avoid a render-cycle race.
    setSelectedPaths(new Set(paths));
    const label = `SharePoint sweep: ${paths.length} file${
      paths.length === 1 ? "" : "s"
    } (all visible)`;

    if (
      scope.kind === "workbook" &&
      sweep.data?.weights_version_id != null &&
      sweep.data?.fingerprint_snapshot != null
    ) {
      try {
        const selSet = new Set(paths);
        const decisions: SweepDecisionEntry[] = sortedCandidates.map((c) => ({
          candidate_path: c.path,
          candidate_name: c.name,
          score_at_decision: c.score,
          signals: c.matched_signals,
          proposed_ccis: c.proposed_ccis,
          included: selSet.has(c.path),
          auto_prechecked: c.score >= PRECHECK_THRESHOLD,
        }));
        recordDecisions.mutate({
          workbook_id: scope.workbookId,
          weights_version_id: sweep.data.weights_version_id,
          fingerprint_snapshot: sweep.data.fingerprint_snapshot,
          decisions,
        });
      } catch {
        /* best-effort */
      }
    }

    ingest.mutate(
      {
        site_url: spStatus.data.site_url,
        library: spStatus.data.library ?? undefined,
        folder_path: folderPath ?? spStatus.data.folder_path ?? undefined,
        file_paths: paths,
        workbookId: scopeWorkbookId,
      },
      { onSuccess: (res) => onIngestStart?.(label, res.job_id) },
    );
  }

  /**
   * Re-fire the sweep with the currently-checked candidates as pseudo-
   * relevance feedback exemplars. The backend embeds these in the LLM
   * judge's cached system block so the next pass has a richer semantic
   * prior than the host-token list alone — useful when the first round
   * surfaced a few obvious winners but missed semantically-related files
   * (e.g. a network diagram with no token overlap).
   *
   * Reuses the same AbortController + mutation as the auto-fire effect.
   * Doesn't close the dialog — the user wants to compare rounds in place.
   */
  function refineWithSelection() {
    if (!spSiteUrl || sweep.isPending) return;
    if (selectedPaths.size === 0) {
      toast.info(
        "Nothing selected",
        "Check at least one candidate to seed the refine pass.",
      );
      return;
    }
    sweepAbortRef.current?.abort();
    const controller = new AbortController();
    sweepAbortRef.current = controller;
    const seeds = Array.from(selectedPaths);
    sweep.mutate(
      {
        body: {
          workbook_id: scopeWorkbookId,
          system_context_id: scopeSystemContextId,
          site_url: spSiteUrl,
          library: spLibrary,
          folder_path: folderPath ?? spFolderPath,
          time_cap_seconds: timeCapSeconds,
          cost_cap_usd: costCapUsd,
          seed_candidate_paths: seeds,
        },
        signal: controller.signal,
      },
      {
        onSuccess: (res) => {
          // Preserve the prior selection plus any newly pre-checked rows so
          // the user sees the refine result as "old picks + new winners",
          // not a reset.
          const next = new Set<string>(seeds);
          for (const c of res.candidates) {
            // Same dedupe rule as the initial pre-check: don't auto-add
            // already-credited rows. User can still manually check them.
            if (c.score >= PRECHECK_THRESHOLD && !c.already_in_evidence) {
              next.add(c.path);
            }
          }
          setSelectedPaths(next);
          toast.success(
            "Refine complete",
            `Re-scored with ${seeds.length} exemplar${seeds.length === 1 ? "" : "s"}.`,
          );
        },
      },
    );
  }

  /**
   * Manual escape hatch — ingest every supported file in the folder, no
   * scoring. Use when the boundary sweep still missed something obvious
   * (renamed folder, no lexical overlap with hosts, etc.). The user has
   * to acknowledge this skips precision filtering before it fires.
   */
  function startIngestAll() {
    if (!spStatus.data?.site_url || ingestAll.isPending) return;
    const effectiveFolder =
      folderPath ?? spStatus.data.folder_path ?? "";
    const folderLabel = effectiveFolder || "(library root)";
    const ok = window.confirm(
      `Ingest EVERY supported file under "${folderLabel}" without scoring?\n\n` +
        "This bypasses the boundary sweep entirely — use only when the " +
        "ranked list above is missing obviously-relevant evidence.",
    );
    if (!ok) return;

    const label = `SharePoint ingest-all: ${folderLabel}`;
    ingestAll.mutate(
      {
        site_url: spStatus.data.site_url,
        library: spStatus.data.library ?? undefined,
        folder_path: effectiveFolder || undefined,
        // Workbook mode binds the auto-tag pass to the right framework lens;
        // pending mode leaves it null and the tagger writes unscoped tags.
        ...(scope.kind === "workbook"
          ? { workbook_id: scope.workbookId }
          : {}),
      },
      {
        onSuccess: (res) => {
          // Defensive: a 502 from Graph with no body can arrive as a falsy
          // payload. Without this guard the `in` check below throws
          // "Cannot use 'in' on undefined" and the All button "crashes" the
          // dialog (the prior demo regression).
          if (!res) {
            toast.error(
              "SharePoint ingest-all failed",
              "Empty response from sidecar.",
            );
            return;
          }
          // Two shapes: success carries job_id; pending carries device-code.
          if ("job_id" in res) {
            toast.success(
              "SharePoint ingest-all started",
              "Progress shows on the Evidence tab.",
            );
            onIngestStart?.(label, res.job_id);
            onOpenChange(false);
          } else if (res.pending) {
            // Surface the device-code prompt — same UX as the /test pending
            // path the Settings card handles. Keep the dialog open so the
            // user can click again after signing in.
            toast.info(
              "SharePoint sign-in required",
              `Open ${res.verification_uri ?? ""} and enter ${res.user_code ?? "the code"} to authorize, then click again.`,
            );
          } else {
            toast.error(
              "SharePoint ingest-all failed",
              res.detail ?? "Unknown error.",
            );
          }
        },
      },
    );
  }

  const sweepError = (sweep.error as Error | null)?.message ?? null;
  const allSelected =
    sortedCandidates.length > 0 && selectedPaths.size === sortedCandidates.length;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-5xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Search className="h-5 w-5" />
            Boundary-aware sweep
            {scope.kind === "pending" && (
              <span className="ml-2 rounded bg-warning/15 text-warning-foreground px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide">
                pending scope
              </span>
            )}
          </DialogTitle>
          <DialogDescription>
            {scope.kind === "workbook" ? (
              <>
                Scoring files in SharePoint against this workbook's boundary —
                hosts, in-scope control families, doc-number prefixes, and the
                CRM responsibility map.
              </>
            ) : (
              <>
                Scoring files in SharePoint against your{" "}
                <strong>pending boundary scope</strong> — host tokens extracted
                from the boundary docs you've dropped so far. Open a workbook
                and promote the pending scope onto it to enable control-family
                and CRM signals.
              </>
            )}{" "}
            Nothing is downloaded until you click <strong>Ingest</strong> below.
            Rows are pre-checked at score ≥ {PRECHECK_THRESHOLD.toFixed(2)};
            uncheck noise before ingesting.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-3 min-h-[400px]">
          {sweep.isPending && (
            <div className="flex flex-col items-center justify-center h-48 text-sm text-muted-foreground gap-2">
              <div className="flex items-center">
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
                Scoring candidates against boundary…
                <span className="ml-2 tabular-nums text-xs">
                  {formatElapsed(elapsedSec)}
                </span>
              </div>
              {/* Past ~30s the BFS is genuinely walking the share +
                  running per-token Graph /search + per-survivor LLM judge
                  calls. Wall-clock depends on scan-root breadth and LLM
                  concurrency — set a per-run time cap next to the Sweep
                  button if you need a hard ceiling. Closing this dialog
                  now actually aborts the in-flight request. */}
              {elapsedSec >= 30 && (
                <p className="text-xs text-center max-w-md text-muted-foreground/80">
                  Working — BFS depth 4, per-token Graph search, and the
                  LLM judge are all live. Wall-clock scales with scan-root
                  size; set a time cap next to the Sweep button to bound
                  this. Closing this dialog aborts the request.
                </p>
              )}
              {elapsedSec >= 180 && (
                <p className="text-xs text-center max-w-md text-warning-foreground/90">
                  Past 3 minutes — likely a wide scan root or a stalled
                  LLM batch. Sidecar logs at
                  <code className="mx-1">~/.cybersecurity-assessor/sidecar.log</code>
                  show BFS and search progress. Close to abort.
                </p>
              )}
            </div>
          )}

          {sweepError && !sweep.isPending && (
            <div className="rounded border border-destructive/40 bg-destructive/5 p-4 text-sm text-destructive">
              <p className="font-medium">Sweep failed</p>
              <p className="text-xs mt-1 font-mono break-all">{sweepError}</p>
            </div>
          )}

          {!sweep.isPending && sweep.isSuccess && sweep.data && (
            <>
              {/* Summary header */}
              <div className="rounded border border-info/40 bg-info/5 px-3 py-2 text-xs space-y-1">
                <div className="text-foreground">
                  <strong>{candidates.length}</strong> candidate
                  {candidates.length === 1 ? "" : "s"} from{" "}
                  <span className="font-mono">{sweep.data.scan_root}</span>
                  {sweep.data.truncated && (
                    <span className="text-warning ml-1">
                      (truncated at cap)
                    </span>
                  )}
                  {" — "}
                  <span className="text-muted-foreground">
                    {sweep.data.elapsed_ms} ms
                  </span>
                </div>
                {skipped.length > 0 && (
                  <button
                    type="button"
                    onClick={() => setSkippedExpanded((v) => !v)}
                    className="flex items-center gap-1 text-muted-foreground hover:text-foreground"
                    title="Families hidden because every in-scope control is provider/inherited/not-applicable per the CRM"
                  >
                    {skippedExpanded ? (
                      <ChevronDown className="h-3 w-3" />
                    ) : (
                      <ChevronRight className="h-3 w-3" />
                    )}
                    Skipped {skipped.length} provider/inherited{" "}
                    {skipped.length === 1 ? "family" : "families"} per CRM
                    {skippedExpanded && (
                      <span className="ml-1 font-mono">
                        ({skipped.join(", ")})
                      </span>
                    )}
                  </button>
                )}
                {/* Pre-credit filter — default ON to keep the list honest
                    ("what's new"). Flipping OFF shows already-ingested rows
                    with the "In Evidence" badge so the user can audit prior
                    decisions or manually re-ingest (rare; orchestrator will
                    dedupe by path anyway). */}
                {creditedCount > 0 && (
                  <label
                    className="flex items-center gap-1.5 text-muted-foreground hover:text-foreground cursor-pointer select-none"
                    title="Hide rows whose path already exists in Evidence — the orchestrator dedupes these on ingest, so re-checking is a no-op."
                  >
                    <input
                      type="checkbox"
                      checked={hideCredited}
                      onChange={(e) => setHideCredited(e.target.checked)}
                      className="h-3 w-3"
                    />
                    Hide {creditedCount} already in Evidence
                  </label>
                )}
              </div>

              {/* Result table */}
              {candidates.length === 0 ? (
                <div className="flex items-center justify-center h-32 rounded border text-sm text-muted-foreground p-6 text-center">
                  No files matched the boundary above the surface threshold.
                  Verify the scan root in Settings → SharePoint, or attach a
                  CRM with customer/hybrid families.
                </div>
              ) : (
                <div className="flex-1 overflow-y-auto rounded border max-h-[450px]">
                  <table className="w-full text-sm">
                    <thead className="bg-muted/40 sticky top-0 text-[11px] uppercase tracking-wide text-muted-foreground">
                      <tr>
                        <th className="px-2 py-2 w-8">
                          <input
                            type="checkbox"
                            checked={allSelected}
                            onChange={toggleAll}
                            className="h-3.5 w-3.5"
                            title={allSelected ? "Uncheck all" : "Check all"}
                          />
                        </th>
                        <th
                          className="px-2 py-2 text-left cursor-pointer hover:text-foreground"
                          onClick={() => setSortKey("name")}
                        >
                          Name {sortKey === "name" && "↓"}
                        </th>
                        <th
                          className="px-2 py-2 text-left w-32 cursor-pointer hover:text-foreground"
                          onClick={() => setSortKey("score")}
                        >
                          Score {sortKey === "score" && "↓"}
                        </th>
                        <th className="px-2 py-2 text-left">
                          Proposed CCIs
                        </th>
                        <th className="px-2 py-2 text-left">
                          Matched signals
                        </th>
                        <th
                          className="px-2 py-2 text-right w-24 cursor-pointer hover:text-foreground"
                          onClick={() => setSortKey("modified")}
                        >
                          Modified {sortKey === "modified" && "↓"}
                        </th>
                        <th className="px-2 py-2 w-8"></th>
                      </tr>
                    </thead>
                    <tbody className="divide-y">
                      {sortedCandidates.map((c) => {
                        const checked = selectedPaths.has(c.path);
                        return (
                          <tr
                            key={c.path}
                            className={`hover:bg-accent cursor-pointer ${
                              checked ? "bg-accent/30" : ""
                            }`}
                            onClick={() => toggleSelected(c.path)}
                            title={c.snippet ?? c.path}
                          >
                            <td className="px-2 py-1.5">
                              <input
                                type="checkbox"
                                checked={checked}
                                onChange={() => toggleSelected(c.path)}
                                onClick={(e) => e.stopPropagation()}
                                className="h-3.5 w-3.5"
                              />
                            </td>
                            <td className="px-2 py-1.5 min-w-0">
                              <div
                                className="truncate font-medium flex items-center gap-1.5"
                                title={c.name}
                              >
                                <span className="truncate">{c.name}</span>
                                {c.already_in_evidence && (
                                  // No deep-link route into the Evidence
                                  // detail view exists today; tooltip surfaces
                                  // the row id so the assessor can search
                                  // for it manually. If a route is added
                                  // later, wrap this span in a Link.
                                  <span
                                    className="shrink-0 rounded bg-muted text-muted-foreground border border-border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide"
                                    title={
                                      c.existing_evidence_id != null
                                        ? `Already ingested (Evidence #${c.existing_evidence_id}) — orchestrator will skip on re-ingest.`
                                        : "Already ingested — orchestrator will skip on re-ingest."
                                    }
                                  >
                                    In Evidence
                                  </span>
                                )}
                              </div>
                              {/* Absolute path — wraps so the whole thing is
                                  visible (user requested prominence); still
                                  monospaced + dim so it doesn't compete with
                                  the name. Click-to-copy via the title tip. */}
                              <div
                                className="break-all text-[10px] text-muted-foreground font-mono leading-tight"
                                title={`${c.path}\n(click to copy)`}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  void navigator.clipboard
                                    ?.writeText(c.path)
                                    .then(() =>
                                      toast.success(
                                        "Path copied",
                                        c.path,
                                      ),
                                    )
                                    .catch(() => {
                                      /* clipboard blocked — silent */
                                    });
                                }}
                              >
                                {c.path}
                              </div>
                            </td>
                            <td className="px-2 py-1.5">
                              <ScoreBar score={c.score} />
                            </td>
                            <td className="px-2 py-1.5">
                              <div className="flex flex-wrap gap-1">
                                {(c.proposed_ccis ?? []).length === 0 && (
                                  <span className="text-[10px] text-muted-foreground italic">
                                    none
                                  </span>
                                )}
                                {(c.proposed_ccis ?? []).slice(0, 6).map((cci) => (
                                  <span
                                    key={cci}
                                    className="rounded bg-info/15 text-info-foreground px-1.5 py-0.5 text-[10px] font-mono font-medium"
                                  >
                                    {cci}
                                  </span>
                                ))}
                                {(c.proposed_ccis ?? []).length > 6 && (
                                  <span
                                    className="text-[10px] text-muted-foreground"
                                    title={(c.proposed_ccis ?? []).slice(6).join(", ")}
                                  >
                                    +{(c.proposed_ccis ?? []).length - 6}
                                  </span>
                                )}
                              </div>
                            </td>
                            <td className="px-2 py-1.5">
                              <div className="flex flex-wrap gap-1">
                                {(c.matched_signals ?? []).length === 0 && (
                                  <span className="text-[10px] text-muted-foreground italic">
                                    none
                                  </span>
                                )}
                                {(c.matched_signals ?? []).slice(0, 6).map((sig) => (
                                  <span
                                    key={sig}
                                    className="rounded bg-muted text-muted-foreground px-1.5 py-0.5 text-[10px] font-mono"
                                  >
                                    {sig}
                                  </span>
                                ))}
                                {(c.matched_signals ?? []).length > 6 && (
                                  <span
                                    className="text-[10px] text-muted-foreground"
                                    title={(c.matched_signals ?? []).slice(6).join(", ")}
                                  >
                                    +{(c.matched_signals ?? []).length - 6}
                                  </span>
                                )}
                              </div>
                            </td>
                            <td className="px-2 py-1.5 text-right text-[11px] text-muted-foreground tabular-nums">
                              {formatModified(c.modified)}
                            </td>
                            <td className="px-2 py-1.5">
                              {c.web_url && (
                                <a
                                  href={c.web_url}
                                  target="_blank"
                                  rel="noreferrer"
                                  onClick={(e) => e.stopPropagation()}
                                  className="inline-flex p-1 rounded hover:bg-accent text-muted-foreground"
                                  title="Open in SharePoint"
                                >
                                  <ExternalLink className="h-3.5 w-3.5" />
                                </a>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}

              {/* Selection counter — honest about credited rows the
                  orchestrator would silently dedupe. */}
              <div className="text-xs text-muted-foreground">
                <strong className="text-foreground">{selectedPaths.size}</strong>{" "}
                of {candidates.length} selected for ingest.
                {creditedCount > 0 && (
                  <span className="ml-2">
                    {creditedCount} already in Evidence{" "}
                    <span className="text-muted-foreground/70">
                      (skipped on ingest)
                    </span>
                    .
                  </span>
                )}
              </div>
            </>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          {/* Refine pass — re-fires the sweep with the currently-checked
              candidates as pseudo-relevance feedback exemplars for the LLM
              judge. Disabled when there's nothing selected or a sweep is
              already in flight. Doesn't close the dialog — the user is
              iterating in place. */}
          <Button
            variant="outline"
            onClick={refineWithSelection}
            disabled={
              sweep.isPending ||
              ingest.isPending ||
              ingestAll.isPending ||
              selectedPaths.size === 0 ||
              !sweep.isSuccess
            }
            title={
              selectedPaths.size === 0
                ? "Check at least one candidate to seed the refine pass"
                : `Re-sweep with ${selectedPaths.size} selected file${selectedPaths.size === 1 ? "" : "s"} as exemplars`
            }
          >
            {sweep.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Sparkles className="h-4 w-4" />
            )}
            Refine with selection
          </Button>
          {/* Escape hatch — only enabled once we know the SharePoint site
              and aren't already kicking off an ingest of either kind.
              Sits between Cancel and the primary Ingest button so it's
              discoverable without being the default action. */}
          <Button
            variant="outline"
            onClick={startIngestAll}
            disabled={
              ingestAll.isPending ||
              ingest.isPending ||
              !spStatus.data?.site_url
            }
            title="Ingest every supported file in this folder — bypasses sweep scoring"
          >
            {ingestAll.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <FolderDown className="h-4 w-4" />
            )}
            Ingest entire folder
          </Button>
          {/* One-click "grab everything the sweep surfaced" — sits next to
              "Ingest selected" so the assessor can switch modes without
              fighting the checkbox column. Excludes pre-credited rows
              regardless of the `hideCredited` toggle state — the orchestrator
              would dedupe them anyway, so quietly skipping is more honest
              than double-counting in the button label. */}
          <Button
            variant="outline"
            onClick={startIngestAllVisible}
            disabled={
              ingest.isPending ||
              ingestAll.isPending ||
              ingestableVisible.length === 0 ||
              !sweep.isSuccess
            }
            title={
              ingestableVisible.length === 0
                ? "No ingestable visible candidates"
                : `Ingest all ${ingestableVisible.length} visible candidate${ingestableVisible.length === 1 ? "" : "s"} (excludes already-in-Evidence)`
            }
          >
            {ingest.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Cloud className="h-4 w-4" />
            )}
            Ingest all visible ({ingestableVisible.length})
          </Button>
          <Button
            onClick={startIngest}
            disabled={
              ingest.isPending ||
              ingestAll.isPending ||
              selectedPaths.size === 0 ||
              !sweep.isSuccess
            }
            title={
              selectedPaths.size === 0
                ? "Check at least one candidate to ingest"
                : `Ingest ${selectedPaths.size} selected file${selectedPaths.size === 1 ? "" : "s"}`
            }
          >
            {ingest.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Cloud className="h-4 w-4" />
            )}
            Ingest selected ({selectedPaths.size})
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/**
 * Score is 0..1ish but the additive scorer can exceed 1 (e.g. host +
 * control_id + family + crm + doc-prefix = 1.15). Cap the bar visually at
 * 1.0 and color in three bands: ≥0.60 strong, ≥0.30 weak, below dropped.
 */
function ScoreBar({ score }: { score: number }) {
  const pct = Math.min(100, Math.max(0, score * 100));
  const color =
    score >= 0.6
      ? "bg-emerald-500"
      : score >= 0.3
        ? "bg-amber-500"
        : "bg-muted-foreground";
  return (
    <div className="flex items-center gap-2">
      <div className="relative h-1.5 w-16 rounded bg-muted overflow-hidden">
        <div
          className={`absolute inset-y-0 left-0 ${color}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-[11px] text-muted-foreground tabular-nums">
        {score.toFixed(2)}
      </span>
    </div>
  );
}

function formatModified(iso: string | null): string {
  if (!iso) return "—";
  // Just date portion — full timestamp clutters the row.
  return iso.slice(0, 10);
}

/** "12s" under a minute, "1m23s" over. Matches the cadence the user
 *  is looking for ("is it still going?") without burning column width. */
function formatElapsed(sec: number): string {
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return `${m}m${s.toString().padStart(2, "0")}s`;
}
