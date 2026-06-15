/**
 * Browse-and-ingest dialog for SharePoint.
 *
 * Mirrors the strategy used in our nist-assessor plugin: instead of ingesting
 * an entire site blindly (which spins forever on real-world share roots), the
 * user drills into a subfolder, sees what's there, and ingests just that
 * subset. Saves their time and our context window.
 *
 * Two top-level modes:
 *   1. Browse mode (default) — breadcrumb + folders + files for the current
 *      subfolder under the configured scan root; footer ingests the whole
 *      visible folder.
 *   2. Search mode — typing in the search box and pressing Enter swaps the
 *      file list for a flat, folder-grouped list of filename matches with
 *      checkboxes; footer ingests only the assessor-selected files. This
 *      mirrors the nist-assessor plugin's find-evidence command and keeps
 *      ingestion narrow on huge shares. Filename matching is heuristic —
 *      a banner above the results reminds the assessor to verify each hit
 *      is actually applicable to the control before ingesting.
 *
 * Plus a left-sidebar of Priority Links: bookmarks the user pastes from the
 * SharePoint browser address bar. Clicking "Use as scan root" pulls the path
 * part into the dialog (best-effort URL parsing) so they can ingest from
 * there in one click.
 */

import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  ChevronRight,
  Cloud,
  FileText,
  Folder,
  Home,
  Loader2,
  LogIn,
  RefreshCw,
  Scan,
  Search,
  Star,
  X,
} from "lucide-react";

import { SweepTriageDialog } from "@/components/SweepTriageDialog";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  useBrowseSharePoint,
  useIngestSharePoint,
  usePendingSystemContext,
  useSearchSharePoint,
  useSharePointPriorityLinks,
  useSharePointStatus,
} from "@/lib/queries";
import type { SharePointSearchHit } from "@/lib/api";
import { toast } from "@/components/ui/toaster";
import { humanize } from "@/lib/errors";
import { usePendingModeOverride } from "@/lib/usePendingModeOverride";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /**
   * Notifier so the parent (Evidence tab) can update its "Last ingest" stats
   * card and lastFolder display string when the dialog kicks off an ingest.
   * The second arg is the daemon-thread job_id the sidecar just registered —
   * the parent hands it straight to ``setActiveJobId`` so the progress strip
   * lights up on the same tick instead of waiting for the next
   * ``useActiveIngestJob`` refetch (which is staleTime-gated to 30s).
   */
  onIngestStart?: (label: string, jobId: string) => void;
  /**
   * Workbook to score the boundary-aware sweep against. When undefined AND
   * no pending SystemContext exists, the "Sweep for boundary…" button is
   * disabled. When undefined but a pending SystemContext exists (assessor
   * dropped boundary docs before opening a workbook — the workbook-decoupling
   * slice), the sweep falls back to pending-mode scoring (host_tokens only).
   * Browse + search modes always work.
   */
  workbookId?: number;
}

export function BrowseSharePointDialog({
  open,
  onOpenChange,
  onIngestStart,
  workbookId,
}: Props) {
  const spStatus = useSharePointStatus();
  const priorityLinks = useSharePointPriorityLinks();
  const browse = useBrowseSharePoint();
  const search = useSearchSharePoint();
  // Pending-scope fallback. When no workbook is open, the sweep can still
  // run as long as the assessor has dropped boundary docs (those extract
  // into a pending SystemContext with host_tokens). The hook returns null
  // when there's no pending row — gate is then dual-disabled.
  const pendingCtx = usePendingSystemContext();
  const pendingSystemContextId = pendingCtx.data?.context?.id;
  // Honor the Sweep Context page's "Close workbook" override — when ON, treat
  // workbookId as undefined so this dialog routes through the pending-scope
  // path even though a workbook is technically open.
  const [pendingOverride] = usePendingModeOverride();
  const effectiveWorkbookId = pendingOverride ? undefined : workbookId;
  const ingest = useIngestSharePoint({
    // Ingest is fire-and-poll — the response is just {job_id}. We hand the
    // job_id back to the parent via the per-call onSuccess in
    // startBrowseIngest/startSearchIngest below, so the Evidence tab's
    // progress strip lights up on the same tick. This hook-level callback
    // just handles the dialog-side UX (toast + close).
    onSuccess: () => {
      toast.success("SharePoint ingest started", "Progress shows on the Evidence tab.");
      onOpenChange(false);
    },
    onError: (err) => toast.error("SharePoint ingest failed to start", humanize(err)),
  });

  // The current subfolder shown in the main pane, relative to the configured
  // scan root. Empty string = scan root itself.
  const [subfolder, setSubfolder] = useState("");
  // When set, overrides the saved scan root for this dialog session — e.g. if
  // the user picked a priority link that resolved to a different folder.
  const [overrideFolderPath, setOverrideFolderPath] = useState<string | null>(null);

  // Search input state. searchQuery = live text in the input; activeQuery =
  // the term we actually fired against the backend (set on Enter / Search
  // button). Separating them lets us keep the input editable while showing
  // the previous result set and prevents stutter on every keypress.
  const [searchQuery, setSearchQuery] = useState("");
  const [activeQuery, setActiveQuery] = useState("");
  // Selected hits in search mode, keyed by hit.path so re-running the same
  // query preserves the assessor's checkbox state.
  const [selectedPaths, setSelectedPaths] = useState<Set<string>>(new Set());

  // Boundary-aware sweep dialog visibility. Triggered from the toolbar; it
  // takes the current effectiveScanRoot + workbookId so the assessor can
  // pre-filter the share by relevance rather than browsing folder-by-folder.
  const [sweepOpen, setSweepOpen] = useState(false);
  // Per-run wall-clock ceiling on the LLM judge, set inline next to the
  // Sweep button. Default OFF — judge default is unlimited. Time is a
  // better UX knob than dollars: assessors think in "I have 10 min before
  // my next meeting", not "$5 of API spend". When the cap trips, in-flight
  // calls finish and the remainder falls back to keyword-only (graceful).
  const [sweepTimeCapEnabled, setSweepTimeCapEnabled] = useState(false);
  const [sweepTimeCapMin, setSweepTimeCapMin] = useState<string>("5");
  // Per-run dollar ceiling on the LLM judge. Off by default — the backend
  // default in config.toml is "unlimited" and sized for a strong first sweep,
  // so the checkbox stays unchecked until the user explicitly opts in. When
  // flipped on, the input seeds at "1.00" as a sane starting point instead of
  // an empty field. Same graceful-degrade contract as the time cap: pre-flight
  // 402 if the estimate overshoots, in-flight overshoot silently falls back to
  // keyword-only on the tail.
  const [sweepCostCapEnabled, setSweepCostCapEnabled] = useState<boolean>(false);
  const [sweepCostCapUsd, setSweepCostCapUsd] = useState<string>("1.00");

  const inSearchMode = activeQuery.length > 0;

  const effectiveScanRoot = overrideFolderPath ?? spStatus.data?.folder_path ?? "";

  // Gate the browse call on a present sign-in token cache. The Evidence page
  // already swaps Browse for "Configure SharePoint…" when not signed in, but
  // status can be stale (e.g. the user signed out in another window) — better
  // to render a friendly "go sign in" empty state than fire a doomed request
  // and surface its raw 502 to the user.
  const spConfigured = !!spStatus.data?.configured;
  const spSignedIn = !!spStatus.data?.token_cache_exists;
  const spSiteUrl = spStatus.data?.site_url ?? "";
  // Extract library as a primitive so the browse/search effects below can
  // depend on it directly without dragging in the whole spStatus.data
  // object (which churns identity on every status refetch and would cause
  // spurious re-fires). With v5 React Query, mutation.mutate is also a
  // stable callback — depending on it is safe.
  const spLibrary = spStatus.data?.library ?? "";
  const spReady = spConfigured && spSignedIn && !!spSiteUrl;
  const signInGuidance = !spConfigured
    ? "SharePoint isn't configured yet — paste your tenant, client ID, and site URL in Settings → SharePoint."
    : !spSignedIn
      ? "You're not signed in to SharePoint yet. Open Settings → SharePoint and click Sign in to start the device-code flow."
      : !spSiteUrl
        ? "No SharePoint site URL is saved — open Settings → SharePoint to set one."
        : null;

  // Re-browse whenever the dialog opens or the user drills/jumps. Browse is a
  // mutation (not query) because the input changes on every click — see
  // useBrowseSharePoint for the rationale. Skipped while in search mode —
  // the search response is what's on screen, no need to also keep the folder
  // listing fresh.
  useEffect(() => {
    if (!open || !spReady || inSearchMode) return;
    browse.mutate({
      site_url: spSiteUrl,
      library: spLibrary,
      folder_path: effectiveScanRoot,
      subfolder,
    });
  }, [open, subfolder, effectiveScanRoot, spReady, inSearchMode, browse.mutate, spSiteUrl, spLibrary]);

  // Re-search when the active query changes or the scan root changes under us.
  useEffect(() => {
    if (!open || !spReady || !inSearchMode) return;
    search.mutate({
      site_url: spSiteUrl,
      library: spLibrary,
      folder_path: effectiveScanRoot,
      query: activeQuery,
    });
  }, [open, activeQuery, effectiveScanRoot, spReady, inSearchMode, search.mutate, spSiteUrl, spLibrary]);

  // Reset everything when dialog closes — next open should start clean.
  useEffect(() => {
    if (!open) {
      setSubfolder("");
      setOverrideFolderPath(null);
      setSearchQuery("");
      setActiveQuery("");
      setSelectedPaths(new Set());
    }
  }, [open]);

  const breadcrumbs = useMemo(() => {
    if (!subfolder) return [];
    const parts = subfolder.split("/").filter(Boolean);
    return parts.map((part, i) => ({
      label: part,
      path: parts.slice(0, i + 1).join("/"),
    }));
  }, [subfolder]);

  // Group search hits by their folder for scannable rendering. Hits with no
  // folder (i.e. directly at the scan root) get bucketed under "" so the UI
  // can label them "(scan root)".
  const hitsByFolder = useMemo(() => {
    const hits = search.data?.matches ?? [];
    const groups = new Map<string, SharePointSearchHit[]>();
    for (const h of hits) {
      const existing = groups.get(h.folder);
      if (existing) existing.push(h);
      else groups.set(h.folder, [h]);
    }
    return Array.from(groups.entries()).sort(([a], [b]) => a.localeCompare(b));
  }, [search.data]);

  function startBrowseIngest() {
    if (!spStatus.data?.site_url) return;
    // Per-workbook hard-scoping (PR 2): Evidence rows must bind to a real
    // workbook id. In pending-override mode there's no workbook to attach
    // to, so block ingest and tell the assessor to open one.
    if (effectiveWorkbookId == null) {
      toast.error(
        "No workbook open",
        "Open a workbook from the Catalogs screen before ingesting SharePoint evidence.",
      );
      return;
    }
    const fullPath = [effectiveScanRoot, subfolder].filter(Boolean).join("/");
    const label = `SharePoint: ${spStatus.data.site_url}${
      spStatus.data.library ? ` · ${spStatus.data.library}` : ""
    }${fullPath ? `/${fullPath}` : ""}`;
    // Pass label + job_id to the parent inside the mutation's per-call
    // onSuccess so the progress strip appears on the same tick the sidecar
    // registers the job — not whenever ``useActiveIngestJob`` next refetches.
    ingest.mutate(
      {
        site_url: spStatus.data.site_url,
        library: spStatus.data.library ?? "",
        folder_path: fullPath,
        workbookId: effectiveWorkbookId,
      },
      { onSuccess: (res) => onIngestStart?.(label, res.job_id) },
    );
  }

  function startSearchIngest() {
    if (!spStatus.data?.site_url || selectedPaths.size === 0) return;
    if (effectiveWorkbookId == null) {
      toast.error(
        "No workbook open",
        "Open a workbook from the Catalogs screen before ingesting SharePoint evidence.",
      );
      return;
    }
    const paths = Array.from(selectedPaths);
    const label = `SharePoint search: ${selectedPaths.size} file${
      selectedPaths.size === 1 ? "" : "s"
    } from "${activeQuery}"`;
    ingest.mutate(
      {
        site_url: spStatus.data.site_url,
        library: spStatus.data.library ?? "",
        folder_path: effectiveScanRoot,
        file_paths: paths,
        workbookId: effectiveWorkbookId,
      },
      { onSuccess: (res) => onIngestStart?.(label, res.job_id) },
    );
  }

  function runSearch() {
    const q = searchQuery.trim();
    if (!q) {
      // Empty input acts as "exit search mode".
      setActiveQuery("");
      setSelectedPaths(new Set());
      return;
    }
    setActiveQuery(q);
    setSelectedPaths(new Set());
  }

  function clearSearch() {
    setSearchQuery("");
    setActiveQuery("");
    setSelectedPaths(new Set());
  }

  function toggleSelected(path: string) {
    setSelectedPaths((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  }

  function selectAllVisible() {
    const all = (search.data?.matches ?? [])
      .filter((h) => h.ingestible)
      .map((h) => h.path);
    setSelectedPaths(new Set(all));
  }

  function applyPriorityLink(url: string) {
    // Best-effort parse: SharePoint deep links typically encode the folder via
    // either ?id=/sites/X/SharedDocs/folder or /Forms/AllItems.aspx?id=...
    // Failures leave the dialog at its current location and the user can
    // navigate manually.
    try {
      const u = new URL(url);
      const id = u.searchParams.get("id") || u.searchParams.get("RootFolder");
      if (!id) {
        toast.error(
          "Could not parse link",
          "Drop the URL into Settings → SharePoint to save it as the scan root.",
        );
        return;
      }
      // id is server-relative: /sites/{site}/{library}/{folder...}
      // Strip the site portion (matches spStatus.data.site_url path) and the
      // library segment to land on the folder relative to the library root.
      const sitePath = spStatus.data?.site_url
        ? new URL(spStatus.data.site_url).pathname.replace(/\/$/, "")
        : "";
      let rel = id;
      if (sitePath && rel.startsWith(sitePath)) {
        rel = rel.slice(sitePath.length).replace(/^\//, "");
      }
      // First segment is the library; drop it.
      const segs = rel.split("/").filter(Boolean);
      if (segs.length > 0) segs.shift();
      const folder = segs.join("/");
      setOverrideFolderPath(folder);
      setSubfolder("");
      clearSearch();
    } catch {
      toast.error("Invalid link", "Could not parse that URL.");
    }
  }

  // Either pane (browse or search) can hit the auth error — share one
  // detector + recovery panel so an expired token always routes the user
  // to Settings, regardless of which call surfaced the error.
  const browseOrSearchError = inSearchMode
    ? ((search.error as Error | null)?.message ?? null)
    : ((browse.error as Error | null)?.message ?? null);
  const looksLikeAuth =
    browseOrSearchError != null &&
    /401|403|unauthorized|forbidden|AADSTS|token|sign[- ]?in|expired|invalid_grant/i.test(
      browseOrSearchError,
    );

  return (
    <>
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Cloud className="h-5 w-5" />
            Browse SharePoint
          </DialogTitle>
          <DialogDescription>
            This is a <strong>preview</strong> of what's in SharePoint — nothing
            is downloaded or ingested until you click an <strong>Ingest</strong>{" "}
            button. Drill into a subfolder, or use the search box to find files
            by name across the scan root.
          </DialogDescription>
        </DialogHeader>

        <div className="grid grid-cols-[200px_1fr] gap-4 min-h-[400px]">
          {/* Priority links sidebar */}
          <aside className="border-r pr-3 space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground uppercase tracking-wide">
              <Star className="h-3 w-3" />
              Jump to…
            </div>
            {priorityLinks.isLoading && (
              <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
            )}
            {!priorityLinks.isLoading &&
              (priorityLinks.data?.links?.length ?? 0) === 0 && (
                <p className="text-xs text-muted-foreground">
                  No bookmarks yet. Add some in Settings → SharePoint.
                </p>
              )}
            <ul className="space-y-1">
              {priorityLinks.data?.links?.map((link) => (
                <li key={link.url}>
                  <button
                    type="button"
                    onClick={() => applyPriorityLink(link.url)}
                    className="w-full rounded px-2 py-1 text-left text-xs hover:bg-accent truncate"
                    title={link.url}
                  >
                    {link.label || link.url}
                  </button>
                </li>
              ))}
            </ul>
          </aside>

          {/* Main pane */}
          <div className="flex flex-col gap-3 min-w-0">
            {signInGuidance ? (
              <div className="flex flex-col items-center justify-center gap-3 rounded border border-warning/40 bg-warning/5 p-8 text-center min-h-[300px]">
                <LogIn className="h-8 w-8 text-warning" />
                <div className="space-y-1">
                  <p className="text-sm font-medium">
                    Sign in to SharePoint first
                  </p>
                  <p className="text-xs text-muted-foreground max-w-sm">
                    {signInGuidance}
                  </p>
                </div>
                <Button asChild size="sm" onClick={() => onOpenChange(false)}>
                  <Link to="/settings?tab=connectors">
                    Open Settings → SharePoint
                  </Link>
                </Button>
              </div>
            ) : (
              <>
                {/* Search row — always visible. Enter or click runs the
                    search; clearing the input + clicking X returns to
                    browse mode. */}
                <div className="flex items-center gap-2">
                  <div className="relative flex-1">
                    <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground pointer-events-none" />
                    <Input
                      autoFocus
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          runSearch();
                        }
                      }}
                      placeholder="Filename search — control IDs (AC-2), USD doc numbers, or keywords"
                      className="pl-7 pr-7 h-8 text-sm"
                    />
                    {searchQuery && (
                      <button
                        type="button"
                        onClick={clearSearch}
                        className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded p-0.5 hover:bg-accent"
                        title="Clear search"
                      >
                        <X className="h-3.5 w-3.5 text-muted-foreground" />
                      </button>
                    )}
                  </div>
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={runSearch}
                    disabled={!searchQuery.trim() || search.isPending}
                    className="h-8"
                  >
                    {search.isPending ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <Search className="h-3.5 w-3.5" />
                    )}
                    Search
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => setSweepOpen(true)}
                    disabled={!effectiveWorkbookId && !pendingSystemContextId}
                    className="h-8"
                    title={
                      effectiveWorkbookId
                        ? "Score every file in the scan root against this workbook's boundary, then pick the ones to ingest"
                        : pendingSystemContextId
                          ? "Score files against your pending boundary scope (host tokens from boundary docs you've dropped so far)"
                          : "Open a workbook or add boundary docs on the Sweep page first."
                    }
                  >
                    <Scan className="h-3.5 w-3.5" />
                    Sweep for boundary…
                    {!effectiveWorkbookId && pendingSystemContextId && (
                      <span className="ml-1 rounded bg-warning/15 text-warning-foreground px-1 py-0.5 text-[9px] font-medium uppercase tracking-wide">
                        pending
                      </span>
                    )}
                  </Button>
                  {/* Inline per-sweep time cap. Default off → unlimited.
                      Checking the box reveals a "minutes" input; value is
                      forwarded through SweepTriageDialog → SweepBody.
                      time_cap_seconds (converted min→sec). When tripped,
                      in-flight LLM calls finish and the rest of the
                      candidates fall back to keyword-only scoring — sweep
                      always returns a ranked list, never an error. */}
                  <label
                    className="flex items-center gap-1.5 text-xs text-muted-foreground select-none whitespace-nowrap"
                    title="Wall-clock ceiling on the LLM judge for this sweep. Unchecked = unlimited (default). When the cap trips, remaining candidates are scored with keywords only."
                  >
                    <input
                      type="checkbox"
                      className="h-3.5 w-3.5 rounded border-input"
                      checked={sweepTimeCapEnabled}
                      onChange={(e) => setSweepTimeCapEnabled(e.target.checked)}
                    />
                    Stop after
                    <input
                      type="number"
                      min="1"
                      step="1"
                      value={sweepTimeCapMin}
                      onChange={(e) => setSweepTimeCapMin(e.target.value)}
                      disabled={!sweepTimeCapEnabled}
                      className="h-7 w-12 rounded border bg-background px-1.5 text-xs disabled:opacity-50"
                    />
                    min
                  </label>
                  {/* Inline per-sweep dollar cap. Pre-fills from the saved
                      default in Settings → SharePoint sweep — LLM judge.
                      Unchecked = unlimited for this run; checked = forward
                      as cost_cap_usd. Same graceful degrade as time cap. */}
                  <label
                    className="flex items-center gap-1.5 text-xs text-muted-foreground select-none whitespace-nowrap"
                    title="Per-sweep dollar ceiling for the LLM judge. Pre-fills from your saved default in Settings. Unchecked = unlimited for this run."
                  >
                    <input
                      type="checkbox"
                      className="h-3.5 w-3.5 rounded border-input"
                      checked={sweepCostCapEnabled}
                      onChange={(e) => setSweepCostCapEnabled(e.target.checked)}
                    />
                    Stop at $
                    <input
                      type="number"
                      min="0"
                      step="0.10"
                      value={sweepCostCapUsd}
                      onChange={(e) => setSweepCostCapUsd(e.target.value)}
                      disabled={!sweepCostCapEnabled}
                      className="h-7 w-16 rounded border bg-background px-1.5 text-xs disabled:opacity-50"
                    />
                  </label>
                </div>

                {!inSearchMode && (
                  <>
                    {/* Breadcrumb */}
                    <div className="flex items-center gap-1 text-sm border-b pb-2 flex-wrap">
                      <button
                        type="button"
                        onClick={() => setSubfolder("")}
                        className="flex items-center gap-1 hover:underline text-muted-foreground"
                        title={`Scan root: ${effectiveScanRoot || "(library root)"}`}
                      >
                        <Home className="h-3.5 w-3.5" />
                        {effectiveScanRoot || "library root"}
                      </button>
                      {breadcrumbs.map((bc) => (
                        <span key={bc.path} className="flex items-center gap-1">
                          <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
                          <button
                            type="button"
                            onClick={() => setSubfolder(bc.path)}
                            className="hover:underline"
                          >
                            {bc.label}
                          </button>
                        </span>
                      ))}
                      <Button
                        variant="ghost"
                        size="sm"
                        className="ml-auto h-7"
                        onClick={() =>
                          browse.mutate({
                            site_url: spStatus.data?.site_url ?? "",
                            library: spStatus.data?.library ?? "",
                            folder_path: effectiveScanRoot,
                            subfolder,
                          })
                        }
                        disabled={browse.isPending}
                        title="Refresh"
                      >
                        <RefreshCw
                          className={`h-3.5 w-3.5 ${browse.isPending ? "animate-spin" : ""}`}
                        />
                      </Button>
                    </div>

                    {/* Preview banner — make clear the listing is read-only until Ingest */}
                    {browse.isSuccess &&
                      browse.data &&
                      (browse.data.files.length > 0 ||
                        browse.data.folders.length > 0) && (
                        <div className="rounded border border-info/40 bg-info/5 px-3 py-2 text-xs text-muted-foreground">
                          <strong className="text-foreground">Preview only.</strong>{" "}
                          The items below exist in this SharePoint folder — none are queued
                          or ingested yet. Click <strong>Ingest this folder</strong> at the
                          bottom to walk this scope and pull supported files into the local
                          evidence store.
                        </div>
                      )}
                  </>
                )}

                {inSearchMode && (
                  /* Verification banner — filename match is a heuristic, the
                     assessor still owns the applicability call. */
                  <div className="rounded border border-warning/40 bg-warning/5 px-3 py-2 text-xs">
                    <strong className="text-foreground">
                      Filename match only.
                    </strong>{" "}
                    <span className="text-muted-foreground">
                      Verify each file is actually applicable to your control
                      before ingesting. These are heuristic hits, not control
                      mappings.
                    </span>
                  </div>
                )}

                {/* Result area — browse listing OR search results */}
                <div className="flex-1 overflow-y-auto rounded border min-h-[300px] max-h-[400px]">
                  {(inSearchMode ? search.isPending : browse.isPending) && (
                    <div className="flex items-center justify-center h-32 text-sm text-muted-foreground">
                      <Loader2 className="h-4 w-4 animate-spin mr-2" />
                      Loading…
                    </div>
                  )}

                  {browseOrSearchError && looksLikeAuth && (
                    <div className="flex flex-col items-center justify-center gap-3 p-6 text-center">
                      <LogIn className="h-6 w-6 text-warning" />
                      <div className="space-y-1">
                        <p className="text-sm font-medium">
                          SharePoint sign-in looks expired
                        </p>
                        <p className="text-xs text-muted-foreground max-w-sm">
                          Your saved token didn't work. Sign in again from
                          Settings → SharePoint, then reopen this dialog.
                        </p>
                        <p className="text-[10px] text-muted-foreground/70 font-mono pt-2 break-all">
                          {browseOrSearchError}
                        </p>
                      </div>
                      <Button asChild size="sm" onClick={() => onOpenChange(false)}>
                        <Link to="/settings?tab=connectors">
                          Open Settings → SharePoint
                        </Link>
                      </Button>
                    </div>
                  )}
                  {browseOrSearchError && !looksLikeAuth && (
                    <div className="p-4 text-sm text-destructive">
                      {browseOrSearchError}
                    </div>
                  )}

                  {/* Browse mode result list */}
                  {!inSearchMode && browse.isSuccess && browse.data && (
                    <ul className="divide-y">
                      {browse.data.folders.length === 0 &&
                        browse.data.files.length === 0 && (
                          <li className="p-4 text-sm text-muted-foreground text-center">
                            Empty folder
                          </li>
                        )}
                      {browse.data.folders.map((f) => (
                        <li
                          key={f.path}
                          className="flex items-center gap-2 px-3 py-1.5 hover:bg-accent cursor-pointer"
                          onClick={() => setSubfolder(f.path)}
                        >
                          <Folder className="h-4 w-4 text-blue-500 shrink-0" />
                          <span className="text-sm flex-1 truncate">{f.name}</span>
                          {f.child_count > 0 && (
                            <span className="text-xs text-muted-foreground">
                              {f.child_count} item{f.child_count === 1 ? "" : "s"}
                            </span>
                          )}
                          <ChevronRight className="h-4 w-4 text-muted-foreground" />
                        </li>
                      ))}
                      {browse.data.files.map((file) => (
                        <li
                          key={file.path}
                          className={`flex items-center gap-2 px-3 py-1.5 ${
                            file.ingestible ? "" : "opacity-50"
                          }`}
                          title={
                            file.ingestible
                              ? "Would be ingested if you click Ingest this folder"
                              : "File type not supported — would be skipped on ingest"
                          }
                        >
                          <FileText className="h-4 w-4 text-muted-foreground shrink-0" />
                          <span className="text-sm flex-1 truncate">{file.name}</span>
                          <span className="text-xs text-muted-foreground tabular-nums">
                            {formatBytes(file.size)}
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}

                  {/* Search mode result list — flat, folder-grouped, with checkboxes */}
                  {inSearchMode && search.isSuccess && search.data && (
                    <>
                      {search.data.matches.length === 0 ? (
                        <div className="p-6 text-sm text-muted-foreground text-center">
                          No files matched <strong>{activeQuery}</strong>. Try
                          fewer or different terms, or widen the scan root in
                          Settings → SharePoint.
                        </div>
                      ) : (
                        <div>
                          {hitsByFolder.map(([folder, hits]) => (
                            <div key={folder || "__root__"}>
                              <div className="bg-muted/40 px-3 py-1 text-[11px] font-medium text-muted-foreground uppercase tracking-wide flex items-center gap-1">
                                <Folder className="h-3 w-3" />
                                {folder || "(scan root)"}
                                <span className="ml-auto normal-case tracking-normal">
                                  {hits.length} hit{hits.length === 1 ? "" : "s"}
                                </span>
                              </div>
                              <ul className="divide-y">
                                {hits.map((hit) => {
                                  const checked = selectedPaths.has(hit.path);
                                  const disabled = !hit.ingestible;
                                  return (
                                    <li
                                      key={hit.path}
                                      className={`flex items-center gap-2 px-3 py-1.5 ${
                                        disabled
                                          ? "opacity-50"
                                          : "hover:bg-accent cursor-pointer"
                                      }`}
                                      onClick={() => {
                                        if (!disabled) toggleSelected(hit.path);
                                      }}
                                      title={
                                        disabled
                                          ? "File type not supported — cannot ingest"
                                          : hit.path
                                      }
                                    >
                                      <input
                                        type="checkbox"
                                        checked={checked}
                                        disabled={disabled}
                                        onChange={() => toggleSelected(hit.path)}
                                        onClick={(e) => e.stopPropagation()}
                                        className="h-3.5 w-3.5 shrink-0"
                                      />
                                      <FileText className="h-4 w-4 text-muted-foreground shrink-0" />
                                      <span className="text-sm flex-1 truncate">
                                        {hit.name}
                                      </span>
                                      <div className="flex items-center gap-1 shrink-0">
                                        {hit.matched_terms.map((term) => (
                                          <span
                                            key={term}
                                            className="rounded bg-info/15 text-info-foreground px-1.5 py-0.5 text-[10px] font-medium"
                                            title={`Matched: ${term}`}
                                          >
                                            {term}
                                          </span>
                                        ))}
                                      </div>
                                      <span className="text-xs text-muted-foreground tabular-nums w-16 text-right">
                                        {formatBytes(hit.size)}
                                      </span>
                                    </li>
                                  );
                                })}
                              </ul>
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  )}
                </div>

                {/* Status / counts line below the list */}
                <div className="text-xs text-muted-foreground flex items-center gap-3">
                  {!inSearchMode && browse.data && (
                    <span>
                      Found {browse.data.folders.length} folder
                      {browse.data.folders.length === 1 ? "" : "s"} ·{" "}
                      {browse.data.files.filter((f) => f.ingestible).length}{" "}
                      file
                      {browse.data.files.filter((f) => f.ingestible).length === 1
                        ? ""
                        : "s"}{" "}
                      would be ingested
                      {browse.data.files.filter((f) => !f.ingestible).length >
                        0 && (
                        <>
                          {" "}·{" "}
                          {browse.data.files.filter((f) => !f.ingestible).length}{" "}
                          would be skipped (unsupported type)
                        </>
                      )}
                      {" "}if you click <em>Ingest this folder</em>.
                    </span>
                  )}
                  {inSearchMode && search.data && (
                    <>
                      <span>
                        {search.data.matches.length} hit
                        {search.data.matches.length === 1 ? "" : "s"} across{" "}
                        {search.data.scanned_folders} folder
                        {search.data.scanned_folders === 1 ? "" : "s"}
                        {search.data.truncated && (
                          <span className="text-warning ml-1">
                            (truncated — narrow your search)
                          </span>
                        )}
                        {selectedPaths.size > 0 && (
                          <>
                            {" · "}
                            <strong className="text-foreground">
                              {selectedPaths.size} selected
                            </strong>
                          </>
                        )}
                      </span>
                      {search.data.matches.length > 0 && (
                        <button
                          type="button"
                          onClick={selectAllVisible}
                          className="ml-auto text-xs hover:underline"
                        >
                          Select all ingestible
                        </button>
                      )}
                    </>
                  )}
                </div>
              </>
            )}
          </div>
        </div>

        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={ingest.isPending}
          >
            Cancel
          </Button>
          {inSearchMode ? (
            <Button
              onClick={startSearchIngest}
              disabled={
                ingest.isPending ||
                selectedPaths.size === 0 ||
                !search.isSuccess
              }
              title={
                selectedPaths.size === 0
                  ? "Check at least one file to ingest"
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
          ) : (
            <Button
              onClick={startBrowseIngest}
              disabled={ingest.isPending || !browse.isSuccess}
              title={`Walk ${[effectiveScanRoot, subfolder].filter(Boolean).join("/") || "library root"} and ingest every supported file`}
            >
              {ingest.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Cloud className="h-4 w-4" />
              )}
              Ingest this folder
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>

    {/* Sweep dialog stacks on top of the browse dialog. Pass the *effective*
        scan root (priority-link overrides included) so the sweep walks the
        same scope the assessor is currently looking at, not the saved
        default.

        Workbook mode wins when both are available; pending mode is the
        fallback when no workbook is open. The button above is dual-disabled
        when neither is set, so the SweepTriageDialog is only mounted when
        we can construct a valid scope. */}
    {(effectiveWorkbookId || pendingSystemContextId) && (
      <SweepTriageDialog
        open={sweepOpen}
        onOpenChange={setSweepOpen}
        scope={
          effectiveWorkbookId
            ? { kind: "workbook", workbookId: effectiveWorkbookId }
            : { kind: "pending", systemContextId: pendingSystemContextId! }
        }
        folderPath={effectiveScanRoot}
        timeCapSeconds={
          sweepTimeCapEnabled && Number(sweepTimeCapMin) > 0
            ? Number(sweepTimeCapMin) * 60
            : undefined
        }
        costCapUsd={
          sweepCostCapEnabled && Number(sweepCostCapUsd) > 0
            ? Number(sweepCostCapUsd)
            : undefined
        }
        onIngestStart={(label, jobId) => {
          onIngestStart?.(label, jobId);
          // Close the parent browse dialog too — the sweep dialog itself
          // closes on success via its own onIngestStart, but the underlying
          // BrowseSharePointDialog stays open otherwise, which is confusing
          // (the user clicked Ingest, they expect both to close).
          onOpenChange(false);
        }}
      />
    )}
    </>
  );
}

function formatBytes(bytes: number | null): string {
  if (bytes == null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  if (mb < 1024) return `${mb.toFixed(1)} MB`;
  return `${(mb / 1024).toFixed(2)} GB`;
}
