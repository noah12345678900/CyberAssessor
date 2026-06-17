import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle,
  ChevronDown,
  Cloud,
  Database,
  FileText,
  FolderPlus,
  GitBranch,
  Loader2,
  Network,
  Radar,
  ScrollText,
  ShieldCheck,
  Ticket,
  Trash2,
} from "lucide-react";

import { BrowseSharePointDialog } from "@/components/BrowseSharePointDialog";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
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
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "@/components/ui/toaster";
import { humanize } from "@/lib/errors";
import {
  useClearEvidence,
  useCrosscheck,
  useDeleteEvidence,
  useEvidence,
  useSetAssetList,
  useSettings,
  useSharePointStatus,
  useTenableStatus,
  useWorkbooks,
} from "@/lib/queries";
import { useIngestJobContext } from "@/contexts/IngestJobContext";
import {
  hasNativeBridge,
  type CoverageHost,
  type CoverageSource,
  type Evidence as EvidenceArtifact,
  type HostCoverage,
} from "@/lib/api";

// UI-only cap on hostnames rendered per gap section. The full host list is
// still cached in React Query and the LLM prompt block (capped separately in
// the backend at MAX_HOSTS_IN_BLOCK) — this only keeps the card scannable
// when a scan returns hundreds of unknown hosts.
const MAX_HOSTS_IN_PANEL = 25;

// Kinds whose host enumeration is auto-derived from the artifact itself —
// no manual flag needed, and the "Declared inventory" toggle would be
// misleading. STIG checklists and Nessus scans land here.
const AUTO_DERIVED_KINDS = new Set<string>([
  "nessus",
  "stig_ckl",
  "stig_cklb",
  "stig_xccdf",
]);

// Declared inventories only come via spreadsheet — any Excel format plus CSV.
// Used to gate the "Declared inventory" toggle; the backend rejects the flag
// on artifacts that aren't one of these extensions too.
const INVENTORY_EXTS = [".xlsx", ".xlsm", ".xls", ".csv"];
function isInventoryFile(filename: string | null | undefined): boolean {
  if (!filename) return false;
  const lower = filename.toLowerCase();
  return INVENTORY_EXTS.some((ext) => lower.endsWith(ext));
}

export function Evidence() {
  // ``evidence`` is declared further down, after ``activeWorkbookId`` resolves,
  // so the list query can be scoped to the open workbook.
  // Ingest is fire-and-poll, and its state now lives in <IngestJobProvider>
  // (mounted in the App shell) so the job — its 1s poll, mount re-adoption,
  // and done/error toasts — survives navigating away from this page. The
  // global <IngestProgressStrip> renders the live counter + ETA on every
  // route, so this page no longer reads the live ``job`` snapshot itself.
  // Here we just consume the context: ``lastSummary``/``lastFolder`` back the
  // "Last ingest" card, ``isIngesting`` disables the kickoff buttons, and the
  // ingestFolder/adoptJob/reset actions drive the kickoff handlers.
  const {
    lastFolder,
    lastSummary,
    isIngesting,
    ingestFolder,
    adoptJob,
    reset: resetIngest,
  } = useIngestJobContext();
  const spStatus = useSharePointStatus();
  const tenableStatus = useTenableStatus();
  // Connector master switch lives in Settings → Connectors (features.sharepoint).
  // When the user flips this OFF, hide the SharePoint button entirely instead
  // of leaving a "Configure SharePoint…" CTA that contradicts the disabled
  // connector. Same flag the Sidebar uses to hide the Sweep Context tab.
  const settings = useSettings();
  const features = settings.data?.features;
  const sharepointEnabled = features?.sharepoint ?? false;
  const tenableEnabled = features?.tenable ?? false;
  const splunkEnabled = features?.splunk ?? false;
  const gitlabEnabled = features?.gitlab ?? false;
  const confluenceEnabled = features?.confluence ?? false;
  const jiraEnabled = features?.jira ?? false;
  const emassEnabled = features?.emass ?? false;
  const servicenowEnabled = features?.servicenow_grc ?? false;
  const archerEnabled = features?.archer ?? false;
  const boundarySweepEnabled = features?.boundary_sweep ?? false;
  const [error, setError] = useState<string | null>(null);
  const [manualFolder, setManualFolder] = useState("");
  const [confirmClearOpen, setConfirmClearOpen] = useState(false);
  // Row pending per-row delete confirmation. Null = no dialog open.
  // Holding the whole artifact (not just the id) lets the dialog render
  // the filename without a follow-up lookup.
  const [confirmDeleteRow, setConfirmDeleteRow] = useState<EvidenceArtifact | null>(null);
  const [browseSpOpen, setBrowseSpOpen] = useState(false);
  const [crosscheckOpen, setCrosscheckOpen] = useState(true);
  const nativeBridge = hasNativeBridge();
  // ``evidenceCount`` is computed after the useEvidence() call below.

  // The cross-check endpoint takes a workbook_id even though v0.1 backend
  // ignores it (asset-list selection isn't scoped per workbook yet). Pick
  // the most-recently-opened workbook so the panel has *something* to ask
  // about — when no workbook exists at all, the hook stays disabled and
  // the panel won't render.
  const workbooks = useWorkbooks();
  // The workbooks list endpoint already orders by ``last_opened DESC`` and
  // ``openWorkbook`` bumps that timestamp, so ``data[0]`` IS the currently-open
  // workbook — the same single source of truth Controls.tsx defaults to. Don't
  // re-sort client-side: a null ``last_opened`` made the old localeCompare
  // unstable and could surface a different workbook than the rest of the app.
  const activeWorkbookId = workbooks.data?.[0]?.id;

  // Evidence is hard-bound at ingest to the open workbook, and the list is
  // scoped to that workbook on the server (strict ``workbook_id`` equality —
  // NULL-workbook rows never leak in). There is deliberately NO scope selector:
  // the open workbook IS the scope, and you switch systems by opening a
  // different workbook on the Workbooks page. Every artifact in the open
  // workbook renders here, tagged or not.
  const evidence = useEvidence({
    workbookId: activeWorkbookId,
  });
  const evidenceCount = evidence.data?.length ?? 0;
  const crosscheck = useCrosscheck(activeWorkbookId);
  const setAssetList = useSetAssetList({
    onError: (err) => toast.error("Couldn't update asset-list flag", humanize(err)),
  });

  // Enable the SharePoint ingest button only when the user has signed in
  // (token cache exists) AND a site URL is saved — otherwise the call would
  // just fail with a config error. Tooltip explains why it's disabled.
  const spConfigured = !!spStatus.data?.configured;
  const spSignedIn = !!spStatus.data?.token_cache_exists;
  const spSiteUrl = spStatus.data?.site_url ?? "";
  const spReady = spConfigured && spSignedIn && !!spSiteUrl;
  const spDisabledReason = !spConfigured
    ? "SharePoint not configured — paste tenant/client/site in Settings → SharePoint"
    : !spSignedIn
      ? "Not signed in — open Settings → SharePoint and click Sign in"
      : !spSiteUrl
        ? "No SharePoint site URL saved — open Settings → SharePoint"
        : null;

  // Tenable readiness — keyset + flavor + (host if sc). Same configured/
  // disabled-reason split as SharePoint so the button renders parallel.
  const tenableConfigured = !!tenableStatus.data?.configured;
  const tenableDisabledReason = tenableConfigured
    ? null
    : "Tenable not configured — pick a flavor and save API keys in Settings → Tenable";

  const clear = useClearEvidence({
    onSuccess: (res) => {
      setConfirmClearOpen(false);
      // The "Last ingest" card below is driven by context state, not by a
      // cache key — invalidateQueries can't reach it. Reset the ingest
      // context (clears mutation + lastFolder + lastSummary) so the stats
      // card vanishes the moment the clear lands, instead of lingering with
      // pre-clear scanned/ingested numbers until the user reloads.
      resetIngest();
      toast.success(
        "Evidence cleared",
        `Removed ${res.evidence_removed} artifact${res.evidence_removed === 1 ? "" : "s"}, ${res.tags_removed} tag${res.tags_removed === 1 ? "" : "s"}, ${res.findings_removed} STIG finding${res.findings_removed === 1 ? "" : "s"}${res.text_files_removed ? ` · ${res.text_files_removed} cached text file${res.text_files_removed === 1 ? "" : "s"}` : ""}.`,
      );
    },
    onError: (err) => toast.error("Clear failed", humanize(err)),
  });

  const deleteOne = useDeleteEvidence({
    onSuccess: (res) => {
      setConfirmDeleteRow(null);
      const parts = [`Removed 1 artifact`];
      if (res.tags_removed) {
        parts.push(`${res.tags_removed} tag${res.tags_removed === 1 ? "" : "s"}`);
      }
      if (res.findings_removed) {
        parts.push(
          `${res.findings_removed} STIG finding${res.findings_removed === 1 ? "" : "s"}`,
        );
      }
      if (res.poam_links_removed) {
        parts.push(
          `${res.poam_links_removed} POAM link${res.poam_links_removed === 1 ? "" : "s"}`,
        );
      }
      toast.success("Evidence deleted", `${parts.join(", ")}.`);
    },
    onError: (err) => toast.error("Delete failed", humanize(err)),
  });

  async function pickAndIngest() {
    setError(null);
    // Evidence is hard-scoped to the open workbook (PR 2): without one the
    // backend would reject the ingest. Guard here so the user gets a clear
    // "open a workbook first" message instead of a crashed daemon thread.
    if (activeWorkbookId == null) {
      toast.error(
        "No workbook open",
        "Open a workbook from the Catalogs screen before ingesting evidence.",
      );
      return;
    }
    if (!nativeBridge) {
      toast.error(
        "Native folder picker unavailable",
        "Running in a browser, not Electron. Paste a folder path below, or launch with `pnpm electron:dev`.",
      );
      return;
    }
    const folder = await window.ccis!.openFolder();
    if (!folder) return; // user cancelled
    try {
      await ingestFolder({ folder, workbookId: activeWorkbookId, recursive: true });
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function ingestManualFolder() {
    setError(null);
    if (activeWorkbookId == null) {
      toast.error(
        "No workbook open",
        "Open a workbook from the Catalogs screen before ingesting evidence.",
      );
      return;
    }
    const folder = manualFolder.trim();
    if (!folder) {
      toast.error("Path required", "Paste an absolute folder path to ingest.");
      return;
    }
    try {
      await ingestFolder({ folder, workbookId: activeWorkbookId, recursive: true });
      setManualFolder("");
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className="p-8 space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Evidence</h1>
          <p className="text-sm text-muted-foreground">
            Ingested artifacts available for objective tagging. Doc-number and family-keyword
            tagging runs as part of ingest.
          </p>
          {/* Read-only scope indicator — NOT a picker. Evidence is hard-bound at
              ingest to whatever workbook is open, and this list shows only that
              workbook's artifacts. Switch systems by opening a workbook on the
              Workbooks page. */}
          <p className="mt-2 text-sm">
            <span className="text-muted-foreground">Workbook open: </span>
            <span className="font-medium">
              {workbooks.data?.find((w) => w.id === activeWorkbookId)?.filename ??
                "No workbook open — open one to ingest and view evidence"}
            </span>
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => setConfirmClearOpen(true)}
            disabled={clear.isPending || isIngesting || evidenceCount === 0}
            className="text-destructive hover:text-destructive"
            title={
              isIngesting
                ? "Wait for the in-flight ingest to finish — DELETE shares the same SQLite writer"
                : evidenceCount === 0
                  ? "Nothing to clear"
                  : `Wipe all ${evidenceCount} indexed artifacts`
            }
          >
            {clear.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Trash2 className="h-4 w-4" />
            )}
            Clear evidence
          </Button>
          {/* Stacked ingest control: one button, one source per enabled
              connector. Items appear/disappear with their Settings →
              Connectors feature flag — Local folder is always present.
              SharePoint carries its real browse action; the not-yet-wired
              connectors route to their Settings card to configure (their
              ingest UI lands in follow-up MRs). */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button disabled={isIngesting || clear.isPending}>
                {isIngesting ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <FolderPlus className="h-4 w-4" />
                )}
                Ingest
                <ChevronDown className="h-4 w-4 opacity-70" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-64">
              <DropdownMenuLabel>Add evidence from…</DropdownMenuLabel>
              <DropdownMenuItem onSelect={() => pickAndIngest()}>
                <FolderPlus className="h-4 w-4" />
                Local folder…
              </DropdownMenuItem>
              {sharepointEnabled && (
                spDisabledReason ? (
                  <DropdownMenuItem asChild>
                    <Link to="/settings?tab=connectors" title={spDisabledReason}>
                      <Cloud className="h-4 w-4" />
                      Configure SharePoint…
                    </Link>
                  </DropdownMenuItem>
                ) : (
                  <DropdownMenuItem
                    disabled={!spReady}
                    onSelect={() => setBrowseSpOpen(true)}
                  >
                    <Cloud className="h-4 w-4" />
                    Browse SharePoint…
                  </DropdownMenuItem>
                )
              )}
              {tenableEnabled && (
                tenableDisabledReason ? (
                  <DropdownMenuItem asChild>
                    <Link to="/settings?tab=connectors" title={tenableDisabledReason}>
                      <Radar className="h-4 w-4" />
                      Configure Tenable…
                    </Link>
                  </DropdownMenuItem>
                ) : (
                  <DropdownMenuItem
                    disabled
                    title="Tenable scan ingest UI lands in a follow-up MR — credentials are saved and the source spec is wired into /api/evidence/ingest."
                  >
                    <Radar className="h-4 w-4" />
                    Pull Tenable scans…
                  </DropdownMenuItem>
                )
              )}
              {splunkEnabled && (
                <DropdownMenuItem asChild>
                  <Link to="/settings?tab=connectors">
                    <Database className="h-4 w-4" />
                    Configure Splunk…
                  </Link>
                </DropdownMenuItem>
              )}
              {gitlabEnabled && (
                <DropdownMenuItem asChild>
                  <Link to="/settings?tab=connectors">
                    <GitBranch className="h-4 w-4" />
                    Configure GitLab…
                  </Link>
                </DropdownMenuItem>
              )}
              {confluenceEnabled && (
                <DropdownMenuItem asChild>
                  <Link to="/settings?tab=connectors">
                    <FileText className="h-4 w-4" />
                    Configure Confluence…
                  </Link>
                </DropdownMenuItem>
              )}
              {jiraEnabled && (
                <DropdownMenuItem asChild>
                  <Link to="/settings?tab=connectors">
                    <Ticket className="h-4 w-4" />
                    Configure Jira…
                  </Link>
                </DropdownMenuItem>
              )}
              {emassEnabled && (
                <DropdownMenuItem asChild>
                  <Link to="/settings?tab=connectors">
                    <ShieldCheck className="h-4 w-4" />
                    Configure eMASS…
                  </Link>
                </DropdownMenuItem>
              )}
              {servicenowEnabled && (
                <DropdownMenuItem asChild>
                  <Link to="/settings?tab=connectors">
                    <ScrollText className="h-4 w-4" />
                    Configure ServiceNow GRC…
                  </Link>
                </DropdownMenuItem>
              )}
              {archerEnabled && (
                <DropdownMenuItem asChild>
                  <Link to="/settings?tab=connectors">
                    <ScrollText className="h-4 w-4" />
                    Configure Archer…
                  </Link>
                </DropdownMenuItem>
              )}
              {boundarySweepEnabled && (
                <DropdownMenuItem asChild>
                  <Link to="/settings?tab=connectors">
                    <Network className="h-4 w-4" />
                    Configure boundary sweep…
                  </Link>
                </DropdownMenuItem>
              )}
              <DropdownMenuSeparator />
              <DropdownMenuItem asChild>
                <Link to="/settings?tab=connectors">
                  <Network className="h-4 w-4" />
                  Manage connectors…
                </Link>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </header>

      <Dialog open={confirmClearOpen} onOpenChange={setConfirmClearOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Clear all evidence?</DialogTitle>
            <DialogDescription>
              Removes <strong>{evidenceCount}</strong> ingested artifact
              {evidenceCount === 1 ? "" : "s"} plus every tag and STIG finding
              linked to them. Cached extracted text on disk is deleted too.
              <br />
              <br />
              Workbooks, assessments, the catalog, and program-controls overlays
              are <em>not</em> touched — re-ingest the source folder to repopulate.
              This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setConfirmClearOpen(false)}
              disabled={clear.isPending}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => clear.mutate()}
              disabled={clear.isPending}
            >
              {clear.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Trash2 className="h-4 w-4" />
              )}
              Clear evidence
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={confirmDeleteRow !== null}
        onOpenChange={(open) => {
          if (!open) setConfirmDeleteRow(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete this evidence row?</DialogTitle>
            <DialogDescription>
              Removes <strong>{confirmDeleteRow?.filename}</strong> from the
              evidence index along with every tag, STIG finding, and POAM
              link pointing at it. Any other artifact superseded by this row
              gets its supersession back-pointer nulled. Cached extracted
              text on disk is deleted too.
              <br />
              <br />
              Workbooks, assessments, the catalog, and program-controls
              overlays are <em>not</em> touched. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setConfirmDeleteRow(null)}
              disabled={deleteOne.isPending}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => {
                if (confirmDeleteRow) {
                  deleteOne.mutate({ id: confirmDeleteRow.id });
                }
              }}
              disabled={deleteOne.isPending || !confirmDeleteRow}
            >
              {deleteOne.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Trash2 className="h-4 w-4" />
              )}
              Delete evidence
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {sharepointEnabled && (
        <BrowseSharePointDialog
          open={browseSpOpen}
          onOpenChange={setBrowseSpOpen}
          onIngestStart={(label, jobId) =>
            // Adopt the job_id into the shared context so the global progress
            // strip lights up on the same tick the dialog closes — no wait for
            // ``useActiveIngestJob`` to refetch.
            adoptJob(jobId, label)
          }
          workbookId={activeWorkbookId}
        />
      )}

      {!nativeBridge && (
        <Card className="border-warning/40 bg-warning/5">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <AlertTriangle className="h-4 w-4 text-warning" />
              Running outside Electron — native folder picker disabled
            </CardTitle>
            <CardDescription>
              Paste an absolute folder path to ingest, or launch with{" "}
              <code>pnpm electron:dev</code> for the OS folder dialog.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex gap-2">
              <Input
                placeholder="C:\Users\Noah.Jaskolski\Downloads\local_snapshot\"
                value={manualFolder}
                onChange={(e) => setManualFolder(e.target.value)}
                className="font-mono text-xs"
                onKeyDown={(e) => {
                  if (e.key === "Enter") ingestManualFolder();
                }}
              />
              <Button
                onClick={ingestManualFolder}
                disabled={isIngesting || clear.isPending || !manualFolder.trim()}
              >
                {isIngesting ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <FolderPlus className="h-4 w-4" />
                )}
                Ingest path
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {error && (
        <Card className="border-destructive">
          <CardContent className="pt-6 text-sm text-destructive">{error}</CardContent>
        </Card>
      )}

      {/* Live progress UI is now the global <IngestProgressStrip /> mounted in
          the App shell (above <Routes>), so it survives route changes — drop
          boundary docs, then navigate to Baselines/Controls while the walk
          runs and the strip stays pinned to the top with a live counter + ETA.
          The page-local card was removed when the state was hoisted into
          IngestJobContext; see contexts/IngestJobContext.tsx. */}

      {(() => {
        // Render the most recent completed summary — snapshotted into
        // ``lastSummary`` when the polling hook saw status="done", so the
        // card survives after the job clears.
        const summary = lastSummary;
        if (!summary || !lastFolder) return null;
        return (
          <Card>
            <CardHeader>
              <CardTitle>Last ingest</CardTitle>
              <CardDescription className="font-mono">{lastFolder}</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4 text-sm">
              <div className="flex flex-wrap gap-4">
                <Stat label="Scanned" value={summary.scanned} />
                <Stat label="Ingested" value={summary.ingested} />
                <Stat label="Skipped" value={summary.skipped_existing} />
                <Stat label="Unmapped" value={summary.untagged?.length ?? 0} />
                <Stat label="Errors" value={summary.errors.length} />
              </div>
              {summary.untagged && summary.untagged.length > 0 && (
                // Files that ingested fine but mapped to ZERO controls. Without
                // this they'd be invisible on every control page — the silent-
                // drop failure mode. Amber (warning), not red (error): the file
                // IS stored, it just needs a control reference or manual tag.
                <details className="rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2">
                  <summary className="cursor-pointer text-sm font-medium text-amber-600">
                    {summary.untagged.length} file{summary.untagged.length === 1 ? "" : "s"} didn't map to any control — review
                  </summary>
                  <ul className="mt-2 space-y-1 text-xs">
                    {summary.untagged.map((u, i) => (
                      <li
                        key={`${u.path}-${i}`}
                        className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 border-t border-amber-500/20 pt-1 first:border-t-0 first:pt-0"
                      >
                        <span
                          className="font-mono truncate text-muted-foreground"
                          title={u.path}
                        >
                          {u.path}
                        </span>
                        <span className="text-amber-600" title={u.reason}>
                          {u.reason}
                        </span>
                      </li>
                    ))}
                  </ul>
                </details>
              )}
              {summary.errors.length > 0 && (
                // <details> over a custom expander: the per-file failure list
                // can run to dozens of rows on a noisy share, so collapsing
                // by default keeps the card scannable while still letting
                // the user inspect specifics without a follow-up API call.
                <details className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2">
                  <summary className="cursor-pointer text-sm font-medium text-destructive">
                    {summary.errors.length} file{summary.errors.length === 1 ? "" : "s"} failed — show details
                  </summary>
                  <ul className="mt-2 space-y-1 text-xs">
                    {summary.errors.map((err, i) => (
                      <li
                        key={`${err.path}-${i}`}
                        className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 border-t border-destructive/20 pt-1 first:border-t-0 first:pt-0"
                      >
                        <span
                          className="font-mono truncate text-muted-foreground"
                          title={err.path}
                        >
                          {err.path}
                        </span>
                        <span className="text-destructive" title={err.error}>
                          {err.error}
                        </span>
                      </li>
                    ))}
                  </ul>
                </details>
              )}
            </CardContent>
          </Card>
        );
      })()}

      {/* Auto-derived asset-coverage panel — renders whenever any scan,
          STIG checklist, or declared inventory has been ingested. The
          underlying report is what the LLM sees for CM-8 / CM-6 / CA-3 /
          CA-7 / PM-5 / RA-5 prompts, so showing it inline is the user-
          facing confirmation that boundary inventory + scan coverage
          will reach the assessor. No more manual asset-list tagging
          required — hosts are pulled from ACAS .nessus ReportHost
          blocks and STIG checklist targets automatically. */}
      {crosscheck.data && crosscheck.data.sources.length > 0 && (
        <Card>
          <CardHeader>
            <button
              type="button"
              onClick={() => setCrosscheckOpen((v) => !v)}
              className="flex w-full items-center justify-between gap-3 text-left"
            >
              <div>
                <CardTitle className="flex items-center gap-2">
                  <Network className="h-4 w-4" />
                  Asset coverage
                  <Badge variant="outline" className="font-mono">
                    {crosscheck.data.totals.union} host
                    {crosscheck.data.totals.union === 1 ? "" : "s"}
                  </Badge>
                </CardTitle>
                <CardDescription>
                  Auto-derived from ACAS scans, STIG checklists, and declared
                  inventories. Gaps surface as findings for CM-8 / CM-6 / CA-3
                  / CA-7 / PM-5 / RA-5.
                </CardDescription>
              </div>
              <span className="text-xs text-muted-foreground">
                {crosscheckOpen ? "Hide" : "Show"}
              </span>
            </button>
          </CardHeader>
          {crosscheckOpen && (
            <CardContent className="space-y-4 text-sm">
              <CoverageTotals totals={crosscheck.data.totals} />
              <CoverageSources sources={crosscheck.data.sources} />
              <CoverageGaps
                gaps={crosscheck.data.gaps}
                hostIndex={crosscheck.data.hosts}
              />
            </CardContent>
          )}
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Indexed evidence</CardTitle>
          <CardDescription>
            {evidence.data?.length ?? 0} artifacts available for objective tagging
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>File</TableHead>
                <TableHead>Title / doc #</TableHead>
                <TableHead>Kind</TableHead>
                <TableHead>Size</TableHead>
                <TableHead>Ingested</TableHead>
                <TableHead title="Mark XLSX/CSV inventories as authoritative declared assets. Scans and STIG checklists are auto-derived.">
                  Declared inventory
                </TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {evidence.data?.map((e) => (
                <TableRow key={e.id}>
                  <TableCell className="font-medium max-w-md truncate" title={e.display_path}>
                    {e.filename}
                  </TableCell>
                  <TableCell className="text-sm">
                    <div>{e.title ?? "—"}</div>
                    {e.doc_number && (
                      <div className="text-xs text-muted-foreground font-mono">{e.doc_number}</div>
                    )}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{e.kind}</Badge>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground tabular-nums">
                    {formatBytes(e.size_bytes)}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {e.ingested_at ? new Date(e.ingested_at).toLocaleString() : "—"}
                  </TableCell>
                  <TableCell>
                    {AUTO_DERIVED_KINDS.has(e.kind) ? (
                      // Nessus + STIG checklists enumerate hosts on their own —
                      // showing a "declared inventory" toggle here would let a
                      // user double-count or silently override the auto-derived
                      // signal. Show a static tag instead.
                      <span
                        className="text-xs text-muted-foreground"
                        title="Hosts auto-derived from this artifact — no manual flag needed"
                      >
                        auto
                      </span>
                    ) : isInventoryFile(e.filename) ? (
                      <AssetListToggle
                        ev={e}
                        onToggle={(is_asset_list, asset_list_label) =>
                          setAssetList.mutate({
                            id: e.id,
                            is_asset_list,
                            asset_list_label,
                          })
                        }
                        disabled={setAssetList.isPending}
                      />
                    ) : (
                      // Declared inventories only come via spreadsheet. A
                      // non-spreadsheet artifact can't be a declared asset list,
                      // so don't offer the toggle (the backend also rejects it).
                      <span
                        className="text-xs text-muted-foreground"
                        title="Declared inventories must be spreadsheets (.xlsx/.xlsm/.xls/.csv)"
                      >
                        —
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="w-10">
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => setConfirmDeleteRow(e)}
                      disabled={isIngesting || clear.isPending || deleteOne.isPending}
                      title={
                        isIngesting
                          ? "Wait for the in-flight ingest to finish — DELETE shares the same SQLite writer"
                          : "Delete this evidence row"
                      }
                      className="text-destructive hover:text-destructive"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
              {evidence.isLoading && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-sm text-muted-foreground py-8">
                    <Loader2 className="inline h-4 w-4 animate-spin mr-2" />
                    Loading evidence…
                  </TableCell>
                </TableRow>
              )}
              {!evidence.isLoading && evidence.data?.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-sm text-muted-foreground py-8">
                    No evidence yet — click <strong>Ingest folder…</strong> to scan one.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

/**
 * Per-row "declared inventory" toggle + inline label input. Only rendered for
 * non-auto-derived kinds (XLSX, CSV, PDF inventories) — Nessus and STIG
 * checklists enumerate their own hosts and don't need a manual flag. When ON,
 * reveals a label input that defaults to the filename and commits on blur —
 * keeps the round-trip count low (one PATCH for the flip, one PATCH on blur
 * if the label actually changed).
 */
function AssetListToggle({
  ev,
  onToggle,
  disabled,
}: {
  ev: EvidenceArtifact;
  onToggle: (is_asset_list: boolean, asset_list_label: string | null) => void;
  disabled: boolean;
}) {
  // Local mirror of the label so typing doesn't fire a PATCH on every keystroke.
  const [label, setLabel] = useState<string>(ev.asset_list_label ?? ev.title ?? ev.filename);
  return (
    <div className="flex flex-col gap-1">
      <label
        className="flex cursor-pointer items-center gap-2 text-xs"
        title="Treat this workbook as an authoritative declared asset inventory (CM-8)"
      >
        <input
          type="checkbox"
          checked={ev.is_asset_list}
          disabled={disabled}
          onChange={(e) => {
            const next = e.target.checked;
            // When flipping ON, send the label we already have queued locally
            // so the coverage report renders with a meaningful name on first load.
            onToggle(next, next ? label : null);
          }}
          className="h-3.5 w-3.5"
        />
        <span className="text-muted-foreground">Declared</span>
      </label>
      {ev.is_asset_list && (
        <Input
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          onBlur={() => {
            // Only PATCH if the label actually changed — avoids a no-op write
            // when the user just clicks into and out of the input.
            const trimmed = label.trim() || ev.filename;
            if (trimmed !== (ev.asset_list_label ?? "")) {
              onToggle(true, trimmed);
            }
          }}
          disabled={disabled}
          placeholder="Label (e.g. Approved HW/SW)"
          className="h-7 text-xs"
        />
      )}
    </div>
  );
}

/**
 * Headline counters across the asset universe. The "union" column is the
 * effective denominator for CM-8 narratives — every host the assessor
 * should expect to see covered somewhere.
 */
function CoverageTotals({
  totals,
}: {
  totals: { scanned: number; checklisted: number; declared: number; union: number };
}) {
  return (
    <div className="flex flex-wrap gap-3">
      <Stat label="Scanned" value={totals.scanned} />
      <Stat label="Checklisted" value={totals.checklisted} />
      <Stat label="Declared" value={totals.declared} />
      <Stat label="Union (all assets)" value={totals.union} />
    </div>
  );
}

/**
 * Source-artifact roll-up grouped by category. Lets the assessor confirm
 * "yes, the ACAS scan I just ingested is the one feeding this panel" before
 * trusting the gap counts below.
 */
function CoverageSources({ sources }: { sources: CoverageSource[] }) {
  const grouped: Record<CoverageSource["category"], CoverageSource[]> = {
    scanned: [],
    checklisted: [],
    declared: [],
  };
  for (const s of sources) {
    grouped[s.category].push(s);
  }
  const sections: Array<{
    key: CoverageSource["category"];
    title: string;
    blurb: string;
  }> = [
    { key: "scanned", title: "Scans", blurb: "ACAS / Nessus — host enumeration is free" },
    {
      key: "checklisted",
      title: "STIG checklists",
      blurb: "CKL / CKLB / XCCDF — target host pulled from the artifact",
    },
    {
      key: "declared",
      title: "Declared inventories",
      blurb: "XLSX / CSV flagged as authoritative",
    },
  ];
  return (
    <div className="space-y-2">
      {sections.map(({ key, title, blurb }) => {
        const items = grouped[key];
        if (items.length === 0) return null;
        return (
          <div key={key} className="rounded-md border px-3 py-2">
            <div className="flex items-baseline justify-between gap-2">
              <div className="text-xs font-medium">{title}</div>
              <div className="text-[10px] text-muted-foreground">{blurb}</div>
            </div>
            <ul className="mt-1 flex flex-wrap gap-1.5 text-xs">
              {items.map((s) => (
                <li key={s.evidence_id}>
                  <Badge
                    variant="outline"
                    className="font-mono"
                    title={`${s.kind} · ${s.host_count} host${s.host_count === 1 ? "" : "s"}`}
                  >
                    <span className="max-w-[26ch] truncate">{s.label}</span>
                    <span className="ml-1 text-muted-foreground">
                      {s.host_count}
                    </span>
                  </Badge>
                </li>
              ))}
            </ul>
          </div>
        );
      })}
    </div>
  );
}

/**
 * Gap roll-up — one block per non-empty coverage state. The "complete" key
 * is intentionally rendered as a count-only line (matching the LLM block,
 * which omits "complete" entirely) since listing matched hosts isn't
 * actionable. Each gapped host gets its applied-STIG list inline so the
 * assessor can see at a glance whether a "checklisted_not_scanned" host is
 * a missed RA-5 target or a host that's deliberately offline.
 */
function CoverageGaps({
  gaps,
  hostIndex,
}: {
  gaps: Partial<Record<HostCoverage | "checklisted_but_stig_unknown", string[]>>;
  hostIndex: CoverageHost[];
}) {
  // hostname → record lookup so we can inline stigs_applied without
  // re-iterating the full list per gap section.
  const byName = useMemo(() => {
    const m = new Map<string, CoverageHost>();
    for (const h of hostIndex) m.set(h.hostname, h);
    return m;
  }, [hostIndex]);

  // Gap key → (header, blurb, severity tone). Order matters: surface the
  // CM-8-relevant gaps first so the assessor's eye lands on the boundary
  // issues before the parse-quality warning.
  const legend: Array<{
    key: HostCoverage | "checklisted_but_stig_unknown";
    title: string;
    blurb: string;
    tone: "destructive" | "warn" | "info";
  }> = [
    {
      key: "observed_not_declared",
      title: "Observed but not declared",
      blurb: "Scan or CKL sees host; inventory doesn't list it (CM-8)",
      tone: "destructive",
    },
    {
      key: "declared_not_observed",
      title: "Declared but never observed",
      blurb: "Inventory lists host; no scan or CKL touches it (CM-8 ghost)",
      tone: "destructive",
    },
    {
      key: "scanned_not_checklisted",
      title: "Scanned, no STIG",
      blurb: "Host scanned but no checklist applied (RA-5 / CM-6)",
      tone: "warn",
    },
    {
      key: "checklisted_not_scanned",
      title: "Checklisted, no scan",
      blurb: "STIG applied but no scan record (CA-7)",
      tone: "warn",
    },
    {
      key: "scanned_only",
      title: "Scanned only",
      blurb: "No checklist, no inventory entry",
      tone: "warn",
    },
    {
      key: "checklisted_only",
      title: "Checklisted only",
      blurb: "No scan, no inventory entry",
      tone: "warn",
    },
    {
      key: "checklisted_but_stig_unknown",
      title: "Checklist STIG title missing",
      blurb: "Parse issue — title couldn't be extracted from the checklist",
      tone: "info",
    },
  ];

  const completeCount = gaps.complete?.length ?? 0;
  const renderedAny = legend.some(({ key }) => (gaps[key]?.length ?? 0) > 0);

  return (
    <div className="space-y-2">
      {completeCount > 0 && (
        <div className="rounded-md border border-emerald-500/40 bg-emerald-500/5 px-3 py-2 text-xs">
          <span className="font-medium">Complete:</span>{" "}
          <span className="tabular-nums">{completeCount}</span> host
          {completeCount === 1 ? "" : "s"} appear in scans, checklists, and
          inventory.
        </div>
      )}
      {!renderedAny && completeCount === 0 && (
        <div className="rounded-md border px-3 py-2 text-xs text-muted-foreground">
          No coverage signal yet — ingest an ACAS scan, a STIG checklist, or
          mark a workbook as declared inventory.
        </div>
      )}
      {legend.map(({ key, title, blurb, tone }) => {
        const hosts = gaps[key] ?? [];
        if (hosts.length === 0) return null;
        const visible = hosts.slice(0, MAX_HOSTS_IN_PANEL);
        const overflow = hosts.length - visible.length;
        const border =
          tone === "destructive"
            ? "border-destructive/40 bg-destructive/5"
            : tone === "warn"
              ? "border-amber-500/40 bg-amber-500/5"
              : "border-muted bg-muted/30";
        return (
          <div key={key} className={`rounded-md border px-3 py-2 ${border}`}>
            <div className="flex items-baseline justify-between gap-2">
              <div className="text-xs font-medium">
                {title}{" "}
                <span className="ml-1 tabular-nums text-muted-foreground">
                  ({hosts.length})
                </span>
              </div>
              <div className="text-[10px] text-muted-foreground">{blurb}</div>
            </div>
            <ul className="mt-1.5 space-y-0.5 text-xs font-mono">
              {visible.map((h) => {
                const rec = byName.get(h);
                const stigs = rec?.stigs_applied ?? [];
                return (
                  <li key={h} className="flex items-baseline justify-between gap-2">
                    <span>{h}</span>
                    {stigs.length > 0 && (
                      <span
                        className="truncate text-[10px] text-muted-foreground"
                        title={stigs.join(", ")}
                      >
                        {stigs.length === 1
                          ? stigs[0]
                          : `${stigs[0]} +${stigs.length - 1}`}
                      </span>
                    )}
                  </li>
                );
              })}
              {overflow > 0 && (
                <li className="text-muted-foreground">
                  … +{overflow} more (full list reaches the LLM)
                </li>
              )}
            </ul>
          </div>
        );
      })}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border px-4 py-2">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-xl font-semibold tabular-nums">{value}</div>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  if (mb < 1024) return `${mb.toFixed(1)} MB`;
  return `${(mb / 1024).toFixed(2)} GB`;
}
