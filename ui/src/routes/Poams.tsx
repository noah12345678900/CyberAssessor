/**
 * POAMs list view.
 *
 * Three core flows live on this screen:
 *   1. **Generate** — cluster NC assessments in a workbook into draft POAMs.
 *      Idempotent (backend skips already-clustered controls), so re-running
 *      after the assessor has edited drafts is safe.
 *   2. **Export** — write workbook POAMs to a copy of the eMASS RMF POAM
 *      template via xlwings. Stamps `exported_at` on every row written.
 *   3. **Import** — round-trip an eMASS POAM workbook back into the DB
 *      (merge by emass_poam_id when present, else by control_cluster).
 *
 * Highest-risk-first sort is server-side (routes/poams.py:_sort_key), so
 * we render the list verbatim — no client sort.
 *
 * Workbook + status filters are local-state only; both drive the
 * `usePoams(workbook_id, status)` query key so TanStack Query handles
 * refetch + cache busting transparently.
 */

import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  AlertTriangle,
  Download,
  FileUp,
  FolderOpen,
  Loader2,
  ShieldAlert,
  Sparkles,
  Trash2,
  Upload,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { toast } from "@/components/ui/toaster";
import { humanize } from "@/lib/errors";
import { hasNativeBridge } from "@/lib/api";
import type { PoamStatus, PoamSummary, Workbook } from "@/lib/api";
import { formatDate, severityClasses, statusClasses } from "@/lib/poamFormat";
import {
  useDeleteAllPoams,
  useDeletePoam,
  useExportPoams,
  useGeneratePoams,
  useImportPoams,
  usePoams,
  useWorkbooks,
} from "@/lib/queries";

const STATUS_VALUES: PoamStatus[] = [
  "Draft",
  "Ongoing",
  "Risk Accepted",
  "Completed",
];

const ALL = "__all__";

export function Poams() {
  const navigate = useNavigate();
  const workbooks = useWorkbooks();
  const [workbookFilter, setWorkbookFilter] = useState<string>(ALL);
  const [statusFilter, setStatusFilter] = useState<string>(ALL);

  const workbookIdFilter =
    workbookFilter === ALL ? undefined : Number(workbookFilter);
  const statusFilterValue =
    statusFilter === ALL ? undefined : (statusFilter as PoamStatus);

  const poams = usePoams(workbookIdFilter, statusFilterValue);
  // Separate query (workbook scope only, no status filter) so we know which
  // status buckets are populated. Without this the dropdown would show every
  // bucket regardless of whether any POAMs exist in it — the user clicks
  // "Completed" expecting a few rows and gets an empty table.
  const poamsForStatusOptions = usePoams(workbookIdFilter, undefined);
  const presentStatuses = useMemo(() => {
    const set = new Set<PoamStatus>();
    for (const p of poamsForStatusOptions.data ?? []) set.add(p.status);
    return set;
  }, [poamsForStatusOptions.data]);
  const visibleStatuses = STATUS_VALUES.filter((s) => presentStatuses.has(s));

  // --- Dialog state ----------------------------------------------------------
  const [generateOpen, setGenerateOpen] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<PoamSummary | null>(null);
  const [deleteAllOpen, setDeleteAllOpen] = useState(false);

  const nativeBridge = hasNativeBridge();
  const workbookById = useMemo(() => {
    const m = new Map<number, string>();
    for (const w of workbooks.data ?? []) m.set(w.id, w.filename);
    return m;
  }, [workbooks.data]);

  // --- Mutations -------------------------------------------------------------
  const generate = useGeneratePoams({
    onSuccess: (res) => {
      setGenerateOpen(false);
      // Build a precise, multi-bucket flash. The prior "X new POAMs" line
      // silently flashed "0 new" on every re-run after the first, even when
      // the generator had usefully rewritten 50+ descriptions or honored
      // assessor edits — making the button feel broken. List only buckets
      // that fired so the toast stays tight.
      const c = res.counts;
      const parts: string[] = [];
      if (c.created > 0) parts.push(`${c.created} new`);
      if (c.rewritten > 0) parts.push(`${c.rewritten} rewritten`);
      if (c.locked_skipped > 0)
        parts.push(
          `${c.locked_skipped} locked edit${c.locked_skipped === 1 ? "" : "s"} preserved`,
        );
      if (c.non_draft_skipped > 0)
        parts.push(`${c.non_draft_skipped} non-draft preserved`);
      if (c.unchanged > 0 && parts.length === 0) {
        // Pure no-op run — say so explicitly so the assessor knows the
        // button worked and there was nothing to update.
        parts.push(`${c.unchanged} already up to date`);
      }
      const detail = parts.length > 0 ? parts.join(" · ") : "No NC assessments to cluster.";
      toast.success("Generated POAMs", detail);
    },
    onError: (err) => toast.error("Generate failed", humanize(err)),
  });

  const exportMut = useExportPoams({
    onSuccess: (res) => {
      setExportOpen(false);
      toast.success(
        "Exported to eMASS template",
        `Wrote ${res.written} POAM${res.written === 1 ? "" : "s"}${res.skipped ? ` · skipped ${res.skipped}` : ""} → ${res.output_path}`,
      );
    },
    onError: (err) => toast.error("Export failed", humanize(err)),
  });

  const importMut = useImportPoams({
    onSuccess: (res) => {
      setImportOpen(false);
      toast.success(
        "Imported eMASS workbook",
        `Read ${res.read} · matched ${res.matched} · created ${res.created}`,
      );
    },
    onError: (err) => toast.error("Import failed", humanize(err)),
  });

  const del = useDeletePoam({
    onSuccess: () => {
      setDeleteTarget(null);
      toast.success("POAM deleted", "Milestones and objective links removed too.");
    },
    onError: (err) => toast.error("Delete failed", humanize(err)),
  });

  const delAll = useDeleteAllPoams({
    onSuccess: (res) => {
      setDeleteAllOpen(false);
      toast.success(
        "POAMs deleted",
        `Removed ${res.deleted} POAM${res.deleted === 1 ? "" : "s"} and their milestones, objectives, and evidence links.`,
      );
    },
    onError: (err) => toast.error("Delete all failed", humanize(err)),
  });

  const poamCount = poams.data?.length ?? 0;

  // Status filter is only useful when there are at least two buckets to
  // discriminate between — one bucket and "All statuses" return the same
  // rows. Keep the control visible when the user has an active selection
  // even if the bucket became empty, so the <Select> stays controllable.
  const showStatusFilter =
    visibleStatuses.length > 1 || statusFilterValue !== undefined;

  return (
    <div className="p-8 space-y-6">
      {/*
        Page header is title + description only — matches the Baselines
        pattern. Primary actions (Import / Export / Generate) live inside
        the table Card's CardHeader below, so they sit slightly below the
        page title instead of crowding the very top edge.
      */}
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">POAMs</h1>
        <p className="text-sm text-muted-foreground">
          Plans of Action &amp; Milestones — clustered from Non-Compliant
          assessments, editable here, round-tripped through the eMASS RMF
          POAM template.
        </p>
      </header>

      {/* Filters */}
      <Card>
        <CardContent className="flex flex-wrap items-center gap-4 pt-6">
          <div className="flex items-center gap-2">
            <span className="text-xs uppercase tracking-wider text-muted-foreground">
              Workbook
            </span>
            <Select value={workbookFilter} onValueChange={setWorkbookFilter}>
              <SelectTrigger className="w-[280px]">
                <SelectValue placeholder="All workbooks" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={ALL}>All workbooks</SelectItem>
                {(workbooks.data ?? []).map((w) => (
                  <SelectItem key={w.id} value={String(w.id)}>
                    {w.filename}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {showStatusFilter && (
            <div className="flex items-center gap-2">
              <span className="text-xs uppercase tracking-wider text-muted-foreground">
                Status
              </span>
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-[180px]">
                  <SelectValue placeholder="All statuses" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value={ALL}>All statuses</SelectItem>
                  {visibleStatuses.map((s) => (
                    <SelectItem key={s} value={s}>
                      {s}
                    </SelectItem>
                  ))}
                  {statusFilterValue && !presentStatuses.has(statusFilterValue) && (
                    <SelectItem value={statusFilterValue}>
                      {statusFilterValue} (empty)
                    </SelectItem>
                  )}
                </SelectContent>
              </Select>
            </div>
          )}
          <div className="ml-auto text-xs text-muted-foreground">
            {poamCount} POAM{poamCount === 1 ? "" : "s"}
          </div>
        </CardContent>
      </Card>

      {/* Table */}
      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-4 space-y-0">
          <div className="space-y-1.5">
            <CardTitle>POAMs</CardTitle>
            <CardDescription>
              Sorted highest-risk first (raw severity desc, then newest).
            </CardDescription>
          </div>
          <div className="flex gap-2 shrink-0">
            <Button variant="outline" onClick={() => setImportOpen(true)}>
              <Upload className="h-4 w-4" />
              Import…
            </Button>
            <Button variant="outline" onClick={() => setExportOpen(true)}>
              <Download className="h-4 w-4" />
              Export…
            </Button>
            <Button
              variant="outline"
              className="text-destructive hover:text-destructive border-destructive/40 hover:bg-destructive/10"
              onClick={() => setDeleteAllOpen(true)}
              disabled={poamCount === 0 || delAll.isPending}
              title="Delete all POAMs currently shown"
            >
              <Trash2 className="h-4 w-4" />
              Delete all…
            </Button>
            <Button onClick={() => setGenerateOpen(true)}>
              <Sparkles className="h-4 w-4" />
              Generate from NCs…
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Control cluster</TableHead>
                <TableHead>Vulnerability</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead className="text-right">CCIs</TableHead>
                <TableHead className="text-right">Milestones</TableHead>
                <TableHead className="text-right">Evidence</TableHead>
                <TableHead>Scheduled</TableHead>
                <TableHead>Workbook</TableHead>
                <TableHead className="w-[1%]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {poams.data?.map((p) => (
                <TableRow
                  key={p.id}
                  className="cursor-pointer hover:bg-accent/50"
                  onClick={() => navigate(`/poams/${p.id}`)}
                >
                  <TableCell className="font-medium font-mono text-xs">
                    {p.control_cluster}
                  </TableCell>
                  <TableCell
                    className="max-w-md truncate text-sm"
                    title={p.vulnerability_description}
                  >
                    {p.vulnerability_description}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className={statusClasses(p.status)}>
                      {p.status}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {p.raw_severity ? (
                      <Badge
                        variant="outline"
                        className={severityClasses(p.raw_severity)}
                      >
                        {p.raw_severity}
                      </Badge>
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell className="text-right tabular-nums text-sm">
                    {p.objective_count}
                  </TableCell>
                  <TableCell className="text-right tabular-nums text-sm">
                    {p.milestone_count}
                  </TableCell>
                  <TableCell className="text-right tabular-nums text-sm">
                    {p.evidence_count}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatDate(p.scheduled_completion_date)}
                  </TableCell>
                  <TableCell
                    className="text-xs text-muted-foreground max-w-[200px] truncate"
                    title={workbookById.get(p.workbook_id) ?? ""}
                  >
                    {workbookById.get(p.workbook_id) ?? `#${p.workbook_id}`}
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 w-7 p-0 text-destructive hover:text-destructive"
                      onClick={(e) => {
                        e.stopPropagation();
                        setDeleteTarget(p);
                      }}
                      title="Delete POAM"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
              {poams.isLoading && (
                <TableRow>
                  <TableCell
                    colSpan={9}
                    className="text-center text-sm text-muted-foreground py-8"
                  >
                    <Loader2 className="inline h-4 w-4 animate-spin mr-2" />
                    Loading POAMs…
                  </TableCell>
                </TableRow>
              )}
              {!poams.isLoading && poamCount === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={9}
                    className="text-center text-sm text-muted-foreground py-8"
                  >
                    No POAMs yet. Click{" "}
                    <strong>Generate from NCs…</strong> to cluster
                    Non-Compliant assessments into draft POAMs.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <GenerateDialog
        open={generateOpen}
        onOpenChange={setGenerateOpen}
        workbooks={workbooks.data ?? []}
        pending={generate.isPending}
        onSubmit={(workbookId) => generate.mutate(workbookId)}
      />
      <ExportDialog
        open={exportOpen}
        onOpenChange={setExportOpen}
        workbooks={workbooks.data ?? []}
        nativeBridge={nativeBridge}
        pending={exportMut.isPending}
        onSubmit={(args) => exportMut.mutate(args)}
      />
      <ImportDialog
        open={importOpen}
        onOpenChange={setImportOpen}
        workbooks={workbooks.data ?? []}
        nativeBridge={nativeBridge}
        pending={importMut.isPending}
        onSubmit={(args) => importMut.mutate(args)}
      />

      <Dialog
        open={!!deleteTarget}
        onOpenChange={(o) => !o && setDeleteTarget(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-destructive" />
              Delete POAM?
            </DialogTitle>
            <DialogDescription>
              Removes <strong>{deleteTarget?.control_cluster}</strong> and all
              of its milestones and objective links. The underlying
              assessments are <em>not</em> touched. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setDeleteTarget(null)}
              disabled={del.isPending}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => deleteTarget && del.mutate(deleteTarget.id)}
              disabled={del.isPending}
            >
              {del.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Trash2 className="h-4 w-4" />
              )}
              Delete POAM
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={deleteAllOpen} onOpenChange={(o) => !o && setDeleteAllOpen(false)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-destructive" />
              Delete all POAMs?
            </DialogTitle>
            <DialogDescription>
              This will permanently remove all{" "}
              <strong>{poamCount} POAM{poamCount === 1 ? "" : "s"}</strong>{" "}
              currently shown
              {workbookIdFilter !== undefined ? " for this workbook" : ""}
              {statusFilterValue !== undefined ? ` with status "${statusFilterValue}"` : ""}
              , along with their milestones, objective links, evidence links,
              and risk history. The underlying assessments are{" "}
              <em>not</em> touched. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setDeleteAllOpen(false)}
              disabled={delAll.isPending}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() =>
                delAll.mutate({
                  workbook_id: workbookIdFilter,
                  status: statusFilterValue,
                })
              }
              disabled={delAll.isPending}
            >
              {delAll.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Trash2 className="h-4 w-4" />
              )}
              Delete {poamCount} POAM{poamCount === 1 ? "" : "s"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Generate dialog — pick a workbook, run /api/poams/generate.
// ---------------------------------------------------------------------------

function GenerateDialog({
  open,
  onOpenChange,
  workbooks,
  pending,
  onSubmit,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  workbooks: Workbook[];
  pending: boolean;
  onSubmit: (workbookId: number) => void;
}) {
  const [workbookId, setWorkbookId] = useState<string>("");
  const selectedWorkbook = workbooks.find((w) => String(w.id) === workbookId);
  const showImportWarning =
    selectedWorkbook && selectedWorkbook.last_emass_import_at === null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Generate POAMs from NC assessments</DialogTitle>
          <DialogDescription>
            Clusters Non-Compliant assessments at the remediation boundary
            (shared control + owner + fix). Idempotent — re-running won't
            duplicate existing POAMs.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <label className="text-sm font-medium">Workbook</label>
          <Select value={workbookId} onValueChange={setWorkbookId}>
            <SelectTrigger>
              <SelectValue placeholder="Select a workbook…" />
            </SelectTrigger>
            <SelectContent>
              {workbooks.map((w) => (
                <SelectItem key={w.id} value={String(w.id)}>
                  {w.filename}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          {workbooks.length === 0 && (
            <p className="text-xs text-muted-foreground">
              No workbooks opened yet — open one from the Workbooks screen first.
            </p>
          )}
          {showImportWarning && <ImportFirstWarning verb="generate" />}
        </div>
        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={pending}
          >
            Cancel
          </Button>
          <Button
            onClick={() => workbookId && onSubmit(Number(workbookId))}
            disabled={pending || !workbookId}
          >
            {pending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Sparkles className="h-4 w-4" />
            )}
            Generate
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Export dialog — pick workbook + output path. Uses the bundled scrubbed
// eMASS RMF POAM template, so no template-path picker is needed.
// ---------------------------------------------------------------------------

function ExportDialog({
  open,
  onOpenChange,
  workbooks,
  nativeBridge,
  pending,
  onSubmit,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  workbooks: Workbook[];
  nativeBridge: boolean;
  pending: boolean;
  onSubmit: (args: {
    workbook_id: number;
    output_path: string;
    system_name?: string;
  }) => void;
}) {
  const [workbookId, setWorkbookId] = useState<string>("");
  const [outputPath, setOutputPath] = useState("");
  const [systemName, setSystemName] = useState("");
  const selectedWorkbook = workbooks.find((w) => String(w.id) === workbookId);
  const showImportWarning =
    selectedWorkbook && selectedWorkbook.last_emass_import_at === null;

  async function pickFolder() {
    if (!nativeBridge) return;
    const d = await window.ccis!.openFolder();
    if (d) setOutputPath(d);
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>Export POAMs to eMASS template</DialogTitle>
          <DialogDescription>
            Writes a copy of the bundled scrubbed eMASS RMF POAM template
            populated with this workbook's POAMs, preserving data validation,
            merged cells, and the header banner. Pick a folder — the file is
            auto-named CYBERSECURITY_ASSESSOR_POAMS_&lt;timestamp&gt;.xlsx.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">Workbook</label>
            <Select value={workbookId} onValueChange={setWorkbookId}>
              <SelectTrigger>
                <SelectValue placeholder="Select a workbook…" />
              </SelectTrigger>
              <SelectContent>
                {workbooks.map((w) => (
                  <SelectItem key={w.id} value={String(w.id)}>
                    {w.filename}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium">Output folder</label>
            <div className="flex gap-2">
              <Input
                value={outputPath}
                onChange={(e) => setOutputPath(e.target.value)}
                placeholder="C:\path\to\export-folder"
                className="font-mono text-xs"
              />
              {nativeBridge && (
                <Button variant="outline" onClick={pickFolder}>
                  <FolderOpen className="h-4 w-4" />
                  Browse
                </Button>
              )}
            </div>
            {!nativeBridge && (
              <div className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/5 p-3 text-xs text-muted-foreground">
                <AlertTriangle className="h-4 w-4 text-warning shrink-0 mt-0.5" />
                Native folder picker unavailable — paste an absolute folder
                path above.
              </div>
            )}
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium">
              System name <span className="text-muted-foreground">(optional)</span>
            </label>
            <Input
              value={systemName}
              onChange={(e) => setSystemName(e.target.value)}
              placeholder="Example System EI IATT"
            />
          </div>

          {showImportWarning && <ImportFirstWarning verb="export" />}
        </div>
        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={pending}
          >
            Cancel
          </Button>
          <Button
            onClick={() =>
              onSubmit({
                workbook_id: Number(workbookId),
                output_path: outputPath.trim(),
                system_name: systemName.trim() || undefined,
              })
            }
            disabled={pending || !workbookId || !outputPath.trim()}
          >
            {pending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Download className="h-4 w-4" />
            )}
            Export
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Import dialog — pick workbook + eMASS POAM file, merge into DB.
// ---------------------------------------------------------------------------

function ImportDialog({
  open,
  onOpenChange,
  workbooks,
  nativeBridge,
  pending,
  onSubmit,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  workbooks: Workbook[];
  nativeBridge: boolean;
  pending: boolean;
  onSubmit: (args: { workbook_id: number; poam_file_path: string }) => void;
}) {
  const [workbookId, setWorkbookId] = useState<string>("");
  const [poamPath, setPoamPath] = useState("");

  async function pickFile() {
    if (!nativeBridge) return;
    const p = await window.ccis!.openFile([
      { name: "eMASS POAM workbook", extensions: ["xlsx", "xlsm"] },
    ]);
    if (p) setPoamPath(p);
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>Import from eMASS workbook</DialogTitle>
          <DialogDescription>
            Reads an eMASS POAM workbook and merges its rows. Existing POAMs
            are matched by <code>emass_poam_id</code> (or control cluster as
            fallback) — unmatched rows are inserted as new POAMs.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">Target workbook</label>
            <Select value={workbookId} onValueChange={setWorkbookId}>
              <SelectTrigger>
                <SelectValue placeholder="Select a workbook…" />
              </SelectTrigger>
              <SelectContent>
                {workbooks.map((w) => (
                  <SelectItem key={w.id} value={String(w.id)}>
                    {w.filename}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium">eMASS POAM file</label>
            <div className="flex gap-2">
              <Input
                value={poamPath}
                onChange={(e) => setPoamPath(e.target.value)}
                placeholder="C:\path\to\eMASS-POAM-export.xlsx"
                className="font-mono text-xs"
              />
              {nativeBridge && (
                <Button variant="outline" onClick={pickFile}>
                  <FileUp className="h-4 w-4" />
                  Browse
                </Button>
              )}
            </div>
          </div>

          {!nativeBridge && (
            <div className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/5 p-3 text-xs text-muted-foreground">
              <AlertTriangle className="h-4 w-4 text-warning shrink-0 mt-0.5" />
              Native file picker unavailable — paste an absolute path above.
            </div>
          )}
        </div>
        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={pending}
          >
            Cancel
          </Button>
          <Button
            onClick={() =>
              onSubmit({
                workbook_id: Number(workbookId),
                poam_file_path: poamPath.trim(),
              })
            }
            disabled={pending || !workbookId || !poamPath.trim()}
          >
            {pending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Upload className="h-4 w-4" />
            )}
            Import
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Reusable banner: warn that this workbook hasn't been reconciled against the
// eMASS POAM export yet. Shows on Generate (drafts may collide with eMASS
// rows that already exist) and Export (the export will overwrite, but the
// assessor probably wants to merge first to keep any external edits).
// ---------------------------------------------------------------------------

function ImportFirstWarning({ verb }: { verb: "generate" | "export" }) {
  const message =
    verb === "generate"
      ? "This workbook has never been reconciled against eMASS. Drafts you generate now may collide with POAMs that already exist in eMASS — import the current eMASS export first to merge by emass_poam_id."
      : "This workbook has never been reconciled against eMASS. Exporting now will produce a one-way snapshot — any rows or edits that exist only in eMASS will not be preserved. Import the current eMASS export first to merge.";
  return (
    <div className="flex items-start gap-2 rounded-md border border-warning/40 bg-warning/5 p-3 text-xs">
      <AlertTriangle className="h-4 w-4 text-warning shrink-0 mt-0.5" />
      <span className="text-muted-foreground">{message}</span>
    </div>
  );
}
