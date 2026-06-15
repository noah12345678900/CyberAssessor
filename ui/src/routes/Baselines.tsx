import { useMemo, useState } from "react";
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
} from "@tanstack/react-table";
import {
  AlertTriangle,
  ArrowLeft,
  Check,
  ListChecks,
  Loader2,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  X,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
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
import {
  useBaseline,
  useBaselineControls,
  useBaselineObjectives,
  useBaselines,
  useCrmSuspicion,
  useDeleteBaseline,
  useFrameworks,
  useMarkSuspicionFalsePositive,
  useRefreshBaseline,
} from "@/lib/queries";
import type {
  BaselineControlRow,
  BaselineObjective,
  CrmSuspicionReport,
} from "@/lib/api";
import { summarizeOdpNotes } from "./Workbooks";

// Overlay source types are stored as Baseline rows (so they show up in the
// per-workbook attach UI and the global Catalogs view) but they are NOT
// baselines — they're overlays. The Baselines page must only list true
// baselines, so we allow-list the baseline-kind source types here. Mirrors
// the overlay bucketing in Settings.tsx (crm / other / program_controls /
// iso_soa / cis_csat are all overlays).
const BASELINE_SOURCE_TYPES = new Set([
  "ccis_workbook",
  "oscal_ssp",
  "oscal_profile",
  "manual",
]);

export function Baselines() {
  const baselines = useBaselines();
  const frameworks = useFrameworks();
  const [selectedId, setSelectedId] = useState<number | undefined>();

  // Drop overlay rows — they are not baselines (BUG: overlays appearing as
  // baselines). Allow-list keeps any future genuine baseline source type
  // visible while excluding the overlay vocabulary.
  const baselineRows = useMemo(
    () =>
      (baselines.data ?? []).filter((b) =>
        BASELINE_SOURCE_TYPES.has(b.source_type),
      ),
    [baselines.data],
  );

  const frameworkName = (fid: number) => {
    const f = frameworks.data?.find((x) => x.id === fid);
    return f ? `${f.name} ${f.version}` : `#${fid}`;
  };

  if (selectedId !== undefined) {
    return (
      <BaselineDetail
        baselineId={selectedId}
        onBack={() => setSelectedId(undefined)}
        frameworkName={frameworkName}
      />
    );
  }

  return (
    <div className="p-8 space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
          <ListChecks className="h-6 w-6 text-primary" />
          Baselines
        </h1>
        <p className="text-sm text-muted-foreground">
          The tailored in-scope objective set for a system. Created when a workbook is opened
          with a framework selected, or imported from OSCAL.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Indexed baselines</CardTitle>
          <CardDescription>
            {baselineRows.length} baseline
            {baselineRows.length === 1 ? "" : "s"} known
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Framework</TableHead>
                <TableHead>Source</TableHead>
                <TableHead className="text-right">In scope</TableHead>
                <TableHead className="text-right">Out of scope</TableHead>
                <TableHead>Refreshed</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {baselineRows.map((b) => (
                <BaselineRow
                  key={b.id}
                  id={b.id}
                  name={b.name}
                  framework={frameworkName(b.framework_id)}
                  source_type={b.source_type}
                  source_ref={b.source_ref}
                  refreshed_at={b.refreshed_at}
                  onOpen={() => setSelectedId(b.id)}
                />
              ))}
              {baselines.isLoading && (
                <TableRow>
                  <TableCell
                    colSpan={6}
                    className="text-center text-sm text-muted-foreground py-8"
                  >
                    <Loader2 className="inline h-4 w-4 animate-spin mr-2" />
                    Loading baselines…
                  </TableCell>
                </TableRow>
              )}
              {!baselines.isLoading && baselineRows.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={6}
                    className="text-center text-sm text-muted-foreground py-8"
                  >
                    No baselines yet — open a workbook with a framework selected to create one.
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

function BaselineRow({
  id,
  name,
  framework,
  source_type,
  source_ref,
  refreshed_at,
  onOpen,
}: {
  id: number;
  name: string;
  framework: string;
  source_type: string;
  source_ref: string | null;
  refreshed_at: string;
  onOpen: () => void;
}) {
  const detail = useBaseline(id);
  return (
    <TableRow className="cursor-pointer hover:bg-accent/40" onClick={onOpen}>
      <TableCell className="font-medium">
        <Button variant="link" className="h-auto p-0" onClick={onOpen}>
          {name}
        </Button>
      </TableCell>
      <TableCell>
        <Badge variant="outline">{framework}</Badge>
      </TableCell>
      <TableCell>
        <div className="flex flex-col">
          <Badge variant="secondary" className="w-fit">
            {source_type}
          </Badge>
          {source_ref && (
            <span
              className="mt-1 max-w-xs truncate text-[10px] text-muted-foreground font-mono"
              title={source_ref}
            >
              {source_ref}
            </span>
          )}
        </div>
      </TableCell>
      <TableCell className="text-right tabular-nums">
        {detail.data?.counts.in_scope ?? "…"}
      </TableCell>
      <TableCell className="text-right tabular-nums">
        {detail.data?.counts.out_of_scope ?? "…"}
      </TableCell>
      <TableCell className="text-xs text-muted-foreground">
        {new Date(refreshed_at).toLocaleString()}
      </TableCell>
    </TableRow>
  );
}

// ---------------------------------------------------------------------------
// Detail view
// ---------------------------------------------------------------------------

function BaselineDetail({
  baselineId,
  onBack,
  frameworkName,
}: {
  baselineId: number;
  onBack: () => void;
  frameworkName: (fid: number) => string;
}) {
  const baseline = useBaseline(baselineId);
  const [inScopeOnly, setInScopeOnly] = useState(false);
  const controls = useBaselineControls(baselineId, inScopeOnly);
  const objectives = useBaselineObjectives(baselineId, inScopeOnly);
  const refresh = useRefreshBaseline({
    onSuccess: (r) => {
      // Base subtitle covers control/CCI scope counts. ODP clause is
      // appended only when the workbook ingest landed something worth
      // surfacing (insert/update/orphan/abstain) — same "quiet on a clean
      // re-open" rule the Workbooks card uses for its inline OdpStats.
      const base = `${r.controls_in_scope} controls in / ${r.controls_out_of_scope} out / ${r.controls_unknown} unknown · ${r.objectives_seen} CCIs seen`;
      const odpDetail = summarizeOdpNotes(r.notes?.odp_assignments);
      toast.success(
        "Baseline refreshed",
        odpDetail ? `${base} · ${odpDetail}` : base,
      );
    },
    onError: (err) => toast.error("Refresh failed", humanize(err)),
  });

  const [confirmDeleteOpen, setConfirmDeleteOpen] = useState(false);
  // When the first (non-force) delete hits the 409 in-use guard we arm a
  // second, fully-destructive confirmation that also cascade-removes the
  // dependent workbook(s). blockingMsg holds the backend detail (names the
  // workbooks) so the force prompt can tell the user exactly what dies.
  const [forceArmed, setForceArmed] = useState(false);
  const [blockingMsg, setBlockingMsg] = useState<string | null>(null);
  const resetDeleteDialog = () => {
    setConfirmDeleteOpen(false);
    setForceArmed(false);
    setBlockingMsg(null);
  };
  const del = useDeleteBaseline({
    onSuccess: (r) => {
      const wbNote =
        r.workbooks_removed.length > 0
          ? ` · removed ${r.workbooks_removed.length} dependent workbook${r.workbooks_removed.length === 1 ? "" : "s"}`
          : "";
      toast.success(
        "Baseline deleted",
        `Removed ${r.controls_removed} control${r.controls_removed === 1 ? "" : "s"} / ${r.objectives_removed} CCI${r.objectives_removed === 1 ? "" : "s"}` +
          (r.overlay_attachments_removed > 0
            ? ` · detached ${r.overlay_attachments_removed} overlay${r.overlay_attachments_removed === 1 ? "" : "s"}`
            : "") +
          wbNote,
      );
      resetDeleteDialog();
      onBack();
    },
    onError: (err) => {
      // 409 = a workbook still points at this baseline as its primary scope.
      // Rather than dead-end the user, arm the force path: keep the dialog
      // open and surface the dependent-workbook detail so they can choose to
      // cascade-delete those workbooks too (memory: force-delete + cascade).
      const status = (err as { status?: number }).status;
      if (status === 409) {
        setForceArmed(true);
        setBlockingMsg(humanize(err));
        setConfirmDeleteOpen(true);
        return;
      }
      toast.error("Delete failed", humanize(err));
    },
  });

  const [globalFilter, setGlobalFilter] = useState("");
  const [familyFilter, setFamilyFilter] = useState<string>("__all__");

  // Family list comes from Controls (the authoritative scoping surface). Falls
  // back to deriving from objective codes if the Controls query hasn't landed.
  const families = useMemo(() => {
    const set = new Set<string>();
    for (const c of controls.data ?? []) {
      if (c.family) set.add(c.family);
    }
    if (set.size === 0) {
      for (const o of objectives.data ?? []) {
        const m = o.objective_code.match(/^([A-Z]{2})/);
        if (m) set.add(m[1]);
      }
    }
    return Array.from(set).sort();
  }, [controls.data, objectives.data]);

  const filteredControlRows = useMemo(() => {
    let rows = controls.data ?? [];
    if (familyFilter !== "__all__") {
      rows = rows.filter((c) => c.family === familyFilter);
    }
    return rows;
  }, [controls.data, familyFilter]);

  const filteredRows = useMemo(() => {
    let rows = objectives.data ?? [];
    if (familyFilter !== "__all__") {
      rows = rows.filter((o) => o.objective_code.startsWith(`${familyFilter}-`));
    }
    return rows;
  }, [objectives.data, familyFilter]);

  const controlColumns = useMemo<ColumnDef<BaselineControlRow>[]>(
    () => [
      {
        accessorKey: "control_code",
        header: "Control",
        cell: (ctx) => (
          <span className="font-mono text-xs">{ctx.row.original.control_code}</span>
        ),
      },
      {
        accessorKey: "family",
        header: "Family",
        cell: (ctx) => (
          <Badge variant="outline" className="text-[10px]">
            {ctx.row.original.family}
          </Badge>
        ),
      },
      {
        accessorKey: "title",
        header: "Title",
        cell: (ctx) => (
          <span className="block max-w-md truncate text-xs" title={ctx.row.original.title}>
            {ctx.row.original.title}
          </span>
        ),
      },
      {
        accessorKey: "in_scope",
        header: "In scope",
        cell: (ctx) =>
          ctx.row.original.in_scope ? (
            <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400 text-xs">
              <Check className="h-3.5 w-3.5" /> Yes
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 text-muted-foreground text-xs">
              <X className="h-3.5 w-3.5" /> No
            </span>
          ),
      },
      {
        accessorKey: "tailoring_reason",
        header: "Tailoring reason",
        cell: (ctx) => (
          <span className="text-xs text-muted-foreground">
            {ctx.row.original.tailoring_reason ?? "—"}
          </span>
        ),
      },
    ],
    [],
  );

  const controlsTable = useReactTable({
    data: filteredControlRows,
    columns: controlColumns,
    state: { globalFilter },
    onGlobalFilterChange: setGlobalFilter,
    globalFilterFn: (row, _id, value) => {
      const v = String(value).toLowerCase();
      const c = row.original;
      return (
        c.control_code.toLowerCase().includes(v) ||
        c.title.toLowerCase().includes(v) ||
        c.family.toLowerCase().includes(v) ||
        (c.tailoring_reason ?? "").toLowerCase().includes(v)
      );
    },
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  const columns = useMemo<ColumnDef<BaselineObjective>[]>(
    () => [
      {
        accessorKey: "objective_code",
        header: "Code",
        cell: (ctx) => (
          <span className="font-mono text-xs">{ctx.row.original.objective_code}</span>
        ),
      },
      {
        accessorKey: "source",
        header: "Source",
        cell: (ctx) => (
          <Badge variant="outline" className="text-[10px]">
            {ctx.row.original.source}
          </Badge>
        ),
      },
      {
        accessorKey: "in_scope",
        header: "In scope",
        cell: (ctx) =>
          ctx.row.original.in_scope ? (
            <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400 text-xs">
              <Check className="h-3.5 w-3.5" /> Yes
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 text-muted-foreground text-xs">
              <X className="h-3.5 w-3.5" /> No
            </span>
          ),
      },
      {
        accessorKey: "tailoring_reason",
        header: "Tailoring reason",
        cell: (ctx) => (
          <span className="text-xs text-muted-foreground">
            {ctx.row.original.tailoring_reason ?? "—"}
          </span>
        ),
      },
      {
        accessorKey: "source_row",
        header: "Row",
        cell: (ctx) => (
          <span className="font-mono text-xs text-muted-foreground">
            {ctx.row.original.source_row ?? "—"}
          </span>
        ),
      },
      {
        accessorKey: "text",
        header: "Text",
        cell: (ctx) => (
          <span className="block max-w-md truncate text-xs" title={ctx.row.original.text}>
            {ctx.row.original.text}
          </span>
        ),
      },
    ],
    [],
  );

  const table = useReactTable({
    data: filteredRows,
    columns,
    state: { globalFilter },
    onGlobalFilterChange: setGlobalFilter,
    globalFilterFn: (row, _id, value) => {
      const v = String(value).toLowerCase();
      const o = row.original;
      return (
        o.objective_code.toLowerCase().includes(v) ||
        o.text.toLowerCase().includes(v) ||
        (o.tailoring_reason ?? "").toLowerCase().includes(v)
      );
    },
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  if (baseline.isLoading || !baseline.data) {
    return (
      <div className="p-8 space-y-4">
        <Button variant="ghost" size="sm" onClick={onBack}>
          <ArrowLeft className="h-4 w-4" />
          Back to baselines
        </Button>
        <div className="text-sm text-muted-foreground">
          {baseline.isLoading ? (
            <>
              <Loader2 className="inline h-4 w-4 animate-spin mr-2" />
              Loading baseline…
            </>
          ) : (
            "Baseline not found."
          )}
        </div>
      </div>
    );
  }

  const b = baseline.data;

  return (
    <div className="p-8 space-y-6">
      <Button variant="ghost" size="sm" onClick={onBack}>
        <ArrowLeft className="h-4 w-4" />
        Back to baselines
      </Button>

      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{b.name}</h1>
          <p className="text-sm text-muted-foreground">
            {frameworkName(b.framework_id)} — source {b.source_type}
          </p>
          {b.source_ref && (
            <p className="text-xs font-mono text-muted-foreground mt-1" title={b.source_ref}>
              {b.source_ref}
            </p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button
            onClick={() => refresh.mutate(baselineId)}
            disabled={refresh.isPending}
            variant="outline"
          >
            {refresh.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4" />
            )}
            Refresh from source
          </Button>
          <Button
            onClick={() => setConfirmDeleteOpen(true)}
            disabled={del.isPending}
            variant="outline"
            className="text-destructive hover:text-destructive"
          >
            <Trash2 className="h-4 w-4" />
            Delete
          </Button>
        </div>
      </header>

      <Dialog
        open={confirmDeleteOpen}
        onOpenChange={(open) => (open ? setConfirmDeleteOpen(true) : resetDeleteDialog())}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {forceArmed ? "Force-delete baseline " : "Delete baseline "}“{b.name}”?
            </DialogTitle>
            <DialogDescription>
              {forceArmed ? (
                <>
                  <strong className="text-destructive">
                    This baseline is still the primary scope for one or more
                    workbooks.
                  </strong>{" "}
                  Force-deleting will also <strong>permanently remove those
                  workbooks</strong> and every assessment, POAM, and sweep
                  result that hangs off them. Uploaded evidence is kept (it's a
                  shared pool); everything else is gone.
                  {blockingMsg ? (
                    <>
                      <br />
                      <br />
                      <span className="text-muted-foreground">{blockingMsg}</span>
                    </>
                  ) : null}
                  <br />
                  <br />
                  This cannot be undone.
                </>
              ) : (
                <>
                  Removes the baseline and its{" "}
                  <strong>{b.counts.controls_in_scope + b.counts.controls_out_of_scope}</strong>{" "}
                  control tailoring decision{(b.counts.controls_in_scope + b.counts.controls_out_of_scope) === 1 ? "" : "s"} and{" "}
                  <strong>{b.counts.objectives_total}</strong> CCI back-reference
                  {b.counts.objectives_total === 1 ? "" : "s"}. Reference-overlay attachments on workbooks
                  are detached automatically.
                  <br />
                  <br />
                  If a workbook still has this baseline as its primary scope you'll be
                  offered a force-delete that removes those workbooks too. The catalog
                  (controls + CCIs) is <em>not</em> touched. This cannot be undone.
                </>
              )}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={resetDeleteDialog}
              disabled={del.isPending}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => del.mutate({ id: baselineId, force: forceArmed })}
              disabled={del.isPending}
            >
              {del.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Trash2 className="h-4 w-4" />
              )}
              {forceArmed ? "Force-delete everything" : "Delete baseline"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <div className="flex flex-wrap gap-4">
        <Stat label="Controls in scope" value={b.counts.controls_in_scope} />
        <Stat label="Controls out of scope" value={b.counts.controls_out_of_scope} />
        <Stat label="Objectives in scope" value={b.counts.objectives_in_scope} />
        <Stat label="Objectives total" value={b.counts.objectives_total} />
        <Stat label="Refreshed" value={new Date(b.refreshed_at).toLocaleString()} />
      </div>

      {b.source_type === "crm" && b.attached_workbook_ids.length > 0 && (
        <CrmSuspicionBanner workbookIds={b.attached_workbook_ids} />
      )}

      <Card>
        <CardHeader>
          <CardTitle>Controls / Control Enhancements</CardTitle>
          <CardDescription>
            Scope is owned at the Control level — a control is in-scope iff any of its CCIs are
            marked required in the workbook. {filteredControlRows.length} of{" "}
            {controls.data?.length ?? 0} shown.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative max-w-md flex-1">
              <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Filter by code, title, family, or reason…"
                value={globalFilter}
                onChange={(e) => setGlobalFilter(e.target.value)}
                className="pl-8"
              />
            </div>
            <Select value={familyFilter} onValueChange={setFamilyFilter}>
              <SelectTrigger className="w-[180px]">
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
            <label className="flex items-center gap-2 text-sm text-muted-foreground">
              <input
                type="checkbox"
                checked={inScopeOnly}
                onChange={(e) => setInScopeOnly(e.target.checked)}
                className="h-4 w-4 rounded border-input"
              />
              In-scope only
            </label>
          </div>

          <Table>
            <TableHeader>
              {controlsTable.getHeaderGroups().map((hg) => (
                <TableRow key={hg.id}>
                  {hg.headers.map((h) => (
                    <TableHead key={h.id}>
                      {h.isPlaceholder
                        ? null
                        : flexRender(h.column.columnDef.header, h.getContext())}
                    </TableHead>
                  ))}
                </TableRow>
              ))}
            </TableHeader>
            <TableBody>
              {controlsTable.getRowModel().rows.map((row) => (
                <TableRow key={row.id}>
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))}
              {controlsTable.getRowModel().rows.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={controlColumns.length}
                    className="text-center text-sm text-muted-foreground py-8"
                  >
                    {controls.isLoading ? "Loading…" : "No controls match"}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Objectives (CCIs)</CardTitle>
          <CardDescription>
            Per-CCI rows are still shown for traceability. The In-scope column reflects the
            inherited value from each row's parent Control.{" "}
            {filteredRows.length} of {objectives.data?.length ?? 0} shown.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Table>
            <TableHeader>
              {table.getHeaderGroups().map((hg) => (
                <TableRow key={hg.id}>
                  {hg.headers.map((h) => (
                    <TableHead key={h.id}>
                      {h.isPlaceholder
                        ? null
                        : flexRender(h.column.columnDef.header, h.getContext())}
                    </TableHead>
                  ))}
                </TableRow>
              ))}
            </TableHeader>
            <TableBody>
              {table.getRowModel().rows.map((row) => (
                <TableRow key={row.id}>
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))}
              {table.getRowModel().rows.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={columns.length}
                    className="text-center text-sm text-muted-foreground py-8"
                  >
                    {objectives.isLoading ? "Loading…" : "No objectives match"}
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

function Stat({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-md border px-4 py-2">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-base font-semibold tabular-nums">{value}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// CRM suspicion banner
// ---------------------------------------------------------------------------

const SEVERITY_STYLES: Record<
  "info" | "warn" | "alert",
  { container: string; icon: string; badge: string }
> = {
  info: {
    container:
      "border-blue-200 bg-blue-50 text-blue-900 dark:border-blue-900 dark:bg-blue-950/40 dark:text-blue-100",
    icon: "text-blue-600 dark:text-blue-400",
    badge: "bg-blue-100 text-blue-900 dark:bg-blue-900/60 dark:text-blue-100",
  },
  warn: {
    container:
      "border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-100",
    icon: "text-amber-600 dark:text-amber-400",
    badge: "bg-amber-100 text-amber-900 dark:bg-amber-900/60 dark:text-amber-100",
  },
  alert: {
    container:
      "border-red-200 bg-red-50 text-red-900 dark:border-red-900 dark:bg-red-950/40 dark:text-red-100",
    icon: "text-red-600 dark:text-red-400",
    badge: "bg-red-100 text-red-900 dark:bg-red-900/60 dark:text-red-100",
  },
};

function fmtScore(v: number | null | undefined): string {
  if (v === null || v === undefined) return "—";
  return v.toFixed(2);
}

function CrmSuspicionBanner({ workbookIds }: { workbookIds: number[] }) {
  const [selectedWb, setSelectedWb] = useState<number>(workbookIds[0]);
  const [dismissed, setDismissed] = useState(false);

  const suspicion = useCrmSuspicion(selectedWb);
  const markFp = useMarkSuspicionFalsePositive({
    onSuccess: () => toast.success("Marked as false positive"),
    onError: (err) => toast.error("Mark failed", humanize(err)),
  });

  if (dismissed) return null;

  const report: CrmSuspicionReport | undefined = suspicion.data;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div>
            <CardTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-amber-500" />
              CRM suspicion guard
            </CardTitle>
            <CardDescription>
              Adversarial-CRM check. Hybrid heuristics + TF-IDF boilerplate detector +
              IsolationForest anomaly score + embedding-based narrative quality.
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            {workbookIds.length > 1 && (
              <Select
                value={String(selectedWb)}
                onValueChange={(v) => setSelectedWb(Number(v))}
              >
                <SelectTrigger className="w-[180px]">
                  <SelectValue placeholder="Workbook" />
                </SelectTrigger>
                <SelectContent>
                  {workbookIds.map((id) => (
                    <SelectItem key={id} value={String(id)}>
                      Workbook #{id}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={() => suspicion.refetch()}
              disabled={suspicion.isFetching}
            >
              {suspicion.isFetching ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <ShieldCheck className="h-4 w-4" />
              )}
              {report ? "Recompute" : "Compute suspicion"}
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {!report && !suspicion.isFetching && (
          <p className="text-sm text-muted-foreground">
            Suspicion has not been computed for this CRM + workbook pairing. Click{" "}
            <em>Compute suspicion</em> to run the three-tier scoring pass.
          </p>
        )}
        {suspicion.isError && !suspicion.isFetching && (
          <p className="text-sm text-destructive">
            {suspicion.error instanceof Error
              ? suspicion.error.message
              : "Suspicion compute failed."}
          </p>
        )}
        {report && <CrmSuspicionReportView report={report} />}

        {report && (
          <div className="flex flex-wrap items-center gap-2 pt-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                markFp.mutate({
                  logId: report.suspicion_log_id,
                  workbookId: report.workbook_id,
                })
              }
              disabled={markFp.isPending}
            >
              {markFp.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Check className="h-4 w-4" />
              )}
              Mark as false positive
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setDismissed(true)}>
              Proceed anyway
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function CrmSuspicionReportView({ report }: { report: CrmSuspicionReport }) {
  const styles = SEVERITY_STYLES[report.severity];
  const heuristicFlags = report.flags.filter((f) => f.name !== "ml_anomaly");

  return (
    <div className={`rounded-md border p-4 space-y-3 ${styles.container}`}>
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <AlertTriangle className={`h-5 w-5 ${styles.icon}`} />
          <span className="font-semibold">
            Overall suspicion: {fmtScore(report.overall_suspicion)}
          </span>
          <Badge className={styles.badge} variant="secondary">
            {report.severity}
          </Badge>
        </div>
        <span className="text-xs text-muted-foreground">
          corpus n={report.n_corpus}
        </span>
      </div>

      <div className="grid gap-1 text-sm">
        <ScoreLine
          label="Heuristic"
          score={report.heuristic_score}
          detail={
            heuristicFlags.length === 0
              ? "no rules tripped"
              : `${heuristicFlags.length} flag${heuristicFlags.length === 1 ? "" : "s"} — ${heuristicFlags
                  .map((f) => f.name)
                  .join(", ")}`
          }
        />
        {report.ml_anomaly_score !== null && (
          <ScoreLine
            label="ML anomaly"
            score={report.ml_anomaly_score}
            detail={`IsolationForest vs. corpus of ${report.n_corpus} CRM${report.n_corpus === 1 ? "" : "s"}`}
          />
        )}
        {report.ml_anomaly_score === null && (
          <p className="text-xs text-muted-foreground italic">
            ML anomaly: cold-start (corpus &lt; 10 CRMs, IsolationForest withheld).
          </p>
        )}
        {report.narrative_quality_score !== null && (
          <ScoreLine
            label="Narrative quality"
            score={report.narrative_quality_score}
            detail="embedding-distance vs. boilerplate centroid (higher = more substantive)"
            invert
          />
        )}
        {report.narrative_quality_score === null && (
          <p className="text-xs text-muted-foreground italic">
            Narrative quality: no embeddings provider configured (TF-IDF fallback only).
          </p>
        )}
      </div>

      {heuristicFlags.length > 0 && (
        <details className="text-xs">
          <summary className="cursor-pointer font-medium opacity-80 hover:opacity-100">
            Review flag details
          </summary>
          <ul className="mt-2 space-y-1.5 pl-1">
            {heuristicFlags.map((f) => (
              <li key={f.name} className="rounded border px-2 py-1.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[11px]">{f.name}</span>
                  <Badge
                    variant="outline"
                    className={`text-[10px] ${SEVERITY_STYLES[f.severity].badge}`}
                  >
                    {f.severity}
                  </Badge>
                </div>
                <p className="mt-1 opacity-90">{f.summary}</p>
              </li>
            ))}
          </ul>
        </details>
      )}

      <p className="text-[11px] opacity-70">
        Computed {new Date(report.computed_at).toLocaleString()} · log #
        {report.suspicion_log_id}
      </p>
    </div>
  );
}

function ScoreLine({
  label,
  score,
  detail,
  invert = false,
}: {
  label: string;
  score: number;
  detail: string;
  invert?: boolean;
}) {
  // For narrative quality, "higher is better", so don't paint it red when high.
  const visualScore = invert ? 1 - score : score;
  const tone =
    visualScore >= 0.6
      ? "text-red-700 dark:text-red-300"
      : visualScore >= 0.3
        ? "text-amber-700 dark:text-amber-300"
        : "text-emerald-700 dark:text-emerald-400";
  return (
    <div className="flex flex-wrap items-baseline gap-x-2">
      <span className="w-32 font-medium opacity-80">{label}:</span>
      <span className={`font-mono font-semibold ${tone}`}>{fmtScore(score)}</span>
      <span className="text-xs opacity-80">({detail})</span>
    </div>
  );
}

