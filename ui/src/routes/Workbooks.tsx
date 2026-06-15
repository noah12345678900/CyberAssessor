import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, FileSpreadsheet, FolderOpen, Layers, Loader2, RefreshCw, ShieldCheck, Trash2, Upload, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { api, hasNativeBridge } from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
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
  ComplianceTargetPicker,
  type ComplianceTarget,
} from "@/components/ComplianceTargetPicker";
import type { OdpAssignmentNotes, Workbook } from "@/lib/api";
import {
  useAttachOverlay,
  useBaselines,
  useCatalogStatus,
  useDeleteWorkbook,
  useDetachOverlay,
  useDownloadWorkbookSar,
  useFrameworks,
  useImportOverlay,
  useOpenWorkbook,
  useScopeLabels,
  useWorkbooks,
} from "@/lib/queries";

export function Workbooks() {
  const workbooks = useWorkbooks();
  const frameworks = useFrameworks();
  const catalog = useCatalogStatus();
  const open = useOpenWorkbook({
    onSuccess: (res) => {
      const bl = res.baseline;
      if (bl) {
        const odpDetail = summarizeOdpNotes(bl.notes?.odp_assignments);
        toast.success(
          `Opened ${res.filename}`,
          `Baseline: ${bl.controls_in_scope} controls in / ${bl.controls_out_of_scope} out / ${bl.controls_unknown} unknown · ${bl.objectives_seen} CCIs seen` +
            (odpDetail ? ` · ${odpDetail}` : ""),
        );
      } else {
        toast.info(
          `Opened ${res.filename}`,
          "No framework bound — pick one to materialize a baseline",
        );
      }
    },
    onError: (err) => toast.error("Open failed", humanize(err)),
  });
  const downloadSar = useDownloadWorkbookSar();
  const baselines = useBaselines();
  const [target, setTarget] = useState<ComplianceTarget | undefined>();
  const [manualPath, setManualPath] = useState("");
  // ID of the workbook whose overlay dialog is currently open (null = closed).
  // We track the ID and derive the live workbook from the `workbooks` query
  // below so attach/detach mutations (which invalidate `qk.workbooks`) cause
  // the dialog to re-render with fresh `overlay_baseline_ids`. Holding the
  // Workbook object directly here would freeze a stale snapshot and the
  // dialog's `attachedIds` set would lag the backend by one click.
  const [overlayWbId, setOverlayWbId] = useState<number | null>(null);
  const overlayWb = useMemo(
    () => workbooks.data?.find((w) => w.id === overlayWbId) ?? null,
    [workbooks.data, overlayWbId],
  );

  // ID of the workbook currently pending delete confirmation (null = no
  // dialog open). Resolves to the live Workbook via useMemo so the dialog
  // header rerenders if the list updates underneath it.
  const [confirmDeleteId, setConfirmDeleteId] = useState<number | null>(null);
  const confirmDeleteWb = useMemo(
    () => workbooks.data?.find((w) => w.id === confirmDeleteId) ?? null,
    [workbooks.data, confirmDeleteId],
  );
  const del = useDeleteWorkbook({
    onSuccess: (r) => {
      // Surface the cascade counts so the user sees what was removed —
      // assessments + POAMs are the biggest deletions; CRM/sweep/asset
      // rows are bundled into "ancillary" since each one alone isn't
      // interesting. Evidence + SystemContext are unlinked (workbook_id
      // NULL'd), not deleted, because they may be reusable artifacts.
      const counts = r.cascade ?? {};
      const big = [
        ["assessments", counts.assessments],
        ["POAMs", counts.poams],
        ["sweep runs", counts.sweep_runs],
        ["assets", counts.assets],
      ]
        .filter(([, n]) => typeof n === "number" && (n as number) > 0)
        .map(([k, n]) => `${n} ${k}`)
        .join(" · ");
      const unlinked = [
        ["evidence", counts.evidence_unlinked],
        ["system contexts", counts.system_contexts_unlinked],
      ]
        .filter(([, n]) => typeof n === "number" && (n as number) > 0)
        .map(([k, n]) => `${n} ${k}`)
        .join(", ");
      const detail =
        [big, unlinked ? `unlinked ${unlinked}` : ""].filter(Boolean).join(" · ") ||
        "no dependent rows";
      toast.success(`Deleted ${r.filename}`, detail);
      setConfirmDeleteId(null);
    },
    onError: (err) => toast.error("Delete failed", humanize(err)),
  });
  const nativeBridge = hasNativeBridge();

  // openWorkbook only carries frameworkId — baseline_id is server-materialized
  // from the workbook's column A scoping. Derive it here so the rest of the
  // file doesn't need to know about the picker's richer target shape.
  const frameworkId = target?.frameworkId;

  // Auto-select the only framework once loaded. "Only one" is measured
  // against the ENABLED set (migration 0012 display gate) — if a single
  // framework is enabled we auto-pick it even when disabled catalogs also
  // exist, and we never auto-pick a disabled one.
  useEffect(() => {
    const enabled = frameworks.data?.filter((f) => f.enabled !== false) ?? [];
    if (!target && enabled.length === 1) {
      setTarget({ frameworkId: enabled[0].id });
    }
  }, [target, frameworks.data]);

  async function pickAndOpen() {
    if (!nativeBridge) return; // button is hidden in browser mode
    const path = await window.ccis!.openFile([
      { name: "CCIS Workbook", extensions: ["xlsx", "xlsm"] },
    ]);
    if (!path) return; // user cancelled the dialog
    try {
      await open.mutateAsync({ path, frameworkId });
    } catch {
      // toast handled by onError
    }
  }

  async function openManualPath() {
    const path = manualPath.trim();
    if (!path) {
      toast.error("Path required", "Paste the absolute path to a .xlsx / .xlsm CCIS workbook.");
      return;
    }
    try {
      await open.mutateAsync({ path, frameworkId });
      setManualPath("");
    } catch {
      // toast handled by onError
    }
  }

  async function reopen(w: Workbook) {
    // If the workbook is already bound to a framework, reuse that binding
    // and skip the header picker entirely — passing frameworkId=undefined
    // lets the backend fall back to wb.framework_id (see workbooks.py
    // line ~82). Only require the picker for unbound workbooks (and for
    // first opens, handled by pickAndOpen / openManualPath above).
    const idForReopen = w.framework_id ?? frameworkId;
    try {
      await open.mutateAsync({ path: w.path, frameworkId: idForReopen });
    } catch {
      // toast handled by onError
    }
  }

  async function rebind(w: Workbook, newFrameworkId: number) {
    // Inline catalog rebind — used when the user picks a different framework
    // from the row's Framework dropdown. POST /api/workbooks is idempotent on
    // path: it reuses the existing Workbook row, rewrites framework_id, and
    // re-materializes the baseline against the new catalog (workbooks.py
    // open_workbook line ~107).
    if (newFrameworkId === w.framework_id) return;
    try {
      await open.mutateAsync({ path: w.path, frameworkId: newFrameworkId });
    } catch {
      // toast handled by onError
    }
  }

  async function downloadSarReport(workbookId: number) {
    try {
      await downloadSar.mutateAsync(workbookId);
    } catch (e) {
      toast.error("SAR download failed", humanize(e));
    }
  }

  const lastOpen = open.data;

  return (
    <div className="p-8 space-y-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Catalogs</h1>
          <p className="text-sm text-muted-foreground">
            Load a control catalog (NIST 800-53 r4 / r5, FedRAMP profile) and
            open the program workbook you'll assess against it. The framework
            is the published control library; the workbook is the program-
            specific assessment target — its column A defines what's in-scope
            and which CCIs are flagged NA. Both are managed here: use the
            framework picker's <em>Load</em> actions to add a catalog, and{" "}
            <em>Open workbook</em> to bring in a controls spreadsheet from disk.
          </p>
        </div>
        <div className="flex items-end gap-2">
          {/* Two independent pickers so "framework" (control catalog
              like NIST 800-53) and "baseline" (empty scope like SDA
              Enterprise Services / FedRAMP profile) stay visually and
              semantically separate. A baseline pick replaces both
              fields because a baseline is bound to a specific framework;
              a framework pick clears the baseline since the new
              framework may not have one selected. With no program
              workbook open, the user can still set a default framework
              AND/OR a default baseline here. */}
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground block">
              Framework
            </label>
            <ComplianceTargetPicker
              value={
                target?.frameworkId !== undefined
                  ? { frameworkId: target.frameworkId }
                  : undefined
              }
              onChange={(t) => setTarget({ frameworkId: t.frameworkId })}
              includeBaselines={false}
              placeholder="Pick a framework"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground block">
              Workbook
            </label>
            {/* Note: this picker lists *saved* workbooks (what the DB
                calls baselines — empty scopes materialized from a real
                assessment, a CRM overlay, an SSP, or manual). The
                "Open workbook" button next to it adds a *new* one from
                disk. Same noun, different verb: pick existing vs. add
                new. */}
            <ComplianceTargetPicker
              value={
                target?.baselineId !== undefined ? target : undefined
              }
              onChange={setTarget}
              includeFrameworks={false}
              showAddActions={false}
              placeholder="Pick a workbook"
            />
          </div>
          {nativeBridge && (
            <Button
              onClick={pickAndOpen}
              disabled={open.isPending || frameworkId === undefined}
              title={
                frameworkId === undefined
                  ? "Pick a framework first — opening without one indexes the file but skips baseline materialization"
                  : "Pick a CCIS program workbook (.xlsx / .xlsm) from disk"
              }
            >
              {open.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <FolderOpen className="h-4 w-4" />
              )}
              Open workbook
            </Button>
          )}
        </div>
      </header>

      {!nativeBridge && (
        <Card className="border-warning/40 bg-warning/5">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <AlertTriangle className="h-4 w-4 text-warning" />
              Running outside Electron — native file picker disabled
            </CardTitle>
            <CardDescription>
              You're connected to the sidecar over HTTP, but the OS file dialog only works in
              the Electron shell. Launch <code>pnpm electron:dev</code> for full UX, or paste a
              workbook path here to open it directly.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex gap-2">
              <Input
                placeholder="C:\Users\Noah.Jaskolski\OneDrive - …\CCIS_*.xlsx"
                value={manualPath}
                onChange={(e) => setManualPath(e.target.value)}
                className="font-mono text-xs"
                onKeyDown={(e) => {
                  if (e.key === "Enter") openManualPath();
                }}
              />
              <Button
                onClick={openManualPath}
                disabled={open.isPending || frameworkId === undefined || !manualPath.trim()}
                title={
                  frameworkId === undefined
                    ? "Pick a framework first"
                    : "Open the pasted workbook path"
                }
              >
                {open.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <FolderOpen className="h-4 w-4" />
                )}
                Open path
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Open workbook's baseline summary lives at the top, visually separated
          from the framework catalog below — the user's workbook-specific
          scope shouldn't compete for attention with the loaded-frameworks
          inventory (which is org-level, not per-workbook). */}
      {lastOpen?.baseline && (
        <Card className="border-primary/40 bg-primary/[0.03]">
          <CardHeader>
            <CardTitle>Open workbook — baseline summary</CardTitle>
            <CardDescription>
              {lastOpen.filename} — source {lastOpen.baseline.source_type}
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-4 text-sm">
            <Stat label="Controls in scope" value={lastOpen.baseline.controls_in_scope} />
            <Stat label="Controls out of scope" value={lastOpen.baseline.controls_out_of_scope} />
            <Stat label="Controls unknown" value={lastOpen.baseline.controls_unknown} />
            <Stat label="CCIs seen" value={lastOpen.baseline.objectives_seen} />
            {/* ODP ingest counters from the Assignment Values tab. Only the
                nonzero ones render — clean workbooks stay quiet, anything
                needing attention (new inserts, value changes, slot drift)
                surfaces as a discrete Stat. Orphan tooltip lists the
                control ids so the assessor knows where to look. */}
            <OdpStats notes={lastOpen.baseline.notes?.odp_assignments} />
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Loaded frameworks</CardTitle>
          <CardDescription>
            Published control catalogs (NIST 800-53, FedRAMP, …) available
            for binding. Load missing pieces from <strong>Settings</strong>.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {catalog.isLoading ? (
            <div className="text-sm text-muted-foreground">Loading…</div>
          ) : catalog.error ? (
            <div className="text-sm text-destructive">
              Couldn't reach the sidecar — is the backend running?
            </div>
          ) : (catalog.data?.frameworks.filter((f) => f.enabled !== false)
              .length ?? 0) === 0 ? (
            <div className="text-sm text-muted-foreground">
              No frameworks loaded yet. Click <strong>Load NIST 800-53r5</strong> above
              to get started.
            </div>
          ) : (
            <>
              {/* Catalog inventory = frameworks "available for binding". A
                  framework toggled off in Settings (migration 0012 display
                  gate) is not available for binding, so it drops out of this
                  section entirely — re-enable it in Settings to bring it back. */}
              <div className="flex flex-wrap gap-3">
                {catalog
                  .data!.frameworks.filter((f) => f.enabled !== false)
                  .map((f) => (
                  <div
                    key={f.id}
                    className="rounded-md border px-4 py-2 flex flex-col gap-1 min-w-[220px]"
                  >
                    <div className="text-sm font-medium">
                      {f.name}{" "}
                      <span className="text-xs text-muted-foreground">
                        {f.version}
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-2 text-xs">
                      <Badge variant="outline" className="tabular-nums">
                        {f.control_count} controls
                      </Badge>
                      {f.objective_count > 0 ? (
                        <Badge variant="secondary" className="tabular-nums">
                          {f.objective_count} CCIs
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-muted-foreground">
                          DISA CCI overlay not loaded
                        </Badge>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Indexed</CardTitle>
          <CardDescription>
            {workbooks.data?.length ?? 0} workbook
            {workbooks.data?.length === 1 ? "" : "s"} known
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>File</TableHead>
                <TableHead>Path</TableHead>
                <TableHead>Framework</TableHead>
                <TableHead>Baseline</TableHead>
                <TableHead>Overlays</TableHead>
                <TableHead>Last opened</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {workbooks.data?.map((w) => (
                <TableRow key={w.id}>
                  <TableCell className="font-medium">
                    <div className="flex items-center gap-2">
                      <FileSpreadsheet className="h-4 w-4 text-muted-foreground" />
                      <span>{w.filename}</span>
                      {/* Running LLM-judge spend on SharePoint sweeps for this
                          workbook. Hidden when zero so we don't clutter
                          freshly-created rows. */}
                      {w.total_sweep_cost_usd && w.total_sweep_cost_usd > 0 ? (
                        <span
                          className="text-[11px] font-normal text-muted-foreground tabular-nums"
                          title="Total LLM-judge spend on SharePoint sweeps for this workbook"
                        >
                          ${w.total_sweep_cost_usd.toFixed(2)} total
                        </span>
                      ) : null}
                    </div>
                  </TableCell>
                  <TableCell
                    className="text-xs text-muted-foreground max-w-md"
                    title={w.path}
                  >
                    <div className="truncate">{w.path}</div>
                    {w.working_path && (
                      <div
                        className="truncate text-[11px] mt-0.5 text-foreground/70"
                        title={w.working_path}
                      >
                        Assessments → {w.working_path.split(/[\\/]/).pop()}
                      </div>
                    )}
                  </TableCell>
                  <TableCell>
                    {/* Inline catalog rebind — picking a different framework
                        re-opens the workbook against the new catalog
                        (open_workbook is idempotent on path). Lets users fix
                        a mis-bound workbook without re-opening through the
                        header picker. Disabled while an open is in flight
                        for THIS workbook so two clicks can't race. */}
                    <Select
                      value={w.framework_id != null ? String(w.framework_id) : ""}
                      onValueChange={(v) => rebind(w, Number(v))}
                      disabled={
                        (frameworks.data ?? []).length === 0 ||
                        (open.isPending && open.variables?.path === w.path)
                      }
                    >
                      <SelectTrigger
                        className="h-7 w-[200px] text-xs"
                        title={
                          w.framework_id != null
                            ? "Change the framework this workbook is bound to — re-runs baseline materialization against the new framework"
                            : "Bind this workbook to a loaded framework"
                        }
                      >
                        <SelectValue placeholder="— pick framework —" />
                      </SelectTrigger>
                      <SelectContent>
                        {/* Rebind targets are the ENABLED frameworks
                            (migration 0012 display gate). The workbook's
                            currently-bound framework is always kept in the
                            list even if it was later disabled, so the Select
                            value still resolves and the user can see what
                            it's bound to (and rebind away from it). */}
                        {(frameworks.data ?? [])
                          .filter(
                            (f) =>
                              f.enabled !== false || f.id === w.framework_id,
                          )
                          .map((f) => (
                            <SelectItem key={f.id} value={String(f.id)}>
                              {f.name} {f.version}
                            </SelectItem>
                          ))}
                      </SelectContent>
                    </Select>
                  </TableCell>
                  <TableCell>
                    {w.baseline_id ? (
                      <Badge variant="secondary">#{w.baseline_id}</Badge>
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <OverlayChips
                      workbook={w}
                      baselines={baselines.data ?? []}
                      onManage={() => setOverlayWbId(w.id)}
                    />
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {new Date(w.last_opened).toLocaleString()}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => reopen(w)}
                        disabled={
                          open.isPending ||
                          // Unbound workbook AND no header picker = no
                          // target to use — disable to avoid a silent
                          // no-baseline open.
                          (w.framework_id === null && frameworkId === undefined)
                        }
                        title={
                          w.framework_id !== null
                            ? `Re-open with this workbook's saved framework (#${w.framework_id}) — header picker ignored`
                            : frameworkId === undefined
                              ? "Pick a framework first — this workbook has no saved binding"
                              : "Re-open with the selected framework (will bind this workbook to it)"
                        }
                      >
                        {open.isPending && open.variables?.path === w.path ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <RefreshCw className="h-4 w-4" />
                        )}
                        Re-open
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => downloadSarReport(w.id)}
                        disabled={downloadSar.isPending && downloadSar.variables === w.id}
                        title="Download NIST SP 800-53A Security Assessment Report"
                      >
                        {downloadSar.isPending && downloadSar.variables === w.id ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <ShieldCheck className="h-4 w-4" />
                        )}
                        SAR
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => setConfirmDeleteId(w.id)}
                        disabled={del.isPending && del.variables === w.id}
                        className="text-destructive hover:text-destructive"
                        title="Delete this workbook and its assessments/POAMs (Evidence stays)"
                      >
                        {del.isPending && del.variables === w.id ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <Trash2 className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {workbooks.data?.length === 0 && (
                <TableRow>
                  <TableCell
                    colSpan={7}
                    className="text-center text-sm text-muted-foreground py-8"
                  >
                    No workbooks yet — pick a framework, then click{" "}
                    <strong>Open workbook</strong> to load your program
                    workbook.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <ManageOverlaysDialog
        workbook={overlayWb}
        baselines={baselines.data ?? []}
        onClose={() => setOverlayWbId(null)}
      />

      <Dialog
        open={confirmDeleteId !== null}
        onOpenChange={(open) => {
          if (!open && !del.isPending) setConfirmDeleteId(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              Delete workbook
              {confirmDeleteWb ? ` “${confirmDeleteWb.filename}”` : ""}?
            </DialogTitle>
            <DialogDescription>
              Removes the workbook record plus every workbook-owned row:{" "}
              <strong>assessments</strong> (verdicts + traces + prompt snapshots),{" "}
              <strong>POAMs</strong> with their milestones and objective links,{" "}
              <strong>sweep runs</strong>, <strong>CRM telemetry</strong>{" "}
              (suspicion / short-circuit events / corpus features),{" "}
              <strong>assets</strong>, <strong>boundary segments</strong>, and{" "}
              <strong>STIG findings</strong>. Overlay attachments are detached.
              <br />
              <br />
              <strong>Evidence files and system-context entries are kept</strong>{" "}
              — their <code>workbook_id</code> is just unlinked so they can be
              re-attached to a future workbook. The xlsx on disk and the
              auto-created Baseline are <em>not</em> touched. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setConfirmDeleteId(null)}
              disabled={del.isPending}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => {
                if (confirmDeleteId !== null) del.mutate(confirmDeleteId);
              }}
              disabled={del.isPending || confirmDeleteId === null}
            >
              {del.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Trash2 className="h-4 w-4" />
              )}
              Delete workbook
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function OverlayChips({
  workbook,
  baselines,
  onManage,
}: {
  workbook: Workbook;
  // source_type is included so the chip can render an OTHER overlay
  // subdued ("inert · no resolver") instead of the same tone as an
  // active CRM/PSC overlay.
  baselines: { id: number; name: string; source_type?: string }[];
  onManage: () => void;
}) {
  const byId = useMemo(
    () => new Map(baselines.map((b) => [b.id, b])),
    [baselines],
  );
  const ids = workbook.overlay_baseline_ids ?? [];
  return (
    <div className="flex flex-wrap items-center gap-1">
      {ids.length === 0 ? (
        <span className="text-xs text-muted-foreground">—</span>
      ) : (
        ids.map((id) => {
          const b = byId.get(id);
          const isInert = b?.source_type === "other";
          return (
            <Badge
              key={id}
              variant="outline"
              className={cn(
                "text-xs",
                isInert &&
                  "border-dashed text-muted-foreground/70",
              )}
              title={
                b
                  ? `${b.name} (#${id})${isInert ? " · inert, no resolver" : ""}`
                  : `Baseline #${id}`
              }
            >
              {b?.name ?? `#${id}`}
            </Badge>
          );
        })
      )}
      <Button
        size="sm"
        variant="ghost"
        className="h-6 px-2 text-xs"
        onClick={onManage}
        title="Attach / detach reference overlays for this workbook"
      >
        <Layers className="h-3 w-3" />
        Manage
      </Button>
    </div>
  );
}

function ManageOverlaysDialog({
  workbook,
  baselines,
  onClose,
}: {
  workbook: Workbook | null;
  baselines: { id: number; name: string; framework_id: number; source_type: string }[];
  onClose: () => void;
}) {
  const attach = useAttachOverlay();
  const detach = useDetachOverlay();
  const importOverlay = useImportOverlay();
  const nativeBridge = hasNativeBridge();

  // --- Scope-label picker state for CRM uploads (ported from Settings.tsx
  // ImportOverlayCard). The file-picker fires first, then the scope-label
  // inline form appears so the user can pick a scope before the POST.
  const scopeLabels = useScopeLabels();
  const [crmPendingPath, setCrmPendingPath] = useState<string | null>(null);
  const [crmScopeChoice, setCrmScopeChoice] = useState<string>("");
  const [crmScopeOther, setCrmScopeOther] = useState<string>("");
  const otherLabel = scopeLabels.data?.other ?? "Other";
  const onPremLabel = scopeLabels.data?.on_prem ?? "On-Premises";
  const resolvedCrmScopeLabel =
    crmScopeChoice === otherLabel ? crmScopeOther.trim() : crmScopeChoice.trim();
  const crmScopeReady =
    resolvedCrmScopeLabel !== "" && resolvedCrmScopeLabel !== onPremLabel;

  if (!workbook) return null;

  // Phase 1: pick a file — this opens the native dialog and stores the path;
  // the scope-label picker renders inline so the user can choose before POST.
  async function pickCrmFile() {
    if (!nativeBridge || !workbook || workbook.framework_id == null) return;
    const path = await window.ccis!.openFile([
      { name: "CRM workbook", extensions: ["xlsx", "xlsm"] },
    ]);
    if (!path) return; // user cancelled
    setCrmPendingPath(path);
    setCrmScopeChoice("");
    setCrmScopeOther("");
  }

  // Phase 2: upload with scope_label via the unified import endpoint.
  async function confirmCrmUpload() {
    if (!workbook || workbook.framework_id == null || !crmPendingPath || !crmScopeReady) return;
    try {
      const result = await importOverlay.mutateAsync({
        framework_id: workbook.framework_id,
        path: crmPendingPath,
        kind_hint: "crm",
        scope_label: resolvedCrmScopeLabel,
      });
      // Auto-attach the newly-created baseline to this workbook.
      let applied = 0;
      if (result.baseline_id != null) {
        const attachResult = await attach.mutateAsync({
          workbookId: workbook.id,
          baselineId: result.baseline_id,
        });
        applied = attachResult.backfill?.applied ?? 0;
      }
      // Split diagnostics by failure mode. Catalog-miss (control not in
      // loaded framework) and unrecognized-responsibility (typo'd cell
      // value) are independent — the old toast conflated them under one
      // label and silently dropped the responsibility-miss count entirely.
      const parts: string[] = [];
      if (result.controls_in_scope !== undefined) {
        parts.push(`${result.controls_in_scope} controls ingested`);
      }
      if ((result.controls_unknown ?? 0) > 0) {
        const ids = result.unknown_control_ids ?? [];
        const sample = ids.slice(0, 5).join(", ");
        const more = ids.length > 5 ? `, +${ids.length - 5} more` : "";
        parts.push(
          `${result.controls_unknown} not in catalog (${sample}${more})`,
        );
      }
      if ((result.unknown_responsibility_rows ?? 0) > 0) {
        parts.push(
          `${result.unknown_responsibility_rows} row${
            result.unknown_responsibility_rows === 1 ? "" : "s"
          } with unrecognized responsibility`,
        );
      }
      if (applied > 0) {
        parts.push(
          `backfilled ${applied} control${applied === 1 ? "" : "s"}`,
        );
      }
      // Re-surface any cached suspicion verdict from a prior compute on
      // this workbook. Pure read — does NOT trigger the embedder /
      // IsolationForest pipeline, so re-uploading the same CRM is cheap.
      // 404 = never computed → silent skip. Mark-false-positive also
      // suppresses the toast clause so a cleared verdict doesn't re-nag.
      try {
        const cached = await api.getLatestCrmSuspicion(workbook.id);
        if (!cached.assessor_marked_false_positive) {
          const elevated = cached.flags.filter(
            (f) => f.severity === "alert" || f.severity === "warn",
          );
          if (elevated.length > 0) {
            const pct = Math.round(cached.overall_suspicion * 100);
            const sample = elevated
              .slice(0, 2)
              .map((f) => f.name)
              .join(", ");
            const more =
              elevated.length > 2 ? `, +${elevated.length - 2} more` : "";
            parts.push(
              `prior suspicion ${pct}% (${sample}${more}) — review on CRM detail`,
            );
          }
        }
      } catch {
        // 404 (never computed) or transient — toast stays informative
        // without the suspicion clause.
      }
      toast.success(`Loaded CRM "${result.name}"`, parts.join(" · "));
      setCrmPendingPath(null); // close the inline scope picker
    } catch (e) {
      toast.error("CRM upload failed", humanize(e));
    }
  }

  // Upload PSC = pick a program-specific controls xlsx, materialize the
  // synthetic Baseline + RequirementSource into the global catalog, then
  // explicitly attach it to THIS workbook. Mirrors pickAndUploadCrm's
  // two-step pattern: the loader is a pure catalog op (no implicit
  // WorkbookOverlay writes) so reload semantics are predictable — every
  // attach is explicit and visible at this call site, not a hidden
  // side effect gated on "first creation". See program_controls_loader.py
  // for the no-auto-attach rationale.
  async function pickAndUploadPsc() {
    if (!nativeBridge || !workbook || workbook.framework_id == null) return;
    const path = await window.ccis!.openFile([
      { name: "PSC workbook", extensions: ["xlsx", "xlsm"] },
    ]);
    if (!path) return;
    try {
      const result = await importOverlay.mutateAsync({
        framework_id: workbook.framework_id,
        path,
        kind_hint: "psc",
      });
      // Explicit attach — the import endpoint no longer auto-attaches.
      // baseline_id is optional in the response type because OTHER-kind
      // overlays don't materialize a Baseline, but the PSC dispatch
      // always returns one; guard anyway to keep the type honest.
      if (result.baseline_id != null) {
        await attach.mutateAsync({
          workbookId: workbook.id,
          baselineId: result.baseline_id,
        });
      }
      const parts: string[] = [];
      if (result.rows_seen !== undefined) {
        parts.push(`${result.rows_seen} rows`);
      }
      if (result.maps_written !== undefined) {
        parts.push(`${result.maps_written} mappings`);
      }
      const unmapped = result.unmapped_ccis?.length ?? 0;
      if (unmapped > 0) {
        parts.push(`${unmapped} unmapped CCI${unmapped === 1 ? "" : "s"}`);
      }
      const unmappedCtl = result.unmapped_control_ids?.length ?? 0;
      if (unmappedCtl > 0) {
        parts.push(
          `${unmappedCtl} unmapped control${unmappedCtl === 1 ? "" : "s"}`,
        );
      }
      if (result.warnings.length > 0) {
        parts.push(result.warnings[0]);
      }
      toast.success(
        `Loaded PSC "${result.name}"`,
        parts.length > 0 ? parts.join(" · ") : "Attached to this workbook",
      );
    } catch (e) {
      toast.error("PSC upload failed", humanize(e));
    }
  }

  const attachedIds = new Set(workbook.overlay_baseline_ids ?? []);
  // Show baselines on the same framework as the workbook, excluding the
  // workbook's own primary (it can't be both write target and read overlay).
  // OSCAL-profile baselines (FedRAMP Low/Mod/High/Li-SaaS) are filtered out
  // because they're first-class assessment targets — you pick them from the
  // compliance target dropdown, not attach them as annotation overlays. The
  // backend mirrors this rule in routes/workbooks.py::attach_workbook_overlay.
  const eligible = baselines.filter(
    (b) =>
      (workbook.framework_id == null || b.framework_id === workbook.framework_id) &&
      b.id !== workbook.baseline_id &&
      b.source_type !== "oscal_profile",
  );
  // Split the eligible list into two visually distinct sections so the
  // currently-attached set isn't redundantly rendered as "checked checkboxes"
  // alongside available candidates. Detach is a dedicated button on each
  // attached row; attach is a click on an available row. This was the
  // "weird checkbox" feedback after CRM auto-upload: the just-attached CRM
  // appeared in the candidate list as already-checked, which read as a
  // confirmation control rather than a detach toggle.
  // Sort PSC → CRM → OTHER so the active resolvers surface first and
  // the inert OTHER overlays sit at the bottom. Within a kind, keep
  // the existing (id) order so the list is stable across re-renders.
  const overlayRank: Record<string, number> = {
    program_controls: 0,
    crm: 1,
    other: 2,
  };
  const byKind = (a: { source_type: string }, b: { source_type: string }) =>
    (overlayRank[a.source_type] ?? 99) - (overlayRank[b.source_type] ?? 99);
  const attached = eligible.filter((b) => attachedIds.has(b.id)).sort(byKind);
  const available = eligible.filter((b) => !attachedIds.has(b.id)).sort(byKind);

  const doAttach = async (baselineId: number) => {
    try {
      const result = await attach.mutateAsync({
        workbookId: workbook.id,
        baselineId,
      });
      const bf = result.backfill;
      const parts: string[] = [`Baseline #${baselineId}`];
      if (bf) {
        if (bf.applied > 0) {
          parts.push(
            `backfilled ${bf.applied} control${bf.applied === 1 ? "" : "s"}`,
          );
        }
        // When applied=0 the user is left wondering why the CRM attach
        // looked like a no-op. Surface the dominant skip reason so the
        // toast explains the silence. Priority order:
        //   1. skipped_existing — controls already had assessment data;
        //      backfill refuses to overwrite assessor work. This is the
        //      most common "nothing happened" cause on a re-attach.
        //   2. skipped_non_deterministic — CRM entries were customer or
        //      hybrid; those need assessor judgment, not auto-backfill.
        //   3. skipped_no_crm_entry / skipped_no_workbook_row — usually
        //      uninteresting (CRM is partial by design, workbook scope
        //      is the user's choice). Only surface if they're the only
        //      non-zero reason, to avoid the "nothing happened, no
        //      explanation" UX.
        if (bf.applied === 0) {
          if (bf.skipped_existing > 0) {
            parts.push(
              `${bf.skipped_existing} already assessed (left intact)`,
            );
          } else if (bf.skipped_non_deterministic > 0) {
            parts.push(
              `${bf.skipped_non_deterministic} customer/hybrid (needs assessor)`,
            );
          } else if (bf.skipped_no_crm_entry > 0) {
            parts.push(`${bf.skipped_no_crm_entry} not in CRM`);
          } else if (bf.skipped_no_workbook_row > 0) {
            parts.push(
              `${bf.skipped_no_workbook_row} not in workbook scope`,
            );
          }
        }
      }
      toast.success("Overlay attached", parts.join(" · "));
    } catch (e) {
      toast.error("Attach failed", humanize(e));
    }
  };
  const doDetach = async (baselineId: number) => {
    try {
      await detach.mutateAsync({ workbookId: workbook.id, baselineId });
      toast.info("Overlay detached", `Baseline #${baselineId}`);
    } catch (e) {
      toast.error("Detach failed", humanize(e));
    }
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>Manage overlays — {workbook.filename}</DialogTitle>
          <DialogDescription>
            Reference overlays annotate this workbook with another baseline's
            scope so the Controls grid and SAR PDF show cross-baseline
            coverage. They do <strong>not</strong> change which CCIs are
            assessed — that stays the workbook's primary baseline
            (#{workbook.baseline_id ?? "—"}).
          </DialogDescription>
        </DialogHeader>
        {eligible.length === 0 ? (
          <div className="text-sm text-muted-foreground py-4">
            No other baselines on this workbook's framework to attach as
            overlays.
          </div>
        ) : (
          <div className="max-h-[400px] overflow-y-auto space-y-4">
            {attached.length > 0 && (
              <div className="space-y-1">
                <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground px-1">
                  Attached ({attached.length})
                </div>
                {attached.map((b) => {
                  const busy =
                    detach.isPending && detach.variables?.baselineId === b.id;
                  const isInert = b.source_type === "other";
                  // Map storage source_type to the user-facing taxonomy label
                  // (PSC / CRM / Other) — internal strings stay as-is.
                  const kindLabel =
                    b.source_type === "program_controls"
                      ? "PSC"
                      : b.source_type === "crm"
                        ? "CRM"
                        : b.source_type === "other"
                          ? "Other"
                          : b.source_type;
                  return (
                    <div
                      key={b.id}
                      className={cn(
                        "flex items-center gap-3 rounded-md border px-3 py-2",
                        isInert
                          ? "border-dashed border-muted-foreground/40 bg-muted/30"
                          : "border-primary/30 bg-primary/5",
                      )}
                    >
                      <Layers
                        className={cn(
                          "h-4 w-4 shrink-0",
                          isInert ? "text-muted-foreground/60" : "text-primary",
                        )}
                      />
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium truncate">{b.name}</div>
                        <div className="text-xs text-muted-foreground">
                          #{b.id} · {kindLabel}
                          {isInert && (
                            <span className="italic"> · inert, no resolver</span>
                          )}
                        </div>
                      </div>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-7 px-2 text-xs"
                        onClick={() => doDetach(b.id)}
                        disabled={busy}
                        title="Detach this overlay from the workbook"
                      >
                        {busy ? (
                          <Loader2 className="h-3 w-3 animate-spin" />
                        ) : (
                          <X className="h-3 w-3" />
                        )}
                        Detach
                      </Button>
                    </div>
                  );
                })}
              </div>
            )}
            {available.length > 0 && (
              <div className="space-y-1">
                <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground px-1">
                  Available ({available.length})
                </div>
                {available.map((b) => {
                  const busy =
                    attach.isPending && attach.variables?.baselineId === b.id;
                  const isInert = b.source_type === "other";
                  const kindLabel =
                    b.source_type === "program_controls"
                      ? "PSC"
                      : b.source_type === "crm"
                        ? "CRM"
                        : b.source_type === "other"
                          ? "Other"
                          : b.source_type;
                  return (
                    <button
                      key={b.id}
                      type="button"
                      onClick={() => doAttach(b.id)}
                      disabled={busy}
                      className={cn(
                        "w-full flex items-center gap-3 rounded-md border px-3 py-2 hover:bg-muted text-left disabled:opacity-60",
                        isInert && "border-dashed text-muted-foreground/80",
                      )}
                    >
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium truncate">{b.name}</div>
                        <div className="text-xs text-muted-foreground">
                          #{b.id} · {kindLabel}
                          {isInert && (
                            <span className="italic"> · inert, no resolver</span>
                          )}
                        </div>
                      </div>
                      {busy ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <span className="text-xs text-muted-foreground">Attach</span>
                      )}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        )}
        {/* Inline scope-label picker — appears after the user picks a CRM
            file via the native dialog. Must choose a scope before the POST
            fires. Mirrors the ImportOverlayCard pattern from Settings.tsx. */}
        {crmPendingPath && (
          <div className="space-y-2 rounded-md border p-3">
            <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              CRM scope label
            </div>
            <p className="text-xs text-muted-foreground">
              Pick the cloud implementation scope this CRM covers.
            </p>
            <Select value={crmScopeChoice} onValueChange={(v) => setCrmScopeChoice(v)}>
              <SelectTrigger>
                <SelectValue placeholder="Pick a scope label" />
              </SelectTrigger>
              <SelectContent>
                {(scopeLabels.data?.canonical ?? []).map((label: string) => (
                  <SelectItem key={label} value={label}>
                    {label}
                  </SelectItem>
                ))}
                <SelectItem value={otherLabel}>{otherLabel}…</SelectItem>
              </SelectContent>
            </Select>
            {crmScopeChoice === otherLabel && (
              <Input
                value={crmScopeOther}
                onChange={(e) => setCrmScopeOther(e.target.value)}
                placeholder="Custom scope label (e.g. IBM Cloud for Government)"
                autoComplete="off"
              />
            )}
            {resolvedCrmScopeLabel === onPremLabel && (
              <p className="text-xs text-destructive">
                "{onPremLabel}" is reserved — the assessor derives the
                on-prem implementation automatically. Pick a cloud scope
                label (or "{otherLabel}…" for a custom value).
              </p>
            )}
            <div className="flex items-center gap-2 pt-1">
              <Button
                size="sm"
                onClick={confirmCrmUpload}
                disabled={!crmScopeReady || importOverlay.isPending || attach.isPending}
              >
                {importOverlay.isPending || attach.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Upload className="h-4 w-4" />
                )}
                Import CRM
              </Button>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => setCrmPendingPath(null)}
                disabled={importOverlay.isPending}
              >
                Cancel
              </Button>
            </div>
          </div>
        )}
        <div className="flex items-center justify-between gap-2">
          {nativeBridge && workbook.framework_id != null ? (
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                onClick={pickCrmFile}
                disabled={importOverlay.isPending || attach.isPending || !!crmPendingPath}
                title="Pick a FedRAMP-style CRM xlsx — you will choose a scope label before upload"
              >
                {importOverlay.isPending || attach.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Upload className="h-4 w-4" />
                )}
                Upload CRM…
              </Button>
              <Button
                variant="outline"
                onClick={pickAndUploadPsc}
                disabled={importOverlay.isPending || attach.isPending}
                title="Pick a program-specific controls (PSC) xlsx — it will be loaded into the global catalog and attached to this workbook as an overlay"
              >
                {importOverlay.isPending || attach.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Upload className="h-4 w-4" />
                )}
                Upload PSC…
              </Button>
            </div>
          ) : (
            <span className="text-xs text-muted-foreground">
              {workbook.framework_id == null
                ? "Bind a framework first to upload an overlay"
                : "Overlay upload requires the Electron shell"}
            </span>
          )}
          <Button variant="outline" onClick={onClose}>
            <X className="h-4 w-4" />
            Close
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function Stat({
  label,
  value,
  title,
}: {
  label: string;
  value: number;
  title?: string;
}) {
  return (
    <div className="rounded-md border px-4 py-2" title={title}>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-xl font-semibold tabular-nums">{value}</div>
    </div>
  );
}

/**
 * Render ODP ingest counters from `WorkbookBaselineSummary.notes.odp_assignments`.
 *
 * Renders ONLY the counters that are nonzero. Three signals matter to the
 * assessor:
 *   - `inserted` / `updated` — what landed on this ingest
 *   - `value_rows_without_slot` — workbook drift (orphan rows the
 *     positional bridge couldn't align). Tooltip lists the affected
 *     control ids so the assessor knows where to investigate.
 *   - `oscal_mapping_abstained` — the bridge intentionally abstained on
 *     a control because OSCAL param count didn't match workbook slot
 *     count. Worth flagging because the renderer will fall back to
 *     by-id lookup (still correct, just lower-precision).
 */
function OdpStats({ notes }: { notes?: OdpAssignmentNotes }) {
  if (!notes) return null;
  const orphanCount = notes.value_rows_without_slot;
  return (
    <>
      {notes.inserted > 0 && (
        <Stat label="ODPs inserted" value={notes.inserted} />
      )}
      {notes.updated > 0 && (
        <Stat label="ODPs updated" value={notes.updated} />
      )}
      {orphanCount > 0 && (
        <Stat
          label="ODP orphans"
          value={orphanCount}
          title={
            notes.controls_with_orphan_values.length > 0
              ? `Value-bearing rows whose odp_id isn't in the parameterized statement column's slot list. Affected controls:\n${notes.controls_with_orphan_values.join(", ")}`
              : "Value-bearing rows whose odp_id isn't in the parameterized statement column's slot list."
          }
        />
      )}
      {notes.oscal_mapping_abstained > 0 && (
        <Stat
          label="OSCAL bridge abstained"
          value={notes.oscal_mapping_abstained}
          title="OSCAL param count didn't match workbook slot count for this many controls — the positional bridge abstained rather than risk a misalignment. Renderer falls back to by-id lookup."
        />
      )}
    </>
  );
}

/**
 * One-line compact form of `OdpStats` for toast subtitles.
 *
 * Joins only nonzero counters with commas. Returns `null` when every
 * counter is zero so callers can omit the clause entirely (no trailing
 * separator on clean workbooks). Same "only when nonzero" rule as
 * `OdpStats` — quiet on routine re-opens, vocal when something landed.
 */
export function summarizeOdpNotes(notes?: OdpAssignmentNotes): string | null {
  if (!notes) return null;
  const parts: string[] = [];
  if (notes.inserted > 0) parts.push(`+${notes.inserted} ODP`);
  if (notes.updated > 0) parts.push(`${notes.updated} updated`);
  if (notes.value_rows_without_slot > 0)
    parts.push(`${notes.value_rows_without_slot} orphan${notes.value_rows_without_slot === 1 ? "" : "s"}`);
  if (notes.oscal_mapping_abstained > 0)
    parts.push(`${notes.oscal_mapping_abstained} bridge-abstained`);
  return parts.length > 0 ? parts.join(", ") : null;
}
