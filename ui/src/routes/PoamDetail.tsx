/**
 * Single-POAM editor.
 *
 * Layout (top → bottom):
 *   1. Back link + header with status badge, severity badge, delete button
 *   2. Identity card  — control_cluster (read-only), eMASS POAM id,
 *      security_control_number, source_identifying_control_vulnerability,
 *      office_org
 *   3. Description card — vulnerability_description (textarea),
 *      resources_required, mitigations, comments
 *   4. Risk card — likelihood / impact / relevance_of_threat / residual_risk
 *      dropdowns; computed raw_severity readout next to likelihood+impact
 *   5. Schedule card — status, scheduled + actual completion date inputs
 *   6. Milestones card — list with edit/delete + "add milestone" form
 *   7. Linked objectives card — list with unlink + numeric add-objective form
 *
 * Editing model: every text/date/select field is "dirty-aware" — the field
 * holds local state while focused and writes back via `useUpdatePoam.mutate`
 * on blur. Risk + status dropdowns fire immediately on change (no blur step
 * for a Select). Mutations invalidate the per-POAM detail query and the
 * POAM list query (milestone/objective counts move).
 *
 * Out of scope here: free-text controlId search for linking objectives
 * (that needs an autocomplete UX backed by a new endpoint) — for v0.1 the
 * user pastes a numeric Objective.id, same as the manual-create flow.
 */

import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeft,
  Loader2,
  Pencil,
  Plus,
  Trash2,
  X,
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
import type {
  PoamEvidenceLink,
  PoamMilestone,
  PoamStatus,
  RiskLevel,
} from "@/lib/api";
import {
  dateInputToIso,
  formatDate,
  formatDateTime,
  isoToDateInput,
  severityClasses,
  statusClasses,
} from "@/lib/poamFormat";
import {
  useCreatePoamMilestone,
  useDeletePoam,
  useDeletePoamMilestone,
  useLinkPoamEvidence,
  useLinkPoamObjective,
  usePoam,
  usePoamRiskLevels,
  useUnlinkPoamEvidence,
  useUnlinkPoamObjective,
  useUpdatePoam,
  useUpdatePoamMilestone,
} from "@/lib/queries";
import { RiskHistoryCard } from "@/components/poam/RiskHistoryCard";
import { ResidualAdvisorCard } from "@/components/poam/ResidualAdvisorCard";

const STATUS_VALUES: PoamStatus[] = [
  "Draft",
  "Ongoing",
  "Risk Accepted",
  "Completed",
];

const SENTINEL_CLEAR = "__clear__";

type ProvenanceSource =
  | "auto"
  | "default"
  | "manual"
  | "llm_suggested"
  | null;

/**
 * Source badge next to a risk dropdown. Mirrors the provenance taxonomy in
 * alembic 0008 / poam/risk.py. NULL renders nothing so legacy rows stay clean
 * until the assessor edits them (at which point the PATCH stamps "manual").
 */
function SourceBadge({ source }: { source: ProvenanceSource }) {
  if (!source) return null;
  const cfg = {
    auto: {
      label: "Auto",
      title: "Seeded by the generator from STIG CAT severity.",
      className: "border-sky-400/60 text-sky-700 dark:text-sky-300",
    },
    default: {
      label: "Default",
      title:
        "Baseline MODERATE default seeded by the generator — no STIG/CVSS signal to ground it. Review before exporting.",
      className: "border-muted-foreground/40 text-muted-foreground",
    },
    manual: {
      label: "Manual",
      title: "Set by the assessor.",
      className: "border-muted-foreground/40 text-muted-foreground",
    },
    llm_suggested: {
      label: "LLM",
      title:
        "Applied from the residual-risk advisor suggestion. Review the rationale before exporting.",
      className: "border-amber-400/60 text-amber-700 dark:text-amber-300",
    },
  }[source];
  return (
    <Badge
      variant="outline"
      className={`text-[10px] uppercase tracking-wide ${cfg.className}`}
      title={cfg.title}
    >
      {cfg.label}
    </Badge>
  );
}

/**
 * One row of the Risk card: label + source badge + RiskSelect + rationale
 * TextArea. Combines the three pieces that all share the same provenance
 * triple so the assessor sees them as one logical control.
 */
function RiskFieldWithProvenance({
  label,
  value,
  options,
  onValueChange,
  source,
  rationale,
  onRationaleCommit,
  rationaleLabel,
}: {
  label: string;
  value: RiskLevel | null;
  options: RiskLevel[];
  onValueChange: (next: RiskLevel | null) => void;
  source: ProvenanceSource;
  rationale: string | null;
  onRationaleCommit: (next: string | null) => void;
  rationaleLabel: string;
}) {
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-xs font-medium text-muted-foreground">
          {label}
        </span>
        <SourceBadge source={source} />
      </div>
      <RiskSelect value={value} options={options} onChange={onValueChange} />
      <TextArea
        label={rationaleLabel}
        value={rationale}
        onCommit={onRationaleCommit}
        rows={2}
      />
    </div>
  );
}

/**
 * Build the option list for a RiskLevel dropdown. We always lead with a
 * "—" choice so the field can be cleared without typing — the special
 * `SENTINEL_CLEAR` value is mapped back to `null` before being sent.
 */
function RiskSelect({
  value,
  onChange,
  options,
  disabled,
  placeholder = "—",
}: {
  value: RiskLevel | null;
  onChange: (next: RiskLevel | null) => void;
  options: RiskLevel[];
  disabled?: boolean;
  placeholder?: string;
}) {
  return (
    <Select
      value={value ?? SENTINEL_CLEAR}
      disabled={disabled}
      onValueChange={(v) =>
        onChange(v === SENTINEL_CLEAR ? null : (v as RiskLevel))
      }
    >
      <SelectTrigger className="w-[160px]">
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={SENTINEL_CLEAR}>—</SelectItem>
        {options.map((o) => (
          <SelectItem key={o} value={o}>
            {o}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

export function PoamDetail() {
  const { poamId: poamIdParam } = useParams<{ poamId: string }>();
  const poamId = poamIdParam ? Number(poamIdParam) : NaN;
  const navigate = useNavigate();

  const poam = usePoam(Number.isFinite(poamId) ? poamId : undefined);
  const riskLevels = usePoamRiskLevels();
  const riskOptions: RiskLevel[] = (riskLevels.data ?? []).map((r) => r.value);

  const update = useUpdatePoam(poamId, {
    onError: (e) => toast.error("Update failed", humanize(e)),
  });
  const del = useDeletePoam({
    onSuccess: () => {
      toast.success("POAM deleted");
      navigate("/poams");
    },
    onError: (e) => toast.error("Delete failed", humanize(e)),
  });

  const [confirmDelete, setConfirmDelete] = useState(false);

  if (poam.isLoading || !poam.data) {
    return (
      <div className="p-8 space-y-4">
        <Button asChild variant="ghost" size="sm">
          <Link to="/poams">
            <ArrowLeft className="h-4 w-4" />
            Back to POAMs
          </Link>
        </Button>
        <div className="text-sm text-muted-foreground">
          {poam.isLoading ? (
            <>
              <Loader2 className="inline h-4 w-4 animate-spin mr-2" />
              Loading POAM…
            </>
          ) : (
            "POAM not found."
          )}
        </div>
      </div>
    );
  }

  const p = poam.data;

  return (
    <div className="p-8 space-y-6">
      <Button asChild variant="ghost" size="sm">
        <Link to="/poams">
          <ArrowLeft className="h-4 w-4" />
          Back to POAMs
        </Link>
      </Button>

      <header className="flex flex-wrap items-start justify-between gap-4">
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight font-mono">
              {p.control_cluster}
            </h1>
            <Badge variant="outline" className={statusClasses(p.status)}>
              {p.status}
            </Badge>
            {p.raw_severity && (
              <Badge
                variant="outline"
                className={severityClasses(p.raw_severity)}
              >
                {p.raw_severity}
              </Badge>
            )}
            {p.exported_at && (
              <Badge variant="outline" className="bg-muted/50 text-xs">
                Exported {formatDate(p.exported_at)}
              </Badge>
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            Created {formatDateTime(p.created_at)} · Updated{" "}
            {formatDateTime(p.updated_at)}
          </p>
        </div>
        <Button
          variant="outline"
          className="text-destructive hover:text-destructive"
          onClick={() => setConfirmDelete(true)}
        >
          <Trash2 className="h-4 w-4" />
          Delete POAM
        </Button>
      </header>

      {/* ---- Identity ----------------------------------------------------- */}
      <Card>
        <CardHeader>
          <CardTitle>Identity</CardTitle>
          <CardDescription>
            Cluster is fixed at generation time. eMASS POAM id is set by the
            importer after a round-trip to the eMASS template.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 sm:grid-cols-2">
          <Field
            label="eMASS POAM id"
            value={p.emass_poam_id}
            onCommit={(v) => update.mutate({ emass_poam_id: v })}
          />
          <Field
            label="Security control number"
            value={p.security_control_number}
            onCommit={(v) => update.mutate({ security_control_number: v })}
          />
          <Field
            label="Source identifying control / vulnerability"
            value={p.source_identifying_control_vulnerability}
            onCommit={(v) =>
              update.mutate({ source_identifying_control_vulnerability: v })
            }
            className="sm:col-span-2"
          />
          <Field
            label="Office / org"
            value={p.office_org}
            onCommit={(v) => update.mutate({ office_org: v })}
          />
        </CardContent>
      </Card>

      {/* ---- Narrative --------------------------------------------------- */}
      <Card>
        <CardHeader>
          <CardTitle>Description</CardTitle>
          <CardDescription>
            Vulnerability statement and remediation context. Free text; the
            eMASS template wraps long lines at export time.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <TextArea
            label="Vulnerability description"
            value={p.vulnerability_description}
            onCommit={(v) =>
              update.mutate({ vulnerability_description: v ?? "" })
            }
            rows={4}
          />
          <TextArea
            label="Resources required"
            value={p.resources_required}
            onCommit={(v) => update.mutate({ resources_required: v })}
            rows={2}
          />
          <TextArea
            label="Mitigations"
            value={p.mitigations}
            onCommit={(v) => update.mutate({ mitigations: v })}
            rows={3}
          />
          <TextArea
            label="Comments"
            value={p.comments}
            onCommit={(v) => update.mutate({ comments: v })}
            rows={2}
          />
        </CardContent>
      </Card>

      {/* ---- Risk -------------------------------------------------------- */}
      <Card>
        <CardHeader>
          <CardTitle>Risk</CardTitle>
          <CardDescription>
            NIST SP 800-30 qualitative matrix. Raw severity is derived from
            likelihood × impact server-side.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid gap-6 sm:grid-cols-2">
            <RiskFieldWithProvenance
              label="Likelihood"
              value={p.likelihood}
              options={riskOptions}
              onValueChange={(v) => update.mutate({ likelihood: v })}
              source={p.likelihood_source}
              rationale={p.likelihood_rationale}
              onRationaleCommit={(v) =>
                update.mutate({ likelihood_rationale: v })
              }
              rationaleLabel="Why this likelihood?"
            />
            <RiskFieldWithProvenance
              label="Impact"
              value={p.impact}
              options={riskOptions}
              onValueChange={(v) => update.mutate({ impact: v })}
              source={p.impact_source}
              rationale={p.impact_rationale}
              onRationaleCommit={(v) =>
                update.mutate({ impact_rationale: v })
              }
              rationaleLabel="Why this impact?"
            />
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <FieldRow label="Raw severity (computed)">
              {p.raw_severity ? (
                <Badge
                  variant="outline"
                  className={severityClasses(p.raw_severity)}
                >
                  {p.raw_severity}
                  {p.raw_severity_score != null && (
                    <span className="ml-1 text-muted-foreground">
                      ({p.raw_severity_score})
                    </span>
                  )}
                </Badge>
              ) : (
                <span className="text-xs text-muted-foreground">
                  Set likelihood + impact to derive
                </span>
              )}
            </FieldRow>
            <FieldRow label="Relevance of threat">
              <RiskSelect
                value={p.relevance_of_threat}
                options={riskOptions}
                onChange={(v) => update.mutate({ relevance_of_threat: v })}
              />
            </FieldRow>
          </div>
          <RiskFieldWithProvenance
            label="Residual risk"
            value={p.residual_risk}
            options={riskOptions}
            onValueChange={(v) => update.mutate({ residual_risk: v })}
            source={p.residual_risk_source}
            rationale={p.residual_risk_rationale}
            onRationaleCommit={(v) =>
              update.mutate({ residual_risk_rationale: v })
            }
            rationaleLabel="Why this residual risk?"
          />
        </CardContent>
      </Card>

      {/* ---- Schedule ---------------------------------------------------- */}
      <Card>
        <CardHeader>
          <CardTitle>Schedule</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4 sm:grid-cols-3">
          <FieldRow label="Status">
            <Select
              value={p.status}
              onValueChange={(v) =>
                update.mutate({ status: v as PoamStatus })
              }
            >
              <SelectTrigger className="w-[160px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {STATUS_VALUES.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </FieldRow>
          <FieldRow label="Scheduled completion">
            <DateField
              value={p.scheduled_completion_date}
              onCommit={(iso) =>
                update.mutate({ scheduled_completion_date: iso })
              }
            />
          </FieldRow>
          <FieldRow label="Actual completion">
            <DateField
              value={p.actual_completion_date}
              onCommit={(iso) =>
                update.mutate({ actual_completion_date: iso })
              }
            />
          </FieldRow>
        </CardContent>
      </Card>

      {/* ---- Milestones -------------------------------------------------- */}
      <MilestonesCard poamId={p.id} milestones={p.milestones} />

      {/* ---- Objectives -------------------------------------------------- */}
      <ObjectivesCard poamId={p.id} objectives={p.objectives} />

      {/* ---- Evidence ---------------------------------------------------- */}
      <EvidenceCard poamId={p.id} evidence={p.evidence} />

      {/* ---- Residual risk advisor (LLM) -------------------------------- */}
      <ResidualAdvisorCard poamId={p.id} />

      {/* ---- Risk history (audit trail) --------------------------------- */}
      <RiskHistoryCard poamId={p.id} />

      {/* ---- Delete confirm --------------------------------------------- */}
      <Dialog open={confirmDelete} onOpenChange={setConfirmDelete}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete this POAM?</DialogTitle>
            <DialogDescription>
              This removes the POAM, its {p.milestones.length} milestone
              {p.milestones.length === 1 ? "" : "s"}, and{" "}
              {p.objectives.length} objective link
              {p.objectives.length === 1 ? "" : "s"}. The underlying CCI
              assessments are not touched.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmDelete(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={del.isPending}
              onClick={() => del.mutate(p.id)}
            >
              {del.isPending && (
                <Loader2 className="h-4 w-4 animate-spin" />
              )}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Field primitives
// ---------------------------------------------------------------------------

/**
 * Label + value layout used by the read-only computed fields and the
 * dropdown rows. Keeps the gap consistent across cards.
 */
function FieldRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <div className="text-xs font-medium text-muted-foreground">{label}</div>
      <div>{children}</div>
    </div>
  );
}

/**
 * Single-line text field that holds local state until blur, then commits.
 * Empty string commits as `null` so the server-side patch clears the column
 * (matches the Pydantic shape — None means "clear").
 */
function Field({
  label,
  value,
  onCommit,
  className,
}: {
  label: string;
  value: string | null;
  onCommit: (next: string | null) => void;
  className?: string;
}) {
  const [draft, setDraft] = useState(value ?? "");
  // Sync local draft when the canonical value changes from outside (e.g. after
  // a save round-trips with a normalized value, or a peer field's mutation
  // refetches the POAM). Don't clobber the user mid-typing.
  useEffect(() => {
    setDraft(value ?? "");
  }, [value]);
  return (
    <div className={`space-y-1 ${className ?? ""}`}>
      <div className="text-xs font-medium text-muted-foreground">{label}</div>
      <Input
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={() => {
          const next = draft.trim() === "" ? null : draft;
          if (next !== value) onCommit(next);
        }}
      />
    </div>
  );
}

/**
 * Multi-line text field. Same commit-on-blur semantics as `Field` — clearing
 * to whitespace commits `null` so the column actually empties out.
 */
function TextArea({
  label,
  value,
  onCommit,
  rows = 3,
}: {
  label: string;
  value: string | null;
  onCommit: (next: string | null) => void;
  rows?: number;
}) {
  const [draft, setDraft] = useState(value ?? "");
  useEffect(() => {
    setDraft(value ?? "");
  }, [value]);
  return (
    <div className="space-y-1">
      <div className="text-xs font-medium text-muted-foreground">{label}</div>
      <textarea
        value={draft}
        rows={rows}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={() => {
          const next = draft.trim() === "" ? null : draft;
          if (next !== value) onCommit(next);
        }}
        className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
      />
    </div>
  );
}

/**
 * Date input bridged to ISO datetime strings the backend understands.
 * Empty input commits null so the schedule can be cleared.
 */
function DateField({
  value,
  onCommit,
}: {
  value: string | null;
  onCommit: (iso: string | null) => void;
}) {
  const [draft, setDraft] = useState(isoToDateInput(value));
  useEffect(() => {
    setDraft(isoToDateInput(value));
  }, [value]);
  return (
    <Input
      type="date"
      value={draft}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={() => {
        const next = dateInputToIso(draft);
        if (next !== value) onCommit(next);
      }}
      className="w-[180px]"
    />
  );
}

// ---------------------------------------------------------------------------
// Milestones
// ---------------------------------------------------------------------------

function MilestonesCard({
  poamId,
  milestones,
}: {
  poamId: number;
  milestones: PoamMilestone[];
}) {
  const create = useCreatePoamMilestone(poamId, {
    onError: (e) => toast.error("Add milestone failed", humanize(e)),
  });
  const [editingId, setEditingId] = useState<number | null>(null);
  const [newOpen, setNewOpen] = useState(false);
  const [newDesc, setNewDesc] = useState("");
  const [newDate, setNewDate] = useState("");

  const onSubmitNew = (e: FormEvent) => {
    e.preventDefault();
    if (!newDesc.trim()) return;
    create.mutate(
      {
        description: newDesc,
        scheduled_date: dateInputToIso(newDate),
      },
      {
        onSuccess: () => {
          setNewDesc("");
          setNewDate("");
          setNewOpen(false);
        },
      },
    );
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <div>
          <CardTitle>Milestones</CardTitle>
          <CardDescription>
            Remediation steps with their target dates. {milestones.length} total.
          </CardDescription>
        </div>
        <Button size="sm" onClick={() => setNewOpen((o) => !o)}>
          <Plus className="h-4 w-4" />
          Add milestone
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        {newOpen && (
          <form
            onSubmit={onSubmitNew}
            className="flex flex-wrap items-end gap-3 rounded-md border bg-muted/30 p-3"
          >
            <div className="flex-1 min-w-[280px] space-y-1">
              <div className="text-xs font-medium text-muted-foreground">
                Description
              </div>
              <Input
                value={newDesc}
                onChange={(e) => setNewDesc(e.target.value)}
                placeholder="e.g. Apply GPO baseline to domain controllers"
                autoFocus
              />
            </div>
            <div className="space-y-1">
              <div className="text-xs font-medium text-muted-foreground">
                Scheduled date
              </div>
              <Input
                type="date"
                value={newDate}
                onChange={(e) => setNewDate(e.target.value)}
                className="w-[180px]"
              />
            </div>
            <div className="flex gap-2">
              <Button type="submit" disabled={create.isPending || !newDesc.trim()}>
                {create.isPending && (
                  <Loader2 className="h-4 w-4 animate-spin" />
                )}
                Add
              </Button>
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  setNewOpen(false);
                  setNewDesc("");
                  setNewDate("");
                }}
              >
                <X className="h-4 w-4" />
              </Button>
            </div>
          </form>
        )}

        {milestones.length === 0 ? (
          <p className="text-sm text-muted-foreground italic">
            No milestones yet — add one above.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Description</TableHead>
                <TableHead className="w-[140px]">Scheduled</TableHead>
                <TableHead className="w-[140px]">Completed</TableHead>
                <TableHead className="w-[1%]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {milestones.map((m) =>
                editingId === m.id ? (
                  <MilestoneEditRow
                    key={m.id}
                    poamId={poamId}
                    milestone={m}
                    onClose={() => setEditingId(null)}
                  />
                ) : (
                  <MilestoneReadRow
                    key={m.id}
                    poamId={poamId}
                    milestone={m}
                    onEdit={() => setEditingId(m.id)}
                  />
                ),
              )}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function MilestoneReadRow({
  poamId,
  milestone,
  onEdit,
}: {
  poamId: number;
  milestone: PoamMilestone;
  onEdit: () => void;
}) {
  const del = useDeletePoamMilestone(poamId, {
    onError: (e) => toast.error("Delete milestone failed", humanize(e)),
  });
  return (
    <TableRow>
      <TableCell className="text-sm">{milestone.description}</TableCell>
      <TableCell className="text-sm tabular-nums">
        {formatDate(milestone.scheduled_date)}
      </TableCell>
      <TableCell className="text-sm tabular-nums">
        {formatDate(milestone.completion_date)}
      </TableCell>
      <TableCell className="whitespace-nowrap">
        <Button size="sm" variant="ghost" onClick={onEdit} title="Edit">
          <Pencil className="h-4 w-4" />
        </Button>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => del.mutate(milestone.id)}
          disabled={del.isPending}
          title="Delete"
          className="text-destructive hover:text-destructive"
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      </TableCell>
    </TableRow>
  );
}

function MilestoneEditRow({
  poamId,
  milestone,
  onClose,
}: {
  poamId: number;
  milestone: PoamMilestone;
  onClose: () => void;
}) {
  const update = useUpdatePoamMilestone(poamId, milestone.id, {
    onSuccess: onClose,
    onError: (e) => toast.error("Update milestone failed", humanize(e)),
  });
  const [desc, setDesc] = useState(milestone.description);
  const [sched, setSched] = useState(isoToDateInput(milestone.scheduled_date));
  const [done, setDone] = useState(isoToDateInput(milestone.completion_date));

  return (
    <TableRow className="bg-muted/30">
      <TableCell>
        <Input value={desc} onChange={(e) => setDesc(e.target.value)} />
      </TableCell>
      <TableCell>
        <Input
          type="date"
          value={sched}
          onChange={(e) => setSched(e.target.value)}
        />
      </TableCell>
      <TableCell>
        <Input
          type="date"
          value={done}
          onChange={(e) => setDone(e.target.value)}
        />
      </TableCell>
      <TableCell className="whitespace-nowrap">
        <Button
          size="sm"
          disabled={update.isPending || !desc.trim()}
          onClick={() =>
            update.mutate({
              description: desc,
              scheduled_date: dateInputToIso(sched),
              completion_date: dateInputToIso(done),
            })
          }
        >
          {update.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
          Save
        </Button>
        <Button size="sm" variant="ghost" onClick={onClose}>
          <X className="h-4 w-4" />
        </Button>
      </TableCell>
    </TableRow>
  );
}

// ---------------------------------------------------------------------------
// Linked objectives
// ---------------------------------------------------------------------------

function ObjectivesCard({
  poamId,
  objectives,
}: {
  poamId: number;
  objectives: ReturnType<typeof usePoam>["data"] extends infer T
    ? T extends { objectives: infer O }
      ? O
      : never
    : never;
}) {
  const link = useLinkPoamObjective(poamId, {
    onError: (e) => toast.error("Link failed", humanize(e)),
  });
  const unlink = useUnlinkPoamObjective(poamId, {
    onError: (e) => toast.error("Unlink failed", humanize(e)),
  });
  const [newId, setNewId] = useState("");

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const n = Number(newId);
    if (!Number.isFinite(n) || n <= 0) {
      toast.error("Invalid objective id", "Enter a numeric Objective.id");
      return;
    }
    link.mutate(n, { onSuccess: () => setNewId("") });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Linked CCIs</CardTitle>
        <CardDescription>
          CCIs that this POAM tracks remediation for. {objectives.length} linked.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <form
          onSubmit={onSubmit}
          className="flex flex-wrap items-end gap-3 rounded-md border bg-muted/30 p-3"
        >
          <div className="space-y-1">
            <div className="text-xs font-medium text-muted-foreground">
              Objective id (numeric)
            </div>
            <Input
              value={newId}
              onChange={(e) => setNewId(e.target.value)}
              placeholder="e.g. 42"
              className="w-[160px]"
            />
          </div>
          <Button type="submit" disabled={link.isPending || !newId.trim()}>
            {link.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            <Plus className="h-4 w-4" />
            Link
          </Button>
        </form>

        {objectives.length === 0 ? (
          <p className="text-sm text-muted-foreground italic">
            No CCIs linked yet.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[140px]">CCI</TableHead>
                <TableHead className="w-[120px]">Control</TableHead>
                <TableHead>Text</TableHead>
                <TableHead className="w-[140px]">Status at creation</TableHead>
                <TableHead className="w-[1%]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {objectives.map((o) => (
                <TableRow key={o.objective_id}>
                  <TableCell className="font-mono text-xs">
                    {o.objective_code}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {o.control_id}
                  </TableCell>
                  <TableCell
                    className="max-w-md truncate text-sm"
                    title={o.objective_text}
                  >
                    {o.objective_text}
                  </TableCell>
                  <TableCell className="text-xs">
                    {o.status_at_creation ?? "—"}
                  </TableCell>
                  <TableCell>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => unlink.mutate(o.objective_id)}
                      disabled={unlink.isPending}
                      title="Unlink"
                      className="text-destructive hover:text-destructive"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Linked evidence
// ---------------------------------------------------------------------------

/** Best-effort display label for a linked evidence row.
 *
 * Falls back to the basename of the on-disk path when no Title was parsed
 * at ingest. Handles both Windows and POSIX separators so the renderer
 * works regardless of which side wrote the path. */
function evidenceLabel(e: PoamEvidenceLink): string {
  if (e.title && e.title.trim()) return e.title;
  const parts = e.path.split(/[\\/]/);
  return parts[parts.length - 1] || e.path;
}

function EvidenceCard({
  poamId,
  evidence,
}: {
  poamId: number;
  evidence: PoamEvidenceLink[];
}) {
  // Same shape as ObjectivesCard — link/unlink mutations with toast on error.
  // The backend treats re-link of an already-linked evidence_id as a note
  // edit, so the same Plus button doubles as "save my new note". The Note
  // column has an inline edit affordance for that reason.
  const link = useLinkPoamEvidence(poamId, {
    onError: (e) => toast.error("Link failed", humanize(e)),
  });
  const unlink = useUnlinkPoamEvidence(poamId, {
    onError: (e) => toast.error("Unlink failed", humanize(e)),
  });
  const [newId, setNewId] = useState("");
  const [newNote, setNewNote] = useState("");

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const n = Number(newId);
    if (!Number.isFinite(n) || n <= 0) {
      toast.error("Invalid evidence id", "Enter a numeric Evidence.id");
      return;
    }
    link.mutate(
      { evidence_id: n, note: newNote.trim() ? newNote.trim() : null },
      {
        onSuccess: () => {
          setNewId("");
          setNewNote("");
        },
      },
    );
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Linked evidence</CardTitle>
        <CardDescription>
          Artifacts that support this POAM (referenced docs, scan exports, STIG
          checklists). {evidence.length} linked.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <form
          onSubmit={onSubmit}
          className="flex flex-wrap items-end gap-3 rounded-md border bg-muted/30 p-3"
        >
          <div className="space-y-1">
            <div className="text-xs font-medium text-muted-foreground">
              Evidence id (numeric)
            </div>
            <Input
              value={newId}
              onChange={(e) => setNewId(e.target.value)}
              placeholder="e.g. 17"
              className="w-[140px]"
            />
          </div>
          <div className="space-y-1 flex-1 min-w-[220px]">
            <div className="text-xs font-medium text-muted-foreground">
              Note (optional)
            </div>
            <Input
              value={newNote}
              onChange={(e) => setNewNote(e.target.value)}
              placeholder="Why this evidence supports the POAM…"
            />
          </div>
          <Button type="submit" disabled={link.isPending || !newId.trim()}>
            {link.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            <Plus className="h-4 w-4" />
            Link
          </Button>
        </form>

        {evidence.length === 0 ? (
          <p className="text-sm text-muted-foreground italic">
            No evidence linked yet.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Title</TableHead>
                <TableHead className="w-[110px]">Kind</TableHead>
                <TableHead className="w-[150px]">Doc number</TableHead>
                <TableHead>Note</TableHead>
                <TableHead className="w-[1%]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {evidence.map((e) => (
                <TableRow key={e.evidence_id}>
                  <TableCell
                    className="max-w-md truncate text-sm"
                    title={e.path}
                  >
                    {evidenceLabel(e)}
                  </TableCell>
                  <TableCell className="font-mono text-xs uppercase">
                    {e.kind}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {e.doc_number ?? "—"}
                  </TableCell>
                  <TableCell
                    className="max-w-xs truncate text-sm text-muted-foreground"
                    title={e.note ?? ""}
                  >
                    {e.note ?? "—"}
                  </TableCell>
                  <TableCell>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => unlink.mutate(e.evidence_id)}
                      disabled={unlink.isPending}
                      title="Unlink"
                      className="text-destructive hover:text-destructive"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}
