/**
 * Metrics tab — Accuracy / Cost / Time, each Live vs Reference.
 *
 * The three families are the categories the assessor (and the Nuon
 * marketing site) actually care about. Live numbers are aggregated by
 * the backend over `AssessmentRun` rows (see routes/metrics.py); the
 * Reference column comes from the bundled `references.json` and is
 * user-sourced over time. Same JSON shape powers `/api/metrics/public`
 * for the marketing site.
 *
 * Supersession + validator rejections + CRM overlay live below the
 * Accuracy section under "Mechanisms" — the deterministic accuracy
 * controls. Supersession used to be a generic counter on the Runs view;
 * it belongs here, with the other accuracy mechanisms.
 */

import {
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  CircleSlash,
  Clock,
  DollarSign,
  Gauge,
  Layers,
  PiggyBank,
  Repeat,
  ShieldCheck,
  Sparkles,
  Timer,
  TrendingUp,
  Zap,
} from "lucide-react";

import { MetricCompareCard } from "@/components/MetricCompareCard";
import { StatCard } from "@/components/StatCard";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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
import type {
  MetricsMechanisms,
  MetricsPayload,
  MetricsReferenceEntry,
  MetricsSavings,
} from "@/lib/api";
import { useMetrics, useSupersessionChains, useWorkbooks } from "@/lib/queries";
import { useEffect, useState } from "react";

export function Metrics() {
  const metrics = useMetrics();

  if (metrics.isLoading) {
    return (
      <div className="p-8 text-sm text-muted-foreground">Loading metrics…</div>
    );
  }
  if (metrics.error || !metrics.data) {
    return (
      <div className="p-8 text-sm text-destructive">
        Couldn't reach the sidecar — is the backend running?
      </div>
    );
  }

  const data = metrics.data;
  const refByKey = indexReferences(data);

  return (
    <div className="p-8 space-y-8">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
          <BarChart3 className="h-6 w-6 text-primary" />
          Metrics
        </h1>
        <p className="text-sm text-muted-foreground">
          Accuracy, cost, and time — the assessor's live numbers compared
          against published manual-assessment benchmarks. Same data backs
          the public /api/metrics/public endpoint.{" "}
          {data.live.n_runs === 0 && (
            <span className="text-amber-600 dark:text-amber-400">
              No runs yet — assess a CCI to populate the Live column.
            </span>
          )}
        </p>
      </header>

      <SavingsHero savings={data.savings} />
      <AccuracySection data={data} refByKey={refByKey} />
      <CostSection data={data} refByKey={refByKey} />
      <TimeSection data={data} refByKey={refByKey} />
      <RateCardSection data={data} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Savings hero — ROI headline (dollars + time saved vs manual A&A baseline)
// ---------------------------------------------------------------------------

/**
 * The headline ROI tile. Lives above the three families because it's the
 * answer to "what's this thing worth to me?" — the marketing-quotable
 * number that bridges Cost and Time into a single dollar figure.
 *
 * When references.json is unfilled (both reference values null), we render
 * a compact "Sourcing benchmarks…" placeholder instead of fake zeros. The
 * card still shows live spend + minutes burned so the user sees the cost
 * side of the equation even without a benchmark.
 */
function SavingsHero({ savings }: { savings: MetricsSavings }) {
  const hasDollars = savings.dollars_saved_usd !== null;
  const hasMinutes = savings.minutes_saved !== null;
  const anyReference = hasDollars || hasMinutes;
  const dollarsPositive = hasDollars && (savings.dollars_saved_usd ?? 0) > 0;
  const minutesPositive = hasMinutes && (savings.minutes_saved ?? 0) > 0;

  return (
    <Card className="border-emerald-500/30 bg-gradient-to-br from-emerald-50/60 to-background dark:from-emerald-950/20 dark:to-background">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <PiggyBank className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
          Savings vs manual A&amp;A baseline
        </CardTitle>
        <CardDescription>
          {anyReference
            ? `Reference cost × ${savings.ccis_credited.toLocaleString()} accepted CCIs, minus what the assessor actually spent. Abstentions and validator rejects don't count — only CCIs the assessor confidently closed.`
            : "Unsourced references — fill in manual_assessment_cost_per_cci / manual_assessment_time_per_cci in references.json to unlock the ROI number."}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <SavingsTile
            icon={DollarSign}
            label="Dollars saved"
            value={hasDollars ? formatCost(savings.dollars_saved_usd) : "—"}
            positive={dollarsPositive}
            placeholder={!hasDollars}
            sublabel={
              hasDollars
                ? `${formatCost(savings.manual_baseline_cost_usd)} manual baseline · ${formatCost(savings.live_cost_usd)} live spend`
                : "Awaiting manual_assessment_cost_per_cci"
            }
          />
          <SavingsTile
            icon={Clock}
            label="Time saved"
            value={hasMinutes ? formatMinutesAsHours(savings.minutes_saved) : "—"}
            positive={minutesPositive}
            placeholder={!hasMinutes}
            sublabel={
              hasMinutes
                ? `${formatMinutesAsHours(savings.manual_baseline_minutes)} manual baseline · ${formatMinutesAsHours(savings.live_minutes)} live wall-clock`
                : "Awaiting manual_assessment_time_per_cci"
            }
          />
        </div>
      </CardContent>
    </Card>
  );
}

function SavingsTile({
  icon: Icon,
  label,
  value,
  positive,
  placeholder,
  sublabel,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
  positive: boolean;
  placeholder: boolean;
  sublabel: string;
}) {
  const numberTone = placeholder
    ? "text-muted-foreground/60"
    : positive
      ? "text-emerald-600 dark:text-emerald-400"
      : "text-amber-600 dark:text-amber-400";
  return (
    <div className="rounded-md border bg-card px-5 py-4">
      <div className="flex items-center gap-2 text-[11px] uppercase tracking-wide text-muted-foreground">
        <Icon className="h-3.5 w-3.5" />
        {label}
      </div>
      <div className={`text-4xl font-semibold tabular-nums mt-1 ${numberTone}`}>
        {!placeholder && positive ? <TrendingUp className="inline h-5 w-5 mr-1 align-baseline" /> : null}
        {value}
      </div>
      <div className="text-xs text-muted-foreground mt-1">{sublabel}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Accuracy
// ---------------------------------------------------------------------------

function AccuracySection({
  data,
  refByKey,
}: {
  data: MetricsPayload;
  refByKey: Map<string, MetricsReferenceEntry>;
}) {
  const a = data.live.accuracy;
  return (
    <section className="space-y-4">
      <SectionHeader
        icon={ShieldCheck}
        title="Accuracy"
        description="What the assessor got right and the mechanisms that made it right. Accuracy = accepted / decided, where decided = accepted + abstained (final per-CCI verdicts). Abstentions count against the denominator because they're still a CCI the user has to handle; validator rejections are mid-assessment retry events, not terminal outcomes, so they're reported separately and not in the denominator."
      />

      <MetricCompareCard
        family="accuracy"
        label="CCI verdict agreement"
        description="Live = portion of CCIs the assessor decided that survived validator + dual-pass. Reference = published inter-rater agreement between two human assessors on the same CCI."
        live={{
          value: a.accuracy_pct !== null ? `${a.accuracy_pct.toFixed(1)}%` : "—",
          sublabel:
            a.accuracy_pct !== null
              ? `${a.ccis_accepted.toLocaleString()} accepted of ${a.decided.toLocaleString()} decided`
              : "Run an assessment to populate",
        }}
        reference={refByKey.get("manual_assessment_accuracy") ?? null}
      />

      {/* Current verdicts — where the workbook stands NOW (live Assessment
          rows). These are counts of CONTROLS, post-review. */}
      <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
        Current verdicts
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard
          label="CCIs accepted"
          value={a.ccis_accepted.toLocaleString()}
          icon={CheckCircle2}
          tone="success"
          sublabel={`of ${a.decided.toLocaleString()} decided`}
        />
        <StatCard
          label="Abstained"
          value={a.abstained.toLocaleString()}
          icon={CircleSlash}
          sublabel={
            a.abstention_rate_pct !== null
              ? `${a.abstention_rate_pct.toFixed(1)}% of decided · pending review`
              : "Precision over recall"
          }
        />
        <StatCard
          label="Decided"
          value={a.decided.toLocaleString()}
          icon={CheckCircle2}
          sublabel="accepted + abstained"
        />
        <StatCard
          label="Dual-pass agreement"
          value={
            a.dual_pass_agreement_pct !== null
              ? `${a.dual_pass_agreement_pct.toFixed(1)}%`
              : "—"
          }
          icon={Repeat}
          sublabel={`${a.activity.cumulative.dual_pass_disagreements.toLocaleString()} disagreements (all runs)`}
        />
      </div>

      {/* Assessment activity — what the assessor DID getting there (run
          history). These are EVENTS, not controls: a validator complaint is a
          rule-#11 flag on one attempt (several can fire per retry), and most
          rejected attempts recover on the retry. Shown latest-run-first with
          the cumulative total in the sublabel so "this assessment" is never
          confused with lifetime history. */}
      <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide pt-1">
        Assessment activity (latest run · cumulative)
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard
          label="Validator complaints"
          value={a.activity.latest.validator_complaints.toLocaleString()}
          icon={AlertTriangle}
          tone={a.activity.latest.validator_complaints > 0 ? "warning" : undefined}
          sublabel={`${a.activity.cumulative.validator_complaints.toLocaleString()} all runs · rule-#11 flags, not failed controls`}
        />
        <StatCard
          label="Retries"
          value={a.activity.latest.retries.toLocaleString()}
          icon={Repeat}
          sublabel={`${a.activity.cumulative.retries.toLocaleString()} all runs · LLM re-asks`}
        />
        <StatCard
          label="Dual-pass disagreements"
          value={a.activity.latest.dual_pass_disagreements.toLocaleString()}
          icon={Repeat}
          sublabel={`${a.activity.cumulative.dual_pass_disagreements.toLocaleString()} all runs`}
        />
        <StatCard
          label="LLM calls"
          value={a.activity.latest.llm_calls.toLocaleString()}
          icon={Repeat}
          sublabel={`${a.activity.cumulative.llm_calls.toLocaleString()} all runs · ${a.activity.cumulative.runs} runs`}
        />
      </div>

      <MechanismsSubsection data={data} />
    </section>
  );
}

function MechanismsSubsection({ data }: { data: MetricsPayload }) {
  const m = data.mechanisms;

  // Per-workbook supersession view. The chains are auto-detected at ingest
  // (Rev A superseded by Rev B), so they differ per workbook — pick one.
  const workbooks = useWorkbooks();
  const [workbookId, setWorkbookId] = useState<number | undefined>();
  useEffect(() => {
    if (workbookId === undefined && workbooks.data && workbooks.data.length > 0) {
      setWorkbookId(workbooks.data[0].id);
    }
  }, [workbookId, workbooks.data]);
  const selectedWorkbook = workbooks.data?.find((w) => w.id === workbookId);
  const chains = useSupersessionChains(workbookId ?? null);
  const chainRows = chains.data ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Sparkles className="h-4 w-4 text-primary" />
          Accuracy mechanisms
        </CardTitle>
        <CardDescription>
          Deterministic controls that catch what the LLM can't. These are the
          accuracy-supporting mechanisms behind the patent claim.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <StatCard
            label="Supersession rewrites"
            value={
              selectedWorkbook ? chainRows.length.toLocaleString() : "—"
            }
            icon={Repeat}
            sublabel={`${m.supersession.total_hits.toLocaleString()} hits across all runs`}
          />
          <StatCard
            label="Validator rejection rate"
            value={
              m.validator.rejection_rate_pct !== null
                ? `${m.validator.rejection_rate_pct.toFixed(1)}%`
                : "—"
            }
            icon={AlertTriangle}
            tone={
              m.validator.total_rejections > 0 ? "warning" : undefined
            }
            sublabel={`${m.validator.total_rejections.toLocaleString()} total`}
          />
          <CrmOverlayStat crm={m.crm_overlay} />
        </div>

        <div>
          <div className="text-sm font-medium mb-2 flex items-center gap-2">
            Document supersessions
            <Badge variant="outline" className="text-[10px] uppercase tracking-wide">
              Deterministic · no LLM
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground mb-3">
            Auto-detected for this workbook: when a newer artifact (e.g. Rev B)
            is ingested over an older one (Rev A), narratives that cite the old
            document are rewritten to the current one. Derived from the evidence
            chain, not hand-edited.
          </p>
          <div className="mb-3">
            <Select
              value={workbookId !== undefined ? String(workbookId) : "__none__"}
              onValueChange={(v) =>
                setWorkbookId(v === "__none__" ? undefined : Number(v))
              }
            >
              <SelectTrigger className="w-[320px]">
                <SelectValue placeholder="Pick a workbook" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="__none__">None</SelectItem>
                {(workbooks.data ?? []).map((w) => (
                  <SelectItem key={w.id} value={String(w.id)}>
                    {w.filename}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Legacy document</TableHead>
                <TableHead>Current document</TableHead>
                <TableHead>Matched on</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {!selectedWorkbook && (
                <TableRow>
                  <TableCell colSpan={3} className="text-center text-sm text-muted-foreground py-6">
                    Select a workbook to view its detected supersessions.
                  </TableCell>
                </TableRow>
              )}
              {selectedWorkbook && chainRows.length === 0 && (
                <TableRow>
                  <TableCell colSpan={3} className="text-center text-sm text-muted-foreground py-6">
                    No superseded evidence detected for this workbook yet.
                  </TableCell>
                </TableRow>
              )}
              {chainRows.map((c, i) => (
                <TableRow key={`${c.stale_evidence_id}-${c.current_evidence_id}-${i}`}>
                  <TableCell className="font-mono text-xs">{c.legacy}</TableCell>
                  <TableCell className="font-mono text-xs">{c.current}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {c.kind === "doc_number" ? "Doc number" : "Title"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}

/**
 * CRM overlay coverage tile — what fraction of in-scope baseline controls
 * carry a customer/provider/hybrid/inherited responsibility tag, plus how
 * many CCIs the kernel short-circuited (skipped LLM entirely) thanks to
 * those tags.
 *
 * Two-state render:
 *   * Not available (fresh install, no CRM ingested yet) — muted placeholder
 *     pointing at the CRM ingestion slice so the tile still claims its slot
 *     in the grid.
 *   * Available — coverage % as the headline, tagged/in-scope as sublabel,
 *     short-circuit count surfaced too (that's the real cost win — every
 *     short-circuit is an LLM call avoided).
 */
function CrmOverlayStat({ crm }: { crm: MetricsMechanisms["crm_overlay"] }) {
  if (!crm.available) {
    return (
      <StatCard
        label="CRM overlay coverage"
        value="—"
        icon={Layers}
        sublabel="No CRM ingested yet — ingest a Customer Responsibility Matrix to tag inherited / provider-owned CCIs"
      />
    );
  }
  const pct = crm.coverage_pct;
  const pctStr = pct !== null ? `${pct.toFixed(1)}%` : "—";
  const shortCircuitHint =
    crm.total_short_circuits > 0
      ? `${crm.total_short_circuits.toLocaleString()} CCIs short-circuited (LLM skipped)`
      : `${crm.tagged_total.toLocaleString()} of ${crm.in_scope_total.toLocaleString()} controls tagged`;
  return (
    <StatCard
      label="CRM overlay coverage"
      value={pctStr}
      icon={Zap}
      tone={crm.total_short_circuits > 0 ? "success" : undefined}
      sublabel={shortCircuitHint}
    />
  );
}

// ---------------------------------------------------------------------------
// Cost
// ---------------------------------------------------------------------------

function CostSection({
  data,
  refByKey,
}: {
  data: MetricsPayload;
  refByKey: Map<string, MetricsReferenceEntry>;
}) {
  const c = data.live.cost;
  return (
    <section className="space-y-4">
      <SectionHeader
        icon={DollarSign}
        title="Cost"
        description="Dollars per decision. Live tokens × current rate card vs. published loaded labor cost for a senior human assessor."
      />

      <MetricCompareCard
        family="cost"
        label="Cost per CCI accepted"
        description="Live = median of (run cost / CCIs accepted on that run). Reference = manual A&A loaded labor cost per CCI."
        live={{
          value: formatCost(c.median_per_cci_usd),
          sublabel:
            c.median_per_cci_usd !== null
              ? `${formatCost(c.total_usd)} total · ${c.llm_calls.toLocaleString()} LLM calls`
              : "Accept a CCI to populate",
        }}
        reference={refByKey.get("manual_assessment_cost_per_cci") ?? null}
      />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard
          label="Total spend"
          value={formatCost(c.total_usd)}
          icon={DollarSign}
        />
        <StatCard
          label="Median $/run"
          value={formatCost(c.median_per_run_usd)}
          icon={Gauge}
        />
        <StatCard
          label="Input tokens"
          value={formatTokens(c.total_input_tokens)}
          icon={BarChart3}
          sublabel={`+ ${formatTokens(c.total_cache_read_tokens)} cache read`}
        />
        <StatCard
          label="Output tokens"
          value={formatTokens(c.total_output_tokens)}
          icon={BarChart3}
        />
      </div>
    </section>
  );
}

function RateCardSection({ data }: { data: MetricsPayload }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Model rate card</CardTitle>
        <CardDescription>
          What the sidecar charges per million tokens. Used to compute the Live
          cost column above. Last revised {data.rate_card.rates_revised}.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Model</TableHead>
              <TableHead className="text-right">Input $/MTok</TableHead>
              <TableHead className="text-right">Output $/MTok</TableHead>
              <TableHead className="text-right">Cache read $/MTok</TableHead>
              <TableHead className="text-right">Cache write $/MTok</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.rate_card.models.map((m) => (
              <TableRow key={m.model}>
                <TableCell className="font-mono text-xs">{m.model}</TableCell>
                <TableCell className="text-right tabular-nums">
                  ${m.input_per_mtok.toFixed(2)}
                </TableCell>
                <TableCell className="text-right tabular-nums">
                  ${m.output_per_mtok.toFixed(2)}
                </TableCell>
                <TableCell className="text-right tabular-nums">
                  ${m.cache_read_per_mtok.toFixed(2)}
                </TableCell>
                <TableCell className="text-right tabular-nums">
                  ${m.cache_write_per_mtok.toFixed(2)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

function TimeSection({
  data,
  refByKey,
}: {
  data: MetricsPayload;
  refByKey: Map<string, MetricsReferenceEntry>;
}) {
  const t = data.live.time;
  return (
    <section className="space-y-4">
      <SectionHeader
        icon={Clock}
        title="Time"
        description="Wall-clock seconds per decision. Live = sidecar duration across runs vs. manual A&A senior-assessor minutes per CCI."
      />

      <MetricCompareCard
        family="time"
        label="Time per CCI accepted"
        description="Live = median of (run wall-clock / CCIs accepted). Reference = manual A&A minutes per CCI."
        live={{
          value: formatSecondsAsCompact(t.median_per_cci_seconds),
          sublabel:
            t.ccis_per_hour !== null
              ? `${t.ccis_per_hour.toFixed(1)} CCIs/hr sustained`
              : "Accept a CCI to populate",
        }}
        reference={refByKey.get("manual_assessment_time_per_cci") ?? null}
      />

      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        <StatCard
          label="Median wall-clock / run"
          value={formatSecondsAsCompact(t.median_per_run_seconds)}
          icon={Timer}
        />
        <StatCard
          label="Total wall-clock"
          value={formatSecondsAsCompact(t.total_seconds)}
          icon={Clock}
        />
        <StatCard
          label="CCIs / hour"
          value={t.ccis_per_hour !== null ? t.ccis_per_hour.toFixed(1) : "—"}
          icon={Gauge}
        />
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function SectionHeader({
  icon: Icon,
  title,
  description,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  description: string;
}) {
  return (
    <div className="border-b pb-2">
      <h2 className="text-lg font-semibold flex items-center gap-2">
        <Icon className="h-5 w-5 text-primary" />
        {title}
      </h2>
      <p className="text-sm text-muted-foreground mt-1">{description}</p>
    </div>
  );
}

function indexReferences(data: MetricsPayload): Map<string, MetricsReferenceEntry> {
  const m = new Map<string, MetricsReferenceEntry>();
  for (const fam of [data.reference.accuracy, data.reference.cost, data.reference.time]) {
    for (const e of fam) m.set(e.key, e);
  }
  return m;
}

function formatCost(usd: number | null): string {
  if (usd === null) return "—";
  if (usd === 0) return "$0.00";
  if (usd < 0.01) return "<$0.01";
  if (usd >= 1000) {
    return `$${usd.toLocaleString(undefined, { maximumFractionDigits: 2, minimumFractionDigits: 2 })}`;
  }
  return `$${usd.toFixed(2)}`;
}

function formatTokens(n: number): string {
  if (n === 0) return "0";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return n.toLocaleString();
}

function formatSecondsAsCompact(s: number | null): string {
  if (s === null) return "—";
  if (s < 1) return `${(s * 1000).toFixed(0)} ms`;
  if (s < 60) return `${s.toFixed(1)} s`;
  if (s < 3600) return `${(s / 60).toFixed(1)} min`;
  return `${(s / 3600).toFixed(2)} h`;
}

/** Format raw minutes — small numbers stay in minutes; big ones flip to
 *  hours / days so a ~4000-minute baseline doesn't read like noise. */
function formatMinutesAsHours(m: number | null): string {
  if (m === null) return "—";
  const abs = Math.abs(m);
  if (abs < 60) return `${m.toFixed(0)} min`;
  if (abs < 60 * 24) return `${(m / 60).toFixed(1)} h`;
  return `${(m / 60 / 24).toFixed(1)} days`;
}
