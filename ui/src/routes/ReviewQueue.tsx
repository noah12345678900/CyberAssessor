/**
 * Review Queue — every v0.2 needs_review Assessment in the active workbook,
 * grouped by `review_reason` category so the reviewer can work the triage
 * pile by failure mode (dual-pass-disagreement, unverified-cites, …)
 * rather than by control_id alphabetical.
 *
 * The Controls grid already exposes the same rows via the "Needs Review"
 * status filter, but that view is at the rollup level (one row per
 * Control) and flattened. This page renders the per-CCI rows joined to
 * Control + Objective metadata so each item links directly to
 * ControlDetail and shows the abstain reason inline.
 *
 * Per the v0.2 precision-over-recall plan:
 *   "New route /review-queue listing all needs_review=true rows for the
 *    active workbook, sorted by (review_reason category, control_id)."
 *
 * Workbook selection: same dropdown pattern as Controls.tsx. The amber
 * pill in the Controls header navigates here with no querystring — the
 * page picks the most-recently-opened workbook by default (first row of
 * `useWorkbooks`), matching how Controls.tsx defaults.
 */

import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, ArrowRight, Loader2 } from "lucide-react";

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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useWorkbookReviewQueue, useWorkbooks } from "@/lib/queries";
import type { ReviewQueueItem } from "@/lib/api";

/**
 * Human-readable label and one-line explanation for each known
 * review_reason prefix (everything before the first colon in the raw
 * string the backend writes). Anything not in this map falls into
 * `~uncategorized` which the backend already sorts to the bottom.
 */
const CATEGORY_META: Record<
  string,
  { label: string; description: string; tone: "amber" | "rose" | "violet" | "slate" }
> = {
  "dual-pass-disagreement": {
    label: "Dual-pass disagreement",
    description:
      "Pass 1 and pass 2 picked different statuses. The model isn't confident in either verdict — pick the correct status manually.",
    tone: "rose",
  },
  "unverified-cites": {
    label: "Unverified citations",
    description:
      "Narrative cited a document, CCI, or control that wasn't found verbatim in the evidence text. Likely hallucinated — verify each cite before accepting.",
    tone: "rose",
  },
  "validator-exhausted": {
    label: "Validator exhausted",
    description:
      "Three corrective retries couldn't produce a narrative that passed the validator. Last rejection summary is in the row reason.",
    tone: "amber",
  },
  "llm-parse-error": {
    label: "Parse error",
    description:
      "LLM response didn't match the expected JSON schema. The narrative may be malformed or the model went off-script entirely.",
    tone: "amber",
  },
  "stale-reference": {
    label: "Stale doc reference",
    description:
      "Narrative cites a document that's been superseded. Confirm the legacy doc still applies (or rewrite to point at the current version).",
    tone: "violet",
  },
  "boundary-conflict": {
    label: "Boundary conflict",
    description:
      "Narrative says \"outside boundary\" / \"out of scope\" but the proposed status isn't Not Applicable. Pick NA or rewrite the narrative.",
    tone: "violet",
  },
  "na-reconsideration": {
    label: "NA reconsideration",
    description:
      "Supersession engine flagged the NA narrative as worth a second look — usually because a referenced doc just changed materially.",
    tone: "violet",
  },
  "pending-human-review": {
    label: "Pending human review",
    description:
      "Single-control Assess produced a proposal that hasn't been approved yet. Open the control, review the narrative, and Save to clear this flag (or edit + Save).",
    tone: "slate",
  },
  "~uncategorized": {
    label: "Other",
    description:
      "Abstain reason didn't match any known prefix. Inspect the raw reason text and triage manually.",
    tone: "slate",
  },
};

const TONE_CLASSES: Record<string, string> = {
  amber:
    "border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-700 dark:bg-amber-950/40 dark:text-amber-100",
  rose: "border-rose-300 bg-rose-50 text-rose-900 dark:border-rose-700 dark:bg-rose-950/40 dark:text-rose-100",
  violet:
    "border-violet-300 bg-violet-50 text-violet-900 dark:border-violet-700 dark:bg-violet-950/40 dark:text-violet-100",
  slate:
    "border-slate-300 bg-slate-50 text-slate-900 dark:border-slate-700 dark:bg-slate-950/40 dark:text-slate-100",
};

function reasonCategory(reason: string | null): string {
  if (!reason) return "~uncategorized";
  const head = reason.split(":", 1)[0].trim();
  return head in CATEGORY_META ? head : head || "~uncategorized";
}

/** Strip the category prefix so the detail string isn't redundant with the section header. */
function reasonDetail(reason: string | null): string {
  if (!reason) return "";
  const idx = reason.indexOf(":");
  if (idx < 0) return reason;
  return reason.slice(idx + 1).trim();
}

export function ReviewQueue() {
  const workbooks = useWorkbooks();
  const [workbookId, setWorkbookId] = useState<number | undefined>();

  useEffect(() => {
    if (workbookId === undefined && workbooks.data && workbooks.data.length > 0) {
      setWorkbookId(workbooks.data[0].id);
    }
  }, [workbookId, workbooks.data]);

  const selectedWorkbook = workbooks.data?.find((w) => w.id === workbookId);
  const queue = useWorkbookReviewQueue(workbookId);

  // Backend already sorts by (reasonPrefix, control_label). Group sequentially —
  // no re-sort, no Map indirection, just walk the array and bucket on prefix
  // change so order is preserved exactly.
  const grouped = useMemo(() => {
    const out: { category: string; items: ReviewQueueItem[] }[] = [];
    if (!queue.data) return out;
    for (const item of queue.data) {
      const cat = reasonCategory(item.review_reason);
      const last = out[out.length - 1];
      if (last && last.category === cat) last.items.push(item);
      else out.push({ category: cat, items: [item] });
    }
    return out;
  }, [queue.data]);

  const total = queue.data?.length ?? 0;

  return (
    <div className="p-8 space-y-6 max-w-5xl">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
            <AlertTriangle className="h-6 w-6 text-amber-500" />
            Review Queue
          </h1>
          <p className="text-sm text-muted-foreground">
            Abstained CCIs grouped by failure mode. Per the precision-over-recall
            contract, these rows are blocked from CCIS / POAM export until a
            reviewer sets a trusted status.
          </p>
        </div>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Workbook</CardTitle>
          <CardDescription>
            {selectedWorkbook
              ? `${selectedWorkbook.filename} — ${total} abstained CCI${total === 1 ? "" : "s"}`
              : "Pick a workbook to load its review queue"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Select
            value={workbookId !== undefined ? String(workbookId) : "__none__"}
            onValueChange={(v) =>
              setWorkbookId(v === "__none__" ? undefined : Number(v))
            }
          >
            <SelectTrigger className="w-[320px]">
              <SelectValue placeholder="None" />
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
        </CardContent>
      </Card>

      {queue.isLoading ? (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading…
        </div>
      ) : queue.error ? (
        <Card>
          <CardContent className="py-6 text-sm text-rose-700 dark:text-rose-300">
            Failed to load the review queue: {(queue.error as Error).message}
          </CardContent>
        </Card>
      ) : total === 0 && workbookId ? (
        <Card>
          <CardContent className="py-6 text-sm text-muted-foreground">
            No abstained CCIs in this workbook — every assessed row is either
            trusted or hasn't been assessed yet. (Unassessed CCIs show up in
            the Controls grid as <em>Not Assessed</em>, not here.)
          </CardContent>
        </Card>
      ) : (
        grouped.map(({ category, items }) => {
          const meta = CATEGORY_META[category] ?? CATEGORY_META["~uncategorized"];
          return (
            <Card key={category}>
              <CardHeader>
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <span
                        className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${TONE_CLASSES[meta.tone]}`}
                      >
                        {meta.label}
                      </span>
                      <span className="text-sm font-normal text-muted-foreground">
                        {items.length} CCI{items.length === 1 ? "" : "s"}
                      </span>
                    </CardTitle>
                    <CardDescription>{meta.description}</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-2">
                {items.map((item) => (
                  <ReviewRow key={item.assessment_id} item={item} />
                ))}
              </CardContent>
            </Card>
          );
        })
      )}
    </div>
  );
}

function ReviewRow({ item }: { item: ReviewQueueItem }) {
  const detail = reasonDetail(item.review_reason);
  const conf = item.confidence;
  const confText =
    conf === null
      ? null
      : `${Math.round(conf * 100)}%`;
  return (
    <div className="flex flex-wrap items-start justify-between gap-3 rounded-md border bg-card/60 p-3">
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant="outline" className="font-mono text-[10px]">
            {item.control_label}
          </Badge>
          <span className="font-mono text-xs text-muted-foreground">
            {item.cci_id}
          </span>
          <Badge
            variant="outline"
            className="text-xs line-through opacity-70"
            title="Status the LLM proposed before the abstain gate fired. Shown struck-through because it is NOT trusted."
          >
            {item.proposed_status}
          </Badge>
          {confText !== null && (
            <span
              className="text-[10px] text-muted-foreground"
              title="LLM-self-reported confidence. Null/missing for deterministic short-circuits."
            >
              conf {confText}
            </span>
          )}
        </div>
        <div className="text-sm font-medium leading-tight">
          {item.control_title}
        </div>
        <div className="line-clamp-2 text-xs text-muted-foreground">
          {item.objective_text}
        </div>
        {detail && (
          <div className="text-xs text-amber-900 dark:text-amber-200">
            <span className="font-medium">Reason:</span> {detail}
          </div>
        )}
      </div>
      <Button asChild variant="outline" size="sm">
        <Link to={`/controls/${item.control_id}`}>
          Triage
          <ArrowRight className="ml-1 h-3.5 w-3.5" />
        </Link>
      </Button>
    </div>
  );
}
