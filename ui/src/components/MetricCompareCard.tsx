/**
 * Side-by-side comparison tile — Live (this user's runs) vs Reference
 * (published manual-assessment benchmark). Rendered once per family
 * headline on the Metrics tab (Accuracy / Cost / Time).
 *
 * Reference values are user-sourced and live in
 * backend/cybersecurity_assessor/metrics/_bundled/references.json. While
 * the user hasn't filled in a citation yet (`value === null`), the right
 * column renders an "Awaiting source" placeholder with a tooltip pointing
 * at the file — that keeps the layout stable so we can ship the tab
 * before every reference is sourced.
 */

import { ExternalLink } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { MetricsReferenceEntry } from "@/lib/api";

export interface MetricCompareCardProps {
  family: "accuracy" | "cost" | "time";
  label: string;
  description?: string;
  live: {
    value: string;
    sublabel?: string;
  };
  // null = no published benchmark loaded yet (TODO in references.json).
  reference: MetricsReferenceEntry | null;
}

export function MetricCompareCard({
  family: _family,
  label,
  description,
  live,
  reference,
}: MetricCompareCardProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{label}</CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="rounded-md border bg-card px-4 py-3">
            <div className="text-[11px] uppercase tracking-wide text-muted-foreground">
              Live · ccis-assessor
            </div>
            <div className="text-3xl font-semibold tabular-nums mt-1">{live.value}</div>
            {live.sublabel && (
              <div className="text-xs text-muted-foreground mt-1">{live.sublabel}</div>
            )}
          </div>
          <div className="rounded-md border bg-muted/30 px-4 py-3">
            <div className="text-[11px] uppercase tracking-wide text-muted-foreground">
              Reference · manual A&amp;A
            </div>
            {reference && reference.value !== null ? (
              <>
                <div className="text-3xl font-semibold tabular-nums mt-1">
                  {formatReferenceValue(reference)}
                </div>
                {reference.sublabel && (
                  <div className="text-xs text-muted-foreground mt-1">{reference.sublabel}</div>
                )}
                <ReferenceFootnote reference={reference} />
              </>
            ) : (
              <>
                <div
                  className="text-3xl font-semibold tabular-nums mt-1 text-muted-foreground/60"
                  title="See backend/cybersecurity_assessor/metrics/_bundled/references.json"
                >
                  —
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  Awaiting source — fill in references.json
                </div>
              </>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

/**
 * Format a reference value with its unit. References are quantitative
 * (USD, hours, percent, etc.) so we don't try to be clever — unit drives
 * the prefix/suffix and we let the user-sourced number print as-is.
 */
function formatReferenceValue(ref: MetricsReferenceEntry): string {
  const v = ref.value;
  if (v === null) return "—";
  const unit = (ref.unit || "").toLowerCase();
  if (unit === "usd") {
    if (v >= 1000) {
      return `$${v.toLocaleString(undefined, { maximumFractionDigits: 0 })}`;
    }
    return `$${v.toFixed(2)}`;
  }
  if (unit === "percent" || unit === "pct" || unit === "%") {
    return `${v.toFixed(1)}%`;
  }
  if (unit === "hours" || unit === "hour" || unit === "h") {
    return `${v.toLocaleString(undefined, { maximumFractionDigits: 1 })} h`;
  }
  if (unit === "minutes" || unit === "min") {
    return `${v.toLocaleString(undefined, { maximumFractionDigits: 0 })} min`;
  }
  if (unit === "days" || unit === "day") {
    return `${v.toLocaleString(undefined, { maximumFractionDigits: 0 })} days`;
  }
  return `${v.toLocaleString()} ${ref.unit}`;
}

/**
 * Citation row — renders a clickable [source] when the JSON has a real URL,
 * otherwise a muted "citation pending" hint. The link opens in the OS
 * browser via the standard <a target="_blank"> (Electron forwards externals).
 */
function ReferenceFootnote({ reference }: { reference: MetricsReferenceEntry }) {
  const { source } = reference;
  const hasUrl = source.url && source.url !== "TODO";
  const hasCitation = source.citation && source.citation !== "TODO";
  if (!hasUrl && !hasCitation) {
    return (
      <div className="text-[11px] text-muted-foreground mt-2 italic">
        Citation pending
      </div>
    );
  }
  return (
    <div className="text-[11px] text-muted-foreground mt-2 flex items-center gap-1">
      <span>{hasCitation ? source.citation : "Source"}</span>
      {hasUrl && (
        <a
          href={source.url}
          target="_blank"
          rel="noreferrer noopener"
          className="inline-flex items-center gap-0.5 text-primary hover:underline"
        >
          <ExternalLink className="h-3 w-3" />
        </a>
      )}
      {source.as_of && source.as_of !== "TODO" && (
        <span className="text-muted-foreground/70">· as of {source.as_of}</span>
      )}
    </div>
  );
}
