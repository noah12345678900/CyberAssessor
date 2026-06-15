/**
 * Compact stat tile — icon + label + big number + optional sublabel.
 *
 * Extracted verbatim from the inline `Stat` previously embedded in
 * routes/Runs.tsx so the new Metrics tab can reuse the same shape without
 * duplication. Behavior is unchanged from the Runs version; if you tweak
 * tone classes or padding here, both Runs and Metrics pick it up.
 */

import * as React from "react";

export type StatCardTone = "success" | "warning";

export interface StatCardProps {
  label: string;
  value: string;
  icon: React.ComponentType<{ className?: string }>;
  tone?: StatCardTone;
  sublabel?: string;
}

export function StatCard({ label, value, icon: Icon, tone, sublabel }: StatCardProps) {
  const toneClass =
    tone === "success"
      ? "text-emerald-600 dark:text-emerald-400"
      : tone === "warning"
        ? "text-amber-600 dark:text-amber-400"
        : "text-muted-foreground";
  return (
    <div className="rounded-md border bg-card px-4 py-3 flex items-start gap-3">
      <Icon className={`h-4 w-4 mt-0.5 ${toneClass}`} />
      <div>
        <div className="text-xs text-muted-foreground">{label}</div>
        <div className="text-xl font-semibold tabular-nums">{value}</div>
        {sublabel && <div className="text-[11px] text-muted-foreground mt-0.5">{sublabel}</div>}
      </div>
    </div>
  );
}
