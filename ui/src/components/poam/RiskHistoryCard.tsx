/**
 * Audit-trail card for one POAM's risk-field transitions.
 *
 * Renders newest-first rows from GET /api/poams/{id}/risk-history. Each row
 * is a single field-level transition (likelihood, impact, raw_severity, or
 * residual_risk) recorded by ``record_risk_change`` on every codepath that
 * mutates risk state: the generator seed, manual POAM creation, PATCH from
 * the UI, and the "Apply suggestion" button from ResidualAdvisorCard.
 *
 * Layout mirrors ``OdpHistoryGroupBlock`` in ControlDetail — small mono
 * table-like grid, no chrome, "Show all" collapse past N rows so a noisy
 * POAM doesn't push the rest of the page off-screen.
 *
 * Auto-refreshes via React Query — ``useUpdatePoam`` /
 * ``useApplyPoamResidualSuggestion`` already invalidate the ``["poam", id]``
 * prefix, so a successful edit anywhere in the page re-fetches this list
 * without an explicit invalidation branch here.
 */

import { useState } from "react";
import { History } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import type { PoamRiskHistoryEntry } from "@/lib/api";
import { formatDateTime } from "@/lib/poamFormat";
import { usePoamRiskHistory } from "@/lib/queries";

const DEFAULT_VISIBLE = 10;

const FIELD_LABEL: Record<PoamRiskHistoryEntry["field"], string> = {
  likelihood: "Likelihood",
  impact: "Impact",
  raw_severity: "Raw severity",
  residual_risk: "Residual risk",
};

function SourceTag({
  source,
}: {
  source: PoamRiskHistoryEntry["prev_source"];
}) {
  if (!source) return null;
  const labels = {
    auto: "auto",
    manual: "manual",
    llm_suggested: "llm",
  } as const;
  return (
    <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
      [{labels[source]}]
    </span>
  );
}

/**
 * Strip the colon-prefix actor convention (``"system:generator"`` →
 * "generator", ``"assessor:update"`` → "assessor:update") so the table
 * doesn't waste a column. ``system:`` actors render dimmer; ``assessor:``
 * actors render in the body color so human edits stand out.
 */
function ActorCell({ actor }: { actor: string | null }) {
  if (!actor) {
    return <span className="text-muted-foreground">—</span>;
  }
  const isSystem = actor.startsWith("system:");
  const display = isSystem ? actor.slice("system:".length) : actor;
  return (
    <span className={isSystem ? "text-muted-foreground" : ""}>{display}</span>
  );
}

function ValueCell({
  value,
  source,
}: {
  value: string | null;
  source: PoamRiskHistoryEntry["prev_source"];
}) {
  return (
    <span className="inline-flex items-center gap-1">
      <span className="font-medium">{value ?? "—"}</span>
      <SourceTag source={source} />
    </span>
  );
}

export interface RiskHistoryCardProps {
  poamId: number;
}

export function RiskHistoryCard({ poamId }: RiskHistoryCardProps) {
  const history = usePoamRiskHistory(poamId);
  const [showAll, setShowAll] = useState(false);

  const rows = history.data ?? [];
  const total = rows.length;
  const visible = showAll ? rows : rows.slice(0, DEFAULT_VISIBLE);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <History className="h-4 w-4 text-muted-foreground" />
              Risk history
            </CardTitle>
            <CardDescription>
              Append-only audit trail. Every likelihood, impact, raw severity,
              and residual risk transition is recorded with the actor and
              rationale at the time of the change.
            </CardDescription>
          </div>
          {total > 0 && (
            <Badge variant="outline" className="text-xs">
              {total} {total === 1 ? "change" : "changes"}
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent>
        {history.isLoading ? (
          <p className="text-sm text-muted-foreground">Loading history…</p>
        ) : history.isError ? (
          <p className="text-sm text-destructive">
            Failed to load risk history.
          </p>
        ) : total === 0 ? (
          <p className="text-sm text-muted-foreground">
            No risk-field changes recorded yet for this POAM.
          </p>
        ) : (
          <>
            <div className="overflow-x-auto rounded-md border">
              <table className="w-full text-xs">
                <thead className="bg-muted/40">
                  <tr className="text-left">
                    <th className="px-3 py-2 font-medium">When (UTC)</th>
                    <th className="px-3 py-2 font-medium">Who</th>
                    <th className="px-3 py-2 font-medium">Field</th>
                    <th className="px-3 py-2 font-medium">Was → Is</th>
                    <th className="px-3 py-2 font-medium">Rationale</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((row) => (
                    <tr
                      key={row.id}
                      className="border-t align-top last:border-b-0"
                    >
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-[11px] text-muted-foreground">
                        {formatDateTime(row.created_at)}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2">
                        <ActorCell actor={row.actor} />
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                        {FIELD_LABEL[row.field] ?? row.field}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2">
                        <ValueCell
                          value={row.prev_value}
                          source={row.prev_source}
                        />
                        <span className="mx-1 text-muted-foreground">→</span>
                        <ValueCell
                          value={row.new_value}
                          source={row.new_source}
                        />
                      </td>
                      <td className="px-3 py-2 text-muted-foreground">
                        {row.new_rationale ? (
                          <span className="line-clamp-2 whitespace-normal">
                            {row.new_rationale}
                          </span>
                        ) : (
                          <span>—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {total > DEFAULT_VISIBLE && (
              <div className="mt-3 flex justify-end">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowAll((v) => !v)}
                >
                  {showAll
                    ? `Show first ${DEFAULT_VISIBLE}`
                    : `Show all ${total}`}
                </Button>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
