/**
 * LLM-powered residual-risk advisor card.
 *
 * Lazy-loads `GET /api/poams/{id}/residual-suggestion` on mount, then renders
 * one of three states:
 *
 *   1. **Suggestion present** — model returned a `RiskLevel`. Shows level,
 *      prose rationale, confidence badge, and key-factors badge list. "Apply
 *      suggestion" stamps it via `POST /apply-residual-suggestion` which
 *      flips `residual_risk_source = "llm_suggested"` server-side and writes
 *      a `PoamRiskHistory` row in the same transaction.
 *
 *   2. **Abstain** — `suggested === null`. Per ``feedback_precision_over_recall``
 *      the model must abstain when boundary context is insufficient; the card
 *      explains why and points the assessor at the linked-controls section so
 *      they can flesh out the boundary narrative that feeds the next call.
 *
 *   3. **Loading / error** — small inline placeholder; the "Refresh
 *      suggestion" button is always available so the assessor can force a
 *      recompute after editing narratives or mitigations.
 *
 * Lives below the Risk card in `PoamDetail.tsx`. Sibling to `RiskHistoryCard`.
 */

import { Sparkles, RefreshCw } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { toast } from "@/components/ui/toaster";
import { api, type PoamResidualSuggestion } from "@/lib/api";
import { humanize } from "@/lib/errors";
import { formatDateTime } from "@/lib/poamFormat";
import {
  qk,
  useApplyPoamResidualSuggestion,
  usePoamResidualSuggestion,
} from "@/lib/queries";

const CONFIDENCE_LABEL: Record<
  PoamResidualSuggestion["confidence"],
  string
> = {
  high: "High confidence",
  medium: "Medium confidence",
  low: "Low confidence",
};

function ConfidenceBadge({
  confidence,
}: {
  confidence: PoamResidualSuggestion["confidence"];
}) {
  const variant: "default" | "secondary" | "outline" =
    confidence === "high"
      ? "default"
      : confidence === "medium"
        ? "secondary"
        : "outline";
  return (
    <Badge variant={variant} className="text-[10px] uppercase tracking-wide">
      {CONFIDENCE_LABEL[confidence]}
    </Badge>
  );
}

export interface ResidualAdvisorCardProps {
  poamId: number;
}

export function ResidualAdvisorCard({ poamId }: ResidualAdvisorCardProps) {
  const queryClient = useQueryClient();
  const [refreshing, setRefreshing] = useState(false);
  const suggestion = usePoamResidualSuggestion(poamId, { enabled: true });
  const apply = useApplyPoamResidualSuggestion({
    onSuccess: () => toast.success("Residual risk updated"),
    onError: (e) => toast.error("Apply failed", humanize(e)),
  });

  // Refresh must BYPASS the server-side decision cache. suggestion.refetch()
  // reruns the original queryFn with force_refresh undefined, so it just
  // replays the cached decision — the button looked like a no-op. Call the
  // API directly with force_refresh:true and write the fresh result into the
  // query cache so the card re-renders with it.
  const onRefresh = () => {
    setRefreshing(true);
    api
      .getPoamResidualSuggestion(poamId, { force_refresh: true })
      .then((fresh) => {
        queryClient.setQueryData(qk.poamResidualSuggestion(poamId), fresh);
      })
      .catch((e: unknown) => {
        toast.error("Refresh failed", humanize(e));
      })
      .finally(() => setRefreshing(false));
  };

  const onApply = () => {
    const data = suggestion.data;
    if (!data || data.suggested == null) return;
    apply.mutate({
      poamId,
      residual_risk: data.suggested,
      residual_risk_rationale: data.rationale,
    });
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-muted-foreground" />
              Residual risk advisor
            </CardTitle>
            <CardDescription>
              Boundary-aware suggestion derived from linked control narratives,
              contributing STIG findings, and the POAM mitigations. Advisory
              only — abstains when context is too sparse to be defensible.
            </CardDescription>
          </div>
          {suggestion.data && (
            <ConfidenceBadge confidence={suggestion.data.confidence} />
          )}
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {suggestion.isLoading ? (
          <p className="text-sm text-muted-foreground">
            Reasoning over boundary context…
          </p>
        ) : suggestion.isError ? (
          <p className="text-sm text-destructive">
            Failed to load suggestion: {humanize(suggestion.error)}
          </p>
        ) : !suggestion.data ? (
          <p className="text-sm text-muted-foreground">
            Click <em>Refresh suggestion</em> to request a residual-risk
            recommendation.
          </p>
        ) : suggestion.data.suggested == null ? (
          <div className="space-y-2 rounded-md border border-dashed bg-muted/30 p-3">
            <p className="text-sm font-medium">
              Insufficient context — advisor abstained.
            </p>
            <p className="text-sm text-muted-foreground whitespace-pre-wrap">
              {suggestion.data.rationale}
            </p>
            <p className="text-xs text-muted-foreground">
              Improve the boundary description in the linked control
              narratives below (network exposure, compensating controls,
              exploit prerequisites), then refresh.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-muted-foreground">
                Suggested residual risk:
              </span>
              <Badge variant="default" className="text-sm">
                {suggestion.data.suggested}
              </Badge>
            </div>
            <p className="text-sm text-muted-foreground whitespace-pre-wrap">
              {suggestion.data.rationale}
            </p>
            {suggestion.data.key_factors.length > 0 && (
              <div className="space-y-1">
                <p className="text-xs uppercase tracking-wide text-muted-foreground">
                  Key factors
                </p>
                <div className="flex flex-wrap gap-1">
                  {suggestion.data.key_factors.map((factor, i) => (
                    <Badge
                      key={`${i}-${factor.slice(0, 32)}`}
                      variant="outline"
                      className="text-xs"
                    >
                      {factor}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {suggestion.data && (
          <p className="text-[11px] text-muted-foreground">
            Decided {formatDateTime(suggestion.data.decided_at)} ·{" "}
            {suggestion.data.cache_source === "cache_hit" ? "cached" : "fresh"}
          </p>
        )}
      </CardContent>

      <CardFooter className="flex justify-end gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={onRefresh}
          disabled={suggestion.isFetching || refreshing}
        >
          <RefreshCw
            className={`h-3.5 w-3.5 ${
              suggestion.isFetching || refreshing ? "animate-spin" : ""
            }`}
          />
          Refresh suggestion
        </Button>
        <Button
          variant="default"
          size="sm"
          onClick={onApply}
          disabled={
            !suggestion.data ||
            suggestion.data.suggested == null ||
            apply.isPending
          }
        >
          Apply suggestion
        </Button>
      </CardFooter>
    </Card>
  );
}
