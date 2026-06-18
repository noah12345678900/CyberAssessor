"""Metrics endpoints — Accuracy / Cost / Time rollups + reference benchmarks.

Drives two surfaces from the same JSON shape:

* ``GET /api/metrics`` — in-app Metrics tab. Includes per-run history.
* ``GET /api/metrics/public`` — Nuon marketing site. Aggregates + reference
  table only; no run ids, no workbook ids, no command strings.

Live numbers are aggregated in Python (single pass over AssessmentRun rows).
The dataset is small (one row per /assess-batch invocation, never thousands)
so window-function SQL would be more code for no gain. Mirrors the
``summarize()`` reducer in ``ui/src/routes/Runs.tsx:247-281`` — the frontend
no longer needs that reducer because the backend pre-aggregates.

Mechanisms section surfaces the deterministic accuracy controls in one place:
* Supersession (registry + total hits across runs)
* Validator rejections (rate)
* CRM overlay coverage (deferred — placeholder, see plan)
"""

from __future__ import annotations

from statistics import median
from typing import Any

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from ..db import get_session
from ..llm.pricing import RATES, RATES_REVISED
from ..metrics.references import load_references, rates_revised
from ..models import (
    Assessment,
    AssessmentRun,
    BaselineControl,
    ComplianceStatus,
    CrmShortCircuitEvent,
)
from sqlalchemy import func

router = APIRouter(prefix="/api/metrics", tags=["metrics"])


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------


def _safe_div(numer: float, denom: float) -> float | None:
    """Return numer/denom, or None when denom==0 — avoids fake zeros."""
    if denom <= 0:
        return None
    return numer / denom


def _duration_seconds(r: AssessmentRun) -> float | None:
    if r.started_at is None or r.finished_at is None:
        return None
    delta = (r.finished_at - r.started_at).total_seconds()
    if delta < 0:
        return None
    return delta


def _ref_value(
    references: dict[str, list[dict[str, Any]]], key: str
) -> float | None:
    """Pluck a single reference number by key, returning None when unsourced.

    The references.json shipped today has every value as null + citation
    "TODO" — so callers must treat None as "operator hasn't filled it in"
    and render a placeholder rather than crash or display 0.
    """
    for fam_entries in references.values():
        for entry in fam_entries:
            if entry.get("key") == key:
                v = entry.get("value")
                if isinstance(v, int | float):
                    return float(v)
                return None
    return None


def _savings(
    rows: list[AssessmentRun],
    references: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    """Dollars + minutes the assessor saved versus a manual A&A baseline.

    Headline ROI number for the Metrics tab — answers "what is this thing
    worth to me?" in a single figure. Reads the published per-CCI cost and
    time benchmarks out of references.json and compares them to live spend
    / wall-clock totals.

    Multiplier is ``ccis_accepted`` (not "decided"): we only claim credit
    for CCIs the assessor actually closed out with a verdict the operator
    can ship. Abstentions and validator rejects still bounced back to a
    human, so counting them as "saved" would be overclaiming. Result is
    conservative and matches what the marketing site can legally say.

    Returns null fields when the reference value is unfilled, so the UI
    can render an "Awaiting source" placeholder without faking a zero.
    """
    total_accepted = sum(r.ccis_accepted for r in rows)
    total_cost = sum(r.cost_usd for r in rows)
    total_minutes = (
        sum(d for d in (_duration_seconds(r) for r in rows) if d is not None) / 60.0
    )

    ref_cost_per_cci = _ref_value(references, "manual_assessment_cost_per_cci")
    ref_time_per_cci_min = _ref_value(references, "manual_assessment_time_per_cci")

    dollars_saved = None
    if ref_cost_per_cci is not None and total_accepted > 0:
        dollars_saved = round(ref_cost_per_cci * total_accepted - total_cost, 2)

    minutes_saved = None
    if ref_time_per_cci_min is not None and total_accepted > 0:
        minutes_saved = round(
            ref_time_per_cci_min * total_accepted - total_minutes, 2
        )

    return {
        "ccis_credited": total_accepted,
        "reference_cost_per_cci_usd": ref_cost_per_cci,
        "reference_time_per_cci_minutes": ref_time_per_cci_min,
        "manual_baseline_cost_usd": (
            round(ref_cost_per_cci * total_accepted, 2)
            if ref_cost_per_cci is not None
            else None
        ),
        "manual_baseline_minutes": (
            round(ref_time_per_cci_min * total_accepted, 2)
            if ref_time_per_cci_min is not None
            else None
        ),
        "live_cost_usd": round(total_cost, 2),
        "live_minutes": round(total_minutes, 2),
        "dollars_saved_usd": dollars_saved,
        "minutes_saved": minutes_saved,
        # Echoed so the UI can show a stable "Awaiting source" state without
        # second-guessing which reference key to look up.
        "reference_filled": (
            ref_cost_per_cci is not None or ref_time_per_cci_min is not None
        ),
    }


def _aggregate(rows: list[AssessmentRun], s: Session | None = None) -> dict[str, Any]:
    """Single-pass aggregation over AssessmentRun rows.

    Empty input is handled — every numeric field returns 0 or None (UI
    renders 'No runs yet') instead of crashing on a /metrics call against
    a fresh install.

    Accuracy ("CCI verdict agreement") is derived from the FINAL Assessment
    rows when a session is provided, NOT from the per-run RunRecorder event
    sums. The run-sum approach undercounted and double-counted:
      * Deterministic controls (rule 8a/8b, CRM provider/inherited/NA) are
        written by the open-time backfill with ``outcome=None`` — no
        AssessmentRun, no ``ccis_accepted`` — and then skipped by a later
        "Assess all" (skip_existing). They never entered the numerator, so a
        13-CCI workbook showed "11 of 13". Counting final Assessment rows
        includes them (one trusted verdict = one accepted CCI).
      * ``validator_rejections`` counts every retry REJECTION event, so a CCI
        rejected-then-accepted-on-retry landed in BOTH accepted and rejected,
        inflating "decided" — the "2 rejects when there were none" symptom.
        The agreement denominator is now accepted + abstained (final per-CCI
        states); raw rejection events stay below as a separate telemetry stat.
    """
    n_runs = len(rows)

    total_cost = sum(r.cost_usd for r in rows)
    total_input = sum(r.llm_input_tokens for r in rows)
    total_output = sum(r.llm_output_tokens for r in rows)
    total_cache = sum(r.llm_cache_read_tokens for r in rows)
    total_llm_calls = sum(r.llm_calls for r in rows)

    total_rejects = sum(r.validator_rejections for r in rows)
    total_retries = sum(r.retry_count for r in rows)
    total_supersession = sum(r.supersession_hits for r in rows)
    total_dual_pass = sum(getattr(r, "dual_pass_disagreements", 0) or 0 for r in rows)

    # Final per-CCI verdict counts (source of truth) when we have a session.
    # A trusted verdict (needs_review=False) is "accepted"; an abstain
    # (needs_review=True) is "abstained". Fall back to the legacy run-sum
    # behavior only when no session is available (keeps callers that pass just
    # rows working, though the route always passes the session now).
    if s is not None:
        total_accepted = (
            s.exec(
                select(func.count(Assessment.id)).where(
                    Assessment.needs_review.is_(False)  # type: ignore[union-attr]
                )
            ).one()
            or 0
        )
        total_abstained = (
            s.exec(
                select(func.count(Assessment.id)).where(
                    Assessment.needs_review.is_(True)  # type: ignore[union-attr]
                )
            ).one()
            or 0
        )
    else:
        total_accepted = sum(r.ccis_accepted for r in rows)
        total_abstained = sum(getattr(r, "abstained", 0) or 0 for r in rows)

    per_run_costs = [r.cost_usd for r in rows if r.cost_usd is not None]
    per_run_durations = [d for d in (_duration_seconds(r) for r in rows) if d is not None]
    per_cci_cost = [
        r.cost_usd / r.ccis_accepted
        for r in rows
        if r.ccis_accepted and r.cost_usd
    ]
    per_cci_seconds = [
        _duration_seconds(r) / r.ccis_accepted  # type: ignore[operator]
        for r in rows
        if r.ccis_accepted and _duration_seconds(r) is not None
    ]

    # Accuracy ("CCI verdict agreement"): accepted / (accepted + abstained),
    # over FINAL per-CCI states. "Decided" = every CCI that reached a terminal
    # state (a trusted verdict OR a reviewer-gated abstain). Validator
    # rejections are NOT in the denominator: they are mid-assessment retry
    # events, not terminal per-CCI outcomes, and a rejected-then-accepted CCI
    # would otherwise be counted twice (the "2 rejects when there were none"
    # bug). The raw rejection count is still surfaced separately below.
    decided_denom = total_accepted + total_abstained
    accuracy_pct = _safe_div(total_accepted * 100.0, decided_denom)

    # Dual-pass agreement = 1 - disagreement-rate over LLM calls.
    dual_pass_agreement_pct = None
    if total_llm_calls > 0:
        dual_pass_agreement_pct = (
            (1.0 - (total_dual_pass / total_llm_calls)) * 100.0
        )

    return {
        "n_runs": n_runs,
        "accuracy": {
            "ccis_accepted": total_accepted,
            "validator_rejections": total_rejects,
            "abstained": total_abstained,
            "retries": total_retries,
            "dual_pass_disagreements": total_dual_pass,
            "accuracy_pct": accuracy_pct,
            "dual_pass_agreement_pct": dual_pass_agreement_pct,
            "rejection_rate_pct": _safe_div(total_rejects * 100.0, decided_denom),
            "abstention_rate_pct": _safe_div(total_abstained * 100.0, decided_denom),
        },
        "cost": {
            "total_usd": round(total_cost, 4),
            "median_per_run_usd": round(median(per_run_costs), 4) if per_run_costs else None,
            "median_per_cci_usd": round(median(per_cci_cost), 4) if per_cci_cost else None,
            "total_input_tokens": total_input,
            "total_output_tokens": total_output,
            "total_cache_read_tokens": total_cache,
            "llm_calls": total_llm_calls,
        },
        "time": {
            "total_seconds": round(sum(per_run_durations), 2) if per_run_durations else 0.0,
            "median_per_run_seconds": (
                round(median(per_run_durations), 2) if per_run_durations else None
            ),
            "median_per_cci_seconds": (
                round(median(per_cci_seconds), 2) if per_cci_seconds else None
            ),
            "ccis_per_hour": (
                round(total_accepted / (sum(per_run_durations) / 3600.0), 2)
                if per_run_durations and sum(per_run_durations) > 0 and total_accepted
                else None
            ),
        },
    }


def _crm_overlay_coverage(s: Session) -> dict[str, Any]:
    """CRM overlay coverage — tagged-responsibility breakdown + short-circuit hits.

    Two complementary numbers:

    * **Coverage** — what fraction of in-scope :class:`BaselineControl` rows
      carry a CRM responsibility tag at all. Untagged rows fall back to the
      default-local rule (assessed as 100% customer-owned), so the gap
      between "tagged" and "in-scope" is the surface area the LLM still has
      to reason about from scratch.
    * **Short-circuit hits** — :class:`CrmShortCircuitEvent` rows the kernel
      wrote when ``responsibility`` was ``provider``/``inherited``/
      ``not_applicable``. Those CCIs skipped LLM evaluation entirely, so
      this is the concrete cost/time win the overlay produced.

    Aggregated across ALL baselines so a fresh install with no CRM still
    returns ``available=False`` and the UI renders a stable placeholder.
    """
    rows: list[BaselineControl] = list(
        s.exec(select(BaselineControl).where(BaselineControl.in_scope == True))  # noqa: E712 — SQL needs ==
    )
    breakdown = {
        "customer": 0,
        "provider": 0,
        "hybrid": 0,
        "inherited": 0,
        "not_applicable": 0,
        "untagged": 0,
    }
    for bc in rows:
        key = (bc.responsibility or "").strip().lower() or "untagged"
        if key not in breakdown:
            # Unknown vocab value — bucket as untagged so totals still reconcile.
            breakdown["untagged"] += 1
        else:
            breakdown[key] += 1
    in_scope_total = len(rows)
    tagged_total = sum(v for k, v in breakdown.items() if k != "untagged")
    coverage_pct = _safe_div(tagged_total * 100.0, in_scope_total)

    events: list[CrmShortCircuitEvent] = list(s.exec(select(CrmShortCircuitEvent)))
    by_resp = {"provider": 0, "inherited": 0, "not_applicable": 0}
    for ev in events:
        if ev.responsibility in by_resp:
            by_resp[ev.responsibility] += 1
    total_short_circuits = sum(by_resp.values())

    return {
        # `available` lets the UI keep a stable card slot — flips False when
        # no baseline has any CRM data yet (fresh install / pre-CRM workbook).
        "available": tagged_total > 0 or total_short_circuits > 0,
        "in_scope_total": in_scope_total,
        "tagged_total": tagged_total,
        "coverage_pct": coverage_pct,
        "responsibility_breakdown": breakdown,
        "total_short_circuits": total_short_circuits,
        "short_circuits_by_responsibility": by_resp,
    }


def _mechanisms(rows: list[AssessmentRun], s: Session) -> dict[str, Any]:
    """Deterministic accuracy controls — cumulative hits.

    Supersession is data-driven per workbook (the evidence-chain rewriter
    walks ``Evidence.superseded_by_id``); there is no global registry to
    size. ``total_hits`` is the cumulative rewrite count across all runs
    (``supersession_hits`` is an int counter on AssessmentRun). The
    per-workbook chain *entries* are served by the in-app
    ``GET /api/supersession/chains`` endpoint — never here, because
    ``_mechanisms`` also feeds the Nuon-safe ``/public`` payload and chain
    entries carry program doc numbers/titles.
    """
    total_hits = sum(r.supersession_hits for r in rows)
    total_rejects = sum(r.validator_rejections for r in rows)
    total_llm_calls = sum(r.llm_calls for r in rows)

    return {
        "supersession": {
            "total_hits": total_hits,
        },
        "validator": {
            "total_rejections": total_rejects,
            "rejection_rate_pct": _safe_div(total_rejects * 100.0, total_llm_calls),
        },
        # CRM overlay coverage — live aggregates from BaselineControl +
        # CrmShortCircuitEvent. See `_crm_overlay_coverage()`.
        "crm_overlay": _crm_overlay_coverage(s),
    }


def _rate_card() -> list[dict[str, Any]]:
    """Flatten the LLM pricing table for the Cost section."""
    return [
        {
            "model": model,
            "input_per_mtok": rates.input_per_mtok,
            "output_per_mtok": rates.output_per_mtok,
            "cache_read_per_mtok": rates.cache_read_per_mtok,
            "cache_write_per_mtok": rates.cache_write_per_mtok,
        }
        for model, rates in RATES.items()
    ]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("")
def get_metrics(s: Session = Depends(get_session)) -> dict[str, Any]:
    """Full in-app payload — live aggregates + mechanisms + references."""
    rows = s.exec(select(AssessmentRun)).all()
    references = load_references()
    return {
        "live": _aggregate(rows, s),
        "mechanisms": _mechanisms(rows, s),
        "reference": references,
        # Top-level (not nested under live/reference) because savings is the
        # delta between the two — the ROI headline the marketing site quotes.
        "savings": _savings(rows, references),
        "rate_card": {
            "rates_revised": RATES_REVISED,
            "models": _rate_card(),
        },
        "references_revised": rates_revised(),
    }


@router.get("/public")
def get_metrics_public(s: Session = Depends(get_session)) -> dict[str, Any]:
    """Nuon-safe payload — aggregates + reference table, no per-run records.

    Same shape as ``/api/metrics`` but omits any field that could leak a
    specific workbook id, run id, or command string. Safe to render on a
    public static site.
    """
    rows = s.exec(select(AssessmentRun)).all()
    references = load_references()
    return {
        "live": _aggregate(rows, s),
        "mechanisms": _mechanisms(rows, s),
        "reference": references,
        "savings": _savings(rows, references),
        "rate_card": {
            "rates_revised": RATES_REVISED,
            "models": _rate_card(),
        },
        "references_revised": rates_revised(),
    }
