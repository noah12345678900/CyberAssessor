"""Per-model Anthropic pricing for the operational cost denominator.

Rates are USD per million tokens (MTok), pulled from anthropic.com/pricing
as of 2026-06-02. They are deliberately hard-coded rather than fetched at
runtime so an offline / GovCloud-gateway run never silently zero-costs.
When Anthropic ships a new tier or rate, update the table and bump the
``RATES_REVISED`` constant — that's all.

Cost math:
    cost = (input_tokens     * input_rate
         +  output_tokens    * output_rate
         +  cache_read_tokens * cache_read_rate) / 1_000_000

Cache reads are billed at ~10% of the base input rate (Anthropic's standard
"ephemeral" cache discount). They MUST be tracked separately from the base
``input_tokens`` count — the AnthropicClient previously summed them into
``input_tokens`` which inflated cost by 10x for cache-heavy runs.

Models without an entry fall back to ``DEFAULT_RATES`` and the run notes
get a "unknown model, used default pricing" line so a stale tab in the
Settings dropdown can't silently produce wrong cost numbers.
"""

from __future__ import annotations

from dataclasses import dataclass

RATES_REVISED = "2026-06-02"


@dataclass(frozen=True)
class ModelRates:
    """USD per million tokens, per channel."""

    input_per_mtok: float
    output_per_mtok: float
    # Anthropic discounts cache reads to ~10% of the base input rate.
    cache_read_per_mtok: float
    # Cache writes are billed at ~125% of input on first use of a prefix.
    # Tracked but not load-bearing in v0.1 — we don't separate writes yet.
    cache_write_per_mtok: float


# Claude 4.x family rates. Update when Anthropic publishes new tiers.
RATES: dict[str, ModelRates] = {
    # Opus 4.7/4.8 — same rate card on the Example AI gateway as 4.6 Opus.
    # Source: /v1/models metadata returned by https://api.ai.example.com.
    # Cache rates expressed at the gateway's true per-MTok numbers (no
    # 10%/125% Anthropic-direct ratio because the gateway re-prices).
    "claude-4-7-opus": ModelRates(
        input_per_mtok=5.50,
        output_per_mtok=27.50,
        cache_read_per_mtok=0.55,
        cache_write_per_mtok=6.875,
    ),
    "claude-4-8-opus": ModelRates(
        input_per_mtok=5.50,
        output_per_mtok=27.50,
        cache_read_per_mtok=0.55,
        cache_write_per_mtok=6.875,
    ),
    # 4.6 Opus on the Example gateway — same rate card as 4.7/4.8.
    "claude-4-6-opus": ModelRates(
        input_per_mtok=5.50,
        output_per_mtok=27.50,
        cache_read_per_mtok=0.55,
        cache_write_per_mtok=6.875,
    ),
    "claude-opus-4-6": ModelRates(
        input_per_mtok=15.00,
        output_per_mtok=75.00,
        cache_read_per_mtok=1.50,
        cache_write_per_mtok=18.75,
    ),
    "claude-sonnet-4-6": ModelRates(
        input_per_mtok=3.00,
        output_per_mtok=15.00,
        cache_read_per_mtok=0.30,
        cache_write_per_mtok=3.75,
    ),
    "claude-haiku-4-5-20251001": ModelRates(
        input_per_mtok=1.00,
        output_per_mtok=5.00,
        cache_read_per_mtok=0.10,
        cache_write_per_mtok=1.25,
    ),
    # Friendly short aliases the Settings dropdown might surface.
    "claude-haiku-4-5": ModelRates(
        input_per_mtok=1.00,
        output_per_mtok=5.00,
        cache_read_per_mtok=0.10,
        cache_write_per_mtok=1.25,
    ),
    # ----- OpenAI ---------------------------------------------------------
    # Rates pulled from openai.com/api/pricing on RATES_REVISED. OpenAI's
    # "prompt caching" auto-applies to repeated prefixes >=1024 tokens and
    # is billed at ~50% of the base input rate (no explicit cache_control
    # like Anthropic's ephemeral marker). We surface that as
    # ``cache_read_per_mtok``; cache_write is 0 because OpenAI doesn't
    # charge an explicit write premium — first call is plain input rate.
    "gpt-5.1": ModelRates(
        input_per_mtok=2.50,
        output_per_mtok=10.00,
        cache_read_per_mtok=1.25,
        cache_write_per_mtok=0.0,
    ),
    "gpt-5.1-mini": ModelRates(
        input_per_mtok=0.25,
        output_per_mtok=2.00,
        cache_read_per_mtok=0.125,
        cache_write_per_mtok=0.0,
    ),
    "gpt-4o": ModelRates(
        input_per_mtok=2.50,
        output_per_mtok=10.00,
        cache_read_per_mtok=1.25,
        cache_write_per_mtok=0.0,
    ),
    "gpt-4o-mini": ModelRates(
        input_per_mtok=0.15,
        output_per_mtok=0.60,
        cache_read_per_mtok=0.075,
        cache_write_per_mtok=0.0,
    ),
}


# Conservative fallback (matches Sonnet) so an unknown model is still
# costed rather than silently appearing free. Run notes flag the fallback.
DEFAULT_RATES = RATES["claude-sonnet-4-6"]


def get_rates(model: str) -> tuple[ModelRates, bool]:
    """Look up rates for a model id. Returns (rates, is_fallback)."""
    rates = RATES.get(model)
    if rates is None:
        return DEFAULT_RATES, True
    return rates, False


def compute_cost(
    model: str,
    *,
    input_tokens: int,
    output_tokens: int,
    cache_read_tokens: int = 0,
    cache_write_tokens: int = 0,
) -> float:
    """Compute total run cost in USD given token totals.

    ``input_tokens`` should be the base (non-cache) input count only —
    cache reads pass in via ``cache_read_tokens``. The AnthropicClient
    splits them before they reach the recorder; legacy callers that
    pre-summed will overstate cost by ~10% on cache-heavy runs.
    """
    rates, _ = get_rates(model)
    return (
        input_tokens * rates.input_per_mtok
        + output_tokens * rates.output_per_mtok
        + cache_read_tokens * rates.cache_read_per_mtok
        + cache_write_tokens * rates.cache_write_per_mtok
    ) / 1_000_000.0
