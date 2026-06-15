"""LLM judge for the SharePoint sweep (v0.2).

The keyword scorer in ``sweep.py`` is fast and free but misses semantically
relevant docs whose filenames don't hit any token (e.g. an "incident response
runbook" with no ``IR-`` prefix in the name) and surfaces noise that happens
to contain a control-family substring. This module layers a short-rubric
LLM classifier on top: every keyword-surviving candidate is scored against
a cached boundary brief, and the result is blended into the final score
that drives the surface/precheck thresholds.

Design committed in plans/cuddly-twirling-planet.md (user directive 2026-06-04:
*"idc about bang for buck accuracy"*):

- **Judge every survivor, not top-N.** Accuracy over cost. Skip-family
  vetoed candidates (already score 0.0) never reach the judge.
- **One cached system block per sweep.** Boundary brief goes in a single
  Anthropic ``cache_control: ephemeral`` block so the second call onward
  reads at ~10% input rate. Per-candidate user turn stays under ~300
  input tokens (filename + path + snippet + JSON rubric).
- **Bounded ThreadPoolExecutor.** SDKs are sync; threads are the cheapest
  correct path. Running cost tally under a lock — when it crosses the cap,
  remaining futures are cancelled and ``fallback_reason`` set.
- **Graceful degradation.** Any per-call exception is caught and rendered
  as a JudgeResult with ``error`` set; the sweep blends those rows as
  pure-keyword. A sweep MUST complete.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any

from ...llm.pricing import compute_cost
from .sweep import BoundaryFingerprint

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class JudgeResult:
    """One candidate's judge output. 1:1 with the input list."""

    score: float          # [0, 1]
    reasoning: str        # <= 200 chars
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    error: str | None = None


@dataclass(frozen=True)
class JudgeBatchResult:
    """Aggregate output of ``judge_candidates_concurrent``.

    ``results`` is 1:1 with the input candidate list by index. When the
    running cost tally crosses the cap mid-batch, the remaining slots are
    filled with ``JudgeResult(score=0.0, error="cost_cap_exceeded", ...)``
    and ``fallback_reason`` is set so the caller can mark those rows as
    judge-skipped and use the pure-keyword score for the blend.
    """

    results: list[JudgeResult]
    total_input_tokens: int
    total_output_tokens: int
    total_cache_read_tokens: int
    total_cache_write_tokens: int
    estimated_cost_usd: float
    fallback_reason: str | None  # None | "cost_cap_exceeded" | "time_cap_exceeded" | "api_error: ..."


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------


_JUDGE_INSTRUCTIONS = """\
You are a classifier that scores a single candidate file for how likely it
is to be useful evidence for the cybersecurity assessment described in the
boundary brief above.

Reply with a JSON object and nothing else:

  {"score": <0.0-1.0>, "reasoning": "<<=200 chars>"}

Scoring rubric:
  1.0  - clearly in-scope for this boundary; names a host/service/control
         that appears in the brief; assessor should examine it
  0.7  - probably relevant; mentions an in-scope control family or a CRM
         keyword, but no direct host/control hit
  0.4  - tangentially relevant; right document type but unclear whether
         it covers this boundary
  0.1  - unlikely to help this assessment but not obviously off-topic
  0.0  - clearly off-topic; different program, different system, marketing
         material, etc.

Be strict. The keyword scorer already passed this candidate; your job is to
catch the false positives it can't see (e.g. a file named "AC_Policy.docx"
that is actually a different program's access control policy) and to
upgrade semantically-relevant files whose names don't hit any keyword."""


def build_boundary_brief(
    fp: BoundaryFingerprint,
    *,
    seed_exemplars: list[tuple[str, str, str | None]] | None = None,
) -> list[dict]:
    """Build the cacheable system block describing this assessment's boundary.

    Returns a single-element list shaped for Anthropic's ``system=`` param
    with ``cache_control: ephemeral`` set. The OpenAI client flattens this
    into a plain system message (automatic prefix caching handles reuse).

    The brief intentionally lists raw tokens rather than narrative prose —
    the judge isn't reading for understanding, it's pattern-matching against
    the candidate filename/path/snippet. Sorted everywhere so the same
    fingerprint produces the same cache key.

    ``seed_exemplars`` (optional, pseudo-relevance feedback): a list of
    ``(name, path, snippet)`` tuples drawn from artifacts the assessor
    confirmed in a prior sweep round. Rendered as an "exemplar in-scope
    artifacts" block ahead of the scoring rubric so the judge has concrete
    semantic anchors beyond bare host tokens. The whole brief is still one
    cached block — the exemplars travel with the cache key, so a refine pass
    pays one fresh cache write up front and amortizes across every
    per-candidate call in that pass.
    """
    lines: list[str] = [
        "You are judging file relevance for one cybersecurity assessment.",
        "Below is the boundary brief — the signals that define what is in scope.",
        "",
    ]

    # System narrative goes first because it's the only block carrying
    # operator intent ("what is this system?") rather than bare tokens.
    # The judge can use it to upgrade semantically-relevant candidates
    # whose snippet/path don't lexically intersect the token sets below.
    if fp.system_narrative:
        lines.append("System under assessment (operator-authored description):")
        lines.append(fp.system_narrative.strip())
        lines.append("")
        lines.append(
            "Treat the narrative above as authoritative for what the system IS. "
            "A candidate may be in scope on semantic grounds even when no token "
            "below appears in its filename, path, or snippet."
        )
        lines.append("")

    if fp.host_tokens:
        lines.append("Host / service tokens (highest signal):")
        lines.append("  " + ", ".join(sorted(fp.host_tokens)))
        lines.append("")

    if fp.in_scope_control_ids:
        lines.append("In-scope control IDs (OSCAL canonical):")
        lines.append("  " + ", ".join(sorted(fp.in_scope_control_ids)))
        lines.append("")

    if fp.control_families:
        lines.append("In-scope control families:")
        lines.append("  " + ", ".join(sorted(fp.control_families)))
        lines.append("")

    if fp.crm_skip_families:
        lines.append(
            "Skip these families entirely (provider-owned / inherited / NA):"
        )
        lines.append("  " + ", ".join(sorted(fp.crm_skip_families)))
        lines.append("")

    if fp.crm_keywords:
        # Cap to avoid blowing up the cached block. The richest 20 controls
        # by keyword count is plenty signal — the judge falls back to the
        # control IDs above for everything else.
        top = sorted(
            fp.crm_keywords.items(),
            key=lambda kv: (-len(kv[1]), kv[0]),
        )[:20]
        lines.append("CRM narrative keywords by control:")
        for cid, toks in top:
            if toks:
                lines.append(f"  {cid}: {', '.join(sorted(toks))}")
        lines.append("")

    if fp.doc_number_prefixes:
        lines.append("Document number prefixes the program uses:")
        lines.append("  " + ", ".join(sorted(fp.doc_number_prefixes)))
        lines.append("")

    if fp.priority_path_prefixes:
        lines.append("Assessor-bookmarked priority folders (path substrings):")
        for prefix in sorted(fp.priority_path_prefixes):
            label = fp.label_by_priority_prefix.get(prefix, "")
            lines.append(f"  {prefix}" + (f"  ({label})" if label else ""))
        lines.append("")

    # Pseudo-relevance feedback. The assessor's prior-round picks become
    # explicit "this is what in-scope looks like" anchors. Cap snippets at
    # 300 chars apiece so a fat exemplar list doesn't blow the cache block.
    # Sort by path so the cache key stays stable for the same exemplar set.
    if seed_exemplars:
        lines.append(
            "Exemplar in-scope artifacts (assessor-confirmed in a prior pass — "
            "treat as authoritative anchors for what 'in scope' looks like; a "
            "new candidate that resembles any of these on semantic grounds is "
            "likely in scope even with zero token overlap):"
        )
        for name, path, snippet in sorted(seed_exemplars, key=lambda t: t[1]):
            lines.append(f"  - {name}  ({path})")
            if snippet:
                trimmed = snippet.strip().replace("\n", " ")
                if len(trimmed) > 300:
                    trimmed = trimmed[:300] + "…"
                lines.append(f"    snippet: {trimmed}")
        lines.append("")

    lines.append(_JUDGE_INSTRUCTIONS)
    text = "\n".join(lines)

    return [
        {
            "type": "text",
            "text": text,
            "cache_control": {"type": "ephemeral"},
        }
    ]


def _build_candidate_turn(
    name: str,
    path: str,
    snippet: str | None,
    *,
    keyword_score: float | None = None,
    keyword_signals: list[str] | tuple[str, ...] | None = None,
) -> str:
    """Per-candidate user turn. Kept short so non-cache input stays cheap.

    ``keyword_score`` and ``keyword_signals`` are the pure-lexical pass-1
    output from :func:`sweep.score_candidate`. They are exposed to the judge
    as a *signal*, not a gate — the judge is free to upgrade a 0.0 lexical
    score on semantic grounds (the demo failure mode) and equally free to
    downgrade a high lexical score that turns out to be a false positive
    (e.g. another program's AC policy that matches the AC keyword set).
    """
    snippet_text = (snippet or "").strip()
    if len(snippet_text) > 600:
        snippet_text = snippet_text[:600] + "…"
    parts = [
        f"Filename: {name}",
        f"Path: {path}",
    ]
    if keyword_score is not None:
        signals_str = (
            ", ".join(keyword_signals) if keyword_signals else "(none)"
        )
        parts.append(
            f"Lexical keyword score: {keyword_score:.2f}  (signals: {signals_str})"
        )
        parts.append(
            "  Note: this is a hint, not a verdict — upgrade or downgrade as the snippet warrants."
        )
    if snippet_text:
        parts.append(f"Snippet:\n{snippet_text}")
    else:
        parts.append("Snippet: (none — judge from filename + path only)")
    parts.append("")
    parts.append("Score this candidate per the rubric.")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Single-candidate judge
# ---------------------------------------------------------------------------


def judge_candidate(
    client: Any,
    brief_system_blocks: list[dict],
    name: str,
    path: str,
    snippet: str | None,
    *,
    model: str | None = None,
    keyword_score: float | None = None,
    keyword_signals: list[str] | tuple[str, ...] | None = None,
) -> JudgeResult:
    """Score one candidate. Catches all exceptions — never raises.

    ``client`` is an AnthropicClient or OpenAIClient — both implement
    ``judge_relevance(system_blocks, user_text, *, model=None) ->
    (score, reasoning, _UsageBlock)``. Any exception bubbling out of the
    SDK lands in ``JudgeResult.error`` so the sweep can keep going and the
    row blends as pure-keyword.

    Rate-limit retry is NOT done here. ``judge_relevance`` already routes
    through ``llm/_rate_limit.run_with_rate_limit_retry`` — the single,
    process-wide 429 backoff path that honors ``Retry-After`` and holds the
    global admission semaphore (``llm_max_concurrency``); the SDK's own
    ``max_retries`` covers transient 5xx/overloaded beneath that. The old
    per-candidate 1s/2s/4s loop here re-ran that whole stack on every 429,
    compounding the wait (SDK ×2 → global ×4 → here ×3) for no extra
    resilience. With the admission gate sized below the sum of the worker
    pools, a 429 storm is rare and the global path absorbs the few that slip
    through, so this function makes a single attempt and degrades on error.

    FIXME(sweep-audit 2026-06-07): no abstain path. Per
    feedback_precision_over_recall, the judge should return a "not sure"
    verdict when it can't tell — instead this contract forces a 0.0-1.0
    score on every call, which silently coerces uncertainty into either a
    surface (false positive) or a drop (false negative). Add a third
    return state ("abstain") and let the route route abstain candidates
    to a separate review-only tray.
    """
    user_text = _build_candidate_turn(
        name,
        path,
        snippet,
        keyword_score=keyword_score,
        keyword_signals=keyword_signals,
    )

    try:
        score, reasoning, usage = client.judge_relevance(
            brief_system_blocks, user_text, model=model
        )
        return JudgeResult(
            score=score,
            reasoning=reasoning,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cache_read_tokens=usage.cache_read_input_tokens,
            cache_write_tokens=usage.cache_creation_input_tokens,
        )
    except Exception as exc:  # noqa: BLE001 — graceful degradation by design
        log.warning("judge_candidate failed for %s: %s", name, exc)
        return JudgeResult(
            score=0.0,
            reasoning="",
            input_tokens=0,
            output_tokens=0,
            cache_read_tokens=0,
            cache_write_tokens=0,
            error=f"api_error: {type(exc).__name__}: {exc}",
        )


# ---------------------------------------------------------------------------
# Concurrent batch with cost cap
# ---------------------------------------------------------------------------


def judge_candidates_concurrent(
    client: Any,
    fp: BoundaryFingerprint,
    candidates: list[
        tuple[str, str, str | None]
        | tuple[str, str, str | None, float | None]
        | tuple[str, str, str | None, float | None, list[str] | tuple[str, ...] | None]
    ],
    *,
    max_workers: int,
    cost_cap_usd: float,
    model: str,
    time_cap_seconds: float = 0.0,
    seed_exemplars: list[tuple[str, str, str | None]] | None = None,
) -> JudgeBatchResult:
    """Judge every candidate in parallel, capped by cost and/or wall-clock time.

    ``candidates`` is a list of tuples. The original 3-tuple form
    ``(name, path, snippet)`` is still accepted for backward-compat; the
    hybrid pipeline (sharepoint.py) passes the 5-tuple form
    ``(name, path, snippet, keyword_score, keyword_signals)`` so the judge
    can use the lexical score as a signal (NOT a gate) in its prompt.
    Returns a ``JudgeBatchResult`` whose ``results`` list is 1:1 with
    ``candidates`` by index. The caller pairs back by index and uses the
    keyword score for any row whose JudgeResult has ``error`` set.

    Cap policy (both checked under the same lock after each completion):

    - ``cost_cap_usd <= 0`` ⇒ unlimited; cost cap-check is bypassed entirely.
      Otherwise, running cost tally crossing the cap sets fallback_reason to
      "cost_cap_exceeded".
    - ``time_cap_seconds <= 0`` ⇒ unlimited; time cap-check is bypassed.
      Otherwise, wall-clock since pool start exceeding the cap sets
      fallback_reason to "time_cap_exceeded". This is the user-facing knob
      ("stop after N minutes") — cost cap is the config-only safety rail.
    - When either cap trips, all not-yet-started futures are cancelled and
      any in-flight calls are allowed to finish (we already paid for them).
    - Unfilled slots default to ``JudgeResult(error="cap_skipped")`` so the
      index alignment holds.

    Workers default to 8 — short request, mostly cache reads, no streaming.
    Bumping past ~16 hits Anthropic's per-org concurrent-request limits on
    most plans without much wall-clock win.
    """
    n = len(candidates)
    if n == 0:
        return JudgeBatchResult(
            results=[],
            total_input_tokens=0,
            total_output_tokens=0,
            total_cache_read_tokens=0,
            total_cache_write_tokens=0,
            estimated_cost_usd=0.0,
            fallback_reason=None,
        )

    brief = build_boundary_brief(fp, seed_exemplars=seed_exemplars)

    results: list[JudgeResult | None] = [None] * n
    lock = threading.Lock()
    cost_so_far: dict[str, float] = {"v": 0.0}
    fallback_reason: dict[str, str | None] = {"v": None}
    start_time = time.monotonic()

    def _worker(idx: int) -> tuple[int, JudgeResult]:
        item = candidates[idx]
        # Tuple width is 3 (legacy), 4 (kw_score only), or 5 (kw_score + signals).
        name = item[0]
        path = item[1]
        snippet = item[2]
        kw_score = item[3] if len(item) >= 4 else None
        kw_signals = item[4] if len(item) >= 5 else None
        r = judge_candidate(
            client,
            brief,
            name,
            path,
            snippet,
            model=model,
            keyword_score=kw_score,
            keyword_signals=kw_signals,
        )
        # Tally + cap-check under the lock so we never double-count or race.
        per_call_cost = compute_cost(
            model,
            input_tokens=r.input_tokens,
            output_tokens=r.output_tokens,
            cache_read_tokens=r.cache_read_tokens,
            cache_write_tokens=r.cache_write_tokens,
        )
        with lock:
            cost_so_far["v"] += per_call_cost
            # cost_cap_usd <= 0 disables the cap entirely (default).
            if (
                cost_cap_usd > 0
                and cost_so_far["v"] > cost_cap_usd
                and fallback_reason["v"] is None
            ):
                fallback_reason["v"] = "cost_cap_exceeded"
            # time_cap_seconds <= 0 disables the cap entirely (default).
            elif (
                time_cap_seconds > 0
                and (time.monotonic() - start_time) > time_cap_seconds
                and fallback_reason["v"] is None
            ):
                fallback_reason["v"] = "time_cap_exceeded"
        return idx, r

    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
        futures = {pool.submit(_worker, i): i for i in range(n)}
        for fut in as_completed(futures):
            idx, r = fut.result()
            results[idx] = r
            # If we just crossed either cap, cancel pending futures. In-flight
            # ones will still land in `results` — that's fine, we already
            # paid for them and the data is good.
            if fallback_reason["v"] in ("cost_cap_exceeded", "time_cap_exceeded"):
                for f, j in futures.items():
                    if results[j] is None and not f.running():
                        f.cancel()

    # Fill any cancelled slots with a sentinel so the caller's index pairing
    # stays aligned.
    sentinel = JudgeResult(
        score=0.0,
        reasoning="",
        input_tokens=0,
        output_tokens=0,
        cache_read_tokens=0,
        cache_write_tokens=0,
        error="cap_skipped",
    )
    final: list[JudgeResult] = [r if r is not None else sentinel for r in results]

    # Aggregate. Any rows with `error` set contributed nothing to tokens.
    tot_in = sum(r.input_tokens for r in final)
    tot_out = sum(r.output_tokens for r in final)
    tot_cr = sum(r.cache_read_tokens for r in final)
    tot_cw = sum(r.cache_write_tokens for r in final)
    total_cost = compute_cost(
        model,
        input_tokens=tot_in,
        output_tokens=tot_out,
        cache_read_tokens=tot_cr,
        cache_write_tokens=tot_cw,
    )

    # If every call errored with the same api_error, surface that as the
    # fallback_reason so the route can show one toast instead of N.
    if fallback_reason["v"] is None:
        api_errs = [r.error for r in final if r.error and r.error.startswith("api_error:")]
        if api_errs and len(api_errs) == n:
            # Use the first one verbatim — they're almost always identical
            # (key revoked, network down, model id wrong).
            fallback_reason["v"] = api_errs[0]

    return JudgeBatchResult(
        results=final,
        total_input_tokens=tot_in,
        total_output_tokens=tot_out,
        total_cache_read_tokens=tot_cr,
        total_cache_write_tokens=tot_cw,
        estimated_cost_usd=total_cost,
        fallback_reason=fallback_reason["v"],
    )
