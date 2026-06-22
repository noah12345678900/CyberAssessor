"""Shared 429 retry-with-backoff helper for LLM clients.

Plug-and-play across every gateway we care about (direct Anthropic,
direct OpenAI, Example corporate gateway at ``api.ai.example.com``, Vertex-
proxied Anthropic, and any future corporate proxy) — HTTP 429 + the
``Retry-After`` header are RFC standards, so the same handler works
without per-gateway tuning.

Why this exists on top of the SDKs' built-in retry:

* The Anthropic SDK defaults to ``max_retries=2`` for transient 429s and
  the OpenAI SDK similarly retries twice. That handles the direct APIs
  fine but the Example gateway sustains "Too many calls" for several seconds
  when 8 assess-batch workers burst out at once, exhausting the SDKs'
  budget. We layer a second, larger retry budget at the call-site so the
  CCI doesn't go to ``unresolved`` just because the gateway was crowded
  for ~10s.

* Both client classes (``AnthropicLlmClient._call_once`` and
  ``OpenAiClient._call_once``) call ``run_with_rate_limit_retry`` so the
  policy stays symmetric across providers — no provider-specific
  concurrency caps in the route layer.

Behavior:

* On ``anthropic.RateLimitError`` / ``openai.RateLimitError``, sleep and
  retry. Up to ``MAX_ATTEMPTS`` total attempts (default 5: initial + 4
  retries).
* Sleep duration is, in order of preference:
    1. ``Retry-After`` header value if the SDK exposes it on the
       exception's ``response`` (RFC 7231 §7.1.3 — seconds or HTTP-date).
    2. Otherwise exponential backoff: ``BASE_DELAY * 2**attempt`` (2s,
       4s, 8s, 16s) plus uniform [0, 1)s of jitter to stagger workers
       so they don't all retry at the same instant and re-trip the limit.
* After the final attempt, the original exception bubbles to the caller
  (route's ``_assess_one`` catches it and marks the CCI unresolved).
* Non-rate-limit exceptions pass through immediately — we do NOT retry
  generic ``Exception``.
"""

from __future__ import annotations

import contextlib
import logging
import random
import threading
import time
from email.utils import parsedate_to_datetime
from typing import Callable, Iterator, TypeVar

log = logging.getLogger(__name__)

MAX_ATTEMPTS = 5
BASE_DELAY_SECONDS = 2.0
JITTER_SECONDS = 1.0
# Hard cap on a single sleep — paranoid guard against a gateway sending
# ``Retry-After: 3600``. The user's batch would hang for an hour; better
# to fail fast and let them re-queue.
MAX_SINGLE_SLEEP_SECONDS = 60.0
# Proactive stagger applied *before* every call, once a worker has been
# admitted through the concurrency gate. The reactive backoff above only
# kicks in after a 429 has already been spent; this small uniform sleep
# spreads the burst that happens when N pooled judge workers all clear the
# semaphore in the same instant, so fewer calls trip the gateway's "Too
# many calls" window in the first place. Tiny (well under the per-call
# latency) so throughput is unaffected — it only de-synchronizes starts.
PRECALL_JITTER_SECONDS = 0.15


T = TypeVar("T")

# Global LLM admission gate. Built lazily from config the first time any
# call site needs it, then shared across every assess/judge/sweep worker
# thread in the process — the rate limit is a property of the *endpoint*,
# so one cap governs all providers and call sites. Guarded by a lock so
# concurrent first-callers don't each build their own semaphore.
_semaphore: threading.Semaphore | None = None
_semaphore_disabled = False
_semaphore_lock = threading.Lock()

# Global forward-propagated 429 cooldown. When ANY worker eats a 429, the
# server's backpressure applies to the whole endpoint, not just that one
# call — but the SDK's per-call retry only pauses the offending thread while
# every sibling worker keeps hammering, re-tripping the limit (the
# self-inflicted thundering-herd seen during bulk ingest: one thread sleeps
# out its Retry-After while 15 others 429 again). Publishing the cooldown
# deadline here makes EVERY admission (new dispatch + retry) hold until it
# passes, so the herd pauses ONCE on the server's own signal and resumes
# together. This is the research-backed fix (honor Retry-After globally) —
# NOT predictive AIMD / token-bucket, which is over-engineering for a single
# process whose retries already recover. Monotonic clock so a wall-clock
# adjustment can't wedge the gate. ``0.0`` = no active cooldown.
_cooldown_until: float = 0.0
_cooldown_lock = threading.Lock()
# Cap how long a single published cooldown can park the fleet — defense
# against a gateway returning an absurd Retry-After. Mirrors the per-call
# MAX_SINGLE_SLEEP_SECONDS guard so the global gate can't hang an ingest.
MAX_COOLDOWN_SECONDS = MAX_SINGLE_SLEEP_SECONDS


def _publish_cooldown(seconds: float) -> None:
    """Extend the global cooldown deadline to at least ``now + seconds``.

    Called from the 429 retry path with the same delay the offending thread
    is about to sleep (server ``Retry-After`` when present, else backoff).
    ``max`` so a longer in-flight cooldown is never shortened by a smaller
    later one. Bounded by ``MAX_COOLDOWN_SECONDS``.
    """
    if seconds <= 0:
        return
    seconds = min(seconds, MAX_COOLDOWN_SECONDS)
    deadline = time.monotonic() + seconds
    global _cooldown_until
    with _cooldown_lock:
        if deadline > _cooldown_until:
            _cooldown_until = deadline


def _await_cooldown() -> None:
    """Block until any active global cooldown has elapsed.

    Cheap fast-path: a single unlocked read of the deadline; only sleeps
    when a cooldown is actually pending. Re-checks after sleeping in case a
    fresh 429 extended the deadline while we waited.
    """
    while True:
        remaining = _cooldown_until - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(remaining, MAX_COOLDOWN_SECONDS))


def _get_semaphore() -> threading.Semaphore | None:
    """Return the shared admission semaphore, or None when capping is off.

    The cap comes from ``AppConfig.llm_max_concurrency``: a value ``<= 0``
    disables the gate entirely (returns None) so deployments that don't
    want admission control pay nothing. Config is read exactly once and
    cached — changing the cap requires a sidecar restart, which is the
    same lifecycle as every other startup-time knob.
    """
    global _semaphore, _semaphore_disabled
    if _semaphore is not None or _semaphore_disabled:
        return _semaphore
    with _semaphore_lock:
        if _semaphore is not None or _semaphore_disabled:
            return _semaphore
        # Imported lazily to avoid any import-time cycle with config.
        from ..config import load_config

        try:
            cap = int(load_config().llm_max_concurrency)
        except Exception:  # noqa: BLE001 — never let config wedge an LLM call
            cap = 0
        if cap <= 0:
            _semaphore_disabled = True
            return None
        _semaphore = threading.Semaphore(cap)
        log.info("LLM admission gate enabled (max_concurrency=%d)", cap)
        return _semaphore


@contextlib.contextmanager
def _admit() -> Iterator[None]:
    """Acquire the admission gate for the duration of one LLM call.

    No-op context when capping is disabled, so the call path is identical
    whether or not a cap is configured.
    """
    # Honor any active global 429 cooldown BEFORE taking a semaphore slot —
    # waiting here (not while holding a slot) keeps the concurrency cap
    # meaningful and pauses the whole fleet on the server's backpressure.
    # Runs on both the gated and disabled paths so the cooldown holds even
    # when admission control is off.
    _await_cooldown()
    sem = _get_semaphore()
    if sem is None:
        yield
        return
    sem.acquire()
    try:
        yield
    finally:
        sem.release()


def _rate_limit_exception_types() -> tuple[type[BaseException], ...]:
    """Collect provider-specific RateLimitError classes, skipping unavailable SDKs.

    Built lazily (not at import time) so a deployment that uses only
    Anthropic doesn't blow up when ``openai`` is missing, and vice
    versa. The tuple is what we pass to ``except`` — empty tuple means
    we have nothing to catch and the retry layer becomes a no-op.
    """
    types: list[type[BaseException]] = []
    try:
        from anthropic import RateLimitError as AnthropicRateLimitError  # type: ignore[import-not-found]

        types.append(AnthropicRateLimitError)
    except ImportError:
        pass
    try:
        from openai import RateLimitError as OpenAiRateLimitError  # type: ignore[import-not-found]

        types.append(OpenAiRateLimitError)
    except ImportError:
        pass
    return tuple(types)


def _retry_after_seconds(exc: BaseException) -> float | None:
    """Extract a Retry-After hint from a rate-limit exception, if present.

    Both SDKs hang the underlying ``httpx.Response`` off the exception as
    ``exc.response``. Header lookups are case-insensitive on httpx
    Headers but we use ``.get()`` defensively. The header value is either
    an integer count of seconds or an HTTP-date — parse both.

    Returns None if the header is absent or unparseable; the caller
    falls back to exponential backoff in that case.
    """
    response = getattr(exc, "response", None)
    if response is None:
        return None
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    try:
        raw = headers.get("retry-after") or headers.get("Retry-After")
    except Exception:  # noqa: BLE001 — exotic header containers
        return None
    if not raw:
        return None
    raw = str(raw).strip()
    # Integer seconds form (most common).
    try:
        seconds = float(raw)
        if seconds >= 0:
            return seconds
    except ValueError:
        pass
    # HTTP-date form (rare but RFC-compliant).
    try:
        dt = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    now = time.time()
    delta = dt.timestamp() - now
    return max(delta, 0.0)


def _compute_sleep(attempt_index: int, exc: BaseException) -> float:
    """Pick sleep duration: server hint first, exponential backoff fallback."""
    hint = _retry_after_seconds(exc)
    if hint is not None:
        return min(hint, MAX_SINGLE_SLEEP_SECONDS)
    base = BASE_DELAY_SECONDS * (2**attempt_index)
    jitter = random.uniform(0.0, JITTER_SECONDS)
    return min(base + jitter, MAX_SINGLE_SLEEP_SECONDS)


def run_with_rate_limit_retry(
    callable_: Callable[[], T],
    *,
    label: str = "llm-call",
    max_attempts: int = MAX_ATTEMPTS,
) -> T:
    """Invoke ``callable_`` with bounded 429 retry.

    ``label`` is used in the warning log line so the operator can see
    which call site (``assess`` vs. ``judge`` vs. ``sweep``) is getting
    throttled. Passing the same label across providers is intentional —
    the rate limit is a property of the *endpoint*, not the provider.
    """
    exc_types = _rate_limit_exception_types()
    if not exc_types:
        # No SDKs installed that expose RateLimitError — caller-only
        # exception model. Still gate on the admission semaphore so the
        # concurrency cap holds regardless of which SDKs are present.
        with _admit():
            return callable_()

    last_exc: BaseException | None = None
    for attempt in range(max_attempts):
        # Admission gate + proactive stagger wrap each *attempt*: a retry
        # after a 429 re-acquires the gate and re-jitters, so retried calls
        # don't pile back onto the endpoint in lockstep either. The reactive
        # backoff sleep below already happened outside the gate (we don't
        # hold a slot while sleeping out a 429), keeping the cap meaningful.
        try:
            with _admit():
                if PRECALL_JITTER_SECONDS > 0:
                    time.sleep(random.uniform(0.0, PRECALL_JITTER_SECONDS))
                return callable_()
        except exc_types as exc:
            last_exc = exc
            remaining = max_attempts - attempt - 1
            if remaining <= 0:
                log.warning(
                    "%s: rate-limit after %d attempts; giving up",
                    label,
                    max_attempts,
                )
                raise
            sleep_for = _compute_sleep(attempt, exc)
            # Publish the delay globally so sibling workers (and new
            # dispatches) hold too — one thread's 429 pauses the whole fleet
            # once, instead of each worker independently discovering the wall
            # and re-tripping it (thundering herd). This thread still sleeps
            # the same duration below; _await_cooldown() in _admit() makes the
            # others wait. Cheap no-op once the deadline passes.
            _publish_cooldown(sleep_for)
            log.warning(
                "%s: rate-limit (attempt %d/%d); sleeping %.1fs before retry",
                label,
                attempt + 1,
                max_attempts,
                sleep_for,
            )
            time.sleep(sleep_for)
    # Unreachable — the loop either returns or raises.
    assert last_exc is not None
    raise last_exc
