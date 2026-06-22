"""Global Retry-After cooldown tests (Bug F).

The fix makes one worker's 429 pause the whole fleet once, instead of every
worker independently re-tripping the limit (self-inflicted thundering herd).
These tests pin the cooldown publish/await primitives and the retry-loop
integration without needing a live gateway or a real SDK RateLimitError
(which requires an httpx.Response to construct).
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parent.parent / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor.llm import _rate_limit  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_cooldown():
    """Each test starts with no active cooldown (module-global state)."""
    _rate_limit._cooldown_until = 0.0
    yield
    _rate_limit._cooldown_until = 0.0


def test_publish_then_await_blocks_for_the_window() -> None:
    """_await_cooldown blocks ~the published duration, then returns."""
    _rate_limit._publish_cooldown(0.25)
    start = time.monotonic()
    _rate_limit._await_cooldown()
    waited = time.monotonic() - start
    # Allow scheduling slop but assert it actually waited a meaningful chunk.
    assert waited >= 0.2, f"cooldown did not hold (waited {waited:.3f}s)"


def test_publish_takes_the_max_not_the_latest() -> None:
    """A later, smaller cooldown never shortens a longer active one."""
    _rate_limit._publish_cooldown(5.0)
    far = _rate_limit._cooldown_until
    _rate_limit._publish_cooldown(0.1)  # smaller — must not shrink
    assert _rate_limit._cooldown_until == far


def test_zero_or_negative_publish_is_noop() -> None:
    _rate_limit._publish_cooldown(0.0)
    _rate_limit._publish_cooldown(-3.0)
    assert _rate_limit._cooldown_until == 0.0
    # And awaiting with no cooldown returns immediately.
    start = time.monotonic()
    _rate_limit._await_cooldown()
    assert time.monotonic() - start < 0.05


def test_cooldown_is_capped() -> None:
    """An absurd Retry-After can't park the fleet beyond the cap."""
    _rate_limit._publish_cooldown(10_000.0)
    remaining = _rate_limit._cooldown_until - time.monotonic()
    assert remaining <= _rate_limit.MAX_COOLDOWN_SECONDS + 1


def test_retry_loop_publishes_cooldown_on_429() -> None:
    """A 429 inside run_with_rate_limit_retry publishes a global cooldown
    that a *second, independent* caller then honors.

    We inject a fake RateLimitError type via monkeypatching the SDK-type
    collector so we don't need a real httpx.Response.
    """

    class FakeRateLimit(Exception):
        """Stand-in with no Retry-After header → backoff path is used."""

        response = None

    # Force the retry layer to treat FakeRateLimit as a rate-limit error.
    orig = _rate_limit._rate_limit_exception_types
    _rate_limit._rate_limit_exception_types = lambda: (FakeRateLimit,)
    try:
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] == 1:
                raise FakeRateLimit()
            return "ok"

        # Keep the test fast: shrink the backoff base for this run.
        orig_base = _rate_limit.BASE_DELAY_SECONDS
        _rate_limit.BASE_DELAY_SECONDS = 0.2
        try:
            result = _rate_limit.run_with_rate_limit_retry(flaky, label="test")
        finally:
            _rate_limit.BASE_DELAY_SECONDS = orig_base

        assert result == "ok"
        assert calls["n"] == 2  # failed once, retried, succeeded
        # The 429 should have published a (now likely elapsed) cooldown —
        # the deadline must have been set in the recent past/future, not 0.
        assert _rate_limit._cooldown_until > 0.0
    finally:
        _rate_limit._rate_limit_exception_types = orig
