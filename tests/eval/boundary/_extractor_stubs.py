"""Stubs for the boundary-doc extraction eval harness.

The boundary-docs adapter (``system_context/boundary_docs.py``) talks to
the LLM through the ``LlmExtractorClient`` Protocol — a tiny one-method
surface:

    extract_system_context(prompt: str) -> {"tokens": [...], "confidence": float}

This module ships a FIFO stub that satisfies that Protocol structurally,
mirroring the kernel-side ``StubLlmClient`` pattern at
``tests/eval/_stubs.py`` so callers can read either harness without
chasing imports across test trees.

The stub records every prompt string into ``.calls`` so a case file can
assert on what was actually sent to the model (e.g. "the SSP section
header survived into the prompt", "the per-doc 40K char cap was
respected"). On queue exhaustion it raises ``AssertionError`` with a
diagnostic rather than returning a placeholder — that surfaces a case
file declaring fewer envelopes than the adapter requested instead of
silently passing.
"""

from __future__ import annotations

from typing import Any

__all__ = ["StubExtractorClient"]


class StubExtractorClient:
    """Returns canned ``{tokens, confidence}`` envelopes in FIFO order.

    Construct with a list of dicts, each shaped like the real LLM's
    parsed JSON envelope::

        StubExtractorClient([
            {"tokens": ["server01", "10.0.0.0/24"], "confidence": 0.85},
            ...
        ])

    Each ``extract_system_context`` call pops one envelope off the front
    and records the incoming prompt into ``self.calls``. The boundary
    adapter typically only calls once per ``apply()`` (one prompt = all
    sections concatenated), so most case files queue exactly one
    envelope — but the FIFO supports multi-call cases without a special
    path.

    Raises ``AssertionError`` on empty-queue rather than ``ValueError``
    so a misconfigured case file fails the test as a *test bug* (visible
    in pytest output) rather than as an adapter degradation
    (``confidence=0.2`` fallthrough in ``boundary_docs.apply``).
    """

    def __init__(self, envelopes: list[dict[str, Any]]) -> None:
        self._queue: list[dict[str, Any]] = list(envelopes)
        self.calls: list[str] = []

    def extract_system_context(self, prompt: str) -> dict[str, Any]:
        self.calls.append(prompt)
        if not self._queue:
            raise AssertionError(
                "StubExtractorClient queue exhausted — case file declared "
                "fewer envelopes than the boundary-docs adapter requested. "
                "Inspect stub.calls to see the prompts that were issued."
            )
        return self._queue.pop(0)
