"""Sibling Protocol to LlmClient — for non-CcisRow LLM calls.

``LlmClient.propose()`` (see engine/assessor.py) is hardcoded to assessment
of a CCI row. SystemContext extraction is a different shape: prompt in,
JSON out. Rather than extending the assessment Protocol (which would force
test stubs to implement an unrelated method), this Protocol is satisfied
structurally by both ``AnthropicClient`` and ``OpenAIClient`` via their
generic completion plumbing — both clients pick up an
``extract_system_context`` method without touching the assessor kernel.
"""

from __future__ import annotations

from typing import Protocol


class LlmExtractorClient(Protocol):
    """Minimal contract for adapters that need free-form LLM extraction.

    The single method takes a prompt that the caller has already formatted
    (with the extraction instructions and the freeform source text) and
    returns the parsed JSON envelope.

    Implementations MUST return a dict with at least these keys:

    * ``tokens`` — list[str], short normalized identifiers
    * ``confidence`` — float 0.0..1.0, the model's self-estimate of how
      concrete the source text was

    Raises ``ValueError`` (or subclass) on malformed JSON. The
    ``FreeformContextSource`` adapter catches and degrades gracefully:
    the SystemContext row is still saved (text inputs are not lost),
    confidence drops to 0.2, and a note is added.
    """

    def extract_system_context(self, prompt: str) -> dict:  # pragma: no cover - Protocol
        ...
