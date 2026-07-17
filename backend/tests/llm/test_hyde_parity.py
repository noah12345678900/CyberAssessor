"""HyDE query-expansion parity across providers + chunked-embed resilience.

Regression guard for the tagger recall bug that caused false Non-Compliant
verdicts on the OpenAI provider:

* OpenAIClient had NO ``expand_to_control_prose`` method, so on OpenAI the
  tagger's ``getattr(client, "expand_to_control_prose")`` returned None and
  HyDE silently no-opped — killing 2 of 5 candidate lanes (hyde-cosine +
  triage). Claude (which HAS the method) tagged all controls; OpenAI dropped
  some -> false NC. These tests pin that BOTH clients expose HyDE.
* Multi-sample HyDE unions N scaffolds to average out gpt-5.x nondeterminism,
  but Claude runs at temp 0 (deterministic) so its ``_multi`` must delegate to
  a SINGLE call — no 3x cost regression on the already-working Claude path.
* The embeddings provider chunks large inputs so the control catalog can't
  time out and permanently disable the dense lane.
"""

from __future__ import annotations

import pytest

from cybersecurity_assessor.llm.client import (
    _HYDE_SCAFFOLDS,
    AnthropicClient,
    OpenAIClient,
)


# --- Fake OpenAI SDK (mirrors tests/llm/test_openai_vision.py) --------------


class _FakeMessage:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeChoice:
    def __init__(self, content: str) -> None:
        self.message = _FakeMessage(content)


class _FakeResponse:
    def __init__(self, content: str) -> None:
        self.choices = [_FakeChoice(content)]
        self.id = "chatcmpl-test"
        self.model = "gpt-test"
        self.usage = None


class _FakeCompletions:
    def __init__(self, content: str = "AU-2 event logging control language") -> None:
        self._content = content
        self.calls: list[dict] = []

    def create(self, **kwargs):  # noqa: ANN003, ANN201
        self.calls.append(kwargs)
        return _FakeResponse(self._content)


class _FakeChat:
    def __init__(self, completions: _FakeCompletions) -> None:
        self.completions = completions


class _FakeSDK:
    def __init__(self, completions: _FakeCompletions) -> None:
        self.chat = _FakeChat(completions)


def _openai(completions: _FakeCompletions) -> OpenAIClient:
    return OpenAIClient(model="gpt-test", _sdk_client=_FakeSDK(completions))


# --- Provider parity: BOTH clients expose HyDE ------------------------------


def test_both_clients_expose_hyde_methods() -> None:
    # The root-cause regression: OpenAIClient was missing these entirely.
    for cls in (AnthropicClient, OpenAIClient):
        assert hasattr(cls, "expand_to_control_prose"), cls.__name__
        assert hasattr(cls, "expand_to_control_prose_multi"), cls.__name__


def test_openai_hyde_single_calls_model_and_returns_prose() -> None:
    comp = _FakeCompletions(content="Demonstrates AU-2 auditable events.")
    client = _openai(comp)
    out = client.expand_to_control_prose("sestatus -> enforcing")
    assert "AU-2" in out
    assert len(comp.calls) == 1
    # Went through the funnel: max_tokens translated to max_completion_tokens.
    kw = comp.calls[0]
    assert "max_completion_tokens" in kw and "max_tokens" not in kw


def test_openai_hyde_multi_runs_all_scaffolds_and_unions() -> None:
    comp = _FakeCompletions(content="AU-6 audit review language")
    client = _openai(comp)
    out = client.expand_to_control_prose_multi("some evidence")
    # One call per scaffold (concurrent, but all land in .calls).
    assert len(comp.calls) == len(_HYDE_SCAFFOLDS)
    # Union of the (identical here) parts -> non-empty prose.
    assert "AU-6" in out
    # Each call used a DIFFERENT scaffold prompt (union of framings).
    prompts = {c["messages"][0]["content"] for c in comp.calls}
    assert len(prompts) == len(_HYDE_SCAFFOLDS)


def test_openai_hyde_degrades_to_empty_on_error() -> None:
    class _Boom(_FakeCompletions):
        def create(self, **kwargs):  # noqa: ANN003, ANN201
            raise RuntimeError("boom")

    client = _openai(_Boom())
    assert client.expand_to_control_prose("x") == ""
    assert client.expand_to_control_prose_multi("x") == ""  # all scaffolds fail


# --- Claude path: no 3x cost regression -------------------------------------


def test_anthropic_multi_delegates_to_single() -> None:
    """Claude is deterministic at temp 0 — multi must NOT fan out to N calls."""
    calls: list[str] = []

    client = AnthropicClient.__new__(AnthropicClient)  # bypass __init__/network

    def _fake_single(evidence_text: str, *, model: str | None = None) -> str:
        calls.append(evidence_text)
        return "AU-2 language"

    client.expand_to_control_prose = _fake_single  # type: ignore[method-assign]
    out = AnthropicClient.expand_to_control_prose_multi(client, "evidence")
    assert out == "AU-2 language"
    assert len(calls) == 1  # exactly ONE call — no 3x cost on Claude


# --- Chunked embed + fatal-error classification -----------------------------


def test_embed_chunks_large_input_without_partial_return() -> None:
    from cybersecurity_assessor.engine import narrative_embeddings as ne

    class _EmbItem:
        def __init__(self, v): self.embedding = v

    class _EmbResp:
        def __init__(self, n): self.data = [_EmbItem([0.1, 0.2]) for _ in range(n)]

    class _Embeddings:
        def __init__(self): self.batch_sizes = []
        def create(self, *, model, input):  # noqa: A002
            self.batch_sizes.append(len(input))
            return _EmbResp(len(input))

    class _SDK:
        def __init__(self): self.embeddings = _Embeddings()

    sdk = _SDK()
    prov = ne.OpenAIEmbeddingsProvider(_sdk_client=sdk)
    n = ne._EMBED_BATCH_SIZE * 2 + 5  # 3 chunks
    vecs = prov.embed(["x"] * n)
    assert len(vecs) == n
    # Chunked: no single call exceeded the batch size.
    assert max(sdk.embeddings.batch_sizes) <= ne._EMBED_BATCH_SIZE
    assert len(sdk.embeddings.batch_sizes) == 3


def test_is_fatal_embed_error_classification() -> None:
    from cybersecurity_assessor.engine.narrative_embeddings import (
        _is_fatal_embed_error as f,
    )

    class APITimeoutError(Exception): ...
    class RateLimitError(Exception): ...
    class APIConnectionError(Exception): ...

    assert f(APITimeoutError("Request timed out.")) is False  # slow != dead
    assert f(RateLimitError("429 too many")) is False  # throttled != dead
    assert f(APIConnectionError("Connection error.")) is True
    assert f(Exception("Error code: 404 - model not found")) is True
    assert f(Exception("Error code: 500 - internal")) is True
    # A stray HTTP-code-looking substring in prose must NOT read as fatal.
    assert f(Exception("processed 500 audit events")) is False
    assert f(Exception("mystery")) is False  # unknown -> don't poison the lane


def test_embed_timeout_does_not_trip_killswitch() -> None:
    from cybersecurity_assessor.engine import narrative_embeddings as ne

    ne._OPENAI_EMBEDDINGS_DISABLED = False

    class APITimeoutError(Exception): ...

    class _Embeddings:
        def create(self, *, model, input):  # noqa: A002
            raise APITimeoutError("Request timed out.")

    class _SDK:
        def __init__(self): self.embeddings = _Embeddings()

    prov = ne.OpenAIEmbeddingsProvider(_sdk_client=_SDK())
    with pytest.raises(Exception):
        prov.embed(["x"])
    # Timeout is capacity, not liveness — the lane stays enabled.
    assert ne._OPENAI_EMBEDDINGS_DISABLED is False
