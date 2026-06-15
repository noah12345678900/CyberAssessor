"""Tests for ``narrative_embeddings`` — Tier-3 of CRM suspicion scoring.

What we pin:

1. **TfidfFallbackProvider works without an API key.** This is the
   universal floor — sklearn is a runtime dep, so ``score_narrative_quality``
   can always score *something* without network access. The pilot
   deployment runs in a SCIF where outbound HTTPS to the OpenAI API is
   blocked; the TF-IDF path is the only one available there.

2. **Provider Protocol conformance.** Every provider exposes
   ``provider_name``, ``model_name`` (both strings) and a callable
   ``embed(texts) -> list[list[float]]``. ``embed([])`` returns ``[]``
   without invoking any backend (matters for OpenAI billing — empty
   batches must not round-trip).

3. **Substantive > filler ranking.** This is the load-bearing accuracy
   contract: narratives that look like real implementation detail score
   strictly higher than narratives that mimic the canned filler corpus.
   Without this, the tier provides no signal.

4. **Empty / whitespace narratives → 0.0.** Filler-equivalent by
   definition. Must NOT crash, must NOT divide by zero, and must NOT
   surface as "high quality" just because the cosine math degenerates.

5. **NarrativeQualityResult shape + metadata.** ``scores`` is a tuple
   parallel to the input list; ``provider_name`` / ``model_name`` /
   ``filler_version`` are populated so the route handler can record
   which backend serviced the call (the suspicion log's audit trail).

6. **Misbehaving provider safety.** If a provider returns a vector list
   of wrong length, we fall back to all-zero scores instead of crashing
   the request. Defensive against a swap-in third-party provider that
   silently drops embeddings.

7. **``resolve_provider`` resolution paths.** ``prefer="tfidf"`` always
   succeeds; ``prefer="openai"`` without a key raises ``RuntimeError``
   so callers can fall back deliberately; auto (no ``prefer``) falls
   back silently to TF-IDF when OpenAI isn't available.

sklearn is required (TF-IDF backend); module-level ``importorskip``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

pytest.importorskip("sklearn", reason="TfidfFallbackProvider needs scikit-learn")

from cybersecurity_assessor.engine.narrative_embeddings import (  # noqa: E402
    _FILLER_CORPUS,
    _FILLER_VERSION,
    NarrativeQualityResult,
    OpenAIEmbeddingsProvider,
    TfidfFallbackProvider,
    resolve_provider,
    score_narrative_quality,
)


# ---------------------------------------------------------------------------
# TfidfFallbackProvider — Protocol conformance
# ---------------------------------------------------------------------------


def test_tfidf_provider_exposes_protocol_attributes():
    """provider_name / model_name are non-empty strings; model_name embeds
    the filler version so cache rows from different filler vintages don't
    collide (CrmNarrativeEmbedding keys on (sha256, provider, model_name)).
    """
    p = TfidfFallbackProvider()
    assert p.provider_name == "tfidf"
    assert isinstance(p.model_name, str)
    assert p.model_name.endswith(_FILLER_VERSION)


def test_tfidf_embed_empty_list_returns_empty_list_without_fitting():
    """Empty input → no work, no crash. Required for cold-start where the
    CRM has no claim narratives yet.
    """
    p = TfidfFallbackProvider()
    assert p.embed([]) == []


def test_tfidf_embed_returns_one_vector_per_input_text():
    """Five inputs → five vectors of equal length. The dimensionality is
    not pinned (depends on the corpus + filler vocabulary), but the
    parallel-list contract is what the centroid math depends on.
    """
    p = TfidfFallbackProvider()
    texts = [
        "Customer enforces 14-character passwords via Active Directory GPO.",
        "Multi-factor authentication via FIDO2 hardware tokens.",
        "Baseline images signed with cosign and verified at boot.",
        "Audit log forwarding to Splunk via the syslog agent.",
        "Vulnerability scans run weekly via Tenable agents.",
    ]
    vecs = p.embed(texts)
    assert len(vecs) == len(texts)
    dims = {len(v) for v in vecs}
    assert len(dims) == 1, "all vectors must share dimensionality"
    # All non-empty (each text contributes at least one token to the vocab).
    assert all(any(x != 0.0 for x in v) for v in vecs)


# ---------------------------------------------------------------------------
# score_narrative_quality — substantive vs filler ranking
# ---------------------------------------------------------------------------


def test_substantive_narratives_score_higher_than_filler_lookalikes():
    """The load-bearing accuracy assertion. Substantive narratives sit
    far from the filler centroid; filler-lookalike narratives sit close.

    We use the TF-IDF provider because it ships with the runtime — no
    API or model download required during CI.
    """
    provider = TfidfFallbackProvider()
    narratives = [
        # Substantive: domain-specific vocabulary, no filler tokens.
        "Customer enforces 14-character passwords via Active Directory GPO "
        "AcctSec-PWLen-14 applied to OU=Workstations and audited monthly.",
        "Multi-factor authentication is enforced via FIDO2 hardware tokens "
        "registered during onboarding and revoked through HR offboarding.",
        # Filler lookalikes: phrases drawn from the canon vague-CRM set.
        "The customer is responsible.",
        "Inherited from the provider. See SSP.",
    ]
    result = score_narrative_quality(narratives, provider)
    s_substantive_1, s_substantive_2, s_filler_1, s_filler_2 = result.scores

    # All in [0, 1].
    for s in result.scores:
        assert 0.0 <= s <= 1.0
    # Both substantive narratives outrank both filler ones.
    assert s_substantive_1 > s_filler_1
    assert s_substantive_1 > s_filler_2
    assert s_substantive_2 > s_filler_1
    assert s_substantive_2 > s_filler_2


def test_empty_narrative_scores_zero():
    """Empty string → 0.0 by definition (filler-equivalent), not NaN."""
    provider = TfidfFallbackProvider()
    result = score_narrative_quality(["", "Real substantive content."], provider)
    assert result.scores[0] == 0.0
    # The substantive one is non-zero (real text far from filler centroid).
    assert result.scores[1] > 0.0


def test_whitespace_only_narrative_scores_zero():
    """``"   \\n\\t"`` is filler-equivalent — stripping happens in the
    scorer, not the provider.
    """
    provider = TfidfFallbackProvider()
    result = score_narrative_quality(["   \n\t  ", "Real content here."], provider)
    assert result.scores[0] == 0.0
    assert result.scores[1] > 0.0


def test_none_narrative_treated_as_empty_string():
    """``None`` in the list must not crash (the route handler may pass
    raw CRM narratives which can be None for customer-owned rows).
    """
    provider = TfidfFallbackProvider()
    result = score_narrative_quality([None, "Substantive."], provider)  # type: ignore[list-item]
    assert result.scores[0] == 0.0
    assert result.scores[1] > 0.0


def test_score_narrative_quality_with_empty_input_returns_empty_result():
    """No narratives → empty scores tuple, no provider call. Avoids
    paying OpenAI's per-request overhead for a cold-start CRM.
    """
    provider = TfidfFallbackProvider()
    result = score_narrative_quality([], provider)
    assert result.scores == ()
    assert result.provider_name == "tfidf"
    assert result.model_name == provider.model_name


# ---------------------------------------------------------------------------
# NarrativeQualityResult shape
# ---------------------------------------------------------------------------


def test_result_carries_provider_and_filler_metadata():
    """Pins the audit-trail contract: every result is self-describing
    so the suspicion log can record which backend produced the scores.
    """
    provider = TfidfFallbackProvider()
    result = score_narrative_quality(["Substantive narrative."], provider)
    assert isinstance(result, NarrativeQualityResult)
    assert isinstance(result.scores, tuple)
    assert result.provider_name == "tfidf"
    assert result.model_name == provider.model_name
    assert result.filler_version == _FILLER_VERSION


def test_result_scores_is_parallel_to_input_list():
    """``scores[i]`` corresponds to ``narratives[i]`` — pinned because
    the route handler maps scores back to control_ids by index.
    """
    provider = TfidfFallbackProvider()
    inputs = [
        "First narrative — long and substantive about credential rotation.",
        "",
        "Third narrative — also substantive, about backup restore drills.",
        "N/A.",
    ]
    result = score_narrative_quality(inputs, provider)
    assert len(result.scores) == len(inputs)
    # Empties at indexes 1 and 3 are 0.0; 0 and 2 are positive.
    assert result.scores[1] == 0.0
    assert result.scores[3] >= 0.0  # filler-lookalike, may be 0 or small
    assert result.scores[0] > 0.0
    assert result.scores[2] > 0.0


# ---------------------------------------------------------------------------
# Misbehaving provider safety
# ---------------------------------------------------------------------------


class _BrokenProvider:
    """Returns wrong-length vector lists — simulates a buggy third-party
    provider drop-in. The scorer must NOT crash; must produce all-zero
    scores so the blend formula in crm_sanity stays unit-bounded.
    """

    @property
    def provider_name(self) -> str:
        return "broken"

    @property
    def model_name(self) -> str:
        return "broken-v0"

    def embed(self, texts: list[str]) -> list[list[float]]:
        # Always return one fewer vector than asked for.
        return [[1.0, 0.0, 0.0] for _ in texts[:-1]]


def test_misbehaving_provider_falls_back_to_zero_scores_without_crashing():
    """If embed() returns wrong number of vectors → all-zero scores."""
    result = score_narrative_quality(["a", "b", "c"], _BrokenProvider())
    assert result.scores == (0.0, 0.0, 0.0)
    assert result.provider_name == "broken"


# ---------------------------------------------------------------------------
# resolve_provider
# ---------------------------------------------------------------------------


def test_resolve_provider_tfidf_always_succeeds():
    """Universal floor — no API, no model download."""
    p = resolve_provider(prefer="tfidf")
    assert p.provider_name == "tfidf"


def test_resolve_provider_openai_without_key_raises(monkeypatch):
    """Explicit prefer="openai" with no key → RuntimeError, so callers
    can decide whether to fall back or surface the failure.
    """
    # Force the config resolver to look like a no-key environment.
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    from cybersecurity_assessor import config as _cfg

    monkeypatch.setattr(_cfg, "resolve_openai_endpoint", lambda: (None, None))
    with pytest.raises(RuntimeError, match="OpenAI API key"):
        resolve_provider(prefer="openai")


def test_resolve_provider_auto_falls_back_to_tfidf_when_openai_unavailable(monkeypatch):
    """Auto path: try OpenAI silently → on RuntimeError, return TF-IDF.

    The "silently" part matters — auto callers (the route handler) don't
    want to see a stack trace for a perfectly normal "no key configured"
    deployment.
    """
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    from cybersecurity_assessor import config as _cfg

    monkeypatch.setattr(_cfg, "resolve_openai_endpoint", lambda: (None, None))
    p = resolve_provider()
    assert p.provider_name == "tfidf"


# ---------------------------------------------------------------------------
# OpenAI provider — injection-only test (no live API)
# ---------------------------------------------------------------------------


class _FakeOpenAISDK:
    """Stand-in for the openai SDK's client surface that the provider
    actually touches: ``client.embeddings.create(model=..., input=...)``.
    """

    class _Embeddings:
        def __init__(self, vectors_for_text: dict[str, list[float]]):
            self._vectors_for_text = vectors_for_text
            self.calls: list[dict] = []

        def create(self, *, model: str, input: list[str]):  # noqa: A002
            self.calls.append({"model": model, "input": list(input)})

            class _Item:
                def __init__(self, embedding: list[float]) -> None:
                    self.embedding = embedding

            class _Response:
                def __init__(self, items: list[_Item]) -> None:
                    self.data = items

            return _Response(
                [_Item(self._vectors_for_text.get(t, [0.0, 0.0, 0.0])) for t in input]
            )

    def __init__(self, vectors_for_text: dict[str, list[float]]) -> None:
        self.embeddings = self._Embeddings(vectors_for_text)


def test_openai_provider_uses_injected_client_and_batches_in_one_call():
    """Pin the batching contract: one ``embed`` call → one underlying
    SDK call. Critical for OpenAI billing — we should NOT issue one
    request per narrative.
    """
    vectors = {f"text-{i}": [float(i), 0.0, 0.0] for i in range(5)}
    fake = _FakeOpenAISDK(vectors)
    provider = OpenAIEmbeddingsProvider(_sdk_client=fake)

    out = provider.embed([f"text-{i}" for i in range(5)])
    assert len(out) == 5
    assert out[0] == [0.0, 0.0, 0.0]
    assert out[4] == [4.0, 0.0, 0.0]
    # Exactly one batched call.
    assert len(fake.embeddings.calls) == 1
    assert fake.embeddings.calls[0]["input"] == [f"text-{i}" for i in range(5)]


def test_openai_provider_embed_empty_list_does_not_call_sdk():
    """Empty input must short-circuit before any HTTP call — empty
    OpenAI requests are billable + counted against rate limits.
    """
    fake = _FakeOpenAISDK({})
    provider = OpenAIEmbeddingsProvider(_sdk_client=fake)
    assert provider.embed([]) == []
    assert fake.embeddings.calls == []


def test_openai_provider_reports_provider_and_model_name():
    """Metadata used by the suspicion log to track which embedding
    model was active when the score was computed.
    """
    fake = _FakeOpenAISDK({})
    provider = OpenAIEmbeddingsProvider(_sdk_client=fake, model="text-embedding-3-large")
    assert provider.provider_name == "openai"
    assert provider.model_name == "text-embedding-3-large"


# ---------------------------------------------------------------------------
# Filler corpus invariant
# ---------------------------------------------------------------------------


def test_filler_corpus_is_non_empty_and_unique():
    """The filler centroid is the load-bearing reference. If someone
    accidentally empties or deduplicates it to nothing, every score
    collapses to 0.0 silently — pin this contract so that bug trips here.
    """
    assert len(_FILLER_CORPUS) > 0
    # No duplicates (would skew the centroid toward the duplicated phrase).
    assert len(set(_FILLER_CORPUS)) == len(_FILLER_CORPUS)
