"""Per-narrative substantiveness scoring via text embeddings.

Powers the third tier of CRM suspicion scoring (see ``crm_sanity``):
distance from a fixed "vague filler" centroid is interpreted as
narrative quality. A real customer narrative like

    "Customer enforces 14-character passwords via Active Directory GPO
    `AcctSec-PWLen-14` applied to OU=Workstations; audited monthly."

sits far from filler like "The customer is responsible." or "See SSP."
Boilerplate-laden CRMs cluster near the filler centroid; substantive
CRMs sit far from it.

Three providers implement the ``EmbeddingsProvider`` Protocol:

* :class:`OpenAIEmbeddingsProvider` — production path. Reuses the
  configured OpenAI key (the same one the assessor's LLM may already
  use). text-embedding-3-small is the cheapest dense option at
  ~$0.00002/narrative — a 500-control CRM costs $0.01 per recompute,
  which the suspicion-log cache further amortizes (one embedding per
  unique narrative across all CRMs the user ever uploads).
* :class:`SentenceTransformersProvider` — opt-in offline fallback. Only
  imported when explicitly requested so users without the
  ``[offline-embeddings]`` extra installed never pay the import cost.
* :class:`TfidfFallbackProvider` — no-API last resort. Fits a TF-IDF
  vectorizer on (narratives ∪ filler corpus) and uses cosine distance.
  Pure-sklearn, ships with the runtime.

The factory :func:`resolve_provider` picks the highest-fidelity
implementation that can actually run in the current environment, so
callers can stay agnostic about which backend serviced them.

``score_narrative_quality`` is the only function callers need: pass a
list of narratives + a provider, get back per-narrative scores in
``[0, 1]`` where 1.0 = maximally substantive (far from filler centroid).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol


# ---------------------------------------------------------------------------
# Filler corpus — the empirical "what does vague boilerplate look like"
# reference set. Held fixed across versions so historical
# CrmNarrativeEmbedding cache rows stay comparable.
#
# Sourced from: actual hand-reviewed vendor CRMs in the assessor's pilot
# corpus (Example System, two SaaS vendors, one CSP). When adding entries, also
# bump _FILLER_VERSION so the cache key in CrmNarrativeEmbedding can
# distinguish old centroid rows from new ones.
# ---------------------------------------------------------------------------

_FILLER_VERSION = "v1"

_FILLER_CORPUS: tuple[str, ...] = (
    "The customer is responsible.",
    "See SSP.",
    "See system security plan.",
    "Inherited from the provider.",
    "Not applicable.",
    "N/A.",
    "Customer responsibility.",
    "Provider responsibility.",
    "Refer to the System Security Plan.",
    "This control is inherited.",
    "Customer must implement.",
    "Implemented by the customer.",
    "See documentation.",
    "Refer to vendor documentation.",
    "Standard practice.",
    "Compliant with policy.",
    "Per company policy.",
)


# ---------------------------------------------------------------------------
# Provider Protocol
# ---------------------------------------------------------------------------


class EmbeddingsProvider(Protocol):
    """Embed a batch of texts into fixed-length dense vectors.

    Implementations MUST be deterministic for a given input list — the
    cache key in :class:`CrmNarrativeEmbedding` is sha256 of the text
    alone, not (text, model_version). Bumping a provider's model_name
    invalidates the cache implicitly by virtue of the route handler
    keying lookups by ``(narrative_sha256, provider, model_name)``.
    """

    @property
    def provider_name(self) -> str:  # "openai" | "sentence_transformers" | "tfidf"
        ...

    @property
    def model_name(self) -> str:
        ...

    def embed(self, texts: list[str]) -> list[list[float]]: ...


# ---------------------------------------------------------------------------
# OpenAI provider
# ---------------------------------------------------------------------------


class OpenAIEmbeddingsProvider:
    """Wraps the OpenAI Embeddings API (text-embedding-3-small by default).

    Uses the existing ``llm.client._resolve_api_key``-style resolution
    via the AppConfig so users don't have to manage a second key. If the
    sidecar's primary LLM is Anthropic, this still works — embeddings
    don't share the LLM provider knob; they only need an OpenAI key
    (Anthropic doesn't currently offer a public embeddings endpoint).
    """

    DEFAULT_MODEL = "text-embedding-3-small"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        _sdk_client: Any | None = None,
    ) -> None:
        self._model = model
        if _sdk_client is not None:
            self._client = _sdk_client
            return
        # Resolve via the same config plumbing OpenAIClient uses for chat.
        from .. import config as _cfg

        base_url, resolved_key = _cfg.resolve_openai_endpoint()
        resolved_key = api_key or resolved_key
        if not resolved_key:
            raise RuntimeError(
                "OpenAIEmbeddingsProvider requires an OpenAI API key. Set "
                "OPENAI_API_KEY or save one via Settings."
            )
        try:
            from openai import OpenAI  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - install-time error
            raise RuntimeError(
                "`openai` SDK is not installed. Add it to backend/pyproject.toml."
            ) from exc
        self._client = OpenAI(api_key=resolved_key, base_url=base_url)

    @property
    def provider_name(self) -> str:
        return "openai"

    @property
    def model_name(self) -> str:
        return self._model

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        # OpenAI embeddings API: batched is much cheaper than per-text calls.
        # 2048-item batch is the documented limit; we don't expect to exceed it
        # in a single CRM (largest control catalogs run ~400 controls).
        response = self._client.embeddings.create(model=self._model, input=texts)
        return [list(item.embedding) for item in response.data]


# ---------------------------------------------------------------------------
# Sentence-transformers provider (opt-in offline)
# ---------------------------------------------------------------------------


class SentenceTransformersProvider:
    """Local offline embeddings via the ``sentence-transformers`` extra.

    Lazy-imports the library so users without the ``[offline-embeddings]``
    install never pay the ~80MB import. The default ``all-MiniLM-L6-v2``
    model is 80MB on first use (downloaded to the HuggingFace cache).
    Quality is well below text-embedding-3-small but acceptable for
    relative ordering — and it's free and works without internet, which
    matters on disconnected SCIF deployments.
    """

    DEFAULT_MODEL = "all-MiniLM-L6-v2"

    def __init__(self, *, model: str = DEFAULT_MODEL) -> None:
        self._model_name = model
        try:
            from sentence_transformers import (  # type: ignore[import-not-found]
                SentenceTransformer,
            )
        except ImportError as exc:
            raise RuntimeError(
                "`sentence-transformers` is not installed. Install the "
                "`[offline-embeddings]` extra to use this provider."
            ) from exc
        self._model = SentenceTransformer(model)

    @property
    def provider_name(self) -> str:
        return "sentence_transformers"

    @property
    def model_name(self) -> str:
        return self._model_name

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        vectors = self._model.encode(texts, convert_to_numpy=True)
        return [vec.tolist() for vec in vectors]


# ---------------------------------------------------------------------------
# TF-IDF fallback provider — no API, no model download
# ---------------------------------------------------------------------------


class TfidfFallbackProvider:
    """Cheap pseudo-embeddings from a TF-IDF vectorizer.

    Quality is the lowest of the three providers — TF-IDF doesn't know
    "passwords" and "credentials" are related — but it ships with
    scikit-learn (already a runtime dep) and needs nothing else. Acts
    as the universal floor so :func:`score_narrative_quality` never has
    to refuse a call due to missing infrastructure.

    Fits the vectorizer at ``embed`` time on (input texts ∪ filler
    corpus) so we always have a consistent vocabulary at scoring time.
    Pure cosine distance against the filler centroid in the same call.

    **Determinism contract (2026-06-10 reproducibility fix).** All vectors
    returned from one ``embed`` call MUST share a single vocabulary space —
    :func:`score_narrative_quality` averages the filler rows into a centroid and
    cosines every narrative row against it, which is only meaningful if every
    row is fit together (the ``test_tfidf_embed_returns_one_vector_per_input_text``
    pin asserts ``len(dims) == 1``). So a per-text fit is NOT an option here;
    the shared fit is load-bearing, not the bug.

    The fit is, however, already order-invariant: a ``TfidfVectorizer`` sorts
    its vocabulary lexically and derives idf from document frequency, both of
    which are independent of the order documents arrive in. Given the same SET
    of (texts ∪ fixed ``_FILLER_CORPUS``) the matrix is identical run-to-run.
    The one residual drift risk is the *tokenizer*: sklearn's default
    ``token_pattern`` has changed across versions, which would silently
    re-tokenize identical text and shift every vector. We pin ``token_pattern``
    explicitly (below) so an auditor re-running the same CRM on a different
    sklearn build gets byte-identical embeddings and therefore the same
    suspicion score.
    """

    MODEL_NAME = f"tfidf-{_FILLER_VERSION}"

    def __init__(self) -> None:
        # Validate sklearn is importable at construction time so callers
        # fail fast instead of mid-batch.
        try:
            from sklearn.feature_extraction.text import (  # type: ignore[import-not-found]  # noqa: F401
                TfidfVectorizer,
            )
        except ImportError as exc:  # pragma: no cover - sklearn is a runtime dep
            raise RuntimeError(
                "scikit-learn is required for TfidfFallbackProvider. Add it "
                "to backend/pyproject.toml runtime deps."
            ) from exc

    @property
    def provider_name(self) -> str:
        return "tfidf"

    @property
    def model_name(self) -> str:
        return self.MODEL_NAME

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        from sklearn.feature_extraction.text import (  # type: ignore[import-not-found]
            TfidfVectorizer,
        )

        # Fit on (texts + filler) so vocabulary covers everything we'll score.
        # Lowercase + 1-2 ngrams catches both word-level and phrase-level
        # boilerplate ("see ssp" should match "see ssp."). A single shared fit
        # is required: the consumer cosines each narrative against the filler
        # centroid, so all rows must live in one vocabulary space.
        # ``token_pattern`` is pinned to sklearn's historical default so a
        # version bump can't silently re-tokenize and shift vectors run-to-run
        # (2026-06-10 reproducibility fix — see class docstring).
        corpus = list(texts) + list(_FILLER_CORPUS)
        vectorizer = TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            min_df=1,
            max_df=1.0,
            token_pattern=r"(?u)\b\w\w+\b",
        )
        matrix = vectorizer.fit_transform(corpus)
        # Return only the first len(texts) rows as dense lists.
        n = len(texts)
        return [matrix[i].toarray()[0].tolist() for i in range(n)]


# ---------------------------------------------------------------------------
# Public scoring API
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NarrativeQualityResult:
    """Per-narrative substantiveness scores + provider metadata.

    ``scores`` is parallel to the input ``narratives`` list. NaN-safe:
    empty narratives get a score of 0.0 (treated as filler-equivalent).
    """

    scores: tuple[float, ...]
    provider_name: str
    model_name: str
    filler_version: str = _FILLER_VERSION


def _cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity, defensive against zero vectors.

    Returns 0.0 for any vector pair where either side has zero norm —
    empty narratives or unknown-vocab TF-IDF rows safely produce a
    neutral similarity instead of NaN.
    """
    num = sum(x * y for x, y in zip(a, b, strict=False))
    a_norm = sum(x * x for x in a) ** 0.5
    b_norm = sum(y * y for y in b) ** 0.5
    if a_norm == 0.0 or b_norm == 0.0:
        return 0.0
    return num / (a_norm * b_norm)


def _centroid(vectors: list[list[float]]) -> list[float]:
    """Element-wise mean of equal-length vectors."""
    if not vectors:
        return []
    dim = len(vectors[0])
    sums = [0.0] * dim
    for v in vectors:
        for i, x in enumerate(v):
            sums[i] += x
    n = float(len(vectors))
    return [s / n for s in sums]


def score_narrative_quality(
    narratives: Iterable[str],
    provider: EmbeddingsProvider,
) -> NarrativeQualityResult:
    """Return a per-narrative substantiveness score in ``[0, 1]``.

    1.0 = far from the filler centroid (substantive).
    0.0 = identical to a filler centroid sample (vague boilerplate).

    Scoring strategy: embed (narratives ∪ filler corpus) in ONE provider
    call so providers like OpenAI batch-bill us once; compute the filler
    centroid; for each narrative compute ``1 - cosine_sim(narrative,
    centroid)`` and clip to ``[0, 1]``.

    Why ``1 - cosine`` and not absolute distance: cosine is the natural
    similarity for dense embeddings (TF-IDF, sentence-transformers,
    OpenAI all use it as their canonical metric), and the symmetric
    interpretation "0 = filler-like, 1 = orthogonal-to-filler" makes the
    score directly composable with the heuristic and ML-anomaly scores
    in :mod:`crm_sanity` (which both also live in ``[0, 1]``).
    """
    narrative_list = [str(n) if n is not None else "" for n in narratives]
    if not narrative_list:
        return NarrativeQualityResult(
            scores=(),
            provider_name=provider.provider_name,
            model_name=provider.model_name,
        )

    # Embed in one shot. Filler corpus is appended so we get the centroid in
    # the same batch — saves a second API round-trip on OpenAI.
    combined = narrative_list + list(_FILLER_CORPUS)
    vectors = provider.embed(combined)
    if len(vectors) != len(combined):
        # Provider misbehaved; fall back to all-zero scores rather than crash.
        return NarrativeQualityResult(
            scores=tuple(0.0 for _ in narrative_list),
            provider_name=provider.provider_name,
            model_name=provider.model_name,
        )

    n = len(narrative_list)
    narrative_vecs = vectors[:n]
    filler_vecs = vectors[n:]
    centroid = _centroid(filler_vecs)

    scores: list[float] = []
    for text, vec in zip(narrative_list, narrative_vecs, strict=True):
        if not text.strip():
            # Empty narrative is filler-equivalent by definition.
            scores.append(0.0)
            continue
        sim = _cosine(vec, centroid)
        quality = 1.0 - sim
        # Clip — cosine can dip slightly negative for orthogonal sparse vecs.
        if quality < 0.0:
            quality = 0.0
        elif quality > 1.0:
            quality = 1.0
        scores.append(quality)

    return NarrativeQualityResult(
        scores=tuple(scores),
        provider_name=provider.provider_name,
        model_name=provider.model_name,
    )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def resolve_provider(
    *,
    prefer: str | None = None,
) -> EmbeddingsProvider:
    """Return the best available provider for the current environment.

    Resolution order (best → worst):

    1. ``prefer="openai"`` and a key is available → OpenAI.
    2. ``prefer="sentence_transformers"`` and the extra is installed →
       local model.
    3. ``prefer="tfidf"`` always succeeds (sklearn is a runtime dep).
    4. ``prefer=None`` (auto): OpenAI if a key is available, else TF-IDF.
       Sentence-transformers is opt-in only — never auto-picked because
       the first call triggers an 80MB model download we shouldn't do
       silently.

    Raises ``RuntimeError`` only when an explicit ``prefer=`` request
    can't be satisfied (so callers can fall back deliberately).
    """
    if prefer == "openai":
        return OpenAIEmbeddingsProvider()
    if prefer == "sentence_transformers":
        return SentenceTransformersProvider()
    if prefer == "tfidf":
        return TfidfFallbackProvider()
    # Auto path: try OpenAI silently, fall back to TF-IDF on any failure.
    try:
        return OpenAIEmbeddingsProvider()
    except Exception:
        return TfidfFallbackProvider()
