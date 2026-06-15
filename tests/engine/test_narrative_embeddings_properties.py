"""Property-based tests for narrative_embeddings (Tier-3 CRM suspicion).

The example-driven suite in ``backend/tests/engine/test_narrative_embeddings.py``
pins concrete substantive-vs-filler ranking, empty-input handling, and
provider Protocol conformance. This file fuzzes the pure math primitives
and the score-range contract so a refactor that breaks an invariant in a
corner of the (text × provider × vector) input space gets caught:

  1. **Score range.** ``score_narrative_quality`` MUST return scores in
     ``[0, 1]`` for any narrative input + any conforming provider.
     The clip line at the end of the function is the load-bearing
     defense; a regression that dropped the clip would let cosine's
     small negative excursions on orthogonal sparse vectors surface as
     "quality < 0" — which would crash the downstream blend in
     ``crm_sanity`` that assumes unit-bounded inputs.

  2. **Parallel-list contract.** ``len(result.scores) == len(narratives)``
     for every call. The route handler maps scores back to control_ids
     by index; a refactor that silently dropped or duplicated an entry
     would mis-attribute the suspicion score to the wrong control.

  3. **_cosine pure-function properties.** Symmetry, identity on
     non-zero vectors, zero-vector defense, bounded in [-1, 1].
     Defends against an "optimization" that swapped to an unnormalized
     dot product or removed the zero-norm guard.

  4. **_centroid pure-function properties.** Element-wise mean is
     equivariant to row order; empty input → empty output; single-vector
     centroid equals that vector; output dimensionality matches input.

  5. **Whitespace/None robustness.** Arbitrary whitespace-only strings
     and ``None`` entries MUST score 0.0 — the "no information"
     contract. A regression where None crashed before the strip-check
     would tank an entire CRM batch on the first customer-owned row.

  6. **Provider determinism.** Same input → same scores under the
     TF-IDF provider. The cache key in CrmNarrativeEmbedding assumes
     deterministic outputs; a non-deterministic provider would silently
     re-embed identical text on every recompute.

  7. **Misbehaving-provider safety.** A provider that returns the wrong
     number of vectors MUST yield all-zero scores without crashing —
     the patent-supporting "no narrative left unscored" claim depends
     on this universal floor.

The TF-IDF provider is the universal floor (sklearn is a runtime dep)
so these tests run in any environment.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Mirror the path setup the example test file uses so we can import
# the module under test when pytest is invoked from the repo root.
_BACKEND = Path(__file__).resolve().parents[2] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

hypothesis = pytest.importorskip("hypothesis")
pytest.importorskip("sklearn", reason="TfidfFallbackProvider needs scikit-learn")

from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from cybersecurity_assessor.engine.narrative_embeddings import (  # noqa: E402
    _FILLER_CORPUS,
    _FILLER_VERSION,
    NarrativeQualityResult,
    TfidfFallbackProvider,
    _centroid,
    _cosine,
    score_narrative_quality,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


# Vectors used to exercise _cosine and _centroid. Bounded magnitudes so
# Hypothesis doesn't burn its budget on float-overflow edge cases that
# the cosine math (sum of squares → sqrt) handles independently.
_FLOAT = st.floats(
    min_value=-1e6, max_value=1e6, allow_nan=False, allow_infinity=False,
)


def _vectors_strategy(min_size: int = 1, max_size: int = 8, dim: int = 4):
    """Lists of equal-length vectors (the contract _centroid requires).

    Centroid's element-wise mean only makes sense when all vectors share a
    dimension; Hypothesis can't infer this so we fix the dim per draw.
    """
    return st.lists(
        st.lists(_FLOAT, min_size=dim, max_size=dim),
        min_size=min_size,
        max_size=max_size,
    )


# Narrative text strategies — printable short strings plus the empty /
# whitespace edge cases.
_WHITESPACE_TEXT = st.sampled_from(["", " ", "  ", "\n", "\t", " \t \n  "])

_GENERIC_TEXT = st.text(min_size=0, max_size=120)

_NARRATIVE_INPUT = st.one_of(
    st.none(),
    _WHITESPACE_TEXT,
    _GENERIC_TEXT,
    st.sampled_from(
        [
            "Customer enforces 14-character passwords via AD GPO.",
            "MFA via FIDO2 hardware tokens, revoked at offboarding.",
            "Baseline images signed with cosign and verified at boot.",
            "Audit log forwarding to Splunk via syslog agent.",
            "Vulnerability scans run weekly via Tenable agents.",
            "The customer is responsible.",
            "Inherited from the provider.",
            "Not applicable.",
            "See SSP.",
        ]
    ),
)

_NARRATIVE_LIST = st.lists(_NARRATIVE_INPUT, min_size=0, max_size=8)


# ---------------------------------------------------------------------------
# Module-shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def tfidf_provider() -> TfidfFallbackProvider:
    """Module-scoped — TfidfFallbackProvider is stateless after __init__
    so reusing it across examples is safe and avoids paying the sklearn
    import overhead per Hypothesis case.
    """
    return TfidfFallbackProvider()


# ---------------------------------------------------------------------------
# _cosine — pure-function properties
# ---------------------------------------------------------------------------


@given(a=st.lists(_FLOAT, min_size=1, max_size=12),
       b=st.lists(_FLOAT, min_size=1, max_size=12))
@settings(max_examples=300, deadline=None)
def test_cosine_is_symmetric(a, b):
    """cosine(a, b) == cosine(b, a) (within FP tolerance).

    The dot-product numerator is commutative and the norms in the
    denominator don't depend on order. A regression that introduced
    an asymmetric correction term (e.g., normalizing only one side)
    would surface here.
    """
    # Pad/truncate so the vectors share a length (cosine's zip uses
    # strict=False so unequal lengths silently drop elements, but the
    # property only holds on equal-length inputs).
    n = min(len(a), len(b))
    a2, b2 = a[:n], b[:n]
    assert _cosine(a2, b2) == pytest.approx(_cosine(b2, a2))


@given(v=st.lists(_FLOAT, min_size=1, max_size=12))
@settings(max_examples=200, deadline=None)
def test_cosine_self_is_one_for_nonzero(v):
    """cosine(v, v) == 1.0 for any vector with non-zero norm.

    The defensive zero-norm guard returns 0.0; for everything else
    the identity ``v·v / (|v||v|) == 1`` must hold (within FP).
    """
    norm_sq = sum(x * x for x in v)
    if norm_sq == 0.0:
        # All-zero vector — the defensive branch returns 0.0; pin that.
        assert _cosine(v, v) == 0.0
    else:
        assert _cosine(v, v) == pytest.approx(1.0)


@given(v=st.lists(_FLOAT, min_size=1, max_size=12))
@settings(max_examples=200, deadline=None)
def test_cosine_negation_is_minus_one_for_nonzero(v):
    """cosine(v, -v) == -1.0 for any non-zero vector.

    A sign-flip regression (e.g., taking abs() somewhere) would let
    anti-parallel vectors score as similar — breaking the substantive
    vs filler ranking that depends on the full [-1, 1] range.
    """
    norm_sq = sum(x * x for x in v)
    neg = [-x for x in v]
    if norm_sq == 0.0:
        assert _cosine(v, neg) == 0.0
    else:
        assert _cosine(v, neg) == pytest.approx(-1.0)


@given(other=st.lists(_FLOAT, min_size=1, max_size=12))
@settings(max_examples=150, deadline=None)
def test_cosine_zero_vector_is_zero(other):
    """Any zero-norm input → 0.0 (defensive branch). No NaN, no crash.

    The filler centroid CAN be a zero vector under TF-IDF if every
    filler row mapped to all-zero vocab terms (pathological but
    possible). The downstream scorer must NOT divide by zero.
    """
    zero = [0.0] * len(other)
    assert _cosine(zero, other) == 0.0
    assert _cosine(other, zero) == 0.0


@given(a=st.lists(_FLOAT, min_size=1, max_size=12),
       b=st.lists(_FLOAT, min_size=1, max_size=12))
@settings(max_examples=200, deadline=None)
def test_cosine_bounded_in_minus_one_one(a, b):
    """cosine ∈ [-1, 1] for any finite vector pair (within FP).

    Pin the Cauchy-Schwarz bound. An "optimization" that returned the
    raw dot product without normalizing would break this immediately
    and surface scores outside [0, 1] from score_narrative_quality.
    """
    n = min(len(a), len(b))
    a2, b2 = a[:n], b[:n]
    if not a2:
        return  # both empty after truncation; cosine is 0.0 by branch
    result = _cosine(a2, b2)
    # Tolerance for FP drift near the boundary.
    assert -1.0 - 1e-9 <= result <= 1.0 + 1e-9


# ---------------------------------------------------------------------------
# _centroid — pure-function properties
# ---------------------------------------------------------------------------


def test_centroid_empty_input_returns_empty_list():
    """No vectors → no centroid. Required for the
    ``score_narrative_quality([], provider)`` short-circuit path."""
    assert _centroid([]) == []


@given(vectors=_vectors_strategy(min_size=1, max_size=8, dim=4))
@settings(max_examples=200, deadline=None)
def test_centroid_dimensionality_matches_input(vectors):
    """len(centroid) == len(vectors[0]).

    A drift here (e.g., off-by-one in the sums list init) would mean
    the downstream cosine call zips against the wrong dim and silently
    truncates information from every narrative scoring round.
    """
    c = _centroid(vectors)
    assert len(c) == len(vectors[0])


@given(v=st.lists(_FLOAT, min_size=1, max_size=8))
@settings(max_examples=150, deadline=None)
def test_centroid_single_vector_returns_that_vector(v):
    """Centroid of a one-vector list IS that vector (within FP).

    Smallest possible centroid identity — a regression where the
    averaging divisor was wrong (e.g., len+1) would fail here.
    """
    c = _centroid([v])
    assert len(c) == len(v)
    for got, want in zip(c, v, strict=True):
        assert got == pytest.approx(want)


@given(vectors=_vectors_strategy(min_size=2, max_size=8, dim=4))
@settings(max_examples=150, deadline=None)
def test_centroid_each_component_is_arithmetic_mean(vectors):
    """centroid[i] == mean(v[i] for v in vectors).

    Pins the element-wise mean formula directly. Any swap to median /
    geometric mean / weighted mean would surface here.
    """
    c = _centroid(vectors)
    for i in range(len(vectors[0])):
        expected = sum(v[i] for v in vectors) / len(vectors)
        assert c[i] == pytest.approx(expected)


@given(vectors=_vectors_strategy(min_size=2, max_size=8, dim=4))
@settings(max_examples=100, deadline=None)
def test_centroid_invariant_under_row_permutation(vectors):
    """Mean is commutative — reversing the row order MUST give the
    same centroid. Defends against an order-dependent running-mean
    refactor that diverges across orderings due to FP accumulation.
    """
    forward = _centroid(vectors)
    reverse = _centroid(list(reversed(vectors)))
    for f, r in zip(forward, reverse, strict=True):
        assert f == pytest.approx(r)


# ---------------------------------------------------------------------------
# score_narrative_quality — range + parallel-list contract
# ---------------------------------------------------------------------------


@given(narratives=_NARRATIVE_LIST)
@settings(max_examples=80, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_scores_always_in_unit_interval(narratives, tfidf_provider):
    """Every score ∈ [0, 1] for any narrative input via TF-IDF.

    The clip at the end of ``score_narrative_quality`` is the
    load-bearing guard against cosine's small negative excursions on
    orthogonal sparse vectors. A regression that dropped the clip
    would let a downstream blend in crm_sanity see a negative
    "quality" and produce out-of-range total suspicion.
    """
    result = score_narrative_quality(narratives, tfidf_provider)
    for s in result.scores:
        assert 0.0 <= s <= 1.0


@given(narratives=_NARRATIVE_LIST)
@settings(max_examples=80, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_scores_length_matches_input(narratives, tfidf_provider):
    """``len(result.scores) == len(narratives)``.

    The route handler maps scores back to control_ids by index; a
    refactor that silently dropped or duplicated an entry would
    mis-attribute every suspicion score downstream.
    """
    result = score_narrative_quality(narratives, tfidf_provider)
    assert len(result.scores) == len(narratives)


@given(narratives=_NARRATIVE_LIST)
@settings(max_examples=60, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_scores_is_tuple_for_immutable_result(narratives, tfidf_provider):
    """``scores`` MUST be a ``tuple`` for any input (frozen dataclass).

    A regression that returned a mutable list would break callers that
    rely on the result being hashable / passable across thread
    boundaries without defensive copies.
    """
    result = score_narrative_quality(narratives, tfidf_provider)
    assert isinstance(result.scores, tuple)


@given(narratives=_NARRATIVE_LIST)
@settings(max_examples=60, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_result_carries_filler_version(narratives, tfidf_provider):
    """``filler_version`` always equals the module's ``_FILLER_VERSION``.

    The audit-trail contract: the suspicion log records which filler
    vintage produced each score so a vintage bump can invalidate
    historical cache rows. Any divergence here breaks cache coherence.
    """
    result = score_narrative_quality(narratives, tfidf_provider)
    assert result.filler_version == _FILLER_VERSION


# ---------------------------------------------------------------------------
# Whitespace / None robustness
# ---------------------------------------------------------------------------


@given(whitespace=st.lists(_WHITESPACE_TEXT, min_size=1, max_size=8))
@settings(max_examples=80, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_all_whitespace_inputs_score_zero(whitespace, tfidf_provider):
    """Whitespace-only narratives are filler-equivalent → 0.0.

    The ``not text.strip()`` short-circuit in score_narrative_quality
    is the only thing that prevents these from running through cosine
    and producing arbitrary similarity values. Defends that branch.
    """
    result = score_narrative_quality(whitespace, tfidf_provider)
    for s in result.scores:
        assert s == 0.0


@given(count=st.integers(min_value=1, max_value=8))
@settings(max_examples=20, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_all_none_inputs_score_zero(count, tfidf_provider):
    """Lists of all ``None`` → all 0.0, no crash.

    The route handler may receive customer-owned CRM rows whose
    narratives are None; the scorer's ``str(n) if n is not None else
    ""`` normalization MUST handle every None safely.
    """
    nones: list[str | None] = [None] * count
    result = score_narrative_quality(nones, tfidf_provider)  # type: ignore[arg-type]
    assert len(result.scores) == count
    for s in result.scores:
        assert s == 0.0


@given(
    nones_first=st.integers(min_value=0, max_value=4),
    substantive=st.sampled_from([
        "Customer enforces 14-character passwords via AD GPO.",
        "MFA via FIDO2 hardware tokens, revoked at offboarding.",
        "Vulnerability scans run weekly via Tenable agents.",
    ]),
)
@settings(max_examples=30, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_none_entries_do_not_contaminate_substantive_score(
    nones_first, substantive, tfidf_provider
):
    """Substantive narrative scored alongside None entries scores > 0.

    Pins isolation: the None rows must NOT pull the substantive row's
    cosine via shared vocabulary or batched re-fitting in a way that
    silently zeros it out.
    """
    inputs: list[str | None] = [None] * nones_first + [substantive]
    result = score_narrative_quality(inputs, tfidf_provider)  # type: ignore[arg-type]
    assert result.scores[-1] > 0.0
    for i in range(nones_first):
        assert result.scores[i] == 0.0


# ---------------------------------------------------------------------------
# Provider determinism — same input → same output
# ---------------------------------------------------------------------------


@given(narratives=st.lists(_NARRATIVE_INPUT, min_size=1, max_size=6))
@settings(max_examples=40, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_tfidf_scores_are_deterministic(narratives, tfidf_provider):
    """Calling ``score_narrative_quality`` twice with identical inputs
    produces identical scores.

    The CrmNarrativeEmbedding cache key is sha256 of the text alone;
    a non-deterministic provider would silently re-embed and the
    cached centroid would drift across recomputes — defeating the
    cache's "one embedding per unique narrative" claim.
    """
    a = score_narrative_quality(narratives, tfidf_provider)
    b = score_narrative_quality(narratives, tfidf_provider)
    assert len(a.scores) == len(b.scores)
    for x, y in zip(a.scores, b.scores, strict=True):
        assert x == pytest.approx(y)


# ---------------------------------------------------------------------------
# Misbehaving-provider safety
# ---------------------------------------------------------------------------


class _WrongCountProvider:
    """Returns ``drop_n`` fewer vectors than asked for — exercises the
    "provider misbehaved" branch in ``score_narrative_quality``.
    """

    def __init__(self, drop_n: int = 1) -> None:
        self._drop_n = drop_n

    @property
    def provider_name(self) -> str:
        return "wrong-count"

    @property
    def model_name(self) -> str:
        return "wrong-v0"

    def embed(self, texts: list[str]) -> list[list[float]]:
        n = max(0, len(texts) - self._drop_n)
        return [[1.0, 0.0, 0.0] for _ in range(n)]


@given(
    n_narratives=st.integers(min_value=1, max_value=8),
    drop_n=st.integers(min_value=1, max_value=4),
)
@settings(max_examples=40, deadline=None)
def test_wrong_count_provider_yields_all_zero_scores(n_narratives, drop_n):
    """Provider returning the wrong vector count → all-zero scores,
    parallel to the input list, with the input provider's metadata.

    The "no narrative left unscored" contract: even a buggy provider
    can't crash the suspicion pipeline. Pins the defensive branch in
    ``score_narrative_quality``.
    """
    provider = _WrongCountProvider(drop_n=drop_n)
    inputs = [f"narrative-{i}" for i in range(n_narratives)]
    result = score_narrative_quality(inputs, provider)
    assert isinstance(result, NarrativeQualityResult)
    assert len(result.scores) == n_narratives
    for s in result.scores:
        assert s == 0.0
    assert result.provider_name == "wrong-count"
    assert result.model_name == "wrong-v0"


# ---------------------------------------------------------------------------
# Filler corpus surface — must remain non-empty + unique under any
# refactor (the centroid is built from it directly)
# ---------------------------------------------------------------------------


def test_filler_corpus_strings_are_all_non_empty_strings():
    """Each filler entry is a non-empty string.

    An accidental ``None`` or empty-string entry in the corpus would
    skew the centroid toward "no signal" and pull substantive scores
    toward zero across the entire pipeline.
    """
    for entry in _FILLER_CORPUS:
        assert isinstance(entry, str)
        assert entry.strip(), f"filler entry is whitespace-only: {entry!r}"
