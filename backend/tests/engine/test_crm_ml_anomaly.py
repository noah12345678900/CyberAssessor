"""Tests for ``crm_ml.fit_anomaly_model`` + ``score_anomaly`` — the
IsolationForest tier of the three-tier CRM suspicion scoring.

What we pin:

1. **MIN_CORPUS_SIZE refusal.** ``fit_anomaly_model`` raises
   ``ValueError`` when the corpus has fewer than ``MIN_CORPUS_SIZE``
   (10) vectors. Below that, the model would just memorize its training
   set — every point is its own outlier, which would page the assessor
   on every CRM upload.

2. **Wrong-schema refusal.** A corpus mixing
   ``CURRENT_FEATURE_SCHEMA_VERSION`` with stale versions is rejected
   wholesale. The refit script is supposed to filter before calling us;
   this is the defensive assertion.

3. **FitResult shape.** Successful fit returns
   ``FitResult(model_blob: bytes, metadata: dict)``. ``model_blob`` is
   non-empty (the joblib pickle). ``metadata`` carries the
   training-time summary fields the operator inspects before promoting
   the model (n_samples, feature_schema_version, score stats, n_features).

4. **Schema-version mismatch at score time → 0.0.** If a persisted
   model blob was fit on schema version N but a feature vector at
   version M arrives, ``score_anomaly`` returns 0.0 instead of running
   the (mis-aligned) numeric row through the model. The caller treats
   0.0 as "no ML score available" (route handler greys out the row).

5. **Score range invariant.** Output is always in ``[0, 1]``. The
   underlying ``IsolationForest.score_samples`` returns a value in
   roughly ``[-0.5, 0]``; the wrapper applies ``1 - exp(raw)`` plus
   clamp so the blend formula can treat all three tier scores
   symmetrically.

6. **Score determinism.** Scoring the same vector twice against the
   same model blob returns the same float (joblib round-trip + sklearn
   ``score_samples`` are deterministic; we pin this as a contract so a
   future swap to a non-deterministic backend trips a test).

7. **Outlier > inlier ordering.** This is the load-bearing accuracy
   assertion: a vector that lives at the centroid of the training
   distribution scores LOWER than a vector at the far extreme of every
   feature. We don't pin exact values (IsolationForest paths are
   randomized even with fixed seed across sklearn versions), but
   ordering is the actual product contract.

sklearn + joblib are required; module-level ``importorskip``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

pytest.importorskip("sklearn", reason="IsolationForest fit needs sklearn")
pytest.importorskip("joblib", reason="model blob round-trip needs joblib")

from cybersecurity_assessor.engine.crm_ml import (  # noqa: E402
    CURRENT_FEATURE_SCHEMA_VERSION,
    MIN_CORPUS_SIZE,
    CrmFeatureVector,
    FitResult,
    fit_anomaly_model,
    score_anomaly,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _vec(
    *,
    inherited_pct: float = 0.4,
    provider_pct: float = 0.1,
    not_applicable_pct: float = 0.0,
    narrative_present_pct: float = 0.9,
    narrative_len_mean: float = 120.0,
    narrative_len_stdev: float = 30.0,
    intra_crm_tfidf_max_similarity: float = 0.4,
    intra_crm_tfidf_mean_similarity: float = 0.2,
    family_evidence_contradictions: int = 0,
    in_scope_control_count: int = 50,
    schema_version: int = CURRENT_FEATURE_SCHEMA_VERSION,
) -> CrmFeatureVector:
    """Build a CrmFeatureVector with sensible 'middle of the corpus' defaults.

    Override individual fields per-test to construct outliers or stale
    versions.
    """
    return CrmFeatureVector(
        schema_version=schema_version,
        inherited_pct=inherited_pct,
        provider_pct=provider_pct,
        not_applicable_pct=not_applicable_pct,
        narrative_present_pct=narrative_present_pct,
        narrative_len_mean=narrative_len_mean,
        narrative_len_stdev=narrative_len_stdev,
        intra_crm_tfidf_max_similarity=intra_crm_tfidf_max_similarity,
        intra_crm_tfidf_mean_similarity=intra_crm_tfidf_mean_similarity,
        family_evidence_contradictions=family_evidence_contradictions,
        in_scope_control_count=in_scope_control_count,
    )


def _typical_corpus(n: int = 12) -> list[CrmFeatureVector]:
    """A small "well-behaved" corpus clustered around moderate inheritance,
    substantive narratives, no contradictions. The model fit on this
    should treat extreme-inheritance/empty-narrative vectors as outliers.

    Slight per-row jitter via the index so IsolationForest sees a real
    distribution and not 12 copies of one point (which would collapse to
    a single tree path).
    """
    out: list[CrmFeatureVector] = []
    for i in range(n):
        out.append(
            _vec(
                inherited_pct=0.35 + 0.01 * (i % 5),
                provider_pct=0.10 + 0.005 * (i % 3),
                not_applicable_pct=0.02 * (i % 2),
                narrative_present_pct=0.88 + 0.01 * (i % 4),
                narrative_len_mean=110.0 + 5.0 * (i % 5),
                narrative_len_stdev=25.0 + 2.0 * (i % 4),
                intra_crm_tfidf_max_similarity=0.35 + 0.02 * (i % 4),
                intra_crm_tfidf_mean_similarity=0.18 + 0.01 * (i % 3),
                family_evidence_contradictions=0,
                in_scope_control_count=45 + (i % 7),
            )
        )
    return out


# ---------------------------------------------------------------------------
# fit_anomaly_model — refusal paths
# ---------------------------------------------------------------------------


def test_fit_refuses_when_corpus_below_min_size():
    """Below MIN_CORPUS_SIZE = 10 → ValueError, no FitResult.

    The error message must reference the threshold so an operator
    grepping logs can find it without source-diving.
    """
    corpus = _typical_corpus(n=MIN_CORPUS_SIZE - 1)
    with pytest.raises(ValueError, match=str(MIN_CORPUS_SIZE)):
        fit_anomaly_model(corpus)


def test_fit_refuses_corpus_with_wrong_schema_version_vectors():
    """One stale-version vector in an otherwise-current corpus → reject.

    Defensive: the refit script is supposed to filter, but if a bug
    slipped through and a v0 row got into the training batch, the
    fitted model would learn a meaningless distribution. Refuse loudly.
    """
    corpus = _typical_corpus(n=12)
    # Replace one row with a stale-schema vector.
    bad = _vec(schema_version=CURRENT_FEATURE_SCHEMA_VERSION - 1)
    corpus[5] = bad
    with pytest.raises(ValueError, match="schema version"):
        fit_anomaly_model(corpus)


def test_fit_refuses_empty_corpus():
    """Zero vectors → still a ValueError (n < MIN_CORPUS_SIZE)."""
    with pytest.raises(ValueError):
        fit_anomaly_model([])


# ---------------------------------------------------------------------------
# fit_anomaly_model — happy path
# ---------------------------------------------------------------------------


def test_fit_returns_fit_result_with_blob_and_metadata():
    """Successful fit → FitResult(model_blob=non-empty bytes, metadata=dict)."""
    corpus = _typical_corpus(n=12)
    result = fit_anomaly_model(corpus)
    assert isinstance(result, FitResult)
    assert isinstance(result.model_blob, bytes)
    assert len(result.model_blob) > 0
    assert isinstance(result.metadata, dict)


def test_fit_metadata_carries_corpus_summary_for_operator_review():
    """The metadata dict is stored in CrmAnomalyModel.notes so the
    operator can compare candidate models before activation. Pins the
    field set the UI relies on.
    """
    corpus = _typical_corpus(n=14)
    result = fit_anomaly_model(corpus)
    md = result.metadata
    assert md["n_samples"] == 14
    assert md["feature_schema_version"] == CURRENT_FEATURE_SCHEMA_VERSION
    assert md["n_features"] == len(CrmFeatureVector._NUMERIC_FIELDS)
    # Score stats are floats covering the training set's anomaly distribution.
    assert isinstance(md["training_score_min"], float)
    assert isinstance(md["training_score_max"], float)
    assert isinstance(md["training_score_mean"], float)
    assert isinstance(md["training_score_stdev"], float)
    # Sanity: max >= mean >= min.
    assert md["training_score_min"] <= md["training_score_mean"] <= md["training_score_max"]


# ---------------------------------------------------------------------------
# score_anomaly — schema gate + range
# ---------------------------------------------------------------------------


def test_score_returns_zero_when_vector_schema_version_does_not_match_current():
    """Stale-schema input vector → 0.0 short-circuit, no model load.

    The route handler interprets 0.0 as "no ML score available" — the
    only way the schema mismatches is if the persisted blob outlived a
    schema bump. This is the "fail safe" path.
    """
    corpus = _typical_corpus(n=12)
    result = fit_anomaly_model(corpus)
    stale = _vec(schema_version=CURRENT_FEATURE_SCHEMA_VERSION - 1)
    assert score_anomaly(result.model_blob, stale) == 0.0


def test_score_returns_value_in_unit_interval():
    """Output must be in [0, 1] — the blend formula in crm_sanity
    assumes all three tier scores are unit-bounded.
    """
    corpus = _typical_corpus(n=12)
    result = fit_anomaly_model(corpus)
    # Try a centroid-ish vector and an extreme outlier — both must be unit-bounded.
    for vec in [
        _vec(),
        _vec(
            inherited_pct=1.0,
            provider_pct=0.0,
            narrative_present_pct=0.0,
            narrative_len_mean=0.0,
            narrative_len_stdev=0.0,
            intra_crm_tfidf_max_similarity=1.0,
            intra_crm_tfidf_mean_similarity=1.0,
            family_evidence_contradictions=10,
            in_scope_control_count=500,
        ),
    ]:
        score = score_anomaly(result.model_blob, vec)
        assert 0.0 <= score <= 1.0


def test_score_is_deterministic_for_same_model_and_vector():
    """Scoring the same vector twice → exact float equality.

    joblib round-trip + sklearn IsolationForest score_samples are
    deterministic; this test pins that contract so a future change
    (e.g. swapping to an OnlineForest variant) trips here before it
    silently destabilizes the blend.
    """
    corpus = _typical_corpus(n=12)
    result = fit_anomaly_model(corpus)
    vec = _vec()
    s1 = score_anomaly(result.model_blob, vec)
    s2 = score_anomaly(result.model_blob, vec)
    assert s1 == s2


# ---------------------------------------------------------------------------
# Outlier > inlier ordering — the actual product contract
# ---------------------------------------------------------------------------


def test_extreme_outlier_scores_higher_than_centroid_vector():
    """The load-bearing accuracy assertion.

    Fit on a "normal" corpus (moderate inheritance, substantive
    narratives, no contradictions). Score two vectors:

    - ``centroid_like`` — sits inside the training distribution.
    - ``extreme_outlier`` — saturates every "this looks suspicious"
      feature: 100% inherited, zero narratives, identical narratives,
      many contradictions, huge in-scope count.

    The outlier must score strictly higher. IsolationForest path-depth
    semantics make this near-guaranteed given enough corpus variance,
    so we use a corpus large enough (16) that path randomness can't
    flip the ordering.
    """
    corpus = _typical_corpus(n=16)
    result = fit_anomaly_model(corpus)

    centroid_like = _vec(
        inherited_pct=0.38,
        provider_pct=0.12,
        not_applicable_pct=0.02,
        narrative_present_pct=0.90,
        narrative_len_mean=120.0,
        narrative_len_stdev=27.0,
        intra_crm_tfidf_max_similarity=0.38,
        intra_crm_tfidf_mean_similarity=0.20,
        family_evidence_contradictions=0,
        in_scope_control_count=48,
    )
    extreme_outlier = _vec(
        inherited_pct=1.0,
        provider_pct=0.0,
        not_applicable_pct=0.0,
        narrative_present_pct=0.0,
        narrative_len_mean=0.0,
        narrative_len_stdev=0.0,
        intra_crm_tfidf_max_similarity=1.0,
        intra_crm_tfidf_mean_similarity=1.0,
        family_evidence_contradictions=15,
        in_scope_control_count=400,
    )
    s_in = score_anomaly(result.model_blob, centroid_like)
    s_out = score_anomaly(result.model_blob, extreme_outlier)
    assert s_out > s_in, (
        f"extreme outlier ({s_out}) should score higher than centroid ({s_in})"
    )
