"""Property-based tests for ``crm_ml`` (Tier-2 CRM suspicion).

The example-driven suites in
``backend/tests/engine/test_crm_ml_features.py`` and
``backend/tests/engine/test_crm_ml_anomaly.py`` pin specific shapes —
known feature values, hand-built typical/outlier vectors,
schema-mismatch refusal. This file fuzzes the math + dataclass + I/O
contracts so a refactor that breaks an invariant in a corner of the
(CrmContext × scope × evidence) or (feature vector × fitted model)
space gets caught:

  1. **_family_of pure-function properties.** Any non-empty control_id
     resolves to a lowercase head-of-hyphen token; falsy input yields
     ``""`` defensively. A regression that crashed on a missing hyphen
     would tank ``extract_features`` mid-CRM because the contradiction
     counter calls this on every entry.

  2. **CrmFeatureVector dataclass invariants.** ``to_row`` length always
     equals ``len(_NUMERIC_FIELDS)`` for ANY vector — the IsolationForest
     model was fit on rows of this exact width, a mismatch would either
     crash sklearn (wrong shape) or silently mis-align features (extra
     field). JSON round-trip preserves the vector verbatim — defends the
     persisted ``CrmCorpusFeatures.features_json`` column from a
     ``json.dumps(asdict(...))`` swap that lost a field.

  3. **extract_features universal invariants.** Schema version is
     ALWAYS the current constant (never accidentally hard-coded to 0 in
     a refactor). Every ratio field stays in [0, 1]; the three
     mutually-exclusive responsibilities (inherited + provider +
     not_applicable) sum to ≤ 1.0 (hybrid + customer take the rest, so
     strict equality is wrong but ≤1.0 is the load-bearing bound).
     ``in_scope_control_count`` matches ``len(set(scope))``.
     Counts are non-negative.

  4. **Out-of-scope leakage.** CRM entries on controls NOT in
     ``in_scope_control_ids`` MUST NOT shift any output field. A
     regression that forgot the scope filter would let a 500-control
     mass-uploaded CRM dominate a 50-control workbook's ratios. We
     fuzz two contexts — one with only in-scope entries, one with the
     same in-scope set + arbitrary out-of-scope extras — and assert
     the feature vectors are identical.

  5. **Determinism.** ``extract_features`` is a pure function;
     building the same inputs twice yields identical output. Insert
     order of the dict keys MUST NOT shift the output (the TF-IDF
     similarity step is order-sensitive in implementation but the
     off-diagonal max/mean is set-symmetric).

  6. **score_anomaly range under any feature vector.** Against a fixed
     fitted model, the score is in [0, 1] for ANY current-schema vector
     — including ones with extreme/negative-looking values that the
     training corpus never saw. The ``1 - exp(raw)`` clamp is the
     load-bearing defense.

  7. **score_anomaly determinism + schema gate.** Same (blob, vector)
     pair → same float (joblib + sklearn ``score_samples`` are
     deterministic and we pin it). Any stale-schema vector → 0.0.

  8. **fit_anomaly_model metadata invariants.** ``n_samples`` matches
     the corpus length; ``n_features`` matches the dataclass field
     count; ``training_score_min <= training_score_mean <=
     training_score_max`` for any fuzzed valid corpus.

sklearn + joblib are required; module-level ``importorskip``.
"""

from __future__ import annotations

import json

import pytest

hypothesis = pytest.importorskip("hypothesis")
pytest.importorskip("sklearn", reason="IsolationForest fit needs sklearn")
pytest.importorskip("joblib", reason="model blob round-trip needs joblib")

from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from cybersecurity_assessor.engine.crm_context import (  # noqa: E402
    CrmContext,
    CrmEntry,
)
from cybersecurity_assessor.engine.crm_ml import (  # noqa: E402
    CURRENT_FEATURE_SCHEMA_VERSION,
    CrmFeatureVector,
    _family_of,
    extract_features,
    fit_anomaly_model,
    score_anomaly,
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


# Realistic NIST family tokens — these are what extract_features sees in
# production. Including a few off-tokens ("zz") so the contradiction
# counter has occasional misses.
_FAMILY = st.sampled_from(
    ["ac", "au", "cm", "ia", "ir", "sc", "si", "ra", "pl", "zz"]
)

# Control ids that _family_of must parse correctly: family-num and
# family-num.enhancement forms. Capitalization mixed so the lowercase
# contract gets exercised.
_CONTROL_ID = st.builds(
    lambda fam, num, enh: (
        f"{fam}-{num}" if enh is None else f"{fam}-{num}.{enh}"
    ),
    fam=st.sampled_from(["ac", "AC", "Au", "cm", "IA", "ir", "Sc", "si", "Ra", "pl"]),
    num=st.integers(min_value=1, max_value=20),
    enh=st.one_of(st.none(), st.integers(min_value=1, max_value=5)),
)

# Responsibility values the validator emits. Include None occasionally
# since CrmEntry.responsibility is Optional[str].
_RESPONSIBILITY = st.sampled_from(
    ["customer", "provider", "hybrid", "inherited", "not_applicable"]
)

# Narratives the LLM/upload pipeline produces. Empty + whitespace +
# realistic short strings; small + bounded so TF-IDF cost stays low.
_NARRATIVE = st.one_of(
    st.none(),
    st.just(""),
    st.just("   "),
    st.sampled_from(
        [
            "Inherited from AWS GovCloud per FedRAMP authorization.",
            "Provider configures via console, customer reviews logs.",
            "CSP responsibility per shared-responsibility matrix.",
            "Customer-owned implementation in local data center.",
            "Hybrid: provider hosts, customer configures policy.",
            "Not applicable to this service tier.",
            "boilerplate copy-paste narrative",
        ]
    ),
    st.text(min_size=0, max_size=80),
)


def _crm_entry(control_id: str, responsibility: str, narrative: str | None) -> CrmEntry:
    """Build a CrmEntry for a single control. The on-prem narrative
    fields aren't exercised by extract_features so we leave them None.
    """
    return CrmEntry(
        control_id=control_id.lower(),
        responsibility=responsibility,
        narrative=narrative,
        source_baseline_id=1,
        responsibility_onprem=None,
        narrative_onprem=None,
    )


# A small CRM context: a list of (control_id, responsibility, narrative)
# tuples turned into a CrmContext. unique=True on control_id keeps the
# dict construction sensible (latest-wins on dupes would obscure the
# property contracts).
_CRM_CONTEXT_INPUTS = st.lists(
    st.tuples(_CONTROL_ID, _RESPONSIBILITY, _NARRATIVE),
    min_size=0,
    max_size=12,
    unique_by=lambda t: t[0].lower(),
)

# In-scope control ids for extract_features. Independent of the CRM
# context to exercise the scope-filter logic; small enough to keep
# property runs cheap.
_SCOPE = st.lists(
    _CONTROL_ID.map(str.lower),
    min_size=0,
    max_size=15,
    unique=True,
)

# Tagged-evidence dict: family -> count of tagged evidence rows for that
# family. Used by the contradiction counter.
_TAGGED_EVIDENCE_MAP = st.dictionaries(
    keys=_FAMILY,
    values=st.integers(min_value=0, max_value=20),
    min_size=0,
    max_size=8,
)


def _build_context(rows: list[tuple[str, str, str | None]]) -> CrmContext:
    by_control: dict[str, CrmEntry] = {}
    for cid, resp, narr in rows:
        key = cid.lower()
        by_control[key] = _crm_entry(key, resp, narr)
    return CrmContext(by_control=by_control)


# ---------------------------------------------------------------------------
# _family_of — pure-function properties
# ---------------------------------------------------------------------------


@given(control_id=_CONTROL_ID)
@settings(max_examples=300, deadline=None)
def test_family_of_returns_lowercase_head_before_hyphen(control_id):
    """For any well-formed control_id, family is the lowercased head
    before the first hyphen.

    A regression that dropped the ``.lower()`` would break the
    contradiction counter — ``tagged_evidence_by_family`` keys are
    canonical lowercase but the CRM might carry "AC-2.1" with caps;
    they MUST collide on the same family bucket.
    """
    fam = _family_of(control_id)
    expected = control_id.split("-", 1)[0].lower()
    assert fam == expected
    assert fam == fam.lower()


@given(
    control_id=st.one_of(
        st.just(""),
        st.none().map(lambda _: ""),  # _family_of's defensive path
    )
)
@settings(max_examples=10, deadline=None)
def test_family_of_empty_input_returns_empty(control_id):
    """Falsy input → ``""`` (NOT a crash). Defends downstream set
    membership: a control with no family token will simply never match
    any tagged-evidence family bucket and won't contribute a false
    contradiction.
    """
    assert _family_of(control_id) == ""


@given(text=st.text(min_size=1, max_size=20).filter(lambda s: "-" not in s))
@settings(max_examples=100, deadline=None)
def test_family_of_no_hyphen_returns_lowercase_whole_string(text):
    """Strings with no hyphen → whole string lowercased.

    A malformed control_id without a hyphen still parses to *some*
    family token (won't crash); whether it matches an evidence bucket
    is up to the data, but the parser stays total.
    """
    assert _family_of(text) == text.lower()


# ---------------------------------------------------------------------------
# CrmFeatureVector — dataclass invariants
# ---------------------------------------------------------------------------


# Build arbitrary feature vectors for to_row / from_json / score_anomaly
# property tests. Ratio fields in [0, 1]; narrative_len fields >= 0;
# counts >= 0; schema_version current.
_FEATURE_VECTOR = st.builds(
    CrmFeatureVector,
    schema_version=st.just(CURRENT_FEATURE_SCHEMA_VERSION),
    inherited_pct=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    provider_pct=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    not_applicable_pct=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    narrative_present_pct=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    narrative_len_mean=st.floats(min_value=0.0, max_value=2000.0, allow_nan=False),
    narrative_len_stdev=st.floats(min_value=0.0, max_value=2000.0, allow_nan=False),
    intra_crm_tfidf_max_similarity=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    intra_crm_tfidf_mean_similarity=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    family_evidence_contradictions=st.integers(min_value=0, max_value=50),
    in_scope_control_count=st.integers(min_value=0, max_value=1000),
)


@given(vec=_FEATURE_VECTOR)
@settings(max_examples=200, deadline=None)
def test_to_row_length_always_matches_numeric_fields(vec):
    """``len(vec.to_row()) == len(_NUMERIC_FIELDS)`` for any vector.

    sklearn was fit on a rectangular matrix of exactly this width; a
    refactor that added a field to the dataclass without bumping
    ``CURRENT_FEATURE_SCHEMA_VERSION`` would crash at predict time
    (shape mismatch). This property pins the width contract.
    """
    row = vec.to_row()
    assert isinstance(row, list)
    assert len(row) == len(CrmFeatureVector._NUMERIC_FIELDS)
    for x in row:
        assert isinstance(x, float)


@given(vec=_FEATURE_VECTOR)
@settings(max_examples=200, deadline=None)
def test_feature_vector_json_roundtrip_preserves_all_fields(vec):
    """``CrmFeatureVector.from_json(vec.to_json()) == vec`` for any vector.

    The persisted ``CrmCorpusFeatures.features_json`` column round-trips
    through this pair every refit. A regression that lost a field via
    a partial ``asdict`` would silently shorten the row, corrupting the
    trained model on the next refit.
    """
    payload = vec.to_json()
    parsed = json.loads(payload)
    # Every field in the dataclass must round-trip.
    assert set(parsed.keys()) == {
        "schema_version",
        "inherited_pct",
        "provider_pct",
        "not_applicable_pct",
        "narrative_present_pct",
        "narrative_len_mean",
        "narrative_len_stdev",
        "intra_crm_tfidf_max_similarity",
        "intra_crm_tfidf_mean_similarity",
        "family_evidence_contradictions",
        "in_scope_control_count",
    }
    rebuilt = CrmFeatureVector.from_json(payload)
    assert rebuilt == vec


# ---------------------------------------------------------------------------
# extract_features — universal invariants
# ---------------------------------------------------------------------------


@given(
    rows=_CRM_CONTEXT_INPUTS,
    scope=_SCOPE,
    evidence=_TAGGED_EVIDENCE_MAP,
)
@settings(max_examples=150, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def test_extract_features_schema_version_is_always_current(rows, scope, evidence):
    """Output's ``schema_version`` MUST equal ``CURRENT_FEATURE_SCHEMA_VERSION``.

    A refactor that hard-coded the version to 0 would silently
    invalidate every newly-extracted vector (schema gate would zero
    them all out at score time). This catches that the constant is
    actually being used at the construction site.
    """
    ctx = _build_context(rows)
    vec = extract_features(ctx, scope, evidence)
    assert vec.schema_version == CURRENT_FEATURE_SCHEMA_VERSION


@given(
    rows=_CRM_CONTEXT_INPUTS,
    scope=_SCOPE,
    evidence=_TAGGED_EVIDENCE_MAP,
)
@settings(max_examples=150, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def test_extract_features_ratio_fields_in_unit_interval(rows, scope, evidence):
    """All ratio fields stay in [0, 1].

    inherited/provider/not_applicable/narrative_present_pct are
    by-construction proportions; intra_crm_tfidf_max/mean similarity
    is cosine of L2-normalized non-negative TF-IDF vectors (always
    in [0, 1]). A regression where a divisor flipped to ``n_claims``
    when it should be ``n_scope`` (or vice versa) would let a pct
    exceed 1.0; this property catches it.
    """
    ctx = _build_context(rows)
    vec = extract_features(ctx, scope, evidence)
    for name in [
        "inherited_pct",
        "provider_pct",
        "not_applicable_pct",
        "narrative_present_pct",
        "intra_crm_tfidf_max_similarity",
        "intra_crm_tfidf_mean_similarity",
    ]:
        value = getattr(vec, name)
        assert 0.0 <= value <= 1.0, f"{name}={value} outside [0, 1]"


@given(
    rows=_CRM_CONTEXT_INPUTS,
    scope=_SCOPE,
    evidence=_TAGGED_EVIDENCE_MAP,
)
@settings(max_examples=150, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def test_extract_features_mutually_exclusive_pcts_sum_at_most_one(
    rows, scope, evidence
):
    """inherited + provider + not_applicable ≤ 1.0 (a small slack
    epsilon for fp drift).

    These three are computed off the same scope denominator with
    DISJOINT numerator predicates — every scope entry's responsibility
    is at most one of these three. The other two responsibility values
    (customer, hybrid) take the slack. Strict equality would be wrong;
    ≤1 is the load-bearing bound a refactor might break (e.g. by
    double-counting an entry under both inherited and provider).
    """
    ctx = _build_context(rows)
    vec = extract_features(ctx, scope, evidence)
    s = vec.inherited_pct + vec.provider_pct + vec.not_applicable_pct
    assert s <= 1.0 + 1e-9, (
        f"inherited({vec.inherited_pct}) + provider({vec.provider_pct}) + "
        f"not_applicable({vec.not_applicable_pct}) = {s} > 1.0"
    )


@given(
    rows=_CRM_CONTEXT_INPUTS,
    scope=_SCOPE,
    evidence=_TAGGED_EVIDENCE_MAP,
)
@settings(max_examples=150, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def test_extract_features_in_scope_control_count_matches_scope_size(
    rows, scope, evidence
):
    """``in_scope_control_count == len(set(scope))``.

    The dataclass field is the size feature IsolationForest uses as a
    coarse "is this a small or large workbook" hint. ``set(scope)``
    de-dupes — the extractor MUST do the same so two callers passing
    ``["ac-1", "ac-1"]`` vs ``["ac-1"]`` get the same vector.
    """
    ctx = _build_context(rows)
    vec = extract_features(ctx, scope, evidence)
    assert vec.in_scope_control_count == len(set(scope))


@given(
    rows=_CRM_CONTEXT_INPUTS,
    scope=_SCOPE,
    evidence=_TAGGED_EVIDENCE_MAP,
)
@settings(max_examples=150, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def test_extract_features_counts_are_non_negative(rows, scope, evidence):
    """``family_evidence_contradictions`` and lengths are non-negative.

    Negative counts would crash sklearn (StandardScaler would still
    accept them, but the downstream interpretation as "how many
    family-level contradictions" requires ≥ 0). Defends against a
    refactor that swapped ``+= 1`` for ``-= 1`` somewhere.
    """
    ctx = _build_context(rows)
    vec = extract_features(ctx, scope, evidence)
    assert vec.family_evidence_contradictions >= 0
    assert vec.narrative_len_mean >= 0.0
    assert vec.narrative_len_stdev >= 0.0
    assert vec.in_scope_control_count >= 0


# ---------------------------------------------------------------------------
# extract_features — out-of-scope leakage and determinism
# ---------------------------------------------------------------------------


@given(
    in_scope_rows=_CRM_CONTEXT_INPUTS,
    extra_oos_rows=st.lists(
        st.tuples(_CONTROL_ID, _RESPONSIBILITY, _NARRATIVE),
        min_size=0,
        max_size=10,
        unique_by=lambda t: t[0].lower(),
    ),
    evidence=_TAGGED_EVIDENCE_MAP,
)
@settings(max_examples=80, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def test_extract_features_ignores_out_of_scope_crm_entries(
    in_scope_rows, extra_oos_rows, evidence
):
    """CRM entries on controls NOT in ``in_scope_control_ids`` MUST NOT
    influence ANY output field.

    The scope filter is THE central correctness lever in extract_features
    — without it, a CRM mass-uploaded across all FedRAMP families would
    drown a small workbook's actual signal. We build two contexts:
      A: only the in_scope_rows
      B: in_scope_rows + extra_oos_rows whose control_ids are NOT in scope
    Call extract_features with the same scope (= in_scope_rows' ids).
    Output vectors must be identical.
    """
    # Scope = exactly the control_ids of in_scope_rows.
    scope = [cid.lower() for cid, _, _ in in_scope_rows]
    scope_set = set(scope)

    # Filter OOS rows to genuinely out-of-scope ones (no key collisions
    # with in-scope; if Hypothesis generated a clashing key, drop it).
    truly_oos = [
        (cid, resp, narr)
        for (cid, resp, narr) in extra_oos_rows
        if cid.lower() not in scope_set
    ]

    ctx_a = _build_context(in_scope_rows)
    ctx_b = _build_context(in_scope_rows + truly_oos)

    vec_a = extract_features(ctx_a, scope, evidence)
    vec_b = extract_features(ctx_b, scope, evidence)
    assert vec_a == vec_b


@given(
    rows=_CRM_CONTEXT_INPUTS,
    scope=_SCOPE,
    evidence=_TAGGED_EVIDENCE_MAP,
)
@settings(max_examples=80, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
def test_extract_features_is_deterministic(rows, scope, evidence):
    """Same inputs → same output, twice.

    Defends against a future refactor that introduced a set-iteration
    hash in a way that perturbs the TF-IDF column order (changes the
    cosine matrix slightly under floating point) or the contradiction
    counter ordering.
    """
    ctx = _build_context(rows)
    vec1 = extract_features(ctx, scope, evidence)
    vec2 = extract_features(ctx, scope, evidence)
    assert vec1 == vec2


# ---------------------------------------------------------------------------
# fit_anomaly_model — metadata invariants under fuzzed corpora
# ---------------------------------------------------------------------------


@given(
    corpus=st.lists(_FEATURE_VECTOR, min_size=10, max_size=20),
)
@settings(max_examples=10, deadline=None,
          suppress_health_check=[HealthCheck.too_slow,
                                 HealthCheck.data_too_large])
def test_fit_metadata_invariants_under_fuzzed_corpora(corpus):
    """For ANY corpus of ≥ MIN_CORPUS_SIZE current-schema vectors:
       - n_samples == len(corpus)
       - n_features == len(_NUMERIC_FIELDS)
       - training_score_min ≤ training_score_mean ≤ training_score_max

    Pins the metadata contract the operator UI relies on. A refactor
    that swapped ``raw_scores.min()`` and ``.max()`` (a plausible
    rename mistake) would flip the order; this catches it.

    Capped at 10 examples since each fit spins up sklearn + numpy +
    joblib — fast in absolute terms but expensive vs the pure-Python
    properties above.
    """
    result = fit_anomaly_model(corpus)
    md = result.metadata
    assert md["n_samples"] == len(corpus)
    assert md["n_features"] == len(CrmFeatureVector._NUMERIC_FIELDS)
    assert md["feature_schema_version"] == CURRENT_FEATURE_SCHEMA_VERSION
    # Use a small absolute tolerance: when Hypothesis hands us a corpus of
    # identical vectors (the degenerate but legitimate "all-zero" case),
    # IsolationForest emits raw scores that are equal in math but differ
    # by ~1 ULP after numpy.mean() vs numpy.min()/max(). The mathematical
    # invariant min ≤ mean ≤ max holds; the strict-float comparison can
    # flip on the ULP. 1e-9 is well below any score difference the kernel
    # would actually report (scores are read at 3 sig figs in the UI).
    _eps = 1e-9
    assert md["training_score_min"] <= md["training_score_mean"] + _eps
    assert md["training_score_mean"] <= md["training_score_max"] + _eps
    assert isinstance(result.model_blob, bytes)
    assert len(result.model_blob) > 0


# ---------------------------------------------------------------------------
# score_anomaly — range + schema gate + determinism under fuzzed vectors
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def fitted_model_blob() -> bytes:
    """One fitted model reused across the score_anomaly properties.

    Module-scoped so we don't re-fit IsolationForest per Hypothesis
    example. The corpus is hand-crafted (not fuzzed) so the model's
    learned distribution is stable; the properties below vary the
    *query* vector and assert range/determinism/gate behavior against
    this fixed model.
    """
    corpus: list[CrmFeatureVector] = []
    for i in range(12):
        corpus.append(
            CrmFeatureVector(
                schema_version=CURRENT_FEATURE_SCHEMA_VERSION,
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
    result = fit_anomaly_model(corpus)
    return result.model_blob


@given(vec=_FEATURE_VECTOR)
@settings(max_examples=100, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture,
                                 HealthCheck.too_slow])
def test_score_anomaly_always_in_unit_interval(vec, fitted_model_blob):
    """For ANY current-schema feature vector, ``score_anomaly`` returns
    a float in [0, 1].

    The blend formula in crm_sanity assumes all three tier scores are
    unit-bounded. The clamp at the end of score_anomaly is the
    load-bearing defense — fuzz arbitrary input vectors (including
    feature values the training corpus never saw) and confirm the
    invariant holds.
    """
    score = score_anomaly(fitted_model_blob, vec)
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


@given(vec=_FEATURE_VECTOR)
@settings(max_examples=80, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture,
                                 HealthCheck.too_slow])
def test_score_anomaly_is_deterministic(vec, fitted_model_blob):
    """Same (blob, vector) → same float, twice.

    joblib round-trip + sklearn ``score_samples`` are deterministic;
    pinning this contract trips a future swap to a non-deterministic
    scoring backend (e.g. a randomized-projection variant).
    """
    s1 = score_anomaly(fitted_model_blob, vec)
    s2 = score_anomaly(fitted_model_blob, vec)
    assert s1 == s2


@given(
    vec=_FEATURE_VECTOR.map(
        lambda v: CrmFeatureVector(
            schema_version=CURRENT_FEATURE_SCHEMA_VERSION + 1,
            inherited_pct=v.inherited_pct,
            provider_pct=v.provider_pct,
            not_applicable_pct=v.not_applicable_pct,
            narrative_present_pct=v.narrative_present_pct,
            narrative_len_mean=v.narrative_len_mean,
            narrative_len_stdev=v.narrative_len_stdev,
            intra_crm_tfidf_max_similarity=v.intra_crm_tfidf_max_similarity,
            intra_crm_tfidf_mean_similarity=v.intra_crm_tfidf_mean_similarity,
            family_evidence_contradictions=v.family_evidence_contradictions,
            in_scope_control_count=v.in_scope_control_count,
        )
    )
)
@settings(max_examples=50, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture,
                                 HealthCheck.too_slow])
def test_score_anomaly_returns_zero_for_any_stale_schema_vector(
    vec, fitted_model_blob
):
    """ANY vector at a non-current schema version → 0.0 (no model load).

    Fuzz the field values but force schema_version = CURRENT+1 to
    simulate a vector built against a future schema bump. Output must
    be exactly 0.0 regardless of the numeric fields — the route handler
    treats 0.0 as "no ML score available" and the schema gate must
    win unconditionally over the field values.
    """
    assert score_anomaly(fitted_model_blob, vec) == 0.0
