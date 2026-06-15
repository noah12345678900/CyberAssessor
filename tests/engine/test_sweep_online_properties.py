"""Property-based tests for the sweep_online weight updater's pure helpers.

The online SGD path (``update_weights_online``) is sklearn-bound and
exercised by the integration tests once a real triage dialog has produced
``SweepDecision`` rows. What's covered here are the *pure* helpers that
run on every fit and on every inference-time weight load:

    ``_signal_prefix``            — ``"host:server01"`` → ``"host"``
    ``_clip_coefficients``        — sign-constraint enforcer
    ``_hand_tuned_init_vector``   — deterministic v1 warm-start vector
    ``_active_weights_to_vector`` — SweepWeights row → 6-vector
    ``decision_to_features``      — SweepDecision row → FeatureRow|None

Beyond per-helper contracts this module pins two cross-helper invariants
the patent-supporting online learner depends on:

  1. **Sign constraint is total:** any output of ``_clip_coefficients``
     contains no negatives. A single sign-flipped weight written to
     ``SweepWeights`` would corrupt every subsequent ``score_candidate``
     call until an operator manually rolled back the row.

  2. **Vector order is load-bearing:** the order
     ``_hand_tuned_init_vector`` emits MUST match what
     ``_active_weights_to_vector`` emits from a row carrying those exact
     hand-tuned constants. If the two drift, the SGD warm start would
     blend the wrong column into the wrong feature and silently re-learn
     a permuted model on the next online pass.

Hypothesis is in the dev extras and imported via ``pytest.importorskip``
so a user running ``pytest`` without the dev install gets a clean skip
rather than a collection error.
"""

from __future__ import annotations

import json

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from cybersecurity_assessor.engine.sweep_online import (  # noqa: E402
    FEATURE_NAMES,
    FeatureRow,
    _active_weights_to_vector,
    _clip_coefficients,
    _hand_tuned_init_vector,
    _signal_prefix,
    decision_to_features,
)
from cybersecurity_assessor.evidence.sources.sweep import (  # noqa: E402
    _W_CONTROL_ID,
    _W_CRM_KEYWORD,
    _W_DOC_PREFIX,
    _W_FAMILY,
    _W_HOST,
    _W_PRIORITY_LINK,
)
from cybersecurity_assessor.models import SweepDecision, SweepWeights  # noqa: E402


# ---------------------------------------------------------------------------
# _signal_prefix — strict colon-split contract
# ---------------------------------------------------------------------------


# Avoid colons in the body so a generated text doesn't accidentally turn
# a "no-colon" case into a "with-colon" case.
_NO_COLON_TEXT = st.text(max_size=40).filter(lambda s: ":" not in s)


@given(s=_NO_COLON_TEXT)
def test_signal_prefix_no_colon_returns_empty(s: str) -> None:
    """A signal without ``:`` is malformed — the contract is empty string,
    not the bare token.

    The set-membership check in ``decision_to_features`` keys on prefixes
    that fall in ``FEATURE_NAMES``. Empty string is never a feature name,
    so a malformed signal silently contributes zero — which is correct.
    Returning the bare token instead would let, say, ``"host"`` (no
    colon) match the ``"host"`` feature even though the canonical wire
    format requires ``"host:<value>"``.
    """
    assert _signal_prefix(s) == ""


@given(
    prefix=st.text(
        alphabet=st.characters(min_codepoint=33, max_codepoint=126).filter(
            lambda c: c != ":"
        ),
        min_size=1,
        max_size=20,
    ),
    body=_NO_COLON_TEXT,
)
def test_signal_prefix_strips_and_lowercases(prefix: str, body: str) -> None:
    """``"  HoSt:server01  "`` → ``"host"``. Padding stripped, case folded.

    The eMASS-adjacent code paths occasionally upper-case identifiers
    when round-tripping through other tools; the prefix matcher must be
    case-insensitive or those signals silently stop counting.
    """
    raw = f"  {prefix}:{body}  "
    out = _signal_prefix(raw)
    assert out == prefix.strip().lower()


@given(
    a=_NO_COLON_TEXT.filter(lambda s: s.strip() != ""),
    b=st.text(max_size=20),
    c=st.text(max_size=20),
)
def test_signal_prefix_only_splits_on_first_colon(a: str, b: str, c: str) -> None:
    """Multi-colon signals (e.g. ``"host:srv:port"``) split on the FIRST
    colon — the prefix is everything before it.

    Hostnames and SharePoint URLs both legitimately contain colons in
    the body; the split limit must be 1 or a SharePoint path signal
    would lose its scheme half.
    """
    raw = f"{a}:{b}:{c}"
    assert _signal_prefix(raw) == a.strip().lower()


def test_signal_prefix_empty_string_returns_empty() -> None:
    """Concrete edge case: empty input has no colon → returns ``""``."""
    assert _signal_prefix("") == ""


def test_signal_prefix_bare_colon_returns_empty() -> None:
    """Concrete edge case: ``":foo"`` has empty prefix → returns ``""``."""
    assert _signal_prefix(":foo") == ""


# ---------------------------------------------------------------------------
# _clip_coefficients — sign constraint
# ---------------------------------------------------------------------------


_FINITE_FLOATS = st.floats(
    allow_nan=False,
    allow_infinity=False,
    min_value=-100.0,
    max_value=100.0,
    width=64,
)


@given(
    coefs=st.lists(
        _FINITE_FLOATS,
        min_size=len(FEATURE_NAMES),
        max_size=len(FEATURE_NAMES),
    )
)
def test_clip_coefficients_never_returns_negative(coefs: list[float]) -> None:
    """No element of the clipped output is < 0.

    Negative coefficients in ``SweepWeights`` would invert the contribution
    of a positive signal: a file that looks more on-boundary would score
    LOWER. The sign-constraint clipper is the single rail keeping a noisy
    SGD pass from poisoning the row that ``score_candidate`` reads on
    every triage open.
    """
    clipped, _warnings = _clip_coefficients(coefs)
    assert all(c >= 0.0 for c in clipped)


@given(
    coefs=st.lists(
        _FINITE_FLOATS,
        min_size=len(FEATURE_NAMES),
        max_size=len(FEATURE_NAMES),
    )
)
def test_clip_coefficients_preserves_non_negative(coefs: list[float]) -> None:
    """Each non-negative input survives the clip unchanged (as ``float``).

    Guards against a future refactor that adds a "shrinkage" pass — the
    clipper's sole job is sign enforcement; if it ever starts shrinking
    values, the active-row weights would drift below the surface
    threshold on the next online pass and silently pre-check fewer rows.
    """
    clipped, _warnings = _clip_coefficients(coefs)
    for original, out in zip(coefs, clipped):
        if original >= 0:
            assert out == float(original)


@given(
    coefs=st.lists(
        _FINITE_FLOATS,
        min_size=len(FEATURE_NAMES),
        max_size=len(FEATURE_NAMES),
    )
)
def test_clip_coefficients_negatives_become_zero(coefs: list[float]) -> None:
    """Each negative input becomes exactly ``0.0`` in the output."""
    clipped, _warnings = _clip_coefficients(coefs)
    for original, out in zip(coefs, clipped):
        if original < 0:
            assert out == 0.0


@given(
    coefs=st.lists(
        _FINITE_FLOATS,
        min_size=len(FEATURE_NAMES),
        max_size=len(FEATURE_NAMES),
    )
)
def test_clip_coefficients_warning_count_matches_negative_count(
    coefs: list[float],
) -> None:
    """One warning is emitted for every clipped negative — no more, no less.

    The warning list is persisted into ``SweepWeights.notes`` for audit.
    Dropping a warning would hide a clip from a reviewing operator;
    double-emitting would falsely inflate the apparent label noise.
    """
    _clipped, warnings = _clip_coefficients(coefs)
    expected_count = sum(1 for c in coefs if c < 0)
    assert len(warnings) == expected_count


@given(
    coefs=st.lists(
        _FINITE_FLOATS,
        min_size=len(FEATURE_NAMES),
        max_size=len(FEATURE_NAMES),
    )
)
def test_clip_coefficients_is_idempotent(coefs: list[float]) -> None:
    """Clipping the clipped output is a no-op AND emits no new warnings.

    A second pass with all-non-negative input must produce identical
    values and zero warnings — otherwise the online updater would log
    spurious "clipped" messages on every refit of an already-clean row.
    """
    once, warnings_once = _clip_coefficients(coefs)
    twice, warnings_twice = _clip_coefficients(once)
    assert once == twice
    assert warnings_twice == []


@given(
    coefs=st.lists(
        _FINITE_FLOATS,
        min_size=len(FEATURE_NAMES),
        max_size=len(FEATURE_NAMES),
    )
)
def test_clip_coefficients_output_length_matches_feature_names(
    coefs: list[float],
) -> None:
    """Output length equals ``len(FEATURE_NAMES)`` for matching input.

    The caller spreads ``clipped[0]..clipped[5]`` into the 6 weight_*
    fields of ``SweepWeights``; a length drift here would either raise
    an IndexError on persist or silently store the wrong column.
    """
    clipped, _warnings = _clip_coefficients(coefs)
    assert len(clipped) == len(FEATURE_NAMES)


@given(
    coefs=st.lists(
        _FINITE_FLOATS,
        min_size=len(FEATURE_NAMES),
        max_size=len(FEATURE_NAMES),
    )
)
def test_clip_coefficients_output_is_float_type(coefs: list[float]) -> None:
    """Every element of the clipped output is a ``float`` (not int, not bool).

    SQLModel's column type for ``weight_*`` is float; an int slipping
    through would write fine but break downstream code that uses
    ``isinstance(w, float)`` for validation.
    """
    clipped, _warnings = _clip_coefficients(coefs)
    for out in clipped:
        assert type(out) is float  # noqa: E721 — exact type, not isinstance


# ---------------------------------------------------------------------------
# _hand_tuned_init_vector / _active_weights_to_vector — order agreement
# ---------------------------------------------------------------------------


def test_hand_tuned_init_vector_length_matches_feature_names() -> None:
    """The warm-start vector has exactly one element per feature.

    A length mismatch would crash the SGD warm-start at numpy reshape time
    — but only after the operator has clicked Ingest, so the failure is
    user-visible. Pin the length here so a future feature add must update
    BOTH the vector and the test.
    """
    assert len(_hand_tuned_init_vector()) == len(FEATURE_NAMES)


def test_hand_tuned_init_vector_matches_source_constants() -> None:
    """The warm-start vector is the hand-tuned ``_W_*`` constants from
    ``evidence.sources.sweep`` in FEATURE_NAMES order.

    The values are imported, not copied — but a refactor could re-order
    the imports or substitute a constant. Pin the exact mapping so a
    silent reorder breaks here, not in production scoring.
    """
    expected = [
        _W_HOST,
        _W_CONTROL_ID,
        _W_FAMILY,
        _W_CRM_KEYWORD,
        _W_DOC_PREFIX,
        _W_PRIORITY_LINK,
    ]
    assert _hand_tuned_init_vector() == expected


def test_active_weights_to_vector_none_returns_hand_tuned_defaults() -> None:
    """``_active_weights_to_vector(None)`` equals ``_hand_tuned_init_vector()``.

    No active row means first-run user — the SGD warm-start must fall
    back to the hand-tuned defaults so the first fit doesn't crawl from
    zero on a 25-row mini-batch.
    """
    assert _active_weights_to_vector(None) == _hand_tuned_init_vector()


@given(
    host=_FINITE_FLOATS,
    control=_FINITE_FLOATS,
    family=_FINITE_FLOATS,
    crm=_FINITE_FLOATS,
    doc=_FINITE_FLOATS,
    priority=_FINITE_FLOATS,
)
def test_active_weights_to_vector_returns_canonical_order(
    host: float,
    control: float,
    family: float,
    crm: float,
    doc: float,
    priority: float,
) -> None:
    """A populated ``SweepWeights`` row maps to a 6-vector in FEATURE_NAMES
    order: host, control, family, crm, doc-prefix, priority.

    The SGD warm-start blends ``clf.coef_`` toward this vector elementwise.
    If the column order drifted, the model would learn (e.g.) the host
    weight as the crm-keyword weight on the next online pass — a silent
    permutation that's invisible until score histograms start looking
    wrong.
    """
    weights = SweepWeights(
        source="manual",
        weight_host=host,
        weight_control_id=control,
        weight_family=family,
        weight_crm_keyword=crm,
        weight_doc_prefix=doc,
        weight_priority_link=priority,
    )
    out = _active_weights_to_vector(weights)
    assert out == [host, control, family, crm, doc, priority]


@given(
    host=_FINITE_FLOATS,
    control=_FINITE_FLOATS,
    family=_FINITE_FLOATS,
    crm=_FINITE_FLOATS,
    doc=_FINITE_FLOATS,
    priority=_FINITE_FLOATS,
)
def test_active_weights_to_vector_output_is_float_type(
    host: float,
    control: float,
    family: float,
    crm: float,
    doc: float,
    priority: float,
) -> None:
    """Every element is a ``float`` even if the model column held an int.

    Sqlite stores numeric columns loosely; an int could leak through. The
    explicit ``float(...)`` cast in the helper guards numpy's array
    construction which would otherwise infer dtype=int64 and downstream
    matrix arithmetic against a float warm-start vector would broadcast
    in unexpected ways.
    """
    weights = SweepWeights(
        source="manual",
        weight_host=host,
        weight_control_id=control,
        weight_family=family,
        weight_crm_keyword=crm,
        weight_doc_prefix=doc,
        weight_priority_link=priority,
    )
    out = _active_weights_to_vector(weights)
    for v in out:
        assert type(v) is float  # noqa: E721 — exact type, not isinstance


# ---------------------------------------------------------------------------
# decision_to_features — pure conversion from SweepDecision
# ---------------------------------------------------------------------------


def _make_decision(
    signals_json: str,
    included: bool = True,
    decision_id: int | None = 1,
) -> SweepDecision:
    """Minimal SweepDecision factory for keying tests on signals only.

    Other columns are populated with sentinel values that pass SQLModel
    validation but never get inspected by ``decision_to_features``.
    """
    return SweepDecision(
        id=decision_id,
        workbook_id=1,
        candidate_path="/sentinel",
        candidate_name="sentinel",
        score_at_decision=0.5,
        signals_json=signals_json,
        proposed_ccis_json="[]",
        fingerprint_snapshot_json="{}",
        weights_version_id=1,
        included=included,
        auto_prechecked=False,
    )


@given(
    raw=st.text(max_size=200).filter(
        lambda s: not s.strip().startswith("[") and not s.strip().startswith("{")
    )
)
def test_decision_to_features_unparseable_json_returns_none(raw: str) -> None:
    """Non-JSON ``signals_json`` returns None — the row is dropped from
    the fit batch.

    Skipping is required: a row that decoded into ``[]`` would fit a
    zero-vector with label=included, teaching the model "no signals →
    kept" which is the OPPOSITE of the surface heuristic. Better to drop
    the row entirely until an operator notices the data corruption.
    """
    decision = _make_decision(signals_json=raw)
    assert decision_to_features(decision) is None


@given(
    payload=st.one_of(
        st.text(max_size=20).map(json.dumps),
        st.integers().map(json.dumps),
        st.booleans().map(json.dumps),
        st.dictionaries(st.text(max_size=10), st.text(max_size=10)).map(json.dumps),
    )
)
def test_decision_to_features_non_list_json_returns_none(payload: str) -> None:
    """JSON that decodes to a string/int/bool/object (not a list) returns
    None.

    Guards against schema drift where the column became, say, a dict
    keyed by prefix. The contract is "list of strings or skip" — never
    "make a best effort to coerce".
    """
    decision = _make_decision(signals_json=payload)
    assert decision_to_features(decision) is None


@given(
    signals=st.lists(
        st.text(max_size=30).map(
            lambda s: s if ":" in s else f"unknown:{s}"
        ),
        max_size=20,
    ),
    included=st.booleans(),
)
def test_decision_to_features_returns_correct_length(
    signals: list[str], included: bool
) -> None:
    """Output ``features`` tuple length always equals ``len(FEATURE_NAMES)``.

    The SGD ``X`` matrix is shaped ``(n_rows, 6)``; a length drift here
    would crash numpy's array() at fit time. Pin the length so the
    failure shows up at unit-test time, not user-click time.
    """
    decision = _make_decision(signals_json=json.dumps(signals), included=included)
    out = decision_to_features(decision)
    assert out is not None
    assert len(out.features) == len(FEATURE_NAMES)


@given(
    signals=st.lists(
        st.text(max_size=30).map(
            lambda s: s if ":" in s else f"unknown:{s}"
        ),
        max_size=20,
    ),
    included=st.booleans(),
)
def test_decision_to_features_features_are_binary(
    signals: list[str], included: bool
) -> None:
    """Each feature value is exactly ``0.0`` or ``1.0`` — strict binary.

    Logistic-regression SGD expects calibrated binary indicators here;
    a fractional value would silently let one row contribute partial
    weight, breaking the additive-linear interpretation that
    ``score_candidate`` assumes at inference.
    """
    decision = _make_decision(signals_json=json.dumps(signals), included=included)
    out = decision_to_features(decision)
    assert out is not None
    for v in out.features:
        assert v in (0.0, 1.0)


@given(included=st.booleans())
def test_decision_to_features_label_matches_included(included: bool) -> None:
    """``label == 1`` iff ``decision.included is True``; else ``0``.

    Label inversion would teach the model the exact opposite of the
    operator's intent — every triage click would push the scorer the
    wrong way. Pin this explicitly because the cast from bool to int is
    one of those "obviously correct" bits that's easy to flip in a
    refactor.
    """
    decision = _make_decision(signals_json="[]", included=included)
    out = decision_to_features(decision)
    assert out is not None
    assert out.label == (1 if included else 0)


@given(
    case=st.sampled_from(["host", "HOST", "Host", "hOsT", "  host  "]),
    value=st.text(max_size=20),
)
def test_decision_to_features_prefix_matching_is_case_insensitive(
    case: str, value: str
) -> None:
    """Mixed-case / padded ``host:`` prefix still flips the host feature.

    Inherits from ``_signal_prefix``'s case-folding; this test pins that
    the round-trip through json + the set comprehension preserves the
    fold. A regression that bypassed ``_signal_prefix`` (e.g. by manual
    splitting) would let upper-case signals stop counting silently.
    """
    decision = _make_decision(
        signals_json=json.dumps([f"{case}:{value}"]),
        included=True,
    )
    out = decision_to_features(decision)
    assert out is not None
    host_idx = FEATURE_NAMES.index("host")
    assert out.features[host_idx] == 1.0


def test_decision_to_features_unknown_prefix_contributes_zero() -> None:
    """A signal with an unrecognized prefix doesn't fire any feature.

    The feature vector keys on ``FEATURE_NAMES`` — any prefix outside
    that set is silently ignored. This is the correct behavior (avoid
    schema-drift crashes) but the test pins it so a future "raise on
    unknown" refactor is forced to reckon with the existing contract.
    """
    decision = _make_decision(
        signals_json=json.dumps(["does-not-exist:value"]),
        included=True,
    )
    out = decision_to_features(decision)
    assert out is not None
    assert out.features == tuple(0.0 for _ in FEATURE_NAMES)


def test_decision_to_features_returns_feature_row_instance() -> None:
    """Output type is ``FeatureRow`` (the frozen dataclass).

    Concrete type check guards against a refactor that swaps in a bare
    tuple or dict — callers iterate ``.features`` and ``.label``
    attributes, which would AttributeError on a tuple at runtime.
    """
    decision = _make_decision(signals_json="[]", included=True)
    out = decision_to_features(decision)
    assert isinstance(out, FeatureRow)


@given(
    signals=st.lists(
        st.one_of(
            st.text(max_size=30).map(lambda s: f"host:{s}"),
            st.integers(),  # non-string list element
            st.none(),
            st.booleans(),
        ),
        max_size=10,
    ),
)
def test_decision_to_features_skips_non_string_list_elements(
    signals: list[object],
) -> None:
    """Non-string elements in the signals list are silently skipped.

    The list might legitimately carry a stray null from a broken sql
    cast or an int from a schema drift; the contract is "do the best you
    can with the strings and ignore the rest" so one bad element doesn't
    drop the whole row.
    """
    decision = _make_decision(signals_json=json.dumps(signals), included=True)
    out = decision_to_features(decision)
    # Either the list parses (always — json.dumps round-trips) and we
    # get a FeatureRow, OR we get None — never an exception.
    assert out is None or isinstance(out, FeatureRow)


def test_decision_to_features_decision_id_passthrough() -> None:
    """``FeatureRow.decision_id`` carries the input ``SweepDecision.id``."""
    decision = _make_decision(signals_json="[]", included=True, decision_id=12345)
    out = decision_to_features(decision)
    assert out is not None
    assert out.decision_id == 12345


def test_decision_to_features_null_decision_id_becomes_negative_one() -> None:
    """A SweepDecision without an id (transient, unflushed) maps to -1.

    The sentinel is load-bearing — ``_mark_consumed`` filters on real
    ids, and -1 is unambiguously non-real so a transient row never gets
    marked consumed by accident.
    """
    decision = _make_decision(signals_json="[]", included=True, decision_id=None)
    out = decision_to_features(decision)
    assert out is not None
    assert out.decision_id == -1
