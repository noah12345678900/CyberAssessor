"""Property-based tests for the CRM suspicion-scoring kernel.

``engine/crm_sanity.py`` is the adversarial guard on top of the CRM
short-circuit at ``Assessor._finalize_crm_decision`` — a single
vendor-supplied document silently flips potentially hundreds of
assessment verdicts (provider→NA, inherited→COMPLIANT, etc.). The
overlay-default-local rule protects against MISSING CRM data; this
module is the WRONG-data guard. Until now it has had zero direct test
coverage despite 548 LOC of decision logic.

Invariants proven here cover the pure-helper surface — the heuristics
and the blend math — which are session-free, take dataclass inputs, and
can be exercised in isolation from the embeddings provider and the
IsolationForest blob.

* ``_blend`` — output always in ``[0, 1]``; weight redistribution math
  is correct when ML / narrative tiers drop out; matches a hand-computed
  closed form for the all-three-tiers-present case.
* ``_family_of`` — pure lowercaser; idempotent; matches the OSCAL
  ``family-num.enhancement`` shape the rest of the engine uses as a
  join key.
* ``_eval_high_inheritance`` — severity bucketing follows the documented
  thresholds (warn at 70%, alert at 90%); component score stays in
  ``[0, 1]``; never raises on empty scope.
* ``_eval_local_evidence_contradiction`` — fires iff at least one family
  is fully off-loaded AND has tagged evidence; component saturates at 5
  contradicting families.
* ``_eval_narrative_poverty`` — only counts inherited/provider/hybrid
  claims (NA does not require narrative justification); component
  ramps linearly to ``1.0`` at 60% empty.
* ``_build_per_family`` — sum of per-responsibility counters equals the
  family's ``n_entries`` for the five tracked responsibility strings.

Hypothesis is in the dev extras; the module imports it lazily via
``pytest.importorskip`` so a user running ``pytest`` without the dev
install gets a clean skip rather than a collection error.
"""

from __future__ import annotations

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from cybersecurity_assessor.engine.crm_context import CrmEntry  # noqa: E402
from cybersecurity_assessor.engine.crm_sanity import (  # noqa: E402
    BLEND_W_HEURISTIC,
    BLEND_W_ML_ANOMALY,
    BLEND_W_NARRATIVE,
    HIGH_INHERITANCE_ALERT,
    HIGH_INHERITANCE_WARN,
    NARRATIVE_POVERTY_THRESHOLD,
    _blend,
    _build_per_family,
    _eval_high_inheritance,
    _eval_local_evidence_contradiction,
    _eval_narrative_poverty,
    _family_of,
)

# Responsibility values the heuristics treat as "off-loaded" — i.e. the
# vendor took the burden, so the assessor never validates locally. Mirrors
# the literal sets in crm_sanity.py; if the production module ever extends
# this list, both the source and these tests should evolve together.
_OFF_LOADED_RESPONSIBILITIES = ("inherited", "provider", "not_applicable")
_LOCAL_RESPONSIBILITIES = ("customer", "hybrid")
_ALL_RESPONSIBILITIES = _OFF_LOADED_RESPONSIBILITIES + _LOCAL_RESPONSIBILITIES

# Real OSCAL families pulled from the catalog families list, so the
# _family_of fuzz exercises strings that will actually appear in
# production data.
_NIST_FAMILY_TOKENS = (
    "ac", "at", "au", "ca", "cm", "cp", "ia", "ir", "ma", "mp", "pe",
    "pl", "pm", "ps", "ra", "sa", "sc", "si", "sr",
)


def _make_entry(
    control_id: str,
    responsibility: str | None,
    narrative: str | None = None,
) -> CrmEntry:
    """Minimal CrmEntry factory — only the three heuristic-touched
    fields matter, source_baseline_id is positional-required noise.
    """
    return CrmEntry(
        control_id=control_id,
        responsibility=responsibility,
        narrative=narrative,
        source_baseline_id=1,
    )


# ---------------------------------------------------------------------------
# _blend — weight redistribution + clipping
# ---------------------------------------------------------------------------


@given(
    h=st.floats(min_value=0.0, max_value=1.0),
    m=st.one_of(st.none(), st.floats(min_value=0.0, max_value=1.0)),
    nq=st.one_of(st.none(), st.floats(min_value=0.0, max_value=1.0)),
)
def test_blend_output_always_in_unit_interval(
    h: float, m: float | None, nq: float | None
) -> None:
    """For any valid (heuristic, ml_anomaly, narrative_quality) triple,
    ``_blend`` returns a value in ``[0, 1]``.

    The UI banner buckets by hard thresholds (0.30 / 0.60). A score that
    leaks above 1.0 or below 0.0 would either always-alert or always-clean
    silently, defeating the entire suspicion gate.
    """
    out = _blend(h, m, nq)
    assert 0.0 <= out <= 1.0


@given(h=st.floats(min_value=0.0, max_value=1.0))
def test_blend_heuristic_only_returns_heuristic_value(h: float) -> None:
    """When both ML and narrative tiers are missing, the result equals
    the heuristic value — the redistribution math must not introduce a
    silent floor or shrinkage on cold-start CRMs (the common case before
    the IsolationForest corpus reaches MIN_CORPUS_SIZE).
    """
    assert _blend(h, None, None) == pytest.approx(h)


@given(x=st.floats(min_value=0.0, max_value=1.0))
def test_blend_all_three_equal_returns_same_value(x: float) -> None:
    """When all three tiers agree on the same suspicion level ``x``, the
    blend is exactly ``x`` — proves the per-tier weights sum to 1.0 and
    that the closed-form is a true weighted average.

    Note narrative_quality enters as ``(1 - quality)`` per
    ``_blend``'s contract, so we feed ``(1 - x)`` for narrative_quality
    to express "same suspicion contribution from all three tiers".
    """
    out = _blend(x, x, 1.0 - x)
    assert out == pytest.approx(x)


def test_blend_documented_weights_sum_to_one() -> None:
    """Sanity guard: if a future refactor changes the constants without
    updating the redistribution math, the closed-form blend stops
    matching its docstring claim. Pin the weights here.
    """
    assert BLEND_W_HEURISTIC + BLEND_W_ML_ANOMALY + BLEND_W_NARRATIVE == pytest.approx(1.0)


@given(
    h=st.floats(min_value=0.0, max_value=1.0),
    m=st.floats(min_value=0.0, max_value=1.0),
)
def test_blend_no_narrative_uses_heuristic_and_ml_only(h: float, m: float) -> None:
    """When narrative_quality is None, the result equals the weighted
    average of heuristic + ml renormalized to their two-tier weights —
    closed-form check for the common "embeddings provider unavailable"
    branch.
    """
    expected = (BLEND_W_HEURISTIC * h + BLEND_W_ML_ANOMALY * m) / (
        BLEND_W_HEURISTIC + BLEND_W_ML_ANOMALY
    )
    assert _blend(h, m, None) == pytest.approx(expected)


# ---------------------------------------------------------------------------
# _family_of — lowercase-and-split string normalizer
# ---------------------------------------------------------------------------


@given(
    fam=st.sampled_from(_NIST_FAMILY_TOKENS),
    num=st.integers(min_value=1, max_value=99),
    enh=st.one_of(st.none(), st.integers(min_value=1, max_value=99)),
)
def test_family_of_returns_lowercase_family_token(
    fam: str, num: int, enh: int | None
) -> None:
    """``ac-2`` → ``ac``, ``AC-2.1`` → ``ac``. The per-family aggregation
    in ``_build_per_family`` joins on this; case drift between upstream
    catalog ids and the family key would silently scatter the same family
    across two buckets.
    """
    cid = f"{fam.upper()}-{num}" + (f".{enh}" if enh is not None else "")
    assert _family_of(cid) == fam


def test_family_of_empty_string_returns_empty() -> None:
    """Empty control_id (defensive — should never happen post-resolution)
    returns ``""`` rather than raising. The eval helpers drop empty
    families via ``if not fam: continue``, so this contract is the gate
    that keeps a malformed row from crashing the whole report.
    """
    assert _family_of("") == ""


@given(s=st.text(max_size=30))
def test_family_of_is_idempotent(s: str) -> None:
    """``_family_of(_family_of(x)) == _family_of(x)``. The family token
    has no hyphens by construction (everything after the first ``-`` is
    discarded), so a second pass is a no-op. Idempotence guards against
    a refactor that adds normalization steps which themselves emit
    hyphens.
    """
    once = _family_of(s)
    twice = _family_of(once)
    assert once == twice


# ---------------------------------------------------------------------------
# _eval_high_inheritance — severity bucketing + component clamping
# ---------------------------------------------------------------------------


@given(
    responsibilities=st.lists(
        st.sampled_from(_ALL_RESPONSIBILITIES),
        min_size=0,
        max_size=50,
    ),
)
def test_eval_high_inheritance_component_in_unit_interval(
    responsibilities: list[str],
) -> None:
    """Component score is always in ``[0, 1]`` regardless of input mix.

    The score feeds the heuristic ``max(...)`` aggregator; a value
    outside ``[0, 1]`` would either drown out every other heuristic or
    silently sink the overall score below the alert threshold.
    """
    entries = [_make_entry(f"ac-{i}", r) for i, r in enumerate(responsibilities)]
    n_scope = len(entries)
    _, component = _eval_high_inheritance(entries, n_scope)
    assert 0.0 <= component <= 1.0


def test_eval_high_inheritance_empty_scope_returns_no_flag() -> None:
    """``n_scope=0`` short-circuits to ``(None, 0.0)``. Division by zero
    would crash the entire suspicion report; an empty CRM (zero in-scope
    controls) must degrade gracefully.
    """
    flag, component = _eval_high_inheritance([], 0)
    assert flag is None
    assert component == 0.0


@given(
    n_off=st.integers(min_value=0, max_value=20),
    n_local=st.integers(min_value=0, max_value=20),
)
def test_eval_high_inheritance_severity_matches_threshold(
    n_off: int, n_local: int,
) -> None:
    """Flag severity is ``alert`` at ≥90% off-loaded, ``warn`` at ≥70%,
    None below. Pinned to the documented constants — a regression that
    swapped warn/alert order (or shifted the threshold by 1pp) would
    silently miss the most-suspicious CRMs while flagging the
    moderately-claimed ones.
    """
    if n_off + n_local == 0:
        return  # covered by the empty-scope test
    entries = (
        [_make_entry(f"ac-{i}", "inherited") for i in range(n_off)]
        + [_make_entry(f"ac-{i + n_off}", "customer") for i in range(n_local)]
    )
    n_scope = len(entries)
    flag, _ = _eval_high_inheritance(entries, n_scope)
    pct = n_off / n_scope
    if pct >= HIGH_INHERITANCE_ALERT:
        assert flag is not None and flag.severity == "alert"
    elif pct >= HIGH_INHERITANCE_WARN:
        assert flag is not None and flag.severity == "warn"
    else:
        assert flag is None


@given(n=st.integers(min_value=1, max_value=30))
def test_eval_high_inheritance_all_off_loaded_alerts_with_component_one(n: int) -> None:
    """100% off-loaded scope → alert flag and component score 1.0.
    The asymptotic case is the strongest signal we have; if the
    component ever floored below 1.0 here, the blend could under-rank
    a vendor that claimed everything.
    """
    entries = [_make_entry(f"ac-{i}", "provider") for i in range(n)]
    flag, component = _eval_high_inheritance(entries, n)
    assert flag is not None and flag.severity == "alert"
    assert component == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# _eval_local_evidence_contradiction — fires iff offload AND local evidence
# ---------------------------------------------------------------------------


@given(
    n_inherited=st.integers(min_value=1, max_value=10),
    evidence_count=st.integers(min_value=1, max_value=10),
)
def test_contradiction_fires_when_offloaded_family_has_evidence(
    n_inherited: int, evidence_count: int,
) -> None:
    """A family with all entries off-loaded AND tagged evidence → alert.

    This is the LITERAL contradiction case: vendor said "we handle it,
    you don't need to assess locally" — but the workbook already has
    locally-collected evidence for that family. The hardest signal in
    the entire suspicion suite; must not miss this case.
    """
    entries = [_make_entry(f"ac-{i}", "inherited") for i in range(n_inherited)]
    tagged = {"ac": evidence_count}
    flag, component = _eval_local_evidence_contradiction(entries, tagged)
    assert flag is not None
    assert flag.severity == "alert"
    assert "ac" in flag.details["families"]
    assert 0.0 < component <= 1.0


@given(
    n_inherited=st.integers(min_value=1, max_value=10),
)
def test_contradiction_no_evidence_no_flag(n_inherited: int) -> None:
    """Off-loaded family with NO local evidence → no flag, component 0.

    The vendor's claim is plausible when we have nothing locally to
    contradict it; missing-data is handled by ``high_inheritance``,
    not this heuristic.
    """
    entries = [_make_entry(f"ac-{i}", "inherited") for i in range(n_inherited)]
    flag, component = _eval_local_evidence_contradiction(entries, {})
    assert flag is None
    assert component == 0.0


@given(
    n_customer=st.integers(min_value=1, max_value=10),
    evidence_count=st.integers(min_value=1, max_value=10),
)
def test_contradiction_local_responsibility_with_evidence_no_flag(
    n_customer: int, evidence_count: int,
) -> None:
    """Family marked ``customer`` (we own it) WITH local evidence is the
    HAPPY path, not a contradiction — vendor correctly said "this is on
    you" and we did the work. Heuristic must not fire here.
    """
    entries = [_make_entry(f"ac-{i}", "customer") for i in range(n_customer)]
    tagged = {"ac": evidence_count}
    flag, component = _eval_local_evidence_contradiction(entries, tagged)
    assert flag is None
    assert component == 0.0


@given(n_families=st.integers(min_value=6, max_value=15))
def test_contradiction_component_saturates_at_five_families(n_families: int) -> None:
    """Component caps at 1.0 once five families contradict. Beyond that
    the heuristic can't intensify further (max ``score = max(components)``
    upstream is already 1.0); pins the documented saturation behavior.
    """
    families = list(_NIST_FAMILY_TOKENS[:n_families])
    entries = [
        _make_entry(f"{fam}-1", "inherited") for fam in families
    ]
    tagged = {fam: 3 for fam in families}
    _, component = _eval_local_evidence_contradiction(entries, tagged)
    assert component == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# _eval_narrative_poverty — only inherited/provider/hybrid count as claims
# ---------------------------------------------------------------------------


@given(
    n_with_narrative=st.integers(min_value=0, max_value=10),
    n_empty=st.integers(min_value=0, max_value=10),
)
def test_narrative_poverty_component_in_unit_interval(
    n_with_narrative: int, n_empty: int,
) -> None:
    """Component is in ``[0, 1]`` for any input mix.

    Even when poverty is 100% (every claim empty), the ramp tops out at
    ``1.0`` (since ``component = min(1.0, pct / 0.6)``). A regression that
    forgot the cap would leak ``1.67`` into the blend at 100% poverty.
    """
    entries = (
        [_make_entry(f"ac-{i}", "inherited", "real narrative") for i in range(n_with_narrative)]
        + [_make_entry(f"ac-{i + n_with_narrative}", "inherited", None) for i in range(n_empty)]
    )
    _, component = _eval_narrative_poverty(entries)
    assert 0.0 <= component <= 1.0


@given(n=st.integers(min_value=1, max_value=20))
def test_narrative_poverty_not_applicable_does_not_count_as_claim(n: int) -> None:
    """``not_applicable`` entries are EXCLUDED from the claim denominator.

    The rule is "vendor took credit (inherited/provider/hybrid) without
    justifying it". Saying "this control doesn't apply" doesn't require
    a narrative — it requires a scope decision. A regression that lumped
    NA into the poverty check would flag every minimum-baseline CRM as
    narrative-poor.
    """
    entries = [
        _make_entry(f"ac-{i}", "not_applicable", None) for i in range(n)
    ]
    flag, component = _eval_narrative_poverty(entries)
    assert flag is None
    assert component == 0.0


@given(n=st.integers(min_value=1, max_value=20))
def test_narrative_poverty_all_claims_have_narrative_no_flag(n: int) -> None:
    """100% narrative-present → no flag, component 0.

    Confirms the heuristic is silent on a well-documented CRM; suspicion
    score from this tier must be exactly zero so the blend reflects only
    the other tiers' contribution.
    """
    entries = [_make_entry(f"ac-{i}", "inherited", "justification") for i in range(n)]
    flag, component = _eval_narrative_poverty(entries)
    assert flag is None
    assert component == 0.0


@given(n=st.integers(min_value=4, max_value=20))
def test_narrative_poverty_flag_fires_above_threshold(n: int) -> None:
    """When > 30% of claims have empty narrative, the flag fires.

    Use a 50% poverty mix to be safely above the 30% trigger regardless
    of integer rounding for small ``n``.
    """
    half = n // 2
    entries = (
        [_make_entry(f"ac-{i}", "inherited", "ok") for i in range(half)]
        + [_make_entry(f"ac-{i + half}", "inherited", None) for i in range(n - half)]
    )
    pct = (n - half) / n
    flag, _ = _eval_narrative_poverty(entries)
    if pct >= NARRATIVE_POVERTY_THRESHOLD:
        assert flag is not None
        assert flag.severity == "warn"


# ---------------------------------------------------------------------------
# _build_per_family — sum invariant + bucket initialization
# ---------------------------------------------------------------------------


@given(
    responsibilities=st.lists(
        st.sampled_from(_ALL_RESPONSIBILITIES),
        min_size=1,
        max_size=30,
    ),
)
def test_build_per_family_responsibility_counters_sum_to_n_entries(
    responsibilities: list[str],
) -> None:
    """Per-family ``n_<resp>`` counters sum to that family's ``n_entries``.

    All five responsibility strings produced by the sampler have a
    matching bucket key — so the per-resp sum must equal the entry
    count. A drift here (a missed responsibility, a typo'd bucket key)
    would silently under-count a category and skew the UI's family
    breakdown.
    """
    entries = [_make_entry("ac-1", r) for r in responsibilities]
    per_family = _build_per_family(entries, {})
    bucket = per_family["ac"]
    bucket_sum = (
        bucket["n_inherited"]
        + bucket["n_provider"]
        + bucket["n_not_applicable"]
        + bucket["n_customer"]
        + bucket["n_hybrid"]
    )
    assert bucket_sum == bucket["n_entries"]
    assert bucket["n_entries"] == len(responsibilities)


@given(
    responsibilities=st.lists(
        st.sampled_from(_ALL_RESPONSIBILITIES),
        min_size=1,
        max_size=20,
    ),
    n_with_narr=st.integers(min_value=0, max_value=20),
)
def test_build_per_family_narrative_count_never_exceeds_entries(
    responsibilities: list[str], n_with_narr: int,
) -> None:
    """``n_with_narrative <= n_entries`` for every family.

    A regression that double-counted (e.g. incremented per pass through
    a loop instead of once per entry) would let the narrative ratio
    exceed 1.0 and mis-trigger the narrative_poverty heuristic.
    """
    n_with_narr = min(n_with_narr, len(responsibilities))
    entries = [
        _make_entry("ac-1", r, "real narrative" if i < n_with_narr else None)
        for i, r in enumerate(responsibilities)
    ]
    per_family = _build_per_family(entries, {})
    bucket = per_family["ac"]
    assert bucket["n_with_narrative"] <= bucket["n_entries"]


def test_build_per_family_empty_entries_returns_empty_dict() -> None:
    """No entries → empty dict (not a dict of empty buckets).

    Downstream code uses ``if not per_family:`` to short-circuit the
    "expand details" panel render; a dict of zero-buckets would render
    an empty panel with a useless header.
    """
    assert _build_per_family([], {}) == {}


@given(
    families=st.lists(
        st.sampled_from(_NIST_FAMILY_TOKENS),
        min_size=1,
        max_size=5,
        unique=True,
    ),
)
def test_build_per_family_partitions_by_family(families: list[str]) -> None:
    """Each entry contributes to exactly its own family's bucket.

    Sum of ``n_entries`` across families equals the total entry count;
    a leak between buckets (e.g. a shared mutable default) would
    over-count and inflate the per-family fractions in the UI panel.
    """
    entries = [_make_entry(f"{fam}-1", "inherited") for fam in families]
    per_family = _build_per_family(entries, {})
    assert set(per_family.keys()) == set(families)
    assert sum(b["n_entries"] for b in per_family.values()) == len(entries)
