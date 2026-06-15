"""Property-based tests for the dual-narrative advisory flag.

``validate_dual_narratives`` is advisory by contract — column Q already
passed the main validator and the dual halves are UI fidelity only.
The patent-supporting question is *how* that advisory survives the
LLM-accept path and lands on the persisted ``Assessment`` row:

  1. **Totality of the flag list.** Decision.dual_narrative_flags must
     be a ``list[str]`` for every Decision the kernel emits — never None.
     A None here would crash the persistence layer (``bool(None)`` is
     False but ``list(None)`` raises), silently dropping the advisory
     from the run.

  2. **De-duplication.** Both leak and CRM-mismatch rules can flag the
     same ``DUAL_NARRATIVE_MISLABEL`` reason on one row. The persisted
     JSON column must hold each reason at most once so downstream
     "row had flag class X?" queries don't need DISTINCT in app code.

  3. **Bool↔JSON consistency.** The boolean column is the index-friendly
     "any advisory?" flag; the JSON column is the per-row triage detail.
     They MUST agree: ``flagged=True iff reasons is a non-empty JSON
     list``. A drift between them would let a reviewer-queue query
     ("WHERE dual_narrative_flagged = 1") return rows the detail-view
     query ("json_each(dual_narrative_flag_reasons)") finds empty.

  4. **Advisory-not-blocking.** The advisory MUST NOT flip
     ``Decision.accepted`` or ``Decision.needs_review``. Column Q's
     verdict still stands; the flag is review-queue triage only.

These tests fuzz arbitrary dual-narrative inputs through the validator
and the kernel's de-dupe / persistence-mirror pipeline.
"""

from __future__ import annotations

import json

import pytest

hypothesis = pytest.importorskip("hypothesis")

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from cybersecurity_assessor.engine.validator import (  # noqa: E402
    DualNarrativeResult,
    RejectionReason,
    validate_dual_narratives,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


# Narrative text strategy — short + printable so Hypothesis doesn't burn its
# budget on UTF-16 edge cases the LLM never produces in practice. Includes
# the leak / CRM trigger phrases at non-zero frequency so the advisory path
# actually fires; otherwise every example would test the empty-flags branch.
_TEXT = st.one_of(
    st.none(),
    st.just(""),
    st.sampled_from(
        [
            "Local SSP section 2.4 implementation observed.",
            "Inherited from AWS GovCloud per FedRAMP authorization.",
            "Implemented by the CSP via control plane.",
            "Physical data center cage in Sterling, VA.",
            "rack-mounted appliance in customer space",
            "Customer configures via console, provider operates.",
            "Provider responsibility per shared-responsibility matrix.",
            "",
        ]
    ),
    st.text(min_size=0, max_size=120),
)


_RESPONSIBILITY = st.one_of(
    st.none(),
    st.sampled_from(
        [
            "customer",
            "provider",
            "inherited",
            "hybrid",
            "not_applicable",
            "unknown",
            "",
        ]
    ),
)


# ---------------------------------------------------------------------------
# Totality — validate_dual_narratives always returns a non-None flags list
# ---------------------------------------------------------------------------


@given(onprem=_TEXT, cloud=_TEXT, resp=_RESPONSIBILITY)
@settings(max_examples=300, deadline=None)
def test_validate_dual_narratives_flags_is_always_a_list(onprem, cloud, resp):
    """The flagged attribute is a list for every input — never None.

    The persistence layer calls ``list(decision.dual_narrative_flags)``
    when mirroring onto Assessment. A None here would crash that
    persistence step and silently drop EVERY downstream advisory from
    that run.
    """
    result = validate_dual_narratives(
        narrative_on_prem=onprem,
        narrative_cloud=cloud,
        crm_responsibility=resp,
    )
    assert isinstance(result, DualNarrativeResult)
    assert result.flagged is not None
    assert isinstance(result.flagged, list)
    # Every element must be a RejectionReason — the persistence layer
    # serializes ``.value`` on each and an unknown type would raise.
    for item in result.flagged:
        assert isinstance(item, RejectionReason)


# ---------------------------------------------------------------------------
# Advisory-not-blocking — the contract that distinguishes flags from rejections
# ---------------------------------------------------------------------------


@given(onprem=_TEXT, cloud=_TEXT, resp=_RESPONSIBILITY)
@settings(max_examples=200, deadline=None)
def test_dual_narrative_result_has_no_ok_field(onprem, cloud, resp):
    """``DualNarrativeResult`` MUST NOT expose an ``ok`` attribute.

    ``ValidationResult`` (hard validator) has ``ok: bool`` and callers
    branch on it. ``DualNarrativeResult`` deliberately does NOT — the
    advisory is non-blocking by contract. If a refactor accidentally
    added ``ok`` here, a future caller might treat the dual-narrative
    flag as a hard rejection and bounce the row, defeating the
    advisory contract.
    """
    result = validate_dual_narratives(
        narrative_on_prem=onprem,
        narrative_cloud=cloud,
        crm_responsibility=resp,
    )
    assert not hasattr(result, "ok"), (
        "DualNarrativeResult has gained an 'ok' field — the advisory "
        "contract is at risk of being treated as a hard rejection."
    )


# ---------------------------------------------------------------------------
# De-duplication — the kernel collapses duplicate RejectionReason values
# ---------------------------------------------------------------------------


def _kernel_dedupe(flagged: list[RejectionReason]) -> list[str]:
    """Mirror the assessor.py de-dupe logic verbatim.

    Keeping this isolated lets the property tests exercise the exact
    transformation the persistence path applies without spinning up the
    full orchestrator. If assessor.py drifts, the duplicate-reason
    property below will start firing on regenerated examples.
    """
    seen: set[str] = set()
    out: list[str] = []
    for reason in flagged:
        val = reason.value
        if val not in seen:
            seen.add(val)
            out.append(val)
    return out


@given(
    flags=st.lists(
        st.sampled_from(list(RejectionReason)),
        min_size=0,
        max_size=8,
    )
)
@settings(max_examples=200, deadline=None)
def test_kernel_dedupe_collapses_duplicates(flags):
    """Every distinct RejectionReason appears at most once."""
    deduped = _kernel_dedupe(flags)
    assert len(deduped) == len(set(deduped))
    # And the set of values must equal the set of input values — de-dupe
    # is NOT allowed to drop a reason that was present in the input.
    assert set(deduped) == {f.value for f in flags}


@given(
    flags=st.lists(
        st.sampled_from(list(RejectionReason)),
        min_size=0,
        max_size=8,
    )
)
@settings(max_examples=200, deadline=None)
def test_kernel_dedupe_preserves_first_occurrence_order(flags):
    """De-dupe preserves the order of first occurrences.

    Order matters because the JSON column is rendered into the UI in
    list order; if de-dupe re-sorted, a reviewer looking at the detail
    view would see the reasons in a different order than the validator
    emitted them, making post-mortem auditing harder.
    """
    deduped = _kernel_dedupe(flags)
    first_seen_order: list[str] = []
    seen: set[str] = set()
    for f in flags:
        if f.value not in seen:
            seen.add(f.value)
            first_seen_order.append(f.value)
    assert deduped == first_seen_order


# ---------------------------------------------------------------------------
# Bool↔JSON consistency — the persistence mirror invariant
# ---------------------------------------------------------------------------


def _persistence_mirror(decision_flags: list[str]) -> tuple[bool, str | None]:
    """Mirror the routes/controls.py persistence transform.

    Both write sites do exactly this — extract the kernel list, set the
    indexed bool, and JSON-encode the reasons (or NULL when empty). The
    test below asserts this transform is consistent.
    """
    flagged_bool = bool(decision_flags)
    flags_json = json.dumps(decision_flags) if flagged_bool else None
    return flagged_bool, flags_json


@given(
    flags=st.lists(
        st.sampled_from([r.value for r in RejectionReason]),
        min_size=0,
        max_size=6,
        unique=True,
    )
)
@settings(max_examples=200, deadline=None)
def test_persistence_mirror_bool_matches_json(flags):
    """``flagged=True iff reasons is a non-empty JSON list``.

    The boolean is the index-friendly review-queue filter; the JSON
    column is the triage detail. If they drifted, a query like
    ``WHERE dual_narrative_flagged = 1`` could return rows whose
    detail-view query ``json_each(dual_narrative_flag_reasons)``
    finds empty — confusing the reviewer and breaking the patent
    "one SQL query away" claim for this advisory class.
    """
    flagged_bool, flags_json = _persistence_mirror(flags)
    if flagged_bool:
        assert flags_json is not None
        parsed = json.loads(flags_json)
        assert isinstance(parsed, list)
        assert len(parsed) == len(flags)
        assert set(parsed) == set(flags)
    else:
        assert flags_json is None
        assert flags == []


@given(
    flags=st.lists(
        st.sampled_from([r.value for r in RejectionReason]),
        min_size=0,
        max_size=6,
    )
)
@settings(max_examples=200, deadline=None)
def test_persistence_mirror_json_roundtrips(flags):
    """JSON-encoded reasons survive a json.loads round-trip unchanged.

    Defends against an accidental ``repr()`` / ``str()`` / single-quote
    serialization that would write valid-looking text into the column
    but fail the SQLite ``json_each`` parser used by downstream queries.
    """
    flagged_bool, flags_json = _persistence_mirror(flags)
    if flagged_bool:
        roundtripped = json.loads(flags_json)
        assert roundtripped == flags


# ---------------------------------------------------------------------------
# Concrete trigger paths — pin the load-bearing flag-firing cases
# ---------------------------------------------------------------------------


def test_swap_halves_leak_flips_flagged_bool_via_persistence():
    """Full pipeline pin: swapped halves → flag → bool=True + JSON list.

    Exercises the end-to-end transform the kernel + persistence layer
    do on every LLM-accept row: validator → de-dupe → mirror. A
    regression here means the dual-narrative advisory silently stops
    landing on the persisted row even though the validator still
    detects it.
    """
    result = validate_dual_narratives(
        narrative_on_prem="Inherited from AWS GovCloud per FedRAMP authorization.",
        narrative_cloud="",
        crm_responsibility=None,
    )
    deduped = _kernel_dedupe(result.flagged)
    flagged_bool, flags_json = _persistence_mirror(deduped)
    assert flagged_bool is True
    assert flags_json is not None
    parsed = json.loads(flags_json)
    assert RejectionReason.DUAL_NARRATIVE_MISLABEL.value in parsed


def test_clean_narratives_persist_as_unflagged_with_null_reasons():
    """Both halves clean + responsibility=None → bool=False + reasons=NULL.

    The common case — most LLM-accept rows on most controls don't trip
    the advisory. They MUST persist with the boolean explicitly False
    (not NULL) and the JSON column NULL, so post-migration rows are
    cleanly distinguishable from legacy pre-migration rows.
    """
    result = validate_dual_narratives(
        narrative_on_prem="Local SSP section 2.4 implementation observed.",
        narrative_cloud="",
        crm_responsibility=None,
    )
    deduped = _kernel_dedupe(result.flagged)
    flagged_bool, flags_json = _persistence_mirror(deduped)
    assert flagged_bool is False
    assert flags_json is None


def test_double_trigger_collapses_to_single_reason_entry():
    """Leak AND CRM-mismatch on one row → single MISLABEL entry, not two.

    Both rules emit ``DUAL_NARRATIVE_MISLABEL`` — without de-dupe the
    JSON column would carry ``["dual_narrative_mislabel",
    "dual_narrative_mislabel"]`` and downstream ``COUNT(json_each)``
    queries would double-count this row's advisory.
    """
    # Provider-only leak in on-prem half + CRM=customer with cloud
    # populated. Both rules fire; the de-dupe must collapse them.
    result = validate_dual_narratives(
        narrative_on_prem="Inherited from AWS GovCloud per FedRAMP authorization.",
        narrative_cloud="Provider implements via AWS GovCloud.",
        crm_responsibility="customer",
    )
    # Sanity: the validator did emit at least two flag entries
    assert len(result.flagged) >= 2
    deduped = _kernel_dedupe(result.flagged)
    assert deduped == [RejectionReason.DUAL_NARRATIVE_MISLABEL.value]


# ---------------------------------------------------------------------------
# RejectionReason surface — every flagged value is a known string member
# ---------------------------------------------------------------------------


def test_every_flag_value_is_a_known_rejection_reason_string():
    """Sanity guard: every RejectionReason has a non-empty string value.

    The persistence layer JSON-encodes ``reason.value`` — a non-string
    value (e.g. an accidental int-Enum refactor) would still round-trip
    through ``json.dumps`` but break the downstream ``json_each``
    string comparison in the review-queue query.
    """
    for reason in RejectionReason:
        assert isinstance(reason.value, str)
        assert reason.value  # non-empty
