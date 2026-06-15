"""Property-based tests for the verdict-provenance tag.

The patent application cites two distinct guarantees about per-row
provenance, both of which depend on ``Assessment.verdict_source`` being
a *total function* of ``Decision``:

  1. Every persisted row has a non-null ``verdict_source`` — no Decision
     emitted anywhere in the kernel may produce a None mapping. Without
     this the patent's "kernel-driven verdicts are one SQL query away"
     claim degrades to "kernel-driven verdicts are one SQL query away
     when the helper happens to match" which is unfalsifiable.

  2. The mapping respects the documented precedence:
       cache > abstain > rule-family > LLM-family > CRM-family.
     A cache-hit on an LLM-derived row must persist as ``CACHE_HIT``
     (otherwise telemetry double-counts cache hits as fresh LLM calls);
     a ``needs_review`` row must persist as ``ABSTAIN`` (otherwise the
     reviewer queue filter misses it).

These tests fuzz arbitrary Decision permutations through
``routes.controls._decision_to_verdict_source`` and assert both the
totality and the precedence properties hold for every input.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

hypothesis = pytest.importorskip("hypothesis")

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from cybersecurity_assessor.models import VerdictSource  # noqa: E402
from cybersecurity_assessor.routes.controls import (  # noqa: E402
    _decision_to_verdict_source,
)


# ---------------------------------------------------------------------------
# Lightweight Decision stand-in
# ---------------------------------------------------------------------------
#
# The real ``engine.assessor.Decision`` dataclass carries 20+ fields with
# nontrivial defaults (ValidatorRejection logs, SupersessionHit logs,
# CrmShortCircuit records, dual narratives, …). The helper under test
# only consults three of them: ``source``, ``cache_source``, and
# ``needs_review``. A minimal stand-in keeps the strategy space small
# enough that Hypothesis can explore the precedence corners without
# spending its budget generating irrelevant fields.


@dataclass
class _FakeDecision:
    source: str
    cache_source: str | None = None
    needs_review: bool = False


# Every source string the kernel emission sites can produce. Lifted from
# the ``grep -n "source=" assessor.py`` audit in routes/controls.py and
# the Decision docstring. Adding a new emission site without adding it
# here means the safety-net branch (ABSTAIN catch-all) catches it — but
# the explicit-list test below will fail on the new value, forcing the
# author to extend both the enum and the helper consciously.
_KERNEL_SOURCES = (
    "rule_8a",
    "rule_8b",
    "rule-8c",
    "rule_no_evidence",
    "crm_provider",
    "crm_inherited",
    "crm_not_applicable",
    "crm_provider+onprem_not_applicable",  # hybrid mixed
    "crm_inherited+onprem_not_applicable",  # hybrid mixed
    "crm_not_applicable+onprem_inherited",  # hybrid mixed
    "llm",
    "llm_after_retry",
    "abstain",
)


_decision_strategy = st.builds(
    _FakeDecision,
    source=st.sampled_from(_KERNEL_SOURCES),
    cache_source=st.one_of(st.none(), st.just("cache_hit")),
    needs_review=st.booleans(),
)


# ---------------------------------------------------------------------------
# Totality — every Decision maps to a real VerdictSource enum value
# ---------------------------------------------------------------------------


@given(decision=_decision_strategy)
@settings(max_examples=200, deadline=None)
def test_every_decision_maps_to_a_verdict_source(decision):
    """The helper is total — no Decision input returns None or raises."""
    result = _decision_to_verdict_source(decision)
    assert isinstance(result, VerdictSource)
    # The enum's string value must be the persistable form — defends
    # against an accidental ``Enum`` (not ``str, Enum``) refactor that
    # would break the TEXT-column migration.
    assert isinstance(result.value, str)
    assert result.value  # non-empty


# ---------------------------------------------------------------------------
# Precedence — cache > abstain > source-family
# ---------------------------------------------------------------------------


@given(decision=_decision_strategy)
@settings(max_examples=200, deadline=None)
def test_cache_hit_beats_every_other_signal(decision):
    """``cache_source='cache_hit'`` always maps to CACHE_HIT.

    A replayed Decision keeps its original ``source`` string for
    downstream telemetry, but the persisted row records the cache
    provenance so cost queries don't double-count cache hits as
    fresh LLM calls. The precedence MUST be strict — even an
    abstain-shaped Decision with cache_source='cache_hit' persists
    as CACHE_HIT.
    """
    decision.cache_source = "cache_hit"
    assert _decision_to_verdict_source(decision) == VerdictSource.CACHE_HIT


@given(decision=_decision_strategy)
@settings(max_examples=200, deadline=None)
def test_needs_review_without_cache_hit_beats_source(decision):
    """``needs_review=True`` without a cache hit always maps to ABSTAIN.

    Every abstain path (validator-exhausted, LLM-parse-error,
    dual-pass-mismatch, low-confidence, unverified-cites,
    stale-reference, boundary-conflict, no-llm-client) flips
    ``needs_review`` regardless of the source string. The reviewer
    queue filter is ``WHERE verdict_source = 'abstain'`` — if a
    needs_review row leaks through as RULE_8A or LLM_ACCEPT the
    reviewer never sees it.
    """
    decision.cache_source = None
    decision.needs_review = True
    assert _decision_to_verdict_source(decision) == VerdictSource.ABSTAIN


# ---------------------------------------------------------------------------
# Source-family — explicit per-emission-site coverage
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source,expected",
    [
        ("rule_8a", VerdictSource.RULE_8A),
        ("rule_8b", VerdictSource.RULE_8B),
        ("rule-8c", VerdictSource.RULE_8C),
        ("rule_no_evidence", VerdictSource.RULE_NO_EVIDENCE),
        ("crm_provider", VerdictSource.CRM_PROVIDER),
        ("crm_inherited", VerdictSource.CRM_INHERITED),
        ("crm_not_applicable", VerdictSource.CRM_NOT_APPLICABLE),
        ("crm_provider+onprem_not_applicable", VerdictSource.CRM_HYBRID_MIXED),
        ("crm_inherited+onprem_not_applicable", VerdictSource.CRM_HYBRID_MIXED),
        ("crm_not_applicable+onprem_inherited", VerdictSource.CRM_HYBRID_MIXED),
        ("llm", VerdictSource.LLM_ACCEPT),
        ("llm_after_retry", VerdictSource.LLM_AFTER_RETRY),
    ],
)
def test_clean_decision_maps_to_expected_source(source, expected):
    """No cache, no abstain — pure source-string dispatch."""
    d = _FakeDecision(source=source, cache_source=None, needs_review=False)
    assert _decision_to_verdict_source(d) == expected


def test_abstain_source_with_no_review_flag_still_maps_to_abstain():
    """``source='abstain'`` always lands on ABSTAIN.

    ``_abstain`` always sets ``needs_review=True``, but a defensive
    map shouldn't depend on the caller setting both fields. The
    safety-net branch covers ``source='abstain'`` because it isn't
    in the explicit dispatch list and doesn't start with ``crm_``.
    """
    d = _FakeDecision(source="abstain", cache_source=None, needs_review=False)
    assert _decision_to_verdict_source(d) == VerdictSource.ABSTAIN


# ---------------------------------------------------------------------------
# Safety net — unknown sources don't silently mis-tag
# ---------------------------------------------------------------------------


@given(
    src=st.text(min_size=1, max_size=40).filter(
        lambda s: s not in _KERNEL_SOURCES and not s.startswith("crm_")
    )
)
@settings(max_examples=100, deadline=None)
def test_unknown_source_routes_to_abstain(src):
    """Unknown source strings land in the reviewer queue, never in a
    trusted bucket. Defensive: protects against a future kernel
    emission site whose author forgets to extend the helper.
    """
    d = _FakeDecision(source=src, cache_source=None, needs_review=False)
    assert _decision_to_verdict_source(d) == VerdictSource.ABSTAIN


@given(
    src=st.text(min_size=1, max_size=40).map(lambda s: f"crm_{s}").filter(
        lambda s: s not in {"crm_provider", "crm_inherited", "crm_not_applicable"}
        and "+onprem_" not in s
    )
)
@settings(max_examples=100, deadline=None)
def test_unknown_crm_variant_routes_to_hybrid_mixed(src):
    """Unknown ``crm_*`` variants land on CRM_HYBRID_MIXED.

    The intent: any future CRM verdict the helper doesn't recognize is
    treated as "mixed / not jointly inheritable" — the conservative
    default that flags the row for closer review without dropping it
    into the abstain queue (which is reserved for kernel failures).
    """
    d = _FakeDecision(source=src, cache_source=None, needs_review=False)
    assert _decision_to_verdict_source(d) == VerdictSource.CRM_HYBRID_MIXED


# ---------------------------------------------------------------------------
# Enum surface — every emission site has a corresponding enum value
# ---------------------------------------------------------------------------


def test_every_documented_kernel_source_has_a_distinct_enum_target():
    """Every distinct source the helper dispatches on must produce a
    distinct enum value (except the three CRM hybrid permutations,
    which intentionally collapse to CRM_HYBRID_MIXED).

    Guards against an accidental enum collision — e.g. RULE_8A and
    RULE_8B sharing a string value — that would break the
    GROUP BY verdict_source patent-telemetry query.
    """
    expected_distinct = {
        "rule_8a": VerdictSource.RULE_8A,
        "rule_8b": VerdictSource.RULE_8B,
        "rule-8c": VerdictSource.RULE_8C,
        "rule_no_evidence": VerdictSource.RULE_NO_EVIDENCE,
        "crm_provider": VerdictSource.CRM_PROVIDER,
        "crm_inherited": VerdictSource.CRM_INHERITED,
        "crm_not_applicable": VerdictSource.CRM_NOT_APPLICABLE,
        "llm": VerdictSource.LLM_ACCEPT,
        "llm_after_retry": VerdictSource.LLM_AFTER_RETRY,
    }
    # All targets are distinct
    assert len(set(expected_distinct.values())) == len(expected_distinct)
    # And the helper agrees with the expected mapping
    for src, want in expected_distinct.items():
        got = _decision_to_verdict_source(
            _FakeDecision(source=src, cache_source=None, needs_review=False)
        )
        assert got == want, f"{src!r} -> {got} (expected {want})"
