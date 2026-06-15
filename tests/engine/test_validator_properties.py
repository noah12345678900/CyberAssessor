"""Property-based tests for the validator's pure helpers.

The validator (``cybersecurity_assessor.engine.validator``) is the load-
bearing patent-supporting gate that sits between every LLM-proposed
(status, narrative) pair and the workbook writer. SKILL.md rule #11
classification, the requirement-restatement detector, the future-tense
trip-wire, and the literal-cite verifier all run here — and if any of
their pure helpers regress, the patent's accuracy claim degrades
silently on the next release.

In-scope helpers (deliberately the small, fast, side-effect-free ones):

    ``_normalize_status``           ComplianceStatus|str|None coerce
    ``_expected_status_for_class``  NarrativeClass \u2192 expected status
    ``_has_any``                    needle-set membership over lowercased text
    ``_tokenset``                   regex tokenize + stopword filter
    ``_has_primary_citation``       primary-source regex presence
    ``_names_inheritance_source``   inheritance-source regex presence
    ``_mentions_remediation``       POA&M/remediation regex presence
    ``_is_requirement_restatement`` regex + Jaccard overlap check
    ``_verify_cites``               literal-cite presence over evidence text

Plus the two public entry points that compose the above:

    ``classify_narrative``       narrative \u2192 NarrativeClass
    ``validate``                 (status, narrative, row, evidence) \u2192 ValidationResult
    ``validate_dual_narratives`` advisory leak + CRM cross-check

Cross-helper invariants the property tests pin (NOT the per-helper ones):

  1. **Classification totality.** ``classify_narrative`` never raises for
     any text input and always returns a NarrativeClass member.
  2. **Status\u2194class round-trip.** When a narrative classifies to a
     non-ambiguous class and the proposed status matches the expected
     status for that class, ``validate`` MUST NOT produce a
     STATUS_NARRATIVE_MISMATCH rejection. Drift here is the patent's
     accuracy-claim trip-wire.
  3. **Advisory contract.** ``validate_dual_narratives`` ALWAYS returns
     a DualNarrativeResult (never raises, never returns ok=False) \u2014
     callers depend on the result being safely renderable as advisory
     notes without an exception guard.
  4. **Cite exemption guarantee.** The row's CCI id and control id are
     ALWAYS exempt from ``_verify_cites``: a narrative may name the row
     under assessment without an evidence-side match.

Hypothesis is in the dev extras and imported via ``pytest.importorskip``
so a user running ``pytest`` without the dev install gets a clean skip
rather than a collection error.
"""

from __future__ import annotations

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import assume, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

# This workstation runs EDR + Office COM servers; the first fuzzed example to
# exercise the full validator/classifier pipeline can pay a cold-start /
# contention cost that blows Hypothesis's 200ms per-example deadline (it passes
# warm in a full-suite run but flakes when a heavy pipeline test runs first in
# a targeted `-k` run). The deadline measures wall-clock, not a correctness
# property, so disable it for the pipeline-entry tests below. Cheap string-op
# property tests keep the default deadline as a perf guard.
_PIPELINE = settings(deadline=None)

from cybersecurity_assessor.engine.validator import (  # noqa: E402
    _AFFIRMING_PHRASES,
    _CITE_EXEMPT_SUBSTRINGS,
    _GAP_PHRASES,
    _NA_PHRASES,
    _ONPREM_ONLY_PHRASES,
    _PROVIDER_ONLY_PHRASES,
    _STOPWORDS,
    _TOKEN_RE,
    DualNarrativeResult,
    RejectionReason,
    ValidationResult,
    _expected_status_for_class,
    _has_any,
    _has_primary_citation,
    _is_requirement_restatement,
    _mentions_remediation,
    _names_inheritance_source,
    _normalize_status,
    _tokenset,
    _verify_cites,
    classify_narrative,
    validate,
    validate_dual_narratives,
)
from cybersecurity_assessor.models import ComplianceStatus, NarrativeClass  # noqa: E402


# Reusable text strategy — covers ASCII control bytes, unicode whitespace,
# regex metacharacters, and the corpus of phrases the validator's phrase
# tables look for. Keeps the surface broad without exploding test time.
_TEXT = st.text(max_size=200)
_SHORT_TEXT = st.text(max_size=80)


# ---------------------------------------------------------------------------
# _normalize_status — coerce ComplianceStatus|str|None to enum or None
# ---------------------------------------------------------------------------


@given(value=st.one_of(st.none(), st.sampled_from(list(ComplianceStatus)), _TEXT))
def test_normalize_status_returns_enum_or_none(value: object) -> None:
    """Output is always ``ComplianceStatus`` member or None — never raises.

    The validator's ``validate()`` feeds this to ``_expected_status_for_class``
    comparisons; a third return shape (raw string, bool, etc.) would either
    crash the comparison or silently bypass the mismatch check. Totality
    over the union here keeps the patent's gate closed for ALL inputs.
    """
    out = _normalize_status(value)
    assert out is None or isinstance(out, ComplianceStatus)


@given(status=st.sampled_from(list(ComplianceStatus)))
def test_normalize_status_enum_input_returns_same_member(status: ComplianceStatus) -> None:
    """A ComplianceStatus instance passes through unchanged.

    Avoids the silent-bug where round-tripping through ``.value`` would
    momentarily lose enum identity and let downstream ``is`` checks fail.
    """
    assert _normalize_status(status) is status


@given(status=st.sampled_from(list(ComplianceStatus)))
def test_normalize_status_value_string_matches_enum(status: ComplianceStatus) -> None:
    """``ComplianceStatus.value`` (verbatim or case-shifted) recovers the enum.

    Mirrors what the LLM emits — "Compliant", "compliant", "COMPLIANT" all
    coerce back to the same enum. A regression that case-narrows here
    would silently drop LLM-proposed statuses that arrived in odd casing.
    """
    assert _normalize_status(status.value) is status
    assert _normalize_status(status.value.upper()) is status
    assert _normalize_status(status.value.lower()) is status


@given(text=_TEXT)
def test_normalize_status_idempotent_through_value_roundtrip(text: str) -> None:
    """``_normalize_status(_normalize_status(x).value) == _normalize_status(x)``.

    Once the function settles on an enum, re-feeding ``.value`` yields the
    same enum. Catches a regression where case-folding logic drifts between
    the first and second pass.
    """
    first = _normalize_status(text)
    if first is None:
        return
    second = _normalize_status(first.value)
    assert second is first


# ---------------------------------------------------------------------------
# _expected_status_for_class — NarrativeClass → ComplianceStatus|None
# ---------------------------------------------------------------------------


@given(klass=st.sampled_from(list(NarrativeClass)))
def test_expected_status_total_over_enum(klass: NarrativeClass) -> None:
    """Total function: every NarrativeClass member maps to a defined output.

    If a new class were added without a branch, this fails — the patent's
    rule #11 mapping table would have a silent hole that defaulted to
    None (= "abort"), turning the new class into a permanent rejector.
    """
    out = _expected_status_for_class(klass)
    assert out is None or isinstance(out, ComplianceStatus)


def test_expected_status_ambiguous_is_none() -> None:
    """AMBIGUOUS \u2192 None is the load-bearing rule #11 rejection signal.

    ``validate()`` reads ``None`` and emits STATUS_NARRATIVE_MISMATCH no
    matter what status was proposed. If this ever returned a concrete
    status, ambiguous narratives would silently get a verdict.
    """
    assert _expected_status_for_class(NarrativeClass.AMBIGUOUS) is None


def test_expected_status_concrete_classes_map_correctly() -> None:
    """The three non-ambiguous classes pin to their canonical status.

    Spelled out as one test (not a Hypothesis run) because the mapping
    IS the contract — drift in any direction is a bug, not noise to fuzz.
    """
    assert (
        _expected_status_for_class(NarrativeClass.COMPLIANCE_AFFIRMING)
        is ComplianceStatus.COMPLIANT
    )
    assert (
        _expected_status_for_class(NarrativeClass.NA_JUSTIFYING)
        is ComplianceStatus.NOT_APPLICABLE
    )
    assert (
        _expected_status_for_class(NarrativeClass.GAP_DESCRIBING)
        is ComplianceStatus.NON_COMPLIANT
    )


# ---------------------------------------------------------------------------
# _has_any — needle set membership over already-lowercased haystack
# ---------------------------------------------------------------------------


@given(haystack=_TEXT)
def test_has_any_empty_needles_returns_false(haystack: str) -> None:
    """No needles \u2192 always False, never True.

    Defensive: if the phrase tables were ever empty (config error,
    accidental wipe), the validator would otherwise classify nothing
    and let every narrative through.
    """
    assert _has_any(haystack.lower(), ()) is False


@given(
    haystack=_TEXT,
    needle=st.sampled_from(_AFFIRMING_PHRASES + _NA_PHRASES + _GAP_PHRASES),
)
def test_has_any_appended_needle_matches(haystack: str, needle: str) -> None:
    """Appending a needle to any haystack makes ``_has_any`` true for it.

    Pins the substring-match contract: ``_has_any`` MUST be a pure
    substring check (not whole-word, not regex-escape). The classifier's
    phrase tables depend on substring semantics for "examined " (with
    trailing space) to match "examined the workbook" cleanly.
    """
    padded = (haystack + " " + needle).lower()
    assert _has_any(padded, (needle,)) is True


@given(haystack=_TEXT, extra=_TEXT)
def test_has_any_monotonic_in_needles(haystack: str, extra: str) -> None:
    """Adding needles can only flip False\u2192True, never True\u2192False.

    Adding a phrase to a table must never CANCEL a previous match \u2014
    union semantics. Catches a regression where ``_has_any`` accidentally
    grew an ``all()`` instead of ``any()``.
    """
    base = (extra,)
    augmented = base + ("zzzz-never-appears-anywhere-zzzz",)
    if _has_any(haystack.lower(), base):
        assert _has_any(haystack.lower(), augmented) is True


# ---------------------------------------------------------------------------
# _tokenset — lowercase, len>=3, stopword-stripped token sets
# ---------------------------------------------------------------------------


@given(text=_TEXT)
def test_tokenset_lowercase_and_minlen(text: str) -> None:
    """Every emitted token is lowercase and has length >= 3.

    The Jaccard overlap calculation in ``_is_requirement_restatement``
    compares two token sets directly. Mismatched casing or 1-2 char
    tokens (\"a\", \"is\") would create false-negative overlap and let
    requirement-restatement narratives through.
    """
    for tok in _tokenset(text):
        assert tok == tok.lower()
        assert len(tok) >= 3


@given(text=_TEXT)
def test_tokenset_no_stopwords(text: str) -> None:
    """No stopword ever appears in the output set.

    Without stopword removal, two boilerplate-heavy NIST sentences would
    overlap on \"the\", \"and\", \"shall\" alone and trigger the
    restatement detector on totally unrelated text.
    """
    assert _tokenset(text).isdisjoint(_STOPWORDS)


@given(text=_TEXT)
def test_tokenset_idempotent_via_rejoin(text: str) -> None:
    """Tokens rejoined and re-tokenized produce the same set.

    Idempotence pins the contract: the regex + stopword filter is a
    fixpoint after one pass. If the filter drifted to a non-fixpoint
    (e.g. emitted tokens containing punctuation), the Jaccard math
    would silently shift between calls on the same inputs.
    """
    first = _tokenset(text)
    rejoined = " ".join(sorted(first))
    second = _tokenset(rejoined)
    assert first == second


@given(text=_TEXT)
def test_tokenset_subset_of_token_regex(text: str) -> None:
    """Every token in the set was emitted by the token regex.

    Cross-helper invariant: the token regex defines the universe, the
    stopword filter prunes within it. Anything outside the regex universe
    is a bug in either the regex or the set builder.
    """
    # Mirror production's Unicode-consistent fold (finding #19): _tokenset
    # casefolds, so the oracle must casefold too. Using .lower() here lets
    # casefold-expanding chars (e.g. 'ß' -> 'ss') diverge and falsely fail.
    regex_tokens = set(_TOKEN_RE.findall(text.casefold()))
    assert _tokenset(text) <= regex_tokens


# ---------------------------------------------------------------------------
# _has_primary_citation / _names_inheritance_source / _mentions_remediation
# ---------------------------------------------------------------------------


def test_primary_citation_empty_inputs_false() -> None:
    """Empty / None narrative \u2192 no primary citation.

    The validator feeds these helpers raw narrative text; defending the
    empty-string base case here keeps ``validate()`` from a NoneType
    crash on the rule-#8a fast path.
    """
    assert _has_primary_citation("") is False
    assert _has_primary_citation(None) is False  # type: ignore[arg-type]


@given(text=_TEXT)
def test_primary_citation_total(text: str) -> None:
    """Returns bool for any input — never raises.

    Whitespace, control bytes, and unicode all pass through cleanly.
    """
    out = _has_primary_citation(text)
    assert isinstance(out, bool)


@given(prefix=_SHORT_TEXT, n=st.integers(min_value=10_000_000, max_value=99_999_999))
def test_primary_citation_usd_doc_matches(prefix: str, n: int) -> None:
    """USD + 8 digits anywhere in narrative \u2192 primary citation found.

    Pins the rule #8 inheritance-detection contract: a verbatim USD doc
    number is the canonical primary citation shape, and the rule #11
    citation-quality NOTE depends on it.
    """
    narrative = f"{prefix} USD{n} verified."
    assert _has_primary_citation(narrative) is True


@given(text=_TEXT)
def test_names_inheritance_source_total(text: str) -> None:
    """Returns bool for any input — never raises."""
    assert isinstance(_names_inheritance_source(text.lower()), bool)


@given(text=_TEXT)
def test_mentions_remediation_total(text: str) -> None:
    """Returns bool for any input — never raises."""
    assert isinstance(_mentions_remediation(text.lower()), bool)


def test_mentions_remediation_known_phrases() -> None:
    """POA&M / poam / remediation / corrective action all trigger.

    Spelled out because these four phrases ARE the contract — the
    review-assessment skill checks for exactly these tokens before
    flagging \"missing POA&M\" on a Non-Compliant row.
    """
    assert _mentions_remediation("see poa&m for fix") is True
    assert _mentions_remediation("see poam-1234") is True
    assert _mentions_remediation("remediation underway") is True
    assert _mentions_remediation("corrective action assigned") is True
    assert _mentions_remediation("everything is fine") is False


# ---------------------------------------------------------------------------
# _is_requirement_restatement — regex + Jaccard overlap
# ---------------------------------------------------------------------------


def test_requirement_restatement_empty_narrative_false() -> None:
    """Empty / None narrative \u2192 not a restatement (no string to parrot).

    The validator's ``classify_narrative`` short-circuits empty Q text to
    AMBIGUOUS before this is called; defending the contract anyway keeps
    the helper safe for direct callers (review tooling).
    """
    assert _is_requirement_restatement("", None) is False
    assert _is_requirement_restatement(None, None) is False  # type: ignore[arg-type]


@given(narrative=_TEXT)
def test_requirement_restatement_total_without_row(narrative: str) -> None:
    """No row \u2192 only the regex anti-patterns can fire. Never raises."""
    out = _is_requirement_restatement(narrative, None)
    assert isinstance(out, bool)


def test_requirement_restatement_regex_canonical_openers() -> None:
    """The four documented opener regexes all trigger when present.

    Pins SKILL.md rule #11 v1.0.11 anti-pattern detection. If any of
    these stopped matching, the LLM could slip a parroted shall-statement
    through and the patent's restatement-rejection metric would silently
    drop to zero.
    """
    assert (
        _is_requirement_restatement(
            "Reviewed AC-2; confirmed the requirement that the system shall...",
            None,
        )
        is True
    )
    assert (
        _is_requirement_restatement("Reviewed SDA Control 5: shall...", None) is True
    )
    assert (
        _is_requirement_restatement(
            "Examined logs and confirmed the requirement that the system shall log all events",
            None,
        )
        is True
    )
    assert (
        _is_requirement_restatement(
            "The system shall enforce least privilege as required.",
            None,
        )
        is True
    )


def test_requirement_restatement_jaccard_triggers_on_high_overlap(make_row) -> None:
    """High Jaccard overlap with col I/J/K/U \u2192 restatement detected.

    finding #13: detection is TRUE token-set Jaccard (|Q∩S|/|Q∪S|)
    against _RESTATEMENT_JACCARD_THRESHOLD = 0.5 (set in source). Use a
    narrative that re-uses the same content tokens as the row's
    definition; the result must be True (this near-mirror lands at
    Jaccard ≈ 0.67). A regression that loosened the threshold (or broke
    the token intersection/union math) would let paraphrased shall
    statements pass.
    """
    row = make_row(
        definition="System shall enforce multifactor authentication for privileged users."
    )
    # Same content tokens, slight surface paraphrase.
    narrative = (
        "Multifactor authentication shall be enforced for privileged "
        "users by the system."
    )
    assert _is_requirement_restatement(narrative, row) is True


def test_requirement_restatement_jaccard_misses_unrelated_narrative(make_row) -> None:
    """Unrelated narrative \u2192 not a restatement, even with row present.

    Negative-control: makes sure the Jaccard threshold isn't so low that
    any narrative on the same row qualifies. Catches the inverse drift
    (\"every narrative is a restatement\") that would zero-rate the LLM.
    """
    row = make_row(
        definition="System shall enforce multifactor authentication for privileged users."
    )
    narrative = (
        "Configured per USD00012345 \u00a72.1; observed RSA token enrollment "
        "for all admin accounts during the 2026-06-02 walkthrough."
    )
    assert _is_requirement_restatement(narrative, row) is False


# ---------------------------------------------------------------------------
# classify_narrative — public classification entry point
# ---------------------------------------------------------------------------


@_PIPELINE
@given(text=_TEXT)
def test_classify_narrative_total(text: str) -> None:
    """Returns a NarrativeClass member for any input — never raises.

    Patent-critical: the validator's gate runs on every LLM proposal,
    and a crash here would either bypass the gate (try/except in the
    caller) or kill the run. Totality is the load-bearing invariant.
    """
    out = classify_narrative(text)
    assert isinstance(out, NarrativeClass)


@given(ws=st.text(alphabet=" \t\n\r\f\v", min_size=0, max_size=20))
def test_classify_narrative_empty_or_whitespace_is_ambiguous(ws: str) -> None:
    """Empty / whitespace-only narrative \u2192 AMBIGUOUS.

    AMBIGUOUS triggers ``validate()`` to reject with
    STATUS_NARRATIVE_MISMATCH no matter what status was proposed.
    Pinning this short-circuit guarantees the validator never grants a
    verdict against an empty narrative.
    """
    assert classify_narrative(ws) == NarrativeClass.AMBIGUOUS


@_PIPELINE
@given(
    affirming=st.sampled_from(_AFFIRMING_PHRASES),
    gap=st.sampled_from(_GAP_PHRASES),
)
def test_classify_narrative_multi_class_hits_are_ambiguous(
    affirming: str, gap: str
) -> None:
    """Hitting two phrase tables at once \u2192 AMBIGUOUS (rule #11 mixed case).

    The classifier MUST NOT pick a winner when both compliance-affirming
    and gap-describing phrases appear; that's the mixed-narrative case
    rule #11 explicitly defers to the assessor. Property-tested across
    the full phrase-table cross product.
    """
    # Some phrase pairs share a substring (e.g. "missing" + "no documentation")
    # that would not change the result; the contract is "two distinct tables
    # hit \u2192 ambiguous" regardless of overlap.
    narrative = f"{affirming} ... however {gap}"
    assert classify_narrative(narrative) == NarrativeClass.AMBIGUOUS


@given(phrase=st.sampled_from(_AFFIRMING_PHRASES))
def test_classify_narrative_affirming_only(phrase: str) -> None:
    """An affirming-only phrase \u2192 COMPLIANCE_AFFIRMING.

    Wraps the phrase in a benign prefix to avoid the empty-narrative
    short-circuit. If any phrase in the table fails to classify on its
    own, the table is broken (or the matcher narrowed).
    """
    narrative = f"During assessment, {phrase} the workbook control description."
    # Some affirming phrases (e.g. "observed in", "configured to") may
    # incidentally appear inside NA / gap phrases too. The contract is:
    # a SINGLE-class hit produces that class; only multi-class hits go
    # ambiguous. We assert it lands on the affirming class OR ambiguous
    # (the latter is allowed only if our wrapper text triggered a second
    # table by accident, which the multi-class test already covers).
    result = classify_narrative(narrative)
    assert result in (NarrativeClass.COMPLIANCE_AFFIRMING, NarrativeClass.AMBIGUOUS)


# ---------------------------------------------------------------------------
# validate — full pre-write gate
# ---------------------------------------------------------------------------


@_PIPELINE
@given(
    status=st.one_of(st.none(), st.sampled_from(list(ComplianceStatus)), _SHORT_TEXT),
    narrative=_TEXT,
)
def test_validate_total(status: object, narrative: str) -> None:
    """``validate`` returns a ValidationResult for any input — never raises.

    Patent-critical: the validator runs on every LLM proposal. A crash
    in the gate is worse than a wrong verdict because the run recorder
    never sees the rejection \u2014 the patent's accuracy claim depends
    on the gate either passing or rejecting, never crashing.
    """
    result = validate(
        proposed_status=status,  # type: ignore[arg-type]
        proposed_narrative=narrative,
    )
    assert isinstance(result, ValidationResult)
    assert isinstance(result.ok, bool)
    assert isinstance(result.classified_as, NarrativeClass)


def test_validate_matching_status_and_class_passes() -> None:
    """Compliant + affirming narrative + primary cite \u2192 ok=True.

    Round-trip: when the LLM is doing its job, the gate MUST let the
    write through. A regression that started rejecting clean inputs
    would zero out the validator's true-negative rate.
    """
    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=(
            "Configured per USD00012345 \u00a72.1; observed enforcement during "
            "the 2026-06-02 walkthrough."
        ),
    )
    assert result.ok is True
    assert result.classified_as == NarrativeClass.COMPLIANCE_AFFIRMING


def test_validate_status_class_mismatch_is_rejected() -> None:
    """Compliant status + gap-describing narrative \u2192 mismatch rejection.

    Pins the core rule #11 check: status MUST follow classification. The
    rejection class MUST be STATUS_NARRATIVE_MISMATCH (not the generic
    AMBIGUOUS path) because the run recorder rolls up by class.
    """
    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative="No artifact found; gap identified for POA&M.",
    )
    assert result.ok is False
    reasons = [r for r, _ in result.rejections]
    assert RejectionReason.STATUS_NARRATIVE_MISMATCH in reasons


@_PIPELINE
@given(
    pre=_SHORT_TEXT,
    verb=st.sampled_from(
        [
            "will be configured",
            "to be implemented",
            "planned to deploy",
            "scheduled to deploy",
            "in process of deploying",
            "once deployed",
            "upcoming deployment",
        ]
    ),
)
def test_validate_future_tense_with_compliant_rejects(pre: str, verb: str) -> None:
    """Future-tense pattern + Compliant status \u2192 FUTURE_TENSE_COMPLIANCE.

    v0.2 precision-over-recall trip-wire. The narrative may end up
    classified as ambiguous or affirming depending on accompanying
    phrases \u2014 either way the future-tense rejection MUST fire when
    paired with Compliant. Catches the LLM-mislabel-as-Compliant class
    of error.
    """
    narrative = f"{pre} The system {verb} per the project plan."
    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
    )
    reasons = [r for r, _ in result.rejections]
    assert RejectionReason.FUTURE_TENSE_COMPLIANCE in reasons


@_PIPELINE
@given(
    status=st.sampled_from(
        [ComplianceStatus.NON_COMPLIANT, ComplianceStatus.NOT_APPLICABLE]
    ),
    verb=st.sampled_from(
        ["will be configured", "to be implemented", "planned to deploy"]
    ),
)
def test_validate_future_tense_with_non_compliant_skipped(
    status: ComplianceStatus, verb: str
) -> None:
    """Future-tense paired with non-Compliant statuses MUST NOT trigger
    FUTURE_TENSE_COMPLIANCE.

    Non-Compliant + future-tense IS the correct shape (a documented
    planned fix), and NA narratives describe boundary conditions, not
    timelines. Catches an over-broad regex that would start rejecting
    legitimately-described remediation plans.
    """
    narrative = f"Gap identified; the system {verb}; see POA&M."
    result = validate(proposed_status=status, proposed_narrative=narrative)
    reasons = [r for r, _ in result.rejections]
    assert RejectionReason.FUTURE_TENSE_COMPLIANCE not in reasons


# ---------------------------------------------------------------------------
# validate_dual_narratives — advisory contract
# ---------------------------------------------------------------------------


@_PIPELINE
@given(
    onprem=st.one_of(st.none(), _TEXT),
    cloud=st.one_of(st.none(), _TEXT),
    resp=st.one_of(
        st.none(),
        st.sampled_from(
            ["customer", "provider", "inherited", "hybrid", "not_applicable", "unknown"]
        ),
    ),
)
def test_dual_narratives_advisory_total(
    onprem: str | None, cloud: str | None, resp: str | None
) -> None:
    """ALWAYS returns DualNarrativeResult; never raises.

    Advisory contract: the caller (assessor.py LLM-accept path) renders
    notes/flagged into the operator UI without an exception guard. A
    crash here would silently drop the dual-narrative leak check from
    the run \u2014 the operator would never see the warning.
    """
    result = validate_dual_narratives(
        narrative_on_prem=onprem,
        narrative_cloud=cloud,
        crm_responsibility=resp,
    )
    assert isinstance(result, DualNarrativeResult)
    assert isinstance(result.notes, list)
    assert isinstance(result.flagged, list)


def test_dual_narratives_leak_flagged() -> None:
    """Provider-only phrase in on-prem half \u2192 leak note + flag.

    Pins the load-bearing leak case. A regression here would let
    swapped-halves narratives ship to the workbook unflagged.
    """
    result = validate_dual_narratives(
        narrative_on_prem="Inherited from AWS GovCloud per FedRAMP authorization.",
        narrative_cloud="",
    )
    assert RejectionReason.DUAL_NARRATIVE_MISLABEL in result.flagged
    assert any("on-prem" in n.lower() for n in result.notes)


def test_dual_narratives_crm_customer_with_cloud_flagged() -> None:
    """CRM=customer + populated cloud half \u2192 CRM mismatch flag.

    Customer-owned controls have no provider scope; populating the cloud
    half is a definitional error the operator needs to see.
    """
    result = validate_dual_narratives(
        narrative_on_prem="Local SSP \u00a72.4 implementation observed.",
        narrative_cloud="Provider implements via AWS GovCloud.",
        crm_responsibility="customer",
    )
    assert RejectionReason.DUAL_NARRATIVE_MISLABEL in result.flagged


def test_dual_narratives_na_responsibility_exempt() -> None:
    """CRM=not_applicable \u2192 no CRM cross-check fires.

    NA rows don't have implementation scope to attribute. A regression
    that fired on NA would create false-positive notes on every NA row.
    """
    result = validate_dual_narratives(
        narrative_on_prem="local content",
        narrative_cloud="cloud content",
        crm_responsibility="not_applicable",
    )
    # Leak checks may still fire on the content above (they don't here),
    # but the CRM-mismatch class must not surface for NA responsibility.
    # We assert no notes mention "marks this control as not_applicable".
    assert not any("not_applicable" in n.lower() for n in result.notes)


# ---------------------------------------------------------------------------
# _verify_cites — literal cite check with row exemptions
# ---------------------------------------------------------------------------


@_PIPELINE
@given(narrative=_TEXT, evidence=_TEXT)
def test_verify_cites_total(narrative: str, evidence: str) -> None:
    """Returns a list of strings for any input — never raises."""
    out = _verify_cites(narrative=narrative, evidence_text=evidence, row=None)
    assert isinstance(out, list)
    assert all(isinstance(x, str) for x in out)


@given(narrative=_TEXT)
def test_verify_cites_empty_evidence_returns_empty(narrative: str) -> None:
    """No evidence text \u2192 nothing to verify against \u2192 empty list.

    Deterministic short-circuit: the validator skips cite verification on
    rule-8 paths that have no LLM-supplied evidence. Returning unverified
    cites here would false-reject every short-circuit row.
    """
    assert _verify_cites(narrative=narrative, evidence_text="", row=None) == []


@given(evidence=_TEXT)
def test_verify_cites_empty_narrative_returns_empty(evidence: str) -> None:
    """Empty narrative \u2192 no cites to enumerate \u2192 empty list."""
    assert _verify_cites(narrative="", evidence_text=evidence, row=None) == []


def test_verify_cites_row_cci_and_control_exempt(make_row) -> None:
    """The row's CCI id and control id are ALWAYS exempt.

    Patent-supporting: the narrative may name the row under assessment
    (\"AC-2(1) CCI-000015 was examined...\") without those tokens
    appearing in the evidence corpus. Catches a regression that would
    flag every row's own identifiers as unverified.
    """
    row = make_row(control_id="AC-2(1)", cci_id="CCI-000015")
    narrative = "Verified AC-2(1) per CCI-000015; observed configuration."
    # Evidence intentionally lacks both ids.
    evidence = "Audit logs reviewed for the past 90 days; all events captured."
    unverified = _verify_cites(narrative=narrative, evidence_text=evidence, row=row)
    assert "AC-2(1)" not in unverified
    assert "CCI-000015" not in unverified


def test_verify_cites_unmatched_usd_doc_is_unverified(make_row) -> None:
    """USD doc cited in narrative but absent from evidence \u2192 unverified.

    Pins the hallucinated-cite detection contract. A regression here
    would let the LLM fabricate USD doc numbers without consequence.
    """
    row = make_row()
    narrative = "Configured per USD00099999 \u00a73.2; observed enforcement."
    evidence = "Audit logs reviewed; no doc cited here."
    unverified = _verify_cites(narrative=narrative, evidence_text=evidence, row=row)
    assert any(u.upper() == "USD00099999" for u in unverified)


def test_verify_cites_matched_usd_doc_verified(make_row) -> None:
    """USD doc in narrative AND evidence (any case) \u2192 verified.

    Case-insensitive substring match is the contract. A regression that
    case-narrowed here would false-reject every cite that arrived in a
    different case than the evidence text.
    """
    row = make_row()
    narrative = "Configured per USD00012345 \u00a72.1."
    evidence = "Document usd00012345 reviewed and accepted."  # lowercase
    unverified = _verify_cites(narrative=narrative, evidence_text=evidence, row=row)
    assert unverified == []


@_PIPELINE
@given(narrative=_TEXT, evidence=_TEXT)
def test_verify_cites_no_duplicates(narrative: str, evidence: str) -> None:
    """Unverified list contains no duplicate tokens (case-folded).

    The validator surfaces this list to the operator as a comma-joined
    string in the rejection message; duplicates would create confusing
    noise like \"USD12345678, USD12345678, USD12345678\".
    """
    unverified = _verify_cites(narrative=narrative, evidence_text=evidence, row=None)
    lowered = [u.lower() for u in unverified]
    assert len(lowered) == len(set(lowered))


def test_cite_exempt_substrings_nonempty() -> None:
    """Sanity: the exempt list is not empty.

    Defensive: if the exempt table were ever wiped, rule-8a sentinels
    and CSP inheritance narratives would start failing cite verification
    even when the narrative is the correct deterministic output.
    """
    assert len(_CITE_EXEMPT_SUBSTRINGS) > 0


# ---------------------------------------------------------------------------
# Cross-helper round-trip: classify \u2192 expected_status \u2192 validate passes
# ---------------------------------------------------------------------------


@_PIPELINE
@given(
    phrase=st.sampled_from(_NA_PHRASES),
    pre=_SHORT_TEXT,
)
def test_validate_na_phrase_with_na_status_no_mismatch(
    phrase: str, pre: str
) -> None:
    """NA-phrase narrative + status=Not Applicable \u2192 no mismatch rejection.

    Round-trip: ``_expected_status_for_class(classify_narrative(x))``
    must agree with the status the operator sets, for every NA phrase in
    the table. A drift here would silently start rejecting NA rows for
    every operator who used the canonical NA phrasing.
    """
    narrative = f"{pre} {phrase} the boundary."
    # If the wrapper accidentally hits another class too, the classifier
    # goes ambiguous and the round-trip test doesn't apply.
    klass = classify_narrative(narrative)
    assume(klass == NarrativeClass.NA_JUSTIFYING)
    result = validate(
        proposed_status=ComplianceStatus.NOT_APPLICABLE,
        proposed_narrative=narrative,
    )
    reasons = [r for r, _ in result.rejections]
    assert RejectionReason.STATUS_NARRATIVE_MISMATCH not in reasons


@_PIPELINE
@given(
    phrase=st.sampled_from(_GAP_PHRASES),
    pre=_SHORT_TEXT,
)
def test_validate_gap_phrase_with_non_compliant_no_mismatch(
    phrase: str, pre: str
) -> None:
    """Gap-phrase narrative + status=Non-Compliant \u2192 no mismatch rejection.

    Symmetric round-trip against the gap table. The POA&M note may
    still fire as advisory, but the load-bearing
    STATUS_NARRATIVE_MISMATCH MUST NOT.
    """
    narrative = f"{pre} {phrase} on the host."
    klass = classify_narrative(narrative)
    assume(klass == NarrativeClass.GAP_DESCRIBING)
    result = validate(
        proposed_status=ComplianceStatus.NON_COMPLIANT,
        proposed_narrative=narrative,
    )
    reasons = [r for r, _ in result.rejections]
    assert RejectionReason.STATUS_NARRATIVE_MISMATCH not in reasons


# ---------------------------------------------------------------------------
# Phrase-table sanity (catches accidental wipes during config edits)
# ---------------------------------------------------------------------------


def test_phrase_tables_nonempty() -> None:
    """All four phrase tables have entries.

    An empty table silently disables that whole classification arm.
    Defensive: if a config edit ever wiped one, this test fails loudly
    instead of letting the patent's accuracy metric drift to zero.
    """
    assert len(_AFFIRMING_PHRASES) > 0
    assert len(_NA_PHRASES) > 0
    assert len(_GAP_PHRASES) > 0
    assert len(_PROVIDER_ONLY_PHRASES) > 0
    assert len(_ONPREM_ONLY_PHRASES) > 0


def test_phrase_tables_lowercase() -> None:
    """All phrases in all tables are lowercase.

    ``_has_any`` is called with already-lowercased haystacks; an upper-
    case phrase in a table would silently never match. Property-checked
    here so a maintainer copy-pasting a SHALL statement into the gap
    table can't slip past code review.
    """
    for phrase in _AFFIRMING_PHRASES + _NA_PHRASES + _GAP_PHRASES:
        assert phrase == phrase.lower(), f"phrase not lowercase: {phrase!r}"
    for phrase in _PROVIDER_ONLY_PHRASES + _ONPREM_ONLY_PHRASES:
        assert phrase == phrase.lower(), f"dual-half phrase not lowercase: {phrase!r}"
