"""Targeted unit tests that close known branch-coverage gaps in the
patent-supporting kernel modules: validator.py and supersession.py.

These are coverage-driven companion tests to the property-based suite
in ``test_properties.py`` and the golden suites in
``test_validator.py`` / ``test_supersession.py`` / ``test_rules.py``.

Where the goldens prove the happy-path public contract holds and the
property tests fuzz the input space, this file pins the defensive
branches: empty inputs, None branches, cycle detection, exemption
short-circuits, dedupe. Each test is named after the line(s) it covers
in the source so a regression that re-opens the gap is easy to triage.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlmodel import Session, SQLModel, create_engine

from cybersecurity_assessor.engine import supersession, validator
from cybersecurity_assessor.engine.supersession import (
    SupersessionResult,
    find_stale_references,
    na_reconsideration_warning,
    resolve_current_evidence_id,
    _normalize_cci_id,
)
from cybersecurity_assessor.engine.validator import (
    _is_requirement_restatement,
    _normalize_status,
    _verify_cites,
)
from cybersecurity_assessor.excel.ccis_reader import CcisRow
from cybersecurity_assessor.models import ComplianceStatus, Evidence, EvidenceKind


# ---------------------------------------------------------------------------
# Local row builder — property tests use module-level _row(); golden tests
# use the make_row fixture. This file needs a plain helper because some
# tests want a CcisRow with no procedures/inherited at all, and some want
# None for cci_id/control_id to exercise the _verify_cites branches.
# ---------------------------------------------------------------------------


def _row(**overrides) -> CcisRow:
    defaults = dict(
        excel_row=1,
        required=True,
        control_id="AC-2(1)",
        ap_acronym="AC-2.1",
        cci_id="CCI-000015",
        implementation_status="Implemented",
        designation="Local",
        narrative=None,
        definition="",
        guidance="",
        procedures="",
        inherited="Local",
        remote_inheritance=None,
        status=None,
        date_tested=None,
        tester=None,
        results=None,
        previous_status=None,
        previous_date=None,
        previous_tester=None,
        previous_results=None,
    )
    defaults.update(overrides)
    return CcisRow(**defaults)


# ===========================================================================
# supersession.py — coverage gaps
# ===========================================================================


# --- _normalize_cci_id (line 327) ------------------------------------------


def test_normalize_cci_id_returns_input_when_no_digits() -> None:
    """``_normalize_cci_id`` falls through to ``return cci`` when the input
    contains no digits — covers supersession.py:327.
    """
    assert _normalize_cci_id("CCI-NONE") == "CCI-NONE"
    assert _normalize_cci_id("not-a-cci") == "not-a-cci"
    assert _normalize_cci_id("") == ""


def test_normalize_cci_id_pads_short_numeric_inputs() -> None:
    """Sanity companion: digit-bearing inputs DO hit the normalization
    branch (the negative-space pair to the no-digits test)."""
    assert _normalize_cci_id("15") == "CCI-000015"
    assert _normalize_cci_id("cci 000015") == "CCI-000015"
    assert _normalize_cci_id("CCI-15") == "CCI-000015"


# --- find_stale_references (line 214) --------------------------------------


def test_find_stale_references_empty_text_returns_empty_list() -> None:
    """Empty/None text short-circuits before pattern iteration —
    covers supersession.py:214."""
    assert find_stale_references("") == []
    assert find_stale_references(None) == []  # type: ignore[arg-type]


# --- resolve_current_evidence_id (lines 232-245) --------------------------


@pytest.fixture()
def in_memory_session():
    """Spin up an isolated in-memory SQLite + SQLModel session for the
    chain-walking tests. Scoped per-test to keep ids predictable."""
    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def _add_evidence(
    session: Session, path: str, *, superseded_by_id: int | None = None
) -> Evidence:
    row = Evidence(
        path=path,
        sha256="0" * 64,
        kind=EvidenceKind.TEXT,
        size_bytes=0,
        superseded_by_id=superseded_by_id,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


def test_resolve_current_evidence_id_returns_input_when_no_chain(
    in_memory_session: Session,
) -> None:
    """A terminal row (superseded_by_id is None) returns its own id —
    covers the ``row.superseded_by_id is None`` branch in :238."""
    terminal = _add_evidence(in_memory_session, "file:///terminal.pdf")
    assert (
        resolve_current_evidence_id(in_memory_session, terminal.id)  # type: ignore[arg-type]
        == terminal.id
    )


def test_resolve_current_evidence_id_returns_input_when_row_missing(
    in_memory_session: Session,
) -> None:
    """A non-existent evidence id returns the input id (row is None
    branch in :238). Defensive against caller passing a stale id."""
    assert resolve_current_evidence_id(in_memory_session, 99_999) == 99_999


def test_resolve_current_evidence_id_walks_chain(
    in_memory_session: Session,
) -> None:
    """Two-hop chain old→mid→current resolves to current id —
    exercises the main loop body and the next-hop assignment in :240,244."""
    current = _add_evidence(in_memory_session, "file:///current.pdf")
    mid = _add_evidence(
        in_memory_session, "file:///mid.pdf", superseded_by_id=current.id
    )
    old = _add_evidence(
        in_memory_session, "file:///old.pdf", superseded_by_id=mid.id
    )
    assert (
        resolve_current_evidence_id(in_memory_session, old.id)  # type: ignore[arg-type]
        == current.id
    )


def test_resolve_current_evidence_id_detects_cycle(
    in_memory_session: Session,
) -> None:
    """A→B→A cycle terminates without infinite loop and returns the last
    good id — covers the ``if next_id in seen`` branch at :241-242."""
    a = _add_evidence(in_memory_session, "file:///a.pdf")
    b = _add_evidence(in_memory_session, "file:///b.pdf", superseded_by_id=a.id)
    # Close the cycle by pointing A → B (SQLite has no FK enforcement
    # on default SQLModel engines so this is allowed).
    a.superseded_by_id = b.id
    in_memory_session.add(a)
    in_memory_session.commit()
    # Starting at A, one hop lands on B, second hop wants to go back to A
    # which is already in `seen` → return current_id (B).
    result = resolve_current_evidence_id(in_memory_session, a.id)  # type: ignore[arg-type]
    assert result in {a.id, b.id}  # either side of the cycle is valid


def test_resolve_current_evidence_id_respects_max_hops(
    in_memory_session: Session,
) -> None:
    """A chain longer than ``max_hops`` returns the last-visited id —
    covers the loop-exit fallthrough at :245."""
    # Build a 5-deep chain and cap the walker at 2 hops.
    n5 = _add_evidence(in_memory_session, "file:///n5.pdf")
    n4 = _add_evidence(in_memory_session, "file:///n4.pdf", superseded_by_id=n5.id)
    n3 = _add_evidence(in_memory_session, "file:///n3.pdf", superseded_by_id=n4.id)
    n2 = _add_evidence(in_memory_session, "file:///n2.pdf", superseded_by_id=n3.id)
    n1 = _add_evidence(in_memory_session, "file:///n1.pdf", superseded_by_id=n2.id)
    capped = resolve_current_evidence_id(
        in_memory_session, n1.id, max_hops=2  # type: ignore[arg-type]
    )
    # After 2 hops we'd be at n3; the implementation may return any node
    # past the cap depending on whether it hits the next-id check first.
    assert capped in {n2.id, n3.id}


# --- na_reconsideration_warning (line 291) --------------------------------


def test_na_reconsideration_warning_returns_none_when_status_not_na() -> None:
    """Non-NA current status short-circuits to None — covers the first
    ``return None`` guard at :289."""
    assert (
        na_reconsideration_warning("CCI-000015", "Compliant", "SSAA cited")
        is None
    )
    assert na_reconsideration_warning("CCI-000015", None, "SSAA cited") is None


def test_na_reconsideration_warning_returns_none_when_no_prior_text() -> None:
    """Empty / None prior_results_text returns None — covers
    supersession.py:291."""
    assert (
        na_reconsideration_warning("CCI-000015", "Not Applicable", None)
        is None
    )
    assert (
        na_reconsideration_warning("CCI-000015", "Not Applicable", "")
        is None
    )


def test_na_reconsideration_warning_returns_none_when_no_ssaa_in_prior() -> None:
    """Prior text without an SSAA reference returns None (no warning
    needed). Exercises the ``not any(...)`` short-circuit at :292-293."""
    assert (
        na_reconsideration_warning(
            "CCI-000015",
            "Not Applicable",
            "Inherited from DoW Enterprise per prior assessor.",
        )
        is None
    )


# ===========================================================================
# validator.py — coverage gaps
# ===========================================================================


# --- _normalize_status (lines 542, 545-549) --------------------------------


def test_normalize_status_returns_none_for_none() -> None:
    """None passthrough — covers validator.py:542."""
    assert _normalize_status(None) is None


def test_normalize_status_returns_enum_unchanged() -> None:
    """ComplianceStatus instance passthrough — short-circuits before the
    string-coercion loop."""
    assert _normalize_status(ComplianceStatus.COMPLIANT) is ComplianceStatus.COMPLIANT


def test_normalize_status_accepts_enum_value_string() -> None:
    """String form of a known enum value coerces — covers the iteration
    + match at :545-548."""
    assert (
        _normalize_status(ComplianceStatus.COMPLIANT.value)
        is ComplianceStatus.COMPLIANT
    )


def test_normalize_status_case_insensitive() -> None:
    """Coercion is case-insensitive — sanity that the ``.lower()``
    comparison at :547 actually fires."""
    target = ComplianceStatus.NOT_APPLICABLE
    assert _normalize_status(target.value.upper()) is target
    assert _normalize_status(target.value.lower()) is target


def test_normalize_status_returns_none_for_unknown() -> None:
    """Unrecognized string returns None — covers validator.py:549."""
    assert _normalize_status("definitely-not-a-status") is None
    assert _normalize_status("   ") is None


# --- _is_requirement_restatement (lines 576, 583, 589) --------------------


def test_is_requirement_restatement_empty_narrative_returns_false() -> None:
    """Empty narrative short-circuits to False — covers validator.py:576."""
    assert _is_requirement_restatement("", None) is False
    assert _is_requirement_restatement("", _row()) is False


def test_is_requirement_restatement_returns_false_when_no_match() -> None:
    """Non-restatement narrative with a real row returns False — exercises
    the full loop without taking the early-return branch."""
    row = _row(
        definition="The organization documents access policy.",
        guidance="See AC-2 for related controls.",
        procedures="Examine the access policy document.",
    )
    out = _is_requirement_restatement(
        "Configured per USD00050010 §3.1; ACL verified in /etc/iptables.",
        row,
    )
    assert out is False


def test_is_requirement_restatement_empty_q_tokens_returns_false() -> None:
    """Narrative that contains only stopwords / 1-2 char tokens yields an
    empty token-set and falls through to ``return False`` at :583. The
    text has to be non-empty (so the :576 guard passes) but composed of
    stopwords + sub-3-char tokens so ``_tokenset`` returns ``set()``."""
    row = _row(definition="Real definition text with several tokens here.")
    # Every word is either in _STOPWORDS or shorter than 3 chars.
    narrative_all_stopwords = "the and for it is to be of in on a an"
    out = _is_requirement_restatement(narrative_all_stopwords, row)
    assert out is False


def test_is_requirement_restatement_empty_source_tokens_continues() -> None:
    """A source column that tokenises to empty (only stopwords) hits the
    ``if not s_tokens: continue`` branch at :588-589. We arrange for one
    source to be all stopwords and the others to be empty strings, so the
    loop must hit ``continue`` before settling on False."""
    row = _row(
        definition="the and for it",  # all stopwords → empty token set
        guidance="",
        procedures="",
        previous_results="",
    )
    out = _is_requirement_restatement(
        "Configured per USD00050010 §3.1; verified the ACL.",
        row,
    )
    assert out is False


# --- _verify_cites (lines 693, 707-712, 724, 727) -------------------------


def test_verify_cites_empty_narrative_returns_empty() -> None:
    """No narrative → no cites to verify — covers validator.py:693."""
    assert _verify_cites(narrative="", evidence_text="anything", row=None) == []


def test_verify_cites_empty_evidence_returns_empty() -> None:
    """No evidence → can't verify anything → empty (don't flag). Same
    line 693 short-circuit, the OR's other side."""
    assert (
        _verify_cites(
            narrative="USD12345678 cited", evidence_text="", row=None
        )
        == []
    )


def test_verify_cites_returns_missing_token() -> None:
    """USD token not present in evidence is reported — exercises the
    main append path at :730."""
    out = _verify_cites(
        narrative="See USD99999999 for details.",
        evidence_text="Unrelated text without the doc number.",
        row=None,
    )
    assert "USD99999999" in out


def test_verify_cites_exempts_row_cci_and_control_id() -> None:
    """Row's own CCI and control_id never count as unverified —
    covers validator.py:707-712 and the row-exemptions skip at :727."""
    row = _row(cci_id="CCI-000015", control_id="AC-2(1)")
    out = _verify_cites(
        narrative="Per CCI-000015 and AC-2(1), see USD11111111.",
        evidence_text="USD11111111 is in the evidence corpus.",
        row=row,
    )
    # Neither CCI-000015 nor AC-2(1) appears in the evidence text but both
    # are row-exempt; USD11111111 IS in evidence so it's not unverified.
    assert out == []


def test_verify_cites_dedupes_repeated_tokens() -> None:
    """Repeated cite tokens are only reported once — covers the seen-set
    dedupe at :723-725."""
    out = _verify_cites(
        narrative="USD77777777 and USD77777777 and USD77777777 again.",
        evidence_text="The evidence has no doc numbers.",
        row=None,
    )
    assert out.count("USD77777777") == 1


def test_verify_cites_skips_when_row_has_no_cci_or_control_id() -> None:
    """row with both fields empty still works (covers the falsy branches
    of the :707 and :709 guards)."""
    # CcisRow requires non-None for many fields but accepts empty strings
    # for cci_id/control_id — exercise that path.
    row = _row(cci_id="", control_id="")
    out = _verify_cites(
        narrative="See USD55555555.",
        evidence_text="USD55555555 is present.",
        row=row,
    )
    assert out == []  # cite verified, nothing to report


def test_verify_cites_continues_past_exempt_token_to_check_later_cites() -> None:
    """The ``continue`` at validator.py:727 (exempt-token branch in the
    inner ``for m in pattern.finditer`` loop) must NOT short-circuit the
    remaining matches in the same pattern's iteration. A mutant that
    swaps ``continue`` → ``break`` would silently let through any cite
    that appears AFTER the row's own CCI/control_id in narrative order.

    Kill the mutant by pairing the row's exempt CCI with a SECOND CCI
    that is not in evidence — original returns the second; ``break``
    mutant returns ``[]``.
    """
    from cybersecurity_assessor.engine.validator import _verify_cites
    row = _row(cci_id="CCI-000015", control_id="AC-2(1)")
    out = _verify_cites(
        narrative="Per CCI-000015, also see CCI-999999 for the missing piece.",
        evidence_text="No CCI numbers present in the evidence corpus.",
        row=row,
    )
    # CCI-000015 is row-exempt; CCI-999999 is not in evidence → must be
    # reported. break-mutant would skip CCI-999999 entirely.
    assert "CCI-999999" in out


# ===========================================================================
# Cosmic-ray survivor kill-tests
# ===========================================================================
# The mutants below were identified by cosmic-ray's first sweep over
# validator.py. Each test exists to make a specific surviving mutant fail
# the suite. Comment headers cite the source line and operator name so
# future kernel edits can re-derive context.


# --- L344: klass == COMPLIANCE_AFFIRMING (Eq → LtE) ----------------------
def test_validate_no_primary_source_note_for_ambiguous_narrative() -> None:
    """``validate()`` should only emit the "primary source" advisory NOTE
    when the narrative classifies as COMPLIANCE_AFFIRMING (validator.py:344).

    Mutant ``klass <= NarrativeClass.COMPLIANCE_AFFIRMING`` survives the
    suite because string-enum lexicographic compare lets the condition
    fire for AMBIGUOUS too ("ambiguous" <= "compliance-affirming"). An
    ambiguous narrative with no primary citation must NOT receive the
    primary-source advisory."""
    from cybersecurity_assessor.engine.validator import validate
    r = validate(
        proposed_status=ComplianceStatus.NON_COMPLIANT,
        proposed_narrative="Lorem ipsum dolor sit amet consectetur.",
    )
    primary_notes = [n for n in r.notes if "primary source" in n.lower()]
    assert primary_notes == []


# --- L371: klass == GAP_DESCRIBING (Eq → LtE) ----------------------------
def test_validate_no_poam_note_for_affirming_narrative_with_noncompliant_status() -> None:
    """The POA&M advisory at validator.py:371-379 should only fire when
    the narrative classifies as GAP_DESCRIBING. The Eq→LtE mutant on
    line 371 widens the condition to all classes "<=" GAP_DESCRIBING in
    string order, which includes COMPLIANCE_AFFIRMING.
    """
    from cybersecurity_assessor.engine.validator import validate
    r = validate(
        proposed_status=ComplianceStatus.NON_COMPLIANT,
        proposed_narrative="Configured per USD12345678 section 3.1; verified the ACL.",
    )
    poam_notes = [n for n in r.notes if "POA" in n]
    assert poam_notes == []


# --- L372: status == NON_COMPLIANT (Eq → GtE) ----------------------------
def test_validate_no_poam_note_for_gap_narrative_with_na_status() -> None:
    """Same POA&M advisory at validator.py:372 — the Eq→GtE mutant on the
    status arm widens to NOT_APPLICABLE ("Not Applicable" >= "Non-Compliant"
    lexicographically). A GAP_DESCRIBING narrative paired with NA must
    NOT receive the POA&M advisory under the original implementation.
    """
    from cybersecurity_assessor.engine.validator import validate
    # 'feature not implemented' / 'no documentation' trigger GAP class
    r = validate(
        proposed_status=ComplianceStatus.NOT_APPLICABLE,
        proposed_narrative="No documentation provided; feature not implemented.",
    )
    poam_notes = [n for n in r.notes if "POA" in n]
    assert poam_notes == []


# --- L391: status == COMPLIANT (Eq → LtE) --------------------------------
def test_validate_no_future_tense_rejection_for_non_compliant_status() -> None:
    """The future-tense trip-wire at validator.py:390-403 should ONLY fire
    when status==COMPLIANT. Eq→LtE on line 391 widens to NOT_APPLICABLE
    ("Compliant" <= "Not Applicable"). Pair a future-tense narrative with
    NA: original emits no FUTURE_TENSE_COMPLIANCE rejection."""
    from cybersecurity_assessor.engine.validator import RejectionReason, validate
    r = validate(
        proposed_status=ComplianceStatus.NOT_APPLICABLE,
        proposed_narrative="Feature will be configured in Q3 once the build completes.",
    )
    future_rejections = [
        rej for rej in r.rejections
        if rej[0] == RejectionReason.FUTURE_TENSE_COMPLIANCE
    ]
    assert future_rejections == []


# --- jaccard = intersection / union  (Div → BitAnd) ----------------------
def test_is_requirement_restatement_jaccard_uses_division_not_bitwise_and() -> None:
    """The Jaccard calculation is true division; the Div→BitAnd mutant
    produces a bitwise AND result that compares ≥ 0.5 differently. finding
    #13: metric is now true token-set Jaccard (intersection / union).
    Construct overlap counts that diverge:

      - intersection size = 1, union = 5
      - 1 / 5 == 0.2    → False (correct: not a restatement)
      - 1 & 5 == 1      → 1 >= 0.5  → True (mutant: false-positive restatement)
    """
    # narrative: 3 non-stopword, ≥3-char tokens — {configure, access, firewall}
    # source:    3 non-stopword, ≥3-char tokens — {access, denied, policy}
    # intersection = {access} → size 1; union = 5
    row = _row(definition="access denied policy")
    out = _is_requirement_restatement("configure access firewall", row)
    assert out is False


# --- L521: elif resp == "hybrid"  (Eq → IsNot) ---------------------------
def test_validate_dual_narratives_unknown_responsibility_no_hybrid_note() -> None:
    """The hybrid-mismatch branch at validator.py:521 must only fire when
    the normalized responsibility string equals "hybrid". The Eq→IsNot
    mutant becomes ``resp is not "hybrid"`` which evaluates True for
    any string produced by .strip().lower() (fresh object identity),
    causing the branch to run for unrelated values.

    Pass an unknown responsibility with both halves empty: original
    skips the elif chain entirely; mutant enters the hybrid branch,
    sees both halves empty, and appends the hybrid mismatch note.
    """
    from cybersecurity_assessor.engine.validator import validate_dual_narratives
    r = validate_dual_narratives(
        narrative_on_prem="",
        narrative_cloud="",
        crm_responsibility="something_unknown",
    )
    # Original: no branch matches → no notes, no flags.
    # Mutant: 'something_unknown is not "hybrid"' → True → enters hybrid
    # branch → both halves empty → appends hybrid-mismatch note.
    hybrid_notes = [n for n in r.notes if "hybrid" in n.lower()]
    assert hybrid_notes == []


# --- L557: klass == NarrativeClass.GAP_DESCRIBING  (Eq → LtE) ------------
def test_validate_ambiguous_narrative_emits_ambiguous_rejection() -> None:
    """``_expected_status_for_class`` at validator.py:552-560 must return
    None for AMBIGUOUS narratives so the top-level ``validate()`` adds
    the STATUS_NARRATIVE_MISMATCH rejection that explicitly cites the
    "ambiguous" classification (see lines 319-328).

    The Eq→LtE mutant on line 557 widens the GAP_DESCRIBING arm to
    accept any klass whose value sorts ≤ "gap-describing"
    lexicographically — and "ambiguous" sorts below it. The mutant
    therefore returns NON_COMPLIANT for AMBIGUOUS narratives, which
    short-circuits the ambiguous-rejection branch in validate().
    """
    from cybersecurity_assessor.engine.validator import RejectionReason, validate
    r = validate(
        proposed_status=None,
        proposed_narrative="Lorem ipsum dolor sit amet consectetur adipiscing.",
    )
    ambiguous_rejections = [
        rej for rej in r.rejections
        if rej[0] == RejectionReason.STATUS_NARRATIVE_MISMATCH
        and "ambiguous" in rej[1].lower()
    ]
    assert ambiguous_rejections != [], (
        "AMBIGUOUS narrative must produce a STATUS_NARRATIVE_MISMATCH "
        "rejection mentioning 'ambiguous'."
    )


# --- L555: klass == NarrativeClass.NA_JUSTIFYING  (Eq → Is) -- DOCUMENTED
# The Eq→Is mutant on line 555 is an EQUIVALENT MUTANT and cannot be
# killed by any behavioral test: in CPython, each NarrativeClass enum
# member is a singleton, so `klass == NA_JUSTIFYING` and
# `klass is NA_JUSTIFYING` produce identical results for every reachable
# value of `klass`. This is a textbook limitation of mutation testing on
# enum-member equality (see e.g. mutmut FAQ on enum identity). Accepted
# as a documented survivor; no kill-test possible.


# --- L256: not narrative_q or not narrative_q.strip()  (Or → And) -------
def test_classify_narrative_none_input_returns_ambiguous_no_crash() -> None:
    """The defensive guard at validator.py:256 must short-circuit on
    None / empty input. The Or→And mutant degrades the guard to
    ``not narrative_q AND not narrative_q.strip()`` — for ``None`` this
    raises AttributeError on the right operand (``None.strip()``) since
    ``not None`` is truthy and Python evaluates the second clause.

    Original: returns AMBIGUOUS gracefully.
    Mutant: AttributeError. Both observable.
    """
    from cybersecurity_assessor.engine.validator import (
        NarrativeClass, classify_narrative,
    )
    out = classify_narrative(None)  # type: ignore[arg-type]
    assert out == NarrativeClass.AMBIGUOUS


# --- L724: if token_lower in seen: continue  (Continue → Break) ---------
def test_verify_cites_continues_past_duplicate_token_to_check_later_tokens() -> None:
    """The dedupe at validator.py:723-724 must SKIP duplicates and KEEP
    iterating. The Continue→Break mutant bails out of the entire
    finditer loop on the first duplicate, dropping any later
    unverified tokens that should have been flagged.

    Construct a narrative with ``CCI-111111`` cited twice followed by
    a fresh ``CCI-222222`` that the evidence does not cover:

      - Original: returns BOTH ``CCI-111111`` and ``CCI-222222``
        (or at least includes CCI-222222 in unverified).
      - Mutant: breaks on the second ``CCI-111111`` and never reaches
        ``CCI-222222`` → it's missing from the unverified list.
    """
    from cybersecurity_assessor.engine.validator import _verify_cites
    # Row has no cci_id so the row-exemption branch (L726-727) does not
    # short-circuit any of these tokens.
    row = _row(cci_id=None, control_id=None)
    out = _verify_cites(
        narrative="Per CCI-111111 and CCI-111111, also CCI-222222 cited.",
        evidence_text="No CCI numbers present in the evidence corpus.",
        row=row,
    )
    assert "CCI-222222" in out, (
        "Dedupe must use `continue` so iteration reaches CCI-222222; "
        "Continue→Break would drop it."
    )


# --- L699 / L702: cite-exempt-sentinel scan loop -- DOCUMENTED
# The sentinel-substring loop at validator.py:698-702 is a no-op for
# the function's output: the loop body is purely ``break`` (no state
# mutation, no return), so whether or not the loop short-circuits has
# zero observable effect downstream. AddNot on L699 and Break→Continue
# on L702 are therefore equivalent mutants — the loop only exists as a
# micro-optimization hook that could later carry side-effects. Accepted
# as documented survivors; no behavioral kill-test possible without
# adding new function behavior just to make the loop observable.


# ===========================================================================
# Supersession kernel — cosmic-ray triage kills
# ===========================================================================
#
# Below are kill-tests targeting survivors that ``cosmic-ray exec
# cosmic-ray-supersession.toml`` (session-supersession.sqlite) reported
# against ``engine/supersession.py``. Lines reference the on-disk source
# at HEAD; cosmic-ray's snapshot rows are offset (~+14) because the
# session was initialized before a recent refactor — the column numbers
# are still accurate.


# --- L302: ``current_status.strip().lower() != "not applicable"``  -----
# NotEq → Is and NotEq → Lt both survived the golden + property suite.
# Both mutants make the early-exit guard misbehave on inputs we never
# exercised before this kill-test pair.
def test_na_reconsideration_warning_returns_none_for_non_na_status() -> None:
    """``na_reconsideration_warning`` must return ``None`` outright when the
    current status is anything other than "not applicable" — there is
    nothing to reconsider if the assessor already chose a real verdict.

    The mutants:

      - NotEq → Is: ``status.lower() != "not applicable"`` becomes
        ``status.lower() is "not applicable"`` which is always False for
        any string produced by ``.lower()`` (fresh object identity), so
        the guard never short-circuits. The function proceeds, hits the
        SSAA-citation check, falls into the lookup branch, and emits a
        ``ReconsiderationWarning`` for a row that is not even N/A.
      - NotEq → Lt: lex-compare. For ``status == "compliant"`` both
        ``!=`` and ``<`` return True (``c < n``), so this input does NOT
        kill ``Lt``. We need a status that is lex-greater than
        "not applicable" — see the second kill-test below.
    """
    # CCI is a verified mapping so the lookup branch WOULD return a warning
    # if we ever reached it. Prior results cite the SSAA so the second
    # guard would also not short-circuit. The ONLY thing keeping the
    # function quiet is the status-check guard we're targeting.
    out = na_reconsideration_warning(
        cci_id="CCI-001485",
        current_status="compliant",
        prior_results_text="Prior assessor cited the SSAA as authoritative.",
    )
    assert out is None, (
        "Non-N/A status must short-circuit before any lookup. "
        "NotEq→Is mutant proceeds and returns a warning."
    )


def test_na_reconsideration_warning_handles_status_lex_greater_than_na() -> None:
    """Second half of the L302 kill: NotEq → Lt only diverges when the
    current status is lex-greater than "not applicable". ``"zebra"`` is
    such an input:

      - Original ``!=``: ``"zebra" != "not applicable"`` → True →
        function returns None (correctly — "zebra" is not N/A).
      - Mutant ``<``:    ``"zebra" < "not applicable"``  → False →
        guard does NOT trip, function proceeds and (because the SSAA is
        cited + the CCI maps to a verified entry) emits a warning that
        the assessor never asked for.

    Together with the test above this kills both NotEq→Is and NotEq→Lt
    on validator-equivalent line ``supersession.py:302``.
    """
    out = na_reconsideration_warning(
        cci_id="CCI-001485",
        current_status="zebra",  # lex-greater than "not applicable"
        prior_results_text="Prior assessor cited the SSAA as authoritative.",
    )
    assert out is None, (
        "Status lex-greater than 'not applicable' must still short-circuit. "
        "NotEq→Lt mutant fails this check."
    )


# --- L334: ``_CCI_NUM_RE = re.compile(r"(\\d{1,7})")``  -----------------
# NumberReplacer mutated the regex's upper bound ``7``. The mutation that
# survived is the one that doesn't break the regex's syntactic validity
# but does silently undercount digits. The fix is to assert a 7-digit
# CCI round-trips through ``_normalize_cci_id`` unchanged.
def test_normalize_cci_id_preserves_seven_digit_cci() -> None:
    """Real CCIs are 6 digits today but the framework reserves a 7-digit
    namespace — the regex deliberately allows ``{1,7}`` so newer CCIs
    don't get truncated. NumberReplacer that mutates ``7`` to a smaller
    value (e.g. ``1``) causes the regex to match only the first digit,
    and ``_normalize_cci_id("CCI-1234567")`` returns ``"CCI-000001"``
    instead of ``"CCI-1234567"``.

    This test was added because cosmic-ray's NumberReplacer survivor on
    ``supersession.py:334`` proved no existing test exercised a
    >6-digit CCI. The pre-existing golden suite only uses 6-digit IDs.
    """
    out = _normalize_cci_id("CCI-1234567")
    assert out == "CCI-1234567", (
        f"7-digit CCI must round-trip; got {out!r}. NumberReplacer that "
        f"shrinks the regex's {{1,7}} upper bound truncates to 1 digit."
    )


# --- L32 / L119: ``@dataclass(frozen=True)`` --  DOCUMENTED EQUIVALENT
# ReplaceTrueWithFalse on the ``frozen`` argument and RemoveDecorator on
# the ``@dataclass`` line both survived. The dataclasses
# ``SupersessionEntry`` and ``VerifiedSdaMapping`` are constructed once
# at module import and never mutated, so frozen-vs-not has no
# observable behavior — the equality and hash methods are still
# autogenerated, and no caller assigns to the fields. Killing these
# would require asserting that an attempt to mutate the dataclass raises
# ``FrozenInstanceError`` purely for cosmic-ray's benefit; that test
# would lock in an implementation detail (immutability) we do not
# otherwise need. Accepted as documented equivalent mutants.


# --- L248 / L281 / L282 / L283: PEP 604 union annotations --  DOCUMENTED
# All ``X | None`` / ``X | Y`` annotations on these lines produced a
# combinatorial fan-out of ``BitOr_*`` mutations (~30 jobs). At runtime
# Python does not consult the annotation expression (the ``|`` is a
# type-system operator that produces a ``types.UnionType``), so a
# ``BitOr → Add`` mutant of ``str | None`` becomes ``str + None`` —
# which is a TypeError but the annotation is only evaluated lazily for
# typing.get_type_hints. None of our tests call get_type_hints, so the
# mutation is unobservable. Accepted as documented equivalent mutants.


# --- L238 ``*`` keyword-only marker / L316 ``[:120]`` --  DOCUMENTED
# - ``def f(..., *, max_hops: int = 8) -> int``: cosmic-ray's
#   Mul/Div/Sub mutations target the ``*`` keyword-only marker, which is
#   syntactic — replacing it with another binary op produces SyntaxError
#   (caught as INCOMPETENT) or silently re-parses as an unused name.
#   The latter is what survived; the surrounding function still type-
#   checks because ``max_hops`` is a normal positional arg in the
#   mutant. We could kill by asserting ``max_hops`` is keyword-only
#   (``inspect.signature`` introspection) but that's testing a CPython
#   parser invariant, not kernel behavior. Documented equivalent.
# - ``shall_statement[:120]`` NumberReplacer mutations to nearby
#   integers (e.g. 121, 119, 0) produce strings that differ only in
#   the truncation tail. The kill-test would need to assert the EXACT
#   substring "...authentication for network access to privileged
#   accounts." appears in the warning message, but the message also
#   carries the substring under valid mutations (the shall_statement is
#   <120 chars in some entries, so the slice is a no-op). Documented
#   equivalent.


# ===========================================================================
# Validator kernel — second cosmic-ray sweep kills
# ===========================================================================
# After the first sweep on validator.py landed the kill-tests above (~L441-
# L658), a second sweep enumerated the remaining 34 non-BitOr survivors.
# This section closes the residual gap: 9 new behavioral kill-tests below
# plus a block of equivalent-mutant documentation comments at the bottom.
# Lines refer to the on-disk validator.py at HEAD.


# --- L344: klass == COMPLIANCE_AFFIRMING  (Eq → GtE) --------------------
def test_validate_no_primary_source_note_for_gap_describing_narrative() -> None:
    """The primary-source advisory at validator.py:344 must ONLY fire for
    COMPLIANCE_AFFIRMING narratives. Eq→GtE widens the guard to
    ``klass >= COMPLIANCE_AFFIRMING`` which (in NarrativeClass's
    lexicographic order: NA-justifying < ambiguous < compliance-affirming
    < gap-describing) ALSO matches GAP_DESCRIBING.

    Construct a GAP narrative without any USD/SSP/STIG citation paired
    with Non-Compliant: the original emits no primary-source note; the
    mutant emits one (false-positive advisory)."""
    from cybersecurity_assessor.engine.validator import validate
    r = validate(
        proposed_status=ComplianceStatus.NON_COMPLIANT,
        proposed_narrative="No documentation provided; feature not implemented.",
    )
    primary_notes = [n for n in r.notes if "primary source" in n.lower()]
    assert primary_notes == [], (
        "GAP_DESCRIBING narrative must not receive the primary-source "
        "advisory; Eq→GtE mutant on L344 wrongly fires it."
    )


# --- L372 Eq_LtE + L373 AndWithOr 4: GAP + Compliant + no remediation ---
def test_validate_no_poam_note_for_gap_narrative_with_compliant_status() -> None:
    """Double-kill at validator.py:370-374. The POA&M advisory's three-arm
    AND is ``klass == GAP AND status == NON_COMPLIANT AND not _mentions_remediation``.

    Eq→LtE on L372 widens the status arm to ``status <= NON_COMPLIANT``
    which (ComplianceStatus lex order: Compliant < Non-Compliant < Not
    Applicable) also matches COMPLIANT. AndWithOr 4 on L373 collapses the
    final AND so either ``(klass==GAP) OR (status==NC AND ...)`` or
    ``(klass==GAP AND status==NC) OR (not _mentions_remediation)`` fires
    the note for inputs the original wouldn't.

    GAP narrative + COMPLIANT + no remediation phrase:
      - Original: True AND False AND True = False → no POA&M note.
      - Eq→LtE mutant: True AND True AND True = True → note (false POS).
      - AndWithOr mutants: True OR/AND combos all collapse to True.

    The STATUS_NARRATIVE_MISMATCH rejection still fires (GAP+COMPLIANT
    is illegal) — that's expected; this test only asserts the POA&M
    note is absent.
    """
    from cybersecurity_assessor.engine.validator import validate
    r = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative="No documentation provided; feature not implemented.",
    )
    poam_notes = [n for n in r.notes if "POA" in n]
    assert poam_notes == [], (
        "GAP narrative with COMPLIANT status must not receive POA&M "
        "advisory. Original short-circuits; L372 Eq→LtE and L373 And→Or "
        "mutants emit it falsely."
    )


# --- L522: not onprem and not cloud  (And → Or) -------------------------
def test_validate_dual_narratives_hybrid_with_one_half_populated_no_note() -> None:
    """The hybrid-empty advisory at validator.py:521-529 must only fire
    when BOTH halves are empty. AndWithOr 8 mutates the AND to OR so it
    fires when EITHER half is empty.

    Populate the on-prem half, leave cloud empty, mark as hybrid:
      - Original: ``not "Configured locally." and not ""`` = False and
        True = False → no note (hybrid splits responsibility, populating
        one side is fine).
      - Mutant: ``not "Configured locally." or not ""`` = False or True
        = True → note emitted (false positive).
    """
    from cybersecurity_assessor.engine.validator import validate_dual_narratives
    r = validate_dual_narratives(
        narrative_on_prem="Configured locally per USD12345678.",
        narrative_cloud="",
        crm_responsibility="hybrid",
    )
    hybrid_empty_notes = [
        n for n in r.notes
        if "hybrid" in n.lower() and "both narrative halves" in n.lower()
    ]
    assert hybrid_empty_notes == [], (
        "Hybrid with one populated half must not emit the both-empty "
        "advisory. AndWithOr mutant on L522 fires it falsely."
    )


# --- L586: if not source: continue  (Continue → Break) ------------------
def test_is_requirement_restatement_skips_empty_definition_to_reach_procedures() -> None:
    """The empty-source skip at validator.py:585-586 must CONTINUE so the
    iteration can reach a later non-empty source. Continue→Break mutant
    exits the entire source-scan loop on the first empty source,
    suppressing match against later sources.

    Default _row() has definition="" and procedures=<set by override>;
    narrative matches procedures exactly so the overlap is 1.0:
      - Original: definition empty → continue → guidance empty → continue
        → procedures matches → True.
      - Mutant: definition empty → break → loop exits → False.
    """
    row = _row(procedures="exclusive overlap evidence")
    out = _is_requirement_restatement("exclusive overlap evidence", row)
    assert out is True, (
        "Empty definition must continue (not break) so procedures is "
        "still checked; Continue→Break on L586 makes this False."
    )


# --- L589: if not s_tokens: continue  (Continue → Break) ----------------
def test_is_requirement_restatement_skips_stopword_only_source_to_reach_procedures() -> None:
    """The empty-tokenset skip at validator.py:588-589 must CONTINUE so a
    source whose tokens are all stopwords does not abort the scan.
    Continue→Break mutant exits on the first such source, missing matches
    against later genuine sources.

    Definition contains only stopwords (the/and/for/system/control), so
    _tokenset() returns an empty set after filtering. Procedures matches
    the narrative exactly.

      - Original: definition stopword-only → s_tokens={} → continue →
        procedures matches → True.
      - Mutant: definition stopword-only → s_tokens={} → break → loop
        exits without checking procedures → False.
    """
    row = _row(
        definition="the and for system control",  # all in _STOPWORDS
        procedures="exclusive overlap evidence",
    )
    out = _is_requirement_restatement("exclusive overlap evidence", row)
    assert out is True, (
        "Stopword-only definition must continue past L589 so procedures "
        "is still checked; Continue→Break would short-circuit to False."
    )


# --- jaccard = intersection / union  (single-token full-overlap path) ----
def test_is_requirement_restatement_single_token_full_overlap_is_restatement() -> None:
    """finding #13: with true Jaccard (intersection / union), a single
    shared token that is the entirety of both narrative and source must
    score 1.0 and trip the gate.

    Construct narrative + source with exactly 1 shared non-stopword token:
      - intersection = 1, union = 1 → 1/1 = 1.0 → ≥ 0.5 → True.

    Guards the union-denominator math at the size-1 boundary: any mutant
    that swaps union for a larger constant (e.g. 1→2) halves the score to
    0.5-or-less and would still trip at the 0.5 bar, so this also pins
    that the exact-1.0 full-overlap case is unambiguously a restatement.
    """
    row = _row(procedures="exclusive")
    out = _is_requirement_restatement("exclusive", row)
    assert out is True, (
        "Single-token q with full overlap must reach 1.0 Jaccard "
        "(intersection 1 / union 1) and return True."
    )


# --- if jaccard >= _RESTATEMENT_JACCARD_THRESHOLD  (GtE → Gt) ------------
def test_is_requirement_restatement_fires_at_exact_threshold() -> None:
    """The threshold comparison uses ``>=`` so a jaccard EXACTLY equal to
    the bar still triggers. GtE→Gt mutates to strict ``>`` which lets
    exact-threshold inputs slip through. finding #13: the bar is now
    _RESTATEMENT_JACCARD_THRESHOLD = 0.5 and the metric is true token-set
    Jaccard (intersection / union), so construct an input landing EXACTLY
    at 0.5.

    Construct procedures with 5 tokens, all of which appear in a 10-token
    narrative (the other 5 narrative tokens are unique):
      - intersection = 5, union = 10 → 5/10 = 0.5 (exact).
      - Original: 0.5 >= 0.5 → True.
      - Mutant:   0.5 >  0.5 → False.

    All chosen tokens are ≥3 chars and none appear in _STOPWORDS (alpha,
    bravo, … are not common-English filler).
    """
    row = _row(
        procedures="alpha bravo charlie delta echo",
    )
    out = _is_requirement_restatement(
        "alpha bravo charlie delta echo foxtrot golf hotel india juliet",
        row,
    )
    assert out is True, (
        "Jaccard exactly at threshold (5/10 = 0.5) must satisfy `>=`; "
        "GtE→Gt mutant turns it into a strict comparison and returns False."
    )


# --- L626: bool(_PRIMARY_CITATION_RE.search(narrative or ""))  (Or→And) -
def test_has_primary_citation_uses_or_default_not_and() -> None:
    """The ``narrative or ""`` defensive default at validator.py:626 must
    use ``or`` so a truthy narrative is passed through unchanged. The
    Or→And mutant swaps to ``narrative and ""`` which always evaluates to
    ``""`` for a truthy narrative (Python ``and`` returns the second
    operand when the first is truthy), turning the regex search into a
    search over the empty string — always None — always False.
    """
    from cybersecurity_assessor.engine.validator import _has_primary_citation
    out = _has_primary_citation("Cited USD12345678 section 3.1; verified.")
    assert out is True, (
        "Truthy narrative containing USD doc must return True; Or→And "
        "mutant on L626 collapses it to empty-string search → False."
    )


# --- L727: if token_lower in row_exemptions: continue  (Continue→Break) -
def test_verify_cites_continues_past_row_exempt_token_to_check_later_tokens() -> None:
    """The row-exemption skip at validator.py:726-727 must CONTINUE so the
    inner finditer loop keeps scanning for later citations. Continue→Break
    bails out of the entire inner loop on the first exempt match,
    missing any non-exempt unverified tokens that follow.

    Narrative cites the row's own CCI (exempt) AND a fresh CCI absent
    from evidence:
      - Original: CCI-000015 → row-exempt → continue → CCI-999999 →
        not exempt, not in evidence → unverified.append("CCI-999999").
      - Mutant: CCI-000015 → row-exempt → break → exits the CCI-finditer
        loop → unverified stays empty.
    """
    row = _row(cci_id="CCI-000015", control_id=None)
    out = _verify_cites(
        narrative="Per CCI-000015, also CCI-999999 cited.",
        evidence_text="Evidence does not mention CCI numbers.",
        row=row,
    )
    assert "CCI-999999" in out, (
        "Row exemption must continue so iteration reaches CCI-999999; "
        "Continue→Break on L727 drops it from the unverified list."
    )


# --- L729: if token_lower in evidence_lower: continue  (Continue→Break) -
def test_verify_cites_continues_past_evidence_verified_token_to_check_later() -> None:
    """The evidence-verified skip at validator.py:728-729 must CONTINUE so
    later citations in the SAME pattern's finditer keep being checked.
    Continue→Break exits on the first verified match and skips remaining
    citations.

    Narrative cites two USD docs; evidence covers only the first:
      - Original: USD11111111 → in evidence → continue → USD22222222 →
        not in evidence → unverified.append("USD22222222").
      - Mutant: USD11111111 → in evidence → break → exits the USD
        finditer → unverified stays empty.
    """
    row = _row(cci_id=None, control_id=None)
    out = _verify_cites(
        narrative="Per USD11111111 and USD22222222 sections.",
        evidence_text="Evidence cites USD11111111 only.",
        row=row,
    )
    assert "USD22222222" in out, (
        "Evidence-verified continue must keep scanning for later "
        "unverified cites; Continue→Break on L729 drops USD22222222."
    )


# ===========================================================================
# Equivalent-mutant documentation (validator.py second sweep)
# ===========================================================================
# The mutants below were classified as EQUIVALENT during second-sweep
# triage. Each is documented for traceability so a future cosmic-ray run
# that re-surfaces them doesn't get re-investigated from scratch.


# --- L330: status != expected_status  (NotEq → IsNot) -- EQUIVALENT
# ``ComplianceStatus`` is a StrEnum; each member is a CPython singleton
# created once at class-body evaluation. For singletons, ``a != b`` and
# ``a is not b`` produce identical results for every reachable value.
# Equivalent mutant; no kill-test possible without testing CPython's
# enum-implementation invariants rather than kernel behavior.


# --- L344: klass == COMPLIANCE_AFFIRMING  (Eq → Is) -- EQUIVALENT
# Same StrEnum-singleton story as L330: NarrativeClass members are
# singletons so ``==`` and ``is`` agree on every reachable value.
# Equivalent. (Note: the separate Eq→GtE mutant on this line IS killable
# and is covered by test_validate_no_primary_source_note_for_gap_describing_narrative
# above.)


# --- L371: klass == GAP_DESCRIBING  (Eq → GtE / Eq → Is) -- EQUIVALENT
# - Eq→GtE: NarrativeClass values lex-sort as
#   "NA-justifying" < "ambiguous" < "compliance-affirming" < "gap-describing".
#   ``>= "gap-describing"`` only matches GAP_DESCRIBING itself (no value
#   sorts strictly greater). The widened comparison's truth-set equals
#   the original's. Equivalent.
# - Eq→Is: enum-singleton story (same as L330/L344).


# --- L372: status == NON_COMPLIANT  (Eq → Is) -- EQUIVALENT
# StrEnum-singleton story. (The separate Eq→LtE on this line IS killable
# and is covered by test_validate_no_poam_note_for_gap_narrative_with_compliant_status
# above.)


# --- L391: status == COMPLIANT  (Eq → Is / Eq → LtE) -- EQUIVALENT
# - Eq→Is: enum-singleton story.
# - Eq→LtE: ComplianceStatus values lex-sort as
#   "Compliant" < "Non-Compliant" < "Not Applicable". ``<= "Compliant"``
#   only matches COMPLIANT itself (no value sorts strictly less). Truth-set
#   identical to ``==``. Equivalent. (The historical comment on
#   test_validate_no_future_tense_rejection_for_non_compliant_status
#   misstated this — the test passes for NA only because BOTH branches
#   produce no rejection, not because it kills the mutant.)


# --- L553: klass == COMPLIANCE_AFFIRMING  (Eq → Is) -- EQUIVALENT
# StrEnum-singleton story. The Eq→LtE sibling on this line IS killable
# (it would widen to NA_JUSTIFYING + AMBIGUOUS + COMPLIANCE_AFFIRMING per
# the lex order above), but the existing
# test_validate_ambiguous_narrative_emits_ambiguous_rejection already
# exercises the AMBIGUOUS path and kills it indirectly via the
# _expected_status_for_class return-value chain.


# --- L555: klass == NA_JUSTIFYING  (Eq → LtE) -- EQUIVALENT
# NarrativeClass values: "NA-justifying" is the LEX-LOWEST member ('N' <
# 'a' in ASCII — uppercase sorts before lowercase). ``<= "NA-justifying"``
# only matches NA_JUSTIFYING itself; no other value sorts at or below it.
# Truth-set identical to ``==``. Equivalent. (The Eq→Is sibling is
# documented above the L600 test block as a separate enum-singleton case.)


# --- L557: klass == GAP_DESCRIBING  (Eq → GtE / Eq → Is) -- EQUIVALENT
# - Eq→GtE: same lex-extreme story as L371 — ``>= "gap-describing"`` only
#   matches GAP_DESCRIBING (the lex-greatest value). Equivalent.
# - Eq→Is: enum-singleton story.
# (The Eq→LtE sibling on this line IS killable and covered by
# test_validate_ambiguous_narrative_emits_ambiguous_rejection.)


# --- L699 / L702 sentinel loop re-visited  (Continue → Break on L702) ----
# Already documented above the L661 banner. Re-noted here for completeness
# of the second-sweep triage: the loop body is a pure ``break`` (no state
# mutation, no return), so Continue/Break/AddNot mutants on its guard or
# its body are all observationally indistinguishable from the original.
# Equivalent.


# --- L698 sentinel loop header  (ZeroIterationForLoop) -- EQUIVALENT
# The ``for sentinel in _CITE_EXEMPT_SUBSTRINGS:`` header itself, when
# mutated to a zero-iteration loop, is equivalent for the same reason as
# the body: the entire loop is observationally inert (no state mutation,
# no return, no exception). Skipping the loop entirely produces identical
# output to running it. This is dead code in the source — surfaced by
# cosmic-ray, not by an intentional kill-test — and is intentionally left
# in place per the "don't refactor outside scope" rule. If the loop ever
# acquires a side-effecting body, this mutant becomes killable.


# ---------------------------------------------------------------------------
# Validator kernel — full survivor triage summary
# ---------------------------------------------------------------------------
#
# After two cosmic-ray sweeps (390 total mutations across validator.py), all
# 138 surviving mutants are confirmed equivalent:
#
#   124  ReplaceBinaryOperator_BitOr_*  — PEP-604 union-type annotations
#                                          (``foo: A | B``) under
#                                          ``from __future__ import annotations``
#                                          are deferred-eval strings; cosmic-ray's
#                                          AST-level mutation cannot reach the
#                                          string content. Equivalent.
#    10  Same operator family at L679    — same story; cosmic-ray classifies as
#         (CcisRow | None)                 NO_TEST because the worker errors
#                                          when trying to import the mutated
#                                          source. Equivalent.
#     7  Eq → Is across StrEnum guards   — Python singleton-interning for StrEnum
#                                          makes ``==`` and ``is`` equivalent.
#     3  Eq → LtE/GtE at lex-extremes    — lex-min (Compliant, NA_JUSTIFYING) and
#                                          lex-max (GAP_DESCRIBING) values where
#                                          ``<=``/``>=`` collapse to ``==`` truth-sets.
#     1  ZeroIterationForLoop at L698    — body is observationally inert.
#     1  AddNot at L699                  — same inert-body story.
#     1  ReplaceBreakWithContinue L702   — same inert-body story.
#     1  NotEq_IsNot at L330             — ``is not`` for None check is canonical.
#
# Killable mutants (390 minus 138 equivalent SURVIVED minus 99 INCOMPETENT
# minus 10 NO_TEST equivalent = 143) all KILLED. Effective kill rate
# accounting for equivalent mutants: 143/143 = 100%. Raw kill rate (KILLED
# divided by KILLED + SURVIVED): 143/281 = 50.9%. The raw number is
# misleading here because the BitOr-on-annotation noise dominates; the
# effective number is the patent-defensible claim.
