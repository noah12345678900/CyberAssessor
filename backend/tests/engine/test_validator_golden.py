"""Golden tests for the pre-write narrative validator (rule #11).

The validator in ``engine.validator`` is the second of the four
patent-supporting kernel guards. It catches a class of LLM error vanilla
prompting cannot reliably prevent: parroting back the col I/J/K shall
statement instead of documenting what was examined and observed. Every
rejection here is a measurable accuracy-improvement event that the run
recorder logs as a ``ValidatorRejection`` (the patent's accuracy claim
rolls these up).

The validator's actual rejection enum (``RejectionReason``) is:

    REQUIREMENT_RESTATEMENT
    STATUS_NARRATIVE_MISMATCH
    MISSING_INHERITANCE_MARKER
    UNSUPPORTED_DOC_CITATION
    FORMAT_VIOLATION

Note: ``MISSING_PRIMARY_CITATION`` is NOT a rejection — it's surfaced as
a ``note`` on the result. ``CLASSIFICATION_AMBIGUOUS`` doesn't exist —
ambiguous narratives produce a STATUS_NARRATIVE_MISMATCH whose message
contains ``classified=ambiguous``.

Each test below pins one named path through ``validate``.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the backend package is importable when pytest is launched from any cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor.engine.validator import (  # noqa: E402
    RejectionReason,
    classify_narrative,
    validate,
)
from cybersecurity_assessor.excel.ccis_reader import CcisRow  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    ComplianceStatus,
    NarrativeClass,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row(
    *,
    definition: str | None = None,
    guidance: str | None = None,
    procedures: str | None = None,
    previous_results: str | None = None,
) -> CcisRow:
    """Build a minimal CcisRow exposing only the fields the validator reads."""
    return CcisRow(
        excel_row=10,
        required=True,
        control_id="AC-1",
        ap_acronym="AC-1.1",
        cci_id="CCI-000001",
        implementation_status=None,
        designation=None,
        narrative=None,
        definition=definition,
        guidance=guidance,
        procedures=procedures,
        inherited=None,
        remote_inheritance=None,
        status=None,
        date_tested=None,
        tester=None,
        results=None,
        previous_status=None,
        previous_date=None,
        previous_tester=None,
        previous_results=previous_results,
    )


def _has_rejection(result, reason: RejectionReason) -> bool:
    return any(r == reason for r, _msg in result.rejections)


# ---------------------------------------------------------------------------
# Narrative classification (the table that drives status-mismatch detection)
# ---------------------------------------------------------------------------


def test_classify_compliance_affirming_clean_narrative():
    """Affirming verb + USD doc citation → COMPLIANCE_AFFIRMING, no rejections."""
    narrative = (
        "AC-2 account management procedures are documented in USD00050010 §3.2 "
        "and verified via inspection of the production account roster."
    )

    klass = classify_narrative(narrative)
    assert klass is NarrativeClass.COMPLIANCE_AFFIRMING

    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
    )
    assert result.ok
    assert result.rejections == []


def test_classify_na_justifying():
    """'Not applicable because ...' → NA_JUSTIFYING."""
    narrative = "Not applicable because the system does not include wireless networking."

    assert classify_narrative(narrative) is NarrativeClass.NA_JUSTIFYING

    result = validate(
        proposed_status=ComplianceStatus.NOT_APPLICABLE,
        proposed_narrative=narrative,
    )
    assert result.ok


def test_classify_gap_describing():
    """Gap phrase + Non-Compliant + POA&M mention → clean GAP_DESCRIBING pass."""
    narrative = (
        "No artifact found documenting the account review cadence; "
        "remediation tracked via POA&M Example System-2026-014."
    )

    assert classify_narrative(narrative) is NarrativeClass.GAP_DESCRIBING

    result = validate(
        proposed_status=ComplianceStatus.NON_COMPLIANT,
        proposed_narrative=narrative,
    )
    assert result.ok


def test_classify_ambiguous_multi_class_hit():
    """Narrative with BOTH affirming AND gap phrases → AMBIGUOUS → mismatch rejection."""
    narrative = (
        "Verified in USD00050010 §3.2 that the procedure is documented; however, "
        "no evidence found that the quarterly review actually occurred."
    )

    assert classify_narrative(narrative) is NarrativeClass.AMBIGUOUS

    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
    )
    assert not result.ok
    # The validator surfaces this as a status-narrative mismatch whose message
    # names the ambiguous classification (the patent claim hangs on the run
    # recorder seeing this rejection class).
    assert _has_rejection(result, RejectionReason.STATUS_NARRATIVE_MISMATCH)
    msg = next(m for r, m in result.rejections if r == RejectionReason.STATUS_NARRATIVE_MISMATCH)
    assert "classified=ambiguous" in msg


def test_status_class_mismatch_compliant_with_gap_narrative():
    """proposed_status=Compliant + GAP_DESCRIBING narrative → STATUS_NARRATIVE_MISMATCH."""
    narrative = "No evidence found for quarterly account review; remediation pending."

    assert classify_narrative(narrative) is NarrativeClass.GAP_DESCRIBING

    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
    )
    assert not result.ok
    assert _has_rejection(result, RejectionReason.STATUS_NARRATIVE_MISMATCH)


# ---------------------------------------------------------------------------
# Requirement-restatement (the anti-pattern rule #11 v1.0.11 added)
# ---------------------------------------------------------------------------


def test_regex_restatement_anti_pattern_reviewed_cci():
    """Narrative starts with 'Reviewed CCI; confirmed the requirement ...' → restatement."""
    narrative = "Reviewed CCI-000015; confirmed the requirement that the system shall enforce."

    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
    )
    assert not result.ok
    assert _has_rejection(result, RejectionReason.REQUIREMENT_RESTATEMENT)


def test_regex_restatement_anti_pattern_system_shall_as_required():
    """'... the system shall ... as required' phrasing → restatement."""
    narrative = "The system shall enforce least privilege as required by the control objective."

    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
    )
    assert _has_rejection(result, RejectionReason.REQUIREMENT_RESTATEMENT)


def test_jaccard_restatement_against_col_i_definition():
    """Narrative shares >= half its combined vocabulary with col I → restatement.

    finding #13: token-set Jaccard is now the TRUE textbook metric
    ``|Q ∩ source| / |Q ∪ source|`` against the new
    ``_RESTATEMENT_JACCARD_THRESHOLD`` (0.5). The old pin asserted the
    MISNAMED containment metric ``|Q ∩ source| / |Q|`` at 0.70, which
    over-fired on short grounded narratives fully contained in a long
    requirement (see the contained-but-not-restatement test below). A genuine
    restatement reuses nearly the whole requirement vocabulary, so its Jaccard
    clears 0.5: here Q's distinctive tokenset is essentially equal to the
    definition's, giving Jaccard ≈ 1.0.
    """
    definition = (
        "Organization establishes conditions group role membership monitors usage accounts."
    )
    # Same distinctive tokenset as definition (after stopword strip) → union ≈
    # intersection → Jaccard ≈ 1.0, well over the 0.5 bar.
    narrative = (
        "Organization establishes conditions group role membership monitors "
        "usage accounts establishes group role membership."
    )

    row = _row(definition=definition)
    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
        row=row,
    )
    assert _has_rejection(result, RejectionReason.REQUIREMENT_RESTATEMENT)


def test_short_narrative_contained_in_long_requirement_is_not_restatement():
    """finding #13: short grounded narrative fully contained in a long
    requirement → NOT a restatement under true Jaccard.

    This is the case the OLD misnamed metric got wrong. EVERY distinctive
    token of the narrative also appears in the (much longer) col-I
    definition, so containment ``|Q∩S|/|Q|`` = 1.0 → the old 0.70 bar
    FALSE-REJECTED it as a restatement, the assessor looped/abstained, and a
    real verdict was lost. True Jaccard normalizes by the union: a small Q
    fully inside a large S shares only a small fraction of the COMBINED
    vocabulary, so Jaccard stays well below 0.5 → correctly accepted.
    Concretely, Q's distinctive tokenset is {establishes, group, role,
    membership} (4 tokens, ALL in S); S has ~20 distinctive tokens; so
    containment = 4/4 = 1.0 (old → REJECT) but Jaccard = 4/|Q∪S| = 4/~20 ≈
    0.20 (new → ACCEPT). The two metrics give opposite verdicts on this
    input, which is the whole point of the fix.
    """
    definition = (
        "The organization establishes and documents conditions for group "
        "membership and role membership, monitors usage of information system "
        "accounts, reviews account activity periodically, disables inactive "
        "accounts, notifies account managers when accounts are no longer "
        "required, and audits the creation, modification, enabling, disabling, "
        "and removal of every account across the enterprise environment."
    )
    # Short, genuine narrative whose distinctive tokens are ALL present in the
    # long definition (establishes, group, role, membership) -- the worst case
    # for containment, the easy case for Jaccard.
    narrative = "Establishes group role membership."

    row = _row(definition=definition)
    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
        row=row,
    )
    assert not _has_rejection(result, RejectionReason.REQUIREMENT_RESTATEMENT)


def test_jaccard_below_threshold_passes_restatement_check():
    """Narrative with only ~30% token overlap with col I → no restatement rejection.

    A clean compliance-affirming narrative shares some tokens with the
    requirement (control IDs, "account") but stays under the Jaccard bar
    (finding #13: _RESTATEMENT_JACCARD_THRESHOLD = 0.5; true Jaccard only
    lowers this overlap further than the old containment metric did, so the
    accept verdict is unchanged).
    """
    definition = (
        "The organization establishes conditions for group and role membership "
        "and monitors usage of information system accounts."
    )
    narrative = (
        "Account roster reviewed quarterly and documented in USD00050010 §3.2; "
        "verified via inspection of the December 2025 review minutes."
    )

    row = _row(definition=definition)
    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
        row=row,
    )
    assert not _has_rejection(result, RejectionReason.REQUIREMENT_RESTATEMENT)


# ---------------------------------------------------------------------------
# Primary-citation note (surfaced as a note, NOT a rejection)
# ---------------------------------------------------------------------------


def test_compliant_without_primary_citation_emits_note_not_rejection():
    """Affirming narrative with no USD/SSP/STIG/GovCloud citation → note, not rejection.

    Per validator.py:251-258 the primary-citation check appends to
    ``result.notes`` so the UI can surface "consider strengthening" without
    blocking the write. Tests must assert on notes, not rejections.
    """
    narrative = "Verified that the procedure is configured to enforce account management."

    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
    )
    # No primary citation, but no hard rejection either.
    assert result.ok
    assert any("primary source" in n.lower() for n in result.notes)


def test_compliant_with_usd_doc_citation_passes_with_no_note():
    """Affirming narrative naming USD doc → no missing-citation note."""
    narrative = "Configured to enforce session lock per USD00050010 §4.1."

    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
    )
    assert result.ok
    assert not any("primary source" in n.lower() for n in result.notes)


# ---------------------------------------------------------------------------
# Inheritance source naming (MISSING_INHERITANCE_MARKER)
# ---------------------------------------------------------------------------


def test_inherited_narrative_without_source_rejected():
    """'inherited from' with no source token → MISSING_INHERITANCE_MARKER rejection.

    The source regex is ``inherited from\\s+(?:the\\s+)?(dow|dod|enterprise|...|[A-Z][\\w\\s\\-]+)``
    compiled with ``re.IGNORECASE``, so the ``[A-Z]`` catch-all matches ANY
    letter — "inherited from somewhere" would pass. To force a miss we put
    punctuation immediately after "from" so the ``\\s+`` cannot consume
    whitespace + source token. Pair with an affirming verb so the narrative
    classifies as COMPLIANCE_AFFIRMING and the only rejection is the
    inheritance-source one (not a separate status-mismatch).
    """
    narrative = "Verified that this capability is inherited from. No source identified."

    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
    )
    assert _has_rejection(result, RejectionReason.MISSING_INHERITANCE_MARKER)


def test_inherited_narrative_naming_dow_passes_inheritance_check():
    """'inherited from DoW Enterprise' satisfies the inheritance source check."""
    narrative = "Configured per parent system policy; inherited from DoW Enterprise IAM."

    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
    )
    assert not _has_rejection(result, RejectionReason.MISSING_INHERITANCE_MARKER)


# ---------------------------------------------------------------------------
# Rule-#8 template path: validator must accept rule-#8 auto-narratives
# ---------------------------------------------------------------------------


def test_rule8_template_skips_jaccard_when_row_is_none():
    """Rule-#8 narratives echo the trigger phrase verbatim from col K.

    The assessor passes ``row=None`` when validating a rule-#8 auto-narrative
    (see assessor.py:407-411) precisely so Jaccard doesn't trip — the auto
    narrative quotes col K text directly. This test pins that contract:
    a rule-8a template narrative passes when row=None.
    """
    # Verbatim template from rules._format_8a_text_narrative.
    narrative = 'Automatically compliant per Assessment Procedures (col K): "automatically compliant".'

    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
        row=None,  # The contract the assessor relies on.
    )
    assert result.ok
    assert result.rejections == []
    # Validator should recognize "automatically compliant per assessment procedures"
    # as a primary citation, so no note either.
    assert not any("primary source" in n.lower() for n in result.notes)


def test_rule_8a_col_k_template_exempt_from_assessment_procedure_guard():
    """bug(c) regression: the deterministic rule-8a col-K template must NOT
    trip the ASSESSMENT_PROCEDURE_AS_SOURCE guard.

    The guard (added 2026-06-10) rejects narratives that cite the eMASS
    column-K 'assessment procedures' as if they were evidence. But the
    kernel's own rule-8a auto-narrative
    (``rules._format_8a_text_narrative``) legitimately reads
    ``Automatically compliant per Assessment Procedures (col K): "..."`` —
    rule 8a *means* "the assessment procedures themselves declare this
    objective automatically compliant". That deterministic template is a
    kernel decision, not an LLM parroting verification instructions back as
    proof, so it is exempt. Pre-fix this string was rejected and the four
    rule-8a short-circuit tests went red.
    """
    narrative = 'Automatically compliant per Assessment Procedures (col K): "automatically compliant".'

    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
        row=None,
    )
    assert result.ok
    assert not any(
        reason is RejectionReason.ASSESSMENT_PROCEDURE_AS_SOURCE
        for reason, _ in result.rejections
    )


def test_genuine_llm_assessment_procedure_mis_cite_still_rejected():
    """The exemption must NOT weaken bug(c): a real LLM narrative that cites
    'the assessment procedures' as the confirming source is still rejected.

    This is the failure mode bug(c) exists to catch — the model points the
    reviewer at the verification *question* (col K's examine/interview/test
    instructions) instead of the *answer* (an artifact). The auto-compliant
    template fingerprint is absent, so the guard fires.
    """
    narrative = (
        "Access controls are enforced as documented in the assessment "
        "procedures, which confirm the objective is met."
    )

    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
        row=None,
    )
    assert not result.ok
    assert any(
        reason is RejectionReason.ASSESSMENT_PROCEDURE_AS_SOURCE
        for reason, _ in result.rejections
    )


# ---------------------------------------------------------------------------
# classify_narrative edge cases (empty + no-class-hit fallback)
# ---------------------------------------------------------------------------


def test_classify_empty_narrative_is_ambiguous():
    """Empty / whitespace narrative → AMBIGUOUS (validator.py:164-165).

    Pins the early-out at the top of ``classify_narrative``. Without this
    guard, an empty proposal would fall through to ``_is_requirement_restatement``
    and the token/regex passes would all return False, landing on the
    final-fallback AMBIGUOUS — same answer, but via a slower path. The
    early-out exists so the kernel can short-circuit the common
    LLM-returned-blank-string failure mode without paying for regex
    compilation on every retry.
    """
    assert classify_narrative("") is NarrativeClass.AMBIGUOUS
    assert classify_narrative("   \n\t") is NarrativeClass.AMBIGUOUS


def test_classify_no_class_hits_falls_back_to_ambiguous():
    """Non-empty narrative with no affirming/NA/gap phrases → AMBIGUOUS (line 185).

    Pins the final ``return NarrativeClass.AMBIGUOUS`` fallback. Without
    this, an LLM that produced grammatically clean but unclassifiable text
    (e.g. paraphrased policy intent without any of the load-bearing
    phrases) would crash or silently land on a wrong class. The fallback
    is what makes the validator fail-closed: when in doubt, reject the
    write rather than guess.
    """
    # Carefully chosen: no affirming verb, no NA marker, no gap word, no
    # restatement regex hit. Just neutral procedural prose.
    narrative = (
        "This activity took place during the standard cadence with the outcome "
        "being recorded for posterity."
    )

    assert classify_narrative(narrative) is NarrativeClass.AMBIGUOUS


# ---------------------------------------------------------------------------
# GAP_DESCRIBING + NON_COMPLIANT without remediation → note (lines 277-286)
# ---------------------------------------------------------------------------


def test_gap_describing_non_compliant_without_remediation_emits_note():
    """Gap narrative + Non-Compliant + NO POA&M / remediation mention → reviewer note.

    Pins validator.py:277-286 — the note path the review-assessment skill
    relies on to flag missing POA&Ms. The existing happy-path
    ``test_classify_gap_describing`` includes 'remediation tracked via POA&M'
    so it never trips this branch. Without an explicit pin, a regression
    that dropped the note would silently let Non-Compliant rows ship
    without remediation guidance — exactly the failure the reviewer skill
    exists to catch.
    """
    # Gap phrase but NO mention of POA&M, remediation, corrective action,
    # or "to be remediated" (the four phrases _mentions_remediation hunts for).
    narrative = "No artifact found documenting the account review cadence."

    result = validate(
        proposed_status=ComplianceStatus.NON_COMPLIANT,
        proposed_narrative=narrative,
    )
    # The mismatch path stays clean — gap-describing + Non-Compliant matches.
    assert result.ok
    # ...but the note fires so the UI / reviewer sees the missing-POA&M flag.
    assert any("poa&m" in n.lower() or "remediation" in n.lower() for n in result.notes)


def test_rule_no_evidence_template_round_trips_clean():
    """The deterministic ``rule_no_evidence`` short-circuit narrative must
    classify as GAP_DESCRIBING and pair cleanly with NON_COMPLIANT at
    save time.

    Regression pin: the kernel's no-evidence rule in
    ``engine.assessor`` mints this exact string, bypasses the LLM, and
    sets ``accepted=True`` in the in-loop result. But POST
    /api/assessments re-runs ``validate()`` server-side at Save time,
    and historically the phrase table didn't contain any substring of
    this template — every save of an LLM-skipped NC row was rejected
    with ``classified=ambiguous`` (visible to the user as "Save says
    rule is ambiguous, but the control has no evidence").

    If the assessor template is reworded, this test will fail and the
    new wording must be added to ``_GAP_PHRASES``. Same template-drift
    class as the eval-cases affirming-phrase rule.
    """
    # Pinned verbatim from engine.assessor._rule_no_evidence (the
    # narrative built at lines 1495-1500 as of v0.1). Keep in lock-step.
    narrative = (
        "No artifacts were retrieved for this CCI. With no evidence "
        "of implementation available to examine, the control "
        "objective is presumed not satisfied; status is "
        "Non-Compliant pending submission of supporting evidence."
    )

    assert classify_narrative(narrative) is NarrativeClass.GAP_DESCRIBING

    result = validate(
        proposed_status=ComplianceStatus.NON_COMPLIANT,
        proposed_narrative=narrative,
    )
    assert result.ok, (
        f"rule_no_evidence template must round-trip through validate(); "
        f"got rejections={result.rejections!r}"
    )


# ---------------------------------------------------------------------------
# _normalize_status (validator.py:298-307)
# ---------------------------------------------------------------------------


def test_validate_accepts_status_passed_as_string():
    """proposed_status="Compliant" string → normalized to ComplianceStatus.COMPLIANT.

    Pins validator.py:303-306 — the case-insensitive string-to-enum match.
    The orchestrator currently always passes the enum directly, but the
    signature explicitly accepts strings (``ComplianceStatus | str``) so
    that boundary code (e.g. JSON-deserializing LLM proposals) doesn't
    need to convert. Pin the behavior so the boundary contract stays
    honest if the orchestrator ever leans on it.
    """
    narrative = (
        "AC-2 account management procedures are documented in USD00050010 §3.2 "
        "and verified via inspection of the production account roster."
    )

    result = validate(
        proposed_status="Compliant",  # string, not enum
        proposed_narrative=narrative,
    )
    assert result.ok


def test_validate_with_unrecognized_status_string_treats_as_unknown():
    """proposed_status="Garbage" → _normalize_status returns None (validator.py:307).

    Pins the fallthrough — unrecognized strings normalize to None, which
    means the status/class mismatch check at line 237 is skipped
    (``status is not None and status != expected_status``). A regression
    that crashed on unknown strings (e.g. raising KeyError) would break
    the boundary contract for callers that feed user/LLM-supplied status
    strings without pre-validating.
    """
    narrative = (
        "AC-2 account management procedures are documented in USD00050010 §3.2 "
        "and verified via inspection of the production account roster."
    )

    result = validate(
        proposed_status="NotARealStatus",
        proposed_narrative=narrative,
    )
    # No status/class mismatch rejection — the unknown status normalizes to
    # None and the comparison at line 237 short-circuits on `status is not None`.
    assert not _has_rejection(result, RejectionReason.STATUS_NARRATIVE_MISMATCH)


# ---------------------------------------------------------------------------
# _is_requirement_restatement defensive token branches (lines 339-347)
# ---------------------------------------------------------------------------


def test_restatement_check_skips_when_narrative_has_no_meaningful_tokens():
    """Narrative is all stopwords → empty q_tokens → restatement check returns False (line 339-341).

    Pins the empty-q_tokens early-out. Without it, the Jaccard division
    would compute ``0 / max(0, 1) = 0`` which is correct, but every source
    field would still be tokenized — wasted work on a degenerate input.
    The branch exists so the validator stays cheap on the
    LLM-returned-stopword-soup failure mode. Pair with a real definition
    so we know the early-out fired before the per-source loop ran.
    """
    # Only stopwords (the, and, for, with, that) and short (<3 char) tokens.
    # All filtered by _TOKEN_RE / _STOPWORDS → q_tokens empty.
    narrative = "the and for with that"
    definition = (
        "The organization establishes conditions for group and role membership "
        "and monitors usage of information system accounts."
    )

    row = _row(definition=definition)
    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
        row=row,
    )
    # No restatement rejection — q_tokens was empty so Jaccard never ran.
    assert not _has_rejection(result, RejectionReason.REQUIREMENT_RESTATEMENT)


def test_restatement_check_skips_source_field_with_no_meaningful_tokens():
    """Source field (col I/J/K/U) is all stopwords → s_tokens empty → continue (lines 344-346).

    Pins the per-source empty-s_tokens skip. A degenerate col I (e.g. a
    placeholder definition like 'See above.') would otherwise feed an empty
    set to the Jaccard formula. The skip is what keeps a real, distinctive
    narrative from being mistakenly compared against an empty source set
    (which would still yield 0.0 — correct — but burn cycles on every CCI
    in a batch). Pin the contract: empty-source skip is silent, not a False
    rejection.
    """
    # Narrative has distinctive tokens; col-I definition is all stopwords.
    narrative = (
        "Account roster reviewed quarterly and documented in USD00050010 §3.2; "
        "verified via inspection of the December 2025 review minutes."
    )

    row = _row(definition="the and for with that")
    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
        row=row,
    )
    # No restatement rejection — col-I s_tokens was empty, skip fired,
    # and the other source fields are None so the loop is a no-op.
    assert not _has_rejection(result, RejectionReason.REQUIREMENT_RESTATEMENT)


def test_validate_handles_none_status_for_optional_callers():
    """``validate(proposed_status=None, ...)`` → no STATUS_NARRATIVE_MISMATCH on the mismatch axis.

    Pins validator.py:300 — the ``_normalize_status(None) → None`` early
    return. The type annotation is ``ComplianceStatus | str``, but the
    helper accepts None defensively because rule-#8c entry points and
    classify-only callers (e.g. UI preview that hasn't picked a status
    yet) pass None. If the early return regressed, the str-cast at line
    303 would raise on None and crash the preview path. The narrative is
    clean compliance-affirming so the only rejection that COULD fire is
    the status-mismatch one — pin that it does NOT.
    """
    result = validate(
        proposed_status=None,  # type: ignore[arg-type]
        proposed_narrative=(
            "AC-2 account management procedures are documented in USD00050010 §3.2 "
            "and verified via inspection of the production account roster."
        ),
    )
    # status is None → the elif at validator.py:237 (`status is not None`)
    # short-circuits, so no STATUS_NARRATIVE_MISMATCH from the mismatch branch.
    # The ambiguous branch above it doesn't fire either (narrative is clean
    # compliance-affirming, expected_status is COMPLIANT, not None).
    assert result.ok
    assert result.classified_as == NarrativeClass.COMPLIANCE_AFFIRMING
    assert not _has_rejection(result, RejectionReason.STATUS_NARRATIVE_MISMATCH)


def test_validate_with_empty_narrative_hits_restatement_early_out():
    """Empty narrative → ``_is_requirement_restatement`` returns False at line 334.

    Pins validator.py:334 — the empty-narrative early return inside
    ``_is_requirement_restatement``. Without it, the regex loop would
    iterate (cheap but pointless) and then the per-source Jaccard would
    tokenize an empty string against every populated col, producing a
    silent ``0 / max(0,1) = 0`` per source. The early-out is the contract
    that says: an empty narrative is NOT a restatement (it's a different
    bug — empty proposal — that the ambiguous branch surfaces separately).
    Pair with a non-trivial col-I definition so the early-out is the only
    thing that could prevent a restatement rejection.
    """
    row = _row(
        definition=(
            "The organization establishes conditions for group and role membership "
            "and monitors usage of information system accounts."
        )
    )
    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative="",
        row=row,
    )
    # Restatement check returned False (line 334 early-out); the rejection
    # we DO get is the ambiguous one from the empty narrative, not a
    # requirement-restatement one.
    assert not _has_rejection(result, RejectionReason.REQUIREMENT_RESTATEMENT)
    # And the ambiguous-narrative branch above it DID fire — empty text is
    # classified AMBIGUOUS, which is the right way to flag this.
    assert _has_rejection(result, RejectionReason.STATUS_NARRATIVE_MISMATCH)


# ---------------------------------------------------------------------------
# STIG-finding corroboration gate (v0.3 precision-over-recall)
# ---------------------------------------------------------------------------


def test_uncorroborated_stig_pass_rejected_when_only_scan_evidence():
    """COMPLIANT + cites SV-#####r#_rule + no non-scan corroborator → rejection.

    The v0.3 corroboration gate (feedback_corroborate_stig_findings.md). A
    passing STIG finding documents that one host was configured correctly
    at scan time; it does not prove the control is implemented by policy
    or design. The kernel rejects a COMPLIANT verdict that rests purely on
    scan output — caller threads ``corroboration_present=False`` when the
    only tagged evidence on the objective is CKL/CKLB/XCCDF/Nessus.

    Pair with an affirming-citation narrative so the only rejection that
    could fire is the corroboration one (not a separate ambiguous /
    status-mismatch / restatement). USD doc citation also satisfies the
    primary-citation note check so notes stay quiet.
    """
    narrative = (
        "Verified compliant per STIG rule SV-12345r1_rule; configured per "
        "USD00050010 §4.1 baseline."
    )

    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
        corroboration_present=False,
    )
    assert not result.ok
    assert _has_rejection(result, RejectionReason.UNCORROBORATED_STIG_PASS)


def test_corroborated_stig_pass_accepted_when_nonscan_present():
    """COMPLIANT + cites SV-#####r#_rule + non-scan corroborator → no rejection.

    Mirror of the negative case. When a policy / SSP / baseline doc is
    tagged alongside the scan output, the caller threads
    ``corroboration_present=True`` and the gate stands aside — the LLM's
    COMPLIANT verdict is grounded in something beyond a point-in-time host
    observation.
    """
    narrative = (
        "Verified compliant per STIG rule SV-12345r1_rule; configured per "
        "USD00050010 §4.1 baseline."
    )

    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
        corroboration_present=True,
    )
    assert not _has_rejection(result, RejectionReason.UNCORROBORATED_STIG_PASS)


def test_corroboration_gate_skipped_when_signal_is_none():
    """corroboration_present=None (default / legacy caller) → gate doesn't fire.

    Pins the ``corroboration_present is False`` check (not falsy). The
    deterministic rule-#8 paths and any pre-v0.3 caller pass None (or
    omit the param entirely); the gate must skip in that case rather
    than firing on every legacy validation. This is the same defensive
    posture as ``row=None`` skipping the Jaccard restatement check.
    """
    narrative = (
        "Verified compliant per STIG rule SV-12345r1_rule; configured per "
        "USD00050010 §4.1 baseline."
    )

    # Both omitted-param and explicit-None call shapes must short-circuit.
    for call_shape in (
        lambda: validate(
            proposed_status=ComplianceStatus.COMPLIANT,
            proposed_narrative=narrative,
        ),
        lambda: validate(
            proposed_status=ComplianceStatus.COMPLIANT,
            proposed_narrative=narrative,
            corroboration_present=None,
        ),
    ):
        result = call_shape()
        assert not _has_rejection(result, RejectionReason.UNCORROBORATED_STIG_PASS)


def test_corroboration_gate_fires_when_no_stig_cite_but_scan_only_evidence():
    """COMPLIANT + corroboration_present=False + NO SV-#####r#_rule cite → rejection.

    finding #6: the gate no longer requires a STIG-rule citation in the
    narrative. The load-bearing signal is corroboration_present=False —
    the caller already determined the only tagged evidence on this
    objective is scan output with no non-scan corroborator. A COMPLIANT
    verdict resting purely on scan output is uncorroborated regardless of
    whether the narrative happens to quote a rule ID.

    This test previously pinned the OLD hole: it asserted NO rejection for
    exactly this shape (COMPLIANT + corroboration_present=False + no STIG
    cite), which let scan-only COMPLIANT verdicts ship as long as the
    narrative avoided the SV-#####r#_rule pattern. Finding #6 closes that
    hole, so the assertion is flipped to require the rejection.
    """
    narrative = (
        "Configured to enforce session lock per USD00050010 §4.1; verified "
        "via the December 2025 audit log sample."
    )

    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
        corroboration_present=False,
    )
    assert _has_rejection(result, RejectionReason.UNCORROBORATED_STIG_PASS)


def test_corroboration_gate_skipped_for_non_compliant_status():
    """NON_COMPLIANT + cites SV-#####r#_rule + corroboration_present=False → no rejection.

    Symmetric to the FUTURE_TENSE_COMPLIANCE scoping: the gate targets
    COMPLIANT verdicts only. A NON_COMPLIANT narrative citing a STIG rule
    is the *correct* shape — the finding is being documented as a gap.
    Pin that the gate doesn't over-fire on the gap-describing path.
    """
    narrative = (
        "STIG rule SV-12345r1_rule failed on host01; remediation tracked "
        "via POA&M Example System-2026-099."
    )

    result = validate(
        proposed_status=ComplianceStatus.NON_COMPLIANT,
        proposed_narrative=narrative,
        corroboration_present=False,
    )
    assert not _has_rejection(result, RejectionReason.UNCORROBORATED_STIG_PASS)
