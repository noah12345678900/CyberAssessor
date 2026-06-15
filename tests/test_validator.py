"""Tests for rule #11 pre-write narrative validator.

These tests are the patent-supporting evidence for the "deterministic
post-validator" claim: every assertion documents a class of LLM error
(restatement, status/narrative mismatch, missing inheritance source,
ambiguous narrative) that gets caught BEFORE the row is written.
"""

from __future__ import annotations

from cybersecurity_assessor.engine import validator
from cybersecurity_assessor.engine.measurement import RejectionClass  # noqa: F401 — type used in assert
from cybersecurity_assessor.models import ComplianceStatus, NarrativeClass


# ---------------------------------------------------------------------------
# Narrative classification
# ---------------------------------------------------------------------------


def test_classify_affirming_narrative():
    text = "Verified via USD00050010 §3.2 that account management is configured per the plan."
    assert validator.classify_narrative(text) == NarrativeClass.COMPLIANCE_AFFIRMING


def test_classify_na_narrative():
    text = "Not applicable because the control is implemented by AWS GovCloud; no local responsibility."
    assert validator.classify_narrative(text) == NarrativeClass.NA_JUSTIFYING


def test_classify_gap_narrative():
    text = "No artifact found documenting privileged account review; POA&M opened for remediation."
    assert validator.classify_narrative(text) == NarrativeClass.GAP_DESCRIBING


def test_classify_ambiguous_when_multi_class_hits():
    text = "Configured per the plan but no artifact found documenting the most recent review."
    # Mix of affirming + gap → ambiguous (rule #11 mixed case).
    assert validator.classify_narrative(text) == NarrativeClass.AMBIGUOUS


def test_classify_empty_is_ambiguous():
    assert validator.classify_narrative("") == NarrativeClass.AMBIGUOUS
    assert validator.classify_narrative("   ") == NarrativeClass.AMBIGUOUS


# ---------------------------------------------------------------------------
# Requirement restatement detection
# ---------------------------------------------------------------------------


def test_restatement_regex_catches_reviewed_pattern(make_row):
    row = make_row()
    bad = "Reviewed SDA Control AC-2; confirmed the requirement that the system shall do X."
    result = validator.validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=bad,
        row=row,
    )
    assert not result.ok
    reasons = [r for r, _ in result.rejections]
    assert validator.RejectionReason.REQUIREMENT_RESTATEMENT in reasons


def test_restatement_jaccard_overlap_catches_paraphrase(make_row):
    # Build a row where col K is a known shall statement, then craft a
    # narrative that re-uses almost all the same content tokens. finding
    # #13: detection is now TRUE token-set Jaccard (|Q∩S|/|Q∪S|) against
    # _RESTATEMENT_JACCARD_THRESHOLD = 0.5; this near-mirror paraphrase
    # lands at Jaccard ≈ 0.63, still well over the bar.
    row = make_row(
        procedures=(
            "Examine account management documentation; verify automation supports "
            "enterprise identity tooling and confirms automated provisioning."
        ),
    )
    paraphrase = (
        "Examined account management documentation and verified automation supports "
        "enterprise identity tooling, confirming automated provisioning."
    )
    result = validator.validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=paraphrase,
        row=row,
    )
    reasons = [r for r, _ in result.rejections]
    assert validator.RejectionReason.REQUIREMENT_RESTATEMENT in reasons


def test_genuine_assessment_act_is_not_flagged_as_restatement(make_row):
    row = make_row()
    good = (
        "Verified via USD00050010 §3.2 that Example System uses Active Directory for account "
        "provisioning; observed sample of three accounts created in the last 30 days."
    )
    result = validator.validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=good,
        row=row,
    )
    reasons = [r for r, _ in result.rejections]
    assert validator.RejectionReason.REQUIREMENT_RESTATEMENT not in reasons


# ---------------------------------------------------------------------------
# Status ↔ narrative class match (the core rule #11 check)
# ---------------------------------------------------------------------------


def test_affirming_narrative_with_non_compliant_status_is_rejected(make_row):
    row = make_row()
    result = validator.validate(
        proposed_status=ComplianceStatus.NON_COMPLIANT,
        proposed_narrative="Verified via SSP §4.1 that the system is configured to enforce.",
        row=row,
    )
    assert not result.ok
    reasons = [r for r, _ in result.rejections]
    assert validator.RejectionReason.STATUS_NARRATIVE_MISMATCH in reasons


def test_gap_narrative_with_compliant_status_is_rejected(make_row):
    row = make_row()
    result = validator.validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative="No artifact found; POA&M opened for remediation.",
        row=row,
    )
    assert not result.ok
    reasons = [r for r, _ in result.rejections]
    assert validator.RejectionReason.STATUS_NARRATIVE_MISMATCH in reasons


def test_matching_status_and_class_passes(make_row):
    row = make_row()
    result = validator.validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=(
            "Verified via USD00050010 §3.2 that automated provisioning is configured per the plan."
        ),
        row=row,
    )
    assert result.ok
    assert result.classified_as == NarrativeClass.COMPLIANCE_AFFIRMING
    assert result.rejections == []


def test_matching_na_status_and_class_passes(make_row):
    row = make_row()
    result = validator.validate(
        proposed_status=ComplianceStatus.NOT_APPLICABLE,
        proposed_narrative="Not applicable because the control is implemented by AWS GovCloud.",
        row=row,
    )
    assert result.ok


def test_matching_gap_status_and_class_passes(make_row):
    row = make_row()
    result = validator.validate(
        proposed_status=ComplianceStatus.NON_COMPLIANT,
        proposed_narrative="No artifact found documenting the most recent review; POA&M opened.",
        row=row,
    )
    assert result.ok


# ---------------------------------------------------------------------------
# Inheritance source naming
# ---------------------------------------------------------------------------


def test_inherited_from_without_source_is_rejected(make_row):
    row = make_row()
    result = validator.validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative="Configured per the plan; control responsibilities inherited from.",
        row=row,
    )
    reasons = [r for r, _ in result.rejections]
    assert validator.RejectionReason.MISSING_INHERITANCE_MARKER in reasons


def test_inherited_from_with_named_source_passes(make_row):
    row = make_row()
    result = validator.validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=(
            "Configured per the plan; control responsibilities inherited from DoD enterprise services."
        ),
        row=row,
    )
    reasons = [r for r, _ in result.rejections]
    assert validator.RejectionReason.MISSING_INHERITANCE_MARKER not in reasons


# ---------------------------------------------------------------------------
# Notes (non-blocking advisory)
# ---------------------------------------------------------------------------


def test_compliant_without_primary_citation_gets_note(make_row):
    row = make_row()
    result = validator.validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative="Verified that the team observed the procedure during the walkthrough.",
        row=row,
    )
    # Passes validation but advisory note is attached.
    assert any("primary source" in n for n in result.notes)


def test_non_compliant_without_poam_gets_note(make_row):
    row = make_row()
    result = validator.validate(
        proposed_status=ComplianceStatus.NON_COMPLIANT,
        proposed_narrative="No artifact found documenting the most recent review.",
        row=row,
    )
    assert any("POA&M" in n for n in result.notes)


# ---------------------------------------------------------------------------
# RejectionReason ↔ measurement.RejectionClass parity
# ---------------------------------------------------------------------------


def test_rejection_reason_values_match_measurement_class():
    """Validator's RejectionReason.value strings must match the
    measurement.RejectionClass Literal members 1:1 so callers can pass
    `reason.value` directly into ValidatorRejection(rejection_class=...).
    """
    from typing import get_args

    expected = set(get_args(RejectionClass))
    actual = {r.value for r in validator.RejectionReason}
    # Every RejectionReason value must be a valid RejectionClass.
    assert actual.issubset(expected), f"Drift: {actual - expected}"


# ---------------------------------------------------------------------------
# Future-tense compliance trip-wire (v0.2)
# ---------------------------------------------------------------------------


def test_future_tense_compliant_is_rejected(make_row):
    row = make_row()
    result = validator.validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=(
            "Verified via SSP §4.1 that MFA will be configured for all privileged "
            "users in the upcoming rollout."
        ),
        row=row,
    )
    assert not result.ok
    reasons = [r for r, _ in result.rejections]
    assert validator.RejectionReason.FUTURE_TENSE_COMPLIANCE in reasons


def test_future_tense_with_non_compliant_is_fine(make_row):
    # "will be configured" + Non-Compliant + POA&M is the *correct* shape
    # for a documented planned fix -- shouldn't trip the future-tense rule.
    row = make_row()
    result = validator.validate(
        proposed_status=ComplianceStatus.NON_COMPLIANT,
        proposed_narrative=(
            "No artifact found; MFA will be configured per upcoming deployment. "
            "POA&M opened with remediation target Q3."
        ),
        row=row,
    )
    reasons = [r for r, _ in result.rejections]
    assert validator.RejectionReason.FUTURE_TENSE_COMPLIANCE not in reasons


def test_future_tense_to_be_implemented_pattern(make_row):
    row = make_row()
    result = validator.validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=(
            "Configured per the plan; remaining audit log retention to be implemented "
            "by end of quarter."
        ),
        row=row,
    )
    reasons = [r for r, _ in result.rejections]
    assert validator.RejectionReason.FUTURE_TENSE_COMPLIANCE in reasons


def test_past_tense_compliant_passes(make_row):
    row = make_row()
    result = validator.validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=(
            "Verified via USD00050010 §3.2 that automated provisioning is configured "
            "per the plan; observed three accounts created last week."
        ),
        row=row,
    )
    reasons = [r for r, _ in result.rejections]
    assert validator.RejectionReason.FUTURE_TENSE_COMPLIANCE not in reasons


# ---------------------------------------------------------------------------
# Dual-narrative leak detection + CRM cross-check (v0.2)
# ---------------------------------------------------------------------------


def test_dual_narrative_clean_emits_no_notes():
    result = validator.validate_dual_narratives(
        narrative_on_prem="Configured per local SCAP baseline; verified via STIG scan.",
        narrative_cloud="Inherited from AWS GovCloud per FedRAMP authorization.",
        crm_responsibility="hybrid",
    )
    assert result.notes == []
    assert result.flagged == []


def test_provider_language_in_on_prem_half_is_flagged():
    result = validator.validate_dual_narratives(
        narrative_on_prem="Implemented by AWS GovCloud per FedRAMP authorization.",
        narrative_cloud="Local SCAP baseline applied.",
        crm_responsibility="hybrid",
    )
    assert validator.RejectionReason.DUAL_NARRATIVE_MISLABEL in result.flagged
    assert any("provider-only language" in n for n in result.notes)


def test_onprem_language_in_cloud_half_is_flagged():
    result = validator.validate_dual_narratives(
        narrative_on_prem="Inherited from AWS GovCloud.",
        narrative_cloud="Rack-mounted servers in the physical data center are hardened.",
        crm_responsibility="hybrid",
    )
    assert validator.RejectionReason.DUAL_NARRATIVE_MISLABEL in result.flagged
    assert any("on-prem-only language" in n for n in result.notes)


def test_crm_customer_with_populated_cloud_is_flagged():
    result = validator.validate_dual_narratives(
        narrative_on_prem="Configured locally per SSP §4.1.",
        narrative_cloud="Some text the LLM shouldn't have emitted here.",
        crm_responsibility="customer",
    )
    assert validator.RejectionReason.DUAL_NARRATIVE_MISLABEL in result.flagged
    assert any("customer-owned" in n for n in result.notes)


def test_crm_provider_with_populated_onprem_is_flagged():
    result = validator.validate_dual_narratives(
        narrative_on_prem="Local hardening applied via SCAP baseline.",
        narrative_cloud="Inherited from AWS GovCloud per FedRAMP.",
        crm_responsibility="provider",
    )
    assert validator.RejectionReason.DUAL_NARRATIVE_MISLABEL in result.flagged


def test_crm_inherited_with_populated_onprem_is_flagged():
    result = validator.validate_dual_narratives(
        narrative_on_prem="Local hardening applied via SCAP baseline.",
        narrative_cloud="Inherited from DoD enterprise.",
        crm_responsibility="inherited",
    )
    assert validator.RejectionReason.DUAL_NARRATIVE_MISLABEL in result.flagged


def test_crm_hybrid_with_both_empty_is_flagged():
    result = validator.validate_dual_narratives(
        narrative_on_prem=None,
        narrative_cloud="",
        crm_responsibility="hybrid",
    )
    assert validator.RejectionReason.DUAL_NARRATIVE_MISLABEL in result.flagged
    assert any("both narrative halves" in n for n in result.notes)


def test_unknown_responsibility_skips_crm_check():
    # CRM unknown -- only leak detection runs, no responsibility mismatch.
    result = validator.validate_dual_narratives(
        narrative_on_prem="Configured per SCAP baseline.",
        narrative_cloud="Inherited from AWS GovCloud.",
        crm_responsibility=None,
    )
    assert result.flagged == []


def test_na_responsibility_skips_crm_check():
    # Per the function docstring: NA rows don't carry implementation scope.
    result = validator.validate_dual_narratives(
        narrative_on_prem="Some text.",
        narrative_cloud="Other text.",
        crm_responsibility="not_applicable",
    )
    assert result.flagged == []
