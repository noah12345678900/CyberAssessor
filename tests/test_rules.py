"""Tests for the rule #8 auto-status engine.

These tests are the patent-supporting evidence for the "deterministic
pre-filter" claim: every assertion here documents one row-shape that
the rules engine must classify the same way every time, without calling
the LLM. If one of these flips, the patent's accuracy story regresses.
"""

from __future__ import annotations

from cybersecurity_assessor.engine import rules
from cybersecurity_assessor.models import ComplianceStatus


# ---------------------------------------------------------------------------
# Rule 8a (CSP / external-inheritance lane) — Compliant via inherited provider
#
# v0.11.0 redesign: CSP/provider attribution ("implemented by AWS") means the
# control IS satisfied, just by a provider we inherit from → Compliant, NOT
# Not Applicable. The recognizer reads the human-authored rationale in col Q
# (results) / col U (previous_results) only — never the generic DISA template
# text in K/J.
# ---------------------------------------------------------------------------


def test_csp_attribution_in_results_is_compliant_8a(make_row):
    row = make_row(
        results="Control is implemented by AWS GovCloud at the platform layer.",
    )
    result = rules.classify_row(row)
    assert result.verdict == rules.AutoStatusVerdict.COMPLIANT_8A
    assert result.status == ComplianceStatus.COMPLIANT
    assert result.rule == "8a"
    assert result.trigger_column == "Q"
    assert "AWS" in (result.narrative or "")


def test_csp_attribution_in_previous_results_is_compliant_8a(make_row):
    row = make_row(
        previous_results="This requirement is implemented by the CSP.",
    )
    result = rules.classify_row(row)
    assert result.verdict == rules.AutoStatusVerdict.COMPLIANT_8A
    assert result.rule == "8a"
    assert result.trigger_column == "U"


def test_csp_phrase_in_procedures_does_not_fire(make_row):
    # CSP attribution is recognized only in col Q/U, never the generic DISA
    # template text in K/J. "implemented by AWS" sitting in procedures (col K)
    # alone is not an auto-rule signal.
    row = make_row(procedures="Control is implemented by AWS GovCloud.")
    result = rules.classify_row(row)
    assert result.verdict == rules.AutoStatusVerdict.NO_AUTO_RULE


# ---------------------------------------------------------------------------
# Rule 8b — Not Applicable via documented scope exclusion in col Q/U
# ---------------------------------------------------------------------------


def test_8b_fires_on_scope_exclusion_in_results(make_row):
    row = make_row(results="Not applicable per SDA control.")
    result = rules.classify_row(row)
    assert result.verdict == rules.AutoStatusVerdict.NOT_APPLICABLE_8B
    assert result.status == ComplianceStatus.NOT_APPLICABLE
    assert result.rule == "8b"
    assert result.trigger_column == "Q"


def test_8a_explicit_phrase_precedes_q_u_recognizer(make_row):
    # An 8a explicit phrase in col K is authoritative and fires before the
    # Q/U recognizer ever runs. A CSP attribution in col Q does not override it.
    row = make_row(
        procedures="Automatically compliant per inheritance.",
        results="implemented by AWS",
    )
    result = rules.classify_row(row)
    assert result.verdict == rules.AutoStatusVerdict.COMPLIANT_8A
    assert result.rule == "8a"
    assert result.trigger_column == "K"


def test_compliance_guard_suppresses_na_in_results(make_row):
    # An explicit compliance claim in the same Q/U rationale means the human
    # ruled it Compliant, so the scope-exclusion NA phrase is suppressed.
    row = make_row(
        results=(
            "Not applicable per SDA control, however compliance is satisfied "
            "at the program level."
        ),
    )
    result = rules.classify_row(row)
    assert result.verdict != rules.AutoStatusVerdict.NOT_APPLICABLE_8B


# ---------------------------------------------------------------------------
# Rule 8a — Compliant via internal inheritance
# ---------------------------------------------------------------------------


def test_8a_fires_on_automatically_compliant_phrase(make_row):
    row = make_row(procedures="Automatically compliant per assessment procedures.")
    result = rules.classify_row(row)
    assert result.verdict == rules.AutoStatusVerdict.COMPLIANT_8A
    assert result.status == ComplianceStatus.COMPLIANT
    assert result.rule == "8a"
    assert result.narrative is not None
    assert "Automatically compliant" in result.narrative


def test_8a_fires_on_qualified_inherited_from_dod(make_row):
    row = make_row(guidance="This requirement is inherited from DoD enterprise services.")
    result = rules.classify_row(row)
    assert result.verdict == rules.AutoStatusVerdict.COMPLIANT_8A
    assert result.rule == "8a"


def test_8a_structural_fires_when_col_l_is_non_local_non_csp(make_row):
    row = make_row(
        procedures="Examine artifacts and confirm implementation.",
        guidance="Implementation guidance only.",
        inherited="Parent System",  # not "Local", not a CSP
    )
    result = rules.classify_row(row)
    assert result.verdict == rules.AutoStatusVerdict.COMPLIANT_8A
    assert result.trigger_column == "L"
    assert result.trigger_phrase == "Parent System"
    assert 'col L = "Parent System"' in (result.narrative or "")


def test_8a_structural_does_not_fire_for_local(make_row):
    row = make_row(
        procedures="Examine artifacts.",
        guidance="Guidance only.",
        inherited="Local",
    )
    result = rules.classify_row(row)
    # "Local" means we own it locally → no auto-rule fires
    assert result.verdict == rules.AutoStatusVerdict.NO_AUTO_RULE


def test_8a_structural_does_not_fire_when_col_l_names_csp(make_row):
    row = make_row(
        procedures="Examine artifacts.",
        guidance="Guidance only.",
        inherited="AWS GovCloud",
    )
    result = rules.classify_row(row)
    # Col L names a CSP-ish source but no text trigger in K/J for 8b →
    # fall through (not auto-compliant, not auto-NA).
    assert result.verdict == rules.AutoStatusVerdict.NO_AUTO_RULE


# ---------------------------------------------------------------------------
# Rule 8c — bare "inherited from" with no qualifier
# ---------------------------------------------------------------------------


def test_8c_fires_on_bare_inherited_from(make_row):
    row = make_row(
        procedures="Control responsibilities are inherited from the upstream provider.",
        guidance="See SSP.",
        inherited="Local",
    )
    result = rules.classify_row(row)
    assert result.verdict == rules.AutoStatusVerdict.UNCLEAR_8C
    assert result.rule == "8c"
    assert result.status is None
    assert result.narrative is None
    assert "does not name the source" in (result.reason or "")


def test_8c_does_not_fire_when_inheritance_source_is_named(make_row):
    row = make_row(
        procedures="Control responsibilities are inherited from DoD enterprise services.",
        guidance="See SSP.",
    )
    result = rules.classify_row(row)
    # Qualified 8a inheritance fires before bare-8c check.
    assert result.verdict == rules.AutoStatusVerdict.COMPLIANT_8A


# ---------------------------------------------------------------------------
# NO_AUTO_RULE — passthrough to LLM
# ---------------------------------------------------------------------------


def test_no_auto_rule_for_ordinary_row(make_row):
    row = make_row(
        procedures="Examine account management documentation; verify automation is enabled.",
        guidance="Automated mechanisms include enterprise IdAM tooling.",
        inherited="Local",
    )
    result = rules.classify_row(row)
    assert result.verdict == rules.AutoStatusVerdict.NO_AUTO_RULE
    assert result.status is None
    assert result.narrative is None
    assert result.rule is None


def test_empty_cells_do_not_crash(make_row):
    row = make_row(procedures=None, guidance=None, inherited=None)
    result = rules.classify_row(row)
    assert result.verdict == rules.AutoStatusVerdict.NO_AUTO_RULE


# ---------------------------------------------------------------------------
# Narrative formatter output
# ---------------------------------------------------------------------------


def test_csp_compliant_narrative_names_provider_for_aws(make_row):
    row = make_row(results="implemented by AWS")
    result = rules.classify_row(row)
    assert "AWS" in (result.narrative or "")
    assert "compliant" in (result.narrative or "").lower()


def test_csp_compliant_narrative_names_provider_for_azure(make_row):
    row = make_row(results="implemented by azure")
    result = rules.classify_row(row)
    assert "Azure" in (result.narrative or "")


def test_8a_text_narrative_quotes_trigger(make_row):
    row = make_row(procedures="This is automatically compliant per the inheritance map.")
    result = rules.classify_row(row)
    assert '"automatically compliant"' in (result.narrative or "")
    assert "col K" in (result.narrative or "") or "Assessment Procedures" in (result.narrative or "")


# ---------------------------------------------------------------------------
# Column-L flex-slice resolver (pie-slice model)
# ---------------------------------------------------------------------------


def test_resolve_col_l_flex_named_source_is_inherited():
    assert (
        rules.resolve_col_l_flex_status("DoW Enterprise")
        is rules.ColLFlexOutcome.INHERITED
    )
    assert (
        rules.resolve_col_l_flex_status("SDA Enterprise Service")
        is rules.ColLFlexOutcome.INHERITED
    )


def test_resolve_col_l_flex_local_blank_no_are_assess():
    for v in ("Local", "local", "", None, "No", "n/a", "not inherited"):
        assert (
            rules.resolve_col_l_flex_status(v) is rules.ColLFlexOutcome.ASSESS
        ), f"{v!r} should be ASSESS"


def test_resolve_col_l_flex_bare_yes_is_escalate():
    for v in ("Yes", "yes", "inherited", "true"):
        assert (
            rules.resolve_col_l_flex_status(v) is rules.ColLFlexOutcome.ESCALATE
        ), f"{v!r} should be ESCALATE"


def test_resolve_col_l_flex_named_csp_is_assess():
    # A col-L value naming a CSP is an 8b structural hint but can't auto-N/A
    # without K/J triggers — resolver defers to assessment, never auto-pass.
    for v in ("AWS GovCloud", "Azure", "inherited from CSP"):
        assert (
            rules.resolve_col_l_flex_status(v) is rules.ColLFlexOutcome.ASSESS
        ), f"{v!r} should be ASSESS (CSP-named)"
