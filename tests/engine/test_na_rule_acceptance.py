"""Regression: a deterministic N/A (rule #8b) counts as accepted.

User bug: "N/A controls aren't counting in 'accepted' — 11/13 when I
accepted all besides AC-7." A control whose col N already says "Not
Applicable" is finalized by rule #8b. The formatter
(_format_prefilled_na_narrative) inlines the assessor's own col-Q/U rationale
excerpt. When that borrowed human prose contains a gap or strong-affirming
phrase, the validator's multi-class ambiguity guard (classes_hit >= 2)
flips the narrative to AMBIGUOUS → result.ok=False → accepted=False, so the
N/A drops into the unresolved bucket and vanishes from the accepted count.

The fix: a rule #8b N/A verdict is authoritative (a human wrote it in col
N), so accept it even when the ONLY validator rejection is the ambiguity
status/narrative mismatch. Real formatter defects still reject.
"""

from __future__ import annotations

from cybersecurity_assessor.engine import rules
from cybersecurity_assessor.engine.assessor import Assessor
from cybersecurity_assessor.excel.ccis_reader import CcisRow
from cybersecurity_assessor.models import ComplianceStatus, NarrativeClass


def _na_row(rationale: str) -> CcisRow:
    return CcisRow(
        excel_row=5,
        required=True,
        control_id="AC-18",
        ap_acronym="AC-18.1",
        cci_id="CCI-001438",
        implementation_status=None,
        designation=None,
        narrative=None,
        definition="Wireless access controls.",
        guidance=None,
        procedures=None,
        inherited=None,
        remote_inheritance=None,
        status="Not Applicable",  # col N
        date_tested=None,
        tester=None,
        results=rationale,  # col Q rationale, inlined by the NA formatter
        previous_status=None,
        previous_date=None,
        previous_tester=None,
        previous_results=None,
    )


def _finalize(row: CcisRow):
    auto = rules.classify_row(row)
    assert auto.rule == "8b"
    assert auto.status is ComplianceStatus.NOT_APPLICABLE
    a = Assessor(llm=None)
    return a._finalize_rule_decision(
        row, "CCI-001438", auto, source="rule_8b", outcome=None, workbook_id=None
    )


def test_na_with_gap_phrase_rationale_is_accepted():
    """Borrowed rationale carrying a gap phrase must NOT drop the N/A.

    "not implemented" / "descoped" would classify the inlined excerpt toward
    GAP, tripping the ambiguity guard. Pre-fix this made accepted=False.
    """
    d = _finalize(
        _na_row(
            "No wireless capability exists; the subsystem was descoped and is "
            "not implemented within the authorization boundary."
        )
    )
    assert d.accepted is True, "N/A verdict must count as accepted"
    assert d.status is ComplianceStatus.NOT_APPLICABLE


def test_na_with_clean_rationale_still_accepted_and_na_class():
    """A clean rationale stays NA-justifying and accepted (no regression)."""
    d = _finalize(
        _na_row("The control does not apply to this system's architecture.")
    )
    assert d.accepted is True
    assert d.status is ComplianceStatus.NOT_APPLICABLE
    assert d.narrative_class is NarrativeClass.NA_JUSTIFYING
