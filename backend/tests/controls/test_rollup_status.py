"""Unit tests for ``controls.exporter._rollup_status`` and helpers.

The rollup contract is the heart of the eMASS export: it converts a list
of objective-level assessments + CRM overlays into the multi-line Status
cell the user specified, e.g.::

    Compliant: CCI-000196, CCI-000197 (inherited from AWS GovCloud)
    Non-Compliant: CCI-000198 (no documented sanctions procedure)

These tests pin the bucketing rules so a future refactor can't silently
break the column the eMASS reviewer reads.
"""

from __future__ import annotations

from cybersecurity_assessor.controls.exporter import (
    ObjectiveAssessment,
    _classify,
    _crm_source_phrase,
    _format_psc_column,
    _rollup_status,
    _short_reason,
    ProgramControlRow,
)
from cybersecurity_assessor.models import ComplianceStatus


def _oa(
    *,
    code: str = "CCI-000001",
    status: ComplianceStatus = ComplianceStatus.COMPLIANT,
    narrative: str | None = None,
    needs_review: bool = False,
    inheritance_rule: str | None = None,
    crm_responsibility: str | None = None,
    crm_narrative: str | None = None,
) -> ObjectiveAssessment:
    return ObjectiveAssessment(
        objective_id=hash(code) & 0x7FFFFFFF,
        objective_code=code,
        status=status,
        narrative_q=narrative,
        needs_review=needs_review,
        inheritance_rule=inheritance_rule,
        crm_responsibility=crm_responsibility,
        crm_narrative=crm_narrative,
    )


class TestRollupStatusSingleBucket:
    def test_empty_input_returns_empty_string(self):
        assert _rollup_status([]) == ""

    def test_single_compliant_emits_just_token(self):
        """Single-bucket controls collapse to the bucket name alone so the
        cell stays eMASS-single-value compatible when no ambiguity exists."""
        out = _rollup_status([_oa(code="CCI-1"), _oa(code="CCI-2")])
        assert out == "Compliant"

    def test_single_non_compliant_emits_just_token(self):
        out = _rollup_status([
            _oa(code="CCI-1", status=ComplianceStatus.NON_COMPLIANT),
            _oa(code="CCI-2", status=ComplianceStatus.NON_COMPLIANT),
        ])
        assert out == "Non-Compliant"

    def test_single_not_applicable_emits_just_token(self):
        out = _rollup_status([
            _oa(code="CCI-1", status=ComplianceStatus.NOT_APPLICABLE),
        ])
        assert out == "Not Applicable"


class TestRollupStatusMultiBucket:
    def test_compliant_and_nc_emit_separate_lines(self):
        """User-specified format: one line per status bucket, CCI list +
        reason in parens."""
        out = _rollup_status([
            _oa(code="CCI-196", status=ComplianceStatus.COMPLIANT,
                narrative="Reviewed AWS GovCloud SSP for inheritance."),
            _oa(code="CCI-198", status=ComplianceStatus.NON_COMPLIANT,
                narrative="No documented sanctions procedure for account misuse."),
        ])
        lines = out.split("\n")
        assert len(lines) == 2
        assert lines[0].startswith("Compliant: CCI-196")
        assert lines[1].startswith("Non-Compliant: CCI-198")
        # Reasons truncated from narrative first-sentence.
        assert "AWS GovCloud" in lines[0]
        assert "sanctions" in lines[1]

    def test_buckets_ordered_compliant_then_nc_then_na_then_review(self):
        """Display order is fixed regardless of input order — reviewers
        scan top-down for Compliant first, problems below."""
        out = _rollup_status([
            _oa(code="CCI-D", needs_review=True, narrative="Awaiting STIG scan."),
            _oa(code="CCI-A", status=ComplianceStatus.COMPLIANT, narrative="Good."),
            _oa(code="CCI-C", status=ComplianceStatus.NOT_APPLICABLE,
                narrative="Tailored out."),
            _oa(code="CCI-B", status=ComplianceStatus.NON_COMPLIANT,
                narrative="Gap."),
        ])
        lines = out.split("\n")
        assert lines[0].startswith("Compliant:")
        assert lines[1].startswith("Non-Compliant:")
        assert lines[2].startswith("Not Applicable:")
        assert lines[3].startswith("Needs Review:")

    def test_same_reason_within_bucket_collapses_to_one_line(self):
        """Three inherited CCIs from one source emit one line, not three."""
        out = _rollup_status([
            _oa(code="CCI-1", crm_responsibility="inherited",
                crm_narrative="AWS GovCloud — inherited."),
            _oa(code="CCI-2", crm_responsibility="inherited",
                crm_narrative="AWS GovCloud — inherited."),
            _oa(code="CCI-3", crm_responsibility="inherited",
                crm_narrative="AWS GovCloud — inherited."),
            _oa(code="CCI-4", status=ComplianceStatus.NON_COMPLIANT,
                narrative="Gap identified."),
        ])
        # Multi-bucket → not collapsed to single token. CCI-1/2/3 share
        # reason "inherited from AWS GovCloud" → one Compliant line.
        compliant_lines = [
            ln for ln in out.split("\n") if ln.startswith("Compliant:")
        ]
        assert len(compliant_lines) == 1
        assert "CCI-1, CCI-2, CCI-3" in compliant_lines[0]
        assert "inherited from AWS GovCloud" in compliant_lines[0]


class TestClassifyCrmShortCircuits:
    def test_inherited_with_narrative_extracts_source(self):
        bucket, reason = _classify(_oa(
            crm_responsibility="inherited",
            crm_narrative="AWS GovCloud — inherited from authorizing system.",
            status=ComplianceStatus.NON_COMPLIANT,  # ignored
        ))
        assert bucket == "Compliant"
        assert "AWS GovCloud" in reason

    def test_provider_with_narrative(self):
        bucket, reason = _classify(_oa(
            crm_responsibility="provider",
            crm_narrative="Microsoft Azure Government implements this control.",
        ))
        assert bucket == "Compliant"
        assert "Microsoft Azure" in reason

    def test_not_applicable_via_crm(self):
        bucket, reason = _classify(_oa(crm_responsibility="not_applicable"))
        assert bucket == "Not Applicable"
        assert "CRM" in reason

    def test_needs_review_wins_over_status(self):
        """Precision-over-recall: a needs_review=True row never gets an
        eMASS status, even if the LLM proposed COMPLIANT."""
        bucket, _ = _classify(_oa(
            status=ComplianceStatus.COMPLIANT, needs_review=True,
            narrative="Dual-pass disagreed.",
        ))
        assert bucket == "Needs Review"

    def test_rule_8a_inheritance(self):
        bucket, reason = _classify(_oa(inheritance_rule="8a"))
        assert bucket == "Compliant"
        assert "8a" in reason

    def test_plain_compliant(self):
        bucket, _ = _classify(_oa(status=ComplianceStatus.COMPLIANT))
        assert bucket == "Compliant"

    def test_plain_nc_with_no_narrative_gets_fallback_reason(self):
        bucket, reason = _classify(_oa(
            status=ComplianceStatus.NON_COMPLIANT, narrative=None,
        ))
        assert bucket == "Non-Compliant"
        assert reason  # never empty for NC — exporter needs something to show


class TestCrmSourcePhrase:
    def test_first_sentence_short(self):
        assert _crm_source_phrase("AWS GovCloud") == "AWS GovCloud"

    def test_first_sentence_only(self):
        out = _crm_source_phrase("AWS GovCloud. Detailed narrative follows.")
        assert out == "AWS GovCloud"

    def test_long_first_sentence_truncated(self):
        long = "X" * 80
        out = _crm_source_phrase(long)
        assert out.endswith("...")
        assert len(out) <= 50

    def test_none_or_empty(self):
        assert _crm_source_phrase(None) == ""
        assert _crm_source_phrase("") == ""


class TestShortReason:
    def test_first_sentence(self):
        assert _short_reason("Hello world. More stuff.") == "Hello world"

    def test_truncated_when_too_long(self):
        long = "A" * 200
        out = _short_reason(long)
        assert out.endswith("...")
        assert len(out) <= 80

    def test_none(self):
        assert _short_reason(None) == ""


class TestFormatPscColumn:
    def test_empty_rows_returns_empty(self):
        assert _format_psc_column([]) == ""

    def test_single_row_format(self):
        rows = [ProgramControlRow(
            source_name="SDA",
            requirement_number="SDA-127",
            requirement_text="Least privilege.",
            objective_id=1,
        )]
        assert _format_psc_column(rows) == "SDA-127: Least privilege."

    def test_multi_row_newline_separated(self):
        rows = [
            ProgramControlRow("SDA", "SDA-127", "Least privilege.", 1),
            ProgramControlRow("T1TL", "T1TL-031", "Approval chain.", 2),
        ]
        out = _format_psc_column(rows)
        assert out == "SDA-127: Least privilege.\nT1TL-031: Approval chain."

    def test_long_requirement_text_per_line_capped(self):
        """Per-line cap (500) trims one row without affecting others."""
        rows = [
            ProgramControlRow("SDA", "SDA-001", "X" * 800, 1),
            ProgramControlRow("SDA", "SDA-002", "short.", 2),
        ]
        out = _format_psc_column(rows)
        lines = out.split("\n")
        assert lines[1] == "SDA-002: short."
        assert lines[0].endswith("...")
        assert len(lines[0]) < 600  # well under cell cap

    def test_excel_cell_cap_truncates_with_marker(self):
        """Many rows that would exceed Excel's 32,767-char cap drop a
        trailing '...[N more truncated]' marker instead of silently losing
        data."""
        rows = [
            ProgramControlRow("SRC", f"REQ-{i:04d}", "X" * 400, i)
            for i in range(100)
        ]
        out = _format_psc_column(rows)
        assert "more truncated" in out
        assert len(out) <= 32_767
