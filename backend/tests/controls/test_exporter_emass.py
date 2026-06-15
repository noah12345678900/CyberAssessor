"""eMASS exporter tests — xlwings COM, Excel required.

Gated behind ``@pytest.mark.requires_excel`` because xlwings drives the
live Excel desktop app. CI skips with ``-m "not requires_excel"``.

These tests pin:
  - Header detection works on the canonical 1-row template.
  - PSC column is inserted right after Control Acronym (idempotent).
  - Multi-line status rollup lands in the Status cell.
  - needs_review controls are skipped (precision-over-recall).
  - Workbook.exported_at is stamped on success.
"""

from __future__ import annotations

import pytest
from openpyxl import Workbook as PyXlWorkbook
from openpyxl import load_workbook

from cybersecurity_assessor.controls.exporter import export_controls_to_emass
from cybersecurity_assessor.models import ComplianceStatus, Workbook

pytestmark = pytest.mark.requires_excel


def _make_template(path, sheet="Controls"):
    """Single-sheet template with the headers the exporter needs.

    Real enterprise services controls.xlsx carries 29 tabs and rich
    validation — for these tests we just need the column contract intact.
    Idempotency / preservation tests are run end-to-end against the real
    template in the verification step from the plan.
    """
    pwb = PyXlWorkbook()
    ws = pwb.active
    ws.title = sheet
    ws.cell(1, 1, "Control Acronym")
    ws.cell(1, 2, "Status")
    ws.cell(1, 3, "Implementation Narrative")
    pwb.save(str(path))


def _seed_assessments(assess, ctx):
    wb_id = ctx["workbook"].id
    objs = ctx["objectives"]
    # AC-2: single-bucket Compliant.
    assess(wb_id, objs["CCI-000015"].id, ComplianceStatus.COMPLIANT,
           narrative="Compliant per system inventory.")
    assess(wb_id, objs["CCI-000016"].id, ComplianceStatus.COMPLIANT,
           narrative="Compliant per system inventory.")
    # AC-3: mixed → multi-line rollup.
    assess(wb_id, objs["CCI-000213"].id, ComplianceStatus.COMPLIANT,
           narrative="Reviewed quarterly per SOP.")
    assess(wb_id, objs["CCI-000214"].id, ComplianceStatus.NON_COMPLIANT,
           narrative="No documented quarterly review cadence.")
    # AC-5: needs_review → skipped from export.
    assess(wb_id, objs["CCI-000038"].id, ComplianceStatus.COMPLIANT,
           narrative="Dual-pass disagreed.",
           needs_review=True)


class TestEmassExport:
    def test_writes_psc_column_and_status_rollup(
        self, session, controls_catalog, assess, tmp_path
    ):
        _seed_assessments(assess, controls_catalog)
        tpl = tmp_path / "tpl.xlsx"
        out = tmp_path / "out.xlsx"
        _make_template(tpl)

        result = export_controls_to_emass(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            template_path=str(tpl),
            output_path=str(out),
        )

        # AC-5 skipped (needs_review); AC-2, AC-3, AC-4 written.
        assert result.rows_written == 3
        assert len(result.skipped) == 1
        assert result.skipped[0][0] == "AC-5"
        assert result.controls_with_psc >= 2  # AC-2 + AC-3 carry PSC overlays

        # Re-open with openpyxl to assert structure.
        pwb = load_workbook(str(out))
        ws = pwb["Controls"]
        headers = [ws.cell(1, c).value for c in range(1, 6)]
        assert headers[0] == "Control Acronym"
        assert headers[1] == "Program-Specific Controls"  # inserted at B
        assert headers[2] == "Status"  # shifted right by 1

        # Find the AC-3 row and verify multi-line rollup.
        ac3_row = None
        for r in range(2, ws.max_row + 1):
            if ws.cell(r, 1).value == "AC-3":
                ac3_row = r
                break
        assert ac3_row is not None
        status_cell = ws.cell(ac3_row, 3).value or ""
        assert "Compliant:" in status_cell
        assert "Non-Compliant:" in status_cell

    def test_idempotent_psc_column_not_double_inserted(
        self, session, controls_catalog, assess, tmp_path
    ):
        """Re-export onto the same output_path must leave exactly ONE
        Program-Specific Controls column — the second run detects the
        existing header and re-writes in place."""
        _seed_assessments(assess, controls_catalog)
        tpl = tmp_path / "tpl.xlsx"
        out = tmp_path / "out.xlsx"
        _make_template(tpl)

        export_controls_to_emass(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            template_path=str(tpl),
            output_path=str(out),
        )
        # Run again with the FIRST export's output as the template — this
        # is the realistic "operator re-exports onto their previous file"
        # path the idempotency contract protects.
        export_controls_to_emass(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            template_path=str(out),
            output_path=str(out),
        )

        pwb = load_workbook(str(out))
        ws = pwb["Controls"]
        psc_count = sum(
            1 for c in range(1, 20)
            if (ws.cell(1, c).value or "").strip().lower()
            == "program-specific controls"
        )
        assert psc_count == 1

    def test_stamps_workbook_exported_at(
        self, session, controls_catalog, assess, tmp_path
    ):
        _seed_assessments(assess, controls_catalog)
        wb_id = controls_catalog["workbook"].id
        tpl = tmp_path / "tpl.xlsx"
        out = tmp_path / "out.xlsx"
        _make_template(tpl)

        before = session.get(Workbook, wb_id).exported_at
        assert before is None

        export_controls_to_emass(
            session=session, workbook_id=wb_id,
            template_path=str(tpl), output_path=str(out),
        )

        session.expire_all()
        after = session.get(Workbook, wb_id).exported_at
        assert after is not None

    def test_missing_template_raises(self, session, controls_catalog, tmp_path):
        with pytest.raises(FileNotFoundError):
            export_controls_to_emass(
                session=session,
                workbook_id=controls_catalog["workbook"].id,
                template_path=str(tmp_path / "nope.xlsx"),
                output_path=str(tmp_path / "out.xlsx"),
            )

    def test_missing_sheet_raises_value_error(
        self, session, controls_catalog, tmp_path
    ):
        tpl = tmp_path / "tpl.xlsx"
        out = tmp_path / "out.xlsx"
        # Template has a sheet, but it's not named "Controls".
        pwb = PyXlWorkbook()
        pwb.active.title = "WrongSheet"
        pwb.save(str(tpl))

        with pytest.raises(ValueError, match="Controls"):
            export_controls_to_emass(
                session=session,
                workbook_id=controls_catalog["workbook"].id,
                template_path=str(tpl),
                output_path=str(out),
            )

    def test_missing_acronym_header_raises_value_error(
        self, session, controls_catalog, tmp_path
    ):
        """Template without a Control Acronym column can't be safely
        written — the loader bails before any rows go out."""
        tpl = tmp_path / "tpl.xlsx"
        out = tmp_path / "out.xlsx"
        pwb = PyXlWorkbook()
        ws = pwb.active
        ws.title = "Controls"
        ws.cell(1, 1, "Unrelated")
        ws.cell(1, 2, "Other")
        pwb.save(str(tpl))

        with pytest.raises(ValueError, match="Control Acronym"):
            export_controls_to_emass(
                session=session,
                workbook_id=controls_catalog["workbook"].id,
                template_path=str(tpl),
                output_path=str(out),
            )
