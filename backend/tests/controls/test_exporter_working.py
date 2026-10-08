"""Working-view export tests — openpyxl path, no Excel COM required.

The working-view export is the assessor's personal triage workbook:
one row per objective (not per control), needs_review surfaced as a
column, PSC mappings rendered the same way as the eMASS export. These
tests pin:

  - One row per objective (not per control).
  - Family / search filters and control-level status rollups honored.
  - needs_review rows INCLUDED (unlike eMASS export, which excludes them).
  - PSC column rendered per control with source-prefixed lines.
"""

from __future__ import annotations

from openpyxl import Workbook as OpenPyxlWorkbook
from openpyxl import load_workbook

from cybersecurity_assessor.controls.exporter import (
    ControlsFilterState,
    export_controls_working_view,
)
from cybersecurity_assessor.models import ComplianceStatus


def _write_wholly_na_ccis(path, control_id: str, cci_ids: list[str]) -> None:
    workbook = OpenPyxlWorkbook()
    sheet = workbook.active
    sheet.title = "WORKING SHEET"
    sheet.cell(6, 1).value = "Required"
    sheet.cell(6, 2).value = "Control Acronym"
    for offset, cci_id in enumerate(cci_ids, start=7):
        sheet.cell(offset, 1).value = "YES"
        sheet.cell(offset, 2).value = control_id
        sheet.cell(offset, 8).value = cci_id
        sheet.cell(offset, 4).value = "Not Applicable"
    workbook.save(path)


def _seed_assessments(assess, ctx):
    """Populate AC-2 (compliant), AC-3 (NC), AC-5 (needs_review).

    AC-4 is left without assessments so the CRM short-circuit drives its
    status — that's the realistic "the LLM never had to look at this"
    inherited-control case.
    """
    wb_id = ctx["workbook"].id
    objs = ctx["objectives"]

    # AC-2: both CCIs compliant.
    seeded = {}
    seeded["ac2_1"] = assess(
        wb_id,
        objs["CCI-000015"].id,
        ComplianceStatus.COMPLIANT,
        narrative="AC-2 CCI-000015 compliant narrative.",
    )
    seeded["ac2_2"] = assess(
        wb_id,
        objs["CCI-000016"].id,
        ComplianceStatus.COMPLIANT,
        narrative="AC-2 CCI-000016 compliant narrative.",
    )

    # AC-3: one compliant + one NC -> Non-Compliant control rollup.
    seeded["ac3_compliant"] = assess(
        wb_id,
        objs["CCI-000213"].id,
        ComplianceStatus.COMPLIANT,
        narrative="AC-3 CCI-000213 compliant.",
    )
    seeded["ac3_second"] = assess(
        wb_id,
        objs["CCI-000214"].id,
        ComplianceStatus.NON_COMPLIANT,
        narrative="AC-3 CCI-000214 gap on quarterly review cadence.",
    )

    # AC-5: needs_review — surfaced in working view, excluded from eMASS.
    seeded["ac5_review"] = assess(
        wb_id,
        objs["CCI-000038"].id,
        ComplianceStatus.COMPLIANT,
        narrative="Dual-pass disagreed, awaiting tester.",
        needs_review=True,
        review_reason="Status confidence below threshold.",
    )
    return seeded


class TestRowExpansion:
    def test_one_row_per_objective_not_per_control(
        self, session, controls_catalog, assess, tmp_path
    ):
        _seed_assessments(assess, controls_catalog)
        out_path = tmp_path / "working.xlsx"

        result = export_controls_working_view(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            output_path=str(out_path),
        )

        # 4 controls, total 6 objectives (AC-2:2, AC-3:2, AC-4:1, AC-5:1).
        assert result.rows_written == 6
        assert out_path.exists()

        py_wb = load_workbook(str(out_path))
        ws = py_wb.active
        # Header row + 6 data rows.
        assert ws.max_row == 7

    def test_needs_review_rows_included_with_flag(
        self, session, controls_catalog, assess, tmp_path
    ):
        """Unlike the eMASS export (precision-over-recall gate), the
        working view surfaces needs_review rows so the assessor can
        triage them in Excel."""
        _seed_assessments(assess, controls_catalog)
        out_path = tmp_path / "working_nr.xlsx"

        export_controls_working_view(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            output_path=str(out_path),
        )

        py_wb = load_workbook(str(out_path))
        ws = py_wb.active
        headers = [c.value for c in ws[1]]
        nr_idx = headers.index("Needs Review")
        cci_idx = headers.index("CCI")

        # Locate the AC-5 / CCI-000038 row.
        nr_rows = [
            row for row in ws.iter_rows(min_row=2, values_only=True)
            if row[cci_idx] == "CCI-000038"
        ]
        assert len(nr_rows) == 1
        assert nr_rows[0][nr_idx] == "Yes"


class TestFilters:
    def test_family_filter_only_emits_matching_controls(
        self, session, controls_catalog, assess, tmp_path
    ):
        """All seeded controls are family=AC so a non-AC filter must
        drop everything — empty data set, header row still present."""
        _seed_assessments(assess, controls_catalog)
        out_path = tmp_path / "fam_none.xlsx"

        result = export_controls_working_view(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            output_path=str(out_path),
            filter_state=ControlsFilterState(family="AU"),
        )

        assert result.rows_written == 0
        py_wb = load_workbook(str(out_path))
        ws = py_wb.active
        assert ws.max_row == 1  # header only

    def test_family_filter_ac_emits_all(
        self, session, controls_catalog, assess, tmp_path
    ):
        _seed_assessments(assess, controls_catalog)
        out_path = tmp_path / "fam_ac.xlsx"

        result = export_controls_working_view(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            output_path=str(out_path),
            filter_state=ControlsFilterState(family="AC"),
        )

        # Family filter is case-insensitive in the loader (upper()).
        assert result.rows_written == 6

    def test_search_filter_substring_on_control_id(
        self, session, controls_catalog, assess, tmp_path
    ):
        """search='AC-2' must match only AC-2 control, leaving 2 rows."""
        _seed_assessments(assess, controls_catalog)
        out_path = tmp_path / "search.xlsx"

        result = export_controls_working_view(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            output_path=str(out_path),
            filter_state=ControlsFilterState(search="AC-2"),
        )

        # AC-2 has two objectives.
        assert result.rows_written == 2

    def test_status_filter_selects_non_compliant_control_then_keeps_all_objectives(
        self, session, controls_catalog, assess, tmp_path
    ):
        """One trusted NC selects AC-3, including its compliant objective."""
        _seed_assessments(assess, controls_catalog)
        out_path = tmp_path / "status.xlsx"

        result = export_controls_working_view(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            output_path=str(out_path),
            filter_state=ControlsFilterState(status="Non-Compliant"),
        )

        assert result.rows_written == 2
        py_wb = load_workbook(str(out_path))
        ws = py_wb.active
        headers = [c.value for c in ws[1]]
        ctl_idx = headers.index("Control")
        cci_idx = headers.index("CCI")
        data_rows = list(ws.iter_rows(min_row=2, values_only=True))
        assert {row[ctl_idx] for row in data_rows} == {"AC-3"}
        assert {row[cci_idx] for row in data_rows} == {
            "CCI-000213",
            "CCI-000214",
        }

    def test_compliant_filter_keeps_every_objective_for_matching_control(
        self, session, controls_catalog, assess, tmp_path
    ):
        _seed_assessments(assess, controls_catalog)
        out_path = tmp_path / "status_compliant.xlsx"

        result = export_controls_working_view(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            output_path=str(out_path),
            filter_state=ControlsFilterState(status="Compliant"),
        )

        assert result.rows_written == 2
        ws = load_workbook(str(out_path)).active
        controls = [row[0] for row in ws.iter_rows(min_row=2, values_only=True)]
        assert controls == ["AC-2", "AC-2"]

    def test_mixed_filter_uses_compliant_plus_na_control_rollup(
        self, session, controls_catalog, assess, tmp_path
    ):
        seeded = _seed_assessments(assess, controls_catalog)
        seeded["ac3_second"].status = ComplianceStatus.NOT_APPLICABLE
        session.add(seeded["ac3_second"])
        session.commit()
        _write_wholly_na_ccis(
            controls_catalog["path"],
            "AC-3",
            ["CCI-000214"],
        )
        out_path = tmp_path / "status_mixed.xlsx"

        result = export_controls_working_view(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            output_path=str(out_path),
            filter_state=ControlsFilterState(status="Mixed"),
        )

        assert result.rows_written == 2
        ws = load_workbook(str(out_path)).active
        headers = [c.value for c in ws[1]]
        ctl_idx = headers.index("Control")
        status_idx = headers.index("Status")
        data_rows = list(ws.iter_rows(min_row=2, values_only=True))
        assert {row[ctl_idx] for row in data_rows} == {"AC-3"}
        assert {row[status_idx] for row in data_rows} == {
            "Compliant",
            "Not Applicable",
        }

    def test_needs_review_filter_uses_control_rollup_not_raw_status(
        self, session, controls_catalog, assess, tmp_path
    ):
        _seed_assessments(assess, controls_catalog)
        out_path = tmp_path / "status_review.xlsx"

        result = export_controls_working_view(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            output_path=str(out_path),
            filter_state=ControlsFilterState(status="Needs Review"),
        )

        assert result.rows_written == 1
        ws = load_workbook(str(out_path)).active
        data_row = next(ws.iter_rows(min_row=2, values_only=True))
        assert data_row[0] == "AC-5"
        assert data_row[5] == "Compliant"
        assert data_row[6] == "Yes"

    def test_partial_filter_does_not_overstate_incomplete_control(
        self, session, controls_catalog, assess, tmp_path
    ):
        seeded = _seed_assessments(assess, controls_catalog)
        session.delete(seeded["ac2_2"])
        session.commit()
        out_path = tmp_path / "status_partial.xlsx"

        result = export_controls_working_view(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            output_path=str(out_path),
            filter_state=ControlsFilterState(status="Partially Assessed"),
        )

        assert result.rows_written == 2
        ws = load_workbook(str(out_path)).active
        headers = [cell.value for cell in ws[1]]
        status_idx = headers.index("Status")
        data_rows = list(ws.iter_rows(min_row=2, values_only=True))
        assert {row[0] for row in data_rows} == {"AC-2"}
        assert {row[status_idx] for row in data_rows} == {"Compliant", None}

    def test_unassessed_filter_selects_only_controls_without_assessments(
        self, session, controls_catalog, assess, tmp_path
    ):
        _seed_assessments(assess, controls_catalog)
        out_path = tmp_path / "status_unassessed.xlsx"

        result = export_controls_working_view(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            output_path=str(out_path),
            filter_state=ControlsFilterState(status="__unassessed__"),
        )

        assert result.rows_written == 1
        ws = load_workbook(str(out_path)).active
        data_row = next(ws.iter_rows(min_row=2, values_only=True))
        assert data_row[0] == "AC-4"
        assert data_row[5] is None

    def test_not_applicable_filter_accepts_canonical_and_legacy_tokens(
        self, session, controls_catalog, assess, tmp_path
    ):
        seeded = _seed_assessments(assess, controls_catalog)
        for key in ("ac2_1", "ac2_2"):
            seeded[key].status = ComplianceStatus.NOT_APPLICABLE
            session.add(seeded[key])
        session.commit()
        _write_wholly_na_ccis(
            controls_catalog["path"],
            "AC-2",
            ["CCI-000015", "CCI-000016"],
        )

        for token in ("Not Applicable", "N/A", " n/a "):
            out_path = tmp_path / f"status_na_{token.strip().replace('/', '-')}.xlsx"
            result = export_controls_working_view(
                session=session,
                workbook_id=controls_catalog["workbook"].id,
                output_path=str(out_path),
                filter_state=ControlsFilterState(status=token),
            )

            assert result.rows_written == 2
            ws = load_workbook(str(out_path)).active
            data_rows = list(ws.iter_rows(min_row=2, values_only=True))
            assert {row[0] for row in data_rows} == {"AC-2"}
            assert {row[5] for row in data_rows} == {"Not Applicable"}

    def test_inferred_column_n_na_matches_ui_and_is_not_unassessed(
        self, session, controls_catalog, assess, tmp_path
    ):
        _seed_assessments(assess, controls_catalog)
        _write_wholly_na_ccis(
            controls_catalog["path"], "AC-4", ["CCI-001548"]
        )

        na_path = tmp_path / "status_inferred_na.xlsx"
        na_result = export_controls_working_view(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            output_path=str(na_path),
            filter_state=ControlsFilterState(status="Not Applicable"),
        )
        assert na_result.rows_written == 1
        na_row = next(load_workbook(str(na_path)).active.iter_rows(
            min_row=2, values_only=True
        ))
        assert na_row[0] == "AC-4"
        assert na_row[5] == "Not Applicable"

        unassessed_path = tmp_path / "status_inferred_na_unassessed.xlsx"
        unassessed_result = export_controls_working_view(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            output_path=str(unassessed_path),
            filter_state=ControlsFilterState(status="__unassessed__"),
        )
        assert unassessed_result.rows_written == 0

    def test_column_d_na_overrides_stale_persisted_statuses_in_export(
        self, session, controls_catalog, assess, tmp_path
    ):
        _write_wholly_na_ccis(
            controls_catalog["path"],
            "AC-2",
            ["CCI-000015", "CCI-000016"],
        )
        assess(
            controls_catalog["workbook"].id,
            controls_catalog["objectives"]["CCI-000015"].id,
            ComplianceStatus.COMPLIANT,
        )

        out_path = tmp_path / "status_persisted_beats_inference.xlsx"
        result = export_controls_working_view(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            output_path=str(out_path),
            filter_state=ControlsFilterState(status="Not Applicable"),
        )

        assert result.rows_written == 2
        ws = load_workbook(str(out_path)).active
        headers = [cell.value for cell in ws[1]]
        status_idx = headers.index("Status")
        narrative_idx = headers.index("Narrative")
        data_rows = list(ws.iter_rows(min_row=2, values_only=True))
        assert {row[0] for row in data_rows} == {"AC-2"}
        assert {row[status_idx] for row in data_rows} == {"Not Applicable"}
        assert all("Column D" in row[narrative_idx] for row in data_rows)
        assert all("Stale Compliant" not in row[narrative_idx] for row in data_rows)

    def test_non_na_column_d_suppresses_stale_persisted_na(
        self, session, controls_catalog, assess, tmp_path
    ):
        assess(
            controls_catalog["workbook"].id,
            controls_catalog["objectives"]["CCI-001548"].id,
            ComplianceStatus.NOT_APPLICABLE,
            narrative="Stale N/A from a prior release.",
        )

        out_path = tmp_path / "stale-na-working.xlsx"
        result = export_controls_working_view(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            output_path=str(out_path),
        )

        assert result.rows_written == 6
        ws = load_workbook(str(out_path)).active
        headers = [cell.value for cell in ws[1]]
        status_idx = headers.index("Status")
        ac4_rows = [
            row
            for row in ws.iter_rows(min_row=2, values_only=True)
            if row[0] == "AC-4"
        ]
        assert len(ac4_rows) == 1
        assert ac4_rows[0][status_idx] in (None, "")


class TestPscColumn:
    def test_psc_text_appears_for_controls_with_overlays(
        self, session, controls_catalog, assess, tmp_path
    ):
        """AC-2 has two PSC mappings (SDA-127, T1TL-031); AC-3 has one
        (SDA-201). AC-4 and AC-5 have none."""
        _seed_assessments(assess, controls_catalog)
        out_path = tmp_path / "psc.xlsx"

        result = export_controls_working_view(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            output_path=str(out_path),
        )

        # controls_with_psc counts unique controls, not rows.
        assert result.controls_with_psc == 2

        py_wb = load_workbook(str(out_path))
        ws = py_wb.active
        headers = [c.value for c in ws[1]]
        ctl_idx = headers.index("Control")
        psc_idx = headers.index("Program-Specific Controls")

        psc_by_control: dict[str, str] = {}
        for row in ws.iter_rows(min_row=2, values_only=True):
            psc_by_control[row[ctl_idx]] = row[psc_idx]

        # AC-2: source-prefixed lines from both SDA and T1TL, sorted by
        # source name then requirement_number.
        ac2 = psc_by_control["AC-2"] or ""
        assert "SDA-127:" in ac2
        assert "T1TL-031:" in ac2
        # SDA sorts before T1TL alphabetically.
        assert ac2.index("SDA-127:") < ac2.index("T1TL-031:")

        # AC-3: just SDA-201.
        ac3 = psc_by_control["AC-3"] or ""
        assert "SDA-201:" in ac3

        # AC-4, AC-5: no PSC overlays.
        assert not psc_by_control["AC-4"]
        assert not psc_by_control["AC-5"]


class TestHeaderContract:
    def test_header_row_columns(
        self, session, controls_catalog, tmp_path
    ):
        """Header row pinned — UI/CSV consumers index by column name."""
        out_path = tmp_path / "headers.xlsx"

        export_controls_working_view(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            output_path=str(out_path),
        )

        py_wb = load_workbook(str(out_path))
        ws = py_wb.active
        headers = [c.value for c in ws[1]]
        assert headers == [
            "Control",
            "Title",
            "Family",
            "Program-Specific Controls",
            "CCI",
            "Status",
            "Needs Review",
            "Narrative",
            "Narrative (On-Prem)",
            "Narrative (Cloud)",
            "Inheritance Rule",
            "Confidence",
            "CRM Responsibility (Cloud)",
            "CRM Responsibility (On-Prem)",
        ]

    def test_sheet_title(self, session, controls_catalog, tmp_path):
        out_path = tmp_path / "title.xlsx"
        export_controls_working_view(
            session=session,
            workbook_id=controls_catalog["workbook"].id,
            output_path=str(out_path),
        )
        py_wb = load_workbook(str(out_path))
        assert py_wb.active.title == "Controls (Working View)"


class TestErrorPaths:
    def test_missing_workbook_raises_value_error(self, session, tmp_path):
        import pytest
        with pytest.raises(ValueError, match="not found"):
            export_controls_working_view(
                session=session,
                workbook_id=999_999,
                output_path=str(tmp_path / "x.xlsx"),
            )

    def test_no_baseline_raises_value_error(self, session, tmp_path):
        """A workbook without a baseline_id can't materialize an in-scope
        set — the loader bails before touching xlsx output."""
        import pytest

        from cybersecurity_assessor.models import Workbook

        p = tmp_path / "no-baseline.xlsx"
        p.write_bytes(b"x")
        wb = Workbook(path=str(p), filename=p.name)
        session.add(wb)
        session.commit()
        session.refresh(wb)

        with pytest.raises(ValueError, match="Baseline"):
            export_controls_working_view(
                session=session,
                workbook_id=wb.id,
                output_path=str(tmp_path / "out.xlsx"),
            )
