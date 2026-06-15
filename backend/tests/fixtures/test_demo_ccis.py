"""Regression test for the demo CCIS fixture.

Catches accidental drift in ``build_demo_ccis.py`` -- if someone edits
the script and forgets to regenerate ``demo_ccis.xlsx`` (or vice versa),
this test fails fast. It also documents what downstream tests can
count on being present in the fixture.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cybersecurity_assessor.excel.ccis_reader import read_workbook_index

FIXTURE = Path(__file__).resolve().parent / "demo_ccis.xlsx"


@pytest.fixture(scope="module")
def index():
    if not FIXTURE.exists():
        pytest.fail(
            f"Demo workbook missing at {FIXTURE}. "
            "Run: python backend/tests/fixtures/build_demo_ccis.py"
        )
    return read_workbook_index(FIXTURE)


def test_sheet_name_is_working_sheet(index):
    assert index.sheet_name == "WORKING SHEET"


def test_expected_row_count(index):
    # build_demo_ccis.ROWS currently has 7 entries.
    assert len(index.rows) == 7


def test_control_families_covered(index):
    families = {row.control_id.split("-")[0] for row in index.rows}
    assert {"AC", "AU", "SI"}.issubset(families)


def test_expected_control_ids_present(index):
    control_ids = {row.control_id for row in index.rows}
    expected = {"AC-2", "AC-3", "AC-2(1)", "AU-2", "AU-3", "SI-2", "SI-4"}
    assert expected.issubset(control_ids)


def test_ac2_row_has_superseded_usd_reference(index):
    """AC-2 row's column U must cite the legacy T1 doc -- this is what
    the supersession-detection logic keys on."""
    ac2 = next(r for r in index.rows if r.control_id == "AC-2")
    assert ac2.previous_results is not None
    assert "Account Management User Guide" in ac2.previous_results


def test_gap_row_has_no_narrative(index):
    """AC-2(1) is the 'gap' row -- column F intentionally blank."""
    gap = next(r for r in index.rows if r.control_id == "AC-2(1)")
    assert gap.narrative is None


def test_si4_row_has_no_cci(index):
    """SI-4 exercises the 'missing CCI' code path -- col H blank, so
    cci_id should parse to None."""
    si4 = next(r for r in index.rows if r.control_id == "SI-4")
    assert si4.cci_id is None


def test_cci_normalization_strips_bare_to_canonical(index):
    """Col H values are stored bare ('000015'); reader should
    normalize them to the canonical 'CCI-000015' form."""
    ac2 = next(r for r in index.rows if r.control_id == "AC-2")
    assert ac2.cci_id == "CCI-000015"


def test_at_least_one_inherited_row(index):
    inherited = [r for r in index.rows if r.inherited == "DoW Enterprise"]
    assert len(inherited) >= 1


def test_current_assessment_row_round_trips(index):
    """AU-3 has a fully populated current assessment; verify all four
    write-cells survive a parse."""
    au3 = next(r for r in index.rows if r.control_id == "AU-3")
    assert au3.status == "Compliant"
    assert au3.tester == "Noah Jaskolski"
    assert au3.date_tested is not None
    assert au3.results and "Audit Plan Section 4" in au3.results
