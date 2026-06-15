"""Regression tests for the SAR exporter's needs_review filter.

History: ``feedback_sar_needs_review_gate.md`` flagged that
``reports/sar.py`` was the only ``Assessment`` consumer that didn't gate on
``Assessment.needs_review`` -- every other export path (eMASS CCIS via
``controls/exporter.py:28-30``, POAM via ``poam/generator.py:713``,
ccis_writer) correctly excludes ``needs_review=True`` rows. The defect was
latent until the abstain coercion fix (``76f04ef``) started persisting hard
abstains as ``(NON_COMPLIANT, "(abstain -- pending human review)",
needs_review=True)``; from that point on, those coerced rows would have
flowed straight into the SAR's ``status_totals`` rollup, the per-control
verdict promotion (``sar.py:961-962``), and Appendix D's NC list
(``sar.py:1618``) -- misrepresenting placeholder rows as real findings.

These tests pin the fix at the single fanout point: the Assessment query
in ``_gather`` (``sar.py:294-308``). One ``.where()`` clause filters at the
source so every downstream rollup is clean by construction; tests pin both
``status_totals`` and the verdict-promotion behavior so a future refactor
can't reintroduce either failure mode independently.

Tested at the ``_gather`` layer rather than ``build_sar_report``: the
filter contract is what's being regressed, not the reportlab PDF generation
roundtrip. The PDF-integration test is a separate testability investment.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

# Make the backend package importable from any pytest cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.excel.ccis_reader import CcisIndex, CcisRow  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Assessment,
    ComplianceStatus,
    Control,
    Framework,
    NarrativeClass,
    Objective,
    Workbook,
)
from cybersecurity_assessor.reports import sar as sar_module  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ccis_row(*, cci_id: str, control_id: str, excel_row: int) -> CcisRow:
    """Minimal CcisRow with col-N status left empty so the SAR's flatten loop
    relies entirely on the DB overlay -- a row whose DB Assessment is filtered
    out by the needs_review gate then has nothing to fall back to and drops
    out of ``data.rows`` entirely. That's the cleanest expression of "the
    placeholder is gone."
    """
    return CcisRow(
        excel_row=excel_row,
        required=True,
        control_id=control_id,
        ap_acronym=f"{control_id}.1",
        cci_id=cci_id,
        implementation_status=None,
        designation=None,
        narrative=None,
        definition="The organization manages information system accounts.",
        guidance=None,
        procedures="Examine: account management procedures.",
        inherited=None,
        remote_inheritance=None,
        status=None,  # workbook col-N empty; DB row is the only signal
        date_tested=None,
        tester=None,
        results=None,
        previous_status=None,
        previous_date=None,
        previous_tester=None,
        previous_results=None,
    )


def _seed_framework_and_workbook(
    session: Session, wb_path: Path
) -> tuple[int, Control, list[Objective]]:
    """Seed a single Framework + Control + two Objectives + a Workbook tied
    to ``wb_path``. Returns (workbook_id, control, [obj_a, obj_b]).
    """
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)

    ctrl = Control(
        framework_id=fw.id,
        control_id="AC-2",
        title="Account Management",
        family="AC",
    )
    session.add(ctrl)
    session.commit()
    session.refresh(ctrl)

    obj_a = Objective(
        control_id_fk=ctrl.id,
        objective_id="CCI-000001",
        source="CCI",
        text="Define and document the types of accounts allowed.",
    )
    obj_b = Objective(
        control_id_fk=ctrl.id,
        objective_id="CCI-002124",  # the CCI from feedback_abstain_status_none_drops
        source="CCI",
        text="Audit account creation, modification, enabling, disabling, and removal actions.",
    )
    session.add(obj_a)
    session.add(obj_b)
    session.commit()
    session.refresh(obj_a)
    session.refresh(obj_b)

    wb = Workbook(
        path=str(wb_path),
        filename=wb_path.name,
        framework_id=fw.id,
    )
    session.add(wb)
    session.commit()
    session.refresh(wb)

    return wb.id, ctrl, [obj_a, obj_b]


def _make_assessment(
    *,
    workbook_id: int,
    objective_id: int,
    excel_row: int,
    status: ComplianceStatus,
    needs_review: bool,
    narrative_q: str,
) -> Assessment:
    return Assessment(
        workbook_id=workbook_id,
        objective_id=objective_id,
        excel_row=excel_row,
        status=status,
        tester="Noah Jaskolski",
        date_tested=datetime(2026, 6, 1, tzinfo=timezone.utc),
        narrative_q=narrative_q,
        narrative_class=NarrativeClass.COMPLIANCE_AFFIRMING
        if status is ComplianceStatus.COMPLIANT
        else NarrativeClass.GAP_DESCRIBING,
        needs_review=needs_review,
        review_reason="llm-abstain: forced abstain" if needs_review else None,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_sar_excludes_needs_review_rows_from_status_totals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Seed one COMPLIANT row (trusted) and one NON_COMPLIANT
    needs_review=True row (the abstain-coerced shape). The SAR's
    ``status_totals`` must contain only the trusted row -- the placeholder
    must not show up in any rollup.

    Pre-fix (post-``76f04ef`` but pre-this-plan) this test fails: the gate
    didn't exist, so ``status_totals[NON_COMPLIANT]`` was 1.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    wb_path = tmp_path / "ccis_sar_needs_review.xlsx"
    wb_path.touch()

    with Session(engine) as s:
        wb_id, _ctrl, (obj_a, obj_b) = _seed_framework_and_workbook(s, wb_path)
        s.add(
            _make_assessment(
                workbook_id=wb_id,
                objective_id=obj_a.id,
                excel_row=42,
                status=ComplianceStatus.COMPLIANT,
                needs_review=False,
                narrative_q="Real assessor narrative.",
            )
        )
        s.add(
            _make_assessment(
                workbook_id=wb_id,
                objective_id=obj_b.id,
                excel_row=43,
                status=ComplianceStatus.NON_COMPLIANT,  # coerced from abstain
                needs_review=True,
                narrative_q="(abstain -- pending human review)",
            )
        )
        s.commit()

        # Workbook stub: both CCIs present, neither has a col-N status. The
        # COMPLIANT row picks up its status from the DB overlay; the
        # needs_review row's DB overlay is filtered out by ``_gather`` and
        # there's no col-N fallback -- the row drops from data.rows entirely.
        ccis_index = CcisIndex(
            workbook_path=wb_path,
            sheet_name="CCIS",
            rows=[
                _make_ccis_row(cci_id="CCI-000001", control_id="AC-2", excel_row=42),
                _make_ccis_row(cci_id="CCI-002124", control_id="AC-2", excel_row=43),
            ],
        )
        monkeypatch.setattr(
            "cybersecurity_assessor.reports.sar.read_workbook_index",
            lambda path: ccis_index,
        )

        data = sar_module._gather(s, wb_id)

    assert data.status_totals[ComplianceStatus.COMPLIANT] == 1
    assert data.status_totals[ComplianceStatus.NON_COMPLIANT] == 0
    assert data.status_totals[ComplianceStatus.NOT_APPLICABLE] == 0

    # The placeholder narrative must not have landed in any row's narrative.
    # Stronger than just counting -- this asserts the actual text is gone,
    # which is what would have shown up in Appendix D / the per-row column.
    narratives = [r.narrative for r in data.rows]
    assert "(abstain -- pending human review)" not in narratives
    # And only the trusted row's CCI made it through.
    assert {r.cci_id for r in data.rows} == {"CCI-000001"}


def test_sar_verdict_ignores_needs_review_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two Assessments on the same control: one COMPLIANT (trusted), one
    NON_COMPLIANT with needs_review=True (the abstain-coerced shape). Pre-fix
    the SAR's verdict-promotion logic (``sar.py:961-962``) would have flipped
    the control to "Non-Compliant" solely because of the placeholder row.
    Post-fix the needs_review row is filtered before the rollup, so the
    verdict stays "Compliant".

    Rebuilds the verdict inline from ``data.by_control`` rather than calling a
    helper -- ``sar.py:953-966`` keeps the logic inlined in
    ``_render_appendix_a``, so pinning the same expression here ensures the
    test fails if either the filter regresses OR if the verdict-promotion
    expression itself drifts.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    wb_path = tmp_path / "ccis_sar_verdict.xlsx"
    wb_path.touch()

    with Session(engine) as s:
        wb_id, ctrl, (obj_a, obj_b) = _seed_framework_and_workbook(s, wb_path)
        s.add(
            _make_assessment(
                workbook_id=wb_id,
                objective_id=obj_a.id,
                excel_row=42,
                status=ComplianceStatus.COMPLIANT,
                needs_review=False,
                narrative_q="Real assessor narrative.",
            )
        )
        s.add(
            _make_assessment(
                workbook_id=wb_id,
                objective_id=obj_b.id,
                excel_row=43,
                status=ComplianceStatus.NON_COMPLIANT,  # coerced from abstain
                needs_review=True,
                narrative_q="(abstain -- pending human review)",
            )
        )
        s.commit()

        ccis_index = CcisIndex(
            workbook_path=wb_path,
            sheet_name="CCIS",
            rows=[
                _make_ccis_row(cci_id="CCI-000001", control_id="AC-2", excel_row=42),
                _make_ccis_row(cci_id="CCI-002124", control_id="AC-2", excel_row=43),
            ],
        )
        monkeypatch.setattr(
            "cybersecurity_assessor.reports.sar.read_workbook_index",
            lambda path: ccis_index,
        )

        data = sar_module._gather(s, wb_id)

    items = data.by_control[ctrl.control_id]
    nc = sum(1 for r in items if r.status == ComplianceStatus.NON_COMPLIANT)
    c = sum(1 for r in items if r.status == ComplianceStatus.COMPLIANT)
    # Mirror sar.py:961-966 verbatim.
    if nc > 0:
        verdict = "Non-Compliant"
    elif c > 0:
        verdict = "Compliant"
    else:
        verdict = "Not Applicable"

    assert nc == 0, "needs_review NC row leaked into the control's NC count"
    assert c == 1
    assert verdict == "Compliant"
