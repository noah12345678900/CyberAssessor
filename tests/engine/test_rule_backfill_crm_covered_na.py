"""Regression: a wholly-Column-N N/A control that is ALSO CRM-covered still
gets a real rule-8b NOT_APPLICABLE Assessment persisted at workbook-open time.

THE BUG (PE-10, user-found). PE-10 is attested Not Applicable in workbook
Column N (rule 8b) AND is covered by both demo CRMs (clouds N/A). The grid
showed a synthetic "Not Applicable" Status chip (derived live from the col-N
signal) but the batch "already assessed" preflight counted only 2 — because no
real Assessment row was ever persisted for PE-10, so the count and the grid
disagreed (3 chips, 2 counted).

``backfill_workbook_rules`` front-loads deterministic rule verdicts at
workbook-open so col-N N/A controls surface as REAL rows without a manual
Assess. AC-18 (no CRM) already worked; the open question was whether a
CRM-covered control like PE-10 is also written, or wrongly skipped. The
production loop has no CRM-skip — this test pins that contract.

DESIGN OF THIS TEST (hardened per review). The naive version attached CRMs to a
single control and asserted a row was written — but ``backfill_workbook_rules``
never reads CRM overlays, so those attachments were inert and the test would
pass even if a (wrong) CRM-skip were added. To actually catch that regression
class, this test runs BOTH backfills in the real open order
(CRM-backfill THEN rule-backfill) over TWO col-N-NA controls in one workbook:
PE-10 (CRM-covered) and AC-18 (no CRM). It asserts BOTH end up with a real
rule-8b NA Assessment. A wrongful CRM-skip in the rule backfill would drop
PE-10's row while leaving AC-18's — failing the PE-10 assertion specifically.

Lives in the COLLECTED top-level tree (``testpaths=["../tests"]``) so it runs in
the default suite (the sibling ``backend/tests/engine/test_crm_backfill.py`` is
NOT collected by default).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from cybersecurity_assessor import models  # noqa: F401 -- register tables
from cybersecurity_assessor.engine import crm_backfill
from cybersecurity_assessor.engine.crm_backfill import (
    backfill_workbook_crm,
    backfill_workbook_rules,
)
from cybersecurity_assessor.excel.ccis_reader import CcisIndex, CcisRow
from cybersecurity_assessor.models import (
    Assessment,
    Baseline,
    BaselineControl,
    BaselineObjective,
    BaselineSourceType,
    ComplianceStatus,
    Control,
    Framework,
    Objective,
    Workbook,
    WorkbookOverlay,
)


@pytest.fixture
def session() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _na_row(*, control_id: str, cci_id: str, excel_row: int) -> CcisRow:
    """A col-N 'Not Applicable' / col-L 'No' row → classify_row → 8b."""
    return CcisRow(
        excel_row=excel_row,
        required=True,
        control_id=control_id,
        ap_acronym=None,
        cci_id=cci_id,
        implementation_status=None,
        designation=None,
        narrative=None,
        definition=f"{control_id} definition.",
        guidance=None,
        procedures=None,
        inherited="No",  # Column L = ASSESS (but col N wins → 8b)
        remote_inheritance=None,
        status="Not Applicable",  # Column N → rule 8b
        date_tested=None,
        tester=None,
        results="Out of scope for this system.",
        previous_status=None,
        previous_date=None,
        previous_tester=None,
        previous_results=None,
    )


def _make_control(session: Session, fw_id: int, oscal: str, family: str) -> Control:
    c = Control(framework_id=fw_id, control_id=oscal, title=oscal.upper(), family=family)
    session.add(c)
    session.commit()
    session.refresh(c)
    return c


def _make_objective(session: Session, ctrl: Control, cci: str) -> Objective:
    o = Objective(control_id_fk=ctrl.id, objective_id=cci, source="CCI", text=f"{cci} text")
    session.add(o)
    session.commit()
    session.refresh(o)
    return o


def _in_scope(session: Session, baseline_id: int, ctrl: Control, obj: Objective, row: int):
    session.add(BaselineControl(baseline_id=baseline_id, control_id=ctrl.id, in_scope=True))
    session.add(
        BaselineObjective(baseline_id=baseline_id, objective_id=obj.id, source_row=row)
    )
    session.commit()


def test_crm_covered_and_uncovered_col_n_na_both_get_real_rows(session, monkeypatch):
    """Open-order regression: CRM-backfill THEN rule-backfill must leave BOTH a
    CRM-covered col-N-NA control (PE-10) and a non-CRM one (AC-18) with a real
    rule-8b NOT_APPLICABLE Assessment.

    This is the PE-10 fix: the grid's synthetic N/A chip must be backed by a
    persisted row so the batch preflight count includes it. A wrongful CRM-skip
    in the rule backfill would drop PE-10's row (CRM-covered) while keeping
    AC-18's (uncovered) — the PE-10 assertion below catches exactly that.
    """
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)

    pe10 = _make_control(session, fw.id, "pe-10", "PE")
    pe10_obj = _make_objective(session, pe10, "CCI-000813")
    ac18 = _make_control(session, fw.id, "ac-18", "AC")
    ac18_obj = _make_objective(session, ac18, "CCI-001438")

    primary = Baseline(
        framework_id=fw.id, name="primary", source_type=BaselineSourceType.CCIS_WORKBOOK
    )
    session.add(primary)
    session.commit()
    session.refresh(primary)

    wb_path = Path("unused_pe10_ac18.xlsx")
    wb_path.write_bytes(b"")
    try:
        wb = Workbook(path=str(wb_path), filename=wb_path.name, baseline_id=primary.id)
        session.add(wb)
        session.commit()
        session.refresh(wb)

        _in_scope(session, primary.id, pe10, pe10_obj, 99)
        _in_scope(session, primary.id, ac18, ac18_obj, 100)

        # PE-10 is CRM-COVERED: both clouds mark it Not Applicable. AC-18 gets
        # NO CRM — the contrast that makes the CRM-skip regression detectable.
        for label in ("AWS GovCloud", "Azure Government"):
            crm = Baseline(
                framework_id=fw.id,
                name=f"CRM-{label}",
                source_type=BaselineSourceType.CRM,
                scope_label=label,
            )
            session.add(crm)
            session.commit()
            session.refresh(crm)
            session.add(
                BaselineControl(
                    baseline_id=crm.id,
                    control_id=pe10.id,
                    in_scope=True,
                    responsibility="not_applicable",
                    responsibility_narrative=f"{label} provider-internal facility.",
                )
            )
            session.add(
                WorkbookOverlay(
                    workbook_id=wb.id,
                    baseline_id=crm.id,
                    attached_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
                )
            )
            session.commit()

        monkeypatch.setattr(
            crm_backfill,
            "read_workbook_index",
            lambda _p: CcisIndex(
                workbook_path=wb_path,
                sheet_name="WORKING SHEET",
                rows=[
                    _na_row(control_id="PE-10", cci_id="CCI-000813", excel_row=99),
                    _na_row(control_id="AC-18", cci_id="CCI-001438", excel_row=100),
                ],
            ),
        )

        # Real open order: CRM-backfill first (it owns CRM-deterministic
        # controls), then rule-backfill (owns workbook-intrinsic rule verdicts).
        # PE-10's clouds are both NA AND col N is NA — whichever backfill writes
        # it, the persisted verdict must be NOT_APPLICABLE.
        backfill_workbook_crm(workbook_id=wb.id, session=session)
        session.commit()
        rule_result = backfill_workbook_rules(workbook_id=wb.id, session=session)
        session.commit()

        rows = {
            session.get(Objective, a.objective_id).objective_id: a
            for a in session.exec(select(Assessment)).all()
        }

        # BOTH controls must have a persisted NA row — this is the core claim.
        assert "CCI-000813" in rows, (
            "PE-10 (CRM-covered) must get a persisted NA row; a CRM-skip in the "
            "rule backfill would drop it"
        )
        assert "CCI-001438" in rows, "AC-18 (no CRM) must get a persisted NA row"
        assert rows["CCI-000813"].status is ComplianceStatus.NOT_APPLICABLE
        assert rows["CCI-001438"].status is ComplianceStatus.NOT_APPLICABLE

        # AC-18 is rule-8b (no CRM owns it). PE-10 may be written by either
        # backfill (clouds-NA via CRM, or col-N via rule) — both yield NA, which
        # is what the grid chip and the preflight count need.
        assert rows["CCI-001438"].inheritance_rule == "8b"

        # Idempotent: a second open writes nothing new.
        again_crm = backfill_workbook_crm(workbook_id=wb.id, session=session)
        again_rules = backfill_workbook_rules(workbook_id=wb.id, session=session)
        assert again_crm.applied == 0
        assert again_rules.applied == 0
        # Still exactly two assessments — no duplication.
        assert len(session.exec(select(Assessment)).all()) == 2
    finally:
        wb_path.unlink(missing_ok=True)


def _rule8a_row(*, control_id: str, cci_id: str, excel_row: int, source: str) -> CcisRow:
    """A col-L 'Yes' + col-M named-source row → classify_row → COMPLIANT_8A."""
    return CcisRow(
        excel_row=excel_row,
        required=True,
        control_id=control_id,
        ap_acronym=None,
        cci_id=cci_id,
        implementation_status=None,
        designation=None,
        narrative=None,
        definition=f"{control_id} definition.",
        guidance=None,
        procedures=None,
        inherited="Yes",  # Column L = Remote/Yes
        remote_inheritance=source,  # Column M names the source → 8a
        status=None,
        date_tested=None,
        tester=None,
        results=None,
        previous_status=None,
        previous_date=None,
        previous_tester=None,
        previous_results=None,
    )


def test_rule8a_stale_compliant_healed_when_crm_makes_control_hybrid(
    session, monkeypatch
):
    """SC-7 fix: a whole-control rule_8a Compliant (written at open when no CRM
    existed) must NOT survive a later HYBRID CRM attach.

    SC-7 has col L="Yes" + col M="SDA Enterprise Service" → classify_row →
    COMPLIANT_8A, so workbook-open rule-backfill writes Compliant (correct with
    no cloud slices). Attaching two HYBRID CRMs makes the cloud slices need
    assessment, so the whole-control Compliant is stale and masks them. The CRM
    self-heal must DELETE it (healed_deleted), and a subsequent RE-OPEN
    rule-backfill must NOT resurrect it (the control is now CRM-hybrid-covered).
    A col-N rule_8b NA control in the same workbook must be unaffected (PE-10
    guard still holds).
    """
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)

    sc7 = _make_control(session, fw.id, "sc-7", "SC")
    sc7_obj = _make_objective(session, sc7, "CCI-001097")
    pe10 = _make_control(session, fw.id, "pe-10", "PE")
    pe10_obj = _make_objective(session, pe10, "CCI-000813")

    primary = Baseline(
        framework_id=fw.id, name="primary", source_type=BaselineSourceType.CCIS_WORKBOOK
    )
    session.add(primary)
    session.commit()
    session.refresh(primary)

    wb_path = Path("unused_sc7.xlsx")
    wb_path.write_bytes(b"")
    try:
        wb = Workbook(path=str(wb_path), filename=wb_path.name, baseline_id=primary.id)
        session.add(wb)
        session.commit()
        session.refresh(wb)
        _in_scope(session, primary.id, sc7, sc7_obj, 5)
        _in_scope(session, primary.id, pe10, pe10_obj, 6)

        monkeypatch.setattr(
            crm_backfill,
            "read_workbook_index",
            lambda _p: CcisIndex(
                workbook_path=wb_path,
                sheet_name="WORKING SHEET",
                rows=[
                    _rule8a_row(
                        control_id="SC-7",
                        cci_id="CCI-001097",
                        excel_row=5,
                        source="SDA Enterprise Service",
                    ),
                    _na_row(control_id="PE-10", cci_id="CCI-000813", excel_row=6),
                ],
            ),
        )

        # 1) Open: rule-backfill writes SC-7 Compliant (rule_8a) + PE-10 NA (8b).
        backfill_workbook_rules(workbook_id=wb.id, session=session)
        session.commit()
        by_cci = {
            session.get(Objective, a.objective_id).objective_id: a
            for a in session.exec(select(Assessment)).all()
        }
        assert by_cci["CCI-001097"].status is ComplianceStatus.COMPLIANT
        assert by_cci["CCI-001097"].inheritance_rule == "8a"
        assert by_cci["CCI-000813"].status is ComplianceStatus.NOT_APPLICABLE

        # 2) Attach two HYBRID CRMs to SC-7 (and NA CRMs to PE-10).
        for label in ("AWS GovCloud", "Azure Government"):
            crm = Baseline(
                framework_id=fw.id,
                name=f"CRM-{label}",
                source_type=BaselineSourceType.CRM,
                scope_label=label,
            )
            session.add(crm)
            session.commit()
            session.refresh(crm)
            session.add(
                BaselineControl(
                    baseline_id=crm.id,
                    control_id=sc7.id,
                    in_scope=True,
                    responsibility="hybrid",
                    responsibility_narrative=f"{label} shared boundary.",
                )
            )
            session.add(
                BaselineControl(
                    baseline_id=crm.id,
                    control_id=pe10.id,
                    in_scope=True,
                    responsibility="not_applicable",
                    responsibility_narrative=f"{label} N/A.",
                )
            )
            session.add(
                WorkbookOverlay(
                    workbook_id=wb.id,
                    baseline_id=crm.id,
                    attached_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
                )
            )
            session.commit()

        heal = backfill_workbook_crm(workbook_id=wb.id, session=session)
        session.commit()
        # SC-7's stale rule_8a row was deleted (healed); PE-10's 8b survives.
        assert heal.healed_deleted >= 1
        remaining = {
            session.get(Objective, a.objective_id).objective_id: a
            for a in session.exec(select(Assessment)).all()
        }
        assert "CCI-001097" not in remaining, (
            "stale rule_8a Compliant must be healed away on hybrid CRM attach"
        )
        assert remaining["CCI-000813"].status is ComplianceStatus.NOT_APPLICABLE, (
            "PE-10 rule_8b NA must survive the CRM attach (PE-10 guard)"
        )

        # 3) RE-OPEN: rule-backfill must NOT resurrect SC-7's rule_8a Compliant
        # (the control is now CRM-hybrid-covered).
        backfill_workbook_rules(workbook_id=wb.id, session=session)
        session.commit()
        final = {
            session.get(Objective, a.objective_id).objective_id: a
            for a in session.exec(select(Assessment)).all()
        }
        assert "CCI-001097" not in final, (
            "re-open rule-backfill must not resurrect the stale rule_8a Compliant "
            "for a now-hybrid-CRM-covered control"
        )
        assert final["CCI-000813"].status is ComplianceStatus.NOT_APPLICABLE
    finally:
        wb_path.unlink(missing_ok=True)
