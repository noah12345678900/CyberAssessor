"""Tests for grounded remediation defaults on the no-STIG-finding POAM path.

Project grounding rule: when a Non-Compliant cluster has no STIG/scan finding
to source a fix from, the auto-filled remediation milestone must still be
GROUNDED in real inputs — derived from the control's own requirement text —
rather than a content-free placeholder. The scheduled completion date must come
from the severity -> remediation-window policy table (no findings -> cluster
RiskLevel fallback -> Moderate -> 90 days), not a blank or random date.

Covers:
  (a) no-finding NC row gets non-empty grounded remediation derived from the
      control's requirement text (Control.statement, then title, then objective
      text);
  (b) the milestone scheduled date reflects the severity window;
  (c) existing STIG-finding behavior (per-rule milestones) is unchanged.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cybersecurity_assessor.models import (
    ComplianceStatus,
    Control,
    Evidence,
    EvidenceKind,
    EvidenceTag,
    FindingStatus,
    PoamMilestone,
    StigFinding,
)
from cybersecurity_assessor.poam.generator import (
    _SEVERITY_REMEDIATION_DAYS,
    generate_for_workbook,
)
from sqlmodel import select


def _milestones_for(session, poam_id: int) -> list[PoamMilestone]:
    return session.exec(
        select(PoamMilestone).where(PoamMilestone.poam_id == poam_id)
    ).all()


# ---------------------------------------------------------------------------
# (a) No-finding remediation is grounded in the control requirement text
# ---------------------------------------------------------------------------


def test_no_finding_remediation_grounded_in_control_statement(
    session, poam_catalog, assess
) -> None:
    """A NC cluster with no STIG finding gets a lead milestone whose text is
    derived from Control.statement, not the bare placeholder."""
    wb = poam_catalog["workbook"]
    ac2 = poam_catalog["objectives"]["AC-2"]

    # Give the control a real requirement statement to ground against.
    ctrl = session.get(Control, ac2.control_id_fk)
    ctrl.statement = (
        "The organization manages information system accounts, including "
        "establishing, activating, modifying, reviewing, disabling, and "
        "removing accounts."
    )
    session.add(ctrl)
    session.commit()

    assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

    created = generate_for_workbook(wb.id, session).created
    session.commit()
    assert len(created) == 1

    milestones = _milestones_for(session, created[0].id)
    # Exactly one milestone (no findings -> no per-rule milestones).
    assert len(milestones) == 1
    desc = milestones[0].description
    # Grounded: anchored to the control id AND carries requirement substance.
    assert desc, "remediation milestone must not be empty"
    assert "Develop and implement controls satisfying" in desc
    assert "AC-2" in desc
    assert "manages information system accounts" in desc
    # Must NOT be the content-free placeholder.
    assert desc != "Develop and implement remediation plan for AC-2."


def test_no_finding_remediation_falls_back_to_objective_text(
    session, poam_catalog, assess
) -> None:
    """With no Control.statement AND no title, grounding uses Objective.text.

    The fixture seeds Control.title='AC-2 title', so statement wins only when
    set; here we clear both statement and title to exercise the objective-text
    fallback and confirm it is still grounded (not the placeholder).
    """
    wb = poam_catalog["workbook"]
    ac2 = poam_catalog["objectives"]["AC-2"]
    ctrl = session.get(Control, ac2.control_id_fk)
    ctrl.statement = None
    ctrl.title = ""  # force fall-through to objective text
    session.add(ctrl)
    session.commit()

    assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)
    created = generate_for_workbook(wb.id, session).created
    session.commit()

    milestones = _milestones_for(session, created[0].id)
    assert len(milestones) == 1
    desc = milestones[0].description
    # objective text seeded as "objective text for CCI-000015"
    assert "objective text for CCI-000015" in desc
    assert desc != "Develop and implement remediation plan for AC-2."


# ---------------------------------------------------------------------------
# (b) Milestone scheduled date reflects the severity window
# ---------------------------------------------------------------------------


def test_no_finding_milestone_date_uses_moderate_window(
    session, poam_catalog, assess
) -> None:
    """No findings -> RiskLevel fallback (Moderate) -> 90-day window.

    The lead milestone's scheduled_date should be ~90 days out, not blank and
    not the bare 'now'.
    """
    wb = poam_catalog["workbook"]
    ac2 = poam_catalog["objectives"]["AC-2"]
    assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

    before = datetime.now(timezone.utc).replace(tzinfo=None)
    created = generate_for_workbook(wb.id, session).created
    session.commit()

    milestones = _milestones_for(session, created[0].id)
    sched = milestones[0].scheduled_date
    assert sched is not None, "milestone must carry a scheduled date"
    # SQLite round-trips datetimes as offset-naive; drop tzinfo for comparison.
    sched = sched.replace(tzinfo=None)
    expected_days = _SEVERITY_REMEDIATION_DAYS["medium"]
    assert expected_days == 90
    target = before + timedelta(days=expected_days)
    # Allow a small clock-skew window between `before` and date computation.
    assert abs((sched - target).total_seconds()) < 120
    # Also reflected on the POAM scheduled_completion_date.
    assert created[0].scheduled_completion_date is not None


def test_high_severity_finding_shortens_window_to_30_days(
    session, poam_catalog, assess
) -> None:
    """A CAT-I/high STIG finding -> 30-day window (severity table lookup)."""
    wb = poam_catalog["workbook"]
    ac2 = poam_catalog["objectives"]["AC-2"]
    assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

    ev = Evidence(
        path="file:///ckl/high.ckl",
        sha256="sha-high",
        kind=EvidenceKind.STIG_CKL,
        size_bytes=1,
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    session.add(
        EvidenceTag(
            evidence_id=ev.id,
            objective_id=ac2.id,
            relevance=1.0,
            confidence=0.9,
            source="manual",
        )
    )
    session.add(
        StigFinding(
            evidence_id=ev.id,
            rule_id="SV-HIGH",
            cci_refs="CCI-000015",
            severity="high",
            status=FindingStatus.OPEN,
            finding_details="Critical setting not enforced.",
        )
    )
    session.commit()

    before = datetime.now(timezone.utc).replace(tzinfo=None)
    created = generate_for_workbook(wb.id, session).created
    session.commit()

    target = before + timedelta(days=_SEVERITY_REMEDIATION_DAYS["high"])
    assert _SEVERITY_REMEDIATION_DAYS["high"] == 30
    sched = created[0].scheduled_completion_date
    assert sched is not None
    # SQLite round-trips datetimes as offset-naive; drop tzinfo for comparison.
    assert abs((sched.replace(tzinfo=None) - target).total_seconds()) < 120


# ---------------------------------------------------------------------------
# (c) Existing STIG-finding behavior unchanged
# ---------------------------------------------------------------------------


def test_finding_path_still_emits_per_rule_milestones(
    session, poam_catalog, assess
) -> None:
    """With a STIG finding present, the per-rule milestone is still emitted in
    addition to the lead milestone (the grounding change must not regress this).
    """
    wb = poam_catalog["workbook"]
    ac2 = poam_catalog["objectives"]["AC-2"]
    # Statement set so the lead milestone is grounded too — proves the lead is
    # grounded AND the per-rule milestone coexists.
    ctrl = session.get(Control, ac2.control_id_fk)
    ctrl.statement = "Manage accounts: establish, review, disable, remove."
    session.add(ctrl)
    session.commit()

    assess(wb.id, ac2.id, ComplianceStatus.NON_COMPLIANT)

    ev = Evidence(
        path="file:///ckl/rule.ckl",
        sha256="sha-rule",
        kind=EvidenceKind.STIG_CKL,
        size_bytes=1,
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    session.add(
        EvidenceTag(
            evidence_id=ev.id,
            objective_id=ac2.id,
            relevance=1.0,
            confidence=0.9,
            source="manual",
        )
    )
    session.add(
        StigFinding(
            evidence_id=ev.id,
            rule_id="SV-RULE-1",
            cci_refs="CCI-000015",
            severity="medium",
            status=FindingStatus.OPEN,
            finding_details="Account review interval not enforced.",
        )
    )
    session.commit()

    created = generate_for_workbook(wb.id, session).created
    session.commit()

    milestones = _milestones_for(session, created[0].id)
    descs = [m.description for m in milestones]
    # Lead grounded milestone + one per-rule milestone.
    assert len(milestones) == 2
    assert any("Develop and implement controls satisfying" in d for d in descs)
    assert any("Remediate SV-RULE-1:" in d for d in descs)
