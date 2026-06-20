"""Regression: purge_baseline_contribution removes a CRM baseline's
contribution and recomputes affected parents — WITHOUT deleting legitimate work.

THE BUG (user-found). Detaching a CRM overlay (or deleting a CRM baseline) left
orphan CRM telemetry + AssessmentImplementation slices and never recomputed the
parent rollup. A control that was Compliant ONLY via that CRM's inheritance
stayed falsely Compliant, and the stale parent kept the batch preflight skipping
it as "already assessed."

``purge_baseline_contribution`` (engine/crm_backfill.py) is the shared cleanup
used by both detach_workbook_overlay (workbook-scoped) and delete_baseline
(all-workbooks). These tests pin its SAFETY INVARIANT — the
zero-regression bar the owner set ("the app is near-final"):

  * A CRM-only parent (verdict_source CRM_*, tester "system") with NO surviving
    slices is DELETED (the control reverts to unassessed).
  * A parent with surviving slices is RECOMPUTED worst-of, never deleted.
  * A human-edited parent (tester != "system") and a RULE_8B col-N NA parent are
    NEVER deleted — only their CRM-sourced child slice is removed.
  * The CRM telemetry (CrmSuspicionLog / CrmCorpusFeatures / CrmShortCircuitEvent)
    for the baseline is removed.

Collected via testpaths=["../tests"].
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import event
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from cybersecurity_assessor import models  # noqa: F401 -- register tables
from cybersecurity_assessor.engine.crm_backfill import purge_baseline_contribution
from cybersecurity_assessor.models import (
    Assessment,
    AssessmentCitation,
    AssessmentEvidenceShown,
    AssessmentImplementation,
    AssessmentTrace,
    Baseline,
    BaselineSourceType,
    ComplianceStatus,
    Control,
    CrmCorpusFeatures,
    CrmShortCircuitEvent,
    CrmSuspicionLog,
    Evidence,
    EvidenceKind,
    Framework,
    NarrativeClass,
    Objective,
    PromptSnapshot,
    VerdictSource,
    Workbook,
)


def _utc() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def session() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _rec):  # pragma: no cover - trivial
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _base(session: Session):
    """Framework + workbook + primary baseline + one CRM baseline. Returns
    (fw, wb, crm_baseline)."""
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)
    primary = Baseline(
        framework_id=fw.id, name="primary", source_type=BaselineSourceType.CCIS_WORKBOOK
    )
    session.add(primary)
    session.commit()
    session.refresh(primary)
    wb = Workbook(path="x.xlsx", filename="x.xlsx", baseline_id=primary.id)
    session.add(wb)
    session.commit()
    session.refresh(wb)
    crm = Baseline(
        framework_id=fw.id,
        name="CRM-AWS",
        source_type=BaselineSourceType.CRM,
        scope_label="AWS GovCloud",
    )
    session.add(crm)
    session.commit()
    session.refresh(crm)
    return fw, wb, crm


def _objective(session: Session, fw: Framework, control_id: str, cci: str) -> Objective:
    c = Control(framework_id=fw.id, control_id=control_id, title=control_id, family=control_id[:2].upper())
    session.add(c)
    session.commit()
    session.refresh(c)
    o = Objective(control_id_fk=c.id, objective_id=cci, source="CCI", text="t")
    session.add(o)
    session.commit()
    session.refresh(o)
    return o


def _assessment(
    session: Session,
    wb: Workbook,
    obj: Objective,
    *,
    status: ComplianceStatus,
    verdict_source: VerdictSource,
    tester: str = "system",
) -> Assessment:
    a = Assessment(
        workbook_id=wb.id,
        objective_id=obj.id,
        excel_row=1,
        status=status,
        tester=tester,
        date_tested=_utc(),
        narrative_q="x",
        narrative_class=NarrativeClass.COMPLIANCE_AFFIRMING,
        verdict_source=verdict_source,
    )
    session.add(a)
    session.commit()
    session.refresh(a)
    return a


def _impl(session, a, scope, status, baseline_id):
    im = AssessmentImplementation(
        assessment_id=a.id,
        scope_label=scope,
        source_baseline_id=baseline_id,
        responsibility="inherited",
        status=status,
        narrative=f"{scope} narrative",
    )
    session.add(im)
    session.commit()
    return im


def _telemetry(session, wb, crm, obj):
    sl = CrmSuspicionLog(
        workbook_id=wb.id, crm_baseline_id=crm.id, heuristic_score=0.2,
        overall_suspicion=0.2, flags_json="[]", per_family_json="{}",
    )
    session.add(sl)
    session.commit()
    session.refresh(sl)
    session.add(CrmShortCircuitEvent(
        workbook_id=wb.id, control_id_fk=obj.control_id_fk,
        responsibility="inherited", suspicion_log_id=sl.id,
    ))
    session.add(CrmCorpusFeatures(
        workbook_id=wb.id, crm_baseline_id=crm.id,
        feature_schema_version=1, features_json="{}",
    ))
    session.commit()


def test_crm_only_parent_deleted_and_telemetry_purged(session):
    """A CRM-derived parent whose only slice is from the detached CRM is deleted
    (reverts to unassessed); telemetry gone."""
    fw, wb, crm = _base(session)
    obj = _objective(session, fw, "ac-2", "CCI-000015")
    a = _assessment(
        session, wb, obj,
        status=ComplianceStatus.COMPLIANT,
        verdict_source=VerdictSource.CRM_INHERITED,
    )
    _impl(session, a, "AWS GovCloud", ComplianceStatus.COMPLIANT, crm.id)
    _telemetry(session, wb, crm, obj)

    # Seed the parent's three 1:N children (trace / evidence-shown / citation).
    # Under PRAGMA foreign_keys=ON, deleting the parent without first clearing
    # these raises a FK constraint failure → 500. This makes the test exercise
    # the FK-safe child sweep in purge_baseline_contribution (Risk #1 from the
    # diff audit). The citation FKs to evidence-shown, so order matters.
    ev = Evidence(
        path="p.pdf", sha256="d" * 64, kind=EvidenceKind.PDF, size_bytes=1,
        workbook_id=wb.id,
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    prompt = PromptSnapshot(sha256="p" + "0" * 63, text="sys")
    session.add(prompt)
    session.commit()
    session.add(AssessmentTrace(
        assessment_id=a.id, system_prompt_sha=prompt.sha256, user_message="u",
        model="m", anthropic_model_version="m-1", temperature=0.0, max_tokens=8,
        request_id="r", raw_response_json="{}",
    ))
    es = AssessmentEvidenceShown(
        assessment_id=a.id, evidence_id=ev.id, chunk_sha="c", chunk_text="s",
        order_index=0,
    )
    session.add(es)
    session.commit()
    session.refresh(es)
    session.add(AssessmentCitation(
        assessment_id=a.id, narrative_field="narrative_q", claim_text="x",
        evidence_shown_id=es.id, source_quote="s",
    ))
    session.commit()

    res = purge_baseline_contribution(session, baseline_id=crm.id, workbook_id=wb.id)
    session.commit()  # would FK-500 here without the child sweep

    assert res.parents_deleted == 1
    assert session.get(Assessment, a.id) is None  # reverted to unassessed
    assert session.exec(select(AssessmentImplementation)).all() == []
    assert session.exec(select(CrmSuspicionLog)).all() == []
    assert session.exec(select(CrmShortCircuitEvent)).all() == []
    assert session.exec(select(CrmCorpusFeatures)).all() == []
    # The parent's children were swept too (no orphans / no FK violation).
    assert session.exec(select(AssessmentTrace)).all() == []
    assert session.exec(select(AssessmentCitation)).all() == []
    assert session.exec(select(AssessmentEvidenceShown)).all() == []


def test_human_edited_parent_preserved(session):
    """A human-edited parent (tester != system) is NEVER deleted, even when its
    only slice came from the detached CRM — only the slice is removed."""
    fw, wb, crm = _base(session)
    obj = _objective(session, fw, "ac-2", "CCI-000015")
    a = _assessment(
        session, wb, obj,
        status=ComplianceStatus.COMPLIANT,
        verdict_source=VerdictSource.CRM_INHERITED,
        tester="Noah Jaskolski",  # human edit
    )
    _impl(session, a, "AWS GovCloud", ComplianceStatus.COMPLIANT, crm.id)

    res = purge_baseline_contribution(session, baseline_id=crm.id, workbook_id=wb.id)
    session.commit()

    assert res.parents_deleted == 0
    assert session.get(Assessment, a.id) is not None  # human work preserved
    assert session.exec(select(AssessmentImplementation)).all() == []


def test_rule_8b_parent_preserved(session):
    """A RULE_8B (col-N Not Applicable) parent is NEVER deleted by a CRM purge —
    it's a workbook scope-exclusion attestation, not CRM-derived."""
    fw, wb, crm = _base(session)
    obj = _objective(session, fw, "pe-10", "CCI-000813")
    a = _assessment(
        session, wb, obj,
        status=ComplianceStatus.NOT_APPLICABLE,
        verdict_source=VerdictSource.RULE_8B,
    )
    # A CRM slice was attached to it; purge removes the slice, keeps the parent.
    _impl(session, a, "AWS GovCloud", ComplianceStatus.NOT_APPLICABLE, crm.id)

    res = purge_baseline_contribution(session, baseline_id=crm.id, workbook_id=wb.id)
    session.commit()

    assert res.parents_deleted == 0
    parent = session.get(Assessment, a.id)
    assert parent is not None
    assert parent.status is ComplianceStatus.NOT_APPLICABLE


def test_mixed_parent_recomputed_not_deleted(session):
    """A parent with a surviving non-CRM slice is recomputed worst-of, not
    deleted. CRM slice was Compliant; surviving on-prem slice is Non-Compliant
    → parent rolls up Non-Compliant."""
    fw, wb, crm = _base(session)
    obj = _objective(session, fw, "sc-13", "CCI-002450")
    a = _assessment(
        session, wb, obj,
        status=ComplianceStatus.COMPLIANT,
        verdict_source=VerdictSource.CRM_INHERITED,
    )
    _impl(session, a, "AWS GovCloud", ComplianceStatus.COMPLIANT, crm.id)
    # A surviving flex/on-prem slice with no source_baseline_id (synthesized).
    _impl(session, a, "On-Premises", ComplianceStatus.NON_COMPLIANT, None)

    res = purge_baseline_contribution(session, baseline_id=crm.id, workbook_id=wb.id)
    session.commit()

    assert res.parents_deleted == 0
    assert res.parents_recomputed == 1
    parent = session.get(Assessment, a.id)
    assert parent is not None
    # Only the surviving On-Premises NC slice remains → worst-of = Non-Compliant.
    assert parent.status is ComplianceStatus.NON_COMPLIANT
    survivors = session.exec(select(AssessmentImplementation)).all()
    assert {s.scope_label for s in survivors} == {"On-Premises"}
