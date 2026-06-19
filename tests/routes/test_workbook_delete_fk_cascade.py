"""Regression: DELETE /api/workbooks/{id} must satisfy EVERY foreign key.

THE BUG (user-found, two layers). Deleting a workbook in the UI 500'd. Under
``PRAGMA foreign_keys=ON`` (db.py — production) the hand-walked cascade in
delete_workbook failed for two reasons:

  1. WRONG ORDER — it deleted AssessmentEvidenceShown BEFORE AssessmentCitation,
     but AssessmentCitation.evidence_shown_id is a NOT-NULL FK to
     assessmentevidenceshown.id. Same class of bug deleting CrmSuspicionLog
     before its CrmShortCircuitEvent children.
  2. OMITTED CHILDREN — six child tables with NOT-NULL FKs into rows the cascade
     deletes were never cleared: CalibrationEntry (→AssessmentRun),
     PoamRiskHistory + ResidualSuggestionCache (→Poam), SweepHit (→SweepRun),
     ComponentAsset + EvidenceComponent (→Component/Asset).

Either makes ``s.delete(wb)`` raise a FOREIGN KEY constraint failure → HTTP 500
→ the UI delete silently failed and the workbook stayed.

WHY THE OLD TEST MISSED IT (backend/tests/routes/test_workbook_delete.py): it
(a) built its engine WITHOUT foreign-key enforcement, so no FK ever raised, and
(b) seeded none of the child chains above. This test fixes both: FK enforcement
ON (matching production) AND one row seeded in every child chain, so any
ordering/omission regression makes the delete 500 and fails here.

Collected via testpaths=["../tests"].
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import event
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select

from cybersecurity_assessor import models  # noqa: F401 -- register tables
from cybersecurity_assessor.db import get_session
from cybersecurity_assessor.models import (
    Assessment,
    AssessmentCitation,
    AssessmentEvidenceShown,
    AssessmentRun,
    AssessmentTrace,
    Asset,
    AutomationSchedule,
    Baseline,
    BaselineSourceType,
    BoundarySegment,
    CalibrationEntry,
    ComplianceStatus,
    Component,
    ComponentAsset,
    Control,
    CrmCorpusFeatures,
    CrmShortCircuitEvent,
    CrmSuspicionLog,
    Evidence,
    EvidenceAsset,
    EvidenceBoundary,
    EvidenceComponent,
    EvidenceKind,
    EvidenceRetentionEvent,
    FindingStatus,
    Framework,
    NarrativeClass,
    Objective,
    OverrideEpoch,
    Poam,
    PoamEvidence,
    PoamMilestone,
    PoamObjective,
    PoamRiskHistory,
    PromptSnapshot,
    ResidualSuggestionCache,
    StigFinding,
    SweepHit,
    SweepRun,
    SweepWeights,
    SystemContext,
    Workbook,
    WorkbookOverlay,
    WorkbookSyncEvent,
)
from cybersecurity_assessor.server import create_app


def _utc() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def client_and_id(tmp_path: Path):
    """TestClient with FK enforcement ON and a workbook seeded with one row in
    EVERY child chain the cascade must satisfy (the deep FK families)."""
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

    def _override_get_session():
        with Session(engine) as s:
            yield s

    app = create_app()
    app.dependency_overrides[get_session] = _override_get_session

    wb_path = tmp_path / "target.xlsx"
    wb_path.write_bytes(b"x")
    ev_path = tmp_path / "policy.pdf"
    ev_path.write_bytes(b"y")

    with Session(engine) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5")
        s.add(fw)
        s.commit()
        s.refresh(fw)

        ctrl = Control(framework_id=fw.id, control_id="ac-2", title="AC-2", family="AC")
        s.add(ctrl)
        s.commit()
        s.refresh(ctrl)

        obj = Objective(
            control_id_fk=ctrl.id, objective_id="CCI-000015", source="CCI", text="t"
        )
        s.add(obj)
        s.commit()
        s.refresh(obj)

        wb = Workbook(path=str(wb_path), filename=wb_path.name, framework_id=fw.id)
        s.add(wb)
        s.commit()
        s.refresh(wb)

        crm_baseline = Baseline(
            framework_id=fw.id,
            name="CRM",
            source_type=BaselineSourceType.CRM,
            scope_label="AWS GovCloud",
        )
        s.add(crm_baseline)
        s.commit()
        s.refresh(crm_baseline)
        s.add(
            WorkbookOverlay(
                workbook_id=wb.id, baseline_id=crm_baseline.id, attached_at=_utc()
            )
        )

        ev = Evidence(
            path=str(ev_path),
            sha256="d" * 64,
            kind=EvidenceKind.PDF,
            size_bytes=1,
            workbook_id=wb.id,
        )
        s.add(ev)
        s.commit()
        s.refresh(ev)
        s.add(StigFinding(evidence_id=ev.id, rule_id="SV-1_rule", status=FindingStatus.OPEN))

        # --- Assessment chain: Assessment → EvidenceShown → Citation ----------
        run = AssessmentRun(workbook_id=wb.id, started_at=_utc())
        s.add(run)
        s.commit()
        s.refresh(run)
        # CalibrationEntry → AssessmentRun (NOT-NULL) — the omitted child.
        s.add(
            CalibrationEntry(
                run_id=run.id,
                cci_id="CCI-000015",
                fingerprint="fp1",
                stated_confidence=0.9,
                proposed_status="Compliant",
                final_status="Compliant",
            )
        )

        a = Assessment(
            workbook_id=wb.id,
            objective_id=obj.id,
            excel_row=1,
            status=ComplianceStatus.COMPLIANT,
            tester="t",
            date_tested=_utc(),
            narrative_q="x",
            narrative_class=NarrativeClass.COMPLIANCE_AFFIRMING,
        )
        s.add(a)
        s.commit()
        s.refresh(a)

        prompt = PromptSnapshot(sha256="p" + "0" * 63, text="sys")
        s.add(prompt)
        s.commit()
        s.add(
            AssessmentTrace(
                assessment_id=a.id,
                system_prompt_sha=prompt.sha256,
                user_message="u",
                model="claude-opus-4-6",
                anthropic_model_version="claude-opus-4-6-20260101",
                temperature=0.0,
                max_tokens=1024,
                request_id="req",
                raw_response_json="{}",
            )
        )
        es = AssessmentEvidenceShown(
            assessment_id=a.id,
            evidence_id=ev.id,
            chunk_sha="c",
            chunk_text="s",
            order_index=0,
        )
        s.add(es)
        s.commit()
        s.refresh(es)
        # Citation → EvidenceShown (NOT-NULL) — the ordering-bug trigger.
        s.add(
            AssessmentCitation(
                assessment_id=a.id,
                narrative_field="narrative_q",
                claim_text="x",
                evidence_shown_id=es.id,
                source_quote="s",
            )
        )

        # --- POAM chain: Poam → {Objective, Evidence, Milestone, RiskHistory,
        #     ResidualSuggestionCache} -----------------------------------------
        poam = Poam(workbook_id=wb.id, control_cluster="AC-2", vulnerability_description="v")
        s.add(poam)
        s.commit()
        s.refresh(poam)
        s.add(PoamObjective(poam_id=poam.id, objective_id=obj.id))
        s.add(PoamEvidence(poam_id=poam.id, evidence_id=ev.id))
        s.add(PoamMilestone(poam_id=poam.id, description="m"))
        s.add(PoamRiskHistory(poam_id=poam.id, field="likelihood", new_value="High"))
        s.add(
            ResidualSuggestionCache(
                fingerprint="rfp1",
                advisor_version="v1",
                prompt_sha="psha",
                poam_id=poam.id,
                payload_json="{}",
            )
        )

        # --- Sweep chain: SweepRun → SweepHit ---------------------------------
        # SweepRun.weights_version_id is a NOT-NULL FK to SweepWeights (a
        # global, non-workbook-owned table the cascade correctly leaves alone).
        weights = SweepWeights(
            source="manual",
            weight_host=0.2,
            weight_control_id=0.2,
            weight_family=0.2,
            weight_crm_keyword=0.2,
            weight_doc_prefix=0.2,
        )
        s.add(weights)
        s.commit()
        s.refresh(weights)
        sr = SweepRun(
            workbook_id=wb.id,
            weights_version_id=weights.id,
            started_at=_utc(),
            finished_at=_utc(),
            fingerprint_snapshot_json="{}",
        )
        s.add(sr)
        s.commit()
        s.refresh(sr)
        s.add(
            SweepHit(
                sweep_run_id=sr.id,
                candidate_key="k",
                matched_token="t",
                matched_signal="s",
                score_contribution=0.5,
            )
        )

        # --- CRM telemetry: CrmSuspicionLog → CrmShortCircuitEvent ------------
        susp = CrmSuspicionLog(
            workbook_id=wb.id,
            crm_baseline_id=crm_baseline.id,
            heuristic_score=0.2,
            overall_suspicion=0.2,
            flags_json="[]",
            per_family_json="{}",
        )
        s.add(susp)
        s.commit()
        s.refresh(susp)
        s.add(
            CrmShortCircuitEvent(
                workbook_id=wb.id,
                control_id_fk=ctrl.id,
                responsibility="inherited",
                suspicion_log_id=susp.id,
            )
        )
        s.add(
            CrmCorpusFeatures(
                workbook_id=wb.id,
                crm_baseline_id=crm_baseline.id,
                feature_schema_version=1,
                features_json="{}",
            )
        )

        # --- Component / Asset chain: links into Component AND Asset ----------
        asset = Asset(workbook_id=wb.id, hostname="host01")
        s.add(asset)
        s.commit()
        s.refresh(asset)
        comp = Component(workbook_id=wb.id, name="web-tier")
        s.add(comp)
        s.commit()
        s.refresh(comp)
        s.add(EvidenceAsset(evidence_id=ev.id, asset_id=asset.id))
        s.add(ComponentAsset(component_id=comp.id, asset_id=asset.id))
        s.add(EvidenceComponent(evidence_id=ev.id, component_id=comp.id))

        # --- Boundary + the four standalone NOT-NULL-FK tables ----------------
        boundary = BoundarySegment(workbook_id=wb.id, name="enclave-a")
        s.add(boundary)
        s.commit()
        s.refresh(boundary)
        s.add(EvidenceBoundary(evidence_id=ev.id, boundary_segment_id=boundary.id))

        s.add(OverrideEpoch(workbook_id=wb.id, objective_id=obj.id, epoch=1))
        s.add(
            EvidenceRetentionEvent(
                workbook_id=wb.id, evicted_evidence_id=999, reason="cap_exceeded"
            )
        )
        s.add(AutomationSchedule(workbook_id=wb.id, source_type="local"))
        s.add(WorkbookSyncEvent(workbook_id=wb.id, control_id=ctrl.id, event_type="reread"))
        s.add(SystemContext(workbook_id=wb.id, description="boundary"))
        s.commit()

        wb_id = wb.id

    yield TestClient(app), wb_id, engine
    app.dependency_overrides.clear()


def test_delete_workbook_satisfies_all_foreign_keys(client_and_id):
    """A workbook seeded with every deep child chain deletes cleanly under FK
    enforcement (no 500), and every owned table is cleared.
    """
    tc, wb_id, engine = client_and_id

    r = tc.delete(f"/api/workbooks/{wb_id}")
    assert r.status_code == 200, (
        f"delete must satisfy every FK; got {r.status_code}: {r.text}"
    )
    cascade = r.json()["cascade"]
    # The previously-buggy chains all report 1 now.
    assert cascade["assessment_citations"] == 1
    assert cascade["calibration_entries"] == 1
    assert cascade["poam_risk_history"] == 1
    assert cascade["residual_suggestion_cache"] == 1
    assert cascade["sweep_hits"] == 1
    assert cascade["component_asset_links"] >= 1
    assert cascade["evidence_component_links"] == 1
    assert cascade["crm_short_circuit_events"] == 1
    assert cascade["components"] == 1

    with Session(engine) as s:
        assert s.get(Workbook, wb_id) is None
        # Spot-check that the deep children are gone.
        for model in (
            AssessmentCitation,
            CalibrationEntry,
            PoamRiskHistory,
            ResidualSuggestionCache,
            SweepHit,
            ComponentAsset,
            EvidenceComponent,
            CrmShortCircuitEvent,
        ):
            assert s.exec(select(model)).all() == [], f"{model.__name__} not cleared"
