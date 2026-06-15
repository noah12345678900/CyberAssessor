"""Tests for ``DELETE /api/workbooks/{workbook_id}``.

The endpoint hand-walks a 24-counter cascade (no SQLite ON DELETE
CASCADE in our schema) split between:

  * **Hard-deleted** rows the workbook owns outright — Assessment +
    children, AssessmentRun, Poam + children, Asset / BoundarySegment
    with their link tables, StigFinding (filtered through a snapshot of
    workbook-owned Evidence ids), WorkbookOverlay, WorkbookSyncEvent.
  * **NULL'd, not deleted** shared artifacts — Evidence and SystemContext
    survive the delete with ``workbook_id`` set to NULL so other
    workbooks can keep referencing them.

The single end-to-end test seeds one representative row of every table
the cascade touches, plus a sibling workbook to prove the delete is
scoped. A second test pins the 404 contract.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.db import get_session  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Assessment,
    AssessmentCitation,
    AssessmentEvidenceShown,
    AssessmentRun,
    AssessmentTrace,
    Asset,
    Baseline,
    BaselineSourceType,
    BoundarySegment,
    ComplianceStatus,
    Control,
    Evidence,
    EvidenceAsset,
    EvidenceBoundary,
    EvidenceKind,
    FindingStatus,
    Framework,
    NarrativeClass,
    Objective,
    Poam,
    PoamEvidence,
    PoamMilestone,
    PoamObjective,
    PromptSnapshot,
    StigFinding,
    SystemContext,
    Workbook,
    WorkbookOverlay,
    WorkbookSyncEvent,
)
from cybersecurity_assessor.server import create_app  # noqa: E402


def _utc() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture
def seeded(tmp_path: Path):
    """TestClient + IDs for the target workbook, a sibling workbook, and
    every shared artifact the cascade is expected to preserve.

    Seeds one representative row in each cascade-touched table so the
    delete's per-table counts are pinned exactly.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    def _override_get_session():
        with Session(engine) as s:
            yield s

    app = create_app()
    app.dependency_overrides[get_session] = _override_get_session

    target_path = tmp_path / "target.xlsx"
    target_path.write_bytes(b"x")
    sibling_path = tmp_path / "sibling.xlsx"
    sibling_path.write_bytes(b"x")
    evidence_path = tmp_path / "policy.pdf"
    evidence_path.write_bytes(b"y")
    sibling_evidence_path = tmp_path / "sibling_policy.pdf"
    sibling_evidence_path.write_bytes(b"z")

    with Session(engine) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5")
        s.add(fw)
        s.commit()
        s.refresh(fw)

        control = Control(framework_id=fw.id, control_id="ac-2", title="AC-2", family="AC")
        s.add(control)
        s.commit()
        s.refresh(control)

        objective = Objective(
            control_id_fk=control.id,
            objective_id="CCI-000015",
            source="CCI",
            text="Account management automation.",
        )
        s.add(objective)
        s.commit()
        s.refresh(objective)

        target_wb = Workbook(
            path=str(target_path), filename=target_path.name, framework_id=fw.id
        )
        sibling_wb = Workbook(
            path=str(sibling_path), filename=sibling_path.name, framework_id=fw.id
        )
        s.add(target_wb)
        s.add(sibling_wb)
        s.commit()
        s.refresh(target_wb)
        s.refresh(sibling_wb)

        # Sibling overlay baseline — proves WorkbookOverlay row gets deleted.
        sibling_baseline = Baseline(
            framework_id=fw.id,
            name="Sibling baseline",
            source_type=BaselineSourceType.CCIS_WORKBOOK,
            source_ref=str(sibling_path),
        )
        s.add(sibling_baseline)
        s.commit()
        s.refresh(sibling_baseline)

        s.add(
            WorkbookOverlay(
                workbook_id=target_wb.id,
                baseline_id=sibling_baseline.id,
                attached_at=_utc(),
            )
        )

        # WorkbookSyncEvent (one for target, one for sibling — only the target's
        # should be deleted).
        s.add(
            WorkbookSyncEvent(
                workbook_id=target_wb.id,
                control_id=control.id,
                event_type="reread",
            )
        )
        s.add(
            WorkbookSyncEvent(
                workbook_id=sibling_wb.id,
                control_id=control.id,
                event_type="reread",
            )
        )

        # Evidence — one for target, one for sibling. Target's gets NULL'd;
        # sibling's stays untouched.
        target_evidence = Evidence(
            path=str(evidence_path),
            sha256="deadbeef" * 8,
            kind=EvidenceKind.PDF,
            size_bytes=1,
            workbook_id=target_wb.id,
        )
        sibling_evidence = Evidence(
            path=str(sibling_evidence_path),
            sha256="cafebabe" * 8,
            kind=EvidenceKind.PDF,
            size_bytes=1,
            workbook_id=sibling_wb.id,
        )
        s.add(target_evidence)
        s.add(sibling_evidence)
        s.commit()
        s.refresh(target_evidence)
        s.refresh(sibling_evidence)

        # StigFinding hangs off Evidence (no workbook_id column) — cascade
        # filters via the workbook's Evidence-id snapshot.
        s.add(
            StigFinding(
                evidence_id=target_evidence.id,
                rule_id="SV-12345r1_rule",
                status=FindingStatus.OPEN,
            )
        )

        # SystemContext — one for target, one for sibling. Target's gets NULL'd.
        target_ctx = SystemContext(
            workbook_id=target_wb.id, description="Target boundary."
        )
        sibling_ctx = SystemContext(
            workbook_id=sibling_wb.id, description="Sibling boundary."
        )
        s.add(target_ctx)
        s.add(sibling_ctx)

        # Assessment + AssessmentRun + trace family.
        run = AssessmentRun(workbook_id=target_wb.id, started_at=_utc())
        s.add(run)

        target_assessment = Assessment(
            workbook_id=target_wb.id,
            objective_id=objective.id,
            excel_row=1,
            status=ComplianceStatus.NON_COMPLIANT,
            tester="test",
            date_tested=_utc(),
            narrative_q="x",
            narrative_class=NarrativeClass.AMBIGUOUS,
        )
        sibling_assessment = Assessment(
            workbook_id=sibling_wb.id,
            objective_id=objective.id,
            excel_row=1,
            status=ComplianceStatus.COMPLIANT,
            tester="test",
            date_tested=_utc(),
            narrative_q="y",
            narrative_class=NarrativeClass.AMBIGUOUS,
        )
        s.add(target_assessment)
        s.add(sibling_assessment)
        s.commit()
        s.refresh(target_assessment)
        s.refresh(sibling_assessment)

        # PromptSnapshot is cross-workbook dedup — must survive the delete.
        prompt = PromptSnapshot(sha256="prompt" + "0" * 58, text="system prompt")
        s.add(prompt)
        s.commit()

        s.add(
            AssessmentTrace(
                assessment_id=target_assessment.id,
                system_prompt_sha=prompt.sha256,
                user_message="user msg",
                model="claude-opus-4-6",
                anthropic_model_version="claude-opus-4-6-20260101",
                temperature=0.0,
                max_tokens=1024,
                request_id="req_abc",
                raw_response_json="{}",
            )
        )
        evidence_shown = AssessmentEvidenceShown(
            assessment_id=target_assessment.id,
            evidence_id=target_evidence.id,
            chunk_sha="chunk_sha_abc",
            chunk_text="snippet",
            order_index=0,
        )
        s.add(evidence_shown)
        s.commit()
        s.refresh(evidence_shown)
        s.add(
            AssessmentCitation(
                assessment_id=target_assessment.id,
                narrative_field="narrative_q",
                claim_text="x",
                evidence_shown_id=evidence_shown.id,
                source_quote="snippet",
            )
        )

        # Poam + children.
        poam = Poam(
            workbook_id=target_wb.id,
            control_cluster="AC-2",
            vulnerability_description="Open finding.",
        )
        s.add(poam)
        s.commit()
        s.refresh(poam)
        s.add(PoamObjective(poam_id=poam.id, objective_id=objective.id))
        s.add(PoamEvidence(poam_id=poam.id, evidence_id=target_evidence.id))
        s.add(PoamMilestone(poam_id=poam.id, description="Patch by EOQ."))

        # Asset + EvidenceAsset link.
        asset = Asset(workbook_id=target_wb.id, hostname="host01")
        s.add(asset)
        s.commit()
        s.refresh(asset)
        s.add(EvidenceAsset(evidence_id=target_evidence.id, asset_id=asset.id))

        # BoundarySegment + EvidenceBoundary link.
        boundary = BoundarySegment(workbook_id=target_wb.id, name="enclave-a")
        s.add(boundary)
        s.commit()
        s.refresh(boundary)
        s.add(
            EvidenceBoundary(
                evidence_id=target_evidence.id, boundary_segment_id=boundary.id
            )
        )

        s.commit()

        target_id = target_wb.id
        sibling_id = sibling_wb.id
        target_evidence_id = target_evidence.id
        sibling_evidence_id = sibling_evidence.id
        prompt_sha = prompt.sha256

    yield (
        TestClient(app),
        target_id,
        sibling_id,
        target_evidence_id,
        sibling_evidence_id,
        prompt_sha,
        engine,
    )

    app.dependency_overrides.clear()


def test_delete_workbook_cascades_and_preserves_shared_artifacts(seeded) -> None:
    tc, target_id, sibling_id, target_evidence_id, sibling_evidence_id, prompt_sha, engine = seeded

    r = tc.delete(f"/api/workbooks/{target_id}")
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["ok"] is True
    assert payload["workbook_id"] == target_id

    cascade = payload["cascade"]
    # Pin the per-table counts of every cascade-touched row. Each table got
    # exactly one row seeded for the target workbook, so the counts double as
    # a contract on which tables the route knows about.
    assert cascade["assessment_traces"] == 1
    assert cascade["assessment_evidence_shown"] == 1
    assert cascade["assessment_citations"] == 1
    assert cascade["assessments"] == 1
    assert cascade["assessment_runs"] == 1
    assert cascade["poam_objectives"] == 1
    assert cascade["poam_evidence_links"] == 1
    assert cascade["poam_milestones"] == 1
    assert cascade["poams"] == 1
    assert cascade["evidence_asset_links"] == 1
    assert cascade["assets"] == 1
    assert cascade["evidence_boundary_links"] == 1
    assert cascade["boundary_segments"] == 1
    assert cascade["stig_findings"] == 1
    assert cascade["overlay_attachments"] == 1
    assert cascade["sync_events"] == 1
    assert cascade["evidence_unlinked"] == 1
    assert cascade["system_contexts_unlinked"] == 1
    # Tables seeded with zero target rows still report 0 — proves the route
    # didn't skip the table entirely.
    assert cascade["sweep_decisions"] == 0
    assert cascade["sweep_runs"] == 0
    assert cascade["crm_suspicion_logs"] == 0
    assert cascade["crm_short_circuit_events"] == 0
    assert cascade["crm_corpus_features"] == 0

    # Post-conditions: open a fresh session against the same engine and
    # verify the actual table state matches the cascade contract.
    with Session(engine) as s:
        # Target workbook is gone.
        assert s.get(Workbook, target_id) is None
        # Sibling workbook untouched.
        assert s.get(Workbook, sibling_id) is not None

        # Every workbook-owned table now has zero rows for the deleted wb.
        for model in (
            Assessment,
            AssessmentRun,
            Poam,
            Asset,
            BoundarySegment,
            WorkbookOverlay,
            WorkbookSyncEvent,
        ):
            remaining = s.exec(
                select(model).where(model.workbook_id == target_id)  # type: ignore[attr-defined]
            ).all()
            assert remaining == [], f"{model.__name__} not cleared for target workbook"

        # Sibling-owned assessment + sync event survive.
        sibling_assessments = s.exec(
            select(Assessment).where(Assessment.workbook_id == sibling_id)
        ).all()
        assert len(sibling_assessments) == 1
        sibling_sync = s.exec(
            select(WorkbookSyncEvent).where(WorkbookSyncEvent.workbook_id == sibling_id)
        ).all()
        assert len(sibling_sync) == 1

        # Shared Evidence survives — target's is NULL'd, sibling's untouched.
        target_evidence = s.get(Evidence, target_evidence_id)
        assert target_evidence is not None
        assert target_evidence.workbook_id is None
        sibling_evidence = s.get(Evidence, sibling_evidence_id)
        assert sibling_evidence is not None
        assert sibling_evidence.workbook_id == sibling_id

        # SystemContext: target's NULL'd, sibling's intact.
        ctx_target = s.exec(
            select(SystemContext).where(SystemContext.workbook_id == None)  # noqa: E711
        ).all()
        assert len(ctx_target) == 1
        ctx_sibling = s.exec(
            select(SystemContext).where(SystemContext.workbook_id == sibling_id)
        ).all()
        assert len(ctx_sibling) == 1

        # StigFinding for the target evidence got deleted.
        stig_remaining = s.exec(
            select(StigFinding).where(StigFinding.evidence_id == target_evidence_id)
        ).all()
        assert stig_remaining == []

        # PromptSnapshot (cross-workbook dedup) must survive. Regression
        # test for the AttributeError bug from when the cascade tried to
        # filter PromptSnapshot by a non-existent assessment_id column.
        assert s.get(PromptSnapshot, prompt_sha) is not None


def test_delete_missing_workbook_returns_404(seeded) -> None:
    tc, *_ = seeded
    r = tc.delete("/api/workbooks/99999")
    assert r.status_code == 404
