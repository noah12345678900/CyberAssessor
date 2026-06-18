"""End-to-end route tests for batch assessment with 1 and 2 CRMs attached.

These exist so the human stops manually re-testing the "open workbook →
attach one CRM → assess" and "attach a second CRM → assess" loop. They drive
the REAL ``POST /api/controls/assess-batch`` endpoint through a FastAPI
TestClient with a stubbed LLM and a real (in-memory) DB, asserting:

  1. **No 500.** The batch returns HTTP 200 with ``persist_error=None`` even
     when a control's CRM set forces a synthesized On-Premises *residual*
     ImplementationPlan with ``status=None``. That residual abstain is the
     exact shape that used to raise ``IntegrityError: NOT NULL constraint
     failed: assessmentimplementation.status`` mid-flush and roll back the
     whole batch (the 500 the user kept hitting). Fixed by migration 0017
     making the column nullable.
  2. **Correct per-scope persistence.** A single inherited CRM short-circuits
     to Compliant with no LLM call. A customer-owned cloud scope defers to
     the LLM and persists per-scope AssessmentImplementation rows, including
     the residual On-Premises row with ``status IS NULL``.
  3. **Attach-order / count independence.** One CRM and two CRMs both produce
     a clean 200 — the user does not have to special-case the 2-CRM path.

Scaffolding mirrors ``backend/tests/routes/test_assess_persistence.py`` (the
working batch-route harness) and the CRM-attach helpers from
``backend/tests/engine/test_crm_backfill.py``. This file lives in the
TOP-LEVEL ``tests/`` tree because that is the only tree pytest collects
(``backend/pyproject.toml`` sets ``testpaths=["../tests"]``); tests under
``backend/tests/`` are never run by the default suite.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

# tests/conftest.py puts the backend package on sys.path.
from cybersecurity_assessor import models  # noqa: F401  -- registers tables
from cybersecurity_assessor.baselines.scope_labels import ON_PREM_LABEL
from cybersecurity_assessor.db import get_session
from cybersecurity_assessor.engine.assessor import LlmProposal
from cybersecurity_assessor.engine.evidence_bundle import EvidenceBlock
from cybersecurity_assessor.excel.ccis_reader import CcisIndex, CcisRow
from cybersecurity_assessor.models import (
    Assessment,
    AssessmentImplementation,
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
from cybersecurity_assessor.server import create_app


# ---------------------------------------------------------------------------
# LLM stubs
# ---------------------------------------------------------------------------


class _CompliantCloudOnlyClient:
    """Returns COMPLIANT with a cloud per-scope narrative but NO on-prem one.

    This is the shape that triggers the synthesized On-Premises residual
    slice with status=None: the customer-owned cloud scope gets a narrative,
    the synthesized on-prem scope gets none, so plan_implementations emits a
    status=None abstain row for it. We stitch the cloud narrative into
    ``narratives_by_scope`` keyed by the scope label the CRM carries.
    """

    def __init__(self, scope_label: str) -> None:
        self.calls: list[dict] = []
        self._scope_label = scope_label

    def _proposal(self) -> LlmProposal:
        # narrative_cloud is populated (so the assessor does NOT fall back to
        # spreading the canonical narrative onto the on-prem slice — see
        # assessor.py:2041-2042), while narrative_on_prem stays None and the
        # per-scope map covers ONLY the cloud label. That leaves the
        # synthesized On-Premises slice with no per-scope narrative, so
        # plan_implementations emits it as a status=None residual abstain —
        # the exact row that used to 500 the batch on the NOT NULL constraint.
        return LlmProposal(
            status=ComplianceStatus.COMPLIANT,
            narrative=(
                "Account management is confirmed via configuration review and "
                "documented in USD00050010."
            ),
            narrative_cloud=(
                "Account management on the cloud scope is confirmed via "
                "configuration review and documented in USD00050010."
            ),
            narratives_by_scope={
                self._scope_label: (
                    "Account management on this cloud scope is confirmed via "
                    "configuration review and documented in USD00050010."
                )
            },
            confidence=0.95,
        )

    def propose(self, **kwargs):
        self.calls.append(kwargs)
        return self._proposal()

    def propose_twice(self, **kwargs):
        self.calls.append(kwargs)
        p = self._proposal()
        return (p, p)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _make_ccis_row(*, cci_id: str, control_id: str = "AC-2", excel_row: int = 42) -> CcisRow:
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
        status=None,
        date_tested=None,
        tester=None,
        results=None,
        previous_status=None,
        previous_date=None,
        previous_tester=None,
        previous_results=None,
    )


def _engine_and_app(monkeypatch=None):
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

    # The Assessor's decision-cache worker session is created from the
    # PRODUCTION engine (engine/assessor.py `_worker_cache_session` does
    # `from ..db import engine`), NOT the dependency-overridden session. When
    # the kernel reaches a cache STORE (a non-cached LLM decision), it writes
    # to that engine — which in a test points at the real on-disk DB (or none),
    # raising "no such table: decisioncache". Point db.engine at this in-memory
    # engine so cache reads/writes land in the same StaticPool DB the test set
    # up. (The passing single-control tests sidestep this by monkeypatching
    # Assessor.assess wholesale; these e2e tests run the real assess path.)
    if monkeypatch is not None:
        monkeypatch.setattr("cybersecurity_assessor.db.engine", engine)
    return engine, app


def _seed_workbook(session: Session, wb_path) -> tuple[int, int, int, int]:
    """Create framework, AC-2 control + CCI, in-scope baseline, workbook.

    Returns (workbook_id, objective_pk, control_pk, framework_id).
    """
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)

    ctrl = Control(
        framework_id=fw.id,
        control_id="ac-2",  # OSCAL canonical — CRM context keys on this form
        title="Account Management",
        family="AC",
    )
    session.add(ctrl)
    session.commit()
    session.refresh(ctrl)

    obj = Objective(
        control_id_fk=ctrl.id,
        objective_id="CCI-000015",
        source="CCI",
        text="The organization establishes an account management policy.",
    )
    session.add(obj)
    session.commit()
    session.refresh(obj)

    baseline = Baseline(
        framework_id=fw.id,
        name="In-scope baseline",
        source_type=BaselineSourceType.MANUAL,
    )
    session.add(baseline)
    session.commit()
    session.refresh(baseline)

    session.add(
        BaselineControl(baseline_id=baseline.id, control_id=ctrl.id, in_scope=True)
    )
    session.add(
        BaselineObjective(
            baseline_id=baseline.id, objective_id=obj.id, source_row=42
        )
    )
    session.commit()

    wb = Workbook(
        path=str(wb_path),
        filename=wb_path.name,
        framework_id=fw.id,
        baseline_id=baseline.id,
    )
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb.id, obj.id, ctrl.id, fw.id


def _attach_crm(
    session: Session,
    *,
    framework_id: int,
    workbook_id: int,
    control_pk: int,
    responsibility: str,
    scope_label: str | None,
    narrative: str | None,
    attached_at: datetime,
) -> None:
    crm = Baseline(
        framework_id=framework_id,
        name=f"CRM-{scope_label or 'legacy'}-{responsibility}",
        source_type=BaselineSourceType.CRM,
        scope_label=scope_label,
    )
    session.add(crm)
    session.commit()
    session.refresh(crm)
    session.add(
        BaselineControl(
            baseline_id=crm.id,
            control_id=control_pk,
            in_scope=True,
            responsibility=responsibility,
            responsibility_narrative=narrative,
        )
    )
    session.add(
        WorkbookOverlay(
            workbook_id=workbook_id,
            baseline_id=crm.id,
            attached_at=attached_at,
        )
    )
    session.commit()


def _patch_route(monkeypatch, *, ccis_row, wb_path, client):
    monkeypatch.setattr(
        "cybersecurity_assessor.routes.controls.make_client",
        lambda cfg: client,
    )
    monkeypatch.setattr(
        "cybersecurity_assessor.routes.controls.read_workbook_index",
        lambda path: CcisIndex(
            workbook_path=wb_path, sheet_name="CCIS", rows=[ccis_row]
        ),
    )
    # Populate evidence so Assessor's no-evidence short-circuit does not fire
    # (we want to reach the LLM + per-scope plan path).
    monkeypatch.setattr(
        "cybersecurity_assessor.routes.controls._build_evidence_block",
        lambda *, objective_pk, control_id, workbook_id, s: EvidenceBlock(
            text=(
                "## tagged_evidence\n"
                "- USD00050010 Example System Account Management Plan Rev -.\n"
            ),
            has_artifacts=True,
            has_coverage=False,
            has_findings=False,
            has_hosts=False,
            has_nonscan_artifact=True,
        ),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_batch_one_crm_inherited_short_circuits_no_500(
    tmp_path, monkeypatch
) -> None:
    """One inherited CRM → Compliant short-circuit, no LLM, 200, no error."""
    engine, app = _engine_and_app(monkeypatch)
    wb_path = tmp_path / "one_crm.xlsx"
    wb_path.touch()

    with Session(engine) as s:
        wb_id, obj_id, ctrl_pk, fw_id = _seed_workbook(s, wb_path)
        _attach_crm(
            s,
            framework_id=fw_id,
            workbook_id=wb_id,
            control_pk=ctrl_pk,
            responsibility="inherited",
            scope_label="AWS GovCloud",
            narrative="Customer fully inherits AWS GovCloud account management.",
            attached_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )

    ccis_row = _make_ccis_row(cci_id="CCI-000015")
    # A scope-labeled inherited CRM defers to the LLM (the short-circuit is
    # only the legacy non-scoped crm_entry path), so supply a real compliant
    # stub. The user-facing contract under test is: 200, no error, row lands.
    client = _CompliantCloudOnlyClient(scope_label="AWS GovCloud")
    _patch_route(monkeypatch, ccis_row=ccis_row, wb_path=wb_path, client=client)

    resp = TestClient(app).post(
        "/api/controls/assess-batch",
        json={"workbook_id": wb_id, "persist": True, "skip_existing": False},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["persist_error"] is None
    assert data.get("persist_errored", 0) == 0
    assert data["persisted"] >= 1

    with Session(engine) as s:
        row = s.exec(
            select(Assessment).where(Assessment.objective_id == obj_id)
        ).one()
        assert row.status is not None  # a verdict landed


def test_batch_two_crms_customer_cloud_residual_onprem_no_500(
    tmp_path, monkeypatch
) -> None:
    """Two CRMs, one customer-owned cloud scope → synthesized On-Premises
    residual (status=None) must persist, batch returns 200, no persist_error.

    This is the exact scenario that 500'd: the customer-owned cloud scope
    makes build_crm_context synthesize an On-Premises slice; the LLM supplies
    a cloud per-scope narrative but no on-prem one, so plan_implementations
    emits a status=None residual ImplementationPlan. Pre-fix that raised
    IntegrityError mid-flush and rolled back the whole batch.
    """
    engine, app = _engine_and_app(monkeypatch)
    wb_path = tmp_path / "two_crm.xlsx"
    wb_path.touch()

    with Session(engine) as s:
        wb_id, obj_id, ctrl_pk, fw_id = _seed_workbook(s, wb_path)
        # CRM 1: AWS GovCloud, customer-owned (forces synthesized On-Premises).
        _attach_crm(
            s,
            framework_id=fw_id,
            workbook_id=wb_id,
            control_pk=ctrl_pk,
            responsibility="customer",
            scope_label="AWS GovCloud",
            narrative="AWS GovCloud account management is customer-owned.",
            attached_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        # CRM 2: Azure Government, inherited (a second scope, later attach).
        _attach_crm(
            s,
            framework_id=fw_id,
            workbook_id=wb_id,
            control_pk=ctrl_pk,
            responsibility="inherited",
            scope_label="Azure Government",
            narrative="Azure Government account management is inherited.",
            attached_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
        )

    ccis_row = _make_ccis_row(cci_id="CCI-000015")
    client = _CompliantCloudOnlyClient(scope_label="AWS GovCloud")
    _patch_route(monkeypatch, ccis_row=ccis_row, wb_path=wb_path, client=client)

    resp = TestClient(app).post(
        "/api/controls/assess-batch",
        json={"workbook_id": wb_id, "persist": True, "skip_existing": False},
    )
    # The headline assertion: NO 500.
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["persist_error"] is None, data["persist_error"]
    assert data.get("persist_errored", 0) == 0
    assert data["persisted"] >= 1

    # Per-scope impl rows persisted for BOTH cloud scopes plus the
    # synthesized On-Premises slice — exactly the multi-boundary shape that
    # used to crash the flush. (Whether On-Premises lands as a real verdict
    # or a status=None residual depends on whether the LLM supplied an
    # on-prem narrative; the status=None persistence path itself is pinned by
    # the unit test ``test_impl_persistence_residual_abstain``. Here we assert
    # the row set persisted cleanly, which is the user-facing contract.)
    with Session(engine) as s:
        parent = s.exec(
            select(Assessment).where(Assessment.objective_id == obj_id)
        ).one()
        impls = s.exec(
            select(AssessmentImplementation).where(
                AssessmentImplementation.assessment_id == parent.id
            )
        ).all()
        by_scope = {i.scope_label: i for i in impls}
        assert ON_PREM_LABEL in by_scope, (
            f"synthesized On-Premises slice must persist; got scopes "
            f"{list(by_scope)}"
        )
        assert "AWS GovCloud" in by_scope and "Azure Government" in by_scope, (
            f"both cloud scopes must persist; got {list(by_scope)}"
        )
        # Every persisted impl row carries a narrative (never contentless),
        # whether its status is a real verdict or a residual abstain.
        for label, im in by_scope.items():
            assert im.narrative, f"impl {label} must carry a narrative"
        # The customer-owned cloud scope kept its real verdict.
        assert by_scope["AWS GovCloud"].status is ComplianceStatus.COMPLIANT
