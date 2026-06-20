"""Regression: re-uploading a CRM under the same scope_label must satisfy
EVERY foreign key when it cascade-deletes the prior CRM baseline.

THE BUG (cascade audit, third instance of the same class). The
``POST /api/catalog/overlays/import`` CRM branch implements "replace-by-label":
uploading a CRM with the same (framework, scope_label) but a NEW file path
deletes the prior Baseline so re-attach is idempotent. But that delete cleared
ONLY BaselineControl / BaselineObjective / WorkbookOverlay — it never purged the
CRM telemetry a CRM baseline owns (CrmSuspicionLog / CrmCorpusFeatures /
CrmShortCircuitEvent, all NOT-NULL FKs to baseline.id) nor its
AssessmentImplementation slices (source_baseline_id). Under
``PRAGMA foreign_keys=ON`` (db.py — production) the ``s.delete(prior)`` then
raised a FOREIGN KEY constraint failure → HTTP 500, so the replace-upload failed
the moment the prior CRM had ever been suspicion-scored or assessed.

The fix routes the prior-baseline delete through
``purge_baseline_contribution`` (the same helper delete_baseline uses), which
clears the telemetry in FK-safe order and recomputes affected parents.

WHY THE OLD overlay-import test missed it: it built its engine WITHOUT FK
enforcement and seeded no telemetry on the prior baseline, so no FK ever raised.
This test enables FK enforcement (matching production) AND seeds one row in every
CRM-owned child chain on the prior baseline, so any regression makes the replace
upload 500 and fails here.

Collected via testpaths=["../tests"].
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from openpyxl import Workbook as XlsxWorkbook
from sqlalchemy import event
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select

from cybersecurity_assessor import models  # noqa: F401 -- register tables
from cybersecurity_assessor.db import get_session
from cybersecurity_assessor.models import (
    Assessment,
    AssessmentImplementation,
    Baseline,
    BaselineSourceType,
    ComplianceStatus,
    Control,
    CrmCorpusFeatures,
    CrmShortCircuitEvent,
    CrmSuspicionLog,
    Framework,
    NarrativeClass,
    Objective,
    Workbook,
    WorkbookOverlay,
)
from cybersecurity_assessor.server import create_app


def _utc() -> datetime:
    return datetime.now(timezone.utc)


def _write_crm_xlsx(path: Path) -> None:
    """CRM-shaped: control-id column + responsibility column on one sheet."""
    wb = XlsxWorkbook()
    ws = wb.active
    ws.title = "CRM"
    ws.append(["Control ID", "Responsibility", "Customer Responsibility"])
    ws.append(["AC-2", "Customer", "Customer owns account lifecycle."])
    wb.save(path)


@pytest.fixture
def env(tmp_path: Path):
    """TestClient with FK enforcement ON, a framework + AC-2/CCI seeded, and a
    PRIOR CRM baseline under scope_label 'AWS GovCloud' carrying one row in every
    CRM-owned child chain (telemetry + an impl slice) so the replace-by-label
    delete must satisfy every FK."""
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

    with Session(engine) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5")
        s.add(fw)
        s.commit()
        s.refresh(fw)

        ctrl = Control(
            framework_id=fw.id, control_id="ac-2", title="AC-2", family="AC"
        )
        s.add(ctrl)
        s.commit()
        s.refresh(ctrl)

        obj = Objective(
            control_id_fk=ctrl.id, objective_id="CCI-000015", source="CCI", text="t"
        )
        s.add(obj)
        s.commit()
        s.refresh(obj)

        wb = Workbook(path=str(tmp_path / "wb.xlsx"), filename="wb.xlsx", framework_id=fw.id)
        s.add(wb)
        s.commit()
        s.refresh(wb)

        # PRIOR CRM baseline — same (framework, scope_label) as the upload below,
        # but a DIFFERENT source_ref path so the route takes the replace branch.
        prior = Baseline(
            framework_id=fw.id,
            name="CRM v1",
            source_type=BaselineSourceType.CRM,
            scope_label="AWS GovCloud",
            source_ref=str(tmp_path / "crm_v1.xlsx"),
        )
        s.add(prior)
        s.commit()
        s.refresh(prior)
        s.add(WorkbookOverlay(workbook_id=wb.id, baseline_id=prior.id, attached_at=_utc()))

        # An assessed parent that this CRM contributed an inherited slice to.
        a = Assessment(
            workbook_id=wb.id,
            objective_id=obj.id,
            excel_row=1,
            status=ComplianceStatus.COMPLIANT,
            tester="system",
            date_tested=_utc(),
            narrative_q="inherited via CRM",
            narrative_class=NarrativeClass.COMPLIANCE_AFFIRMING,
            verdict_source="CRM_INHERITED",
        )
        s.add(a)
        s.commit()
        s.refresh(a)
        s.add(
            AssessmentImplementation(
                assessment_id=a.id,
                scope_label="AWS GovCloud",
                source_baseline_id=prior.id,
                responsibility="inherited",
                status=ComplianceStatus.COMPLIANT,
                narrative="inherited via CRM",
            )
        )

        # CRM telemetry: CrmSuspicionLog → CrmShortCircuitEvent + CrmCorpusFeatures.
        susp = CrmSuspicionLog(
            workbook_id=wb.id,
            crm_baseline_id=prior.id,
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
                crm_baseline_id=prior.id,
                feature_schema_version=1,
                features_json="{}",
            )
        )
        s.commit()

        prior_id = prior.id
        framework_id = fw.id

    yield {
        "client": TestClient(app),
        "engine": engine,
        "framework_id": framework_id,
        "prior_id": prior_id,
        "tmp": tmp_path,
    }
    app.dependency_overrides.clear()


def test_crm_replace_by_label_satisfies_all_foreign_keys(env) -> None:
    """Re-uploading a CRM under the same scope_label (new path) cascade-deletes
    the prior CRM baseline cleanly under FK enforcement (no 500) and purges its
    telemetry + impl slices."""
    new_path = env["tmp"] / "crm_v2.xlsx"
    _write_crm_xlsx(new_path)

    r = env["client"].post(
        "/api/catalog/overlays/import",
        json={
            "framework_id": env["framework_id"],
            "path": str(new_path),
            "scope_label": "AWS GovCloud",
        },
    )
    assert r.status_code == 200, (
        f"replace-by-label must satisfy every FK; got {r.status_code}: {r.text}"
    )
    payload = r.json()
    assert payload["kind"] == "crm"
    # The prior baseline was reported as replaced.
    assert env["prior_id"] in payload["replaced_baseline_ids"]

    prior_ref = str(env["tmp"] / "crm_v1.xlsx")
    new_ref = str(new_path)
    with Session(env["engine"]) as s:
        # The PRIOR baseline (by its old file path) is gone. NB: SQLite recycles
        # the freed rowid, so the new baseline may reuse prior_id — assert by
        # source_ref, not by primary key.
        assert (
            s.exec(select(Baseline).where(Baseline.source_ref == prior_ref)).all() == []
        ), "prior CRM baseline not deleted"
        # Exactly the new CRM baseline survives under this scope_label.
        survivors = s.exec(
            select(Baseline).where(Baseline.scope_label == "AWS GovCloud")
        ).all()
        assert [b.source_ref for b in survivors] == [new_ref]

        # ALL CRM telemetry from the prior baseline was purged. crm.apply does
        # not write telemetry, so no rows should reference the (recycled) id and
        # no short-circuit events should survive at all (the only log was the
        # prior baseline's).
        assert s.exec(select(CrmShortCircuitEvent)).all() == [], "short-circuit events not purged"
        assert s.exec(select(CrmSuspicionLog)).all() == [], "suspicion log not purged"
        assert s.exec(select(CrmCorpusFeatures)).all() == [], "corpus features not purged"
        # The CRM-only parent had its sole impl slice removed; no impl slice may
        # dangle on a baseline id that the prior owned.
        assert (
            s.exec(
                select(AssessmentImplementation).where(
                    AssessmentImplementation.source_baseline_id == env["prior_id"]
                )
            ).all()
            == []
        )
