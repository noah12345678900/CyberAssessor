"""Tests for Gap B — ``attach_workbook_overlay`` auto-fires
``compute_and_persist_crm_suspicion`` when the attached baseline is a CRM.

Producer side (``compute_and_persist_crm_suspicion``) is exercised by
``tests/routes/test_crm_suspicion_endpoint.py``. These tests pin the
auto-trigger contract:

  1. Attaching a CRM writes exactly one ``CrmSuspicionLog`` with a valid
     severity bucket and a ``CrmCorpusFeatures`` row at the current
     feature-schema version (the plan's
     ``feature_vector_schema_version == CURRENT_FEATURE_SCHEMA_VERSION``
     check — that field lives on ``CrmCorpusFeatures`` in the schema).
  2. Attaching a non-CRM overlay (e.g. ``CCIS_WORKBOOK`` sibling) writes
     zero ``CrmSuspicionLog`` rows — the auto-trigger is CRM-only.
  3. A scoring exception is swallowed: the attach response is still 200,
     the ``WorkbookOverlay`` row is committed, and no ``CrmSuspicionLog``
     row appears. This is the ``engine/CRM_SANITY_DESIGN.md`` "don't
     crash the report on ML failure" contract — the user can retry via
     the manual ``GET /api/baselines/{id}/crm-suspicion`` endpoint.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

# Make the backend package importable from any pytest cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.db import get_session  # noqa: E402
from cybersecurity_assessor.engine.crm_ml import (  # noqa: E402
    CURRENT_FEATURE_SCHEMA_VERSION,
)
from cybersecurity_assessor.models import (  # noqa: E402
    Baseline,
    BaselineSourceType,
    CrmCorpusFeatures,
    CrmSuspicionLog,
    Framework,
    Workbook,
    WorkbookOverlay,
)
from cybersecurity_assessor.server import create_app  # noqa: E402


@pytest.fixture
def app_ctx(tmp_path: Path):
    """TestClient + the underlying engine, so tests can both hit the
    HTTP attach endpoint AND query persistence directly.

    Seeds: framework, workbook (real file on disk for path validation),
    one CRM baseline and one CCIS_WORKBOOK sibling baseline. Caller
    receives ``(client, engine, workbook_id, crm_baseline_id, sibling_baseline_id)``.
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

    wb_path = tmp_path / "demo.xlsx"
    wb_path.write_bytes(b"x")

    with Session(engine) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5")
        s.add(fw)
        s.commit()
        s.refresh(fw)

        wb = Workbook(path=str(wb_path), filename=wb_path.name, framework_id=fw.id)
        s.add(wb)

        crm = Baseline(
            framework_id=fw.id,
            name="Test CRM",
            source_type=BaselineSourceType.CRM,
            source_ref=str(tmp_path / "crm.xlsx"),
        )
        s.add(crm)

        sibling = Baseline(
            framework_id=fw.id,
            name="Sibling system CCIS",
            source_type=BaselineSourceType.CCIS_WORKBOOK,
            source_ref=str(tmp_path / "sibling.xlsx"),
        )
        s.add(sibling)

        s.commit()
        s.refresh(wb)
        s.refresh(crm)
        s.refresh(sibling)
        wb_id, crm_id, sibling_id = wb.id, crm.id, sibling.id

    yield TestClient(app), engine, wb_id, crm_id, sibling_id

    app.dependency_overrides.clear()


def test_crm_attach_auto_creates_one_suspicion_log(app_ctx) -> None:
    """Attaching a CRM overlay triggers ``compute_and_persist_crm_suspicion``
    synchronously. Exactly one log row lands for the (workbook, crm)
    pair, severity is one of the canonical buckets, and a CorpusFeatures
    row at the current schema version grows the IsolationForest training
    set."""
    client, engine, wb_id, crm_id, _ = app_ctx

    r = client.post(
        f"/api/workbooks/{wb_id}/overlays",
        json={"baseline_id": crm_id, "note": "auto-trigger smoke"},
    )
    assert r.status_code == 200, r.text

    with Session(engine) as s:
        logs = s.exec(
            select(CrmSuspicionLog).where(
                CrmSuspicionLog.workbook_id == wb_id,
                CrmSuspicionLog.crm_baseline_id == crm_id,
            )
        ).all()
        assert len(logs) == 1, "CRM attach must auto-write exactly one log"
        log = logs[0]
        # Severity is a derived bucket on the report, not stored. Pin the
        # raw inputs that decide the bucket are in [0.0, 1.0] and round-
        # trippable — the bucket itself is asserted via the report API in
        # tests/routes/test_crm_suspicion_endpoint.py.
        assert 0.0 <= log.overall_suspicion <= 1.0
        assert 0.0 <= log.heuristic_score <= 1.0

        # Plan's `feature_vector_schema_version == CURRENT_FEATURE_SCHEMA_VERSION`
        # check — that field is on CrmCorpusFeatures (the corpus row the
        # extractor grows for future IsolationForest refits), not on the
        # log itself.
        features = s.exec(
            select(CrmCorpusFeatures).where(
                CrmCorpusFeatures.workbook_id == wb_id,
                CrmCorpusFeatures.crm_baseline_id == crm_id,
            )
        ).all()
        assert len(features) == 1
        assert features[0].feature_schema_version == CURRENT_FEATURE_SCHEMA_VERSION


def test_non_crm_attach_does_not_trigger_suspicion(app_ctx) -> None:
    """Attaching a CCIS_WORKBOOK overlay must NOT fire the CRM-only
    suspicion auto-trigger. Zero log rows after the attach."""
    client, engine, wb_id, _, sibling_id = app_ctx

    r = client.post(
        f"/api/workbooks/{wb_id}/overlays",
        json={"baseline_id": sibling_id},
    )
    assert r.status_code == 200, r.text

    with Session(engine) as s:
        count = len(s.exec(select(CrmSuspicionLog)).all())
        assert count == 0, "Non-CRM overlay must not produce a suspicion log"


def test_scoring_exception_is_swallowed_attach_still_succeeds(
    app_ctx, monkeypatch
) -> None:
    """Per ``engine/CRM_SANITY_DESIGN.md`` 'don't crash the report on ML
    failure': a scoring crash (TF-IDF blob unpickle, IsolationForest
    refit, embeddings provider) must NOT 500 the attach. The
    ``WorkbookOverlay`` row commits, the response is 200, and no
    ``CrmSuspicionLog`` lands — the user can retry compute manually."""
    client, engine, wb_id, crm_id, _ = app_ctx

    def _boom(*_args, **_kwargs):
        raise RuntimeError("simulated IsolationForest refit failure")

    # Monkeypatch the SYMBOL imported into the workbooks module — that's
    # the binding the attach handler actually calls. Patching the source
    # module would miss the already-imported reference.
    monkeypatch.setattr(
        "cybersecurity_assessor.routes.workbooks.compute_and_persist_crm_suspicion",
        _boom,
    )

    r = client.post(
        f"/api/workbooks/{wb_id}/overlays",
        json={"baseline_id": crm_id, "note": "scoring will fail"},
    )
    assert r.status_code == 200, r.text

    with Session(engine) as s:
        # Overlay row is committed (the failure is post-commit).
        overlays = s.exec(
            select(WorkbookOverlay).where(
                WorkbookOverlay.workbook_id == wb_id,
                WorkbookOverlay.baseline_id == crm_id,
            )
        ).all()
        assert len(overlays) == 1

        # Suspicion log was never written because the helper raised.
        logs = s.exec(select(CrmSuspicionLog)).all()
        assert logs == []
