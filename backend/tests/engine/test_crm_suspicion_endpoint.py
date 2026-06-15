"""Tests for ``GET /api/baselines/{workbook_id}/crm-suspicion`` and
``PATCH /api/baselines/crm-suspicion/{log_id}/mark`` — the route layer
that wraps the three-tier suspicion scorer.

What we pin (plan B8):

1. **Happy path returns a JSON-safe report payload + persists side effects.**
   The route extracts crm_context + fingerprint + tagged-evidence
   from the session, calls ``score_crm_suspicion``, persists one
   ``CrmSuspicionLog`` row and one ``CrmCorpusFeatures`` row, and
   returns the report dict with ``suspicion_log_id`` appended so the UI
   can wire the "mark false positive" action.

2. **404 when the workbook doesn't exist.** Generic guard — the route
   uses ``s.get(Workbook, workbook_id)`` and raises 404 immediately.

3. **404 when no CRM overlay is attached.** The UI hides the banner
   for workbooks in this state, so 404 here is the expected silent path
   (not an error toast). Confirms the JOIN-on-source_type=CRM works.

4. **Cold-start (n_corpus < 10) → ``ml_anomaly_score is None``.**
   Tier 3 is gated; below MIN_CORPUS_SIZE the route MUST NOT load a
   model (even if one happens to exist), and the payload's
   ``ml_anomaly_score`` must be None — the banner uses this to hide the
   ML row entirely.

5. **Populated corpus + active model → ``ml_anomaly_score`` is a unit
   float.** End-to-end: the route loads the active model blob, threads
   it through the scorer, and the payload surfaces a float in [0, 1].
   This pins the joblib round-trip across the persistence boundary.

6. **Each call grows the corpus by exactly one CrmCorpusFeatures row.**
   Plan section B8 calls this idempotency "intentionally loose" — the
   operator recomputes freely, duplicates naturally weight a frequently-
   scrutinized CRM higher. Pinning ``n+1`` after one call defends
   against a future "skip if recent" silent regression.

7. **PATCH happy path — flips ``assessor_marked_false_positive=True``,
   persists optional notes, returns marked_at timestamp.** The mark is
   the v0.3+ labeled-corpus seed; losing it silently would erase the
   only supervised signal we'll ever have.

8. **PATCH 404 for a missing log_id.** Same 404 shape as the GET — keeps
   the UI's error toasting consistent.

These tests use FastAPI's TestClient with an in-memory SQLite engine and
``app.dependency_overrides[get_session]`` to swap the session — same
pattern the rest of the route tests use.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

pytest.importorskip("sklearn", reason="IsolationForest fit needs sklearn")
pytest.importorskip("joblib", reason="model blob round-trip needs joblib")

from cybersecurity_assessor import models  # noqa: F401,E402  -- register tables
from cybersecurity_assessor.db import get_session  # noqa: E402
from cybersecurity_assessor.engine.crm_ml import (  # noqa: E402
    CURRENT_FEATURE_SCHEMA_VERSION,
    CrmFeatureVector,
    fit_anomaly_model,
)
from cybersecurity_assessor.models import (  # noqa: E402
    Baseline,
    BaselineControl,
    BaselineSourceType,
    Control,
    CrmAnomalyModel,
    CrmCorpusFeatures,
    CrmSuspicionLog,
    Framework,
    Objective,
    Workbook,
    WorkbookOverlay,
)
from cybersecurity_assessor.server import create_app  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    """In-memory SQLite with StaticPool — same pattern as test_assessor_e2e."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def client(session):
    """FastAPI TestClient with get_session overridden to the test session.

    Reuses the production app so the URL prefix + route decorators are
    exactly what runs in the sidecar — no copy-paste route definitions
    that could drift.
    """
    app = create_app()
    app.dependency_overrides[get_session] = lambda: session
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Seeding helpers
# ---------------------------------------------------------------------------


def _seed_framework(session: Session) -> Framework:
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)
    return fw


def _seed_control(
    session: Session, framework: Framework, control_id: str, family: str
) -> Control:
    c = Control(
        framework_id=framework.id,
        control_id=control_id,
        title=f"{control_id} Title",
        family=family,
    )
    session.add(c)
    session.commit()
    session.refresh(c)
    # Every Control needs at least one Objective for build_crm_context's
    # downstream consumers (and to keep the tagged-evidence join healthy).
    obj = Objective(
        control_id_fk=c.id,
        objective_id=f"CCI-{c.id:06d}",
        source="CCI",
        text=f"Objective for {control_id}",
    )
    session.add(obj)
    session.commit()
    return c


def _seed_workbook_with_primary_baseline(
    session: Session, framework: Framework, controls: list[Control]
) -> Workbook:
    """Create a primary baseline + workbook with all controls in_scope.

    ``build_boundary_fingerprint`` reads ``Workbook.baseline_id`` to find
    in-scope controls; without this, ``in_scope_control_ids`` would be
    empty and the heuristic floor wouldn't have a denominator.
    """
    primary = Baseline(
        framework_id=framework.id,
        name="Primary baseline",
        source_type=BaselineSourceType.CCIS_WORKBOOK,
    )
    session.add(primary)
    session.commit()
    session.refresh(primary)
    for ctl in controls:
        session.add(
            BaselineControl(baseline_id=primary.id, control_id=ctl.id, in_scope=True)
        )
    session.commit()

    wb = Workbook(
        path="/tmp/test_crm_suspicion_endpoint.xlsx",
        filename="test.xlsx",
        framework_id=framework.id,
        baseline_id=primary.id,
    )
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb


def _attach_crm_overlay(
    session: Session,
    framework: Framework,
    workbook: Workbook,
    controls: list[Control],
    *,
    responsibility_per_control: dict[str, str],
    narrative: str | None = "Inherited from FedRAMP-authorized provider XYZ.",
    name: str = "Test CRM",
    attached_at: datetime | None = None,
) -> Baseline:
    """Attach one CRM-type baseline overlay populating responsibility rows.

    ``responsibility_per_control`` maps control_id (e.g. "AC-2") to a
    responsibility string; controls not listed get no BaselineControl
    row on the CRM baseline (which is what real workbooks look like —
    CRMs typically cover only a subset of the catalog).
    """
    crm = Baseline(
        framework_id=framework.id,
        name=name,
        source_type=BaselineSourceType.CRM,
    )
    session.add(crm)
    session.commit()
    session.refresh(crm)
    for ctl in controls:
        resp = responsibility_per_control.get(ctl.control_id)
        if resp is None:
            continue
        session.add(
            BaselineControl(
                baseline_id=crm.id,
                control_id=ctl.id,
                in_scope=True,
                responsibility=resp,
                responsibility_narrative=narrative,
            )
        )
    overlay_kwargs = {"workbook_id": workbook.id, "baseline_id": crm.id}
    if attached_at is not None:
        overlay_kwargs["attached_at"] = attached_at
    session.add(WorkbookOverlay(**overlay_kwargs))
    session.commit()
    return crm


def _seed_min_corpus_features(
    session: Session, workbook: Workbook, baseline_id: int, *, n: int
) -> None:
    """Seed ``n`` CrmCorpusFeatures rows at the current schema version.

    Used to drive the cold-start / populated bifurcation. Values mirror
    the synthetic corpus from test_crm_ml_anomaly.py so a real
    IsolationForest fit on these rows produces a meaningful model.
    """
    for i in range(n):
        vec = CrmFeatureVector(
            schema_version=CURRENT_FEATURE_SCHEMA_VERSION,
            inherited_pct=0.35 + 0.01 * (i % 5),
            provider_pct=0.10 + 0.005 * (i % 3),
            not_applicable_pct=0.02 * (i % 2),
            narrative_present_pct=0.88 + 0.01 * (i % 4),
            narrative_len_mean=110.0 + 5.0 * (i % 5),
            narrative_len_stdev=25.0 + 2.0 * (i % 4),
            intra_crm_tfidf_max_similarity=0.35 + 0.02 * (i % 4),
            intra_crm_tfidf_mean_similarity=0.18 + 0.01 * (i % 3),
            family_evidence_contradictions=0,
            in_scope_control_count=45 + (i % 7),
        )
        session.add(
            CrmCorpusFeatures(
                crm_baseline_id=baseline_id,
                workbook_id=workbook.id,
                feature_schema_version=CURRENT_FEATURE_SCHEMA_VERSION,
                features_json=vec.to_json(),
            )
        )
    session.commit()


def _seed_active_anomaly_model(session: Session, n_corpus: int = 12) -> CrmAnomalyModel:
    """Fit a real IsolationForest and persist it as the active model.

    Uses ``fit_anomaly_model`` so the bytes are a genuine joblib pickle
    the route can round-trip. This pins the persistence boundary against
    accidental "store metadata instead of blob" regressions.
    """
    corpus = [
        CrmFeatureVector(
            schema_version=CURRENT_FEATURE_SCHEMA_VERSION,
            inherited_pct=0.35 + 0.01 * (i % 5),
            provider_pct=0.10 + 0.005 * (i % 3),
            not_applicable_pct=0.02 * (i % 2),
            narrative_present_pct=0.88 + 0.01 * (i % 4),
            narrative_len_mean=110.0 + 5.0 * (i % 5),
            narrative_len_stdev=25.0 + 2.0 * (i % 4),
            intra_crm_tfidf_max_similarity=0.35 + 0.02 * (i % 4),
            intra_crm_tfidf_mean_similarity=0.18 + 0.01 * (i % 3),
            family_evidence_contradictions=0,
            in_scope_control_count=45 + (i % 7),
        )
        for i in range(n_corpus)
    ]
    result = fit_anomaly_model(corpus)
    model = CrmAnomalyModel(
        n_samples=len(corpus),
        feature_schema_version=CURRENT_FEATURE_SCHEMA_VERSION,
        model_blob=result.model_blob,
        is_active=True,
    )
    session.add(model)
    session.commit()
    session.refresh(model)
    return model


def _bootstrap_workbook_with_crm(
    session: Session, *, responsibility_per_control: dict[str, str] | None = None
) -> tuple[Workbook, Baseline, list[Control]]:
    """Common scaffold: framework + 3 controls + primary + CRM overlay."""
    fw = _seed_framework(session)
    controls = [
        _seed_control(session, fw, "AC-2", "AC"),
        _seed_control(session, fw, "AC-3", "AC"),
        _seed_control(session, fw, "AU-6", "AU"),
    ]
    wb = _seed_workbook_with_primary_baseline(session, fw, controls)
    if responsibility_per_control is None:
        responsibility_per_control = {
            "AC-2": "inherited",
            "AC-3": "provider",
            "AU-6": "customer",
        }
    crm = _attach_crm_overlay(
        session,
        fw,
        wb,
        controls,
        responsibility_per_control=responsibility_per_control,
    )
    return wb, crm, controls


# ---------------------------------------------------------------------------
# GET happy path
# ---------------------------------------------------------------------------


def test_get_returns_report_and_persists_log_and_corpus_row(session, client):
    """End-to-end: workbook with CRM overlay → 200 + payload + side effects.

    The payload must carry the JSON-safe report shape AND the
    ``suspicion_log_id`` the UI needs to wire the "mark false positive"
    PATCH. One ``CrmSuspicionLog`` row is persisted; one
    ``CrmCorpusFeatures`` row is appended for the next refit.
    """
    wb, crm, _ = _bootstrap_workbook_with_crm(session)

    resp = client.get(f"/api/baselines/{wb.id}/crm-suspicion")
    assert resp.status_code == 200, resp.text
    body = resp.json()

    # Payload shape: every key the to_json_safe contract promises.
    for key in (
        "workbook_id",
        "crm_baseline_id",
        "computed_at",
        "heuristic_score",
        "ml_anomaly_score",
        "narrative_quality_score",
        "overall_suspicion",
        "severity",
        "flags",
        "per_family",
        "n_corpus",
        "suspicion_log_id",
    ):
        assert key in body, f"missing key {key!r}"

    assert body["workbook_id"] == wb.id
    assert body["crm_baseline_id"] == crm.id
    assert isinstance(body["heuristic_score"], float)
    assert 0.0 <= body["heuristic_score"] <= 1.0
    assert isinstance(body["overall_suspicion"], float)
    assert 0.0 <= body["overall_suspicion"] <= 1.0
    assert body["severity"] in {"info", "warn", "alert"}
    assert isinstance(body["flags"], list)
    assert isinstance(body["per_family"], dict)

    # CrmSuspicionLog persisted with matching fields.
    logs = session.exec(select(CrmSuspicionLog)).all()
    assert len(logs) == 1
    log = logs[0]
    assert log.id == body["suspicion_log_id"]
    assert log.workbook_id == wb.id
    assert log.crm_baseline_id == crm.id
    assert log.heuristic_score == body["heuristic_score"]
    assert log.overall_suspicion == body["overall_suspicion"]
    assert log.assessor_marked_false_positive is None
    # JSON columns round-trip.
    assert isinstance(json.loads(log.flags_json), list)
    assert isinstance(json.loads(log.per_family_json), dict)

    # Corpus row appended for the next IsolationForest refit.
    corpus_rows = session.exec(select(CrmCorpusFeatures)).all()
    assert len(corpus_rows) == 1
    assert corpus_rows[0].crm_baseline_id == crm.id
    assert corpus_rows[0].workbook_id == wb.id
    assert corpus_rows[0].feature_schema_version == CURRENT_FEATURE_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# GET 404 paths
# ---------------------------------------------------------------------------


def test_get_returns_404_when_workbook_missing(client):
    """Generic guard — no workbook, no suspicion."""
    resp = client.get("/api/baselines/999999/crm-suspicion")
    assert resp.status_code == 404
    assert "Workbook not found" in resp.json()["detail"]


def test_get_returns_404_when_no_crm_overlay_attached(session, client):
    """Workbook exists but has no CRM-type overlay → 404.

    The UI uses this 404 as the signal to hide the suspicion banner
    entirely. Any other status (e.g. 200 with all-None scores) would
    show the banner with broken affordances.
    """
    fw = _seed_framework(session)
    controls = [_seed_control(session, fw, "AC-2", "AC")]
    wb = _seed_workbook_with_primary_baseline(session, fw, controls)
    # Intentionally no CRM overlay attached.

    resp = client.get(f"/api/baselines/{wb.id}/crm-suspicion")
    assert resp.status_code == 404
    assert "No CRM overlay" in resp.json()["detail"]


def test_get_ignores_non_crm_overlays_when_picking_baseline_id(session, client):
    """A workbook with a non-CRM overlay attached is treated as if it had
    no CRM overlay — 404. Pins the ``source_type == CRM`` filter in the
    overlay-selection subquery.
    """
    fw = _seed_framework(session)
    controls = [_seed_control(session, fw, "AC-2", "AC")]
    wb = _seed_workbook_with_primary_baseline(session, fw, controls)
    # Attach a non-CRM overlay (e.g. another CCIS workbook for gap analysis).
    sibling = Baseline(
        framework_id=fw.id,
        name="Sibling CCIS",
        source_type=BaselineSourceType.CCIS_WORKBOOK,
    )
    session.add(sibling)
    session.commit()
    session.refresh(sibling)
    session.add(WorkbookOverlay(workbook_id=wb.id, baseline_id=sibling.id))
    session.commit()

    resp = client.get(f"/api/baselines/{wb.id}/crm-suspicion")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Tier 3 gating — cold-start vs populated corpus
# ---------------------------------------------------------------------------


def test_get_cold_start_returns_null_ml_anomaly_score(session, client):
    """Corpus below MIN_CORPUS_SIZE AND no active model → ml score None.

    The banner's ML row hides on None — this protects against a
    "show 0.0 instead of None" bug that would mis-cue the assessor
    into trusting an unfitted score.
    """
    wb, crm, _ = _bootstrap_workbook_with_crm(session)
    # No CrmCorpusFeatures, no CrmAnomalyModel seeded.

    resp = client.get(f"/api/baselines/{wb.id}/crm-suspicion")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ml_anomaly_score"] is None
    # n_corpus surfaces 0 (this call appends after compute; the call-time
    # value the scorer saw was zero).
    assert body["n_corpus"] == 0


def test_get_with_populated_corpus_and_active_model_returns_float_ml_score(
    session, client
):
    """Corpus ≥ 10 AT CURRENT SCHEMA VERSION + active model → ml score in [0, 1].

    Pins the full route → scorer → IsolationForest persistence path:
    the joblib blob round-trips, the feature vector matches the schema
    version, and the scorer returns a unit float (not None).
    """
    wb, crm, _ = _bootstrap_workbook_with_crm(session)
    _seed_min_corpus_features(session, wb, crm.id, n=12)
    _seed_active_anomaly_model(session, n_corpus=12)

    resp = client.get(f"/api/baselines/{wb.id}/crm-suspicion")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ml_anomaly_score"] is not None
    assert isinstance(body["ml_anomaly_score"], float)
    assert 0.0 <= body["ml_anomaly_score"] <= 1.0
    assert body["n_corpus"] == 12


def test_get_with_corpus_but_no_active_model_returns_null_ml_score(session, client):
    """Even with enough corpus rows, ``ml_anomaly_score`` is None until a
    model is fitted and activated. Pins the AND-gate: corpus ≥ 10 AND
    active model — not OR.
    """
    wb, crm, _ = _bootstrap_workbook_with_crm(session)
    _seed_min_corpus_features(session, wb, crm.id, n=12)
    # No active CrmAnomalyModel.

    resp = client.get(f"/api/baselines/{wb.id}/crm-suspicion")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ml_anomaly_score"] is None


# ---------------------------------------------------------------------------
# Corpus grows on every call (intentional loose idempotency)
# ---------------------------------------------------------------------------


def test_each_get_call_appends_one_corpus_features_row(session, client):
    """Plan B8: "Idempotency is intentionally loose — duplicate corpus rows
    naturally weight a frequently-recomputed CRM higher."

    Three calls → three CrmCorpusFeatures rows. Defends against a future
    "skip if recent" silent regression that would starve the corpus.
    """
    wb, _, _ = _bootstrap_workbook_with_crm(session)

    for expected in (1, 2, 3):
        resp = client.get(f"/api/baselines/{wb.id}/crm-suspicion")
        assert resp.status_code == 200
        assert len(session.exec(select(CrmCorpusFeatures)).all()) == expected

    # And three CrmSuspicionLog rows — each call writes one verdict.
    assert len(session.exec(select(CrmSuspicionLog)).all()) == 3


# ---------------------------------------------------------------------------
# Latest-attached CRM wins for crm_baseline_id selection
# ---------------------------------------------------------------------------


def test_get_picks_most_recently_attached_crm_overlay_for_log(session, client):
    """When two CRMs are attached, the most-recently-attached one's id is
    the ``crm_baseline_id`` on the persisted log.

    This matches ``build_crm_context``'s latest-wins merge semantics — if
    the log pointed at the older overlay, the operator's "mark false
    positive" would label the wrong CRM.
    """
    fw = _seed_framework(session)
    controls = [
        _seed_control(session, fw, "AC-2", "AC"),
        _seed_control(session, fw, "AU-6", "AU"),
    ]
    wb = _seed_workbook_with_primary_baseline(session, fw, controls)
    older_time = datetime.now(timezone.utc) - timedelta(days=2)
    newer_time = datetime.now(timezone.utc)
    older = _attach_crm_overlay(
        session,
        fw,
        wb,
        controls,
        responsibility_per_control={"AC-2": "inherited"},
        name="Older CRM",
        attached_at=older_time,
    )
    newer = _attach_crm_overlay(
        session,
        fw,
        wb,
        controls,
        responsibility_per_control={"AU-6": "provider"},
        name="Newer CRM",
        attached_at=newer_time,
    )

    resp = client.get(f"/api/baselines/{wb.id}/crm-suspicion")
    assert resp.status_code == 200
    body = resp.json()
    assert body["crm_baseline_id"] == newer.id
    assert body["crm_baseline_id"] != older.id


# ---------------------------------------------------------------------------
# PATCH — mark false positive
# ---------------------------------------------------------------------------


def test_patch_marks_suspicion_log_false_positive_with_notes(session, client):
    """Happy path: PATCH flips the flag, persists notes, returns
    marked_at. The flag is the v0.3+ supervised classifier's only label —
    silent loss here = silent loss of the entire labeled corpus.
    """
    wb, _, _ = _bootstrap_workbook_with_crm(session)
    # Materialize a log via the GET endpoint so we have a real id to patch.
    log_id = client.get(f"/api/baselines/{wb.id}/crm-suspicion").json()[
        "suspicion_log_id"
    ]

    resp = client.patch(
        f"/api/baselines/crm-suspicion/{log_id}/mark",
        json={"notes": "Verified with vendor — high inheritance is correct for SaaS."},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body == {
        "ok": True,
        "suspicion_log_id": log_id,
        "marked_at": body["marked_at"],  # opaque timestamp string
    }
    assert isinstance(body["marked_at"], str) and body["marked_at"]

    # Verify persistence.
    session.expire_all()
    log = session.get(CrmSuspicionLog, log_id)
    assert log is not None
    assert log.assessor_marked_false_positive is True
    assert log.assessor_review_notes == (
        "Verified with vendor — high inheritance is correct for SaaS."
    )


def test_patch_without_notes_still_flips_flag(session, client):
    """``notes`` is optional. Body ``{}`` must still flip the flag —
    notes are recommended but not required by the v0.3+ classifier.
    """
    wb, _, _ = _bootstrap_workbook_with_crm(session)
    log_id = client.get(f"/api/baselines/{wb.id}/crm-suspicion").json()[
        "suspicion_log_id"
    ]

    resp = client.patch(f"/api/baselines/crm-suspicion/{log_id}/mark", json={})
    assert resp.status_code == 200

    session.expire_all()
    log = session.get(CrmSuspicionLog, log_id)
    assert log.assessor_marked_false_positive is True
    assert log.assessor_review_notes is None


def test_patch_returns_404_when_log_missing(client):
    """Unknown log_id → 404. Same error shape as GET so the UI's toast
    handling is uniform.
    """
    resp = client.patch(
        "/api/baselines/crm-suspicion/999999/mark",
        json={"notes": "nope"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# GET /{workbook_id}/crm-suspicion/latest — cached read, no side effects
# ---------------------------------------------------------------------------


def test_latest_returns_most_recent_log_without_recomputing(session, client):
    """The /latest endpoint is the cached-read companion to the live-
    compute endpoint. After two compute calls, ``/latest`` MUST return
    the second (newer) log — and importantly MUST NOT add a third
    CrmCorpusFeatures row, because pure read.

    This is the contract the post-attach toast in Workbooks.tsx keys off:
    re-uploading a CRM cheaply re-surfaces the most recent suspicion
    verdict without paying the embedder + IsolationForest cost again.
    """
    wb, _, _ = _bootstrap_workbook_with_crm(session)

    # Two computes → two CrmSuspicionLog rows + two CrmCorpusFeatures rows.
    first = client.get(f"/api/baselines/{wb.id}/crm-suspicion").json()
    second = client.get(f"/api/baselines/{wb.id}/crm-suspicion").json()
    assert first["suspicion_log_id"] != second["suspicion_log_id"]

    session.expire_all()
    corpus_after_two_computes = session.exec(
        select(CrmCorpusFeatures).where(CrmCorpusFeatures.workbook_id == wb.id)
    ).all()
    assert len(corpus_after_two_computes) == 2

    # /latest returns the newer log; the corpus must NOT grow.
    resp = client.get(f"/api/baselines/{wb.id}/crm-suspicion/latest")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["suspicion_log_id"] == second["suspicion_log_id"]

    # Field set the UI toast renderer keys off — must include the cached
    # verdict and decoded flags list (not raw JSON string).
    assert body["overall_suspicion"] == second["overall_suspicion"]
    assert body["assessor_marked_false_positive"] is None
    assert isinstance(body["flags"], list)

    session.expire_all()
    corpus_after_latest = session.exec(
        select(CrmCorpusFeatures).where(CrmCorpusFeatures.workbook_id == wb.id)
    ).all()
    assert len(corpus_after_latest) == 2, (
        "/latest must be pure read — corpus row count must not change"
    )


def test_latest_404_when_never_computed(session, client):
    """A workbook with a CRM attached but no compute calls yet → 404.
    The toast keys off the 404 to silently skip the suspicion clause
    rather than render a confusing 'no data' state."""
    wb, _, _ = _bootstrap_workbook_with_crm(session)

    resp = client.get(f"/api/baselines/{wb.id}/crm-suspicion/latest")
    assert resp.status_code == 404


def test_latest_404_for_missing_workbook(client):
    """Unknown workbook_id → 404. Same shape as the live-compute
    endpoint's missing-workbook error for UI consistency."""
    resp = client.get("/api/baselines/999999/crm-suspicion/latest")
    assert resp.status_code == 404


def test_latest_carries_false_positive_mark(session, client):
    """When the assessor has already marked the latest log as false
    positive, ``/latest`` MUST surface ``assessor_marked_false_positive
    = True`` so the upload toast can suppress the re-warning. Without
    this the user would get re-nagged on every CRM re-upload despite
    having already cleared the verdict."""
    wb, _, _ = _bootstrap_workbook_with_crm(session)
    log_id = client.get(f"/api/baselines/{wb.id}/crm-suspicion").json()[
        "suspicion_log_id"
    ]
    client.patch(
        f"/api/baselines/crm-suspicion/{log_id}/mark",
        json={"notes": "cleared by assessor"},
    )

    resp = client.get(f"/api/baselines/{wb.id}/crm-suspicion/latest")
    assert resp.status_code == 200
    body = resp.json()
    assert body["suspicion_log_id"] == log_id
    assert body["assessor_marked_false_positive"] is True
