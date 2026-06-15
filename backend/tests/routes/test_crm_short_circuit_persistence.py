"""Tests for ``_persist_crm_short_circuits`` — the route-side writer that
turns ``CciOutcome.crm_short_circuit`` dataclasses into ``CrmShortCircuitEvent``
rows.

The producer side (kernel attaches a ``CrmShortCircuit`` to every
provider/inherited/not_applicable outcome) is pinned by
``tests/engine/test_assessor_logs_short_circuits.py``. These tests pin the
consumer half: given a list of outcomes, the writer must

  1. emit one row per short-circuit, carrying the right ``responsibility``,
  2. resolve ``suspicion_log_id`` to the latest ``CrmSuspicionLog`` for the
     ``(workbook, crm_baseline)`` pair (None when no log exists),
  3. write zero rows for customer / hybrid outcomes (no short-circuit).

We drive the helper directly with synthesized ``CciOutcome`` objects rather
than the full HTTP ``/assess`` endpoint — the producer is already covered,
and going through the endpoint would force a real workbook on disk, an LLM
client, and a CCI lookup just to assert two SQL writes.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

# Make the backend package importable from any pytest cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.engine.measurement import (  # noqa: E402
    CciOutcome,
    CrmShortCircuit,
    RunRecorder,
)
from cybersecurity_assessor.models import (  # noqa: E402
    AssessmentRun,
    Baseline,
    BaselineSourceType,
    Control,
    CrmShortCircuitEvent,
    CrmSuspicionLog,
    Framework,
    Workbook,
)
from cybersecurity_assessor.routes.controls import (  # noqa: E402
    _persist_crm_short_circuits,
)


@pytest.fixture
def seeded(tmp_path: Path):
    """In-memory SQLite seeded with framework, workbook, CRM baseline, and a
    handful of Controls (AC-2/AC-3/AC-4/AC-5/AC-6).

    Yields ``(session, workbook_id, baseline_id, control_id_map)``. Caller
    closes the session.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    wb_path = tmp_path / "demo.xlsx"
    wb_path.write_bytes(b"x")

    with Session(engine) as s:
        fw = Framework(name="NIST SP 800-53", version="Rev 5")
        s.add(fw)
        s.commit()
        s.refresh(fw)

        wb = Workbook(path=str(wb_path), filename=wb_path.name, framework_id=fw.id)
        crm = Baseline(
            framework_id=fw.id,
            name="Test CRM",
            source_type=BaselineSourceType.CRM,
            source_ref=str(tmp_path / "crm.xlsx"),
        )
        controls = [
            Control(framework_id=fw.id, control_id=cid, title=cid, family=cid.split("-")[0])
            for cid in ("AC-2", "AC-3", "AC-4", "AC-5", "AC-6")
        ]
        s.add(wb)
        s.add(crm)
        for c in controls:
            s.add(c)
        s.commit()
        s.refresh(wb)
        s.refresh(crm)
        for c in controls:
            s.refresh(c)

        control_pk_map = {c.control_id: c.id for c in controls}
        yield s, wb.id, crm.id, control_pk_map


def _outcome(cci: str, control_id: str, responsibility: str, baseline_id: int) -> CciOutcome:
    """Build a CciOutcome carrying a CrmShortCircuit — minimum shape needed
    by the writer."""
    return CciOutcome(
        cci=cci,
        crm_short_circuit=CrmShortCircuit(
            cci=cci,
            control_id=control_id,
            responsibility=responsibility,  # type: ignore[arg-type]
            baseline_id=baseline_id,
        ),
    )


def test_three_responsibility_types_persist_one_row_each(seeded) -> None:
    """provider + inherited + not_applicable each produce a row, with the
    matching ``responsibility`` string and ``suspicion_log_id is None``
    when no log exists for the (workbook, baseline) pair yet.

    Also drives the same three outcomes through a ``RunRecorder`` and
    re-queries the persisted ``AssessmentRun`` row to assert that the
    per-run ``crm_short_circuit_count`` aggregate landed as 3 — the
    end-to-end recorder → DB column contract that the unit tests in
    ``tests/engine/test_recorder_crm_short_circuit_count.py`` don't
    catch (those exercise the aggregator math in-memory; this one
    walks the same outcomes through ``finish()`` and re-fetches via
    ``select(AssessmentRun)`` to confirm the column write is real).
    """
    session, wb_id, crm_id, _ = seeded
    outcomes = [
        _outcome("CCI-000001", "AC-2", "provider", crm_id),
        _outcome("CCI-000002", "AC-3", "inherited", crm_id),
        _outcome("CCI-000003", "AC-4", "not_applicable", crm_id),
    ]

    written = _persist_crm_short_circuits(
        session, workbook_id=wb_id, outcomes=outcomes
    )
    session.commit()

    assert written == 3
    rows = session.exec(
        select(CrmShortCircuitEvent).where(CrmShortCircuitEvent.workbook_id == wb_id)
    ).all()
    assert len(rows) == 3
    by_resp = {r.responsibility: r for r in rows}
    assert set(by_resp) == {"provider", "inherited", "not_applicable"}
    for r in rows:
        assert r.suspicion_log_id is None
        assert r.workbook_id == wb_id
        assert r.control_id_fk is not None

    # End-to-end per-run aggregate: feed the same three short-circuited
    # outcomes through RunRecorder and confirm the AssessmentRun column
    # round-trips a count of 3. This is the seam the route handler relies
    # on — the recorder writes to the DB column and the /api/runs endpoint
    # reads from it; if either side regresses, the patent ROI tile silently
    # zeroes out.
    rec = RunRecorder.start(session, workbook_id=wb_id)
    for o in outcomes:
        with rec.cci(o.cci) as ctx:
            ctx.crm_short_circuit = o.crm_short_circuit
    run = rec.finish()

    persisted_run = session.exec(
        select(AssessmentRun).where(AssessmentRun.id == run.id)
    ).one()
    assert persisted_run.crm_short_circuit_count == 3


def test_suspicion_log_resolution_links_to_latest_log(seeded) -> None:
    """When a CrmSuspicionLog row exists for the (workbook, crm_baseline)
    pair, every persisted event's ``suspicion_log_id`` resolves to it."""
    session, wb_id, crm_id, _ = seeded

    log = CrmSuspicionLog(
        workbook_id=wb_id,
        crm_baseline_id=crm_id,
        heuristic_score=0.4,
        ml_anomaly_score=None,
        narrative_quality_score=None,
        overall_suspicion=0.4,
        flags_json="[]",
        per_family_json="{}",
        n_corpus=0,
    )
    session.add(log)
    session.commit()
    session.refresh(log)
    expected_log_id = log.id

    outcomes = [
        _outcome("CCI-000001", "AC-2", "provider", crm_id),
        _outcome("CCI-000002", "AC-3", "inherited", crm_id),
        _outcome("CCI-000003", "AC-4", "not_applicable", crm_id),
    ]

    written = _persist_crm_short_circuits(
        session, workbook_id=wb_id, outcomes=outcomes
    )
    session.commit()

    assert written == 3
    rows = session.exec(
        select(CrmShortCircuitEvent).where(CrmShortCircuitEvent.workbook_id == wb_id)
    ).all()
    assert len(rows) == 3
    assert all(r.suspicion_log_id == expected_log_id for r in rows)


def test_customer_and_hybrid_produce_no_events(seeded) -> None:
    """customer / hybrid outcomes don't carry a CrmShortCircuit dataclass
    (the LLM still runs); the writer must skip them and emit zero rows."""
    session, wb_id, _, _ = seeded
    # Customer / hybrid don't short-circuit — the kernel does NOT attach a
    # CrmShortCircuit to those outcomes. So in the consumer's view the
    # outcomes simply have crm_short_circuit=None.
    outcomes = [
        CciOutcome(cci="CCI-000010"),  # customer — LLM path
        CciOutcome(cci="CCI-000011"),  # hybrid — LLM path
    ]

    written = _persist_crm_short_circuits(
        session, workbook_id=wb_id, outcomes=outcomes
    )
    session.commit()

    assert written == 0
    rows = session.exec(
        select(CrmShortCircuitEvent).where(CrmShortCircuitEvent.workbook_id == wb_id)
    ).all()
    assert rows == []
