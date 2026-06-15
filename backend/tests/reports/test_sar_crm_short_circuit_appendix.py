"""Tests for the SAR Appendix G loader — the runtime CRM short-circuit
ledger.

Pinning the gap closed by `_appendix_crm_short_circuits`: until this
slice, the only reader of ``CrmShortCircuitEvent`` was the Metrics tile;
the SAR PDF built Appendix F entirely off ``BaselineControl.responsibility``
(declared scope) and the table beneath the "...were short-circuited..."
blurb was a lie — declared scope, not actually-exercised events.

Tested at the ``_gather`` layer rather than ``build_sar_report``: the
contract being regressed is the data shape ``_appendix_crm_short_circuits``
consumes, not reportlab byte output. Same justification as
``test_sar.py`` — the PDF-integration test is a separate investment, and
asserting on PDF bytes for a row-count regression is the wrong tool.

The four cases pin the four branches the loader exercises:

  1. Events WITH a suspicion log resolve severity (bucketed via
     ``_suspicion_bucket``) and the raw score.
  2. Events WITHOUT a suspicion log (``suspicion_log_id IS NULL``)
     surface with ``severity is None`` and ``score is None`` so the
     renderer can emit "—" rather than crashing on a missing FK.
  3. Workbooks with zero events leave the field empty list — the
     ``if not data.crm_short_circuit_events: return []`` skip path in
     the renderer.
  4. Deleted controls (FK no longer in ``control_pk_to_id``) are
     silently skipped, not rendered as orphan rows with an empty
     control cell.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

# Make the backend package importable from any pytest cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.excel.ccis_reader import CcisIndex  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Baseline,
    BaselineSourceType,
    Control,
    CrmShortCircuitEvent,
    CrmSuspicionLog,
    Framework,
    Workbook,
)
from cybersecurity_assessor.reports import sar as sar_module  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _empty_index(wb_path: Path) -> CcisIndex:
    """Empty CcisIndex — the short-circuit loader doesn't touch col-N rows
    at all, so we just stub the workbook reader with a no-op index."""
    return CcisIndex(workbook_path=wb_path, sheet_name="CCIS", rows=[])


def _seed(
    session: Session, wb_path: Path
) -> tuple[int, int, dict[str, int]]:
    """Seed framework + CRM baseline + workbook + two Controls. Returns
    ``(workbook_id, crm_baseline_id, control_pk_by_id)``."""
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)

    controls = [
        Control(framework_id=fw.id, control_id="AC-2", title="AC-2", family="AC"),
        Control(framework_id=fw.id, control_id="AC-3", title="AC-3", family="AC"),
    ]
    for c in controls:
        session.add(c)
    session.commit()
    for c in controls:
        session.refresh(c)
    control_pk_by_id = {c.control_id: c.id for c in controls}

    wb = Workbook(path=str(wb_path), filename=wb_path.name, framework_id=fw.id)
    crm = Baseline(
        framework_id=fw.id,
        name="Test CRM",
        source_type=BaselineSourceType.CRM,
        source_ref=str(wb_path.parent / "crm.xlsx"),
    )
    session.add(wb)
    session.add(crm)
    session.commit()
    session.refresh(wb)
    session.refresh(crm)

    return wb.id, crm.id, control_pk_by_id


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_events_with_suspicion_log_resolve_severity_and_score(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Three events all pointing at one CrmSuspicionLog at
    overall=0.45 (warn bucket: 0.30 ≤ 0.45 < 0.60). Each loaded tuple
    must surface severity="warn" and score==0.45, and rows must be
    grouped by control_id in the final list."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    wb_path = tmp_path / "ccis_sar_g.xlsx"
    wb_path.touch()

    with Session(engine) as s:
        wb_id, crm_id, control_pks = _seed(s, wb_path)

        log = CrmSuspicionLog(
            workbook_id=wb_id,
            crm_baseline_id=crm_id,
            heuristic_score=0.4,
            ml_anomaly_score=None,
            narrative_quality_score=None,
            overall_suspicion=0.45,  # warn bucket
            flags_json="[]",
            per_family_json="{}",
            n_corpus=0,
        )
        s.add(log)
        s.commit()
        s.refresh(log)

        # Three events: 2 on AC-2 (provider, inherited), 1 on AC-3
        # (not_applicable). Different timestamps to verify ordering math.
        s.add(CrmShortCircuitEvent(
            workbook_id=wb_id,
            control_id_fk=control_pks["AC-2"],
            responsibility="provider",
            suspicion_log_id=log.id,
            created_at=datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc),
        ))
        s.add(CrmShortCircuitEvent(
            workbook_id=wb_id,
            control_id_fk=control_pks["AC-2"],
            responsibility="inherited",
            suspicion_log_id=log.id,
            created_at=datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc),
        ))
        s.add(CrmShortCircuitEvent(
            workbook_id=wb_id,
            control_id_fk=control_pks["AC-3"],
            responsibility="not_applicable",
            suspicion_log_id=log.id,
            created_at=datetime(2026, 6, 1, 11, 0, tzinfo=timezone.utc),
        ))
        s.commit()

        monkeypatch.setattr(
            "cybersecurity_assessor.reports.sar.read_workbook_index",
            lambda path: _empty_index(wb_path),
        )

        data = sar_module._gather(s, wb_id)

    assert len(data.crm_short_circuit_events) == 3
    for ctl_id, responsibility, severity, score, _created_at in data.crm_short_circuit_events:
        assert severity == "warn"
        assert score == pytest.approx(0.45)
        assert ctl_id in {"AC-2", "AC-3"}
        assert responsibility in {"provider", "inherited", "not_applicable"}

    # AC-2 (the control with two events) must appear twice; AC-3 once.
    by_control = {"AC-2": 0, "AC-3": 0}
    for ctl_id, *_ in data.crm_short_circuit_events:
        by_control[ctl_id] += 1
    assert by_control == {"AC-2": 2, "AC-3": 1}


def test_event_without_suspicion_log_returns_none_severity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An event with ``suspicion_log_id=None`` (CRM attached but scoring
    never ran, or ran after the short-circuit fired) must load with
    ``severity is None`` and ``score is None`` so the renderer can emit
    an em-dash rather than KeyError on the missing FK."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    wb_path = tmp_path / "ccis_sar_g_nolog.xlsx"
    wb_path.touch()

    with Session(engine) as s:
        wb_id, _crm_id, control_pks = _seed(s, wb_path)

        s.add(CrmShortCircuitEvent(
            workbook_id=wb_id,
            control_id_fk=control_pks["AC-2"],
            responsibility="inherited",
            suspicion_log_id=None,  # no suspicion log yet
            created_at=datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc),
        ))
        s.commit()

        monkeypatch.setattr(
            "cybersecurity_assessor.reports.sar.read_workbook_index",
            lambda path: _empty_index(wb_path),
        )

        data = sar_module._gather(s, wb_id)

    assert len(data.crm_short_circuit_events) == 1
    ctl_id, responsibility, severity, score, _ = data.crm_short_circuit_events[0]
    assert ctl_id == "AC-2"
    assert responsibility == "inherited"
    assert severity is None
    assert score is None


def test_no_events_leaves_field_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Workbook with no CrmShortCircuitEvent rows must yield an empty
    list — the renderer's ``if not data.crm_short_circuit_events:
    return []`` skip path."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    wb_path = tmp_path / "ccis_sar_g_empty.xlsx"
    wb_path.touch()

    with Session(engine) as s:
        wb_id, _crm_id, _control_pks = _seed(s, wb_path)
        # No events seeded.

        monkeypatch.setattr(
            "cybersecurity_assessor.reports.sar.read_workbook_index",
            lambda path: _empty_index(wb_path),
        )

        data = sar_module._gather(s, wb_id)

    assert data.crm_short_circuit_events == []


def test_deleted_control_is_silently_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Event whose ``control_id_fk`` references a Control that was deleted
    (or otherwise isn't in ``control_pk_to_id``) must be skipped, not
    rendered as an orphan row with an empty control cell. Simulates the
    post-delete state by writing the event then deleting the Control row
    (the schema doesn't cascade — the event survives the delete)."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)

    wb_path = tmp_path / "ccis_sar_g_orphan.xlsx"
    wb_path.touch()

    with Session(engine) as s:
        wb_id, _crm_id, control_pks = _seed(s, wb_path)

        # One event on AC-2 (which we'll delete), one on AC-3 (kept).
        s.add(CrmShortCircuitEvent(
            workbook_id=wb_id,
            control_id_fk=control_pks["AC-2"],
            responsibility="provider",
            suspicion_log_id=None,
            created_at=datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc),
        ))
        s.add(CrmShortCircuitEvent(
            workbook_id=wb_id,
            control_id_fk=control_pks["AC-3"],
            responsibility="not_applicable",
            suspicion_log_id=None,
            created_at=datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc),
        ))
        s.commit()

        # Delete AC-2 to simulate the orphan-FK condition. The event row
        # survives (no cascade) but ``control_pk_to_id`` in _gather won't
        # carry an entry for AC-2's PK.
        ac2 = s.get(Control, control_pks["AC-2"])
        s.delete(ac2)
        s.commit()

        monkeypatch.setattr(
            "cybersecurity_assessor.reports.sar.read_workbook_index",
            lambda path: _empty_index(wb_path),
        )

        data = sar_module._gather(s, wb_id)

    # Only AC-3 survived. The AC-2 event was silently skipped.
    assert len(data.crm_short_circuit_events) == 1
    ctl_id, responsibility, *_ = data.crm_short_circuit_events[0]
    assert ctl_id == "AC-3"
    assert responsibility == "not_applicable"
