"""Whole-module tests for the attach-time CRM backfill.

``engine.crm_backfill.backfill_workbook_crm`` is what makes a freshly-
attached CRM overlay produce visible Assessment rows immediately, rather
than sitting inert until the next batch_assess pass. It is a thin
read-side wrapper around the same ``_finalize_crm_decision`` short-circuit
the assess pipeline uses for ``provider`` / ``inherited`` /
``not_applicable`` responsibilities (hybrid + customer are deliberately
deferred to LLM time so the user can review).

This module starts at 0% line coverage. The branches under test:

  * 6 early-return guards (no workbook, no baseline_id, primary baseline
    missing, file missing, ValueError on read, FileNotFoundError on
    read, no in-scope pairs, no CRM overlays attached)
  * 4 mid-loop skip counters (no_row, no_entry, non_deterministic,
    existing)
  * 1 defensive guard (lines 167-170) that skips writing an Assessment
    if ``_finalize_crm_decision`` returns a malformed Decision —
    ``_finalize_crm_decision`` always accepts, so the only way to reach
    this branch is via monkeypatch
  * 3 happy paths (provider → NA, inherited → Compliant,
    not_applicable → NA) — each writes exactly one Assessment row with
    the status/narrative_class the responsibility mapping dictates
  * ``BackfillResult.as_dict()`` round-trip — used by the route handler

DB-shaped: in-memory SQLite + StaticPool (same pattern as
``test_crm_context.py``). ``read_workbook_index`` is monkeypatched to
return a controllable ``CcisIndex`` rather than building a real .xlsx
fixture — the function under test only consumes ``index.by_cci()``.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

# Ensure the backend package is importable when pytest is launched from any cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.engine import crm_backfill  # noqa: E402
from cybersecurity_assessor.engine.assessor import Assessor, Decision  # noqa: E402
from cybersecurity_assessor.engine.crm_backfill import (  # noqa: E402
    BackfillResult,
    backfill_workbook_crm,
)
from cybersecurity_assessor.excel.ccis_reader import CcisIndex, CcisRow  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Assessment,
    Baseline,
    BaselineControl,
    BaselineObjective,
    BaselineSourceType,
    ComplianceStatus,
    Control,
    Framework,
    NarrativeClass,
    Objective,
    Workbook,
    WorkbookOverlay,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    """In-memory SQLite, single shared connection per test."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def framework(session) -> Framework:
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)
    return fw


@pytest.fixture
def control_ac2(session, framework) -> Control:
    c = Control(
        framework_id=framework.id,
        control_id="ac-2",  # OSCAL canonical — CRM lookup keys on this form
        title="Account Management",
        family="AC",
    )
    session.add(c)
    session.commit()
    session.refresh(c)
    return c


@pytest.fixture
def objective_ac2(session, control_ac2) -> Objective:
    obj = Objective(
        control_id_fk=control_ac2.id,
        objective_id="CCI-000015",
        source="CCI",
        text="The organization establishes an account management policy.",
    )
    session.add(obj)
    session.commit()
    session.refresh(obj)
    return obj


@pytest.fixture
def workbook_file(tmp_path) -> Path:
    """Real path on disk so ``Path(wb.path).exists()`` returns True."""
    p = tmp_path / "wb.xlsx"
    p.write_bytes(b"")  # contents irrelevant — read_workbook_index is monkeypatched
    return p


@pytest.fixture
def primary_baseline(session, framework) -> Baseline:
    """The workbook's primary baseline (the catalog the workbook was built from)."""
    b = Baseline(
        framework_id=framework.id,
        name="primary",
        source_type=BaselineSourceType.CCIS_WORKBOOK,
    )
    session.add(b)
    session.commit()
    session.refresh(b)
    return b


@pytest.fixture
def workbook(session, workbook_file, primary_baseline) -> Workbook:
    wb = Workbook(
        path=str(workbook_file),
        filename=workbook_file.name,
        baseline_id=primary_baseline.id,
    )
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb


def _attach_in_scope(
    session: Session,
    *,
    baseline_id: int,
    control_id_int: int,
    objective_id_int: int,
    excel_row: int = 100,
) -> None:
    """Wire up the BaselineControl + BaselineObjective rows the in-scope join needs."""
    session.add(
        BaselineControl(
            baseline_id=baseline_id,
            control_id=control_id_int,
            in_scope=True,
        )
    )
    session.add(
        BaselineObjective(
            baseline_id=baseline_id,
            objective_id=objective_id_int,
            source_row=excel_row,
        )
    )
    session.commit()


def _attach_crm(
    session: Session,
    *,
    framework_id: int,
    workbook_id: int,
    control_id_int: int,
    responsibility: str,
    narrative: str | None = None,
) -> Baseline:
    """Build a CRM baseline + responsibility tag + WorkbookOverlay link."""
    crm = Baseline(
        framework_id=framework_id,
        name=f"CRM-{responsibility}",
        source_type=BaselineSourceType.CRM,
    )
    session.add(crm)
    session.commit()
    session.refresh(crm)
    session.add(
        BaselineControl(
            baseline_id=crm.id,
            control_id=control_id_int,
            in_scope=True,
            responsibility=responsibility,
            responsibility_narrative=narrative,
        )
    )
    session.add(
        WorkbookOverlay(
            workbook_id=workbook_id,
            baseline_id=crm.id,
            attached_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        )
    )
    session.commit()
    return crm


def _attach_crm_scoped(
    session: Session,
    *,
    framework_id: int,
    workbook_id: int,
    control_id_int: int,
    responsibility: str,
    scope_label: str,
    attached_at: datetime,
    narrative: str | None = None,
) -> Baseline:
    """Attach a scope_label-bearing CRM (v0.2 multi-impl) at a specific time.

    Differs from ``_attach_crm`` in two ways the masking regression needs:
    the Baseline carries a ``scope_label`` (so ``build_crm_context``
    emits an ``ImplementationSlice`` for it), and ``attached_at`` is
    caller-controlled (so two CRMs on the same control have a
    deterministic latest-wins order in ``by_control``).
    """
    crm = Baseline(
        framework_id=framework_id,
        name=f"CRM-{scope_label}-{responsibility}",
        source_type=BaselineSourceType.CRM,
        scope_label=scope_label,
    )
    session.add(crm)
    session.commit()
    session.refresh(crm)
    session.add(
        BaselineControl(
            baseline_id=crm.id,
            control_id=control_id_int,
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
    return crm


def _make_row(
    *,
    excel_row: int = 100,
    control_id: str = "AC-2",
    cci_id: str | None = "CCI-000015",
) -> CcisRow:
    """Minimal CcisRow — only fields the backfill touches need values."""
    return CcisRow(
        excel_row=excel_row,
        required=True,
        control_id=control_id,
        ap_acronym=None,
        cci_id=cci_id,
        implementation_status=None,
        designation=None,
        narrative=None,
        definition=None,
        guidance=None,
        procedures=None,
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


def _fake_index(rows: list[CcisRow]) -> CcisIndex:
    """CcisIndex with our hand-built rows; workbook_path/sheet_name are unused here."""
    return CcisIndex(workbook_path=Path("unused.xlsx"), sheet_name="WORKING SHEET", rows=rows)


def _install_fake_reader(monkeypatch: pytest.MonkeyPatch, rows: list[CcisRow]) -> None:
    """Replace the module-level ``read_workbook_index`` re-export."""
    monkeypatch.setattr(crm_backfill, "read_workbook_index", lambda _path: _fake_index(rows))


# ---------------------------------------------------------------------------
# BackfillResult shape — used by the route handler payload
# ---------------------------------------------------------------------------


def test_backfill_result_as_dict_round_trip():
    """All five counters round-trip through ``as_dict`` with their key names."""
    r = BackfillResult(
        applied=3,
        skipped_existing=2,
        skipped_no_crm_entry=4,
        skipped_non_deterministic=1,
        skipped_no_workbook_row=5,
    )
    assert r.as_dict() == {
        "applied": 3,
        "skipped_existing": 2,
        "skipped_no_crm_entry": 4,
        "skipped_non_deterministic": 1,
        "skipped_no_workbook_row": 5,
    }


# ---------------------------------------------------------------------------
# Early-return guards (six of them, all return all-zero BackfillResult)
# ---------------------------------------------------------------------------


def test_returns_zero_when_workbook_missing(session):
    """Unknown workbook_id → all-zeros, no raise.

    Pins crm_backfill.py:80-82 first branch (``wb is None``). The route
    handler calls backfill for every newly-attached overlay; if the
    workbook was deleted between the attach and the backfill the function
    MUST NOT raise — the user's CRM-attach request already succeeded.
    """
    result = backfill_workbook_crm(workbook_id=999_999, session=session)

    assert result == BackfillResult(0, 0, 0, 0, 0)


def test_returns_zero_when_workbook_baseline_id_is_none(session, workbook_file):
    """Workbook exists but has no primary baseline → all-zeros.

    Pins crm_backfill.py:80-82 second branch (``wb.baseline_id is None``).
    Fresh workbooks without a framework binding can still receive CRM
    overlays — the docstring explicitly calls this out.
    """
    wb = Workbook(path=str(workbook_file), filename="wb.xlsx", baseline_id=None)
    session.add(wb)
    session.commit()
    session.refresh(wb)

    result = backfill_workbook_crm(workbook_id=wb.id, session=session)

    assert result == BackfillResult(0, 0, 0, 0, 0)


def test_returns_zero_when_primary_baseline_row_missing(session, workbook_file):
    """Workbook.baseline_id points at a non-existent Baseline → all-zeros.

    Pins crm_backfill.py:84-86. Data-integrity bug (FK orphan); guard
    rather than raise so the attach still succeeds.
    """
    wb = Workbook(path=str(workbook_file), filename="wb.xlsx", baseline_id=12345)
    session.add(wb)
    session.commit()
    session.refresh(wb)

    result = backfill_workbook_crm(workbook_id=wb.id, session=session)

    assert result == BackfillResult(0, 0, 0, 0, 0)


def test_returns_zero_when_workbook_file_missing(session, primary_baseline, tmp_path):
    """Workbook row exists but its file path has been moved/deleted → all-zeros.

    Pins crm_backfill.py:88-93. Per the inline comment: the attach itself
    still succeeds; the user will get a clearer error when they try to
    open or assess.
    """
    wb = Workbook(
        path=str(tmp_path / "does_not_exist.xlsx"),
        filename="does_not_exist.xlsx",
        baseline_id=primary_baseline.id,
    )
    session.add(wb)
    session.commit()
    session.refresh(wb)

    result = backfill_workbook_crm(workbook_id=wb.id, session=session)

    assert result == BackfillResult(0, 0, 0, 0, 0)


def test_returns_zero_when_read_workbook_index_raises_value_error(
    session, workbook, monkeypatch
):
    """File present but ``read_workbook_index`` raises ValueError → all-zeros.

    Pins crm_backfill.py:95-100 ValueError branch. Schema bug in the
    workbook (e.g. WORKING SHEET tab renamed); same recovery posture as
    file-missing — don't fail the attach.
    """
    def boom(_path: Path) -> CcisIndex:
        raise ValueError("WORKING SHEET tab not found")

    monkeypatch.setattr(crm_backfill, "read_workbook_index", boom)

    result = backfill_workbook_crm(workbook_id=workbook.id, session=session)

    assert result == BackfillResult(0, 0, 0, 0, 0)


def test_returns_zero_when_read_workbook_index_raises_file_not_found(
    session, workbook, monkeypatch
):
    """Race-condition where file vanishes between .exists() and read → all-zeros.

    Pins crm_backfill.py:95-100 FileNotFoundError branch. The
    ``wb_path.exists()`` check is best-effort — a concurrent delete
    between that check and the read MUST not propagate.
    """
    def boom(_path: Path) -> CcisIndex:
        raise FileNotFoundError("workbook vanished")

    monkeypatch.setattr(crm_backfill, "read_workbook_index", boom)

    result = backfill_workbook_crm(workbook_id=workbook.id, session=session)

    assert result == BackfillResult(0, 0, 0, 0, 0)


def test_returns_zero_when_no_in_scope_pairs(
    session, workbook, primary_baseline, control_ac2, objective_ac2, monkeypatch
):
    """No BaselineControl/BaselineObjective rows → no pairs → all-zeros.

    Pins crm_backfill.py:118-119. The in-scope join produces zero pairs
    when the workbook's primary baseline has no scoping rows. The early-
    return prevents a wasted ``build_crm_context`` round trip.
    """
    _install_fake_reader(monkeypatch, [_make_row()])
    # NOTE: deliberately do NOT call _attach_in_scope → empty pairs join.

    result = backfill_workbook_crm(workbook_id=workbook.id, session=session)

    assert result == BackfillResult(0, 0, 0, 0, 0)


def test_returns_zero_when_no_crm_overlays_attached(
    session, workbook, primary_baseline, control_ac2, objective_ac2, monkeypatch
):
    """Pairs exist but no CRM overlays attached → all-zeros.

    Pins crm_backfill.py:130-134. ``build_crm_context`` returns an empty
    context when no CRM-typed overlays exist; the early-return skips the
    loop entirely.
    """
    _attach_in_scope(
        session,
        baseline_id=primary_baseline.id,
        control_id_int=control_ac2.id,
        objective_id_int=objective_ac2.id,
    )
    _install_fake_reader(monkeypatch, [_make_row()])

    result = backfill_workbook_crm(workbook_id=workbook.id, session=session)

    assert result == BackfillResult(0, 0, 0, 0, 0)


# ---------------------------------------------------------------------------
# Mid-loop skip counters — pairs+CRM exist, but each row hits a skip branch
# ---------------------------------------------------------------------------


def test_skipped_no_workbook_row(
    session,
    workbook,
    framework,
    primary_baseline,
    control_ac2,
    objective_ac2,
    monkeypatch,
):
    """Pair exists, CRM exists, but CcisIndex has no row for that CCI.

    Pins crm_backfill.py:149-151. Objective row in DB but the CCI is
    missing from the workbook (workbook was edited between catalog load
    and this attach) → ``skipped_no_workbook_row`` increments, nothing
    is written.
    """
    _attach_in_scope(
        session,
        baseline_id=primary_baseline.id,
        control_id_int=control_ac2.id,
        objective_id_int=objective_ac2.id,
    )
    _attach_crm(
        session,
        framework_id=framework.id,
        workbook_id=workbook.id,
        control_id_int=control_ac2.id,
        responsibility="provider",
    )
    # CcisIndex contains a different CCI — no row for CCI-000015.
    _install_fake_reader(monkeypatch, [_make_row(cci_id="CCI-999999")])

    result = backfill_workbook_crm(workbook_id=workbook.id, session=session)

    assert result.applied == 0
    assert result.skipped_no_workbook_row == 1
    assert session.exec(select(Assessment)).all() == []


def test_skipped_no_crm_entry(
    session,
    workbook,
    framework,
    primary_baseline,
    control_ac2,
    objective_ac2,
    monkeypatch,
):
    """Pair + workbook row exist; CRM has no entry for that control → skipped_no_crm_entry.

    Pins crm_backfill.py:152-155. Workbook row's control is ac-3 but
    the CRM only tags ac-2 — lookup returns None → row is skipped, no
    Assessment written.
    """
    _attach_in_scope(
        session,
        baseline_id=primary_baseline.id,
        control_id_int=control_ac2.id,
        objective_id_int=objective_ac2.id,
    )
    # CRM tags a different control — no entry for ac-2 (the row's control).
    other = Control(
        framework_id=framework.id,
        control_id="ac-3",
        title="Access Enforcement",
        family="AC",
    )
    session.add(other)
    session.commit()
    session.refresh(other)
    _attach_crm(
        session,
        framework_id=framework.id,
        workbook_id=workbook.id,
        control_id_int=other.id,  # ac-3, not ac-2
        responsibility="provider",
    )
    _install_fake_reader(monkeypatch, [_make_row(control_id="AC-2")])

    result = backfill_workbook_crm(workbook_id=workbook.id, session=session)

    assert result.applied == 0
    assert result.skipped_no_crm_entry == 1
    assert session.exec(select(Assessment)).all() == []


@pytest.mark.parametrize("non_det", ["hybrid", "customer"])
def test_skipped_non_deterministic(
    non_det,
    session,
    workbook,
    framework,
    primary_baseline,
    control_ac2,
    objective_ac2,
    monkeypatch,
):
    """``hybrid`` and ``customer`` are deferred to the LLM → skipped_non_deterministic.

    Pins crm_backfill.py:156-159. The deterministic set is exactly
    {provider, inherited, not_applicable}; anything else falls through to
    the LLM at assess time and we MUST NOT write a placeholder Assessment.
    """
    _attach_in_scope(
        session,
        baseline_id=primary_baseline.id,
        control_id_int=control_ac2.id,
        objective_id_int=objective_ac2.id,
    )
    _attach_crm(
        session,
        framework_id=framework.id,
        workbook_id=workbook.id,
        control_id_int=control_ac2.id,
        responsibility=non_det,
    )
    _install_fake_reader(monkeypatch, [_make_row()])

    result = backfill_workbook_crm(workbook_id=workbook.id, session=session)

    assert result.applied == 0
    assert result.skipped_non_deterministic == 1
    assert session.exec(select(Assessment)).all() == []


def test_skipped_existing_assessment_is_not_stomped(
    session,
    workbook,
    framework,
    primary_baseline,
    control_ac2,
    objective_ac2,
    monkeypatch,
):
    """Prior Assessment row exists for this objective → skipped_existing, no overwrite.

    Pins crm_backfill.py:160-162. The "never stomp prior writes" guarantee
    in the module docstring — user edits, prior LLM runs, prior backfill
    from a different overlay all win over a re-backfill.
    """
    _attach_in_scope(
        session,
        baseline_id=primary_baseline.id,
        control_id_int=control_ac2.id,
        objective_id_int=objective_ac2.id,
    )
    _attach_crm(
        session,
        framework_id=framework.id,
        workbook_id=workbook.id,
        control_id_int=control_ac2.id,
        responsibility="provider",
    )
    _install_fake_reader(monkeypatch, [_make_row()])
    # Pre-existing Assessment that backfill must NOT touch.
    prior = Assessment(
        workbook_id=workbook.id,
        objective_id=objective_ac2.id,
        excel_row=100,
        status=ComplianceStatus.COMPLIANT,
        tester="Noah Jaskolski",
        narrative_q="Prior assessor narrative — must not be stomped.",
        narrative_class=NarrativeClass.COMPLIANCE_AFFIRMING,
        date_tested=datetime(2026, 1, 1, 9, 0, 0),
    )
    session.add(prior)
    session.commit()

    result = backfill_workbook_crm(workbook_id=workbook.id, session=session)

    assert result.applied == 0
    assert result.skipped_existing == 1
    # Original narrative still there, exactly one Assessment row.
    rows = session.exec(select(Assessment)).all()
    assert len(rows) == 1
    assert rows[0].narrative_q.startswith("Prior assessor narrative")
    assert rows[0].status == ComplianceStatus.COMPLIANT


# ---------------------------------------------------------------------------
# Happy paths — three deterministic responsibilities each write one Assessment
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("responsibility", "expected_status", "expected_class"),
    [
        ("provider", ComplianceStatus.NOT_APPLICABLE, NarrativeClass.NA_JUSTIFYING),
        ("inherited", ComplianceStatus.COMPLIANT, NarrativeClass.COMPLIANCE_AFFIRMING),
        (
            "not_applicable",
            ComplianceStatus.NOT_APPLICABLE,
            NarrativeClass.NA_JUSTIFYING,
        ),
    ],
)
def test_happy_path_writes_assessment_with_responsibility_mapping(
    responsibility,
    expected_status,
    expected_class,
    session,
    workbook,
    framework,
    primary_baseline,
    control_ac2,
    objective_ac2,
    monkeypatch,
):
    """provider/inherited/not_applicable each write one Assessment with the right shape.

    Pins crm_backfill.py:164-189. End-to-end check that the backfill
    reuses ``_finalize_crm_decision`` (so the status mapping stays
    co-tenant with the assess pipeline) and stages a single Assessment
    row per CRM-tagged objective.
    """
    _attach_in_scope(
        session,
        baseline_id=primary_baseline.id,
        control_id_int=control_ac2.id,
        objective_id_int=objective_ac2.id,
        excel_row=42,
    )
    _attach_crm(
        session,
        framework_id=framework.id,
        workbook_id=workbook.id,
        control_id_int=control_ac2.id,
        responsibility=responsibility,
        narrative=f"CRM narrative for {responsibility}",
    )
    _install_fake_reader(monkeypatch, [_make_row(excel_row=42)])

    result = backfill_workbook_crm(
        workbook_id=workbook.id, session=session, tester="unit-test"
    )

    assert result.applied == 1
    assert result.skipped_existing == 0
    assert result.skipped_no_crm_entry == 0
    assert result.skipped_non_deterministic == 0
    assert result.skipped_no_workbook_row == 0
    # Caller commits — flush so we can query.
    session.flush()
    rows = session.exec(select(Assessment)).all()
    assert len(rows) == 1
    a = rows[0]
    assert a.workbook_id == workbook.id
    assert a.objective_id == objective_ac2.id
    assert a.excel_row == 42
    assert a.status == expected_status
    assert a.narrative_class == expected_class
    assert a.tester == "unit-test"
    # CRM narrative passes through (no supersession map hits on this text).
    assert f"CRM narrative for {responsibility}" in a.narrative_q


# ---------------------------------------------------------------------------
# Defensive guard at lines 167-170 — _finalize_crm_decision always accepts,
# so this branch is unreachable without monkeypatch. Pin it so a refactor
# that drops the guard (because "the function always accepts anyway") shows
# up as a red test instead of a partial Assessment write in production.
# ---------------------------------------------------------------------------


def test_defensive_guard_skips_when_decision_not_accepted(
    session,
    workbook,
    framework,
    primary_baseline,
    control_ac2,
    objective_ac2,
    monkeypatch,
):
    """If _finalize_crm_decision returns a non-accepted Decision → no Assessment row.

    Pins crm_backfill.py:167-170. Defends the invariant the guard was
    written for: a future change that makes _finalize_crm_decision capable
    of returning ``accepted=False`` (e.g. validator integration on CRM
    narratives) MUST NOT silently produce partial Assessment rows.
    """
    _attach_in_scope(
        session,
        baseline_id=primary_baseline.id,
        control_id_int=control_ac2.id,
        objective_id_int=objective_ac2.id,
    )
    _attach_crm(
        session,
        framework_id=framework.id,
        workbook_id=workbook.id,
        control_id_int=control_ac2.id,
        responsibility="provider",
    )
    _install_fake_reader(monkeypatch, [_make_row()])

    def fake_finalize(self, row, cci, entry, *, outcome):
        return Decision(
            cci_id=cci,
            excel_row=row.excel_row,
            accepted=False,  # the branch under test
            status=None,
            narrative=None,
            narrative_class=None,
            source="forced-reject",
            rule=None,
            retries=0,
        )

    monkeypatch.setattr(Assessor, "_finalize_crm_decision", fake_finalize)

    result = backfill_workbook_crm(workbook_id=workbook.id, session=session)

    # Loop ran, hit the guard, continued — neither applied nor any skip counter
    # increments (the guard is a defensive bail-out, not a counted skip).
    assert result.applied == 0
    assert session.exec(select(Assessment)).all() == []


# ---------------------------------------------------------------------------
# In-loop bookkeeping: two CRMs in the same workbook resolve once per objective
# ---------------------------------------------------------------------------


def test_existing_obj_ids_set_updated_in_memory_within_call(
    session,
    workbook,
    framework,
    primary_baseline,
    control_ac2,
    monkeypatch,
):
    """Two objectives on the same control, both backed by CRM → both written, once each.

    Pins crm_backfill.py:189 ``existing_obj_ids.add(obj.id)`` — the
    in-call bookkeeping that keeps a second iteration over the same
    objective (e.g. two CRM overlays both tagging the same control) from
    double-writing.
    """
    # Two objectives on ac-2: CCI-000015 and CCI-000016.
    obj1 = Objective(
        control_id_fk=control_ac2.id,
        objective_id="CCI-000015",
        source="CCI",
        text="objective one",
    )
    obj2 = Objective(
        control_id_fk=control_ac2.id,
        objective_id="CCI-000016",
        source="CCI",
        text="objective two",
    )
    session.add_all([obj1, obj2])
    session.commit()
    session.refresh(obj1)
    session.refresh(obj2)
    session.add(
        BaselineControl(
            baseline_id=primary_baseline.id,
            control_id=control_ac2.id,
            in_scope=True,
        )
    )
    session.add(
        BaselineObjective(
            baseline_id=primary_baseline.id, objective_id=obj1.id, source_row=10
        )
    )
    session.add(
        BaselineObjective(
            baseline_id=primary_baseline.id, objective_id=obj2.id, source_row=11
        )
    )
    session.commit()
    _attach_crm(
        session,
        framework_id=framework.id,
        workbook_id=workbook.id,
        control_id_int=control_ac2.id,
        responsibility="inherited",
    )
    _install_fake_reader(
        monkeypatch,
        [
            _make_row(excel_row=10, cci_id="CCI-000015"),
            _make_row(excel_row=11, cci_id="CCI-000016"),
        ],
    )

    result = backfill_workbook_crm(workbook_id=workbook.id, session=session)

    assert result.applied == 2
    session.flush()
    rows = session.exec(select(Assessment)).all()
    assert len(rows) == 2
    # Both objectives are NOW in existing_obj_ids → if we re-run, no new writes.
    second = backfill_workbook_crm(workbook_id=workbook.id, session=session)
    assert second.applied == 0
    assert second.skipped_existing == 2


# ---------------------------------------------------------------------------
# Multi-scope_label masking guard — backfill side of the short-circuit fix.
#
# Companion to tests/engine/test_assessor_multiscope_masking.py (which pins
# the assess-time consumer) and tests/engine/test_crm_context_edges.py (which
# pins the data-layer symptom). When two CRMs cover one control under
# different scope_labels and the NEWEST attach is deterministic (inherited),
# ``build_crm_context`` keeps only that newest attach in ``by_control`` —
# masking an earlier customer scope. Backfill must NOT write a deterministic
# Assessment off the masking entry; it has to consult the per-scope slices,
# see the customer half, and defer the whole control to the LLM at assess
# time. Precision over recall: never set the customer-side work
# COMPLIANT-by-inheritance without evidence.
# ---------------------------------------------------------------------------


def test_masked_customer_multiscope_defers_to_llm(
    session,
    workbook,
    framework,
    primary_baseline,
    control_ac2,
    objective_ac2,
    monkeypatch,
):
    """AWS GovCloud 'customer' (older) + Azure 'inherited' (newer) → no backfill write.

    The latest-wins ``by_control`` entry is Azure 'inherited' — deterministic
    on its own, so the legacy single-entry path would short-circuit and write
    a COMPLIANT-by-inheritance Assessment. The per-scope slices preserve the
    AWS GovCloud 'customer' verdict (plus a synthesized On-Premises customer
    slice), so the backfill must classify the control as non-deterministic
    and skip the write, leaving it for the LLM at assess time.
    """
    _attach_in_scope(
        session,
        baseline_id=primary_baseline.id,
        control_id_int=control_ac2.id,
        objective_id_int=objective_ac2.id,
    )
    # Older attach: AWS GovCloud, customer-owned.
    _attach_crm_scoped(
        session,
        framework_id=framework.id,
        workbook_id=workbook.id,
        control_id_int=control_ac2.id,
        responsibility="customer",
        scope_label="AWS GovCloud",
        attached_at=datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc),
        narrative="Customer manages IAM roles in AWS GovCloud.",
    )
    # Newer attach: Azure, inherited — the masking entry that wins by_control.
    _attach_crm_scoped(
        session,
        framework_id=framework.id,
        workbook_id=workbook.id,
        control_id_int=control_ac2.id,
        responsibility="inherited",
        scope_label="Azure",
        attached_at=datetime(2026, 2, 1, 9, 0, 0, tzinfo=timezone.utc),
        narrative="Inherited from Azure Active Directory baseline.",
    )
    _install_fake_reader(monkeypatch, [_make_row()])

    result = backfill_workbook_crm(workbook_id=workbook.id, session=session)

    # The customer slice forces a non-deterministic classification — deferred,
    # not written.
    assert result.applied == 0, (
        "masked-customer multi-scope must NOT backfill a deterministic "
        f"inheritance row; got applied={result.applied}"
    )
    assert result.skipped_non_deterministic == 1, (
        "customer slice under a masking 'inherited' entry must count as "
        f"non-deterministic; got {result.as_dict()}"
    )
    assert session.exec(select(Assessment)).all() == [], (
        "no Assessment may be written when a customer slice is present"
    )


def test_masked_provider_only_multiscope_still_backfills(
    session,
    workbook,
    framework,
    primary_baseline,
    control_ac2,
    objective_ac2,
    monkeypatch,
):
    """Recall guard: two inheritable cloud slices (provider + inherited) DO backfill.

    The fix must only defer when a customer/hybrid slice actually exists.
    AWS GovCloud 'provider' (older) + Azure 'inherited' (newer) carry no
    customer-side work, so ``build_crm_context`` synthesizes no On-Premises
    slice and every slice is deterministic. The control still backfills a
    single deterministic Assessment, exactly as a lone inherited CRM would —
    over-deferring here would spuriously force the LLM on genuinely
    fully-inherited controls.
    """
    _attach_in_scope(
        session,
        baseline_id=primary_baseline.id,
        control_id_int=control_ac2.id,
        objective_id_int=objective_ac2.id,
    )
    _attach_crm_scoped(
        session,
        framework_id=framework.id,
        workbook_id=workbook.id,
        control_id_int=control_ac2.id,
        responsibility="provider",
        scope_label="AWS GovCloud",
        attached_at=datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc),
        narrative="AWS owns this at the platform layer.",
    )
    _attach_crm_scoped(
        session,
        framework_id=framework.id,
        workbook_id=workbook.id,
        control_id_int=control_ac2.id,
        responsibility="inherited",
        scope_label="Azure",
        attached_at=datetime(2026, 2, 1, 9, 0, 0, tzinfo=timezone.utc),
        narrative="Inherited from Azure AD baseline.",
    )
    _install_fake_reader(monkeypatch, [_make_row()])

    result = backfill_workbook_crm(workbook_id=workbook.id, session=session)

    assert result.applied == 1, (
        "all-inheritable multi-scope must still backfill; "
        f"got {result.as_dict()}"
    )
    assert result.skipped_non_deterministic == 0
    session.flush()
    rows = session.exec(select(Assessment)).all()
    assert len(rows) == 1
    # Latest-wins by_control entry (Azure 'inherited') drives the verdict.
    assert rows[0].status == ComplianceStatus.COMPLIANT
