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
    backfill_workbook_rules,
)
from cybersecurity_assessor.excel.ccis_reader import CcisIndex, CcisRow  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Assessment,
    AssessmentImplementation,
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
    inherited: str | None = None,
    remote_inheritance: str | None = None,
) -> CcisRow:
    """Minimal CcisRow — only fields the backfill touches need values.

    ``inherited`` / ``remote_inheritance`` are Column L / Column M. Pass
    ``inherited="Yes", remote_inheritance="<source>"`` to make the synthesized
    flex (On-Premises) slice resolve INHERITED — which is what now makes a
    flex-bearing control "deterministic" at backfill time (col L is the flex
    slice's status authority; ASSESS/ESCALATE defer to assess). Default None →
    flex slice ASSESS → control deferred (the post-flex-slice behavior).
    """
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
        inherited=inherited,
        remote_inheritance=remote_inheritance,
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
    """All counters round-trip through ``as_dict`` with their key names."""
    r = BackfillResult(
        applied=3,
        skipped_existing=2,
        skipped_no_crm_entry=4,
        skipped_non_deterministic=1,
        skipped_no_workbook_row=5,
        healed_deleted=6,
    )
    assert r.as_dict() == {
        "applied": 3,
        "skipped_existing": 2,
        "skipped_no_crm_entry": 4,
        "skipped_non_deterministic": 1,
        "skipped_no_workbook_row": 5,
        "healed_deleted": 6,
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
    # Flex slice must resolve INHERITED (col L "Yes" + col M source) so the
    # control is deterministic and the loop reaches the not-accepted guard;
    # otherwise the synthesized flex slice defers the control (ASSESS) and the
    # guard is never exercised.
    _install_fake_reader(
        monkeypatch,
        [_make_row(inherited="Yes", remote_inheritance="DoW Enterprise")],
    )

    def fake_finalize(
        self, row, cci, entry, *, outcome, workbook_id=None, slices=None,
        flex_statuses=None,
    ):
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
    customer-side work. ``build_crm_context`` now ALWAYS synthesizes an
    On-Premises flex slice; for the control to be deterministic that flex slice
    must resolve INHERITED via col L (the flex-slice status authority), so this
    row is col-L "Yes" + col-M source. With both clouds inheritable AND the flex
    slice inherited, the control backfills a single deterministic Assessment —
    over-deferring here would spuriously force the LLM on a fully-inherited
    control.
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
    _install_fake_reader(
        monkeypatch,
        [_make_row(inherited="Yes", remote_inheritance="DoW Enterprise")],
    )

    result = backfill_workbook_crm(workbook_id=workbook.id, session=session)

    assert result.applied == 1, (
        "all-inheritable multi-scope (incl. flex-inherited) must still backfill; "
        f"got {result.as_dict()}"
    )
    assert result.skipped_non_deterministic == 0
    session.flush()
    rows = session.exec(select(Assessment)).all()
    assert len(rows) == 1
    # Latest-wins by_control entry (Azure 'inherited') drives the verdict.
    assert rows[0].status == ComplianceStatus.COMPLIANT


def test_two_inherited_crms_backfill_per_scope_rows_and_api_serializes_both(
    session,
    workbook,
    framework,
    primary_baseline,
    control_ac2,
    objective_ac2,
    monkeypatch,
):
    """END-TO-END regression: 2 inherited CRMs → impl rows + both-cloud column Q + API.

    This is the exact flow the user hit: attach an AWS GovCloud 'inherited' CRM
    AND an Azure Government 'inherited' CRM to a FRESH workbook, let attach-time
    backfill run, then read the control via the same endpoint ControlDetail uses
    (``list_assessments``). Before the three-part fix the symptom was: parent
    narrative cited only the latest-attach cloud (Azure/Microsoft), NO
    AssessmentImplementation rows were written (control_id keying bug), and even
    if they were, the API never serialized them (so no per-scope chips rendered).

    Pins all three together:
      1. backfill writes 2 AssessmentImplementation rows (keying fix).
      2. parent narrative_q composes BOTH clouds (narratives_by_scope fix).
      3. list_assessments serializes ``implementations`` so the UI receives them.

    The prior test (test_masked_provider_only_multiscope_still_backfills) only
    asserted applied==1 + parent status — which is exactly why the missing impl
    rows / single-cloud narrative slipped through. This asserts the payload.
    """
    from cybersecurity_assessor.models import AssessmentImplementation
    from cybersecurity_assessor.routes.controls import list_assessments

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
        responsibility="inherited",
        scope_label="AWS GovCloud",
        attached_at=datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc),
        narrative="AWS GovCloud datacenters enforce physical access controls.",
    )
    _attach_crm_scoped(
        session,
        framework_id=framework.id,
        workbook_id=workbook.id,
        control_id_int=control_ac2.id,
        responsibility="inherited",
        scope_label="Azure Government",
        attached_at=datetime(2026, 2, 1, 9, 0, 0, tzinfo=timezone.utc),
        narrative="Microsoft Azure Government enforces datacenter physical access.",
    )
    # Flex slice resolves INHERITED via col L so the control is deterministic
    # (col L is the flex-slice status authority). The synthesized On-Premises
    # slice is now always present, so the control writes THREE impl rows.
    _install_fake_reader(
        monkeypatch,
        [_make_row(inherited="Yes", remote_inheritance="DoW Enterprise")],
    )

    result = backfill_workbook_crm(workbook_id=workbook.id, session=session)
    session.commit()

    # 1. Backfill ran and produced the per-scope impl rows (2 clouds + flex).
    assert result.applied == 1, f"expected one backfilled control; got {result.as_dict()}"
    impls = session.exec(select(AssessmentImplementation)).all()
    assert len(impls) == 3, (
        "two inherited CRMs + the synthesized flex slice must write three "
        f"AssessmentImplementation rows; got {len(impls)}"
    )
    assert {im.scope_label for im in impls} == {
        "AWS GovCloud", "Azure Government", "On-Premises",
    }
    assert all(im.status is ComplianceStatus.COMPLIANT for im in impls)

    # 2. Parent narrative_q composes BOTH clouds — not just the latest attach.
    parent = session.exec(select(Assessment)).one()
    assert "AWS GovCloud" in parent.narrative_q
    assert "Azure Government" in parent.narrative_q
    assert "AWS GovCloud datacenters" in parent.narrative_q
    assert "Microsoft Azure Government" in parent.narrative_q

    # 3. The API the UI calls serializes the per-scope rows so chips render.
    out = list_assessments(control_ac2.id, workbook_id=workbook.id, s=session)
    assert len(out) == 1
    api_impls = out[0]["implementations"]
    assert len(api_impls) == 3, (
        "list_assessments must serialize implementations so ControlDetail's "
        f"N-impl editor/chips activate; got {api_impls!r}"
    )
    assert {i["scope_label"] for i in api_impls} == {
        "AWS GovCloud", "Azure Government", "On-Premises",
    }
    assert "AWS GovCloud" in out[0]["narrative_q"]
    assert "Azure Government" in out[0]["narrative_q"]


def test_two_na_crms_backfill_per_scope_not_applicable(
    session,
    workbook,
    framework,
    primary_baseline,
    control_ac2,
    objective_ac2,
    monkeypatch,
):
    """Two not_applicable cloud CRMs + a non-inherited flex slice → DEFER.

    Updated 2026-06-19 for the flex-slice model. build_crm_context now always
    synthesizes an On-Premises flex slice. With col L unset, that flex slice
    resolves ASSESS (col L is the flex-slice status authority; only INHERITED is
    deterministic at backfill). Two NA clouds + one ASSESS flex slice is NOT
    fully deterministic, so the CRM backfill correctly DEFERS the control to
    assess time rather than writing a premature verdict. (An all-NA control that
    should short-circuit comes from col N "Not Applicable" via rule 8b — the
    backfill_workbook_rules path — not from the CRM N/A columns.)
    """
    from cybersecurity_assessor.models import AssessmentImplementation  # noqa: F401

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
        responsibility="not_applicable",
        scope_label="AWS GovCloud",
        attached_at=datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc),
        narrative="Not applicable on AWS GovCloud — no such surface.",
    )
    _attach_crm_scoped(
        session,
        framework_id=framework.id,
        workbook_id=workbook.id,
        control_id_int=control_ac2.id,
        responsibility="not_applicable",
        scope_label="Azure Government",
        attached_at=datetime(2026, 2, 1, 9, 0, 0, tzinfo=timezone.utc),
        narrative="Not applicable on Azure Government — no such surface.",
    )
    _install_fake_reader(monkeypatch, [_make_row()])  # col L unset → flex ASSESS

    result = backfill_workbook_crm(workbook_id=workbook.id, session=session)
    session.commit()

    # Non-deterministic (flex slice ASSESS) → deferred, no row written.
    assert result.applied == 0, f"got {result.as_dict()}"
    assert result.skipped_non_deterministic == 1
    assert session.exec(select(Assessment)).all() == []


def test_multitenant_empty_slices_defers_not_backfill(
    session,
    workbook,
    framework,
    primary_baseline,
    control_ac2,
    objective_ac2,
    monkeypatch,
):
    """A multi-tenant workbook control with EMPTY per-scope slices must DEFER.

    Reproduces the real bug: two scope-labeled CRMs (AWS GovCloud + Azure
    Government) are attached and reveal two tenant labels via OTHER controls —
    but the assessed control AC-2 has only an UNLABELED inherited CRM entry, so
    ``build_crm_context`` produces NO per-scope slices for it. Because the
    workbook is genuinely multi-tenant (distinct_scope_label_count >= 2), the
    single latest-attach-wins "inherited" entry must NOT backfill COMPLIANT —
    that would mask the other tenant's customer obligation with no LLM call. It
    must skip as non-deterministic and defer to assess time.
    """
    _attach_in_scope(
        session,
        baseline_id=primary_baseline.id,
        control_id_int=control_ac2.id,
        objective_id_int=objective_ac2.id,
    )
    # Two SCOPE-LABELED CRMs establish the multi-tenant context. They cover a
    # different control (ac-9) so AC-2 itself has no per-scope slices.
    other = Control(
        framework_id=framework.id, control_id="ac-9", title="Other", family="AC"
    )
    session.add(other)
    session.commit()
    session.refresh(other)
    _attach_crm_scoped(
        session, framework_id=framework.id, workbook_id=workbook.id,
        control_id_int=other.id, responsibility="customer",
        scope_label="AWS GovCloud",
        attached_at=datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc),
    )
    _attach_crm_scoped(
        session, framework_id=framework.id, workbook_id=workbook.id,
        control_id_int=other.id, responsibility="inherited",
        scope_label="Azure Government",
        attached_at=datetime(2026, 2, 1, 9, 0, 0, tzinfo=timezone.utc),
    )
    # AC-2 (the assessed control) gets an UNLABELED inherited CRM entry -> no
    # slices for it, but the legacy by_control entry says "inherited".
    _attach_crm(
        session,
        framework_id=framework.id,
        workbook_id=workbook.id,
        control_id_int=control_ac2.id,
        responsibility="inherited",
        narrative="Inherited (unlabeled).",
    )
    _install_fake_reader(monkeypatch, [_make_row()])

    result = backfill_workbook_crm(workbook_id=workbook.id, session=session)

    assert result.applied == 0, (
        "multi-tenant empty-slices control must NOT auto-backfill; "
        f"got {result.as_dict()}"
    )
    assert result.skipped_non_deterministic == 1
    assert session.exec(select(Assessment)).all() == []


# ---------------------------------------------------------------------------
# Self-heal: attach-order independence (the AC-17 / PE-3 production bug)
# ---------------------------------------------------------------------------


def test_self_heal_deterministic_then_customer_deletes_stale_row(
    session,
    workbook,
    framework,
    primary_baseline,
    control_ac2,
    objective_ac2,
    monkeypatch,
):
    """AC-17 bug: inherited CRM attached first, customer CRM attached second.

    First attach (Azure inherited) writes a deterministic Compliant row. Second
    attach (AWS customer) makes the control customer/hybrid — it must now defer
    to the LLM. The self-heal deletes the stale system-written deterministic
    row so no frozen single-scope Compliant survives.

    Col L is "Yes" + col M source so the synthesized flex slice resolves
    INHERITED — required for attach #1 to be deterministic and write a row
    (flex ASSESS would defer it and there'd be nothing to self-heal). The
    customer CLOUD slice from attach #2 is what makes the control
    non-deterministic, independent of the flex slice.
    """
    _attach_in_scope(
        session,
        baseline_id=primary_baseline.id,
        control_id_int=control_ac2.id,
        objective_id_int=objective_ac2.id,
    )
    _install_fake_reader(
        monkeypatch,
        [_make_row(inherited="Yes", remote_inheritance="DoW Enterprise")],
    )

    # Attach #1 — Azure inherited (deterministic) → backfill writes a row.
    _attach_crm_scoped(
        session,
        framework_id=framework.id,
        workbook_id=workbook.id,
        control_id_int=control_ac2.id,
        responsibility="inherited",
        scope_label="Azure Government",
        attached_at=datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc),
        narrative="Inherited via managed Azure plane.",
    )
    r1 = backfill_workbook_crm(workbook_id=workbook.id, session=session)
    session.commit()
    assert r1.applied == 1
    assert len(session.exec(select(Assessment)).all()) == 1

    # Attach #2 — AWS customer → control is now customer/hybrid.
    _attach_crm_scoped(
        session,
        framework_id=framework.id,
        workbook_id=workbook.id,
        control_id_int=control_ac2.id,
        responsibility="customer",
        scope_label="AWS GovCloud",
        attached_at=datetime(2026, 2, 1, 9, 0, 0, tzinfo=timezone.utc),
        narrative="Customer configures AWS Client VPN.",
    )
    r2 = backfill_workbook_crm(workbook_id=workbook.id, session=session)
    session.commit()

    # The stale deterministic row was healed (deleted); control now defers.
    assert r2.healed_deleted == 1, f"expected self-heal delete; got {r2.as_dict()}"
    assert session.exec(select(Assessment)).all() == [], (
        "stale single-scope deterministic row must be deleted so the control "
        "defers to the LLM"
    )
    impls = session.exec(select(AssessmentImplementation)).all()
    assert impls == [], "impl rows of the deleted assessment must be removed too"


def test_self_heal_never_stomps_user_edited_row(
    session,
    workbook,
    framework,
    primary_baseline,
    control_ac2,
    objective_ac2,
    monkeypatch,
):
    """A human-edited assessment is NEVER deleted by the self-heal path.

    Even when the control becomes customer/hybrid (which would normally delete a
    system-written deterministic row), a row whose tester is a human / whose
    verdict_source is not a backfill source must survive untouched.
    """
    from cybersecurity_assessor.models import VerdictSource

    _attach_in_scope(
        session,
        baseline_id=primary_baseline.id,
        control_id_int=control_ac2.id,
        objective_id_int=objective_ac2.id,
    )
    _install_fake_reader(monkeypatch, [_make_row()])

    # Seed a human-edited assessment for this objective.
    human = Assessment(
        workbook_id=workbook.id,
        objective_id=objective_ac2.id,
        excel_row=1,
        status=ComplianceStatus.COMPLIANT,
        tester="Noah Jaskolski",
        date_tested=datetime(2026, 1, 1, tzinfo=timezone.utc),
        narrative_q="Human-reviewed and confirmed.",
        narrative_class=NarrativeClass.COMPLIANCE_AFFIRMING,
        verdict_source=VerdictSource.LLM_ACCEPT,
        needs_review=False,
    )
    session.add(human)
    session.commit()

    # Attach a customer CRM that would make the control non-deterministic.
    _attach_crm_scoped(
        session,
        framework_id=framework.id,
        workbook_id=workbook.id,
        control_id_int=control_ac2.id,
        responsibility="customer",
        scope_label="AWS GovCloud",
        attached_at=datetime(2026, 2, 1, 9, 0, 0, tzinfo=timezone.utc),
        narrative="Customer-owned.",
    )
    result = backfill_workbook_crm(workbook_id=workbook.id, session=session)
    session.commit()

    assert result.healed_deleted == 0, "must NOT delete a human-edited row"
    survivors = session.exec(select(Assessment)).all()
    assert len(survivors) == 1
    assert survivors[0].tester == "Noah Jaskolski"


# ---------------------------------------------------------------------------
# Deterministic-RULE backfill (AC-18 col-N Not Applicable)
# ---------------------------------------------------------------------------


def test_rule_backfill_writes_col_n_not_applicable(
    session,
    workbook,
    framework,
    primary_baseline,
    control_ac2,
    objective_ac2,
    monkeypatch,
):
    """A workbook col-N 'Not Applicable' row surfaces via rule backfill.

    The AC-18 bug: a control marked Not Applicable in the workbook had no
    auto-writer (only CRM controls were backfilled), so it showed a blank chip.
    backfill_workbook_rules classifies the row (rule_8b) and writes a parent
    NOT_APPLICABLE assessment with no per-scope impl rows.
    """
    _attach_in_scope(
        session,
        baseline_id=primary_baseline.id,
        control_id_int=control_ac2.id,
        objective_id_int=objective_ac2.id,
    )
    na_row = _make_row()
    na_row.status = "Not Applicable"
    na_row.results = "System has no wireless capability; control out of scope."
    _install_fake_reader(monkeypatch, [na_row])

    result = backfill_workbook_rules(workbook_id=workbook.id, session=session)
    session.commit()

    assert result.applied == 1, f"expected one rule backfill; got {result.as_dict()}"
    rows = session.exec(select(Assessment)).all()
    assert len(rows) == 1
    assert rows[0].status is ComplianceStatus.NOT_APPLICABLE
    assert rows[0].inheritance_rule == "8b"
    # No CRM slices → parent-only row.
    assert session.exec(select(AssessmentImplementation)).all() == []

    # Idempotent: re-run writes nothing.
    again = backfill_workbook_rules(workbook_id=workbook.id, session=session)
    assert again.applied == 0
    assert again.skipped_existing == 1


def test_rule_backfill_skips_no_auto_rule_rows(
    session,
    workbook,
    framework,
    primary_baseline,
    control_ac2,
    objective_ac2,
    monkeypatch,
):
    """A plain gap row (no col-N status, no rule trigger) is left for the LLM."""
    _install_fake_reader(monkeypatch, [_make_row()])
    _attach_in_scope(
        session,
        baseline_id=primary_baseline.id,
        control_id_int=control_ac2.id,
        objective_id_int=objective_ac2.id,
    )
    result = backfill_workbook_rules(workbook_id=workbook.id, session=session)
    assert result.applied == 0
    assert result.skipped_no_rule == 1
    assert session.exec(select(Assessment)).all() == []
