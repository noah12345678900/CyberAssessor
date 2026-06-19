"""Property-based tests for the CRM attach-time backfill.

The example suite at ``backend/tests/engine/test_crm_backfill.py`` pins
specific branches: each early-return guard, each skip counter, each
happy-path (provider, inherited, not_applicable). This file fuzzes the
(in-scope corpus × CRM responsibility mix × pre-existing assessments)
input space so a refactor that broke an invariant in a corner of the
input set gets caught:

  1. **Counter partition totality.** The five counters
     (applied, skipped_existing, skipped_no_crm_entry,
     skipped_non_deterministic, skipped_no_workbook_row) MUST sum to the
     in-scope pair count. A regression that added a new skip branch
     without bumping a counter would leave a count gap; the route
     handler's "explain what happened" payload would silently understate
     the work and confuse the user.

  2. **Idempotency.** A second call to ``backfill_workbook_crm`` produces
     zero new ``applied`` rows and bumps ``skipped_existing`` by exactly
     the first call's ``applied`` count. The patent-supporting
     "attach-time write" claim depends on re-attaching the same CRM
     (or attaching a second overlapping CRM) being a no-op rather than
     double-writing the Assessment row.

  3. **Non-stomping.** Pre-existing Assessment rows are never overwritten
     regardless of CRM input — status, tester, and narrative of every
     pre-existing row are byte-for-byte identical after backfill. A
     regression here would silently destroy reviewer edits or prior
     LLM-run results that the user trusted to be preserved.

  4. **Deterministic responsibilities are exhaustive.** For any corpus
     whose every CRM entry is hybrid or customer, ``applied == 0`` and
     ``skipped_non_deterministic == (matching CCI count)``. Inverts to
     pin "non-deterministic" classification: hybrid/customer MUST defer
     to assess-time LLM, never write at attach time.

  5. **Status mapping integrity.** For every applied row the persisted
     ``status`` matches the responsibility-to-status table verbatim
     (provider→NA, inherited→Compliant, not_applicable→NA). A typo
     in the mapping that mis-routed inherited to "Not Applicable" would
     silently waste compliance credit.

  6. **In-scope filter totality.** Out-of-scope BaselineControl rows
     never produce an Assessment row regardless of CRM input.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")

from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

# Ensure backend is importable regardless of pytest cwd. tests/conftest.py
# already does this, but property tests sometimes run in isolation during
# test development — belt-and-braces.
_BACKEND = Path(__file__).resolve().parents[2] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.engine import crm_backfill  # noqa: E402
from cybersecurity_assessor.engine.crm_backfill import (  # noqa: E402
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
# Strategies
# ---------------------------------------------------------------------------


# 5 valid responsibility values + the "no CRM entry" sentinel. The
# backfill must handle all five distinct responsibilities AND the
# "control listed in scope but absent from any CRM" case.
_RESPONSIBILITY = st.one_of(
    st.sampled_from(["provider", "inherited", "not_applicable", "hybrid", "customer"]),
    st.none(),  # represents "no CRM entry for this control"
)


# A small but non-trivial control corpus (1-6 controls per case). Each
# case fits in a single in-memory SQLite session without blowing up the
# Hypothesis time budget; that range still hits the partition-totality
# math hard enough to find a missing counter.
_CORPUS = st.lists(_RESPONSIBILITY, min_size=1, max_size=6)


# Deterministic responsibilities — the only ones that write Assessment
# rows at backfill time. Used by the status-mapping property to assert
# the exact persisted status per row.
_DETERMINISTIC_TO_STATUS = {
    "provider": ComplianceStatus.NOT_APPLICABLE,
    "inherited": ComplianceStatus.COMPLIANT,
    "not_applicable": ComplianceStatus.NOT_APPLICABLE,
}


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    """In-memory SQLite, single shared connection per Hypothesis example.

    Each Hypothesis example wipes & rebuilds inside the body — see
    ``_setup_corpus`` — so this fixture is per-test, not per-example.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def workbook_file(tmp_path) -> Path:
    """Real file on disk so ``Path(wb.path).exists()`` is True."""
    p = tmp_path / "wb.xlsx"
    p.write_bytes(b"")  # read_workbook_index is monkeypatched
    return p


def _wipe(session: Session) -> None:
    """Drop every row Hypothesis might have inserted last example.

    Each example rebuilds the whole corpus; without this, prior-example
    rows would inflate the counters and tank every property assertion.
    Order respects FK relationships (children before parents).
    """
    for table in (
        Assessment, WorkbookOverlay, BaselineObjective, BaselineControl,
        Objective, Control, Workbook, Baseline, Framework,
    ):
        for row in session.exec(select(table)).all():
            session.delete(row)
    session.commit()


def _make_row(
    *,
    excel_row: int,
    control_id: str,
    cci_id: str,
) -> CcisRow:
    """Minimal CcisRow — only fields backfill touches."""
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


def _setup_corpus(
    session: Session,
    workbook_file: Path,
    corpus: list[str | None],
    monkeypatch: pytest.MonkeyPatch,
    *,
    in_scope_overrides: list[bool] | None = None,
) -> tuple[int, list[int], list[CcisRow]]:
    """Build a fresh DB + faked workbook for one Hypothesis example.

    Returns (workbook_id, list[objective_id], list[CcisRow]) so the
    test body can assert against the inserted shape.

    ``corpus[i] is None`` means "control i is in-scope but has no CRM
    entry". Otherwise corpus[i] is the responsibility value attached
    to that control's CRM overlay.

    ``in_scope_overrides[i]`` lets the in-scope-filter property mark
    selected controls as out-of-scope. Defaults to all in-scope.
    """
    _wipe(session)
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)

    primary = Baseline(
        framework_id=fw.id,
        name="primary",
        source_type=BaselineSourceType.CCIS_WORKBOOK,
    )
    session.add(primary)
    session.commit()
    session.refresh(primary)

    wb = Workbook(
        path=str(workbook_file),
        filename=workbook_file.name,
        baseline_id=primary.id,
    )
    session.add(wb)
    session.commit()
    session.refresh(wb)

    rows: list[CcisRow] = []
    obj_ids: list[int] = []
    crm_baselines_by_resp: dict[str, Baseline] = {}

    for i, resp in enumerate(corpus):
        cid_text = f"ac-{i + 1}"
        cci_text = f"CCI-{i + 1:06d}"
        excel_row = 100 + i

        control = Control(
            framework_id=fw.id,
            control_id=cid_text,
            title=f"Control {cid_text}",
            family="AC",
        )
        session.add(control)
        session.commit()
        session.refresh(control)

        obj = Objective(
            control_id_fk=control.id,
            objective_id=cci_text,
            source="CCI",
            text=f"Objective {cci_text}",
        )
        session.add(obj)
        session.commit()
        session.refresh(obj)
        obj_ids.append(obj.id)

        in_scope = (
            in_scope_overrides[i] if in_scope_overrides is not None else True
        )
        session.add(
            BaselineControl(
                baseline_id=primary.id,
                control_id=control.id,
                in_scope=in_scope,
            )
        )
        session.add(
            BaselineObjective(
                baseline_id=primary.id,
                objective_id=obj.id,
                source_row=excel_row,
            )
        )
        session.commit()

        if resp is not None:
            # One CRM baseline per distinct responsibility — keeps the
            # WorkbookOverlay rows small while still exercising the
            # build_crm_context join across multiple overlays.
            crm = crm_baselines_by_resp.get(resp)
            if crm is None:
                crm = Baseline(
                    framework_id=fw.id,
                    name=f"CRM-{resp}",
                    source_type=BaselineSourceType.CRM,
                )
                session.add(crm)
                session.commit()
                session.refresh(crm)
                session.add(
                    WorkbookOverlay(
                        workbook_id=wb.id,
                        baseline_id=crm.id,
                        attached_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                    )
                )
                session.commit()
                crm_baselines_by_resp[resp] = crm
            session.add(
                BaselineControl(
                    baseline_id=crm.id,
                    control_id=control.id,
                    in_scope=True,
                    responsibility=resp,
                    responsibility_narrative=None,
                )
            )
            session.commit()

        rows.append(
            _make_row(excel_row=excel_row, control_id=cid_text.upper(), cci_id=cci_text)
        )

    fake_index = CcisIndex(
        workbook_path=Path("unused.xlsx"),
        sheet_name="WORKING SHEET",
        rows=rows,
    )
    monkeypatch.setattr(
        crm_backfill, "read_workbook_index", lambda _path: fake_index
    )
    return wb.id, obj_ids, rows


# ---------------------------------------------------------------------------
# Counter partition totality
# ---------------------------------------------------------------------------


@given(corpus=_CORPUS)
@settings(max_examples=40, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_counters_partition_in_scope_pairs(
    corpus, session, workbook_file, monkeypatch
):
    """Counters sum to the in-scope pair count — every row is accounted for.

    The route handler's payload tells the user "we wrote N rows and
    skipped M for these reasons"; the counters are the only thing the
    UI can show. If a refactor added a new skip branch but forgot a
    counter, this assertion catches the missing accounting before
    review-queue numbers start contradicting themselves.

    Edge case: when the corpus has at least one None entry AND at least
    one CRM-mapped entry, ``build_crm_context`` is non-empty so we don't
    hit the "no CRM overlays" early-return. With every entry None, the
    early-return fires and totals are all-zero (also covered here).
    """
    wb_id, _, _ = _setup_corpus(session, workbook_file, corpus, monkeypatch)
    result = backfill_workbook_crm(wb_id, session)
    session.commit()

    total = (
        result.applied
        + result.skipped_existing
        + result.skipped_no_crm_entry
        + result.skipped_non_deterministic
        + result.skipped_no_workbook_row
    )
    # All-None corpus hits the "no CRM overlays" early-return → all-zeros.
    if all(r is None for r in corpus):
        assert total == 0
    else:
        assert total == len(corpus)


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


@given(corpus=_CORPUS)
@settings(max_examples=30, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_backfill_is_idempotent(corpus, session, workbook_file, monkeypatch):
    """Second call to backfill applies zero new rows.

    The patent-supporting "attach-time write" claim depends on a re-
    attach (or a second CRM overlay) being safe to call. If idempotency
    drifted, attaching the same CRM twice would double-write the
    Assessment row — silently corrupting the report.
    """
    wb_id, _, _ = _setup_corpus(session, workbook_file, corpus, monkeypatch)
    first = backfill_workbook_crm(wb_id, session)
    session.commit()

    second = backfill_workbook_crm(wb_id, session)
    session.commit()

    assert second.applied == 0
    # Every row first-call applied appears in second-call's skip-existing
    # bucket. The other skip counters (no_entry, non_det, no_row) carry
    # over unchanged because the input shape hasn't changed.
    assert second.skipped_existing == first.applied + first.skipped_existing
    assert second.skipped_no_crm_entry == first.skipped_no_crm_entry
    assert second.skipped_non_deterministic == first.skipped_non_deterministic
    assert second.skipped_no_workbook_row == first.skipped_no_workbook_row


# ---------------------------------------------------------------------------
# Non-stomping — pre-existing Assessment rows are untouched
# ---------------------------------------------------------------------------


@given(corpus=_CORPUS)
@settings(max_examples=30, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_preexisting_assessment_rows_are_never_stomped(
    corpus, session, workbook_file, monkeypatch
):
    """Pre-existing Assessment rows survive backfill byte-for-byte.

    Plants a sentinel Assessment row for the first objective BEFORE
    backfill, with a clearly-not-default tester name and status. After
    backfill the row must be unchanged — same status, same tester,
    same narrative. A regression that switched the "skip existing"
    branch to "update existing" would silently destroy reviewer edits.
    """
    wb_id, obj_ids, _ = _setup_corpus(
        session, workbook_file, corpus, monkeypatch
    )
    if not obj_ids:
        return  # nothing to plant against

    sentinel_obj = obj_ids[0]
    sentinel = Assessment(
        workbook_id=wb_id,
        objective_id=sentinel_obj,
        excel_row=100,
        status=ComplianceStatus.NON_COMPLIANT,
        tester="reviewer-do-not-touch",
        narrative_q="SENTINEL — must survive backfill",
        narrative_class=NarrativeClass.GAP_DESCRIBING,
        date_tested=datetime(2025, 12, 31, tzinfo=timezone.utc),
    )
    session.add(sentinel)
    session.commit()

    backfill_workbook_crm(wb_id, session)
    session.commit()

    survivor = session.exec(
        select(Assessment).where(
            Assessment.workbook_id == wb_id,
            Assessment.objective_id == sentinel_obj,
        )
    ).all()
    # MUST be exactly one row — backfill never inserted a second.
    assert len(survivor) == 1
    row = survivor[0]
    assert row.status == ComplianceStatus.NON_COMPLIANT
    assert row.tester == "reviewer-do-not-touch"
    assert row.narrative_q == "SENTINEL — must survive backfill"


# ---------------------------------------------------------------------------
# Non-deterministic responsibilities never write
# ---------------------------------------------------------------------------


@given(
    # Every responsibility is hybrid or customer — both deferred to LLM.
    corpus=st.lists(
        st.sampled_from(["hybrid", "customer"]),
        min_size=1, max_size=6,
    ),
)
@settings(max_examples=25, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_non_deterministic_responsibilities_never_apply(
    corpus, session, workbook_file, monkeypatch
):
    """All-hybrid / all-customer corpora produce zero applied rows.

    Pins the contract that distinguishes "attach-time deterministic
    short-circuit" from "assess-time LLM proposal" — hybrid prepends a
    scoping block at LLM time, customer is the no-op default. Either
    being written at attach time would skip the LLM entirely and
    silently lose those scoping/review steps.
    """
    wb_id, _, _ = _setup_corpus(session, workbook_file, corpus, monkeypatch)
    result = backfill_workbook_crm(wb_id, session)
    session.commit()
    assert result.applied == 0
    assert result.skipped_non_deterministic == len(corpus)


# ---------------------------------------------------------------------------
# Status mapping integrity
# ---------------------------------------------------------------------------


@given(
    corpus=st.lists(
        st.sampled_from(["provider", "inherited", "not_applicable"]),
        min_size=1, max_size=6,
    ),
)
@settings(max_examples=30, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_status_mapping_matches_responsibility_table(
    corpus, session, workbook_file, monkeypatch
):
    """Every applied row's status matches the deterministic mapping.

    Detects a typo / sign-flip in the responsibility→status table that
    would silently mis-classify entire control families (e.g. inherited
    routed to "Not Applicable" would silently waste compliance credit
    on every inherited control in every program).
    """
    wb_id, obj_ids, _ = _setup_corpus(
        session, workbook_file, corpus, monkeypatch
    )
    backfill_workbook_crm(wb_id, session)
    session.commit()

    written = {
        a.objective_id: a
        for a in session.exec(
            select(Assessment).where(Assessment.workbook_id == wb_id)
        ).all()
    }
    # Every CCI in the corpus was deterministic, so every objective
    # MUST have produced a row.
    assert len(written) == len(corpus)
    for i, resp in enumerate(corpus):
        row = written[obj_ids[i]]
        assert row.status == _DETERMINISTIC_TO_STATUS[resp], (
            f"control {i} responsibility={resp!r} expected "
            f"{_DETERMINISTIC_TO_STATUS[resp]} got {row.status}"
        )


# ---------------------------------------------------------------------------
# In-scope filter totality
# ---------------------------------------------------------------------------


@given(
    # Every responsibility is deterministic (provider) so the only thing
    # gating an applied row is the in-scope flag. Use 1-6 controls;
    # half_in_scope mask picks which are in-scope.
    n=st.integers(min_value=1, max_value=6),
    mask=st.lists(st.booleans(), min_size=1, max_size=6),
)
@settings(max_examples=25, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_out_of_scope_controls_never_apply(
    n, mask, session, workbook_file, monkeypatch
):
    """OOS controls produce zero Assessment rows regardless of CRM.

    The in-scope flag on BaselineControl is the user's "skip this
    control" lever. A backfill that ignored it would write rows the
    user explicitly excluded from scope — corrupting the workbook
    after a fresh attach without any user action.
    """
    # Align mask length with n (Hypothesis generates them independently).
    while len(mask) < n:
        mask.append(True)
    mask = mask[:n]
    corpus = ["provider"] * n
    wb_id, obj_ids, _ = _setup_corpus(
        session, workbook_file, corpus, monkeypatch, in_scope_overrides=mask
    )
    result = backfill_workbook_crm(wb_id, session)
    session.commit()
    in_scope_count = sum(mask)
    # Only in-scope deterministic controls produced rows.
    assert result.applied == in_scope_count
    written_obj_ids = {
        a.objective_id
        for a in session.exec(
            select(Assessment).where(Assessment.workbook_id == wb_id)
        ).all()
    }
    expected_obj_ids = {
        obj_ids[i] for i, in_scope in enumerate(mask) if in_scope
    }
    assert written_obj_ids == expected_obj_ids


# ---------------------------------------------------------------------------
# Result shape — every counter is a non-negative int (defensive sanity guard)
# ---------------------------------------------------------------------------


@given(corpus=_CORPUS)
@settings(max_examples=20, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_all_counters_are_non_negative_ints(
    corpus, session, workbook_file, monkeypatch
):
    """No counter is ever negative or non-int.

    A subtraction-based counter implementation (e.g. ``applied =
    total - skipped``) could under/overflow on edge inputs. This
    catches such a refactor before it ships.
    """
    wb_id, _, _ = _setup_corpus(session, workbook_file, corpus, monkeypatch)
    result = backfill_workbook_crm(wb_id, session)
    session.commit()
    for name, val in result.as_dict().items():
        assert isinstance(val, int), f"{name} is {type(val).__name__}, not int"
        assert val >= 0, f"{name} is negative: {val}"


# ---------------------------------------------------------------------------
# Flex-slice (pie-slice model) backfill — Column L drives the synthesized
# On-Premises/workbook slice's status, NOT the CRM. Regression for PE-3
# (clouds inherited + col L = named source) showing "—" because the backfill
# deferred the whole control to the LLM on the flex slice's "customer" label.
# ---------------------------------------------------------------------------


def _setup_flex_control(
    session, workbook_file, monkeypatch, *, col_l: str, col_m: str | None = None
):
    """One control inherited on TWO scope-labeled cloud CRMs (AWS + Azure),
    with the given Column-L flag (+ optional Column-M source) on the workbook
    row. Scope-labeled CRMs cause build_crm_context to synthesize the
    On-Premises flex slice. Owner convention: col L is a flag (Remote/Yes =>
    inherited, source in col M); col M names the source."""
    _wipe(session)
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw); session.commit(); session.refresh(fw)
    primary = Baseline(framework_id=fw.id, name="primary",
                       source_type=BaselineSourceType.CCIS_WORKBOOK)
    session.add(primary); session.commit(); session.refresh(primary)
    wb = Workbook(path=str(workbook_file), filename=workbook_file.name,
                  baseline_id=primary.id)
    session.add(wb); session.commit(); session.refresh(wb)

    control = Control(framework_id=fw.id, control_id="pe-3",
                      title="Physical Access Control", family="PE")
    session.add(control); session.commit(); session.refresh(control)
    obj = Objective(control_id_fk=control.id, objective_id="CCI-000919",
                    source="CCI", text="Physical access")
    session.add(obj); session.commit(); session.refresh(obj)
    session.add(BaselineControl(baseline_id=primary.id, control_id=control.id,
                                in_scope=True))
    session.add(BaselineObjective(baseline_id=primary.id, objective_id=obj.id,
                                  source_row=100))
    session.commit()

    for label in ("AWS GovCloud", "Azure Government"):
        crm = Baseline(framework_id=fw.id, name=f"CRM-{label}",
                       source_type=BaselineSourceType.CRM, scope_label=label)
        session.add(crm); session.commit(); session.refresh(crm)
        session.add(WorkbookOverlay(workbook_id=wb.id, baseline_id=crm.id,
                                    attached_at=datetime(2026, 1, 1, tzinfo=timezone.utc)))
        session.add(BaselineControl(baseline_id=crm.id, control_id=control.id,
                                    in_scope=True, responsibility="inherited",
                                    responsibility_narrative=f"{label} inherits"))
        session.commit()

    row = _make_row(excel_row=100, control_id="PE-3", cci_id="CCI-000919")
    row.inherited = col_l  # Column L (flag)
    row.remote_inheritance = col_m  # Column M (source)
    fake_index = CcisIndex(workbook_path=Path("unused.xlsx"),
                           sheet_name="WORKING SHEET", rows=[row])
    monkeypatch.setattr(crm_backfill, "read_workbook_index", lambda _p: fake_index)
    return wb.id, obj.id


def test_flex_col_l_inherited_backfills_compliant(session, workbook_file, monkeypatch):
    """PE-3: clouds inherited + Column L names an inheritance source
    ("DoW Enterprise" → INHERITED) → backfill auto-writes COMPLIANT with all
    three scopes Compliant. (Regression: previously deferred → "—".)"""
    wb_id, obj_id = _setup_flex_control(
        session, workbook_file, monkeypatch, col_l="Remote", col_m="DoW Enterprise"
    )
    result = backfill_workbook_crm(wb_id, session)
    session.commit()
    assert result.applied == 1
    a = session.exec(select(Assessment).where(Assessment.objective_id == obj_id)).one()
    assert a.status is ComplianceStatus.COMPLIANT
    impls = {
        im.scope_label: im.status
        for im in session.exec(
            select(crm_backfill.AssessmentImplementation).where(
                crm_backfill.AssessmentImplementation.assessment_id == a.id
            )
        )
    }
    assert impls.get("On-Premises") is ComplianceStatus.COMPLIANT
    assert impls.get("AWS GovCloud") is ComplianceStatus.COMPLIANT
    assert impls.get("Azure Government") is ComplianceStatus.COMPLIANT


def test_flex_col_l_assess_defers_to_llm(session, workbook_file, monkeypatch):
    """Column L = "No" (ASSESS) → the flex outcome depends on assess-time
    evidence (NC-on-no-evidence), which backfill runs before. So backfill must
    DEFER (write nothing), not write a premature verdict."""
    wb_id, obj_id = _setup_flex_control(
        session, workbook_file, monkeypatch, col_l="No"
    )
    result = backfill_workbook_crm(wb_id, session)
    session.commit()
    assert result.applied == 0
    assert result.skipped_non_deterministic == 1
    rows = session.exec(select(Assessment).where(Assessment.objective_id == obj_id)).all()
    assert rows == []
