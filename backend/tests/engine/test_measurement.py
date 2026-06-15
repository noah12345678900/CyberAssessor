"""Golden tests for the RunRecorder edges the e2e suite doesn't reach.

``test_assessor_e2e.py`` and ``test_assessor_outcome_branches.py`` exercise
the RunRecorder through the assessor — they cover ``start``, ``cci`` ctx,
``_commit_outcome`` (via ``__exit__``), and the aggregation in ``finish``
for accepted/rejected/supersession/retry paths. What they don't cover are
the two purely-mechanical accessors:

* **``run_id`` property** (``measurement.py:146``) — read by the route
  handler so it can return ``{"run_id": ...}`` to the UI right after
  ``start`` and before ``finish``. If this regressed to ``None`` or
  raised, the UI would lose its handle on the in-flight run and the
  user-visible progress card would never bind.
* **``cost_usd`` setter on ``finish``** (``measurement.py:174``) — the
  one cost-side number the assessor passes through (the rest of the
  ``finish`` aggregation is accuracy-only and covered elsewhere). Pin
  that ``finish(cost_usd=...)`` actually writes through, so when the
  pricing module starts producing real numbers in v0.2 they land on the
  row the patent audit reads.

Both are one-line getter/setter sites where a refactor (e.g. renaming
``self._run`` to ``self._assessment_run``) could break the contract
silently — no LLM/validator path exercises either.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- register tables
from cybersecurity_assessor.engine.measurement import RunRecorder  # noqa: E402
from cybersecurity_assessor.models import AssessmentRun, Workbook  # noqa: E402


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def workbook(session) -> Workbook:
    wb = Workbook(path="/tmp/test.xlsx", filename="test.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb


def test_run_id_property_exposes_persisted_id_after_start(session, workbook):
    """``RunRecorder.start`` flushes the AssessmentRun row → ``run_id`` is the integer PK.

    Pins measurement.py:146. ``start`` calls ``session.refresh(run)`` so
    the auto-assigned PK is available before ``finish`` is called — the
    route handler uses ``rec.run_id`` to return ``{"run_id": ...}`` to
    the UI right after kickoff, so the user can poll for progress. If
    the refresh ever moved (or ``_run.id`` was nulled out somewhere
    between start and the first cci context), the UI would lose its
    handle. Pin the contract: ``run_id`` is a real int as soon as
    ``start`` returns, with no cci contexts in between.
    """
    rec = RunRecorder.start(session, workbook_id=workbook.id)

    assert rec.run_id is not None
    assert isinstance(rec.run_id, int)
    # And it matches what's actually on disk — start did persist.
    persisted = session.exec(
        select(AssessmentRun).where(AssessmentRun.id == rec.run_id)
    ).one()
    assert persisted.workbook_id == workbook.id


def test_finish_writes_cost_usd_when_provided(session, workbook):
    """``finish(cost_usd=0.0182)`` → persisted row has ``cost_usd == 0.0182``.

    Pins measurement.py:174. ``cost_usd`` is the only cost-side field
    the recorder accepts as a kwarg on finish — the rest of the
    aggregation reads from the accumulator. The pricing module (not yet
    in v0.1) will eventually call ``finish(cost_usd=...)`` per run; pin
    the write-through so the wiring is ready and a future regression
    (e.g. renaming the kwarg) would surface here before it silently
    zeroed cost on every run.
    """
    rec = RunRecorder.start(session, workbook_id=workbook.id)
    # No cci contexts — finish should still write cost_usd through.

    run = rec.finish(cost_usd=0.0182)

    assert run.cost_usd == pytest.approx(0.0182)
    # And it's persisted, not just on the in-memory object.
    persisted = session.exec(
        select(AssessmentRun).where(AssessmentRun.id == run.id)
    ).one()
    assert persisted.cost_usd == pytest.approx(0.0182)


def test_finish_without_cost_leaves_cost_usd_unset(session, workbook):
    """``finish()`` with no kwarg → cost_usd stays at its default (None / 0).

    Belt-and-braces for the line 173 conditional (``if cost_usd is not
    None``). Without this guard, a refactor that always wrote the kwarg
    through would clobber pre-existing cost values during multi-stage
    finish flows (none today, but the contract guards against it). Pin
    that omitting the kwarg is a no-op on the cost field.
    """
    rec = RunRecorder.start(session, workbook_id=workbook.id)

    run = rec.finish()

    # Field defaults to 0.0 on a fresh AssessmentRun (models.py:581); the
    # missing-kwarg branch must leave that default alone (never write None,
    # never raise — the conditional at measurement.py:173 is the guard).
    assert run.cost_usd == 0.0
