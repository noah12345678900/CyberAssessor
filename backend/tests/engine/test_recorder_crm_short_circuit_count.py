"""Unit tests for ``AssessmentRun.crm_short_circuit_count``.

Drives ``RunRecorder`` directly with hand-synthesized ``CciOutcome``
objects — no assessor pipeline, no LLM call, no DB round-trip beyond
in-memory SQLite. Same shape as the rule-#8 short-circuit aggregator
coverage, just pointed at the CRM sibling counter.

These pin the aggregator contract:

* ``crm_short_circuit_count`` counts CciOutcome rows whose
  ``crm_short_circuit`` attribute is non-None.
* All three responsibility buckets (provider / inherited /
  not_applicable) participate — the counter is inclusive across the
  whole CRM short-circuit cohort, not just one responsibility flavor.
* customer / hybrid outcomes (which leave ``crm_short_circuit=None``
  because the LLM ran) do NOT participate. The counter is the
  "kernel skipped the LLM via CRM" number, not "controls touched by
  any CRM."
* Empty run → 0 (no garbage write when no CRM is attached at all).

The end-to-end assessor → DB column round-trip lives in
``tests/routes/test_crm_short_circuit_persistence.py``; this file
isolates the aggregator math from every other moving piece in the
pipeline so a regression points straight at ``_apply_aggregates``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- register tables
from cybersecurity_assessor.engine.measurement import (  # noqa: E402
    CrmShortCircuit,
    RunRecorder,
)
from cybersecurity_assessor.models import Workbook  # noqa: E402


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


def _short_circuit(cci: str, responsibility: str, control_id: str = "AC-1") -> CrmShortCircuit:
    """Construct a CrmShortCircuit with sensible defaults — only the
    responsibility bucket matters for the counter aggregation."""
    return CrmShortCircuit(
        cci=cci,
        control_id=control_id,
        responsibility=responsibility,  # type: ignore[arg-type]
        baseline_id=1,
    )


def test_provider_inherited_not_applicable_each_count_one(session, workbook):
    """All three CRM responsibility buckets participate in the counter.

    The CRM short-circuit kernel fires on provider, inherited, AND
    not_applicable — the counter must be inclusive of all three. Pin
    the contract by exercising one outcome of each kind and asserting
    the sum is 3, not 1 (which would mean the aggregator filtered on
    one specific responsibility) and not 0 (which would mean the
    sentinel check is wrong).
    """
    rec = RunRecorder.start(session, workbook_id=workbook.id)
    with rec.cci("CCI-000001") as o:
        o.crm_short_circuit = _short_circuit("CCI-000001", "provider")
    with rec.cci("CCI-000002") as o:
        o.crm_short_circuit = _short_circuit("CCI-000002", "inherited")
    with rec.cci("CCI-000003") as o:
        o.crm_short_circuit = _short_circuit("CCI-000003", "not_applicable")

    run = rec.finish()

    assert run.crm_short_circuit_count == 3


def test_customer_and_hybrid_outcomes_do_not_count(session, workbook):
    """Outcomes with ``crm_short_circuit=None`` don't count, even when
    the row touched a CRM.

    Customer and hybrid responsibilities run the LLM normally and
    leave ``crm_short_circuit=None`` (see
    ``engine/measurement.py:172`` docstring). The counter must NOT
    include them — it is the "kernel skipped the LLM" number, not the
    "row touched any CRM" number. Without this gate, every CRM-aware
    run would report inflated short-circuit counts and the patent
    cost-savings claim would lose its precision.
    """
    rec = RunRecorder.start(session, workbook_id=workbook.id)
    with rec.cci("CCI-000010") as o:
        # Customer / hybrid path — LLM ran, no short-circuit.
        pass
    with rec.cci("CCI-000011") as o:
        # Same — explicit None for clarity.
        o.crm_short_circuit = None

    run = rec.finish()

    assert run.crm_short_circuit_count == 0


def test_mixed_outcomes_count_only_short_circuited(session, workbook):
    """Realistic mixed run: 2 provider + 1 not_applicable + 2 customer
    → counter == 3.

    The provider/inherited/not_applicable rows contribute one each;
    the customer rows (LLM ran) contribute zero. This is the shape of
    a typical FedRAMP-High workbook against the DUALSCOPE CRM, where
    most controls are customer-owned and a minority are inherited or
    provider-only. Pin the aggregator's per-row decision against a
    mixed batch so a regression that flips the sentinel polarity
    (e.g. ``if o.crm_short_circuit is None``) surfaces immediately.
    """
    rec = RunRecorder.start(session, workbook_id=workbook.id)
    with rec.cci("CCI-000100") as o:
        o.crm_short_circuit = _short_circuit("CCI-000100", "provider", "AC-2")
    with rec.cci("CCI-000101") as o:
        o.crm_short_circuit = _short_circuit("CCI-000101", "provider", "AC-2")
    with rec.cci("CCI-000102") as o:
        o.crm_short_circuit = _short_circuit("CCI-000102", "not_applicable", "AC-3")
    with rec.cci("CCI-000103") as o:
        # Customer — LLM ran.
        pass
    with rec.cci("CCI-000104") as o:
        # Customer — LLM ran.
        pass

    run = rec.finish()

    assert run.crm_short_circuit_count == 3


def test_empty_run_counter_is_zero(session, workbook):
    """No outcomes recorded → counter == 0.

    A run with no CRM attached (and therefore no CciOutcome rows
    flowing through the short-circuit path) should leave the counter
    at its default of 0, not write garbage and not raise. The default
    column value on the schema is ``0 NOT NULL`` so the aggregator
    must not write ``None`` and must not skip writing entirely (which
    would leave the column at the previous tick's value if the run
    were ever reused — currently not possible, but the invariant
    holds even so).
    """
    rec = RunRecorder.start(session, workbook_id=workbook.id)

    run = rec.finish()

    assert run.crm_short_circuit_count == 0
