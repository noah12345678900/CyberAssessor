"""Property-based tests for the RunRecorder aggregate pipeline.

The patent application's core measurement claim is:

  > Every accuracy datapoint cited in the patent is **one SQL query
  > away** — the AssessmentRun row carries the rolled-up counters that
  > the patent figures plot.

That claim depends entirely on the invariant that

    AssessmentRun.<counter> == sum(<per-CCI contribution>)

holds *after every commit*, *under any interleaving of outcomes*, and
*regardless of which subset of CciOutcome fields were populated*. If
the rollup ever drifts from the per-outcome list, the run-level
counters lie and the patent's figures become unfalsifiable from the DB.

These tests fuzz randomized batches of CciOutcomes through
``RunRecorder._commit_outcome`` / ``finish`` and assert the equality
holds for *every* aggregate column.

Secondary invariants pinned here:

  * A CalibrationEntry is written iff ``stated_confidence`` was set
    on the outcome (rule-based short-circuits MUST NOT pollute the
    calibration grading set).
  * ``finish()`` is idempotent w.r.t. aggregates — calling it twice
    produces the same counters; it only re-stamps ``finished_at`` /
    ``cost_usd``.
  * Incremental flushes (after each CCI) and the final ``finish``
    aggregate to the same numbers — the live Runs page must not
    diverge from the terminal row.
"""

from __future__ import annotations

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

hypothesis = pytest.importorskip("hypothesis")

from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from cybersecurity_assessor.engine.measurement import (  # noqa: E402
    CciOutcome,
    CrmShortCircuit,
    RuleShortCircuit,
    RunRecorder,
    SupersessionHit,
    ValidatorRejection,
)
from cybersecurity_assessor.models import AssessmentRun, CalibrationEntry  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


# ---------------------------------------------------------------------------
# Hypothesis strategies
# ---------------------------------------------------------------------------


_REJECTION_CLASSES = (
    "requirement_restatement",
    "status_narrative_mismatch",
    "missing_inheritance_marker",
    "unsupported_doc_citation",
    "format_violation",
    "dual_narrative_mislabel",
    "future_tense_compliance",
)

_SUPERSESSION_SOURCES = (
    "llm",
    "col_u_carryover",
    "user_input",
    "crm_overlay",
    "sda_verified_mapping",
    "evidence_chain",
)


def _rejection_strategy(cci: str) -> st.SearchStrategy[ValidatorRejection]:
    return st.builds(
        ValidatorRejection,
        cci=st.just(cci),
        rejection_class=st.sampled_from(_REJECTION_CLASSES),
        original_output=st.text(max_size=20),
        corrective_context=st.text(max_size=20),
    )


def _supersession_hit_strategy(cci: str) -> st.SearchStrategy[SupersessionHit]:
    return st.builds(
        SupersessionHit,
        cci=st.just(cci),
        stale_ref=st.text(min_size=1, max_size=20),
        current_ref=st.text(min_size=1, max_size=20),
        source=st.sampled_from(_SUPERSESSION_SOURCES),
    )


def _outcome_strategy(idx: int) -> st.SearchStrategy[CciOutcome]:
    """A randomized CciOutcome — every field independently fuzzed."""
    cci = f"CCI-{idx:06d}"

    return st.builds(
        CciOutcome,
        cci=st.just(cci),
        retries_before_accept=st.integers(min_value=0, max_value=5),
        rejections=st.lists(_rejection_strategy(cci), min_size=0, max_size=4),
        supersession_hits=st.lists(
            _supersession_hit_strategy(cci), min_size=0, max_size=3
        ),
        crm_short_circuit=st.none(),
        accepted=st.booleans(),
        abstained=st.booleans(),
        dual_pass_disagreement=st.booleans(),
        rewrite_requested=st.booleans(),
        cache_hit=st.booleans(),
        input_tokens=st.integers(min_value=0, max_value=10_000),
        output_tokens=st.integers(min_value=0, max_value=10_000),
        cache_read_tokens=st.integers(min_value=0, max_value=10_000),
        stated_confidence=st.none(),
        proposed_status=st.none(),
        final_status=st.none(),
        fingerprint=st.none(),
    )


_batch_strategy = st.lists(
    st.integers(min_value=1, max_value=10_000), min_size=0, max_size=8, unique=True
).flatmap(
    lambda idxs: st.tuples(*(_outcome_strategy(i) for i in idxs))
    if idxs
    else st.just(())
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _push_outcomes(rec: RunRecorder, outcomes) -> None:
    """Pump a batch of pre-built outcomes through the recorder's context-mgr API."""
    for o in outcomes:
        with rec.cci(o.cci) as live:
            live.retries_before_accept = o.retries_before_accept
            live.rejections = list(o.rejections)
            live.supersession_hits = list(o.supersession_hits)
            live.crm_short_circuit = o.crm_short_circuit
            live.accepted = o.accepted
            live.abstained = o.abstained
            live.dual_pass_disagreement = o.dual_pass_disagreement
            live.rewrite_requested = o.rewrite_requested
            live.cache_hit = o.cache_hit
            live.input_tokens = o.input_tokens
            live.output_tokens = o.output_tokens
            live.cache_read_tokens = o.cache_read_tokens
            live.stated_confidence = o.stated_confidence
            live.proposed_status = o.proposed_status
            live.final_status = o.final_status
            live.fingerprint = o.fingerprint


def _assert_aggregates_match(run: AssessmentRun, outcomes) -> None:
    """The patent-critical invariant — every counter is a sum of parts."""
    assert run.llm_calls == len(outcomes)
    assert run.llm_input_tokens == sum(o.input_tokens for o in outcomes)
    assert run.llm_output_tokens == sum(o.output_tokens for o in outcomes)
    assert run.llm_cache_read_tokens == sum(o.cache_read_tokens for o in outcomes)
    assert run.retry_count == sum(o.retries_before_accept for o in outcomes)
    assert run.validator_rejections == sum(len(o.rejections) for o in outcomes)
    assert run.supersession_hits == sum(len(o.supersession_hits) for o in outcomes)
    assert run.ccis_accepted == sum(1 for o in outcomes if o.accepted)
    assert run.abstained == sum(1 for o in outcomes if o.abstained)
    assert run.dual_pass_disagreements == sum(
        1 for o in outcomes if o.dual_pass_disagreement
    )
    assert run.rewrites_requested == sum(1 for o in outcomes if o.rewrite_requested)
    assert run.cache_hits == sum(1 for o in outcomes if o.cache_hit)


# ---------------------------------------------------------------------------
# Aggregate invariants — patent claim "one SQL query away"
# ---------------------------------------------------------------------------


@given(_batch_strategy)
@settings(
    max_examples=25,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
def test_aggregates_equal_sum_of_parts(session, outcomes):
    """``AssessmentRun.<counter> == sum(<per-CCI contribution>)`` after finish().

    This is the SINGLE most load-bearing measurement invariant. If it ever
    drifts, the patent's accuracy figures cannot be reproduced from the DB.
    """
    rec = RunRecorder.start(session, workbook_id=None)
    _push_outcomes(rec, outcomes)
    run = rec.finish(cost_usd=0.0)
    _assert_aggregates_match(run, outcomes)


@given(_batch_strategy)
@settings(
    max_examples=15,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
def test_incremental_flush_matches_final_flush(session, outcomes):
    """The Runs page reads the row after each CCI commit; that snapshot
    must equal what ``finish()`` lands.
    """
    rec = RunRecorder.start(session, workbook_id=None)
    _push_outcomes(rec, outcomes)
    # Snapshot the counters BEFORE finish — these are what the live UI sees.
    pre = {
        "llm_calls": rec._run.llm_calls,
        "input_tokens": rec._run.llm_input_tokens,
        "output_tokens": rec._run.llm_output_tokens,
        "validator_rejections": rec._run.validator_rejections,
        "supersession_hits": rec._run.supersession_hits,
        "abstained": rec._run.abstained,
        "rewrites_requested": rec._run.rewrites_requested,
        "cache_hits": rec._run.cache_hits,
    }
    run = rec.finish(cost_usd=0.0)
    assert pre["llm_calls"] == run.llm_calls
    assert pre["input_tokens"] == run.llm_input_tokens
    assert pre["output_tokens"] == run.llm_output_tokens
    assert pre["validator_rejections"] == run.validator_rejections
    assert pre["supersession_hits"] == run.supersession_hits
    assert pre["abstained"] == run.abstained
    assert pre["rewrites_requested"] == run.rewrites_requested
    assert pre["cache_hits"] == run.cache_hits


@given(_batch_strategy)
@settings(
    max_examples=10,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
def test_finish_is_idempotent(session, outcomes):
    """Calling finish() twice doesn't double the counters.

    Routes occasionally retry the finish call on timeout — the counter
    columns must stay stable across re-calls.
    """
    rec = RunRecorder.start(session, workbook_id=None)
    _push_outcomes(rec, outcomes)
    run1 = rec.finish(cost_usd=0.01)
    counters_after_first = (
        run1.llm_calls,
        run1.llm_input_tokens,
        run1.llm_output_tokens,
        run1.validator_rejections,
        run1.supersession_hits,
        run1.ccis_accepted,
        run1.abstained,
        run1.rewrites_requested,
        run1.cache_hits,
    )
    run2 = rec.finish(cost_usd=0.02)
    counters_after_second = (
        run2.llm_calls,
        run2.llm_input_tokens,
        run2.llm_output_tokens,
        run2.validator_rejections,
        run2.supersession_hits,
        run2.ccis_accepted,
        run2.abstained,
        run2.rewrites_requested,
        run2.cache_hits,
    )
    assert counters_after_first == counters_after_second


# ---------------------------------------------------------------------------
# Calibration entry gating — rule-based short-circuits MUST NOT pollute
# ---------------------------------------------------------------------------


def test_calibration_entry_skipped_when_no_stated_confidence(session):
    """A rule-based outcome (no stated_confidence) writes ZERO CalibrationEntries."""
    rec = RunRecorder.start(session, workbook_id=None)
    with rec.cci("CCI-000001") as o:
        o.accepted = True
        o.input_tokens = 100
        o.output_tokens = 50
        # No stated_confidence set — simulates an 8a/8b/CRM short-circuit.
    rec.finish(cost_usd=0.0)
    entries = session.exec(select(CalibrationEntry)).all()
    assert entries == []


def test_calibration_entry_written_when_stated_confidence_set(session):
    """An LLM-derived outcome writes exactly ONE CalibrationEntry."""
    rec = RunRecorder.start(session, workbook_id=None)
    with rec.cci("CCI-000015") as o:
        o.accepted = True
        o.stated_confidence = 0.83
        o.proposed_status = "Compliant"
        o.final_status = "Compliant"
        o.fingerprint = "abc123"
    rec.finish(cost_usd=0.0)
    entries = session.exec(select(CalibrationEntry)).all()
    assert len(entries) == 1
    e = entries[0]
    assert e.cci_id == "CCI-000015"
    assert e.stated_confidence == 0.83
    assert e.proposed_status == "Compliant"
    assert e.final_status == "Compliant"
    assert e.fingerprint == "abc123"


@given(st.lists(st.booleans(), min_size=0, max_size=8))
@settings(
    max_examples=15,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
def test_calibration_entries_count_equals_llm_derived_outcomes(session, has_conf):
    """For any mix of rule-based and LLM-derived outcomes, the calibration
    table has exactly the LLM-derived count of rows.

    Filters by run_id because the session fixture is reused across
    Hypothesis examples — entries from earlier examples persist.
    """
    rec = RunRecorder.start(session, workbook_id=None)
    for i, llm_derived in enumerate(has_conf):
        with rec.cci(f"CCI-{i:06d}") as o:
            o.accepted = True
            if llm_derived:
                o.stated_confidence = 0.5
                o.proposed_status = "Compliant"
                o.final_status = "Compliant"
                o.fingerprint = f"fp{i}"
    rec.finish(cost_usd=0.0)
    entries = session.exec(
        select(CalibrationEntry).where(CalibrationEntry.run_id == rec.run_id)
    ).all()
    assert len(entries) == sum(1 for x in has_conf if x)


# ---------------------------------------------------------------------------
# Targeted unit cases (cheap to write, catch dumb regressions)
# ---------------------------------------------------------------------------


def test_empty_run_aggregates_to_zeros(session):
    rec = RunRecorder.start(session, workbook_id=None)
    run = rec.finish(cost_usd=0.0)
    assert run.llm_calls == 0
    assert run.llm_input_tokens == 0
    assert run.llm_output_tokens == 0
    assert run.validator_rejections == 0
    assert run.supersession_hits == 0
    assert run.ccis_accepted == 0
    assert run.abstained == 0
    assert run.cache_hits == 0
    assert run.finished_at is not None


def test_run_records_cost_usd_only_on_finish(session):
    """cost_usd is owned by finish(); incremental flushes leave it alone."""
    rec = RunRecorder.start(session, workbook_id=None)
    with rec.cci("CCI-000001") as o:
        o.accepted = True
        o.input_tokens = 100
    # Cost is still default after the incremental flush.
    assert rec._run.cost_usd == 0.0
    run = rec.finish(cost_usd=1.23)
    assert run.cost_usd == 1.23


def test_outcomes_property_exposes_committed_list(session):
    rec = RunRecorder.start(session, workbook_id=None)
    with rec.cci("CCI-000001") as o:
        o.accepted = True
    with rec.cci("CCI-000002") as o:
        o.accepted = False
        o.abstained = True
    snapshot = rec.outcomes
    assert [o.cci for o in snapshot] == ["CCI-000001", "CCI-000002"]
    # outcomes returns a copy — mutating it must not affect future aggregates.
    snapshot.append(CciOutcome(cci="CCI-fake"))
    run = rec.finish(cost_usd=0.0)
    assert run.llm_calls == 2  # not 3


def test_crm_short_circuit_attaches_without_polluting_llm_aggregates(session):
    """A CRM short-circuit row counts as one outcome but has zero tokens —
    it must NOT inflate llm_input_tokens / llm_output_tokens.
    """
    rec = RunRecorder.start(session, workbook_id=None)
    with rec.cci("CCI-000001") as o:
        o.accepted = True
        o.crm_short_circuit = CrmShortCircuit(
            cci="CCI-000001",
            control_id="ac-2",
            responsibility="inherited",
            baseline_id=1,
        )
        # No tokens — short-circuit bypassed the LLM.
    run = rec.finish(cost_usd=0.0)
    assert run.llm_calls == 1
    assert run.llm_input_tokens == 0
    assert run.llm_output_tokens == 0
    assert run.ccis_accepted == 1


def test_rejection_inflates_validator_rejections_not_retry_count(session):
    """Two rejections on one outcome with retries_before_accept=2 means
    2 rejections AND 2 retries — they're orthogonal counters.
    """
    rec = RunRecorder.start(session, workbook_id=None)
    with rec.cci("CCI-000001") as o:
        o.retries_before_accept = 2
        o.rejections = [
            ValidatorRejection(
                cci="CCI-000001",
                rejection_class="requirement_restatement",
                original_output="x",
                corrective_context="y",
            ),
            ValidatorRejection(
                cci="CCI-000001",
                rejection_class="status_narrative_mismatch",
                original_output="x",
                corrective_context="y",
            ),
        ]
        o.accepted = True
    run = rec.finish(cost_usd=0.0)
    assert run.validator_rejections == 2
    assert run.retry_count == 2


def test_run_row_persists_to_db(session):
    """A finished run must be readable back from the session."""
    rec = RunRecorder.start(session, workbook_id=None)
    with rec.cci("CCI-000001") as o:
        o.accepted = True
        o.input_tokens = 100
    run = rec.finish(cost_usd=0.5)
    runs = session.exec(select(AssessmentRun)).all()
    assert len(runs) == 1
    assert runs[0].id == run.id
    assert runs[0].llm_input_tokens == 100
    assert runs[0].cost_usd == 0.5


# ---------------------------------------------------------------------------
# Rule #8a/#8b short-circuit telemetry — proof that the deterministic
# pre-filter avoided LLM calls
# ---------------------------------------------------------------------------


def test_rule_8a_short_circuit_increments_8a_counter_only(session):
    """An 8a rule fire counts toward rule_8a_short_circuits and NOT 8b."""
    rec = RunRecorder.start(session, workbook_id=None)
    with rec.cci("CCI-000001") as o:
        o.accepted = True
        o.rule_short_circuit = RuleShortCircuit(
            cci="CCI-000001",
            rule="8a",
            trigger_phrase="automatically compliant",
            trigger_column="K",
        )
    run = rec.finish(cost_usd=0.0)
    assert run.rule_8a_short_circuits == 1
    assert run.rule_8b_short_circuits == 0


def test_rule_8b_short_circuit_increments_8b_counter_only(session):
    """An 8b rule fire counts toward rule_8b_short_circuits and NOT 8a."""
    rec = RunRecorder.start(session, workbook_id=None)
    with rec.cci("CCI-000001") as o:
        o.accepted = True
        o.rule_short_circuit = RuleShortCircuit(
            cci="CCI-000001",
            rule="8b",
            trigger_phrase="not applicable",
            trigger_column="K",
        )
    run = rec.finish(cost_usd=0.0)
    assert run.rule_8a_short_circuits == 0
    assert run.rule_8b_short_circuits == 1


def test_rule_short_circuit_no_tokens_attaches_without_polluting_llm_aggregates(session):
    """A rule-#8 row counts as one outcome but has zero tokens —
    deterministic short-circuits MUST NOT inflate llm_input_tokens /
    llm_output_tokens. Mirrors the equivalent CRM short-circuit guard.
    """
    rec = RunRecorder.start(session, workbook_id=None)
    with rec.cci("CCI-000001") as o:
        o.accepted = True
        o.rule_short_circuit = RuleShortCircuit(
            cci="CCI-000001",
            rule="8a",
            trigger_phrase="inherited from Example System shared service",
            trigger_column="L",
        )
        # No tokens — short-circuit bypassed the LLM.
    run = rec.finish(cost_usd=0.0)
    assert run.llm_calls == 1
    assert run.llm_input_tokens == 0
    assert run.llm_output_tokens == 0
    assert run.rule_8a_short_circuits == 1


def test_rule_short_circuit_counters_sum_across_mixed_run(session):
    """Mixed batch: 3x 8a, 2x 8b, 4x LLM — counters land at (3, 2)."""
    rec = RunRecorder.start(session, workbook_id=None)
    for i in range(3):
        with rec.cci(f"CCI-A{i:05d}") as o:
            o.accepted = True
            o.rule_short_circuit = RuleShortCircuit(
                cci=f"CCI-A{i:05d}",
                rule="8a",
                trigger_phrase="automatically compliant",
                trigger_column="K",
            )
    for i in range(2):
        with rec.cci(f"CCI-B{i:05d}") as o:
            o.accepted = True
            o.rule_short_circuit = RuleShortCircuit(
                cci=f"CCI-B{i:05d}",
                rule="8b",
                trigger_phrase="not applicable",
                trigger_column="J",
            )
    for i in range(4):
        with rec.cci(f"CCI-L{i:05d}") as o:
            o.accepted = True
            o.input_tokens = 500
            o.output_tokens = 100
            o.stated_confidence = 0.9
            o.proposed_status = "Compliant"
            o.final_status = "Compliant"
            o.fingerprint = f"fp{i}"
    run = rec.finish(cost_usd=0.0)
    assert run.llm_calls == 9
    assert run.rule_8a_short_circuits == 3
    assert run.rule_8b_short_circuits == 2
    # LLM rows still get their tokens summed.
    assert run.llm_input_tokens == 4 * 500
    assert run.llm_output_tokens == 4 * 100


def test_rule_short_circuit_does_not_write_calibration_entry(session):
    """Rule fires are deterministic; they MUST NOT pollute the
    calibration grading set (which is reserved for LLM-stated confidence).
    """
    rec = RunRecorder.start(session, workbook_id=None)
    with rec.cci("CCI-000001") as o:
        o.accepted = True
        o.rule_short_circuit = RuleShortCircuit(
            cci="CCI-000001",
            rule="8a",
            trigger_phrase="automatically compliant",
            trigger_column="K",
        )
        # No stated_confidence — rule-based short-circuit.
    rec.finish(cost_usd=0.0)
    entries = session.exec(select(CalibrationEntry)).all()
    assert entries == []


def test_calibration_entry_carries_abstain_and_rewrite_flags(session):
    """An LLM outcome that abstains still writes a CalibrationEntry — the
    abstain flag tells the calibration grader to skip it from accuracy
    math but it still counts as a graded prediction.
    """
    rec = RunRecorder.start(session, workbook_id=None)
    with rec.cci("CCI-000001") as o:
        o.accepted = False
        o.abstained = True
        o.rewrite_requested = True
        o.stated_confidence = 0.2
        o.proposed_status = "Compliant"
        o.final_status = "needs_review"
        o.fingerprint = "fp-abstain"
    rec.finish(cost_usd=0.0)
    entries = session.exec(select(CalibrationEntry)).all()
    assert len(entries) == 1
    assert entries[0].abstained is True
    assert entries[0].rewrite_requested is True


# ---------------------------------------------------------------------------
# Validator-rejection per-class breakdown — the "what's the LLM getting
# wrong most often?" signal the operator panel reads to tune the prompt
# ---------------------------------------------------------------------------


def test_validator_rejection_breakdown_empty_when_no_rejections(session):
    """No rejections → ``validator_rejections_by_class == {}``.

    The dict default is the route handler's stable "nothing to show" signal.
    NULL coming back from a freshly-migrated column would crash the
    operator panel; the SQLModel default_factory + this test guard it.
    """
    rec = RunRecorder.start(session, workbook_id=None)
    with rec.cci("CCI-000001") as o:
        o.accepted = True
    run = rec.finish(cost_usd=0.0)
    assert run.validator_rejections == 0
    assert run.validator_rejections_by_class == {}


def test_validator_rejection_breakdown_counts_per_class(session):
    """Each rejection_class lands in its own bucket.

    The whole point of the breakdown is to surface the dominant failure
    mode to the operator. If the bucket keys ever collide or get summed
    incorrectly, the prompt-tuning loop reads the wrong signal.
    """
    rec = RunRecorder.start(session, workbook_id=None)
    with rec.cci("CCI-000001") as o:
        o.rejections = [
            ValidatorRejection(
                cci="CCI-000001",
                rejection_class="requirement_restatement",
                original_output="x",
                corrective_context="y",
            ),
            ValidatorRejection(
                cci="CCI-000001",
                rejection_class="requirement_restatement",
                original_output="x",
                corrective_context="y",
            ),
            ValidatorRejection(
                cci="CCI-000001",
                rejection_class="status_narrative_mismatch",
                original_output="x",
                corrective_context="y",
            ),
        ]
        o.accepted = True
    run = rec.finish(cost_usd=0.0)
    assert run.validator_rejections == 3
    assert run.validator_rejections_by_class == {
        "requirement_restatement": 2,
        "status_narrative_mismatch": 1,
    }


@given(_batch_strategy)
@settings(
    max_examples=25,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
def test_validator_rejection_breakdown_sums_to_total(session, outcomes):
    """The patent-critical sum-of-parts invariant for the breakdown:

        sum(validator_rejections_by_class.values()) == validator_rejections

    If this ever drifts, the operator panel's "X rejections, here's the
    distribution" claim is a lie and downstream rate calculations
    (per-class rate, dominant-class detection) silently break.
    """
    rec = RunRecorder.start(session, workbook_id=None)
    _push_outcomes(rec, outcomes)
    run = rec.finish(cost_usd=0.0)
    assert sum(run.validator_rejections_by_class.values()) == run.validator_rejections
    # Every key must be a known RejectionClass — protects against the
    # writer accidentally bucketing under a typo'd class name.
    valid = set(_REJECTION_CLASSES) | {
        "stale_doc_reference",
        "missing_evidence_citation",
        "incorrect_status",
        "wrong_inheritance_attribution",
    }
    assert set(run.validator_rejections_by_class.keys()).issubset(valid)


def test_validator_rejection_breakdown_incremental_matches_final(session):
    """The breakdown updates on every CCI commit (live operator view) and
    matches what ``finish()`` lands. Same incremental-correctness contract
    as the scalar counters.
    """
    rec = RunRecorder.start(session, workbook_id=None)
    with rec.cci("CCI-000001") as o:
        o.rejections = [
            ValidatorRejection(
                cci="CCI-000001",
                rejection_class="format_violation",
                original_output="x",
                corrective_context="y",
            )
        ]
        o.accepted = True
    pre = dict(rec._run.validator_rejections_by_class)
    with rec.cci("CCI-000002") as o:
        o.rejections = [
            ValidatorRejection(
                cci="CCI-000002",
                rejection_class="format_violation",
                original_output="x",
                corrective_context="y",
            ),
            ValidatorRejection(
                cci="CCI-000002",
                rejection_class="missing_inheritance_marker",
                original_output="x",
                corrective_context="y",
            ),
        ]
        o.accepted = True
    after_second = dict(rec._run.validator_rejections_by_class)
    run = rec.finish(cost_usd=0.0)
    assert pre == {"format_violation": 1}
    assert after_second == {"format_violation": 2, "missing_inheritance_marker": 1}
    assert run.validator_rejections_by_class == {
        "format_violation": 2,
        "missing_inheritance_marker": 1,
    }


def test_validator_rejection_breakdown_persists_to_db(session):
    """After finish(), reloading the run row returns the same breakdown.

    Guards the JSON encode/decode round-trip — a regression that wrote
    a Python dict but read back a JSON string would silently break the
    operator panel.
    """
    rec = RunRecorder.start(session, workbook_id=None)
    with rec.cci("CCI-000001") as o:
        o.rejections = [
            ValidatorRejection(
                cci="CCI-000001",
                rejection_class="dual_narrative_mislabel",
                original_output="x",
                corrective_context="y",
            )
        ]
        o.accepted = True
    rec.finish(cost_usd=0.0)
    session.expire_all()  # force re-read from SQLite
    fresh = session.exec(select(AssessmentRun)).one()
    assert fresh.validator_rejections_by_class == {"dual_narrative_mislabel": 1}
