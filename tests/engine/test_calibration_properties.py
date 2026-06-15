"""Property-based tests for the calibration scoring math.

The example-driven suite in ``test_calibration.py`` pins specific
shapes (perfect-calibration, worst-case, mixed bins). This file fuzzes
the math primitives so a refactor that breaks an invariant in a corner
of the (confidence × accept) input space gets caught:

  1. **Brier bounds.** Squared-error of values in [0, 1] is in [0, 1];
     the mean is in [0, 1]. A regression that emits a negative or >1
     score would break the patent-supporting "operator-readable
     calibration number" claim — operators interpret the score against
     a 0-1 scale and >1 means "the kernel mis-summed something".

  2. **ECE bounds.** Same range — |mean_conf - accept_rate| is in
     [0, 1], weighted average of weights summing to ≤1 stays in [0, 1].

  3. **Bin partition totality.** Every reviewed entry lands in exactly
     one bin; the breakdown counts must sum to total_reviewed. A
     regression where edge-case confidences (0.0, 1.0, exact bin edges)
     are dropped would silently shrink the calibration sample.

  4. **Bin edge handling.** confidence=0.0 → bin 0; confidence=1.0 →
     bin (bins-1). The top bin is intentionally closed at the right
     edge so a perfectly-confident decision isn't lost to overflow.

  5. **Unreviewed exclusion.** No matter how many ``human_accepted is
     None`` rows exist, they MUST NOT contribute to Brier or ECE. The
     report's ``total_unreviewed`` counter is the only place they show
     up — operators read it as "how big is our calibration sample?"

  6. **Run-scoping isolation.** Brier/ECE for run_id=A must not be
     swayed by reviewed entries in run_id=B. Operators read per-run
     calibration to detect "did this run drift?" so cross-run leakage
     would mask actual drift events.

  7. **Insert-order invariance.** Brier/ECE are set-functions of the
     reviewed rows; reordering inserts must produce the same scores.
     A future "stream-incremental" Brier implementation that secretly
     depended on order would regress here.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

hypothesis = pytest.importorskip("hypothesis")

from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from cybersecurity_assessor.engine import calibration as calibration_engine  # noqa: E402
from cybersecurity_assessor.engine.calibration import _bin_index  # noqa: E402
from cybersecurity_assessor.models import CalibrationEntry, ComplianceStatus  # noqa: E402


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


# Confidences are bounded floats in [0, 1] with a few exact-edge values
# baked in so the binning edge cases are sampled frequently.
_CONFIDENCE = st.one_of(
    st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
    st.sampled_from([0.0, 0.05, 0.1, 0.5, 0.9, 0.95, 1.0]),
)

_BIN_COUNT = st.integers(min_value=2, max_value=20)

# A single reviewed row: (confidence, accepted-bool).
_REVIEWED = st.tuples(_CONFIDENCE, st.booleans())

# Up to 30 reviewed rows per case — large enough that random falsifying
# examples have room to land in multiple bins, small enough that the
# in-memory session writes don't make Hypothesis exhaust its budget.
_REVIEWED_SET = st.lists(_REVIEWED, min_size=0, max_size=30)


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def session() -> Session:
    """Fresh in-memory SQLite session per test (mirrors test_calibration.py).

    Hypothesis re-invokes the test body many times per case; the fixture
    rebuilds the schema each invocation so reviewed-row inserts from
    prior examples can't bleed into the score.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _wipe(session: Session) -> None:
    """Delete every CalibrationEntry — call at the top of every property
    test body.

    The pytest fixture is function-scoped, but Hypothesis re-invokes the
    body many times per fixture instance. Without an explicit wipe,
    rows from prior examples leak into the current example's count
    assertions (e.g. ``total_reviewed == len(input)`` fails because
    prior inserts inflated the total).
    """
    for entry in session.exec(select(CalibrationEntry)).all():
        session.delete(entry)
    session.commit()


def _insert_reviewed(
    session: Session,
    *,
    run_id: int,
    confidence: float,
    accepted: bool,
    cci_id: str,
) -> CalibrationEntry:
    """Insert a reviewed CalibrationEntry — bypasses the assessor pipeline."""
    entry = CalibrationEntry(
        run_id=run_id,
        cci_id=cci_id,
        fingerprint=f"fp-{cci_id}-{confidence}-{accepted}",
        stated_confidence=confidence,
        proposed_status=ComplianceStatus.COMPLIANT.value,
        final_status=ComplianceStatus.COMPLIANT.value,
        abstained=False,
        rewrite_requested=False,
        human_accepted=accepted,
        recorded_at=datetime.now(timezone.utc),
        reviewed_at=datetime.now(timezone.utc),
    )
    session.add(entry)
    session.commit()
    return entry


def _insert_unreviewed(
    session: Session,
    *,
    run_id: int,
    confidence: float,
    cci_id: str,
) -> CalibrationEntry:
    """Insert an unreviewed (``human_accepted is None``) entry."""
    entry = CalibrationEntry(
        run_id=run_id,
        cci_id=cci_id,
        fingerprint=f"fp-{cci_id}-unreviewed",
        stated_confidence=confidence,
        proposed_status=ComplianceStatus.COMPLIANT.value,
        final_status=ComplianceStatus.COMPLIANT.value,
        abstained=False,
        rewrite_requested=False,
        human_accepted=None,
        recorded_at=datetime.now(timezone.utc),
    )
    session.add(entry)
    session.commit()
    return entry


# ---------------------------------------------------------------------------
# _bin_index — pure-function properties (fast, no DB)
# ---------------------------------------------------------------------------


@given(confidence=_CONFIDENCE, bins=_BIN_COUNT)
@settings(max_examples=400, deadline=None)
def test_bin_index_always_in_range(confidence, bins):
    """For any (confidence in [0,1], bins ≥ 2), bin index is in [0, bins-1].

    An out-of-range index would either crash the bucket build in
    ``expected_calibration_error`` (negative index) or silently push the
    row into the wrong bucket (overflow), miscounting the calibration
    sample without raising.
    """
    idx = _bin_index(confidence, bins)
    assert isinstance(idx, int)
    assert 0 <= idx <= bins - 1


@given(bins=_BIN_COUNT)
@settings(max_examples=50, deadline=None)
def test_bin_index_zero_and_one_edges(bins):
    """0.0 → bin 0; 1.0 → bin (bins-1).

    The top bin is closed at the right edge by design — without that,
    a confidence-1.0 decision would overflow to ``bins`` and the
    bucket-build loop would IndexError.
    """
    assert _bin_index(0.0, bins) == 0
    assert _bin_index(1.0, bins) == bins - 1


@given(
    confidence=st.floats(
        min_value=0.0, max_value=0.999999, allow_nan=False, allow_infinity=False,
        exclude_min=False,
    ),
    bins=_BIN_COUNT,
)
@settings(max_examples=300, deadline=None)
def test_bin_index_monotonic_in_confidence(confidence, bins):
    """For confidence in [0, 1), the index never exceeds (bins-1).

    A regression where the per-bin width drifted (e.g., used ``bins+1``
    in a divisor) would let a sub-1.0 confidence overflow to the
    (bins)-th bucket — caught here before it reaches production.
    """
    idx = _bin_index(confidence, bins)
    assert idx < bins
    # And the index is monotone non-decreasing in confidence within a
    # given bin: stepping up by half a bin-width can only stay or
    # increase the bin index, never decrease.
    width = 1.0 / bins
    next_idx = _bin_index(min(confidence + width / 2.0, 0.9999999), bins)
    assert next_idx >= idx


# ---------------------------------------------------------------------------
# Brier — value-range and degenerate-case properties
# ---------------------------------------------------------------------------


@given(reviewed=_REVIEWED_SET)
@settings(max_examples=100, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_brier_in_zero_to_one(reviewed, session):
    """Brier ∈ [0, 1] for any reviewed sample.

    Squared error of two values in [0, 1] is in [0, 1]; the mean stays
    in [0, 1]. A score >1 means the implementation mis-summed; <0
    means a sign flip. Operators interpret Brier against a fixed
    0-1 scale, so a regression here invalidates every report headline.
    """
    _wipe(session)
    run_id = 1
    for i, (conf, acc) in enumerate(reviewed):
        _insert_reviewed(
            session, run_id=run_id, confidence=conf, accepted=acc, cci_id=f"R{i}"
        )
    score = calibration_engine.brier_score(session, run_id=run_id)
    assert 0.0 <= score <= 1.0


def test_brier_empty_sample_returns_zero(session):
    """Documented contract: no reviewed rows → 0.0 (not an error).

    Callers MUST cross-check ``total_reviewed`` before reading the
    score; this test pins the API rather than testing a calibration
    claim.
    """
    assert calibration_engine.brier_score(session, run_id=999) == pytest.approx(0.0)


@given(confidences=st.lists(_CONFIDENCE, min_size=1, max_size=15))
@settings(max_examples=80, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_brier_zero_when_all_perfectly_calibrated(confidences, session):
    """When every row has (confidence=1, accepted=True) Brier collapses
    to 0; same for (confidence=0, accepted=False).

    Hypothesis ignores the input confidences here on purpose — the
    point is to vary the *number* of perfectly-calibrated rows and
    confirm averaging doesn't drift. Use the input list only for
    cci_id count.
    """
    _wipe(session)
    run_id = 2
    # Half perfect-confident-accepts, half perfect-confident-rejects.
    for i, _ in enumerate(confidences):
        if i % 2 == 0:
            _insert_reviewed(
                session, run_id=run_id, confidence=1.0, accepted=True,
                cci_id=f"A{i}",
            )
        else:
            _insert_reviewed(
                session, run_id=run_id, confidence=0.0, accepted=False,
                cci_id=f"B{i}",
            )
    assert calibration_engine.brier_score(session, run_id=run_id) == pytest.approx(0.0)


@given(reviewed=_REVIEWED_SET)
@settings(max_examples=60, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_brier_invariant_under_insert_order(reviewed, session):
    """Brier is a set-function: reordering inserts produces the same score.

    Defends against a streaming/online Brier rewrite that secretly
    depends on commit order (e.g., a running-mean with floating-point
    accumulation bias that diverges across orderings).
    """
    _wipe(session)
    run_id = 3
    for i, (conf, acc) in enumerate(reviewed):
        _insert_reviewed(
            session, run_id=run_id, confidence=conf, accepted=acc,
            cci_id=f"O{i}",
        )
    score_a = calibration_engine.brier_score(session, run_id=run_id)

    # Wipe and re-insert in reverse order.
    _wipe(session)
    for i, (conf, acc) in enumerate(reversed(reviewed)):
        _insert_reviewed(
            session, run_id=run_id, confidence=conf, accepted=acc,
            cci_id=f"R{i}",
        )
    score_b = calibration_engine.brier_score(session, run_id=run_id)
    assert score_a == pytest.approx(score_b)


# ---------------------------------------------------------------------------
# ECE — value-range and degenerate-case properties
# ---------------------------------------------------------------------------


@given(reviewed=_REVIEWED_SET, bins=_BIN_COUNT)
@settings(max_examples=80, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_ece_in_zero_to_one(reviewed, bins, session):
    """ECE ∈ [0, 1] for any (reviewed sample, bins).

    Each bucket's gap |mean_conf - accept_rate| ∈ [0, 1]; the weighted
    average over disjoint buckets (weights summing to 1) stays in
    [0, 1]. A score outside the unit interval implies broken bucket
    weighting or a bug in the abs() / division.
    """
    _wipe(session)
    run_id = 4
    for i, (conf, acc) in enumerate(reviewed):
        _insert_reviewed(
            session, run_id=run_id, confidence=conf, accepted=acc,
            cci_id=f"E{i}",
        )
    ece = calibration_engine.expected_calibration_error(
        session, bins=bins, run_id=run_id
    )
    assert 0.0 <= ece <= 1.0


def test_ece_empty_sample_returns_zero(session):
    """Documented contract: no reviewed rows → 0.0 (not an error)."""
    assert calibration_engine.expected_calibration_error(
        session, bins=10, run_id=999
    ) == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# Report — partition totality + unreviewed exclusion
# ---------------------------------------------------------------------------


@given(
    reviewed=_REVIEWED_SET,
    unreviewed=st.lists(_CONFIDENCE, min_size=0, max_size=10),
    bins=_BIN_COUNT,
)
@settings(max_examples=60, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_report_partition_is_total(reviewed, unreviewed, bins, session):
    """Sum of bin counts == total_reviewed; total_reviewed + total_unreviewed
    == total entries; bin_breakdown length == bins.

    These are the three invariants the UI relies on to render the
    histogram and the headline "reviewed/total" counter. If a
    refactor dropped a row into an off-by-one bucket, this test would
    catch the count mismatch before it shipped.
    """
    _wipe(session)
    run_id = 5
    for i, (conf, acc) in enumerate(reviewed):
        _insert_reviewed(
            session, run_id=run_id, confidence=conf, accepted=acc,
            cci_id=f"R{i}",
        )
    for j, conf in enumerate(unreviewed):
        _insert_unreviewed(
            session, run_id=run_id, confidence=conf, cci_id=f"U{j}",
        )

    report = calibration_engine.calibration_report(
        session, run_id=run_id, bins=bins
    )

    # Partition totality.
    assert report["total_reviewed"] == len(reviewed)
    assert report["total_unreviewed"] == len(unreviewed)
    assert len(report["bin_breakdown"]) == bins
    assert sum(b["count"] for b in report["bin_breakdown"]) == len(reviewed)

    # Bin edges cover [0, 1] continuously and non-overlapping.
    for i, bucket in enumerate(report["bin_breakdown"]):
        assert bucket["lower"] == pytest.approx(i / bins)
        assert bucket["upper"] == pytest.approx((i + 1) / bins)

    # Empty bins use None for rates (not 0 — see report docstring).
    for bucket in report["bin_breakdown"]:
        if bucket["count"] == 0:
            assert bucket["mean_confidence"] is None
            assert bucket["accept_rate"] is None
        else:
            assert bucket["mean_confidence"] is not None
            assert bucket["accept_rate"] is not None
            assert 0.0 <= bucket["mean_confidence"] <= 1.0
            assert 0.0 <= bucket["accept_rate"] <= 1.0


@given(
    reviewed=st.lists(_REVIEWED, min_size=1, max_size=15),
    unreviewed=st.lists(_CONFIDENCE, min_size=1, max_size=15),
    bins=_BIN_COUNT,
)
@settings(max_examples=60, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_unreviewed_never_contributes_to_score(reviewed, unreviewed, bins, session):
    """Brier and ECE computed with N unreviewed extras == computed without.

    The unreviewed entries are reviewer-pending; a math layer that
    silently treated ``human_accepted is None`` as False would skew
    every report. This test pins the exclusion.
    """
    _wipe(session)
    run_id = 6
    for i, (conf, acc) in enumerate(reviewed):
        _insert_reviewed(
            session, run_id=run_id, confidence=conf, accepted=acc,
            cci_id=f"R{i}",
        )

    brier_before = calibration_engine.brier_score(session, run_id=run_id)
    ece_before = calibration_engine.expected_calibration_error(
        session, bins=bins, run_id=run_id
    )

    for j, conf in enumerate(unreviewed):
        _insert_unreviewed(
            session, run_id=run_id, confidence=conf, cci_id=f"U{j}",
        )

    brier_after = calibration_engine.brier_score(session, run_id=run_id)
    ece_after = calibration_engine.expected_calibration_error(
        session, bins=bins, run_id=run_id
    )
    assert brier_before == pytest.approx(brier_after)
    assert ece_before == pytest.approx(ece_after)


# ---------------------------------------------------------------------------
# Run-scoping — reviewed rows in other runs MUST NOT leak into the score
# ---------------------------------------------------------------------------


@given(
    run_a=st.lists(_REVIEWED, min_size=1, max_size=10),
    run_b=st.lists(_REVIEWED, min_size=1, max_size=10),
)
@settings(max_examples=40, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_run_scoping_isolates_brier(run_a, run_b, session):
    """Brier(run=A) doesn't shift when run B grows.

    Operators read per-run Brier to detect drift in one assessment;
    cross-run leakage would mask actual drift events.
    """
    _wipe(session)
    for i, (conf, acc) in enumerate(run_a):
        _insert_reviewed(
            session, run_id=100, confidence=conf, accepted=acc,
            cci_id=f"A{i}",
        )

    brier_a_alone = calibration_engine.brier_score(session, run_id=100)

    for j, (conf, acc) in enumerate(run_b):
        _insert_reviewed(
            session, run_id=200, confidence=conf, accepted=acc,
            cci_id=f"B{j}",
        )

    brier_a_after_b = calibration_engine.brier_score(session, run_id=100)
    assert brier_a_alone == pytest.approx(brier_a_after_b)


# ---------------------------------------------------------------------------
# Concrete pins — load-bearing math identities
# ---------------------------------------------------------------------------


@given(
    confidence=st.floats(
        min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False,
    ),
)
@settings(max_examples=100, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_brier_single_row_equals_squared_error(confidence, session):
    """One reviewed row with (conf, acc=True) → Brier == (conf - 1)**2.

    This is the smallest possible Brier check — a regression where the
    accept signal was inverted (1↔0) would flip the squared term and
    fail here.
    """
    _wipe(session)
    run_id = 7
    _insert_reviewed(
        session, run_id=run_id, confidence=confidence, accepted=True,
        cci_id="single",
    )
    expected = (confidence - 1.0) ** 2
    assert calibration_engine.brier_score(session, run_id=run_id) == pytest.approx(
        expected
    )
