"""Calibration telemetry for the patent-kernel orchestrator.

The kernel already emits a ``confidence`` number on every LLM-derived
Decision and gates abstain on
:data:`engine.assessor.CONFIDENCE_THRESHOLD`. This module measures
whether that number is *honest* — i.e. whether a "confidence 0.9"
decision actually gets accepted by reviewers 90% of the time. Without
this loop, the threshold is a guess.

Two scores are computed against the :class:`CalibrationEntry` table:

* **Brier score** — mean squared error between stated confidence and the
  reviewer's binary accept signal. Lower is better. 0 = perfectly
  calibrated, 0.25 = random baseline, 1 = worst case (perfectly
  confident and perfectly wrong).
* **Expected Calibration Error (ECE)** — the weighted average gap
  between each bin's mean confidence and that bin's actual accept rate.
  Lower is better. 0 = perfectly calibrated across the full
  0..1 confidence range.

Only entries with a reviewer signal (``human_accepted is not None``)
contribute to either score. Unreviewed entries are surfaced in the
report's ``total_unreviewed`` counter so operators can see the sample
size before reading the score.

The module is session-aware but session-free at import: callers pass a
:class:`sqlmodel.Session` per call (matches the kernel's session-free
contract — route handlers own the session, this module just reads).

Why no auto-tuning yet:
    The plan defers the "lower CONFIDENCE_THRESHOLD if ECE shows we're
    over-cautious" loop to a future kernel version. v0.2 ships the
    measurement only — operators read the report and bump
    KERNEL_VERSION + CONFIDENCE_THRESHOLD by hand. This keeps the
    determinism contract clean (no silent threshold drift mid-run).
"""

from __future__ import annotations

from typing import Any

from sqlmodel import Session, select

from ..models import CalibrationEntry

# ---------------------------------------------------------------------------
# Scoring primitives
# ---------------------------------------------------------------------------


def _reviewed_entries(
    session: Session, run_id: int | None
) -> list[CalibrationEntry]:
    """Pull every reviewed (``human_accepted is not None``) entry.

    Filters by ``run_id`` when provided so the operator panel can scope
    the report to a single assessment run; ``None`` returns the global
    history (useful for trend analysis across many runs).
    """
    stmt = select(CalibrationEntry).where(
        CalibrationEntry.human_accepted.is_not(None)  # type: ignore[union-attr]
    )
    if run_id is not None:
        stmt = stmt.where(CalibrationEntry.run_id == run_id)
    return list(session.exec(stmt).all())


def brier_score(session: Session, run_id: int | None = None) -> float:
    """Mean squared error between stated_confidence and accept signal.

    Returns ``0.0`` when there are no reviewed entries — interpret with
    care via ``calibration_report``'s ``total_reviewed`` counter; a
    zero-sample "0.0" is not a calibration claim.

    The accept signal is binary (1 = reviewer accepted, 0 = rejected),
    and the confidence is the [0..1] value the LLM emitted at decision
    time. Squared-error puts heavy weight on confident-but-wrong rows,
    which is the failure mode the patent kernel must surface.
    """
    rows = _reviewed_entries(session, run_id)
    if not rows:
        return 0.0
    total = 0.0
    for entry in rows:
        outcome = 1.0 if entry.human_accepted else 0.0
        total += (entry.stated_confidence - outcome) ** 2
    return total / len(rows)


def _bin_index(confidence: float, bins: int) -> int:
    """Right-open binning: [0,1/N), [1/N,2/N), ..., [(N-1)/N, 1].

    Confidence exactly equal to 1.0 lands in the top bin (the right edge
    is closed for the final bin only) so a fully-confident decision is
    accounted for instead of overflowing.
    """
    if confidence >= 1.0:
        return bins - 1
    if confidence <= 0.0:
        return 0
    idx = int(confidence * bins)
    return min(idx, bins - 1)


def expected_calibration_error(
    session: Session,
    *,
    bins: int = 10,
    run_id: int | None = None,
) -> float:
    """Weighted gap between bin mean confidence and bin accept rate.

    Standard ECE formulation: partition reviewed entries into ``bins``
    equal-width buckets over [0, 1] by stated_confidence, take
    |mean_confidence_k - accept_rate_k| per non-empty bucket, weight by
    bucket size, sum. Returns ``0.0`` on an empty sample — same caveat
    as :func:`brier_score`.
    """
    rows = _reviewed_entries(session, run_id)
    if not rows:
        return 0.0

    buckets: list[list[CalibrationEntry]] = [[] for _ in range(bins)]
    for entry in rows:
        buckets[_bin_index(entry.stated_confidence, bins)].append(entry)

    total = len(rows)
    ece = 0.0
    for bucket in buckets:
        if not bucket:
            continue
        mean_conf = sum(e.stated_confidence for e in bucket) / len(bucket)
        accept_rate = sum(1.0 for e in bucket if e.human_accepted) / len(bucket)
        ece += (len(bucket) / total) * abs(mean_conf - accept_rate)
    return ece


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def calibration_report(
    session: Session,
    run_id: int | None = None,
    *,
    bins: int = 10,
) -> dict[str, Any]:
    """Bundle Brier + ECE + per-bucket breakdown for the operator panel.

    Output shape::

        {
          "brier": float,                  # 0 best, 0.25 random, 1 worst
          "ece": float,                    # 0 best, higher = miscalibrated
          "total_reviewed": int,           # contributes to brier/ece
          "total_unreviewed": int,         # awaiting reviewer signal
          "bin_breakdown": [               # length == bins
            {
              "lower": float,              # bin's left edge
              "upper": float,              # bin's right edge
              "count": int,
              "mean_confidence": float | None,  # None when count == 0
              "accept_rate": float | None,
            },
            ...
          ],
        }

    Empty-bucket entries keep their slot (so the UI can render the full
    histogram) but use ``None`` for the rate fields rather than 0 — a 0
    means "we asked and nobody accepted", which is not the same as "we
    have no data here".
    """
    reviewed = _reviewed_entries(session, run_id)

    # Total entries (reviewed + unreviewed), scoped the same way.
    stmt = select(CalibrationEntry)
    if run_id is not None:
        stmt = stmt.where(CalibrationEntry.run_id == run_id)
    all_rows = list(session.exec(stmt).all())
    total_unreviewed = sum(1 for r in all_rows if r.human_accepted is None)

    # Bin every reviewed row for the breakdown.
    buckets: list[list[CalibrationEntry]] = [[] for _ in range(bins)]
    for entry in reviewed:
        buckets[_bin_index(entry.stated_confidence, bins)].append(entry)

    width = 1.0 / bins
    breakdown: list[dict[str, Any]] = []
    for i, bucket in enumerate(buckets):
        lower = i * width
        upper = (i + 1) * width
        if not bucket:
            breakdown.append(
                {
                    "lower": lower,
                    "upper": upper,
                    "count": 0,
                    "mean_confidence": None,
                    "accept_rate": None,
                }
            )
            continue
        mean_conf = sum(e.stated_confidence for e in bucket) / len(bucket)
        accept_rate = sum(1.0 for e in bucket if e.human_accepted) / len(bucket)
        breakdown.append(
            {
                "lower": lower,
                "upper": upper,
                "count": len(bucket),
                "mean_confidence": mean_conf,
                "accept_rate": accept_rate,
            }
        )

    return {
        "brier": brier_score(session, run_id),
        "ece": expected_calibration_error(session, bins=bins, run_id=run_id),
        "total_reviewed": len(reviewed),
        "total_unreviewed": total_unreviewed,
        "bin_breakdown": breakdown,
    }
