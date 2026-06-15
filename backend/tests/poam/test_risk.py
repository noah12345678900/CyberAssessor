"""Tests for poam/risk.py — the SP 800-30r1 Table I-2 5×5 matrix.

The risk numbers are auditable against the source document; if any of these
fail, someone has likely transcribed the matrix wrong, not rewritten the
algorithm.
"""

from __future__ import annotations

import pytest

from cybersecurity_assessor.models import RiskLevel
from cybersecurity_assessor.poam.risk import (
    DEFAULT_IMPACT,
    DEFAULT_LIKELIHOOD,
    LEVEL_DESCRIPTIONS,
    RISK_MATRIX,
    SCORES,
    compute_risk,
    score_to_level,
)


class TestScoreToLevel:
    """SP 800-30r1 score buckets: 0 | 1-3 | 4-6 | 7-9 | 10."""

    @pytest.mark.parametrize(
        "score, expected",
        [
            (-5, RiskLevel.VERY_LOW),  # clamped below 0
            (0, RiskLevel.VERY_LOW),
            (1, RiskLevel.LOW),
            (2, RiskLevel.LOW),
            (3, RiskLevel.LOW),
            (4, RiskLevel.MODERATE),
            (5, RiskLevel.MODERATE),
            (6, RiskLevel.MODERATE),
            (7, RiskLevel.HIGH),
            (8, RiskLevel.HIGH),
            (9, RiskLevel.HIGH),
            (10, RiskLevel.VERY_HIGH),
            (15, RiskLevel.VERY_HIGH),  # above 10 still very high
        ],
    )
    def test_score_buckets(self, score: int, expected: RiskLevel) -> None:
        assert score_to_level(score) == expected

    def test_scores_round_trip_to_their_own_level(self) -> None:
        """The canonical score for each level must bucket back to that level."""
        for level, score in SCORES.items():
            assert score_to_level(score) == level, (
                f"{level} has canonical score {score} but score_to_level "
                f"returns {score_to_level(score)}"
            )


class TestComputeRisk:
    """Spot-check the Table I-2 matrix at corners + the diagonal."""

    def test_very_low_x_very_low_is_very_low(self) -> None:
        assert compute_risk(RiskLevel.VERY_LOW, RiskLevel.VERY_LOW) == RiskLevel.VERY_LOW

    def test_very_high_x_very_high_is_very_high(self) -> None:
        assert (
            compute_risk(RiskLevel.VERY_HIGH, RiskLevel.VERY_HIGH) == RiskLevel.VERY_HIGH
        )

    def test_moderate_x_moderate_is_moderate(self) -> None:
        # Default-generator path: Mod × Mod = Mod.
        assert compute_risk(RiskLevel.MODERATE, RiskLevel.MODERATE) == RiskLevel.MODERATE

    def test_high_x_very_high_is_very_high(self) -> None:
        assert compute_risk(RiskLevel.HIGH, RiskLevel.VERY_HIGH) == RiskLevel.VERY_HIGH

    def test_very_low_x_high_is_low(self) -> None:
        # From the published table; sanity-check we didn't off-by-one a row.
        assert compute_risk(RiskLevel.VERY_LOW, RiskLevel.HIGH) == RiskLevel.LOW

    def test_low_x_very_high_is_moderate(self) -> None:
        assert compute_risk(RiskLevel.LOW, RiskLevel.VERY_HIGH) == RiskLevel.MODERATE


class TestRiskMatrixShape:
    """Matrix structural invariants — guards against accidental edits."""

    def test_all_levels_have_rows(self) -> None:
        assert set(RISK_MATRIX.keys()) == set(RiskLevel)

    def test_all_levels_have_columns(self) -> None:
        for row in RISK_MATRIX.values():
            assert set(row.keys()) == set(RiskLevel)

    def test_matrix_is_monotonic_along_impact_axis(self) -> None:
        """Holding likelihood fixed, risk must never *decrease* as impact rises."""
        order = [
            RiskLevel.VERY_LOW,
            RiskLevel.LOW,
            RiskLevel.MODERATE,
            RiskLevel.HIGH,
            RiskLevel.VERY_HIGH,
        ]
        for likelihood in order:
            scores = [SCORES[RISK_MATRIX[likelihood][impact]] for impact in order]
            assert scores == sorted(scores), (
                f"likelihood={likelihood} produces non-monotonic risk across impact: "
                f"{scores}"
            )

    def test_matrix_is_monotonic_along_likelihood_axis(self) -> None:
        """Holding impact fixed, risk must never *decrease* as likelihood rises."""
        order = [
            RiskLevel.VERY_LOW,
            RiskLevel.LOW,
            RiskLevel.MODERATE,
            RiskLevel.HIGH,
            RiskLevel.VERY_HIGH,
        ]
        for impact in order:
            scores = [SCORES[RISK_MATRIX[likelihood][impact]] for likelihood in order]
            assert scores == sorted(scores), (
                f"impact={impact} produces non-monotonic risk across likelihood: "
                f"{scores}"
            )


def test_defaults_are_moderate() -> None:
    """Generator-default risk per feedback: Mod/Mod, conservative middle."""
    assert DEFAULT_LIKELIHOOD == RiskLevel.MODERATE
    assert DEFAULT_IMPACT == RiskLevel.MODERATE


def test_level_descriptions_cover_all_levels() -> None:
    assert set(LEVEL_DESCRIPTIONS.keys()) == set(RiskLevel)
    for text in LEVEL_DESCRIPTIONS.values():
        assert text, "description must be non-empty"
