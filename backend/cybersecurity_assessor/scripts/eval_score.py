"""Precision / recall scoring harness for the assessment engine.

Runs the engine against ground-truth CCI fixtures and reports per-verdict-
class precision, recall, F1, overall agreement, abstain rate, and false-
confident rate.  Outputs a human-readable table to stdout and a JSON
snapshot to ``tests/eval/scores/<ISO-date>.json`` for tracking over time.

Usage::

    # Live LLM run (requires ANTHROPIC_API_KEY or keyring):
    RUN_LIVE_LLM=1 uv --directory backend run python -m cybersecurity_assessor.scripts.eval_score

    # Compare against a saved baseline (regression gate):
    RUN_LIVE_LLM=1 uv --directory backend run python -m cybersecurity_assessor.scripts.eval_score \
        --diff tests/eval/scores/2026-06-01.json

Convention for ground-truth fixtures
-------------------------------------
Fixtures in ``tests/eval/cases/*.json`` are included in scoring iff
the top-level object contains ``"ground_truth": true``.  Fixtures
without that key (or with ``false``) are synthetic / smoke-test data
and are skipped by this script.

See ``tests/eval/SCORING.md`` for metric definitions and the
interpretation guide.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_BACKEND = Path(__file__).resolve().parents[2]  # backend/
_CASES_DIR = _BACKEND / "tests" / "eval" / "cases"
_SCORES_DIR = _BACKEND / "tests" / "eval" / "scores"

# ---------------------------------------------------------------------------
# Verdict label normalisation
# ---------------------------------------------------------------------------

# Canonical label set used in the confusion matrix.
VERDICT_CLASSES = ("Compliant", "Non-Compliant", "Not Applicable", "abstain")


def _normalise_verdict(raw: str | None) -> str:
    """Map engine / fixture verdict strings to canonical labels.

    Engine outputs ComplianceStatus enum values ("Compliant",
    "Non-Compliant", "Not Applicable") and ``None`` for abstain.
    Fixtures use the same strings (case-insensitive) or "abstain".
    """
    if raw is None:
        return "abstain"
    raw_lower = raw.strip().lower()
    mapping = {
        "compliant": "Compliant",
        "non-compliant": "Non-Compliant",
        "non compliant": "Non-Compliant",
        "noncompliant": "Non-Compliant",
        "not applicable": "Not Applicable",
        "not_applicable": "Not Applicable",
        "n/a": "Not Applicable",
        "abstain": "abstain",
        "needs_review": "abstain",
    }
    label = mapping.get(raw_lower)
    if label is None:
        raise ValueError(f"Unrecognised verdict label: {raw!r}")
    return label


# ---------------------------------------------------------------------------
# Metrics dataclass
# ---------------------------------------------------------------------------


@dataclass
class ClassMetrics:
    """Precision / recall / F1 for a single verdict class."""

    label: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0


@dataclass
class ScoreReport:
    """Full scoring output for one run."""

    timestamp: str
    total_cases: int
    confusion_matrix: dict[str, dict[str, int]]
    per_class: list[ClassMetrics]
    overall_agreement_pct: float
    abstain_rate_pct: float
    false_confident_rate_pct: float
    # Raw counts for the false-confident metric:
    false_confident_count: int
    total_with_ground_truth_verdict: int


# ---------------------------------------------------------------------------
# Confusion matrix + derived metrics
# ---------------------------------------------------------------------------


def build_confusion_matrix(
    pairs: list[tuple[str, str]],
) -> dict[str, dict[str, int]]:
    """Build a confusion matrix from (ground_truth, predicted) pairs.

    Returns ``{gt_label: {pred_label: count}}``.  Every cell in the
    ``VERDICT_CLASSES × VERDICT_CLASSES`` grid is present (zero-filled).
    """
    cm: dict[str, dict[str, int]] = {
        gt: {pred: 0 for pred in VERDICT_CLASSES} for gt in VERDICT_CLASSES
    }
    for gt, pred in pairs:
        cm[gt][pred] += 1
    return cm


def compute_class_metrics(
    cm: dict[str, dict[str, int]],
) -> list[ClassMetrics]:
    """Compute per-class precision / recall / F1 from a confusion matrix."""
    results = []
    for label in VERDICT_CLASSES:
        tp = cm[label][label]
        fp = sum(cm[gt][label] for gt in VERDICT_CLASSES if gt != label)
        fn = sum(cm[label][pred] for pred in VERDICT_CLASSES if pred != label)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        results.append(
            ClassMetrics(
                label=label,
                true_positives=tp,
                false_positives=fp,
                false_negatives=fn,
                precision=round(precision, 4),
                recall=round(recall, 4),
                f1=round(f1, 4),
            )
        )
    return results


def compute_overall_agreement(
    pairs: list[tuple[str, str]],
) -> float:
    """Overall agreement percentage.

    Convention: we exclude rows where BOTH ground-truth AND prediction are
    "abstain" from both numerator and denominator.  A ground-truth case
    whose expected verdict is "abstain" tests the engine's ability to
    recognise when it should NOT answer — counting it as agreement would
    inflate the metric.  But we DO count:

    * Ground-truth has a verdict, engine matched it → agreement.
    * Ground-truth has a verdict, engine abstained → NOT agreement (miss).
    * Ground-truth has a verdict, engine returned wrong verdict → NOT agreement.
    * Ground-truth says abstain, engine returned a verdict → NOT agreement.

    Only (abstain, abstain) pairs are excluded.
    """
    relevant = [(gt, pred) for gt, pred in pairs if not (gt == "abstain" and pred == "abstain")]
    if not relevant:
        return 0.0
    matches = sum(1 for gt, pred in relevant if gt == pred)
    return round(100 * matches / len(relevant), 2)


def compute_abstain_rate(
    pairs: list[tuple[str, str]],
) -> float:
    """Percentage of cases where ground-truth has a verdict but engine abstained.

    This is acceptable behaviour (precision > recall) but worth tracking.
    """
    with_gt_verdict = [(gt, pred) for gt, pred in pairs if gt != "abstain"]
    if not with_gt_verdict:
        return 0.0
    abstained = sum(1 for _, pred in with_gt_verdict if pred == "abstain")
    return round(100 * abstained / len(with_gt_verdict), 2)


def compute_false_confident(
    pairs: list[tuple[str, str]],
) -> tuple[float, int, int]:
    """False-confident rate: engine returned a verdict but disagreed with ground truth.

    This is the metric that should DECREASE as the engine improves.
    Returns (rate_pct, false_confident_count, total_with_gt_verdict).
    """
    with_gt_verdict = [(gt, pred) for gt, pred in pairs if gt != "abstain"]
    if not with_gt_verdict:
        return 0.0, 0, 0
    wrong = sum(
        1
        for gt, pred in with_gt_verdict
        if pred != "abstain" and pred != gt
    )
    return round(100 * wrong / len(with_gt_verdict), 2), wrong, len(with_gt_verdict)


def score_pairs(pairs: list[tuple[str, str]]) -> ScoreReport:
    """Build the full ScoreReport from (ground_truth, predicted) label pairs."""
    cm = build_confusion_matrix(pairs)
    per_class = compute_class_metrics(cm)
    agreement = compute_overall_agreement(pairs)
    abstain_rate = compute_abstain_rate(pairs)
    fc_pct, fc_count, gt_total = compute_false_confident(pairs)

    return ScoreReport(
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        total_cases=len(pairs),
        confusion_matrix=cm,
        per_class=per_class,
        overall_agreement_pct=agreement,
        abstain_rate_pct=abstain_rate,
        false_confident_rate_pct=fc_pct,
        false_confident_count=fc_count,
        total_with_ground_truth_verdict=gt_total,
    )


# ---------------------------------------------------------------------------
# Fixture loading
# ---------------------------------------------------------------------------


def load_ground_truth_cases(cases_dir: Path | None = None) -> list[dict[str, Any]]:
    """Load all ground-truth fixtures from the cases directory.

    A fixture qualifies if it has ``"ground_truth": true`` at the top
    level.  Returns the parsed JSON objects.
    """
    d = cases_dir or _CASES_DIR
    if not d.is_dir():
        return []
    cases = []
    for f in sorted(d.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Skipping %s: %s", f.name, exc)
            continue
        if data.get("ground_truth") is True:
            cases.append(data)
    return cases


# ---------------------------------------------------------------------------
# Engine invocation
# ---------------------------------------------------------------------------


def _build_row_from_fixture(case: dict) -> "CcisRow":
    """Construct a CcisRow from a ground-truth fixture's ``input`` block."""
    # Lazy import so the module can be imported for metric-math tests
    # without pulling in the full engine dependency tree.
    from ..excel.ccis_reader import CcisRow

    inp = case["input"]
    return CcisRow(
        excel_row=inp.get("excel_row", 10),
        required=inp.get("required", True),
        control_id=inp["control_id"],
        ap_acronym=inp.get("ap_acronym"),
        cci_id=inp.get("cci_id"),
        implementation_status=inp.get("implementation_status"),
        designation=inp.get("designation"),
        narrative=inp.get("narrative"),
        definition=inp.get("definition"),
        guidance=inp.get("guidance"),
        procedures=inp.get("procedures"),
        inherited=inp.get("inherited"),
        remote_inheritance=inp.get("remote_inheritance"),
        status=inp.get("status"),
        date_tested=None,
        tester=inp.get("tester"),
        results=inp.get("results"),
        previous_status=inp.get("previous_status"),
        previous_date=None,
        previous_tester=inp.get("previous_tester"),
        previous_results=inp.get("previous_results"),
    )


def run_engine_on_case(case: dict, llm_client: Any) -> str:
    """Run the engine on a fixture and return the normalised verdict label.

    Returns one of the VERDICT_CLASSES strings.
    """
    from ..engine.assessor import Assessor

    row = _build_row_from_fixture(case)
    tagged_evidence = case.get("input", {}).get("tagged_evidence")
    assessor = Assessor(llm=llm_client)
    decision = assessor.assess(row, tagged_evidence=tagged_evidence)

    if decision.needs_review or decision.status is None:
        return "abstain"
    return _normalise_verdict(decision.status.value)


# ---------------------------------------------------------------------------
# Diff / regression gate
# ---------------------------------------------------------------------------

# Thresholds for regression detection.
PRECISION_RECALL_DROP_THRESHOLD_PP = 5.0  # percentage-point drop
FALSE_CONFIDENT_INCREASE_THRESHOLD_PP = 2.0  # percentage-point increase


@dataclass
class RegressionResult:
    """Outcome of comparing current run against a baseline."""

    regressed: bool
    messages: list[str] = field(default_factory=list)


def check_regression(
    current: ScoreReport,
    baseline_path: Path,
) -> RegressionResult:
    """Compare *current* against a saved baseline JSON.

    Returns a RegressionResult.  ``regressed=True`` + messages when any
    metric crosses the threshold.
    """
    baseline_data = json.loads(baseline_path.read_text(encoding="utf-8"))
    msgs: list[str] = []

    # Per-class precision / recall
    baseline_per_class = {
        c["label"]: c for c in baseline_data.get("per_class", [])
    }
    for cm in current.per_class:
        bc = baseline_per_class.get(cm.label)
        if bc is None:
            continue
        prec_drop = (bc.get("precision", 0) - cm.precision) * 100
        rec_drop = (bc.get("recall", 0) - cm.recall) * 100
        if prec_drop > PRECISION_RECALL_DROP_THRESHOLD_PP:
            msgs.append(
                f"REGRESSION: {cm.label} precision dropped {prec_drop:+.1f}pp "
                f"({bc.get('precision', 0):.2%} -> {cm.precision:.2%})"
            )
        if rec_drop > PRECISION_RECALL_DROP_THRESHOLD_PP:
            msgs.append(
                f"REGRESSION: {cm.label} recall dropped {rec_drop:+.1f}pp "
                f"({bc.get('recall', 0):.2%} -> {cm.recall:.2%})"
            )

    # False-confident rate
    baseline_fc = baseline_data.get("false_confident_rate_pct", 0)
    fc_increase = current.false_confident_rate_pct - baseline_fc
    if fc_increase > FALSE_CONFIDENT_INCREASE_THRESHOLD_PP:
        msgs.append(
            f"REGRESSION: false-confident rate increased {fc_increase:+.1f}pp "
            f"({baseline_fc:.1f}% -> {current.false_confident_rate_pct:.1f}%)"
        )

    return RegressionResult(regressed=len(msgs) > 0, messages=msgs)


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def format_table(report: ScoreReport) -> str:
    """Human-readable summary table."""
    lines = []
    lines.append("")
    lines.append("=" * 72)
    lines.append("  EVAL SCORING REPORT")
    lines.append("=" * 72)
    lines.append(f"  Timestamp:    {report.timestamp}")
    lines.append(f"  Total cases:  {report.total_cases}")
    lines.append("")

    # Confusion matrix
    lines.append("  CONFUSION MATRIX  (rows=ground-truth, cols=predicted)")
    lines.append("  " + "-" * 68)
    header = f"  {'':18s}"
    for v in VERDICT_CLASSES:
        header += f"{v:>16s}"
    lines.append(header)
    lines.append("  " + "-" * 68)
    for gt in VERDICT_CLASSES:
        row_str = f"  {gt:18s}"
        for pred in VERDICT_CLASSES:
            row_str += f"{report.confusion_matrix[gt][pred]:>16d}"
        lines.append(row_str)
    lines.append("  " + "-" * 68)
    lines.append("")

    # Per-class metrics
    lines.append("  PER-CLASS METRICS")
    lines.append("  " + "-" * 68)
    lines.append(f"  {'Class':18s}{'Precision':>12s}{'Recall':>12s}{'F1':>12s}{'TP':>8s}{'FP':>8s}{'FN':>8s}")
    lines.append("  " + "-" * 68)
    for cm in report.per_class:
        lines.append(
            f"  {cm.label:18s}{cm.precision:>12.2%}{cm.recall:>12.2%}"
            f"{cm.f1:>12.2%}{cm.true_positives:>8d}{cm.false_positives:>8d}"
            f"{cm.false_negatives:>8d}"
        )
    lines.append("  " + "-" * 68)
    lines.append("")

    # Summary metrics
    lines.append("  SUMMARY")
    lines.append("  " + "-" * 68)
    lines.append(f"  Overall agreement:     {report.overall_agreement_pct:>6.1f}%")
    lines.append(f"  Abstain rate:          {report.abstain_rate_pct:>6.1f}%  (engine abstained when GT had verdict)")
    lines.append(f"  False-confident rate:  {report.false_confident_rate_pct:>6.1f}%  ({report.false_confident_count}/{report.total_with_ground_truth_verdict} cases)")
    lines.append("  " + "-" * 68)
    lines.append("")
    lines.append("  Key: false-confident = engine returned a verdict but disagreed")
    lines.append("       with ground truth.  This should DECREASE over time.")
    lines.append("       abstain = engine declined to answer.  Acceptable but tracked.")
    lines.append("=" * 72)
    lines.append("")
    return "\n".join(lines)


def report_to_dict(report: ScoreReport) -> dict:
    """Serialise a ScoreReport to a JSON-friendly dict."""
    return {
        "timestamp": report.timestamp,
        "total_cases": report.total_cases,
        "confusion_matrix": report.confusion_matrix,
        "per_class": [
            {
                "label": cm.label,
                "true_positives": cm.true_positives,
                "false_positives": cm.false_positives,
                "false_negatives": cm.false_negatives,
                "precision": cm.precision,
                "recall": cm.recall,
                "f1": cm.f1,
            }
            for cm in report.per_class
        ],
        "overall_agreement_pct": report.overall_agreement_pct,
        "abstain_rate_pct": report.abstain_rate_pct,
        "false_confident_rate_pct": report.false_confident_rate_pct,
        "false_confident_count": report.false_confident_count,
        "total_with_ground_truth_verdict": report.total_with_ground_truth_verdict,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``python -m cybersecurity_assessor.scripts.eval_score``."""
    parser = argparse.ArgumentParser(
        description="Run the eval scoring harness against ground-truth fixtures."
    )
    parser.add_argument(
        "--diff",
        type=Path,
        default=None,
        metavar="BASELINE.json",
        help="Compare against a saved baseline and exit nonzero on regression.",
    )
    parser.add_argument(
        "--cases-dir",
        type=Path,
        default=None,
        help="Override the fixture cases directory (default: tests/eval/cases/).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Override the scores output directory (default: tests/eval/scores/).",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    # Gate: require RUN_LIVE_LLM=1 since this harness must use real LLM
    if not os.environ.get("RUN_LIVE_LLM"):
        print(
            "ERROR: eval_score requires a live LLM.  Set RUN_LIVE_LLM=1 to proceed.",
            file=sys.stderr,
        )
        return 1

    # Load ground-truth cases
    cases = load_ground_truth_cases(args.cases_dir)
    if not cases:
        print(
            "ERROR: no ground-truth fixtures found.  "
            "Add JSON files with '\"ground_truth\": true' to tests/eval/cases/.",
            file=sys.stderr,
        )
        return 1

    print(f"Found {len(cases)} ground-truth fixture(s).  Running engine...")

    # Build LLM client
    from ..llm.client import AnthropicClient

    llm = AnthropicClient()

    # Run engine on each case and collect (ground_truth, predicted) pairs
    pairs: list[tuple[str, str]] = []
    for i, case in enumerate(cases, 1):
        case_id = case.get("id", case.get("cci_id", f"case-{i}"))
        expected_raw = case.get("expected", {}).get("status")
        expected = _normalise_verdict(expected_raw)
        print(f"  [{i}/{len(cases)}] {case_id} (expected: {expected}) ... ", end="", flush=True)
        try:
            predicted = run_engine_on_case(case, llm)
        except Exception as exc:
            log.error("Engine failed on %s: %s", case_id, exc)
            predicted = "abstain"  # treat engine crash as abstain
        match_str = "OK" if predicted == expected else f"MISMATCH (got {predicted})"
        print(match_str)
        pairs.append((expected, predicted))

    # Score
    report = score_pairs(pairs)

    # Output
    print(format_table(report))

    # Write JSON
    out_dir = args.output_dir or _SCORES_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{date.today().isoformat()}.json"
    out_path.write_text(
        json.dumps(report_to_dict(report), indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"  Scores written to {out_path}")

    # Diff
    if args.diff is not None:
        if not args.diff.is_file():
            print(f"ERROR: baseline file not found: {args.diff}", file=sys.stderr)
            return 1
        result = check_regression(report, args.diff)
        if result.regressed:
            print("\n  REGRESSION DETECTED:")
            for msg in result.messages:
                print(f"    {msg}")
            return 1
        else:
            print("\n  No regression detected vs. baseline.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
