"""Precision / recall / F1 scorer for the tagger recall eval set.

This is a *measurement tool*, not a CI gate (mirrors the convention in
``scripts/eval_workbook.py``). It runs every ``recall_*.json`` case under
``recall_cases/`` through the deterministic ``tag_evidence`` adapter and
scores the produced tag set against the case's labeled oracle:

  * ``expected.tags_must_include`` — the RECALL oracle: objectives the
    file SHOULD have been tagged to (the eMASS-folder / CTP-name ground
    truth). A missing one is a *false negative* — a recall miss, which
    per the project rule ("a miss is a failure, not a safe default") is
    the failure mode the RAG rewrite must fix.
  * ``expected.tags_must_not_include`` — the PRECISION guard: distractor
    objectives in the same catalog that must NOT be tagged. A tagged one
    is a *false positive*.

Scoring model (micro-averaged across all cases)::

    TP = produced ∩ must_include
    FN = must_include \\ produced              (recall misses)
    FP_guard = produced ∩ must_not_include    (precision violations)
    FP_extra = produced \\ (must_include ∪ must_not_include)
               — tags to catalog controls that are neither oracle-
                 positive nor a named distractor. Counted as FP too, so
                 a tagger that sprays every control can't game recall.

    precision = TP / (TP + FP_guard + FP_extra)
    recall    = TP / (TP + FN)
    f1        = 2PR / (P + R)

Why micro-average: it weights each (case, objective) pair equally, so a
case asserting two oracle objectives contributes twice as much as a
one-objective case — the right weighting when the goal is "how many of
the real-world evidence→control links does the tagger recover".

CLI::

    uv run --no-sync python tests/eval/tagger/score_recall.py
    uv run --no-sync python tests/eval/tagger/score_recall.py --json
    uv run --no-sync python tests/eval/tagger/score_recall.py --output before.json

``score_recall_cases()`` returns the report dict
(``{precision, recall, f1, totals, per_case:[...]}``) for programmatic
use (the pytest runner imports it).
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

# Make the backend package importable from any cwd, same bootstrap the
# parametrized runner uses.
_BACKEND = Path(__file__).resolve().parents[3] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from sqlmodel import select  # noqa: E402

from cybersecurity_assessor import models  # noqa: F401,E402 -- register tables
from cybersecurity_assessor.evidence.tagger import tag_evidence  # noqa: E402
from cybersecurity_assessor.models import EvidenceTag, Objective  # noqa: E402

from _fixtures import (  # noqa: E402
    _build_stig_findings,
    _load_catalog,
    _load_evidence,
    _make_session,
)

RECALL_CASES_DIR = _HERE / "recall_cases"


# ---------------------------------------------------------------------------
# Core: run one case, return the set of produced objective_id strings
# ---------------------------------------------------------------------------


def _resolve_framework_pk(case: dict[str, Any], id_map: dict[str, int]):
    """Mirror the runner's framework_id resolution (str → PK, int → passthrough)."""
    if "framework_id" not in case or case["framework_id"] is None:
        return None
    if isinstance(case["framework_id"], int):
        return case["framework_id"]
    return id_map[case["framework_id"]]


def _produced_objective_ids(case: dict[str, Any]) -> set[str]:
    """Run ``tag_evidence`` for one case and return tagged objective_id strings.

    Deterministic: no LLM client is passed, so this captures the
    *current* (pre-RAG) tagger behavior — the "before" baseline.
    """
    session, engine = _make_session()
    tmp = tempfile.TemporaryDirectory()
    try:
        id_map = _load_catalog(case, session)
        ev_block = case["evidence"]
        ev = _load_evidence(case, session, Path(tmp.name))
        stig_findings = _build_stig_findings(ev_block.get("stig_findings") or [])
        framework_pk = _resolve_framework_pk(case, id_map)

        tag_evidence(
            session,
            ev,
            text=ev_block.get("text", ""),
            stig_findings=stig_findings,
            cci_refs=ev_block.get("cci_refs"),
            evidence_type=ev_block.get("evidence_type"),
            evidence_type_signals=ev_block.get("evidence_type_signals"),
            framework_id=framework_pk,
        )
        session.commit()

        rows = session.exec(
            select(EvidenceTag, Objective)
            .join(Objective, Objective.id == EvidenceTag.objective_id)
            .where(EvidenceTag.evidence_id == ev.id)
        ).all()
        return {obj.objective_id for _tag, obj in rows}
    finally:
        session.close()
        engine.dispose()
        tmp.cleanup()


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _score_one(case: dict[str, Any]) -> dict[str, Any]:
    """Score a single case; return per-case metrics + confusion sets."""
    expected = case.get("expected") or {}
    must_include = {
        e["objective_id"] for e in (expected.get("tags_must_include") or [])
    }
    must_not_include = {
        e["objective_id"] for e in (expected.get("tags_must_not_include") or [])
    }

    produced = _produced_objective_ids(case)

    tp = produced & must_include
    fn = must_include - produced
    fp_guard = produced & must_not_include
    fp_extra = produced - must_include - must_not_include

    n_tp = len(tp)
    n_fp = len(fp_guard) + len(fp_extra)
    n_fn = len(fn)

    precision = n_tp / (n_tp + n_fp) if (n_tp + n_fp) else None
    recall = n_tp / (n_tp + n_fn) if (n_tp + n_fn) else None
    if precision and recall:
        f1 = 2 * precision * recall / (precision + recall)
    else:
        f1 = 0.0 if (n_tp + n_fp + n_fn) else None

    return {
        "case": case.get("name", "<unnamed>"),
        "tp": sorted(tp),
        "fn_recall_misses": sorted(fn),
        "fp_precision_violations": sorted(fp_guard),
        "fp_extra_tags": sorted(fp_extra),
        "produced": sorted(produced),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "passed_recall": not fn,
        "passed_precision": not fp_guard and not fp_extra,
    }


def score_recall_cases(
    cases_dir: Path = RECALL_CASES_DIR,
) -> dict[str, Any]:
    """Score every ``recall_*.json`` case and return the aggregate report.

    Returns::

        {
          "precision": float, "recall": float, "f1": float,
          "totals": {"tp": int, "fp": int, "fn": int, "cases": int},
          "per_case": [ {case-level metrics...}, ... ],
        }

    Aggregate P/R/F1 are micro-averaged: summed TP/FP/FN across cases,
    not the mean of per-case rates.
    """
    case_files = sorted(cases_dir.glob("recall_*.json"))
    if not case_files:
        raise FileNotFoundError(
            f"no recall_*.json cases found under {cases_dir}"
        )

    per_case: list[dict[str, Any]] = []
    tot_tp = tot_fp = tot_fn = 0
    for cf in case_files:
        case = json.loads(cf.read_text(encoding="utf-8"))
        result = _score_one(case)
        per_case.append(result)
        tot_tp += len(result["tp"])
        tot_fp += len(result["fp_precision_violations"]) + len(
            result["fp_extra_tags"]
        )
        tot_fn += len(result["fn_recall_misses"])

    precision = tot_tp / (tot_tp + tot_fp) if (tot_tp + tot_fp) else None
    recall = tot_tp / (tot_tp + tot_fn) if (tot_tp + tot_fn) else None
    if precision and recall:
        f1 = 2 * precision * recall / (precision + recall)
    else:
        f1 = 0.0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "totals": {
            "tp": tot_tp,
            "fp": tot_fp,
            "fn": tot_fn,
            "cases": len(case_files),
        },
        "per_case": per_case,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _fmt(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.3f}"


def _print_human(report: dict[str, Any]) -> None:
    totals = report["totals"]
    print("=" * 72)
    print("Tagger recall eval — CURRENT (pre-RAG) baseline")
    print("=" * 72)
    print(
        f"cases: {totals['cases']}   "
        f"TP: {totals['tp']}   FP: {totals['fp']}   FN: {totals['fn']}"
    )
    print(
        f"precision: {_fmt(report['precision'])}   "
        f"recall: {_fmt(report['recall'])}   "
        f"f1: {_fmt(report['f1'])}"
    )
    print("-" * 72)
    print(f"{'case':<48}{'rec':>5}{'prec':>6}  misses")
    print("-" * 72)
    for c in report["per_case"]:
        misses = ",".join(c["fn_recall_misses"]) or "-"
        viol = c["fp_precision_violations"] + c["fp_extra_tags"]
        flag = "" if not viol else f"  !FP:{','.join(viol)}"
        print(
            f"{c['case']:<48}{_fmt(c['recall']):>5}{_fmt(c['precision']):>6}"
            f"  {misses}{flag}"
        )
    print("-" * 72)
    n_recall_fail = sum(1 for c in report["per_case"] if not c["passed_recall"])
    print(
        f"{n_recall_fail}/{totals['cases']} cases miss at least one oracle "
        "objective (expected pre-RAG-rewrite)."
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Score the tagger recall eval set (precision/recall/F1)."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the full report as JSON to stdout instead of a table.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write the full report JSON to this path (e.g. before.json).",
    )
    parser.add_argument(
        "--cases-dir",
        type=Path,
        default=RECALL_CASES_DIR,
        help="Directory of recall_*.json case files.",
    )
    args = parser.parse_args(argv)

    report = score_recall_cases(args.cases_dir)

    if args.output is not None:
        args.output.write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )
        print(f"wrote report to {args.output}")

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
