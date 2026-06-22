"""Tagger RECALL eval — labeled-oracle harness (xfail until RAG rewrite).

Companion to ``test_tagger_precision.py``. That file pins CURRENT
deterministic behavior and stays green. *This* file holds the
``recall_cases/recall_*.json`` set: realistic eMASS Body-of-Evidence
files (Linux ``script(1)`` terminal captures, GUI screenshot OCR text,
STIG ``.xlsx`` exports) that tagged to ZERO controls in the field
because their vocabulary has near-zero lexical overlap with NIST control
prose — the exact failure mode the RAG rewrite must fix.

Why ``xfail`` instead of plain asserts
--------------------------------------
Every recall case is *expected to fail* against today's tagger (no
control-ID string, no scrapable CCI, too terse / too low-overlap for the
Tier-5 TF-IDF backstop). If these were plain assertions they'd redden
the suite permanently and the team would learn to ignore the red.

Marking each case ``xfail(strict=False)`` keeps the suite green while
still *executing* every case (so the scorer's confusion math is exercised
on every run). The moment the RAG rewrite lets a case recover its oracle
objectives, pytest reports it as **XPASS** — a loud, non-failing signal
that the gap closed. Flip that case's expectation (remove the marker) in
the same slice that lands the fix; the removed marker is the gate that
proves the recall win is real and didn't widen precision.

The aggregate "before" numbers come from ``score_recall.py`` (run it
directly); this file is the per-case correctness ledger.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[3] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from cybersecurity_assessor import models  # noqa: F401,E402 -- register tables

from score_recall import _score_one  # noqa: E402

RECALL_CASES_DIR = _HERE / "recall_cases"
RECALL_CASE_FILES = sorted(RECALL_CASES_DIR.glob("recall_*.json"))


def test_recall_cases_directory_is_not_empty() -> None:
    """Fail loudly if the recall cases dir is missing or empty.

    Without this, an accidentally-deleted ``recall_cases/`` collects zero
    parametrize IDs and reports green — masking total harness failure.
    """
    assert RECALL_CASES_DIR.exists(), (
        f"recall_cases directory missing: {RECALL_CASES_DIR}"
    )
    assert RECALL_CASE_FILES, (
        f"no recall_*.json files under {RECALL_CASES_DIR}"
    )


@pytest.mark.xfail(
    reason="recall miss expected pre-RAG-rewrite; XPASS = the gap closed",
    strict=False,
)
@pytest.mark.parametrize(
    "case_path", RECALL_CASE_FILES, ids=lambda p: p.stem
)
def test_tagger_recall_case(case_path: Path) -> None:
    """Assert the tagger recovers every oracle objective for one case.

    Recall assertion only: every ``tags_must_include`` objective must be
    produced (no false negatives). Precision violations are reported by
    the scorer's aggregate but are not what gates *this* recall ledger —
    the precision suite (``test_tagger_precision.py``) owns the
    no-spray invariant. We DO surface any precision violation in the
    failure message so a fix that trades recall for spray is visible.
    """
    case = json.loads(case_path.read_text(encoding="utf-8"))
    result = _score_one(case)

    if result["fn_recall_misses"]:
        viol = (
            result["fp_precision_violations"] + result["fp_extra_tags"]
        )
        raise AssertionError(
            f"{case['name']}: recall miss — oracle objectives not tagged: "
            f"{result['fn_recall_misses']}\n"
            f"  produced: {result['produced']}\n"
            f"  precision violations (if any): {viol}"
        )
