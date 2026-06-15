"""Ad-hoc verification: confirm the demo CCIS workbook exercises EVERY
deterministic rule #8 lane in engine.rules.classify_row, so the demo can
showcase every auto-status feature of the app (NA, internal inheritance,
CSP-provided inheritance, DoD-auto, unclear-escalate) plus the LLM hand-off
lane (NO_AUTO_RULE) -- not just the happy "Local -> LLM" path.

This reads the BUILT demo workbook through the faithful production reader
(excel.ccis_reader.read_workbook_index) and runs the production classifier
(engine.rules.classify_row) over each CcisRow, then asserts that every
AutoStatusVerdict is hit by at least one fixture and that the specific
anchor rows land in their intended lane.

Run:  backend/.venv/Scripts/python.exe demo/_verify_ccis_coverage.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

from cybersecurity_assessor.engine import rules as r
from cybersecurity_assessor.engine.rules import AutoStatusVerdict as V
from cybersecurity_assessor.excel import ccis_reader

DEMO = Path(__file__).parent
WORKBOOK = DEMO / "ccis" / "CCIS_Example System_Demo_System_2026May.xlsx"

# Every verdict the deterministic engine can emit must be demonstrated by at
# least one demo fixture. NO_AUTO_RULE is the LLM hand-off lane (the rows the
# assessor actually reasons over).
REQUIRED_VERDICTS: tuple[AutoStatusVerdict, ...] = (
    V.COMPLIANT_8A,
    V.NOT_APPLICABLE_8B,
    V.UNCLEAR_8C,
    V.NO_AUTO_RULE,
)

# Anchor rows: (control_id, expected verdict, expected rule, why it's here).
# control_id is matched case-insensitively as a substring of CcisRow.control_id
# so "AC-1" tolerates the reader's canonical "AC-1" / "AC-1(0)" forms.
ANCHORS: list[tuple[str, "AutoStatusVerdict", str | None, str]] = [
    ("AC-1", V.COMPLIANT_8A, "8a", "DoD-level auto-compliant phrase in col K"),
    ("AU-4", V.COMPLIANT_8A, "8a", "internal inheritance ('inherited from the enterprise') col K"),
    ("AC-18", V.NOT_APPLICABLE_8B, "8b", "documented scope exclusion in col Q"),
    ("PE-3", V.COMPLIANT_8A, "8a", "CSP-provided ('implemented by AWS') col Q"),
    ("SC-7", V.COMPLIANT_8A, "8a", "structural inheritance (col L names a source)"),
    ("CP-7", V.UNCLEAR_8C, "8c", "bare 'inherited from' with no source -> escalate"),
    ("SC-13", V.NO_AUTO_RULE, None, "no rule fires -> LLM assessment (NC feeder)"),
]


def _find_row(rows, control_id: str):
    target = control_id.lower()
    for row in rows:
        if row.control_id and target in row.control_id.lower():
            return row
    return None


def main() -> int:
    index = ccis_reader.read_workbook_index(WORKBOOK)
    rows = index.rows
    print(f"Read {len(rows)} CCI rows from {WORKBOOK.name}\n")

    # --- Full sweep: classify every row, tally verdicts ---
    print("=== classify_row sweep (all rows) ===")
    seen: dict[AutoStatusVerdict, list[str]] = {v: [] for v in V}
    for row in rows:
        res = r.classify_row(row)
        seen[res.verdict].append(row.control_id)
        rule = res.rule or "-"
        trig = (res.trigger_phrase or "")[:48]
        print(f"  {row.control_id:<14} {res.verdict.value:<16} rule={rule:<3} {trig}")

    failures = 0

    # --- Assertion 1: every required verdict lane is populated ---
    print("\n=== lane coverage ===")
    for v in REQUIRED_VERDICTS:
        hits = seen.get(v, [])
        mark = "OK " if hits else "MISS"
        print(f"  [{mark}] {v.value:<16} ({len(hits)}): {', '.join(hits) or '<none>'}")
        if not hits:
            failures += 1

    # --- Assertion 2: each anchor row lands in its intended lane ---
    print("\n=== anchor rows ===")
    for control_id, expect_v, expect_rule, why in ANCHORS:
        row = _find_row(rows, control_id)
        if row is None:
            failures += 1
            print(f"  [MISS] {control_id:<8} row not found in workbook -- {why}")
            continue
        res = r.classify_row(row)
        ok = res.verdict == expect_v and (expect_rule is None or res.rule == expect_rule)
        mark = "OK " if ok else "FAIL"
        if not ok:
            failures += 1
        print(
            f"  [{mark}] {control_id:<8} got {res.verdict.value}/{res.rule} "
            f"expected {expect_v.value}/{expect_rule} -- {why}"
        )

    print()
    if failures:
        print(f"-> {failures} FAILURE(S): demo does NOT yet cover every lane.")
        return 1
    print("-> ALL lanes covered and every anchor row classified as intended.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
