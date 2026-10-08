"""Verify that Column D is the only workbook source of N/A decisions."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from cybersecurity_assessor.engine import rules
from cybersecurity_assessor.excel.ccis_reader import read_workbook_index


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("workbook", type=Path)
    args = parser.parse_args()

    rows = list(read_workbook_index(args.workbook).rows)
    column_d_na = [row for row in rows if rules.is_column_d_not_applicable(row)]
    non_na = [row for row in rows if not rules.is_column_d_not_applicable(row)]

    na_failures = [
        row.cci_id
        for row in column_d_na
        if rules.classify_row(row).verdict
        is not rules.AutoStatusVerdict.NOT_APPLICABLE_8B
        or rules.classify_row(row).trigger_column != "D"
    ]
    false_na = [
        row.cci_id
        for row in non_na
        if rules.classify_row(row).verdict
        is rules.AutoStatusVerdict.NOT_APPLICABLE_8B
    ]
    outcomes = Counter(rules.classify_row(row).verdict.value for row in non_na)

    print(f"rows={len(rows)}")
    print(f"column_d_na={len(column_d_na)}")
    print(f"non_na={len(non_na)}")
    print(f"non_na_outcomes={dict(sorted(outcomes.items()))}")
    print(f"column_d_na_failures={na_failures}")
    print(f"false_na={false_na}")

    return 1 if na_failures or false_na else 0


if __name__ == "__main__":
    raise SystemExit(main())
