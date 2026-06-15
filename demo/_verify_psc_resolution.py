"""Ad-hoc verification: confirm each per-revision demo PSC resolves 100% clean
against the demo DISA CCI source at its matching 800-53 revision.

Replicates the program_controls_loader extraction order (prose control IDs from
the Threshold text, falling back to the structured "Security Control" column)
WITHOUT a database, then checks every normalized control id is present in the
DISA source at that revision via the disa_cci_loader rev-picking logic.

Run:  backend/.venv/Scripts/python.exe demo/_verify_psc_resolution.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

from cybersecurity_assessor.catalogs import disa_cci_loader as d
from cybersecurity_assessor.catalogs import program_controls_loader as p

DEMO = Path(__file__).parent
DISA_SRC = DEMO / "cci_list" / "stig-mapping-to-nist-800-53.xlsx"
SHEET = "Ground Security Controls"


def disa_control_ids_for_rev(rev: int) -> set[str]:
    """Normalized 800-53 control ids that have at least one CCI at this rev."""
    items = d._parse_cci_xlsx(DISA_SRC)
    ids: set[str] = set()
    for it in items:
        idx = d._pick_best_nist_index(it.refs, target_revision=rev)
        if idx:
            ids.add(d._ccis_ref_to_oscal_control_id(idx))
    return ids


def psc_control_ids(psc_path: Path) -> list[tuple[str, str, str]]:
    """Replicate loader extraction. Returns (req_number, raw_source, norm_id)."""
    wb = p.load_workbook(psc_path, data_only=True)
    sheet = p._resolve_sheet(wb, SHEET)
    header_row, col_map = p._find_header_row(sheet)
    req_col = col_map.get("req_number")
    text_col = col_map.get("requirement_text")
    control_id_col = col_map.get("control_id")

    out: list[tuple[str, str, str]] = []
    for cells in sheet.iter_rows(min_row=header_row + 1):
        row = tuple(c.value for c in cells)
        if not row or all(c is None for c in row):
            continue
        req = str(row[req_col - 1]).strip() if req_col and row[req_col - 1] else ""
        req_text = str(row[text_col - 1]).strip() if text_col and row[text_col - 1] else ""

        ids = p._extract_control_ids(req_text) if req_text else []
        src = "prose"
        if not ids and control_id_col is not None:
            ids = p._extract_control_ids_direct(row[control_id_col - 1])
            src = "structured"
        for cid in ids:
            out.append((req, src, cid))
    return out


def main() -> int:
    failures = 0
    # The demo corpus targets NIST 800-53 Rev 5 exclusively. None of the PSC
    # control IDs renumber between Rev 4 and Rev 5, so the Rev 5 fixture resolves
    # 100% clean against the shipped demo DISA source even though that source
    # carries only Rev 4 references: at resolve time the loader falls back to the
    # highest available revision (Rev 4), which is exactly what we replicate here
    # via disa_control_ids_for_rev(4). A MISS therefore IS a real failure.
    FALLBACK_REV = 4  # highest revision present in the demo DISA source
    CLEAN_REVS = (5,)

    for rev in CLEAN_REVS:
        psc = DEMO / "psc" / f"Example_Program_Ground_Security_Controls_PSC_800-53r{rev}.xlsx"
        disa = disa_control_ids_for_rev(FALLBACK_REV)
        extracted = psc_control_ids(psc)
        print(f"\n=== Rev {rev} (must resolve clean): {psc.name} ===")
        print(
            f"  Demo DISA source has {len(disa)} distinct control ids "
            f"(resolved at its highest available Rev {FALLBACK_REV})"
        )
        unmapped = []
        for req, src, cid in extracted:
            ok = cid in disa
            mark = "OK " if ok else "MISS"
            print(f"  [{mark}] {req:<10} {src:<10} {cid}")
            if not ok:
                unmapped.append((req, cid))
        if unmapped:
            failures += 1
            print(f"  -> {len(unmapped)} UNMAPPED: {unmapped}")
        else:
            print(f"  -> ALL {len(extracted)} control ids resolve clean for Rev {rev}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
