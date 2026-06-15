"""Diagnose T1TL loader truncation against framework_id=3 (Rev 4)."""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root on path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlmodel import Session, create_engine

from cybersecurity_assessor.catalogs.program_controls_loader import load_program_controls

import os
DB = os.path.expanduser(r"~\.cybersecurity-assessor\assessor.sqlite")
# Copy first so we don't modify live data
import shutil
DIAG_DB = os.path.expandvars(r"%TEMP%\assessor_diag.sqlite")
shutil.copy2(DB, DIAG_DB)
DB = DIAG_DB
print("Using DB:", DB)
XLSX = r"C:\Users\Noah.Jaskolski\Downloads\RMF Process and Security Controls for T1TL Ground and Space Segments_Original.xlsx"

engine = create_engine(f"sqlite:///{DB}")
with Session(engine) as s:
    src = load_program_controls(
        s,
        source_name="testsda",
        workbook_path=XLSX,
        framework_id=3,
        sheet_name="Ground Security Controls",
    )

print("rows_seen:", src.__dict__["_rows_seen"])
print("maps_written:", src.__dict__["_maps_written"])
print("unmapped_ccis count:", len(src.__dict__["_unmapped_ccis"]))
print("unmapped_control_ids count:", len(src.__dict__["_unmapped_control_ids"]))
print()
print("unmapped_control_ids:")
for cid in src.__dict__["_unmapped_control_ids"]:
    print(" ", cid)
