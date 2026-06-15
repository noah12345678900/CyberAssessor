"""Write Poam + PoamMilestone rows into an eMASS RMF POAM template.

Strategy: copy the user-supplied template file, then drive ``xlsx_surgery``
(pure-Python zip surgery against the underlying .xlsx XML) to write the
data area (row 13+) and optionally a few header fields. This preserves
data validation, merged cells, column widths, conditional formatting, and
the header banner without requiring a live Excel install — the writer
replaces existing ``<c>`` elements in place and leaves every other zip
entry byte-identical.

Previously this module shelled out to xlwings/COM; switching to surgery
removed the hard runtime dep on Excel and aligned the POAM export path
with ``excel/ccis_writer.py``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sqlmodel import Session, select

from ..excel.xlsx_surgery import CellValue, patch_cells
from ..models import Poam, PoamMilestone
from .template import COLS, DATA_START_ROW, EMPTY_CELL_SENTINEL, HEADER_FIELDS, SHEET_NAME

# Bundled scrubbed copy of the eMASS RMF_POAM workbook (preamble + header row
# intact, all Example System-identifying data wiped). Shipped alongside the package so
# callers don't have to locate an eMASS export to use the exporter. To refresh
# from a newer eMASS template: drop the new file into this path, run the
# scrub helper (see commit history for poam/templates/), and re-run export
# tests against a known POAM.
DEFAULT_TEMPLATE_PATH: Path = (
    Path(__file__).resolve().parent / "templates" / "rmf_poam_template.xlsx"
)

# Columns AU..BD are the Personnel + Non-Personnel resource-ledger block
# (cost codes, funded/unfunded hours and amounts, non-funding obstacles).
# The assessor's Poam model doesn't capture these — they're an eMASS-side
# bookkeeping concern — so on export we emit the EMPTY_CELL_SENTINEL ('-')
# on each POAM's first row to satisfy the importer contract: blank ⇒ "field
# never asked", '-' ⇒ "explicitly empty". Continuation rows (additional
# milestones for the same POAM) leave these blank since they inherit from
# the parent row above. See poam/template.py for the column inventory.
_RESOURCE_LEDGER_KEYS: tuple[str, ...] = (
    "personnel_cost_code",
    "personnel_funded_hours",
    "personnel_unfunded_hours",
    "personnel_non_funding_obstacle",
    "personnel_non_funding_obstacle_other",
    "non_personnel_cost_code",
    "non_personnel_funded_amount",
    "non_personnel_unfunded_amount",
    "non_personnel_non_funding_obstacle",
    "non_personnel_non_funding_obstacle_other",
)


def _fmt_date(d: datetime | None) -> str | None:
    """eMASS uses 'DD-Mmm-YYYY' (e.g. 01-Jun-2025) in date columns."""
    return d.strftime("%d-%b-%Y") if d else None


def _cell(value: object) -> CellValue:
    """Normalize a cell value for eMASS import.

    None or empty-string ⇒ EMPTY_CELL_SENTINEL ('-'); everything else passes
    through. The importer contract treats a truly blank cell as "field never
    asked" — semantically distinct from "we considered it and have nothing",
    which is what the sentinel encodes. Returning the sentinel keeps the
    written cell as a real string so ``patch_cells`` will route it through
    the shared-strings table rather than clearing the cell (which is what
    a ``None`` value would do).
    """
    if value is None:
        return EMPTY_CELL_SENTINEL
    if isinstance(value, str) and not value.strip():
        return EMPTY_CELL_SENTINEL
    # CellValue accepts str/int/float/datetime/date/bool/None.
    if isinstance(value, (str, int, float, bool, datetime)):
        return value
    # Fall back to str() for anything exotic (shouldn't happen in practice;
    # the call sites all pass strings or formatted dates).
    return str(value)


def export_poams(
    workbook_id: int,
    output_path: str | Path,
    s: Session,
    *,
    system_name: str | None = None,
    template_path: str | Path | None = None,
) -> dict:
    """Render this workbook's POAMs into a copy of the eMASS template.

    Returns a small report dict: {poams_written, milestones_written,
    output_path}.

    The exporter writes one row per Poam, then APPENDS additional rows for
    POAMs that have more than one milestone. eMASS's UI shows milestones
    inline with the POAM ID repeated on each milestone row — that's the
    shape we emit so the import round-trip is symmetric.

    ``template_path`` is an escape hatch for callers that need to target a
    program-specific eMASS export (e.g. one carrying pre-populated header
    metadata or custom data validations). When omitted, the bundled
    ``DEFAULT_TEMPLATE_PATH`` is used — that's the common case.
    """
    import shutil

    src = Path(template_path) if template_path else DEFAULT_TEMPLATE_PATH
    if not src.exists():
        raise FileNotFoundError(f"POAM template not found: {src}")

    # Resolve the destination. Callers (incl. the native folder picker) may
    # hand us a *directory* rather than a full file path; copying a file onto
    # a directory raises OSError, which the route would mis-map to a 503
    # "Excel unavailable". So if output_path is an existing directory, or
    # carries no .xlsx/.xlsm suffix, auto-name a workbook inside it.
    dst = Path(output_path)
    if dst.is_dir() or dst.suffix.lower() not in (".xlsx", ".xlsm"):
        # Auto-name with the app's standard export convention so the user
        # only has to pick a folder. Timestamp to the second keeps repeated
        # same-day exports from colliding.
        stamp = f"{datetime.now(timezone.utc):%Y-%m-%d_%H%M%S}"
        fname = f"CYBERSECURITY_ASSESSOR_POAMS_{stamp}.xlsx"
        dst = dst / fname
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)

    poams = s.exec(
        select(Poam).where(Poam.workbook_id == workbook_id).order_by(Poam.control_cluster)
    ).all()

    rows_written = 0
    milestones_written = 0

    # Build a single {address: value} map for the whole template, then make
    # one patch_cells call. xlsx_surgery walks the sheet XML once per call,
    # so batching is markedly cheaper than per-cell writes and matches the
    # ccis_writer pattern.
    cells: dict[str, CellValue] = {}

    # Optional system-name update — leave other header fields alone.
    if system_name:
        r, c = HEADER_FIELDS["system_project_name"]
        cells[_addr(r, c)] = system_name
        r2, c2 = HEADER_FIELDS["date_last_updated"]
        cells[_addr(r2, c2)] = _cell(_fmt_date(datetime.now(timezone.utc)))

    row = DATA_START_ROW
    for poam in poams:
        milestones = s.exec(
            select(PoamMilestone)
            .where(PoamMilestone.poam_id == poam.id)
            .order_by(PoamMilestone.scheduled_date)
        ).all()

        # If a POAM has no milestones (shouldn't happen — generator
        # seeds one — but possible after an import or manual delete),
        # write a single row with empty milestone fields.
        rendered_milestones = milestones or [None]

        for i, m in enumerate(rendered_milestones):
            # POAM-level fields on the first row; subsequent milestone
            # rows leave most POAM cells empty but repeat the ID so
            # the importer can re-cluster.
            cells[f"{COLS['id'].letter}{row}"] = _cell(
                poam.emass_poam_id or f"DRAFT-{poam.id}"
            )
            if i == 0:
                cells[f"{COLS['vulnerability_description'].letter}{row}"] = _cell(
                    poam.vulnerability_description
                )
                cells[f"{COLS['controls_aps'].letter}{row}"] = _cell(
                    poam.security_control_number or poam.control_cluster
                )
                cells[f"{COLS['status'].letter}{row}"] = _cell(
                    poam.status.value if poam.status else None
                )
                cells[f"{COLS['scheduled_completion_date'].letter}{row}"] = _cell(
                    _fmt_date(poam.scheduled_completion_date)
                )
                cells[f"{COLS['completion_date'].letter}{row}"] = _cell(
                    _fmt_date(poam.actual_completion_date)
                )
                cells[f"{COLS['office_org'].letter}{row}"] = _cell(poam.office_org)
                cells[f"{COLS['resources'].letter}{row}"] = _cell(
                    poam.resources_required
                )
                cells[f"{COLS['mitigations'].letter}{row}"] = _cell(poam.mitigations)
                cells[f"{COLS['comments'].letter}{row}"] = _cell(poam.comments)
                cells[f"{COLS['raw_severity'].letter}{row}"] = _cell(
                    poam.raw_severity.value if poam.raw_severity else None
                )
                cells[f"{COLS['likelihood'].letter}{row}"] = _cell(
                    poam.likelihood.value if poam.likelihood else None
                )
                cells[f"{COLS['impact'].letter}{row}"] = _cell(
                    poam.impact.value if poam.impact else None
                )
                cells[f"{COLS['relevance_of_threat'].letter}{row}"] = _cell(
                    poam.relevance_of_threat.value if poam.relevance_of_threat else None
                )
                cells[f"{COLS['residual_risk'].letter}{row}"] = _cell(
                    poam.residual_risk.value if poam.residual_risk else None
                )
                # AU..BD resource-ledger block — the Poam model doesn't
                # capture these eMASS-side bookkeeping fields, so we
                # write the sentinel on the first row of each POAM to
                # satisfy the importer contract (blank ⇒ "field never
                # asked", '-' ⇒ "explicitly empty"). Continuation
                # milestone rows leave them blank; eMASS treats those
                # as inherited from the parent row above.
                for key in _RESOURCE_LEDGER_KEYS:
                    cells[f"{COLS[key].letter}{row}"] = EMPTY_CELL_SENTINEL

            if m is not None:
                cells[f"{COLS['milestone_id'].letter}{row}"] = _cell(str(m.id))
                cells[f"{COLS['milestone_description'].letter}{row}"] = _cell(
                    m.description
                )
                cells[f"{COLS['milestone_scheduled_date'].letter}{row}"] = _cell(
                    _fmt_date(m.scheduled_date)
                )
                cells[f"{COLS['milestone_completion_date'].letter}{row}"] = _cell(
                    _fmt_date(m.completion_date)
                )
                cells[f"{COLS['milestone_status_comments'].letter}{row}"] = _cell(
                    m.changes_history
                )
                milestones_written += 1

            row += 1
        rows_written += 1

        poam.exported_at = datetime.now(timezone.utc)

    # Single sheet-rewrite pass for the entire export.
    patch_cells(dst, SHEET_NAME, cells)

    s.commit()
    return {
        "poams_written": rows_written,
        "milestones_written": milestones_written,
        "output_path": str(dst),
    }


def _addr(row: int, col: int) -> str:
    """1-based (row, col) → Excel A1 address. Header fields in template.py
    are stored as (row, col); the rest of the exporter goes straight from
    a ``PoamColumn.letter`` so this is only used for the optional system-
    name + date-updated writes above row 12."""
    letters = ""
    n = col
    while n > 0:
        n, rem = divmod(n - 1, 26)
        letters = chr(65 + rem) + letters
    return f"{letters}{row}"
