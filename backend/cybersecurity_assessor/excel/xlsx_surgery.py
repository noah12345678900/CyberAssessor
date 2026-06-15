"""Headless surgical .xlsx cell patcher.

Treats an .xlsx workbook as a zip of XML and surgically updates target ``<c>``
cell elements in ``xl/worksheets/sheetN.xml``, appending new strings to
``xl/sharedStrings.xml`` when needed. Every other zip entry is byte-copied
verbatim, so comments, named ranges, data validation, conditional formatting,
merged cells, formulas, styles, and ``_rels/`` parts survive untouched.

This replaces the xlwings/COM dependency in :mod:`ccis_writer` — those features
were the reason the writer required a live Excel install. By byte-copying every
part we don't rewrite (and using regex surgery on the parts we do), we keep
them intact without a process boundary.

Public API:

    patch_cells(
        workbook_path,
        sheet_name,
        cells,               # {"N7": "Compliant", "O7": date(2026, 6, 5), ...}
        *,
        insert_row_before=None,   # bump rows >= N by 1; extends sqref ranges
    )

Only the stdlib is used (``zipfile``, ``xml.etree.ElementTree``, ``re``). No
new dependencies.

Notes on regex-vs-ET strategy
-----------------------------
``xl/workbook.xml`` and ``xl/sharedStrings.xml`` are parsed with ElementTree —
they're small and we control their re-serialization. The sheet XML uses regex
surgery: ET round-trips would mangle namespace prefixes, attribute ordering,
and whitespace in subtle ways that some Excel features (notably comments and
data validation references) react badly to. Surgery on a string preserves
every byte we don't explicitly touch.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import zipfile
from datetime import date, datetime
from pathlib import Path
from typing import Mapping
from xml.etree import ElementTree as ET

CellValue = str | int | float | datetime | date | bool | None

# Excel's 1900 date system anchors at 1899-12-30 (Excel treats 1900 as a
# leap year due to a legacy Lotus 1-2-3 bug, so 1900-01-01 is serial 1).
_EXCEL_EPOCH = datetime(1899, 12, 30)

# Sheet name candidates in priority order (mirrors ccis_writer/ccis_reader).
_WORKING_SHEET_NAMES = ["WORKING SHEET", "Working Sheet", "Working sheet"]

# XML namespaces used by xlsx parts.
_NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_NS_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_NS_REL = "http://schemas.openxmlformats.org/package/2006/relationships"

# Register namespaces for ET so default-namespaced output stays default-prefixed.
ET.register_namespace("", _NS_MAIN)
ET.register_namespace("r", _NS_R)

# Cell address parser: e.g. "AB12" → ("AB", 12).
_ADDR_RE = re.compile(r"^([A-Z]+)(\d+)$")

# Match a cell element by its r="ADDR" attribute (self-closing or with body).
def _cell_pattern(addr: str) -> re.Pattern[str]:
    return re.compile(
        r'<c\s+([^>]*?\br="' + re.escape(addr) + r'"[^>]*?)\s*(/>|>(.*?)</c>)',
        re.DOTALL,
    )


# Match any cell ref like A7, AB123 inside a `r="..."` attribute on a <c> tag.
_C_REF_RE = re.compile(r'(<c\b[^>]*?\br=")([A-Z]+)(\d+)(")')
# Match a row element's r="N" attribute.
_ROW_REF_RE = re.compile(r'(<row\b[^>]*?\br=")(\d+)(")')
# Match any A1-style range fragment inside an attribute. We post-process matches
# from sqref/ref/range attributes to skip column-only ($A:$A) references.
_RANGE_TOKEN_RE = re.compile(r'(\$?)([A-Z]+)(\$?)(\d+)(?::(\$?)([A-Z]+)(\$?)(\d+))?')
# Attribute carriers that hold one or more A1 ranges we need to bump on row insert.
_SQREF_ATTR_RE = re.compile(r'\b(sqref|ref|range)="([^"]+)"')

# Tags that conceptually carry sqref attributes Excel uses to scope styling,
# validation, conditional formatting, merged cells, etc. We bump rows inside
# *all* of these via _SQREF_ATTR_RE — listing them here for traceability.
_SQREF_BEARING_TAGS = (
    "mergeCell",
    "dataValidation",
    "conditionalFormatting",
    "tableColumn",
    "autoFilter",
    "tablePart",
)


def _addr_split(addr: str) -> tuple[str, int]:
    m = _ADDR_RE.match(addr)
    if not m:
        raise ValueError(f"Bad cell address: {addr!r}")
    return m.group(1), int(m.group(2))


def _col_to_index(col: str) -> int:
    """Excel column letters → 1-based index. E.g. A=1, Z=26, AA=27."""
    n = 0
    for ch in col:
        n = n * 26 + (ord(ch) - ord("A") + 1)
    return n


def _xml_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ---------------------------------------------------------------------------
# Sheet path resolution
# ---------------------------------------------------------------------------


def _read_workbook_sheets(workbook_xml: bytes) -> list[tuple[str, str]]:
    """Parse xl/workbook.xml and return ``[(sheet_name, rId), ...]``."""
    root = ET.fromstring(workbook_xml)
    pairs: list[tuple[str, str]] = []
    for sheet in root.iter(f"{{{_NS_MAIN}}}sheet"):
        name = sheet.get("name") or ""
        rid = sheet.get(f"{{{_NS_R}}}id") or ""
        if name and rid:
            pairs.append((name, rid))
    return pairs


def _read_rels_targets(rels_xml: bytes) -> dict[str, str]:
    """Parse xl/_rels/workbook.xml.rels into ``{rId: target_relative_to_xl}``."""
    root = ET.fromstring(rels_xml)
    out: dict[str, str] = {}
    for rel in root.iter(f"{{{_NS_REL}}}Relationship"):
        rid = rel.get("Id")
        target = rel.get("Target") or ""
        if rid:
            out[rid] = target
    return out


def find_sheet_xml_path(workbook_path: Path, sheet_name: str) -> str:
    """Resolve the zip-internal path to ``sheet_name`` inside ``workbook_path``.

    Returns a path like ``xl/worksheets/sheet1.xml``. Falls back through the
    ``_WORKING_SHEET_NAMES`` ladder and a case-insensitive ``"working"``
    substring match (same logic as ccis_reader/ccis_writer).

    Raises ``ValueError`` if no matching sheet is found.
    """
    with zipfile.ZipFile(workbook_path, "r") as zf:
        wb_xml = zf.read("xl/workbook.xml")
        rels_xml = zf.read("xl/_rels/workbook.xml.rels")
    sheets = _read_workbook_sheets(wb_xml)
    rels = _read_rels_targets(rels_xml)
    return _resolve_sheet_target(sheet_name, sheets, rels)


def _resolve_sheet_target(
    sheet_name: str,
    sheets: list[tuple[str, str]],
    rels: dict[str, str],
) -> str:
    # Exact match first, then case-insensitive equality, then "working" substring.
    candidates: list[str] = [sheet_name]
    if sheet_name in _WORKING_SHEET_NAMES:
        candidates.extend(c for c in _WORKING_SHEET_NAMES if c != sheet_name)
    rid: str | None = None
    for cand in candidates:
        for name, r in sheets:
            if name == cand:
                rid = r
                break
        if rid:
            break
    if rid is None:
        wanted = sheet_name.lower()
        for name, r in sheets:
            if name.lower() == wanted:
                rid = r
                break
    if rid is None and "working" in sheet_name.lower():
        for name, r in sheets:
            if "working" in name.lower():
                rid = r
                break
    if rid is None:
        raise ValueError(
            f"Sheet not found: {sheet_name!r}. "
            f"Available: {[n for n, _ in sheets]}"
        )
    target = rels.get(rid)
    if not target:
        raise ValueError(f"Sheet rId {rid!r} not found in workbook rels")
    # Targets are typically relative to xl/ (e.g. "worksheets/sheet1.xml").
    if target.startswith("/"):
        return target.lstrip("/")
    return f"xl/{target}"


# ---------------------------------------------------------------------------
# Shared strings
# ---------------------------------------------------------------------------


class _SharedStrings:
    """Mutable shared strings table backed by the original sst XML.

    ``index_of(s)`` returns the existing sst index for ``s`` or appends a new
    entry and returns its index. ``to_xml()`` serializes back to the
    ``xl/sharedStrings.xml`` byte form, preserving every entry we didn't add.
    """

    def __init__(self, xml_bytes: bytes | None) -> None:
        # Map text → index. Also keep the raw XML chunks per index so untouched
        # entries (e.g. ``<si><r>...formatted runs...</r></si>``) survive
        # verbatim. New entries are emitted as plain <si><t>...</t></si>.
        self._index_by_text: dict[str, int] = {}
        self._raw_entries: list[str] = []
        self._modified = False
        if xml_bytes is None:
            return
        text = xml_bytes.decode("utf-8")
        # Capture each <si>...</si> as a raw blob. xl/sharedStrings.xml entries
        # can be plain text (<si><t>foo</t></si>) or formatted runs
        # (<si><r>...</r><r>...</r></si>); we don't care which — we keep the
        # blob and rebuild a text-only index for matching plain values.
        for m in re.finditer(r"<si\b.*?</si>", text, re.DOTALL):
            blob = m.group(0)
            idx = len(self._raw_entries)
            self._raw_entries.append(blob)
            plain = self._extract_plain_text(blob)
            # Only register the first index per plain text — preserves
            # original sst lookups.
            if plain is not None and plain not in self._index_by_text:
                self._index_by_text[plain] = idx

    @staticmethod
    def _extract_plain_text(si_xml: str) -> str | None:
        # Plain <si><t>text</t></si> form — easy.
        m = re.match(r"<si\b[^>]*>\s*<t\b[^>]*>(.*?)</t>\s*</si>", si_xml, re.DOTALL)
        if m:
            return _xml_unescape(m.group(1))
        # Formatted-run form — concatenate every <t> inside the <si>. Won't be
        # used for new lookups (since our writes are always plain text via
        # index_of) but means the constructor sees a "best-effort" mapping.
        parts = re.findall(r"<t\b[^>]*>(.*?)</t>", si_xml, re.DOTALL)
        if parts:
            return "".join(_xml_unescape(p) for p in parts)
        return None

    def index_of(self, value: str) -> int:
        idx = self._index_by_text.get(value)
        if idx is not None:
            return idx
        idx = len(self._raw_entries)
        # preserveSpace ensures leading/trailing whitespace round-trips correctly.
        si = (
            f'<si><t xml:space="preserve">{_xml_escape(value)}</t></si>'
        )
        self._raw_entries.append(si)
        self._index_by_text[value] = idx
        self._modified = True
        return idx

    @property
    def modified(self) -> bool:
        return self._modified

    def to_xml(self) -> bytes:
        count = len(self._raw_entries)
        body = "".join(self._raw_entries)
        xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            f'<sst xmlns="{_NS_MAIN}" count="{count}" uniqueCount="{count}">'
            f"{body}</sst>"
        )
        return xml.encode("utf-8")


def _xml_unescape(text: str) -> str:
    return (
        text.replace("&quot;", '"')
        .replace("&gt;", ">")
        .replace("&lt;", "<")
        .replace("&amp;", "&")
    )


# ---------------------------------------------------------------------------
# Sheet XML patching
# ---------------------------------------------------------------------------


def _build_cell_xml(
    addr: str, value: CellValue, sst: _SharedStrings, style_attr: str
) -> str:
    """Render a single ``<c>`` element for ``addr=value``.

    ``style_attr`` is the existing ``s="N"`` fragment (with leading space) when
    replacing a cell that already had a style — preserves number/border format.
    """
    if value is None:
        return f'<c r="{addr}"{style_attr}/>'
    if isinstance(value, bool):
        return f'<c r="{addr}"{style_attr} t="b"><v>{1 if value else 0}</v></c>'
    if isinstance(value, datetime):
        serial = (value - _EXCEL_EPOCH).total_seconds() / 86400.0
        return f'<c r="{addr}"{style_attr}><v>{serial:.10g}</v></c>'
    if isinstance(value, date):
        serial = (datetime(value.year, value.month, value.day) - _EXCEL_EPOCH).days
        return f'<c r="{addr}"{style_attr}><v>{serial}</v></c>'
    if isinstance(value, (int, float)):
        return f'<c r="{addr}"{style_attr} t="n"><v>{value}</v></c>'
    # String — register in shared strings and reference by index.
    idx = sst.index_of(str(value))
    return f'<c r="{addr}"{style_attr} t="s"><v>{idx}</v></c>'


def _replace_or_insert_cell(
    sheet_xml: str, addr: str, value: CellValue, sst: _SharedStrings
) -> str:
    """Replace an existing ``<c r="ADDR">`` or insert a new one into its row.

    Preserves the ``s=`` style attribute when the cell already exists so
    number-formatting / borders / fills tied to the styles table survive.
    """
    pattern = _cell_pattern(addr)
    m = pattern.search(sheet_xml)
    if m:
        attrs = m.group(1)
        style_m = re.search(r'\bs="(\d+)"', attrs)
        style_attr = f' s="{style_m.group(1)}"' if style_m else ""
        new_cell = _build_cell_xml(addr, value, sst, style_attr)
        # Replace exactly one match (re.sub with count=1, escape via lambda).
        return pattern.sub(lambda _m: new_cell, sheet_xml, count=1)
    # Cell doesn't yet exist — insert into its row, creating the row if needed.
    col, row = _addr_split(addr)
    new_cell = _build_cell_xml(addr, value, sst, "")
    return _insert_cell_into_sheet(sheet_xml, row, col, new_cell)


def _insert_cell_into_sheet(
    sheet_xml: str, row: int, col: str, new_cell_xml: str
) -> str:
    """Insert a brand-new ``<c>`` into the right place inside ``<sheetData>``.

    If the row exists, splice the cell into the row's cell list at the proper
    column order. If the row doesn't exist, build a fresh ``<row r="N">`` and
    splice that into ``<sheetData>`` at the proper row order.
    """
    row_pattern = re.compile(
        r'(<row\b[^>]*?\br="' + str(row) + r'"[^>]*?>)(.*?)(</row>)', re.DOTALL
    )
    rm = row_pattern.search(sheet_xml)
    if rm:
        open_tag, body, close_tag = rm.group(1), rm.group(2), rm.group(3)
        new_body = _splice_cell_into_row_body(body, col, new_cell_xml)
        return sheet_xml[: rm.start()] + open_tag + new_body + close_tag + sheet_xml[rm.end() :]
    # Row doesn't exist — splice a new <row> into <sheetData> at the right spot.
    new_row = f'<row r="{row}">{new_cell_xml}</row>'
    return _splice_row_into_sheet_data(sheet_xml, row, new_row)


def _splice_cell_into_row_body(body: str, col: str, new_cell_xml: str) -> str:
    """Place ``new_cell_xml`` in column order within an existing row's body."""
    target_idx = _col_to_index(col)
    matches = list(re.finditer(r'<c\b[^>]*?\br="([A-Z]+)(\d+)"[^>]*?(?:/>|>.*?</c>)', body, re.DOTALL))
    insert_at = len(body)
    for m in matches:
        if _col_to_index(m.group(1)) > target_idx:
            insert_at = m.start()
            break
    return body[:insert_at] + new_cell_xml + body[insert_at:]


def _splice_row_into_sheet_data(sheet_xml: str, row: int, new_row_xml: str) -> str:
    sd_open = re.search(r"<sheetData\b[^>]*?>", sheet_xml)
    sd_close = re.search(r"</sheetData>", sheet_xml)
    if not sd_open or not sd_close:
        # No sheetData section — give up gracefully (very unusual).
        raise ValueError("Worksheet has no <sheetData> section")
    sd_start = sd_open.end()
    sd_end = sd_close.start()
    body = sheet_xml[sd_start:sd_end]
    # Find row position by row number.
    insert_at_in_body = len(body)
    for m in re.finditer(r'<row\b[^>]*?\br="(\d+)"', body):
        if int(m.group(1)) > row:
            insert_at_in_body = m.start()
            break
    new_body = body[:insert_at_in_body] + new_row_xml + body[insert_at_in_body:]
    return sheet_xml[:sd_start] + new_body + sheet_xml[sd_end:]


# ---------------------------------------------------------------------------
# Row insertion (bump-rows + extend-ranges)
# ---------------------------------------------------------------------------


def _bump_rows_in_sheet(sheet_xml: str, insert_at: int) -> str:
    """Bump every row >= ``insert_at`` by 1 and extend sqref ranges that span
    the insert point.

    Then insert an empty ``<row r="insert_at"/>`` so callers can populate it
    via subsequent ``patch_cells`` calls (or in the same call).
    """

    # 1) Bump <row r="N">
    def bump_row(m: re.Match[str]) -> str:
        n = int(m.group(2))
        if n >= insert_at:
            return f"{m.group(1)}{n + 1}{m.group(3)}"
        return m.group(0)

    sheet_xml = _ROW_REF_RE.sub(bump_row, sheet_xml)

    # 2) Bump <c r="LN">
    def bump_cell(m: re.Match[str]) -> str:
        n = int(m.group(3))
        if n >= insert_at:
            return f"{m.group(1)}{m.group(2)}{n + 1}{m.group(4)}"
        return m.group(0)

    sheet_xml = _C_REF_RE.sub(bump_cell, sheet_xml)

    # 3) Extend sqref-style ranges (mergeCells, dataValidation,
    #    conditionalFormatting, autoFilter, tableColumn, etc.).
    def bump_range_attr(m: re.Match[str]) -> str:
        attr_name = m.group(1)
        ranges_str = m.group(2)
        new_ranges = " ".join(
            _bump_range_token(tok, insert_at) for tok in ranges_str.split()
        )
        return f'{attr_name}="{new_ranges}"'

    sheet_xml = _SQREF_ATTR_RE.sub(bump_range_attr, sheet_xml)

    # 4) Splice in an empty <row r="insert_at"></row>. Open/close form (not
    #    self-closing) so subsequent calls to _insert_cell_into_sheet can
    #    splice <c> elements into the row body — the row_pattern requires
    #    a </row> close tag to match.
    sheet_xml = _splice_row_into_sheet_data(
        sheet_xml, insert_at, f'<row r="{insert_at}"></row>'
    )
    return sheet_xml


def _bump_range_token(token: str, insert_at: int) -> str:
    """Bump a single A1 range fragment (e.g. ``A1:B10``, ``$N$7:$N$500``).

    A row number >= ``insert_at`` is incremented. If the range *spans* the
    insert point (start < insert_at <= end), the end row is bumped so the
    range grows to include the newly-inserted row — preserving the original
    intent of mergeCells / dataValidation / conditionalFormatting.
    """
    m = _RANGE_TOKEN_RE.match(token)
    if not m:
        return token
    (
        c1_dollar,
        col1,
        r1_dollar,
        row1_str,
        c2_dollar,
        col2,
        r2_dollar,
        row2_str,
    ) = m.groups()
    row1 = int(row1_str)
    new_row1 = row1 + 1 if row1 >= insert_at else row1
    if col2 is None:
        # Single-cell ref (e.g. "$A$7").
        return f"{c1_dollar}{col1}{r1_dollar}{new_row1}"
    row2 = int(row2_str)
    # Range-end bumps if (a) it's at-or-after the insert, OR (b) the range
    # spans the insert point (start before, end after-or-at insert-1).
    if row2 >= insert_at:
        new_row2 = row2 + 1
    elif row1 < insert_at <= row2 + 1:
        # Original range ends just below the insert; extend by 1 so the new
        # row inherits sqref membership.
        new_row2 = row2 + 1
    else:
        new_row2 = row2
    return (
        f"{c1_dollar}{col1}{r1_dollar}{new_row1}:"
        f"{c2_dollar}{col2}{r2_dollar}{new_row2}"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def patch_cells(
    workbook_path: Path,
    sheet_name: str,
    cells: Mapping[str, CellValue],
    *,
    insert_row_before: int | None = None,
) -> None:
    """Patch one or more cells in an existing .xlsx workbook in place.

    Args:
        workbook_path: Absolute path to the .xlsx file.
        sheet_name: Name of the target sheet. Falls back through the
            ``_WORKING_SHEET_NAMES`` ladder and a ``"working"`` substring
            match (same behavior as ccis_reader/ccis_writer).
        cells: Mapping of A1 cell address → value. Supported value types:
            str, int, float, bool, datetime, date, None (empty cell).
            Strings are added to ``sharedStrings.xml`` and referenced by
            index. Dates are converted to Excel serial.
        insert_row_before: Optional 1-based row number. If given, every row
            >= this number is bumped by 1, sqref ranges that span the insert
            point are extended, and an empty ``<row>`` is inserted at the
            given position. ``cells`` are then applied AFTER the bump, so
            addresses should reference post-insert row numbers.

    The write is atomic — the new zip is built in a temp file then
    ``shutil.move``'d over the original. Every zip entry we don't touch is
    byte-copied verbatim, preserving comments, named ranges, data
    validation, conditional formatting, merged cells, formulas, styles, and
    every ``_rels/`` part.
    """
    workbook_path = Path(workbook_path)
    if not workbook_path.exists():
        raise FileNotFoundError(f"Workbook not found: {workbook_path}")

    # Pull every entry into memory once. xlsx files are small (a few MB at
    # most for the workbooks we deal with), and we need to rewrite the whole
    # zip anyway to maintain valid central-directory offsets.
    with zipfile.ZipFile(workbook_path, "r") as zf:
        entries: dict[str, bytes] = {name: zf.read(name) for name in zf.namelist()}
        # Preserve compression + zip-info metadata per entry.
        infos: dict[str, zipfile.ZipInfo] = {
            info.filename: info for info in zf.infolist()
        }

    # Resolve the target sheet path.
    sheets = _read_workbook_sheets(entries["xl/workbook.xml"])
    rels = _read_rels_targets(entries["xl/_rels/workbook.xml.rels"])
    sheet_path = _resolve_sheet_target(sheet_name, sheets, rels)
    if sheet_path not in entries:
        raise ValueError(
            f"Resolved sheet path {sheet_path!r} not present in workbook zip"
        )

    sheet_xml = entries[sheet_path].decode("utf-8")
    sst_bytes = entries.get("xl/sharedStrings.xml")
    sst = _SharedStrings(sst_bytes)

    if insert_row_before is not None:
        sheet_xml = _bump_rows_in_sheet(sheet_xml, insert_row_before)

    for addr, value in cells.items():
        sheet_xml = _replace_or_insert_cell(sheet_xml, addr, value, sst)

    entries[sheet_path] = sheet_xml.encode("utf-8")

    # If we added any new strings, the sst part needs to be rewritten. If the
    # workbook had no sst yet (rare for non-trivial sheets), we need to add
    # it AND register a relationship + content-type override.
    if sst.modified:
        sst_xml = sst.to_xml()
        had_sst = "xl/sharedStrings.xml" in entries
        entries["xl/sharedStrings.xml"] = sst_xml
        if not had_sst:
            _register_shared_strings_part(entries, infos)

    _rewrite_zip(workbook_path, entries, infos)


def _register_shared_strings_part(
    entries: dict[str, bytes], infos: dict[str, zipfile.ZipInfo]
) -> None:
    """Add the rel + content-type override for a freshly-created sst part.

    Most real workbooks already ship a non-empty ``xl/sharedStrings.xml``;
    this branch is the safety net for the rare case of a sheet that had
    only number/inline-string cells before our first write.
    """
    rels_path = "xl/_rels/workbook.xml.rels"
    rels_xml = entries[rels_path].decode("utf-8")
    # Pick an unused rId.
    existing_ids = set(re.findall(r'Id="(rId\d+)"', rels_xml))
    n = 1
    while f"rId{n}" in existing_ids:
        n += 1
    new_id = f"rId{n}"
    new_rel = (
        f'<Relationship Id="{new_id}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" '
        'Target="sharedStrings.xml"/>'
    )
    rels_xml = rels_xml.replace("</Relationships>", new_rel + "</Relationships>")
    entries[rels_path] = rels_xml.encode("utf-8")

    ct_path = "[Content_Types].xml"
    if ct_path in entries:
        ct_xml = entries[ct_path].decode("utf-8")
        if "sharedStrings.xml" not in ct_xml:
            override = (
                '<Override PartName="/xl/sharedStrings.xml" '
                'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
            )
            ct_xml = ct_xml.replace("</Types>", override + "</Types>")
            entries[ct_path] = ct_xml.encode("utf-8")


def _rewrite_zip(
    workbook_path: Path,
    entries: dict[str, bytes],
    infos: dict[str, zipfile.ZipInfo],
) -> None:
    """Atomically rewrite the zip with updated entries.

    New entries (those not present in ``infos``) are written with default
    deflate compression. Existing entries keep their original compression
    method so we don't accidentally inflate a workbook that was stored.
    """
    # Build into a temp file in the same directory so the final move is
    # rename-only (atomic on the same filesystem).
    parent = workbook_path.parent
    fd, tmp_path = tempfile.mkstemp(
        prefix=workbook_path.name + ".", suffix=".tmp", dir=parent
    )
    import os

    os.close(fd)
    try:
        with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as zout:
            # Preserve original order — Excel reads via the central directory
            # but some validators flag re-ordered parts.
            for name in [
                *infos.keys(),
                *(n for n in entries if n not in infos),
            ]:
                if name not in entries:
                    continue
                data = entries[name]
                if name in infos:
                    src_info = infos[name]
                    new_info = zipfile.ZipInfo(
                        filename=src_info.filename,
                        date_time=src_info.date_time,
                    )
                    new_info.compress_type = src_info.compress_type
                    new_info.external_attr = src_info.external_attr
                    new_info.create_system = src_info.create_system
                    new_info.internal_attr = src_info.internal_attr
                else:
                    new_info = zipfile.ZipInfo(filename=name)
                    new_info.compress_type = zipfile.ZIP_DEFLATED
                zout.writestr(new_info, data)
        # Replace original atomically (Windows: shutil.move handles in-place).
        shutil.move(tmp_path, workbook_path)
    except Exception:
        try:
            Path(tmp_path).unlink()
        except OSError:
            pass
        raise
