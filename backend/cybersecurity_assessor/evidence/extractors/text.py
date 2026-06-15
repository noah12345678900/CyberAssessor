"""Plain-text extractor.

Handles ``.txt``, ``.md``, ``.log``, ``.csv``. Decodes UTF-8 with
fallbacks for Windows-1252 / Latin-1 since prior-assessor logs are
frequently exported from Windows tools with no BOM.
"""

from __future__ import annotations

import csv
import io
from pathlib import PurePosixPath
from typing import BinaryIO

from ...models import EvidenceKind
from .base import ExtractedDoc, ExtractorError, register, resolve_doc_number

_DECODE_FALLBACKS = ("utf-8-sig", "utf-8", "cp1252", "latin-1")

# Same set as xlsx.py / asset_crosscheck — kept in sync so a user-flagged CSV
# asset list resolves the same hosts whether the cache hit or the re-parse
# path is taken.
_HOSTNAME_HEADERS = frozenset(
    {
        "hostname",
        "host",
        "host name",
        "fqdn",
        "computer name",
        "computer",
        "node name",
        "system name",
        "asset name",
        "device name",
    }
)


def _csv_hostnames(text: str) -> list[str]:
    """Return raw hostname-column values from a CSV body, or [] if none."""
    try:
        reader = csv.reader(io.StringIO(text))
        header = next(reader, None)
        if not header:
            return []
        col_idx: int | None = None
        for i, cell in enumerate(header):
            if cell is None:
                continue
            if str(cell).strip().lower() in _HOSTNAME_HEADERS:
                col_idx = i
                break
        if col_idx is None:
            return []
        out: list[str] = []
        for row in reader:
            if col_idx < len(row):
                s = (row[col_idx] or "").strip()
                if s:
                    out.append(s)
        return out
    except (csv.Error, StopIteration):
        return []


@register(".txt", ".md", ".log", ".csv")
def extract_text(stream: BinaryIO, name: str) -> ExtractedDoc:
    """Read a plain-text file and detect any USD doc number in it.

    Reads in bytes mode first then tries each encoding in turn. A truly
    undecodable file (corrupt or actually binary) raises
    ``ExtractorError`` so the orchestrator records it without text.
    """
    try:
        data = stream.read()
    except OSError as exc:
        raise ExtractorError(f"Cannot read {name}: {exc}") from exc

    stem = PurePosixPath(name).stem

    text: str | None = None
    for encoding in _DECODE_FALLBACKS:
        try:
            text = data.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    if text is None:  # pragma: no cover - exotic encodings
        raise ExtractorError(f"Could not decode {name} with any of {_DECODE_FALLBACKS}")

    metadata: dict = {}
    if name.lower().endswith(".csv"):
        hosts = _csv_hostnames(text)
        if hosts:
            metadata["hostnames"] = hosts

    return ExtractedDoc(
        text=text,
        title=stem,
        doc_number=resolve_doc_number(name, stem, text),
        kind=EvidenceKind.TEXT,
        metadata=metadata,
    )
