"""Plain-text extractor.

Handles ``.txt``, ``.md``, ``.log``, ``.csv``, ``.json``. Decodes UTF-8 with
fallbacks for Windows-1252 / Latin-1 since prior-assessor logs are
frequently exported from Windows tools with no BOM.
"""

from __future__ import annotations

import csv
import io
import json as _json
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


def _prettify_json(text: str) -> str:
    """Re-render JSON with indentation so keys/values tokenize cleanly.

    A minified config export (``{"selinux":"enforcing","fips":true}``) is
    one long token-poor line; pretty-printing puts each key/value on its
    own line so the tagger's lexical + semantic lanes see ``selinux`` and
    ``enforcing`` as distinct tokens. Best-effort: invalid JSON falls back
    to the raw text unchanged (a ``.json`` file that isn't valid JSON is
    still useful plain text).
    """
    try:
        obj = _json.loads(text)
    except (ValueError, TypeError):
        return text
    try:
        return _json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=True)
    except (ValueError, TypeError):  # pragma: no cover - non-serializable
        return text


@register(".txt", ".md", ".log", ".csv", ".json")
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
    lname = name.lower()
    if lname.endswith(".csv"):
        hosts = _csv_hostnames(text)
        if hosts:
            metadata["hostnames"] = hosts
    elif lname.endswith(".json"):
        # Pretty-print for tokenization; doc-number detection runs on the
        # original text below regardless.
        text = _prettify_json(text)

    return ExtractedDoc(
        text=text,
        title=stem,
        doc_number=resolve_doc_number(name, stem, text),
        kind=EvidenceKind.TEXT,
        metadata=metadata,
    )
