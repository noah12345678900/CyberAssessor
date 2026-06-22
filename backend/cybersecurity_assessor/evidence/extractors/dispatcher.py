"""Dispatcher: pick the right extractor for a path or stream.

Importing this module imports every extractor sub-module so their
``@register`` decorators populate the shared registry. Heavy
third-party deps remain lazy — they're only touched when their
extractor's ``extract()`` is actually called.

Two public entry points:

* :func:`extract_path` — opens a local file and dispatches by suffix.
  Convenience wrapper for callers that already have a ``Path``.
* :func:`extract_stream` — pure stream-based dispatch. Use this for
  archive members, cloud blobs, NFS reads, or anything else where the
  bytes don't live at a stable filesystem path.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import BinaryIO

from ...models import EvidenceKind
from .base import ExtractedDoc, ExtractorError, extract as _extract_via_registry

# Import sub-modules for their side effect (registering callables).
# Order does not matter; the dict keys are unique by extension.
from . import diagram as _diagram  # noqa: F401
from . import docx as _docx  # noqa: F401
from . import image as _image  # noqa: F401
from . import nessus as _nessus  # noqa: F401
from . import pcap as _pcap  # noqa: F401
from . import pdf as _pdf  # noqa: F401
from . import pptx as _pptx  # noqa: F401
from . import stig_ckl as _stig_ckl  # noqa: F401
from . import stig_cklb as _stig_cklb  # noqa: F401
from . import stig_xccdf as _stig_xccdf  # noqa: F401
from . import text as _text  # noqa: F401
from . import xlsx as _xlsx  # noqa: F401


# ---------------------------------------------------------------------------
# Extension -> EvidenceKind mapping
# ---------------------------------------------------------------------------

_KIND_BY_SUFFIX = {
    ".pdf": EvidenceKind.PDF,
    ".docx": EvidenceKind.DOCX,
    ".pptx": EvidenceKind.PPTX,
    ".xlsx": EvidenceKind.XLSX,
    ".xlsm": EvidenceKind.XLSX,
    ".ckl": EvidenceKind.STIG_CKL,
    ".cklb": EvidenceKind.STIG_CKLB,
    ".xml": EvidenceKind.STIG_XCCDF,  # XCCDF lives in .xml; sniff inside
    ".arf": EvidenceKind.STIG_XCCDF,  # ARF wraps XCCDF; same extractor/kind
    ".nessus": EvidenceKind.NESSUS,
    ".txt": EvidenceKind.TEXT,
    ".md": EvidenceKind.TEXT,
    ".log": EvidenceKind.TEXT,
    ".csv": EvidenceKind.TEXT,
    ".json": EvidenceKind.TEXT,
    # Packet captures — summary digest extractor (stdlib, dependency-free).
    ".pcap": EvidenceKind.PCAP,
    ".pcapng": EvidenceKind.PCAP,
    ".cap": EvidenceKind.PCAP,
    # Raster images (no OCR — filename/metadata tagging only).
    ".png": EvidenceKind.IMAGE,
    ".jpg": EvidenceKind.IMAGE,
    ".jpeg": EvidenceKind.IMAGE,
    ".gif": EvidenceKind.IMAGE,
    ".bmp": EvidenceKind.IMAGE,
    ".tif": EvidenceKind.IMAGE,
    ".tiff": EvidenceKind.IMAGE,
    # Vector/structured diagrams (shape/label text extracted via stdlib).
    ".vsdx": EvidenceKind.DIAGRAM,
    ".svg": EvidenceKind.DIAGRAM,
}


def infer_kind(name: str | Path) -> EvidenceKind:
    """Map a filename (or path) to an ``EvidenceKind`` purely by extension.

    Accepts a plain string (e.g. a zip member name or cloud key) or a
    ``Path``. Returns ``OTHER`` for anything not in the table. The
    extractor will error out, the ingest orchestrator will record the
    file with empty text, and the tagger gets a chance via filename
    heuristics.
    """
    if isinstance(name, Path):
        suffix = name.suffix.lower()
    else:
        suffix = PurePosixPath(name).suffix.lower()
    return _KIND_BY_SUFFIX.get(suffix, EvidenceKind.OTHER)


def extract_stream(stream: BinaryIO, name: str) -> ExtractedDoc:
    """Run the registered extractor against an in-memory stream.

    Use for archive members, cloud blobs, HTTP bodies — anything where
    the bytes don't live at a stable filesystem path. ``name`` drives
    the extension lookup and is used in error messages and titles.
    """
    return _extract_via_registry(stream, name)


def extract_path(path: Path) -> ExtractedDoc:
    """Open ``path`` and run the registered extractor on its bytes.

    Convenience wrapper for the common case of a local file on disk.
    Errors propagate as :class:`ExtractorError`.
    """
    with path.open("rb") as fh:
        return _extract_via_registry(fh, path.name)


__all__ = [
    "ExtractedDoc",
    "ExtractorError",
    "extract_path",
    "extract_stream",
    "infer_kind",
]
