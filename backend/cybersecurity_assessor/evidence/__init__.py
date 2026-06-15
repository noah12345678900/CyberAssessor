"""Evidence ingest, extraction, and tagging.

The pipeline is split into three layers so each piece is independently
testable and the heavy third-party libraries (pdfplumber, python-docx,
python-pptx) can stay optional at import time:

* :mod:`ingest` — walks a folder, hashes files, dispatches to the right
  extractor, persists ``Evidence`` rows, kicks off tagging.
* :mod:`extractors` — one module per file type. Each exposes
  ``extract(path) -> ExtractedDoc``. STIG parsers also produce
  ``StigFinding`` rows.
* :mod:`tagger` — applies doc-number regex + family keyword heuristics
  against the loaded ``Objective`` catalog to produce ``EvidenceTag``
  rows.

The tagger is deliberately deterministic (no LLM). Embedding-based
search is deferred to v0.2 — the doc-number regex covers the common
case where prior assessors cited USD#### numbers in column U of the
CCIS workbook, which is the highest-signal tagging path.
"""

from .extractors.base import ExtractedDoc, ExtractorError
from .ingest import IngestSummary, ingest_folder

__all__ = [
    "ExtractedDoc",
    "ExtractorError",
    "IngestSummary",
    "ingest_folder",
]
