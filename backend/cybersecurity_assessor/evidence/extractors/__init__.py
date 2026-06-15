"""Extractors: one module per file type, all returning ``ExtractedDoc``.

Import the dispatcher (:func:`extract`) from this package — it picks the
right extractor by extension and lazily imports heavy third-party libs
so the package loads even when pdfplumber / python-docx / python-pptx
are not installed.
"""

from .base import ExtractedDoc, ExtractorError, ExtractorSkip, extract, register
from .dispatcher import extract_path, extract_stream, infer_kind

__all__ = [
    "ExtractedDoc",
    "ExtractorError",
    "ExtractorSkip",
    "extract",  # synonym used by ingest
    "extract_path",
    "extract_stream",
    "infer_kind",
    "register",
]
