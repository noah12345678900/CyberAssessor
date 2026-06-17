"""Shared Tesseract OCR helper — one tested implementation for every path.

Both the PDF extractor (scan-only fallback) and the image extractor need to
turn pixels into text. This module is the single home for:

  * locating the Tesseract binary — bundled-first, then PATH, then a
    pytesseract version probe (covers a user's own UB-Mannheim install);
  * the render/recognize calls themselves.

BUNDLED-FIRST RESOLUTION
------------------------
The v2.0 installer ships a self-contained Tesseract under the sidecar bundle
(``backend/vendor/tesseract/`` → PyInstaller ``_internal/tesseract/`` when
frozen). That makes OCR work offline on a locked-down workstation with zero
user setup — no admin MSI, no PATH edits. :func:`_resolve_tesseract` points
``pytesseract`` at the bundled exe and sets ``TESSDATA_PREFIX`` to the bundled
``tessdata/`` the first time it's called. If the bundle isn't present (running
from source without the vendored copy), it falls back to a PATH lookup and
finally to whatever ``pytesseract`` can find on its own — so a developer with
their own Tesseract still gets OCR, and a box with none degrades gracefully
(callers treat "unavailable" as "no text", never a crash).

DPI / accuracy
--------------
200 DPI is the sweet spot for typed text (config screens, GPO exports, MFA
dialogs — our evidence): ~2s/page on a laptop CPU, and accuracy plateaus
above it for screen-captured UI text. Kept identical to the historical PDF
OCR path so PDF behavior is byte-for-byte unchanged after the extraction.
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

if TYPE_CHECKING:
    from PIL.Image import Image as PILImage

logger = logging.getLogger(__name__)

# Render DPI for OCR. pypdfium2's scale=1 == 72 DPI, so DPI/72 is the
# multiplier. 200 balances typed-text accuracy against CPU cost.
OCR_DPI = 200


def _bundled_tesseract_dir() -> Path | None:
    """Return the vendored Tesseract dir, frozen-aware.

    Frozen (PyInstaller onedir): ``<exe>/_internal/tesseract/`` —
    ``sys._MEIPASS`` points at ``_internal`` for onedir builds.
    Source tree: ``backend/vendor/tesseract/`` resolved relative to this
    file (……/cybersecurity_assessor/evidence/extractors/_ocr.py →
    backend/vendor/tesseract).
    """
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        cand = Path(meipass) / "tesseract"
        if (cand / "tesseract.exe").exists():
            return cand
    # Source-tree layout: walk up to backend/ then into vendor/tesseract.
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "vendor" / "tesseract"
        if (cand / "tesseract.exe").exists():
            return cand
        # Stop once we pass the backend/ root to avoid scanning the whole disk.
        if parent.name == "backend":
            break
    return None


@lru_cache(maxsize=1)
def _resolve_tesseract() -> str | None:
    """Locate the Tesseract binary and configure pytesseract once.

    Resolution order:
      1. Bundled vendor copy (offline, zero-setup — the shipped path).
      2. ``tesseract`` on PATH (a developer's own install).
      3. pytesseract's own default (covers an explicit ``tesseract_cmd``
         set elsewhere).

    Returns the resolved command path, or ``None`` when no binary is
    available. Cached so the filesystem probe + env mutation happen once
    per process. Side effects (setting ``pytesseract.tesseract_cmd`` and
    ``TESSDATA_PREFIX``) only fire for the bundled path — a PATH/own install
    already knows where its tessdata lives.
    """
    bundled = _bundled_tesseract_dir()
    if bundled is not None:
        exe = bundled / "tesseract.exe"
        try:
            import pytesseract  # type: ignore[import-not-found]

            pytesseract.pytesseract.tesseract_cmd = str(exe)
        except Exception:  # pragma: no cover - pytesseract is a core dep
            pass
        # Point Tesseract at the bundled language data. setdefault so an
        # operator who deliberately set TESSDATA_PREFIX wins.
        os.environ.setdefault("TESSDATA_PREFIX", str(bundled / "tessdata"))
        logger.debug("Using bundled Tesseract at %s", exe)
        return str(exe)

    on_path = shutil.which("tesseract")
    if on_path:
        return on_path

    # Last resort: ask pytesseract whether it can find one itself.
    try:
        import pytesseract  # type: ignore[import-not-found]

        pytesseract.get_tesseract_version()
        return pytesseract.pytesseract.tesseract_cmd
    except Exception:
        return None


def tesseract_available() -> bool:
    """True when an OCR binary is resolvable (bundled, PATH, or own install)."""
    return _resolve_tesseract() is not None


def ocr_image(image: "PILImage") -> str:
    """OCR a single PIL image to text. Returns ``""`` on any failure.

    Never raises — OCR is an enrichment, not a hard requirement. Callers
    that need to distinguish "no binary" from "binary ran, found nothing"
    should gate on :func:`tesseract_available` first.
    """
    if not tesseract_available():
        return ""
    try:
        import pytesseract  # type: ignore[import-not-found]

        return (pytesseract.image_to_string(image) or "").strip()
    except Exception as exc:  # pragma: no cover - exotic image/Tesseract faults
        logger.warning("OCR failed on image: %s", exc)
        return ""


def ocr_pdf_pages(stream: BinaryIO, name: str) -> tuple[list[str], dict]:
    """Render each PDF page via pypdfium2 and OCR it. (pages, metadata).

    Lifted verbatim from the historical ``pdf.py::_extract_with_ocr`` so the
    PDF scan-only path is unchanged; metadata is empty because pdfium doesn't
    surface an /Info dict. One bad page logs + yields an empty placeholder so
    page_count stays truthful and earlier pages still land.
    """
    import pypdfium2 as pdfium  # type: ignore[import-not-found]

    # Make sure the resolver has configured pytesseract before the loop.
    _resolve_tesseract()

    try:
        stream.seek(0)
    except Exception:
        pass
    data = stream.read()
    pdf = pdfium.PdfDocument(data)
    try:
        pages: list[str] = []
        scale = OCR_DPI / 72
        for page_idx in range(len(pdf)):
            page = pdf[page_idx]
            try:
                pil_image = page.render(scale=scale).to_pil()
                pages.append(ocr_image(pil_image))
            except Exception as page_exc:
                logger.warning(
                    "OCR failed on page %d of %s: %s", page_idx + 1, name, page_exc
                )
                pages.append("")
            finally:
                page.close()
        return pages, {}
    finally:
        pdf.close()
