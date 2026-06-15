"""PDF extractor — three-stage pipeline.

Stage 1 — **pdfplumber** (primary).
    Best layout-aware text extraction; handles tables well. Raises on
    permission-flagged / malformed-xref PDFs, which is most of what DoD
    signs.

Stage 2 — **pypdf** (fallback for born-digital but pdfplumber-hostile).
    Permissive parser: ignores extraction-disallowed permission flags,
    tolerates malformed xref tables, attempts empty-password decrypt.
    Catches the vast majority of DoD-signed policy PDFs.

Stage 3 — **Tesseract OCR** (last resort for scan-only PDFs).
    When stages 1 & 2 return empty/sparse text, render each page to a
    PIL image via pypdfium2 and OCR via pytesseract. Triggered only
    when the prior stages produced essentially no characters — so
    born-digital PDFs never pay the OCR cost.

    The Tesseract *binary* must be installed separately. The Python
    wrapper (pytesseract) is on pip but it shells out to ``tesseract.exe``.
    On Windows, install the UB-Mannheim build:
        https://github.com/UB-Mannheim/tesseract/wiki
    The installer is a per-user MSI — no admin rights needed. After
    install, ensure ``tesseract.exe`` is on PATH (the installer offers
    a checkbox for this).

    If Tesseract is missing, we don't crash — the extractor logs a
    one-line hint, returns whatever text the earlier stages produced
    (possibly empty), and the file still lands in Evidence with the
    filename as a tagging hint.

Image-only / scan PDFs with no text layer used to return empty text and
get flagged for manual review. With OCR they now extract automatically.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import PurePosixPath
from typing import BinaryIO

from ...models import EvidenceKind
from .base import ExtractedDoc, ExtractorError, register, resolve_doc_number

logger = logging.getLogger(__name__)

# Heuristic for "essentially no text" — under this many characters across the
# whole document, assume the PDF is scan-only and try OCR. 40 is generous
# enough to skip OCR on a PDF that genuinely has just a title page of body
# text, but low enough that a 50-page scan with one stray "Page 1" footer
# won't be mistaken for born-digital. Tune if false positives show up.
_OCR_THRESHOLD_CHARS = 40

# DPI for OCR rendering. 200 is the standard "good enough" for typed text;
# 300 buys ~30% better accuracy at 2x the CPU. 200 keeps single-page OCR
# under ~2s on a typical laptop CPU.
_OCR_DPI = 200


def _extract_with_pypdf(stream: BinaryIO, name: str) -> tuple[list[str], dict]:
    """Fallback path — pypdf is laxer about permission flags / xref damage.

    Returns (pages, metadata) in the same shape the pdfplumber branch produces
    so the caller can stitch the final ExtractedDoc identically. Raises on
    its own failures; the caller decides whether to surface or swallow.
    """
    from pypdf import PdfReader  # type: ignore[import-not-found]

    # strict=False matches pdfplumber's permissiveness — DoD policy PDFs
    # frequently have malformed xref tables that the strict parser rejects.
    reader = PdfReader(stream, strict=False)
    # Some encrypted-but-not-password-protected PDFs need an empty-password
    # decrypt call before text extraction works. Cheap to try; ignore failures.
    if reader.is_encrypted:
        try:
            reader.decrypt("")
        except Exception:
            pass
    pages = [(page.extract_text() or "") for page in reader.pages]
    meta_obj = reader.metadata or {}
    # PdfReader.metadata is a DocumentInformation mapping; dict() works.
    meta = dict(meta_obj) if meta_obj else {}
    return pages, meta


def _tesseract_available() -> bool:
    """Best-effort detection of an installed Tesseract binary.

    Checks ``PATH`` via ``shutil.which`` first (cheap), then asks pytesseract
    for the version (catches cases where ``tesseract_cmd`` was set explicitly
    via env or config). Either positive result is enough.
    """
    if shutil.which("tesseract"):
        return True
    try:
        import pytesseract  # type: ignore[import-not-found]

        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


def _extract_with_ocr(stream: BinaryIO, name: str) -> tuple[list[str], dict]:
    """Stage-3 OCR fallback — render each page and run Tesseract.

    Returns (pages, metadata) shaped like the other stages. ``metadata``
    is empty because pdfium doesn't surface the same /Info dict as
    pdfplumber/pypdf; the filename stem is the title fallback anyway.

    Raises if pypdfium2 can't open the file or Tesseract fails on every
    page. Empty per-page strings are kept — they let the caller compute
    an honest page_count.
    """
    import pypdfium2 as pdfium  # type: ignore[import-not-found]
    import pytesseract  # type: ignore[import-not-found]

    # Rewind defensively — the stream may have been read twice already.
    try:
        stream.seek(0)
    except Exception:
        pass
    data = stream.read()
    pdf = pdfium.PdfDocument(data)
    try:
        pages: list[str] = []
        # OCR scale: pypdfium2's scale=1 == 72 DPI, so DPI / 72 gives the
        # multiplier. 200 DPI is the sweet spot for typed text accuracy
        # vs CPU cost.
        scale = _OCR_DPI / 72
        for page_idx in range(len(pdf)):
            page = pdf[page_idx]
            try:
                pil_image = page.render(scale=scale).to_pil()
                text = pytesseract.image_to_string(pil_image) or ""
                pages.append(text.strip())
            except Exception as page_exc:
                # One bad page shouldn't tank the whole doc — log and
                # continue with an empty placeholder so page_count stays
                # truthful and any earlier pages still land.
                logger.warning(
                    "OCR failed on page %d of %s: %s", page_idx + 1, name, page_exc
                )
                pages.append("")
            finally:
                page.close()
        return pages, {}
    finally:
        pdf.close()


@register(".pdf")
def extract_pdf(stream: BinaryIO, name: str) -> ExtractedDoc:
    """Extract text from a PDF using the three-stage pipeline.

    Concatenates each page with form-feed delimiters so downstream
    consumers can split if they need page-level context. Title comes
    from PDF metadata (``Title`` field) when present.

    The returned ``metadata`` dict carries ``extraction_method`` so the
    UI / sweep scorer can tell whether text came from a clean parse or
    from OCR (which is noisier and may want different downstream weighting).
    """
    try:
        import pdfplumber  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ExtractorError(
            "pdfplumber is not installed — add it to backend/pyproject.toml "
            "to extract PDF evidence."
        ) from exc

    stem = PurePosixPath(name).stem

    pages: list[str]
    meta: dict
    method: str

    # ── Stage 1: pdfplumber ────────────────────────────────────────────────
    try:
        with pdfplumber.open(stream) as pdf:
            pages = [page.extract_text() or "" for page in pdf.pages]
            meta = pdf.metadata or {}
        method = "pdfplumber"
    except Exception as primary_exc:  # pragma: no cover - errors are diverse
        # ── Stage 2: pypdf ────────────────────────────────────────────────
        logger.info(
            "pdfplumber failed on %s (%s) — trying pypdf", name, primary_exc
        )
        try:
            stream.seek(0)
        except Exception:
            pass
        try:
            pages, meta = _extract_with_pypdf(stream, name)
            method = "pypdf"
        except Exception as fallback_exc:
            # Both stage-1 and stage-2 raised — try OCR before giving up,
            # because the same exception can come from "permission flag +
            # scan-only" PDFs where neither parser can read the metadata.
            logger.info(
                "pypdf also failed on %s (%s) — trying OCR", name, fallback_exc
            )
            if not _tesseract_available():
                raise ExtractorError(
                    f"pdfplumber failed on {name}: {primary_exc}; "
                    f"pypdf fallback also failed: {fallback_exc}; "
                    f"OCR unavailable (install Tesseract from "
                    f"https://github.com/UB-Mannheim/tesseract/wiki and "
                    f"ensure tesseract.exe is on PATH)"
                ) from primary_exc
            try:
                stream.seek(0)
            except Exception:
                pass
            try:
                pages, meta = _extract_with_ocr(stream, name)
                method = "ocr"
            except Exception as ocr_exc:
                raise ExtractorError(
                    f"pdfplumber failed on {name}: {primary_exc}; "
                    f"pypdf fallback also failed: {fallback_exc}; "
                    f"OCR also failed: {ocr_exc}"
                ) from primary_exc

    # ── Stage 3: OCR — kick in if stages 1/2 returned essentially nothing ──
    # Born-digital PDFs that parse cleanly will sail past this check;
    # only true scan-only docs end up paying the OCR cost.
    if method != "ocr":
        total_chars = sum(len(p) for p in pages)
        if total_chars < _OCR_THRESHOLD_CHARS:
            if _tesseract_available():
                logger.info(
                    "PDF %s parsed but text is sparse (%d chars) — running OCR",
                    name,
                    total_chars,
                )
                try:
                    stream.seek(0)
                except Exception:
                    pass
                try:
                    ocr_pages, _ = _extract_with_ocr(stream, name)
                    # Keep the richer metadata from the first parse; replace
                    # only the page text with the OCR output.
                    pages = ocr_pages
                    method = "ocr"
                except Exception as ocr_exc:
                    # OCR is an enhancement, not a requirement — if it
                    # fails here, fall through with the (sparse) original
                    # text rather than failing the whole ingest.
                    logger.warning(
                        "OCR enrichment failed for %s: %s", name, ocr_exc
                    )
            else:
                logger.info(
                    "PDF %s appears scan-only (%d chars extracted) — "
                    "install Tesseract to OCR it",
                    name,
                    total_chars,
                )

    text = "\f".join(p.strip() for p in pages if p.strip())
    title = (meta.get("Title") if isinstance(meta, dict) else None) or stem

    return ExtractedDoc(
        text=text,
        title=str(title) if title else stem,
        doc_number=resolve_doc_number(name, title, text),
        kind=EvidenceKind.PDF,
        metadata={"page_count": len(pages), "extraction_method": method},
    )
