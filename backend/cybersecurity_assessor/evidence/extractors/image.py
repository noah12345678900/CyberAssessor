"""Raster-image extractor (PNG / JPG / GIF / BMP / TIFF) with OCR.

Compliance evidence is full of *images of text*: MFA enrollment screenshots,
GPO/registry export captures, account-lockout config dialogs, scan-result
screen grabs. The pixels ARE the evidence. So this extractor runs OCR
(Tesseract, via the shared :mod:`._ocr` helper) to pull that text into the
evidence bundle the LLM reasons over — not just a filename caption.

OCR is bundled, offline, zero-setup: the v2.0 installer ships Tesseract inside
the sidecar (see ._ocr._resolve_tesseract), so OCR works on a locked-down
workstation with no admin MSI and no PATH edits.

Graceful degrade: if no OCR binary is resolvable (running from source without
the vendored copy and no system Tesseract), the extractor does NOT fail — it
falls back to dimensions/format/EXIF + a filename caption, exactly as before,
and the synthesized text is marked so the assessor knows the pixels were never
read. Either way the image lands as an Evidence row (never silently dropped),
and the zero-tag ingest warning still fires when nothing maps.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import BinaryIO

from ...models import EvidenceKind
from ._ocr import ocr_image, tesseract_available
from .base import ExtractedDoc, ExtractorError, register, resolve_doc_number


@register(".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff")
def extract_image(stream: BinaryIO, name: str) -> ExtractedDoc:
    """Read an image's text (OCR) + dimensions/format/EXIF.

    Returns an :class:`ExtractedDoc` whose ``text`` is the OCR'd content when
    a Tesseract binary is available, prefixed with the filename caption so
    filename signals (control-id / boundary-diagram tagger rules) still match.
    When OCR is unavailable the text is the caption alone, tagged
    ``[no OCR]`` so the bundle is honest about the pixels being unread.
    """
    try:
        from PIL import ExifTags, Image
    except ImportError as exc:  # pragma: no cover - Pillow is a core dep
        raise ExtractorError(
            "Pillow not installed — cannot read image evidence. "
            "Add 'pillow' to backend/pyproject.toml."
        ) from exc

    stem = PurePosixPath(name).stem
    metadata: dict = {}
    ocr_text = ""
    try:
        with Image.open(stream) as img:
            metadata["width"], metadata["height"] = img.size
            metadata["image_format"] = img.format
            metadata["mode"] = img.mode
            # EXIF is best-effort — most screenshots/diagrams carry none.
            try:
                exif = img.getexif()
                if exif:
                    metadata["exif"] = {
                        ExifTags.TAGS.get(k, str(k)): str(v)
                        for k, v in exif.items()
                        # keep it small + JSON-safe; skip binary blobs
                        if isinstance(v, (str, int, float))
                    }
            except Exception:  # pragma: no cover - exotic EXIF tables
                pass
            # OCR while the image is still open. ocr_image never raises and
            # returns "" when no binary is resolvable or nothing is found.
            if tesseract_available():
                # Normalize to a clean raster Tesseract can read. Exotic modes
                # (CMYK, I;16, F, multi-frame frame-0) can make .convert raise;
                # OCR is an enrichment, so a conversion failure must degrade to
                # the no-text caption, NOT drop the whole image. We isolate the
                # convert+OCR in its own guard so a bad raster never escalates
                # to ExtractorError. .convert is a no-op for RGB/L.
                try:
                    ocr_target = (
                        img.convert("RGB") if img.mode not in ("RGB", "L") else img
                    )
                    ocr_text = ocr_image(ocr_target)
                except Exception:  # noqa: BLE001 — OCR is best-effort
                    ocr_text = ""
                metadata["ocr"] = True
            else:
                metadata["ocr"] = False
    except Exception as exc:
        # Corrupt / unreadable image — record it (empty text) rather than
        # dropping it; ingest persists with kind=IMAGE and the zero-tag
        # warning will flag it for manual review.
        raise ExtractorError(f"Cannot read image {name}: {exc}") from exc

    # Filename-derived caption: keeps filename signals (control-id / boundary
    # kind rules) working AND gives the no-text guard a surface.
    caption = stem.replace("_", " ").replace("-", " ").strip()

    if ocr_text:
        # Real pixel content recovered. Lead with the caption so filename
        # signals still match, then the OCR body the LLM actually assesses.
        header = f"[image] {caption}" if caption else "[image]"
        text = f"{header}\n{ocr_text}"
    elif metadata.get("ocr"):
        # OCR ran but found no text (blank/graphic-only image). Be explicit so
        # the assessor doesn't mistake silence for "no evidence to read".
        text = f"[image — OCR found no text] {caption}".strip()
    else:
        # No OCR binary available — honest marker so a Compliant verdict can't
        # rest on pixels nobody read.
        text = f"[image — no OCR] {caption}".strip()

    return ExtractedDoc(
        text=text,
        title=stem,
        doc_number=resolve_doc_number(name, stem, ocr_text),
        kind=EvidenceKind.IMAGE,
        metadata=metadata,
    )
