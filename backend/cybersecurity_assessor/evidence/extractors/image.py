"""Raster-image extractor (PNG / JPG / GIF / BMP / TIFF).

Images are ingested so they can't silently vanish — but their PIXEL content
is NOT read. There is deliberately **no OCR**: Tesseract needs a system binary
(admin install, unavailable on the locked-down assessor workstation) and
easyocr drags in ~3 GB of torch, which would balloon the PyInstaller sidecar.
So an image maps to controls by (a) its filename signal — handled by the
tagger's diagram/boundary kind rule and the doc-number/control-id passes — and
(b) the metadata we extract here (dimensions, format, EXIF). The synthesized
``text`` is a short filename-derived caption so the tagger has a surface to
match and the zero-tag ingest warning still fires when nothing maps.

If real text-in-image extraction is ever needed, add an OCR path here behind a
config kill-switch — but treat that as a separate, dependency-heavy feature.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import BinaryIO

from ...models import EvidenceKind
from .base import ExtractedDoc, ExtractorError, register, resolve_doc_number


@register(".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff")
def extract_image(stream: BinaryIO, name: str) -> ExtractedDoc:
    """Read image dimensions/format/EXIF (no OCR) and a filename caption."""
    try:
        from PIL import ExifTags, Image
    except ImportError as exc:  # pragma: no cover - Pillow is a core dep
        raise ExtractorError(
            "Pillow not installed — cannot read image evidence. "
            "Add 'pillow' to backend/pyproject.toml."
        ) from exc

    stem = PurePosixPath(name).stem
    metadata: dict = {}
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
    except Exception as exc:
        # Corrupt / unreadable image — record it (empty text) rather than
        # dropping it; ingest persists with kind=IMAGE and the zero-tag
        # warning will flag it for manual review.
        raise ExtractorError(f"Cannot read image {name}: {exc}") from exc

    # Filename-derived caption: gives the tagger (control-id / kind rule) and
    # the no-text guard something to work with. Not pixel content.
    caption = stem.replace("_", " ").replace("-", " ").strip()
    text = f"[image] {caption}" if caption else ""

    return ExtractedDoc(
        text=text,
        title=stem,
        doc_number=resolve_doc_number(name, stem, ""),
        kind=EvidenceKind.IMAGE,
        metadata=metadata,
    )
