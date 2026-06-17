"""Vector/structured diagram extractor (Visio .vsdx, .svg).

Unlike raster images, these formats carry real, machine-readable TEXT — shape
labels, callouts, titles — so we extract it with the stdlib (no OCR, no extra
deps). A network/boundary diagram's labels ("DMZ", "firewall", host names,
"external boundary") become the document body, which then flows through the
normal tagger tiers AND the diagram→boundary-control kind rule.

- ``.vsdx`` is an OPC package (a zip of XML). Shape text lives in
  ``visio/pages/page*.xml`` inside ``<Text>`` runs.
- ``.svg`` is XML; text lives in ``<text>`` / ``<tspan>`` / ``<title>`` /
  ``<desc>`` elements.

Legacy binary ``.vsd`` (OLE compound format) is intentionally NOT handled —
there is no stdlib path; it is excluded from the ingest allowlist.
"""

from __future__ import annotations

import zipfile
from pathlib import PurePosixPath
from typing import BinaryIO

from ...models import EvidenceKind
from .base import ExtractedDoc, ExtractorError, register, resolve_doc_number


def _strip_ns(tag: str) -> str:
    """Drop an XML ``{namespace}local`` prefix → ``local``."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _vsdx_text(stream: BinaryIO, name: str) -> str:
    """Concatenate shape text from every page of a .vsdx package."""
    try:
        from defusedxml import ElementTree as ET  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - defusedxml is a dep
        raise ExtractorError(
            "defusedxml is not installed — add it to backend/pyproject.toml."
        ) from exc

    chunks: list[str] = []
    try:
        with zipfile.ZipFile(stream) as zf:
            page_xmls = [
                n for n in zf.namelist()
                if n.startswith("visio/pages/page") and n.endswith(".xml")
            ]
            for page in sorted(page_xmls):
                try:
                    root = ET.fromstring(zf.read(page))
                except Exception:
                    continue  # skip a malformed page, keep the rest
                for el in root.iter():
                    if _strip_ns(el.tag) == "Text":
                        # <Text> may hold mixed content + child runs; itertext
                        # flattens all descendant text.
                        t = "".join(el.itertext()).strip()
                        if t:
                            chunks.append(t)
    except zipfile.BadZipFile as exc:
        raise ExtractorError(f"{name} is not a valid .vsdx (zip) package: {exc}") from exc
    return "\n".join(chunks)


def _svg_text(stream: BinaryIO, name: str) -> str:
    """Concatenate text/title/desc element content from an SVG."""
    try:
        from defusedxml import ElementTree as ET  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - defusedxml is a dep
        raise ExtractorError(
            "defusedxml is not installed — add it to backend/pyproject.toml."
        ) from exc

    try:
        tree = ET.parse(stream)
    except Exception as exc:
        raise ExtractorError(f"defusedxml failed on {name}: {exc}") from exc

    chunks: list[str] = []
    for el in tree.iter():
        if _strip_ns(el.tag) in {"text", "tspan", "title", "desc"}:
            t = "".join(el.itertext()).strip()
            if t:
                chunks.append(t)
    return "\n".join(chunks)


@register(".vsdx", ".svg")
def extract_diagram(stream: BinaryIO, name: str) -> ExtractedDoc:
    """Extract embedded shape/label text from a Visio or SVG diagram."""
    stem = PurePosixPath(name).stem
    suffix = PurePosixPath(name).suffix.lower()

    if suffix == ".vsdx":
        body = _vsdx_text(stream, name)
    else:  # .svg
        body = _svg_text(stream, name)

    # Prepend a filename caption so the diagram→boundary kind rule + the
    # no-text guard have a stable surface even when a diagram is unlabeled.
    caption = stem.replace("_", " ").replace("-", " ").strip()
    text = f"[diagram] {caption}\n{body}".strip() if body else (
        f"[diagram] {caption}" if caption else ""
    )

    return ExtractedDoc(
        text=text,
        title=stem,
        doc_number=resolve_doc_number(name, stem, body),
        kind=EvidenceKind.DIAGRAM,
        metadata={"diagram_format": suffix.lstrip(".")},
    )
