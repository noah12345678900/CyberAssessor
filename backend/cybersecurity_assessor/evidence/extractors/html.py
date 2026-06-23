"""HTML report extractor (`.html` / `.htm`).

SCAP tools (SCC, OpenSCAP `oscap ... --report`, ACAS) auto-generate a
human-readable HTML summary alongside the machine-readable XCCDF/ARF
results. Those summaries restate the pass/fail counts, host, and rule
titles in prose — useful to keep searchable so a control narrative can
cite the rendered report a human actually looked at.

We strip tags with the stdlib :mod:`html.parser` (no bs4 / lxml
dependency): script/style bodies are dropped, block-level tags become
line breaks, and entities are unescaped. The result is plain text that
flows into the same tagger/doc-number pipeline as ``.txt``.
"""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import PurePosixPath
from typing import BinaryIO

from ...models import EvidenceKind
from .base import ExtractedDoc, ExtractorError, register, resolve_doc_number

_DECODE_FALLBACKS = ("utf-8-sig", "utf-8", "cp1252", "latin-1")

# Tags whose text content is markup/code, not human-readable report text.
_SKIP_CONTENT = {"script", "style", "head", "title"}

# Block-level tags that should force a line break so words on adjacent
# rows/cells don't fuse into one un-tokenizable run.
_BLOCK = {
    "p", "div", "br", "tr", "td", "th", "li", "h1", "h2", "h3", "h4",
    "h5", "h6", "table", "thead", "tbody", "section", "article", "header",
    "footer", "ul", "ol", "pre", "hr",
}


class _TextHarvester(HTMLParser):
    """Collect visible text + the document <title>, dropping script/style."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []
        self._skip_depth = 0
        self._in_title = False
        self.title: str | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        if tag in _SKIP_CONTENT:
            self._skip_depth += 1
            if tag == "title":
                self._in_title = True
        if tag in _BLOCK:
            self._chunks.append("\n")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in _SKIP_CONTENT and self._skip_depth > 0:
            self._skip_depth -= 1
            if tag == "title":
                self._in_title = False
        if tag in _BLOCK:
            self._chunks.append("\n")

    def handle_data(self, data: str) -> None:
        if self._in_title:
            cleaned = data.strip()
            if cleaned and not self.title:
                self.title = cleaned
            return
        if self._skip_depth:
            return
        if data.strip():
            self._chunks.append(data)

    def text(self) -> str:
        # Collapse runs of blank lines / stray whitespace introduced by the
        # block-tag breaks so the body reads cleanly and tokenizes well.
        raw = "".join(self._chunks)
        lines = [ln.strip() for ln in raw.splitlines()]
        return "\n".join(ln for ln in lines if ln)


@register(".html", ".htm")
def extract_html(stream: BinaryIO, name: str) -> ExtractedDoc:
    """Strip HTML to searchable plain text via the stdlib parser.

    Dependency-free: uses :class:`html.parser.HTMLParser` only. Decodes
    the bytes with the same UTF-8 / Windows fallbacks as the text
    extractor (SCAP HTML reports are often Windows-authored). An
    undecodable file raises :class:`ExtractorError` so the orchestrator
    records it without text.
    """
    try:
        data = stream.read()
    except OSError as exc:
        raise ExtractorError(f"Cannot read {name}: {exc}") from exc

    raw: str | None = None
    for encoding in _DECODE_FALLBACKS:
        try:
            raw = data.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    if raw is None:  # pragma: no cover - exotic encodings
        raise ExtractorError(f"Could not decode {name} with any of {_DECODE_FALLBACKS}")

    harvester = _TextHarvester()
    try:
        harvester.feed(raw)
        harvester.close()
    except Exception as exc:  # malformed HTML — keep what we parsed
        # HTMLParser is forgiving, but guard against pathological input so a
        # single bad report can't abort the ingest.
        raise ExtractorError(f"HTML parse failed on {name}: {exc}") from exc

    text = harvester.text()
    stem = PurePosixPath(name).stem
    title = harvester.title or stem

    return ExtractedDoc(
        text=text,
        title=title,
        doc_number=resolve_doc_number(name, title, text),
        kind=EvidenceKind.TEXT,
        metadata={},
    )
