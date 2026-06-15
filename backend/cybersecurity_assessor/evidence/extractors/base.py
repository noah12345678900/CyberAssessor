"""Shared types and registry for extractors.

Each extractor module registers a callable that takes a binary stream
and a display name, and returns an :class:`ExtractedDoc`. The dispatcher
(see :mod:`evidence.extractors.dispatcher`) picks the right callable by
file extension; new formats slot in by importing their module so the
``register`` decorator runs at import time.

Stream-based by design: the same extractor must work whether the source
is a local file, a member inside a zip archive, an HTTP response body,
or a blob from cloud storage. Extractors never touch ``Path`` — the
caller resolves whatever URI scheme it speaks into a readable
``BinaryIO`` and passes it down with a display name.

Heavy third-party libraries (pdfplumber, python-docx, python-pptx,
defusedxml) are imported lazily INSIDE the extractor functions, never
at module import. This keeps the package usable in CI environments and
in the unit-test suite where only the deterministic STIG/text paths
need to run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import BinaryIO, Callable, Dict, List, Optional

from ...models import EvidenceKind

# ---------------------------------------------------------------------------
# Shared dataclass returned by every extractor
# ---------------------------------------------------------------------------


@dataclass
class ExtractedDoc:
    """Result of extracting one source file.

    Attributes:
        text: Plain-text content. May be empty (e.g. scan-only PDF) — in
            which case downstream tagging falls back to filename.
        title: Document title from metadata if available, else the
            file stem. Used in the evidence UI list.
        doc_number: USD-series document number if found in the text or
            filename (e.g. ``"USD00050010"``). Drives the doc-number
            tagger.
        kind: Logical ``EvidenceKind`` for the source — same value
            stored on the ``Evidence`` row.
        metadata: Extractor-specific extras. Kept loose to avoid coupling
            the schema to each format's quirks. The STIG extractors stash
            their normalized findings here under
            ``metadata["stig_findings"]``.
    """

    text: str
    title: Optional[str] = None
    doc_number: Optional[str] = None
    kind: EvidenceKind = EvidenceKind.OTHER
    metadata: dict = field(default_factory=dict)


class ExtractorError(RuntimeError):
    """Raised when an extractor cannot produce text from its input.

    The orchestrator catches this and records the source as ingested
    with empty text — the tagger then falls back to filename heuristics.
    A missing optional library (e.g. pdfplumber not installed) also
    raises this, with a hint pointing at ``backend/pyproject.toml``.
    """


class ExtractorSkip(ExtractorError):
    """Raised when an extractor intentionally refuses a file.

    Distinct from :class:`ExtractorError` (which means "I tried and
    failed"); ``ExtractorSkip`` means "this file isn't evidence — drop
    it on the floor quietly, don't create an Evidence row, don't show
    it as an error in the UI." Today the only caller is the XLSX
    extractor refusing a CCIS workbook (it's the assessment target,
    not evidence), but the same path covers any future "wrong document
    type" case (template files, lock files, etc.).

    Subclasses ``ExtractorError`` so existing ``except ExtractorError``
    blocks still catch it as a safety net — callers that want to honor
    the skip semantics must check for ``ExtractorSkip`` first.
    """


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ExtractorFn = Callable[[BinaryIO, str], ExtractedDoc]
"""Signature: ``fn(stream, name) -> ExtractedDoc``.

``stream`` is a readable, binary, seekable-where-possible file-like.
``name`` is the leaf filename (no path components) — used for the
filename heuristics (doc number, title fallback) and for error messages.
"""

_REGISTRY: Dict[str, ExtractorFn] = {}


def register(*extensions: str) -> Callable[[ExtractorFn], ExtractorFn]:
    """Decorator: associate a callable with one or more file extensions.

    Extensions are stored lower-case with a leading dot. Re-registration
    overwrites silently — tests use this to swap in stubs.
    """

    def _wrap(fn: ExtractorFn) -> ExtractorFn:
        for ext in extensions:
            key = ext.lower()
            if not key.startswith("."):
                key = "." + key
            _REGISTRY[key] = fn
        return fn

    return _wrap


def extract(stream: BinaryIO, name: str) -> ExtractedDoc:
    """Look up the registered extractor for ``name``'s suffix and run it.

    Raises ``ExtractorError`` if no extractor is registered for the
    suffix. Callers that want a fall-through to a generic kind should
    catch the error and persist the source with an empty text body.
    """
    ext = PurePosixPath(name).suffix.lower()
    fn = _REGISTRY.get(ext)
    if fn is None:
        raise ExtractorError(f"No extractor registered for suffix {ext!r}")
    return fn(stream, name)


# ---------------------------------------------------------------------------
# Doc-number detection (shared)
# ---------------------------------------------------------------------------

# USD-series numbers can show up as "USD00050010", "USD-50010",
# "USD 00050010", "USD_00010082" — be liberal about separators but require
# at least 5 digits to avoid false positives like ``USD1`` in unrelated copy.
#
# Boundaries are explicit rather than ``\b`` because the program's actual
# filing convention underscore-delimits the number inside filenames/titles
# (e.g. ``snap0527core__USD00050015_Rev_D_SSP``). ``_`` is a regex word
# character, so ``\bUSD...\d{5,}\b`` silently fails on every underscore-
# delimited name — which forced doc identity to fall through to the body and
# adopt whatever USD number was cited first. We instead reject only a
# *letter* immediately before USD (so ``BOGUSD12345`` stays excluded but
# ``__USD`` / ``-USD`` / start-of-string match) and stop the digit run on a
# non-digit lookahead (so a trailing ``_`` or ``.`` doesn't break the match).
_USD_RE = re.compile(r"(?<![A-Za-z])USD[\s\-_]?0*(\d{5,})(?!\d)", re.IGNORECASE)


def find_doc_number(*hay: str) -> Optional[str]:
    """Return the first canonical USD doc number found in any haystack.

    Canonical form is ``USD`` + zero-padded 8-digit number (matches
    the program's filing convention). Returns ``None`` if no match.
    Used by the tagger's filename fallback and as the primitive behind
    :func:`resolve_doc_number`.

    NOTE: this is a raw "first match in arg order" scan. For an
    Evidence row's *own identity* prefer :func:`resolve_doc_number`,
    which searches filename/title before the body and ignores numbers
    cited under a References heading.
    """
    for source in hay:
        if not source:
            continue
        m = _USD_RE.search(source)
        if m:
            digits = m.group(1)
            return f"USD{digits.zfill(8)}"
    return None


# Headings under which USD numbers name OTHER documents (citations), not the
# document's own identity. A file that merely lists "Applicable Documents:
# USD00050015" must NOT adopt that number as its own — the old
# first-USD-anywhere scan did exactly that, cross-linking unrelated evidence
# and driving false supersession + Tier-1 mis-tagging. We stop scanning the
# body at the first such heading.
_REFERENCE_HEADING_RE = re.compile(
    r"^[ \t]*(?:\d+(?:\.\d+)*[.)]?\s+)?"
    r"(?:references?|applicable\s+documents?|reference\s+documents?|"
    r"related\s+documents?|source\s+documents?|bibliography)"
    r"\s*:?\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def _body_before_references(text: str) -> str:
    """Return the body up to the first References/Applicable-Documents heading.

    USD numbers appearing after such a heading reference *other* documents;
    truncating there keeps the body fallback from adopting a cited number as
    this document's own identity.
    """
    if not text:
        return ""
    m = _REFERENCE_HEADING_RE.search(text)
    return text[: m.start()] if m else text


def resolve_doc_number(
    name: Optional[str] = None,
    title: Optional[str] = None,
    body: Optional[str] = None,
) -> Optional[str]:
    """Resolve a document's *own* USD number, identity-first.

    Priority order:

    1. ``name`` (filename) — names the document itself; authoritative.
    2. ``title`` (metadata title) — also names the document itself.
    3. ``body`` — last resort only, and truncated at the first References /
       Applicable-Documents heading so a doc that merely *cites* another
       USD-numbered doc does not adopt that number as its own identity.

    This replaces the old ``find_doc_number(text, name)`` call pattern that
    scanned the body first and returned the first USD token anywhere — which
    let a cited number become the row's identity, corrupting supersession
    (same_doc_number policy) and the doc-number tagger's Tier-1 matches.
    """
    for src in (name, title):
        if src:
            hit = find_doc_number(src)
            if hit:
                return hit
    return find_doc_number(_body_before_references(body or ""))


def collect_doc_numbers(text: str) -> List[str]:
    """Return all canonical USD numbers in ``text``, de-duplicated, in order."""
    seen: List[str] = []
    for m in _USD_RE.finditer(text or ""):
        canon = f"USD{m.group(1).zfill(8)}"
        if canon not in seen:
            seen.append(canon)
    return seen
