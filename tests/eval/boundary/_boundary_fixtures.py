"""Fixture loaders and assertion helpers for the boundary-doc eval harness.

This module owns the two operations every boundary-doc case file performs:

1. ``_load_doc_evidence`` — materializes the ``fixture_docs`` block of a
   case file as on-disk text + ``Evidence`` rows. The adapter under test
   (``BoundaryDocsContextSource.apply``) reads ``Evidence.extracted_text_path``
   off the filesystem during ``apply()``, so the helper writes each
   declared ``text`` payload to a tmp file and seeds an Evidence row
   pointing at it. The DOCX/PDF binaries themselves are NEVER touched —
   the adapter only consumes the pre-extracted text, which keeps the
   harness hermetic (no python-docx/pypdf in the test path) and lets a
   case file declare inline text instead of shipping a real binary.

2. ``_assert_token_kernel`` — the curated-kernel half of the hybrid
   recording strategy (decision D1 in the plan): ``expected_tokens`` must
   ALL be present, ``banned_tokens`` must NONE be present. Snapshot drift
   is a separate, looser check handled by the test module so the kernel
   stays stable as the prompt evolves.

Inline-text fixtures vs. real DOCX/PDF
--------------------------------------
The original plan referenced real fixture binaries under
``tests/fixtures/example_system/...``. That directory is currently empty in
this repo, and the adapter's only filesystem touch is
``_read_text(extracted_text_path)`` (see
``system_context/boundary_docs.py``) — it never opens the original
artifact. So the case-file ``fixture_docs[*].text`` field is the
ground-truth doc text as the extractor would have produced it, and the
helper writes it to a ``.txt`` file in ``tmp_path``. This keeps cases:

  * Self-contained — one JSON file per case, no parallel binary corpus.
  * Deterministic — no extractor variability between runs.
  * Cheap — no python-docx/pypdf import cost on every collection.

If a future case needs to assert the extractor's pre-processing (table
flattening, page-break handling, etc.) it can ship the real binary AND
the expected extracted text; the helper only needs the latter, so the
contract stays stable.

Evidence row shape
------------------
The adapter pulls Evidence rows where
``is_boundary_doc=True`` scoped by workbook_id, then concatenates each
doc's extracted text under a ``## {kind}: {title}\\n`` header. The
helper preserves both ``boundary_doc_kind`` and ``title`` per fixture so
case files can assert on the header that lands in the prompt (e.g.
"the SSP heading survived" or "the per-doc 40K char cap fired"). The
``path`` URI uses a synthetic ``file:///fixtures/<filename>`` scheme —
the adapter doesn't open it, but ``Evidence.path`` is UNIQUE so each
filename in one case must differ.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from sqlmodel import Session

from cybersecurity_assessor.models import Evidence, EvidenceKind

__all__ = ["_load_doc_evidence", "_assert_token_kernel"]


# Filename extension → EvidenceKind. The adapter doesn't inspect ``kind``
# (it routes purely on ``is_boundary_doc``), but seeding a sensible kind
# keeps the seed data realistic for any downstream reader that does.
_KIND_BY_SUFFIX: dict[str, EvidenceKind] = {
    ".pdf": EvidenceKind.PDF,
    ".docx": EvidenceKind.DOCX,
    ".pptx": EvidenceKind.PPTX,
    ".xlsx": EvidenceKind.XLSX,
    ".txt": EvidenceKind.TEXT,
}


def _load_doc_evidence(
    case: dict[str, Any],
    session: Session,
    tmp_path: Path,
    *,
    workbook_id: int | None = None,
) -> list[int]:
    """Materialize ``case["fixture_docs"]`` as on-disk text + Evidence rows.

    Each entry in ``fixture_docs`` is a dict shaped like::

        {
          "filename": "ssp.docx",          # required, must be unique within case
          "boundary_doc_kind": "SSP",      # optional, surfaces in prompt header
          "title": "Acme SSP v1",          # optional, defaults to filename
          "text": "Hostnames: ...",        # required, written to tmp file as-is
          "sha256": "deadbeef..."          # optional, derived from text if absent
        }

    Returns Evidence IDs in declaration order so callers can re-query
    rows for per-token provenance assertions (Phase 2).

    The default ``workbook_id=None`` matches the "pending" scope the
    boundary adapter uses when the harness drives ``apply(workbook_id=
    None, ...)`` — that's the path the Sweep Context UI hits before a
    workbook is attached, and it's the simplest scope to seed.
    """
    evidence_ids: list[int] = []

    fixture_docs = case.get("fixture_docs") or []
    if not fixture_docs:
        # Empty corpus is a legitimate case (see
        # ``empty_doc_low_confidence.json``); the adapter handles it
        # deterministically without an LLM call. Return early so the
        # caller's session.commit() still works on an empty add().
        return evidence_ids

    for entry in fixture_docs:
        filename = entry["filename"]  # KeyError = case file bug, fail loud
        text = entry.get("text", "")
        title = entry.get("title") or filename
        kind = entry.get("boundary_doc_kind")  # None lands on adapter default "Document"

        # Write the extractor's "output" to disk where the adapter will
        # read it. We use UTF-8 so unicode hostname cases (the
        # ``unicode_hostname_preserved`` case) round-trip cleanly through
        # the filesystem.
        text_path = tmp_path / f"{filename}.txt"
        text_path.write_text(text, encoding="utf-8")

        sha = entry.get("sha256") or hashlib.sha256(text.encode("utf-8")).hexdigest()
        suffix = Path(filename).suffix.lower()
        ev_kind = _KIND_BY_SUFFIX.get(suffix, EvidenceKind.OTHER)

        ev = Evidence(
            # Synthetic URI — the adapter never opens this. Must be
            # unique across the row set; case-file authors guarantee that
            # by giving each fixture a distinct filename.
            path=f"file:///fixtures/{filename}",
            sha256=sha,
            kind=ev_kind,
            size_bytes=len(text.encode("utf-8")),
            extracted_text_path=str(text_path),
            title=title,
            is_boundary_doc=True,
            boundary_doc_kind=kind,
            workbook_id=workbook_id,
        )
        session.add(ev)
        session.commit()
        session.refresh(ev)
        evidence_ids.append(ev.id)

    return evidence_ids


def _assert_token_kernel(
    actual: list[str],
    expected: list[str],
    banned: list[str],
) -> None:
    """Set-arithmetic kernel check: all expected present, none banned.

    Raises ``AssertionError`` with both diagnostics inlined so a failing
    case shows BOTH missing-required and leaked-forbidden in one
    pytest output block — fixing one and re-running to find the other
    would burn a CI cycle per fix on multi-issue regressions.

    Comparison is case-sensitive and exact-match. Tokens that should
    survive normalization differences (e.g. trailing dots, casing) get
    listed in canonical form on both sides of the case-file kernel.
    """
    actual_set = set(actual)
    expected_set = set(expected)
    banned_set = set(banned)

    missing = sorted(expected_set - actual_set)
    leaked = sorted(banned_set & actual_set)

    if not missing and not leaked:
        return

    diagnostics: list[str] = []
    if missing:
        diagnostics.append(
            f"  Missing expected tokens ({len(missing)}): {missing}"
        )
    if leaked:
        diagnostics.append(
            f"  Leaked banned tokens ({len(leaked)}): {leaked}"
        )
    diagnostics.append(f"  Actual tokens ({len(actual)}): {sorted(actual_set)}")

    raise AssertionError(
        "Token kernel assertion failed:\n" + "\n".join(diagnostics)
    )
