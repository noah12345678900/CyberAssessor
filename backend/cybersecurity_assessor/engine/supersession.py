"""Document supersession (data-driven, per-workbook).

When a newer artifact retires an older one, narratives that cite the
older document should resolve to the current-tier doc. Legacy docs may
still exist on SharePoint side-by-side with the current ones — assessors
must NOT cite the legacy doc just because it is findable.

This is the **patent-supporting** component: a deterministic catch for
stale citations the LLM cannot know about on its own. Every rewrite is
recorded as a ``SupersessionHit`` (see ``engine.measurement``) so the
patent's accuracy claim is one SQL query away.

Supersession is fully data-driven: the evidence-chain rewriter walks
``Evidence.superseded_by_id`` (see ``rewrite_evidence_chain`` /
``build_evidence_chain_index``), which the ingest-time supersession
tracker populates per workbook (a newer Rev over an older one). No
hardcoded phrase tables — an earlier manual ``_LEGACY_TO_CURRENT`` /
``_SSAA_TO_SDA_MAPPINGS`` registry held one program's verbatim doc
architecture, shipped empty after scrubbing, and was removed.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


def resolve_current_evidence_id(session, evidence_id: int, *, max_hops: int = 8) -> int:
    """Walk ``Evidence.superseded_by_id`` to the terminal (current) row.

    Returns the input id if no chain exists. ``max_hops`` is a safety guard
    against a cycle introduced by bad data — chains are 1-2 deep in practice.
    Caller passes an active SQLModel ``Session``; we do not open one here so
    this stays usable from inside a larger transaction.
    """
    from cybersecurity_assessor.models import Evidence  # local import: avoid cycles

    current_id = evidence_id
    seen: set[int] = {current_id}
    for _ in range(max_hops):
        row = session.get(Evidence, current_id)
        if row is None or row.superseded_by_id is None:
            return current_id
        next_id = row.superseded_by_id
        if next_id in seen:  # cycle — stop and return the last good id
            log.warning(
                "resolve_current_evidence_id: cycle detected starting at "
                "evidence_id=%s; stopping at id=%s (chain=%s)",
                evidence_id,
                current_id,
                sorted(seen),
            )
            return current_id
        seen.add(next_id)
        current_id = next_id
    # Reached max_hops without finding a terminal — most likely bad data
    # (chain longer than 8 in practice means something is wrong); log so
    # an operator can investigate without having to instrument the call
    # site.
    log.warning(
        "resolve_current_evidence_id: max_hops=%d reached starting at "
        "evidence_id=%s; returning id=%s (chain may be longer)",
        max_hops,
        evidence_id,
        current_id,
    )
    return current_id


# ---------------------------------------------------------------------------
# Evidence-chain rewriter — the patent-supporting deterministic catch for
# narratives that cite a retired Evidence row.
# ---------------------------------------------------------------------------


@dataclass
class EvidenceChainHit:
    """One stale-evidence-ref → current-evidence-ref rewrite."""

    stale_ref: str  # the exact substring that was matched in text
    current_ref: str  # what it was rewritten to (title or doc_number of chain head)
    stale_evidence_id: int
    current_evidence_id: int


@dataclass
class EvidenceChainResult:
    """Result of running narrative through the evidence-chain rewriter."""

    rewritten_text: str
    hits: list[EvidenceChainHit]

    @property
    def changed(self) -> bool:
        return bool(self.hits)


# Candidate tuple shape: (legacy_ref, current_ref, stale_id, current_id, kind,
# compiled_pattern). Shared between the legacy per-call path and the indexed
# fast path so both walk identical data — equivalence contract lives on one
# tuple shape, no drift possible.
_Candidate = tuple[str, str, int, int, str, "re.Pattern[str]"]


@dataclass(frozen=True)
class EvidenceChainIndex:
    """Precomputed candidates for ``rewrite_evidence_chain``.

    Built once per assess-batch by the route handler (see
    ``Assessor.prime_evidence_chain_index``) and reused across every CCI's
    four finalize paths — saves N full-table scans + N×head-lookup N+1
    round trips against ``Evidence`` per batch.

    Each entry is the same shape the per-call path builds inline, with the
    regex pre-compiled once at build time. The candidates tuple is already
    sorted longest-legacy-first, so the rewriter just walks it.

    Frozen so multiple worker threads in the assess-batch fan-out can read
    it lock-free without contention on the shared session lock.
    """

    candidates: tuple[_Candidate, ...]
    workbook_id: int | None  # what scope the index was built for (debug/safety)


# Titles shorter than this are skipped — generic short names ("Notes",
# "draft", "report") would create false positives across unrelated narratives.
# 12 chars is empirically the floor where a title becomes specific enough
# to be unambiguous (e.g. "AcctMgmt-001" is 12; "Notes" is 5).
_MIN_TITLE_LEN_FOR_MATCH = 12

# Common one-word titles that should never trigger a rewrite even if they
# happen to be ≥ 12 chars (e.g. compound generic terms). The list stays
# small on purpose — additions should be backed by a real false positive.
_GENERIC_TITLE_BLOCKLIST: frozenset[str] = frozenset(
    {
        "documentation",
        "specifications",
        "configuration",
        "requirements",
    }
)


def _preferred_ref(evidence) -> str:
    """Choose the canonical ref text for an Evidence row.

    doc_number wins when present (USD-numbers are unambiguous); else title.
    Returns the empty string when neither is set — caller filters these out.
    """
    dn = (getattr(evidence, "doc_number", None) or "").strip()
    if dn:
        return dn
    title = (getattr(evidence, "title", None) or "").strip()
    return title


def _title_is_matchable(title: str) -> bool:
    """Precision gate for title-based matching."""
    if len(title) < _MIN_TITLE_LEN_FOR_MATCH:
        return False
    if title.lower() in _GENERIC_TITLE_BLOCKLIST:
        return False
    return True


def _build_candidates_from_rows(session, superseded_rows) -> list[_Candidate]:
    """Turn superseded ``Evidence`` rows into sorted, regex-compiled candidates.

    Shared between the legacy in-``rewrite_evidence_chain`` path and the
    batch-scoped ``build_evidence_chain_index`` builder so both produce
    identical candidate tuples — the equivalence contract sits on one
    implementation, no drift.

    Walks each row's chain to the head via :func:`resolve_current_evidence_id`
    (this is the N+1 lookup the indexed path amortizes across a whole batch),
    derives the preferred ref of the head, and emits one candidate per
    (doc_number, stale row) and (title, stale row) match seed. The compiled
    regex is attached up front so the hot rewrite loop is pure CPU.
    """
    from cybersecurity_assessor.models import Evidence  # local import: avoid cycles

    candidates: list[_Candidate] = []
    seen_keys: set[tuple[str, str]] = set()
    for row in superseded_rows:
        if row.id is None:
            continue
        head_id = resolve_current_evidence_id(session, row.id)
        if head_id == row.id:
            continue  # broken chain (FK points to missing row); skip
        head = session.get(Evidence, head_id)
        if head is None:
            continue
        current_ref = _preferred_ref(head)
        if not current_ref:
            continue

        dn = (row.doc_number or "").strip()
        if dn and dn != current_ref:
            key = ("doc_number", dn)
            if key not in seen_keys:
                seen_keys.add(key)
                pattern = re.compile(rf"\b{re.escape(dn)}\b")
                candidates.append((dn, current_ref, row.id, head_id, "doc_number", pattern))

        title = (row.title or "").strip()
        if title and title != current_ref and _title_is_matchable(title):
            key = ("title", title.lower())
            if key not in seen_keys:
                seen_keys.add(key)
                pattern = re.compile(re.escape(title), re.IGNORECASE)
                candidates.append((title, current_ref, row.id, head_id, "title", pattern))

    # Longest legacy strings first so a substring-overlapping shorter ref
    # doesn't win over a more specific match.
    candidates.sort(key=lambda c: len(c[0]), reverse=True)
    return candidates


def build_evidence_chain_index(
    session, *, workbook_id: int | None = None
) -> EvidenceChainIndex:
    """Build an :class:`EvidenceChainIndex` for one assess-batch's scope.

    Called ONCE per ``/api/controls/assess-batch`` from the route handler,
    before the parallel worker fan-out. Replaces the N per-call DB queries
    + N×head-lookup N+1 round trips that ``rewrite_evidence_chain`` used to
    do on every CCI's four finalize paths — for a 300-CCI batch this is
    ~1200 queries collapsed to 1.

    ``workbook_id`` scopes the candidate pool exactly like the legacy path:
    when provided, only rows with that ``workbook_id`` (or workbook-agnostic
    null) are included; None matches all rows.
    """
    from cybersecurity_assessor.models import Evidence  # local import: avoid cycles
    from sqlmodel import select

    stmt = select(Evidence).where(Evidence.superseded_by_id.is_not(None))
    if workbook_id is not None and hasattr(Evidence, "workbook_id"):
        # Match rows for this workbook OR workbook-agnostic (null) rows so
        # global evidence (e.g. an org-wide policy library) still resolves.
        stmt = stmt.where(
            (Evidence.workbook_id == workbook_id) | (Evidence.workbook_id.is_(None))
        )
    superseded_rows = session.exec(stmt).all()
    candidates = _build_candidates_from_rows(session, superseded_rows)
    return EvidenceChainIndex(candidates=tuple(candidates), workbook_id=workbook_id)


def _apply_candidates(text: str, candidates: list[_Candidate] | tuple[_Candidate, ...]) -> EvidenceChainResult:
    """Walk pre-compiled candidates against ``text`` — the hot loop.

    Pure CPU: no session, no lock, no DB. Safe to call from any thread on
    the same ``EvidenceChainIndex`` (frozen dataclass, no shared mutation).
    """
    out = text
    hits: list[EvidenceChainHit] = []
    for legacy_ref, current_ref, stale_id, current_id, _kind, pattern in candidates:
        if pattern.search(out):
            hits.append(
                EvidenceChainHit(
                    stale_ref=legacy_ref,
                    current_ref=current_ref,
                    stale_evidence_id=stale_id,
                    current_evidence_id=current_id,
                )
            )
            out = pattern.sub(current_ref, out)
    return EvidenceChainResult(rewritten_text=out, hits=hits)


def rewrite_evidence_chain(
    session,
    text: str,
    *,
    workbook_id: int | None = None,
    index: EvidenceChainIndex | None = None,
) -> EvidenceChainResult:
    """Rewrite references to superseded Evidence rows in narrative text.

    Scans ``text`` for any substring that matches the ``doc_number`` or
    ``title`` of an ``Evidence`` row whose ``superseded_by_id`` is set,
    and replaces it with the chain head's preferred ref (doc_number if
    present, else title). Uses :func:`resolve_current_evidence_id` to
    walk multi-hop chains defensively.

    Two modes — produce identical output for the same ``(text, workbook_id)``:

    * **Indexed (fast)**: caller supplies ``index=<EvidenceChainIndex>``
      built by :func:`build_evidence_chain_index`. The function is
      session-free and lock-free; just walks pre-compiled regexes against
      ``text``. ``workbook_id`` is ignored in this mode (the index carries
      its own scope). This is the assess-batch hot path.

    * **Legacy (slow)**: ``index`` is None. Queries the session for
      superseded rows, walks each chain to the head, builds candidates,
      then walks them. Used by single-shot ``/assess``, CLI tools, and
      tests that don't bother priming an index.

    ``workbook_id`` (legacy mode only) scopes the candidate pool: when
    provided, only rows with that ``workbook_id`` (or workbook-agnostic
    null) are considered. None matches all rows.

    Matching strategy — high precision over recall:
      1. ``doc_number`` — exact, word-boundary, case-sensitive (USD-numbers
         are unambiguous; case-insensitive would hit prose).
      2. ``title`` — exact case-insensitive substring, but ONLY when the
         title is long enough (>= 12 chars) and not on the generic blocklist.
         Short or generic titles are skipped to avoid false positives.
      3. Skip if the matched substring is already the current ref (idempotency).

    Like the indexed builder, this function does NOT touch the DB on the
    indexed path (the builder already paid that cost) — callers attach
    hits to the run recorder.
    """
    if not text:
        return EvidenceChainResult(rewritten_text=text or "", hits=[])

    # Indexed fast path — session-free, lock-free, pure CPU.
    if index is not None:
        if not index.candidates:
            return EvidenceChainResult(rewritten_text=text, hits=[])
        return _apply_candidates(text, index.candidates)

    # Legacy path — preserved verbatim for callers that don't prime.
    if session is None:
        return EvidenceChainResult(rewritten_text=text, hits=[])

    from cybersecurity_assessor.models import Evidence  # local import: avoid cycles
    from sqlmodel import select

    stmt = select(Evidence).where(Evidence.superseded_by_id.is_not(None))
    if workbook_id is not None and hasattr(Evidence, "workbook_id"):
        # Match rows for this workbook OR workbook-agnostic (null) rows so
        # global evidence (e.g. an org-wide policy library) still resolves.
        stmt = stmt.where(
            (Evidence.workbook_id == workbook_id) | (Evidence.workbook_id.is_(None))
        )
    superseded_rows = session.exec(stmt).all()
    if not superseded_rows:
        return EvidenceChainResult(rewritten_text=text, hits=[])

    candidates = _build_candidates_from_rows(session, superseded_rows)
    if not candidates:
        return EvidenceChainResult(rewritten_text=text, hits=[])
    return _apply_candidates(text, candidates)


