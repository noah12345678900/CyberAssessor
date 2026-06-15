"""Populate ``Evidence.superseded_by_id`` at ingest time.

The column has existed since the schema was first cut and the
read-side respects it (see :mod:`engine.evidence_bundle` and
:mod:`evidence.asset_crosscheck` — both filter
``Evidence.superseded_by_id.is_(None)``). Until now nothing wrote it,
so every read-side filter was effectively a no-op. This module is the
missing writer.

Two deterministic policies. Both are conservative — when in doubt we
leave the chain alone, because flipping a legacy artifact to
"superseded" makes it disappear from the LLM bundle and the asset
diff. Better to under-link than to silently mute real evidence.

**Policy A — same ``doc_number``, older loses.**
    When a newly-ingested artifact has a non-empty ``doc_number``
    matching one or more existing un-superseded rows, the older rows
    (by ``ingested_at``) are pointed at the new one. This handles the
    common "uploaded Rev B over Rev A" case. Empty / null doc_numbers
    are excluded — extractors leave doc_number null for things like
    scan output, screenshots, and free-form notes, and we don't want
    every untitled PDF to chain together.

**Policy B — legacy phrase → current USD-numbered doc.**
    Uses :data:`engine.supersession._LEGACY_TO_CURRENT` (the narrative
    rewrite table). When the new artifact looks like one of the
    ``current`` docs in that table (matched by doc_number prefix or
    title equality), each existing un-superseded row whose title
    contains a corresponding ``legacy`` phrase is pointed at the new
    one. This is how a freshly-uploaded
    ``USD00050010 Example System Account Management Plan`` retires the older
    ``SDA T1 O&I Account Management User Guide`` and ``...Plan`` PDFs
    sitting in the same evidence folder.

Chains stay shallow because policy A re-points existing dependents
of the row being superseded — so a third-generation upload doesn't
leave a two-hop trail. :func:`engine.supersession.resolve_current_evidence_id`
still walks the chain defensively up to 8 hops if anything ever
escapes this invariant.

The orchestrator calls :func:`apply_supersession_at_ingest` once per
new Evidence row, *after* ``session.flush()`` (so the new row has an
id) and before the per-batch ``session.commit()``. It returns the
number of newly-created supersession links so the IngestSummary can
surface it; nothing here raises — supersession is best-effort, not
a precondition for ingest.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Iterable

from sqlmodel import Session, select

from ..db import chunked
from ..engine.supersession import (
    _LEGACY_TO_CURRENT,
    _title_is_matchable,
    SupersessionEntry,
)
from ..models import Evidence

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pre-computed lookup: every distinct "current" → list of its legacy phrases.
# Built once at import; the legacy table is appended to but never mutated at
# runtime so a module-level dict is safe.
# ---------------------------------------------------------------------------


def _build_current_to_legacies() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for entry in _LEGACY_TO_CURRENT:
        out.setdefault(entry.current.strip(), []).append(entry.legacy)
    return out


_CURRENT_TO_LEGACIES: dict[str, list[str]] = _build_current_to_legacies()


def _as_utc(dt: datetime | None) -> datetime | None:
    """Force a datetime to tz-aware UTC.

    SQLite roundtrips drop the tzinfo, so a freshly-defaulted (aware)
    ``new_evidence.ingested_at`` cannot be directly compared with a row
    re-read from the DB (naive). Treat naive values as already-UTC —
    that's how ``models._utcnow`` stores them.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def apply_supersession_at_ingest(session: Session, new_evidence: Evidence) -> int:
    """Link any prior rows that ``new_evidence`` supersedes.

    Returns the count of links created (an int, not a list of ids,
    because the orchestrator only needs a counter for IngestSummary).
    Safe to call on every ingest — when nothing matches, returns 0.

    Both policies are run; their results union. Within a single call
    the same prior row is never linked twice (we filter on
    ``superseded_by_id IS NULL`` before each update).
    """
    if new_evidence.id is None:
        # Caller forgot to flush — refusing to write would chain to
        # the wrong row when the id finally settles.
        log.warning("apply_supersession_at_ingest called before flush; skipping")
        return 0

    linked = 0
    try:
        linked += _policy_same_doc_number(session, new_evidence)
        linked += _policy_legacy_title_rewrite(session, new_evidence)
    except Exception:  # pragma: no cover - never let supersession kill ingest
        log.exception("supersession tracker failed for evidence id=%s", new_evidence.id)
        return linked
    if linked:
        # Persist the FK updates so callers (and the next read in the same
        # session) see them. Without an explicit flush, a session.refresh()
        # would reload the pre-mutation row from the DB and silently revert
        # the link — verified by the chain-collapse test.
        session.flush()
    return linked


# ---------------------------------------------------------------------------
# Policy A — same doc_number
# ---------------------------------------------------------------------------

# Boilerplate tokens that carry no document-identity signal — Rev/version
# markers, articles, and lifecycle words. Stripped before measuring title
# overlap so "USD00050015 Rev C SSP" and "USD00050015 Rev D SSP" corroborate
# on their *real* tokens (usd00010082, ssp) and not on the shared "rev".
_TITLE_TOKEN_STOPWORDS: frozenset[str] = frozenset(
    {
        "rev",
        "revision",
        "version",
        "ver",
        "draft",
        "final",
        "updated",
        "update",
        "the",
        "and",
        "for",
        "doc",
        "document",
    }
)


def _title_tokens(title: str) -> set[str]:
    """Lower-cased, ≥3-char, non-boilerplate tokens of a title.

    Splits on any non-alphanumeric run so underscore/dash-delimited
    filenames (``snap0527core__USD00050015_Rev_D_SSP``) tokenize the same
    way as space-delimited titles.
    """
    return {
        tok
        for tok in re.split(r"[^a-z0-9]+", title.lower())
        if len(tok) >= 3 and tok not in _TITLE_TOKEN_STOPWORDS
    }


def _titles_corroborate(older_title: str | None, new_title: str | None) -> bool:
    """Precision guard for a same-``doc_number`` supersession link.

    A shared ``doc_number`` is *necessary* but, when both titles are
    specific, not *sufficient*. Two specific titles with zero token
    overlap that nonetheless share a USD number are almost always a
    body-cited citation collision (the failure mode the identity-first
    resolver fixes) rather than a genuine Rev-over-Rev — linking them
    would mute real evidence by chaining unrelated docs together.

    Policy:

      * Either title missing / short / generic (not
        :func:`_title_is_matchable`) → return ``True``. There is no usable
        title signal, so fall back to the doc_number match alone. This
        preserves the common untitled / scan-output revision case
        ("better to under-link than to silently mute real evidence" cuts
        the other way here: the doc_number IS the signal).
      * Both titles specific → require at least one shared significant
        token. No overlap ⇒ contradicted ⇒ ``False`` (skip the link).
    """
    a = (older_title or "").strip()
    b = (new_title or "").strip()
    if not _title_is_matchable(a) or not _title_is_matchable(b):
        return True
    return bool(_title_tokens(a) & _title_tokens(b))


def _policy_same_doc_number(session: Session, new_evidence: Evidence) -> int:
    """Older rows sharing this exact ``doc_number`` get pointed at ``new_evidence``.

    Skipped when the new row has no doc_number — most non-document
    evidence (scan output, screenshots, free-form text) leaves it
    null and we don't want to chain those.

    A shared doc_number alone is not enough: each candidate older row must
    also pass :func:`_titles_corroborate` (doc_number match AND, when both
    titles are specific, a shared significant token). This is the belt to
    the identity-first resolver's suspenders — even if a body-cited number
    ever slips back into ``doc_number``, a disjoint-title collision will not
    create a false supersession link.
    """
    dn = (new_evidence.doc_number or "").strip()
    if not dn:
        return 0

    # Pull both unsuperseded older rows AND rows that already chain to one of
    # those older rows. We re-point dependents in the same pass so chains
    # stay one-hop deep.
    older = session.exec(
        select(Evidence).where(
            Evidence.doc_number == dn,
            Evidence.id != new_evidence.id,
        )
    ).all()
    if not older:
        return 0

    # Title-corroboration precision guard. Keep only candidates whose title
    # does not *contradict* the new row's title (see _titles_corroborate).
    new_title = new_evidence.title
    older = [row for row in older if _titles_corroborate(row.title, new_title)]
    if not older:
        return 0

    older_ids = {row.id for row in older if row.id is not None}

    # Re-point chained dependents that currently terminate at one of the
    # older rows. Done first so we don't accidentally re-point through a
    # row that's about to be marked superseded itself.
    dependents: list[Evidence] = []
    for batch in chunked(list(older_ids)):
        dependents.extend(
            session.exec(
                select(Evidence).where(
                    Evidence.superseded_by_id.in_(batch)  # type: ignore[attr-defined]
                )
            ).all()
        )

    now = datetime.now(timezone.utc)
    linked = 0
    for dep in dependents:
        if dep.id == new_evidence.id:
            continue  # never chain a row to itself
        prior_head_id = dep.superseded_by_id
        dep.superseded_by_id = new_evidence.id
        dep.superseded_at = now
        dep.superseded_policy = "same_doc_number"
        dep.superseded_reason = (
            f"re-pointed from prior chain head id={prior_head_id} during "
            f"policy_same_doc_number on doc_number={dn!r}"
        )
        session.add(dep)
        linked += 1

    # Now mark each older row as superseded — but only ones that aren't
    # already pointed somewhere (respect prior decisions).
    for row in older:
        if row.id == new_evidence.id:
            continue
        if row.superseded_by_id is not None:
            continue
        # Don't link a row to itself, and don't supersede a *newer* row by
        # an older one — compare ingested_at to be safe.
        row_dt = _as_utc(row.ingested_at)
        new_dt = _as_utc(new_evidence.ingested_at)
        if row_dt and new_dt and row_dt > new_dt:
            continue
        row.superseded_by_id = new_evidence.id
        row.superseded_at = now
        row.superseded_policy = "same_doc_number"
        row.superseded_reason = (
            f"doc_number={dn!r} matched newly-ingested evidence id={new_evidence.id}"
        )
        session.add(row)
        linked += 1
    return linked


# ---------------------------------------------------------------------------
# Policy B — legacy-phrase → current USD-numbered doc
# ---------------------------------------------------------------------------


def _policy_legacy_title_rewrite(session: Session, new_evidence: Evidence) -> int:
    """If ``new_evidence`` is one of the canonical "current" docs, retire its legacies.

    Match: the new row's ``doc_number`` (if any) appears as a token at
    the start of a ``current`` string in :data:`_LEGACY_TO_CURRENT`,
    or the new row's ``title`` equals the ``current`` string
    (case-insensitive). Either is sufficient.

    For every match, every un-superseded Evidence row whose ``title``
    contains one of the corresponding ``legacy`` phrases (case-
    insensitive substring) gets pointed at ``new_evidence``.
    """
    legacies = _legacies_for_new_evidence(new_evidence)
    if not legacies:
        return 0

    # One query, one substring filter per legacy phrase. SQLite ``LIKE`` is
    # case-insensitive by default for ASCII; collating on Python side avoids
    # surprises with funky doc titles.
    candidates = session.exec(
        select(Evidence).where(
            Evidence.id != new_evidence.id,
            Evidence.superseded_by_id.is_(None),
            Evidence.title.is_not(None),
        )
    ).all()

    legacies_lower = [legacy.lower() for legacy in legacies]
    now = datetime.now(timezone.utc)
    new_title = (new_evidence.title or "").strip()
    linked = 0
    for row in candidates:
        title = (row.title or "").lower()
        matched_legacy: str | None = None
        for legacy, legacy_lower in zip(legacies, legacies_lower):
            if legacy_lower in title:
                matched_legacy = legacy
                break
        if matched_legacy is None:
            continue
        # Skip if the candidate's own doc_number matches the new row's
        # doc_number — Policy A already linked it.
        if (
            row.doc_number
            and new_evidence.doc_number
            and row.doc_number.strip() == new_evidence.doc_number.strip()
        ):
            continue
        # Don't supersede a newer row by an older one.
        row_dt = _as_utc(row.ingested_at)
        new_dt = _as_utc(new_evidence.ingested_at)
        if row_dt and new_dt and row_dt > new_dt:
            continue
        row.superseded_by_id = new_evidence.id
        row.superseded_at = now
        row.superseded_policy = "legacy_title_rewrite"
        row.superseded_reason = (
            f"title contained legacy phrase {matched_legacy!r}; "
            f"superseded by {new_title!r}"
        )
        session.add(row)
        linked += 1
    return linked


def _legacies_for_new_evidence(new_evidence: Evidence) -> list[str]:
    """Return all legacy phrases whose ``current`` matches this new row.

    A "match" is permissive on purpose — extractors don't always set
    doc_number, and titles drift from the canonical string by a Rev
    suffix or a trailing space. We accept either:

      - the new row's ``doc_number`` (stripped) is the leading
        whitespace-delimited token of one of the ``current`` strings, or
      - the new row's ``title`` equals a ``current`` string
        (case-insensitive, whitespace-trimmed).
    """
    out: list[str] = []
    dn = (new_evidence.doc_number or "").strip()
    title = (new_evidence.title or "").strip().lower()

    for current, legacies in _CURRENT_TO_LEGACIES.items():
        current_lower = current.lower()
        # Token-prefix match against doc_number (e.g. "USD00050010" matches
        # "USD00050010 Example System Account Management Plan Rev -").
        if dn:
            first_token = current.split(None, 1)[0]
            if first_token == dn:
                out.extend(legacies)
                continue
        # Whole-string match against title.
        if title and title == current_lower:
            out.extend(legacies)
    # De-dupe while preserving order.
    seen: set[str] = set()
    deduped: list[str] = []
    for legacy in out:
        if legacy.lower() in seen:
            continue
        seen.add(legacy.lower())
        deduped.append(legacy)
    return deduped


# ---------------------------------------------------------------------------
# Test-support helper (kept here so tests don't reach into private names)
# ---------------------------------------------------------------------------


def legacy_phrases_for_current(current: str) -> Iterable[str]:
    """Return the legacy phrases registered for a given ``current`` string.

    Test-friendly accessor over :data:`_CURRENT_TO_LEGACIES` so unit
    tests can assert that the canonical map captures what they expect
    without poking at module-private state.
    """
    return list(_CURRENT_TO_LEGACIES.get(current.strip(), []))
