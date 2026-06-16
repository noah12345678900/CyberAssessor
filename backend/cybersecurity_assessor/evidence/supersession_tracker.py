"""Populate ``Evidence.superseded_by_id`` at ingest time.

The column has existed since the schema was first cut and the
read-side respects it (see :mod:`engine.evidence_bundle` and
:mod:`evidence.asset_crosscheck` — both filter
``Evidence.superseded_by_id.is_(None)``). Until now nothing wrote it,
so every read-side filter was effectively a no-op. This module is the
missing writer.

Policy — same ``doc_number``, older loses. Conservative by design: when
in doubt we leave the chain alone, because flipping a legacy artifact to
"superseded" makes it disappear from the LLM bundle and the asset diff.
Better to under-link than to silently mute real evidence.

    When a newly-ingested artifact has a non-empty ``doc_number``
    matching one or more existing un-superseded rows, the older rows
    (by ``ingested_at``) are pointed at the new one. This handles the
    common "uploaded Rev B over Rev A" case. Empty / null doc_numbers
    are excluded — extractors leave doc_number null for things like
    scan output, screenshots, and free-form notes, and we don't want
    every untitled PDF to chain together.

Chains stay shallow because the policy re-points existing dependents
of the row being superseded — so a third-generation upload doesn't
leave a two-hop trail. :func:`engine.supersession.resolve_current_evidence_id`
still walks the chain defensively up to 8 hops if anything ever
escapes this invariant.

(A second, manual policy that matched hardcoded legacy→current phrase
pairs was removed with the manual supersession registry — supersession
is now fully data-driven off ``doc_number`` revisions.)

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

from sqlmodel import Session, select

from ..db import chunked
from ..engine.supersession import _title_is_matchable
from ..models import Evidence

log = logging.getLogger(__name__)


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

    Within a single call the same prior row is never linked twice (we
    filter on ``superseded_by_id IS NULL`` before each update).
    """
    if new_evidence.id is None:
        # Caller forgot to flush — refusing to write would chain to
        # the wrong row when the id finally settles.
        log.warning("apply_supersession_at_ingest called before flush; skipping")
        return 0

    linked = 0
    try:
        linked += _policy_same_doc_number(session, new_evidence)
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
