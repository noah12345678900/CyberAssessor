"""Per-workbook evidence retention engine — rolling eviction to a cap.

Evidence accumulates without bound when a continuously-pulling connector
(SharePoint, Tenable, Splunk — or the v2.0 in-boundary autonomous service)
keeps feeding rows. For long-running workbooks this eventually slows every
query that touches the evidence table and inflates the extracted_text
directory into gigabytes. This module enforces a per-workbook cap by
evicting the OLDEST SAFE-TO-EVICT rows whenever the count exceeds the cap.

"Safe to evict" is intentionally narrow — only artifacts that NOTHING
load-bearing references:

  * not referenced by EvidenceTag.evidence_id
  * not referenced by StigFinding.evidence_id
  * not referenced by PoamEvidence.evidence_id
  * not referenced by AssessmentEvidenceShown.evidence_id
    (AssessmentCitation.evidence_shown_id → AssessmentEvidenceShown.evidence_id,
     so the AES check transitively covers citations too)
  * not is_asset_list and not is_boundary_doc
  * not a supersession anchor: no other Evidence row has
    superseded_by_id == this row's id

Every eviction is logged in EvidenceRetentionEvent — an append-only ledger
that survives the Evidence deletion so auditors can trace "what was deleted
from this workbook, when, and why."

Design notes
------------
* Best-effort, like supersession_tracker: wrap in try/except, log, never
  let retention kill ingest. The caller (ingest.ingest_source) discards
  exceptions.
* SQLite IN-clause ceiling: use :func:`..db.chunked` for any .in_() over
  id collections to stay under the 32766 host-parameter ceiling.
* Stop-gap, not a guarantee: if every remaining row is load-bearing we
  emit a warning but do NOT forcibly evict anything. The cap is a soft
  guide; defensibility beats velocity.
"""

from __future__ import annotations

import logging
from pathlib import Path

from sqlmodel import Session, func, select

from ..config import load_config
from ..db import chunked
from ..models import (
    AssessmentEvidenceShown,
    Evidence,
    EvidenceRetentionEvent,
    EvidenceTag,
    PoamEvidence,
    StigFinding,
)

log = logging.getLogger(__name__)

# Default cap: 30,000 rows per workbook. Sized to the realistic worst case
# for the largest systems we assess: a ~10,000-person system implies on the
# order of 10k user endpoints plus ~10-15% servers/network/appliance hosts
# (~11-12k hosts), and a granular per-host evidence model ingests roughly two
# artifacts per host (a STIG CKL plus a scan/config export) — already ~22-24k.
# Adding scan rollups, policy/SSP/CRM docs, and re-ingested supersession
# copies lands a defensible upper bound near 30,000. The figure also sits just
# below SQLite's SQLITE_MAX_VARIABLES = 32,766 bound-parameter cap, so the
# load-bearing exclusion walk stays within a sane number of chunked() batches.
# Override via AppConfig.evidence_retention_cap in config.toml.
DEFAULT_RETENTION_CAP: int = 30_000


def _resolve_cap(cap: int | None) -> int:
    """Resolve the effective cap: explicit arg → AppConfig → DEFAULT."""
    if cap is not None:
        return cap
    try:
        cfg_cap = load_config().evidence_retention_cap
        if cfg_cap is not None:
            return cfg_cap
    except Exception:
        pass
    return DEFAULT_RETENTION_CAP


def enforce_retention(
    session: Session,
    workbook_id: int,
    cap: int | None = None,
) -> int:
    """Evict the oldest safe-to-evict Evidence rows until count <= cap.

    Parameters
    ----------
    session:
        An active SQLModel Session.  The caller is responsible for the
        surrounding transaction; this function commits nothing — all writes
        are flushed but the commit is the caller's responsibility.
        (ingest_source calls session.commit() before and after.)
    workbook_id:
        The workbook whose evidence pool to check.
    cap:
        Optional explicit cap. None → resolve from AppConfig, then
        DEFAULT_RETENTION_CAP.  A cap of 0 disables enforcement (returns 0).

    Returns
    -------
    int
        Number of Evidence rows deleted.
    """
    effective_cap = _resolve_cap(cap)
    if effective_cap <= 0:
        # Caller or config explicitly opted out of retention enforcement.
        return 0

    # --- 1. Count current evidence rows for this workbook ----------------
    count_q = select(func.count()).select_from(Evidence).where(
        Evidence.workbook_id == workbook_id
    )
    total: int = session.exec(count_q).one()

    if total <= effective_cap:
        return 0  # within budget — nothing to do

    to_evict_count = total - effective_cap
    log.info(
        "retention: workbook_id=%s has %d evidence rows (cap=%d); "
        "need to evict up to %d rows",
        workbook_id,
        total,
        effective_cap,
        to_evict_count,
    )

    # --- 2. Collect all evidence IDs for this workbook, oldest first ------
    # We fetch just the IDs in ingested_at order; full row data loaded only
    # for the candidate rows we actually plan to evict.
    all_ids_q = (
        select(Evidence.id)
        .where(Evidence.workbook_id == workbook_id)
        .where(Evidence.id.is_not(None))  # type: ignore[union-attr]
        .order_by(Evidence.ingested_at.asc())  # type: ignore[union-attr]
    )
    all_ids: list[int] = list(session.exec(all_ids_q).all())

    # --- 3. Build exclusion sets (referenced IDs that are load-bearing) ---
    # We query each reference table in chunks to respect the SQLite
    # host-parameter ceiling (32766). Each set is the UNION of
    # evidence_id values that appear in that table for ANY row (global
    # across all workbooks for cross-workbook safety, but in practice
    # FK integrity means they're always scoped to one workbook's pool).

    referenced_ids: set[int] = set()

    # EvidenceTag → evidence_id
    for batch in chunked(all_ids):
        rows = session.exec(
            select(EvidenceTag.evidence_id).where(
                EvidenceTag.evidence_id.in_(batch)  # type: ignore[union-attr]
            )
        ).all()
        referenced_ids.update(r for r in rows if r is not None)

    # StigFinding → evidence_id
    for batch in chunked(all_ids):
        rows = session.exec(
            select(StigFinding.evidence_id).where(
                StigFinding.evidence_id.in_(batch)  # type: ignore[union-attr]
            )
        ).all()
        referenced_ids.update(r for r in rows if r is not None)

    # PoamEvidence → evidence_id
    for batch in chunked(all_ids):
        rows = session.exec(
            select(PoamEvidence.evidence_id).where(
                PoamEvidence.evidence_id.in_(batch)  # type: ignore[union-attr]
            )
        ).all()
        referenced_ids.update(r for r in rows if r is not None)

    # AssessmentEvidenceShown → evidence_id
    # This transitively covers AssessmentCitation (citation → AES.id →
    # AES.evidence_id), so one check is sufficient.
    for batch in chunked(all_ids):
        rows = session.exec(
            select(AssessmentEvidenceShown.evidence_id).where(
                AssessmentEvidenceShown.evidence_id.in_(batch)  # type: ignore[union-attr]
            )
        ).all()
        referenced_ids.update(r for r in rows if r is not None)

    # Supersession anchors: rows that have superseded_by_id pointing TO them
    # (i.e., they are the "current" end of a supersession chain). Evicting
    # the anchor would break the chain for the rows that depend on it.
    for batch in chunked(all_ids):
        rows = session.exec(
            select(Evidence.superseded_by_id).where(
                Evidence.superseded_by_id.in_(batch)  # type: ignore[union-attr]
            ).where(Evidence.superseded_by_id.is_not(None))  # type: ignore[union-attr]
        ).all()
        referenced_ids.update(r for r in rows if r is not None)

    # --- 4. Walk candidates oldest-first, evict until we reach the cap ---
    evicted = 0
    remaining = total

    for ev_id in all_ids:
        if evicted >= to_evict_count:
            break

        # Skip load-bearing rows
        if ev_id in referenced_ids:
            continue

        # Load the full Evidence row so we can check flag fields and
        # snapshot the ledger data. Use session.get() — fastest for PK.
        ev = session.get(Evidence, ev_id)
        if ev is None:
            # Race condition or already gone — skip quietly.
            continue

        # Do NOT evict asset lists or boundary docs — they are structurally
        # significant even if no explicit FK references them yet.
        if ev.is_asset_list or ev.is_boundary_doc:
            continue

        # --- Evict ---
        remaining -= 1

        # Write the ledger entry first, before deleting the Evidence row,
        # so any FK-check failure on the Evidence delete doesn't leave an
        # orphaned ledger row (the session rollback removes both).
        detail = (
            f"Evicted to enforce retention cap={effective_cap}; "
            f"ingested_at={ev.ingested_at.isoformat() if ev.ingested_at else 'unknown'}; "
            f"kind={ev.kind}; "
            f"path={ev.path!r}"
        )
        ledger_row = EvidenceRetentionEvent(
            workbook_id=workbook_id,
            evicted_evidence_id=ev_id,
            evicted_path=ev.path,
            evicted_sha256=ev.sha256,
            evicted_title=ev.title,
            evicted_ingested_at=ev.ingested_at,
            reason="cap_exceeded",
            detail=detail,
            remaining_count=remaining,
        )
        session.add(ledger_row)

        # Delete the extracted text sidecar if present.
        if ev.extracted_text_path:
            _try_delete_sidecar(ev.extracted_text_path)

        session.delete(ev)
        # Flush after each deletion so the next loop iteration's session.get()
        # doesn't re-see the deleted row if SQLite caches it in the identity map.
        session.flush()

        evicted += 1
        log.debug(
            "retention: evicted evidence id=%s path=%r (remaining=%d)",
            ev_id,
            ev.path,
            remaining,
        )

    # Warn if we couldn't reach the cap due to all remaining rows being
    # load-bearing. This is expected in small workbooks where every artifact
    # is referenced; on large auto-pull workbooks it signals a policy gap.
    if evicted < to_evict_count:
        log.warning(
            "retention: workbook_id=%s evicted %d/%d rows; "
            "%d rows could not be evicted because they are load-bearing "
            "(tags, findings, POAMs, assessments, boundary/asset flags, "
            "or supersession anchors). Evidence pool remains above cap.",
            workbook_id,
            evicted,
            to_evict_count,
            to_evict_count - evicted,
        )
    else:
        log.info(
            "retention: workbook_id=%s evicted %d rows; pool now at %d (cap=%d)",
            workbook_id,
            evicted,
            remaining,
            effective_cap,
        )

    return evicted


def _try_delete_sidecar(text_path: str) -> None:
    """Best-effort unlink of an extracted-text sidecar file.

    Mirrors the semantics of :func:`ingest._safe_delete_extracted_text` but
    simplified for the retention context: by the time retention runs, a
    per-evidence-id ``<id>.txt`` file is owned exclusively by the row being
    evicted (the global-pool era is over; PR 2 enforces per-workbook
    naming). Legacy ``<sha256>.txt`` files may be shared, but the worst
    case is leaving an orphan on disk — not a data loss. We unlink
    unconditionally; a missing file or permission error is swallowed.
    """
    try:
        p = Path(text_path)
        if p.exists():
            p.unlink()
    except OSError as exc:
        log.warning("retention: could not unlink sidecar %s: %s", text_path, exc)
