"""One-shot legacy → scope-table backfill.

Runs at sidecar startup. Migrates the legacy per-Evidence scope hints
into the v0.3-ready scope tables so existing workbooks light up the new
filter chips without re-ingest:

* ``Evidence.host_inventory`` JSON → :class:`Asset` rows (deduped per
  ``(workbook_id, hostname)``) + :class:`EvidenceAsset` links.
* ``Evidence.is_boundary_doc`` flag → :class:`BoundarySegment` rows
  (deduped per ``(workbook_id, kind)``) + :class:`EvidenceBoundary`
  links.

**Idempotent.** The whole pass short-circuits on the first run that
discovers either an :class:`EvidenceAsset` or :class:`EvidenceBoundary`
row already exists. Re-running on a backfilled DB is a no-op — the
guard means we don't have to scan every Evidence row to decide whether
to do anything. The trade-off: if a partial run got interrupted (e.g.
sidecar killed mid-loop), the guard will say "already done" on next
startup. That's acceptable because:

1. Backfill is wrapped in a single transaction — partial state means
   either zero or all rows for a given session, never half.
2. The legacy fields (``host_inventory``, ``is_boundary_doc``) stay
   populated through v0.2 as a fallback, so any row the backfill
   missed still resolves correctly via the legacy read path.

Evidence rows with ``workbook_id IS NULL`` are skipped — :class:`Asset`
and :class:`BoundarySegment` are workbook-scoped, and we don't want to
invent a fake workbook to hold orphan rows. Those evidence rows
continue to be served by the legacy ``host_inventory`` fallback path
in :mod:`asset_crosscheck` until the user opens them under a workbook
and re-attaches.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from sqlmodel import Session, select

from ..models import (
    Asset,
    AssetSource,
    BoundarySegment,
    Evidence,
    EvidenceAsset,
    EvidenceBoundary,
    EvidenceKind,
    ScopeLinkSource,
)

log = logging.getLogger(__name__)


# Evidence kinds whose host_inventory comes from a vulnerability scan
# observing the host live (Nessus). STIG checklists are evidence the
# host was config-audited, also observational — treat as SCAN source
# for the CM-8 ghost/orphan logic.
_SCAN_EVIDENCE_KINDS = frozenset(
    {
        EvidenceKind.NESSUS,
        EvidenceKind.STIG_CKL,
        EvidenceKind.STIG_CKLB,
        EvidenceKind.STIG_XCCDF,
    }
)


@dataclass
class BackfillSummary:
    """Per-run counts surfaced to startup logs + (optionally) telemetry."""

    short_circuited: bool = False
    evidence_scanned: int = 0
    evidence_skipped_no_workbook: int = 0
    assets_created: int = 0
    asset_links_created: int = 0
    boundary_segments_created: int = 0
    boundary_links_created: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "short_circuited": self.short_circuited,
            "evidence_scanned": self.evidence_scanned,
            "evidence_skipped_no_workbook": self.evidence_skipped_no_workbook,
            "assets_created": self.assets_created,
            "asset_links_created": self.asset_links_created,
            "boundary_segments_created": self.boundary_segments_created,
            "boundary_links_created": self.boundary_links_created,
            "errors": self.errors,
        }


def _asset_source_for(ev: Evidence) -> AssetSource:
    """Derive AssetSource from Evidence.kind / is_asset_list flag.

    NESSUS + STIG kinds = SCAN (host was observed). is_asset_list = ASSET_LIST
    (declared inventory). Everything else falls back to MANUAL — the assessor
    presumably attached it for a reason but we can't tell from kind alone.
    """
    if ev.kind in _SCAN_EVIDENCE_KINDS:
        return AssetSource.SCAN
    if ev.is_asset_list:
        return AssetSource.ASSET_LIST
    return AssetSource.MANUAL


def _parse_host_inventory(raw: str | None) -> list[str]:
    """Return the list of normalized hostnames from the JSON cache, [] on miss.

    Mirrors :func:`evidence.asset_crosscheck._hostnames_from_cache` but returns
    a list rather than a frozenset because the backfill needs stable iteration
    order for log clarity.
    """
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    out = sorted({str(x).strip().lower() for x in data if x})
    return [h for h in out if h]


def run_scope_backfill(session: Session) -> BackfillSummary:
    """Migrate legacy scope hints into Asset / BoundarySegment + links.

    Idempotent — short-circuits if either link table already has any rows.
    The caller (startup hook) commits the session; this function does the
    inserts and one final flush so FK ids populate before link rows go in,
    but does not commit so a startup-time DB error rolls everything back.
    """
    summary = BackfillSummary()

    # Idempotency guard. Either link table being non-empty means we've done
    # at least one successful pass; assume the rest got committed atomically.
    existing_asset_link = session.exec(select(EvidenceAsset).limit(1)).first()
    existing_boundary_link = session.exec(select(EvidenceBoundary).limit(1)).first()
    if existing_asset_link is not None or existing_boundary_link is not None:
        summary.short_circuited = True
        log.debug("scope backfill: short-circuiting (link tables already populated)")
        return summary

    evidence_rows = session.exec(
        select(Evidence).where(Evidence.superseded_by_id.is_(None))
    ).all()

    # In-memory caches keyed by (workbook_id, hostname / kind) so we don't
    # round-trip SELECT-then-INSERT per host. Built fresh per run; the
    # short-circuit above guarantees an empty starting state.
    asset_cache: dict[tuple[int, str], Asset] = {}
    boundary_cache: dict[tuple[int, str], BoundarySegment] = {}

    for ev in evidence_rows:
        summary.evidence_scanned += 1
        wb_id = ev.workbook_id
        if wb_id is None:
            # Skip workbook-agnostic rows — Asset/BoundarySegment require
            # workbook scope. The legacy fallback path in asset_crosscheck
            # still resolves these via host_inventory JSON.
            summary.evidence_skipped_no_workbook += 1
            continue

        # ---- Host inventory → Asset + EvidenceAsset ---------------------
        hosts = _parse_host_inventory(ev.host_inventory)
        if hosts:
            asset_source = _asset_source_for(ev)
            for hostname in hosts:
                key = (wb_id, hostname)
                asset = asset_cache.get(key)
                if asset is None:
                    asset = Asset(
                        workbook_id=wb_id,
                        hostname=hostname,
                        source=asset_source,
                    )
                    session.add(asset)
                    session.flush()  # populate asset.id for the link row
                    asset_cache[key] = asset
                    summary.assets_created += 1

                # Composite-PK link row. Safe to insert directly — the
                # short-circuit guard guarantees no pre-existing rows, and
                # the asset_cache de-dupes within this run so we won't try
                # to insert the same (evidence_id, asset_id) pair twice for
                # this Evidence row.
                session.add(
                    EvidenceAsset(
                        evidence_id=ev.id,
                        asset_id=asset.id,
                        confidence=1.0,
                        source=ScopeLinkSource.BACKFILL,
                    )
                )
                summary.asset_links_created += 1

        # ---- is_boundary_doc → BoundarySegment + EvidenceBoundary -------
        if ev.is_boundary_doc:
            # boundary_doc_kind is the free-text label ("SSP", "Network
            # Diagram") — use it as the segment name+kind so the UI chip
            # reads naturally. Fall back to "boundary" when the assessor
            # flagged the doc without typing a kind.
            kind_label = (ev.boundary_doc_kind or "boundary").strip() or "boundary"
            key = (wb_id, kind_label.lower())
            segment = boundary_cache.get(key)
            if segment is None:
                segment = BoundarySegment(
                    workbook_id=wb_id,
                    name=kind_label,
                    kind=kind_label.lower(),
                    description="Auto-migrated from legacy is_boundary_doc flag.",
                )
                session.add(segment)
                session.flush()
                boundary_cache[key] = segment
                summary.boundary_segments_created += 1

            session.add(
                EvidenceBoundary(
                    evidence_id=ev.id,
                    boundary_segment_id=segment.id,
                    confidence=1.0,
                    source=ScopeLinkSource.BACKFILL,
                )
            )
            summary.boundary_links_created += 1

    session.flush()
    log.info(
        "scope backfill: scanned=%d skipped_no_wb=%d assets=%d asset_links=%d "
        "segments=%d boundary_links=%d",
        summary.evidence_scanned,
        summary.evidence_skipped_no_workbook,
        summary.assets_created,
        summary.asset_links_created,
        summary.boundary_segments_created,
        summary.boundary_links_created,
    )
    return summary
