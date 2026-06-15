"""Auto-derived asset inventory + STIG-coverage cross-check.

CM-8 / CA-3 / PM-5 / RA-5 / CA-7 turn on whether the boundary asset list
is complete AND whether every asset has been both scanned and checklisted.
Earlier versions of this module asked the assessor to manually flag each
"asset list" artifact via ``is_asset_list``. That threw away the host
enumeration ACAS scans and STIG checklists already carry for free, and
hid the real signal (host scanned but no CKL; CKL exists but no scan;
inventory claims a host nothing else sees).

This module computes the asset universe from three derived sources, no
manual tagging required:

* **scanned** — every ``ReportHost`` enumerated by a Nessus / ACAS scan
  (``Evidence.kind == NESSUS``). The scan is, by definition, evidence the
  host exists in the environment.
* **checklisted** — every host targeted by a STIG checklist (CKL / CKLB
  / XCCDF). The ``Evidence.title`` carries the STIG name (e.g. "Microsoft
  Windows Server 2022 STIG"), so we get "which STIGs were applied to which
  hosts" as a side-effect.
* **declared** — XLSX / CSV inventories the assessor explicitly flagged as
  authoritative (``is_asset_list = True``). This is the only remaining
  use of the manual flag — a vendor parts catalog and an HW/SW inventory
  look identical by column shape, so we will not auto-classify them.

Host names are normalized to bare lowercase short form so ``server01``
in an HW/SW workbook lines up with ``server01.dom.mil`` in a CKL and
``SERVER01`` in a Nessus report.

The coverage report surfaces five gap classes mapped to specific control
families:

* ``scanned_not_checklisted`` — RA-5 / CM-6 (missing STIG check)
* ``checklisted_not_scanned`` — CA-7 (no continuous monitoring evidence)
* ``declared_not_observed``   — CM-8 (ghost asset)
* ``observed_not_declared``   — CM-8 (inventory incomplete)
* ``no_stig_applied``         — CM-6 (host present, zero STIGs)

Hostname resolution is two-tier as of 2026-06-06:

1. **Scope tables (preferred).** :class:`EvidenceAsset` joined to
   :class:`Asset` is the v0.3 source of truth. The scope_backfill module
   pre-populates it from legacy ``host_inventory`` on startup, so any
   pre-v0.3 ingest is included.
2. **``Evidence.host_inventory`` JSON (fallback).** Used only when a
   given Evidence row has zero EvidenceAsset links — e.g. legacy rows
   with ``workbook_id IS NULL`` that the backfill skipped, or fresh
   ingests in workbooks where the user hasn't run the scope migration.
   Will be removed in v0.2 once backfill is proven across the install
   base.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from sqlmodel import Session, select

from ..db import chunked
from ..models import Asset, Evidence, EvidenceAsset, EvidenceKind

# ---------------------------------------------------------------------------
# Source categorization
# ---------------------------------------------------------------------------

# Evidence kinds that constitute a vulnerability/configuration scan. A scan
# observing a host is proof the host exists in the boundary at scan time.
_SCAN_KINDS: frozenset[EvidenceKind] = frozenset({EvidenceKind.NESSUS})

# Evidence kinds that are STIG checklists. The Evidence.title field carries
# the STIG name (e.g. "Windows Server 2022 STIG"), used to answer "which
# STIGs were applied to host X".
_CHECKLIST_KINDS: frozenset[EvidenceKind] = frozenset(
    {EvidenceKind.STIG_CKL, EvidenceKind.STIG_CKLB, EvidenceKind.STIG_XCCDF}
)

# Cap the per-host list rendered into the LLM prompt block so a wildly
# divergent diff (e.g. an inventory of 5000 nodes vs a 10-host scan) can't
# blow the user-message budget. The full report is still available via
# GET /api/evidence/crosscheck for the UI panel.
MAX_HOSTS_IN_BLOCK = 25


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceRef:
    """One artifact that mentioned a given host."""

    evidence_id: int
    label: str  # display name (asset_list_label > title > filename)
    kind: str  # EvidenceKind value


@dataclass
class HostRecord:
    """Per-host roll-up across all three derived sources."""

    hostname: str
    scanned_in: list[SourceRef] = field(default_factory=list)
    checklisted_in: list[SourceRef] = field(default_factory=list)
    declared_in: list[SourceRef] = field(default_factory=list)
    # STIG titles applied to this host, deduped. Sourced from Evidence.title
    # of each CKL/CKLB/XCCDF that mentions it. Empty list = host appears in
    # scan or inventory only.
    stigs_applied: list[str] = field(default_factory=list)

    @property
    def coverage(self) -> str:
        """Concise tag describing this host's source mix."""
        s = bool(self.scanned_in)
        c = bool(self.checklisted_in)
        d = bool(self.declared_in)
        if s and c and d:
            return "complete"
        if s and c and not d:
            return "observed_not_declared"
        if s and not c and d:
            return "scanned_not_checklisted"
        if s and not c and not d:
            return "scanned_only"
        if not s and c and d:
            return "checklisted_not_scanned"
        if not s and c and not d:
            return "checklisted_only"
        if not s and not c and d:
            return "declared_not_observed"
        return "unknown"  # impossible (host wouldn't be in the report)


@dataclass(frozen=True)
class SourceSummary:
    """One source artifact's contribution to the asset universe."""

    evidence_id: int
    label: str
    kind: str
    category: str  # "scanned" | "checklisted" | "declared"
    host_count: int


@dataclass(frozen=True)
class AssetCoverageReport:
    """Full cross-check rollup for one workbook (or the whole DB pre-scoping)."""

    sources: list[SourceSummary]
    hosts: list[HostRecord]
    # Gap buckets — each entry is a hostname. Names mirror HostRecord.coverage
    # so the UI can render a tab per gap class.
    gaps: dict[str, list[str]]
    # Sets used for the headline counts. Materialized once so the route handler
    # doesn't re-derive them per response.
    scanned_set: frozenset[str]
    checklisted_set: frozenset[str]
    declared_set: frozenset[str]


# ---------------------------------------------------------------------------
# Hostname normalization (kept from the prior module — same rules apply)
# ---------------------------------------------------------------------------


def _normalize(name: str) -> str:
    """Lower-case, strip dot-domain suffix, drop surrounding whitespace."""
    n = (name or "").strip().lower()
    if "." in n:
        n = n.split(".", 1)[0]
    return n


def _normalize_all(raw: Iterable[str]) -> frozenset[str]:
    out: set[str] = set()
    for r in raw:
        norm = _normalize(r)
        if norm:
            out.add(norm)
    return frozenset(out)


def _hostnames_from_cache(ev: Evidence) -> frozenset[str]:
    """Read the ingest-time host_inventory JSON. Empty set on miss/malformed.

    Fallback path — preferred source is the scope tables
    (:func:`_hostnames_for_evidence`). Kept for any Evidence row the
    backfill couldn't process (workbook_id IS NULL, post-backfill
    legacy ingests). Will be removed alongside the host_inventory
    column in v0.2.
    """
    raw = getattr(ev, "host_inventory", None)
    if not raw:
        return frozenset()
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return frozenset()
    if not isinstance(data, list):
        return frozenset()
    return _normalize_all(str(x) for x in data if x)


def _hostnames_from_scope_tables(
    session: Session,
    evidence_ids: Iterable[int],
) -> dict[int, frozenset[str]]:
    """Bulk-resolve EvidenceAsset → Asset.hostname for many Evidence rows.

    One query for the entire workbook instead of N per-row joins.
    Returns ``{evidence_id: frozenset(hostnames)}``; evidence rows with
    no EvidenceAsset link are absent from the dict, which signals the
    caller to fall back to the legacy ``host_inventory`` JSON cache.

    Hostnames are passed through :func:`_normalize` for consistency with
    the legacy path — Asset.hostname is already stored normalized by the
    backfill and the create_asset route, but ingest paths that predate
    that normalization may still have mixed-case rows.
    """
    ids = [e for e in evidence_ids if e]
    if not ids:
        return {}
    out: dict[int, set[str]] = defaultdict(set)
    # Chunk the IN-clause: on a 10k-host enterprise the asset-list evidence
    # set can exceed SQLITE_MAX_VARIABLES (32766) and a single .in_(ids)
    # would raise "too many SQL variables".
    for batch in chunked(ids):
        rows = session.exec(
            select(EvidenceAsset.evidence_id, Asset.hostname)
            .join(Asset, Asset.id == EvidenceAsset.asset_id)
            .where(EvidenceAsset.evidence_id.in_(batch))  # type: ignore[attr-defined]
        ).all()
        for ev_id, hostname in rows:
            norm = _normalize(hostname)
            if norm:
                out[ev_id].add(norm)
    return {k: frozenset(v) for k, v in out.items()}


def _label(ev: Evidence) -> str:
    """Best display name for an evidence row."""
    return ev.asset_list_label or ev.title or Path(ev.path).name


def _category(ev: Evidence) -> str | None:
    """Bucket an evidence row into scanned / checklisted / declared, or None.

    Declared = XLSX/CSV the assessor explicitly flagged as an authoritative
    inventory. The flag stays manual on purpose: a vendor parts catalog and
    an HW/SW spreadsheet have indistinguishable column shapes and we don't
    want silent misclassification driving a CM-8 narrative.
    """
    if ev.kind in _SCAN_KINDS:
        return "scanned"
    if ev.kind in _CHECKLIST_KINDS:
        return "checklisted"
    if ev.is_asset_list:
        return "declared"
    return None


# ---------------------------------------------------------------------------
# Coverage report build
# ---------------------------------------------------------------------------


def summarize_asset_coverage(
    workbook_id: int, session: Session
) -> AssetCoverageReport:
    """Compute the auto-derived asset universe and per-host source mix.

    Scoped to ``workbook_id`` with the SAME strict hard-binding the Evidence
    list route uses (``list_evidence``): only rows whose ``workbook_id``
    matches the open workbook are considered — no NULL/global leak. Without
    this, swapping the open workbook left the coverage panel showing the
    DB-wide union of every workbook's evidence (it never changed — "stuck"),
    while the Evidence table beside it correctly re-scoped. The two views are
    now consistent: the open workbook IS the boundary, on both.
    """
    rows = session.exec(
        select(Evidence)
        .where(Evidence.superseded_by_id.is_(None))
        .where(Evidence.workbook_id == workbook_id)
    ).all()

    # Pre-fetch hostnames for every in-scope evidence row from the scope
    # tables in one query. Per-row fallback to host_inventory JSON only
    # fires when the scope-table lookup returns an empty set for that
    # evidence — keeps the post-backfill steady state at one query for
    # the whole report.
    in_scope_ids = [ev.id for ev in rows if ev.id is not None and _category(ev) is not None]
    scope_table_hosts = _hostnames_from_scope_tables(session, in_scope_ids)

    # host → HostRecord under construction
    host_index: dict[str, HostRecord] = {}
    # host → set of STIG titles applied (deduped across multi-STIG CKLs)
    stigs_by_host: dict[str, set[str]] = defaultdict(set)
    sources: list[SourceSummary] = []

    scanned_set: set[str] = set()
    checklisted_set: set[str] = set()
    declared_set: set[str] = set()

    for ev in rows:
        category = _category(ev)
        if category is None:
            continue
        hosts = scope_table_hosts.get(ev.id or 0, frozenset())
        if not hosts:
            # Legacy fallback — Evidence rows pre-backfill (or with
            # workbook_id IS NULL, which the backfill intentionally
            # skips) still resolve through the JSON cache.
            hosts = _hostnames_from_cache(ev)
        sources.append(
            SourceSummary(
                evidence_id=ev.id or 0,
                label=_label(ev),
                kind=ev.kind.value,
                category=category,
                host_count=len(hosts),
            )
        )
        # Empty host set is still a valid source entry (visible in the UI as
        # "0 hosts" so the assessor can see the artifact was processed) but
        # contributes nothing to the per-host map.
        if not hosts:
            continue

        ref = SourceRef(
            evidence_id=ev.id or 0, label=_label(ev), kind=ev.kind.value
        )
        for h in hosts:
            rec = host_index.get(h)
            if rec is None:
                rec = HostRecord(hostname=h)
                host_index[h] = rec
            if category == "scanned":
                rec.scanned_in.append(ref)
                scanned_set.add(h)
            elif category == "checklisted":
                rec.checklisted_in.append(ref)
                checklisted_set.add(h)
                # Evidence.title for CKL/CKLB/XCCDF carries the STIG name.
                # Skip when missing rather than substituting the filename
                # — a filename like "WIN2022.ckl" is not the STIG title and
                # would mislead the coverage panel.
                if ev.title:
                    stigs_by_host[h].add(ev.title)
            else:  # declared
                rec.declared_in.append(ref)
                declared_set.add(h)

    # Attach STIG titles to each host, sorted for stable display.
    for hostname, rec in host_index.items():
        rec.stigs_applied = sorted(stigs_by_host.get(hostname, ()))

    hosts_sorted = sorted(host_index.values(), key=lambda r: r.hostname)

    # Gap buckets. The same hostname can be in two different buckets
    # (e.g. scanned_not_checklisted AND observed_not_declared) — the UI
    # tabs render each independently so the user sees the full picture.
    gaps: dict[str, list[str]] = defaultdict(list)
    for rec in hosts_sorted:
        cov = rec.coverage
        # Render every coverage state as its own bucket. The "complete"
        # bucket is informational; the UI shows a count, not a list.
        gaps[cov].append(rec.hostname)
        # No-STIG hosts are a separate concern from source coverage: a
        # host might be both scanned AND checklisted but the checklist's
        # title wasn't extractable, leaving stigs_applied empty.
        if rec.checklisted_in and not rec.stigs_applied:
            gaps["checklisted_but_stig_unknown"].append(rec.hostname)

    return AssetCoverageReport(
        sources=sorted(sources, key=lambda s: (s.category, s.label.lower())),
        hosts=hosts_sorted,
        gaps=dict(gaps),
        scanned_set=frozenset(scanned_set),
        checklisted_set=frozenset(checklisted_set),
        declared_set=frozenset(declared_set),
    )


# ---------------------------------------------------------------------------
# Prompt block rendering (CM-8 / CA-3 / PM-5 / RA-5 / CA-7)
# ---------------------------------------------------------------------------


def render_coverage_block(report: AssetCoverageReport) -> str | None:
    """Format the coverage report for injection into the user prompt.

    Returns ``None`` when no source contributed any hosts — keeping that
    path explicit lets the caller skip the placeholder so the prompt-cache
    prefix stays bit-identical to the no-evidence path.
    """
    if not report.sources:
        return None

    lines: list[str] = [
        "## asset_inventory_coverage",
        (
            "Auto-derived asset universe across scans (ACAS/Nessus), "
            "STIG checklists, and declared inventories. Gaps below indicate "
            "boundary-completeness or scan-coverage issues to call out."
        ),
        "",
        f"- scanned hosts:       {len(report.scanned_set)}",
        f"- checklisted hosts:   {len(report.checklisted_set)}",
        f"- declared hosts:      {len(report.declared_set)}",
        (
            "- union (all assets): "
            f"{len(report.scanned_set | report.checklisted_set | report.declared_set)}"
        ),
        "",
    ]

    # Gap classes we want the LLM to react to. "complete" is intentionally
    # omitted — confirming that everything matched isn't actionable and
    # eats budget on every CM-8 assess.
    gap_legend = [
        ("scanned_not_checklisted", "scanned but no STIG checklist (RA-5/CM-6)"),
        ("checklisted_not_scanned", "checklisted but no scan (CA-7)"),
        ("declared_not_observed", "declared in inventory, never observed (CM-8 ghost)"),
        ("observed_not_declared", "observed in scan/CKL, not in inventory (CM-8)"),
        ("scanned_only", "scanned only (no checklist, no inventory)"),
        ("checklisted_only", "checklisted only (no scan, no inventory)"),
        ("declared_not_observed", "declared only (never seen by scanner or CKL)"),
        ("checklisted_but_stig_unknown", "STIG title missing on checklist (parse issue)"),
    ]
    seen: set[str] = set()
    any_gaps = False
    for key, description in gap_legend:
        if key in seen:
            continue
        seen.add(key)
        hosts = report.gaps.get(key, [])
        if not hosts:
            continue
        any_gaps = True
        rendered = hosts[:MAX_HOSTS_IN_BLOCK]
        more = len(hosts) - len(rendered)
        suffix = f" ...(+{more} more)" if more > 0 else ""
        lines.append(f"GAP: {description} — {len(hosts)} host(s)")
        lines.append(f"  hosts: {rendered}{suffix}")

    if not any_gaps:
        lines.append(
            "MATCH: every observed host appears in scans, checklists, and inventory."
        )
    return "\n".join(lines)
