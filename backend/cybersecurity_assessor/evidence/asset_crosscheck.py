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
* **declared** — XLSX / CSV inventories the assessor flagged authoritative
  (``is_asset_list = True``). Per CM-8 the org's documented inventory IS the
  authority; scans/checklists VERIFY it (that's why declared seeds the host
  universe — so a declared-but-never-observed host surfaces as a CM-8 ghost).
  The flag is no longer a blind file-extension check: the ingest classifier
  (extractors/xlsx.py ``_classify_asset_workbook`` + hostname-column sniff)
  must have parsed the spreadsheet as a host inventory (non-empty
  ``host_inventory``) before it can be flagged — a budget or parts catalog with
  no host columns is rejected. The flag stays MANUAL (the assessor confirms
  which inventory is authoritative), but is now content-gated.

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
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from sqlmodel import Session, select

from ..db import chunked
from ..models import (
    Asset,
    BoundarySegment,
    Evidence,
    EvidenceAsset,
    EvidenceBoundary,
    EvidenceKind,
    StigFinding,
)

# Sentinel boundary for hosts whose evidence carries no boundary signal —
# no EvidenceBoundary link and no parseable folder-path token. In a
# single-boundary workbook EVERY host lands here, so the report behaves
# exactly as it did before boundary-awareness (zero regression). Two
# same-named hosts both "unspecified" still collapse — which is correct,
# because we have no evidence they are different devices.
UNSPECIFIED_BOUNDARY = "unspecified"

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
    """Per-host roll-up across all three derived sources.

    The identity of a host is ``(boundary, hostname)`` — a workbook can span
    multiple boundaries / CRNs under one ATO, and RFC1918 space + default
    hostnames are reused per enclave, so a bare ``192.168.1.1`` or ``dc01`` is
    NOT globally unique. ``boundary`` carries the per-evidence boundary label
    (from an EvidenceBoundary link, else a gated folder-path token, else
    ``"unspecified"``) so two same-named hosts in different boundaries stay
    distinct in the inventory while the same host across scan + checklist in ONE
    boundary still unions. ``"unspecified"`` is the single-boundary / untagged
    default — behaviour there is identical to the pre-boundary report.
    """

    hostname: str
    boundary: str = "unspecified"
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
class HostIdentityConflict:
    """A high-confidence contradiction in host identity, surfaced for review.

    The trust hierarchy (credentialed-scan ``(ip,fqdn)`` pair > declared
    inventory > checklist hostname) is normally used to COLLAPSE multiple IPs
    under one device silently. But when two sources bind the SAME IP in the SAME
    boundary to DIFFERENT device names, there is no safe collapse — one of them
    is wrong (a mislabeled checklist, a stale inventory row, an IP reassigned
    between scans). Per the assessor's "abstain, never guess" posture we do NOT
    pick a winner; we emit this record so a human reconciles it.

    Only the IP↔hostname disagreement is a conflict here. The other "orphan"
    case the design called out — a checklisted host no scan/inventory ever saw —
    is already visible as the ``checklisted_only`` gap bucket, so it is not
    duplicated into this channel (keeps the review list high-signal, no alert
    spam).
    """

    kind: str  # currently only "ip_hostname_disagreement"
    boundary: str
    ip: str
    hostnames: list[str]  # the >1 distinct device names claimed for this IP
    sources: list[SourceRef]  # artifacts that made the conflicting claims


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
    # ---- Source-type breakdown (additive, render-time) -------------------
    # These power the UI "what did we actually look at" card and replace the
    # misleading "Scanned 86 / Checklisted 0" headline with a device-centric
    # view. All four default to 0 so older callers / tests that build the
    # report directly keep working.
    #
    # distinct_ips      — bare IP literals seen by scans that are NOT collapsed
    #                     under a resolved device (uncredentialed scan IPs with
    #                     no (ip,fqdn) pair and no declared IP↔host mapping).
    #                     Shown calmly as "scanned IP not yet mapped to a
    #                     device" — NOT a conflict.
    # resolved_devices  — distinct device hostnames (everything in the host
    #                     universe that is a real name, not a bare IP). One per
    #                     physical/virtual box regardless of how many IPs it has.
    # checklists_regular — count of checklist Evidence rows whose file is a real
    #                     .ckl / .cklb / XCCDF checklist.
    # checklists_xlsx   — count of distinct (benchmark × host) checklists inside
    #                     DISA STIG-report .xlsx/.xlsm files. NOT a file count:
    #                     one such spreadsheet bundles one sheet per benchmark ×
    #                     one column per host, so it carries many checklists. We
    #                     count the distinct (rule_version, host) pairs its
    #                     StigFinding rows establish (see _xlsx_checklist_count),
    #                     falling back to 1-per-file for any that didn't parse.
    distinct_ips: int = 0
    resolved_devices: int = 0
    checklists_regular: int = 0
    checklists_xlsx: int = 0
    # ---- Host-identity conflicts (additive, render-time) -----------------
    # High-confidence contradictions where one IP is bound to >1 device name in
    # one boundary. Surfaced for human reconciliation, never auto-merged. Empty
    # for the overwhelming common case (clean credentialed scan / no inventory
    # disagreement), so older callers/tests that build the report directly keep
    # working.
    conflicts: list[HostIdentityConflict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Hostname normalization (kept from the prior module — same rules apply)
# ---------------------------------------------------------------------------


def _looks_like_ip(token: str) -> bool:
    """True if ``token`` parses as an IPv4/IPv6 address.

    Mirrors ``ingest._looks_like_ip`` (kept local to avoid an import
    cycle). An IP literal's dots are address octets, not a DNS suffix, so
    it must not be truncated — otherwise ``172.20.8.86`` → ``172`` and a
    whole scanned subnet collapses to one bogus host key.
    """
    import ipaddress

    try:
        ipaddress.ip_address(token.strip())
        return True
    except ValueError:
        return False


def _clean_host_token(name: str) -> str:
    """Lowercase + drop a trailing dot and a ``:port`` suffix before IP checks.

    Mirrors ``ingest._clean_host_token`` (kept local to avoid an import
    cycle). Strips a ``:port`` only when there is exactly one colon with an
    all-digit suffix, so a bare IPv6 literal is never mangled. Without this,
    ``1.2.3.4:443`` fails the IP guard and dot-splits to the bogus key ``"1"``.
    """
    n = (name or "").strip().lower().rstrip(".")
    if n.count(":") == 1:
        head, _, tail = n.partition(":")
        if head and tail.isdigit():
            n = head
    return n


def _normalize(name: str) -> str:
    """Lower-case, strip dot-domain suffix, drop surrounding whitespace.

    IP guard mirrors ``ingest._normalize_host``: an IPv4/IPv6 literal is
    returned whole so ingest-time and query-time host keys stay identical.
    A ``:port`` / trailing-dot is stripped first (see ``_clean_host_token``).
    """
    n = _clean_host_token(name)
    if "." in n and not _looks_like_ip(n):
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


# Spreadsheet extensions that mark a STIG_CKL evidence row as a DISA
# STIG-report .xlsx rather than a real .ckl/.cklb/XCCDF checklist. The
# kind is shared (xlsx.py emits STIG_CKL for STIG-report spreadsheets), so
# provenance must come from the file extension.
_STIG_XLSX_SUFFIXES: frozenset[str] = frozenset({".xlsx", ".xlsm"})


def _is_stig_xlsx(ev: Evidence) -> bool:
    """True if a checklist-kind Evidence row is really a STIG-report spreadsheet.

    ``xlsx.py`` tags DISA STIG-report ``.xlsx``/``.xlsm`` files as
    ``EvidenceKind.STIG_CKL`` so they flow into the checklisted bucket, but
    for the UI source-type breakdown the assessor wants them counted
    separately from hand/tool-authored ``.ckl`` checklists. The only
    discriminator is the file extension.
    """
    try:
        suffix = Path(ev.path).suffix.lower()
    except (TypeError, ValueError):
        return False
    return suffix in _STIG_XLSX_SUFFIXES


# STIG benchmark id looks like ``RHEL-08-010030`` / ``CNTR-R2-000010`` /
# ``FFOX-00-000001`` / ``DTBC-0001`` — a product/release token followed by a
# per-rule number. The CHECKLIST unit is the benchmark (the product+release),
# NOT the individual rule, so we strip the trailing rule number to a stable
# benchmark key: RHEL-08-010030 -> RHEL-08 ; DTBC-0001 -> DTBC.
_STIG_BENCHMARK_RE = re.compile(r"^([A-Za-z0-9]+(?:-[A-Za-z0-9]{1,3})?)")


def _benchmark_key(rule_version: str | None) -> str | None:
    """Reduce a STIG rule_version to its BENCHMARK key, or None if it isn't a
    STIG id (e.g. the OSCAP report puts a ``CCI-######`` in this column — that's
    a control mapping, NOT a benchmark, and must not be counted as one)."""
    rv = (rule_version or "").strip()
    if not rv or rv.upper().startswith("CCI-"):
        return None
    # DTBC-0001 / DTBC-0045 are all the Chrome benchmark -> collapse to DTBC.
    rv = re.sub(r"^(DTBC)-\d+$", r"\1", rv)
    m = _STIG_BENCHMARK_RE.match(rv)
    return m.group(1) if m else rv


def _xlsx_checklist_count(
    session: Session, xlsx_evidence_ids: list[int]
) -> int:
    """Count distinct (benchmark × host) checklists inside STIG-report xlsx files.

    A DISA STIG-report ``.xlsx`` is ONE Evidence row but bundles MANY checklists:
    one BENCHMARK (RHEL-08, Firefox, Chrome, RKE2…) assessed on each HOST. The
    extractor emits a :class:`StigFinding` per (rule × host) with the STIG id in
    ``rule_version`` and ``host=<hn>`` in ``comments``. The CHECKLIST unit is
    (benchmark × host) — NOT per-rule and NOT per-file:
      * counting files badly understated (a SCAP export = dozens of checklists);
      * counting raw (rule_version, host) badly OVERstated — rule_version is the
        per-rule id (RHEL-08-010030 vs -010040 are the SAME benchmark) and the
        OSCAP report even puts CCI-###### in that column. So we reduce
        rule_version to its benchmark key (``_benchmark_key``) and skip CCI rows.

    Falls back to one-per-file for any xlsx that produced NO parseable benchmark
    findings, so the count never drops BELOW the file count.
    """
    if not xlsx_evidence_ids:
        return 0
    pairs: set[tuple[str, str]] = set()
    files_with_findings: set[int] = set()
    for batch in chunked(xlsx_evidence_ids):
        rows = session.exec(
            select(
                StigFinding.evidence_id,
                StigFinding.rule_version,
                StigFinding.comments,
            ).where(StigFinding.evidence_id.in_(batch))  # type: ignore[attr-defined]
        ).all()
        for eid, rule_version, comments in rows:
            benchmark = _benchmark_key(rule_version)
            if benchmark is None:
                continue  # CCI row / non-STIG — not a benchmark checklist
            files_with_findings.add(eid)
            host = ""
            if comments and comments.startswith("host="):
                host = comments[len("host="):].strip()
            pairs.add((benchmark, host))
    parsed_count = len(pairs)
    # Files we tagged as STIG-xlsx but that produced no parseable benchmark
    # finding still count once each (processed, just not parseable).
    unparsed_files = len(set(xlsx_evidence_ids) - files_with_findings)
    return parsed_count + unparsed_files


def _device_ip_map(
    session: Session, evidence_ids: Iterable[int]
) -> dict[str, set[str]]:
    """Resolve credentialed-scan ``host_pairs`` into ``{device: {ips}}``.

    Reads the SIBLING ``host_pairs`` JSON column on each in-scope Evidence
    row (populated by ``ingest._capture_host_pairs`` for credentialed
    scans). The map lets the cross-check collapse every IP a scan reported
    for a device under that ONE device key, so a box scanned on two
    interfaces counts as a single resolved device with two IP attributes —
    not two hosts.

    Device key = bare short form of the pair's FQDN (matches ``_normalize``
    so it lines up with the host universe keys). IP literals stay whole.
    Malformed / empty blobs contribute nothing. One query for the workbook.
    """
    ids = [e for e in evidence_ids if e]
    if not ids:
        return {}
    out: dict[str, set[str]] = defaultdict(set)
    for batch in chunked(ids):
        rows = session.exec(
            select(Evidence.host_pairs).where(Evidence.id.in_(batch))  # type: ignore[attr-defined]
        ).all()
        for raw in rows:
            if not raw:
                continue
            try:
                data = json.loads(raw)
            except (TypeError, ValueError):
                continue
            if not isinstance(data, list):
                continue
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                ip = entry.get("ip")
                fqdn = entry.get("fqdn")
                if not (
                    isinstance(ip, str) and ip and isinstance(fqdn, str) and fqdn
                ):
                    continue
                device = _normalize(fqdn)
                if not device:
                    continue
                out[device].add(ip.strip())
    return {k: set(v) for k, v in out.items()}


def _ip_hostname_conflicts(
    session: Session,
    evidence_ids: Iterable[int],
    boundary_by_ev: dict[int, str],
) -> list[HostIdentityConflict]:
    """Detect IPs that two sources bind to DIFFERENT device names, per boundary.

    Reads every in-scope Evidence row's ``host_pairs`` JSON (the ``{ip,fqdn}``
    list ingest captures for credentialed scans + any inventory that supplies
    it) and indexes ``(boundary, ip) -> {device -> [SourceRef]}``. An IP that
    resolves to a SINGLE device name across all its claims is a normal collapse
    (handled silently by :func:`_device_ip_map`). An IP claimed for TWO OR MORE
    distinct device names in the SAME boundary is a genuine identity
    contradiction — we cannot trust either binding, so we emit a
    :class:`HostIdentityConflict` for human review instead of silently picking
    one (the "abstain, never guess" posture the assessor uses everywhere).

    Boundary-keyed so the same IP legitimately reused for different devices in
    two enclaves is NOT a conflict — only a disagreement WITHIN one boundary is.
    One query over ``host_pairs`` for the whole workbook (no N+1). Device names
    run through :func:`_normalize` so ``dc01`` and ``dc01.dom.mil`` claiming the
    same IP do not read as a false conflict.
    """
    ids = [e for e in evidence_ids if e]
    if not ids:
        return []
    # (boundary, ip) -> {device -> {evidence_id: SourceRef}}
    claims: dict[tuple[str, str], dict[str, dict[int, SourceRef]]] = defaultdict(
        lambda: defaultdict(dict)
    )
    for batch in chunked(ids):
        rows = session.exec(
            select(Evidence.id, Evidence.host_pairs, Evidence.kind, Evidence.title, Evidence.path, Evidence.asset_list_label).where(
                Evidence.id.in_(batch)  # type: ignore[attr-defined]
            )
        ).all()
        for ev_id, raw, kind, title, path, asset_label in rows:
            if not raw:
                continue
            try:
                data = json.loads(raw)
            except (TypeError, ValueError):
                continue
            if not isinstance(data, list):
                continue
            bnd = boundary_by_ev.get(ev_id, UNSPECIFIED_BOUNDARY)
            label = asset_label or title or (Path(path).name if path else "")
            ref = SourceRef(
                evidence_id=ev_id or 0,
                label=label,
                kind=kind.value if hasattr(kind, "value") else str(kind),
            )
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                ip = entry.get("ip")
                fqdn = entry.get("fqdn")
                if not (isinstance(ip, str) and ip.strip()):
                    continue
                device = _normalize(fqdn) if isinstance(fqdn, str) else ""
                if not device:
                    continue
                claims[(bnd, ip.strip())][device][ev_id or 0] = ref

    conflicts: list[HostIdentityConflict] = []
    for (bnd, ip), by_device in claims.items():
        if len(by_device) < 2:
            continue  # single device name for this IP — normal collapse
        # Gather the artifacts that made the conflicting claims, deduped by
        # evidence id, deterministically ordered for stable output.
        refs: dict[int, SourceRef] = {}
        for dev_refs in by_device.values():
            refs.update(dev_refs)
        conflicts.append(
            HostIdentityConflict(
                kind="ip_hostname_disagreement",
                boundary=bnd,
                ip=ip,
                hostnames=sorted(by_device.keys()),
                sources=[refs[k] for k in sorted(refs.keys())],
            )
        )
    # Stable order: boundary, then IP.
    conflicts.sort(key=lambda c: (c.boundary, c.ip))
    return conflicts


def _mapped_ips_by_boundary(
    session: Session,
    evidence_ids: Iterable[int],
    boundary_by_ev: dict[int, str],
) -> set[tuple[str, str]]:
    """Reverse index of every IP claimed by a credentialed pair, per boundary.

    Returns ``{(boundary, ip)}`` so an IP paired to a device in one boundary
    cannot mark a bare same-IP host in another boundary as "already mapped".
    Single query over ``host_pairs`` for the whole workbook (no per-evidence
    N+1); the boundary for each row comes from the pre-resolved
    ``boundary_by_ev`` map (default :data:`UNSPECIFIED_BOUNDARY`).
    """
    ids = [e for e in evidence_ids if e]
    if not ids:
        return set()
    out: set[tuple[str, str]] = set()
    for batch in chunked(ids):
        rows = session.exec(
            select(Evidence.id, Evidence.host_pairs).where(
                Evidence.id.in_(batch)  # type: ignore[attr-defined]
            )
        ).all()
        for ev_id, raw in rows:
            if not raw:
                continue
            try:
                data = json.loads(raw)
            except (TypeError, ValueError):
                continue
            if not isinstance(data, list):
                continue
            bnd = boundary_by_ev.get(ev_id, UNSPECIFIED_BOUNDARY)
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                ip = entry.get("ip")
                if isinstance(ip, str) and ip.strip():
                    out.add((bnd, ip.strip()))
    return out


def _host_gap_label(rec: "HostRecord") -> str:
    """Gap-bucket display label for a host.

    Boundary-qualified (``"CRN-A/dc01"``) when the host carries a real
    boundary so two same-named hosts in different boundaries don't render as
    one indistinguishable row. Unspecified-boundary hosts keep the bare
    hostname so a single-boundary report's gap lists are byte-identical to the
    pre-boundary output (zero churn for the common case).
    """
    if rec.boundary and rec.boundary != UNSPECIFIED_BOUNDARY:
        return f"{rec.boundary}/{rec.hostname}"
    return rec.hostname


# ---------------------------------------------------------------------------
# Boundary resolution (per-evidence → boundary label for the host key)
# ---------------------------------------------------------------------------

# Path segments that are NEVER a boundary even when they sit just above an
# eMASS NN.XX family token — generic container folders, the workbook/system
# name, or a bare year. Lowercased compare. Keeps the folder-path fallback
# from inventing a bogus boundary like "Body of Evidence" or "2026".
_BOUNDARY_PATH_DENYLIST: frozenset[str] = frozenset(
    {
        "evidence",
        "boe",
        "body of evidence",
        "body_of_evidence",
        "artifacts",
        "uploads",
        "upload",
        "scans",
        "stigs",
        "configs",
        "policies",
        "diagrams",
        "documents",
        "docs",
    }
)


def _boundary_from_path(path: str | None) -> str | None:
    """Best-effort boundary label from the eMASS folder convention.

    Anchors on the strict ``NN.XX`` family token (same convention
    ``tagger._family_from_path`` keys on) and takes the path segment
    IMMEDIATELY ABOVE it as the boundary candidate — e.g.
    ``file:///.../CRN-A/01.AC/scan.nessus`` → ``CRN-A``. Returns ``None``
    (contributes nothing, safe default) when the convention is absent, the
    parent segment is generic/denylisted, or it's a bare year. This is a
    LOW-PRIORITY fallback beneath an explicit EvidenceBoundary link — a real
    BoE tree rarely encodes boundary in the path, so this only refines the
    disciplined case and is inert everywhere else.
    """
    if not path:
        return None
    # Find the family token and capture the segment just before it. Split on
    # both / and ! so file:// and zip:// member URIs both work.
    m = re.search(r"[/!]([^/!]+)[/!]\d{2}\.[A-Za-z]{2}[/_.]", path)
    if not m:
        return None
    seg = m.group(1).strip()
    if not seg:
        return None
    low = seg.lower()
    if low in _BOUNDARY_PATH_DENYLIST:
        return None
    if re.fullmatch(r"\d{4}", seg):  # bare year, not a boundary
        return None
    return seg


def _boundary_by_evidence(
    session: Session, evidence_ids: Iterable[int]
) -> dict[int, str]:
    """Resolve each Evidence row to its boundary label.

    Priority: an explicit :class:`EvidenceBoundary` link (the assessor tagged
    the artifact, or a boundary-doc backfill created one) wins; otherwise the
    gated folder-path token; otherwise the row is absent from the dict and the
    caller defaults it to :data:`UNSPECIFIED_BOUNDARY`. One artifact can carry
    multiple boundary links in theory — we take the lowest-id segment name
    deterministically so the key is stable across runs.

    Returns ``{evidence_id: boundary_label}`` for rows that resolved to a
    NON-unspecified boundary only; unresolved rows are simply not present.
    """
    ids = [e for e in evidence_ids if e]
    if not ids:
        return {}

    # 1) Explicit EvidenceBoundary links → BoundarySegment.name. Join once,
    #    bucket per evidence, keep the segment with the smallest id for
    #    determinism when an artifact is linked to several segments.
    link_boundary: dict[int, tuple[int, str]] = {}
    for batch in chunked(ids):
        rows = session.exec(
            select(
                EvidenceBoundary.evidence_id,
                BoundarySegment.id,
                BoundarySegment.name,
            )
            .join(
                BoundarySegment,
                BoundarySegment.id == EvidenceBoundary.boundary_segment_id,
            )
            .where(EvidenceBoundary.evidence_id.in_(batch))  # type: ignore[attr-defined]
        ).all()
        for ev_id, seg_id, seg_name in rows:
            name = (seg_name or "").strip()
            if not name:
                continue
            cur = link_boundary.get(ev_id)
            if cur is None or (seg_id is not None and seg_id < cur[0]):
                link_boundary[ev_id] = (seg_id or 0, name)

    out: dict[int, str] = {ev_id: nm for ev_id, (sid, nm) in link_boundary.items()}

    # 2) Folder-path fallback for rows with no explicit link. One query for
    #    paths of the still-unresolved ids.
    unresolved = [e for e in ids if e not in out]
    if unresolved:
        for batch in chunked(unresolved):
            rows = session.exec(
                select(Evidence.id, Evidence.path).where(
                    Evidence.id.in_(batch)  # type: ignore[attr-defined]
                )
            ).all()
            for ev_id, path in rows:
                label = _boundary_from_path(path)
                if label:
                    out[ev_id] = label
    return out


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

    # Per-evidence boundary label (explicit EvidenceBoundary link > gated
    # folder-path token > unspecified). The host identity is (boundary, host)
    # so a hostname/IP reused across enclaves (192.168.1.1 in CRN-A vs CRN-B,
    # dc01 x2) stays distinct, while the same host across scan + checklist in
    # ONE boundary still unions. Single-boundary / untagged workbooks resolve
    # everything to UNSPECIFIED_BOUNDARY → identical to the pre-boundary report.
    boundary_by_ev = _boundary_by_evidence(session, in_scope_ids)

    # Credentialed-scan (ip, fqdn) pairs, keyed (boundary, ip). A paired
    # 192.168.1.1→dcA in boundary A must NOT absorb a bare 192.168.1.1 scanned
    # in boundary B, so the mapped-IP reverse index is keyed (boundary, ip),
    # not a flat global IP set. One query for the whole workbook (no N+1).
    mapped_ips: set[tuple[str, str]] = _mapped_ips_by_boundary(
        session, in_scope_ids, boundary_by_ev
    )

    # High-confidence host-identity contradictions (one IP → >1 device name in
    # one boundary). Surfaced for human review, NEVER auto-merged. Independent of
    # the silent (ip,fqdn) collapse above — that resolves the agreeing case; this
    # flags the disagreeing one. Empty for the clean common case.
    conflicts = _ip_hostname_conflicts(session, in_scope_ids, boundary_by_ev)

    # (boundary, host) → HostRecord under construction
    host_index: dict[tuple[str, str], HostRecord] = {}
    # (boundary, host) → set of STIG titles applied (deduped across multi-STIG CKLs)
    stigs_by_host: dict[tuple[str, str], set[str]] = defaultdict(set)
    sources: list[SourceSummary] = []

    # Headline-count sets are (boundary, host) tuples so len()/union stop
    # collapsing same-named hosts across boundaries.
    scanned_set: set[tuple[str, str]] = set()
    checklisted_set: set[tuple[str, str]] = set()
    declared_set: set[tuple[str, str]] = set()

    # Source-type breakdown tallies. A regular .ckl/.cklb/XCCDF is one checklist
    # per file (inherently one benchmark × one host). A STIG-report .xlsx is ONE
    # file but MANY checklists (one sheet per benchmark × one column per host) —
    # so we collect its evidence ids here and count distinct (benchmark, host)
    # pairs from its StigFinding rows AFTER the loop (see _xlsx_checklist_count).
    # device/IP counts are derived from the host universe after the loop.
    checklists_regular = 0
    xlsx_checklist_ids: list[int] = []

    for ev in rows:
        category = _category(ev)
        if category is None:
            continue
        if category == "checklisted":
            if _is_stig_xlsx(ev):
                if ev.id is not None:
                    xlsx_checklist_ids.append(ev.id)
            else:
                checklists_regular += 1
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

        boundary = boundary_by_ev.get(ev.id or 0, UNSPECIFIED_BOUNDARY)
        ref = SourceRef(
            evidence_id=ev.id or 0, label=_label(ev), kind=ev.kind.value
        )
        for h in hosts:
            key = (boundary, h)
            rec = host_index.get(key)
            if rec is None:
                rec = HostRecord(hostname=h, boundary=boundary)
                host_index[key] = rec
            # Headline-count de-dup: a bare IP that a credentialed scan PAIRED
            # with a device (same boundary, in mapped_ips) is the SAME physical
            # asset as that device's hostname row — counting both inflated the
            # headline (154) above the device-centric card (86). Skip the paired
            # IP from the count SETS only; its device's hostname row supplies the
            # count. The per-host map / gaps keep the full key so the IP still
            # shows as an attribute row. A genuinely unpaired IP is NOT in
            # mapped_ips, so it still counts once (matches distinct_ips). Gated on
            # (boundary, h) so a paired IP in CRN-A never suppresses the same IP
            # bare-scanned in CRN-B.
            count_in_headline = not (
                _looks_like_ip(h) and (boundary, h) in mapped_ips
            )
            if category == "scanned":
                rec.scanned_in.append(ref)
                if count_in_headline:
                    scanned_set.add(key)
            elif category == "checklisted":
                rec.checklisted_in.append(ref)
                if count_in_headline:
                    checklisted_set.add(key)
                # Evidence.title for CKL/CKLB/XCCDF carries the STIG name.
                # Skip when missing rather than substituting the filename
                # — a filename like "WIN2022.ckl" is not the STIG title and
                # would mislead the coverage panel.
                if ev.title:
                    stigs_by_host[key].add(ev.title)
            else:  # declared
                rec.declared_in.append(ref)
                if count_in_headline:
                    declared_set.add(key)

    # Attach STIG titles to each host, sorted for stable display.
    for key, rec in host_index.items():
        rec.stigs_applied = sorted(stigs_by_host.get(key, ()))

    # Stable order: boundary first, then hostname, so multi-boundary reports
    # group naturally and same-named hosts in different boundaries are adjacent.
    hosts_sorted = sorted(
        host_index.values(), key=lambda r: (r.boundary, r.hostname)
    )

    # Gap buckets. The same hostname can be in two different buckets
    # (e.g. scanned_not_checklisted AND observed_not_declared) — the UI
    # tabs render each independently so the user sees the full picture.
    # Entries are boundary-qualified ("CRN-A/dc01") when the host carries a
    # non-unspecified boundary so two same-named hosts don't render as one
    # indistinguishable row; unspecified hosts keep the bare hostname so the
    # single-boundary report is byte-identical to before.
    gaps: dict[str, list[str]] = defaultdict(list)
    for rec in hosts_sorted:
        label = _host_gap_label(rec)
        cov = rec.coverage
        # Render every coverage state as its own bucket. The "complete"
        # bucket is informational; the UI shows a count, not a list.
        gaps[cov].append(label)
        # No-STIG hosts are a separate concern from source coverage: a
        # host might be both scanned AND checklisted but the checklist's
        # title wasn't extractable, leaving stigs_applied empty.
        if rec.checklisted_in and not rec.stigs_applied:
            gaps["checklisted_but_stig_unknown"].append(label)

    # ---- Source-type breakdown: IPs vs resolved devices -----------------
    # Walk the final host universe once. Device-centric rule:
    #   * a real hostname (not an IP literal)            → resolved device
    #   * a bare IP literal that some scan PAIRED with a  → already collapsed
    #     device (in mapped_ips) IN THE SAME BOUNDARY        under that device;
    #                                                        do NOT double-count
    #   * a bare IP literal with NO pairing               → unmapped scanned IP
    #     and not declared in any inventory map             (calm "not yet
    #                                                        mapped to a device")
    # An IP that the declared inventory itself names as a host is treated as a
    # device (the inventory asserts it IS the device's identity) — so only
    # scanned-only / checklisted-only bare IPs land in distinct_ips.
    # STIG-report xlsx checklists: distinct (benchmark × host), not file count.
    checklists_xlsx = _xlsx_checklist_count(session, xlsx_checklist_ids)

    resolved_devices = 0
    distinct_ips = 0
    for rec in hosts_sorted:
        host = rec.hostname
        if not _looks_like_ip(host):
            resolved_devices += 1
            continue
        # host is a bare IP literal — check the pairing within ITS boundary.
        if (rec.boundary, host) in mapped_ips:
            # Collapsed under a resolved device via a credentialed pair —
            # the device side is (or will be) counted as resolved; the IP is
            # an attribute, not its own device.
            continue
        if rec.declared_in:
            # The declared inventory lists this IP as an asset in its own
            # right. Treat it as a (thinly-identified) device, not an
            # orphan scan IP.
            resolved_devices += 1
            continue
        distinct_ips += 1

    return AssetCoverageReport(
        sources=sorted(sources, key=lambda s: (s.category, s.label.lower())),
        hosts=hosts_sorted,
        gaps=dict(gaps),
        scanned_set=frozenset(scanned_set),
        checklisted_set=frozenset(checklisted_set),
        declared_set=frozenset(declared_set),
        distinct_ips=distinct_ips,
        resolved_devices=resolved_devices,
        checklists_regular=checklists_regular,
        checklists_xlsx=checklists_xlsx,
        conflicts=conflicts,
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

    # Host-identity conflicts: one IP bound to >1 device name in a boundary.
    # These are contradictions to call out (CM-8 inventory accuracy), not gaps —
    # render them distinctly so the assessor reconciles rather than trusting a
    # silent merge.
    if report.conflicts:
        lines.append("")
        lines.append(
            "CONFLICT: host-identity disagreements (one IP claimed for multiple "
            "device names — reconcile, do not assume a single host):"
        )
        for c in report.conflicts[:MAX_HOSTS_IN_BLOCK]:
            where = "" if c.boundary == UNSPECIFIED_BOUNDARY else f" [{c.boundary}]"
            labels = sorted({s.label for s in c.sources})
            lines.append(
                f"  {c.ip}{where} -> {c.hostnames} (per: {labels})"
            )
        extra = len(report.conflicts) - MAX_HOSTS_IN_BLOCK
        if extra > 0:
            lines.append(f"  ...(+{extra} more conflict(s))")
    return "\n".join(lines)
