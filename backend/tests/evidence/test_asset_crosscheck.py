"""Coverage tests for the auto-derived asset cross-check.

The rebuild swapped a manual ``is_asset_list`` tagging workflow for an
auto-derivation pipeline: every ``Evidence.host_inventory`` JSON cache is
sorted into one of three source buckets (scanned / checklisted /
declared), per-host source mix becomes a coverage tag, and gaps are
mapped to CM-8 / CM-6 / CA-3 / CA-7 / PM-5 / RA-5. The shape of that
report drives both the UI panel and the prompt block injected into
coverage-sensitive CCIs.

These tests pin three concerns the rebuild introduced and that nothing
else exercises:

* ``summarize_asset_coverage`` — host index, source dedup, gap
  classification, hostname normalization, supersession filtering.
* ``_COVERAGE_CONTROL_RE`` — the prompt-cache-preserving family gate
  in routes/controls.py. Widened from 3 families to 6; the word-boundary
  anchor must reject ``CM-80`` while accepting ``CM-8(1)``.
* ``render_coverage_block`` — None-on-empty contract (keeps prompt-cache
  prefix bit-identical for evidence-free assess paths), MAX_HOSTS
  truncation marker, and the no-gaps MATCH line.

Backed by hand-seeded ``Evidence`` rows with ``host_inventory`` set
directly so the logic under test is isolated from the extractor pipeline.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.evidence.asset_crosscheck import (  # noqa: E402
    MAX_HOSTS_IN_BLOCK,
    AssetCoverageReport,
    HostRecord,
    SourceSummary,
    render_coverage_block,
    summarize_asset_coverage,
)
from cybersecurity_assessor.engine.inputs import (  # noqa: E402
    _COVERAGE_CONTROL_RE,
    _is_coverage_control,
)
from cybersecurity_assessor.models import Evidence, EvidenceKind  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _make_evidence(
    session: Session,
    *,
    path: str,
    kind: EvidenceKind,
    hosts: list[str] | None,
    title: str | None = None,
    is_asset_list: bool = False,
    asset_list_label: str | None = None,
    superseded_by_id: int | None = None,
    workbook_id: int = 1,
    host_pairs: list[dict[str, str]] | None = None,
) -> Evidence:
    """Seed one Evidence row with host_inventory JSON pre-populated.

    Bypassing the extractor + tagger pipeline keeps the test focused on
    the coverage logic — that pipeline has its own tests in
    test_asset_inventory_autotag.py.

    ``workbook_id`` defaults to 1 to match the ``workbook_id=1`` every
    ``summarize_asset_coverage`` call in this module passes — PR 2's
    per-workbook scoping filters ``Evidence.workbook_id``, so an unscoped
    (None) row is invisible to the coverage query.

    ``host_pairs`` seeds the device-identity sibling column with a list of
    ``{"ip","fqdn"}`` dicts (what a credentialed scan emits). None = the
    column stays NULL, matching uncredentialed scans / legacy rows.
    """
    ev = Evidence(
        path=path,
        sha256=f"sha256:{path}",
        kind=kind,
        size_bytes=1,
        title=title,
        is_asset_list=is_asset_list,
        asset_list_label=asset_list_label,
        host_inventory=json.dumps(hosts) if hosts is not None else None,
        host_pairs=json.dumps(host_pairs) if host_pairs is not None else None,
        superseded_by_id=superseded_by_id,
        workbook_id=workbook_id,
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    return ev


# ---------------------------------------------------------------------------
# summarize_asset_coverage
# ---------------------------------------------------------------------------


def test_empty_db_returns_empty_report(session):
    """No evidence rows → empty sets, empty host list, no gaps."""
    report = summarize_asset_coverage(workbook_id=1, session=session)
    assert report.sources == []
    assert report.hosts == []
    assert report.gaps == {}
    assert report.scanned_set == frozenset()
    assert report.checklisted_set == frozenset()
    assert report.declared_set == frozenset()


def test_nessus_only_host_classified_as_scanned_only(session):
    """A host seen only by Nessus lands in the scanned_only gap."""
    _make_evidence(
        session,
        path="file:///scan.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["server01"],
        title="ACAS scan 2026-06",
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)
    # Host identity is (boundary, hostname); a single-boundary / untagged
    # workbook resolves every host to the "unspecified" sentinel.
    assert report.scanned_set == {("unspecified", "server01")}
    assert report.checklisted_set == frozenset()
    assert report.declared_set == frozenset()
    assert [h.hostname for h in report.hosts] == ["server01"]
    assert report.hosts[0].boundary == "unspecified"
    assert report.hosts[0].coverage == "scanned_only"
    assert "server01" in report.gaps.get("scanned_only", [])


def test_ckl_only_host_attaches_stig_title(session):
    """CKL kind populates checklisted_set AND stigs_applied from title."""
    _make_evidence(
        session,
        path="file:///host.ckl",
        kind=EvidenceKind.STIG_CKL,
        hosts=["server02"],
        title="Microsoft Windows Server 2022 STIG",
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)
    assert report.checklisted_set == {("unspecified", "server02")}
    rec = report.hosts[0]
    assert rec.coverage == "checklisted_only"
    assert rec.stigs_applied == ["Microsoft Windows Server 2022 STIG"]


def test_ckl_without_title_creates_unknown_stig_gap(session):
    """No title on a CKL → host lands in checklisted_but_stig_unknown."""
    _make_evidence(
        session,
        path="file:///headless.ckl",
        kind=EvidenceKind.STIG_CKL,
        hosts=["server03"],
        title=None,  # extractor failed to parse the STIG title
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)
    rec = report.hosts[0]
    assert rec.stigs_applied == []
    assert "server03" in report.gaps.get("checklisted_but_stig_unknown", [])


def test_declared_inventory_requires_explicit_flag(session):
    """is_asset_list=False on an XLSX with hosts → ignored entirely.

    Pins the "no silent misclassification" rule — a vendor parts catalog
    and an HW/SW inventory look identical by column shape.
    """
    _make_evidence(
        session,
        path="file:///vendor_catalog.xlsx",
        kind=EvidenceKind.XLSX,
        hosts=["server04"],
        is_asset_list=False,  # the critical flag
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)
    assert report.sources == []
    assert report.declared_set == frozenset()


def test_declared_inventory_with_flag_populates_declared_set(session):
    """is_asset_list=True XLSX contributes to declared_set."""
    _make_evidence(
        session,
        path="file:///hw_inventory.xlsx",
        kind=EvidenceKind.XLSX,
        hosts=["server05"],
        is_asset_list=True,
        asset_list_label="Approved HW/SW",
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)
    assert report.declared_set == {("unspecified", "server05")}
    assert report.hosts[0].coverage == "declared_not_observed"
    # asset_list_label takes precedence over title/filename in the source label.
    assert report.sources[0].label == "Approved HW/SW"


def test_three_source_full_match_lands_in_complete(session):
    """A host seen by all three sources → coverage = complete, no gaps."""
    _make_evidence(
        session,
        path="file:///scan.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["server06"],
    )
    _make_evidence(
        session,
        path="file:///host.ckl",
        kind=EvidenceKind.STIG_CKL,
        hosts=["server06"],
        title="Windows STIG",
    )
    _make_evidence(
        session,
        path="file:///inv.xlsx",
        kind=EvidenceKind.XLSX,
        hosts=["server06"],
        is_asset_list=True,
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)
    rec = report.hosts[0]
    assert rec.coverage == "complete"
    # complete is rendered as a count, not a gap action — but the bucket
    # exists so the UI can show "N complete hosts".
    assert report.gaps.get("complete") == ["server06"]
    # Headline counts all see the same host.
    assert report.scanned_set == {("unspecified", "server06")}
    assert report.checklisted_set == {("unspecified", "server06")}
    assert report.declared_set == {("unspecified", "server06")}


def test_scanned_and_checklisted_but_not_declared(session):
    """Scan + CKL with no declared inventory → observed_not_declared (CM-8)."""
    _make_evidence(
        session,
        path="file:///scan.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["server07"],
    )
    _make_evidence(
        session,
        path="file:///host.ckl",
        kind=EvidenceKind.STIG_CKL,
        hosts=["server07"],
        title="RHEL STIG",
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)
    assert report.hosts[0].coverage == "observed_not_declared"


def test_hostname_normalization_collapses_variants(session):
    """``Server08.dom.mil`` ≡ ``server08`` ≡ ``SERVER08`` — one HostRecord."""
    _make_evidence(
        session,
        path="file:///scan.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["Server08.dom.mil"],
    )
    _make_evidence(
        session,
        path="file:///host.ckl",
        kind=EvidenceKind.STIG_CKL,
        hosts=["SERVER08"],
        title="STIG",
    )
    _make_evidence(
        session,
        path="file:///inv.xlsx",
        kind=EvidenceKind.XLSX,
        hosts=["server08"],
        is_asset_list=True,
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)
    assert [h.hostname for h in report.hosts] == ["server08"]
    assert report.hosts[0].coverage == "complete"


def test_superseded_evidence_is_excluded(session):
    """A superseded row must not contribute to the asset universe."""
    current = _make_evidence(
        session,
        path="file:///current.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["server-current"],
    )
    _make_evidence(
        session,
        path="file:///old.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["server-old"],
        superseded_by_id=current.id,
    )

    # Normalization lowercases — but both fixture names are already lower.
    report = summarize_asset_coverage(workbook_id=1, session=session)
    assert report.scanned_set == {("unspecified", "server-current")}
    assert ("unspecified", "server-old") not in report.scanned_set


def test_source_with_empty_host_list_still_reported(session):
    """A scan that enumerated zero hosts shows up as a source with count 0.

    The UI uses this to prove the artifact was processed even when its
    host yield was empty — distinguishes "skipped" from "found nothing".
    """
    _make_evidence(
        session,
        path="file:///empty.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=[],
        title="Empty scan",
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)
    assert len(report.sources) == 1
    assert report.sources[0].host_count == 0
    assert report.sources[0].category == "scanned"
    assert report.hosts == []


def test_malformed_host_inventory_is_silently_dropped(session):
    """Non-JSON / non-list host_inventory must not crash the summarizer."""
    _make_evidence(
        session,
        path="file:///broken.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=None,  # NULL host_inventory
    )
    # Insert a row with deliberately garbage JSON.
    bad = Evidence(
        path="file:///garbage.nessus",
        sha256="sha256:garbage",
        kind=EvidenceKind.NESSUS,
        size_bytes=1,
        host_inventory="{not json",
    )
    session.add(bad)
    session.commit()

    report = summarize_asset_coverage(workbook_id=1, session=session)
    # Both rows produce zero-host source entries; no host records.
    assert all(s.host_count == 0 for s in report.sources)
    assert report.hosts == []


def test_multi_stig_titles_dedup_and_sort(session):
    """Two CKLs on the same host → stigs_applied has both, sorted, deduped."""
    _make_evidence(
        session,
        path="file:///a.ckl",
        kind=EvidenceKind.STIG_CKL,
        hosts=["serverC"],
        title="Windows STIG",
    )
    _make_evidence(
        session,
        path="file:///b.cklb",
        kind=EvidenceKind.STIG_CKLB,
        hosts=["serverC"],
        title="Apache STIG",
    )
    _make_evidence(
        session,
        path="file:///c.ckl",
        kind=EvidenceKind.STIG_CKL,
        hosts=["serverC"],
        title="Windows STIG",  # duplicate of the first
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)
    assert report.hosts[0].stigs_applied == ["Apache STIG", "Windows STIG"]


# ---------------------------------------------------------------------------
# _COVERAGE_CONTROL_RE / _is_coverage_control
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "control_id",
    [
        "CM-8", "CM-8(1)", "CM-8 (3)",
        "CM-6", "CM-6(1)",
        "CA-3", "CA-3(5)",
        "CA-7", "CA-7(4)",
        "PM-5", "PM-5(1)",
        "RA-5", "RA-5(2)",
    ],
)
def test_coverage_gate_matches_all_six_families_with_enhancements(control_id):
    """Every family in the rebuild's scope (+ enhancement form) gates true."""
    assert _is_coverage_control(control_id), control_id


@pytest.mark.parametrize(
    "control_id",
    [
        "CM-80",   # would have matched a naive ^CM-8 anchor — the bug guarded by \b
        "CM-800",
        "AC-2",
        "AU-3",
        "SI-4",
        "RA-50",
        "PM-50",
        "",
    ],
)
def test_coverage_gate_rejects_unrelated_controls(control_id):
    """Out-of-scope controls (incl. CM-80 word-boundary trap) gate false."""
    assert not _is_coverage_control(control_id), control_id


def test_coverage_gate_handles_none():
    """A NULL control_id must not raise — narrative builds with no Control row."""
    assert _is_coverage_control(None) is False


def test_coverage_gate_regex_pattern_is_anchored():
    """Defense-in-depth: confirm the regex is start-anchored and word-bounded."""
    # Mid-string match must not fire.
    assert _COVERAGE_CONTROL_RE.search("XCM-8") is None or not _is_coverage_control("XCM-8")
    assert _is_coverage_control("XCM-8") is False


# ---------------------------------------------------------------------------
# render_coverage_block
# ---------------------------------------------------------------------------


def _empty_report() -> AssetCoverageReport:
    return AssetCoverageReport(
        sources=[],
        hosts=[],
        gaps={},
        scanned_set=frozenset(),
        checklisted_set=frozenset(),
        declared_set=frozenset(),
    )


def test_render_returns_none_when_no_sources():
    """Empty report → None so the caller can skip injecting the block.

    Pins the prompt-cache discipline: the no-evidence path must produce
    a bit-identical prefix to the evidence-present path that has nothing
    to say. Returning an empty string would still go into the cache key.
    """
    assert render_coverage_block(_empty_report()) is None


def test_render_returns_none_even_with_hosts_if_no_sources():
    """Source list is the gate, not host list — both should be empty together,
    but the contract pins on ``sources`` alone."""
    report = AssetCoverageReport(
        sources=[],
        hosts=[HostRecord(hostname="ghost")],
        gaps={"scanned_only": ["ghost"]},
        scanned_set=frozenset(),
        checklisted_set=frozenset(),
        declared_set=frozenset(),
    )
    assert render_coverage_block(report) is None


def test_render_includes_headline_counts_and_section_header(session):
    """Block leads with the section header and four headline counts."""
    _make_evidence(
        session,
        path="file:///a.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["h1", "h2"],
    )
    _make_evidence(
        session,
        path="file:///b.ckl",
        kind=EvidenceKind.STIG_CKL,
        hosts=["h2", "h3"],
        title="STIG",
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)
    block = render_coverage_block(report)

    assert block is not None
    assert block.startswith("## asset_inventory_coverage")
    assert "- scanned hosts:       2" in block
    assert "- checklisted hosts:   2" in block
    assert "- declared hosts:      0" in block
    # Union: h1 ∪ h2 ∪ h3 = 3.
    assert "- union (all assets): 3" in block


def test_render_emits_match_line_when_every_host_aligns(session):
    """All hosts complete → no GAP lines, single MATCH line."""
    _make_evidence(session, path="file:///a.nessus", kind=EvidenceKind.NESSUS, hosts=["h"])
    _make_evidence(
        session,
        path="file:///b.ckl",
        kind=EvidenceKind.STIG_CKL,
        hosts=["h"],
        title="STIG",
    )
    _make_evidence(
        session,
        path="file:///c.xlsx",
        kind=EvidenceKind.XLSX,
        hosts=["h"],
        is_asset_list=True,
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)
    block = render_coverage_block(report)
    assert block is not None
    assert "MATCH: every observed host appears in scans" in block
    assert "GAP:" not in block


def test_render_truncates_at_max_hosts_with_more_marker(session):
    """Gap host lists capped at MAX_HOSTS_IN_BLOCK with ``...(+N more)``."""
    overflow = MAX_HOSTS_IN_BLOCK + 5
    hosts = [f"node{i:03d}" for i in range(overflow)]
    _make_evidence(
        session,
        path="file:///big.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=hosts,
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)
    block = render_coverage_block(report)
    assert block is not None
    # First host present, MAX_HOSTS_IN_BLOCK-th present, beyond that suffixed.
    assert "node000" in block
    assert "node024" in block  # MAX_HOSTS_IN_BLOCK is 25 → index 24 is the last rendered
    assert "node025" not in block  # first one beyond the cap
    assert f"...(+{overflow - MAX_HOSTS_IN_BLOCK} more)" in block


def test_render_gap_label_includes_count_and_description(session):
    """``GAP: <description> — N host(s)`` formatting is what the LLM sees."""
    _make_evidence(
        session,
        path="file:///scan.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["lonely"],
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)
    block = render_coverage_block(report)
    assert block is not None
    # "scanned only" gap legend phrasing — pin literal so a copy-edit
    # to render_coverage_block is a deliberate decision, not a silent drift.
    assert "GAP: scanned only (no checklist, no inventory) — 1 host(s)" in block


# ---------------------------------------------------------------------------
# Source ordering / dedup hygiene
# ---------------------------------------------------------------------------


def test_sources_sorted_by_category_then_label(session):
    """Stable ordering for the UI source list (and prompt block, indirectly)."""
    _make_evidence(
        session,
        path="file:///zzz.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["h"],
        title="ZZZ Scan",
    )
    _make_evidence(
        session,
        path="file:///aaa.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["h"],
        title="AAA Scan",
    )
    _make_evidence(
        session,
        path="file:///inv.xlsx",
        kind=EvidenceKind.XLSX,
        hosts=["h"],
        is_asset_list=True,
        asset_list_label="HW Inventory",
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)
    assert [(s.category, s.label) for s in report.sources] == [
        ("declared", "HW Inventory"),
        ("scanned", "AAA Scan"),
        ("scanned", "ZZZ Scan"),
    ]


def test_source_summary_is_a_value_type():
    """SourceSummary is frozen — accidental mutation in the route would raise."""
    s = SourceSummary(
        evidence_id=1, label="x", kind="nessus", category="scanned", host_count=0
    )
    with pytest.raises(Exception):
        s.host_count = 99  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Device-centric source-type breakdown (host_pairs reconciliation)
# ---------------------------------------------------------------------------


def test_credentialed_pair_collapses_two_ips_to_one_device(session):
    """A credentialed scan reporting two IPs for one FQDN → ONE resolved device.

    Mirrors a multi-homed / dual-NIC box: the (ip, fqdn) pairs name the same
    device twice with different IPs. ingest folds the FQDN's bare short form
    into host_inventory, so the host universe key is ``server01``; both IPs
    collapse under it. Expectation: resolved_devices == 1, distinct_ips == 0
    (the IPs are attributes of the device, not their own hosts).
    """
    _make_evidence(
        session,
        path="file:///cred-scan.nessus",
        kind=EvidenceKind.NESSUS,
        # Bare device name only — ingest does NOT add the raw IPs to the
        # host_inventory list (the IP guard would keep them whole and they'd
        # masquerade as their own hosts). The pairs carry the IP side.
        hosts=["server01"],
        title="Credentialed ACAS",
        host_pairs=[
            {"ip": "10.0.0.5", "fqdn": "server01.dom.mil"},
            {"ip": "10.0.0.6", "fqdn": "server01.dom.mil"},
        ],
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)

    assert report.resolved_devices == 1
    assert report.distinct_ips == 0
    # The device itself is the single host in the universe; the two raw IPs
    # never became their own host rows.
    assert [h.hostname for h in report.hosts] == ["server01"]


def test_uncredentialed_ip_shows_unmapped_not_conflict(session):
    """An uncredentialed scan IP with no pair → distinct (unmapped) IP, calmly.

    No (ip, fqdn) pair exists, so the scanner only knows the IP. It must show
    as a scanned IP "not yet mapped to a device" — counted in distinct_ips —
    and must NOT be promoted to a resolved device or raised as a conflict /
    needs-review. Reconciliation stays silent (no alert spam).
    """
    _make_evidence(
        session,
        path="file:///uncred-scan.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["172.20.8.86"],  # bare IP literal, no pair
        title="Uncredentialed ACAS",
        # host_pairs intentionally omitted (NULL) — uncredentialed.
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)

    assert report.distinct_ips == 1
    assert report.resolved_devices == 0
    # The IP-literal host stays in the universe (visible to the assessor) but
    # is tagged scanned_only — a normal coverage state, not a conflict bucket.
    assert [h.hostname for h in report.hosts] == ["172.20.8.86"]
    assert report.hosts[0].coverage == "scanned_only"
    # No conflict / needs-review-style gap bucket was invented for it.
    assert "conflict" not in report.gaps


def test_stig_xlsx_counts_as_checklisted_xlsx(session):
    """A DISA STIG-report .xlsx (kind STIG_CKL) → checklists_xlsx, not regular.

    xlsx.py tags STIG-report spreadsheets as STIG_CKL so they flow into the
    checklisted bucket, but provenance (the .xlsx extension) splits them out
    for the source-type breakdown. A real .ckl alongside it must land in
    checklists_regular so the two are distinguishable in the UI.
    """
    _make_evidence(
        session,
        path="file:///win2022-stig-report.xlsx",
        kind=EvidenceKind.STIG_CKL,  # shared kind; .xlsx extension = SCAP/xlsx
        hosts=["webhost"],
        title="Windows Server 2022 STIG",
    )
    _make_evidence(
        session,
        path="file:///dbhost.ckl",
        kind=EvidenceKind.STIG_CKL,
        hosts=["dbhost"],
        title="SQL Server 2019 STIG",
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)

    assert report.checklists_xlsx == 1
    assert report.checklists_regular == 1
    # Both hosts still flow through the checklisted set as before — the
    # breakdown is additive, not a re-categorization.
    assert report.checklisted_set == frozenset(
        {("unspecified", "webhost"), ("unspecified", "dbhost")}
    )


# ---------------------------------------------------------------------------
# Boundary-aware host identity — (boundary, hostname) keying
# ---------------------------------------------------------------------------


def _link_boundary(
    session: Session, *, evidence_id: int, name: str, workbook_id: int = 1
) -> None:
    """Tag an Evidence row with a named boundary via EvidenceBoundary.

    Mirrors what routes.evidence.set_evidence_boundary persists: get-or-create
    a BoundarySegment for (workbook_id, name), then link this evidence to it.
    """
    from cybersecurity_assessor.models import BoundarySegment, EvidenceBoundary

    seg = session.exec(
        select(BoundarySegment)
        .where(BoundarySegment.workbook_id == workbook_id)
        .where(BoundarySegment.name == name)
    ).first()
    if seg is None:
        seg = BoundarySegment(workbook_id=workbook_id, name=name)
        session.add(seg)
        session.flush()
    session.add(
        EvidenceBoundary(evidence_id=evidence_id, boundary_segment_id=seg.id)
    )
    session.commit()


def test_same_ip_in_two_boundaries_stays_distinct(session):
    """Reused RFC1918 IP in two CRNs must NOT collapse into one device."""
    a = _make_evidence(
        session,
        path="file:///boe/scanA.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["192.168.1.1"],
        title="CRN-A scan",
    )
    b = _make_evidence(
        session,
        path="file:///boe/scanB.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["192.168.1.1"],
        title="CRN-B scan",
    )
    _link_boundary(session, evidence_id=a.id, name="CRN-A")
    _link_boundary(session, evidence_id=b.id, name="CRN-B")

    report = summarize_asset_coverage(workbook_id=1, session=session)

    # Two DISTINCT host records — one per boundary — not one collapsed row.
    assert report.scanned_set == {
        ("CRN-A", "192.168.1.1"),
        ("CRN-B", "192.168.1.1"),
    }
    boundaries = sorted(h.boundary for h in report.hosts)
    assert boundaries == ["CRN-A", "CRN-B"]
    # Both are bare-IP, unpaired, undeclared → each is its own unmapped IP.
    assert report.distinct_ips == 2


def test_same_host_scanned_and_checklisted_one_boundary_unions(session):
    """The legitimate scan+checklist union must survive boundary keying."""
    scan = _make_evidence(
        session,
        path="file:///boe/scan.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["dc01"],
        title="scan",
    )
    ckl = _make_evidence(
        session,
        path="file:///boe/dc01.ckl",
        kind=EvidenceKind.STIG_CKL,
        hosts=["dc01"],
        title="Windows STIG",
    )
    _link_boundary(session, evidence_id=scan.id, name="CRN-A")
    _link_boundary(session, evidence_id=ckl.id, name="CRN-A")

    report = summarize_asset_coverage(workbook_id=1, session=session)

    # ONE host record — same boundary + same host unions across evidence.
    assert len(report.hosts) == 1
    rec = report.hosts[0]
    assert rec.hostname == "dc01"
    assert rec.boundary == "CRN-A"
    assert rec.scanned_in and rec.checklisted_in
    assert rec.coverage == "observed_not_declared"


def test_same_host_different_boundaries_does_not_union(session):
    """dc01 in CRN-A and dc01 in CRN-B are two devices, not one."""
    a = _make_evidence(
        session,
        path="file:///boe/a.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["dc01"],
        title="A",
    )
    b = _make_evidence(
        session,
        path="file:///boe/b.ckl",
        kind=EvidenceKind.STIG_CKL,
        hosts=["dc01"],
        title="Windows STIG",
    )
    _link_boundary(session, evidence_id=a.id, name="CRN-A")
    _link_boundary(session, evidence_id=b.id, name="CRN-B")

    report = summarize_asset_coverage(workbook_id=1, session=session)

    assert len(report.hosts) == 2
    # CRN-A dc01 is scanned-only; CRN-B dc01 is checklisted-only — they did
    # NOT merge into a "complete" host.
    covs = {(h.boundary, h.coverage) for h in report.hosts}
    assert covs == {("CRN-A", "scanned_only"), ("CRN-B", "checklisted_only")}
    # Gap labels are boundary-qualified so the two don't render identically.
    assert "CRN-A/dc01" in report.gaps.get("scanned_only", [])
    assert "CRN-B/dc01" in report.gaps.get("checklisted_only", [])


def test_boundary_inferred_from_folder_path(session):
    """A CRN folder above the NN.XX family token seeds the boundary."""
    _make_evidence(
        session,
        path="file:///boe/CRN-A/01.AC/scan.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["host9"],
        title="scan",
    )
    report = summarize_asset_coverage(workbook_id=1, session=session)
    assert report.hosts[0].boundary == "CRN-A"


def test_explicit_link_beats_folder_path(session):
    """An EvidenceBoundary link overrides a (different) folder-path token."""
    ev = _make_evidence(
        session,
        path="file:///boe/CRN-A/01.AC/scan.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["host9"],
        title="scan",
    )
    _link_boundary(session, evidence_id=ev.id, name="CRN-Z")
    report = summarize_asset_coverage(workbook_id=1, session=session)
    assert report.hosts[0].boundary == "CRN-Z"


def test_generic_folder_segment_does_not_become_boundary(session):
    """A denylisted parent (e.g. 'scans') above NN.XX yields no boundary."""
    _make_evidence(
        session,
        path="file:///boe/scans/01.AC/scan.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["host9"],
        title="scan",
    )
    report = summarize_asset_coverage(workbook_id=1, session=session)
    assert report.hosts[0].boundary == "unspecified"


def test_credentialed_pair_does_not_cross_boundary_for_ip_mapping(session):
    """A paired IP in CRN-A must not mark a bare same-IP host in CRN-B mapped."""
    paired = _make_evidence(
        session,
        path="file:///boe/credA.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["dca", "10.0.0.5"],
        title="A credentialed",
        host_pairs=[{"ip": "10.0.0.5", "fqdn": "dca.dom.mil"}],
    )
    bare = _make_evidence(
        session,
        path="file:///boe/uncredB.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["10.0.0.5"],
        title="B uncredentialed",
    )
    _link_boundary(session, evidence_id=paired.id, name="CRN-A")
    _link_boundary(session, evidence_id=bare.id, name="CRN-B")

    report = summarize_asset_coverage(workbook_id=1, session=session)

    # CRN-A: 10.0.0.5 collapses under device "dca" (paired) → not an unmapped IP.
    # CRN-B: 10.0.0.5 is bare/unpaired → it IS an unmapped IP, NOT absorbed by
    # CRN-A's pairing. So exactly one distinct unmapped IP, and dca is a device.
    assert report.distinct_ips == 1
    a_hosts = {h.hostname for h in report.hosts if h.boundary == "CRN-A"}
    b_hosts = {h.hostname for h in report.hosts if h.boundary == "CRN-B"}
    assert "dca" in a_hosts and "10.0.0.5" in a_hosts
    assert b_hosts == {"10.0.0.5"}


def test_single_boundary_report_unchanged_when_untagged(session):
    """No links + no path tokens → everything 'unspecified' (legacy behaviour)."""
    _make_evidence(
        session,
        path="file:///flat/scan.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["server01", "server02"],
        title="scan",
    )
    report = summarize_asset_coverage(workbook_id=1, session=session)
    assert all(h.boundary == "unspecified" for h in report.hosts)
    # Gap labels stay bare (no "unspecified/" prefix) so single-boundary
    # output is byte-identical to the pre-boundary report.
    assert set(report.gaps.get("scanned_only", [])) == {"server01", "server02"}


# ---------------------------------------------------------------------------
# scope_backfill: credentialed (ip, fqdn) back-fill onto an existing Asset
# ---------------------------------------------------------------------------


def test_scope_backfill_backfills_fqdn_ip_when_credentialed_row_is_later(session):
    """A later credentialed row must back-fill fqdn/ip on an Asset created by
    an earlier bare-hostname row (evidence iteration order is unspecified).

    Regression: first-writer-wins created the Asset with null fqdn/ip from the
    bare row, and the credentialed (ip, fqdn) pair from a later row silently
    vanished. The back-fill fills the null attrs in place without creating a
    second Asset.
    """
    from cybersecurity_assessor.models import Asset, Workbook
    from cybersecurity_assessor.evidence.scope_backfill import run_scope_backfill

    # scope_backfill needs a real workbook row to scope Asset/links to.
    wb = session.get(Workbook, 1)
    if wb is None:
        wb = Workbook(id=1, path="wb.xlsx", filename="wb.xlsx", baseline_id=None)
        session.add(wb)
        session.commit()

    # Earlier row: bare hostname, NO pair → would create Asset(fqdn=None, ip=None).
    _make_evidence(
        session,
        path="file:///boe/bare.ckl",
        kind=EvidenceKind.STIG_CKL,
        hosts=["dca"],
        title="Windows STIG",
    )
    # Later row: same device, credentialed (ip, fqdn) pair. Its host_inventory
    # must include the bare-host form so backfill keys the same Asset.
    _make_evidence(
        session,
        path="file:///boe/cred.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["dca"],
        title="credentialed scan",
        host_pairs=[{"ip": "10.0.0.5", "fqdn": "dca.dom.mil"}],
    )

    summary = run_scope_backfill(session)
    session.commit()

    assets = session.exec(select(Asset).where(Asset.workbook_id == 1)).all()
    dca = [a for a in assets if a.hostname == "dca"]
    # Exactly ONE Asset for the device (no duplicate), with fqdn + ip back-filled.
    assert len(dca) == 1
    assert dca[0].fqdn == "dca.dom.mil"
    assert dca[0].ip_address == "10.0.0.5"
    assert summary.assets_created == 1


def test_paired_ip_not_double_counted_in_headline(session):
    """Headline union must equal the device-centric count (no IP double-count).

    A credentialed scan reports the SAME box as both a bare IP (10.0.0.5) and a
    resolved hostname (dca). Before the fix, the headline union counted BOTH the
    IP and the hostname as separate hosts (inflated count), while the
    source-type card correctly collapsed them — so the two GUI numbers
    disagreed (the live 154-vs-86 bug). The paired IP must NOT inflate the
    headline; its device hostname supplies the count. The IP attribute row is
    still kept in report.hosts (nothing vanishes).
    """
    _make_evidence(
        session,
        path="file:///boe/cred.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["dca", "10.0.0.5"],  # scan reports device AND its IP
        title="credentialed scan",
        host_pairs=[{"ip": "10.0.0.5", "fqdn": "dca.dom.mil"}],
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)

    union = len(report.scanned_set | report.checklisted_set | report.declared_set)
    device_card = report.distinct_ips + report.resolved_devices
    # Headline and device card AGREE — the paired IP folded under its device.
    assert union == device_card
    # One device (dca), zero unmapped IPs (10.0.0.5 is paired).
    assert report.resolved_devices == 1
    assert report.distinct_ips == 0
    assert union == 1
    # The IP attribute row is preserved in the per-host list (nothing lost).
    hostnames = {h.hostname for h in report.hosts}
    assert "dca" in hostnames and "10.0.0.5" in hostnames


def test_unpaired_ip_still_counts_once(session):
    """A genuinely unpaired scanned IP (no host_pairs) must still count once.

    The dedup must NOT under-count: an uncredentialed scan IP with no resolved
    device is its own asset and belongs in the headline + distinct_ips.
    """
    _make_evidence(
        session,
        path="file:///boe/uncred.nessus",
        kind=EvidenceKind.NESSUS,
        hosts=["192.168.50.9"],  # bare IP, NO host_pairs
        title="uncredentialed scan",
    )

    report = summarize_asset_coverage(workbook_id=1, session=session)

    union = len(report.scanned_set | report.checklisted_set | report.declared_set)
    assert union == 1
    assert report.distinct_ips == 1
    assert report.resolved_devices == 0
    assert union == report.distinct_ips + report.resolved_devices
