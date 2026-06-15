"""Supersession-link writer — both policies + integration with ingest.

The :data:`Evidence.superseded_by_id` column has been respected by the
read paths (evidence_bundle, asset_crosscheck) since v0.1, but until
:mod:`evidence.supersession_tracker` landed nothing wrote it. These
tests pin both behaviors:

  * **Policy A** — same ``doc_number``, older rows lose. Covers the
    common case of uploading a new Rev of a known doc.
  * **Policy B** — legacy-phrase → current USD doc. Covers the
    nist-assessor-ported map (``engine.supersession._LEGACY_TO_CURRENT``)
    used by SDA T1 → T2 migrations.

We also cover a couple of "should NOT chain" cases because false
positives mute real evidence from the LLM bundle.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402 -- registers tables
from cybersecurity_assessor.evidence import supersession_tracker  # noqa: E402
from cybersecurity_assessor.evidence.supersession_tracker import (  # noqa: E402
    apply_supersession_at_ingest,
)
from cybersecurity_assessor.models import Evidence, EvidenceKind  # noqa: E402
from cybersecurity_assessor.models import Workbook as WorkbookModel  # noqa: E402


# ---------------------------------------------------------------------------
# Fictional synthetic registry — NO program data. Policy B reads the module
# global ``_CURRENT_TO_LEGACIES`` (built at import from the now-empty shipped
# ``engine.supersession._LEGACY_TO_CURRENT``). The shipped map is therefore
# ``{}`` and Policy B never fires in production; the ``synthetic_registry``
# fixture installs a fictional Acme map so the machinery can be exercised
# without baking program data into the suite. Mirrors the fictional entries
# used in tests/test_supersession.py.
# ---------------------------------------------------------------------------

_FAKE_CURRENT = "ACME-DOC-0010 Acme Widget Operations Plan Rev 2"
_FAKE_LEGACIES = [
    "Acme Widget Legacy Operations User Guide",
    "Acme Widget Legacy Operations Plan",
]


@pytest.fixture
def synthetic_registry(monkeypatch):
    """Install a fictional legacy→current map so Policy B can be exercised
    without program data. The shipped ``_CURRENT_TO_LEGACIES`` is empty
    (registry scrubbed)."""
    monkeypatch.setattr(
        supersession_tracker,
        "_CURRENT_TO_LEGACIES",
        {_FAKE_CURRENT: list(_FAKE_LEGACIES)},
    )
    return supersession_tracker


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


@pytest.fixture
def wb_id(session) -> int:
    """A persisted Workbook id — ingest_folder requires it (PR 2 scoping)."""
    wb = WorkbookModel(path="/tmp/supersession.xlsx", filename="supersession.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb.id


def _add(
    session: Session,
    *,
    path: str,
    title: str,
    doc_number: str | None = None,
    sha: str | None = None,
    ingested_at: datetime | None = None,
    kind: EvidenceKind = EvidenceKind.PDF,
) -> Evidence:
    """Insert + flush an Evidence row and return it with an id."""
    ev = Evidence(
        path=path,
        sha256=sha or f"sha-{path}",
        kind=kind,
        size_bytes=1,
        title=title,
        doc_number=doc_number,
    )
    if ingested_at is not None:
        ev.ingested_at = ingested_at
    session.add(ev)
    session.flush()
    return ev


# ---------------------------------------------------------------------------
# Policy A — same doc_number
# ---------------------------------------------------------------------------


def test_same_doc_number_newer_supersedes_older(session):
    """Re-uploading the same doc number retires the prior row."""
    now = datetime.now(timezone.utc)
    older = _add(
        session,
        path="file:///docs/plan_revA.pdf",
        title="Account Management Plan Rev A",
        doc_number="USD00050010",
        ingested_at=now - timedelta(days=30),
    )
    newer = _add(
        session,
        path="file:///docs/plan_revB.pdf",
        title="Account Management Plan Rev B",
        doc_number="USD00050010",
        ingested_at=now,
    )

    linked = apply_supersession_at_ingest(session, newer)

    assert linked == 1
    session.refresh(older)
    assert older.superseded_by_id == newer.id
    # Audit fields populated alongside the FK — patent-aligned: every
    # retired row carries the when/why/by-which-policy without re-deriving
    # from tracker code.
    assert older.superseded_at is not None
    assert older.superseded_policy == "same_doc_number"
    assert older.superseded_reason is not None
    assert "USD00050010" in older.superseded_reason
    # New row is current — nothing should point past it.
    session.refresh(newer)
    assert newer.superseded_by_id is None
    assert newer.superseded_at is None
    assert newer.superseded_policy is None
    assert newer.superseded_reason is None


def test_same_doc_number_chains_collapse_to_newest(session):
    """An existing one-hop chain re-targets at the new row, staying shallow."""
    now = datetime.now(timezone.utc)
    rev_a = _add(
        session,
        path="file:///docs/a.pdf",
        title="Plan Rev A",
        doc_number="USD00099999",
        ingested_at=now - timedelta(days=60),
    )
    rev_b = _add(
        session,
        path="file:///docs/b.pdf",
        title="Plan Rev B",
        doc_number="USD00099999",
        ingested_at=now - timedelta(days=30),
    )
    # Simulate the chain Policy A would have built on the Rev B ingest.
    rev_a.superseded_by_id = rev_b.id
    session.add(rev_a)
    session.flush()

    rev_c = _add(
        session,
        path="file:///docs/c.pdf",
        title="Plan Rev C",
        doc_number="USD00099999",
        ingested_at=now,
    )

    linked = apply_supersession_at_ingest(session, rev_c)

    # Both prior rows now point at Rev C — one re-pointed, one freshly linked.
    assert linked == 2
    session.refresh(rev_a)
    session.refresh(rev_b)
    assert rev_a.superseded_by_id == rev_c.id
    assert rev_b.superseded_by_id == rev_c.id
    # Both carry policy=same_doc_number; the re-pointed dependent's reason
    # names the prior chain head so a reviewer can reconstruct the hop.
    assert rev_a.superseded_policy == "same_doc_number"
    assert rev_b.superseded_policy == "same_doc_number"
    assert rev_a.superseded_at is not None
    assert rev_b.superseded_at is not None
    assert rev_a.superseded_reason is not None
    assert rev_b.superseded_reason is not None
    assert f"id={rev_b.id}" in rev_a.superseded_reason
    assert "USD00099999" in rev_b.superseded_reason


def test_same_doc_number_does_not_link_when_new_row_is_older(session):
    """Backfilling an older doc must not retire the row that already supersedes it."""
    now = datetime.now(timezone.utc)
    newer = _add(
        session,
        path="file:///docs/new.pdf",
        title="Plan Rev B",
        doc_number="USD00011111",
        ingested_at=now,
    )
    older = _add(
        session,
        path="file:///docs/old.pdf",
        title="Plan Rev A",
        doc_number="USD00011111",
        ingested_at=now - timedelta(days=10),
    )

    # Run the tracker on the OLDER row as if it had just been ingested.
    linked = apply_supersession_at_ingest(session, older)

    # The newer row must not be marked superseded by the older.
    assert linked == 0
    session.refresh(newer)
    assert newer.superseded_by_id is None


def test_empty_doc_number_does_not_chain(session):
    """Scan output / screenshots / untitled PDFs share null doc_numbers — leave alone."""
    now = datetime.now(timezone.utc)
    a = _add(
        session,
        path="file:///scans/scan1.txt",
        title="scan1",
        doc_number=None,
        ingested_at=now - timedelta(days=1),
    )
    b = _add(
        session,
        path="file:///scans/scan2.txt",
        title="scan2",
        doc_number=None,
        ingested_at=now,
    )

    linked = apply_supersession_at_ingest(session, b)

    assert linked == 0
    session.refresh(a)
    assert a.superseded_by_id is None


def test_same_doc_number_disjoint_specific_titles_do_not_link(session):
    """Shared doc_number + two specific, zero-overlap titles ⇒ no link.

    This is the body-cited citation-collision failure mode the
    identity-first resolver fixes and the title-corroboration guard
    backstops. Two genuinely-different documents that happen to carry the
    same USD number (because one *cited* the other in its body before the
    resolver fix, or any future regression) must NOT chain — linking them
    would mute real evidence from the bundle. A shared doc_number is
    necessary but, when both titles are specific, not sufficient.
    """
    now = datetime.now(timezone.utc)
    older = _add(
        session,
        path="file:///docs/firewall_acl_baseline.pdf",
        title="Firewall ACL Baseline Configuration",
        doc_number="USD00050015",
        ingested_at=now - timedelta(days=30),
    )
    newer = _add(
        session,
        path="file:///docs/account_mgmt_plan.pdf",
        title="Example System Account Management Plan",
        doc_number="USD00050015",
        ingested_at=now,
    )

    linked = apply_supersession_at_ingest(session, newer)

    # Guard contradicts the link — disjoint significant tokens.
    assert linked == 0
    session.refresh(older)
    assert older.superseded_by_id is None
    assert older.superseded_policy is None


def test_same_doc_number_links_when_titles_share_significant_token(session):
    """Shared doc_number + one overlapping significant token ⇒ still link.

    The guard only *contradicts* when both titles are specific AND share
    zero significant tokens. Boilerplate (Rev/version markers, articles)
    is stripped before measuring overlap, so two real Revs corroborate on
    their substantive tokens even when the Rev marker differs.
    """
    now = datetime.now(timezone.utc)
    older = _add(
        session,
        path="file:///docs/ssp_revc.pdf",
        title="System Security Plan Rev C",
        doc_number="USD00010083",
        ingested_at=now - timedelta(days=30),
    )
    newer = _add(
        session,
        path="file:///docs/ssp_revd.pdf",
        title="System Security Plan Rev D",
        doc_number="USD00010083",
        ingested_at=now,
    )

    linked = apply_supersession_at_ingest(session, newer)

    assert linked == 1
    session.refresh(older)
    assert older.superseded_by_id == newer.id
    assert older.superseded_policy == "same_doc_number"


def test_same_doc_number_links_when_one_title_generic(session):
    """Shared doc_number + a short/generic title ⇒ link on doc_number alone.

    When either title carries no usable signal (too short, or a generic
    blocklisted word), the guard falls back to the doc_number match — this
    preserves the common untitled / scan-output Rev-over-Rev case. "Better
    to under-link than to silently mute" cuts the other way here: the
    doc_number IS the signal.
    """
    now = datetime.now(timezone.utc)
    older = _add(
        session,
        path="file:///scans/snap0527core.txt",
        title="snap0527",  # short → not _title_is_matchable
        doc_number="USD00010084",
        ingested_at=now - timedelta(days=30),
    )
    newer = _add(
        session,
        path="file:///docs/usd00010084_ssp.pdf",
        title="USD00010084 System Security Plan Rev D",
        doc_number="USD00010084",
        ingested_at=now,
    )

    linked = apply_supersession_at_ingest(session, newer)

    assert linked == 1
    session.refresh(older)
    assert older.superseded_by_id == newer.id


# ---------------------------------------------------------------------------
# Policy B — legacy-phrase rewrites
# ---------------------------------------------------------------------------


def test_legacy_title_rewrite_chains_t1_to_t2(session, synthetic_registry):
    """Uploading the canonical current doc retires its legacy-titled artifacts.

    Exercised against the fictional Acme map installed by
    ``synthetic_registry`` — the shipped registry is scrubbed empty, so
    Policy B is otherwise a no-op (see
    ``test_legacy_title_rewrite_noop_when_registry_empty``).
    """
    now = datetime.now(timezone.utc)
    # Two legacy artifacts under different titles, both registered to the
    # same current doc in the fictional map.
    legacy_guide = _add(
        session,
        path="file:///sp/legacy_ops_user_guide.pdf",
        title="Acme Widget Legacy Operations User Guide",
        doc_number=None,
        ingested_at=now - timedelta(days=90),
    )
    legacy_plan = _add(
        session,
        path="file:///sp/legacy_ops_plan.pdf",
        title="Acme Widget Legacy Operations Plan",
        doc_number=None,
        ingested_at=now - timedelta(days=90),
    )
    # Newly ingested canonical current doc.
    current = _add(
        session,
        path="file:///sp/acme_doc_0010_ops_plan.pdf",
        title="ACME-DOC-0010 Acme Widget Operations Plan Rev 2",
        doc_number="ACME-DOC-0010",
        ingested_at=now,
    )

    linked = apply_supersession_at_ingest(session, current)

    # Both legacy rows retired.
    assert linked == 2
    session.refresh(legacy_guide)
    session.refresh(legacy_plan)
    assert legacy_guide.superseded_by_id == current.id
    assert legacy_plan.superseded_by_id == current.id
    # Audit fields populated; reason names the exact legacy phrase that
    # tripped Policy B so the chain is self-explaining.
    assert legacy_guide.superseded_policy == "legacy_title_rewrite"
    assert legacy_plan.superseded_policy == "legacy_title_rewrite"
    assert legacy_guide.superseded_at is not None
    assert legacy_plan.superseded_at is not None
    assert legacy_guide.superseded_reason is not None
    assert legacy_plan.superseded_reason is not None
    assert "legacy phrase" in legacy_guide.superseded_reason.lower()
    assert "legacy phrase" in legacy_plan.superseded_reason.lower()


def test_legacy_rewrite_skips_already_superseded(session, synthetic_registry):
    """Already-superseded rows are left alone — prior decision wins."""
    now = datetime.now(timezone.utc)
    legacy = _add(
        session,
        path="file:///sp/legacy_ops_plan.pdf",
        title="Acme Widget Legacy Operations Plan",
        doc_number=None,
        ingested_at=now - timedelta(days=120),
    )
    decoy_target = _add(
        session,
        path="file:///sp/decoy.pdf",
        title="some other doc",
        doc_number=None,
        ingested_at=now - timedelta(days=60),
    )
    # Pretend the user manually linked legacy → decoy already.
    legacy.superseded_by_id = decoy_target.id
    session.add(legacy)
    session.flush()

    current = _add(
        session,
        path="file:///sp/acme_doc_0010_ops_plan.pdf",
        title="ACME-DOC-0010 Acme Widget Operations Plan Rev 2",
        doc_number="ACME-DOC-0010",
        ingested_at=now,
    )

    linked = apply_supersession_at_ingest(session, current)

    # No legacy link rewritten — the policy filter excludes non-null
    # superseded_by_id rows. (We may still link other things, so don't
    # assert ==0 on linked.)
    session.refresh(legacy)
    assert legacy.superseded_by_id == decoy_target.id


def test_legacy_title_rewrite_noop_when_registry_empty(session):
    """With the shipped (scrubbed) registry, Policy B never fires.

    No ``synthetic_registry`` fixture here — this exercises the real
    module-level ``_CURRENT_TO_LEGACIES`` (built at import from the empty
    shipped ``_LEGACY_TO_CURRENT``), so the legacy-titled row must survive
    untouched even though its title would match a fictional entry.
    """
    now = datetime.now(timezone.utc)
    legacy = _add(
        session,
        path="file:///sp/legacy_ops_plan.pdf",
        title="Acme Widget Legacy Operations Plan",
        doc_number=None,
        ingested_at=now - timedelta(days=90),
    )
    current = _add(
        session,
        path="file:///sp/acme_doc_0010_ops_plan.pdf",
        title="ACME-DOC-0010 Acme Widget Operations Plan Rev 2",
        doc_number="ACME-DOC-0010",
        ingested_at=now,
    )

    # Empty registry ⇒ Policy B finds no legacies ⇒ no link.
    assert apply_supersession_at_ingest(session, current) == 0
    session.refresh(legacy)
    assert legacy.superseded_by_id is None
    assert legacy.superseded_policy is None


def test_unrelated_titles_are_not_linked(session):
    """A new USD doc must not silently retire random PDFs in the folder."""
    now = datetime.now(timezone.utc)
    bystander = _add(
        session,
        path="file:///sp/firewall_acl.pdf",
        title="Firewall ACL Baseline",
        doc_number=None,
        ingested_at=now - timedelta(days=30),
    )
    current = _add(
        session,
        path="file:///sp/usd00050010.pdf",
        title="USD00050010 Example System Account Management Plan Rev -",
        doc_number="USD00050010",
        ingested_at=now,
    )

    linked = apply_supersession_at_ingest(session, current)

    assert linked == 0
    session.refresh(bystander)
    assert bystander.superseded_by_id is None


def test_apply_returns_zero_when_id_missing(session):
    """Calling before flush is a programmer error; tracker logs and returns 0."""
    floating = Evidence(
        path="file:///nowhere.pdf",
        sha256="sha-floating",
        kind=EvidenceKind.PDF,
        size_bytes=1,
        title="Something",
        doc_number="USD00050010",
    )
    # Deliberately not adding/flushing → id is None.
    assert apply_supersession_at_ingest(session, floating) == 0


# ---------------------------------------------------------------------------
# End-to-end through ingest_folder
# ---------------------------------------------------------------------------


def test_ingest_summary_reports_superseded_links(
    session, wb_id, tmp_path, synthetic_registry
):
    """A real ingest run populates ``IngestSummary.superseded_links``.

    Exercised against the fictional Acme map (``synthetic_registry``) —
    the shipped registry is scrubbed empty, so without the fixture Policy
    B contributes nothing and ``superseded_links`` would be 0.
    """
    from cybersecurity_assessor.evidence.ingest import ingest_folder

    # Pre-populate a legacy doc as if a prior ingest had picked it up.
    # Scoped to the same workbook so the supersession matcher sees it.
    legacy = Evidence(
        path="file:///prior/legacy_ops_plan.pdf",
        sha256="sha-legacy",
        kind=EvidenceKind.PDF,
        size_bytes=1,
        title="Acme Widget Legacy Operations Plan",
        workbook_id=wb_id,
    )
    session.add(legacy)
    session.commit()

    # Drop a plain text file whose title (== stem) matches the canonical
    # current string. The text extractor will pick up the stem as title;
    # we set the contents to something benign.
    target = tmp_path / "ACME-DOC-0010 Acme Widget Operations Plan Rev 2.txt"
    target.write_text("Operations Plan body", encoding="utf-8")

    summary = ingest_folder(session, tmp_path, workbook_id=wb_id)

    assert summary.ingested == 1
    assert summary.superseded_links == 1

    # Legacy row is now chained to the freshly-ingested one.
    session.refresh(legacy)
    assert legacy.superseded_by_id is not None
    # And the as_dict serializer surfaces the counter for the route layer.
    assert summary.as_dict()["superseded_links"] == 1
