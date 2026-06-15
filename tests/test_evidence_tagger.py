"""Tagger tests — doc-number + CCI-direct heuristics.

Uses an in-memory SQLite engine so we can seed a tiny Framework/Control/
Objective catalog without touching ``~/.cybersecurity-assessor/ccis.sqlite``. The
tagger only calls ``session.add`` — the test is responsible for the
commit boundary, which matches how the ingest orchestrator wraps it.

The family-keyword heuristic was removed 2026-06-04 (it over-fired ~600
tags per family match, see tagger.py docstring); its tests moved to the
"prose without high-signal refs yields zero tags" assertion below.
"""

from __future__ import annotations

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from cybersecurity_assessor.evidence.extractors._stig_common import StigFindingRow
from cybersecurity_assessor.evidence.tagger import tag_evidence
from cybersecurity_assessor.models import (
    Control,
    Evidence,
    EvidenceKind,
    EvidenceTag,
    FindingStatus,
    Framework,
    Objective,
)


# ---------------------------------------------------------------------------
# Catalog fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def session() -> Session:
    """In-memory SQLite session seeded with a tiny catalog.

    Layout:
      Framework "NIST SP 800-53 Rev 5"
        Control AC-2  (family=AC)
          Objective CCI-000015  (guidance cites USD00050010)
          Objective CCI-000017  (no doc, no family keyword bait)
        Control AU-2  (family=AU)
          Objective CCI-000130  (procedures cite USD-22222 — short form)
        Control CM-6  (family=CM)
          Objective CCI-000366
    """
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    s = Session(engine)

    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    s.add(fw)
    s.flush()

    # OSCAL loader writes control_id in catalog form: lowercase, dot-notation
    # for enhancements ("ac-2", "ac-2.1"). Tests must seed in the same form
    # or the tagger's IN lookup misses (see _normalize_control_id).
    ac2 = Control(framework_id=fw.id, control_id="ac-2", title="Account Management", family="AC")
    au2 = Control(framework_id=fw.id, control_id="au-2", title="Audit Events", family="AU")
    cm6 = Control(framework_id=fw.id, control_id="cm-6", title="Configuration Settings", family="CM")
    s.add_all([ac2, au2, cm6])
    s.flush()

    s.add_all(
        [
            Objective(
                control_id_fk=ac2.id,
                objective_id="CCI-000015",
                text="Employ automated mechanisms to support account management.",
                implementation_guidance="Local IdAM tooling per USD00050010.",
                assessment_procedures="Examine config; verify automation.",
            ),
            Objective(
                control_id_fk=ac2.id,
                objective_id="CCI-000017",
                text="Notify account managers of account changes.",
            ),
            Objective(
                control_id_fk=au2.id,
                objective_id="CCI-000130",
                text="Generate audit records.",
                assessment_procedures="Confirm logging per USD-22222.",
            ),
            Objective(
                control_id_fk=cm6.id,
                objective_id="CCI-000366",
                text="Implement configuration settings.",
            ),
        ]
    )
    s.commit()
    yield s
    s.close()


def _make_evidence(s: Session, **overrides) -> Evidence:
    defaults = dict(
        path="C:/fake/doc.pdf",
        sha256="deadbeef",
        kind=EvidenceKind.PDF,
        size_bytes=100,
        title="Doc",
        doc_number=None,
    )
    defaults.update(overrides)
    e = Evidence(**defaults)
    s.add(e)
    s.flush()
    return e


# ---------------------------------------------------------------------------
# Doc-number heuristic
# ---------------------------------------------------------------------------


def test_tagger_links_doc_number_to_objective_guidance(session):
    e = _make_evidence(session, doc_number="USD00050010")
    result = tag_evidence(session, e, text="Account mgmt baseline per USD00050010.")
    assert result.doc_number_hits >= 1
    tags = session.exec(select(EvidenceTag).where(EvidenceTag.evidence_id == e.id)).all()
    # CCI-000015 should be tagged (guidance cites USD00050010)
    obj_ids = {t.objective_id for t in tags}
    cci15 = session.exec(select(Objective).where(Objective.objective_id == "CCI-000015")).one()
    assert cci15.id in obj_ids
    doc_tag = next(t for t in tags if t.objective_id == cci15.id)
    assert doc_tag.confidence == 0.9
    assert "USD00050010" in doc_tag.rationale


def test_tagger_matches_short_form_doc_number(session):
    """Objective stores 'USD-22222' (short); evidence has canonical 'USD00022222'."""
    e = _make_evidence(session, doc_number="USD00022222")
    result = tag_evidence(session, e, text="")
    assert result.doc_number_hits >= 1
    cci130 = session.exec(select(Objective).where(Objective.objective_id == "CCI-000130")).one()
    tags = session.exec(select(EvidenceTag).where(EvidenceTag.evidence_id == e.id)).all()
    assert cci130.id in {t.objective_id for t in tags}


def test_tagger_finds_extra_doc_numbers_in_body_text(session):
    """Evidence doc_number is None, but body text mentions USD00050010."""
    e = _make_evidence(session, doc_number=None)
    tag_evidence(session, e, text="Cross-ref to USD-50010 (account mgmt baseline).")
    cci15 = session.exec(select(Objective).where(Objective.objective_id == "CCI-000015")).one()
    tags = session.exec(select(EvidenceTag).where(EvidenceTag.evidence_id == e.id)).all()
    assert cci15.id in {t.objective_id for t in tags}


# ---------------------------------------------------------------------------
# CCI direct ref
# ---------------------------------------------------------------------------


def test_tagger_links_cci_from_stig_finding(session):
    e = _make_evidence(session, kind=EvidenceKind.STIG_CKL)
    finding = StigFindingRow(
        rule_id="SV-1",
        rule_version="WN11-AU-000010",
        cci_refs="CCI-000366",
        severity="medium",
        status=FindingStatus.OPEN,
    )
    result = tag_evidence(session, e, text="", stig_findings=[finding])
    assert result.cci_hits >= 1
    cci366 = session.exec(select(Objective).where(Objective.objective_id == "CCI-000366")).one()
    tags = session.exec(select(EvidenceTag).where(EvidenceTag.evidence_id == e.id)).all()
    cci_tag = next(t for t in tags if t.objective_id == cci366.id)
    assert cci_tag.confidence == 0.95  # CCI ref is highest confidence


def test_tagger_links_cci_scraped_from_body(session):
    # Tier 2's inline-CCI text scrape only fires for structured STIG/Nessus
    # kinds (2026-06-07 gate) — the narrative-text fallback for a CKL whose
    # extractor missed a CCI inside finding_details free-text. A plain policy
    # PDF that merely quotes a CCI no longer earns a 0.95 tag.
    e = _make_evidence(session, kind=EvidenceKind.STIG_CKL)
    tag_evidence(session, e, text="STIG check fires on CCI-000366 per guidance.")
    cci366 = session.exec(select(Objective).where(Objective.objective_id == "CCI-000366")).one()
    tags = session.exec(select(EvidenceTag).where(EvidenceTag.evidence_id == e.id)).all()
    assert cci366.id in {t.objective_id for t in tags}


# ---------------------------------------------------------------------------
# Negative-recall (no high-signal refs → no tags)
# ---------------------------------------------------------------------------


def test_tagger_yields_no_tags_when_no_doc_or_cci_or_control_id_present(session):
    """Prose with no USD, no CCI, and no control-ID token gets nothing.

    Pre-2026-06-04 this produced ~600 family-keyword tags per match.
    Post-Tier 3 (added the same day), a control-ID token *would* now
    tag the matching control's children; this test confirms that
    plain prose without any of the three signals stays empty.
    """
    e = _make_evidence(session)
    tag_evidence(session, e, text="Baseline configuration enforced via GPO. See policy.")
    tags = session.exec(select(EvidenceTag).where(EvidenceTag.evidence_id == e.id)).all()
    assert tags == []


# ---------------------------------------------------------------------------
# Control-ID-in-text (Tier 3) — bounded replacement for family-keyword path
# ---------------------------------------------------------------------------


def test_tagger_links_control_id_from_text(session):
    """Text mentions AC-2 → tag EVERY child Objective of AC-2 at conf 0.5.

    The 2026-06-07 "Tier 3 spray" fix tagged only the Control's primary CCI
    (lowest objective_id) on the assumption the LLM bundler groups evidence
    per Control. That bundler was never shipped — the assess loop runs
    per-CCI and each per-CCI bundle queries ``WHERE objective_id == <one
    CCI>``, so primary-CCI-only tagging starved every sibling CCI. REVERTED
    2026-06-10: a control mention now fans out to EVERY child CCI of AC-2
    (both CCI-000015 and CCI-000017). Must still NOT spill over into AU-2 or
    CM-6 (different controls, different families) — that was the
    family-keyword broadcast bug.
    """
    e = _make_evidence(session)
    tag_evidence(session, e, text="This policy enforces the AC-2 baseline across all hosts.")

    ac2_primary_cci = "CCI-000015"  # lowest objective_id under AC-2
    ac2_sibling_cci = "CCI-000017"  # now ALSO tagged — full child fan-out
    au2_cci = "CCI-000130"
    cm6_cci = "CCI-000366"

    tags = session.exec(select(EvidenceTag).where(EvidenceTag.evidence_id == e.id)).all()
    tagged_obj_ids = {t.objective_id for t in tags}
    obj_id_to_label = {
        o.id: o.objective_id
        for o in session.exec(select(Objective)).all()
    }
    tagged_labels = {obj_id_to_label[oid] for oid in tagged_obj_ids}

    assert ac2_primary_cci in tagged_labels, f"expected AC-2 primary, got {tagged_labels}"
    assert ac2_sibling_cci in tagged_labels, "every AC-2 child is tagged (full fan-out)"
    assert au2_cci not in tagged_labels, "AU-2 must not be tagged from an AC-2 mention"
    assert cm6_cci not in tagged_labels, "CM-6 must not be tagged from an AC-2 mention"

    # Confidence is the medium 0.5 — lower than CCI/doc-number paths.
    for t in tags:
        if obj_id_to_label[t.objective_id] in (ac2_primary_cci, ac2_sibling_cci):
            assert t.confidence == 0.5
            assert "AC-2" in t.rationale


def test_tagger_links_control_id_from_body_not_filename(session):
    """Tier 3 is text-only — filename control IDs are ignored (2026-06-07).

    Scanning ``evidence.path`` was a rename attack surface: a deck named
    ``AC-2_RA-5_SC-7_kitchen_sink.pdf`` could harvest tags for controls it
    never discussed. The body must mention the control ID; a real mention
    fans out to EVERY child CCI of the Control (full fan-out, reverted
    2026-06-10).
    """
    # Filename carries the control ID but the body does NOT — expect zero tags.
    e_path_only = _make_evidence(
        session,
        path="C:/fake/policies/AC-2_account_management_policy.pdf",
    )
    tag_evidence(session, e_path_only, text="")
    path_only_tags = session.exec(
        select(EvidenceTag).where(EvidenceTag.evidence_id == e_path_only.id)
    ).all()
    assert path_only_tags == [], "filename alone must not produce tags"

    # Body mentions the control ID — every AC-2 child CCI gets tagged.
    e_body = _make_evidence(session, path="C:/fake/policies/generic.pdf")
    tag_evidence(session, e_body, text="This document implements the AC-2 control.")

    cci15 = session.exec(select(Objective).where(Objective.objective_id == "CCI-000015")).one()
    cci17 = session.exec(select(Objective).where(Objective.objective_id == "CCI-000017")).one()
    tags = session.exec(select(EvidenceTag).where(EvidenceTag.evidence_id == e_body.id)).all()
    tagged_obj_ids = {t.objective_id for t in tags}

    assert cci15.id in tagged_obj_ids  # primary CCI of AC-2
    assert cci17.id in tagged_obj_ids  # sibling ALSO tagged (full fan-out)


def test_tagger_control_id_does_not_double_count_with_cci(session):
    """Same objective hit by both Tier 2 (CCI) and Tier 3 (control-ID) → one row.

    The higher-confidence Tier 2 wins because _add() de-dupes on
    objective_id and Tier 2 runs first. CCI-000015 belongs to AC-2, so
    a text containing both ``CCI-000015`` and ``AC-2`` would otherwise
    create two EvidenceTag rows for the same (evidence, objective) pair.
    """
    # Tier 2's inline-CCI scrape is gated to structured kinds (2026-06-07),
    # so use a CKL to let the CCI-000015 token earn its 0.95 tag first; the
    # later AC-2 Tier 3 hit then de-dupes on the same objective.
    e = _make_evidence(session, kind=EvidenceKind.STIG_CKL)
    tag_evidence(session, e, text="Per CCI-000015 and the AC-2 family baseline.")

    cci15 = session.exec(select(Objective).where(Objective.objective_id == "CCI-000015")).one()
    cci15_tags = session.exec(
        select(EvidenceTag)
        .where(EvidenceTag.evidence_id == e.id)
        .where(EvidenceTag.objective_id == cci15.id)
    ).all()
    assert len(cci15_tags) == 1
    assert cci15_tags[0].confidence == 0.95  # Tier 2 (CCI) wins, not Tier 3 (0.5)


# ---------------------------------------------------------------------------
# Idempotence
# ---------------------------------------------------------------------------


def test_tagger_does_not_create_duplicate_tags(session):
    e = _make_evidence(session, doc_number="USD00050010")
    tag_evidence(session, e, text="USD00050010")
    first = session.exec(select(EvidenceTag).where(EvidenceTag.evidence_id == e.id)).all()
    tag_evidence(session, e, text="USD00050010")  # re-run
    second = session.exec(select(EvidenceTag).where(EvidenceTag.evidence_id == e.id)).all()
    assert len(first) == len(second)


def test_tagger_requires_persisted_evidence(session):
    e = Evidence(
        path="C:/fake/x.pdf", sha256="x", kind=EvidenceKind.PDF, size_bytes=1
    )
    # e.id is None — must reject
    with pytest.raises(ValueError):
        tag_evidence(session, e, text="anything")
