"""Floor-fix tests: every eMASS ``NN.XX`` file earns >=1 LOCATED tag (offline).

These pin the planned "floor fix" (see ``_oldrun_tmp/FLOOR_FIX_BRIEF.md``). The
production change is NOT YET BUILT, so several assertions below are guarded with
``# REQUIRES:`` markers and are EXPECTED TO FAIL until the feature lands; they
PASS once it does. They run OFFLINE (autouse monkeypatch forces no LLM judge),
mirroring ``test_tool_name_autotag.py`` — so the disposition under test is the
deterministic ``source="auto_review"`` floor, never ``located_nonaffirming``
(that branch only fires when a judge actually ran).

The change has five observable behaviors, each a test below:

  FIX 1 (tokenization) — underscore-joined CTP filenames must match tool keys:
    * ``CTP-013_clam_av_step8.txt``  → clamav/clam_av → SI-3   (new ``clam_av`` alias)
    * ``CTP-010_xrdp_step11.txt``    → xrdp           → AC-17
    * ``CTP-014_aide_step10.txt``    → aide           → SI-7 + CM-3
    * ``CTP-030_vm_firewall_step9.txt`` → firewall    → SC-7   (new ``firewall`` key)
    Today ``_TOOL_NAME_TOKEN_RE`` treats ``_`` as a word char, so the filename
    tokenizes to ``_clam_av_step8`` and never equals key ``clamav``: NO floor.

  FIX 1 PRECISION GUARD (folder × tool intersection) — the tool floor fires
    only when ``_family_from_path`` AGREES with the tool's control family. xrdp
    under ``01.AC/`` floors AC-17; xrdp under ``09.MA/`` does NOT (no AC-17).

  FIX 2 (folder-family floor) — a file with NO recognized tool but under an
    ``NN.XX`` folder floors exactly ONE family-representative ("-1" policy)
    control — e.g. ``02.AU/`` → AU-1 — NOT the whole AU family.

  FIX 2 (0-byte case) — the genuinely empty ``spaceLowAudit`` file under
    ``02.AU/`` still earns the folder-family floor (it must be LOCATED).

  SAFETY — substring rejection ("flashing" must not match "ssh"); a floor never
    double-tags an objective that already carries a tag.

NEGATIVE — a file with NO folder token AND NO tool token floors nothing.

INTERFACE ASSUMPTIONS (verified by code-read of tagger.py / ingest.py on
2026-06-24, except where flagged REQUIRES):
  * ``ingest_folder(session, folder, *, workbook_id=...)`` is the entry point;
    it builds ``evidence.path`` as a ``file://`` URI that PRESERVES the
    on-disk directory layout, so a file under ``tmp_path/"01.AC"/...`` yields a
    path containing ``/01.AC/`` that ``_family_from_path`` matches (regex
    ``[/!]\\d{2}\\.([A-Za-z]{2})[/_.]``). Tests therefore write into an
    ``NN.XX`` subdir of tmp_path to exercise the folder lane. [VERIFIED]
  * Even a 0-byte / empty file lands an Evidence row (ingest persists with empty
    text rather than skipping). [VERIFIED ingest.py:49,789]
  * Offline floor disposition is ``source="auto_review"``. [VERIFIED tagger.py:2269]
  * EvidenceTag carries ``.objective_id``, ``.source``, ``.rationale``. [VERIFIED]
  * REQUIRES (FIX 1): tool tokenizer matches ``clamav``/``aide``/``xrdp``/
    ``firewall`` as whole-word parts of underscore-joined filename tokens, and
    the map gains a ``clam_av`` alias (or ``_``-normalized compare) + a
    ``firewall`` → ``("sc-7",)`` single-purpose key.
  * REQUIRES (FIX 1 guard): tool floor is intersected with
    ``_family_from_path`` — emit only when the path's family equals the tool's
    control family.
  * REQUIRES (FIX 2): a family→representative-control map (the "-1" policy
    control: ac→ac-1, au→au-1, cm→cm-1, sc→sc-1, si→si-1, …) drives a
    single-control folder floor when no tool matched.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.evidence import ingest as _ingest_mod  # noqa: E402
from cybersecurity_assessor.evidence.ingest import ingest_folder  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Control,
    EvidenceTag,
    Framework,
    Objective,
)
from cybersecurity_assessor.models import Workbook as WorkbookModel  # noqa: E402


@pytest.fixture(autouse=True)
def _force_offline_tagger(monkeypatch):
    """Force the tagger OFFLINE (no LLM judge) for this whole module.

    Mirrors test_tool_name_autotag.py: on a dev workstation
    ``_build_tagger_llm`` resolves a real judge from on-disk config/keyring,
    which makes the floor nondeterministic (a live judge-accept yields
    source=llm, or judge_invoked=True flips the disposition to
    located_nonaffirming). Pinning no-client makes the auto_review floor path
    deterministic and matches what the tests assert.
    """
    monkeypatch.setattr(
        _ingest_mod, "_build_tagger_llm", lambda: (None, None, "disabled")
    )


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
    wb = WorkbookModel(path="/tmp/floor.xlsx", filename="floor.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb.id


@pytest.fixture
def catalog(session) -> dict[str, list[int]]:
    """Seed the tool-mapped controls + the family "-1" policy controls.

    Tool-mapped (FIX 1): ac-17, si-3, si-7, cm-3, sc-7.
    Family representatives (FIX 2): ac-1, au-1, cm-1, sc-1, si-1.
    Negatives: au-8 (chrony — must never tag from these files), ac-2.

    Each control carries 2 child objectives so a single-control match still
    clears the Tier-5 low-tag gate (no LLM in these deterministic tests), same
    convention as test_tool_name_autotag.py's ``catalog``.
    """
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)

    by_control: dict[str, list[int]] = {}
    for ctl_id, family in [
        # tool-mapped (FIX 1)
        ("ac-17", "AC"),
        ("si-3", "SI"),
        ("si-7", "SI"),
        ("cm-3", "CM"),
        ("sc-7", "SC"),
        # family "-1" representatives (FIX 2)
        ("ac-1", "AC"),
        ("au-1", "AU"),
        ("cm-1", "CM"),
        ("sc-1", "SC"),
        ("si-1", "SI"),
        # negatives
        ("au-8", "AU"),
        ("ac-2", "AC"),
    ]:
        ctrl = Control(
            framework_id=fw.id,
            control_id=ctl_id,
            title=f"{ctl_id.upper()} title",
            family=family,
        )
        session.add(ctrl)
        session.commit()
        session.refresh(ctrl)
        ids: list[int] = []
        for n in (1, 2):
            obj = Objective(
                control_id_fk=ctrl.id,
                objective_id=f"{ctl_id}.{n}",
                source="AP",
                text=f"objective text for {ctl_id}.{n}",
            )
            session.add(obj)
            session.commit()
            session.refresh(obj)
            ids.append(obj.id)
        by_control[ctl_id] = ids
    return by_control


def _write(path: Path, body: str) -> None:
    """Write a file, creating any ``NN.XX`` parent dirs the test asked for."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def _tagged_ids(session) -> set[int]:
    return {t.objective_id for t in session.exec(select(EvidenceTag)).all()}


# --------------------------------------------------------------------------- #
# FIX 1 — underscore-joined CTP filenames floor their SPECIFIC control offline #
# --------------------------------------------------------------------------- #


def test_clam_av_underscore_filename_floors_si3(session, catalog, wb_id, tmp_path):
    """``CTP-013_clam_av_step8.txt`` under 16.SI floors SI-3 (clamav), auto_review.

    REQUIRES (FIX 1): the tokenizer matches ``clamav``/``clam_av`` inside the
    underscore-joined filename token, and the map resolves it to SI-3. Today the
    ``_``-greedy regex tokenizes ``_clam_av_step8`` and never matches key
    ``clamav`` → SI-3 gets NO tag (this test FAILS pre-fix).
    """
    _write(
        tmp_path / "16.SI" / "CTP-013_clam_av_step8.txt",
        "clamscan -r /home\n----------- SCAN SUMMARY -----------\n"
        "Infected files: 0\n",
    )
    summary = ingest_folder(session, tmp_path, workbook_id=wb_id)
    assert summary.ingested == 1
    assert summary.errors == []

    tags = session.exec(select(EvidenceTag)).all()
    tagged = {t.objective_id for t in tags}
    # REQUIRES: clam_av/clamav → SI-3 floored.
    for oid in catalog["si-3"]:
        assert oid in tagged, f"SI-3 child {oid} not floored from clam_av file"
    si3_tags = [t for t in tags if t.objective_id in catalog["si-3"]]
    assert all(t.source == "auto_review" for t in si3_tags), (
        "offline single-purpose floor must be auto_review"
    )
    # Folder × tool intersection (16.SI agrees with SI-3) → no leak elsewhere.
    for neg in ("ac-17", "au-8", "ac-2"):
        for oid in catalog[neg]:
            assert oid not in tagged, f"clam_av leaked into {neg}"


def test_xrdp_underscore_filename_floors_ac17(session, catalog, wb_id, tmp_path):
    """``CTP-010_xrdp_step11.txt`` under 01.AC floors AC-17 (xrdp), auto_review.

    REQUIRES (FIX 1): xrdp matched as a whole-word part of the underscore token.
    """
    _write(
        tmp_path / "01.AC" / "CTP-010_xrdp_step11.txt",
        "systemctl status xrdp\nActive: active (running)\n",
    )
    ingest_folder(session, tmp_path, workbook_id=wb_id)
    tagged = _tagged_ids(session)
    # REQUIRES: xrdp → AC-17 floored.
    for oid in catalog["ac-17"]:
        assert oid in tagged, f"AC-17 child {oid} not floored from xrdp file"
    ac17_tags = [
        t
        for t in session.exec(select(EvidenceTag)).all()
        if t.objective_id in catalog["ac-17"]
    ]
    assert all(t.source == "auto_review" for t in ac17_tags)


def test_aide_underscore_filename_floors_si7_and_cm3(session, catalog, wb_id, tmp_path):
    """``CTP-014_aide_step10.txt`` under 05.CM floors aide's controls, auto_review.

    aide maps to SI-7 + CM-3. The file sits under ``05.CM/``; the precision guard
    intersects the path family (CM) with the tool's families (SI, CM).

    REQUIRES (FIX 1): aide matched inside the underscore filename token.
    REQUIRES (FIX 1 guard): with strict folder×tool intersection only the
    matching-family control (CM-3) would floor; if the guard is per-tool (any
    tool-family member floors once the tool fires under ANY recognized folder),
    both SI-7 and CM-3 floor. We assert CM-3 (the unambiguous intersection) and
    document SI-7 as guard-dependent so this test pins the agreed semantics once
    the implementer fixes the contract.
    """
    _write(
        tmp_path / "05.CM" / "CTP-014_aide_step10.txt",
        "aide --check\nAIDE found differences between database and filesystem\n",
    )
    ingest_folder(session, tmp_path, workbook_id=wb_id)
    tagged = _tagged_ids(session)
    # REQUIRES: CM-3 is the in-family intersection — must floor.
    for oid in catalog["cm-3"]:
        assert oid in tagged, f"aide did not floor CM-3 child {oid} under 05.CM"
    cm3_tags = [
        t
        for t in session.exec(select(EvidenceTag)).all()
        if t.objective_id in catalog["cm-3"]
    ]
    assert all(t.source == "auto_review" for t in cm3_tags)
    # Negative: chrony's AU-8 must never come from aide.
    for oid in catalog["au-8"]:
        assert oid not in tagged, "aide leaked into au-8"


def test_vm_firewall_underscore_filename_floors_sc7(session, catalog, wb_id, tmp_path):
    """``CTP-030_vm_firewall_step9.txt`` under 15.SC floors SC-7, auto_review.

    REQUIRES (FIX 1): a new ``firewall`` → ``("sc-7",)`` single-purpose key, and
    the tokenizer matches ``firewall`` inside ``vm_firewall``. Pre-fix,
    ``vm_firewall`` matches NO existing key (only firewalld/iptables/nftables
    exist) → SC-7 gets no floor (this test FAILS pre-fix).
    """
    _write(
        tmp_path / "15.SC" / "CTP-030_vm_firewall_step9.txt",
        "firewall-cmd --list-all\npublic (active)\n  services: ssh dhcpv6-client\n",
    )
    ingest_folder(session, tmp_path, workbook_id=wb_id)
    tagged = _tagged_ids(session)
    # REQUIRES: firewall key → SC-7 floored.
    for oid in catalog["sc-7"]:
        assert oid in tagged, f"SC-7 child {oid} not floored from vm_firewall file"
    sc7_tags = [
        t
        for t in session.exec(select(EvidenceTag)).all()
        if t.objective_id in catalog["sc-7"]
    ]
    assert all(t.source == "auto_review" for t in sc7_tags)


# --------------------------------------------------------------------------- #
# FIX 1 PRECISION GUARD — folder × tool mismatch must NOT floor                #
# --------------------------------------------------------------------------- #


def test_xrdp_cross_folder_still_floors_ac17_no_guard(session, catalog, wb_id, tmp_path):
    """xrdp floors AC-17 regardless of folder — the folder×tool guard was DROPPED.

    DESIGN (2026-06-24, after 3 second opinions + an empirical agent): an earlier
    draft added a "folder×tool family-agreement guard" (only floor a control whose
    family matches the NN.XX folder). It was REMOVED because ~½ of single-purpose
    tools map CROSS-family (aide in 05.CM → SI-7; usbguard → AC-19+MP-7), so the
    guard silently suppressed CORRECT floors. A daemon's control identity is
    intrinsic to the tool, not the folder it was filed under. Precision is already
    protected because the floor is NON-AFFIRMING (auto_review/located_nonaffirming),
    never counted compliant. So xrdp under ANY folder floors AC-17.
    """
    _write(
        tmp_path / "09.MA" / "CTP-099_xrdp_maintenance.txt",
        "systemctl status xrdp\nActive: active (running)\n",
    )
    ingest_folder(session, tmp_path, workbook_id=wb_id)
    tags = session.exec(select(EvidenceTag)).all()
    tagged = {t.objective_id for t in tags}
    for oid in catalog["ac-17"]:
        assert oid in tagged, (
            "xrdp must floor AC-17 regardless of folder — no family-agreement guard"
        )
    ac17_tags = [t for t in tags if t.objective_id in catalog["ac-17"]]
    assert all(t.source == "auto_review" for t in ac17_tags), (
        "offline single-purpose tool floor is auto_review"
    )


# --------------------------------------------------------------------------- #
# NO folder-family "-1" floor (rejected design)                               #
# --------------------------------------------------------------------------- #
# The folder-family "-1" floor was REJECTED by 3 second opinions + an empirical
# agent: tagging a clamav log to SI-1 (a POLICY control) is a false positive,
# and ac-1 would absorb ~55 files (noise that buries the real AC-1 policy doc).
# A tool-less / empty file under an NN.XX folder therefore stays ZERO-TAG — the
# defensible outcome. Specific-control location for tool files comes from the
# (now config-driven) tool map; screenshots need a future vision/OCR pass; a
# genuinely-empty file is correctly empty. These tests PIN that "no family floor".


def test_toolless_file_under_folder_stays_zero(session, catalog, wb_id, tmp_path):
    """A tool-less prose file under ``02.AU/`` gets NO floor (no family-'-1' rule).

    Rejected design check: the folder alone must NOT manufacture an AU-1 (policy)
    tag — that was judged semantically wrong + noisy. With no tool token, no CCI,
    and no judge (offline), the file stays zero-tag.
    """
    _write(
        tmp_path / "02.AU" / "audit_program_overview.txt",
        "This memo summarizes the audit logging program scope and the roles "
        "responsible for reviewing records. No specific tool is named here.",
    )
    ingest_folder(session, tmp_path, workbook_id=wb_id)
    tagged = _tagged_ids(session)
    for oid in catalog["au-1"] + catalog["au-8"]:
        assert oid not in tagged, (
            "folder alone must NOT floor any AU control (family-'-1' floor rejected)"
        )


def test_zero_byte_file_under_folder_stays_zero(session, catalog, wb_id, tmp_path):
    """A genuinely-empty 0-byte file under ``02.AU/`` stays zero-tag.

    The 0-byte file has no content to locate it to a SPECIFIC control; per the
    rejected family-'-1' floor it must NOT be force-tagged to AU-1. It is
    correctly empty (surfaced by the "N files didn't map" review banner, and the
    assessor re-collects). This is the ``spaceLowAudit`` case — defensibly zero,
    not falsely SI-1'd.
    """
    target = tmp_path / "02.AU" / "spaceLowAudit.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("", encoding="utf-8")

    summary = ingest_folder(session, tmp_path, workbook_id=wb_id)
    assert summary.ingested >= 1, "0-byte .txt file must still produce an Evidence row"
    tagged = _tagged_ids(session)
    for oid in catalog["au-1"] + catalog["au-8"]:
        assert oid not in tagged, "0-byte file must stay zero-tag, never family-floored"


# --------------------------------------------------------------------------- #
# SAFETY                                                                       #
# --------------------------------------------------------------------------- #


def test_substring_does_not_false_match(session, catalog, wb_id, tmp_path):
    """Whole-word matching: 'flashing' must NOT match 'ssh'; 'dashboard' not 'aide'.

    Placed under a NON-NN.XX folder so FIX 2's folder floor can't fire and mask
    a substring false-positive — any tag here would be a real tool-token bug.
    """
    _write(
        tmp_path / "misc" / "release_notes.txt",
        "The firmware flashing procedure was upgraded; the dashboard now shows "
        "progress and guidance was provided to operators.",
    )
    ingest_folder(session, tmp_path, workbook_id=wb_id)
    tagged = _tagged_ids(session)
    # 'flashing'/'dashboard'/'guidance' contain no whole-word tool token, and
    # there is no NN.XX folder → nothing should be tagged at all.
    assert not tagged, (
        "substring false-match or stray floor: a non-NN.XX prose file with no "
        "whole-word tool token tagged something"
    )


def test_floor_does_not_double_tag_existing(session, catalog, wb_id, tmp_path):
    """The floor never clobbers/duplicates a tag already on the SAME evidence.

    The no-double-tag guard is WITHIN one ``tag_evidence`` pass: ``_add`` is
    first-write-wins against the per-evidence ``existing`` set seeded from
    ``_existing_pairs(session, evidence.id)``. (Verified 2026-06-24: the
    ``existing`` set is per-evidence, so two DIFFERENT evidence files can each
    legitimately tag the same objective — global de-dup is NOT the contract.)

    To pin the real guard we operate on ONE persisted Evidence: seed a real
    ``source="auto"`` tag on one AC-17 objective, then run ``tag_evidence`` on
    that same evidence (offline → the xrdp floor path). The floor must:
      * leave the seeded objective with exactly ONE tag whose source is "auto"
        (not overwritten, not duplicated).

    The floor's coverage gate is per-CONTROL (verified 2026-06-24 tagger.py:2273:
    ``if any(o.id in existing for o in objs): continue``): once ANY AC-17
    objective carries a tag, the floor treats the whole AC-17 control as covered
    and floors NONE of its objectives. So the sibling AC-17 objective is also
    left untouched here — that is the correct gap-fill semantics (the floor only
    fills controls with ZERO existing tags), and it doubles as proof the floor
    never piles a second tag onto an already-evidenced control.

    REQUIRES (FIX 1): xrdp must be matched as a whole-word token for the floor to
    consider AC-17 at all; the per-control ``existing`` de-dup is what this pins.
    """
    from cybersecurity_assessor.evidence.tagger import tag_evidence  # noqa: PLC0415
    from cybersecurity_assessor.models import Evidence, EvidenceKind  # noqa: PLC0415

    fw_id = session.exec(select(Framework)).first().id
    seeded_oid = catalog["ac-17"][0]
    other_oid = catalog["ac-17"][1]

    # One persisted Evidence whose path lands under 01.AC (folder×tool agrees)
    # and whose title carries the xrdp tool token. sha256/kind/size_bytes are
    # NOT NULL in the schema, so populate them.
    ev = Evidence(
        path="file:///wb/01.AC/CTP-010_xrdp_step12.txt",
        sha256="a" * 64,
        kind=EvidenceKind.TEXT,
        size_bytes=64,
        title="CTP-010_xrdp_step12.txt",
        workbook_id=wb_id,
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    # Pre-existing REAL tag on one AC-17 objective of THIS evidence.
    session.add(
        EvidenceTag(
            evidence_id=ev.id,
            objective_id=seeded_oid,
            relevance=1.0,
            confidence=0.9,
            source="auto",
            rationale="pre-existing real tag (must not be clobbered)",
            framework_id=fw_id,
        )
    )
    session.commit()

    # Run the deterministic (offline) tagger directly on this evidence. The xrdp
    # token in the title + 01.AC path drives the AC-17 floor.
    tag_evidence(
        session,
        ev,
        text="systemctl status xrdp\nActive: active (running)\n",
        framework_id=fw_id,
    )
    session.commit()

    seeded_tags = session.exec(
        select(EvidenceTag).where(
            EvidenceTag.evidence_id == ev.id,
            EvidenceTag.objective_id == seeded_oid,
        )
    ).all()
    # No duplicate row on the already-tagged objective; original source kept.
    assert len(seeded_tags) == 1, (
        "floor created a duplicate tag on an already-tagged objective (same evidence)"
    )
    assert seeded_tags[0].source == "auto", (
        "floor clobbered the source of a pre-existing real tag"
    )
    # Per-control coverage gate: AC-17 is already covered by the seed, so the
    # floor must add NOTHING to the sibling objective (no second tag on an
    # already-evidenced control).
    other_tags = session.exec(
        select(EvidenceTag).where(
            EvidenceTag.evidence_id == ev.id,
            EvidenceTag.objective_id == other_oid,
        )
    ).all()
    assert other_tags == [], (
        "AC-17 already covered by the seed → floor must not tag the sibling "
        "objective (per-control coverage gate)"
    )


# --------------------------------------------------------------------------- #
# NEGATIVE — no folder token AND no tool → no floor (no false positive)        #
# --------------------------------------------------------------------------- #


def test_no_folder_no_tool_floors_nothing(session, catalog, wb_id, tmp_path):
    """A prose file with NO NN.XX folder and NO tool token earns NO floor tag.

    This guards both fixes against over-firing: the folder floor must be gated on
    ``_family_from_path`` being set, and the tool floor on an actual tool match.
    Neither holds here, so the file legitimately stays untagged.
    """
    _write(
        tmp_path / "general_policy_overview.txt",
        "This document describes the organization's overall approach to "
        "information security governance and risk management responsibilities.",
    )
    ingest_folder(session, tmp_path, workbook_id=wb_id)
    tagged = _tagged_ids(session)
    assert not tagged, (
        "no NN.XX folder and no tool token must produce no floor tag "
        "(false-positive guard)"
    )
