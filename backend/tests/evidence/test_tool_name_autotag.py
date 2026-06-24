"""Tier 4.5: tool/daemon-name → control nomination (design E+A, 2026).

Terse CTP terminal-output evidence is named for the TOOL it tests
(``CTP-010_xrdp_step7.txt``, ``CTP-014_aide_step10.txt``). The tool name is a
near-definitional control SIGNAL (xrdp=AC-17; aide=SI-7) but carries no
doc/CCI/control-ID token. After a measured A/B showed blind tool-emit was net
NEGATIVE (it suppressed the LLM judge and polysemous tokens sprayed wrong
controls), Tier 4.5 was changed to NOMINATE not emit:
  * design E — every matched tool's controls are injected as JUDGE CANDIDATES
    so the judge confirms/rejects each against the file's real content.
  * design A — SINGLE-PURPOSE (unambiguous) tools get a post-judge auto_review
    FLOOR only when the judge/other tiers left the control untagged, so the
    canonical control is never silently dropped (incl. offline).

These tests run OFFLINE (autouse fixture forces no judge) to pin the
deterministic FLOOR + the polysemous "nominate-only" rule:
  * xrdp .txt (single-purpose) → AC-17 floored at source="auto_review".
  * aide .txt (single-purpose, multi-control) → SI-7 + CM-3 floored auto_review.
  * vault .txt (POLYSEMOUS) → emits NOTHING offline (nominate-only; the judge,
    when present, is the only thing that can confirm it).
  * a plain prose file with no tool token → no tool tag (no false positive).
  * whole-word matching: substrings like "flashing" don't match "ssh".
(The judge-confirmed candidate path is covered in test_evidence_tagger_llm_tier.py.)
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

    These tests exercise the DETERMINISTIC paths: design-E candidate nomination
    is judge-confirmed (covered by the stub-judge tests in
    test_evidence_tagger_llm_tier.py), while THIS module pins the design-A
    single-purpose FLOOR + the polysemous "nominate-only, never blind-emit"
    rule. On a dev workstation ``_build_tagger_llm`` resolves a REAL judge from
    on-disk config/keyring, which made the floor nondeterministic (a live
    judge-accept yields source=llm instead of the auto_review floor). Pinning
    no-client makes the floor path deterministic and matches what the tests
    assert. Mirrors test_evidence_ingest.py's offline monkeypatch.
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
    wb = WorkbookModel(path="/tmp/tool.xlsx", filename="tool.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb.id


@pytest.fixture
def catalog(session) -> dict[str, list[int]]:
    """Seed AC-17, SI-7, CM-3, IA-5, SC-12, SC-28 + a negative AU-8 / AC-2.

    Each control carries 2 child objectives so a single-control match still
    clears the Tier-5 low-tag gate (no LLM in these deterministic tests).
    """
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)

    by_control: dict[str, list[int]] = {}
    for ctl_id, family in [
        ("ac-17", "AC"),
        ("si-7", "SI"),
        ("cm-3", "CM"),
        ("ia-5", "IA"),
        ("sc-12", "SC"),
        ("sc-28", "SC"),
        ("au-8", "AU"),   # negative — chrony maps here; must NOT tag from xrdp/aide/vault
        ("ac-2", "AC"),   # negative — generic account control
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
    path.write_text(body, encoding="utf-8")


# NOTE (design E+A, 2026): these tests run OFFLINE (no LLM client), so they
# exercise the design-A FLOOR path, not the old blind-emit. Under E+A a tool
# name NOMINATES a judge candidate (design E); with no judge available, a
# SINGLE-PURPOSE (unambiguous) tool falls back to a low-confidence auto_review
# FLOOR so the canonical control is never silently dropped. A POLYSEMOUS tool
# emits NOTHING offline — it only ever nominates, never floors — which is the
# precision fix the A/B mandated (no blind cluster-spray).


def test_xrdp_single_purpose_floors_ac17_offline(session, catalog, wb_id, tmp_path):
    """xrdp is single-purpose: with no judge, AC-17 still gets a recall floor."""
    _write(
        tmp_path / "CTP-010_xrdp_step7.txt",
        "more /etc/systemd/system/multi-user.target.wants/xrdp.service\n"
        "Description=xrdp daemon\nExecStart=/usr/sbin/xrdp --nodaemon\n",
    )
    summary = ingest_folder(session, tmp_path, workbook_id=wb_id)
    assert summary.ingested == 1
    assert summary.errors == []

    tags = session.exec(select(EvidenceTag)).all()
    tagged = {t.objective_id for t in tags}
    for oid in catalog["ac-17"]:
        assert oid in tagged, f"AC-17 child {oid} not floored from xrdp file"
    ac17_tags = [t for t in tags if t.objective_id in catalog["ac-17"]]
    # Floor is low-confidence auto_review (NOT the old 0.6/auto blind emit).
    assert all(t.source == "auto_review" for t in ac17_tags), (
        "single-purpose floor is auto_review (judge-unconfirmed recall floor)"
    )
    assert any("xrdp" in t.rationale.lower() for t in ac17_tags)
    assert any("recall floor" in t.rationale.lower() for t in ac17_tags)
    # No leak into unrelated controls.
    for neg in ("au-8", "ac-2", "si-7"):
        for oid in catalog[neg]:
            assert oid not in tagged, f"xrdp leaked into {neg}"


def test_aide_single_purpose_floors_si7_and_cm3_offline(session, catalog, wb_id, tmp_path):
    """aide is single-purpose, maps SI-7 + CM-3: both floored offline."""
    _write(
        tmp_path / "CTP-014_aide_step10.txt",
        "aide --check\nAIDE found differences between database and filesystem\n",
    )
    ingest_folder(session, tmp_path, workbook_id=wb_id)
    tags = session.exec(select(EvidenceTag)).all()
    tagged = {t.objective_id for t in tags}
    for ctl in ("si-7", "cm-3"):
        for oid in catalog[ctl]:
            assert oid in tagged, f"aide did not floor {ctl} child {oid}"
    aide_obj = {oid for c in ("si-7", "cm-3") for oid in catalog[c]}
    assert all(
        t.source == "auto_review" for t in tags if t.objective_id in aide_obj
    )
    for neg in ("ac-17", "au-8"):
        for oid in catalog[neg]:
            assert oid not in tagged, f"aide leaked into {neg}"


def test_vault_polysemous_emits_NOTHING_offline(session, catalog, wb_id, tmp_path):
    """vault is POLYSEMOUS: with no judge to confirm, it emits NO tag at all.

    This is the core precision fix from the A/B — an ambiguous token (vault/ssh/
    sudo/fips) must NEVER blind-emit; it only nominates a judge candidate. Offline
    there is no judge, so nothing is tagged (vs the old build's cluster-spray).
    """
    _write(
        tmp_path / "CTP-022_vault.txt",
        "vault operator init\nvault status: Sealed=false\n",
    )
    ingest_folder(session, tmp_path, workbook_id=wb_id)
    tags = session.exec(select(EvidenceTag)).all()
    tagged = {t.objective_id for t in tags}
    vault_obj_ids = {
        oid for c in ("ia-5", "sc-12", "sc-28") for oid in catalog[c]
    }
    assert not (tagged & vault_obj_ids), (
        "polysemous 'vault' must NOT emit tags offline — it only nominates "
        "judge candidates (no blind cluster-spray)"
    )


def test_non_tool_prose_file_gets_no_tool_tag(session, catalog, wb_id, tmp_path):
    """A prose file with no tool token produces no Tier-4.5 tag (no false positive)."""
    _write(
        tmp_path / "general_policy_overview.txt",
        "This document describes the organization's overall approach to "
        "information security governance and risk management responsibilities.",
    )
    ingest_folder(session, tmp_path, workbook_id=wb_id)
    tags = session.exec(select(EvidenceTag)).all()
    # No tool-name tag (rationale mentions a tool) anywhere.
    assert not [
        t for t in tags if "detected in evidence" in (t.rationale or "").lower()
    ], "a non-tool prose file produced a tool-name tag"


def test_substring_does_not_false_match(session, catalog, wb_id, tmp_path):
    """Whole-word matching: 'flashing' must NOT match the 'aide'/'ssh' tokens."""
    _write(
        tmp_path / "release_notes.txt",
        "The firmware flashing procedure was upgraded; guidance was provided "
        "and the dashboard now displays progress.",
    )
    ingest_folder(session, tmp_path, workbook_id=wb_id)
    tags = session.exec(select(EvidenceTag)).all()
    tagged = {t.objective_id for t in tags}
    # 'flashing'/'guidance'/'dashboard' contain no whole-word tool token.
    for ctl in ("si-7", "cm-3", "ac-17"):
        for oid in catalog[ctl]:
            assert oid not in tagged, f"substring false-matched a tool → {ctl}"
