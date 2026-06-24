"""Tier 4.5: tool/daemon-name → control deterministic auto-tagging (2026).

Terse CTP terminal-output evidence is named for the TOOL it tests
(``CTP-010_xrdp_step7.txt``, ``CTP-014_aide_step10.txt``). The tool name is a
near-definitional control signal (xrdp = remote desktop = AC-17; aide = file
integrity = SI-7) but carries no doc/CCI/control-ID token, so Tiers 1-3 produce
nothing and the file falls to the expensive LLM judge. Tier 4.5 encodes the
canonical tool→control lineage as a deterministic map: it RECOVERS recall (the
file reaches its control page) AND clears the Tier-5 low-tag gate so it skips
the judge.

Pinned here:
  * xrdp .txt → AC-17, single-purpose daemon → source="auto", confidence 0.6.
  * aide .txt → SI-7 + CM-3 (multi-control single tool), source="auto".
  * vault .txt → IA-5/SC-12/SC-28 but POLYSEMOUS → source="auto_review".
  * a plain prose file with no tool token → no tool-name tag (no false positive).
  * whole-word matching: "flashing" does not match the "ssh"... (tested via a
    non-tool file that merely contains tool substrings).
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
from cybersecurity_assessor.evidence.ingest import ingest_folder  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Control,
    EvidenceTag,
    Framework,
    Objective,
)
from cybersecurity_assessor.models import Workbook as WorkbookModel  # noqa: E402


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


def test_xrdp_txt_tags_ac17_auto(session, catalog, wb_id, tmp_path):
    """A file named for xrdp tags AC-17 deterministically at source=auto."""
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
        assert oid in tagged, f"AC-17 child {oid} not tagged from xrdp file"
    ac17_tags = [t for t in tags if t.objective_id in catalog["ac-17"]]
    assert all(t.confidence == 0.6 for t in ac17_tags)
    assert all(t.source == "auto" for t in ac17_tags), "xrdp is single-purpose → auto"
    assert any("xrdp" in t.rationale.lower() for t in ac17_tags)
    # No leak into unrelated controls.
    for neg in ("au-8", "ac-2", "si-7"):
        for oid in catalog[neg]:
            assert oid not in tagged, f"xrdp leaked into {neg}"


def test_aide_txt_tags_si7_and_cm3(session, catalog, wb_id, tmp_path):
    """aide maps to BOTH SI-7 and CM-3 (multi-control single tool)."""
    _write(
        tmp_path / "CTP-014_aide_step10.txt",
        "aide --check\nAIDE found differences between database and filesystem\n",
    )
    ingest_folder(session, tmp_path, workbook_id=wb_id)
    tagged = {t.objective_id for t in session.exec(select(EvidenceTag)).all()}
    for ctl in ("si-7", "cm-3"):
        for oid in catalog[ctl]:
            assert oid in tagged, f"aide did not tag {ctl} child {oid}"
    for neg in ("ac-17", "au-8"):
        for oid in catalog[neg]:
            assert oid not in tagged, f"aide leaked into {neg}"


def test_vault_txt_is_auto_review_not_auto(session, catalog, wb_id, tmp_path):
    """vault is polysemous → tags at source=auto_review (human confirms)."""
    _write(
        tmp_path / "CTP-022_vault.txt",
        "vault operator init\nvault status: Sealed=false\n",
    )
    ingest_folder(session, tmp_path, workbook_id=wb_id)
    tags = session.exec(select(EvidenceTag)).all()
    tagged = {t.objective_id for t in tags}
    for ctl in ("ia-5", "sc-12", "sc-28"):
        for oid in catalog[ctl]:
            assert oid in tagged, f"vault did not tag {ctl} child {oid}"
    vault_obj_ids = {
        oid for c in ("ia-5", "sc-12", "sc-28") for oid in catalog[c]
    }
    vault_tags = [t for t in tags if t.objective_id in vault_obj_ids]
    assert all(t.source == "auto_review" for t in vault_tags), (
        "vault is polysemous → must be auto_review, not auto"
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
