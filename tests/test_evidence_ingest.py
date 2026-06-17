"""Ingest orchestrator tests — folder walk → hash → extract → persist → tag.

Uses an in-memory SQLite engine and monkeypatches ``extracted_text_dir``
so we never touch ``~/.cybersecurity-assessor/``. The synthetic fixtures cover
the three behaviors the orchestrator promises:

  * a happy path (text file + CKL → Evidence + StigFinding + EvidenceTag rows)
  * idempotence (re-ingest skips on path)
  * failure isolation (one unparseable file doesn't abort the run)

Hidden / lock-file filtering is also asserted because that's the only
defense against `~$report.docx` Office turds polluting the index.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from cybersecurity_assessor.evidence import ingest as ingest_mod
from cybersecurity_assessor.evidence.ingest import ingest_folder
from cybersecurity_assessor.models import (
    Control,
    Evidence,
    EvidenceTag,
    Framework,
    Objective,
    StigFinding,
    Workbook,
)

pytest.importorskip("defusedxml")  # CKL fixture needs defusedxml.ElementTree


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


_CKL_FIXTURE = """<?xml version="1.0" encoding="UTF-8"?>
<CHECKLIST>
  <ASSET><HOST_NAME>WIN-01</HOST_NAME></ASSET>
  <STIGS>
    <iSTIG>
      <STIG_INFO>
        <SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>Windows 11 STIG</SID_DATA></SI_DATA>
      </STIG_INFO>
      <VULN>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>SV-1</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE><ATTRIBUTE_DATA>CCI-000366</ATTRIBUTE_DATA></STIG_DATA>
        <STATUS>Open</STATUS>
        <FINDING_DETAILS>per USD00050010</FINDING_DETAILS>
      </VULN>
    </iSTIG>
  </STIGS>
</CHECKLIST>
"""


@pytest.fixture
def session(tmp_path, monkeypatch) -> Session:
    """In-memory DB + seeded catalog + redirected extracted_text_dir."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    s = Session(engine)

    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    s.add(fw)
    s.flush()
    ac2 = Control(framework_id=fw.id, control_id="AC-2", title="Account Management", family="AC")
    cm6 = Control(framework_id=fw.id, control_id="CM-6", title="Configuration Settings", family="CM")
    s.add_all([ac2, cm6])
    s.flush()
    s.add_all(
        [
            Objective(
                control_id_fk=ac2.id,
                objective_id="CCI-000015",
                text="Employ automated mechanisms for account management.",
                implementation_guidance="Local IdAM tooling per USD00050010.",
            ),
            Objective(
                control_id_fk=cm6.id,
                objective_id="CCI-000366",
                text="Implement configuration settings.",
            ),
        ]
    )
    s.commit()

    # Redirect extracted_text_dir into tmp_path so the test doesn't pollute
    # ~/.cybersecurity-assessor/extracted_text/.
    extracted_dir = tmp_path / "extracted_text"
    extracted_dir.mkdir()
    monkeypatch.setattr(ingest_mod, "extracted_text_dir", lambda: extracted_dir)

    yield s
    s.close()


@pytest.fixture
def workbook_id(session) -> int:
    """A persisted Workbook row's id.

    PR 2 per-workbook hard-scoping: ingest requires an explicit workbook_id —
    Evidence rows are physically scoped to one workbook, there is no global
    pool. Every ingest call in this module threads this id through.
    """
    wb = Workbook(path="C:/wb/evidence-ingest-test.xlsx", filename="evidence-ingest-test.xlsx")
    session.add(wb)
    session.commit()
    return wb.id


def _write_evidence_tree(root):
    """Lay down: a text file with a doc number, a CKL, and one piece of
    noise (an unsupported .zip) so we can assert _iter_files filters it."""
    root.mkdir(parents=True, exist_ok=True)
    # Declare the doc number on a labeled line so it's adopted as the file's
    # own identity (a bare prose mention would be treated as a citation).
    (root / "policy.txt").write_text(
        "Document Number: USD00050010\nAccount management policy.\n",
        encoding="utf-8",
    )
    (root / "win11.ckl").write_text(_CKL_FIXTURE, encoding="utf-8")
    (root / "archive.zip").write_bytes(b"PK\x03\x04not-really-a-zip")
    # Office lock file + dotfile — both must be ignored by _iter_files.
    (root / "~$skipme.docx").write_bytes(b"junk")
    (root / ".hidden.txt").write_text("ignore me", encoding="utf-8")


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_ingest_folder_processes_text_and_ckl(session, tmp_path, workbook_id):
    root = tmp_path / "evidence"
    _write_evidence_tree(root)

    summary = ingest_folder(session, root, workbook_id=workbook_id)

    # .zip / lock / dotfile filtered at the walker (not counted as scanned).
    assert summary.scanned == 2
    assert summary.ingested == 2
    assert summary.errors == []

    rows = session.exec(select(Evidence)).all()
    assert {r.title for r in rows} >= {"Windows 11 STIG"}
    assert any(r.doc_number == "USD00050010" for r in rows)

    # CKL produced one StigFinding row with the embedded CCI.
    findings = session.exec(select(StigFinding)).all()
    assert len(findings) == 1
    assert findings[0].cci_refs == "CCI-000366"

    # Tagger linked both the doc-number and the CCI to seeded objectives.
    tags = session.exec(select(EvidenceTag)).all()
    obj_ids = {t.objective_id for t in tags}
    cci15 = session.exec(select(Objective).where(Objective.objective_id == "CCI-000015")).one()
    cci366 = session.exec(select(Objective).where(Objective.objective_id == "CCI-000366")).one()
    assert cci15.id in obj_ids  # via doc number
    assert cci366.id in obj_ids  # via CCI direct ref


# ---------------------------------------------------------------------------
# Idempotence
# ---------------------------------------------------------------------------


def test_ingest_folder_skips_existing_on_second_run(session, tmp_path, workbook_id):
    root = tmp_path / "evidence"
    _write_evidence_tree(root)

    first = ingest_folder(session, root, workbook_id=workbook_id)
    second = ingest_folder(session, root, workbook_id=workbook_id)

    assert second.scanned == first.scanned
    assert second.ingested == 0
    assert second.skipped_existing == first.scanned

    # No duplicate Evidence rows.
    rows = session.exec(select(Evidence)).all()
    assert len(rows) == first.ingested


def test_ingest_folder_dedupes_by_hash_when_path_differs(session, tmp_path, workbook_id):
    """Same bytes copied under a new name → only the first wins."""
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "a.txt").write_text("identical contents", encoding="utf-8")
    (root / "b.txt").write_text("identical contents", encoding="utf-8")

    summary = ingest_folder(session, root, workbook_id=workbook_id)
    assert summary.scanned == 2
    assert summary.ingested == 1
    assert summary.skipped_existing == 1


# ---------------------------------------------------------------------------
# Failure isolation
# ---------------------------------------------------------------------------


def test_ingest_folder_records_extractor_error_but_continues(session, tmp_path, workbook_id):
    """A non-XCCDF .xml file raises ExtractorError; ingest should still
    finish the rest of the folder and persist the bad file as empty-text
    Evidence so the user can see it in the list."""
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "good.txt").write_text("USD00050010 reference", encoding="utf-8")
    (root / "bad.xml").write_text("<?xml version='1.0'?><Random/>", encoding="utf-8")

    summary = ingest_folder(session, root, workbook_id=workbook_id)
    assert summary.scanned == 2
    assert summary.ingested == 2  # both persist; bad one has empty text
    assert any("bad.xml" in e["path"] for e in summary.errors)

    rows = session.exec(select(Evidence)).all()
    paths = {r.path for r in rows}
    assert any(p.endswith("good.txt") for p in paths)
    assert any(p.endswith("bad.xml") for p in paths)


def test_ingest_folder_handles_missing_directory(session, tmp_path):
    missing = tmp_path / "does-not-exist"
    summary = ingest_folder(session, missing)
    assert summary.scanned == 0
    assert summary.ingested == 0
    assert any("not a directory" in e["error"] for e in summary.errors)


# ---------------------------------------------------------------------------
# Recursive walk
# ---------------------------------------------------------------------------


def test_ingest_folder_recursive_descends_into_subdirs(session, tmp_path, workbook_id):
    root = tmp_path / "evidence"
    sub = root / "subdir"
    sub.mkdir(parents=True)
    (root / "top.txt").write_text("USD00050010", encoding="utf-8")
    (sub / "deep.txt").write_text("USD00022222", encoding="utf-8")

    summary = ingest_folder(session, root, recursive=True, workbook_id=workbook_id)
    assert summary.scanned == 2
    assert summary.ingested == 2


def test_ingest_folder_non_recursive_stays_at_top_level(session, tmp_path, workbook_id):
    root = tmp_path / "evidence"
    sub = root / "subdir"
    sub.mkdir(parents=True)
    (root / "top.txt").write_text("USD00050010", encoding="utf-8")
    (sub / "deep.txt").write_text("USD00022222", encoding="utf-8")

    summary = ingest_folder(session, root, recursive=False, workbook_id=workbook_id)
    assert summary.scanned == 1
    assert summary.ingested == 1


# ---------------------------------------------------------------------------
# ARF (Asset Reporting Format) — full pipeline: walk → extract → persist → tag
# ---------------------------------------------------------------------------
#
# An ARF scan (SCAP 1.2/1.3) wraps the same XCCDF Benchmark/TestResult content
# inside an <asset-report-collection> root. The extractor sniffs the root and
# unwraps it, so this exercises the whole chain end-to-end: the .arf suffix
# must reach the walker (local._INGESTIBLE_SUFFIXES), route to the XCCDF
# extractor (dispatcher), produce a STIG_XCCDF Evidence row + a StigFinding,
# and — because the embedded Rule carries CCI-000366 and the rule-result is
# ``fail`` (→ OPEN) — the tagger must link the evidence to the seeded CM-6
# objective and the bundle must render it as a corroborating finding.

_ARF_FIXTURE = """<?xml version="1.0" encoding="UTF-8"?>
<arf:asset-report-collection
    xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1"
    xmlns:ai="http://scap.nist.gov/schema/asset-identification/1.1">
  <arf:assets>
    <arf:asset>
      <ai:computing-device>
        <ai:hostname>arf-box</ai:hostname>
      </ai:computing-device>
    </arf:asset>
  </arf:assets>
  <arf:reports>
    <arf:report id="xccdf1">
      <arf:content>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="b">
          <title>ARF Ingest Benchmark</title>
          <Rule id="rule_arf_1" severity="high">
            <title>Enforce configuration baseline</title>
            <ident system="http://cci">CCI-000366</ident>
          </Rule>
          <TestResult id="tr1">
            <target>arf-box</target>
            <rule-result idref="rule_arf_1"><result>fail</result></rule-result>
          </TestResult>
        </Benchmark>
      </arf:content>
    </arf:report>
  </arf:reports>
</arf:asset-report-collection>
"""


def test_ingest_folder_processes_arf_and_renders_finding(session, tmp_path, workbook_id):
    from cybersecurity_assessor.engine.evidence_bundle import build_tagged_evidence
    from cybersecurity_assessor.models import EvidenceKind, FindingStatus

    root = tmp_path / "evidence"
    root.mkdir()
    (root / "scan.arf").write_text(_ARF_FIXTURE, encoding="utf-8")

    summary = ingest_folder(session, root, workbook_id=workbook_id)
    assert summary.scanned == 1
    assert summary.ingested == 1
    assert summary.findings_created == 1
    assert summary.errors == []

    # Evidence row persisted as STIG_XCCDF with non-empty extracted text.
    evidence = session.exec(select(Evidence)).all()
    assert len(evidence) == 1
    ev = evidence[0]
    assert ev.kind == EvidenceKind.STIG_XCCDF
    assert ev.path.endswith("scan.arf")
    assert ev.extracted_text_path  # text was written, not dropped

    # The embedded XCCDF finding landed with CCI, OPEN status, and host.
    findings = session.exec(select(StigFinding)).all()
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "rule_arf_1"
    assert f.cci_refs == "CCI-000366"
    assert f.status == FindingStatus.OPEN
    assert f.comments == "host=arf-box"

    # Tagger linked the ARF evidence to the seeded CM-6 / CCI-000366 objective
    # via the finding's CCI ref (the ARF body text carries no CCI string).
    cm6_obj = session.exec(
        select(Objective).where(Objective.objective_id == "CCI-000366")
    ).one()
    tagged_obj_ids = {t.objective_id for t in session.exec(select(EvidenceTag)).all()}
    assert cm6_obj.id in tagged_obj_ids

    # The bundle for CM-6 renders the ARF-derived finding (OPEN + matching CCI
    # + tagged evidence all line up → corroboration fires).
    bundle = build_tagged_evidence(cm6_obj.id, session)
    assert bundle is not None
    assert "rule_arf_1" in bundle


# ---------------------------------------------------------------------------
# Image / diagram admission + zero-tag warning
# ---------------------------------------------------------------------------


def test_ingest_admits_images_and_diagrams_and_flags_untagged(
    session, tmp_path, workbook_id, monkeypatch
):
    """Images/diagrams are no longer dropped at the walk; an unmappable image
    surfaces in ``IngestSummary.untagged`` instead of vanishing silently.
    """
    from PIL import Image as PILImage

    # Keep the test offline + fast: no Tier-5 LLM judge (it would retry against
    # a dead endpoint). Deterministic tiers are what this test exercises.
    monkeypatch.setattr(ingest_mod, "_build_tagger_llm", lambda: (None, None))

    root = tmp_path / "ev"
    root.mkdir()
    # A boundary diagram (svg) — should ingest AND tag boundary controls.
    (root / "network_boundary.svg").write_bytes(
        b'<svg xmlns="http://www.w3.org/2000/svg">'
        b"<text>DMZ firewall external boundary</text></svg>"
    )
    # A generic screenshot — ingests but maps to nothing → untagged warning.
    PILImage.new("RGB", (16, 8), "white").save(root / "login_page.png", "PNG")

    summary = ingest_folder(session, root, workbook_id=workbook_id)

    # Both admitted (previously both were skipped at the walk).
    assert summary.ingested == 2
    # The generic image is surfaced as unmapped, not silently dropped.
    untagged_names = {Path(u["path"]).name for u in summary.untagged}
    assert "login_page.png" in untagged_names
    # The boundary diagram is NOT in untagged (it tagged boundary controls) —
    # but this DB only seeds AC-2/CM-6, so sc-7/ca-3 objectives don't exist
    # here; the diagram simply ingests. Assert it became an Evidence row.
    from cybersecurity_assessor.models import Evidence as _Ev

    paths = {Path(e.path).name for e in session.exec(select(_Ev)).all()}
    assert "network_boundary.svg" in paths
    assert "login_page.png" in paths
