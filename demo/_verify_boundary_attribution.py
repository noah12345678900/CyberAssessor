"""Demo showcase: per-artifact BOUNDARY ATTRIBUTION for multi-tenant systems.

Shows the feature that keeps per-scope narratives honest in a multi-boundary
program (e.g. AWS GovCloud + Azure Government): each evidence artifact in the
``## tagged_evidence`` block carries a ``boundary:`` line naming the enclave /
tenant it is attributed to, so the LLM cannot misattribute a boundary-ambiguous
artifact (a global IAM policy, a shared firewall export) to the wrong tenant.

This is fully self-contained — it builds an in-memory DB, ingests the two demo
boundary diagrams, defines two tenant BoundarySegments, links each diagram to
its tenant with an EXPLICIT (manual) link, and prints the rendered bundle so a
viewer can SEE the boundary lines. It also proves the two guardrails:

  * single-boundary workbooks render NO boundary line (prompt-cache stable);
  * BACKFILL (legacy-flag) links are excluded — only AUTO/MANUAL render, so
    unreliable attribution is never laundered into an authoritative header.

Run:  backend/.venv/Scripts/python.exe demo/_verify_boundary_attribution.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from cybersecurity_assessor import models  # noqa: F401  registers tables
from cybersecurity_assessor.engine.evidence_bundle import (
    BOUNDARY_UNSPECIFIED,
    build_tagged_evidence_with_payload,
)
from cybersecurity_assessor.evidence.extractors import extract_path
from cybersecurity_assessor.models import (
    BoundarySegment,
    Control,
    Evidence,
    EvidenceBoundary,
    EvidenceKind,
    EvidenceTag,
    Framework,
    Objective,
    ScopeLinkSource,
    Workbook,
)

DEMO = Path(__file__).parent
DIAGRAMS = DEMO / "diagrams"
# The two tenant-distinct boundary diagrams (one per cloud enclave).
VSDX = DIAGRAMS / "Example_System_AWS_GovCloud_Boundary_Diagram_USD20240620.vsdx"
SVG = DIAGRAMS / "Example_System_Azure_Government_Boundary_Diagram_USD20240621.svg"


def _seed_objective(s: Session) -> Objective:
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    s.add(fw)
    s.commit()
    s.refresh(fw)
    ctrl = Control(
        framework_id=fw.id, control_id="SC-7", title="Boundary Protection", family="SC"
    )
    s.add(ctrl)
    s.commit()
    s.refresh(ctrl)
    obj = Objective(
        control_id_fk=ctrl.id,
        objective_id="CCI-001097",
        source="CCI",
        text="Monitor and control communications at the external boundary.",
    )
    s.add(obj)
    s.commit()
    s.refresh(obj)
    return obj


def _ingest_diagram(s: Session, path: Path, workbook_id: int) -> Evidence:
    """Run the real extractor, persist an Evidence row with its extracted text."""
    doc = extract_path(path)
    tp = Path(tempfile.mktemp(suffix=".txt"))
    tp.write_text(doc.text, encoding="utf-8")
    ev = Evidence(
        path=path.as_uri(),
        sha256=path.name,
        kind=EvidenceKind.DIAGRAM,
        size_bytes=path.stat().st_size,
        title=doc.title,
        doc_number=doc.doc_number,
        extracted_text_path=str(tp),
        workbook_id=workbook_id,
    )
    s.add(ev)
    s.commit()
    s.refresh(ev)
    return ev


def main() -> int:
    if not VSDX.exists() or not SVG.exists():
        print("ERROR: demo diagrams missing — run _build_demo_artifacts.py first.")
        return 1

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    s = Session(engine)

    obj = _seed_objective(s)
    wb = Workbook(path="C:/wb/demo-multitenant.xlsx", filename="demo-multitenant.xlsx")
    s.add(wb)
    s.commit()
    s.refresh(wb)

    # Two cloud tenants — this is what makes the workbook "multi-boundary".
    aws = BoundarySegment(workbook_id=wb.id, name="AWS GovCloud", kind="tenant")
    azure = BoundarySegment(workbook_id=wb.id, name="Azure Government", kind="tenant")
    s.add_all([aws, azure])
    s.commit()
    s.refresh(aws)
    s.refresh(azure)

    # Ingest both demo diagrams; tag both to SC-7.
    ev_vsdx = _ingest_diagram(s, VSDX, wb.id)
    ev_svg = _ingest_diagram(s, SVG, wb.id)
    for ev in (ev_vsdx, ev_svg):
        s.add(
            EvidenceTag(
                evidence_id=ev.id, objective_id=obj.id,
                relevance=0.9, confidence=0.9, source="manual",
            )
        )
    # EXPLICIT (manual) per-tenant links: the .vsdx → AWS, the .svg → Azure.
    s.add(EvidenceBoundary(evidence_id=ev_vsdx.id, boundary_segment_id=aws.id,
                           source=ScopeLinkSource.MANUAL))
    s.add(EvidenceBoundary(evidence_id=ev_svg.id, boundary_segment_id=azure.id,
                           source=ScopeLinkSource.MANUAL))
    s.commit()

    text, _payload, _overflow = build_tagged_evidence_with_payload(
        obj.id, s, workbook_id=wb.id
    )

    print("=" * 70)
    print("MULTI-TENANT BUNDLE  (note the per-artifact `boundary:` lines)")
    print("=" * 70)
    print(text)
    print("=" * 70)

    # ---- assertions so this doubles as a regression check -----------------
    assert text is not None, "bundle should render"
    assert "boundary: AWS GovCloud (tenant)" in text, "vsdx must attribute to AWS"
    assert "boundary: Azure Government (tenant)" in text, "svg must attribute to Azure"
    print("PASS: each diagram is attributed to its own tenant.\n")

    # ---- guardrail 1: single-boundary workbook renders NO boundary line ---
    s2 = Session(engine)
    obj2 = _seed_objective(s2)
    wb2 = Workbook(path="C:/wb/demo-single.xlsx", filename="demo-single.xlsx")
    s2.add(wb2)
    s2.commit()
    s2.refresh(wb2)
    s2.add(BoundarySegment(workbook_id=wb2.id, name="On-Prem Enclave"))
    s2.commit()
    ev = _ingest_diagram(s2, VSDX, wb2.id)
    s2.add(EvidenceTag(evidence_id=ev.id, objective_id=obj2.id,
                       relevance=0.9, confidence=0.9, source="manual"))
    s2.commit()
    text2, _p, _o = build_tagged_evidence_with_payload(obj2.id, s2, workbook_id=wb2.id)
    assert text2 is not None and "boundary:" not in text2, (
        "single-boundary workbook must NOT render a boundary line"
    )
    print("PASS: single-boundary workbook renders no boundary line "
          "(prompt-cache stable).")

    # ---- guardrail 2: a BACKFILL link is excluded -> unspecified ----------
    s3 = Session(engine)
    obj3 = _seed_objective(s3)
    wb3 = Workbook(path="C:/wb/demo-backfill.xlsx", filename="demo-backfill.xlsx")
    s3.add(wb3)
    s3.commit()
    s3.refresh(wb3)
    legacy = BoundarySegment(workbook_id=wb3.id, name="boundary")
    other = BoundarySegment(workbook_id=wb3.id, name="Azure Government", kind="tenant")
    s3.add_all([legacy, other])
    s3.commit()
    s3.refresh(legacy)
    ev = _ingest_diagram(s3, VSDX, wb3.id)
    s3.add(EvidenceTag(evidence_id=ev.id, objective_id=obj3.id,
                       relevance=0.9, confidence=0.9, source="manual"))
    s3.add(EvidenceBoundary(evidence_id=ev.id, boundary_segment_id=legacy.id,
                            source=ScopeLinkSource.BACKFILL))
    s3.commit()
    text3, _p, _o = build_tagged_evidence_with_payload(obj3.id, s3, workbook_id=wb3.id)
    assert text3 is not None and f"boundary: {BOUNDARY_UNSPECIFIED}" in text3, (
        "backfilled link must be excluded -> unspecified"
    )
    assert "boundary: boundary" not in text3, "must NOT render the backfilled label"
    print("PASS: BACKFILL link excluded — renders `unspecified`, not the "
          "laundered legacy label.\n")

    print("All boundary-attribution demo checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
