"""One-off: tally per-tier TAG COUNTS over a raw evidence folder.

WHY THIS EXISTS
---------------
The user wants a deterministic-vs-LLM tag-COUNT comparison ("is the number of
tags from each consistent... betting the LLM is going to have more"). This
script runs the deterministic side EXACTLY and for free (client=None, no
network), summing the per-tier hit counts the tagger already reports on
``TaggingResult``:

    Tier 1  doc_number_hits      (exact program doc-number match)
    Tier 2  cci_hits             (explicit CCI / control-ID string match)
    Tier 3  control_id_hits      (bounded-by-control matches)
    Tier 4  evidence_type_hits   (content-classified xlsx auto-mapping)
    -- deterministic gate --
    Tier 5  llm_hits             (judge-accepted; ZERO here because client=None)

The LLM tier (5) never fires with client=None, so its exact corpus total needs
the slow ~292-doc judged pass. This script reports the deterministic totals
exactly and the LLM-eligible population (docs that fall through the gate), so
the LLM count can be bounded from the capture-sample accept rate.

ISOLATION: temp copy of prod sqlite, rollback, deleted on exit. ASCII-only
output (Windows cp1252 console).

USAGE
-----
    cd backend && uv run --no-sync python ../scripts/measure_tag_counts.py \
        "C:/Users/Noah.Jaskolski/Downloads/GOCO Dev Artifacts" --framework-id 1
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from sqlmodel import Session, create_engine  # noqa: E402

from cybersecurity_assessor import models  # noqa: F401,E402 -- registers tables
from cybersecurity_assessor.config import db_path  # noqa: E402
from cybersecurity_assessor.evidence.extractors import (  # noqa: E402
    ExtractedDoc,
    ExtractorError,
    ExtractorSkip,
    extract_stream,
    infer_kind,
)
from cybersecurity_assessor.evidence.sources import LocalFolderSource  # noqa: E402
from cybersecurity_assessor.models import Evidence, EvidenceKind  # noqa: E402
from cybersecurity_assessor.models import Workbook as WorkbookModel  # noqa: E402
from cybersecurity_assessor.evidence.tagger import tag_evidence  # noqa: E402


def _copy_prod_db(dst_dir: Path) -> Path:
    src = db_path()
    dst = dst_dir / "measure.sqlite"
    shutil.copy2(src, dst)
    for suffix in ("-wal", "-shm"):
        side = Path(str(src) + suffix)
        if side.exists():
            shutil.copy2(side, Path(str(dst) + suffix))
    return dst


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("folder")
    ap.add_argument("--framework-id", type=int, default=1)
    args = ap.parse_args()

    folder = Path(args.folder)
    if not folder.is_dir():
        print(f"ERROR: not a directory: {folder}", file=sys.stderr)
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="tag_counts_"))
    try:
        db_copy = _copy_prod_db(tmp)
        engine = create_engine(
            f"sqlite:///{db_copy}",
            connect_args={"check_same_thread": False, "timeout": 60},
        )

        runs = 0
        empty_text = 0
        skipped = 0
        # Per-tier deterministic tag totals (summed over the corpus).
        t1 = t2 = t3 = t4 = 0
        det_total = 0
        gate_cleared = 0      # docs fully served by deterministic tiers
        llm_eligible = 0      # docs that fall through gate AND have text -> reach judge
        # Distribution of how many deterministic tags land per doc.
        det_per_doc: Counter[int] = Counter()

        source = LocalFolderSource(folder, recursive=True)

        with Session(engine) as session:
            measure_wb = WorkbookModel(
                path=f"measure://tag_counts/{tmp.name}",
                filename="tag_counts_measure",
                framework_id=args.framework_id,
            )
            session.add(measure_wb)
            session.flush()
            measure_wb_id = measure_wb.id

            files = list(source.iter_files())
            total = len(files)
            print(f"[measure] {total} files under {folder}", flush=True)
            for i, sf in enumerate(files, start=1):
                name = sf.name
                print(
                    f"[{i}/{total}] runs={runs} det_tags={det_total} "
                    f"cleared={gate_cleared} llm_elig={llm_eligible} :: {name}",
                    flush=True,
                )
                try:
                    with sf.open() as stream:
                        doc: ExtractedDoc = extract_stream(stream, name)
                except ExtractorSkip:
                    skipped += 1
                    continue
                except ExtractorError as exc:
                    doc = ExtractedDoc(
                        text="", title=Path(name).stem, doc_number=None,
                        kind=infer_kind(name), metadata={"extractor_error": str(exc)},
                    )
                except Exception as exc:  # noqa: BLE001
                    doc = ExtractedDoc(
                        text="", title=Path(name).stem, doc_number=None,
                        kind=infer_kind(name),
                        metadata={"unexpected_error": f"{type(exc).__name__}: {exc}"},
                    )

                md = doc.metadata or {}
                kind = doc.kind if isinstance(doc.kind, EvidenceKind) else infer_kind(name)
                sha = hashlib.sha256(sf.uri.encode("utf-8")).hexdigest()
                evidence = Evidence(
                    path=sf.uri, sha256=sha, kind=kind, size_bytes=sf.size or 0,
                    title=doc.title or Path(name).stem, doc_number=doc.doc_number,
                    workbook_id=measure_wb_id,
                )
                session.add(evidence)
                session.flush()

                stig_rows = md.get("_stig_findings") or None
                result = tag_evidence(
                    session, evidence, doc.text,
                    stig_findings=stig_rows,
                    cci_refs=md.get("cci_refs"),
                    evidence_type=md.get("evidence_type"),
                    evidence_type_signals=md.get("evidence_type_signals"),
                    framework_id=args.framework_id,
                    client=None,        # deterministic only
                    judge_model=None,
                )

                runs += 1
                has_text = bool(doc.text and doc.text.strip())
                if not has_text:
                    empty_text += 1

                t1 += result.doc_number_hits
                t2 += result.cci_hits
                t3 += result.control_id_hits
                t4 += result.evidence_type_hits
                doc_det = (
                    result.doc_number_hits + result.cci_hits
                    + result.control_id_hits + result.evidence_type_hits
                )
                det_total += doc_det
                det_per_doc[doc_det] += 1

                if result.gate_cleared_by_det:
                    gate_cleared += 1
                elif has_text:
                    llm_eligible += 1

            session.rollback()
        engine.dispose()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n=== Deterministic per-tier tag tally [GOCO] ===")
    print(f"folder        : {folder}")
    print(f"framework_id  : {args.framework_id}")
    print(f"docs tagged   : {runs}")
    print(f"empty_text    : {empty_text}")
    print(f"skipped(extr) : {skipped}")
    print("\n-- deterministic tags by tier (exact) --")
    print(f"  T1 doc_number_hits   : {t1}")
    print(f"  T2 cci_hits          : {t2}")
    print(f"  T3 control_id_hits   : {t3}")
    print(f"  T4 evidence_type_hits: {t4}")
    print(f"  DET TOTAL            : {det_total}")
    avg = det_total / runs if runs else 0.0
    print(f"  det tags / doc (avg) : {avg:.2f}")
    print("\n-- gate split --")
    print(f"  cleared by det (>=2) : {gate_cleared}")
    print(f"  LLM-eligible (judge) : {llm_eligible}")
    print("\n-- deterministic tags-per-doc distribution --")
    for k in sorted(det_per_doc):
        print(f"  {k:>3} tag(s): {det_per_doc[k]} docs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
