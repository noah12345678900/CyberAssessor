"""One-off: measure the deterministic Tier-5 gate over a raw evidence folder.

WHY THIS EXISTS
---------------
The lever work (B + C, commit e235672) added new deterministic taggers whose
whole purpose is to drive ``judge_invoked / tagger_runs`` (the fraction of
ingested artifacts that reach the LLM Tier-5 judge) below 0.10. The GOCO dev
baseline was 292/391 = 74.7%. We need a *measured* before/after, not reasoning.

KEY REALIZATION
---------------
The judge gate is DETERMINISTIC and fully computable WITHOUT an API key:

    would_invoke = (NOT gate_cleared_by_det) AND text.strip()  [catalog present]

``gate_cleared_by_det = tier1_4_tags >= 2`` is decided by the deterministic
tiers alone; the LLM call only happens AFTER the gate, gated on
``client is not None``. So running ``tag_evidence(..., client=None)`` over the
corpus and counting the would-invoke set gives the exact judge_ratio the real
run would produce — no provider key, no network, no cost.

ISOLATION
---------
Runs against a TEMP COPY of the production sqlite (so the full 922-control /
2793-objective catalog is present) and never touches the original. The copy is
deleted on exit. Nothing is committed to production.

USAGE
-----
    cd backend && uv run --no-sync python ../scripts/measure_judge_ratio.py \
        "C:/Users/Noah.Jaskolski/Downloads/GOCO Dev Artifacts" \
        --framework-id 1 --workbook-id 1
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
    """Copy the live sqlite + WAL/SHM sidecars into a temp dir, return the copy."""
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
    ap.add_argument("folder", help="Folder of raw evidence files to measure over.")
    ap.add_argument("--framework-id", type=int, default=1)
    ap.add_argument("--workbook-id", type=int, default=1)
    ap.add_argument(
        "--label",
        default="HEAD",
        help="Tag for the printed report (e.g. 'pre-levers' / 'HEAD').",
    )
    args = ap.parse_args()

    folder = Path(args.folder)
    if not folder.is_dir():
        print(f"ERROR: not a directory: {folder}", file=sys.stderr)
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="judge_ratio_"))
    try:
        db_copy = _copy_prod_db(tmp)
        engine = create_engine(
            f"sqlite:///{db_copy}",
            connect_args={"check_same_thread": False, "timeout": 60},
        )

        tagger_runs = 0
        det_cleared = 0
        would_invoke = 0
        empty_text = 0
        skipped = 0
        # Per-outcome breakdowns so we can SEE which file kinds dominate the
        # judge-bound set (the docx/pdf narrative hypothesis).
        would_invoke_by_ext: Counter[str] = Counter()
        det_cleared_by_ext: Counter[str] = Counter()

        source = LocalFolderSource(folder, recursive=True)

        with Session(engine) as session:
            # The copied prod DB already holds workbook_id=1's evidence rows,
            # so reusing it collides on the (workbook_id, path) unique index.
            # Create a throwaway workbook with no evidence and ingest under it —
            # the gate is framework-scoped (framework_id arg), not workbook-
            # scoped, so this changes nothing about would_invoke.
            measure_wb = WorkbookModel(
                path=f"measure://judge_ratio/{tmp.name}",
                filename="judge_ratio_measure",
                framework_id=args.framework_id,
            )
            session.add(measure_wb)
            session.flush()
            measure_wb_id = measure_wb.id

            files = list(source.iter_files())
            total = len(files)
            print(f"[measure] {total} files to scan under {folder}", flush=True)
            for i, sf in enumerate(files, start=1):
                name = sf.name
                ext = Path(name).suffix.lower() or "(none)"
                print(
                    f"[{i}/{total}] runs={tagger_runs} det={det_cleared} "
                    f"judge={would_invoke} :: {name}",
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
                        text="",
                        title=Path(name).stem,
                        doc_number=None,
                        kind=infer_kind(name),
                        metadata={"extractor_error": str(exc)},
                    )
                except Exception as exc:  # noqa: BLE001 - mirror ingest resilience
                    doc = ExtractedDoc(
                        text="",
                        title=Path(name).stem,
                        doc_number=None,
                        kind=infer_kind(name),
                        metadata={"unexpected_error": f"{type(exc).__name__}: {exc}"},
                    )

                md = doc.metadata or {}
                kind = doc.kind if isinstance(doc.kind, EvidenceKind) else infer_kind(name)
                sha = hashlib.sha256(sf.uri.encode("utf-8")).hexdigest()
                evidence = Evidence(
                    path=sf.uri,
                    sha256=sha,
                    kind=kind,
                    size_bytes=sf.size or 0,
                    title=doc.title or Path(name).stem,
                    doc_number=doc.doc_number,
                    workbook_id=measure_wb_id,
                )
                session.add(evidence)
                session.flush()  # populate evidence.id for the tagger

                stig_rows = md.get("_stig_findings") or None
                result = tag_evidence(
                    session,
                    evidence,
                    doc.text,
                    stig_findings=stig_rows,
                    cci_refs=md.get("cci_refs"),
                    evidence_type=md.get("evidence_type"),
                    evidence_type_signals=md.get("evidence_type_signals"),
                    framework_id=args.framework_id,
                    client=None,  # deterministic gate only — no LLM call
                    judge_model=None,
                )

                tagger_runs += 1
                has_text = bool(doc.text and doc.text.strip())
                if not has_text:
                    empty_text += 1
                if result.gate_cleared_by_det:
                    det_cleared += 1
                    det_cleared_by_ext[ext] += 1
                elif has_text:
                    # Exact would-invoke: gate not cleared AND text present.
                    # (Catalog is non-empty for framework_id, so the inner
                    # all_by_control guard is always satisfied.)
                    would_invoke += 1
                    would_invoke_by_ext[ext] += 1

            session.rollback()  # discard every write; measurement only

        engine.dispose()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    ratio = would_invoke / tagger_runs if tagger_runs else 0.0
    print(f"\n=== Tier-5 judge-gate measurement [{args.label}] ===")
    print(f"folder         : {folder}")
    print(f"framework_id   : {args.framework_id}")
    print(f"tagger_runs    : {tagger_runs}")
    print(f"det_cleared    : {det_cleared}  ({det_cleared / tagger_runs:.1%})" if tagger_runs else "det_cleared    : 0")
    print(f"would_invoke   : {would_invoke}  (reaches LLM judge)")
    print(f"empty_text     : {empty_text}  (no text → never reaches judge)")
    print(f"skipped(extr)  : {skipped}  (ExtractorSkip; not counted in tagger_runs)")
    print(f"\nJUDGE_RATIO    : {would_invoke}/{tagger_runs} = {ratio:.4f}  ({ratio:.1%})")
    print(f"GOAL           : < 0.10")
    print("\n-- would_invoke by extension (the judge-bound set) --")
    for ext, n in would_invoke_by_ext.most_common():
        print(f"   {ext:8s} {n}")
    print("\n-- det_cleared by extension (served deterministically) --")
    for ext, n in det_cleared_by_ext.most_common():
        print(f"   {ext:8s} {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
