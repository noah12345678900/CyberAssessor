"""Eval harness — replay a real workbook through engine-only / current /
llm-forced modes and report per-bucket verdict agreement.

Answers two questions about a populated workbook (the "oracle"):

    1. Of the rows the engine short-circuited (RULE_8A / RULE_8B / CRM_* /
       RULE_8C / RULE_NO_EVIDENCE / CACHE_HIT), what fraction does an
       LLM-forced rerun agree with? → tells us whether the deterministic
       gates are silently shipping stale verdicts.

    2. On LLM-decided rows (LLM_ACCEPT / LLM_AFTER_RETRY), what does an
       engine-only rerun do? → measures how much "free" determinism is
       still on the table.

Usage:

    cd backend
    uv run --no-sync python ../scripts/eval_workbook.py \
        --workbook-id 1 \
        --modes engine-only,current,llm-forced \
        --sample 20 \
        --stratified-by verdict_source \
        --output ../eval_v1.json

This is a MEASUREMENT TOOL, not a CI gate — costs real Anthropic / OpenAI
tokens on the ``current`` and ``llm-forced`` modes. The single eval
session opens against the production SQLite DB and is rolled back at
the end; no Assessment rows are mutated. Verify by re-checking the
workbook's assessment count after the run.

Engine-only mode uses ``AssertNoCallStub`` — any row that falls through
to the LLM raises ``AssertionError`` (recorded as an error in the per-row
results, not a verdict), which is intentional: it surfaces rows the
engine couldn't decide deterministically without hiding them as
abstains.

All three modes run with ``cache_session=None`` so the decision cache is
never consulted. If we let the ``current`` mode pull cache hits written
by the original assessment run, every row would trivially agree and the
harness would tell us nothing. Bypassing the cache uniformly is the only
way to measure what each mode would freshly produce.
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Make the backend package importable when this script is invoked from
# either repo root or the backend dir. The script lives at
# ``<repo>/scripts/eval_workbook.py``; the backend package lives at
# ``<repo>/backend/cybersecurity_assessor/``.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_BACKEND = _REPO_ROOT / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from sqlmodel import Session, select  # noqa: E402

# Patch ssl to use the OS-native trust store BEFORE any httpx / anthropic
# client is constructed. The sidecar does the same at server.py:13; without
# this, the Anthropic SDK fails on corporate networks with
# "self-signed certificate in certificate chain" because Python's stdlib ssl
# uses certifi's Mozilla bundle (no corp CA). truststore reads Windows
# CertStore directly so anything the OS already trusts just works.
from cybersecurity_assessor import tls as _tls  # noqa: E402

_tls.install()

from cybersecurity_assessor.config import load_config  # noqa: E402
from cybersecurity_assessor.db import engine  # noqa: E402
from cybersecurity_assessor.engine.assessor import Assessor, Decision  # noqa: E402
from cybersecurity_assessor.engine.inputs import (  # noqa: E402
    build_assessment_inputs,
    build_workbook_inputs,
)
from cybersecurity_assessor.llm.client import (  # noqa: E402
    MissingApiKeyError,
    make_client,
)
from cybersecurity_assessor.models import (  # noqa: E402
    Assessment,
    Control,
    Objective,
    VerdictSource,
    Workbook,
)

# Re-use the route's canonical Decision→VerdictSource mapper so the eval's
# new-source classification matches the persistence-layer enum exactly.
# This is the same mapper that wrote the oracle's verdict_source column,
# so oracle-vs-new comparisons are apples-to-apples.
from cybersecurity_assessor.routes.controls import (  # noqa: E402
    _decision_to_verdict_source,
)

# AssertNoCallStub lives in tests/eval/_stubs.py to keep the stub family
# (StubLlmClient, AssertNoCallStub, LlmProposal re-export) together. Add
# tests/ to sys.path so the script can import it without a packaging
# dependency on tests/.
_TESTS = _REPO_ROOT / "tests"
if str(_TESTS) not in sys.path:
    sys.path.insert(0, str(_TESTS))
from eval._stubs import AssertNoCallStub  # noqa: E402

_log = logging.getLogger("eval_workbook")

_VALID_MODES = ("engine-only", "current", "llm-forced")


# ---------------------------------------------------------------------------
# Per-row result container
# ---------------------------------------------------------------------------


@dataclass
class RowResult:
    """One (assessment row × mode) result for the per-row JSON dump.

    Field grouping mirrors the report sections so the JSON is grep-friendly:
    ``oracle_*`` carry the persisted state we're comparing against;
    ``new_*`` carry the fresh decision the mode produced; ``latency_s`` /
    ``error`` are the operational signal.

    ``decision_payload`` is a thin dict the aggregator reads to render the
    disagreement table — narrative excerpt, confidence, source string. We
    don't dump the full ``Decision`` dataclass because its rejection_log
    and dual_narrative_flags can carry several KB per row and the JSON
    output is meant to be human-skimmable on a 312-row run.
    """

    objective_id: str
    excel_row: int | None
    control_id: str | None
    mode: str
    oracle_status: str | None
    oracle_verdict_source: str | None
    oracle_needs_review: bool
    new_status: str | None
    new_verdict_source: str | None
    latency_s: float
    error: str | None = None
    decision_payload: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Oracle loading
# ---------------------------------------------------------------------------


@dataclass
class OracleRow:
    """One trusted Assessment row, plus the join data the harness needs."""

    assessment_id: int
    objective_pk: int
    objective_cci_id: str
    excel_row: int | None
    control_id: str | None
    status: str
    verdict_source: str | None
    needs_review: bool


def load_oracle_rows(session: Session, workbook_id: int) -> list[OracleRow]:
    """Pull every trusted (``needs_review=False``) Assessment row for a
    workbook, joined to Objective + Control so the harness can rebuild the
    per-CCI inputs without round-tripping back to the DB per row.

    Reject-rows with ``needs_review=True`` are EXCLUDED — those are
    abstains the operator hasn't validated; comparing against them would
    measure stub vs. stub, not engine vs. oracle.
    """
    stmt = (
        select(Assessment, Objective, Control)
        .join(Objective, Objective.id == Assessment.objective_id)  # type: ignore[arg-type]
        .join(Control, Control.id == Objective.control_id_fk)  # type: ignore[arg-type]
        .where(Assessment.workbook_id == workbook_id)
        .where(Assessment.needs_review.is_(False))  # type: ignore[union-attr]
    )
    out: list[OracleRow] = []
    for ass, obj, ctrl in session.exec(stmt).all():
        out.append(
            OracleRow(
                assessment_id=ass.id,  # type: ignore[arg-type]
                objective_pk=obj.id,  # type: ignore[arg-type]
                objective_cci_id=obj.objective_id,
                excel_row=ass.excel_row,
                control_id=ctrl.control_id,
                status=ass.status.value if hasattr(ass.status, "value") else str(ass.status),
                verdict_source=(
                    ass.verdict_source.value
                    if ass.verdict_source is not None
                    else None
                ),
                needs_review=ass.needs_review,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Stratified sampling
# ---------------------------------------------------------------------------


def stratified_sample(
    rows: list[OracleRow],
    *,
    sample_per_bucket: int | None,
    stratified_by: str,
    seed: int = 42,
) -> list[OracleRow]:
    """Pick up to ``sample_per_bucket`` rows per ``stratified_by`` bucket.

    When ``sample_per_bucket`` is None (no ``--sample`` flag), return
    every row unchanged — the operator wants the full workbook.

    Deterministic on ``seed`` so reruns with the same args sample the
    same rows and the eval report is reproducible. Buckets with fewer
    than ``sample_per_bucket`` rows contribute all rows they have (no
    upsampling, no dropping).
    """
    if sample_per_bucket is None:
        return rows
    rng = random.Random(seed)
    buckets: dict[str, list[OracleRow]] = defaultdict(list)
    for r in rows:
        key = _bucket_key(r, stratified_by)
        buckets[key].append(r)
    sampled: list[OracleRow] = []
    for key, bucket in buckets.items():
        if len(bucket) <= sample_per_bucket:
            sampled.extend(bucket)
        else:
            sampled.extend(rng.sample(bucket, sample_per_bucket))
    # Stable order on (control_id, excel_row) so the report reads in
    # workbook order regardless of bucket-iteration order.
    sampled.sort(key=lambda r: (r.control_id or "", r.excel_row or 0))
    return sampled


def _bucket_key(row: OracleRow, stratified_by: str) -> str:
    if stratified_by == "verdict_source":
        return row.verdict_source or "<none>"
    if stratified_by == "status":
        return row.status
    if stratified_by == "control_family":
        # First two chars before the dash; "AC-2(1)" -> "AC"
        cid = row.control_id or ""
        return cid.split("-", 1)[0] if "-" in cid else cid or "<none>"
    # Fall back to a single bucket so caller's choice typo doesn't fan out.
    return "<all>"


# ---------------------------------------------------------------------------
# Per-mode assessor wiring
# ---------------------------------------------------------------------------


def build_assessor_for_mode(mode: str) -> Assessor:
    """Construct the ``Assessor`` for one mode.

    ``cache_session=None`` for ALL modes — see module docstring. Cache
    behavior is itself a thing under measurement (CACHE_HIT vs. fresh
    LLM agreement), so we don't want the cache to satisfy lookups
    inside the eval harness.
    """
    if mode == "engine-only":
        return Assessor(llm=AssertNoCallStub(), cache_session=None)
    # Both ``current`` and ``llm-forced`` need a live client; the
    # ``force_llm`` toggle is per-call on assess(), not on the Assessor
    # constructor, so the same instance can drive both modes if we
    # wanted. We build a fresh one per mode anyway so the LLM client's
    # internal session state (HTTP keepalive pool, prompt cache key)
    # is mode-isolated and a transient HTTP failure on one mode doesn't
    # poison the other.
    cfg = load_config()
    try:
        client = make_client(cfg)
    except MissingApiKeyError as e:
        raise SystemExit(
            f"Mode {mode!r} needs an LLM client but the API key is missing.\n"
            f"  {e}\n"
            "Set the key in Settings (Windows Credential Manager) before rerunning,\n"
            "or pass --modes engine-only to skip LLM-backed modes."
        ) from e
    return Assessor(llm=client, cache_session=None)


# ---------------------------------------------------------------------------
# Per-row eval
# ---------------------------------------------------------------------------


def assess_one(
    *,
    assessor: Assessor,
    mode: str,
    oracle: OracleRow,
    workbook_inputs,
    workbook_id: int,
    session: Session,
) -> RowResult:
    """Run one (mode × oracle row) and capture the outcome.

    Catches every exception from the assessor so one failure can't take
    down the run. Engine-only mode raises ``AssertionError`` on rows
    that need the LLM — that's recorded as an error string, not a
    silent abstain.
    """
    common = dict(
        objective_id=oracle.objective_cci_id,
        excel_row=oracle.excel_row,
        control_id=oracle.control_id,
        mode=mode,
        oracle_status=oracle.status,
        oracle_verdict_source=oracle.verdict_source,
        oracle_needs_review=oracle.needs_review,
    )

    inputs = build_assessment_inputs(
        workbook_inputs=workbook_inputs,
        objective_pk=oracle.objective_pk,
        objective_cci_id=oracle.objective_cci_id,
        control_id=oracle.control_id,
        session=session,
    )
    if inputs is None:
        # The CCI is no longer in the workbook (manual edit / framework
        # swap). Same outcome the production batch loop emits as a skip.
        return RowResult(
            **common,
            new_status=None,
            new_verdict_source=None,
            latency_s=0.0,
            error="not_in_workbook",
        )

    started = time.perf_counter()
    try:
        decision = assessor.assess(
            inputs.row,
            tagged_evidence=inputs.evidence_block.text,
            evidence_block=inputs.evidence_block,
            crm_context=inputs.crm_context,
            workbook_id=workbook_id,
            force_llm=(mode == "llm-forced"),
        )
    except AssertionError as e:
        # AssertNoCallStub raises this when engine-only falls through to
        # the LLM. Surface as a typed error so the aggregator can flag
        # "engine couldn't decide" rows separately from real failures.
        return RowResult(
            **common,
            new_status=None,
            new_verdict_source=None,
            latency_s=time.perf_counter() - started,
            error=f"engine_only_fellthrough: {e}",
        )
    except Exception as e:  # noqa: BLE001 — keep eval alive
        _log.exception(
            "eval: assess raised on cci=%s mode=%s", oracle.objective_cci_id, mode,
        )
        return RowResult(
            **common,
            new_status=None,
            new_verdict_source=None,
            latency_s=time.perf_counter() - started,
            error=f"{type(e).__name__}: {e}",
        )

    latency = time.perf_counter() - started
    new_source = _decision_to_verdict_source(decision)
    payload = _decision_payload(decision)
    new_status = (
        decision.status.value if decision.status is not None else None
    )
    return RowResult(
        **common,
        new_status=new_status,
        new_verdict_source=new_source.value if new_source is not None else None,
        latency_s=latency,
        error=None,
        decision_payload=payload,
    )


def _decision_payload(decision: Decision) -> dict[str, Any]:
    """Thin dict for the JSON dump — narrative excerpt + provenance.

    Truncates the narrative because a full LLM narrative can be a
    paragraph, and the disagreement table is meant to be scannable.
    Full narrative is recoverable from the workbook if the reviewer
    wants to dig deeper.
    """
    narr = decision.narrative or ""
    excerpt = narr if len(narr) <= 600 else narr[:600] + "…"
    return {
        "source": decision.source,
        "cache_source": getattr(decision, "cache_source", None),
        "needs_review": getattr(decision, "needs_review", False),
        "review_reason": getattr(decision, "review_reason", None),
        "confidence": getattr(decision, "confidence", None),
        "narrative_excerpt": excerpt,
        "rule": getattr(decision, "rule", None),
    }


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def aggregate(results: list[RowResult]) -> dict[str, Any]:
    """Build the per-bucket agreement matrix used by both the console
    table and the JSON dump.

    Bucket key = oracle's ``verdict_source`` (None → ``<none>``). For
    each bucket × mode we compute:
      * n: rows attempted
      * agree: new_status equals oracle_status (status-level agreement;
        source-level changes within the same status — e.g., engine sees
        LLM_ACCEPT, llm-forced still LLM_ACCEPT — don't count as a
        disagreement)
      * errors: rows where the mode failed (engine-only fell through,
        or LLM raised)
      * latency_total / cost / tokens: operational totals — only
        latency is populated in v1 (tokens / cost would need a recorder
        wrapper that doesn't commit AssessmentRun rows; deferred)
    """
    by_bucket: dict[str, dict[str, dict[str, Any]]] = defaultdict(
        lambda: defaultdict(lambda: {"n": 0, "agree": 0, "errors": 0, "latency_total": 0.0})
    )
    for r in results:
        bucket = r.oracle_verdict_source or "<none>"
        slot = by_bucket[bucket][r.mode]
        slot["n"] += 1
        slot["latency_total"] += r.latency_s
        if r.error is not None:
            slot["errors"] += 1
            continue
        if r.new_status is not None and r.new_status == r.oracle_status:
            slot["agree"] += 1
    return {
        bucket: {mode: dict(stats) for mode, stats in modes.items()}
        for bucket, modes in by_bucket.items()
    }


def disagreement_rows(results: list[RowResult]) -> list[dict[str, Any]]:
    """Rows where some mode disagreed with the oracle status — the
    eyeball-this section. Engine-only fall-through errors are NOT
    disagreements (they're "couldn't decide"), so they're filtered out
    here and surfaced in the error column of the per-bucket table.
    """
    out: list[dict[str, Any]] = []
    for r in results:
        if r.error is not None:
            continue
        if r.new_status is None:
            continue
        if r.new_status == r.oracle_status:
            continue
        out.append(
            {
                "cci": r.objective_id,
                "control_id": r.control_id,
                "excel_row": r.excel_row,
                "mode": r.mode,
                "oracle_status": r.oracle_status,
                "oracle_verdict_source": r.oracle_verdict_source,
                "new_status": r.new_status,
                "new_verdict_source": r.new_verdict_source,
                "narrative_excerpt": r.decision_payload.get("narrative_excerpt"),
                "confidence": r.decision_payload.get("confidence"),
                "review_reason": r.decision_payload.get("review_reason"),
            }
        )
    return out


# ---------------------------------------------------------------------------
# Console rendering
# ---------------------------------------------------------------------------


def render_table(
    agg: dict[str, Any],
    modes: list[str],
    *,
    oracle_counts: Counter[str],
) -> str:
    """Render the per-bucket agreement matrix as a fixed-width table.

    Engine-only's 0% agreement on LLM_ACCEPT buckets is annotated with
    ``*`` because it's structural, not a bug — that mode physically
    can't produce an LLM verdict.
    """
    lines: list[str] = []
    header = f"{'oracle verdict_source':<24} {'N':>4}"
    for mode in modes:
        header += f" │ {mode:<26}"
    lines.append(header)
    lines.append("─" * len(header))
    # Buckets sorted by N desc so the dominant verdict source is at top.
    sorted_buckets = sorted(
        agg.keys(),
        key=lambda b: oracle_counts.get(b, 0),
        reverse=True,
    )
    for bucket in sorted_buckets:
        row = f"{bucket:<24} {oracle_counts.get(bucket, 0):>4}"
        for mode in modes:
            stats = agg[bucket].get(mode)
            if stats is None:
                cell = "n/a"
            else:
                n = stats["n"]
                agree = stats["agree"]
                errors = stats["errors"]
                pct = (agree / n * 100.0) if n else 0.0
                cell = f"{agree}/{n} ({pct:.1f}%)"
                if errors:
                    cell += f" err={errors}"
                if mode == "engine-only" and bucket in (
                    "llm_accept",
                    "llm_after_retry",
                    "abstain",
                ):
                    cell += " *"
            row += f" │ {cell:<26}"
        lines.append(row)
    lines.append("")
    lines.append(
        "* engine-only structurally cannot produce LLM verdicts → "
        "0% agreement on LLM_* / ABSTAIN buckets is expected, not a bug."
    )
    return "\n".join(lines)


def render_disagreements(disagreements: list[dict[str, Any]]) -> str:
    if not disagreements:
        return "\n(no disagreements — every mode agreed with the oracle on every row)"
    out = ["", "Disagreements (sorted by mode → CCI):", "─" * 80]
    sorted_d = sorted(
        disagreements, key=lambda d: (d["mode"], d["control_id"] or "", d["cci"])
    )
    for d in sorted_d:
        out.append(
            f"[{d['mode']:<11}] {d['cci']:<12} ({d['control_id']}) "
            f"row={d['excel_row']}"
        )
        out.append(
            f"  oracle:  status={d['oracle_status']:<14} "
            f"source={d['oracle_verdict_source']}"
        )
        out.append(
            f"  new:     status={d['new_status']:<14} "
            f"source={d['new_verdict_source']} "
            f"conf={d['confidence']}"
        )
        if d.get("review_reason"):
            out.append(f"  reason:  {d['review_reason']}")
        narr = d.get("narrative_excerpt")
        if narr:
            out.append(f"  excerpt: {narr}")
        out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--workbook-id", type=int, required=True,
        help="ID of the assessed workbook to replay (must exist in DB).",
    )
    p.add_argument(
        "--modes",
        type=str,
        default="engine-only,current,llm-forced",
        help=(
            "Comma-separated modes to run. Valid: "
            + ", ".join(_VALID_MODES)
            + " (default: all three)."
        ),
    )
    p.add_argument(
        "--sample", type=int, default=None,
        help=(
            "Per-bucket sample size for stratified sampling. Default: every "
            "trusted row (no sampling). Use small numbers (5-20) for cheap "
            "smoke runs."
        ),
    )
    p.add_argument(
        "--stratified-by",
        type=str,
        default="verdict_source",
        choices=["verdict_source", "status", "control_family"],
        help="Bucket key for --sample. Default: verdict_source.",
    )
    p.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for sampling (default 42 — runs are reproducible).",
    )
    p.add_argument(
        "--output", type=str, default=None,
        help=(
            "Optional path for the JSON dump (per-row results + aggregates "
            "+ disagreements). Console table is always emitted."
        ),
    )
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable INFO-level logging on the harness logger.",
    )
    args = p.parse_args(argv)
    args.modes_list = [m.strip() for m in args.modes.split(",") if m.strip()]
    bad = [m for m in args.modes_list if m not in _VALID_MODES]
    if bad:
        p.error(f"Unknown mode(s): {bad}. Valid: {list(_VALID_MODES)}")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    # The aggregation table uses Unicode box-drawing chars (U+2500 family).
    # Windows' default console encoding is cp1252 which can't encode them;
    # reconfigure stdout/stderr to UTF-8 so render_table()'s print() doesn't
    # crash with UnicodeEncodeError on Windows. No-op on POSIX (already UTF-8)
    # and on Windows terminals already configured for UTF-8.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8")
            except Exception:  # pragma: no cover — best-effort, never fatal
                pass
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    # Open ONE Session, do NOT commit, roll back at exit. Every write
    # the kernel might perform (RunRecorder rows, decision cache stores)
    # is silenced by passing cache_session=None and skipping RunRecorder;
    # this rollback is defense-in-depth in case anything slips through.
    session = Session(engine)
    try:
        wb = session.get(Workbook, args.workbook_id)
        if wb is None:
            print(f"ERROR: workbook_id={args.workbook_id} not found", file=sys.stderr)
            return 2
        wb_path = Path(wb.path)
        if not wb_path.exists():
            print(
                f"ERROR: workbook file missing on disk: {wb.path}",
                file=sys.stderr,
            )
            return 2

        print(
            f"Loading oracle from workbook_id={args.workbook_id} "
            f"({wb_path.name})..."
        )
        oracle_rows = load_oracle_rows(session, args.workbook_id)
        print(f"  {len(oracle_rows)} trusted Assessment rows (needs_review=False)")
        if not oracle_rows:
            print(
                "No trusted rows to evaluate. Either the workbook hasn't been "
                "assessed yet, or every row was flagged needs_review.",
                file=sys.stderr,
            )
            return 1

        sampled = stratified_sample(
            oracle_rows,
            sample_per_bucket=args.sample,
            stratified_by=args.stratified_by,
            seed=args.seed,
        )
        oracle_counts = Counter(_bucket_key(r, args.stratified_by) for r in sampled)
        print(
            f"  sampling {len(sampled)} row(s) across "
            f"{len(oracle_counts)} bucket(s) "
            f"(stratified-by={args.stratified_by}, sample={args.sample})"
        )

        print("Building workbook inputs (CCIS index + CRM context)...")
        wb_inputs = build_workbook_inputs(args.workbook_id, wb_path, session)

        all_results: list[RowResult] = []
        for mode in args.modes_list:
            print(f"\n=== Mode: {mode} ===")
            assessor = build_assessor_for_mode(mode)
            mode_started = time.perf_counter()
            for i, row in enumerate(sampled, start=1):
                if args.verbose or i % 25 == 0 or i == len(sampled):
                    print(
                        f"  [{i}/{len(sampled)}] {row.objective_cci_id} "
                        f"({row.control_id})"
                    )
                result = assess_one(
                    assessor=assessor,
                    mode=mode,
                    oracle=row,
                    workbook_inputs=wb_inputs,
                    workbook_id=args.workbook_id,
                    session=session,
                )
                all_results.append(result)
            elapsed = time.perf_counter() - mode_started
            print(f"  mode={mode} done in {elapsed:.1f}s")

        agg = aggregate(all_results)
        disagreements = disagreement_rows(all_results)
        print("\n" + "=" * 80)
        print("Per-bucket agreement matrix")
        print("=" * 80)
        print(render_table(agg, args.modes_list, oracle_counts=oracle_counts))
        print(render_disagreements(disagreements))

        if args.output:
            payload = {
                "workbook_id": args.workbook_id,
                "workbook_path": str(wb_path),
                "modes": args.modes_list,
                "sample": args.sample,
                "stratified_by": args.stratified_by,
                "seed": args.seed,
                "oracle_total": len(oracle_rows),
                "sampled_total": len(sampled),
                "results": [r.__dict__ for r in all_results],
                "aggregates": agg,
                "disagreements": disagreements,
            }
            Path(args.output).write_text(
                json.dumps(payload, indent=2, default=str), encoding="utf-8"
            )
            print(f"\nWrote JSON dump → {args.output}")
        return 0
    finally:
        # Rollback any uncommitted state. The CLI deliberately avoids
        # session.commit() anywhere in its own code, so this rollback
        # discards anything the kernel staged (defensive — kernel paths
        # with cache_session=None and no RunRecorder should stage nothing).
        try:
            session.rollback()
        finally:
            session.close()


if __name__ == "__main__":
    raise SystemExit(main())
