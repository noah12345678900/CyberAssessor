"""A/B replay harness for the Rule-#12 calibration block (v2 — full pipeline).

FAITHFULNESS CONTRACT (addresses adversarial review BLOCKER 1 & 2)
-----------------------------------------------------------------
v1 scored the RAW LLM status via ``_call_with_user_message`` — that skipped the
production finalization pipeline (validator, confidence<0.35 -> needs_review,
NA-guard retry, supersession). v2 calls the REAL ``Assessor.assess()`` so the
scored verdict is what production would actually SHIP, including needs_review.

  * Row + evidence are rebuilt with PRODUCTION builders, not reimplemented:
    ``read_workbook_index(wb.path).by_cci()`` -> CcisRow (same as the route),
    ``routes.controls._build_evidence_block(...)`` -> EvidenceBlock (same join).
  * The ONLY variable between arms is the system prompt:
        arm A = assess_control.md verbatim (shipped)
        arm B = assess_control.md + _calibration_block.md
  * ``cache_session=None`` so the decision cache NEVER short-circuits a sample —
    every one of the N runs is a fresh LLM call (KERNEL_VERSION/PROMPT_SHA would
    otherwise replay a cached verdict and collapse the distribution).
  * DUAL_PASS_ENABLED is False in production (verified assessor.py:481) so a
    single propose() + validator loop is the faithful path — no challenger.

SAMPLING (addresses MAJOR 3)
  N samples per arm (default 21). A verdict counts as a STABLE mode only at a
  >= 2/3 supermajority; sub-supermajority is reported as "unstable" and blocks
  the ship gate (we don't call a flip on noise). Ties never silently resolve.

SCORING (addresses MAJOR 4)
  Ground truth: _ab_labels.json (locked, per FULL procedure). Production status
  maps COMPLIANT/NON_COMPLIANT/NOT_APPLICABLE plus a distinct NEEDS_REVIEW.
  - defect_*: recovered = calibrated stable-mode == label AND baseline != label.
  - agreement (locked + sampled guards): regression = calibrated stable-mode
    diverges from baseline stable-mode when baseline matched the guard truth.
    A guard whose BASELINE is unstable/off-truth is reported in its own bucket
    (baseline_unstable / baseline_off_truth), never silently dropped.

SHIP GATE: recovered > 0 AND regressions == 0 AND no unstable calibrated verdict
on any defect/guard case.

USAGE
    cd backend
    .venv/Scripts/python.exe scripts/ab_calibration.py --runs 21 \
        --agreement-sample 40 [--model gpt-5.6-sol] [--out scripts/_ab_result.json]
    # quick smoke:
    .venv/Scripts/python.exe scripts/ab_calibration.py --runs 3 --agreement-sample 0
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

_BACKEND = Path(__file__).resolve().parents[1]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))
_HERE = Path(__file__).resolve().parent

from sqlmodel import Session, select  # noqa: E402

from cybersecurity_assessor import config as cfg  # noqa: E402
from cybersecurity_assessor import models  # noqa: F401,E402
from cybersecurity_assessor import tls  # noqa: E402
from cybersecurity_assessor.db import engine as _ENGINE  # noqa: E402
from cybersecurity_assessor.engine.assessor import Assessor  # noqa: E402
from cybersecurity_assessor.engine.crm_context import build_crm_context  # noqa: E402
from cybersecurity_assessor.excel.ccis_reader import read_workbook_index  # noqa: E402
from cybersecurity_assessor.models import Assessment, Objective, Workbook  # noqa: E402
from cybersecurity_assessor.routes.controls import (  # noqa: E402
    _build_evidence_block,
)
from cybersecurity_assessor.system_context import build_boundary_brief  # noqa: E402


def get_engine():
    return _ENGINE

_STATUS_CANON = {
    "COMPLIANT": "Compliant", "NON_COMPLIANT": "Non-Compliant",
    "NOT_APPLICABLE": "Not Applicable",
    "Compliant": "Compliant", "Non-Compliant": "Non-Compliant",
    "Not Applicable": "Not Applicable",
}
_NEEDS_REVIEW = "Needs-Review"


def _canon(s: str | None) -> str | None:
    return _STATUS_CANON.get(s, s) if s is not None else None


def _decision_status(d) -> str:
    """Map a Decision to the FINALIZED, production-shipped verdict label."""
    if getattr(d, "needs_review", False):
        return _NEEDS_REVIEW
    st = getattr(d, "status", None)
    if st is None:
        return _NEEDS_REVIEW
    return _canon(st.value if hasattr(st, "value") else str(st))


def _stable_mode(statuses: list[str], n: int) -> tuple[str | None, bool, dict]:
    """Return (mode, is_stable, distribution). Stable = mode has >= 2/3 of the
    NON-ERROR samples AND is a strict plurality (no tie at the top)."""
    real = [s for s in statuses if s != "ERROR"]
    dist = dict(Counter(statuses))
    if not real:
        return None, False, dist
    c = Counter(real).most_common()
    top_label, top_n = c[0]
    tie = len(c) > 1 and c[1][1] == top_n
    stable = (not tie) and (top_n >= (2 * len(real) + 2) // 3)  # ceil(2/3 n)
    return top_label, stable, dist


def _build_clients(model: str, max_tokens: int):
    tls.install()
    from openai import OpenAI
    from cybersecurity_assessor.llm.client import OpenAIClient, _load_system_prompt

    base, tok = cfg.resolve_openai_endpoint()
    if not tok:
        raise SystemExit("no OpenAI gateway token resolved — is the keyring set?")
    sdk = OpenAI(base_url=base, api_key=tok, max_retries=3, timeout=240)

    baseline_prompt = _load_system_prompt()
    block = (_HERE / "_calibration_block.md").read_text(encoding="utf-8")
    calibrated_prompt = baseline_prompt.rstrip() + "\n" + block
    arm_a = OpenAIClient(model=model, _sdk_client=sdk,
                         system_prompt=baseline_prompt, max_tokens=max_tokens)
    arm_b = OpenAIClient(model=model, _sdk_client=sdk,
                         system_prompt=calibrated_prompt, max_tokens=max_tokens)
    return arm_a, arm_b, baseline_prompt, calibrated_prompt


# thread-local Session for evidence builds (SQLModel Session isn't thread-safe)
_tl = threading.local()


def _session() -> Session:
    s = getattr(_tl, "s", None)
    if s is None:
        s = Session(get_engine())
        _tl.s = s
    return s


def _prep_case(wb_id: int, cci_to_row: dict, cci: str) -> dict | None:
    """Rebuild (row, evidence_block, crm_context, boundary_brief) via production
    builders on a thread-local session. Returns None if the CCI isn't present."""
    s = _session()
    obj = s.exec(select(Objective).where(Objective.objective_id == cci)).first()
    if obj is None:
        return None
    row = cci_to_row.get(cci)
    if row is None:
        return None
    ev = _build_evidence_block(objective_pk=obj.id, control_id=row.control_id,
                               workbook_id=wb_id, s=s)
    crm = build_crm_context(wb_id, s)
    try:
        bb = build_boundary_brief(wb_id, s, scope_labels=crm.scope_labels())
    except Exception:  # noqa: BLE001
        bb = None
    return {"row": row, "ev": ev, "crm": crm, "bb": bb}


def _assess_once(client, prep: dict) -> str:
    """One faithful production assess() with cache disabled. Returns finalized
    status label (incl. Needs-Review)."""
    assessor = Assessor(llm=client, cache_session=None)  # NO cache -> real re-run
    try:
        d = assessor.assess(
            prep["row"],
            tagged_evidence=prep["ev"].text,
            evidence_block=prep["ev"],
            crm_context=prep["crm"],
            boundary_brief=prep["bb"],
            workbook_id=None,
        )
        return _decision_status(d)
    except Exception as exc:  # noqa: BLE001
        return "ERROR"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--runs", type=int, default=21)
    ap.add_argument("--model", default="gpt-5.6-sol")
    ap.add_argument("--max-tokens", type=int, default=32000)
    ap.add_argument("--agreement-sample", type=int, default=40)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--workers", type=int, default=5)
    ap.add_argument("--labels", default="_ab_labels.json")
    ap.add_argument("--out", default="scripts/_ab_result.json")
    args = ap.parse_args()

    labels = json.loads((_HERE / args.labels).read_text())["cases"]
    main_s = Session(get_engine())
    wb = main_s.get(Workbook, 1)
    if wb is None or not wb.path:
        raise SystemExit("workbook 1 not found / no path")
    index = read_workbook_index(Path(wb.path))
    cci_to_row = index.by_cci()

    flip_ccis = {c["cci"] for c in json.loads((_HERE / "_flip_detail.json").read_text())}

    # ---- case list: locked labels + stratified agreement guards ----
    cases: list[dict[str, Any]] = []
    for c in labels:
        cases.append(dict(c))
    if args.agreement_sample > 0:
        rows = main_s.exec(
            select(Assessment, Objective).join(Objective, Objective.id == Assessment.objective_id)  # type: ignore
        ).all()
        pool = []
        for a, o in rows:
            st = _canon(a.status)
            if a.needs_review or st not in ("Compliant", "Non-Compliant", "Not Applicable"):
                continue
            if o.objective_id in flip_ccis:
                continue
            pool.append({"cci": o.objective_id, "ap": o.objective_id, "aid": a.id,
                         "status": st, "category": "agreement_sampled",
                         "group": "regression_guard", "note": "both-engine agreement"})
        # stratify by status so guards aren't all Compliant
        random.Random(args.seed).shuffle(pool)
        by_status: dict[str, list] = {}
        for p in pool:
            by_status.setdefault(p["status"], []).append(p)
        picked, i = [], 0
        order = sorted(by_status)
        while len(picked) < args.agreement_sample and any(by_status.values()):
            k = order[i % len(order)]
            if by_status[k]:
                picked.append(by_status[k].pop())
            i += 1
        cases.extend(picked)
        print(f"added {len(picked)} stratified agreement guards "
              f"({Counter(p['status'] for p in picked)})")

    # prep all cases (serial, thread-local session on main thread)
    prepped = []
    for c in cases:
        p = _prep_case(1, cci_to_row, c["cci"])
        if p is None:
            print(f"WARN cannot prep {c['cci']} — skipping")
            continue
        prepped.append((c, p))
    print(f"prepped {len(prepped)}/{len(cases)} cases")

    arm_a, arm_b, base_p, cal_p = _build_clients(args.model, args.max_tokens)
    print(f"baseline {len(base_p)}c | calibrated {len(cal_p)}c (+{len(cal_p)-len(base_p)})")
    total = len(prepped) * args.runs * 2
    print(f"cases {len(prepped)} | runs/arm {args.runs} | total calls {total}\n")

    results: dict[int, dict[str, list]] = {i: {"A": [], "B": []} for i in range(len(prepped))}
    jobs = []
    for ci, (_c, prep) in enumerate(prepped):
        for _ in range(args.runs):
            jobs.append((ci, "A", prep))
            jobs.append((ci, "B", prep))
    random.Random(args.seed).shuffle(jobs)  # interleave arms/cases -> even 429 load

    done = 0
    with ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix="ab") as pool:
        futs = {pool.submit(_assess_once, arm_a if arm == "A" else arm_b, prep): (ci, arm)
                for ci, arm, prep in jobs}
        for fut in as_completed(futs):
            ci, arm = futs[fut]
            results[ci][arm].append(fut.result())
            done += 1
            if done % 25 == 0:
                print(f"  {done}/{total} calls")

    # ---- score ----
    out_cases, recovered, regressions, unstable, still_wrong, held = [], [], [], [], [], []
    for ci, (c, _p) in enumerate(prepped):
        a_st, b_st = results[ci]["A"], results[ci]["B"]
        a_mode, a_stable, a_dist = _stable_mode(a_st, args.runs)
        b_mode, b_stable, b_dist = _stable_mode(b_st, args.runs)
        label = c["status"]
        rec = {"cci": c["cci"], "ap": c["ap"], "aid": c.get("aid"),
               "category": c["category"], "group": c.get("group"), "label": label,
               "baseline_mode": a_mode, "baseline_stable": a_stable, "baseline_dist": a_dist,
               "calibrated_mode": b_mode, "calibrated_stable": b_stable, "calibrated_dist": b_dist,
               "note": c.get("note", "")}
        if c["category"] == "borderline":
            rec["verdict"] = "excluded"
        elif c["category"].startswith("defect"):
            if not b_stable:
                rec["verdict"] = "calibrated_unstable"; unstable.append(c["cci"])
            elif b_mode == label and a_mode != label:
                rec["verdict"] = "RECOVERED"; recovered.append(c["cci"])
            elif a_mode == label and b_mode != label:
                rec["verdict"] = "REGRESSED"; regressions.append(c["cci"])
            elif b_mode == label and a_mode == label:
                rec["verdict"] = "both_ok"
            else:
                rec["verdict"] = "still_wrong"; still_wrong.append(c["cci"])
        else:  # agreement guard
            if not a_stable:
                rec["verdict"] = "baseline_unstable"
            elif a_mode != label:
                rec["verdict"] = "baseline_off_truth"
            elif not b_stable:
                rec["verdict"] = "calibrated_unstable"; unstable.append(c["cci"])
            elif b_mode != a_mode:
                rec["verdict"] = "REGRESSED"; regressions.append(c["cci"])
            else:
                rec["verdict"] = "held"; held.append(c["cci"])
        out_cases.append(rec)

    summary = {"model": args.model, "runs": args.runs, "n_cases": len(prepped),
               "recovered": recovered, "n_recovered": len(recovered),
               "regressions": regressions, "n_regressions": len(regressions),
               "unstable": unstable, "n_unstable": len(unstable),
               "still_wrong": still_wrong, "n_still_wrong": len(still_wrong),
               "held": held, "n_held": len(held)}
    Path(args.out).write_text(json.dumps({"summary": summary, "cases": out_cases}, indent=2))

    print("\n================ A/B RESULT (full pipeline) ================")
    print(f"recovered  : {len(recovered)}  {recovered}")
    print(f"regressions: {len(regressions)}  {regressions}")
    print(f"unstable   : {len(unstable)}  {unstable}")
    print(f"still_wrong: {len(still_wrong)}  {still_wrong}")
    print(f"held (guards): {len(held)}")
    print("\nper-defect / borderline detail:")
    for r in out_cases:
        if r["category"].startswith("defect") or r["category"] == "borderline":
            print(f"  {r['ap']:>12} [{r['verdict']:>18}] label={r['label']:>13} "
                  f"base={r['baseline_mode']}(stbl={r['baseline_stable']}) -> "
                  f"cal={r['calibrated_mode']}(stbl={r['calibrated_stable']})")
            print(f"                 A{r['baseline_dist']}  B{r['calibrated_dist']}")
    gate = bool(recovered) and not regressions and not unstable
    print(f"\nSHIP GATE: recovered>0={bool(recovered)} regressions==0={not regressions} "
          f"no-unstable={not unstable} -> {'PASS' if gate else 'NO-GO'}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
