"""Measure the second-stage VERIFIER against the user's rulings + both oracles.

The recall-first judge collapses genuine partials and true noise into a single
0.6 score. The verifier (tagger._VERIFIER_RUBRIC) re-examines a candidate and
assigns a categorical RELATIONSHIP label; only "unrelated" is discarded. Before
wiring it into the ingest hot path, this script runs it over:

  1. the 10 controls the user personally adjudicated (the ground-truth for the
     verifier's keep/discard boundary), and
  2. the full 54 v1-"no" tags (33 disputed + 21 confident-noise),

then reports whether the verifier's keep/discard matches the user's standard and
how it lines up with oracle v1/v2. Read-only w.r.t. production; cached +
concurrency-5 + hard-timeout like the other harness LLM paths.

USAGE
-----
    cd backend
    .venv/Scripts/python.exe scripts/verify_band.py \
        --evidence-root "C:/.../eMASS_BoE_Upload+Stigs_07112026" \
        --framework-id 2 [--model gpt-5.6-sol] [--out scripts/_verifier_result.json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FTimeout
from concurrent.futures import as_completed
from pathlib import Path
from typing import Any

_BACKEND = Path(__file__).resolve().parents[1]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from cybersecurity_assessor import config as cfg  # noqa: E402
from cybersecurity_assessor import models  # noqa: F401,E402
from cybersecurity_assessor.evidence import tagger as T  # noqa: E402

import stage_recall_harness as H  # noqa: E402

# The user's own rulings on the 10 stratified disputed cases (keep/drop), by
# (doc-title-prefix, control). SI-2 is conditional -> treated as "keep" here
# (user: keep for synopsis unless the excerpt shows no flaw-remediation).
_USER_RULINGS = {
    ("GMI Enterprise Authentication", "ia-5"): "keep",
    ("01.o.AC_USD00013961_GMI_Account_Manageme", "ac-2.12"): "keep",
    ("SDA GMI Auditing Procedures", "si-2"): "keep",   # context_only / conditional
    ("01.l.AC_GOCO Account Approval Rev", "at-4"): "keep",
    ("15.f.SC_USD00016244_GMI Ground Sys", "cm-7"): "keep",
    ("17.a.SA_PaaS_SVD_10.1.0", "si-7"): "keep",
    ("17.d.SA_USD00010046_Rev_B_Cybersec", "pl-2"): "keep",
    ("SDA GMI Vulnerability Management P", "pm-4"): "keep",
    ("05.a.CM_10.1.0-release-notes", "ac-2.1"): "keep",
    ("13.a.PL_20241107 IATT Memo - GDMS", "sa-17"): "keep",
}


def _parse_verifier(raw: str) -> dict[str, Any]:
    from cybersecurity_assessor.llm.client import _parse_extraction_json  # type: ignore

    try:
        obj = _parse_extraction_json(raw)
        rel = str(obj.get("relationship", "")).strip().lower()
        if rel in set(T._VERIFIER_RETAIN_LABELS) | {T._VERIFIER_DISCARD_LABEL}:
            return {
                "relationship": rel,
                "supported_requirements": obj.get("supported_requirements", []),
                "evidence_span": str(obj.get("evidence_span", ""))[:200],
                "reason": str(obj.get("reason", ""))[:200],
            }
    except Exception:  # noqa: BLE001
        pass
    return {"relationship": "error", "reason": raw[:120]}


def _verify_raw(client: Any, brief: list[dict], user_text: str, model: str) -> str:
    from cybersecurity_assessor.llm.client import (  # noqa: E402
        _JUDGE_CALL_TIMEOUT_SECONDS,
        _OPENAI_SUBTASK_MIN_TOKENS,
        _extract_openai_text,
    )

    system_text = "\n\n".join(str(b.get("text", "")) for b in brief if b.get("text"))
    kwargs: dict[str, Any] = {
        "model": model,
        "max_tokens": _OPENAI_SUBTASK_MIN_TOKENS,
        "messages": [
            {"role": "system", "content": system_text},
            {"role": "user", "content": user_text},
        ],
        "timeout": _JUDGE_CALL_TIMEOUT_SECONDS,
    }
    if getattr(client, "_supports_temperature", False):
        kwargs["temperature"] = 0.0
    resp = client._chat_create_temperature_aware(label="verifier", **kwargs)
    return _extract_openai_text(resp).strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--evidence-root", required=True)
    ap.add_argument("--framework-id", type=int, default=2)
    ap.add_argument("--catalog-db", default=os.path.join(
        os.path.expanduser("~"), ".cybersecurity-assessor", "assessor.sqlite"))
    ap.add_argument("--model", default="gpt-5.6-sol")
    ap.add_argument("--out", default="scripts/_verifier_result.json")
    args = ap.parse_args()

    H._install_production_tls()
    from openai import OpenAI
    from cybersecurity_assessor.llm.client import OpenAIClient

    base, tok = cfg.resolve_openai_endpoint()
    sdk = OpenAI(base_url=base, api_key=tok, max_retries=1, timeout=60)
    client = OpenAIClient(model=args.model, _sdk_client=sdk)

    cids, _rt, all_by_control = H.load_catalog(args.catalog_db, args.framework_id)
    judge_text = {c: T._control_reference_text(all_by_control[c]) for c in cids}
    files = H.index_evidence_files(args.evidence_root)

    # The 54 v1-"no" pairs to verify, plus oracle labels for scoring.
    review = json.loads(Path("scripts/_disputed_review.json").read_text())
    o2 = {(_d["title"][:40], c): v
          for _o in [json.load(open("scripts/_oracle_v2.json"))]
          for _d in _o["docs"]
          for v in ("yes", "partial", "no") for c in _d[v]}

    pairs = []  # (title_prefix40, cid, class: disputed|confident)
    for r in review["disputed"]:
        pairs.append((r["doc"], r["control"], "disputed"))
    for r in review["confident_noise"]:
        pairs.append((r["doc"], r["control"], "confident_noise"))

    # Resolve each title-prefix to a file + text once.
    # review docs store title[:40]; match to full titles via the pool json.
    pool = json.load(open("scripts/_judged_uncap_newrubric.json"))
    full_titles = {d["title"][:40]: d["title"] for d in pool["per_doc"]}

    cache_dir = Path(__file__).resolve().parent / "_verifier_cache"
    cache_dir.mkdir(exist_ok=True)
    pver = hashlib.sha1(T._VERIFIER_RUBRIC.encode()).hexdigest()[:8]

    # group pairs by doc so the brief (cached body) is reused
    by_doc: dict[str, list[tuple[str, str]]] = {}
    for tpre, cid, cls in pairs:
        by_doc.setdefault(tpre, []).append((cid, cls))

    results: list[dict[str, Any]] = []
    for tpre, items in by_doc.items():
        full = full_titles.get(tpre, tpre)
        f = H.find_file(full, files)
        if not f:
            print(f"[skip] no file for {tpre!r}")
            continue
        text = H.read_text(f)
        if not text:
            continue
        doc_hash = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
        brief = T._build_verifier_brief(full, T._llm_artifact_body(text))

        def _one(cid: str) -> tuple[str, dict]:
            ck = cache_dir / f"{doc_hash}_{cid}_{pver}.json"
            if ck.exists():
                return cid, json.loads(ck.read_text())
            raw = _verify_raw(client, brief, _verifier_user_text_local(cid), args.model)
            v = _parse_verifier(raw)
            if v["relationship"] != "error":
                ck.write_text(json.dumps(v))
            return cid, v

        def _verifier_user_text_local(cid: str) -> str:
            return T._verifier_user_text(cid, judge_text.get(cid, ""))

        cls_by_cid = dict(items)
        with ThreadPoolExecutor(max_workers=5, thread_name_prefix="verify") as pool_ex:
            futs = {pool_ex.submit(_one, c): c for c, _ in items}
            for fut in as_completed(futs, timeout=180 + 20 * len(items)):
                try:
                    cid, v = fut.result(timeout=60)
                except (_FTimeout, Exception):  # noqa: BLE001
                    continue
                rel = v["relationship"]
                keep = rel in T._VERIFIER_RETAIN_LABELS
                results.append({
                    "doc": tpre, "control": cid, "class": cls_by_cid.get(cid),
                    "relationship": rel, "keep": keep,
                    "evidence_span": v.get("evidence_span", ""),
                    "reason": v.get("reason", ""),
                    "oracle_v2": o2.get((tpre, cid), "?"),
                    "user_ruling": _USER_RULINGS.get(
                        (tpre[:34] if (tpre[:34], cid) in {(k[0][:34], k[1]) for k in _USER_RULINGS} else tpre, cid),
                        _USER_RULINGS.get((tpre, cid), None),
                    ),
                })
        print(f"{tpre[:38]:38} verified {len(items)}")

    # match user rulings loosely by (prefix, cid)
    ur = {(k[0][:30], k[1]): v for k, v in _USER_RULINGS.items()}
    for r in results:
        if r["user_ruling"] is None:
            r["user_ruling"] = ur.get((r["doc"][:30], r["control"]))

    # --- Report ---
    from collections import Counter
    rel_counts = Counter(r["relationship"] for r in results)
    disc = [r for r in results if not r["keep"]]
    print(f"\n=== VERIFIER over {len(results)} v1-'no' tags ===")
    print("relationship distribution:", dict(rel_counts))
    print(f"KEEP {sum(r['keep'] for r in results)}  /  DISCARD(unrelated) {len(disc)}")
    print("\ndiscarded (verifier says unrelated):")
    for r in disc:
        print(f"  {r['control']:9} [{r['doc'][:28]}] v2={r['oracle_v2']:8} {r['reason'][:70]}")

    # agreement with the user's 10 rulings
    ruled = [r for r in results if r["user_ruling"]]
    if ruled:
        agree = sum(1 for r in ruled
                    if (r["keep"] and r["user_ruling"] == "keep")
                    or (not r["keep"] and r["user_ruling"] == "drop"))
        print(f"\n=== vs USER's rulings (n={len(ruled)}) ===")
        print(f"agreement: {agree}/{len(ruled)}")
        for r in ruled:
            vk = "keep" if r["keep"] else "drop"
            mark = "OK " if vk == r["user_ruling"] else "XX "
            print(f"  {mark}{r['control']:9} user={r['user_ruling']:5} verifier={vk:5} ({r['relationship']}) [{r['doc'][:26]}]")

    Path(args.out).write_text(json.dumps(results, indent=2))
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
