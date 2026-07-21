"""Measure whether the LIVE LLM assessor correctly fails a CCI on MIXED STIG
evidence (one asset passes, another fails) WITHOUT a deterministic worst-of rule.

THE QUESTION (2026-07-21): a CCI can have multiple STIG checks mapped to it —
e.g. a Windows STIG (Not_A_Finding / pass) and a RHEL STIG (Open / fail) on
different in-boundary hosts. Correct RMF behavior: any applicable Open finding
fails the CCI (worst-of across assets); a passing scan on another host must NOT
mask it. The system today has NO deterministic rule for this — the open finding
is rendered into the `## corroborating_findings` section of the evidence bundle
and the LLM decides. Before building a status-flipping deterministic override in
the 3000-line assessor, MEASURE: how often does the live LLM already get the
mixed case right?

If the LLM returns Non-Compliant ~100% of the time, the deterministic rule is
low-value insurance with real regression cost — skip it. If it slips to
Compliant even 10-20% of the time, that's a real status-flip defect and the
build is justified. This decides build-vs-skip on data, not intuition.

METHOD: build the tagged_evidence bundle EXACTLY as production renders it
(engine.evidence_bundle + finding_corroboration formats), run the REAL
Assessor.assess() with a live OpenAIClient, force_llm=True (skip rule-8), N
times per scenario (reasoning models are nondeterministic — one run proves
nothing), and tally status outcomes.

Scenarios:
  mixed        Windows pass + RHEL Open (the core question). Expect NC.
  fail_only    RHEL Open only. Expect NC (sanity floor).
  pass_only    Windows pass only. Expect Compliant/NC per corroboration rules
               (control — shows the LLM isn't just always-NC).
  mixed_ra     mixed + narrative hint the RHEL finding is risk-accepted. Expect
               NC (RA doesn't make it compliant; user decision).

USAGE
-----
    cd backend
    .venv/Scripts/python.exe scripts/measure_mixed_stig.py \
        [--runs 8] [--model gpt-5.6-sol] [--out scripts/_mixed_stig.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

_BACKEND = Path(__file__).resolve().parents[1]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import config as cfg  # noqa: E402
from cybersecurity_assessor import models  # noqa: F401,E402
from cybersecurity_assessor import tls  # noqa: E402
from cybersecurity_assessor.engine.assessor import Assessor  # noqa: E402
from cybersecurity_assessor.engine.evidence_bundle import (  # noqa: E402
    CORROBORATING_FINDINGS_HEADER,
)
from cybersecurity_assessor.excel.ccis_reader import CcisRow  # noqa: E402


# A realistic CCI with an obvious STIG mapping: AU-9 protect audit info, or
# CM-6 config settings. Use CM-6 (Configuration Settings) — STIG checks map to
# it constantly, and a mixed OS scan is the textbook case.
def _row() -> CcisRow:
    return CcisRow(
        excel_row=100,
        required=True,
        control_id="CM-6",
        ap_acronym="CM-6.1",
        cci_id="CCI-000366",
        implementation_status=None,
        designation=None,
        narrative=None,
        definition=(
            "The organization establishes and documents configuration settings "
            "for information technology products employed within the information "
            "system that reflect the most restrictive mode consistent with "
            "operational requirements."
        ),
        guidance=(
            "The organization establishes and documents configuration settings "
            "for components using DoD STIGs/SRGs; deviations are documented and "
            "approved."
        ),
        procedures=(
            "Examine STIG/SRG scan results and configuration baselines; confirm "
            "settings match the approved baseline on all in-scope hosts."
        ),
        inherited=None,
        remote_inheritance=None,
        status=None,
        date_tested=None,
        tester=None,
        results=None,
        previous_status=None,
        previous_date=None,
        previous_tester=None,
        previous_results=None,
    )


# PRODUCTION-FAITHFUL evidence bundles. CRITICAL (per harness verification): the
# real ## corroborating_findings section is OPEN-only — finding_corroboration.py
# filters status==OPEN, so a PASSING scan NEVER appears there. Production line
# shape (evidence_bundle.py:637): "- {citation} ({sev}): {detail}". Passing
# scans are represented, if at all, only as prose in ## tagged_evidence. So the
# real production "mixed" case is NOT "visible pass line vs visible fail line" —
# it's "a compliant-sounding baseline narrative in tagged_evidence vs a lone
# OPEN finding in corroborating_findings." That is the actual risk: does the
# reassuring baseline prose talk the LLM out of the one open finding? We also
# render ## affected_hosts as production does (host union from inventory).
_RHEL_FAIL_LINE = (
    "- [V-230300 / SV-230300r858734_rule] RHEL 8 must apply the required "
    "configuration setting (STIG-RHEL8-scan.ckl) (medium): the required "
    "configuration setting is not applied on host rhel-db-02."
)
# The passing Windows scan shows up ONLY as baseline prose in tagged_evidence
# (as production would render a policy/baseline artifact), never as a finding.
_BASELINE_PROSE = (
    "- Configuration baseline (CM-BASELINE-2026): DoD STIG/SRG hardening is "
    "applied across the enclave; Windows Server 2022 hosts scanned clean "
    "against the approved baseline (STIG-Win2022-scan.ckl, 0 open findings)."
)
_HOSTS = "## affected_hosts (2)\nrhel-db-02, win-app-01"

_SCENARIOS: dict[str, str] = {
    # The REAL mixed case: reassuring baseline prose (incl. the Windows pass) in
    # tagged_evidence, PLUS a lone RHEL Open finding in corroborating_findings.
    # Correct verdict: Non-Compliant (the open finding fails the CCI).
    "mixed": (
        f"## tagged_evidence\n{_BASELINE_PROSE}\n"
        f"{CORROBORATING_FINDINGS_HEADER}\n{_RHEL_FAIL_LINE}\n"
        f"{_HOSTS}\n"
    ),
    # Sanity floor: only the open finding, minimal prose. Expect NC.
    "fail_only": (
        "## tagged_evidence\n"
        "- STIG scan results for the enclave (STIG-RHEL8-scan.ckl).\n"
        f"{CORROBORATING_FINDINGS_HEADER}\n{_RHEL_FAIL_LINE}\n"
        "## affected_hosts (1)\nrhel-db-02\n"
    ),
    # Control: passing baseline prose, NO open findings section at all (the
    # production shape when everything passed). Shows the LLM isn't always-NC.
    "pass_only": (
        f"## tagged_evidence\n{_BASELINE_PROSE}\n"
        "## affected_hosts (1)\nwin-app-01\n"
    ),
    # mixed + an AO-signed risk-acceptance memo in prose. User decision: still
    # NC (RA is POA&M metadata, not a compliance value). Tests whether the RA
    # memo wrongly talks the LLM into Compliant.
    "mixed_ra": (
        f"## tagged_evidence\n{_BASELINE_PROSE}\n"
        "- Risk Acceptance memo RA-2026-014 (signed by the AO) accepts the "
        "residual risk from the open RHEL configuration finding below.\n"
        f"{CORROBORATING_FINDINGS_HEADER}\n{_RHEL_FAIL_LINE}\n"
        f"{_HOSTS}\n"
    ),
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--runs", type=int, default=8,
                    help="live LLM runs per scenario (nondeterminism sampling)")
    ap.add_argument("--model", default="gpt-5.6-sol")
    ap.add_argument("--out", default="scripts/_mixed_stig.json")
    args = ap.parse_args()

    tls.install()
    from openai import OpenAI
    from cybersecurity_assessor.llm.client import OpenAIClient

    base, tok = cfg.resolve_openai_endpoint()
    sdk = OpenAI(base_url=base, api_key=tok, max_retries=1, timeout=120)
    client = OpenAIClient(model=args.model, _sdk_client=sdk)
    assessor = Assessor(llm=client)  # no cache_session -> no cache, fresh each run

    def _one_run(scenario: str, evidence: str) -> dict[str, Any]:
        # force_llm=True so rule-8 short-circuits don't fire (there's no col-K
        # assertion here anyway, but be explicit). Fresh row each call.
        try:
            d = assessor.assess(_row(), tagged_evidence=evidence, force_llm=True)
            return {
                "status": (d.status.value if d.status else None),
                "needs_review": d.needs_review,
                "narrative": (d.narrative or "")[:240],
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": "ERROR", "error": f"{type(exc).__name__}: {exc}"[:160]}

    results: dict[str, Any] = {"meta": {"model": args.model, "runs": args.runs}, "scenarios": {}}
    for scenario, evidence in _SCENARIOS.items():
        print(f"\n=== {scenario} ({args.runs} runs) ===")
        runs: list[dict[str, Any]] = [None] * args.runs  # type: ignore
        # concurrency 5 = gd-ms gateway safe limit
        with ThreadPoolExecutor(max_workers=5, thread_name_prefix="mixed") as pool:
            futs = {pool.submit(_one_run, scenario, evidence): i for i in range(args.runs)}
            for fut in as_completed(futs):
                runs[futs[fut]] = fut.result()
        counts = Counter(r["status"] for r in runs)
        nc = counts.get("Non-Compliant", 0)
        comp = counts.get("Compliant", 0)
        na = counts.get("Not Applicable", 0)
        err = counts.get("ERROR", 0)
        print(f"  status counts: {dict(counts)}")
        print(f"  Non-Compliant: {nc}/{args.runs}   Compliant: {comp}   NA: {na}   err: {err}")
        # show any Compliant narratives (the failure mode we care about)
        for r in runs:
            if r["status"] == "Compliant":
                print(f"    [COMPLIANT LEAK] {r.get('narrative','')[:180]}")
        results["scenarios"][scenario] = {
            "counts": dict(counts),
            "runs": runs,
        }

    Path(args.out).write_text(json.dumps(results, indent=2))
    print(f"\nwrote {args.out}")

    # verdict summary
    print("\n=== VERDICT ===")
    m = results["scenarios"]["mixed"]["counts"]
    mixed_nc = m.get("Non-Compliant", 0)
    print(f"MIXED (win pass + rhel Open): {mixed_nc}/{args.runs} correctly Non-Compliant")
    if mixed_nc == args.runs:
        print("  -> LLM gets it right every time. Deterministic rule = low-value insurance.")
    elif mixed_nc >= args.runs * 0.8:
        print("  -> LLM mostly right but SLIPS. Deterministic rule justified for defensibility.")
    else:
        print("  -> LLM UNRELIABLE on mixed case. Deterministic rule clearly needed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
