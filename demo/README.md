# Demo evidence — Example System Demo system

Synthetic CCIS workbook + cross-referenced evidence artifacts for exercising
the assessor app end-to-end. **Not real authorization material** — every
document, scan, and log is fabricated for the fictional "Example System Demo" system
(`example-system-demo-ws01.demo.local`, `10.10.5.21`, Windows Server 2022).

> Looking for the **real** Example System IATT artifacts (production CCIS workbook,
> enterprise services controls template, AWS CRM, USD SSP / architecture
> docs)? See [`example_system/README.md`](./example_system/README.md). That bundle is
> the one-stop end-to-end test path against actual program data.
> CUI — gitignored, local-only.

## What this demo proves

1. The CCIS reader/writer round-trips a realistic eMASS export (`WORKING SHEET`,
   headers at row 6, 21 columns A–U, data row 7+).
2. The evidence ingester handles every supported format: text, DOCX, PDF, PPTX,
   XLSX, STIG `.ckl` / `.cklb` / XCCDF XML, and Nessus `.nessus`.
3. The tagger links artifacts to objectives via USD document numbers cited in
   column F (Implementation Narrative) and column U (Previous Test Results).
4. The deterministic Rule #8 pre-filter (`engine/rules.py`) fires on **every**
   auto-status lane without an LLM call — DoD-auto-compliant text (8a),
   internal inheritance (8a), structural inheritance via col L (8a),
   CSP/cloud-provided (8a), documented scope-exclusion NA (8b), and bare
   "inherited from" with no source → escalate (8c) — while the remaining
   `Local` rows fall through to the LLM. See *Deterministic lane coverage*
   below.

## Folder layout

| Folder | What's in it |
|---|---|
| `workbooks/` | One importable demo workbook per framework (NIST 800-53, 800-171, CSF 2.0, ISO 27001, CIS v8, PCI DSS, SOC 2). `DEMO_NIST_800-53r5_Example System.xlsx` is the primary 8-control demo — including AC-17, whose responsibility diverges across the two CRMs (AWS=Customer, Azure=Inherited) to showcase per-scope narratives |
| `policies/` | Implementing policies/procedures referenced by `Col F` and `Col U` |
| `configs/` | GPO export referenced by AC-7, AC-11, IA-5 rows |
| `text/` | Operator-generated weekly review records (AU-6, SI-4 evidence) |
| `scans/` | ACAS / Nessus credentialed scan (RA-5 evidence) |
| `stigs/` | Windows / RHEL / Application Security STIG checklists (CM-6 evidence) |
| `psc/` | Program-Specific Control overlay (T1TL-style, control-grain), 800-53 **Rev 5**; resolves to DISA CCIs at load time |
| `cci_list/` | DISA STIG→800-53 CCI mapping source the PSC resolves against |
| `crm/` | AWS + Azure FedRAMP-High Customer Responsibility Matrices (CSP/provider tags) |
| `diagrams/` | TWO tenant-distinct authorization-boundary diagrams — AWS GovCloud (`.vsdx`, VPC/Security Group/GuardDuty, 10.20.x.x) and Azure Government (`.svg`, VNet/NSG/Sentinel, 172.16.x.x). Drive diagram→boundary-control tagging and the multi-tenant `boundary:` attribution showcase |

## CCIS rows → expected evidence

| CCI (row) | Status in workbook | Cited evidence | File |
|---|---|---|---|
| AC-2.1 | Compliant (prefilled) | Account Mgmt Policy USD20240315 | `policies/Information_System_Account_Management_Policy_USD20240315.docx` |
| AC-2.4 | *blank — assessor's turn* | Windows audit log Event ID 4720 | `text/audit_log_review_2026-05-19.txt` |
| AC-7.a | Compliant (prefilled) | GPO export USD20240218 (5 / 15) | `configs/GPO_Password_Policy_Export_USD20240218.xlsx` |
| AC-11 | *blank* | GPO inactivity-lock setting | `configs/GPO_Password_Policy_Export_USD20240218.xlsx` |
| AT-2.1 | Compliant (prefilled) | Training brief USD20240518 + LMS roster | `policies/Security_Awareness_Training_Brief_2026Q2_USD20240518.pptx` |
| AU-6.1 | Compliant (prefilled) | Weekly review + SIEM correlation | `text/audit_log_review_2026-05-19.txt`, `text/siem_weekly_correlation_report_2026-05-22.txt` |
| IA-5(1)(a) | Compliant (prefilled) | GPO export, IA Procedures USD20240212 | `configs/GPO_Password_Policy_Export_USD20240218.xlsx`, `policies/Identification_and_Authentication_Procedures_USD20240212.pdf` |
| CM-6.1 | Compliant (prefilled) | Windows 2022 + RHEL 9 STIG checklists | `stigs/Windows_Server_2022_STIG_Sample.ckl`, `stigs/RHEL_9_STIG_Sample.cklb` |
| RA-5.1 | Compliant (prefilled) | ACAS / Nessus credentialed scan | `scans/acas_nessus_subnet_10_10_5_0.nessus` |
| SC-7.1 | Compliant (inherited) | SDA Enterprise Boundary Service overlay row 412 | (none — inheritance rule, col L names the source) |
| SI-4.1 | *blank* | SIEM correlation report | `text/siem_weekly_correlation_report_2026-05-22.txt` |

The `SDA Controls` sheet in the workbook is a 5-row overlay stub showing the
program-specific requirement-source pattern (row 412 marks SC-7.1
inheritable). SC-7.1 carries `SDA Enterprise Service` in col L, so Rule #8a
structural resolves it to **Compliant** without an LLM call (inherited ≠ NA).

### Deterministic lane coverage (Rule #8 pre-filter)

Six additional rows exist solely to drive each deterministic auto-status lane,
so the demo showcases every feature path — not just the happy "Local → LLM"
one. The classifier reaches its verdict from the workbook columns alone, with
**no billable LLM call**. Each lane fires as follows:

| CCI (row) | Lane (`classify_row`) | Verdict | Why it lands there |
|---|---|---|---|
| AC-1 | `compliant_8a` (rule 8a) | Compliant | DoD-level auto-compliant phrase in col K |
| AU-4 | `compliant_8a` (rule 8a) | Compliant | internal inheritance ("inherited from the enterprise") col K |
| PE-3 | `compliant_8a` (rule 8a) | Compliant | CSP-provided ("implemented by AWS") col Q |
| SC-7.1 | `compliant_8a` (rule 8a) | Compliant | structural inheritance — col L names a source |
| AC-18 | `not_applicable_8b` (rule 8b) | Not Applicable | documented scope exclusion in col Q |
| CP-7 | `unclear_8c` (rule 8c) | *escalate* | bare "inherited from" with no source → goes to LLM |
| SC-13 | `no_auto_rule` | *(LLM)* | no rule fires → LLM assessment (NC feeder) |

The remaining 10 `Local` rows (AC-2.1, AC-2.4, AC-7.a, AC-11, AT-2.1, AU-6.1,
IA-5(1)(a), CM-6.1, RA-5.1, SI-4.1) also fall through to `no_auto_rule` — the
LLM hand-off lane the assessor actually reasons over.

### PSC overlay (Rev 5)

`psc/Example_Program_Ground_Security_Controls_PSC_800-53r5.xlsx` is a
synthetic control-grain Program-Specific Control overlay. It carries **no CCI
column** — its 16 NIST 800-53 control IDs resolve to DISA CCIs at load time
against `cci_list/stig-mapping-to-nist-800-53.xlsx`. The whole demo corpus
targets **NIST 800-53 Rev 5**; no PSC control renumbers between Rev 4 and Rev 5,
so the single Rev 5 fixture resolves 16/16 clean against the shipped (Rev-4)
demo DISA source via highest-available-revision fallback.
`_verify_psc_resolution.py` asserts this.

## Regenerating

Both generator scripts are idempotent — re-run anytime to refresh:

```sh
cd cybersecurity-assessor
backend/.venv/Scripts/python.exe demo/_build_demo_artifacts.py
backend/.venv/Scripts/python.exe demo/_build_demo_workbooks.py   # one workbook per framework -> demo/workbooks/
backend/.venv/Scripts/python.exe demo/_build_demo_crm.py         # AWS GovCloud CRM
backend/.venv/Scripts/python.exe demo/_build_demo_crm_azure.py   # Azure Government CRM
backend/.venv/Scripts/python.exe demo/_build_demo_psc.py

# Repeatable coverage checks (no LLM / no tokens):
backend/.venv/Scripts/python.exe demo/_verify_psc_resolution.py  # Rev 5 PSC resolves 16/16
backend/.venv/Scripts/python.exe demo/_verify_boundary_attribution.py  # multi-tenant boundary: lines
```

### Showcasing multi-tenant boundary attribution

`_verify_boundary_attribution.py` is a self-contained demo of how the evidence
bundle keeps per-scope narratives honest in a multi-boundary program. It
ingests the two `diagrams/` artifacts into an in-memory workbook with **AWS
GovCloud** and **Azure Government** tenant segments, links each diagram to its
tenant, and prints the rendered `## tagged_evidence` block — where every
artifact now carries a `boundary:` line naming its tenant. It also proves the
two guardrails: single-boundary workbooks render **no** boundary line (so the
prompt prefix stays cache-stable), and legacy `BACKFILL` links are excluded and
render `unspecified` rather than laundering an unreliable attribution. No LLM /
no tokens.

## Smoke test against the app

1. Start the app (`pnpm dev` from repo root).
2. **Workbooks** → Open `demo/workbooks/DEMO_NIST_800-53r5_Example System.xlsx`, select
   framework "NIST SP 800-53 Rev. 5". Baseline summary should report 8
   in-scope controls (AC-2(1), AC-7a, AC-11, IA-5(1)(a), CM-6a, RA-5a, SC-7, AC-17).
3. **Evidence** → Ingest folder `demo/`. Expect: 9 ingested, 0 errors, tags
   linking USD20240315 → AC-2 rows, USD20240218 → AC-7 / AC-11 / IA-5,
   USD20240518 → AT-2.
4. **Controls** → Drill into AC-2.4, AC-11, SI-4.1 — all currently blank.
   "Assess" each one; verify the proposed status + narrative reference the
   ingested artifact, no hallucinated doc numbers.
5. **Apply to workbook** → reopen in Excel and confirm columns N/O/P/Q wrote
   cleanly while formatting, comments, and data validation survived.
6. **SC-7.1** → status should be `Compliant` (inherited, not NA) with
   rationale citing the SDA Controls overlay, produced by `engine/rules.py`
   Rule #8a structural (col L = `SDA Enterprise Service`) *without* a billable
   LLM call. Look for `source: "rule_8a"` in the run telemetry.
