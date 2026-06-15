# Deliverable — End-to-End Assessment Sanity & Evidence Traceability

**Owner:** Noah Jaskolski · **Target:** v0.1 acceptance bar · **Status:** open

## Why

A passing pipeline is not the same as a *sensible* assessment. Today we can
ingest a folder and write verdicts to a workbook, but two questions a 3PAO /
reviewer will ask are not yet answerable from the app:

1. **"What was each control actually assessed against?"** — for every verdict,
   which specific ingested artifact(s) backed it, and was that the *right*
   evidence for that CCI (not a hallucinated doc number, not a stale file, not
   evidence borrowed from the wrong boundary).
2. **"Does every feature path actually fire?"** — the demo must exercise *every*
   verdict lane and *every* control-responsibility shape (local, inherited,
   hybrid, cloud/CSP-provided, NA scope-exclusion, abstain), not just the happy
   "local → LLM → Compliant" path. Per `feedback_defensibility_over_velocity`,
   coverage we can demonstrate beats coverage we assert.

This deliverable defines the acceptance bar for both, grounded in the existing
`demo/` corpus and `engine/rules.py` lanes.

## Two halves (both load-bearing)

### Half A — Every feature path is exercised

There must be at least one demo fixture (CCIS row + cited evidence, or overlay
entry) that drives each lane below to its expected outcome, verified by a
repeatable check (golden test or scripted classify over the regenerated demo
workbook — see the `classify_row` sweep used to validate the inheritance fix).

| # | Feature / lane | Engine path | Demo fixture today | Covered? |
|---|---|---|---|---|
| 1 | Local control → LLM assessment | `NO_AUTO_RULE` | 10 `Local` rows in `demo/ccis` | ✅ (sweep) |
| 2 | Inherited (internal source) → Compliant | rule 8a structural (col L) | SC-7.1 (`SDA Enterprise Service`) | ✅ (sweep) |
| 3 | Inherited (col K/J explicit DoD-auto) → Compliant | rule 8a text | AC-1 (DoD phrase col K), AU-4 ("inherited from the enterprise" col K) | ✅ (sweep) |
| 4 | Cloud / CSP-provided → Compliant | rule 8a CSP phrases (col Q/U) | PE-3 ("implemented by AWS" col Q) | ✅ (sweep) |
| 5 | Hybrid (part local / part inherited) | CRM `hybrid`/`shared` tag → LLM with split context | CRM builders tag hybrid; orchestrator path covered by `test_assessor_e2e` stub, not yet wired to a CCIS row | ⚠ partial |
| 6 | NA via documented scope-exclusion | rule 8b (col Q/U) | AC-18 (documented scope exclusion col Q) | ✅ (sweep) |
| 7 | Unclear inheritance → escalate | rule 8c (bare "inherited from") | CP-7 (bare "inherited from", no source) | ✅ (sweep) |
| 8 | Non-Compliant + POA&M generation | LLM → NC → POAM (remediation + milestone dates) | NC decision lane covered by `test_assessor_e2e` stub; full POAM artifact gen needs real ingest | ⚠ partial |
| 9 | Abstain → `needs_review` (no status) | precision-over-recall gate | `test_assessor_e2e`: validator-exhausted + no-llm-client both → `needs_review` | ✅ (e2e) |
| 10 | PSC overlay maps to CCIs | `program_controls_loader` + DISA CCI resolve | `demo/_build_demo_psc.py` (Rev 5 + Rev 4) | ✅ (reads + 16/16 extract; see note) |
| 11 | CRM ingestion short-circuits inherited | CRM tab → tag → skip LLM | AWS + Azure FedRAMP High CRM | ⛔ verify |
| 12 | FedRAMP HIGH baseline overlay | `fedramp_profile_loader` | CRM workbooks are FedRAMP High | ⛔ verify |
| 13 | Multi-framework ingest | per-framework loaders | `demo/_build_demo_workbooks.py` (all 7) | ⛔ verify each |
| 14 | Supersession detection | `supersession_tracker` | Account Mgmt **Rev A + Rev B** txt pair | ⛔ verify it flags |
| 15 | ODP assignment → render-time resolution | `odp_assignment` | — | ⛔ add fixture |
| 16 | Asset cross-check (ACAS ∪ CKL ∪ declared) | `asset_crosscheck` | nessus + ckl present | ⛔ verify union |
| 17 | Every extractor format | dispatcher | text/docx/pdf/pptx/xlsx/ckl/cklb/xccdf/nessus | ✅ |
| 18 | Boundary context in **every** narrative | per-scope weave | — | ⛔ assert phrasing |
| 19 | Decision-cache hit + invalidation | KERNEL_VERSION/PROMPT_SHA | — | ⛔ verify |
| 20 | SAR + POA&M export (eMASS template) | `reports/sar.py`, POAM exporter | — | ⛔ verify gates |

"✅" = exercised + checked. "⚠" = partially proven (orchestrator-stub level, not
yet a full demo-corpus ingest). "⛔" = fixture and/or check still owed. The bar
for this deliverable is **every row green**, each behind a repeatable check.

#### Verification status (2026-06-15)

Three repeatable checks pass from a clean checkout at **zero token cost**:

- `demo/_verify_ccis_coverage.py` — production reader + `classify_row` over the
  built demo workbook; **EXIT 0**, every deterministic lane (1–4, 6, 7) + all 7
  anchor rows land as intended. 17 rows total.
- `demo/_verify_psc_resolution.py` — Rev 5 PSC resolves **16/16** clean (lane 10).
- `backend/tests/engine/test_assessor_e2e.py` — orchestrator with a deterministic
  stub LLM; **13 passed**, covering the LLM-fed lanes: first-pass accept,
  retry-then-accept, NC decision, abstain→`needs_review` (lane 9, both
  validator-exhausted and no-llm-client paths), CRM provider/inherited/hybrid/NA
  short-circuits, and supersession rewrite.

Together these prove **every Half-A lane composes correctly** at zero token cost.
What remains is **not** lane routing but (a) a real-LLM semantic pass — "do the
demo narratives read sensibly" — which is **blocked on an Anthropic API key**
(none in env or Windows Credential Manager keyring; set `ANTHROPIC_API_KEY` or
save one via Settings → API Key), and (b) the integration "verify" lanes (11–20)
that require a live sidecar ingest of `demo/`.

### Half B — Evidence traceability ("what was it assessed against")

For a completed assessment of the demo workbook, the app (or an export) must
emit a per-CCI provenance trace so a reviewer can confirm the assessment makes
sense:

- For **each CCI**: the verdict, and the **specific artifact(s)** the narrative
  cites (file path + the doc number / scan ID / STIG rule that anchored it).
- **Reverse view** — for **each ingested artifact**: which CCI(s) it was
  assessed against, so orphan evidence (ingested, cited nowhere) and
  unsupported verdicts (verdict with no artifact) are both visible. Emit as a
  row-exploded CSV per `feedback_csv_export_row_explode` — one row per
  (artifact, CCI) pair so Excel AutoFilter can answer "what backed SC-7.1?".
- **Sanity assertions** the trace makes checkable:
  - No verdict cites a doc number absent from the ingested set (no
    hallucinated citations).
  - No `Compliant`/`NC` verdict has zero backing artifacts (abstain is the only
    legitimate no-evidence outcome → `needs_review`).
  - No artifact is cited for a CCI outside its boundary/scope
    (`feedback_boundary_reasoning` — flag, don't silently attribute).
  - Superseded artifacts (Rev A when Rev B exists) are not the sole basis for a
    Compliant verdict.

## Acceptance criteria

1. Every lane in the Half-A matrix is green, each driven by a demo fixture and
   asserted by a golden test or the scripted `classify_row` / ingest sweep.
2. The Half-B traceability trace exists and the four sanity assertions pass over
   the regenerated demo corpus.
3. `demo/README.md` is reconciled with current doctrine — notably SC-7.1 is
   **Compliant (inherited)**, not "Not Applicable" (inherited ≠ NA per
   `feedback_na_recovery_from_col_qu`); and a *separate* row carries the genuine
   8b NA scope-exclusion case.
4. The whole thing runs from a clean checkout via the documented regenerate +
   ingest + assess steps with no manual data edits.

## Dependencies / notes

- **PSC mapping (lane 10) is unblocked.** Two facts had to be true for the demo
  PSC to read+resolve, and both now are: (1) the demo banner no longer contains a
  header-alias substring (`security control`, `cci`) that made
  `_find_header_row` lock onto the preamble instead of the real header at row 6 —
  fixed in `demo/_build_demo_psc.py`, loader untouched; (2) the DISA CCI catalog
  is loaded *before* PSC resolution at the matching revision. The demo emits a
  **Rev 5** fixture (the revision the app targets) and a **Rev 4** fixture; both
  read cleanly and extract all 16 control IDs. The shipped demo DISA source
  (`demo/cci_list/stig-mapping-to-nist-800-53.xlsx`) carries Rev 4 refs only, so
  the Rev 4 fixture also *resolves* 16/16 against the demo source
  (`demo/_verify_psc_resolution.py`); the Rev 5 fixture resolves against the
  Rev 5 DISA CCI source loaded in the app/env. Rev 3 is not emitted (unused).
- The 8b NA hole (lane 6) was opened *by this branch* — flipping SC-7.1 from
  `Not Applicable` to `Compliant` was correct (inherited ≠ NA) but it removed
  the workbook's only NA example. Add a dedicated scope-exclusion row (NA
  rationale in col Q/U) so the 8b lane stays demonstrable.
- Keep this demo-data + check work; do **not** re-patch `engine/rules.py` to
  tolerate unrealistic fixtures (`feedback`: inheritance logic is a workbook
  concern, not an engine concern).
