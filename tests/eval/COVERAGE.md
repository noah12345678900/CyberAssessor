# Eval-harness coverage report

Snapshot of which validator gates and kernel rule-paths are pinned by
fixtures under `tests/eval/cases/` (41 cases, includes 2 real-CCI
ground-truth fixtures from active assessment workbook).

Regenerate by reading `tests/eval/cases/*.json` and matching
`expected.source_in` / `expected.rejection_classes_contains` /
`expected.dual_narrative_flags_contains` against the enums in
`engine/validator.py` and the `source=` literals in `engine/assessor.py`.

## RejectionReason coverage (engine/validator.py:206-245)

| Rejection class               | Cases | Status |
|-------------------------------|------:|--------|
| REQUIREMENT_RESTATEMENT       | 1     | OK     |
| STATUS_NARRATIVE_MISMATCH     | 3     | OK     |
| MISSING_INHERITANCE_MARKER    | 2     | OK (sibling pair, both directions) |
| UNSUPPORTED_DOC_CITATION      | 3     | OK     |
| FORMAT_VIOLATION              | 0     | Not pinnable — defensive branch only reachable by monkeypatching `validator.validate`; integration test at `backend/tests/engine/test_assessor_outcome_branches.py:520` covers it |
| DUAL_NARRATIVE_MISLABEL       | 4     | OK (4 arms: provider-leak, onprem-leak, customer-mismatch, hybrid-empty) |
| FUTURE_TENSE_COMPLIANCE       | 1     | OK     |
| UNCORROBORATED_STIG_PASS      | 1     | OK     |

## Kernel `source=` literal coverage (engine/assessor.py)

| Source literal              | Cases | Status |
|-----------------------------|------:|--------|
| rule_8a                     | 2     | OK (+ structural-L variant) |
| rule_8b                     | 1     | OK     |
| rule-8c                     | 1     | OK (note: hyphen, not underscore — kernel inconsistency) |
| rule_no_evidence            | 3     | OK (both arms of Step 1.65 OR; sibling pair) |
| llm                         | many  | OK     |
| llm_after_retry             | many  | OK (covered as `["llm","llm_after_retry"]` union) |
| abstain                     | 15    | OK (heavily covered) |
| crm_inherited / crm_provider / crm_not_applicable / crm_*+onprem_* | 5 | OK |
| **evidence_chain**          | **0** | **GAP** — `assessor.py:1147, 1475, 1801, 2007` set this when narrative comes from an existing evidence-chain match |
| **col_u_carryover**         | **0** | **GAP** — `assessor.py:1455` when column U prior content is carried verbatim |
| **sda_verified_mapping**    | **0** | **GAP** — `assessor.py:1782` when SDA mapping confirms CCI delivered by SDA service |
| **crm_overlay**             | **0** | **GAP** — `assessor.py:1988` when CRM carries a verbatim narrative |

## Validator phrase-table / regex coverage

| Table / regex                | Pinned by |
|------------------------------|-----------|
| _AFFIRMING_PHRASES           | Every Compliant happy-path case (implicit) |
| _NA_PHRASES                  | NA + CRM short-circuit cases (implicit) |
| _GAP_PHRASES                 | gap_describing_nc.json (implicit) |
| _RESTATEMENT_REGEXES         | requirement_restatement_rejection.json |
| _PROVIDER_ONLY_PHRASES       | dual_narrative_leak_advisory.json |
| _ONPREM_ONLY_PHRASES         | dual_narrative_leak_cloud_onprem_terms.json |
| _FUTURE_TENSE_RE             | future_tense_rejection.json |
| _INHERITANCE_SOURCE_RE       | missing_inheritance_marker_rejection + inheritance_marker_present_accepted (sibling pair) |
| _HYBRID_SPLIT_RE             | hybrid_split_misclassification + hybrid_split_narrative_accepted + hybrid_ambiguous_bubble_up + hybrid_all_na_fallthrough |
| _PRIMARY_CITATION_RE         | Exercised in many cases, no targeted pin |

## Real gaps to consider closing

1. **evidence_chain** source — `assessor.py:1147` happy-path where the
   LLM proposal cites a USD/SV-#####r#_rule that's already in the
   workbook's evidence chain index; assessor short-circuits to a
   chain-derived narrative.
2. **col_u_carryover** source — `assessor.py:1455` when prior-assessor
   narrative in column U is carried over (with explicit assessor
   sign-off) and the LLM is bypassed entirely.
3. **sda_verified_mapping** source — `assessor.py:1782` when SDA Controls
   sheet col F maps the CCI to a delivered SDA service.
4. **crm_overlay** source — `assessor.py:1988` when CRM responsibility
   carries a verbatim narrative the assessor uses verbatim. Distinct
   from the `crm_inherited` / `crm_provider` short-circuit family
   already covered.

## Real-CCI ground-truth fixtures (verbatim from active workbook)

Two cases capture verbatim col-Q narratives from
`CCIS_Example_System_Export.xlsx`. Both currently
pin the FAILURE mode (hard-abstain) because the real human-authored
narratives expose validator phrase-table coverage gaps:

| Case                                             | Control / CCI       | Verdict author intended | Validator outcome | Gap pinned |
|--------------------------------------------------|---------------------|--------------------------|-------------------|------------|
| `ground_truth_ac6_least_privilege_nc.json`       | AC-6.1 / CCI-000225 | Non-Compliant            | hard-abstain      | `_GAP_PHRASES` too narrow — misses "not fully deployed", "excess permissions", "lack permissions", "not consistently enforced" |
| `ground_truth_sa9_external_provider_na.json`     | SA-9.1 / CCI-000669 | Not Applicable           | hard-abstain      | NA + GAP phrase-class collision — "not applicable —" (NA) + "does not currently" (GAP) → AMBIGUOUS classification |

Forcing-function design: when the validator gains coverage for either
gap (extended `_GAP_PHRASES` OR an NA-precedence rule when both NA and
GAP fire), these cases will flip from hard-abstain to source='llm'
with the intended verdict — the assertion deltas force a fixture review
and acknowledgment of the improvement.

## Tagger harness coverage (engine/evidence/tagger.py)

Separate parametrized harness at `tests/eval/tagger/test_tagger_precision.py`
covers the deterministic 4-tier `tag_evidence` adapter. 22 case files,
fully isolated per-case in-memory SQLite catalogs (no shared fixture
state). All cases pass in ~1.6s.

| Tier / shape                | Cases | Notes |
|-----------------------------|------:|-------|
| Tier 1 — doc-number match   | 3     | Direct match, padding variants, in body text |
| Tier 2 — CCI references     | 4     | STIG-finding structured branch, kind-gated PDF (post-fix), case-insensitive, inline-in-text |
| Tier 3 — control ID in text | 3     | Body text, filename, enhancement form (e.g. AC-2(1)) |
| Tier 4 — evidence-type map  | 3     | hw_inventory, sw_inventory, asset_inventory xlsx |
| Negative / no signals       | 3     | Empty body, random alphanumeric (not CCI format), wrong control-ID format |
| Dedup / idempotency         | 2     | Same objective via two tiers, rerun produces zero new rows |
| Pins of current behavior    | 0     | (all five originally-documented failure modes now FIXED + re-recorded) |
| Re-recorded after fixes     | 5     | tier2_kind_gated_pdf_casual_mention (2026-06-07 kind-gate), tier_framework_filter_isolates_lens (2026-06-07 framework filter), pin_tier3_spray_one_mention_tags_all_children (2026-06-07 primary-CCI), pin_tier4_spray_sw_inventory_tags_four_controls (2026-06-07 sw_inventory→cm-8 + primary-CCI), pin_control_id_in_path_only (2026-06-07 Tier 3 text-only) |

**Five originally-documented failure modes** (per
`tests/eval/tagger/cases/README.md`):
- Tier 3 spray — FIXED 2026-06-07, case re-recorded (text-only + primary-CCI narrowing: one tag per matched Control on the lowest-objective_id CCI; per-Control LLM bundler still surfaces evidence to sibling CCIs)
- Tier 4 spray — FIXED 2026-06-07, case re-recorded (EVIDENCE_TYPE_TO_CONTROLS['sw_inventory'] narrowed to ['cm-8'] + primary-CCI narrowing)
- Control ID in path only — FIXED 2026-06-07, case re-recorded (Tier 3 no longer scans evidence.path; rename-attack mitigated; sibling case tier3_control_id_in_filename re-recorded as negative)
- STIG CCI_RE casual-mention scrape — FIXED 2026-06-07, case re-recorded
- No framework filter (cross-framework leak) — FIXED 2026-06-07, case re-recorded

The re-recorded cases are the regression-gate proof that the kind-gate,
framework-filter, primary-CCI narrowing, sw_inventory narrowing, and
text-only Tier 3 fixes landed without widening or narrowing unintended
behavior.

## What's adequately covered

- All validator-side rejection branches except FORMAT_VIOLATION
  (intentional — not fixture-reachable)
- All abstain paths (15 cases — corpus target was 15 per priorities
  memo, met)
- Both arms of the Step 1.65 OR gate (sibling pair)
- Hybrid split classification ladder (4 cases covering 4 branches)
- Dual-narrative leak detection (4 cases — both directions plus CRM
  cross-check arms)
- Inheritance-marker gate (sibling pair, both directions)

## Marginal value of additional validator gate-pins

Low. The 4 remaining `source=` gaps above are all in the deterministic
kernel rule-path (not the LLM-loop), and three of them
(col_u_carryover, sda_verified_mapping, crm_overlay) require fixture
hooks the harness doesn't expose yet (prior-assessor column-U content,
SDA Controls overlay, CRM verbatim-narrative field). Each one is a
slice of its own, not a sibling pair extension.

Higher leverage:
- Real-CCI ground-truth cases from active assessments (catches
  semantic regressions, not code-path regressions)
- Live-LLM mode (catches prompt regressions invisible to stubs)
- Tagger eval cases for retrieval precision
