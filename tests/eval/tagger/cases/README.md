# Tagger eval cases — schema & conventions

Each `*.json` file in this directory is one parametrized case for
[../test_tagger_precision.py](../test_tagger_precision.py). The test
ID matches the filename stem, so `pytest -k tier3_control_id_in_text`
runs exactly one case.

The tagger under test is
[`tag_evidence`](../../../../backend/cybersecurity_assessor/evidence/tagger.py)
— deterministic, no LLM, no embeddings, no network. Every case runs
every time.

## Why cases exist (three buckets)

**A. Tier coverage (filename: `tier{1-4}_*.json`).** One case per tier
× main shape. Documents what each tier does and pins it. A
case-file edit that flips an `expected` count means a tier semantic
just changed — deliberate or regression.

**B. Regression pins (filename: `pin_*.json`).** Five known-behavior
anchors, one per failure mode named in the plan
(`.claude/plans/dreamy-wobbling-chipmunk.md`). Each pin's
`description` says verbatim "this is a pin of CURRENT behavior, not a
correctness claim." When a fix slice lands, the matching pin
re-records to assert correct behavior — the re-record IS the gate
that proves the fix landed without unintended widening or narrowing.

The five pins:

| Pin | Failure mode |
| --- | --- |
| `pin_tier3_spray_one_mention_tags_all_children` | One body mention of "AC-2" tags every ac-2 child objective at 0.7/0.5 |
| `pin_tier4_spray_sw_inventory_tags_four_controls` | `evidence_type="sw_inventory"` fans out to cm-8, cm-7.5, cm-10, cm-11 children |
| `pin_stig_cci_re_scrapes_casual_mentions` | `_CCI_RE` scrapes EVERY CCI mention, no finding-vs-quote anchor |
| `pin_no_framework_filter_cross_framework_leak` | Same CCI under r4 + r5 → tag stamps both rows |
| `pin_control_id_in_path_only` | `AC-2_policy.pdf` tags AC-2 children even when text is empty |

**C. Negative + dedup (filename: `negative_*.json`, `dedup_*.json`).**
"No signals → no tags", random alphanumeric strings that look like
CCIs but don't match `CCI-\d{6}`, same objective hit via two tiers
(dedup via `_existing_pairs`), rerun-idempotency (calling
`tag_evidence` twice on the same evidence adds zero rows).

## Schema

```jsonc
{
  // Required: human-friendly case name (informational; test ID uses the
  // filename stem, not this field).
  "name": "tier3_control_id_in_text",

  // Required: what this case pins, and WHY. For pin_* cases, must
  // explicitly say "pin of current behavior, not a correctness claim"
  // so a future reader knows re-recording is intentional.
  "description": "...",

  // Required: minimal catalog the case operates against. Self-contained
  // per case (no shared fixture) so assertions like "tags all 3 ac-2
  // children" stay exact regardless of real-catalog version drift.
  "catalog": {
    // Single-framework form (common). Use "frameworks" (plural) for
    // multi-framework pins (currently only pin_no_framework_filter_...).
    "framework": {
      "framework_id": "NIST-800-53r4",   // string identifier, NOT the row PK
      "name": "NIST 800-53",             // optional, defaults to "Test Framework"
      "version": "Rev 4"                 // optional, defaults to "test"
    },
    "controls": [
      {
        "control_id": "ac-2",            // catalog form (lowercase, dot notation)
        "title": "Account Management",   // optional
        "family": "AC",                  // optional, derived from control_id prefix
        "framework_id": "NIST-800-53r4"  // optional, defaults to first framework
      }
    ],
    "objectives": [
      {
        "control_id": "ac-2",            // matches a control above
        "objective_id": "CCI-000015",    // string ID (CCI or AO/Practice form)
        "text": "...",                   // optional
        "implementation_guidance": "USD-22222 implements ...",  // for Tier 1 LIKE match
        "assessment_procedures": "...",
        "source": "CCI",                 // optional, defaults "CCI"
        "framework_id": "NIST-800-53r4"  // optional, defaults to first framework
      }
    ]
  },

  // Required: the one Evidence row this case feeds to tag_evidence.
  "evidence": {
    "filename": "policy.pdf",            // required, drives URI + kind
    "text": "This policy implements AC-2 ...",  // optional, fed as `text` arg
    "doc_number": "USD00022222",         // optional, fed to Tier 1
    "kind": "PDF",                       // optional, override _KIND_BY_SUFFIX
    "title": "Acme AC Policy",           // optional, defaults to filename
    "path_override": "file:///fixtures/AC-2_policy.pdf",  // optional, used by
                                         // pin_control_id_in_path_only
    "evidence_type": "sw_inventory",     // optional, drives Tier 4
    "evidence_type_signals": ["hostname","manufacturer"],  // optional
    "stig_findings": [                   // optional, passed by value to Tier 2
      {
        "rule_id": "SV-12345r1_rule",
        "status": "Open",                // FindingStatus name (Open / Not_A_Finding / ...)
        "cci_refs": "CCI-000015, CCI-000016",
        "severity": "medium",
        "finding_details": "...",
        "comments": "..."
      }
    ]
  },

  // Optional: framework_id passed to tag_evidence.
  //   * key absent OR null → framework-agnostic call (None PK, historical)
  //   * string             → resolved via catalog id_map to the int PK
  //   * int                → passed through (escape hatch)
  "framework_id": "NIST-800-53r4",

  // Optional: re-invoke tag_evidence a second time with identical args
  // and assert the EvidenceTag count is unchanged. Pins the
  // `_existing_pairs` dedup invariant.
  "rerun_must_not_duplicate": true,

  // Required: what the case asserts.
  "expected": {
    // Total EvidenceTag rows for this evidence. Null/missing = skip
    // the recall-ceiling check.
    "tag_count": 3,

    // TaggingResult per-tier counters. Only keys named here are
    // checked — a case can pin one tier and ignore the rest.
    "tier_hits": {
      "doc_number_hits": 0,
      "cci_hits": 0,
      "control_id_hits": 3,
      "evidence_type_hits": 0
    },

    // Each entry MUST be tagged. Partial-match dict — only
    // ``objective_id`` is required; other keys are checked only when
    // present.
    "tags_must_include": [
      {
        "objective_id": "CCI-000015",
        "source": "auto",
        "relevance": 0.7,
        "confidence": 0.5,
        "rationale_contains": "Control ID AC-2",
        "framework_id": 1                // optional, the Framework row PK
      }
    ],

    // Each entry MUST NOT be tagged. Catches the spray failure modes —
    // a case can declare "AC-2 mention does NOT tag AC-3's children".
    "tags_must_not_include": [
      {"objective_id": "CCI-000213"}
    ]
  }
}
```

## Adding a new case

1. Pick a bucket and follow its filename convention
   (`tier{1-4}_<shape>.json`, `pin_<failure_mode>.json`,
   `negative_<...>.json`, `dedup_<...>.json`).
2. Copy the closest existing case as a starting template. Self-contain
   the catalog — never reference rows another case seeded.
3. Write `description` so a reader who has never seen the tagger can
   tell whether the case is a correctness assertion or a pin.
4. Run `uv run --no-sync pytest tests/eval/tagger/ -v -k <stem>`. If
   it fails, you're either pinning the wrong thing or the tagger
   behavior diverged from your mental model — diagnose before
   editing the case.

## Re-recording a pin (the regression-gate moment)

When a fix slice lands that addresses a failure mode (e.g. adds a
framework filter to Tier 2/3/4 lookups):

1. Run the harness — the matching `pin_*` case will FAIL because the
   fix narrowed behavior.
2. Edit the case file:
   * Update `description` from "pin of current behavior" to "asserts
     correct behavior after <fix-slice-name>".
   * Update `expected.tag_count`, `expected.tier_hits`,
     `expected.tags_must_include`, and `expected.tags_must_not_include`
     to reflect the new (correct) behavior.
3. Re-run. Now passes. The case has flipped from "pin" to "assert".

If a re-record requires changing more than the four `expected.*`
fields, the fix probably did more than narrow one tier — pause and
write the slice up.
