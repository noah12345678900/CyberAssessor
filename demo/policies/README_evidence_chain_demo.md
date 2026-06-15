# Evidence-chain rewriter demo

This pair of files exercises the **evidence-chain** path of the
deterministic stale-citation rewriter shipped in the
"patent-aligned stale-citation warnings" slice.

## Files

- `Example System Demo Account Mgmt Procedure Manual Rev A.txt`
- `Example System Demo Account Mgmt Procedure Manual Rev B.txt`

Both contain the same `Document Number: USD20260601`. At ingest, the
supersession tracker's Policy A (`_policy_same_doc_number`) sees the
shared doc_number, marks Rev A as `superseded_by_id = <RevB.id>`, and
stamps the new audit fields:

- `superseded_at` = ingest time
- `superseded_policy = "same_doc_number"`
- `superseded_reason = "doc_number='USD20260601' matched newly-ingested evidence id=<id>"`

## How to drive the chain rewriter

1. Load both files via Evidence → Add files (any order; the tracker
   handles both A-then-B and B-then-A).
2. In the demo CCIS workbook
   (`demo/ccis/CCIS_Example System_Demo_System_2026May.xlsx`), open the **AC-2.4**
   row (currently blank, marked "assessor's turn" in `demo/README.md`)
   and paste this snippet into column U:

       Account inventory maintained per Example System Demo Account Mgmt Procedure
       Manual Rev A section 4.2; quarterly attestations on file in the
       Example System Demo SharePoint workspace.

3. Re-import the workbook and run an assessment over AC-2.4.

## What you should see

- **Column Q narrative** no longer contains the literal string
  `Example System Demo Account Mgmt Procedure Manual Rev A`. The chain rewriter
  substitutes the chain head's preferred ref — Rev B's doc_number,
  `USD20260601` — so the persisted narrative cites the current
  authoritative document.
- **Decision Trace → Supersession hits** shows one row with
  `source = "evidence_chain"` (UI chip label: **Evidence chain**),
  `stale_ref = "Example System Demo Account Mgmt Procedure Manual Rev A"`,
  `current_ref = "USD20260601"`.
- **Evidence panel** marks Rev A as superseded; the new audit fields
  (`superseded_at`, `superseded_policy`, `superseded_reason`) are
  populated and visible in any DB-level query.

## Why this isolates the chain rewriter (vs. the doc-phrase rewriter)

The legacy phrase `Example System Demo Account Mgmt Procedure Manual Rev A` is
**not** in `engine.supersession._LEGACY_TO_CURRENT` (that table only
covers historical SDA T1/SSAA phrasings). So the existing
`rewrite_narrative` doc-phrase pass is a no-op on this column-U text —
the only hit you'll see is the new `evidence_chain` one. That makes
the demo a clean unit-of-one for showing the patent-supporting
evidence-aware path.
