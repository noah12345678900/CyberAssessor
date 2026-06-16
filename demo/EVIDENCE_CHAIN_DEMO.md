# Evidence-chain rewriter demo

This pair of files exercises the **evidence-chain** path of the
deterministic stale-citation rewriter shipped in the
"patent-aligned stale-citation warnings" slice.

> This doc lives at `demo/` root (NOT under `demo/policies/`) on purpose:
> it cites the document number `USD20260601` in prose, and if it were
> ingested as evidence the extractor would mis-attribute that cited number
> as the README's own doc_number, colliding with the two real manuals.

## Files

Both live under `demo/policies/`:

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

## Where this shows up in the UI

Supersession is fully data-driven off the evidence chain (there is no
hand-edited phrase registry). After ingesting Rev A + Rev B for a
workbook, open **Metrics → Accuracy mechanisms → Document supersessions**
and pick that workbook: the detected chain appears as
`Example System Demo Account Mgmt Procedure Manual Rev A → USD20260601`,
matched on **Doc number**. The view is per workbook, so a different
workbook with no superseded evidence shows the empty state.
