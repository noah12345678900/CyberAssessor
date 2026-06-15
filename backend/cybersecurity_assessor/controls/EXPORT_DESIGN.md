# Controls Export — Design Notes

Two writers live in [`exporter.py`](./exporter.py):

| Function                          | Output                       | Engine     | Row grain      | needs_review |
|-----------------------------------|------------------------------|------------|----------------|--------------|
| `export_controls_to_emass`        | Copy of user's template      | xlwings    | one per control | **excluded** |
| `export_controls_working_view`    | Fresh xlsx                   | openpyxl   | one per CCI    | included     |

Both surface a `ControlExportResult` so the UI can show
`rows_written` / `controls_with_psc` / `skipped` / `template_warnings`
without parsing the xlsx itself.

---

## eMASS export — template column contract

The user supplies an `enterprise services controls.xlsx`. The writer:

1. Opens the template via xlwings (live Excel — preserves the other 28
   tabs, data validation, conditional formatting, hidden columns).
2. Locates the `Controls` sheet by name (`_DEFAULT_SHEET_NAME`).
3. Locates the **Control Acronym** column by header text. The matcher
   in `_CONTROL_ACRONYM_HEADERS` is case-insensitive and tolerates the
   variants we've seen across program copies:
   - `Control Acronym`
   - `Control Number`
   - `Control ID`
   - `Controls / APs`
4. Inserts a new column titled **Program-Specific Controls** at
   `acronym_col + 1`. If a column with that header already exists in
   row 1, the insert is skipped and the existing column is re-used
   (idempotency — see below).
5. Looks up the `Status` column by header text. If not present, the
   writer emits a `template_warnings` entry and skips status writes
   for that run — the rest of the export still goes out so the
   operator gets the PSC column they came for.
6. Writes one row per in-scope control. The `Status` cell receives
   the multi-line rollup; the PSC cell receives the
   source-prefixed lines (see below).

### Status rollup rule

`_rollup_status` buckets each control's objectives by **effective**
status (CRM-inherited objectives bucket as `Compliant`) and emits one
line per non-empty bucket:

```
Compliant: CCI-000196, CCI-000197 (inherited from AWS GovCloud)
Non-Compliant: CCI-000198 (no documented sanctions procedure)
```

Bucket order (display): `Compliant`, `Non-Compliant`, `Not Applicable`,
`Needs Review`.

Reason text precedence:

1. CRM short-circuit → `"inherited from <crm_source>"`
2. Validator auto-compliant marker → `"Rule 8a auto-compliant"`
3. Narrative first sentence, truncated to ~80 chars

Single-bucket controls collapse to the status token alone (no list /
no reason) so reviewers don't see noise like
`Compliant: CCI-000015, CCI-000016` on uncontroversial rows. This is
also closer to what the canonical eMASS Status field expects when
there's nothing ambiguous to surface.

### PSC column format

`_format_psc_column` groups by `RequirementSource.name`, sorts by
`requirement_number`, and emits:

```
SDA-127: Implement…
SDA-128: Verify…
T1TL-031: All operator…
```

- Each line capped at `_PSC_LINE_MAX` (500 chars) so a single verbose
  requirement can't blow the row budget.
- Total cell capped at `_EXCEL_CELL_MAX` (32,767 — Excel's hard limit).
  Overflow appends `…[N more truncated]` instead of raising.

### needs_review exclusion

Per `feedback_precision_over_recall`, the eMASS writer skips any
control whose only assessable objectives are `needs_review=True` and
includes the skipped row in `result.skipped` as
`(control_acronym, "needs_review")`. Mixed controls (some real
verdicts + some needs_review) write the real verdicts and silently
drop the abstain rows from the rollup — the assessor surfaces the
abstain queue separately on the Review Queue page.

---

## Idempotency guarantee

Re-running `export_controls_to_emass` onto the same `output_path`
(common operator flow: "I tweaked AC-3, give me a fresh export onto
my existing file") must leave **exactly one** Program-Specific
Controls column. `_ensure_psc_column` checks for the header first and
returns the existing index instead of inserting a duplicate.

Test pin: `test_idempotent_psc_column_not_double_inserted` in
[tests/controls/test_exporter_emass.py](../../tests/controls/test_exporter_emass.py).

---

## eMASS schema rigidity caveat

Inserting the PSC column shifts every column right of Control Acronym
by one position. If a downstream importer (eMASS batch upload, an
internal validator, a Power Automate flow) keys off **ordinal column
position** rather than header text, this export will break that
consumer.

We surface this in the export dialog:

> Caveat: inserting the PSC column shifts every column right by one.
> If a downstream batch importer keys off ordinal position rather
> than header text, strip the PSC column before upload.

The user's enterprise-services template is header-keyed in practice
(the program review workflow goes through Excel, not a programmatic
importer), so this is a low-risk default. A future
"strip PSC before final upload" toggle is a possible follow-on if
the canonical eMASS batch importer ever lands.

---

## Working-view export

`export_controls_working_view` is the assessor's own working artifact,
not a deliverable. Differences from eMASS:

- **Fresh openpyxl xlsx** — no template, no Excel app required (so
  the working-view path runs in CI; the eMASS path is gated behind
  `@pytest.mark.requires_excel`).
- **One row per objective**, not per control — needs_review rows,
  abstain reasons, and per-CCI narratives all surface for triage.
- **Honors the page filter** — `family`, `status`, `search` parameters
  mirror what the Controls page UI exposes, so the exported file
  matches what the assessor was looking at on screen.
- **Does not stamp `exported_at`** — only eMASS exports count as
  deliverables.

---

## Stamps & invalidation

The eMASS endpoint writes `Workbook.exported_at = _utcnow()` on
success. The UI mutation invalidates `["workbook"]` and `["workbooks"]`
query keys so the Last Exported badge on the workbook header refreshes
without a manual reload.

Working-view exports are ephemeral; no stamps, no invalidation.

---

## Files touched

- [`exporter.py`](./exporter.py) — the two writers + helpers
- [`../routes/controls.py`](../routes/controls.py) — POST
  `/api/controls/export/emass`, POST `/api/controls/export/working`
- [`../models.py`](../models.py) — `Workbook.exported_at` field
- [`../../tests/controls/`](../../tests/controls/) — four test files:
  `test_rollup_status.py`, `test_exporter_working.py`,
  `test_export_endpoints.py`, `test_exporter_emass.py` (requires_excel)
- [`ui/src/routes/Controls.tsx`](../../../ui/src/routes/Controls.tsx) —
  two header buttons + two inline export dialogs
- [`ui/src/lib/api.ts`](../../../ui/src/lib/api.ts) —
  `ControlExportResultDto` + `exportControls{Emass,Working}` methods
- [`ui/src/lib/queries.ts`](../../../ui/src/lib/queries.ts) —
  `useExportControls{Emass,Working}` mutation hooks
