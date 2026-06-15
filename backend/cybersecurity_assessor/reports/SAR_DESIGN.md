# SAR Generator — Design Spec

Target audience: implementing agent. Read `reports/pdf.py` and `poam/generator.py`
first — the SAR reuses their patterns.

## What this is

A **Security Assessment Report** (NIST SP 800-53A § 3.6) is the formal deliverable
an assessor produces at the end of a control assessment. It is distinct from the
existing **compliance report** (`reports/pdf.py`):

| Aspect | Compliance report (existing) | SAR (new) |
|---|---|---|
| Audience | Internal / ops | AO, ISSM, eMASS package reviewer |
| Tone | Operational dump, family-by-family | Formal NIST deliverable |
| Findings emphasis | Narrative excerpts | Risk-rated findings + recommendations |
| Cluster unit | Family | Control → POAM cluster |
| Front matter | Cover + exec summary | Cover, scope, methodology, executive summary |
| Back matter | None | Appendices (evidence list, assessment plan, telemetry) |

Don't refactor `pdf.py` to be shared. Copy its styling helpers (or extract a tiny
`_common.py`) so the two reports can diverge without coupling.

## File layout

```
backend/cybersecurity_assessor/
  reports/
    __init__.py          # add: from .sar import build_sar_report
    pdf.py               # existing — leave alone
    sar.py               # NEW
  routes/
    reports.py           # add new endpoint, mirror existing one
```

## Public API

```python
# reports/sar.py
def build_sar_report(session: Session, workbook_id: int) -> bytes:
    """Render a NIST SP 800-53A Security Assessment Report PDF.

    Raises ValueError if the workbook can't be located or has no assessments.
    Raises ImportError if reportlab isn't installed.
    """
```

```python
# routes/reports.py — add alongside workbook_report_pdf
@router.get("/workbook/{workbook_id}/sar.pdf")
def workbook_sar_pdf(workbook_id: int, s: Session = Depends(get_session)) -> Response:
    ...  # identical error handling to workbook_report_pdf
    # download_name = f"sar-{stem}.pdf"
```

## Section structure (in order)

Each section is a separate `_build_section_X(...)` helper that returns a list of
Platypus flowables. `build_sar_report` concatenates them with `PageBreak()` between.

### 1. Cover page
- System name (from `Workbook → System.name`)
- "Security Assessment Report" + framework (e.g. "NIST SP 800-53 Rev. 5")
- Baseline (`Workbook.baseline_id → Baseline.name`, e.g. "Moderate + Example System overlay")
- Assessment period (earliest → latest `Assessment.date_tested`)
- Assessor (most-frequent `Assessment.tester`; fall back to "Noah Jaskolski")
- Report generated date + classification banner (read from `System.description` or
  hard-code "CUI" for now — flag a TODO)

### 2. Executive summary
- One paragraph: system, scope, what was assessed, headline outcome
- Status counts table: Compliant / Non-Compliant / Not Applicable / Inherited
- High-risk findings count (POAMs where `raw_severity` in {High, Very High})
- Reuse the color tokens from `pdf.py` (COMPLIANT=#dcfce7 etc.)

### 3. System description & scope
- From `System` and `Workbook`
- Baseline-defined CCIs in scope: count `BaselineObjective` rows for the
  workbook's baseline
- Out-of-scope / tailored-out: any `BaselineObjective` with a tailoring rationale
  (model has `tailoring_decision` / `tailoring_rationale` — verify field names)
- Inheritance summary: count assessments by `inheritance_rule` value

### 4. Assessment methodology
- Standard NIST SP 800-53A boilerplate paragraph (Examine / Interview / Test)
- **Telemetry from `AssessmentRun`** (most recent run for this workbook):
  - LLM model used, total calls, tokens, cost
  - Validator rejections, supersession hits, CCIs auto-accepted vs human-reviewed
- This is what makes our SAR honest — most SARs hand-wave methodology; ours
  has receipts.

### 5. Assessment results (the body — longest section)

Group **by control** (not by family), in `control_id` sort order. For each
`Control` with at least one assessed `Objective`:

```
AC-2 Account Management
    Control statement: <Control.statement>
    Objectives assessed: 12
    Status: Non-Compliant (2 NC, 10 C)

    Per-objective table:
    | CCI       | Status | Methods | Evidence count | Finding ref |
    | AC-2(a)   | C      | E, T    | 3              | —           |
    | AC-2(j)   | NC     | E, I    | 1              | F-001       |
    ...

    Findings (if any NC): see Findings Summary §6
```

- "Methods" column: derive from `EvidenceTag.source` joined through evidence —
  if any tag.source is `interview`, add "I"; `test`, add "T"; default "E" (examine)
- "Evidence count": `len(EvidenceTag)` for that objective
- "Finding ref" links to §6 via a `POAM → ID` map you build once upfront

Don't dump narratives here — that's what the compliance report does and it
overwhelms the SAR. Narratives live in the appendix.

### 6. Findings summary
- One row per `Poam` (use `generate_for_workbook` results — DO NOT re-cluster)
- Columns: Finding ID, Control(s), Severity, Likelihood × Impact, Residual Risk,
  Description (truncated), Recommended remediation (`mitigations` field),
  Scheduled completion
- Color the severity cell with the same risk-tier palette POAMs use in the UI

### 7. Recommendations
- One bullet per finding: "Address F-001 by <scheduled_completion_date>:
  <one-line mitigation>"
- Group by `RiskLevel` desc so AO sees Very High first

### 8. Appendices

**A. Evidence inventory** — every `Evidence` row referenced by any assessment
in this workbook. Columns: title, doc_number, kind, sha256 (first 12 chars),
superseded? (yes/no based on `superseded_by_id`).

**B. STIG findings** (if any `StigFinding` rows exist) — collapsed table of
rule_id, severity, status. Skip section entirely if zero rows.

**C. Assessment plan** — the list of CCIs in baseline scope (mirrors §3 but full)

**D. Per-objective narratives** — the assessor narratives that don't fit in §5.
One subheading per NC objective: narrative_q + narrative_class.

## Styling

Reuse the `_styles()` helper from `pdf.py` and the existing color tokens. The
SAR should look like a sibling document to the compliance report, not a
redesign. If you find yourself wanting new styles, extract them into a
`reports/_styles.py` shared module rather than duplicating.

## UI hook

Add a "Download SAR" button on the Workbook detail row in `ui/src/routes/Workbooks.tsx`,
next to the existing "Download report" button. Wire it to `/api/reports/workbook/{id}/sar.pdf`
via a new `downloadSar(workbookId)` helper in `ui/src/lib/api.ts` that mirrors
the existing `downloadWorkbookReport`.

## What NOT to do

- Don't invent new data — every field in the SAR must come from an existing
  model. If something feels missing (e.g. "Assessor signature block"), leave a
  `# TODO(sar):` comment, don't add a schema column.
- Don't re-cluster findings. POAMs are the canonical finding unit; the SAR
  presents them, the POAM generator produces them.
- Don't gate on "is the assessment complete?" — generate from whatever's in
  the DB. The button can be disabled in the UI if needed; the backend should
  always render what it has.
- Don't add a watermark, classification banner library, or PDF signing. Phase 2.

## Test plan

- Generate against the current Example System workbook (path is in
  `project_current_assessment` memory)
- Verify: PDF opens, no broken cross-refs, finding count in §6 matches POAM
  count in DB, evidence inventory in §A is non-empty
- Smoke-test the empty case: a workbook with zero assessments should produce
  a SAR with sections 1–4 + 5/6 empty-state messages, not crash
