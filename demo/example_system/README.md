# Example System — real-artifact end-to-end test bundle

Local-only slot for a **real** artifact set used to exercise the
assessor end-to-end without hunting through `~/Downloads` or sync
folders. Populate it with your own program's artifacts.

> **Local only — do not commit artifacts.** Every data file here is
> `*.xlsx` / `*.docx` / `*.csv`, all of which are blocked by both the
> repo `.gitignore` and the folder-local `.gitignore` (`*` with
> `!README.md` `!.gitignore`). This folder exists on your local disk
> only; only this README and the `.gitignore` are tracked.

## What goes here

| Subfolder | File (example) | What it is | Used by |
|---|---|---|---|
| `catalogs/` | `stig-mapping-to-nist-800-53.xlsx` | NIST CSRC STIG-to-800-53 mapping — authoritative DISA CCI catalog source (`CCI-000001`..`CCI-003938` mapped to control IDs). Replaces the legacy `U_CCI_List.xml`. | **Settings → Load DISA CCI catalog** (`POST /api/catalog/load/disa-cci`) |
| `catalogs/` | `NIST_SP-800-53_rev5.2_OSCAL_controls.csv` | OSCAL export of NIST SP 800-53 Rev 5.2 controls. Source of truth for control titles / statements when the bundled JSON catalog is out of date. | **Settings → Load NIST 800-53 Rev 5 catalog** (`POST /api/catalog/load/nist-800-53r5`) |
| `ccis/` | `CCIS_Example_System_Export.xlsx` | Program CCIS workbook — in-scope CCIs across the relevant control families, WORKING SHEET tab, rows 7+ are CCI data | **Workbooks → Open** (primary input to the whole app) |
| `emass_template/` | `enterprise services controls.xlsx` | Enterprise-services controls template — multi-tab, `Controls` is the main sheet, with an optional program-overlay tab (CCI-grain) | **Controls → Export to eMASS** (template_path picker) AND **Baselines → Load program-controls overlay** for the overlay tab |
| `overlays/` | `program_controls_overlay.xlsx` | Program controls overlay (control-grain) — exercises the loader's second auto-detect path (`Associated CNSSI 1253 [Control Tag:] AC-2(13)` prose pattern, fanned out across each control's CCIs) | **Baselines → Load program-controls overlay** (`POST /api/catalog/load/program-controls`) |
| `crm/` | `AWS_GovCloud_FedRAMP_High_CRM.xlsx` | AWS GovCloud FedRAMP High Customer Responsibility Matrix | **Workbooks → Attach CRM overlay** (provider/customer/hybrid/inherited tagging) |
| `policies/` | `SSP.docx` | System Security Plan — authoritative PL family | **Evidence → Ingest folder** |
| `policies/` | `Cybersecurity_Architecture.docx` | Program cybersecurity architecture (cloud/on-prem environments) | **Evidence → Ingest folder** |

## End-to-end test path

From a clean sidecar + Electron start. Steps in order — earlier loads
are prerequisites for later ones (CCI rows must exist before a workbook
can hydrate; both overlays attach to an already-open workbook).

1. **Settings → Catalogs → Load DISA CCI** →
   `demo/example_system/catalogs/stig-mapping-to-nist-800-53.xlsx`
   - Expect: ~3.9K CCI rows loaded; loader sniffs the extension and
     uses the NIST CSRC xlsx path, not the legacy XML path.
2. **Settings → Catalogs → Load NIST 800-53 Rev 5** →
   `demo/example_system/catalogs/NIST_SP-800-53_rev5.2_OSCAL_controls.csv`
   - Expect: ~1,200 control rows including titles, statements,
     enhancements.
3. **Workbooks → Open** →
   `demo/example_system/ccis/CCIS_Example_System_Export.xlsx`
   - Framework: NIST SP 800-53 Rev. 5
   - Expect: in-scope objectives loaded across the control families.
4. **Baselines → Load program-controls overlay** →
   either `demo/example_system/emass_template/enterprise services controls.xlsx`
   (overlay tab — CCI-grain) **or**
   `demo/example_system/overlays/program_controls_overlay.xlsx`
   (control-grain — exercises the prose-tag fan-out path)
   - Expect: program-specific controls tagged onto matching CCIs;
     visible on Control Detail in the Program-Specific Controls card.
5. **Workbooks → Attach CRM overlay** →
   `demo/example_system/crm/AWS_GovCloud_FedRAMP_High_CRM.xlsx`
   - Expect: controls tagged provider / customer / hybrid / inherited;
     inherited / provider controls short-circuit to Compliant without
     an LLM call.
6. **Evidence → Ingest folder** → `demo/example_system/policies/`
   - Expect: docx files extracted, document numbers tagged onto
     matching CCIs via the narrative-citation tagger.
7. **Controls** → pick an AC-family control (e.g., AC-2) and click
   **Assess**
   - Expect: status proposal + narrative referencing the ingested SSP
     sections, no hallucinated doc numbers. PSC card on the detail
     page lists the program-control mappings from step 4.
8. **Controls → Export to eMASS** →
   - Template: `demo/example_system/emass_template/enterprise services controls.xlsx`
   - Output: anywhere (e.g., `demo/example_system/_out/Example_System_eMASS.xlsx`)
   - Expect: PSC column inserted at column B, multi-line Status rollup,
     needs_review controls skipped, `Workbook.exported_at` stamped.
9. **Controls → Export (Working View)** → output anywhere
   - Expect: one row per objective, includes needs_review + abstain
     reasons, mirrors current filter state.

## Refreshing the artifacts

When the source files change (new CCIS export, updated SSP, etc.),
re-copy from their canonical locations on your local disk:

```sh
# CCIS workbook + SSP/architecture docs live in your local snapshot
cp ~/Downloads/local_snapshot/CCIS_Example_System_Export.xlsx \
   demo/example_system/ccis/
cp ~/Downloads/local_snapshot/*.docx \
   demo/example_system/policies/

# eMASS template + CRM live in Downloads root
cp "~/Downloads/enterprise services controls.xlsx" \
   demo/example_system/emass_template/
cp ~/Downloads/AWS_GovCloud_FedRAMP_High_CRM.xlsx \
   demo/example_system/crm/

# Catalog sources — NIST CSRC STIG mapping + OSCAL controls CSV
cp ~/Downloads/stig-mapping-to-nist-800-53.xlsx \
   demo/example_system/catalogs/
cp ~/Downloads/NIST_SP-800-53_rev5.2_OSCAL_controls.csv \
   demo/example_system/catalogs/

# Program controls overlay (control-grain example)
cp "~/Downloads/program_controls_overlay.xlsx" \
   demo/example_system/overlays/
```

Keep a pristine copy of the original workbook somewhere untouched as a
re-import baseline.

## Why this folder vs the synthetic `demo/` siblings

| Folder | Data | Purpose |
|---|---|---|
| `demo/ccis/`, `demo/policies/`, `demo/scans/`, etc. | **Synthetic** demo system | Unit tests, CI smoke tests, fresh-developer onboarding (nothing sensitive) |
| `demo/example_system/` (this folder) | **Real** program IATT package | Live end-to-end exercise against actual program data — what gets demoed to reviewers |

Keep the two separate. The synthetic set is regenerated by
`demo/_build_demo_artifacts.py` / `demo/_build_demo_ccis.py`; the
Example System set is manually mirrored from your local disk.
