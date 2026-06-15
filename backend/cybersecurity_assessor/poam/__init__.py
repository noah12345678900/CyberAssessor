"""POAM (Plan of Action & Milestones) generation, persistence, and eMASS
round-trip.

Submodules:
  risk      — NIST SP 800-30 Rev 1 likelihood/impact/risk lookup tables.
  template  — eMASS RMF POAM template column map (single source of truth for
              read+write column indices).
  generator — clusters Non-Compliant assessments into draft POAMs per the
              natural-remediation-boundary heuristic
              (feedback_poam_scoping.md).
  exporter  — writes a workbook's POAMs into the eMASS template (xlwings,
              preserves formatting / data validation).
  importer  — reads an existing eMASS POAM workbook back into the DB, merging
              on emass_poam_id where present.
"""
