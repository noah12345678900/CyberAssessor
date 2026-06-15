"""eMASS RMF POAM template column map.

Single source of truth for the eMASS Plan of Action and Milestones workbook
layout. Verified against:
  C:/Users/Noah.Jaskolski/Downloads/RMFPoam_Example_System_Export_2.xlsx

Layout:
  - Row 1:    CUI banner
  - Row 2:    "Plan of Action and Milestones (POA&M)" title
  - Rows 3-11: System header (Date Initiated, System Name, POC, etc.)
  - Row 12:   COLUMN HEADERS    ← HEADER_ROW
  - Row 13+:  POAM data rows    ← DATA_START_ROW
"""

from __future__ import annotations

from dataclasses import dataclass

HEADER_ROW = 12
DATA_START_ROW = 13
SHEET_NAME = "RMF_POAM"


@dataclass(frozen=True)
class PoamColumn:
    """One column in the eMASS template. `letter` is the Excel column letter
    (for openpyxl/xlwings); `header` is the exact header text in row 12 (used
    to validate on import — if the template ever shifts, we fail loudly)."""

    letter: str
    header: str


# eMASS columns — order matches row 12 of the template. The cell labels for
# columns that participate in merged ranges (e.g. B+C "Vulnerability
# Description") write into the left cell; the merge is preserved by the
# template's existing formatting when we write through xlwings.
COLS: dict[str, PoamColumn] = {
    "id":                            PoamColumn("A",  "ID"),
    "vulnerability_description":     PoamColumn("B",  "Vulnerability Description"),
    "controls_aps":                  PoamColumn("D",  "Controls / APs"),
    "control_criticality":           PoamColumn("F",  "Control Criticality"),
    "security_checks":               PoamColumn("G",  "Security Checks"),
    "status":                        PoamColumn("H",  "POA&M Status"),
    "scheduled_completion_date":     PoamColumn("I",  "POA&M Scheduled Completion Date"),
    "pending_extension_date":        PoamColumn("M",  "POA&M Pending Extension Date"),
    "extension_date":                PoamColumn("N",  "POA&M Extension Date"),
    "risk_accepted_date":            PoamColumn("O",  "POA&M Risk Accepted Date"),
    "requested_risk_accepted_exp":   PoamColumn("P",  "POA&M Requested Risk Accepted Expiration Date"),
    "risk_accepted_expiration_date": PoamColumn("Q",  "POA&M Risk Accepted Expiration Date"),
    "completion_date":               PoamColumn("R",  "POA&M Completion Date"),
    "milestone_id":                  PoamColumn("S",  "Milestone ID"),
    "milestone_description":         PoamColumn("V",  "Milestone Description"),
    "milestone_status":              PoamColumn("W",  "Milestone Status"),
    "milestone_status_comments":     PoamColumn("X",  "Milestone Status Comments"),
    "milestone_scheduled_date":      PoamColumn("Y",  "Milestone Scheduled Completion Date"),
    "milestone_completion_date":     PoamColumn("Z",  "Milestone Completion Date"),
    "artifacts":                     PoamColumn("AA", "Artifacts"),
    "identification_source":         PoamColumn("AB", "Identification Source"),
    "identification_source_details": PoamColumn("AC", "Identification Source Details"),
    "office_org":                    PoamColumn("AD", "Office / Org"),
    "resources":                     PoamColumn("AE", "Resources"),
    "comments":                      PoamColumn("AF", "Comments"),
    "raw_severity":                  PoamColumn("AG", "Raw Severity"),
    "devices_affected":              PoamColumn("AH", "Devices Affected"),
    "mitigations":                   PoamColumn("AI", "Mitigations"),
    "predisposing_conditions":       PoamColumn("AJ", "Predisposing Conditions"),
    "severity":                      PoamColumn("AK", "Severity"),
    "relevance_of_threat":           PoamColumn("AL", "Relevance of Threat"),
    "threat_description":            PoamColumn("AM", "Threat Description"),
    "likelihood":                    PoamColumn("AN", "Likelihood"),
    "impact":                        PoamColumn("AO", "Impact"),
    "impact_description":            PoamColumn("AP", "Impact Description"),
    "residual_risk":                 PoamColumn("AQ", "Residual Risk Level"),
    "recommendations":               PoamColumn("AR", "Recommendations"),
    "resulting_residual_risk":       PoamColumn("AS", "Resulting Residual Risk Level after Proposed Mitigations"),
    "cfo_audit_flag":                PoamColumn("AT", "Identified in CFO Audit or other review"),
    # ------------------------------------------------------------------
    # Personnel + Non-Personnel Resources (AU–BD).
    #
    # eMASS treats these as a resource-cost ledger attached to the POAM:
    # personnel hours and non-personnel dollars, split into Funded vs
    # Unfunded buckets with an explicit "why is this unfunded" reason
    # code when nothing's been allocated. The exporter writes the
    # ``'-'`` sentinel for cells with no data (see the importer contract:
    # blank ⇒ "field never asked", ``'-'`` ⇒ "explicitly empty"). We
    # don't generate resource estimates today; these columns ride along
    # so a round-tripped POAM keeps any values an eMASS user typed in.
    # ------------------------------------------------------------------
    "personnel_cost_code":           PoamColumn("AU", "Personnel Resources: Cost Code"),
    "personnel_funded_hours":        PoamColumn("AV", "Personnel Resources: Funded Base Hours"),
    "personnel_unfunded_hours":      PoamColumn("AW", "Personnel Resources: Unfunded Base Hours"),
    "personnel_non_funding_obstacle": PoamColumn("AX", "Personnel Resources: Non-FundingObstacle"),
    "personnel_non_funding_obstacle_other": PoamColumn("AY", "Personnel Resources: Non-Funding Obstacle Other Reason"),
    "non_personnel_cost_code":       PoamColumn("AZ", "Non-Personnel Resources: Cost Code"),
    "non_personnel_funded_amount":   PoamColumn("BA", "Non-Personnel Resources: Funded Amount"),
    "non_personnel_unfunded_amount": PoamColumn("BB", "Non-Personnel Resources: Unfunded Amount"),
    "non_personnel_non_funding_obstacle": PoamColumn("BC", "Non-Personnel Resources: Non-Funding Obstacle"),
    "non_personnel_non_funding_obstacle_other": PoamColumn("BD", "Non-Personnel Resources: Non-Funding Obstacle Other Reason"),
}


# Sentinel value the eMASS importer expects for "explicitly empty" cells —
# distinct from never-written (truly blank). The exporter substitutes this
# for any data cell it would otherwise leave None/empty so a round-tripped
# POAM keeps the same shape on re-import. See
# reference_emass_poam_template.md for the full contract.
EMPTY_CELL_SENTINEL = "-"


# Header fields above row 12 — read on import to learn system context, written
# on export to keep the new file consistent with the system under assessment.
# Cell coordinates are (row, column) 1-based.
HEADER_FIELDS: dict[str, tuple[int, int]] = {
    "date_initiated":      (3,  3),   # C3
    "dod_system_type":     (3,  7),   # G3
    "system_subtype":      (4,  7),   # G4
    "date_last_updated":   (6,  3),   # C6
    "ccsafa":              (9,  3),   # C9   "CC/S/A/FA"
    "poc_name":            (9,  10),  # J9
    "system_project_name": (10, 3),   # C10
    "system_identification": (11, 3), # C11
    "poc_email":           (11, 10),  # J11
}
