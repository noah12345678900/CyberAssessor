"""Shared helpers across the STIG/SCAP/Nessus parsers.

Every STIG family normalizes to the same ``StigFindingRow`` shape, which
the orchestrator turns into ``StigFinding`` ORM rows after the
``Evidence`` row exists (so it can carry the foreign key).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

from ...models import FindingStatus

# CKL/CKLB use "Open" / "NotAFinding" / "Not_Applicable" / "Not_Reviewed".
# XCCDF uses pass/fail/notapplicable/notchecked/notselected/error/unknown.
# Nessus uses risk_factor + plugin output; we map severity from there.
_STATUS_NORMALIZE = {
    "open": FindingStatus.OPEN,
    "notafinding": FindingStatus.NOT_A_FINDING,
    "not_a_finding": FindingStatus.NOT_A_FINDING,
    "not a finding": FindingStatus.NOT_A_FINDING,
    "not_applicable": FindingStatus.NOT_APPLICABLE,
    "not applicable": FindingStatus.NOT_APPLICABLE,
    "notapplicable": FindingStatus.NOT_APPLICABLE,
    "not_reviewed": FindingStatus.NOT_REVIEWED,
    "not reviewed": FindingStatus.NOT_REVIEWED,
    "notreviewed": FindingStatus.NOT_REVIEWED,
    # XCCDF
    "pass": FindingStatus.NOT_A_FINDING,
    "fail": FindingStatus.OPEN,
    "notchecked": FindingStatus.NOT_REVIEWED,
    "notselected": FindingStatus.NOT_APPLICABLE,
    "error": FindingStatus.NOT_REVIEWED,
    "unknown": FindingStatus.NOT_REVIEWED,
    "informational": FindingStatus.NOT_A_FINDING,
}

# Severity: CKL uses CAT I/II/III; XCCDF uses high/medium/low; Nessus
# uses None/Low/Medium/High/Critical. Normalize to lowercase strings —
# the schema field is plain text so consumers can render however they
# want, but a stable vocabulary helps filtering.
_SEVERITY_NORMALIZE = {
    "cat i": "high",
    "cat ii": "medium",
    "cat iii": "low",
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
    "none": "info",
}

_CCI_RE = re.compile(r"CCI-\d{6}", re.IGNORECASE)


def normalize_status(raw: str | None) -> FindingStatus:
    """Map raw STIG-status text to the ``FindingStatus`` enum.

    Falls back to ``NOT_REVIEWED`` for unknown values — better to keep
    an unrecognized record than drop it; the assessor can fix the
    mapping later.
    """
    if not raw:
        return FindingStatus.NOT_REVIEWED
    key = raw.strip().lower().replace("-", "_")
    return _STATUS_NORMALIZE.get(key, FindingStatus.NOT_REVIEWED)


def normalize_severity(raw: str | None) -> str | None:
    """Map raw severity strings to ``high|medium|low|info`` or pass-through."""
    if not raw:
        return None
    key = raw.strip().lower()
    return _SEVERITY_NORMALIZE.get(key, key or None)


def extract_cci_refs(*sources: str | None) -> str | None:
    """Find CCI-#### references in any free-text field, comma-joined.

    Multiple fields are scanned so the parser can pass in both the
    rule's `CCI_REF` list AND the finding details (some CKLs embed CCI
    numbers only in the description).
    """
    found: list[str] = []
    for src in sources:
        if not src:
            continue
        for m in _CCI_RE.finditer(src):
            cci = m.group(0).upper()
            if cci not in found:
                found.append(cci)
    return ", ".join(found) if found else None


@dataclass
class StigFindingRow:
    """Pre-ORM shape: ingest fills in evidence_id once the row exists."""

    rule_id: str
    status: FindingStatus
    rule_version: str | None = None
    cci_refs: str | None = None
    severity: str | None = None
    finding_details: str | None = None
    comments: str | None = None
    # Human-readable STIG identifiers and verbatim remediation text.
    # Populated by the per-format extractors; None when the source file
    # does not carry the field (absence is a gap, never an error).
    group_id: str | None = None      # STIG Group ID / Vuln_Num, e.g. "V-220706"
    rule_title: str | None = None    # one-line STIG rule title
    check_text: str | None = None    # verbatim check content
    fix_text: str | None = None      # verbatim fix content


@dataclass
class StigParseResult:
    """Composite return: the visible text blob plus normalized findings.

    ``host`` is the *primary* hostname (first one seen) and is what the
    evidence list surfaces. ``hosts`` is the full deduplicated list —
    populated by formats that legitimately carry multiple targets in one
    file (Nessus scan with several ``ReportHost`` elements). For
    single-host formats (.ckl, .cklb, most XCCDF) ``hosts`` will have
    zero or one entry.
    """

    text: str
    findings: List[StigFindingRow] = field(default_factory=list)
    title: str | None = None
    host: str | None = None
    hosts: List[str] = field(default_factory=list)
    # (ip, fqdn) pairs observed together on one ReportHost — the device-identity
    # join key. A credentialed scan reports both the IP and the OS-reported FQDN/
    # netbios for the same live box, so this pairing lets the asset cross-check
    # collapse multiple IPs under one device (hostname) instead of counting each
    # IP as a separate host. Empty for uncredentialed scans (IP only) and for
    # single-host formats that carry no IP. Each entry: {"ip": str, "fqdn": str}.
    host_pairs: List[dict] = field(default_factory=list)
