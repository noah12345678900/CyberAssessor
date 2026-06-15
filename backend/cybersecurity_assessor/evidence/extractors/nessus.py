"""Nessus / ACAS `.nessus` results extractor.

A ``.nessus`` file is XML produced by Tenable Nessus (and ACAS, which
is Nessus with DoD content). Structure:

    <NessusClientData_v2>
      <Report>
        <ReportHost name="hostname">
          <HostProperties>...</HostProperties>
          <ReportItem pluginID="..." severity="3"
                      pluginName="..." pluginFamily="..."
                      risk_factor="High">
            <description>...</description>
            <plugin_output>...</plugin_output>
            <stig_severity>I</stig_severity>  (DoD overlay only)
          </ReportItem>
          ...
        </ReportHost>
      </Report>
    </NessusClientData_v2>

We map each ReportItem to a ``StigFindingRow`` with:
* ``rule_id`` = ``Nessus-<pluginID>`` so it's unambiguous next to STIG
  rule IDs in the same evidence index
* ``status`` = OPEN for severity >= 1, NOT_A_FINDING for 0 (info)
* ``severity`` = normalized from ``risk_factor`` (preferred) or the
  numeric ``severity`` attribute
* ``cci_refs`` = scanned out of description/plugin_output (some ACAS
  plugins inline CCI numbers)
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import BinaryIO

from ...models import EvidenceKind, FindingStatus
from ._stig_common import (
    StigFindingRow,
    StigParseResult,
    extract_cci_refs,
    normalize_severity,
)
from .base import ExtractedDoc, ExtractorError, register, resolve_doc_number

# Nessus numeric severity: 0=info, 1=low, 2=medium, 3=high, 4=critical.
_NUMERIC_TO_NAME = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}


def _parse_nessus(stream: BinaryIO, name: str) -> StigParseResult:
    try:
        from defusedxml import ElementTree as ET  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ExtractorError(
            "defusedxml is not installed — add it to backend/pyproject.toml."
        ) from exc

    try:
        tree = ET.parse(stream)
    except Exception as exc:
        raise ExtractorError(f"defusedxml failed on {name}: {exc}") from exc

    root = tree.getroot()
    findings: list[StigFindingRow] = []
    text_chunks: list[str] = []
    hosts: list[str] = []
    title = None

    # Top-level Policy/policyName is a good title when present.
    for policy_name in root.iter("policyName"):
        title = (policy_name.text or "").strip() or None
        if title:
            break

    for report in root.iter("Report"):
        report_name = report.attrib.get("name")
        if report_name and not title:
            title = report_name

        for rh in report.findall("ReportHost"):
            hostname = rh.attrib.get("name") or ""
            # Track each unique host so the UI / metadata can show
            # "scan covered N hosts". A single .nessus file routinely
            # bundles dozens of ReportHost blocks when ACAS sweeps a
            # subnet — losing the per-host attribution silently was the
            # actual robustness gap here, not the dedupe behaviour.
            if hostname and hostname not in hosts:
                hosts.append(hostname)
            if hostname:
                text_chunks.append(f"Host: {hostname}")

            for item in rh.findall("ReportItem"):
                plugin_id = item.attrib.get("pluginID") or ""
                plugin_name = item.attrib.get("pluginName") or ""
                severity_num = item.attrib.get("severity") or "0"
                risk = (item.findtext("risk_factor") or "").strip()
                description = (item.findtext("description") or "").strip() or None
                output = (item.findtext("plugin_output") or "").strip() or None

                # Status: anything non-info is OPEN. Info plugins are
                # informational scan output, not a finding.
                if severity_num == "0":
                    status = FindingStatus.NOT_A_FINDING
                else:
                    status = FindingStatus.OPEN

                # Prefer the explicit risk_factor / stig_severity, fall
                # back to the numeric attribute. stig_severity (when
                # present) is CAT I/II/III — _stig_common knows those.
                stig_sev = (item.findtext("stig_severity") or "").strip()
                if stig_sev:
                    severity_label = f"cat {stig_sev.lower()}"
                else:
                    severity_label = risk or _NUMERIC_TO_NAME.get(severity_num)

                cci_refs = extract_cci_refs(description, output)

                # Attribute each finding to its host so a multi-host
                # scan doesn't collapse to a faceless pile of rule_ids
                # in the StigFinding table. The comments column is
                # plain text + nullable so prefixing is safe; the raw
                # plugin_output (if any) follows on the next line.
                if hostname:
                    if output:
                        comments = f"host={hostname}\n{output}"
                    else:
                        comments = f"host={hostname}"
                else:
                    comments = output

                findings.append(
                    StigFindingRow(
                        rule_id=f"Nessus-{plugin_id}",
                        status=status,
                        rule_version=None,
                        cci_refs=cci_refs,
                        severity=normalize_severity(severity_label),
                        finding_details=description,
                        comments=comments,
                    )
                )
                text_chunks.append(
                    f"[Nessus-{plugin_id} sev={severity_num}] {plugin_name}".strip()
                )

    text = "\n".join(text_chunks)
    primary_host = hosts[0] if hosts else None
    return StigParseResult(
        text=text, findings=findings, title=title, host=primary_host, hosts=hosts
    )


@register(".nessus")
def extract_nessus(stream: BinaryIO, name: str) -> ExtractedDoc:
    """Extract Nessus/ACAS scan findings."""
    result = _parse_nessus(stream, name)
    stem = PurePosixPath(name).stem
    title = result.title or stem
    return ExtractedDoc(
        text=result.text,
        title=title,
        doc_number=resolve_doc_number(name, title, result.text),
        kind=EvidenceKind.NESSUS,
        metadata={
            "host": result.host,
            "hosts": result.hosts,
            "finding_count": len(result.findings),
            "_stig_findings": result.findings,
        },
    )
