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

# Tenable .audit compliance verdicts → FindingStatus. PASSED is a clean
# control, FAILED is a finding, WARNING/ERROR mean the check couldn't be
# evaluated cleanly (manual review) — map them to NOT_REVIEWED so they're
# kept but flagged rather than silently passed/failed.
_COMPLIANCE_TO_STATUS = {
    "PASSED": FindingStatus.NOT_A_FINDING,
    "FAILED": FindingStatus.OPEN,
    "WARNING": FindingStatus.NOT_REVIEWED,
    "ERROR": FindingStatus.NOT_REVIEWED,
}


def _local(tag: str) -> str:
    """Strip an XML ``{namespace}tag`` (or ``cm:tag``) down to ``tag``."""
    if "}" in tag:
        tag = tag.rsplit("}", 1)[-1]
    if ":" in tag:
        tag = tag.rsplit(":", 1)[-1]
    return tag


def _cm_children(item) -> dict[str, str]:
    """Bucket an ItemReportItem's ``cm:compliance-*`` children by local name.

    Tenable .audit compliance scans put the result in child elements named
    ``compliance-check-name``, ``compliance-result``, ``compliance-actual-
    value``, ``compliance-info``, ``compliance-reference``, ``compliance-
    check-id``, ``compliance-severity`` — all in the ``cm:`` namespace. We
    match on the namespace-stripped local name so either ``cm:foo`` or
    ``{ns}foo`` is found. Last value wins for duplicate tags (rare).
    """
    out: dict[str, str] = {}
    for child in item:
        name = _local(child.tag)
        if name.startswith("compliance-"):
            val = (child.text or "").strip()
            if val:
                out[name] = val
    return out


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
    host_pairs: list[dict] = []  # {"ip":..., "fqdn":...} from HostProperties
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

            # Device-identity capture: a CREDENTIALED scan records both the IP
            # and the OS-reported FQDN/netbios for the SAME live box under
            # <HostProperties>. Capturing the (ip, fqdn) pair lets the asset
            # cross-check collapse multiple IPs under one device (one STIG per
            # device), per the device-centric model. Uncredentialed scans only
            # have host-ip (== the ReportHost name) and no fqdn → empty fqdn,
            # which the cross-check shows calmly as "scanned IP not yet mapped".
            props = {}
            hp = rh.find("HostProperties")
            if hp is not None:
                for tag in hp.findall("tag"):
                    tname = tag.attrib.get("name") or ""
                    if tname in ("host-ip", "host-fqdn", "netbios-name", "host-rdns"):
                        val = (tag.text or "").strip()
                        if val:
                            props[tname] = val
            ip = props.get("host-ip") or (hostname if _looks_like_ip(hostname) else "")
            fqdn = (
                props.get("host-fqdn")
                or props.get("host-rdns")
                or props.get("netbios-name")
                or ""
            )
            if ip and fqdn:
                pair = {"ip": ip, "fqdn": fqdn}
                if pair not in host_pairs:
                    host_pairs.append(pair)

            for item in rh.findall("ReportItem"):
                plugin_id = item.attrib.get("pluginID") or ""
                plugin_name = item.attrib.get("pluginName") or ""
                severity_num = item.attrib.get("severity") or "0"

                # --- Tenable .audit compliance check branch -----------------
                # When a ReportItem carries cm:compliance-* children it's a
                # config-compliance result (.audit), not a vuln. Emit a
                # StigFindingRow keyed on the audit check id/name and skip the
                # vuln path below. The plain-vuln path is unchanged.
                cm = _cm_children(item)
                if cm:
                    result_raw = (cm.get("compliance-result") or "").strip().upper()
                    status = _COMPLIANCE_TO_STATUS.get(
                        result_raw, FindingStatus.NOT_REVIEWED
                    )
                    check_name = (
                        cm.get("compliance-check-name") or plugin_name or ""
                    ).strip()
                    # rule_id: prefer an explicit check id, else the check name,
                    # else fall back to the plugin id so the row is never anon.
                    rule_token = (
                        cm.get("compliance-check-id")
                        or check_name
                        or plugin_id
                        or "compliance"
                    )
                    cm_severity = normalize_severity(
                        cm.get("compliance-severity")
                        or _NUMERIC_TO_NAME.get(severity_num)
                    )
                    # CCI / 800-53 refs live in cm:compliance-reference, with
                    # actual-value/info as secondary haystacks.
                    cci_refs = extract_cci_refs(
                        cm.get("compliance-reference"),
                        cm.get("compliance-info"),
                        cm.get("compliance-actual-value"),
                    )
                    details = (
                        cm.get("compliance-info")
                        or cm.get("compliance-actual-value")
                        or None
                    )
                    actual = cm.get("compliance-actual-value")
                    if hostname:
                        comments = f"host={hostname}"
                        if actual:
                            comments = f"{comments}\n{actual}"
                    else:
                        comments = actual or None

                    findings.append(
                        StigFindingRow(
                            rule_id=f"Nessus-{rule_token}",
                            status=status,
                            rule_version=None,
                            cci_refs=cci_refs,
                            severity=cm_severity,
                            finding_details=details,
                            comments=comments,
                            rule_title=check_name or None,
                        )
                    )
                    text_chunks.append(
                        f"[Nessus-{rule_token} {result_raw}] {check_name}".strip()
                    )
                    continue
                # --- end compliance branch ---------------------------------
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
        text=text,
        findings=findings,
        title=title,
        host=primary_host,
        hosts=hosts,
        host_pairs=host_pairs,
    )


def _looks_like_ip(token: str) -> bool:
    """True if ``token`` parses as an IPv4/IPv6 address (mirrors ingest)."""
    import ipaddress

    try:
        ipaddress.ip_address((token or "").strip())
        return True
    except ValueError:
        return False


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
            "host_pairs": result.host_pairs,
            "finding_count": len(result.findings),
            "_stig_findings": result.findings,
        },
    )
