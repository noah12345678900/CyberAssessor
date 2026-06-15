"""STIG `.cklb` extractor (new STIG Viewer JSON format).

A ``.cklb`` is the successor to ``.ckl`` — same conceptual content
(target + STIG title + flat list of rules with status/details/comments)
but encoded as JSON. STIG Viewer 3+ writes ``.cklb`` by default.

Shape (per DISA's STIG Viewer 3 schema):

    {
      "title": "...", "target_data": {"host_name": "..."},
      "stigs": [
        {
          "display_name": "...",
          "rules": [
            {
              "group_id": "V-12345", "rule_id": "SV-...",
              "rule_id_src": "...", "rule_version": "OS-00-000010",
              "severity": "medium", "status": "open",
              "finding_details": "...", "comments": "...",
              "ccis": ["CCI-000366"], ...
            }, ...
          ]
        }, ...
      ]
    }
"""

from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import BinaryIO

from ...models import EvidenceKind
from ._stig_common import (
    StigFindingRow,
    StigParseResult,
    extract_cci_refs,
    normalize_severity,
    normalize_status,
)
from .base import ExtractedDoc, ExtractorError, register, resolve_doc_number


def _parse_cklb(stream: BinaryIO, name: str) -> StigParseResult:
    raw_bytes = stream.read()
    try:
        raw = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raw = raw_bytes.decode("utf-8-sig")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ExtractorError(f"invalid JSON in {name}: {exc}") from exc

    target = data.get("target_data") or {}
    host = (
        target.get("host_name")
        or target.get("fqdn")
        or target.get("ip_address")
        or None
    )

    title = (data.get("title") or "").strip() or None
    text_chunks: list[str] = []
    if host:
        text_chunks.append(f"Host: {host}")

    findings: list[StigFindingRow] = []
    for stig in data.get("stigs") or []:
        display = (stig.get("display_name") or stig.get("stig_name") or "").strip()
        if display and title is None:
            title = display
        if display:
            text_chunks.append(f"STIG: {display}")

        for rule in stig.get("rules") or []:
            rule_id = (
                rule.get("rule_id")
                or rule.get("rule_id_src")
                or rule.get("group_id")
                or ""
            )
            if not rule_id:
                continue
            status_raw = (rule.get("status") or "").strip()
            details = (rule.get("finding_details") or "").strip() or None
            comments = (rule.get("comments") or "").strip() or None
            severity_raw = rule.get("severity")
            rule_version = rule.get("rule_version") or rule.get("version")

            cci_list = rule.get("ccis") or []
            cci_joined = ", ".join(c for c in cci_list if c)
            cci_refs = extract_cci_refs(cci_joined, details, comments)

            # Mirror the .ckl/Nessus pattern: prefix host onto comments
            # so the StigFinding row stands on its own when surfaced
            # outside the Evidence join (CSV export, per-host filters).
            if host:
                comments_out = (
                    f"host={host}\n{comments}" if comments else f"host={host}"
                )
            else:
                comments_out = comments

            # group_id is the V-number from the JSON "group_id" field.
            # rule_id keeps the SV-... rule identifier (already resolved
            # above from rule_id / rule_id_src / group_id fallback chain).
            group_id = (rule.get("group_id") or "").strip() or None
            rule_title = (rule.get("rule_title") or rule.get("group_title") or "").strip() or None
            check_text = (rule.get("check_content") or rule.get("check_text") or "").strip() or None
            fix_text = (rule.get("fix_text") or rule.get("fixtext") or "").strip() or None

            findings.append(
                StigFindingRow(
                    rule_id=rule_id,
                    status=normalize_status(status_raw),
                    rule_version=rule_version,
                    cci_refs=cci_refs,
                    severity=normalize_severity(severity_raw),
                    finding_details=details,
                    comments=comments_out,
                    group_id=group_id,
                    rule_title=rule_title,
                    check_text=check_text,
                    fix_text=fix_text,
                )
            )

            _rt = rule_title or ""
            text_chunks.append(f"[{rule_id} {status_raw}] {_rt}".strip())
            if details:
                text_chunks.append(f"  details: {details}")
            if comments:
                text_chunks.append(f"  comments: {comments}")

    text = "\n".join(text_chunks)
    hosts = [host] if host else []
    return StigParseResult(
        text=text, findings=findings, title=title, host=host, hosts=hosts
    )


@register(".cklb")
def extract_cklb(stream: BinaryIO, name: str) -> ExtractedDoc:
    """Extract findings + text summary from a STIG ``.cklb`` JSON file."""
    result = _parse_cklb(stream, name)
    stem = PurePosixPath(name).stem
    title = result.title or stem
    return ExtractedDoc(
        text=result.text,
        title=title,
        doc_number=resolve_doc_number(name, title, result.text),
        kind=EvidenceKind.STIG_CKLB,
        metadata={
            "host": result.host,
            "hosts": result.hosts,
            "finding_count": len(result.findings),
            "_stig_findings": result.findings,
        },
    )
