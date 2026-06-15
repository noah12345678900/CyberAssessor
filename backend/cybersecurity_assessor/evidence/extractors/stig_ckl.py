"""STIG `.ckl` extractor (legacy STIG Viewer XML format).

A ``.ckl`` is an XML file that wraps a single STIG iteration: a header
identifying the target host + STIG title, then a flat list of
``<VULN>`` elements. Each ``<VULN>`` has a bag of ``<STIG_DATA>``
key/value pairs (Rule_ID, Severity, CCI_REF, etc.) plus a status,
finding details, and tester comments.

We use ``defusedxml`` because evidence comes from user-supplied files
that we don't control — stdlib ``xml.etree`` is vulnerable to billion-
laughs / external-entity attacks. ``defusedxml`` is a tiny pure-Python
wrapper and is already in ``backend/pyproject.toml`` for the same
reason in the XCCDF/Nessus parsers.
"""

from __future__ import annotations

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


def _stig_data_map(vuln_el) -> dict[str, list[str]]:
    """Turn a ``<VULN>``'s ``<STIG_DATA>`` children into a multimap.

    A single VULN can have multiple ``<STIG_DATA>`` entries with the
    same ``VULN_ATTRIBUTE`` (e.g. several ``CCI_REF`` values), so we
    accumulate values per key instead of last-write-wins.
    """
    out: dict[str, list[str]] = {}
    for sd in vuln_el.findall("STIG_DATA"):
        key_el = sd.find("VULN_ATTRIBUTE")
        val_el = sd.find("ATTRIBUTE_DATA")
        if key_el is None or val_el is None:
            continue
        key = (key_el.text or "").strip()
        val = (val_el.text or "").strip()
        if not key:
            continue
        out.setdefault(key, []).append(val)
    return out


def _first(values: list[str] | None) -> str | None:
    return values[0] if values else None


def _parse_ckl(stream: BinaryIO, name: str) -> StigParseResult:
    try:
        from defusedxml import ElementTree as ET  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ExtractorError(
            "defusedxml is not installed — add it to backend/pyproject.toml "
            "to safely parse STIG/SCAP/Nessus files."
        ) from exc

    try:
        tree = ET.parse(stream)
    except Exception as exc:  # pragma: no cover - XML errors vary
        raise ExtractorError(f"defusedxml failed on {name}: {exc}") from exc

    root = tree.getroot()

    # ASSET block carries the host metadata. It's optional but useful
    # to surface in the evidence list so the user can tell two STIG
    # iterations apart.
    asset = root.find("ASSET")
    host = None
    if asset is not None:
        host = (
            (asset.findtext("HOST_NAME") or "").strip()
            or (asset.findtext("HOST_IP") or "").strip()
            or (asset.findtext("HOST_FQDN") or "").strip()
            or None
        )

    # A ``.ckl`` may contain multiple STIGs (rare but legal). We treat
    # the first one as the title source; findings from all are merged.
    title = None
    findings: list[StigFindingRow] = []
    text_chunks: list[str] = []
    if host:
        text_chunks.append(f"Host: {host}")

    for istig in root.iter("iSTIG"):
        si = istig.find("STIG_INFO")
        if si is not None and title is None:
            for sid in si.findall("SI_DATA"):
                sid_name = (sid.findtext("SID_NAME") or "").strip().lower()
                data = (sid.findtext("SID_DATA") or "").strip()
                if sid_name == "title" and data:
                    title = data
                    break

        if title:
            text_chunks.append(f"STIG: {title}")

        for vuln in istig.findall("VULN"):
            sd = _stig_data_map(vuln)
            rule_id = (
                _first(sd.get("Rule_ID"))
                or _first(sd.get("Vuln_Num"))
                or ""
            )
            if not rule_id:
                continue

            status_raw = (vuln.findtext("STATUS") or "").strip()
            details = (vuln.findtext("FINDING_DETAILS") or "").strip() or None
            comments = (vuln.findtext("COMMENTS") or "").strip() or None
            severity_raw = _first(sd.get("Severity"))
            rule_version = _first(sd.get("Rule_Ver"))
            cci_joined = ", ".join(sd.get("CCI_REF", []))
            cci_refs = extract_cci_refs(cci_joined, details, comments)

            # Carry the host on every finding when known so downstream
            # consumers (UI grouping, reports) can disambiguate two
            # checklists run against different boxes without joining back
            # to Evidence metadata. Existing free-text comments are
            # preserved on the line below the prefix.
            if host:
                comments_out = (
                    f"host={host}\n{comments}" if comments else f"host={host}"
                )
            else:
                comments_out = comments

            # Human-readable identifiers and verbatim remediation text.
            # group_id is the V-number (Vuln_Num), distinct from rule_id
            # (SV-rule).  rule_id keeps its original SV-... semantics.
            group_id = _first(sd.get("Vuln_Num")) or None
            rule_title = _first(sd.get("Rule_Title")) or None
            check_text = _first(sd.get("Check_Content")) or None
            fix_text = _first(sd.get("Fix_Text")) or None

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

            # Build a compact text representation so doc-number /
            # family-keyword tagging downstream still has something
            # to grep against without re-parsing the XML.
            _rt = rule_title or ""
            text_chunks.append(
                f"[{rule_id} {status_raw}] {_rt}".strip()
            )
            if details:
                text_chunks.append(f"  details: {details}")
            if comments:
                text_chunks.append(f"  comments: {comments}")

    text = "\n".join(text_chunks)
    hosts = [host] if host else []
    return StigParseResult(
        text=text, findings=findings, title=title, host=host, hosts=hosts
    )


@register(".ckl")
def extract_ckl(stream: BinaryIO, name: str) -> ExtractedDoc:
    """Extract findings + a text summary from a STIG ``.ckl`` file."""
    result = _parse_ckl(stream, name)
    stem = PurePosixPath(name).stem
    title = result.title or stem
    return ExtractedDoc(
        text=result.text,
        title=title,
        doc_number=resolve_doc_number(name, title, result.text),
        kind=EvidenceKind.STIG_CKL,
        metadata={
            "host": result.host,
            "hosts": result.hosts,
            "finding_count": len(result.findings),
            "_stig_findings": result.findings,  # consumed by ingest.py
        },
    )
