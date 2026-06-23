"""XCCDF results extractor (`.xml` files produced by SCAP scanners).

XCCDF is the OASIS/NIST format that tools like SCC, OpenSCAP, and ACAS
emit when they evaluate a STIG. It carries the same Rule_ID/CCI/result
information as a `.ckl`, just at a different layer in the namespace
soup.

Two important wrinkles:

* XCCDF uses XML namespaces. The version varies (1.1.4, 1.2, …). We
  use local-name matching (``etree`` iter with a wildcard) instead of
  hardcoding namespace URIs so the parser tolerates either flavor.
* Not every ``.xml`` we see is XCCDF — could be OVAL, an MSBuild
  manifest, or random user XML. The dispatcher routes all ``.xml``
  here, so we detect XCCDF by looking for an XCCDF ``Benchmark`` or
  ``TestResult`` root element and raise ``ExtractorError`` otherwise
  (which the orchestrator turns into a "manual review" tag rather
  than killing the ingest).
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


def _local(tag: str) -> str:
    """Strip an XML ``{namespace}tag`` down to just ``tag``."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _findall_local(el, name: str):
    """Find all descendants whose local-name matches, ignoring namespace."""
    return [child for child in el.iter() if _local(child.tag) == name]


def _find_local(el, name: str):
    for child in el.iter():
        if _local(child.tag) == name:
            return child
    return None


def _parse_xccdf(stream: BinaryIO, name: str) -> StigParseResult:
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
    root_local = _local(root.tag)
    # ``asset-report-collection`` is the ARF (Asset Reporting Format, SCAP
    # 1.2/1.3) wrapper element. ARF embeds the very same XCCDF
    # Benchmark/TestResult content one or more layers down (inside
    # reports/report/content), plus richer asset/host identification. Every
    # finding helper below walks ``el.iter()``, which recurses through all
    # descendants, so once we accept the ARF root the embedded Rules,
    # Groups, and rule-results are found exactly as in a bare XCCDF file —
    # no separate ARF parser needed.
    if root_local not in {
        "Benchmark",
        "TestResult",
        "data-stream-collection",
        "asset-report-collection",
    }:
        # Not an XCCDF/ARF file — let the orchestrator know so it can
        # persist the raw file without findings rather than dropping it.
        raise ExtractorError(
            f"{name} is not an XCCDF/ARF document (root=<{root_local}>); "
            "skipping STIG parse."
        )

    # Title can live on Benchmark/title or TestResult/benchmark[@href].
    title_el = _find_local(root, "title")
    title = (title_el.text or "").strip() if title_el is not None else None

    # Pre-index Rules (Benchmark/Rule) so we can pull CCI refs / severity
    # for each rule-result. Keyed by rule id.
    #
    # Also build a group_id map: in XCCDF each <Group id="V-..."> wraps
    # one or more <Rule> elements. We map rule-id → group-id so the
    # human V-number travels through to the StigFindingRow.
    group_id_for_rule: dict[str, str] = {}
    for grp in _findall_local(root, "Group"):
        gid = grp.attrib.get("id") or ""
        for r in _findall_local(grp, "Rule"):
            rid = r.attrib.get("id") or ""
            if rid and gid:
                group_id_for_rule[rid] = gid

    rule_meta: dict[str, dict] = {}
    for rule in _findall_local(root, "Rule"):
        rid = rule.attrib.get("id")
        if not rid:
            continue
        ccis: list[str] = []
        for ident in _findall_local(rule, "ident"):
            sys_attr = (ident.attrib.get("system") or "").lower()
            txt = (ident.text or "").strip()
            if "cci" in sys_attr or txt.upper().startswith("CCI-"):
                ccis.append(txt)

        # check_text: prefer <check-content>, fall back to description
        check_text: str | None = None
        check_content_el = _find_local(rule, "check-content")
        if check_content_el is not None:
            check_text = (check_content_el.text or "").strip() or None
        if check_text is None:
            desc_el = _find_local(rule, "description")
            if desc_el is not None:
                check_text = (desc_el.text or "").strip() or None

        # fix_text: from <fixtext>
        fix_text: str | None = None
        fixtext_el = _find_local(rule, "fixtext")
        if fixtext_el is not None:
            fix_text = (fixtext_el.text or "").strip() or None

        rule_meta[rid] = {
            "severity": rule.attrib.get("severity"),
            "version": (_find_local(rule, "version").text or "").strip()
            if _find_local(rule, "version") is not None
            else None,
            "title": (_find_local(rule, "title").text or "").strip()
            if _find_local(rule, "title") is not None
            else "",
            "ccis": ccis,
            "check_text": check_text,
            "fix_text": fix_text,
        }

    findings: list[StigFindingRow] = []
    text_chunks: list[str] = []
    host_pairs: list[dict] = []  # {"ip":..., "fqdn":...} device-identity pairs
    if title:
        text_chunks.append(f"STIG: {title}")

    # XCCDF legitimately allows multiple <TestResult> blocks in a single
    # benchmark document (SCC writes one per host when sweeping a fleet).
    # We iterate each TestResult, capture its target, and attribute every
    # rule-result inside that block to that target — otherwise a
    # multi-host result file would collapse to a faceless pile of
    # rule_ids with no way to tell which box failed what.
    test_results = _findall_local(root, "TestResult")
    hosts: list[str] = []

    def _looks_like_ip(token: str) -> bool:
        import ipaddress

        try:
            ipaddress.ip_address((token or "").strip())
            return True
        except ValueError:
            return False

    def _facts(node) -> dict[str, list[str]]:
        # ARF (and XCCDF 1.2 TestResult) carry host identity in
        # ``<target-facts><fact name="urn:...:fqdn">host.dom</fact>`` and
        # ``ipv4``/``ipv6`` siblings, rather than as discrete <fqdn>/<target>
        # elements. ARF asset-identification (ai:computing-device) uses the
        # same <fact> shape under <connections>/<connection>. We bucket every
        # <fact> by the local-name suffix of its ``name`` attribute so the
        # caller can pull fqdn vs ip without caring which namespace flavor the
        # scanner emitted.
        out: dict[str, list[str]] = {}
        for fact in _findall_local(node, "fact"):
            raw_name = (fact.attrib.get("name") or "").strip().lower()
            val = (fact.text or "").strip()
            if not raw_name or not val:
                continue
            # name is a URN like "urn:scap:fact:asset:identifier:fqdn";
            # the trailing token is what we key on.
            key = raw_name.rsplit(":", 1)[-1]
            out.setdefault(key, []).append(val)
        return out

    def _host_of(node) -> str | None:
        # ``target``/``target-address``/``target-id-ref`` are the XCCDF
        # TestResult host fields (primary). ``hostname``/``fqdn`` are the
        # ARF asset-identification fields (ai:computing-device) — used as a
        # fallback when an ARF file carries asset metadata but the embedded
        # TestResult omits an explicit target.
        for tag in (
            "target",
            "target-address",
            "target-id-ref",
            "hostname",
            "fqdn",
        ):
            el = _find_local(node, tag)
            if el is not None and (el.text or "").strip():
                return el.text.strip()
        # Fall back to ARF/TestResult <target-facts><fact name="...fqdn">.
        facts = _facts(node)
        for key in ("fqdn", "host-name", "hostname"):
            if facts.get(key):
                return facts[key][0]
        for key in ("ipv4", "ipv6", "ip-address", "ipaddress"):
            if facts.get(key):
                return facts[key][0]
        return None

    def _pairs_of(node) -> None:
        # Capture the (ip, fqdn) device-identity pairing the same way the
        # Nessus parser does: a single live box reports both its IP and its
        # OS-reported FQDN. ARF target-facts/asset facts carry both, so the
        # asset cross-check can collapse multiple IPs under one device.
        facts = _facts(node)
        fqdn = ""
        for key in ("fqdn", "host-name", "hostname"):
            if facts.get(key):
                fqdn = facts[key][0]
                break
        ip = ""
        for key in ("ipv4", "ipv6", "ip-address", "ipaddress"):
            if facts.get(key):
                ip = facts[key][0]
                break
        # An explicit <target> that is itself an IP also seeds the pair.
        if not ip:
            tgt = _find_local(node, "target")
            tgt_txt = (tgt.text or "").strip() if tgt is not None else ""
            if tgt_txt and _looks_like_ip(tgt_txt):
                ip = tgt_txt
        if ip and fqdn:
            pair = {"ip": ip, "fqdn": fqdn}
            if pair not in host_pairs:
                host_pairs.append(pair)

    def _emit_rule_results(node, host_name: str | None) -> None:
        for rr in _findall_local(node, "rule-result"):
            rid = rr.attrib.get("idref") or ""
            if not rid:
                continue
            result_el = _find_local(rr, "result")
            status_raw = (
                (result_el.text or "").strip() if result_el is not None else ""
            )
            meta = rule_meta.get(rid, {})
            severity_raw = rr.attrib.get("severity") or meta.get("severity")
            cci_refs = extract_cci_refs(", ".join(meta.get("ccis", [])))
            comments = f"host={host_name}" if host_name else None

            findings.append(
                StigFindingRow(
                    rule_id=rid,
                    status=normalize_status(status_raw),
                    rule_version=meta.get("version"),
                    cci_refs=cci_refs,
                    severity=normalize_severity(severity_raw),
                    finding_details=None,  # XCCDF rarely carries free-text findings
                    comments=comments,
                    group_id=group_id_for_rule.get(rid) or None,
                    rule_title=meta.get("title") or None,
                    check_text=meta.get("check_text"),
                    fix_text=meta.get("fix_text"),
                )
            )
            text_chunks.append(
                f"[{rid} {status_raw}] {meta.get('title', '')}".strip()
            )

    # ARF carries asset identification (hostname/fqdn) for the SCAN TARGET in
    # ``<target-facts>``. It ALSO carries the SCANNER's own identity elsewhere
    # in the asset/metadata branch (ai:computing-device under <assets>). A
    # tree-wide ``_host_of(root)`` / ``_pairs_of(root)`` walks ``el.iter()`` and
    # can grab whichever asset sorts first — frequently the scanner — and pin
    # every otherwise-untargeted TestResult's findings to the WRONG device.
    #
    # Resolution: PREFER ``<target-facts>`` (unambiguously the target). Only
    # when NO target-facts exist anywhere in the document do we fall back to the
    # whole-tree ``_host_of(root)`` — which reaches the single ARF
    # ``ai:computing-device`` asset branch. That preserves the common
    # single-asset ARF (one scanned box, host only in the asset branch) while
    # still refusing to let a scanner asset win when target-facts ARE present.
    target_facts_nodes = _findall_local(root, "target-facts")

    collection_host: str | None = None
    if target_facts_nodes:
        for tfn in target_facts_nodes:
            collection_host = _host_of(tfn)
            if collection_host:
                break
        # Pairs come only from target-facts when those exist — the scanner's
        # facts (outside target-facts) must never masquerade as a device.
        for tfn in target_facts_nodes:
            _pairs_of(tfn)
    else:
        # No target-facts container anywhere → single-asset ARF / bare XCCDF.
        # The whole-tree fallback is safe here: there is no competing target
        # vs scanner distinction to get wrong.
        collection_host = _host_of(root)
        _pairs_of(root)

    if test_results:
        for tr in test_results:
            host_name = _host_of(tr) or collection_host
            if host_name and host_name not in hosts:
                hosts.append(host_name)
            if host_name:
                text_chunks.append(f"Host: {host_name}")
            _pairs_of(tr)
            _emit_rule_results(tr, host_name)
    else:
        # Benchmark-only or data-stream document — fall back to root-level
        # target and root-level rule-results (older single-host shape).
        host_name = _host_of(root)
        if host_name:
            hosts.append(host_name)
            text_chunks.append(f"Host: {host_name}")
        _emit_rule_results(root, host_name)

    primary_host = hosts[0] if hosts else None
    text = "\n".join(text_chunks)
    return StigParseResult(
        text=text,
        findings=findings,
        title=title,
        host=primary_host,
        hosts=hosts,
        host_pairs=host_pairs,
    )


@register(".xml", ".arf")
def extract_xccdf(stream: BinaryIO, name: str) -> ExtractedDoc:
    """Extract findings from an XCCDF or ARF results XML file.

    Handles both bare XCCDF (``.xml`` with a Benchmark/TestResult root)
    and ARF (``.arf`` or ``.xml`` with an ``asset-report-collection``
    root, which embeds the same XCCDF content). The parser sniffs the
    root element rather than trusting the extension, so an ARF document
    saved with a ``.xml`` suffix is handled identically.
    """
    result = _parse_xccdf(stream, name)
    stem = PurePosixPath(name).stem
    title = result.title or stem
    return ExtractedDoc(
        text=result.text,
        title=title,
        doc_number=resolve_doc_number(name, title, result.text),
        kind=EvidenceKind.STIG_XCCDF,
        metadata={
            "host": result.host,
            "hosts": result.hosts,
            "host_pairs": result.host_pairs,
            "finding_count": len(result.findings),
            "_stig_findings": result.findings,
        },
    )
