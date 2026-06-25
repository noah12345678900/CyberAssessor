"""Robustness tests for the STIG-family evidence extractors.

The four parsers (``.ckl``, ``.cklb``, ``.xml`` XCCDF, ``.nessus``)
share a common ``StigParseResult`` contract and identical host-on-
``comments`` attribution rules. These tests pin the edge cases that
caused real-world data loss before the per-host pattern was added:

* missing hostname (no asset / no target / no ReportHost name attr)
  must not crash and must produce ``host=None`` + ``hosts=[]``
* a single file containing multiple host blocks (Nessus subnet sweep,
  XCCDF fleet TestResult dump) must keep per-finding attribution
* duplicate hostnames within the same file must dedupe in ``hosts``
  while still attributing every finding correctly

Fixtures are tiny in-memory bytestreams — no on-disk fixture files —
so the test file is self-contained and fast.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor.evidence.extractors.nessus import extract_nessus
from cybersecurity_assessor.evidence.extractors.stig_ckl import extract_ckl
from cybersecurity_assessor.evidence.extractors.stig_cklb import extract_cklb
from cybersecurity_assessor.evidence.extractors.stig_xccdf import extract_xccdf


def _stream(data: bytes | str) -> io.BytesIO:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return io.BytesIO(data)


# ---------------------------------------------------------------- .ckl ----


_CKL_TEMPLATE_HOST = """<?xml version="1.0" encoding="UTF-8"?>
<CHECKLIST>
  <ASSET>
    <HOST_NAME>{hostname}</HOST_NAME>
  </ASSET>
  <STIGS>
    <iSTIG>
      <STIG_INFO>
        <SI_DATA>
          <SID_NAME>title</SID_NAME>
          <SID_DATA>Sample STIG</SID_DATA>
        </SI_DATA>
      </STIG_INFO>
      <VULN>
        <STIG_DATA>
          <VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE>
          <ATTRIBUTE_DATA>SV-1001r1_rule</ATTRIBUTE_DATA>
        </STIG_DATA>
        <STIG_DATA>
          <VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE>
          <ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA>
        </STIG_DATA>
        <STIG_DATA>
          <VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE>
          <ATTRIBUTE_DATA>Example check</ATTRIBUTE_DATA>
        </STIG_DATA>
        <STATUS>Open</STATUS>
        <FINDING_DETAILS>finding text</FINDING_DETAILS>
        <COMMENTS>tester note</COMMENTS>
      </VULN>
    </iSTIG>
  </STIGS>
</CHECKLIST>
"""

_CKL_NO_ASSET = """<?xml version="1.0" encoding="UTF-8"?>
<CHECKLIST>
  <STIGS>
    <iSTIG>
      <STIG_INFO/>
      <VULN>
        <STIG_DATA>
          <VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE>
          <ATTRIBUTE_DATA>SV-2002r1_rule</ATTRIBUTE_DATA>
        </STIG_DATA>
        <STATUS>NotAFinding</STATUS>
      </VULN>
    </iSTIG>
  </STIGS>
</CHECKLIST>
"""


def test_ckl_missing_host_does_not_crash_and_findings_have_no_prefix():
    doc = extract_ckl(_stream(_CKL_NO_ASSET), "no-asset.ckl")
    assert doc.metadata["host"] is None
    assert doc.metadata["hosts"] == []
    findings = doc.metadata["_stig_findings"]
    assert len(findings) == 1
    # No host prefix when host is unknown — comments stay as-is (None here).
    assert findings[0].comments is None


def test_ckl_with_host_prefixes_comments_and_populates_hosts_list():
    doc = extract_ckl(
        _stream(_CKL_TEMPLATE_HOST.format(hostname="host-a")), "host-a.ckl"
    )
    assert doc.metadata["host"] == "host-a"
    assert doc.metadata["hosts"] == ["host-a"]
    findings = doc.metadata["_stig_findings"]
    assert findings[0].comments == "host=host-a\ntester note"


# --------------------------------------------------------------- .cklb ----


def _cklb(host: str | None, rules: list[dict]) -> bytes:
    data = {
        "title": "Sample CKLB",
        "target_data": {"host_name": host} if host else {},
        "stigs": [
            {
                "display_name": "Sample STIG",
                "rules": rules,
            }
        ],
    }
    return json.dumps(data).encode("utf-8")


def test_cklb_missing_host_returns_none_and_empty_list():
    doc = extract_cklb(
        _stream(
            _cklb(
                None,
                [
                    {
                        "rule_id": "SV-3001r1_rule",
                        "status": "open",
                        "severity": "low",
                        "finding_details": "stuff",
                    }
                ],
            )
        ),
        "no-host.cklb",
    )
    assert doc.metadata["host"] is None
    assert doc.metadata["hosts"] == []
    findings = doc.metadata["_stig_findings"]
    # No host → comments stay None when input comments were absent.
    assert findings[0].comments is None


def test_cklb_with_host_prefixes_each_finding():
    doc = extract_cklb(
        _stream(
            _cklb(
                "host-b",
                [
                    {
                        "rule_id": "SV-3001r1_rule",
                        "status": "open",
                        "comments": "auditor note",
                    },
                    {
                        "rule_id": "SV-3002r1_rule",
                        "status": "not_a_finding",
                    },
                ],
            )
        ),
        "host-b.cklb",
    )
    assert doc.metadata["host"] == "host-b"
    assert doc.metadata["hosts"] == ["host-b"]
    findings = doc.metadata["_stig_findings"]
    assert findings[0].comments == "host=host-b\nauditor note"
    assert findings[1].comments == "host=host-b"


# --------------------------------------------------------------- xccdf ----


_XCCDF_NO_HOST = """<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="x">
  <title>Empty</title>
  <Rule id="rule_1" severity="medium">
    <title>r1</title>
    <ident system="http://cce.mitre.org">CCI-000001</ident>
  </Rule>
  <TestResult id="tr1">
    <rule-result idref="rule_1">
      <result>fail</result>
    </rule-result>
  </TestResult>
</Benchmark>
"""

_XCCDF_MULTI_HOST = """<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="fleet">
  <title>Fleet Sweep</title>
  <Rule id="rule_1" severity="high">
    <title>r1</title>
  </Rule>
  <Rule id="rule_2" severity="low">
    <title>r2</title>
  </Rule>
  <TestResult id="tr-a">
    <target>host-a</target>
    <rule-result idref="rule_1"><result>fail</result></rule-result>
    <rule-result idref="rule_2"><result>pass</result></rule-result>
  </TestResult>
  <TestResult id="tr-b">
    <target>host-b</target>
    <rule-result idref="rule_1"><result>pass</result></rule-result>
    <rule-result idref="rule_2"><result>fail</result></rule-result>
  </TestResult>
  <TestResult id="tr-a2">
    <target>host-a</target>
    <rule-result idref="rule_1"><result>fail</result></rule-result>
  </TestResult>
</Benchmark>
"""


def test_xccdf_no_host_returns_findings_without_attribution():
    doc = extract_xccdf(_stream(_XCCDF_NO_HOST), "no-host.xml")
    assert doc.metadata["host"] is None
    findings = doc.metadata["_stig_findings"]
    assert len(findings) == 1
    assert findings[0].comments is None


def test_xccdf_multi_testresult_attributes_each_rule_result_to_its_host():
    doc = extract_xccdf(_stream(_XCCDF_MULTI_HOST), "fleet.xml")
    # First-seen host is primary; duplicate host-a in tr-a2 collapses.
    assert doc.metadata["host"] == "host-a"
    assert doc.metadata["hosts"] == ["host-a", "host-b"]
    findings = doc.metadata["_stig_findings"]
    assert len(findings) == 5
    # Group by host via the comments field — every finding should be
    # attributable to its TestResult's target.
    hosts_seen = [f.comments for f in findings]
    assert hosts_seen.count("host=host-a") == 3  # tr-a (2) + tr-a2 (1)
    assert hosts_seen.count("host=host-b") == 2


def test_xccdf_non_xccdf_root_raises_extractor_error():
    from cybersecurity_assessor.evidence.extractors.base import ExtractorError

    junk = b"<?xml version='1.0'?><randomroot><foo/></randomroot>"
    with pytest.raises(ExtractorError):
        extract_xccdf(_stream(junk), "junk.xml")


# ----------------------------------------------------------------- arf ----
#
# ARF (Asset Reporting Format, SCAP 1.2/1.3) wraps the very same XCCDF
# Benchmark/TestResult content inside an <asset-report-collection> root,
# several layers down (assets + reports/report/content). The same
# extractor must unwrap it and produce identical findings, because the
# finding helpers recurse through every descendant via ``el.iter()``.

# Embedded TestResult carries its own <target> — that target wins.
_ARF_WITH_EMBEDDED_TARGET = """<?xml version="1.0" encoding="UTF-8"?>
<arf:asset-report-collection
    xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1"
    xmlns:ai="http://scap.nist.gov/schema/asset-identification/1.1">
  <arf:assets>
    <arf:asset>
      <ai:computing-device>
        <ai:hostname>asset-branch-host</ai:hostname>
      </ai:computing-device>
    </arf:asset>
  </arf:assets>
  <arf:reports>
    <arf:report id="xccdf1">
      <arf:content>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="b">
          <title>ARF Embedded Benchmark</title>
          <Rule id="rule_1" severity="high">
            <title>r1</title>
            <ident system="http://cci">CCI-000010</ident>
          </Rule>
          <TestResult id="tr1">
            <target>embedded-host</target>
            <rule-result idref="rule_1"><result>fail</result></rule-result>
          </TestResult>
        </Benchmark>
      </arf:content>
    </arf:report>
  </arf:reports>
</arf:asset-report-collection>
"""

# No <target> in the embedded TestResult — host attribution must fall
# back to the ARF asset-identification <hostname> in the <assets> branch.
_ARF_HOST_FROM_ASSET_BRANCH = """<?xml version="1.0" encoding="UTF-8"?>
<arf:asset-report-collection
    xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1"
    xmlns:ai="http://scap.nist.gov/schema/asset-identification/1.1">
  <arf:assets>
    <arf:asset>
      <ai:computing-device>
        <ai:hostname>arf-host</ai:hostname>
      </ai:computing-device>
    </arf:asset>
  </arf:assets>
  <arf:reports>
    <arf:report id="xccdf1">
      <arf:content>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="b">
          <title>ARF No Target</title>
          <Rule id="rule_1" severity="medium">
            <title>r1</title>
          </Rule>
          <TestResult id="tr1">
            <rule-result idref="rule_1"><result>fail</result></rule-result>
          </TestResult>
        </Benchmark>
      </arf:content>
    </arf:report>
  </arf:reports>
</arf:asset-report-collection>
"""


def test_arf_embedded_xccdf_extracts_findings_and_prefers_embedded_target():
    doc = extract_xccdf(_stream(_ARF_WITH_EMBEDDED_TARGET), "scan.arf")
    # Embedded TestResult <target> is authoritative over the asset branch.
    assert doc.metadata["host"] == "embedded-host"
    findings = doc.metadata["_stig_findings"]
    assert len(findings) == 1
    assert findings[0].rule_id == "rule_1"
    # fail -> OPEN, CCI carried through from the embedded Rule's <ident>.
    assert findings[0].cci_refs == "CCI-000010"
    assert findings[0].comments == "host=embedded-host"


def test_arf_host_falls_back_to_asset_identification_branch():
    doc = extract_xccdf(_stream(_ARF_HOST_FROM_ASSET_BRANCH), "scan.arf")
    # TestResult names no target, so the ARF <hostname> is used instead.
    assert doc.metadata["host"] == "arf-host"
    findings = doc.metadata["_stig_findings"]
    assert len(findings) == 1
    assert findings[0].comments == "host=arf-host"


# When BOTH a scanner asset and a target-facts target exist, and the
# TestResult names no <target>, the collection-level fallback must use the
# TARGET (target-facts), NEVER the scanner asset. This is the misattribution
# the target-facts scoping fix prevents — the scanner and target deliberately
# have DIFFERENT names so a regression (grabbing the scanner) is visible.
_ARF_SCANNER_AND_TARGET_DIFFER = """<?xml version="1.0" encoding="UTF-8"?>
<arf:asset-report-collection
    xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1"
    xmlns:ai="http://scap.nist.gov/schema/asset-identification/1.1">
  <arf:assets>
    <arf:asset>
      <ai:computing-device>
        <ai:hostname>scanner-box</ai:hostname>
      </ai:computing-device>
    </arf:asset>
  </arf:assets>
  <arf:reports>
    <arf:report id="xccdf1">
      <arf:content>
        <Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="b">
          <title>ARF Scanner vs Target</title>
          <Rule id="rule_1" severity="medium"><title>r1</title></Rule>
          <TestResult id="tr1">
            <target-facts>
              <fact name="urn:scap:fact:asset:identifier:fqdn">target-box</fact>
            </target-facts>
            <rule-result idref="rule_1"><result>fail</result></rule-result>
          </TestResult>
        </Benchmark>
      </arf:content>
    </arf:report>
  </arf:reports>
</arf:asset-report-collection>
"""


def test_arf_target_facts_win_over_scanner_asset():
    doc = extract_xccdf(_stream(_ARF_SCANNER_AND_TARGET_DIFFER), "scan.arf")
    # Findings must attribute to the TARGET, never the scanner-box asset.
    assert doc.metadata["host"] == "target-box"
    findings = doc.metadata["_stig_findings"]
    assert len(findings) == 1
    assert findings[0].comments == "host=target-box"
    assert "scanner-box" not in (findings[0].comments or "")


def test_arf_routes_through_registry_and_dispatcher():
    from cybersecurity_assessor.evidence.extractors import dispatcher
    from cybersecurity_assessor.evidence.extractors.base import extract
    from cybersecurity_assessor.models import EvidenceKind

    # The .arf suffix must resolve to the XCCDF extractor and STIG kind.
    doc = extract(_stream(_ARF_WITH_EMBEDDED_TARGET), "scan.arf")
    assert doc.kind == EvidenceKind.STIG_XCCDF
    assert len(doc.metadata["_stig_findings"]) == 1
    assert dispatcher.infer_kind("scan.arf") == EvidenceKind.STIG_XCCDF


def test_arf_content_saved_as_xml_is_still_parsed():
    # SCC/OpenSCAP frequently emit ARF with a .xml extension; the root
    # sniff (not the suffix) must drive parsing.
    doc = extract_xccdf(_stream(_ARF_WITH_EMBEDDED_TARGET), "scan.xml")
    assert doc.metadata["host"] == "embedded-host"
    assert len(doc.metadata["_stig_findings"]) == 1


# -------------------------------------------------------------- nessus ----


def _nessus(hosts_and_items: list[tuple[str | None, list[dict]]]) -> bytes:
    """Build a tiny .nessus document.

    ``hosts_and_items`` is a list of (hostname, [report_items]). Hostname
    of ``None`` produces a ReportHost with no ``name`` attr — exercises
    the missing-host path.
    """
    parts = ['<?xml version="1.0"?>', "<NessusClientData_v2>", "<Report>"]
    for host, items in hosts_and_items:
        name_attr = f' name="{host}"' if host else ""
        parts.append(f"<ReportHost{name_attr}>")
        for it in items:
            attrs = " ".join(f'{k}="{v}"' for k, v in it["attrs"].items())
            parts.append(f"<ReportItem {attrs}>")
            for child_tag, child_text in it.get("children", {}).items():
                parts.append(f"<{child_tag}>{child_text}</{child_tag}>")
            parts.append("</ReportItem>")
        parts.append("</ReportHost>")
    parts += ["</Report>", "</NessusClientData_v2>"]
    return "".join(parts).encode("utf-8")


def _ri(plugin_id: str, severity: str = "3", output: str | None = None) -> dict:
    """Helper to build a ReportItem dict for ``_nessus``."""
    item = {
        "attrs": {
            "pluginID": plugin_id,
            "pluginName": f"Plugin {plugin_id}",
            "severity": severity,
        },
        "children": {"description": "desc"},
    }
    if output:
        item["children"]["plugin_output"] = output
    return item


def test_nessus_no_hostname_attribute_still_extracts_findings():
    doc = extract_nessus(
        _stream(_nessus([(None, [_ri("1001")])])), "anon.nessus"
    )
    assert doc.metadata["host"] is None
    assert doc.metadata["hosts"] == []
    findings = doc.metadata["_stig_findings"]
    assert len(findings) == 1
    assert findings[0].rule_id == "Nessus-1001"
    # No host → comments fall back to plugin_output, which is absent here.
    assert findings[0].comments is None


def test_nessus_duplicate_hostnames_dedupe_but_findings_each_attributed():
    payload = _nessus(
        [
            ("host-a", [_ri("2001"), _ri("2002")]),
            ("host-a", [_ri("2003")]),  # duplicate hostname (split report)
        ]
    )
    doc = extract_nessus(_stream(payload), "dup.nessus")
    assert doc.metadata["host"] == "host-a"
    # Same hostname must not appear twice.
    assert doc.metadata["hosts"] == ["host-a"]
    findings = doc.metadata["_stig_findings"]
    assert len(findings) == 3
    # Every finding carries the host prefix even though hosts list collapsed.
    for f in findings:
        assert f.comments == "host=host-a"


def test_nessus_multi_host_attributes_findings_per_host():
    payload = _nessus(
        [
            ("host-a", [_ri("3001", output="evidence-a")]),
            ("host-b", [_ri("3001", output="evidence-b")]),
            ("host-c", [_ri("3002")]),
        ]
    )
    doc = extract_nessus(_stream(payload), "sweep.nessus")
    assert doc.metadata["host"] == "host-a"
    assert doc.metadata["hosts"] == ["host-a", "host-b", "host-c"]
    findings = doc.metadata["_stig_findings"]
    assert len(findings) == 3
    # Per-host attribution preserved; output appended after the prefix.
    by_host = {f.comments.split("\n", 1)[0]: f for f in findings}
    assert by_host["host=host-a"].comments == "host=host-a\nevidence-a"
    assert by_host["host=host-b"].comments == "host=host-b\nevidence-b"
    assert by_host["host=host-c"].comments == "host=host-c"


def test_nessus_info_severity_marked_not_a_finding():
    from cybersecurity_assessor.models import FindingStatus

    payload = _nessus(
        [("host-a", [_ri("4001", severity="0"), _ri("4002", severity="2")])]
    )
    doc = extract_nessus(_stream(payload), "mixed.nessus")
    findings = doc.metadata["_stig_findings"]
    by_id = {f.rule_id: f for f in findings}
    assert by_id["Nessus-4001"].status == FindingStatus.NOT_A_FINDING
    assert by_id["Nessus-4002"].status == FindingStatus.OPEN


# ---------------------------------------------------------------------------
# DISA STIG-report .xlsx — benchmark recovery (Manual real id vs OSCAP CCI col)
# ---------------------------------------------------------------------------


def _stig_report_xlsx(sheet_name: str, stig_id_value: str) -> bytes:
    """Build a one-sheet DISA STIG-report workbook in memory.

    Header: Vuln ID | Rule ID | Stig ID | Title | Severity | <host columns...>.
    One data row per call, status "Open" for the single host so it confirms.
    ``stig_id_value`` is what lands in the Stig ID column — a real STIG id for
    the Manual report, a CCI token for the OSCAP report.
    """
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = sheet_name
    ws.append(
        ["Vuln ID", "Rule ID", "Stig ID", "Title", "Severity", "paas-vdi-01"]
    )
    ws.append(
        ["V-230224", "SV-230224r_rule", stig_id_value, "do a thing", "high", "Open"]
    )
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def test_stig_report_xlsx_manual_keeps_real_stig_id():
    """Manual report carries a real STIG id → rule_version is that id, untouched."""
    from cybersecurity_assessor.evidence.extractors.xlsx import extract_xlsx

    data = _stig_report_xlsx("RHEL8", "RHEL-08-010030")
    doc = extract_xlsx(io.BytesIO(data), "STIG_Manual_report.xlsx")
    findings = (doc.metadata or {}).get("_stig_findings") or []
    assert len(findings) == 1
    # Real STIG id preserved verbatim — the sheet-name fallback must NOT fire.
    assert findings[0].rule_version == "RHEL-08-010030"
    assert findings[0].comments == "host=paas-vdi-01"


def test_stig_report_xlsx_oscap_falls_back_to_sheet_benchmark():
    """OSCAP report puts a CCI in the Stig ID column → recover benchmark from sheet name.

    Without the fallback, rule_version would be ``CCI-000366`` and
    ``_benchmark_key`` returns None for every row, collapsing the checklist
    count to a useless 1-per-file. The sheet name (RHEL8) is the benchmark.
    """
    from cybersecurity_assessor.evidence.asset_crosscheck import _benchmark_key
    from cybersecurity_assessor.evidence.extractors.xlsx import extract_xlsx

    data = _stig_report_xlsx("RHEL8", "CCI-000366")
    doc = extract_xlsx(io.BytesIO(data), "STIG_OSCAP_report.xlsx")
    findings = (doc.metadata or {}).get("_stig_findings") or []
    assert len(findings) == 1
    # Stig ID column was a CCI → rule_version stamped with the sheet benchmark.
    assert findings[0].rule_version == "RHEL8"
    # And the benchmark is now recoverable (not None), so the count won't collapse.
    assert _benchmark_key(findings[0].rule_version) == "RHEL8"
    # The CCI itself is not lost — it remains the rule_id.
    assert findings[0].rule_id == "SV-230224r_rule"
