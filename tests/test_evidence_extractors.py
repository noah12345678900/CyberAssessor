"""Extractor tests — STIG/Nessus parsers + text + base helpers.

We deliberately do NOT install pdfplumber/python-docx/python-pptx in
the test environment; those extractors only run lazily so importing
the package must work without them. STIG / text / dispatcher coverage
is what actually exercises end-to-end behavior.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cybersecurity_assessor.evidence.extractors import (
    ExtractorError,
    extract_path,
    infer_kind,
)
from cybersecurity_assessor.evidence.extractors._stig_common import (
    extract_cci_refs,
    normalize_severity,
    normalize_status,
)
from cybersecurity_assessor.evidence.extractors.base import (
    collect_doc_numbers,
    find_doc_number,
)
from cybersecurity_assessor.models import EvidenceKind, FindingStatus


# ---------------------------------------------------------------------------
# Base helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "needle,expected",
    [
        ("USD00050010", "USD00050010"),
        ("usd-50010", "USD00050010"),
        ("USD 50010 was cited", "USD00050010"),
        ("USD0050010", "USD00050010"),
        ("no doc here", None),
        ("USD12", None),  # too short to be a real doc number
    ],
)
def test_find_doc_number_canonicalizes(needle, expected):
    assert find_doc_number(needle) == expected


def test_find_doc_number_searches_multiple_haystacks():
    assert find_doc_number(None, "", "USD-22222") == "USD00022222"


def test_collect_doc_numbers_dedupes_in_order():
    text = "Refs USD00050010, USD-50010 (same), and USD22222."
    assert collect_doc_numbers(text) == ["USD00050010", "USD00022222"]


# ---------------------------------------------------------------------------
# STIG common
# ---------------------------------------------------------------------------


def test_normalize_status_handles_ckl_xccdf_nessus_forms():
    assert normalize_status("Open") == FindingStatus.OPEN
    assert normalize_status("NotAFinding") == FindingStatus.NOT_A_FINDING
    assert normalize_status("Not_Applicable") == FindingStatus.NOT_APPLICABLE
    assert normalize_status("Not_Reviewed") == FindingStatus.NOT_REVIEWED
    assert normalize_status("pass") == FindingStatus.NOT_A_FINDING
    assert normalize_status("fail") == FindingStatus.OPEN
    assert normalize_status("notchecked") == FindingStatus.NOT_REVIEWED
    assert normalize_status(None) == FindingStatus.NOT_REVIEWED
    assert normalize_status("garbage") == FindingStatus.NOT_REVIEWED


def test_normalize_severity_maps_cat_and_passthrough():
    assert normalize_severity("CAT I") == "high"
    assert normalize_severity("CAT II") == "medium"
    assert normalize_severity("CAT III") == "low"
    assert normalize_severity("critical") == "high"
    assert normalize_severity("LOW") == "low"
    assert normalize_severity("informational") == "info"
    assert normalize_severity(None) is None
    # Unknowns pass through lower-cased so we don't drop data
    assert normalize_severity("Funky") == "funky"


def test_extract_cci_refs_dedupes_and_joins():
    text_a = "see CCI-000366 and cci-001199"
    text_b = "CCI-000366 again"
    assert extract_cci_refs(text_a, text_b) == "CCI-000366, CCI-001199"
    assert extract_cci_refs(None, "") is None


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


def test_infer_kind_by_extension():
    assert infer_kind(Path("a.pdf")) == EvidenceKind.PDF
    assert infer_kind(Path("a.CKL")) == EvidenceKind.STIG_CKL
    assert infer_kind(Path("a.cklb")) == EvidenceKind.STIG_CKLB
    assert infer_kind(Path("a.nessus")) == EvidenceKind.NESSUS
    assert infer_kind(Path("a.xml")) == EvidenceKind.STIG_XCCDF
    assert infer_kind(Path("a.xlsx")) == EvidenceKind.XLSX
    assert infer_kind(Path("a.txt")) == EvidenceKind.TEXT
    assert infer_kind(Path("a.png")) == EvidenceKind.IMAGE
    assert infer_kind(Path("a.JPG")) == EvidenceKind.IMAGE
    assert infer_kind(Path("a.tiff")) == EvidenceKind.IMAGE
    assert infer_kind(Path("a.vsdx")) == EvidenceKind.DIAGRAM
    assert infer_kind(Path("a.svg")) == EvidenceKind.DIAGRAM
    assert infer_kind(Path("a.zip")) == EvidenceKind.OTHER


# ---------------------------------------------------------------------------
# Text extractor
# ---------------------------------------------------------------------------


def test_text_extractor_reads_utf8_and_detects_doc_number(tmp_path):
    p = tmp_path / "note.txt"
    # Identity comes from a LABELED declaration line, not loose prose — a bare
    # "per USD00050010" mention is a citation, not the doc's own number.
    p.write_text("Document Number: USD00050010\nAccount mgmt baseline.", encoding="utf-8")
    doc = extract_path(p)
    assert doc.kind == EvidenceKind.TEXT
    assert "USD00050010" in doc.text
    assert doc.doc_number == "USD00050010"


def test_text_extractor_falls_back_to_cp1252(tmp_path):
    p = tmp_path / "note.txt"
    # 0x92 is a Windows-1252 curly apostrophe that's invalid as UTF-8.
    p.write_bytes(b"Org\x92s policy.\nDoc No: USD22222.")
    doc = extract_path(p)
    assert "Org" in doc.text
    assert doc.doc_number == "USD00022222"


def test_text_extractor_does_not_adopt_cited_doc_number_from_prose(tmp_path):
    """A USD number mentioned only in prose is a citation, not identity.

    Regression for the supersession-chain bug: a README that merely cited
    a manual's doc number adopted it as its own, colliding with the real
    manuals and chaining all three together. Identity now requires a
    labeled declaration line, so a bare prose mention yields no doc_number.
    """
    p = tmp_path / "readme.md"
    p.write_text(
        "These manuals share Document Number USD00050010; see the Rev B copy.",
        encoding="utf-8",
    )
    doc = extract_path(p)
    # The number is present in the text (still taggable via collect_doc_numbers)
    # but is NOT adopted as this file's own identity.
    assert "USD00050010" in doc.text
    assert doc.doc_number is None


# ---------------------------------------------------------------------------
# STIG .ckl  (skip if defusedxml missing)
# ---------------------------------------------------------------------------

pytest.importorskip("defusedxml")

_MINIMAL_CKL = """<?xml version="1.0" encoding="UTF-8"?>
<CHECKLIST>
  <ASSET><HOST_NAME>WIN-01</HOST_NAME></ASSET>
  <STIGS>
    <iSTIG>
      <STIG_INFO>
        <SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>Windows 11 STIG</SID_DATA></SI_DATA>
      </STIG_INFO>
      <VULN>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>SV-1</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Audit logs enabled</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>medium</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE><ATTRIBUTE_DATA>CCI-000366</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>CCI_REF</VULN_ATTRIBUTE><ATTRIBUTE_DATA>CCI-001199</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_Ver</VULN_ATTRIBUTE><ATTRIBUTE_DATA>WN11-AU-000010</ATTRIBUTE_DATA></STIG_DATA>
        <STATUS>NotAFinding</STATUS>
        <FINDING_DETAILS>Audit policy verified per USD00050010.</FINDING_DETAILS>
        <COMMENTS>Tester confirmed via GPO.</COMMENTS>
      </VULN>
      <VULN>
        <STIG_DATA><VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE><ATTRIBUTE_DATA>SV-2</ATTRIBUTE_DATA></STIG_DATA>
        <STIG_DATA><VULN_ATTRIBUTE>Severity</VULN_ATTRIBUTE><ATTRIBUTE_DATA>high</ATTRIBUTE_DATA></STIG_DATA>
        <STATUS>Open</STATUS>
      </VULN>
    </iSTIG>
  </STIGS>
</CHECKLIST>
"""


def test_ckl_extractor_parses_status_severity_cci(tmp_path):
    # Identity rides on the filename (authoritative). The USD in the fixture's
    # FINDING_DETAILS prose is a citation and must NOT be adopted as identity.
    p = tmp_path / "USD00050010 win11.ckl"
    p.write_text(_MINIMAL_CKL, encoding="utf-8")
    doc = extract_path(p)
    assert doc.kind == EvidenceKind.STIG_CKL
    assert doc.title == "Windows 11 STIG"
    assert doc.metadata["host"] == "WIN-01"
    assert doc.doc_number == "USD00050010"

    findings = doc.metadata["_stig_findings"]
    assert len(findings) == 2

    f1 = findings[0]
    assert f1.rule_id == "SV-1"
    assert f1.status == FindingStatus.NOT_A_FINDING
    assert f1.severity == "medium"
    assert f1.cci_refs == "CCI-000366, CCI-001199"
    assert f1.rule_version == "WN11-AU-000010"

    f2 = findings[1]
    assert f2.status == FindingStatus.OPEN
    assert f2.severity == "high"


# ---------------------------------------------------------------------------
# STIG .cklb (JSON)
# ---------------------------------------------------------------------------


def test_cklb_extractor_parses_json(tmp_path):
    payload = {
        "title": "RHEL 8 STIG",
        "target_data": {"host_name": "rhel-01", "fqdn": "rhel-01.local"},
        "stigs": [
            {
                "display_name": "Red Hat Enterprise Linux 8",
                "rules": [
                    {
                        "rule_id": "SV-RHEL-1",
                        "rule_version": "RHEL-08-010000",
                        "severity": "high",
                        "status": "open",
                        "rule_title": "Audit daemon running",
                        "finding_details": "auditd stopped — see USD-22222.",
                        "comments": "",
                        "ccis": ["CCI-000130"],
                    },
                    {
                        "rule_id": "SV-RHEL-2",
                        "severity": "low",
                        "status": "not_a_finding",
                        "ccis": [],
                    },
                ],
            }
        ],
    }
    # Identity rides on the filename (authoritative). The USD in the payload's
    # finding_details prose is a citation and must NOT be adopted as identity.
    p = tmp_path / "USD-22222 rhel.cklb"
    p.write_text(json.dumps(payload), encoding="utf-8")
    doc = extract_path(p)
    assert doc.kind == EvidenceKind.STIG_CKLB
    assert doc.title == "RHEL 8 STIG"
    assert doc.metadata["host"] == "rhel-01"
    assert doc.doc_number == "USD00022222"
    findings = doc.metadata["_stig_findings"]
    assert findings[0].rule_id == "SV-RHEL-1"
    assert findings[0].status == FindingStatus.OPEN
    assert findings[0].severity == "high"
    assert findings[0].cci_refs == "CCI-000130"
    assert findings[1].status == FindingStatus.NOT_A_FINDING
    assert findings[1].severity == "low"


def test_cklb_extractor_raises_on_bad_json(tmp_path):
    p = tmp_path / "bad.cklb"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ExtractorError):
        extract_path(p)


# ---------------------------------------------------------------------------
# XCCDF
# ---------------------------------------------------------------------------

_MINIMAL_XCCDF = """<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_test">
  <title>SCC Windows Test</title>
  <Rule id="xccdf_rule_1" severity="medium">
    <title>Audit subsystem enabled</title>
    <version>WN-AU-001</version>
    <ident system="http://iase.disa.mil/cci">CCI-000366</ident>
  </Rule>
  <Rule id="xccdf_rule_2" severity="high">
    <title>Account lockout configured</title>
  </Rule>
  <TestResult id="result-1">
    <target>WIN-01</target>
    <rule-result idref="xccdf_rule_1"><result>pass</result></rule-result>
    <rule-result idref="xccdf_rule_2"><result>fail</result></rule-result>
  </TestResult>
</Benchmark>
"""


def test_xccdf_extractor_parses_rules_and_results(tmp_path):
    p = tmp_path / "scc.xml"
    p.write_text(_MINIMAL_XCCDF, encoding="utf-8")
    doc = extract_path(p)
    assert doc.kind == EvidenceKind.STIG_XCCDF
    assert doc.title == "SCC Windows Test"
    assert doc.metadata["host"] == "WIN-01"
    findings = doc.metadata["_stig_findings"]
    assert len(findings) == 2
    assert findings[0].rule_id == "xccdf_rule_1"
    assert findings[0].status == FindingStatus.NOT_A_FINDING  # pass
    assert findings[0].cci_refs == "CCI-000366"
    assert findings[0].rule_version == "WN-AU-001"
    assert findings[1].status == FindingStatus.OPEN  # fail


def test_xccdf_extractor_rejects_non_xccdf_xml(tmp_path):
    p = tmp_path / "random.xml"
    p.write_text("<?xml version='1.0'?><Project><foo/></Project>", encoding="utf-8")
    with pytest.raises(ExtractorError):
        extract_path(p)


# ---------------------------------------------------------------------------
# Nessus
# ---------------------------------------------------------------------------

_MINIMAL_NESSUS = """<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2>
  <Policy><policyName>ACAS Baseline</policyName></Policy>
  <Report name="Weekly Scan">
    <ReportHost name="rhel-01">
      <ReportItem pluginID="12345" pluginName="OpenSSL CVE" severity="3">
        <risk_factor>High</risk_factor>
        <description>OpenSSL old version. CCI-002824.</description>
        <plugin_output>openssl 1.0.1</plugin_output>
      </ReportItem>
      <ReportItem pluginID="67890" pluginName="Info plugin" severity="0">
        <risk_factor>None</risk_factor>
      </ReportItem>
      <ReportItem pluginID="22222" pluginName="STIG check" severity="2">
        <stig_severity>II</stig_severity>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""


def test_nessus_extractor_maps_severity_and_status(tmp_path):
    p = tmp_path / "scan.nessus"
    p.write_text(_MINIMAL_NESSUS, encoding="utf-8")
    doc = extract_path(p)
    assert doc.kind == EvidenceKind.NESSUS
    assert doc.title == "ACAS Baseline"
    assert doc.metadata["host"] == "rhel-01"
    findings = doc.metadata["_stig_findings"]
    assert len(findings) == 3
    by_id = {f.rule_id: f for f in findings}
    assert by_id["Nessus-12345"].status == FindingStatus.OPEN
    assert by_id["Nessus-12345"].severity == "high"
    assert "CCI-002824" in (by_id["Nessus-12345"].cci_refs or "")
    assert by_id["Nessus-67890"].status == FindingStatus.NOT_A_FINDING
    assert by_id["Nessus-67890"].severity == "info"
    assert by_id["Nessus-22222"].severity == "medium"  # CAT II


# ---------------------------------------------------------------------------
# Dispatcher: no extractor registered
# ---------------------------------------------------------------------------


def test_extract_path_errors_on_unknown_suffix(tmp_path):
    p = tmp_path / "blob.bin"
    p.write_bytes(b"\x00\x01")
    with pytest.raises(ExtractorError):
        extract_path(p)


# ---------------------------------------------------------------------------
# Image extractor (Pillow + Tesseract OCR)
# ---------------------------------------------------------------------------


def test_image_extractor_reads_dimensions_and_caption(tmp_path, monkeypatch):
    """Dimensions/format always read; caption always present. OCR forced off so
    this asserts the deterministic metadata path regardless of whether a
    Tesseract binary is installed in the test environment."""
    from PIL import Image as PILImage

    from cybersecurity_assessor.evidence.extractors import image as image_mod

    # Force the no-OCR branch so the assertion is stable on any box.
    monkeypatch.setattr(image_mod, "tesseract_available", lambda: False)

    p = tmp_path / "mfa_settings_screenshot.png"
    PILImage.new("RGB", (24, 12), "white").save(p, "PNG")
    doc = extract_path(p)
    assert doc.kind == EvidenceKind.IMAGE
    assert doc.metadata["width"] == 24
    assert doc.metadata["height"] == 12
    assert doc.metadata["image_format"] == "PNG"
    assert doc.metadata["ocr"] is False
    # Filename caption present; honesty marker says pixels were NOT read.
    assert "mfa settings screenshot" in doc.text.lower()
    assert "no ocr" in doc.text.lower()


def test_image_extractor_ocr_recovers_text(tmp_path, monkeypatch):
    """When OCR is available, rendered text in the image reaches doc.text.

    We don't depend on a real Tesseract binary — we monkeypatch the shared
    ocr_image helper the extractor calls, so this asserts the WIRING
    (OCR output is spliced into text after the caption, metadata.ocr=True)
    deterministically.
    """
    from PIL import Image as PILImage

    from cybersecurity_assessor.evidence.extractors import image as image_mod

    monkeypatch.setattr(image_mod, "tesseract_available", lambda: True)
    monkeypatch.setattr(
        image_mod, "ocr_image", lambda img: "Minimum password length: 15 characters"
    )

    p = tmp_path / "password_policy.png"
    PILImage.new("RGB", (200, 60), "white").save(p, "PNG")
    doc = extract_path(p)
    assert doc.kind == EvidenceKind.IMAGE
    assert doc.metadata["ocr"] is True
    # Caption first (filename signals), then the OCR body.
    assert doc.text.startswith("[image] password policy")
    assert "Minimum password length: 15 characters" in doc.text


def test_image_extractor_ocr_available_but_blank(tmp_path, monkeypatch):
    """OCR ran but found nothing → explicit 'found no text' marker, not silence."""
    from PIL import Image as PILImage

    from cybersecurity_assessor.evidence.extractors import image as image_mod

    monkeypatch.setattr(image_mod, "tesseract_available", lambda: True)
    monkeypatch.setattr(image_mod, "ocr_image", lambda img: "")

    p = tmp_path / "blank_logo.png"
    PILImage.new("RGB", (24, 12), "white").save(p, "PNG")
    doc = extract_path(p)
    assert doc.metadata["ocr"] is True
    assert "ocr found no text" in doc.text.lower()


def test_image_extractor_ocr_recovers_doc_number(tmp_path, monkeypatch):
    """A USD number OCR'd out of the image is adopted as the doc's identity via
    resolve_doc_number's body arg (labeled-line rule still applies)."""
    from PIL import Image as PILImage

    from cybersecurity_assessor.evidence.extractors import image as image_mod

    monkeypatch.setattr(image_mod, "tesseract_available", lambda: True)
    monkeypatch.setattr(
        image_mod, "ocr_image", lambda img: "Document Number: USD00050010\nGPO export."
    )

    p = tmp_path / "gpo_capture.png"
    PILImage.new("RGB", (200, 60), "white").save(p, "PNG")
    doc = extract_path(p)
    assert doc.doc_number == "USD00050010"


# ---------------------------------------------------------------------------
# Diagram extractor (Visio .vsdx / .svg — stdlib text extraction, no OCR)
# ---------------------------------------------------------------------------


def test_svg_extractor_pulls_label_text(tmp_path):
    p = tmp_path / "network_diagram.svg"
    p.write_bytes(
        b'<svg xmlns="http://www.w3.org/2000/svg">'
        b"<title>Boundary</title><text>DMZ firewall</text>"
        b"<text>external boundary</text></svg>"
    )
    doc = extract_path(p)
    assert doc.kind == EvidenceKind.DIAGRAM
    assert "DMZ firewall" in doc.text
    assert "external boundary" in doc.text


def test_vsdx_extractor_pulls_shape_text(tmp_path):
    import zipfile

    p = tmp_path / "topology.vsdx"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr(
            "visio/pages/page1.xml",
            '<PageContents xmlns="http://schemas.microsoft.com/office/visio/2012/main">'
            "<Shape><Text>Core Switch</Text></Shape>"
            "<Shape><Text>Boundary Router</Text></Shape></PageContents>",
        )
    doc = extract_path(p)
    assert doc.kind == EvidenceKind.DIAGRAM
    assert "Core Switch" in doc.text
    assert "Boundary Router" in doc.text


def test_vsdx_extractor_rejects_non_zip(tmp_path):
    p = tmp_path / "broken.vsdx"
    p.write_bytes(b"not a zip file")
    with pytest.raises(ExtractorError):
        extract_path(p)


def test_image_extractor_degrades_when_convert_raises(tmp_path, monkeypatch):
    """If RGB conversion of an exotic mode raises, OCR degrades to the no-text
    caption — the whole image is NOT dropped (no ExtractorError)."""
    from PIL import Image as PILImage

    from cybersecurity_assessor.evidence.extractors import image as image_mod

    monkeypatch.setattr(image_mod, "tesseract_available", lambda: True)

    # Force .convert to blow up the way an unsupported mode would.
    real_open = PILImage.open

    class _BoomImg:
        def __init__(self, inner):
            self._inner = inner
            self.size = inner.size
            self.format = inner.format
            self.mode = "I;16"  # not in (RGB, L) -> triggers convert path

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def getexif(self):
            return {}

        def convert(self, _mode):
            raise OSError("cannot convert I;16")

    p = tmp_path / "exotic.png"
    PILImage.new("RGB", (20, 10), "white").save(p, "PNG")
    monkeypatch.setattr(
        image_mod.__dict__["__builtins__"] if False else PILImage,
        "open",
        lambda *a, **k: _BoomImg(real_open(*a, **k)),
    )

    doc = extract_path(p)  # must NOT raise
    assert doc.kind == EvidenceKind.IMAGE
    # OCR ran (available) but produced nothing usable -> found-no-text marker.
    assert "ocr found no text" in doc.text.lower()


# ---------------------------------------------------------------------------
# .json + .pcap/.pcapng support (Bug C)
# ---------------------------------------------------------------------------


def test_infer_kind_json_and_pcap():
    assert infer_kind(Path("config.json")) == EvidenceKind.TEXT
    assert infer_kind(Path("cap.pcap")) == EvidenceKind.PCAP
    assert infer_kind(Path("cap.pcapng")) == EvidenceKind.PCAP
    assert infer_kind(Path("cap.cap")) == EvidenceKind.PCAP
    # .arf drift fix: zip allowlist + dispatcher both know it.
    assert infer_kind(Path("scan.arf")) == EvidenceKind.STIG_XCCDF


def test_json_extractor_prettyprints_for_tokenization(tmp_path):
    from cybersecurity_assessor.evidence.extractors import extract_path

    p = tmp_path / "selinux.json"
    p.write_text('{"selinux":"enforcing","fips":true}', encoding="utf-8")
    doc = extract_path(p)
    assert doc.kind == EvidenceKind.TEXT
    # Minified input becomes multi-line so keys/values tokenize.
    assert "selinux" in doc.text and "enforcing" in doc.text
    assert "\n" in doc.text  # pretty-printed, not one line


def test_json_extractor_invalid_json_falls_back_to_raw(tmp_path):
    from cybersecurity_assessor.evidence.extractors import extract_path

    p = tmp_path / "broken.json"
    p.write_text("not valid json {", encoding="utf-8")
    doc = extract_path(p)
    assert "not valid json" in doc.text  # raw text preserved


def _synth_classic_pcap() -> bytes:
    import socket
    import struct

    eth = b"\xaa" * 6 + b"\xbb" * 6 + struct.pack("!H", 0x0800)
    ip = (
        bytes([0x45, 0, 0, 40])
        + b"\x00" * 5
        + bytes([6])
        + b"\x00\x00"
        + socket.inet_aton("172.20.8.86")
        + socket.inet_aton("10.0.0.5")
    )
    tcp = struct.pack("!HH", 51000, 443) + b"\x00" * 16
    pkt = eth + ip + tcp
    gh = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    rec = struct.pack("<IIII", 1700000000, 0, len(pkt), len(pkt)) + pkt
    return gh + rec


def _synth_pcapng() -> bytes:
    import socket
    import struct

    def blk(btype, body):
        body = body + b"\x00" * ((-len(body)) % 4)
        total = 12 + len(body)
        return struct.pack("<II", btype, total) + body + struct.pack("<I", total)

    eth = b"\xaa" * 6 + b"\xbb" * 6 + struct.pack("!H", 0x0800)
    ip = (
        bytes([0x45, 0, 0, 40])
        + b"\x00" * 5
        + bytes([6])
        + b"\x00\x00"
        + socket.inet_aton("172.20.4.9")
        + socket.inet_aton("10.0.0.5")
    )
    tcp = struct.pack("!HH", 5000, 80) + b"\x00" * 16
    pkt = eth + ip + tcp
    shb = blk(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = blk(0x00000001, struct.pack("<HHI", 1, 0, 65535))
    epb = blk(0x00000006, struct.pack("<IIIII", 0, 0, 0, len(pkt), len(pkt)) + pkt)
    return shb + idb + epb


def test_pcap_classic_digest(tmp_path):
    from cybersecurity_assessor.evidence.extractors import extract_path

    p = tmp_path / "classic.pcap"
    p.write_bytes(_synth_classic_pcap())
    doc = extract_path(p)
    assert doc.kind == EvidenceKind.PCAP
    assert "libpcap (classic)" in doc.text
    assert "172.20.8.86" in doc.text  # talker preserved (IP not truncated)
    assert "443" in doc.text  # dst port
    assert "TCP" in doc.text


def test_pcapng_digest(tmp_path):
    from cybersecurity_assessor.evidence.extractors import extract_path

    p = tmp_path / "modern.pcapng"
    p.write_bytes(_synth_pcapng())
    doc = extract_path(p)
    assert doc.kind == EvidenceKind.PCAP
    assert "pcapng" in doc.text
    assert "172.20.4.9" in doc.text
    assert "80" in doc.text
    assert "TCP" in doc.text


# ---------------------------------------------------------------------------
# Drift-guard tests (the .arf drift + IP-guard duplication proved these
# hand-maintained parallel structures DO drift — pin them so they can't again)
# ---------------------------------------------------------------------------


def test_suffix_allowlists_stay_in_sync():
    """The three hand-maintained suffix tables must agree.

    `_KIND_BY_SUFFIX` (dispatcher), local-folder allowlist, and zip-source
    allowlist are separate copies (deliberately, to avoid an import cycle).
    The `.arf`-missing-from-zip drift proves they fall out of sync silently.
    Every ingestible suffix must have a kind mapping, and the two walker
    allowlists must be identical.
    """
    from cybersecurity_assessor.evidence.extractors.dispatcher import _KIND_BY_SUFFIX
    from cybersecurity_assessor.evidence.sources.local import (
        _INGESTIBLE_SUFFIXES as local_set,
    )
    from cybersecurity_assessor.evidence.sources.zip_source import (
        _INGESTIBLE_SUFFIXES as zip_set,
    )

    # The two walkers admit the exact same suffix set.
    assert local_set == zip_set, (
        f"walker allowlists drifted: only-local={local_set - zip_set}, "
        f"only-zip={zip_set - local_set}"
    )
    # Every admitted suffix has a kind mapping (so it doesn't fall to OTHER).
    kinds = set(_KIND_BY_SUFFIX)
    missing_kind = local_set - kinds
    assert not missing_kind, f"suffixes with no kind mapping: {missing_kind}"


def test_ip_guard_normalizers_agree():
    """ingest._normalize_host and asset_crosscheck._normalize must be identical.

    They run at ingest-time and query-time respectively; if their IP guard
    diverges, host keys won't join (the 172.20.8.86 -> 172 bug). Pin agreement
    across IPs, FQDNs, plain hostnames, and edge cases.
    """
    from cybersecurity_assessor.evidence.asset_crosscheck import _normalize
    from cybersecurity_assessor.evidence.ingest import _normalize_host

    for h in (
        "172.20.8.86", "10.0.0.5", "192.168.1.1", "fe80::1", "::1",
        "Server01.dom.mil", "PaaS-VDI-01.sda-es.internal", "host", "HOST",
        "", "   ", "weird.name.with.dots",
    ):
        assert _normalize(h) == _normalize_host(h), f"divergence on {h!r}"


def test_control_family_gloss_terms_are_family_exclusive():
    """No gloss term may appear in two families' glosses.

    A cross-family term erodes TF-IDF discrimination and causes control
    cross-tagging as the catalog grows. The reviewer found aide/baseline/
    yum dnf/scap oscap/vulnerability duplicated; this pins that they (and any
    future addition) stay family-exclusive.
    """
    from cybersecurity_assessor.evidence.tagger import _CONTROL_FAMILY_GLOSS

    term_to_families: dict[str, set[str]] = {}
    for fam, gloss in _CONTROL_FAMILY_GLOSS.items():
        for term in gloss.split():
            term_to_families.setdefault(term, set()).add(fam)
    dupes = {t: sorted(f) for t, f in term_to_families.items() if len(f) > 1}
    assert not dupes, f"cross-family gloss terms (cause cross-tagging): {dupes}"
