"""Regression tests for ``poam/generator.py`` milestone + severity bugs.

Pins two real bugs surfaced by the edge-case probe:

  1. **Whitespace-only rule_id leaks into milestone text.** In Python, the
     string ``"   "`` is truthy, so the guard
     ``if not rule_id or rule_id in seen_rules`` let it through and the
     POAM milestone description ended up as ``"Remediate    : bad config"``.
     Strip first; an empty stripped value is a non-rule and must be skipped.

  2. **_derive_remediation_severity stopped at the first finding even
     when its severity was None / unknown.** Corroboration pre-sorts by
     severity so the first entry IS usually worst, but a None-severity
     row sorts LAST in `_severity_sort_key` (rank 99) — meaning if a
     cluster has [None, "high"], the function would return the
     RiskLevel-based fallback (often "medium") even though "high" is
     present in the list. Fix: iterate past any finding whose severity
     doesn't resolve to a known tier.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor.models import (  # noqa: E402
    FindingStatus,
    RiskLevel,
    StigFinding,
)
from cybersecurity_assessor.poam.generator import (  # noqa: E402
    _derive_remediation_severity,
    _seed_milestones,
)


def _fake_finding(rule_id: str | None, severity: str | None) -> StigFinding:
    return StigFinding(
        id=1,
        evidence_id=1,
        rule_id=rule_id,
        cci_refs="CCI-000015",
        severity=severity,
        status=FindingStatus.OPEN,
        finding_details="An adverse outcome.",
    )


# ---------------------------------------------------------------------------
# Bug #4 — whitespace-only rule_id
# ---------------------------------------------------------------------------


def test_seed_milestones_skips_whitespace_only_rule_id():
    """`"   "` must not produce a `"Remediate    :"` milestone."""
    finding = _fake_finding(rule_id="   ", severity="high")
    out = _seed_milestones(
        poam_id=99,
        cluster_id="ac-2",
        stig_findings=[(finding, "x.ckl")],
        completion_date=datetime.now(timezone.utc),
    )
    # Exactly the generic milestone — no rule-specific row.
    assert len(out) == 1
    assert out[0].description.startswith("Develop and implement")


def test_seed_milestones_skips_empty_rule_id():
    finding = _fake_finding(rule_id="", severity="high")
    out = _seed_milestones(
        poam_id=1,
        cluster_id="ac-2",
        stig_findings=[(finding, "x.ckl")],
        completion_date=datetime.now(timezone.utc),
    )
    assert len(out) == 1


def test_seed_milestones_skips_none_rule_id():
    finding = _fake_finding(rule_id=None, severity="high")
    out = _seed_milestones(
        poam_id=1,
        cluster_id="ac-2",
        stig_findings=[(finding, "x.ckl")],
        completion_date=datetime.now(timezone.utc),
    )
    assert len(out) == 1


def test_seed_milestones_keeps_valid_rule_id_with_padding():
    """Padding around a real rule_id should be stripped, not rejected."""
    finding = _fake_finding(rule_id="  SV-12345  ", severity="high")
    out = _seed_milestones(
        poam_id=1,
        cluster_id="ac-2",
        stig_findings=[(finding, "x.ckl")],
        completion_date=datetime.now(timezone.utc),
    )
    assert len(out) == 2
    assert "Remediate SV-12345:" in out[1].description, (
        "rule_id should be stripped, not surrounded by whitespace in output"
    )


def test_seed_milestones_dedupes_whitespace_variants():
    """`'SV-1'` and `'  SV-1  '` are the same rule — only one milestone."""
    findings = [
        (_fake_finding(rule_id="SV-1", severity="high"), "a.ckl"),
        (_fake_finding(rule_id="  SV-1  ", severity="high"), "b.ckl"),
    ]
    out = _seed_milestones(
        poam_id=1,
        cluster_id="ac-2",
        stig_findings=findings,
        completion_date=datetime.now(timezone.utc),
    )
    # 1 generic + 1 rule-specific (deduped after strip)
    assert len(out) == 2


# ---------------------------------------------------------------------------
# Bug #5 — _derive_remediation_severity walks past None / unknown severity
# ---------------------------------------------------------------------------


def test_derive_severity_skips_none_to_find_high():
    """[None, 'high'] → 'high', not the RiskLevel-based fallback."""
    f_none = _fake_finding(rule_id="A", severity=None)
    f_high = _fake_finding(rule_id="B", severity="high")
    key = _derive_remediation_severity(
        [(f_none, "a"), (f_high, "b")], RiskLevel.MODERATE
    )
    assert key == "high"


def test_derive_severity_skips_unknown_to_find_medium():
    """A garbage severity ("foo") on the first entry must not block lookup."""
    f_bad = _fake_finding(rule_id="A", severity="foo")
    f_med = _fake_finding(rule_id="B", severity="medium")
    key = _derive_remediation_severity(
        [(f_bad, "a"), (f_med, "b")], RiskLevel.LOW
    )
    assert key == "medium"


def test_derive_severity_falls_back_when_all_invalid():
    """All None/unknown → fall back to RiskLevel mapping."""
    findings = [
        (_fake_finding(rule_id="A", severity=None), "a"),
        (_fake_finding(rule_id="B", severity="bogus"), "b"),
    ]
    key = _derive_remediation_severity(findings, RiskLevel.HIGH)
    # _RISK_LEVEL_TO_SEVERITY[HIGH] is "high"
    assert key == "high"


def test_derive_severity_empty_list_uses_fallback():
    """No findings at all → fall back to RiskLevel."""
    assert _derive_remediation_severity([], RiskLevel.LOW) == "low"


def test_derive_severity_cat_i_normalization_still_works():
    """'CAT I' (DISA notation) must still normalize to high."""
    f = _fake_finding(rule_id="A", severity="CAT I")
    assert _derive_remediation_severity([(f, "a")], RiskLevel.LOW) == "cat i"


def test_derive_severity_padding_still_works():
    f = _fake_finding(rule_id="A", severity="  high  ")
    assert _derive_remediation_severity([(f, "a")], RiskLevel.LOW) == "high"
