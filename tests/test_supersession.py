"""Tests for the document supersession map.

These tests prove the "deterministic stale-citation rewrite" behavior:
every legacy doc reference the LLM might emit gets canonicalized to the
current-tier title BEFORE it reaches the workbook.

The shipped registry (``_LEGACY_TO_CURRENT`` / ``_SSAA_TO_SDA_MAPPINGS``)
ships **empty** — it held one program's verbatim doc map and was scrubbed
so no program data is baked into the app. The machinery is therefore
exercised here against a fictional synthetic registry installed via the
``synthetic_registry`` fixture; nothing in this file references real
program data. A dedicated test asserts the shipped registry stays empty.
"""

from __future__ import annotations

import re

import pytest

from cybersecurity_assessor.engine import supersession
from cybersecurity_assessor.engine.supersession import (
    SupersessionEntry,
    VerifiedSdaMapping,
)


# ---------------------------------------------------------------------------
# Fictional synthetic registry — NO program data. Longest legacy strings
# come first within an overlap group so the matcher picks the most specific
# match first (mirrors the shipped ordering contract).
# ---------------------------------------------------------------------------

_FAKE_ENTRIES: list[SupersessionEntry] = [
    SupersessionEntry(
        legacy="Acme Widget Legacy Operations User Guide",
        current="ACME-DOC-0010 Acme Widget Operations Plan Rev 2",
        sharepoint_folder=None,
        notes=None,
    ),
    SupersessionEntry(
        legacy="Acme Widget Legacy Operations Plan",
        current="ACME-DOC-0010 Acme Widget Operations Plan Rev 2",
        sharepoint_folder=None,
        notes=None,
    ),
    SupersessionEntry(
        legacy="Acme Widget Legacy Auditing Procedures",
        current="ACME-DOC-0021 Acme Widget Auditing Procedures Rev 1",
        sharepoint_folder=None,
        notes=None,
    ),
    # Full form must out-rank the bare acronym (listed first / longer).
    SupersessionEntry(
        legacy="System Security Authorization Agreement",
        current="ACME-DOC-0030 Acme Widget Security Plan Rev 3",
        sharepoint_folder=None,
        notes=None,
    ),
    SupersessionEntry(
        legacy="SSAA",
        current="ACME-DOC-0030 Acme Widget Security Plan Rev 3",
        sharepoint_folder=None,
        notes=None,
    ),
]

_FAKE_MAPPINGS: list[VerifiedSdaMapping] = [
    VerifiedSdaMapping(
        cci_id="CCI-001485",
        control_id="au-2",
        sda_req_number="#29",
        shall_statement="The system shall generate audit records for the defined auditable events.",
    ),
    VerifiedSdaMapping(
        cci_id="CCI-000767",
        control_id="ia-2.3",
        sda_req_number="#12",
        shall_statement="The system shall implement multifactor authentication for local access.",
    ),
    VerifiedSdaMapping(
        cci_id="CCI-001941",
        control_id="ia-2.8",
        sda_req_number="#14",
        shall_statement="The system shall implement replay-resistant authentication.",
    ),
]


@pytest.fixture
def synthetic_registry(monkeypatch):
    """Install a fictional registry so the machinery can be exercised
    without baking program data into the test suite."""
    monkeypatch.setattr(supersession, "_LEGACY_TO_CURRENT", _FAKE_ENTRIES)
    monkeypatch.setattr(
        supersession,
        "_COMPILED_PATTERNS",
        [(re.compile(re.escape(e.legacy), re.IGNORECASE), e) for e in _FAKE_ENTRIES],
    )
    monkeypatch.setattr(supersession, "_SSAA_TO_SDA_MAPPINGS", _FAKE_MAPPINGS)
    return supersession


# ---------------------------------------------------------------------------
# Shipped registry is scrubbed (no program data baked in)
# ---------------------------------------------------------------------------


def test_shipped_registry_is_empty():
    assert supersession._LEGACY_TO_CURRENT == []
    assert supersession._COMPILED_PATTERNS == []
    assert supersession._SSAA_TO_SDA_MAPPINGS == []


def test_rewrite_no_op_when_registry_empty():
    # With the shipped (empty) registry, even a legacy-looking phrase is
    # returned untouched — the machinery degrades gracefully.
    text = "Reviewed Acme Widget Legacy Operations Plan section 3."
    result = supersession.rewrite_narrative(text)
    assert result.rewritten_text == text
    assert result.hits == []
    assert not result.changed


# ---------------------------------------------------------------------------
# rewrite_narrative — core path (synthetic registry)
# ---------------------------------------------------------------------------


def test_rewrites_legacy_user_guide_to_current(synthetic_registry):
    text = "Reviewed Acme Widget Legacy Operations User Guide §3.2."
    result = synthetic_registry.rewrite_narrative(text)
    assert result.changed
    assert "ACME-DOC-0010 Acme Widget Operations Plan Rev 2" in result.rewritten_text
    assert "Legacy Operations User Guide" not in result.rewritten_text
    assert len(result.hits) == 1
    assert result.hits[0][0] == "Acme Widget Legacy Operations User Guide"


def test_rewrite_is_idempotent(synthetic_registry):
    text = "Reviewed Acme Widget Legacy Operations Plan."
    once = synthetic_registry.rewrite_narrative(text)
    twice = synthetic_registry.rewrite_narrative(once.rewritten_text)
    assert twice.rewritten_text == once.rewritten_text
    # Second pass yields no new hits because the legacy phrase is gone.
    assert twice.hits == []


def test_rewrite_is_case_insensitive(synthetic_registry):
    text = "Confirmed via acme widget legacy auditing procedures section 4."
    result = synthetic_registry.rewrite_narrative(text)
    assert result.changed
    assert "ACME-DOC-0021 Acme Widget Auditing Procedures Rev 1" in result.rewritten_text


def test_longest_match_wins_for_user_guide_vs_plan(synthetic_registry):
    # Both the "User Guide" and "Plan" legacy strings are entries. The
    # former is listed first (longer/more specific). Neither contains the
    # other, but this guards order-of-iteration.
    user_guide_text = "Cited Acme Widget Legacy Operations User Guide."
    plan_text = "Cited Acme Widget Legacy Operations Plan."
    ug = synthetic_registry.rewrite_narrative(user_guide_text)
    pl = synthetic_registry.rewrite_narrative(plan_text)
    assert ug.hits[0][0] == "Acme Widget Legacy Operations User Guide"
    assert pl.hits[0][0] == "Acme Widget Legacy Operations Plan"


def test_ssaa_full_form_wins_over_bare_acronym(synthetic_registry):
    text = "Verified per System Security Authorization Agreement appendix B."
    result = synthetic_registry.rewrite_narrative(text)
    # The full form must match before the bare acronym entry sweeps it up.
    assert any(
        legacy == "System Security Authorization Agreement"
        for legacy, _ in result.hits
    )


def test_empty_input_returns_empty_result():
    result = supersession.rewrite_narrative("")
    assert result.rewritten_text == ""
    assert result.hits == []
    assert not result.changed


def test_no_legacy_refs_returns_unchanged(synthetic_registry):
    text = "Reviewed ACME-DOC-0010 Acme Widget Operations Plan Rev 2 directly."
    result = synthetic_registry.rewrite_narrative(text)
    assert result.rewritten_text == text
    assert result.hits == []


# ---------------------------------------------------------------------------
# find_stale_references — review helper
# ---------------------------------------------------------------------------


def test_find_stale_references_lists_entries_without_rewriting(synthetic_registry):
    text = "Cites SSAA and Acme Widget Legacy Operations Plan."
    stale = synthetic_registry.find_stale_references(text)
    legacy_strings = {e.legacy for e in stale}
    # Bare SSAA + Plan should both be flagged.
    assert "Acme Widget Legacy Operations Plan" in legacy_strings
    assert "SSAA" in legacy_strings


def test_find_stale_references_dedupes(synthetic_registry):
    text = "SSAA, SSAA, SSAA — repeated three times."
    stale = synthetic_registry.find_stale_references(text)
    assert sum(1 for e in stale if e.legacy == "SSAA") == 1


def test_find_stale_references_empty_when_registry_empty():
    # No fixture → shipped empty registry → nothing flagged.
    text = "SSAA, SSAA, SSAA — repeated three times."
    assert supersession.find_stale_references(text) == []


# ---------------------------------------------------------------------------
# Verified SDA mappings
# ---------------------------------------------------------------------------


def test_lookup_verified_sda_mapping_normalizes_cci_id(synthetic_registry):
    m = synthetic_registry.lookup_verified_sda_mapping("CCI-1485")
    assert m is not None
    assert m.cci_id == "CCI-001485"
    assert m.sda_req_number == "#29"
    assert m.control_id == "au-2"


def test_lookup_verified_sda_mapping_returns_none_for_unknown(synthetic_registry):
    assert synthetic_registry.lookup_verified_sda_mapping("CCI-999999") is None


def test_lookup_verified_sda_mapping_none_when_registry_empty():
    # No fixture → shipped empty mappings → always None.
    assert supersession.lookup_verified_sda_mapping("CCI-001485") is None


def test_all_verified_mappings_round_trip(synthetic_registry):
    for cci, ctrl in (
        ("CCI-001485", "au-2"),
        ("CCI-000767", "ia-2.3"),
        ("CCI-001941", "ia-2.8"),
    ):
        m = synthetic_registry.lookup_verified_sda_mapping(cci)
        assert m is not None
        assert m.control_id == ctrl


# ---------------------------------------------------------------------------
# NA reconsideration warning
# ---------------------------------------------------------------------------


def test_na_warning_fires_for_verified_mapping(synthetic_registry):
    warn = synthetic_registry.na_reconsideration_warning(
        cci_id="CCI-001485",
        current_status="Not Applicable",
        prior_results_text="Marked N/A per SSAA scope.",
    )
    assert warn is not None
    assert warn.severity == "warning"
    assert "Req #29" in warn.message


def test_na_warning_info_severity_for_ssaa_without_verified_mapping(synthetic_registry):
    warn = synthetic_registry.na_reconsideration_warning(
        cci_id="CCI-999999",
        current_status="Not Applicable",
        prior_results_text="Marked N/A per SSAA scope.",
    )
    assert warn is not None
    assert warn.severity == "info"


def test_na_warning_silent_for_compliant_row(synthetic_registry):
    warn = synthetic_registry.na_reconsideration_warning(
        cci_id="CCI-001485",
        current_status="Compliant",
        prior_results_text="Marked N/A per SSAA scope.",
    )
    assert warn is None


def test_na_warning_silent_when_no_ssaa_reference(synthetic_registry):
    warn = synthetic_registry.na_reconsideration_warning(
        cci_id="CCI-001485",
        current_status="Not Applicable",
        prior_results_text="N/A — feature not present.",
    )
    assert warn is None


def test_na_warning_silent_when_registry_empty():
    # No fixture → no SSAA-bearing compiled patterns → always None even
    # when the prior text mentions the SSAA.
    warn = supersession.na_reconsideration_warning(
        cci_id="CCI-001485",
        current_status="Not Applicable",
        prior_results_text="Marked N/A per SSAA scope.",
    )
    assert warn is None
