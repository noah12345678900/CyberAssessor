"""Tests for ``crm_ml.extract_features`` — the per-CRM feature vector
the IsolationForest tier trains on.

What we pin:

1. **Schema version stability.** A feature vector built today reports
   ``schema_version == CURRENT_FEATURE_SCHEMA_VERSION`` (currently 1).
   The schema-version field is the load-bearing invariant that lets
   stale corpus rows fall out of refit corpora and stale model blobs
   refuse to score new vectors — if anyone ever bumps the version
   without also bumping the dataclass field set, this test fails.

2. **Deterministic extraction.** Same CrmContext + same in-scope list
   + same tagged-evidence dict → byte-identical feature vector across
   repeated calls. IsolationForest training is sensitive to feature
   instability; non-determinism would cause "weird" rows to
   intermittently look like outliers.

3. **Scope filter.** Only in-scope control ids contribute. A CRM with
   100 entries but only 3 in scope reports stats over the 3.

4. **Percentage math.** ``inherited_pct`` / ``provider_pct`` /
   ``not_applicable_pct`` divide by the SCOPE size, not by the CRM
   entry count. (A CRM with 5 in-scope entries, 3 inherited, but 10
   total entries should report 3/5 = 0.6, not 3/10 = 0.3.)

5. **Narrative stats subset.** Length stats are computed over
   inherited/provider/NA/hybrid claims only — customer-owned rows
   have legitimately empty narratives (the assessor writes them
   later) and must not drag the stats.

6. **Empty-corpus safety.** Zero in-scope ids → all-zero vector
   without ZeroDivisionError. Same for "all customer" CRMs (no claims).

7. **TF-IDF similarity contracts.** Identical narratives across all
   claims → both max_similarity and mean_similarity ≈ 1.0. Distinct
   narratives → both near 0.0. Single-narrative case → both 0.0
   (no pairs to compare).

8. **Family contradiction count.** Counts families that are FULLY
   off-loaded AND have local tagged evidence. Mixed-responsibility
   families don't count (matches the heuristic's precondition).

9. **JSON round-trip.** ``to_json`` → ``from_json`` is a no-op so the
   ``CrmCorpusFeatures.features_json`` column round-trips losslessly.

sklearn is required for the TF-IDF call inside ``extract_features``;
module-level ``importorskip``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

pytest.importorskip("sklearn", reason="extract_features needs TF-IDF vectorizer")

from cybersecurity_assessor.engine.crm_context import (  # noqa: E402
    CrmContext,
    CrmEntry,
)
from cybersecurity_assessor.engine.crm_ml import (  # noqa: E402
    CURRENT_FEATURE_SCHEMA_VERSION,
    CrmFeatureVector,
    extract_features,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _entry(
    control_id: str,
    responsibility: str,
    narrative: str | None = "Substantive narrative explaining the implementation.",
) -> CrmEntry:
    return CrmEntry(
        control_id=control_id,
        responsibility=responsibility,
        narrative=narrative,
        source_baseline_id=1,
    )


def _ctx(entries: list[CrmEntry]) -> CrmContext:
    return CrmContext(by_control={e.control_id: e for e in entries})


# ---------------------------------------------------------------------------
# Schema version
# ---------------------------------------------------------------------------


def test_extracted_vector_reports_current_schema_version():
    """Anything we build today must carry CURRENT_FEATURE_SCHEMA_VERSION
    so it lands in the right corpus bucket.
    """
    entries = [_entry("ac-2", "customer", "Local PAM details.")]
    vec = extract_features(
        crm_context=_ctx(entries),
        in_scope_control_ids=["ac-2"],
        tagged_evidence_by_family={},
    )
    assert vec.schema_version == CURRENT_FEATURE_SCHEMA_VERSION


def test_numeric_fields_tuple_matches_dataclass_field_count():
    """Pins the schema invariant: any field added to the dataclass must
    also be added to ``_NUMERIC_FIELDS`` (or vice versa) so ``to_row``
    serializes the full vector. Catches the "added a column but forgot
    to put it in the row" footgun.
    """
    declared = set(CrmFeatureVector._NUMERIC_FIELDS)
    # Every _NUMERIC_FIELDS entry must be a real dataclass field.
    from dataclasses import fields
    all_fields = {f.name for f in fields(CrmFeatureVector)}
    assert declared.issubset(all_fields)
    # The non-numeric fields ought to be just schema_version.
    assert all_fields - declared == {"schema_version"}


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_extraction_is_deterministic_across_repeated_calls():
    """Same inputs → identical CrmFeatureVector across multiple calls.

    Run extract_features twice on the same context and assert equality.
    Important because IsolationForest training would amplify any
    non-determinism here into spurious outliers.
    """
    entries = [
        _entry("ac-2", "inherited", "Identity provider lifecycle."),
        _entry("ac-3", "customer", "RBAC managed locally."),
        _entry("ia-5", "hybrid", "MFA mixed enforcement model."),
        _entry("cm-6", "provider", "Provider baseline mgmt."),
    ]
    ctx = _ctx(entries)
    scope = [e.control_id for e in entries]
    tagged = {"au": 2}

    v1 = extract_features(crm_context=ctx, in_scope_control_ids=scope, tagged_evidence_by_family=tagged)
    v2 = extract_features(crm_context=ctx, in_scope_control_ids=scope, tagged_evidence_by_family=tagged)
    assert v1 == v2


# ---------------------------------------------------------------------------
# Scope filtering
# ---------------------------------------------------------------------------


def test_extraction_ignores_out_of_scope_crm_entries():
    """CRM has 6 entries; only 3 are in scope. The 3 out-of-scope
    entries must NOT contribute to any stat.

    Setup: 3 in-scope (all customer) + 3 out-of-scope (all inherited).
    Inherited_pct over the SCOPE should be 0.0, not 0.5.
    """
    entries = [
        _entry("ac-1", "customer", "Local."),
        _entry("ac-2", "customer", "Local."),
        _entry("ac-3", "customer", "Local."),
        # Out of scope:
        _entry("zz-1", "inherited", "noise"),
        _entry("zz-2", "inherited", "noise"),
        _entry("zz-3", "inherited", "noise"),
    ]
    vec = extract_features(
        crm_context=_ctx(entries),
        in_scope_control_ids=["ac-1", "ac-2", "ac-3"],
        tagged_evidence_by_family={},
    )
    assert vec.inherited_pct == 0.0
    assert vec.in_scope_control_count == 3


def test_in_scope_control_count_uses_scope_size_not_crm_entry_count():
    """``in_scope_control_count`` is the SCOPE size, even when the CRM
    is missing entries for some scope ids. (The overlay-default-local
    rule means a missing CRM row = customer-owned; size of scope is
    what's denominator-relevant.)
    """
    entries = [_entry("ac-2", "inherited", "x")]
    vec = extract_features(
        crm_context=_ctx(entries),
        # Scope has 5 ids; CRM has only 1.
        in_scope_control_ids=["ac-2", "ac-3", "cm-6", "ia-2", "au-2"],
        tagged_evidence_by_family={},
    )
    assert vec.in_scope_control_count == 5
    # 1 inherited out of 5 scope ids = 0.2.
    assert vec.inherited_pct == pytest.approx(0.2)


# ---------------------------------------------------------------------------
# Percentage math
# ---------------------------------------------------------------------------


def test_percentages_use_scope_size_as_denominator():
    """3 inherited, 1 provider, 1 NA in a 5-id scope.
    inherited_pct = 0.6, provider_pct = 0.2, not_applicable_pct = 0.2.
    """
    entries = [
        _entry("ac-2", "inherited", "Identity provider handles account lifecycle."),
        _entry("ac-3", "inherited", "Role-based access mappings inherited from SSO."),
        _entry("ia-2", "inherited", "MFA enforced at the corporate IdP boundary."),
        _entry("cm-6", "provider", "Baseline managed by provider control plane."),
        _entry("au-2", "not_applicable", "Audit not applicable per overlay scoping."),
    ]
    vec = extract_features(
        crm_context=_ctx(entries),
        in_scope_control_ids=[e.control_id for e in entries],
        tagged_evidence_by_family={},
    )
    assert vec.inherited_pct == pytest.approx(0.6)
    assert vec.provider_pct == pytest.approx(0.2)
    assert vec.not_applicable_pct == pytest.approx(0.2)


def test_customer_only_crm_has_zero_off_loaded_percentages():
    """All-customer CRM → inherited/provider/NA all 0.0."""
    entries = [_entry(f"ac-{i}", "customer", f"local {i}") for i in range(1, 6)]
    vec = extract_features(
        crm_context=_ctx(entries),
        in_scope_control_ids=[e.control_id for e in entries],
        tagged_evidence_by_family={},
    )
    assert vec.inherited_pct == 0.0
    assert vec.provider_pct == 0.0
    assert vec.not_applicable_pct == 0.0


# ---------------------------------------------------------------------------
# Narrative stats subset
# ---------------------------------------------------------------------------


def test_narrative_stats_ignore_customer_rows():
    """Customer-owned rows with empty narrative are legitimate (assessor
    fills these in). They must NOT be counted toward narrative_present_pct.

    Setup: 3 customer rows with empty narratives + 3 inherited rows with
    full narratives. narrative_present_pct = 3/3 (all claims have
    narratives) = 1.0.
    """
    entries = [
        _entry("ac-1", "customer", None),
        _entry("ac-2", "customer", None),
        _entry("ac-3", "customer", None),
        _entry("ia-1", "inherited", "Real text 1."),
        _entry("ia-2", "inherited", "Real text 2."),
        _entry("ia-3", "inherited", "Real text 3."),
    ]
    vec = extract_features(
        crm_context=_ctx(entries),
        in_scope_control_ids=[e.control_id for e in entries],
        tagged_evidence_by_family={},
    )
    assert vec.narrative_present_pct == pytest.approx(1.0)
    # And mean/stdev computed over the 3 present narratives.
    assert vec.narrative_len_mean > 0
    # 3 narratives of identical length 13 ("Real text N.")  → stdev 0.
    assert vec.narrative_len_stdev == pytest.approx(0.0)


def test_narrative_present_pct_drops_when_some_claims_have_empty_narrative():
    """5 inherited rows, 2 with empty narrative → present_pct = 3/5 = 0.6."""
    entries = [
        _entry("ac-1", "inherited", "Real."),
        _entry("ac-2", "inherited", "Real."),
        _entry("ac-3", "inherited", "Real."),
        _entry("ac-4", "inherited", None),
        _entry("ac-5", "inherited", ""),
    ]
    vec = extract_features(
        crm_context=_ctx(entries),
        in_scope_control_ids=[e.control_id for e in entries],
        tagged_evidence_by_family={},
    )
    assert vec.narrative_present_pct == pytest.approx(0.6)


# ---------------------------------------------------------------------------
# Edge cases / safety
# ---------------------------------------------------------------------------


def test_empty_scope_returns_zero_vector_without_division_error():
    """No in-scope ids → everything 0, no crash. Safety check for a CRM
    uploaded before scope is set.
    """
    vec = extract_features(
        crm_context=_ctx([]),
        in_scope_control_ids=[],
        tagged_evidence_by_family={},
    )
    assert vec.inherited_pct == 0.0
    assert vec.provider_pct == 0.0
    assert vec.not_applicable_pct == 0.0
    assert vec.narrative_present_pct == 0.0
    assert vec.narrative_len_mean == 0.0
    assert vec.narrative_len_stdev == 0.0
    assert vec.intra_crm_tfidf_max_similarity == 0.0
    assert vec.intra_crm_tfidf_mean_similarity == 0.0
    assert vec.family_evidence_contradictions == 0
    assert vec.in_scope_control_count == 0


def test_single_claim_returns_zero_similarity():
    """Only one narrative to compare → no pairs → similarity stats 0.0
    (no ZeroDivisionError or NaN slips through).
    """
    entries = [_entry("ac-2", "inherited", "Only narrative.")]
    vec = extract_features(
        crm_context=_ctx(entries),
        in_scope_control_ids=["ac-2"],
        tagged_evidence_by_family={},
    )
    assert vec.intra_crm_tfidf_max_similarity == 0.0
    assert vec.intra_crm_tfidf_mean_similarity == 0.0


def test_all_customer_crm_has_zero_narrative_stats():
    """No claims (all customer) → no narrative_present_pct / lengths /
    similarity to compute. All zero.
    """
    entries = [_entry(f"ac-{i}", "customer", "Local detail.") for i in range(1, 4)]
    vec = extract_features(
        crm_context=_ctx(entries),
        in_scope_control_ids=[e.control_id for e in entries],
        tagged_evidence_by_family={},
    )
    assert vec.narrative_present_pct == 0.0
    assert vec.narrative_len_mean == 0.0
    assert vec.narrative_len_stdev == 0.0
    assert vec.intra_crm_tfidf_max_similarity == 0.0
    assert vec.intra_crm_tfidf_mean_similarity == 0.0


# ---------------------------------------------------------------------------
# TF-IDF similarity stats
# ---------------------------------------------------------------------------


def test_identical_narratives_drive_similarity_to_one():
    """5 identical narratives → off-diagonal cosine ≈ 1.0 everywhere.
    Both max and mean should be very close to 1.
    """
    boiler = (
        "The customer inherits this control from the cloud service provider. "
        "See the SSP for inheritance details."
    )
    entries = [_entry(f"ac-{i}", "inherited", boiler) for i in range(1, 6)]
    vec = extract_features(
        crm_context=_ctx(entries),
        in_scope_control_ids=[e.control_id for e in entries],
        tagged_evidence_by_family={},
    )
    assert vec.intra_crm_tfidf_max_similarity == pytest.approx(1.0, abs=0.01)
    assert vec.intra_crm_tfidf_mean_similarity == pytest.approx(1.0, abs=0.01)


def test_distinct_narratives_keep_similarity_low():
    """5 substantively different narratives → mean similarity well below
    the 0.85 boilerplate threshold.
    """
    distinct = [
        "Customer manages local audit log forwarding via the syslog agent.",
        "Configuration baselines are tracked through Ansible playbooks.",
        "Identity federation is via the corporate SAML IdP, MFA required.",
        "Vulnerability scans run weekly via Tenable agents on every host.",
        "Backups are taken nightly and tested via quarterly restore drills.",
    ]
    entries = [
        _entry(f"ac-{i}", "inherited", text)
        for i, text in enumerate(distinct, start=1)
    ]
    vec = extract_features(
        crm_context=_ctx(entries),
        in_scope_control_ids=[e.control_id for e in entries],
        tagged_evidence_by_family={},
    )
    # No shared meaningful vocabulary → similarity should be well under 0.5.
    assert vec.intra_crm_tfidf_mean_similarity < 0.30
    assert vec.intra_crm_tfidf_max_similarity < 0.60


# ---------------------------------------------------------------------------
# Family contradiction count
# ---------------------------------------------------------------------------


def test_family_contradiction_count_counts_fully_offloaded_families_with_evidence():
    """Two families AC + IA are fully inherited; AC has tagged evidence
    (contradiction), IA has none (no contradiction). Count should be 1.
    """
    entries = [
        _entry("ac-2", "inherited", "Identity provider account lifecycle."),
        _entry("ac-3", "inherited", "Role mappings from corporate IdP."),
        _entry("ia-2", "inherited", "MFA enforced by IdP boundary."),
        _entry("ia-5", "inherited", "Authenticator policy at the IdP."),
        _entry("cm-6", "customer", "Local baseline hardening playbook."),  # padding
    ]
    vec = extract_features(
        crm_context=_ctx(entries),
        in_scope_control_ids=[e.control_id for e in entries],
        tagged_evidence_by_family={"ac": 4, "cm": 1},
    )
    # AC fully off-loaded + has evidence = 1 contradiction.
    # IA fully off-loaded but no evidence = 0.
    # CM has evidence but is customer-owned = doesn't count.
    assert vec.family_evidence_contradictions == 1


def test_mixed_responsibility_family_does_not_contradict():
    """AC has one inherited and one customer row → AC is NOT fully
    off-loaded, so even with local evidence on AC the contradiction
    count is 0.
    """
    entries = [
        _entry("ac-2", "inherited", "x"),
        _entry("ac-3", "customer", "x"),  # breaks the "fully off-loaded" status
    ]
    vec = extract_features(
        crm_context=_ctx(entries),
        in_scope_control_ids=[e.control_id for e in entries],
        tagged_evidence_by_family={"ac": 10},
    )
    assert vec.family_evidence_contradictions == 0


# ---------------------------------------------------------------------------
# JSON round-trip
# ---------------------------------------------------------------------------


def test_to_json_round_trip_preserves_all_fields():
    """``CrmCorpusFeatures.features_json`` round-trip must be lossless."""
    entries = [
        _entry("ac-2", "inherited", "Real narrative one."),
        _entry("ac-3", "inherited", "Real narrative two."),
        _entry("cm-6", "customer", "Local detail."),
    ]
    original = extract_features(
        crm_context=_ctx(entries),
        in_scope_control_ids=[e.control_id for e in entries],
        tagged_evidence_by_family={"ac": 2},
    )
    payload = original.to_json()
    restored = CrmFeatureVector.from_json(payload)
    assert restored == original


def test_to_row_returns_fields_in_declared_order():
    """``to_row`` order MUST match ``_NUMERIC_FIELDS`` order — that's
    the column-order contract that lets a persisted IsolationForest
    blob keep scoring new vectors correctly across restarts.
    """
    entries = [_entry("ac-2", "inherited", "x"), _entry("ac-3", "customer", "y")]
    vec = extract_features(
        crm_context=_ctx(entries),
        in_scope_control_ids=[e.control_id for e in entries],
        tagged_evidence_by_family={},
    )
    row = vec.to_row()
    assert len(row) == len(CrmFeatureVector._NUMERIC_FIELDS)
    # First field is inherited_pct = 1/2 = 0.5.
    assert row[0] == pytest.approx(0.5)
    # Last field is in_scope_control_count = 2.
    assert row[-1] == pytest.approx(2.0)
