"""Tests for the inter-tier blend math in ``crm_sanity``.

The four heuristic firings are tested in ``test_crm_sanity_heuristics``;
the feature extraction in ``test_crm_ml_features``. This module pins:

1. **``_blend`` formula correctness** — when all three tiers report,
   weighting is ``0.5 * heuristic + 0.3 * ml_anomaly + 0.2 * (1 - quality)``
   over the sum of present weights (= 1.0). When a tier is missing
   (``None``), its weight is dropped and the result is normalized by the
   remaining weight — so a heuristic-only report doesn't get artificially
   dragged down to 0.5x.

2. **``CrmSuspicionReport.severity`` bucketing** — info/warn/alert
   boundaries at 0.30 and 0.60 (inclusive at 0.60 for alert).

3. **Heuristic-internal aggregation = ``max(components)``** — distinct
   from the inter-tier blend. Rationale (per the module docstring): each
   heuristic detects an independent failure mode; one severe failure
   shouldn't be diluted by three "all clear" components. The inter-tier
   blend, by contrast, is a weighted average because the tiers are
   correlated signals about the same property.

4. **Public-API tier wiring** — passing a stubbed
   ``anomaly_model_blob`` actually populates ``ml_anomaly_score``;
   passing a stubbed ``embeddings_provider`` actually populates
   ``narrative_quality_score``; both ``None``-default to None.

We use private ``_blend`` directly for the math tests — that's the
contract we want to pin without indirection through CRM construction.

sklearn is required for the always-on TF-IDF call inside
``extract_features``; module-level ``importorskip``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

pytest.importorskip("sklearn", reason="extract_features needs TF-IDF vectorizer")

from cybersecurity_assessor.engine import crm_sanity  # noqa: E402
from cybersecurity_assessor.engine.crm_context import (  # noqa: E402
    CrmContext,
    CrmEntry,
)
from cybersecurity_assessor.engine.crm_sanity import (  # noqa: E402
    BLEND_W_HEURISTIC,
    BLEND_W_ML_ANOMALY,
    BLEND_W_NARRATIVE,
    OVERALL_INFO_MAX,
    OVERALL_WARN_MAX,
    CrmSuspicionFlag,
    CrmSuspicionReport,
    _blend,
    score_crm_suspicion,
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


def _report(
    *,
    overall: float,
    heuristic: float = 0.0,
    ml: float | None = None,
    quality: float | None = None,
) -> CrmSuspicionReport:
    """Build a report directly to exercise the severity property without
    going through ``score_crm_suspicion``.
    """
    from datetime import datetime, timezone

    return CrmSuspicionReport(
        workbook_id=1,
        crm_baseline_id=1,
        computed_at=datetime.now(timezone.utc),
        heuristic_score=heuristic,
        ml_anomaly_score=ml,
        narrative_quality_score=quality,
        overall_suspicion=overall,
        flags=(),
        per_family={},
        n_corpus=0,
    )


# ---------------------------------------------------------------------------
# _blend — all three tiers present
# ---------------------------------------------------------------------------


def test_blend_with_all_three_tiers_uses_canonical_weights():
    """heuristic=0.8, ml=0.4, quality=0.6 (→ 0.4 contribution from 1-q).

    Expected: 0.5*0.8 + 0.3*0.4 + 0.2*(1-0.6) = 0.4 + 0.12 + 0.08 = 0.60.
    """
    result = _blend(heuristic=0.8, ml_anomaly=0.4, narrative_quality=0.6)
    expected = (
        BLEND_W_HEURISTIC * 0.8
        + BLEND_W_ML_ANOMALY * 0.4
        + BLEND_W_NARRATIVE * (1.0 - 0.6)
    )
    assert expected == pytest.approx(0.60)
    assert result == pytest.approx(expected)


def test_blend_quality_of_one_contributes_zero_to_suspicion():
    """quality=1.0 → (1 - 1.0) = 0 contribution. Substantive narratives
    are evidence AGAINST suspicion, so a perfect-quality CRM with otherwise
    zero scores has zero overall suspicion.
    """
    result = _blend(heuristic=0.0, ml_anomaly=0.0, narrative_quality=1.0)
    assert result == pytest.approx(0.0)


def test_blend_quality_of_zero_pushes_suspicion_up():
    """quality=0.0 → full 0.2 narrative weight applied. With other tiers
    at zero, overall = 0.2 / (sum of weights) = 0.2 / 1.0 = 0.2.
    """
    result = _blend(heuristic=0.0, ml_anomaly=0.0, narrative_quality=0.0)
    assert result == pytest.approx(BLEND_W_NARRATIVE)


# ---------------------------------------------------------------------------
# _blend — weight redistribution when tiers drop out
# ---------------------------------------------------------------------------


def test_blend_heuristic_only_returns_heuristic_value_unchanged():
    """Only heuristic present → weight is 0.5, divisor is 0.5, result = heuristic.

    Pins the redistribution contract: a heuristic-only CRM should NOT be
    artificially halved because the other tiers are missing.
    """
    for h in [0.0, 0.25, 0.5, 0.75, 1.0]:
        assert _blend(heuristic=h, ml_anomaly=None, narrative_quality=None) == pytest.approx(h)


def test_blend_heuristic_and_ml_anomaly_redistribute_correctly():
    """h=0.6, ml=0.4, quality=None →
    (0.5*0.6 + 0.3*0.4) / (0.5 + 0.3) = (0.3 + 0.12) / 0.8 = 0.525.
    """
    result = _blend(heuristic=0.6, ml_anomaly=0.4, narrative_quality=None)
    expected = (BLEND_W_HEURISTIC * 0.6 + BLEND_W_ML_ANOMALY * 0.4) / (
        BLEND_W_HEURISTIC + BLEND_W_ML_ANOMALY
    )
    assert expected == pytest.approx(0.525)
    assert result == pytest.approx(expected)


def test_blend_heuristic_and_quality_redistribute_correctly():
    """h=0.5, ml=None, quality=0.0 →
    (0.5*0.5 + 0.2*1.0) / (0.5 + 0.2) = (0.25 + 0.2) / 0.7 ≈ 0.6428.
    """
    result = _blend(heuristic=0.5, ml_anomaly=None, narrative_quality=0.0)
    expected = (BLEND_W_HEURISTIC * 0.5 + BLEND_W_NARRATIVE * 1.0) / (
        BLEND_W_HEURISTIC + BLEND_W_NARRATIVE
    )
    assert result == pytest.approx(expected)


def test_blend_clips_to_unit_interval():
    """Defensive: caller passes >1 values (shouldn't, but if it does, we
    clamp so the severity buckets stay sane).
    """
    assert _blend(heuristic=2.0, ml_anomaly=2.0, narrative_quality=-1.0) == pytest.approx(1.0)
    assert _blend(heuristic=-1.0, ml_anomaly=-1.0, narrative_quality=2.0) == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# CrmSuspicionReport.severity bucketing
# ---------------------------------------------------------------------------


def test_severity_is_info_strictly_below_0_30():
    """< 0.30 → info."""
    assert _report(overall=0.0).severity == "info"
    assert _report(overall=0.15).severity == "info"
    # Just below the boundary.
    assert _report(overall=OVERALL_INFO_MAX - 0.0001).severity == "info"


def test_severity_is_warn_between_0_30_and_0_60():
    """[0.30, 0.60) → warn."""
    assert _report(overall=OVERALL_INFO_MAX).severity == "warn"  # 0.30 exactly
    assert _report(overall=0.45).severity == "warn"
    assert _report(overall=OVERALL_WARN_MAX - 0.0001).severity == "warn"


def test_severity_is_alert_at_or_above_0_60():
    """>= 0.60 → alert. Inclusive at the boundary because 0.60 is the
    documented "alert" line in the module docstring.
    """
    assert _report(overall=OVERALL_WARN_MAX).severity == "alert"  # 0.60 exactly
    assert _report(overall=0.85).severity == "alert"
    assert _report(overall=1.0).severity == "alert"


# ---------------------------------------------------------------------------
# Heuristic-internal aggregation: max(components), not mean
# ---------------------------------------------------------------------------


def test_heuristic_score_is_max_of_components_not_mean():
    """One severe firing dominates — mean would dilute it. Pins the
    "independent failure modes" design choice.

    Setup: 8/10 inherited (high_inheritance @ 80% → component ≈ 0.6),
    contradicting AC family with tagged evidence (contradiction
    component = 0.2 with 1 of 5 saturating families). Heuristic_score
    must equal the max (≈ 0.6), not the mean (≈ 0.2).

    Narratives are deliberately distinct (different vocabulary per row)
    so the boilerplate heuristic doesn't ride along and dominate the max.
    """
    distinct_narratives = [
        "Identity provider enforces account lifecycle via SCIM provisioning.",
        "Role-based access mappings inherited from corporate SSO entitlements.",
        "Session timeouts configured at the IdP per FIPS-recommended values.",
        "Privileged account requests routed through PAM workflow approvals.",
        "Account auditing handled by the SIEM tenant of the cloud provider.",
        "Concurrent session limits enforced by the workforce identity broker.",
        "Inactivity locks managed by the device MDM under the boundary.",
        "Notification of account changes flows from the IdP webhook stream.",
    ]
    entries = [
        # 8 inherited (off-loaded) — high_inheritance ramp component
        # = (0.8 - 0.5) / 0.5 = 0.6.
        _entry(f"ac-{i+1}", "inherited", text)
        for i, text in enumerate(distinct_narratives)
    ] + [
        _entry("cm-1", "customer", "Configuration baselines maintained locally via Ansible playbooks."),
        _entry("cm-2", "customer", "Functionality restrictions enforced by host hardening scripts."),
    ]
    report = score_crm_suspicion(
        workbook_id=1,
        crm_baseline_id=1,
        crm_context=_ctx(entries),
        in_scope_control_ids=[e.control_id for e in entries],
        # AC fully off-loaded — contradiction with tagged evidence fires.
        tagged_evidence_by_family={"ac": 3},
    )
    # contradiction component = 1/5 = 0.2; high_inheritance = 0.6.
    # max-of-components → heuristic_score should land at 0.6, NOT 0.2 (mean).
    assert report.heuristic_score == pytest.approx(0.6, abs=0.01)


def test_heuristic_score_is_one_when_any_component_fully_saturates():
    """An alert-grade firing should drive heuristic_score to 1.0
    regardless of the other components.

    100% inherited → high_inheritance component = (1.0 - 0.5)/0.5 = 1.0,
    so heuristic_score must equal 1.0 even with empty narratives etc.
    """
    entries = [
        _entry(f"ac-{i}", "inherited", f"Inherited per IdP {i}.") for i in range(1, 11)
    ]
    report = score_crm_suspicion(
        workbook_id=1,
        crm_baseline_id=1,
        crm_context=_ctx(entries),
        in_scope_control_ids=[e.control_id for e in entries],
        tagged_evidence_by_family={},
    )
    assert report.heuristic_score == pytest.approx(1.0)
    # No ML inputs → heuristic-only blend, so overall == heuristic.
    assert report.overall_suspicion == pytest.approx(1.0)
    assert report.severity == "alert"


# ---------------------------------------------------------------------------
# Public-API tier wiring (None defaults vs stubbed inputs)
# ---------------------------------------------------------------------------


def test_score_crm_suspicion_with_no_ml_inputs_returns_none_for_ml_tiers():
    """No anomaly model + no embeddings provider → ml_anomaly_score and
    narrative_quality_score are both None in the report. Pins the cold-
    start UX where the banner greys out the ML rows.
    """
    entries = [
        _entry("ac-2", "customer", "Local PAM."),
        _entry("cm-6", "customer", "Local baseline."),
    ]
    report = score_crm_suspicion(
        workbook_id=1,
        crm_baseline_id=1,
        crm_context=_ctx(entries),
        in_scope_control_ids=[e.control_id for e in entries],
        tagged_evidence_by_family={},
        # Defaults: no model blob, no provider, n_corpus=0.
    )
    assert report.ml_anomaly_score is None
    assert report.narrative_quality_score is None


def test_score_crm_suspicion_calls_anomaly_scorer_when_model_provided(monkeypatch):
    """Pass a non-empty ``anomaly_model_blob`` AND ``n_corpus >= 10`` →
    the scorer is invoked and its result lands in ``ml_anomaly_score``.

    We monkeypatch ``score_anomaly`` so we don't have to fit a real
    IsolationForest just for the wiring assertion.
    """
    captured: dict = {}

    def fake_score_anomaly(blob: bytes, vector) -> float:
        captured["blob"] = blob
        captured["vector"] = vector
        return 0.77

    monkeypatch.setattr(crm_sanity, "score_anomaly", fake_score_anomaly)

    entries = [
        _entry("ac-2", "customer", "Local PAM."),
        _entry("cm-6", "customer", "Local baseline."),
    ]
    report = score_crm_suspicion(
        workbook_id=1,
        crm_baseline_id=1,
        crm_context=_ctx(entries),
        in_scope_control_ids=[e.control_id for e in entries],
        tagged_evidence_by_family={},
        n_corpus=14,
        anomaly_model_blob=b"<fake-pickle>",
    )
    assert report.ml_anomaly_score == pytest.approx(0.77)
    assert captured["blob"] == b"<fake-pickle>"


def test_score_crm_suspicion_skips_anomaly_when_corpus_below_min():
    """Even with a model blob, if ``n_corpus < 10`` the ML tier stays
    None — the persisted model from a prior fit shouldn't be used to
    score a CRM if we no longer have enough corpus to vouch for it.
    """
    entries = [
        _entry("ac-2", "customer", "Local PAM."),
        _entry("cm-6", "customer", "Local baseline."),
    ]
    report = score_crm_suspicion(
        workbook_id=1,
        crm_baseline_id=1,
        crm_context=_ctx(entries),
        in_scope_control_ids=[e.control_id for e in entries],
        tagged_evidence_by_family={},
        n_corpus=5,  # below MIN_CORPUS_SIZE = 10
        anomaly_model_blob=b"<fake-pickle>",
    )
    assert report.ml_anomaly_score is None


def test_score_crm_suspicion_calls_embeddings_provider_when_supplied():
    """A real ``TfidfFallbackProvider`` (pure-sklearn, no API) on a CRM
    with substantive narratives returns a non-None
    ``narrative_quality_score``. Bounds rather than exact value — TF-IDF
    quality scores depend on vocabulary overlap with the filler corpus.
    """
    from cybersecurity_assessor.engine.narrative_embeddings import (
        TfidfFallbackProvider,
    )

    entries = [
        _entry(
            "ac-2",
            "inherited",
            "Identity provider enforces ten-character random tokens issued via "
            "the OAuth refresh flow and rotated every twelve hours.",
        ),
        _entry(
            "ia-2",
            "inherited",
            "Multi-factor enforced through FIDO2 hardware tokens registered "
            "during onboarding and revoked through HR offboarding workflow.",
        ),
        _entry(
            "cm-6",
            "inherited",
            "Baseline images are signed with cosign and verified at boot via "
            "the secure-boot chain; deviations alert into the SIEM.",
        ),
    ]
    report = score_crm_suspicion(
        workbook_id=1,
        crm_baseline_id=1,
        crm_context=_ctx(entries),
        in_scope_control_ids=[e.control_id for e in entries],
        tagged_evidence_by_family={},
        embeddings_provider=TfidfFallbackProvider(),
    )
    assert report.narrative_quality_score is not None
    assert 0.0 <= report.narrative_quality_score <= 1.0


def test_score_crm_suspicion_records_flags_in_report():
    """End-to-end: a CRM that fires high_inheritance should have a
    matching flag in the report (sanity check that flags are wired up
    into the public report, not lost during construction).
    """
    entries = [
        _entry(f"ac-{i}", "inherited", f"Inherited {i}.") for i in range(1, 11)
    ]
    report = score_crm_suspicion(
        workbook_id=1,
        crm_baseline_id=1,
        crm_context=_ctx(entries),
        in_scope_control_ids=[e.control_id for e in entries],
        tagged_evidence_by_family={},
    )
    flag_names = {f.name for f in report.flags}
    assert "high_inheritance" in flag_names


# ---------------------------------------------------------------------------
# to_json_safe — shape contract for the route handler
# ---------------------------------------------------------------------------


def test_to_json_safe_returns_serializable_dict_with_expected_keys():
    """The endpoint hands this dict to FastAPI. Pins the key set so the
    frontend's typed client doesn't silently break when the dataclass
    evolves.
    """
    report = CrmSuspicionReport(
        workbook_id=7,
        crm_baseline_id=42,
        computed_at=__import__("datetime").datetime(2026, 6, 4, 12, 0, 0),
        heuristic_score=0.5,
        ml_anomaly_score=0.3,
        narrative_quality_score=0.7,
        overall_suspicion=0.45,
        flags=(
            CrmSuspicionFlag(name="x", severity="warn", summary="s", details={"k": 1}),
        ),
        per_family={"ac": {"n_entries": 3}},
        n_corpus=12,
    )
    body = report.to_json_safe()
    assert set(body.keys()) == {
        "workbook_id",
        "crm_baseline_id",
        "computed_at",
        "heuristic_score",
        "ml_anomaly_score",
        "narrative_quality_score",
        "overall_suspicion",
        "severity",
        "flags",
        "per_family",
        "n_corpus",
    }
    # ISO datetime, severity is bucketed, flags are dicts not dataclasses.
    assert body["computed_at"].startswith("2026-06-04")
    assert body["severity"] == "warn"
    assert isinstance(body["flags"], list)
    assert body["flags"][0] == {
        "name": "x",
        "severity": "warn",
        "summary": "s",
        "details": {"k": 1},
    }
