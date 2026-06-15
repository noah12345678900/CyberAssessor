"""Tests for the four CRM-suspicion heuristics in ``crm_sanity.py``.

These tests pin the *individual flag firing behavior* of the four
Tier-1 heuristics. The blend/redistribution math is exercised
separately by ``test_crm_sanity_hybrid_blend.py``; the feature
extraction is exercised by ``test_crm_ml_features.py``. Here we only
care about: "given a hand-crafted CrmContext, does the right flag
fire (or not), with the right severity?"

The heuristics, recap:

1. ``high_inheritance`` — > 70% in-scope claimed inherited/provider/NA
   → warn; >= 90% → alert.
2. ``local_evidence_contradiction`` — CRM says family X fully
   off-loaded, but workbook has ``EvidenceTag`` rows on X → alert.
3. ``narrative_poverty`` — > 30% of inherited/provider/hybrid claims
   have null/empty narrative → warn.
4. ``boilerplate_narrative`` — TF-IDF max intra-CRM cosine > 0.85 AND
   mean similarity >= ``0.85 * 0.50`` (= 0.425) → warn. Catches the
   "vendor copy-pasted one paragraph across N controls" pattern.

Each test crafts a CrmContext that fires ONLY the heuristic under
test — we assert ``{f.name for f in report.flags}`` equality so that
unrelated heuristics firing would surface as a test failure rather
than be silently absorbed.

We also pin one "clean" baseline (a hand-crafted, varied,
locally-evidenced CRM) that fires zero flags. That's the negative
control — if any of the four heuristics ever changes behavior in a
way that fires on a substantive CRM, the negative-control test
catches it before the positive tests can hide the regression.

Session-free: ``score_crm_suspicion`` takes a ``CrmContext`` directly,
so these tests don't need the in-memory SQLite scaffolding the
sweep-online and recalibration tests use.

sklearn is required for the boilerplate heuristic's TF-IDF cosine,
which is computed inside ``extract_features`` regardless of which
heuristic we're testing. Module-level ``importorskip``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

pytest.importorskip("sklearn", reason="boilerplate heuristic needs TF-IDF vectorizer")

from cybersecurity_assessor.engine.crm_context import (  # noqa: E402
    CrmContext,
    CrmEntry,
)
from cybersecurity_assessor.engine.crm_sanity import (  # noqa: E402
    HIGH_INHERITANCE_ALERT,
    HIGH_INHERITANCE_WARN,
    NARRATIVE_POVERTY_THRESHOLD,
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
    """Build a CrmEntry with a sane default narrative.

    Default narrative is long enough to clear the narrative-poverty
    "empty" check. Tests that need an empty narrative pass
    ``narrative=None`` or ``narrative=""``. Tests that need
    boilerplate pass the same string across many entries.
    """
    return CrmEntry(
        control_id=control_id,
        responsibility=responsibility,
        narrative=narrative,
        source_baseline_id=1,
    )


def _ctx(entries: list[CrmEntry]) -> CrmContext:
    return CrmContext(by_control={e.control_id: e for e in entries})


def _score(
    entries: list[CrmEntry],
    *,
    in_scope: list[str] | None = None,
    tagged_evidence_by_family: dict[str, int] | None = None,
):
    """Run ``score_crm_suspicion`` with sane test defaults.

    Heuristics-only mode: no ML anomaly model, no embeddings provider,
    n_corpus=0. The blend collapses to the heuristic score alone, but
    the heuristics-fire assertions don't depend on that.
    """
    scope = in_scope if in_scope is not None else [e.control_id for e in entries]
    tagged = tagged_evidence_by_family if tagged_evidence_by_family is not None else {}
    return score_crm_suspicion(
        workbook_id=1,
        crm_baseline_id=42,
        crm_context=_ctx(entries),
        in_scope_control_ids=scope,
        tagged_evidence_by_family=tagged,
    )


def _flag_names(report) -> set[str]:
    return {f.name for f in report.flags}


def _flag(report, name: str):
    """Pluck one flag by name; assertion failure if missing."""
    for f in report.flags:
        if f.name == name:
            return f
    raise AssertionError(
        f"expected flag {name!r} not found; got {[f.name for f in report.flags]}"
    )


# ---------------------------------------------------------------------------
# Negative control — a clean CRM
# ---------------------------------------------------------------------------


def test_clean_substantive_crm_fires_no_flags():
    """Hand-crafted "good" CRM: mixed responsibility, varied narratives,
    no contradicting evidence → zero flags, ``info`` severity.

    Acts as the regression sentinel: if any heuristic later starts
    firing on a well-formed CRM, this fails before the positive tests
    can mask the change.
    """
    entries = [
        _entry("ac-2", "customer", "Customer manages local privileged accounts via PAM."),
        _entry("ac-3", "customer", "RBAC enforced through the workforce identity provider."),
        _entry(
            "ia-2",
            "inherited",
            "Identity provider handles MFA per the inheritance "
            "boundary documented in the SSP appendix B.",
        ),
        _entry(
            "ia-5",
            "hybrid",
            "Password policy is enforced by the IdP for SSO accounts; "
            "local break-glass accounts use a separate vault rotation policy.",
        ),
        _entry(
            "cm-6",
            "provider",
            "Baseline configurations are managed by the cloud provider's "
            "managed-service control plane; customer cannot deviate.",
        ),
        _entry("cm-7", "customer", "Least functionality enforced via host hardening playbook."),
    ]
    report = _score(entries)
    assert _flag_names(report) == set()
    assert report.severity == "info"


# ---------------------------------------------------------------------------
# Heuristic 1 — high_inheritance
# ---------------------------------------------------------------------------


def test_high_inheritance_warns_between_70_and_90_pct():
    """8 of 10 in-scope (80%) inherited/provider/NA → warn, not alert.

    Narratives are deliberately varied + present so the
    narrative-poverty and boilerplate heuristics don't ride along.
    """
    entries = [
        _entry(f"ac-{i}", "inherited", f"Inherited per IdP boundary doc {i}.")
        for i in range(1, 6)
    ] + [
        _entry(f"cm-{i}", "provider", f"Provider-managed configuration baseline {i}.")
        for i in range(1, 4)
    ] + [
        _entry("ac-99", "customer", "Locally managed account audit."),
        _entry("cm-99", "customer", "Locally managed configuration deviation log."),
    ]
    assert len(entries) == 10  # 8 off-loaded + 2 customer = 80%
    report = _score(entries)
    flag = _flag(report, "high_inheritance")
    assert flag.severity == "warn"
    assert HIGH_INHERITANCE_WARN <= flag.details["off_loaded_pct"] < HIGH_INHERITANCE_ALERT


def test_high_inheritance_alerts_at_or_above_90_pct():
    """9 of 10 in-scope (90%) inherited → alert."""
    entries = [
        _entry(f"ac-{i}", "inherited", f"Inherited boundary detail {i}.")
        for i in range(1, 10)
    ] + [_entry("ac-99", "customer", "Local audit trail managed in our SIEM.")]
    assert len(entries) == 10  # 90% off-loaded
    report = _score(entries)
    flag = _flag(report, "high_inheritance")
    assert flag.severity == "alert"
    assert flag.details["off_loaded_pct"] >= HIGH_INHERITANCE_ALERT


def test_high_inheritance_does_not_fire_below_warn_threshold():
    """6 of 10 (60%) inherited → no flag. Score component may still be
    nonzero (linear ramp from 50%) but ``high_inheritance`` does not
    appear in ``report.flags``.
    """
    entries = [
        _entry(f"ac-{i}", "inherited", f"Detail {i}.") for i in range(1, 7)
    ] + [
        _entry(f"cm-{i}", "customer", f"Locally managed item {i}.") for i in range(1, 5)
    ]
    assert len(entries) == 10  # 60% off-loaded
    report = _score(entries)
    assert "high_inheritance" not in _flag_names(report)


# ---------------------------------------------------------------------------
# Heuristic 2 — local_evidence_contradiction
# ---------------------------------------------------------------------------


def test_local_evidence_contradiction_fires_when_inherited_family_has_local_evidence():
    """CRM claims AC fully inherited, but workbook has EvidenceTag rows
    on AC → alert. Highest-priority signal — we LITERALLY have evidence
    the vendor said wouldn't exist locally.
    """
    entries = [
        # AC family — fully off-loaded.
        _entry("ac-2", "inherited", "IdP handles privileged account lifecycle."),
        _entry("ac-3", "inherited", "RBAC inherited from IdP role mappings."),
        # IA family — also off-loaded; tagged evidence count is 0 so it
        # should NOT contradict. Keeps the test scoped to AC.
        _entry("ia-5", "provider", "MFA managed by the IdP."),
        # Mix in customer-owned families so high_inheritance doesn't
        # tag along and pollute the assertion.
        _entry("cm-6", "customer", "Baseline managed locally."),
        _entry("cm-7", "customer", "Functionality controls managed locally."),
        _entry("au-2", "customer", "Audit events curated locally."),
        _entry("au-3", "customer", "Audit record content defined locally."),
    ]
    report = _score(
        entries,
        # Workbook DOES have tagged evidence on AC — the contradiction.
        tagged_evidence_by_family={"ac": 7},
    )
    flag = _flag(report, "local_evidence_contradiction")
    assert flag.severity == "alert"
    assert flag.details["families"] == ["ac"]


def test_local_evidence_contradiction_does_not_fire_when_family_is_mixed():
    """If AC has *some* customer rows, the family is not "fully
    off-loaded" — no contradiction even if AC has local evidence.

    Pins the "fully claimed off-loaded" precondition: a mixed-
    responsibility family is not the vendor over-claiming.
    """
    entries = [
        _entry("ac-2", "inherited", "Inherited part of AC."),
        # One customer-owned AC entry breaks the "fully off-loaded" status.
        _entry("ac-3", "customer", "Customer-managed RBAC."),
        # Padding so high_inheritance doesn't fire.
        _entry("cm-6", "customer", "Local baseline."),
        _entry("cm-7", "customer", "Local functionality."),
        _entry("au-2", "customer", "Local audit."),
    ]
    report = _score(entries, tagged_evidence_by_family={"ac": 5})
    assert "local_evidence_contradiction" not in _flag_names(report)


def test_local_evidence_contradiction_does_not_fire_without_tagged_evidence():
    """Family fully off-loaded but workbook has zero tagged evidence on
    it → no contradiction. The signal needs BOTH halves: vendor claim
    AND observed local evidence.
    """
    entries = [
        _entry("ac-2", "inherited", "IdP."),
        _entry("ac-3", "inherited", "IdP RBAC."),
        # Padding.
        _entry("cm-6", "customer", "Local baseline."),
        _entry("cm-7", "customer", "Local functionality."),
        _entry("au-2", "customer", "Local audit."),
    ]
    report = _score(entries, tagged_evidence_by_family={"ia": 4})  # wrong family
    assert "local_evidence_contradiction" not in _flag_names(report)


# ---------------------------------------------------------------------------
# Heuristic 3 — narrative_poverty
# ---------------------------------------------------------------------------


def test_narrative_poverty_fires_when_more_than_30_pct_have_empty_narrative():
    """Of 10 inherited/provider rows, 5 have empty narrative (50%) →
    warn. Above the 30% threshold by a comfortable margin.

    Distinct from high_inheritance: the CRM here is 100% off-loaded
    (10/10) so high_inheritance ALSO fires at alert — we assert
    narrative_poverty is in the set, not that it's the only flag.
    """
    entries = [
        _entry(f"ac-{i}", "inherited", "Substantive justification for ac-{i}.")
        for i in range(1, 6)
    ] + [
        _entry(f"cm-{i}", "provider", narrative=None)  # half have NO narrative
        for i in range(1, 6)
    ]
    report = _score(entries)
    flag = _flag(report, "narrative_poverty")
    assert flag.severity == "warn"
    assert flag.details["empty_pct"] >= NARRATIVE_POVERTY_THRESHOLD
    assert flag.details["n_empty"] == 5
    assert flag.details["n_claims"] == 10


def test_narrative_poverty_does_not_fire_when_all_narratives_present():
    """All 10 inherited rows have non-empty narrative → no
    narrative_poverty flag, even though all rows are off-loaded.

    high_inheritance WILL fire (10/10 = 100% inherited, alert level) —
    that's expected and we assert the poverty flag specifically is
    absent.
    """
    entries = [
        _entry(f"ac-{i}", "inherited", f"Real explanation for ac-{i} #{i*7}.")
        for i in range(1, 11)
    ]
    report = _score(entries)
    assert "narrative_poverty" not in _flag_names(report)


def test_narrative_poverty_ignores_customer_entries_with_empty_narrative():
    """Customer-owned controls legitimately have empty narrative in
    most CRMs (the assessor writes the narrative). They must not count
    toward the poverty ratio.

    Setup: 5 customer rows with empty narrative + 4 inherited rows
    with full narratives. Poverty fraction = 0/4 over claims = 0% →
    no flag.
    """
    entries = [
        _entry(f"ac-{i}", "customer", narrative=None) for i in range(1, 6)
    ] + [
        _entry(f"ia-{i}", "inherited", f"Justified inheritance ia-{i}.")
        for i in range(1, 5)
    ]
    report = _score(entries)
    assert "narrative_poverty" not in _flag_names(report)


# ---------------------------------------------------------------------------
# Heuristic 4 — boilerplate_narrative
# ---------------------------------------------------------------------------


def test_boilerplate_narrative_fires_when_same_paragraph_repeated_everywhere():
    """All 8 inherited rows have the IDENTICAL narrative → TF-IDF
    self-similarity off-diagonal mean is 1.0, max is 1.0 → warn.

    high_inheritance ALSO fires (8/8 = 100% off-loaded, alert) — we
    assert boilerplate_narrative is present, not exclusivity.
    """
    boilerplate = (
        "The customer inherits this control from the cloud service provider. "
        "See the System Security Plan for additional inheritance details."
    )
    entries = [
        _entry(f"ac-{i}", "inherited", boilerplate) for i in range(1, 9)
    ]
    report = _score(entries)
    flag = _flag(report, "boilerplate_narrative")
    assert flag.severity == "warn"
    # The narrative-similarity stats live in details for the UI panel.
    assert flag.details["max_similarity"] > 0.85
    assert flag.details["mean_similarity"] > 0.85


def test_boilerplate_narrative_does_not_fire_on_one_duplicated_pair():
    """One pair of identical narratives amid otherwise-distinct ones →
    high MAX similarity but low MEAN → no flag.

    The mean-fraction guard is what prevents a single accidental
    duplicate from screaming "boilerplate." We rely on the
    documented mean threshold ≈ 0.425 (0.85 * 0.50). Six unique
    paragraphs with one duplicated pair lands mean well below that.
    """
    distinct = [
        "Customer manages local audit log forwarding via the syslog agent.",
        "Configuration baselines are tracked through Ansible playbooks.",
        "Identity federation is via the corporate SAML IdP, MFA required.",
        "Vulnerability scans run weekly via Tenable agents on every host.",
        "Backups are taken nightly and tested via quarterly restore drills.",
        "Incident response is coordinated through the SOC ticketing queue.",
    ]
    duplicate = "Customer manages local audit log forwarding via the syslog agent."
    entries = [
        _entry(f"ac-{i}", "inherited", text)
        for i, text in enumerate(distinct, start=1)
    ] + [
        # One extra entry that duplicates the first — creates one similar
        # pair but doesn't dominate the mean.
        _entry("ac-99", "inherited", duplicate),
    ]
    report = _score(entries)
    assert "boilerplate_narrative" not in _flag_names(report)


def test_boilerplate_narrative_does_not_fire_when_narratives_are_distinct():
    """All distinct, substantive narratives → TF-IDF self-similarity
    is low → no boilerplate flag.

    Companion to the negative-control test, narrowed to the
    boilerplate heuristic.
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
    report = _score(entries)
    assert "boilerplate_narrative" not in _flag_names(report)
