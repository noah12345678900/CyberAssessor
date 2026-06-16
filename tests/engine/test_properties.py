"""Property-based tests for the deterministic kernel modules.

Covers validator and rules — the kernel surface whose bugs silently
corrupt assessments. The example-based tests in ``test_assessor.py``
prove the documented happy paths; these tests use Hypothesis to fuzz the
input space and prove that the documented invariants hold across
arbitrary text, not just the canonical fixtures.

Invariants proven here:

* Validator: any narrative containing a known gap-describing phrase
  paired with COMPLIANT must reject. The gap phrase forces the
  narrative into GAP_DESCRIBING (or AMBIGUOUS when combined with an
  affirming phrase) — either way, status COMPLIANT can never validate.
* Rules: the rule-8a phrase ``automatically compliant`` is invariant
  under surrounding noise. Whatever the operator (or prior assessor)
  wrapped the phrase in, the row routes to rule_8a — provided no 8b
  trigger is also present (8b runs first and would short-circuit to NA).

Hypothesis is in the dev extras; the entire module imports it lazily
through ``pytest.importorskip`` so a user running ``pytest`` without the
dev install gets a clean skip rather than a collection error.
"""

from __future__ import annotations

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import assume, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from cybersecurity_assessor.engine.rules import (  # noqa: E402
    _R8A_TRIGGERS,
    _R8B_NA_SCOPE_PHRASES,
    AutoStatusVerdict,
    classify_row,
)
from cybersecurity_assessor.engine.validator import (  # noqa: E402
    _ONPREM_ONLY_PHRASES,
    _PROVIDER_ONLY_PHRASES,
    RejectionReason,
    validate,
    validate_dual_narratives,
)
from cybersecurity_assessor.excel.ccis_reader import CcisRow  # noqa: E402
from cybersecurity_assessor.models import ComplianceStatus  # noqa: E402


# ---------------------------------------------------------------------------
# Local row builder (avoids depending on the make_row pytest fixture, which
# Hypothesis can't inject through @given). One field is varied per test;
# everything else is a neutral default that does NOT contain any rule-8
# trigger phrases, so the test's invariant is the only thing in play.
# ---------------------------------------------------------------------------


_NEUTRAL_GUIDANCE = (
    "Automated mechanisms support the management of information system accounts."
)
_NEUTRAL_PROCEDURES = "Examine account management documentation; verify automation."


def _row(**overrides) -> CcisRow:
    defaults = dict(
        excel_row=42,
        required=True,
        control_id="AC-2(1)",
        ap_acronym="AC-2.1",
        cci_id="CCI-000015",
        implementation_status="Implemented",
        designation="Hybrid",
        narrative=None,
        definition="The organization employs automated mechanisms.",
        guidance=_NEUTRAL_GUIDANCE,
        procedures=_NEUTRAL_PROCEDURES,
        inherited="Local",
        remote_inheritance=None,
        status=None,
        date_tested=None,
        tester=None,
        results=None,
        previous_status=None,
        previous_date=None,
        previous_tester=None,
        previous_results=None,
    )
    defaults.update(overrides)
    return CcisRow(**defaults)


# ---------------------------------------------------------------------------
# Validator invariant
# ---------------------------------------------------------------------------


@given(noise=st.text(max_size=2000))
def test_validator_no_artifact_phrase_always_rejects_compliant(noise: str) -> None:
    """A narrative containing ``no artifact found`` paired with COMPLIANT
    must never validate.

    Embedding the phrase in arbitrary surrounding text covers two paths:
    * Pure gap → narrative classifies as GAP_DESCRIBING → expected
      NON_COMPLIANT → STATUS_NARRATIVE_MISMATCH rejection.
    * Gap + affirming language → classifies as AMBIGUOUS → expected
      status is None → STATUS_NARRATIVE_MISMATCH rejection.
    Either way ``result.ok`` is False.
    """
    narrative = f"{noise} no artifact found {noise}"
    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
    )
    assert not result.ok


# ---------------------------------------------------------------------------
# Rules invariant
# ---------------------------------------------------------------------------


@given(
    prefix=st.text(max_size=200),
    suffix=st.text(max_size=200),
)
def test_rule_8a_phrase_invariant(prefix: str, suffix: str) -> None:
    """``automatically compliant`` in procedures routes to rule_8a,
    regardless of surrounding text.

    v0.11.0: 8a explicit phrases in col K are checked FIRST (rules.py
    step 1) and short-circuit before any other recognizer, so nothing
    in the surrounding text can preempt the 8a verdict. The NA
    scope-exclusion lane only reads col Q/U, never procedures, so an
    NA phrase sneaking into the prefix/suffix is inert here.
    """
    procedures = f"{prefix} automatically compliant {suffix}"
    proc_lower = procedures.lower()
    # Skip cases where the prefix/suffix introduces a competing 8a
    # phrase that fires earlier in the trigger tuple than the one we
    # injected — the rule still routes to 8a, but the trigger_phrase
    # may differ. Easier to keep the assertion strict on the verdict
    # only; the trigger ordering is covered by example-based tests.
    row = _row(procedures=procedures, guidance=_NEUTRAL_GUIDANCE)
    result = classify_row(row)
    assert result.verdict is AutoStatusVerdict.COMPLIANT_8A
    assert result.rule == "8a"
    assert result.status is ComplianceStatus.COMPLIANT
    # Trigger must be one of the documented 8a phrases (sanity: we did
    # route via the 8a path, not e.g. structural col-L).
    assert result.trigger_phrase in _R8A_TRIGGERS


@given(
    r8a=st.sampled_from(_R8A_TRIGGERS),
    r8b=st.sampled_from(_R8B_NA_SCOPE_PHRASES),
)
def test_col_k_8a_explicit_precedes_qu_na_recognizer(r8a: str, r8b: str) -> None:
    """An 8a explicit phrase in col K beats an NA scope-exclusion in col Q.

    v0.11.0 order of checks (rules.py): step 1 (8a explicit phrases in
    col K/J) runs before step 3 (the col Q/U documented-rationale
    recognizer). So a row that is BOTH auto-compliant per its
    assessment procedures AND carries a scope-exclusion phrase in the
    human-authored results must resolve to COMPLIANT_8A — the col-K
    statement is authoritative. A refactor that reordered the recognizer
    ahead of the explicit-phrase pass would silently flip these to NA.
    """
    row = _row(procedures=f"This control is {r8a}.", results=f"{r8b}")
    result = classify_row(row)
    assert result.verdict is AutoStatusVerdict.COMPLIANT_8A
    assert result.rule == "8a"
    assert result.status is ComplianceStatus.COMPLIANT
    assert result.trigger_column == "K"


@given(
    prefix=st.text(max_size=200),
    suffix=st.text(max_size=200),
)
def test_rule_bare_inherited_from_routes_to_8c(prefix: str, suffix: str) -> None:
    """``inherited from`` with no qualifier (no DOW/DOD/enterprise/parent
    AND no CSP name) routes to UNCLEAR_8C, status None.

    This is the patent-relevant "ASK don't guess" path — the historical
    LLM failure was defaulting bare "inherited from" to Compliant. The
    deterministic kernel must surface this to the assessor instead.

    Filter cases where the prefix/suffix accidentally injects a
    qualifying word that would promote this to 8a, or a competing 8a
    explicit phrase. (NA scope phrases are inert in procedures under
    v0.11.0 — they only fire from col Q/U — so no 8b filter is needed.)
    """
    procedures = f"{prefix} inherited from {suffix}"
    proc_lower = procedures.lower()
    # Skip if prefix/suffix accidentally adds a qualifier that promotes
    # to 8a (e.g. " ... inherited from suffix mentioning the dod ...")
    # or an 8a explicit phrase.
    if any(t in proc_lower for t in _R8A_TRIGGERS):
        return
    # Any qualifier word right after "inherited from" — check the broader
    # inheritance-internal list rather than just the exact phrases.
    qualifiers = ("dow", "dod", "enterprise", "parent")
    if any(q in proc_lower for q in qualifiers):
        return
    row = _row(procedures=procedures, guidance=_NEUTRAL_GUIDANCE)
    result = classify_row(row)
    assert result.verdict is AutoStatusVerdict.UNCLEAR_8C
    assert result.rule == "8c"
    assert result.status is None


@given(
    procedures=st.text(max_size=500),
    guidance=st.text(max_size=500),
    inherited=st.text(max_size=100),
)
def test_rule_verdict_status_pairing_is_consistent(
    procedures: str, guidance: str, inherited: str
) -> None:
    """For ANY row, the (verdict, status, rule) tuple is one of four
    documented shapes — and classify_row never raises.

    This is the meta-invariant covering the entire auto-status surface:
    a refactor that returns the wrong status enum for a verdict (e.g.,
    COMPLIANT_8A paired with NOT_APPLICABLE) would silently corrupt
    every assessment downstream. The validator does not re-check the
    pairing — it trusts the rules engine to have produced a coherent
    (status, narrative) pair.
    """
    row = _row(procedures=procedures, guidance=guidance, inherited=inherited)
    result = classify_row(row)  # must not raise
    if result.verdict is AutoStatusVerdict.COMPLIANT_8A:
        assert result.status is ComplianceStatus.COMPLIANT
        assert result.rule == "8a"
        assert result.narrative is not None
    elif result.verdict is AutoStatusVerdict.NOT_APPLICABLE_8B:
        assert result.status is ComplianceStatus.NOT_APPLICABLE
        assert result.rule == "8b"
        assert result.narrative is not None
    elif result.verdict is AutoStatusVerdict.UNCLEAR_8C:
        assert result.status is None
        assert result.rule == "8c"
        assert result.narrative is None
    else:
        assert result.verdict is AutoStatusVerdict.NO_AUTO_RULE
        assert result.status is None
        assert result.rule is None
        assert result.narrative is None
        assert result.trigger_phrase is None
        assert result.trigger_column is None


# ---------------------------------------------------------------------------
# v0.2 validator hardening — future-tense, dual-narrative, cite verification
# ---------------------------------------------------------------------------
#
# These properties pin the v0.2 additions to the validator surface. The
# canonical examples are covered by tests/test_validator.py; here we fuzz
# the surrounding noise so a regression where (say) the future-tense regex
# loses its IGNORECASE flag, or the provider-phrase scan trips on a word
# boundary, shows up as a falsified property instead of slipping through
# the hand-picked examples.


# Curated subset of phrases that match the _FUTURE_TENSE_RE alternation
# in validator.py. Sampling from a fixed list keeps the property robust
# even if the regex grows new alternates -- adding a new one shouldn't
# require updating this list, and the existing samples still prove the
# invariant for the patterns they exercise.
_FUTURE_TENSE_SAMPLES = (
    "will be configured",
    "will be implemented",
    "will be deployed",
    "to be implemented",
    "to be determined",
    "planned to deploy",
    "scheduled to enable",
    "in the process of deploying",
    "once deployed",
    "upcoming deployment",
    "upcoming rollout",
)


# deadline=None: this is typically the first hypothesis-heavy test to run in
# the module, so it absorbs cold-start regex/import warmup (~5s on this
# workstation) and trips the default 200ms deadline as a timing flake. Matches
# the deadline=None convention used across the rest of the property suite.
@settings(deadline=None)
@given(
    phrase=st.sampled_from(_FUTURE_TENSE_SAMPLES),
    prefix=st.text(max_size=200),
    suffix=st.text(max_size=200),
)
def test_validator_future_tense_compliant_always_rejects(
    phrase: str, prefix: str, suffix: str
) -> None:
    """A narrative containing any future-tense phrase paired with COMPLIANT
    must reject with FUTURE_TENSE_COMPLIANCE.

    Precision-over-recall: documented intent isn't compliance. The
    regex fires independently of narrative classification, so even when
    the surrounding noise pushes the narrative into AMBIGUOUS or
    GAP_DESCRIBING (which would also reject for STATUS_NARRATIVE_MISMATCH)
    the future-tense rejection still appears in the list.
    """
    narrative = f"{prefix} {phrase} {suffix}"
    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
    )
    assert not result.ok
    reasons = [r for r, _ in result.rejections]
    assert RejectionReason.FUTURE_TENSE_COMPLIANCE in reasons


# ---------------------------------------------------------------------------
# Dual-narrative leak detection invariants
# ---------------------------------------------------------------------------


@given(
    phrase=st.sampled_from(_PROVIDER_ONLY_PHRASES),
    prefix=st.text(max_size=200),
    suffix=st.text(max_size=200),
    cloud=st.text(max_size=500),
    crm=st.sampled_from(
        [None, "hybrid", "customer", "provider", "inherited", "not_applicable"]
    ),
)
def test_validator_dual_provider_phrase_in_onprem_always_flags(
    phrase: str,
    prefix: str,
    suffix: str,
    cloud: str,
    crm: str | None,
) -> None:
    """Any _PROVIDER_ONLY_PHRASES entry in the on-prem half always flags
    DUAL_NARRATIVE_MISLABEL, regardless of CRM responsibility or the
    contents of the cloud half.

    Leak detection runs unconditionally on populated halves -- the CRM
    cross-check is layered on top and may add ADDITIONAL flags for the
    same reason class (e.g. CRM=customer + populated cloud), but the
    leak flag from the provider-phrase scan must always fire at least
    once. This property guards the regression where a refactor narrows
    the leak scan to a specific CRM value and silently drops it for the
    others.
    """
    on_prem = f"{prefix} {phrase} {suffix}"
    result = validate_dual_narratives(
        narrative_on_prem=on_prem,
        narrative_cloud=cloud,
        crm_responsibility=crm,
    )
    assert RejectionReason.DUAL_NARRATIVE_MISLABEL in result.flagged


@given(
    phrase=st.sampled_from(_ONPREM_ONLY_PHRASES),
    prefix=st.text(max_size=200),
    suffix=st.text(max_size=200),
    on_prem=st.text(max_size=500),
    crm=st.sampled_from(
        [None, "hybrid", "customer", "provider", "inherited", "not_applicable"]
    ),
)
def test_validator_dual_onprem_phrase_in_cloud_always_flags(
    phrase: str,
    prefix: str,
    suffix: str,
    on_prem: str,
    crm: str | None,
) -> None:
    """Symmetric counterpart: any _ONPREM_ONLY_PHRASES entry in the cloud
    half always flags DUAL_NARRATIVE_MISLABEL.

    Cloud-half scan is narrower than the provider scan (the cloud half
    legitimately references local integrations), but the phrases in
    _ONPREM_ONLY_PHRASES are strong enough tells that they must always
    trip the flag. Same robustness story as the provider direction.
    """
    cloud = f"{prefix} {phrase} {suffix}"
    result = validate_dual_narratives(
        narrative_on_prem=on_prem,
        narrative_cloud=cloud,
        crm_responsibility=crm,
    )
    assert RejectionReason.DUAL_NARRATIVE_MISLABEL in result.flagged


# Curated leak-free phrase samples. Random st.text() could accidentally
# generate a phrase that brushes one of the leak patterns; sampling from
# a fixed pool that's been hand-verified disjoint from both
# _PROVIDER_ONLY_PHRASES and _ONPREM_ONLY_PHRASES keeps the clean-case
# property honest.
_CLEAN_ONPREM_SAMPLES = (
    "Configured per local SCAP baseline; verified via STIG scan.",
    "Local hardening applied; sampled three hosts and confirmed settings.",
    "Reviewed account management documentation and observed automation.",
    "Verified MFA enforcement on privileged accounts per SSP section 4.",
)
_CLEAN_CLOUD_SAMPLES = (
    "Inherited from AWS GovCloud per FedRAMP authorization.",
    "Cloud control responsibilities inherited from the provider.",
    "Service Provider boundary handles this; documented in the CRM.",
    "Inherited from the FedRAMP-authorized cloud service.",
)


@given(
    on_prem=st.sampled_from(_CLEAN_ONPREM_SAMPLES),
    cloud=st.sampled_from(_CLEAN_CLOUD_SAMPLES),
    crm=st.sampled_from([None, "hybrid", "not_applicable"]),
)
def test_validator_dual_clean_case_never_flags(
    on_prem: str, cloud: str, crm: str | None,
) -> None:
    """Clean halves + a permissive CRM value never flag.

    Defines the negative space for ``validate_dual_narratives``: with
    on-prem clean of _PROVIDER_ONLY_PHRASES, cloud clean of
    _ONPREM_ONLY_PHRASES, and CRM in {hybrid (with both halves populated),
    not_applicable, None}, ``result.flagged`` is empty. A regression that
    starts flagging legitimate dual-narrative shapes would silently push
    every assessor to second-guess clean rows — the inverse failure mode
    of the leak-detection properties above.
    """
    result = validate_dual_narratives(
        narrative_on_prem=on_prem,
        narrative_cloud=cloud,
        crm_responsibility=crm,
    )
    assert result.flagged == [], (
        f"clean dual narrative flagged unexpectedly: on_prem={on_prem!r}, "
        f"cloud={cloud!r}, crm={crm!r}, flagged={result.flagged}, notes={result.notes}"
    )


# ---------------------------------------------------------------------------
# Cite verification invariant
# ---------------------------------------------------------------------------


@given(
    digits=st.text(alphabet="0123456789", min_size=8, max_size=14),
    evidence_noise=st.text(min_size=1, max_size=500),
)
def test_validator_unsupported_usd_cite_always_rejects(
    digits: str, evidence_noise: str
) -> None:
    """A USD<8+ digits> token in the narrative, paired with non-empty
    evidence_text that does NOT contain that token, always rejects with
    UNSUPPORTED_DOC_CITATION.

    This is the literal-cite-verification gate (mechanism #2 of the
    precision-over-recall stack): every USD doc number named in the
    narrative must appear in the tagged evidence. The property guards
    against regex regressions (boundary errors, IGNORECASE drift, the
    pattern accidentally allowing 7-digit matches) and against the
    cite-verification path being short-circuited when it shouldn't be.

    Constraints:
    * evidence_noise must be non-empty after stripping -- the gate
      skips when no evidence is supplied (deterministic rule-8 paths).
    * evidence must not coincidentally contain our generated token.
    """
    token = f"USD{digits}"
    assume(evidence_noise.strip())
    assume(token.lower() not in evidence_noise.lower())
    # Affirming-classified narrative so STATUS_NARRATIVE_MISMATCH is
    # NOT what's doing the rejecting -- the cite gate is.
    narrative = (
        f"Verified via {token} that the system is configured per the plan."
    )
    result = validate(
        proposed_status=ComplianceStatus.COMPLIANT,
        proposed_narrative=narrative,
        evidence_text=evidence_noise,
    )
    reasons = [r for r, _ in result.rejections]
    assert RejectionReason.UNSUPPORTED_DOC_CITATION in reasons
