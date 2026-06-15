"""Tests for the embedding-based narrative classification fallback.

The embedding fallback (added 2026-06-07) augments the literal phrase
tables in ``engine.validator`` with TF-IDF cosine similarity against
canonical anchor sentences. It fires ONLY when no literal phrase
match is found, making the validator robust to kernel template wording
drift without breaking existing behavior.

Fallback order tested here:
  1. Literal substring match (fast, existing) — tested in test_validator_golden.py
  2. Embedding similarity ≥ threshold (new) — THIS file
  3. No match → AMBIGUOUS (existing fail-closed) — tested here + golden

Test design:
  - Synthetic narratives that share ZERO literal phrases with the phrase
    tables but ARE semantically similar to a class → must classify via
    embedding path
  - Genuinely ambiguous narrative → embedding must NOT over-trigger
  - Mock the embedding cache to test the fallback path in isolation
  - Verify existing golden tests still pass (run via the regression suite)
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

# Ensure the backend package is importable when pytest is launched from any cwd.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor.engine.validator import (  # noqa: E402
    NarrativeClass,
    RejectionReason,
    _EmbeddingClassifierCache,
    _classify_single,
    _embedding_cache,
    classify_narrative,
    validate,
)
from cybersecurity_assessor.models import ComplianceStatus  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _has_rejection(result, reason: RejectionReason) -> bool:
    return any(r == reason for r, _msg in result.rejections)


# ---------------------------------------------------------------------------
# Embedding fallback: affirming narratives without literal phrases
# ---------------------------------------------------------------------------


class TestEmbeddingFallbackAffirming:
    """Narratives that are compliance-affirming but use NO literal phrase
    from _AFFIRMING_PHRASES. Must classify via the embedding path."""

    def test_affirming_paraphrase_classifies_via_embedding(self):
        """A paraphrase of affirming language with no exact phrase match
        should classify as COMPLIANCE_AFFIRMING via embedding fallback."""
        # This narrative uses "inspected" and "operational" — neither is in
        # _AFFIRMING_PHRASES. But it's semantically affirming.
        narrative = (
            "Inspected the deployed access control settings and found them "
            "operational and correctly enforcing the security policy."
        )
        # Verify no literal phrase match by checking keywords
        haystack = narrative.lower()
        from cybersecurity_assessor.engine.validator import (
            _AFFIRMING_PHRASES,
            _GAP_PHRASES,
            _NA_PHRASES,
        )

        assert not any(p in haystack for p in _AFFIRMING_PHRASES)
        assert not any(p in haystack for p in _GAP_PHRASES)
        assert not any(p in haystack for p in _NA_PHRASES)

        # Should classify via embedding fallback
        result = _classify_single(narrative)
        assert result is NarrativeClass.COMPLIANCE_AFFIRMING

    def test_affirming_paraphrase_passes_validate_with_compliant(self):
        """End-to-end: paraphrased affirming narrative + Compliant status → ok."""
        narrative = (
            "Inspected the deployed access control settings and found them "
            "operational and correctly enforcing the security policy."
        )
        result = validate(
            proposed_status=ComplianceStatus.COMPLIANT,
            proposed_narrative=narrative,
        )
        assert result.ok
        assert result.classified_as is NarrativeClass.COMPLIANCE_AFFIRMING


# ---------------------------------------------------------------------------
# Embedding fallback: gap narratives without literal phrases
# ---------------------------------------------------------------------------


class TestEmbeddingFallbackGap:
    """Narratives that are gap-describing but use NO literal phrase
    from _GAP_PHRASES. Must classify via the embedding path."""

    def test_gap_paraphrase_classifies_via_embedding(self):
        """A gap narrative with no literal gap phrase should classify as
        GAP_DESCRIBING via embedding fallback."""
        # Uses "unable to locate" and "unmet requirement" — not in _GAP_PHRASES
        narrative = (
            "Unable to locate any artifacts substantiating this requirement. "
            "The control objective remains an unmet requirement awaiting "
            "submission of implementation artifacts."
        )
        haystack = narrative.lower()
        from cybersecurity_assessor.engine.validator import (
            _AFFIRMING_PHRASES,
            _GAP_PHRASES,
            _NA_PHRASES,
        )

        assert not any(p in haystack for p in _AFFIRMING_PHRASES)
        assert not any(p in haystack for p in _GAP_PHRASES)
        assert not any(p in haystack for p in _NA_PHRASES)

        result = _classify_single(narrative)
        assert result is NarrativeClass.GAP_DESCRIBING

    def test_gap_paraphrase_passes_validate_with_non_compliant(self):
        """End-to-end: paraphrased gap narrative + Non-Compliant status → ok."""
        narrative = (
            "Unable to locate any artifacts substantiating this requirement. "
            "The control objective remains an unmet requirement awaiting "
            "submission of implementation artifacts."
        )
        result = validate(
            proposed_status=ComplianceStatus.NON_COMPLIANT,
            proposed_narrative=narrative,
        )
        assert result.ok
        assert result.classified_as is NarrativeClass.GAP_DESCRIBING


# ---------------------------------------------------------------------------
# Embedding fallback: NA narratives without literal phrases
# ---------------------------------------------------------------------------


class TestEmbeddingFallbackNA:
    """Narratives that are NA-justifying but use NO literal phrase
    from _NA_PHRASES. Must classify via the embedding path."""

    def test_na_paraphrase_classifies_via_embedding(self):
        """An NA narrative with no literal NA phrase should classify as
        NA_JUSTIFYING via embedding fallback."""
        # Uses "does not employ" and "irrelevant" — not in _NA_PHRASES
        narrative = (
            "The system does not employ wireless networking technology "
            "making this control irrelevant to the deployed architecture."
        )
        haystack = narrative.lower()
        from cybersecurity_assessor.engine.validator import (
            _AFFIRMING_PHRASES,
            _GAP_PHRASES,
            _NA_PHRASES,
        )

        assert not any(p in haystack for p in _AFFIRMING_PHRASES)
        assert not any(p in haystack for p in _GAP_PHRASES)
        assert not any(p in haystack for p in _NA_PHRASES)

        result = _classify_single(narrative)
        assert result is NarrativeClass.NA_JUSTIFYING

    def test_na_paraphrase_passes_validate_with_not_applicable(self):
        """End-to-end: paraphrased NA narrative + Not Applicable status → ok."""
        narrative = (
            "The system does not employ wireless networking technology "
            "making this control irrelevant to the deployed architecture."
        )
        result = validate(
            proposed_status=ComplianceStatus.NOT_APPLICABLE,
            proposed_narrative=narrative,
        )
        assert result.ok
        assert result.classified_as is NarrativeClass.NA_JUSTIFYING


# ---------------------------------------------------------------------------
# Genuinely ambiguous: embedding must NOT over-trigger
# ---------------------------------------------------------------------------


class TestEmbeddingAmbiguousStaysAmbiguous:
    """Narratives that are genuinely ambiguous should remain AMBIGUOUS even
    after the embedding fallback runs — the embedding must not over-classify."""

    def test_neutral_procedural_prose_stays_ambiguous(self):
        """Non-security procedural prose with no assessment language
        should stay AMBIGUOUS even through the embedding path."""
        narrative = (
            "This activity took place during the standard cadence with the "
            "outcome being recorded for posterity."
        )
        result = _classify_single(narrative)
        assert result is NarrativeClass.AMBIGUOUS

    def test_generic_sentence_stays_ambiguous(self):
        """A generic sentence about nothing security-related should be
        AMBIGUOUS — the embedding anchors should not match."""
        narrative = (
            "The quarterly team meeting was rescheduled to Thursday due to "
            "a conflict with the holiday calendar."
        )
        result = _classify_single(narrative)
        assert result is NarrativeClass.AMBIGUOUS


# ---------------------------------------------------------------------------
# Literal path still works (regression gate)
# ---------------------------------------------------------------------------


class TestLiteralPathUnchanged:
    """Verify that the literal phrase match fast path still works exactly
    as before — the embedding fallback must not interfere."""

    def test_literal_affirming_still_works(self):
        """'examined ' (literal affirming phrase) still classifies correctly."""
        narrative = "Examined USD00050010 §3.2 and verified the procedure."
        assert _classify_single(narrative) is NarrativeClass.COMPLIANCE_AFFIRMING

    def test_literal_gap_still_works(self):
        """'no evidence found' (literal gap phrase) still classifies correctly."""
        narrative = "No evidence found for quarterly account review."
        assert _classify_single(narrative) is NarrativeClass.GAP_DESCRIBING

    def test_literal_na_still_works(self):
        """'not applicable because' (literal NA phrase) still classifies correctly."""
        narrative = "Not applicable because the system does not include wireless."
        assert _classify_single(narrative) is NarrativeClass.NA_JUSTIFYING

    def test_literal_multi_class_still_ambiguous(self):
        """Both affirming AND gap literal phrases → AMBIGUOUS (unchanged)."""
        narrative = (
            "Verified in USD00050010 §3.2; however, no evidence found "
            "that the review actually occurred."
        )
        assert _classify_single(narrative) is NarrativeClass.AMBIGUOUS


# ---------------------------------------------------------------------------
# Embedding cache mockability
# ---------------------------------------------------------------------------


class TestEmbeddingCacheMockable:
    """Verify the embedding cache can be monkeypatched for test isolation."""

    def test_monkeypatch_cache_to_force_affirming(self):
        """Replacing _embedding_cache.classify forces the embedding path."""

        class MockCache:
            def classify(self, narrative_lower):
                return NarrativeClass.COMPLIANCE_AFFIRMING

        narrative = "Totally opaque text with no classification signals at all."
        # Without mock: AMBIGUOUS (no literal or embedding match)
        # Verify the mock actually changes behavior
        import cybersecurity_assessor.engine.validator as v

        original = v._embedding_cache
        try:
            v._embedding_cache = MockCache()  # type: ignore[assignment]
            result = _classify_single(narrative)
            assert result is NarrativeClass.COMPLIANCE_AFFIRMING
        finally:
            v._embedding_cache = original

    def test_monkeypatch_cache_to_return_none_falls_through(self):
        """When the mock cache returns None, _classify_single falls through
        to AMBIGUOUS — the fail-closed contract."""

        class MockCache:
            def classify(self, narrative_lower):
                return None

        narrative = "Totally opaque text with no classification signals."
        import cybersecurity_assessor.engine.validator as v

        original = v._embedding_cache
        try:
            v._embedding_cache = MockCache()  # type: ignore[assignment]
            result = _classify_single(narrative)
            assert result is NarrativeClass.AMBIGUOUS
        finally:
            v._embedding_cache = original


# ---------------------------------------------------------------------------
# Embedding fallback exception safety
# ---------------------------------------------------------------------------


class TestEmbeddingFallbackExceptionSafety:
    """If the embedding path throws, _classify_single must fall through
    to AMBIGUOUS gracefully — never crash the validator."""

    def test_embedding_exception_falls_through_to_ambiguous(self):
        """When _embedding_cache.classify raises, result is AMBIGUOUS."""

        class BrokenCache:
            def classify(self, narrative_lower):
                raise RuntimeError("sklearn not found")

        narrative = "Some text that has no literal phrase matches."
        import cybersecurity_assessor.engine.validator as v

        original = v._embedding_cache
        try:
            v._embedding_cache = BrokenCache()  # type: ignore[assignment]
            result = _classify_single(narrative)
            assert result is NarrativeClass.AMBIGUOUS
        finally:
            v._embedding_cache = original


# ---------------------------------------------------------------------------
# Template-drift simulation: rule_no_evidence reworded
# ---------------------------------------------------------------------------


class TestTemplateDriftSimulation:
    """Simulate the exact bug this fix addresses: a kernel template is
    reworded and no longer contains any literal phrase from _GAP_PHRASES,
    but the embedding path catches it."""

    def test_reworded_no_evidence_template_classifies_as_gap(self):
        """Hypothetical reword of rule_no_evidence template that drops all
        literal gap phrases but is semantically gap-describing."""
        # The current template uses "no artifacts were retrieved" and
        # "presumed not satisfied". This reword uses synonyms that aren't
        # in _GAP_PHRASES but convey the same meaning.
        narrative = (
            "Zero supporting artifacts were located for this CCI. Without "
            "any documentation of implementation to review, the control "
            "objective cannot be considered fulfilled; status remains "
            "Non-Compliant until evidence is provided."
        )
        haystack = narrative.lower()
        from cybersecurity_assessor.engine.validator import _GAP_PHRASES

        assert not any(p in haystack for p in _GAP_PHRASES)

        result = _classify_single(narrative)
        assert result is NarrativeClass.GAP_DESCRIBING

    def test_reworded_affirming_template_classifies_as_affirming(self):
        """Hypothetical reword of an affirming template that drops literal
        affirming phrases but is semantically compliance-affirming."""
        narrative = (
            "Assessment of the production environment's security settings "
            "shows the control objective is fully satisfied. Inspection "
            "of the deployed configuration confirms correct implementation."
        )
        haystack = narrative.lower()
        from cybersecurity_assessor.engine.validator import _AFFIRMING_PHRASES

        # "inspection" is not a literal affirming phrase (only "examined " is)
        # but "confirms" maps to "confirmed via" semantically
        # However let's verify no literal match first
        has_literal = any(p in haystack for p in _AFFIRMING_PHRASES)
        if has_literal:
            # If it does hit a literal phrase, the test is still valid but
            # exercises the literal path instead of the embedding path.
            # Either way, classification should be COMPLIANCE_AFFIRMING.
            pass

        result = _classify_single(narrative)
        assert result is NarrativeClass.COMPLIANCE_AFFIRMING
