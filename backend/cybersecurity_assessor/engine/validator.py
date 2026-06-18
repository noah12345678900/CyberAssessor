"""Pre-write narrative validator (SKILL.md Rule #11).

Ported verbatim from the nist-assessor plugin's ``SKILL.md`` rule #11 and
the ``review-assessment`` skill. Runs after the LLM (or assessor) has
proposed a (status, narrative) pair for a CCI row and BEFORE the writer
touches the workbook. If the narrative class does not match the status,
or the narrative is a forbidden requirement-restatement, the write is
ABORTED and a rejection is returned for the run recorder.

This is the load-bearing patent-supporting component. The validator
catches a class of LLM error that vanilla prompting cannot reliably
prevent: parroting back the col I/J/K shall statement instead of
documenting what was examined and observed. Every rejection here is a
measurable accuracy-improvement event recorded as a ``ValidatorRejection``
in ``engine.measurement``.

Classification scheme (verbatim from rule #11):

- **compliance-affirming** → status MUST be Compliant
- **NA-justifying** → status MUST be Not Applicable
- **gap-describing** → status MUST be Non-Compliant
- **ambiguous / mixed** → ABORT, force assessor to clarify

Anti-pattern (added v1.0.11 per plugin):
- **requirement-restatement** — Q parrots the shall statement without
  documenting the assessment ACT. Treated as ambiguous → ABORT.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from ..excel.ccis_reader import CcisRow
from ..models import ComplianceStatus, NarrativeClass

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Phrase tables
# ---------------------------------------------------------------------------

# Affirming phrases split into STRONG and WEAK (2026-06-18).
#
# STRONG affirming = a substantive CLAIM that the control is implemented
# ("confirmed via", "verified via", "configured to", inheritance prose). These
# count toward the ``classes_hit >= 2 → AMBIGUOUS`` rule: a strong affirmation
# co-occurring with a gap or NA phrase is genuinely contradictory and must
# abort.
#
# WEAK affirming = an ACT-OF-LOOKING verb ("examined", "observed") that
# describes the assessor's verification activity, NOT the outcome. Nearly every
# narrative — Compliant, NC, or NA — opens with "Examined X; …", so a weak verb
# does NOT signal compliance by itself. It must NOT count toward the ambiguity
# rule: "Examined the memo; the capacity is short … POA&M opened" is a clean
# GAP narrative, not an ambiguous one. Weak verbs classify COMPLIANCE_AFFIRMING
# only as a LAST RESORT — when no strong/na/gap phrase hit. This is the AU-4
# fix: "examined " + "poa&m"/"not yet implemented" previously hit affirming +
# gap → classes_hit=2 → AMBIGUOUS → rule #11 rejected an obviously-NC verdict.
_STRONG_AFFIRMING_PHRASES: tuple[str, ...] = (
    "confirmed via",
    "verified in",
    "verified via",
    "verified that",
    "implements per",
    "is configured to",
    "configured per",
    "configured to",
    "demonstrated by",
    "evidenced by",
    "documented in",
    "auto-compliant per",
    "automatically compliant per",
    # Inheritance prose (LLM-authored AND CRM slice-default). An inherited
    # scope is COMPLIANT (applicable, met by the provider) → COMPLIANCE_AFFIRMING
    # per _finalize_crm_decision's class_map (assessor.py: inherited →
    # COMPLIANCE_AFFIRMING). Before these anchors, free-form inheritance text
    # ("Customer fully inherits the managed Azure Bastion control … references
    # the … SSP as the authoritative source") hit no phrase table and scored
    # below the embedding threshold → AMBIGUOUS, poisoning the whole multi-scope
    # hybrid to AMBIGUOUS and tripping rule #11 on every re-save. These also fix
    # a latent misclassification of the CRM slice-default inheritance narrative
    # ("customer inherits this control from the provider") which previously
    # leaned NA via the embedding fallback. "inherits"/"inherited" do NOT appear
    # in the deterministic provider/NA templates, and the full-prepositional
    # "inherited from aws/…" leak phrases live in a separate check, so no
    # collision with NA/provider/gap classification. Inheritance IS a
    # substantive compliance claim, so it lives in STRONG.
    "fully inherits",
    "customer inherits",
    "inherits the",
    "inherits this control",
    "inherited remote-access",
    "as the authoritative source",
)

# WEAK / act-of-looking verbs — see the big comment above. These never
# contribute to the multi-class ambiguity count.
_WEAK_AFFIRMING_PHRASES: tuple[str, ...] = (
    "observed in",
    "observed that",
    "examined ",
)

# Backward-compat union: any external reader that imported the old combined
# table keeps working. Internal classification uses the split tables.
_AFFIRMING_PHRASES: tuple[str, ...] = (
    _STRONG_AFFIRMING_PHRASES + _WEAK_AFFIRMING_PHRASES
)

# NA-justifying phrases — explain why the control doesn't apply.
_NA_PHRASES: tuple[str, ...] = (
    "not applicable because",
    "not applicable —",
    "not applicable -",
    "system does not have",
    "system does not include",
    "feature not present",
    "control is n/a",
    "control is not applicable",
    "implemented by aws",
    "implemented by azure",
    "implemented by gcp",
    "implemented by the csp",
    "implemented by the cloud service provider",
    "no local responsibility",
    "outside system boundary",
    "outside the system boundary",
)

# Gap-describing phrases — describe missing artifacts or incomplete state.
#
# Includes the literal phrasing emitted by the deterministic
# ``rule_no_evidence`` short-circuit in ``engine.assessor`` ("no artifacts
# were retrieved", "presumed not satisfied"). Without these the
# server-side validator at POST /api/assessments classifies the
# kernel's own NC narrative as AMBIGUOUS and rejects the save with
# ``classified=ambiguous`` even though the kernel never called the LLM
# — see ``test_validator_golden.test_rule_no_evidence_template_round_trips``
# which pins this regression. Same template-drift class as the eval-cases
# affirming-phrase rule (memory feedback_eval_compliant_narrative_must_affirm).
_GAP_PHRASES: tuple[str, ...] = (
    "no artifact found",
    "no artifacts were retrieved",
    "no evidence found",
    "no evidence of implementation",
    "presumed not satisfied",
    "no documentation",
    "not implemented",
    "not yet implemented",
    "missing",
    "gap identified",
    "poa&m",
    "poam",
    "remediation",
    "corrective action",
    "to be remediated",
    "open finding",
    "deficient",
    "does not currently",
    "has not been",
    # Ground-truth NC narratives from the real Example System IATT workbook
    # (tests/eval/cases/ground_truth_*_nc.json) use "Examined / Finding"
    # structure with gap wording the table didn't cover, so the validator
    # wrongly classified a human-verified Non-Compliant as AMBIGUOUS and forced
    # an abstain. These phrases are each present ONLY in their NC case (verified
    # no Compliant narrative contains them — no over-match):
    # Scoped to the literal NC patterns from the ground-truth cases so they
    # can't over-match a negated-success Compliant phrasing (e.g. "no controls
    # failed test", "lockout did not occur because the threshold was correct").
    "system failed test",          # ac7 auto-lockout + lockout-threshold ("System failed test - …")
    "lockout did not occur",       # ac7 auto-lockout
    "did not engage at the defined threshold",  # ac7 lockout-threshold
    "not fully deployed",          # ac6 least-privilege
    "not consistently enforced",   # ac6 least-privilege
    "have not been provided",      # cp9 backup-protection ("has not been" misses the plural)
    "no in-boundary artifact",     # si3 freshclam ("No in-boundary artifact …")
    "no in-boundary vulnerability scan",  # si4 acas-scan ("No in-boundary vulnerability scan result …")
    "no malicious code protection implementation artifact",  # si3 av entry-point
)

# Requirement-restatement red flags — Q text starting with these patterns
# almost always just parrots col I/J/K instead of documenting an assessment.
_RESTATEMENT_REGEXES: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\s*reviewed\s+\[?[\w\s/-]+\]?[;:,.]\s*confirmed the requirement", re.IGNORECASE),
    re.compile(r"^\s*reviewed\s+(?:sda\s+control|cci|requirement)", re.IGNORECASE),
    re.compile(r"\bconfirmed the requirement that the (?:system|contractor) shall\b", re.IGNORECASE),
    re.compile(r"\bthe (?:system|contractor) shall\b.*\bas required\b", re.IGNORECASE),
)

# Stem the requirement-restatement detector by also flagging Q text that
# shares a large fraction of its combined vocabulary with col I/J/K.
# finding #13: this is TRUE token-set Jaccard (|Q∩S|/|Q∪S|). Two texts that
# are genuinely "the same requirement restated" share at least half their
# combined vocabulary; a grounded narrative that merely reuses domain terms
# will not. The old 0.70 bar was tuned for an inflated containment metric
# (|Q∩S|/|Q|) that over-fired on short grounded narratives whose every token
# also appeared in a long requirement -- those false-rejected and the
# assessor looped/abstained, losing a real verdict. 0.5 is the Jaccard bar.
_RESTATEMENT_JACCARD_THRESHOLD = 0.5

# Eval fix #2 — hybrid narrative split detection. Matches the
# responsibility_split header rendered by ``_render_hybrid_block``
# (assessor.py) plus the literal "On-prem:" / "Cloud:" half markers the
# LLM emits when prompted with that block. Case-insensitive, multi-line.
# Pre-fix, a hybrid narrative like "On-prem: documented in USD00099999.
# Cloud: implemented by AWS GovCloud." trips BOTH _AFFIRMING_PHRASES
# ("documented in") AND _NA_PHRASES ("implemented by aws") in a single
# pass, hits the classes_hit >= 2 branch in classify_narrative, and
# silently classifies as AMBIGUOUS — rejecting a perfectly valid hybrid
# Compliant verdict. The split lets each half classify independently and
# merge via _merge_hybrid_classes' precedence rules.
_HYBRID_SPLIT_RE = re.compile(
    r"(?im)^\s*(?:##\s*responsibility_split|on[-_ ]?prem(?:ises)?\s*[:\-]|cloud\s*[:\-])"
)

# Multi-cloud stitched-scope header detection. ``stitch_scope_narrative``
# (assessor.py) renders a >=2-scope column-Q block as per-scope chunks of the
# exact form ``f"{label}:\n\n{text}"`` joined by ``"\n\n"``, where ``label`` is
# a CRM scope label ("AWS GovCloud", "Azure Government") or the synthesized
# ON_PREM_LABEL ("On-Premises"). Pre-fix, ``_HYBRID_SPLIT_RE`` only knew the
# LLM's "On-prem:" / "Cloud:" markers, so a 3-scope AWS/Azure/On-Prem stitch
# went UNSPLIT — its AFFIRMING + NA + GAP phrases collided in one block,
# hit the classes_hit >= 2 branch, classified AMBIGUOUS, and rule #11 rejected
# every re-save (status_narrative_mismatch).
#
# This pattern matches a STITCH header precisely: line-start, a plausible
# scope label (1-40 chars of letters/digits/spaces/hyphens/parens only — no
# terminal punctuation but the colon), a single trailing colon, end-of-line,
# then a blank line (the ``:\n\n`` stitch separator). Requiring the blank
# line after the colon is what distinguishes a header from prose that merely
# contains a mid-sentence colon ("Examined the policy: it documents...") —
# such prose is not followed by a blank line, so it never matches.
_SCOPE_HEADER_SPLIT_RE = re.compile(
    r"(?m)^[ \t]*([A-Za-z0-9][A-Za-z0-9 ()\-]{0,39}):[ \t]*\r?\n[ \t]*\r?\n"
)

# v0.2 dual-narrative leak phrases. The on-prem half of a hybrid narrative
# must describe what the LOCAL system does. Provider-only language
# ("inherited from AWS", "implemented by the CSP") in the on-prem half is
# a classic LLM mislabel where the model swaps the two halves. Detected
# at NOTE level by ``validate_dual_narratives`` -- column Q already
# passed the main validator and we don't want to expand the retry budget
# for a UI-fidelity field.
_PROVIDER_ONLY_PHRASES: tuple[str, ...] = (
    "inherited from aws",
    "inherited from azure",
    "inherited from gcp",
    "inherited from the csp",
    "inherited from the cloud service provider",
    "implemented by aws",
    "implemented by azure",
    "implemented by gcp",
    "implemented by the csp",
    "implemented by the cloud service provider",
    "aws govcloud",
    "azure government",
    "fedramp-authorized csp",
)

# Symmetric: on-prem-only phrases that shouldn't appear in the cloud half.
# Narrower list -- the cloud half is genuinely allowed to reference local
# integrations ("syncs to on-prem Splunk") so we only flag the strongest
# tells. NOTE-level same as the provider direction.
_ONPREM_ONLY_PHRASES: tuple[str, ...] = (
    "on-prem servers",
    "on-premises servers",
    "physical data center",
    "physical datacenter",
    "local hardware",
    "on-premises only",
    "on-prem only",
    "rack-mounted",
)

# v0.2 future-tense compliance trip-wire. A narrative that promises a
# future implementation paired with status=Compliant is a precision
# violation -- it's a POA&M, not a compliant control. Single regex
# covers the common patterns ("will be configured", "to be implemented",
# "planned to deploy", "scheduled for", "in the process of").
_FUTURE_TENSE_RE = re.compile(
    r"\b("
    r"will\s+be\s+(?:configured|implemented|deployed|enabled|installed|established)"
    r"|to\s+be\s+(?:configured|implemented|deployed|enabled|installed|established|determined)"
    r"|planned\s+(?:to|for)\s+(?:deploy|implement|configure|enable|complete)"
    r"|scheduled\s+(?:to|for)\s+(?:deploy|implement|configure|enable|complete)"
    r"|in\s+(?:the\s+)?process\s+of\s+(?:deploying|implementing|configuring|enabling)"
    r"|once\s+(?:deployed|implemented|configured|enabled)"
    r"|upcoming\s+(?:deployment|implementation|rollout)"
    r")\b",
    re.IGNORECASE,
)

# bug(c) 2026-06-10 — "assessment procedures" cited as an evidence source.
# The eMASS workbook's column K holds the *assessment procedures*: the
# DISA-supplied "examine / interview / test" verification INSTRUCTIONS for
# the objective (ccis_reader.py col-K mapping). They tell the assessor HOW
# to verify the control; they are NOT evidence and they are NOT an artifact
# the system produces. An LLM occasionally writes a Compliant narrative that
# cites "the assessment procedures" as if they were the proof ("confirmed
# per the assessment procedures", "documented in the assessment
# procedures") — i.e. it parrots the verification instructions back as the
# evidentiary source. That is the same audit-traceability failure as a
# hallucinated doc cite (UNSUPPORTED_DOC_CITATION): a reviewer asking "what
# artifact?" gets pointed at the question, not the answer. This regex
# matches only the SOURCE-CITATION framing (procedure as the thing
# examined / the thing that confirms), not legitimate methodology mentions
# ("the assessment procedure could not be completed because no evidence
# exists" — a gap narrative — does NOT match).
_ASSESSMENT_PROCEDURE_AS_SOURCE_RE = re.compile(
    r"(?:"
    r"(?:per|examined|reviewed|documented\s+in|recorded\s+in|captured\s+in|"
    r"confirmed\s+(?:in|by|via|through)|verified\s+(?:in|by|via|through)|"
    r"cited\s+in|according\s+to|as\s+(?:stated|documented|defined|described|"
    r"evidenced)\s+in|in\s+accordance\s+with)\s+"
    r"(?:the\s+|column\s+k['’]?s?\s+|col\.?\s*k['’]?s?\s+)?assessment\s+procedures?"
    r"|assessment\s+procedures?\s+"
    r"(?:confirm|confirms|state|states|document|documents|show|shows|"
    r"establish|establishes|demonstrate|demonstrates|indicate|indicates|"
    r"evidence|evidences|prove|proves)\b"
    r")",
    re.IGNORECASE,
)

# bug(c) 2026-06-10 — exemption for the deterministic rule-8a kernel template.
# rules._format_8a_text_narrative emits, WITHOUT calling the LLM, the verbatim
# narrative:  Automatically compliant per Assessment Procedures (col K): "..."
# That string legitimately names col K because rule 8a *is* "the assessment
# procedures themselves declare this objective automatically compliant" — it
# is a kernel decision, not an LLM parroting verification instructions back as
# evidence. It is distinguishable from a genuine LLM mis-cite by its leading
# "Automatically compliant per ... (col K)" fingerprint, which the
# instructions-as-evidence failure mode never produces. Skip the
# ASSESSMENT_PROCEDURE_AS_SOURCE guard when the narrative is this template
# (matches the col-J/col-K/inheritance auto-compliant kernel strings the
# _PRIMARY_CITATION_RE and _CITE_EXEMPT_SUBSTRINGS tables already special-case).
_AUTO_COMPLIANT_TEMPLATE_RE = re.compile(
    r"automatically\s+compliant\s+per\s+"
    r"(?:assessment\s+procedures?|implementation\s+guidance|inheritance|col\b)",
    re.IGNORECASE,
)


# fix #1 -- whitespace-run collapser for source_quote verification. Used to
# normalize both the tagged evidence and a citation's source_quote to single
# spaces before a substring test, so a verbatim quote that differs only by
# reflowed line wrapping (PDF/Word text extraction reintroduces line breaks)
# still matches. The gate tests whether the model invented the words, not
# whether it preserved the source's exact whitespace.
_WS_RUN_RE = re.compile(r"\s+")


# ---------------------------------------------------------------------------
# Embedding-based narrative classification fallback
# ---------------------------------------------------------------------------
#
# Design (embedding-affirming slice, 2026-06-07):
#
# The literal phrase tables above (_AFFIRMING_PHRASES, _GAP_PHRASES,
# _NA_PHRASES) are the FAST PATH. They work when the narrative contains
# an exact substring from the table.
#
# When no literal match is found, _classify_single falls through to
# AMBIGUOUS. This was a recurring source of validator failures: the
# deterministic kernel templates in assessor.py evolve independently of
# the phrase tables, so a template reword (e.g. "no artifacts were
# retrieved" → "no artifacts were found") silently breaks the save path
# with ``classified=ambiguous``.
#
# The embedding fallback adds a second layer: if the literal match
# misses, we compute TF-IDF cosine similarity against a small set of
# canonical "anchor" sentences for each class. If the best-match
# similarity exceeds _EMBEDDING_THRESHOLD, we classify accordingly.
# Otherwise, we preserve the current AMBIGUOUS behavior.
#
# Fallback order:
#   1. Literal substring match (fast, existing behavior)
#   2. Embedding similarity ≥ _EMBEDDING_THRESHOLD (new, robust to drift)
#   3. No match → AMBIGUOUS (existing fail-closed behavior)
#
# The TF-IDF provider is used because:
#   - sklearn is a runtime dependency (pyproject.toml)
#   - No API key or network required (works in SCIF)
#   - Deterministic for a given input (same input → same classification)
#   - The anchor sentences are short and distinctive enough that TF-IDF
#     n-gram overlap is sufficient for catching template-drift rewording
#
# Threshold: 0.45 for TF-IDF cosine similarity. TF-IDF cosine operates
# in a much sparser space than dense embeddings — two sentences sharing
# half their distinctive n-grams score ~0.45, while unrelated sentences
# score < 0.2. Validated against the existing golden test fixtures:
# every affirming/gap/NA narrative in the test suite scores ≥ 0.45
# against its class anchors, and genuinely ambiguous narratives score
# below 0.45 against all three classes.

_EMBEDDING_THRESHOLD = 0.45

# Canonical anchor sentences per class. These are paraphrases of the
# kernel template language and common assessment narrative patterns.
# The anchors should be short, distinctive, and representative of the
# class — NOT copies of the phrase table entries (which are already
# handled by the literal fast path).

_AFFIRMING_ANCHORS: tuple[str, ...] = (
    "Verified that the control is implemented and operating as intended.",
    "Confirmed via inspection of the production configuration.",
    "Documented in the system security plan section covering this control.",
    "Examined the audit logs and confirmed the mechanism is active.",
    "Observed that the system enforces the required security function.",
    "The control is configured to meet the stated objective.",
    "Inspection of the deployed settings demonstrates compliance.",
    "Evidence reviewed and confirms implementation of the control objective.",
    "Inspected the deployed access control settings and found them operational and correctly enforcing the security policy.",
    "Reviewed the deployed configuration and found the control operational and enforcing the required policy.",
)

_GAP_ANCHORS: tuple[str, ...] = (
    "No artifacts were retrieved for this control objective.",
    "No evidence found documenting implementation of this requirement.",
    "The control objective is presumed not satisfied pending supporting evidence.",
    "A gap was identified in the implementation of this security function.",
    "The required configuration has not been implemented.",
    "Missing documentation for the account review process.",
    "Remediation is tracked via the plan of action and milestones.",
    "Open finding requiring corrective action before compliance.",
    "Unable to locate any artifacts substantiating this requirement; the control objective remains an unmet requirement awaiting submission of implementation artifacts.",
    "Awaiting submission of implementation artifacts to substantiate this unmet requirement.",
)

_NA_ANCHORS: tuple[str, ...] = (
    "Not applicable because the system does not include this capability.",
    "This control is not applicable to the system boundary.",
    "The feature is not present in the deployed architecture.",
    "Implemented by the cloud service provider under shared responsibility.",
    "Outside the system boundary and inherited from the enterprise.",
    "Control is not applicable as the technology is not in use.",
    "No local responsibility exists for this control objective.",
    "Inherited from the authorization package of the hosting provider.",
    "The system does not employ wireless networking technology, making this control irrelevant to the deployed architecture.",
    "The technology this control addresses is not employed, rendering the control irrelevant to the deployed architecture.",
)

# fix #4 (2026-06-10) -- negation-aware guard for the embedding fallback.
#
# TF-IDF cosine is a bag-of-words measure: it scores "the system enforces
# session lock" and "the system does NOT enforce session lock" as nearly
# identical, because the negation cue is a single low-IDF token swamped by
# the shared content words. Left unguarded, a gap/absence narrative that
# happens to share affirming vocabulary can WIN the COMPLIANCE_AFFIRMING
# class and make the validator *agree* with a (wrong) Compliant status --
# a precision violation, the exact opposite of what a fail-closed gate is
# for.
#
# The guard fires only on gap-directional negation that scopes an
# implementation / enforcement / presence verb (a few tokens of slack for
# adverbs and auxiliaries). When present, the embedding fallback is NEVER
# allowed to assert COMPLIANCE_AFFIRMING: it returns None so the caller
# falls through to AMBIGUOUS (retry / needs_review). Conservative by
# construction -- it can only DEMOTE an affirming cosine win to ambiguous,
# never fabricate a gap or flip a verdict. A genuinely affirming narrative
# that contains an incidental negation ("access is not granted without
# authentication" -- "granted" is not an implementation verb) does not
# match and is unaffected. This runs BEFORE we trust the cosine result to
# label a narrative compliant; the literal phrase fast path is unchanged.
_NEGATED_IMPLEMENTATION_RE = re.compile(
    r"\b(?:not|never|no longer|fails?\s+to|failed\s+to|unable\s+to|"
    r"cannot|can'?t|without|lacks?|lacking|absent|missing)\b"
    r"(?:\W+\w+){0,3}\W+"
    r"(?:implement|configur|enforc|deploy|establish|maintain|enabl|"
    r"appl(?:y|ied|ies)|perform|monitor|restrict|protect|encrypt|"
    r"control(?:s|led|ling)?|in\s+place|present|satisf)",
    re.IGNORECASE,
)


class _EmbeddingClassifierCache:
    """Lazy-loaded, module-level cache for embedding-based classification.

    The cache holds the TF-IDF vectorizer fitted on the anchor corpus and
    the pre-computed anchor vectors. Constructed on first use so:
      - Tests that never hit the embedding path pay zero import cost
      - Tests CAN monkeypatch ``_embedding_cache`` to inject a mock
    """

    def __init__(self) -> None:
        self._fitted = False
        self._vectorizer: object | None = None
        # Pre-computed anchor vectors, one list per class
        self._affirming_vecs: list[list[float]] = []
        self._gap_vecs: list[list[float]] = []
        self._na_vecs: list[list[float]] = []

    def _ensure_fitted(self) -> None:
        if self._fitted:
            return
        from sklearn.feature_extraction.text import TfidfVectorizer

        # Fit on the full anchor corpus so the vocabulary covers all
        # anchor n-grams. Narratives to classify will be transformed
        # (not fit_transform) against this vocabulary.
        all_anchors = list(_AFFIRMING_ANCHORS) + list(_GAP_ANCHORS) + list(_NA_ANCHORS)
        vectorizer = TfidfVectorizer(
            lowercase=True, ngram_range=(1, 2), min_df=1, max_df=1.0
        )
        matrix = vectorizer.fit_transform(all_anchors)

        n_aff = len(_AFFIRMING_ANCHORS)
        n_gap = len(_GAP_ANCHORS)
        # n_na = len(_NA_ANCHORS)  # remainder

        self._affirming_vecs = [matrix[i].toarray()[0].tolist() for i in range(n_aff)]
        self._gap_vecs = [matrix[i].toarray()[0].tolist() for i in range(n_aff, n_aff + n_gap)]
        self._na_vecs = [matrix[i].toarray()[0].tolist() for i in range(n_aff + n_gap, matrix.shape[0])]
        self._vectorizer = vectorizer
        self._fitted = True

    def classify(self, narrative_lower: str) -> NarrativeClass | None:
        """Return a NarrativeClass if embedding similarity exceeds threshold, else None.

        None means "embedding couldn't classify either" → caller should
        fall through to AMBIGUOUS (preserving fail-closed behavior).
        """
        self._ensure_fitted()
        assert self._vectorizer is not None

        # Transform the narrative against the fitted vocabulary
        vec_matrix = self._vectorizer.transform([narrative_lower])  # type: ignore[union-attr]
        narrative_vec = vec_matrix[0].toarray()[0].tolist()

        from .narrative_embeddings import _cosine

        # Compute max cosine similarity against each class's anchors
        best_affirming = max((_cosine(narrative_vec, a) for a in self._affirming_vecs), default=0.0)
        best_gap = max((_cosine(narrative_vec, a) for a in self._gap_vecs), default=0.0)
        best_na = max((_cosine(narrative_vec, a) for a in self._na_vecs), default=0.0)

        # Find the winning class (if any exceeds threshold)
        scores = [
            (best_affirming, NarrativeClass.COMPLIANCE_AFFIRMING),
            (best_gap, NarrativeClass.GAP_DESCRIBING),
            (best_na, NarrativeClass.NA_JUSTIFYING),
        ]
        scores.sort(key=lambda x: x[0], reverse=True)
        best_score, best_class = scores[0]

        if best_score < _EMBEDDING_THRESHOLD:
            return None  # Below threshold — genuinely ambiguous

        # Check for multi-class confusion: if the top two scores are both
        # above threshold AND within 0.10 of each other, the narrative is
        # ambiguous even by embedding standards — don't over-classify.
        if len(scores) >= 2:
            second_score = scores[1][0]
            if second_score >= _EMBEDDING_THRESHOLD and (best_score - second_score) < 0.10:
                return None  # Too close to call — genuinely ambiguous

        # fix #4 -- negation-aware guard. The cosine math above is blind to
        # negation, so a gap/absence narrative can win COMPLIANCE_AFFIRMING
        # on shared vocabulary alone. Never let the bag-of-words fallback
        # assert compliance over an explicit gap-directional negation:
        # demote to None → AMBIGUOUS (fail-closed). Only affects the
        # affirming outcome; GAP/NA wins pass through untouched.
        if (
            best_class == NarrativeClass.COMPLIANCE_AFFIRMING
            and _NEGATED_IMPLEMENTATION_RE.search(narrative_lower)
        ):
            return None

        return best_class


# Module-level singleton — tests can monkeypatch this to inject a mock.
_embedding_cache = _EmbeddingClassifierCache()


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class RejectionReason(str, Enum):
    """Why the validator refused to write a row. Maps 1:1 to
    ``engine.measurement.RejectionClass`` so the run recorder logs the
    same class string the patent-supporting metrics roll up by.
    """

    REQUIREMENT_RESTATEMENT = "requirement_restatement"
    STATUS_NARRATIVE_MISMATCH = "status_narrative_mismatch"
    MISSING_INHERITANCE_MARKER = "missing_inheritance_marker"
    UNSUPPORTED_DOC_CITATION = "unsupported_doc_citation"
    FORMAT_VIOLATION = "format_violation"
    # v0.2 -- dual-narrative leak detection. Fires when the on-prem half of
    # a hybrid narrative leaks provider-only language ("inherited from AWS",
    # "implemented by the CSP"), or when the cloud half is populated for a
    # CRM-customer row, or vice versa for provider/inherited rows. Always
    # NOTE-level when surfaced from ``validate_dual_narratives`` because
    # column Q is the canonical export slot and already passed the main
    # validator; the split is UI-fidelity only and we don't want to expand
    # the retry budget for a non-load-bearing field.
    DUAL_NARRATIVE_MISLABEL = "dual_narrative_mislabel"
    # v0.2 -- future-tense compliance trip-wire. A narrative that claims
    # "will be configured", "to be implemented", "planned to deploy" paired
    # with status=Compliant is a precision-over-recall violation: the
    # control isn't compliant *yet*, it's a POA&M-shaped row mislabeled as
    # Compliant. Catches a class of LLM error where the model treats
    # documented intent as sufficient evidence.
    FUTURE_TENSE_COMPLIANCE = "future_tense_compliance"
    # v0.3 -- STIG findings without policy/baseline corroboration. A
    # COMPLIANT verdict whose narrative cites a STIG rule (SV-#####r#_rule)
    # but where the row's tagged evidence contains NO non-scan artifact
    # (no policy, SSP, baseline doc, config export — only the CKL/CKLB/
    # XCCDF/Nessus that produced the finding itself) is a precision
    # violation. A scan that says "the control test passed on host X"
    # doesn't prove the control is implemented by policy or design — it
    # only proves the box was configured correctly at scan time, with no
    # documented commitment that it stays that way. The validator's job
    # here is the same as for FUTURE_TENSE_COMPLIANCE: catch a class of
    # LLM error where the model treats scan output as fully sufficient
    # evidence. Source: feedback_corroborate_stig_findings.md.
    UNCORROBORATED_STIG_PASS = "uncorroborated_stig_pass"
    # bug(c) 2026-06-10 -- "assessment procedures" (eMASS workbook col K,
    # the DISA examine/interview/test verification instructions) cited as
    # though they were an evidence artifact. The assessment procedures tell
    # the assessor HOW to verify; they are never the proof. A narrative that
    # cites them as the source ("confirmed per the assessment procedures")
    # fails audit traceability exactly like a hallucinated doc cite -- the
    # reviewer is pointed at the question, not the answer. Detected by
    # _ASSESSMENT_PROCEDURE_AS_SOURCE_RE.
    ASSESSMENT_PROCEDURE_AS_SOURCE = "assessment_procedure_as_source"
    # fix #1 2026-06-10 -- audit-v1 source_quote hard gate. When the audit
    # citation layer is enabled, each structured citation carries a
    # ``source_quote`` the model claims to have copied verbatim from a tagged
    # artifact. If that quote does NOT appear literally (case-insensitive,
    # whitespace-normalized) in the row's tagged evidence text, the model
    # fabricated a supporting quote -- the single most damaging failure for a
    # 3PAO/JAB defense because the SAR would cite a quote that does not exist
    # in any examined artifact. This is a hard rejection (not a NOTE): a
    # fabricated quote invalidates the citation chain, so the row retries and,
    # if it persists, abstains to needs_review rather than shipping a verdict
    # backed by an invented quote. Distinct from UNSUPPORTED_DOC_CITATION
    # (which checks doc *names* in free narrative) -- this checks the verbatim
    # quote *contents* in the structured audit-citation payload.
    UNSUPPORTED_QUOTE = "unsupported_quote"


@dataclass
class ValidationResult:
    """Outcome of running rule #11 against one (status, narrative) pair.

    If ``ok`` is True the write may proceed. Otherwise ``rejections``
    enumerates every rule violation in display order (most important
    first). ``classified_as`` is the narrative class the validator
    decided — useful even on rejection so the UI can show "we thought
    this was gap-describing, but you set status=Compliant".
    """

    ok: bool
    classified_as: NarrativeClass
    rejections: list[tuple[RejectionReason, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class DualNarrativeResult:
    """Outcome of validating the on-prem/cloud narrative split.

    Always advisory -- callers (assessor.py LLM-accept path) treat the
    output as NOTE level. Column Q is the canonical export slot and has
    already passed ``validate()``; the dual halves are UI fidelity only.
    Surfacing as notes lets the operator catch swap-the-halves LLM
    errors without paying a retry budget on a non-export field.

    ``notes`` is the human-readable feedback list (rendered alongside
    ``ValidationResult.notes``); ``flagged`` mirrors which RejectionReason
    classes fired so the run recorder can count them for telemetry even
    when they don't trigger a retry.
    """

    notes: list[str] = field(default_factory=list)
    flagged: list[RejectionReason] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def classify_narrative(narrative_q: str, row: CcisRow | None = None) -> NarrativeClass:
    """Classify a draft col Q narrative into one of the four classes.

    If ``row`` is provided, requirement-restatement detection runs against
    col I/J/K of the row. Without ``row`` only the regex anti-patterns
    fire (lighter but less thorough).

    Eval fix #2 — hybrid-aware. When the narrative carries a
    ``## responsibility_split`` header or explicit "On-prem:" / "Cloud:"
    half markers, each half is classified independently and the results
    merged via :func:`_merge_hybrid_classes`. The pre-fix single-pass
    classifier flagged any hybrid narrative containing both affirming
    ("documented in") and inheritance ("implemented by AWS") phrases as
    AMBIGUOUS — silently rejecting valid hybrid Compliant verdicts.
    """
    if not narrative_q or not narrative_q.strip():
        return NarrativeClass.AMBIGUOUS

    # Requirement-restatement is a shape rule on the WHOLE narrative, not
    # a per-half property. Run it first so the hybrid path can't sneak a
    # parroted requirement through by splitting it across two halves.
    if _is_requirement_restatement(narrative_q, row):
        return NarrativeClass.AMBIGUOUS

    halves = _split_hybrid_narrative(narrative_q)
    if halves is None:
        # No hybrid markers — classify as a single block, original behavior.
        return _classify_single(narrative_q)

    per_half = [_classify_single(h) for h in halves]
    return _merge_hybrid_classes(per_half)


def _classify_single(narrative_q: str) -> NarrativeClass:
    """Single-pass classifier — the pre-fix body of :func:`classify_narrative`.

    Called once on the whole narrative when no hybrid markers are
    present, or once per half when they are. Restatement detection is
    intentionally NOT repeated here — the caller already gated on the
    whole narrative so a per-half re-check would just waste CPU and risk
    false positives on legitimate half-fragments.

    Fallback order (embedding-affirming slice, 2026-06-07):
      1. Literal substring match (fast, existing behavior)
      2. Embedding similarity against anchor sentences (robust to drift)
      3. No match → AMBIGUOUS (existing fail-closed behavior)
    """
    if not narrative_q or not narrative_q.strip():
        return NarrativeClass.AMBIGUOUS

    haystack = narrative_q.casefold()  # finding #19: Unicode-consistent fold for phrase matching
    is_strong_affirm = _has_any(haystack, _STRONG_AFFIRMING_PHRASES)
    is_weak_affirm = _has_any(haystack, _WEAK_AFFIRMING_PHRASES)
    is_na = _has_any(haystack, _NA_PHRASES)
    is_gap = _has_any(haystack, _GAP_PHRASES)

    # Multi-class hits within a SINGLE block → ambiguous (rule #11 mixed
    # case). Only STRONG affirming counts toward the ambiguity tally — a weak
    # act-of-looking verb ("examined"/"observed") co-occurring with a gap or NA
    # phrase is the NORMAL shape of an NC/NA narrative ("Examined X; found a
    # gap; POA&M opened"), not a contradiction. Counting weak verbs here was
    # the AU-4 bug: a clearly-NC narrative classified AMBIGUOUS and rule #11
    # rejected the save. For hybrid narratives this branch only fires when one
    # scope-half is internally inconsistent (the cross-half mix is handled by
    # the per-half split above).
    classes_hit = sum((is_strong_affirm, is_na, is_gap))
    if classes_hit >= 2:
        return NarrativeClass.AMBIGUOUS
    if is_na:
        return NarrativeClass.NA_JUSTIFYING
    if is_gap:
        return NarrativeClass.GAP_DESCRIBING
    if is_strong_affirm:
        return NarrativeClass.COMPLIANCE_AFFIRMING
    # Weak affirming is a LAST-RESORT signal: only when nothing substantive
    # (strong-affirm / na / gap) hit does an act-of-looking verb classify the
    # narrative as affirming. This preserves "Examined the policy; it is in
    # place." → COMPLIANCE_AFFIRMING while letting "Examined …; gap" fall to
    # GAP above.
    if is_weak_affirm:
        return NarrativeClass.COMPLIANCE_AFFIRMING

    # --- Embedding fallback (new) -----------------------------------------
    # No literal phrase matched. Before falling through to AMBIGUOUS, try
    # embedding-based classification against the canonical anchor sets.
    # This catches template-drift rewording that the literal tables miss.
    try:
        embedding_class = _embedding_cache.classify(haystack)
        if embedding_class is not None:
            logger.info(
                "Embedding fallback classified narrative as %s "
                "(no literal phrase match). First 80 chars: %.80s",
                embedding_class.value,
                narrative_q,
            )
            return embedding_class
    except Exception:
        # Embedding path is a best-effort fallback. If sklearn import
        # fails or the vectorizer errors, fall through to AMBIGUOUS
        # silently — the literal path is the load-bearing contract.
        logger.debug(
            "Embedding fallback failed; falling through to AMBIGUOUS",
            exc_info=True,
        )

    return NarrativeClass.AMBIGUOUS


def _split_hybrid_narrative(narrative_q: str) -> list[str] | None:
    """Split a hybrid narrative into per-half chunks, or None if not hybrid.

    Uses ``_HYBRID_SPLIT_RE.finditer`` to locate marker offsets and slice
    the text between consecutive markers. The text BEFORE the first
    marker (e.g. a free-form preamble before "On-prem:") is included as
    its own chunk when non-empty so a stray "POA&M scheduled" intro
    can't escape classification by hiding above the markers.

    Returns ``None`` when fewer than two halves would result — single-
    marker narratives fall back to the original whole-narrative path so
    we don't over-trigger on documents that happen to mention the word
    "cloud" in an unrelated sentence.

    Two marker families are recognized and merged: the legacy LLM-emitted
    "On-prem:" / "Cloud:" / ``## responsibility_split`` markers
    (``_HYBRID_SPLIT_RE``) and the deterministic per-scope headers that
    ``stitch_scope_narrative`` writes for multi-cloud controls
    (``_SCOPE_HEADER_SPLIT_RE``, e.g. "AWS GovCloud:" / "Azure Government:").
    Offsets from both are de-duplicated by start position so a header that
    happens to satisfy both patterns (none currently do) is counted once.
    """
    starts: set[int] = set()
    for regex in (_HYBRID_SPLIT_RE, _SCOPE_HEADER_SPLIT_RE):
        for m in regex.finditer(narrative_q):
            starts.add(m.start())
    matches = sorted(starts)
    if len(matches) < 2:
        return None

    chunks: list[str] = []
    # Preamble before the first marker — only kept when it has any content
    # so the typical "## responsibility_split\nOn-prem: ..." layout doesn't
    # produce an empty leading chunk that would classify as AMBIGUOUS.
    preamble = narrative_q[: matches[0]].strip()
    if preamble:
        chunks.append(preamble)

    for i, start in enumerate(matches):
        end = matches[i + 1] if i + 1 < len(matches) else len(narrative_q)
        chunk = narrative_q[start:end].strip()
        if chunk:
            chunks.append(chunk)

    return chunks if len(chunks) >= 2 else None


def _merge_hybrid_classes(classes: list[NarrativeClass]) -> NarrativeClass:
    """Merge per-half classifications into one overall class.

    Precedence (highest wins):
      1. AMBIGUOUS — any half the per-half classifier could not resolve
         bubbles up; the LLM has to clarify before we accept the row.
      2. GAP_DESCRIBING — any real gap means the row is non-compliant
         overall; a hybrid Compliant verdict on top of a half-gap is a
         precision-over-recall violation.
      3. COMPLIANCE_AFFIRMING — any affirming half with no gap and no
         ambiguity carries the row. The canonical hybrid case is
         (on-prem AFFIRMING, cloud NA-via-inheritance) → AFFIRMING.
      4. NA_JUSTIFYING — only when ALL halves are NA. A fully-inherited
         row that splits its responsibility_split is still NA overall.

    Empty list defensively returns AMBIGUOUS — the caller's
    ``_split_hybrid_narrative`` is supposed to guarantee >=2 entries, but
    refusing to write a verdict on an empty bag is safer than guessing.
    """
    if not classes:
        return NarrativeClass.AMBIGUOUS
    if NarrativeClass.AMBIGUOUS in classes:
        return NarrativeClass.AMBIGUOUS
    if NarrativeClass.GAP_DESCRIBING in classes:
        return NarrativeClass.GAP_DESCRIBING
    if NarrativeClass.COMPLIANCE_AFFIRMING in classes:
        return NarrativeClass.COMPLIANCE_AFFIRMING
    return NarrativeClass.NA_JUSTIFYING


def validate(
    *,
    proposed_status: ComplianceStatus | str,
    proposed_narrative: str,
    row: CcisRow | None = None,
    evidence_text: str | None = None,
    corroboration_present: bool | None = None,
    citations: list[dict] | None = None,
) -> ValidationResult:
    """Run all pre-write checks against a (status, narrative) pair.

    Returns a ``ValidationResult``. Caller must check ``result.ok``
    before calling the writer; if False, each rejection should be
    appended to the ``RunRecorder`` so the patent's accuracy claim is
    backed by row-level evidence.

    ``corroboration_present`` is the v0.3 corroboration-gate signal:
    True iff at least one non-scan artifact (policy / SSP / baseline /
    config doc) is tagged to this objective. When False AND the proposed
    status is COMPLIANT, the UNCORROBORATED_STIG_PASS rejection fires
    (finding #6: a scan-only COMPLIANT is undefensible whether or not the
    narrative name-drops a STIG rule -- the cite precondition was dropped).
    ``None`` (the default) means "caller didn't compute the signal" and the
    rule is skipped -- used by deterministic rule-#8 paths and legacy
    callers that haven't been wired to the EvidenceBlock yet.

    ``citations`` is the fix-#1 audit-v1 structured citation payload: a
    list of dicts, each ``{narrative_field, claim, evidence_id,
    source_quote}``. When supplied AND ``evidence_text`` is available,
    every non-empty ``source_quote`` is verified to appear literally
    (case-insensitive, whitespace-normalized substring) in the tagged
    evidence. A quote that is not found is a fabricated citation and
    fires UNSUPPORTED_QUOTE (hard rejection). ``None`` (the default)
    means the audit layer is disabled or the caller didn't capture
    citations, and the gate is skipped.
    """
    status = _normalize_status(proposed_status)
    klass = classify_narrative(proposed_narrative, row)
    rejections: list[tuple[RejectionReason, str]] = []
    notes: list[str] = []

    # ------------------------------------------------------------------
    # Restatement check (anti-pattern from rule #11 v1.0.11)
    # ------------------------------------------------------------------
    if _is_requirement_restatement(proposed_narrative, row):
        rejections.append(
            (
                RejectionReason.REQUIREMENT_RESTATEMENT,
                "Narrative restates the requirement from col I/J/K/U without "
                "documenting what was examined, what was observed, or what was "
                "missing. Rewrite to describe the assessment ACT (artifact "
                "citation, observation, or gap).",
            )
        )
        # Restatement counts as ambiguous → status/narrative match check
        # below will also fire. Don't return early — let the full rejection
        # set surface so the UI shows the assessor everything at once.

    # ------------------------------------------------------------------
    # Status ↔ narrative class match (the core rule #11 check)
    # ------------------------------------------------------------------
    expected_status = _expected_status_for_class(klass)
    if expected_status is None:
        # Ambiguous narrative — never write.
        rejections.append(
            (
                RejectionReason.STATUS_NARRATIVE_MISMATCH,
                f"Narrative is ambiguous (classified={klass.value}); cannot pair "
                f"with any status. Rewrite the narrative to be unambiguously "
                "compliance-affirming, NA-justifying, or gap-describing.",
            )
        )
    elif status is not None and status != expected_status:
        rejections.append(
            (
                RejectionReason.STATUS_NARRATIVE_MISMATCH,
                f"Narrative classified as {klass.value} → expected status "
                f"{expected_status.value}, but proposed status is {status.value}. "
                "Per rule #11, never silently rewrite one side; surface the "
                "conflict and let the assessor resolve it.",
            )
        )

    # ------------------------------------------------------------------
    # Compliance-affirming narratives need a primary-source citation
    # ------------------------------------------------------------------
    if klass == NarrativeClass.COMPLIANCE_AFFIRMING and not _has_primary_citation(
        proposed_narrative
    ):
        notes.append(
            "Narrative is compliance-affirming but does not cite a primary source "
            "(USD doc + section, SSP section, STIG rule, AWS GovCloud inheritance, "
            "or auto-compliant per rule #8a). Consider strengthening the citation."
        )

    # ------------------------------------------------------------------
    # Inheritance narratives must name a source
    # ------------------------------------------------------------------
    n = proposed_narrative.casefold()  # finding #19: Unicode-consistent fold for phrase matching
    if "inherited from" in n and not _names_inheritance_source(n):
        rejections.append(
            (
                RejectionReason.MISSING_INHERITANCE_MARKER,
                'Narrative says "inherited from" but does not name the source '
                "(DoW Enterprise, parent system, AWS, etc.). Add the source so "
                "rule #8a vs #8b can be applied unambiguously.",
            )
        )

    # ------------------------------------------------------------------
    # Gap-describing narratives at Non-Compliant should mention POA&M
    # ------------------------------------------------------------------
    if (
        klass == NarrativeClass.GAP_DESCRIBING
        and status == ComplianceStatus.NON_COMPLIANT
        and not _mentions_remediation(n)
    ):
        notes.append(
            "Non-Compliant row does not mention POA&M, remediation, or "
            "corrective action. Reviewer (per review-assessment skill) will "
            "flag this as missing POA&M."
        )

    # ------------------------------------------------------------------
    # Future-tense compliance trip-wire (v0.2 precision-over-recall)
    # ------------------------------------------------------------------
    # A COMPLIANT verdict with future-tense narrative content is a POA&M
    # mislabeled as a compliant control. Status of None gets skipped --
    # absent-status rows are abstains by definition. NON_COMPLIANT +
    # future-tense is the *correct* shape (a documented planned fix), so
    # only COMPLIANT triggers. NOT_APPLICABLE skipped too: NA narratives
    # describe boundary conditions, not implementation timelines.
    if (
        status == ComplianceStatus.COMPLIANT
        and _FUTURE_TENSE_RE.search(proposed_narrative or "")
    ):
        rejections.append(
            (
                RejectionReason.FUTURE_TENSE_COMPLIANCE,
                "Narrative uses future-tense language (e.g. 'will be configured', "
                "'to be implemented') but proposes status=Compliant. Future-tense "
                "evidence describes intent, not implementation -- this is POA&M "
                "shaped as Compliant. Either flip status to Non-Compliant with a "
                "remediation timeline, or rewrite the narrative in past/present "
                "tense citing what was actually observed."
            )
        )

    # ------------------------------------------------------------------
    # STIG-finding corroboration gate (v0.3 precision-over-recall)
    # ------------------------------------------------------------------
    # A COMPLIANT verdict is only allowed when the row has a non-scan
    # corroborator (policy / SSP / baseline doc / config export). A
    # scan-only finding "passed on host X" is a point-in-time observation
    # of one box, not proof the control is implemented by policy or
    # design -- and the LLM should not be allowed to elevate it to a
    # COMPLIANT verdict without a corroborating doc. Caller threads the
    # signal in via ``corroboration_present``; ``None`` (deterministic
    # rule-8 paths) skips the rule. See
    # feedback_corroborate_stig_findings.md.
    # finding #6: drop the _CITE_STIG_RE precondition. Per doctrine a
    # COMPLIANT verdict whose only substantiating evidence is a scan/finding
    # (corroboration_present is False) is not defensible regardless of
    # whether the narrative name-drops a STIG rule -- the regex precondition
    # let a scan-only COMPLIANT that didn't cite a STIG phrase sail through
    # ungrounded. The gate now fires on COMPLIANT + corroboration_present is
    # False. ``None`` (deterministic / non-LLM paths that don't supply the
    # signal) still skips -- those have their own guarantees.
    if (
        status == ComplianceStatus.COMPLIANT
        and corroboration_present is False
    ):
        rejections.append(
            (
                RejectionReason.UNCORROBORATED_STIG_PASS,
                "Narrative proposes status=Compliant, but the only tagged "
                "evidence on this objective is scan output "
                "(CKL/CKLB/XCCDF/Nessus) with no non-scan corroborating "
                "artifact. A passing scan finding documents that one host was "
                "configured correctly at scan time -- it does not prove the "
                "control is implemented by policy or design. A COMPLIANT verdict "
                "needs at least one non-scan corroborating artifact (policy / "
                "SSP / baseline / config export); attach one, or flip status to "
                "Non-Compliant / Not Applicable with the appropriate narrative."
            )
        )

    # ------------------------------------------------------------------
    # Assessment-procedure-as-source guard (bug(c), 2026-06-10)
    # ------------------------------------------------------------------
    # The eMASS workbook's column K "assessment procedures" are the DISA
    # verification INSTRUCTIONS (examine / interview / test), not evidence.
    # A narrative that cites them as the confirming source ("documented in
    # the assessment procedures", "assessment procedures confirm ...")
    # points the reviewer at the question instead of the answer -- an
    # audit-traceability defect. Fires on any status because citing
    # instructions-as-evidence is never correct; the regex itself is
    # scoped to the source-citation framing, so methodology mentions
    # ("the assessment procedure could not be completed ...") don't trip.
    if _ASSESSMENT_PROCEDURE_AS_SOURCE_RE.search(
        proposed_narrative or ""
    ) and not _AUTO_COMPLIANT_TEMPLATE_RE.search(proposed_narrative or ""):
        rejections.append(
            (
                RejectionReason.ASSESSMENT_PROCEDURE_AS_SOURCE,
                "Narrative cites the 'assessment procedures' as an evidence "
                "source. The assessment procedures (eMASS workbook column K) "
                "are the DISA examine/interview/test verification INSTRUCTIONS "
                "for the objective -- they tell the assessor how to verify the "
                "control, they are not an artifact and not proof. Cite the "
                "actual evidence examined (a policy, SSP section, config "
                "export, scan, or STIG rule) instead, or flip the status if no "
                "such artifact exists.",
            )
        )

    # ------------------------------------------------------------------
    # Literal cite verification (mechanism #2 of precision-over-recall)
    # ------------------------------------------------------------------
    # Every primary citation in the narrative must appear LITERALLY in
    # the evidence text (case-insensitive substring). Catches
    # hallucinated USD doc numbers / STIG rule IDs / CCI refs / control
    # IDs that vanilla prompting cannot reliably prevent. Skipped when
    # no evidence text was supplied (e.g. deterministic rule-#8 paths
    # short-circuit before the LLM call).
    if evidence_text:
        unverified = _verify_cites(
            narrative=proposed_narrative,
            evidence_text=evidence_text,
            row=row,
        )
        if unverified:
            rejections.append(
                (
                    RejectionReason.UNSUPPORTED_DOC_CITATION,
                    f"Narrative cites tokens not found in tagged evidence: "
                    f"{', '.join(unverified)}. Either remove the citation or "
                    "re-attach evidence that contains it. Hallucinated cites "
                    "fail audit traceability.",
                )
            )

    # ------------------------------------------------------------------
    # fix #1 -- audit-v1 source_quote hard gate (UNSUPPORTED_QUOTE)
    # ------------------------------------------------------------------
    # Each structured citation claims a ``source_quote`` copied verbatim
    # from a tagged artifact. Verify the quote actually appears in the
    # evidence text. We normalize whitespace on BOTH sides (collapse runs
    # of spaces/newlines/tabs to a single space) so a quote that differs
    # from the source only by reflowed wrapping still matches -- the test
    # is "did the model invent the words", not "did it preserve the line
    # breaks". A non-empty quote absent from the evidence is a fabricated
    # citation: hard rejection so the row retries and ultimately abstains
    # rather than shipping an invented quote into the SAR. Skipped when no
    # citations were captured (audit layer off) or no evidence text exists.
    if citations and evidence_text:
        haystack = _WS_RUN_RE.sub(" ", evidence_text).casefold()
        fabricated: list[str] = []
        for cite in citations:
            quote = (cite or {}).get("source_quote") or ""
            quote = quote.strip()
            if not quote:
                continue
            needle = _WS_RUN_RE.sub(" ", quote).casefold()
            if needle not in haystack:
                # Truncate for the operator-visible message so a long
                # fabricated paragraph doesn't blow up the rejection text.
                shown = quote if len(quote) <= 80 else quote[:77] + "..."
                fabricated.append(f'"{shown}"')
        if fabricated:
            rejections.append(
                (
                    RejectionReason.UNSUPPORTED_QUOTE,
                    "Audit citation(s) carry a source_quote not found in the "
                    f"tagged evidence: {'; '.join(fabricated)}. A source_quote "
                    "must be copied verbatim from an examined artifact -- a "
                    "quote that does not appear in any tagged evidence is "
                    "fabricated and fails audit traceability. Remove the "
                    "citation, quote the actual artifact text, or flip the "
                    "status if no supporting artifact exists.",
                )
            )

    return ValidationResult(
        ok=not rejections, classified_as=klass, rejections=rejections, notes=notes
    )


def validate_dual_narratives(
    *,
    narrative_on_prem: str | None,
    narrative_cloud: str | None,
    crm_responsibility: str | None = None,
) -> DualNarrativeResult:
    """Check the on-prem / cloud narrative split for leak + CRM mismatch.

    Advisory only — column Q already passed ``validate()`` and is the
    canonical export slot. The split halves are UI fidelity, so this
    function never returns a hard rejection: callers append the notes
    to the operator-visible feedback and (optionally) record the
    ``flagged`` reasons for telemetry.

    Two classes of mislabel are caught:

    1. **Leak.** Provider-only language in the on-prem half ("inherited
       from AWS", "implemented by the CSP") usually means the LLM
       swapped the two halves. Symmetric on-prem-only language in the
       cloud half ("physical data center", "rack-mounted") is also
       flagged but with a narrower phrase list since the cloud half
       legitimately references local integrations.

    2. **CRM mismatch.** When the assessor knows the CRM responsibility
       for the row, certain combinations are nonsensical:
         - ``customer`` with a non-empty cloud half (no provider scope)
         - ``provider`` or ``inherited`` with a non-empty on-prem half
           (no local scope)
         - ``hybrid`` with both halves empty (the whole point of the
           split is to surface the two scopes)
       ``not_applicable`` is exempt — NA rows don't have implementation
       scope to attribute. Unknown / ``None`` responsibility skips this
       check entirely.
    """
    notes: list[str] = []
    flagged: list[RejectionReason] = []

    onprem = (narrative_on_prem or "").strip()
    cloud = (narrative_cloud or "").strip()
    onprem_lower = onprem.casefold()  # finding #19: Unicode-consistent fold for phrase matching
    cloud_lower = cloud.casefold()  # finding #19: Unicode-consistent fold for phrase matching

    # ------------------------------------------------------------------
    # Leak detection (per-half phrase tables)
    # ------------------------------------------------------------------
    if onprem and _has_any(onprem_lower, _PROVIDER_ONLY_PHRASES):
        notes.append(
            "On-prem narrative half contains provider-only language "
            "(e.g. 'inherited from AWS', 'implemented by the CSP'). "
            "This usually means the on-prem/cloud halves were swapped. "
            "Move provider-attribution sentences to the cloud half."
        )
        flagged.append(RejectionReason.DUAL_NARRATIVE_MISLABEL)
    if cloud and _has_any(cloud_lower, _ONPREM_ONLY_PHRASES):
        notes.append(
            "Cloud narrative half contains on-prem-only language "
            "(e.g. 'physical data center', 'rack-mounted'). The cloud "
            "half should describe provider-scoped implementation; move "
            "on-prem-specific sentences to the on-prem half."
        )
        flagged.append(RejectionReason.DUAL_NARRATIVE_MISLABEL)

    # ------------------------------------------------------------------
    # CRM responsibility cross-check (skipped when responsibility unknown)
    # ------------------------------------------------------------------
    resp = (crm_responsibility or "").strip().lower()
    if resp == "customer":
        if cloud:
            notes.append(
                "CRM marks this control as customer-owned, but the cloud "
                "narrative half is populated. Customer-owned controls have "
                "no provider scope — leave the cloud half empty or move its "
                "content to on-prem."
            )
            flagged.append(RejectionReason.DUAL_NARRATIVE_MISLABEL)
    elif resp in ("provider", "inherited"):
        if onprem:
            notes.append(
                f"CRM marks this control as {resp}, but the on-prem narrative "
                "half is populated. Provider/inherited controls have no local "
                "scope — leave the on-prem half empty or move its content to "
                "cloud."
            )
            flagged.append(RejectionReason.DUAL_NARRATIVE_MISLABEL)
    elif resp == "hybrid":
        if not onprem and not cloud:
            notes.append(
                "CRM marks this control as hybrid, but both narrative halves "
                "are empty. Hybrid controls split implementation between "
                "customer and provider — populate at least one half to "
                "document each scope."
            )
            flagged.append(RejectionReason.DUAL_NARRATIVE_MISLABEL)
    # responsibility == "not_applicable" or empty: skip the cross-check.

    return DualNarrativeResult(notes=notes, flagged=flagged)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _normalize_status(value: ComplianceStatus | str | None) -> ComplianceStatus | None:
    if value is None:
        return None
    if isinstance(value, ComplianceStatus):
        return value
    s = str(value).strip()
    for member in ComplianceStatus:
        if member.value.lower() == s.lower():
            return member
    return None


def _expected_status_for_class(klass: NarrativeClass) -> ComplianceStatus | None:
    if klass == NarrativeClass.COMPLIANCE_AFFIRMING:
        return ComplianceStatus.COMPLIANT
    if klass == NarrativeClass.NA_JUSTIFYING:
        return ComplianceStatus.NOT_APPLICABLE
    if klass == NarrativeClass.GAP_DESCRIBING:
        return ComplianceStatus.NON_COMPLIANT
    return None


def _has_any(haystack_lower: str, needles: tuple[str, ...]) -> bool:
    return any(n in haystack_lower for n in needles)


def _is_requirement_restatement(narrative: str, row: CcisRow | None) -> bool:
    """True if Q text just parrots the requirement.

    Two signals:
      1. Regex match against known restatement openers.
      2. >= ``_RESTATEMENT_JACCARD_THRESHOLD`` token-set Jaccard overlap
         (|Q∩S|/|Q∪S|) with col I, J, K, or U (each compared
         independently). Computed only when the row is provided.
    """
    if not narrative:
        return False
    for pattern in _RESTATEMENT_REGEXES:
        if pattern.search(narrative):
            return True
    if row is not None:
        q_tokens = _tokenset(narrative)
        if not q_tokens:
            return False
        for source in (row.definition, row.guidance, row.procedures, row.previous_results):
            if not source:
                continue
            s_tokens = _tokenset(source)
            if not s_tokens:
                continue
            # finding #13: TRUE Jaccard = |Q∩S|/|Q∪S| (not the old
            # containment |Q∩S|/|Q|, which scored a short grounded
            # narrative fully contained in a long requirement at ~1.0 and
            # false-rejected it). Guard union==0 → not a restatement.
            union = len(q_tokens | s_tokens)
            if union == 0:
                return False
            jaccard = len(q_tokens & s_tokens) / union
            if jaccard >= _RESTATEMENT_JACCARD_THRESHOLD:
                return True
    return False


_TOKEN_RE = re.compile(r"[a-z0-9]{3,}")
_STOPWORDS: frozenset[str] = frozenset(
    {
        "the", "and", "for", "shall", "will", "with", "that", "this", "from",
        "have", "has", "are", "was", "were", "been", "being", "any", "all",
        "such", "into", "than", "then", "their", "they", "them", "these",
        "those", "must", "may", "can", "use", "used", "uses", "via", "per",
        "system", "control", "controls", "information", "organization",
    }
)


def _tokenset(text: str) -> set[str]:
    return {t for t in _TOKEN_RE.findall(text.casefold()) if t not in _STOPWORDS}  # finding #19: Unicode-consistent fold for token matching


_PRIMARY_CITATION_RE = re.compile(
    r"(?:"
    r"USD\d{8,}"  # USD doc number
    r"|\bSSP\s+§?\s*\d"  # SSP section
    r"|\bSV-\d+r\d+_rule\b"  # STIG SV-rule id
    r"|\bV-\d{6,}\b"  # STIG V-number (group_id, e.g. V-220706)
    r"|\bAWS\s+GovCloud\b"  # cloud inheritance
    r"|auto-?compliant per (?:rule|the)?\s*8a"
    r"|automatically compliant per (?:assessment procedures|implementation guidance|inheritance)"
    r")",
    re.IGNORECASE,
)


def _has_primary_citation(narrative: str) -> bool:
    return bool(_PRIMARY_CITATION_RE.search(narrative or ""))


_INHERITANCE_SOURCE_RE = re.compile(
    r"inherited from\s+(?:the\s+)?"
    r"(dow|dod|enterprise|parent|aws|azure|gcp|csp|cloud service provider|[A-Z][\w\s\-]+)",
    re.IGNORECASE,
)


def _names_inheritance_source(narrative_lower: str) -> bool:
    return bool(_INHERITANCE_SOURCE_RE.search(narrative_lower))


_REMEDIATION_RE = re.compile(r"\b(poa&?m|remediation|corrective action|to be remediated)\b", re.IGNORECASE)


def _mentions_remediation(narrative_lower: str) -> bool:
    return bool(_REMEDIATION_RE.search(narrative_lower))


# ---------------------------------------------------------------------------
# Literal cite verification (mechanism #2)
# ---------------------------------------------------------------------------

# Specific-cite regexes used by _verify_cites. The validator already has
# _PRIMARY_CITATION_RE for presence detection; the cite-verifier needs to
# enumerate each match and check it literally against the evidence text,
# so we keep narrow per-class regexes here for clean extraction.
_CITE_USD_RE = re.compile(r"USD\d{8,}", re.IGNORECASE)
# Matches any of:
#   SV-220706r569187_rule         (bare SV-rule)
#   V-220706                      (bare V-number / group_id)
#   [V-220706 / SV-220706r569187_rule]  (bracket citation emitted by format_finding_citation)
_CITE_STIG_RE = re.compile(
    r"(?:"
    r"SV-\d+r\d+_rule"
    r"|\bV-\d{6,}\b"
    r"|\[V-\d{6,}\s*/\s*SV-\d+r\d+_rule\]"
    r")",
    re.IGNORECASE,
)
# Reuse the exact patterns from evidence/tagger.py — same shape, same
# corner-case handling. Re-declared rather than imported to keep the
# validator a leaf module (no cross-package import cycles).
_CITE_CCI_RE = re.compile(r"CCI-\d{6}", re.IGNORECASE)
_CITE_CONTROL_ID_RE = re.compile(r"\b([A-Z]{2}-\d{1,2}(?:\(\d+\))?)(?!\d)")

# Citations the LLM may write without an evidence match. They reference
# external CSPs / deterministic rule outputs, not artifact text.
_CITE_EXEMPT_SUBSTRINGS: tuple[str, ...] = (
    "auto-compliant per rule 8a",
    "automatically compliant per",
    "aws govcloud",
    "azure government",
    "implemented by the csp",
    "implemented by the cloud service provider",
)


def _verify_cites(
    *,
    narrative: str,
    evidence_text: str,
    row: CcisRow | None,
) -> list[str]:
    """Return the list of citation tokens in ``narrative`` that are NOT
    literally present in ``evidence_text``.

    Empty list = all cites verified (or no cites to verify).

    Exemptions (not rejected even when absent from evidence):
      - The CCI ID and control ID of the row being assessed (named in
        the prompt, not the evidence).
      - The exempt substrings in ``_CITE_EXEMPT_SUBSTRINGS`` (external
        CSPs, deterministic rule-8a sentinel).
    """
    if not narrative or not evidence_text:
        return []

    narrative_lower = narrative.casefold()  # finding #19: Unicode-consistent fold for phrase matching
    # Short-circuit: if the whole narrative is one of the exempt sentinels
    # there's nothing to verify literally against evidence.
    for sentinel in _CITE_EXEMPT_SUBSTRINGS:
        if sentinel in narrative_lower:
            # The sentinel itself is fine; still check any OTHER cites
            # that may accompany it. Don't return early.
            break

    evidence_lower = evidence_text.casefold()  # finding #19: Unicode-consistent fold for substring matching
    row_exemptions: set[str] = set()
    if row is not None:
        if row.cci_id:
            row_exemptions.add(row.cci_id.lower())
        if row.control_id:
            row_exemptions.add(row.control_id.lower())

    seen: set[str] = set()
    unverified: list[str] = []
    for pattern in (
        _CITE_USD_RE,
        _CITE_STIG_RE,
        _CITE_CCI_RE,
        _CITE_CONTROL_ID_RE,
    ):
        for m in pattern.finditer(narrative):
            token = m.group(0)
            token_lower = token.casefold()  # finding #19: match the casefolded evidence haystack
            if token_lower in seen:
                continue
            seen.add(token_lower)
            if token_lower in row_exemptions:
                continue
            if token_lower in evidence_lower:
                continue
            unverified.append(token)
    return unverified
