"""Three-tier adversarial CRM suspicion scoring.

The CRM short-circuit at :meth:`Assessor._finalize_crm_decision` lets a
single vendor-supplied document silently change hundreds of assessment
verdicts (provider→NA, inherited→COMPLIANT, not_applicable→NA without
ever consulting the LLM). The overlay-default-local rule (memory:
``feedback_overlay_default_local``) protects against MISSING CRM data,
not WRONG CRM data. This module is the wrong-data guard.

**Three tiers, with graceful degradation:**

================  ====================================  =================================================================
Tier              Signal                                Cold-start behavior
================  ====================================  =================================================================
1. Heuristics     Four hand-coded rules (always run)    Works on the FIRST CRM
2a. TF-IDF        Within-CRM narrative similarity       Works on the FIRST CRM
2b. Embeddings    Distance from "vague filler" centroid Works on first CRM IF OpenAI key/sentence-transformers available
3. IsolationForest Cross-CRM anomaly score              Activates once corpus >= 10 historical CRMs
================  ====================================  =================================================================

The four heuristics:

* ``high_inheritance`` — vendor mass-claimed inheritance.
* ``local_evidence_contradiction`` — CRM says inherited, but the
  workbook has locally-tagged evidence for that family. Hard alert —
  the assessor LITERALLY HAS evidence the vendor said wouldn't exist.
* ``narrative_poverty`` — > 30% of inherited/provider claims have
  null/empty narrative. A CRM that skips justification is asking the
  assessor to trust it on faith.
* ``boilerplate_narrative`` — TF-IDF max intra-CRM cosine similarity
  > 0.85 on > 50% of narratives. Catches the "vendor copy-pasted the
  same paragraph across 500 controls" pattern that the original
  exact-match heuristic missed (boilerplate paragraphs vary in
  whitespace/punctuation while being semantically identical).

**Blend formula** when all three tiers report:

    overall = 0.5 * heuristic
            + 0.3 * ml_anomaly
            + 0.2 * (1 - narrative_quality)

When ML anomaly or narrative quality are unavailable (cold-start /
missing API), their weight is redistributed proportionally to the
remaining tiers — so cold-start runs see a properly-normalized
overall_suspicion rather than artificially low scores. The blend is
capped at 1.0.

**Severity thresholds:**

* ``overall < 0.30`` — info / clean.
* ``0.30 <= overall < 0.60`` — warn / banner with details.
* ``overall >= 0.60`` — alert / banner with "Proceed anyway" gate.

Session-free; the route handler (:mod:`routes.baselines`) builds inputs
and persists the resulting :class:`CrmSuspicionReport`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from .crm_context import CrmContext
from .crm_ml import (
    CURRENT_FEATURE_SCHEMA_VERSION,
    CrmFeatureVector,
    extract_features,
    score_anomaly,
)
from .narrative_embeddings import (
    EmbeddingsProvider,
    NarrativeQualityResult,
    score_narrative_quality,
)

# ---------------------------------------------------------------------------
# Heuristic thresholds — change with care; tests pin to these.
# ---------------------------------------------------------------------------

# high_inheritance: alert at 90%, warn at 70%
HIGH_INHERITANCE_WARN = 0.70
HIGH_INHERITANCE_ALERT = 0.90

# narrative_poverty: warn when > 30% of inherited/provider rows have no narrative
NARRATIVE_POVERTY_THRESHOLD = 0.30

# boilerplate_narrative: warn when > 50% of narratives have max similarity > 0.85
BOILERPLATE_SIMILARITY_THRESHOLD = 0.85
BOILERPLATE_NARRATIVE_FRACTION = 0.50

# Overall-suspicion thresholds for severity bucketing in the UI banner.
OVERALL_INFO_MAX = 0.30
OVERALL_WARN_MAX = 0.60

# Blend weights — must sum to 1.0 when all three tiers report. When tiers
# go missing, _blend redistributes their weight proportionally to keep
# the cap at 1.0 meaningful.
BLEND_W_HEURISTIC = 0.50
BLEND_W_ML_ANOMALY = 0.30
BLEND_W_NARRATIVE = 0.20  # weight on (1 - narrative_quality)


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CrmSuspicionFlag:
    """One named heuristic verdict.

    ``severity`` is one of ``"info"`` / ``"warn"`` / ``"alert"``. The UI
    badges by severity. ``details`` is JSON-serializable — kept flexible
    so heuristics can attach domain-specific evidence (e.g. the list of
    families that contradicted, the boilerplate narrative excerpts).
    """

    name: str
    severity: str
    summary: str
    details: dict = field(default_factory=dict)


@dataclass(frozen=True)
class CrmSuspicionReport:
    """Full hybrid score breakdown for one CRM at one point in time.

    The route handler persists this to :class:`CrmSuspicionLog` and
    returns it to the UI banner. ``ml_anomaly_score`` and
    ``narrative_quality_score`` are nullable — None means the
    corresponding tier had nothing to say (cold-start / missing
    provider), which the UI surfaces as a greyed-out row rather than
    hiding entirely.

    ``per_family`` maps NIST family token ("ac", "ia", ...) to a small
    diagnostic dict — counts of claimed inheritance, contradiction
    flags, narrative-presence ratio. Powers the "expand details" panel
    in the suspicion banner.
    """

    workbook_id: int
    crm_baseline_id: int
    computed_at: datetime
    heuristic_score: float
    ml_anomaly_score: float | None
    narrative_quality_score: float | None
    overall_suspicion: float
    flags: tuple[CrmSuspicionFlag, ...]
    per_family: dict[str, dict]
    n_corpus: int
    feature_vector: CrmFeatureVector | None = None  # for log persistence + refit

    @property
    def severity(self) -> str:
        """Bucketed severity for top-level banner styling."""
        if self.overall_suspicion < OVERALL_INFO_MAX:
            return "info"
        if self.overall_suspicion < OVERALL_WARN_MAX:
            return "warn"
        return "alert"

    def to_json_safe(self) -> dict:
        """JSON-safe shape for the API response body.

        Hand-rolled rather than asdict() because we strip the
        feature_vector (large, only useful to the persistence layer)
        and ISO-format the datetime.
        """
        return {
            "workbook_id": self.workbook_id,
            "crm_baseline_id": self.crm_baseline_id,
            "computed_at": self.computed_at.isoformat(),
            "heuristic_score": self.heuristic_score,
            "ml_anomaly_score": self.ml_anomaly_score,
            "narrative_quality_score": self.narrative_quality_score,
            "overall_suspicion": self.overall_suspicion,
            "severity": self.severity,
            "flags": [asdict(f) for f in self.flags],
            "per_family": self.per_family,
            "n_corpus": self.n_corpus,
        }


# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------


def _family_of(control_id: str) -> str:
    """Mirror of crm_ml._family_of — kept local so this module is
    importable without dragging the ML stack."""
    if not control_id:
        return ""
    return control_id.split("-", 1)[0].lower()


def _eval_high_inheritance(
    in_scope_entries: list,
    n_scope: int,
) -> tuple[CrmSuspicionFlag | None, float]:
    """High inheritance: > 70% warn, > 90% alert.

    Score component: linear ramp from 0.0 at 50% off-loaded to 1.0 at
    100% off-loaded — gives the heuristic score a continuous signal,
    not just a step function from the flag firing.
    """
    if n_scope == 0:
        return None, 0.0
    off_loaded = sum(
        1
        for e in in_scope_entries
        if e.responsibility in ("inherited", "provider", "not_applicable")
    )
    pct = off_loaded / n_scope
    component = max(0.0, min(1.0, (pct - 0.5) / 0.5))

    if pct >= HIGH_INHERITANCE_ALERT:
        flag = CrmSuspicionFlag(
            name="high_inheritance",
            severity="alert",
            summary=(
                f"{pct:.0%} of in-scope controls are claimed inherited/provider/NA "
                f"({off_loaded} of {n_scope}). Vendor may be over-claiming offload."
            ),
            details={"off_loaded_pct": pct, "n_off_loaded": off_loaded, "n_scope": n_scope},
        )
    elif pct >= HIGH_INHERITANCE_WARN:
        flag = CrmSuspicionFlag(
            name="high_inheritance",
            severity="warn",
            summary=(
                f"{pct:.0%} of in-scope controls are claimed inherited/provider/NA "
                f"({off_loaded} of {n_scope}). Worth a spot-check."
            ),
            details={"off_loaded_pct": pct, "n_off_loaded": off_loaded, "n_scope": n_scope},
        )
    else:
        flag = None
    return flag, component


def _eval_local_evidence_contradiction(
    in_scope_entries: list,
    tagged_evidence_by_family: dict[str, int],
) -> tuple[CrmSuspicionFlag | None, float]:
    """CRM claims family X fully off-loaded, but workbook has evidence on X.

    Score: 1.0 if any contradiction; weighted by count of contradicting
    families (cap at 1.0 once five families contradict).
    """
    family_claims: dict[str, set[str]] = {}
    for entry in in_scope_entries:
        fam = _family_of(entry.control_id)
        if not fam:
            continue
        family_claims.setdefault(fam, set()).add(entry.responsibility)

    contradicting: list[str] = []
    off_loaded_set = {"inherited", "provider", "not_applicable"}
    for fam, resps in family_claims.items():
        if resps and resps.issubset(off_loaded_set):
            if tagged_evidence_by_family.get(fam, 0) > 0:
                contradicting.append(fam)
    if not contradicting:
        return None, 0.0
    # Saturate at 5 contradicting families.
    component = min(1.0, len(contradicting) / 5.0)
    flag = CrmSuspicionFlag(
        name="local_evidence_contradiction",
        severity="alert",
        summary=(
            f"{len(contradicting)} control families "
            f"({', '.join(sorted(contradicting)).upper()}) are claimed fully "
            f"inherited/provider/NA but the workbook has locally-tagged evidence "
            f"for them."
        ),
        details={"families": sorted(contradicting)},
    )
    return flag, component


def _eval_narrative_poverty(
    in_scope_entries: list,
) -> tuple[CrmSuspicionFlag | None, float]:
    """Warn when > 30% of inherited/provider claims have null/empty narrative.

    Score: linear from 0.0 at 0% poverty to 1.0 at 60% poverty (poverty
    above 60% is already maximally suspicious).
    """
    claim_entries = [
        e for e in in_scope_entries
        if e.responsibility in ("inherited", "provider", "hybrid")
    ]
    if not claim_entries:
        return None, 0.0
    empty = [e for e in claim_entries if not (e.narrative or "").strip()]
    pct = len(empty) / len(claim_entries)
    component = max(0.0, min(1.0, pct / 0.6))
    if pct < NARRATIVE_POVERTY_THRESHOLD:
        return None, component
    flag = CrmSuspicionFlag(
        name="narrative_poverty",
        severity="warn",
        summary=(
            f"{pct:.0%} of inherited/provider claims ({len(empty)} of "
            f"{len(claim_entries)}) have no narrative justification."
        ),
        details={"empty_pct": pct, "n_empty": len(empty), "n_claims": len(claim_entries)},
    )
    return flag, component


def _eval_boilerplate_narrative(
    feature_vector: CrmFeatureVector,
) -> tuple[CrmSuspicionFlag | None, float]:
    """TF-IDF boilerplate detection.

    Uses the intra_crm_tfidf stats already computed in the feature
    vector — avoids running the TF-IDF vectorizer twice. Flag fires
    when ``max_similarity > 0.85`` AND ``mean_similarity > 0.50``
    (mean threshold prevents firing on a single duplicated pair amid
    otherwise-distinct narratives).

    Score: ramps with mean similarity (more pervasive boilerplate
    = higher score).
    """
    max_sim = feature_vector.intra_crm_tfidf_max_similarity
    mean_sim = feature_vector.intra_crm_tfidf_mean_similarity
    # Component score driven by mean — pervasive boilerplate is worse than
    # one duplicate. Range mean in [0.0, 1.0]; map [0.0, 0.8] -> [0, 1].
    component = max(0.0, min(1.0, mean_sim / 0.8))

    if max_sim <= BOILERPLATE_SIMILARITY_THRESHOLD:
        return None, component
    # The "fraction of narratives at high similarity" stat isn't carried in
    # the feature vector. Use mean as a proxy threshold — if the mean
    # exceeds half of the max-similarity threshold the CRM is broadly
    # boilerplate, not just one duplicate pair.
    if mean_sim < (BOILERPLATE_SIMILARITY_THRESHOLD * BOILERPLATE_NARRATIVE_FRACTION):
        return None, component
    flag = CrmSuspicionFlag(
        name="boilerplate_narrative",
        severity="warn",
        summary=(
            f"Narratives are highly self-similar (max TF-IDF cosine "
            f"{max_sim:.2f}, mean {mean_sim:.2f}). Vendor likely "
            f"copy-pasted the same paragraph across many controls."
        ),
        details={"max_similarity": max_sim, "mean_similarity": mean_sim},
    )
    return flag, component


# ---------------------------------------------------------------------------
# Per-family diagnostics
# ---------------------------------------------------------------------------


def _build_per_family(
    in_scope_entries: list,
    tagged_evidence_by_family: dict[str, int],
) -> dict[str, dict]:
    """Family-grouped diagnostic dict for the UI details panel."""
    by_family: dict[str, dict] = {}
    for entry in in_scope_entries:
        fam = _family_of(entry.control_id)
        if not fam:
            continue
        bucket = by_family.setdefault(
            fam,
            {
                "n_entries": 0,
                "n_inherited": 0,
                "n_provider": 0,
                "n_not_applicable": 0,
                "n_customer": 0,
                "n_hybrid": 0,
                "n_with_narrative": 0,
                "tagged_evidence_count": tagged_evidence_by_family.get(fam, 0),
            },
        )
        bucket["n_entries"] += 1
        key = f"n_{entry.responsibility}"
        if key in bucket:
            bucket[key] += 1
        if (entry.narrative or "").strip():
            bucket["n_with_narrative"] += 1
    return by_family


# ---------------------------------------------------------------------------
# Blend
# ---------------------------------------------------------------------------


def _blend(
    heuristic: float,
    ml_anomaly: float | None,
    narrative_quality: float | None,
) -> float:
    """Weighted blend with weight redistribution when tiers are missing.

    Always-present heuristic is the floor; ML anomaly and narrative
    quality redistribute their weights to the present tiers when they
    drop out. Result is clipped to ``[0, 1]``.
    """
    components: list[tuple[float, float]] = [(BLEND_W_HEURISTIC, heuristic)]
    if ml_anomaly is not None:
        components.append((BLEND_W_ML_ANOMALY, ml_anomaly))
    if narrative_quality is not None:
        # Higher quality = lower suspicion contribution.
        components.append((BLEND_W_NARRATIVE, 1.0 - narrative_quality))
    total_weight = sum(w for w, _ in components)
    if total_weight == 0.0:
        return 0.0
    weighted = sum(w * v for w, v in components) / total_weight
    return max(0.0, min(1.0, weighted))


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def score_crm_suspicion(
    *,
    workbook_id: int,
    crm_baseline_id: int,
    crm_context: CrmContext,
    in_scope_control_ids: Sequence[str],
    tagged_evidence_by_family: dict[str, int],
    n_corpus: int = 0,
    anomaly_model_blob: bytes | None = None,
    embeddings_provider: EmbeddingsProvider | None = None,
    computed_at: datetime | None = None,
) -> CrmSuspicionReport:
    """Compute the full hybrid suspicion report.

    The route handler is responsible for:

    * Fetching the active :class:`CrmAnomalyModel` blob (or None if the
      corpus hasn't reached :data:`MIN_CORPUS_SIZE` yet).
    * Resolving the embeddings provider via
      :func:`narrative_embeddings.resolve_provider` (or None if the user
      explicitly opted out / no provider available).
    * Persisting the returned report to :class:`CrmSuspicionLog`.

    All tiers degrade gracefully — missing ML model and missing
    embeddings provider both return ``None`` for their respective
    component scores and the blend redistributes weight.
    """
    scope = set(in_scope_control_ids)
    n_scope = len(scope)
    in_scope_entries = [
        entry
        for control_id, entry in crm_context.by_control.items()
        if control_id in scope
    ]

    # Always extract the feature vector — it powers both the
    # boilerplate heuristic (via intra_crm_tfidf stats) and the
    # ML anomaly scorer.
    feature_vector = extract_features(
        crm_context=crm_context,
        in_scope_control_ids=in_scope_control_ids,
        tagged_evidence_by_family=tagged_evidence_by_family,
    )

    # --- Tier 1 + 2a: heuristics + TF-IDF (always run) ---
    flags: list[CrmSuspicionFlag] = []
    components: list[float] = []

    f, c = _eval_high_inheritance(in_scope_entries, n_scope)
    if f is not None:
        flags.append(f)
    components.append(c)

    f, c = _eval_local_evidence_contradiction(in_scope_entries, tagged_evidence_by_family)
    if f is not None:
        flags.append(f)
    components.append(c)

    f, c = _eval_narrative_poverty(in_scope_entries)
    if f is not None:
        flags.append(f)
    components.append(c)

    f, c = _eval_boilerplate_narrative(feature_vector)
    if f is not None:
        flags.append(f)
    components.append(c)

    # Heuristic score = max of components rather than mean. Rationale: each
    # heuristic detects an independent failure mode; one severe failure
    # shouldn't be diluted by three "all clear" components. (A separate
    # design choice from the inter-tier blend, which is a weighted average
    # because the tiers are correlated signals about the same property.)
    heuristic_score = max(components) if components else 0.0

    # --- Tier 3: IsolationForest (corpus-gated) ---
    ml_anomaly_score: float | None = None
    if anomaly_model_blob is not None and n_corpus >= 10:
        if feature_vector.schema_version == CURRENT_FEATURE_SCHEMA_VERSION:
            try:
                ml_anomaly_score = score_anomaly(anomaly_model_blob, feature_vector)
            except Exception:
                # ML failure is not a hard error — log it via the score
                # being None so the UI shows "ML unavailable" instead of
                # crashing the whole report.
                ml_anomaly_score = None

    # --- Tier 2b: embedding-based narrative quality ---
    narrative_quality_score: float | None = None
    quality_result: NarrativeQualityResult | None = None
    if embeddings_provider is not None:
        narratives = [
            (e.narrative or "").strip()
            for e in in_scope_entries
            if e.responsibility in ("inherited", "provider", "hybrid")
            and (e.narrative or "").strip()
        ]
        if narratives:
            try:
                quality_result = score_narrative_quality(narratives, embeddings_provider)
                if quality_result.scores:
                    narrative_quality_score = sum(quality_result.scores) / len(
                        quality_result.scores
                    )
            except Exception:
                narrative_quality_score = None

    overall = _blend(heuristic_score, ml_anomaly_score, narrative_quality_score)
    per_family = _build_per_family(in_scope_entries, tagged_evidence_by_family)

    return CrmSuspicionReport(
        workbook_id=workbook_id,
        crm_baseline_id=crm_baseline_id,
        computed_at=computed_at or datetime.now(timezone.utc),
        heuristic_score=heuristic_score,
        ml_anomaly_score=ml_anomaly_score,
        narrative_quality_score=narrative_quality_score,
        overall_suspicion=overall,
        flags=tuple(flags),
        per_family=per_family,
        n_corpus=n_corpus,
        feature_vector=feature_vector,
    )
