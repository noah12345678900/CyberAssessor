"""Unsupervised CRM anomaly detection via IsolationForest.

The ML layer of the three-tier CRM suspicion scoring (see
:mod:`crm_sanity`). Heuristics fire on the FIRST CRM the assessor ever
uploads; IsolationForest only contributes once we have ``n_corpus >= 10``
historical CRMs to train against.

Why IsolationForest and not a one-class SVM / autoencoder / proper
classifier?

* Unsupervised — we have no "this CRM lied" labels yet (that corpus
  builds via :attr:`CrmSuspicionLog.assessor_marked_false_positive`).
* Robust to small corpora — works at n=10 where a deep model wouldn't.
* Cheap to retrain — a typical CRM corpus stays in the hundreds; refit
  is sub-second on commodity hardware. Operator runs
  ``scripts/refit_crm_anomaly_model.py`` after a batch of new CRMs is
  ingested.
* Output is a continuous anomaly score we can normalize to ``[0, 1]``
  and blend with the heuristic/embedding signals.

Schema versioning — :data:`CURRENT_FEATURE_SCHEMA_VERSION` is the
load-bearing piece. Bumping it means old :class:`CrmCorpusFeatures` rows
no longer match new ones, so refit naturally skips stale rows. They're
preserved (not deleted) for diagnostics, but the trained model fits only
on current-version vectors.

This module is session-free. The route handler (:mod:`routes.baselines`)
extracts inputs from the session, calls :func:`extract_features`,
queries the corpus rows + active model blob, and threads everything
through :func:`score_anomaly`.
"""

from __future__ import annotations

import io
import json
import statistics
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import ClassVar

from .crm_context import CrmContext
from .narrative_embeddings import TfidfFallbackProvider

# ---------------------------------------------------------------------------
# Schema version — bump when CrmFeatureVector field set or semantics change.
# Any persisted CrmCorpusFeatures row with feature_schema_version != this
# value is ignored at fit time and at score time.
# ---------------------------------------------------------------------------

CURRENT_FEATURE_SCHEMA_VERSION = 1

# Minimum corpus size to fit IsolationForest. Below this, the model would
# learn essentially nothing — every point is its own outlier. Plan section B5
# pins this at 10 as the cold-start threshold.
MIN_CORPUS_SIZE = 10


# ---------------------------------------------------------------------------
# Feature vector
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CrmFeatureVector:
    """Per-CRM feature vector for IsolationForest.

    All ratio fields are in ``[0, 1]``. Counts (``family_evidence_contradictions``,
    ``in_scope_control_count``) are left as raw integers — IsolationForest
    is scale-sensitive but a single scaler trained at fit time normalizes
    them; we don't pre-scale in the dataclass because that would lose
    interpretability when these rows are inspected manually.

    Field rationale:

    * ``inherited_pct`` / ``provider_pct`` / ``not_applicable_pct`` —
      the "wall of off-loaded controls" signal. A CRM where 95% of
      controls are inherited is suspicious *relative to the corpus*; a
      pure-SaaS CRM legitimately inheriting 90% of NIST IR controls is
      not. IsolationForest learns the corpus distribution and flags
      deviations.
    * ``narrative_present_pct`` — proportion of inherited/provider rows
      that supplied SOME narrative, even if short. Counterpart to
      narrative_poverty heuristic but as a continuous signal.
    * ``narrative_len_mean`` / ``narrative_len_stdev`` — distinguishes
      a CRM with one boilerplate paragraph copy-pasted everywhere
      (low stdev, low mean) from a thorough one (high stdev as
      narratives vary in length).
    * ``intra_crm_tfidf_max_similarity`` / ``intra_crm_tfidf_mean_similarity``
      — within-CRM boilerplate density. A CRM where every narrative is
      ~0.9 cosine-similar to every other narrative is the "vendor copied
      one paragraph to all 500 controls" anti-pattern.
    * ``family_evidence_contradictions`` — count of control families
      claimed inherited/provider but where the workbook has locally
      tagged evidence on that family. Hard signal of "CRM doesn't match
      observed reality."
    * ``in_scope_control_count`` — coarse size feature; small CRMs vary
      more naturally than large ones, IsolationForest accounts for that
      via the contamination parameter.
    """

    schema_version: int
    inherited_pct: float
    provider_pct: float
    not_applicable_pct: float
    narrative_present_pct: float
    narrative_len_mean: float
    narrative_len_stdev: float
    intra_crm_tfidf_max_similarity: float
    intra_crm_tfidf_mean_similarity: float
    family_evidence_contradictions: int
    in_scope_control_count: int

    # Order of fields when serialized to the numpy row for sklearn.
    # MUST match the order learned by the trained model — bumping
    # CURRENT_FEATURE_SCHEMA_VERSION whenever this list changes is the
    # invariant that keeps old model blobs from being mis-applied.
    _NUMERIC_FIELDS: ClassVar[tuple[str, ...]] = (
        "inherited_pct",
        "provider_pct",
        "not_applicable_pct",
        "narrative_present_pct",
        "narrative_len_mean",
        "narrative_len_stdev",
        "intra_crm_tfidf_max_similarity",
        "intra_crm_tfidf_mean_similarity",
        "family_evidence_contradictions",
        "in_scope_control_count",
    )

    def to_row(self) -> list[float]:
        """Convert to the dense numeric row IsolationForest consumes."""
        return [float(getattr(self, name)) for name in self._NUMERIC_FIELDS]

    def to_json(self) -> str:
        """JSON serialization for ``CrmCorpusFeatures.features_json``."""
        return json.dumps(asdict(self), separators=(",", ":"))

    @classmethod
    def from_json(cls, payload: str) -> CrmFeatureVector:
        data = json.loads(payload)
        return cls(**data)


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------


def _family_of(control_id: str) -> str:
    """Return the 2-letter NIST family token from a canonical control_id.

    ``ac-2.1`` -> ``ac``; ``ia-5`` -> ``ia``. Defensive against malformed
    ids — falls back to empty string so downstream set comparison still
    works (an empty-family CRM entry simply won't match any evidence
    family bucket and therefore won't trigger the contradiction count).
    """
    if not control_id:
        return ""
    head = control_id.split("-", 1)[0]
    return head.lower()


def extract_features(
    crm_context: CrmContext,
    in_scope_control_ids: Sequence[str],
    tagged_evidence_by_family: dict[str, int],
) -> CrmFeatureVector:
    """Build the feature vector for one CRM.

    ``in_scope_control_ids`` comes from
    :attr:`BoundaryFingerprint.in_scope_control_ids` so we measure
    inheritance percentages against what's actually in scope for this
    workbook — not against the full catalog (FedRAMP High has 400+
    controls; a 200-control workbook claiming "200 inherited" is 100%,
    not 50%).

    ``tagged_evidence_by_family`` is the counted output of an
    ``EvidenceTag``-by-family GROUP BY: ``{"ac": 14, "ia": 6, ...}``.
    Used to detect the "CRM claims family X is inherited but we have
    locally-tagged evidence for family X" contradiction.
    """
    # Restrict CRM entries to in-scope controls only — out-of-scope CRM
    # entries are noise (e.g. a CRM mass-uploaded across all FedRAMP
    # families but only AC/IA/CM are in scope for this workbook).
    scope = set(in_scope_control_ids)
    in_scope_entries = [
        entry
        for control_id, entry in crm_context.by_control.items()
        if control_id in scope
    ]
    n_scope = len(scope)

    def _pct(responsibility: str) -> float:
        if n_scope == 0:
            return 0.0
        count = sum(1 for e in in_scope_entries if e.responsibility == responsibility)
        return count / n_scope

    inherited_pct = _pct("inherited")
    provider_pct = _pct("provider")
    not_applicable_pct = _pct("not_applicable")

    # Narrative presence/length stats — restrict to inherited/provider/NA
    # since 'customer' rows are full assessments where empty narrative is
    # expected (the assessor will write one). 'hybrid' is borderline; treat
    # it as a real claim that should be substantiated.
    claim_responsibilities = {"inherited", "provider", "not_applicable", "hybrid"}
    claim_entries = [e for e in in_scope_entries if e.responsibility in claim_responsibilities]
    n_claims = len(claim_entries)
    if n_claims == 0:
        narrative_present_pct = 0.0
        narrative_len_mean = 0.0
        narrative_len_stdev = 0.0
    else:
        present = [e for e in claim_entries if e.narrative and e.narrative.strip()]
        narrative_present_pct = len(present) / n_claims
        if len(present) >= 1:
            lengths = [len(e.narrative or "") for e in present]
            narrative_len_mean = float(statistics.fmean(lengths))
            narrative_len_stdev = (
                float(statistics.stdev(lengths)) if len(lengths) > 1 else 0.0
            )
        else:
            narrative_len_mean = 0.0
            narrative_len_stdev = 0.0

    # Intra-CRM narrative similarity — vectorize all present narratives with
    # TF-IDF, compute pairwise cosine, take max/mean of off-diagonal entries.
    # Re-uses TfidfFallbackProvider just for its TF-IDF vectorizer so we
    # don't double-import sklearn.
    present_narratives = [
        (e.narrative or "").strip()
        for e in claim_entries
        if (e.narrative or "").strip()
    ]
    if len(present_narratives) >= 2:
        max_sim, mean_sim = _intra_corpus_similarity(present_narratives)
    else:
        max_sim, mean_sim = 0.0, 0.0

    # Family contradiction count: families fully inheritied/provider AND
    # workbook has any tagged evidence on that family.
    family_claims: dict[str, set[str]] = {}
    for entry in in_scope_entries:
        fam = _family_of(entry.control_id)
        if not fam:
            continue
        family_claims.setdefault(fam, set()).add(entry.responsibility)
    contradictions = 0
    for fam, resps in family_claims.items():
        # Family is "fully claimed off-loaded" iff every CRM row for it is
        # inherited/provider/NA. Mixed families (some customer) don't count.
        off_loaded = {"inherited", "provider", "not_applicable"}
        if resps and resps.issubset(off_loaded):
            if tagged_evidence_by_family.get(fam, 0) > 0:
                contradictions += 1

    return CrmFeatureVector(
        schema_version=CURRENT_FEATURE_SCHEMA_VERSION,
        inherited_pct=inherited_pct,
        provider_pct=provider_pct,
        not_applicable_pct=not_applicable_pct,
        narrative_present_pct=narrative_present_pct,
        narrative_len_mean=narrative_len_mean,
        narrative_len_stdev=narrative_len_stdev,
        intra_crm_tfidf_max_similarity=max_sim,
        intra_crm_tfidf_mean_similarity=mean_sim,
        family_evidence_contradictions=contradictions,
        in_scope_control_count=n_scope,
    )


def _intra_corpus_similarity(texts: list[str]) -> tuple[float, float]:
    """Max + mean off-diagonal cosine similarity for a TF-IDF matrix.

    Uses sklearn's vectorizer for consistency with
    :class:`TfidfFallbackProvider`. Off-diagonal only — a narrative is
    trivially 1.0 similar to itself, which would inflate both stats.
    """
    # Lazy import; sklearn is a runtime dep but we don't want narrative
    # imports to drag it in at module load time for unrelated tests.
    from sklearn.feature_extraction.text import (  # type: ignore[import-not-found]
        TfidfVectorizer,
    )

    _ = TfidfFallbackProvider  # keep import for docs cross-reference
    vectorizer = TfidfVectorizer(
        lowercase=True, ngram_range=(1, 2), min_df=1, max_df=1.0
    )
    try:
        matrix = vectorizer.fit_transform(texts)
    except ValueError:
        # sklearn raises "empty vocabulary" when every narrative tokenizes
        # to nothing (e.g., a corpus of single-character / pure-stop-word
        # narratives like "0", "a", "."). The boilerplate-similarity
        # signal is undefined in that degenerate case — return the same
        # zero pair we'd return for n<2 rather than faulting the whole
        # feature-extraction pipeline. A real CRM with that shape would
        # already be flagged by narrative_present_pct and narrative_len_*.
        return 0.0, 0.0
    # Cosine similarity = normalized dot product. sklearn returns sparse CSR;
    # use the linear_kernel helper which is equivalent for L2-normalized TF-IDF.
    from sklearn.metrics.pairwise import (  # type: ignore[import-not-found]
        cosine_similarity,
    )

    sim_matrix = cosine_similarity(matrix)
    n = sim_matrix.shape[0]
    if n < 2:
        return 0.0, 0.0
    # Zero the diagonal so we only consider distinct-pair similarities.
    off_diag_values: list[float] = []
    for i in range(n):
        for j in range(n):
            if i != j:
                off_diag_values.append(float(sim_matrix[i, j]))
    if not off_diag_values:
        return 0.0, 0.0
    # Cosine similarity is bounded by [0, 1] for non-negative TF-IDF vectors,
    # but cosine_similarity's normalize+dot can drift ~1e-15 above 1.0 when
    # two narratives are byte-identical (hypothesis caught this with two
    # rows sharing the same provider narrative). Clamp to the documented
    # unit interval so downstream callers — and the property test at
    # tests/engine/test_crm_ml_properties.py — get the invariant they expect.
    max_sim = min(1.0, max(0.0, max(off_diag_values)))
    mean_sim = min(1.0, max(0.0, float(statistics.fmean(off_diag_values))))
    return max_sim, mean_sim


# ---------------------------------------------------------------------------
# IsolationForest fit + score
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FitResult:
    """Output of :func:`fit_anomaly_model`.

    ``metadata`` is suitable for stashing in
    :attr:`CrmAnomalyModel.notes` (joblib model blob is opaque; the
    metadata is the operator-readable record).
    """

    model_blob: bytes
    metadata: dict


def fit_anomaly_model(corpus: Sequence[CrmFeatureVector]) -> FitResult:
    """Fit IsolationForest on a corpus of CrmFeatureVectors.

    Refuses to fit if ``len(corpus) < MIN_CORPUS_SIZE`` — at fewer than
    10 samples the model has no useful structure and would just memorize
    its training set. Refit script callers must check the corpus size
    themselves and either wait for more CRMs or use the heuristic-only
    fallback.

    All vectors must match :data:`CURRENT_FEATURE_SCHEMA_VERSION` — the
    fit script filters before calling us; we re-assert defensively.

    Returns the joblib-pickled model blob ready to store in
    :attr:`CrmAnomalyModel.model_blob` and metadata for ``notes``.
    """
    if len(corpus) < MIN_CORPUS_SIZE:
        raise ValueError(
            f"Cannot fit anomaly model: corpus size {len(corpus)} < "
            f"MIN_CORPUS_SIZE ({MIN_CORPUS_SIZE}). Wait until more CRMs are "
            f"uploaded or use the heuristic-only fallback."
        )
    bad_version = [v for v in corpus if v.schema_version != CURRENT_FEATURE_SCHEMA_VERSION]
    if bad_version:
        raise ValueError(
            f"{len(bad_version)} of {len(corpus)} feature vectors are at the "
            f"wrong schema version. Expected {CURRENT_FEATURE_SCHEMA_VERSION}. "
            f"Filter to the current version before calling fit_anomaly_model."
        )

    # Lazy import — sklearn is a runtime dep but the model load path doesn't
    # need it until refit is actually invoked.
    import joblib  # type: ignore[import-not-found]
    import numpy as np  # type: ignore[import-not-found]
    from sklearn.ensemble import IsolationForest  # type: ignore[import-not-found]
    from sklearn.preprocessing import StandardScaler  # type: ignore[import-not-found]

    rows = np.array([v.to_row() for v in corpus], dtype=float)
    # Standard-scale so the integer count features (contradictions, in_scope
    # count) don't dominate the tree splits over the [0,1] ratio features.
    scaler = StandardScaler()
    scaled = scaler.fit_transform(rows)
    # contamination='auto' (default) lets the model decide its own threshold.
    # n_estimators=200 is overkill for n=10 but cheap at corpus scale and
    # smooths out the score distribution noticeably vs the default 100.
    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
    )
    model.fit(scaled)

    # Bundle the scaler with the model so score time replays the same
    # transform. joblib handles numpy + sklearn objects natively.
    blob_buffer = io.BytesIO()
    joblib.dump({"scaler": scaler, "model": model, "version": CURRENT_FEATURE_SCHEMA_VERSION}, blob_buffer)
    blob = blob_buffer.getvalue()

    # Self-report training-set anomaly score distribution so operator can
    # eyeball the spread before promoting.
    raw_scores = model.score_samples(scaled)
    metadata = {
        "n_samples": len(corpus),
        "feature_schema_version": CURRENT_FEATURE_SCHEMA_VERSION,
        "training_score_min": float(raw_scores.min()),
        "training_score_max": float(raw_scores.max()),
        "training_score_mean": float(raw_scores.mean()),
        "training_score_stdev": (
            float(raw_scores.std()) if len(raw_scores) > 1 else 0.0
        ),
        "n_features": len(CrmFeatureVector._NUMERIC_FIELDS),
    }
    return FitResult(model_blob=blob, metadata=metadata)


def score_anomaly(model_blob: bytes, vector: CrmFeatureVector) -> float:
    """Score a single feature vector against a fitted IsolationForest.

    Returns a value in ``[0, 1]`` where 1.0 = most anomalous.

    sklearn's raw ``score_samples`` returns the negative of the average
    path length, normalized — *lower* means more anomalous, ranges over
    roughly ``[-0.5, 0.0]`` for a typical fit. We invert + clip + scale
    to ``[0, 1]`` so the blend formula in :mod:`crm_sanity` can treat
    all three tier scores symmetrically.

    Returns ``0.0`` if the blob's schema version doesn't match the
    incoming vector — defensive against a stale active model surviving
    a feature schema bump. The route handler interprets 0.0 the same as
    "no ML score available" (caller is expected to check the bundled
    schema versions before relying on the score).
    """
    import joblib  # type: ignore[import-not-found]
    import numpy as np  # type: ignore[import-not-found]

    if vector.schema_version != CURRENT_FEATURE_SCHEMA_VERSION:
        return 0.0

    bundle = joblib.load(io.BytesIO(model_blob))
    if bundle.get("version") != vector.schema_version:
        return 0.0

    scaler = bundle["scaler"]
    model = bundle["model"]
    row = np.array([vector.to_row()], dtype=float)
    scaled = scaler.transform(row)
    raw = float(model.score_samples(scaled)[0])
    # IsolationForest scores: ~0 = inlier, more negative = more anomalous.
    # Empirically the bulk falls in [-0.5, 0]; we squash via 1 - exp(raw)
    # which gives a smooth [0, 1] mapping that doesn't require knowing the
    # corpus-specific spread.
    import math

    anomaly = 1.0 - math.exp(raw)
    if anomaly < 0.0:
        return 0.0
    if anomaly > 1.0:
        return 1.0
    return anomaly
