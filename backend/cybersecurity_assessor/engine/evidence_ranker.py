"""Token-budget evidence ranker — the replacement for the fixed-N cap.

Background
----------
The old bundle truncated tagged evidence to a hard ``MAX_ARTIFACTS = 6``
(``evidence_bundle.py``): it sorted by ``(relevance, confidence)`` then did
``rows = rows[:6]``. For an enterprise control with 30-50+ tagged artifacts
that silently discarded artifacts 7..N — they never reached the model AND
never reached the ``AssessmentEvidenceShown`` audit trail. A 3PAO/JAB
reviewer asking "what did you examine for AC-2?" would get an answer that
omitted 80% of the evidence with no record that anything was dropped. That
is the precise failure mode this module exists to eliminate: **silent drops
are unacceptable — anything not examined must be traceable.**

What this module does
---------------------
:func:`rank_artifacts` takes the full ``(EvidenceTag, Evidence)`` set for one
objective and partitions it — never truncates — into two lists:

* ``examined``  — admitted under the token budget, highest ``(relevance,
  confidence)`` first. These are rendered into the prompt AND recorded as
  ``disposition="examined"`` audit rows.
* ``deferred``  — everything over budget. These are NOT sent to the model,
  but they ARE recorded as ``disposition="deferred"`` audit rows with a
  ``deferred_reason`` so the reviewer can see exactly what was held back and
  why. Nothing is dropped.

The budget is deliberately generous (~120k tokens) because cost is **not** a
constraint for this work — the goal is to examine everything an enterprise
control accumulates. Deferral is therefore the rare-pathological path (a
control with hundreds of artifacts), and :func:`classify_overflow` decides
what to do when it happens: finalize on the examined set when the deferred
tail is pure low-relevance corroboration, otherwise escalate so the verdict
is never quietly based on a subset.

No external token library
-------------------------
There is no ``tiktoken`` in the runtime (frozen-bundle / no-network
constraint). Token estimation is the standard ~4-chars-per-token heuristic,
which is conservative enough for budgeting: it over-counts pure-ASCII prose
slightly, so we err toward examining fewer-than-possible rather than
overflowing the real context window.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..models import Evidence, EvidenceTag

# ~4 chars/token is the long-standing rule of thumb for English prose with a
# GPT/Claude BPE tokenizer. We round UP (ceil) so a tiny artifact never
# estimates as 0 tokens.
CHARS_PER_TOKEN = 4

# Generous default: at ~750 tokens per 3000-char artifact this admits ~160
# artifacts before deferral — well past the 30-50 an enterprise control
# accumulates — while staying clear of the model's 200k context ceiling once
# the system prompt + row + corroboration sections are added. Cost is not a
# constraint here; the budget exists only to bound a pathological long tail,
# not to ration normal evidence.
DEFAULT_TOKEN_BUDGET = 120_000

# Disposition + reason string constants. Exposed so the bundle, the audit
# payload, the route persistence loop, and the test suite all agree on the
# exact literals without re-typing them (a typo'd "examined " would silently
# break the SAR coverage join).
DISPOSITION_EXAMINED = "examined"
DISPOSITION_DEFERRED = "deferred"
REASON_TOKEN_BUDGET = "token-budget-exceeded"

# Diagram de-weight (Finding #15, 2026-06-10). Network/architecture diagrams
# are STALE, existence-only evidence per assessor doctrine: they prove a thing
# was drawn, not that it is currently implemented. Scans, configs, and asset
# inventories reflect actual deployed state and must lead an evidence bundle
# ahead of any diagram. We therefore multiply a diagram's RANKING score (not
# its stored tag.relevance, not its presence) by this factor so it sorts below
# equally-relevant live evidence. ORDERING ONLY — diagrams remain in the
# bundle as existence evidence and are never dropped (precision over recall:
# de-rank, do not discard).
DIAGRAM_RANK_MULTIPLIER = 0.5


def _is_diagram(evidence: "Evidence") -> bool:
    """True when an Evidence row is a network/architecture diagram.

    Diagrams enter the system as boundary docs flagged by the assessor; the
    free-text :attr:`Evidence.boundary_doc_kind` carries the human label
    ("Network Diagram", "Architecture Diagram", "SSP", "ATO Letter", ...).
    We match the substring "diagram" case-insensitively — the same loose,
    label-driven matching the boundary-docs adapter uses — so any diagram
    variant is caught without enumerating every program's naming. Defensive
    against None (most Evidence rows are not boundary docs and carry no kind).
    """
    label = getattr(evidence, "boundary_doc_kind", None)
    return bool(label) and "diagram" in label.lower()


def _rank_score(tag: "EvidenceTag", evidence: "Evidence") -> float:
    """The ordering score for a (tag, evidence) pair: tag relevance, de-weighted
    for diagrams.

    Diagrams = stale existence-only evidence, ranked below live scans/configs
    /inventories (Finding #15). The multiplier touches ORDERING only; the
    persisted ``EvidenceTag.relevance`` is unchanged, so the Controls UI and
    the audit trail still show the artifact's intrinsic relevance.
    """
    if _is_diagram(evidence):
        return tag.relevance * DIAGRAM_RANK_MULTIPLIER
    return tag.relevance


def estimate_tokens(text: str | None) -> int:
    """Conservative token estimate for ``text`` (ceil of chars/4).

    Returns 0 for empty/None. Always >=1 for any non-empty string so a
    one-character artifact still consumes budget.
    """
    if not text:
        return 0
    return max(1, -(-len(text) // CHARS_PER_TOKEN))  # ceil division


@dataclass(frozen=True)
class RankerConfig:
    """Tunables for :func:`rank_artifacts` / :func:`classify_overflow`.

    ``token_budget`` is the sum-of-snippets ceiling for the examined set.
    ``corroboration_floor`` is the relevance at/under which a *deferred*
    artifact is considered low-signal corroboration — the overflow
    classifier finalizes on the examined set only when every deferred
    artifact sits at/under this floor (strong evidence was examined; the
    held-back tail is recorded but non-decisive).
    """

    token_budget: int = DEFAULT_TOKEN_BUDGET
    corroboration_floor: float = 0.35


@dataclass
class RankedArtifact:
    """One ``(tag, evidence)`` pair with its ranking + budgeting verdict.

    ``snippet`` is the head/tail-truncated text exactly as it would be shown
    to the model (loaded once here so the caller never re-reads the file).
    ``rank_score`` is the primary ordering signal (the tag relevance);
    ``confidence`` is the secondary tiebreak, denormalized for the audit
    record. ``disposition`` is :data:`DISPOSITION_EXAMINED` or
    :data:`DISPOSITION_DEFERRED`; ``deferred_reason`` is set only on
    deferred artifacts.
    """

    tag: "EvidenceTag"
    evidence: "Evidence"
    snippet: str
    order_index: int
    rank_score: float
    confidence: float
    est_tokens: int
    disposition: str
    deferred_reason: str | None = None


@dataclass
class RankingResult:
    """Total partition of one objective's tagged evidence.

    ``examined + deferred`` always equals the full candidate set — the
    invariant the test suite asserts to prove no artifact is silently
    dropped. ``tokens_examined`` is the realized budget consumption.
    """

    examined: list[RankedArtifact]
    deferred: list[RankedArtifact]
    tokens_examined: int
    token_budget: int
    total_candidates: int

    @property
    def has_overflow(self) -> bool:
        return bool(self.deferred)


def rank_artifacts(
    pairs: Sequence[tuple["EvidenceTag", "Evidence"]],
    *,
    load_snippet: Callable[["Evidence"], str],
    config: RankerConfig | None = None,
) -> RankingResult:
    """Partition ``pairs`` into examined/deferred under the token budget.

    Ordering is ``(relevance, confidence)`` descending — byte-identical to
    the old ``rows.sort(...)`` so, under a generous budget, the examined
    prefix matches the historical top-N exactly (no behavioral surprise for
    the common case). Greedy admission: walk highest-ranked first, admit
    while the running snippet-token sum stays within budget, defer the rest.

    Guaranteed non-empty examined set when ``pairs`` is non-empty: the single
    top-ranked artifact is always admitted even if it alone exceeds the
    budget. A control whose top artifact is a giant file must still be
    assessed — never deferred wholesale into needs_review with an empty
    prompt. Its oversize is surfaced to :func:`classify_overflow` via the
    remaining deferred tail (if any).
    """
    cfg = config or RankerConfig()
    # Sort by the de-weighted ranking score (diagrams ranked below equally-
    # relevant live evidence — Finding #15), then confidence as the secondary
    # tiebreak. ``_rank_score`` returns the raw tag.relevance for non-diagrams
    # so, with no diagrams present, this ordering is byte-identical to the
    # historical ``(relevance, confidence)`` sort.
    ordered = sorted(
        pairs,
        key=lambda pair: (_rank_score(pair[0], pair[1]), pair[0].confidence),
        reverse=True,
    )

    examined: list[RankedArtifact] = []
    deferred: list[RankedArtifact] = []
    tokens_used = 0

    for tag, ev in ordered:
        snippet = load_snippet(ev)
        est = estimate_tokens(snippet)
        fits = (tokens_used + est) <= cfg.token_budget
        # rank_score is the de-weighted ordering value (diagrams halved —
        # Finding #15). Storing the de-weighted value (not the raw
        # tag.relevance) keeps the audit row consistent with the sort order AND
        # makes classify_overflow treat a de-ranked diagram as the low-signal
        # corroboration it is: a diagram whose halved score lands at/under
        # corroboration_floor no longer forces an escalation by itself.
        score = _rank_score(tag, ev)
        # Admit if it fits, or if nothing has been admitted yet (never emit
        # an empty examined set when evidence exists).
        if fits or not examined:
            examined.append(
                RankedArtifact(
                    tag=tag,
                    evidence=ev,
                    snippet=snippet,
                    order_index=len(examined),
                    rank_score=score,
                    confidence=tag.confidence,
                    est_tokens=est,
                    disposition=DISPOSITION_EXAMINED,
                    deferred_reason=None,
                )
            )
            tokens_used += est
        else:
            deferred.append(
                RankedArtifact(
                    tag=tag,
                    evidence=ev,
                    snippet=snippet,
                    # Deferred order_index continues after the examined block
                    # so audit rows sort in a single stable sequence.
                    order_index=len(examined) + len(deferred),
                    rank_score=score,
                    confidence=tag.confidence,
                    est_tokens=est,
                    disposition=DISPOSITION_DEFERRED,
                    deferred_reason=REASON_TOKEN_BUDGET,
                )
            )

    return RankingResult(
        examined=examined,
        deferred=deferred,
        tokens_examined=tokens_used,
        token_budget=cfg.token_budget,
        total_candidates=len(ordered),
    )


# Overflow strategy constants — the three outcomes of classify_overflow.
OVERFLOW_NONE = "none"
OVERFLOW_FINALIZE_ON_EXAMINED = "finalize_on_examined"
OVERFLOW_ESCALATE = "escalate"


@dataclass(frozen=True)
class OverflowDecision:
    """What to do about a ranking that deferred one or more artifacts.

    * ``none``                 — nothing deferred; assess normally.
    * ``finalize_on_examined`` — deferred tail is all low-relevance
      corroboration (<= ``corroboration_floor``); the examined set carries
      the decision. The tail is still recorded as deferred audit rows.
    * ``escalate``             — high-relevance artifacts were deferred; the
      verdict cannot rest on a subset of decisive evidence. The caller routes
      the control to needs_review (status withheld) rather than silently
      finalizing — precision over recall.

    ``reason`` is a human-readable triage line that flows into the
    needs_review ``review_reason`` / SAR appendix verbatim.
    """

    strategy: str
    reason: str
    deferred_count: int


def classify_overflow(
    result: RankingResult, *, config: RankerConfig | None = None
) -> OverflowDecision:
    """Decide how to handle a ranking's deferred tail (if any).

    Finalize-on-examined fires only when EVERY deferred artifact is at or
    under the corroboration floor — i.e. low-signal supporting material. If
    any deferred artifact is high-relevance, we must not pretend the examined
    subset is the whole picture: the decision escalates to needs_review so a
    human sees that decisive evidence exceeded the budget.
    """
    cfg = config or RankerConfig()
    if not result.deferred:
        return OverflowDecision(OVERFLOW_NONE, "all artifacts examined", 0)

    n = len(result.deferred)
    all_corroboration = all(
        a.rank_score <= cfg.corroboration_floor for a in result.deferred
    )
    if all_corroboration:
        return OverflowDecision(
            OVERFLOW_FINALIZE_ON_EXAMINED,
            (
                f"{n} deferred artifact(s) are corroboration-only "
                f"(relevance <= {cfg.corroboration_floor:.2f}); "
                f"{len(result.examined)} higher-relevance artifact(s) examined"
            ),
            n,
        )
    return OverflowDecision(
        OVERFLOW_ESCALATE,
        (
            f"{n} high-relevance artifact(s) exceeded the {result.token_budget}-token "
            f"evidence budget after examining {len(result.examined)}; "
            f"verdict withheld so decisive evidence is not silently excluded"
        ),
        n,
    )
