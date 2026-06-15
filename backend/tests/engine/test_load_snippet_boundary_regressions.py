"""Regression tests for ``engine/evidence_bundle._load_snippet`` boundary.

Pins one real bug surfaced by the edge-case probe:

  **Truncation bloated tiny over-limit files.** With
  ``PER_ARTIFACT_CHARS=3000`` (HEAD=2000 + TAIL=1000), a file of exactly
  3001 chars went through the head/marker/tail construction and came out
  ~3027 chars — LONGER than the input. The whole point of the budget is
  to *shrink* the LLM prompt; padding it is the opposite. Fix: if the
  formatted output isn't strictly shorter than ``raw``, return ``raw``.

The existing tests in ``test_evidence_bundle.py`` cover the obvious
cases (well under / well over the limit). This file pins the boundary
slice they missed.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from types import SimpleNamespace

from cybersecurity_assessor.engine.evidence_bundle import (  # noqa: E402
    HEAD_CHARS,
    MATCH_CONTEXT_CHARS,
    PER_ARTIFACT_CHARS,
    TAIL_CHARS,
    _anchors_from_tag,
    _load_snippet,
)


def test_at_budget_returns_raw_no_marker(tmp_path):
    """Exactly PER_ARTIFACT_CHARS → no truncation path runs, no marker."""
    p = tmp_path / "at_budget.txt"
    raw = "a" * PER_ARTIFACT_CHARS
    p.write_text(raw, encoding="utf-8")
    out = _load_snippet(str(p))
    assert out == raw
    assert "[truncated" not in out


def test_one_over_budget_does_not_bloat(tmp_path):
    """PER_ARTIFACT_CHARS+1 → output must NEVER be longer than raw.

    Pre-fix: HEAD(2000)+marker(~27)+TAIL(1000) = ~3027 > 3001. The
    truncation actively grew the file. Post-fix: return raw whenever
    truncation isn't actually shorter.
    """
    p = tmp_path / "one_over.txt"
    raw_len = PER_ARTIFACT_CHARS + 1
    p.write_text("a" * raw_len, encoding="utf-8")
    out = _load_snippet(str(p))
    assert len(out) <= raw_len, (
        f"snippet bloated past raw size: len(out)={len(out)} raw={raw_len}"
    )


def test_just_over_budget_until_truncation_pays_off(tmp_path):
    """Across the whole 'truncation would bloat' band, output stays ≤ raw.

    The marker text varies in length (``[truncated N chars]`` where N is
    the skipped count), so the break-even point depends on raw length.
    Walk a window past PER_ARTIFACT_CHARS large enough to cross the
    break-even and confirm the guard holds at every size.
    """
    for delta in range(1, 200):
        raw_len = PER_ARTIFACT_CHARS + delta
        p = tmp_path / f"raw_{delta}.txt"
        p.write_text("a" * raw_len, encoding="utf-8")
        out = _load_snippet(str(p))
        assert len(out) <= raw_len, (
            f"bloat at delta={delta}: out={len(out)} raw={raw_len}"
        )


def test_clearly_oversized_still_truncates(tmp_path):
    """A file 4× the budget must still produce a truncation marker.

    Sanity check: the boundary guard must not silently swallow real
    over-budget cases. Pre-fix, marker would always appear. Post-fix
    we want it to appear whenever it can actually shrink the file.
    """
    p = tmp_path / "big.txt"
    raw_len = PER_ARTIFACT_CHARS * 4
    p.write_text("a" * raw_len, encoding="utf-8")
    out = _load_snippet(str(p))
    assert "[truncated" in out
    assert len(out) < raw_len


def test_truncation_preserves_head_and_tail(tmp_path):
    """When truncation does run, head + tail markers from the raw file
    survive — boundary fix must not break the head/tail contract."""
    head = "H" * HEAD_CHARS
    middle = "M" * (PER_ARTIFACT_CHARS * 2)
    tail = "T" * TAIL_CHARS
    raw = head + middle + tail
    p = tmp_path / "ht.txt"
    p.write_text(raw, encoding="utf-8")
    out = _load_snippet(str(p))
    assert "[truncated" in out
    assert head in out
    assert tail in out
    assert "M" * (PER_ARTIFACT_CHARS * 2) not in out


def test_missing_path_returns_placeholder():
    """Path=None must still return the canonical unavailable marker."""
    assert _load_snippet(None) == "(extracted text unavailable)"


def test_nonexistent_path_returns_placeholder(tmp_path):
    ghost = tmp_path / "does_not_exist.txt"
    assert _load_snippet(str(ghost)) == "(extracted text unavailable)"


# ---------------------------------------------------------------------------
# Fix #6 — anchor-aware truncation (the head/tail blindspot)
# ---------------------------------------------------------------------------
#
# Pre-fix, an over-budget file was sliced to HEAD + TAIL and the whole middle
# was thrown away. If the token the tagger matched on (a CCI id, control id,
# or doc number) lived in that middle, the LLM never saw the passage that
# justified the tag — the evidence was tagged but invisible. The fix carves
# a context window around the first matched anchor in the dropped middle.


def _over_budget_with_anchor_in_middle(anchor: str) -> str:
    """Build a raw string > PER_ARTIFACT_CHARS with ``anchor`` squarely in the
    dropped middle (positions [HEAD_CHARS, len-TAIL_CHARS))."""
    head = "a" * HEAD_CHARS  # 0 .. HEAD_CHARS
    mid_pre = "m" * 2000
    mid_post = "m" * 2000
    tail = "z" * TAIL_CHARS
    raw = head + mid_pre + anchor + mid_post + tail
    # Sanity: anchor really is in the middle band, not head or tail.
    idx = raw.find(anchor)
    assert HEAD_CHARS <= idx < len(raw) - TAIL_CHARS
    return raw


def test_anchor_in_middle_invisible_without_anchors(tmp_path):
    """The blindspot itself: matched token in the middle is dropped by plain
    head/tail truncation. This is the bug the fix exists to close."""
    raw = _over_budget_with_anchor_in_middle("CCI-000074")
    p = tmp_path / "blind.txt"
    p.write_text(raw, encoding="utf-8")

    out = _load_snippet(str(p))  # no anchors → legacy behavior
    assert "[truncated" in out
    assert "CCI-000074" not in out


def test_anchor_in_middle_recovered_with_anchors(tmp_path):
    """Passing the matched anchor splices a window around it back in."""
    raw = _over_budget_with_anchor_in_middle("CCI-000074")
    p = tmp_path / "recovered.txt"
    p.write_text(raw, encoding="utf-8")

    out = _load_snippet(str(p), anchors=["CCI-000074"])
    assert "CCI-000074" in out
    # Head and tail survive — the window is spliced *between* them.
    assert raw[:HEAD_CHARS] in out
    assert raw[-TAIL_CHARS:] in out
    # Still a genuine shrink, not the whole file.
    assert len(out) < len(raw)
    assert "[truncated" in out


def test_anchor_window_is_bounded(tmp_path):
    """The recovered window is ~MATCH_CONTEXT_CHARS, not the entire middle."""
    raw = _over_budget_with_anchor_in_middle("CCI-000074")
    p = tmp_path / "bounded.txt"
    p.write_text(raw, encoding="utf-8")

    out = _load_snippet(str(p), anchors=["CCI-000074"])
    # Output ≈ HEAD + window + TAIL + marker overhead. Give generous slack
    # for the two markers but prove we did NOT keep all 4000 middle chars.
    assert len(out) < HEAD_CHARS + TAIL_CHARS + MATCH_CONTEXT_CHARS + 200


def test_anchor_in_head_falls_back_to_plain_truncation(tmp_path):
    """An anchor already inside the head is visible anyway → no extra window,
    output byte-identical to the no-anchor path."""
    anchor = "CCI-000074"
    raw = "a" * 100 + anchor + "a" * 1900 + "m" * 3000 + "z" * TAIL_CHARS
    p = tmp_path / "head_anchor.txt"
    p.write_text(raw, encoding="utf-8")

    with_anchor = _load_snippet(str(p), anchors=[anchor])
    without = _load_snippet(str(p))
    assert with_anchor == without
    # And it's present because it lives in the retained head.
    assert anchor in with_anchor


def test_absent_anchor_falls_back_to_plain_truncation(tmp_path):
    """Anchor not in the file at all → byte-identical to head/tail path."""
    raw = "a" * HEAD_CHARS + "m" * 4000 + "z" * TAIL_CHARS
    p = tmp_path / "absent.txt"
    p.write_text(raw, encoding="utf-8")

    with_anchor = _load_snippet(str(p), anchors=["CCI-999999"])
    without = _load_snippet(str(p))
    assert with_anchor == without
    assert "CCI-999999" not in with_anchor


def test_earliest_middle_anchor_wins(tmp_path):
    """When several anchors land in the middle, the window centers on the
    earliest occurrence regardless of list order."""
    head = "a" * HEAD_CHARS
    early = "CM-8"
    late = "CCI-000074"
    raw = head + "m" * 500 + early + "m" * 2000 + late + "m" * 500 + "z" * TAIL_CHARS
    p = tmp_path / "two_anchors.txt"
    p.write_text(raw, encoding="utf-8")

    # List order puts the LATER token first; position must still win.
    out = _load_snippet(str(p), anchors=[late, early])
    assert early in out
    # The later anchor is ~2000 chars further on, outside one 800-char window.
    assert late not in out


def test_anchor_under_budget_returns_raw(tmp_path):
    """Anchors are irrelevant for files within budget — full text returned."""
    raw = "a" * 100 + "CCI-000074" + "a" * 100
    p = tmp_path / "small.txt"
    p.write_text(raw, encoding="utf-8")
    assert _load_snippet(str(p), anchors=["CCI-000074"]) == raw


# ---------------------------------------------------------------------------
# _anchors_from_tag — token extraction from a tag's rationale
# ---------------------------------------------------------------------------


def test_anchors_from_tag_extracts_cci():
    tag = SimpleNamespace(
        rationale="Direct CCI reference (CCI-000074) found in evidence."
    )
    assert _anchors_from_tag(tag) == ["CCI-000074"]


def test_anchors_from_tag_extracts_control_id():
    tag = SimpleNamespace(
        rationale="Control ID CM-8 referenced in evidence text (text relevance 0.42)."
    )
    assert _anchors_from_tag(tag) == ["CM-8"]


def test_anchors_from_tag_extracts_doc_number():
    tag = SimpleNamespace(
        rationale="Doc number USD00050010 cited in objective guidance/procedures."
    )
    assert _anchors_from_tag(tag) == ["USD00050010"]


def test_anchors_from_tag_tier4_has_no_token():
    """Tier-4 evidence-type rationale describes content shape, not a keyword."""
    tag = SimpleNamespace(
        rationale="Evidence type 'hw_inventory' maps to control by content shape."
    )
    assert _anchors_from_tag(tag) == []


def test_anchors_from_tag_handles_missing_rationale():
    assert _anchors_from_tag(SimpleNamespace(rationale=None)) == []
    assert _anchors_from_tag(SimpleNamespace(rationale="")) == []
    assert _anchors_from_tag(SimpleNamespace()) == []


def test_anchors_from_tag_dedupes_preserving_order():
    tag = SimpleNamespace(
        rationale="CM-8 ... CM-8 again, and CCI-000074, then CM-8 once more."
    )
    assert _anchors_from_tag(tag) == ["CM-8", "CCI-000074"]
