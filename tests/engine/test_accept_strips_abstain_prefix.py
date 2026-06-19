"""Regression: accepting an abstained control strips the [Needs review] prefix.

When a control abstains, the kernel coerces its column Q to
``[Needs review — llm-abstain]\n\n<text>`` so the reviewer queue shows why.
When the reviewer ACCEPTS the row via POST /api/controls/assessments, the
upsert clears needs_review=False and sets a real status — but it used to
persist ``body.narrative_q`` verbatim, leaving the stale marker in the
trusted narrative (and writing it into the workbook). The accept path now
strips a leading ``[Needs review — …]`` marker.

User-found on AU-9: accepted after abstain, but the saved narrative still
read "[Needs review — llm-abstain] …".
"""

from __future__ import annotations

from cybersecurity_assessor.routes.controls import _strip_abstain_prefix


def test_strips_llm_abstain_prefix():
    n = (
        "[Needs review — llm-abstain]\n\nExamined Audit Information Protection "
        "Memo (USD20240624): Sections 2 and 4 contradict each other."
    )
    out = _strip_abstain_prefix(n)
    assert not out.startswith("[Needs review")
    assert out.startswith("Examined Audit Information Protection Memo")


def test_strips_other_reason_labels():
    for reason in ("validator-exhausted: foo", "llm-parse-error", "no-evidence: bar"):
        n = f"[Needs review — {reason}]\n\nbody text"
        out = _strip_abstain_prefix(n)
        assert out == "body text", f"failed for reason {reason!r}: {out!r}"


def test_noop_on_plain_narrative():
    n = "Examined X; confirmed via Y; documented in USD123."
    assert _strip_abstain_prefix(n) == n


def test_none_safe():
    assert _strip_abstain_prefix(None) is None
    assert _strip_abstain_prefix("") == ""


def test_only_strips_one_leading_marker_not_mid_text():
    # A marker that appears mid-narrative (not at the very start) is left alone.
    n = "Real narrative.\n\n[Needs review — llm-abstain]\n\ntrailing"
    assert _strip_abstain_prefix(n) == n
