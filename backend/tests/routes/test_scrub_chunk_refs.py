"""v2.0.6 — narrative OUTPUT scrub of internal "chunk <n>" jargon.

The evidence-bundle prompt header intentionally keeps a ``chunk <n>`` fallback
locator (model input / tagging / scoring stay byte-identical). The model
sometimes echoes it into the verdict narrative, where "chunk 4" is meaningless
to an assessor / 3PAO. ``_scrub_chunk_refs`` removes it from the finalized
narrative TEXT ONLY, right before the decision is returned/persisted. These
tests pin: jargon removed, sentence stays clean, and chunk-free text is a
byte-identical no-op (so it can never alter a legitimate narrative).
"""

from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor.routes.controls import _scrub_chunk_refs  # noqa: E402


def test_scrubs_midsentence_chunk_ref():
    out = _scrub_chunk_refs(
        "Examined USD00015199 chunk 4; the E-CCM Plan lists Appendix E."
    )
    assert "chunk" not in out
    assert out == "Examined USD00015199; the E-CCM Plan lists Appendix E."


def test_scrubs_chunk_between_two_evidence_refs():
    out = _scrub_chunk_refs("Verified via CTP-026 chunk 3 and CTP-022 vault.")
    assert "chunk" not in out
    assert out == "Verified via CTP-026 and CTP-022 vault."


def test_scrubs_comma_wrapped_chunk_without_double_comma():
    out = _scrub_chunk_refs("Examined the SSP, chunk 12, which defines flows.")
    assert "chunk" not in out
    assert ",," not in out
    assert out == "Examined the SSP, which defines flows."


def test_scrubs_trailing_chunk_before_period():
    out = _scrub_chunk_refs("The control is documented in chunk 2.")
    assert "chunk" not in out
    assert out.endswith("documented.")


def test_noop_on_chunkless_narrative_is_byte_identical():
    """The load-bearing safety property: a narrative that never says 'chunk' is
    returned UNCHANGED — the scrub can never corrupt a legitimate verdict."""
    original = (
        "The information system enforces AC-3 access control; examined the RHEL 8 "
        "STIG OSCAP report (SV-230357r1017169) which passed on paas-vdi-01."
    )
    assert _scrub_chunk_refs(original) == original


def test_noop_on_none_and_empty():
    assert _scrub_chunk_refs(None) is None
    assert _scrub_chunk_refs("") == ""


def test_does_not_touch_word_containing_chunk_substring():
    # "chunked" / "chunking" are not the "chunk <n>" token — must survive.
    txt = "The data was chunked for streaming; no chunk index appears here."
    out = _scrub_chunk_refs(txt)
    assert "chunked" in out
