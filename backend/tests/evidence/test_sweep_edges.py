"""Edge-case audit tests for the SharePoint boundary-sweep scorer.

These tests pin behaviors discovered during the 2026-06-07 audit of the
``night-shift/sharepoint-boundary-sweep`` branch. Companion to
``test_sweep_scoring.py``; that file pins the happy-path scoring contract,
this one pins the silent-failure surface (token noise, empty boundary,
unicode/case quirks, skip-family veto interactions, multi-signal additive
cap behavior).

Every test uses pure dataclass fingerprints — no DB, no SharePoint. The
goal is to catch regressions in ``score_candidate`` and adjacent pure
helpers at unit-test speed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.evidence.sources.sweep import (  # noqa: E402
    BoundaryFingerprint,
    SCORE_PRECHECK_THRESHOLD,
    SCORE_SURFACE_THRESHOLD,
    _NARRATIVE_STOPWORDS,
    _W_CONTROL_ID,
    _W_CRM_KEYWORD,
    _W_DOC_PREFIX,
    _W_FAMILY,
    _W_HOST,
    _W_PRIORITY_LINK,
    _extract_narrative_tokens,
    _whole_word_in,
    score_candidate,
)


# ---------------------------------------------------------------------------
# 1. Empty boundary — fingerprint with zero signals
# ---------------------------------------------------------------------------


def test_empty_fingerprint_scores_zero():
    """Sweep against a fingerprint with no signals → score 0, no signals.

    The route layer (routes/sharepoint.py:788-815) rejects this with HTTP
    422 BEFORE invoking the scorer, but the pure function must stay safe
    when called directly (tests, future batch scorers, recalibration).
    """
    fp = BoundaryFingerprint()
    score, sigs, ccis = score_candidate(
        "SSP.docx",
        "/Shared Documents/SSP.docx",
        "system security plan",
        fp,
    )
    assert score == 0.0
    assert sigs == []
    assert ccis == []


def test_empty_fingerprint_below_surface_threshold():
    """Belt-and-suspenders — confirm the silent no-op stays below surface.

    If SCORE_SURFACE_THRESHOLD ever drops to 0.0 (someone's debugging) the
    "empty fingerprint surfaces every file" footgun would silently re-open.
    """
    fp = BoundaryFingerprint()
    score, _, _ = score_candidate("anything.pdf", "/a/b.pdf", None, fp)
    assert score < SCORE_SURFACE_THRESHOLD


# ---------------------------------------------------------------------------
# 2. Host-token noise — short / stopword tokens are NOT filtered on intake
# ---------------------------------------------------------------------------


def test_host_token_two_letter_matches_with_word_boundaries():
    """Two-letter host tokens DO match via _whole_word_in word boundaries.

    The LLM extractor in boundary_docs.py emits ``_normalize_token``-cleaned
    tokens but applies no length floor — so a 2-char token like an env
    label (``dr`` for disaster-recovery) lands in host_tokens. The regex
    in _whole_word_in is word-bounded, so the false-positive surface is
    smaller than a naive substring would imply, but the token DOES still
    score 0.40 against any candidate that mentions it standalone.

    Pins this as expected current behavior — if you want a length floor,
    add it in build_boundary_fingerprint and update this assertion.
    """
    fp = BoundaryFingerprint(host_tokens=frozenset({"dr"}))
    score, sigs, _ = score_candidate(
        "DR_Plan_2026.pdf",
        "/policies/DR_Plan_2026.pdf",
        "Disaster recovery procedures and DR testing schedule.",
        fp,
    )
    # _whole_word_in("dr", blob) — "dr" appears as standalone word in snippet.
    assert score >= _W_HOST - 0.001
    assert "host:dr" in sigs


def test_host_token_is_lowercased_at_intake_assumption():
    """``host_tokens`` are case-sensitive at score time — lowercased on intake.

    score_candidate lowercases the blob (name+path+snippet) but does NOT
    re-lowercase the fingerprint token. Production paths
    (build_boundary_fingerprint lines 527, 548) lowercase before insertion;
    callers building fingerprints by hand for tests / future batch jobs
    must do the same. This test pins the contract: an uppercase token in
    the fingerprint will NEVER match (since the blob is lowercase).
    """
    # Uppercase token bypassed normalization — won't match.
    fp_bad = BoundaryFingerprint(host_tokens=frozenset({"SERVER01"}))
    score_bad, sigs_bad, _ = score_candidate(
        "server01_config.txt",
        "/configs/server01.txt",
        "server01 hardening baseline",
        fp_bad,
    )
    assert score_bad == 0.0, "uppercase fingerprint token leaks past the matcher"
    assert sigs_bad == []

    # Lowercase token — matches.
    fp_good = BoundaryFingerprint(host_tokens=frozenset({"server01"}))
    score_good, sigs_good, _ = score_candidate(
        "server01_config.txt",
        "/configs/server01.txt",
        "server01 hardening baseline",
        fp_good,
    )
    assert score_good >= _W_HOST - 0.001
    assert "host:server01" in sigs_good


def test_host_token_punctuation_does_not_break_word_boundary():
    """FQDNs and IPs with dots/dashes still match via the word-boundary regex.

    Pins that ``bastion01.acme.local`` matches inside a snippet — the regex
    escapes special chars via re.escape, so periods stay literal and the
    word-boundary check (``[^a-z0-9]`` on either side) admits punctuation
    + whitespace as boundaries.
    """
    fp = BoundaryFingerprint(host_tokens=frozenset({"bastion01.acme.local"}))
    score, sigs, _ = score_candidate(
        "Hardening.docx",
        "/Documents/Hardening.docx",
        "Connect via bastion01.acme.local (10.20.0.7) for ssh.",
        fp,
    )
    assert score >= _W_HOST - 0.001
    assert any(s.startswith("host:bastion01") for s in sigs)


def test_host_token_caps_once_with_multiple_hits():
    """Multiple host-token matches still only contribute _W_HOST once.

    Verifies the ``break`` on sweep.py:838 — without it, a doc that
    mentions 5 in-scope hostnames would single-handedly clear the
    pre-check threshold (0.60) just on host weight.
    """
    fp = BoundaryFingerprint(
        host_tokens=frozenset({"server01", "server02", "bastion01"})
    )
    score, sigs, _ = score_candidate(
        "All_Hosts.docx",
        "/Documents/All_Hosts.docx",
        "Inventory: server01, server02, bastion01 — all production.",
        fp,
    )
    # Exactly one host signal, score capped at _W_HOST (0.40), not 1.20.
    host_sigs = [s for s in sigs if s.startswith("host:")]
    assert len(host_sigs) == 1
    assert score == pytest.approx(_W_HOST, abs=0.001)


# ---------------------------------------------------------------------------
# 3. Skip-family veto — interactions with other signals
# ---------------------------------------------------------------------------


def test_skip_family_veto_dropped_when_only_skip_family_matches():
    """File matching ONLY a skip-family keyword is dropped (score 0).

    AU is in scope but every in-scope AU control is provider-owned per
    CRM → family added to crm_skip_families. A file whose only signal is
    "audit logs" must not surface; the provider owns it.
    """
    fp = BoundaryFingerprint(
        control_families=frozenset({"AU"}),
        crm_skip_families=frozenset({"AU"}),
    )
    score, sigs, _ = score_candidate(
        "Audit_Log_Policy.docx",
        "/Documents/Audit_Log_Policy.docx",
        "Audit logs are retained per provider's standard.",
        fp,
    )
    assert score == 0.0
    assert sigs == []


def test_host_evidence_survives_skip_family_keyword_collision():
    """Host signal immunizes a candidate against the skip-family veto.

    A file matching BOTH a host token AND a skip-family keyword (e.g.
    ``server01`` + "audit log" while AU is in ``crm_skip_families``) MUST
    still surface — it represents real host evidence, not pure provider
    noise. Before the 2026-06-07 fix the veto at sweep.py:935 fired on
    family-only signals and dropped the host hit silently. The fix added
    a ``matched_non_family_signal`` track for host/doc-prefix/priority-
    link signals and gated the veto on its absence.
    """
    fp = BoundaryFingerprint(
        host_tokens=frozenset({"server01"}),
        control_families=frozenset({"AU"}),
        crm_skip_families=frozenset({"AU"}),
    )
    score, sigs, _ = score_candidate(
        "Audit_On_Server01.docx",
        "/Documents/Audit_On_Server01.docx",
        "Audit log config on server01.",
        fp,
    )
    # Post-fix: host signal survives the family veto.
    assert score > 0
    assert any(s.startswith("host:server01") for s in sigs)


def test_pure_skip_family_keyword_still_vetoed_no_other_signal():
    """Belt-and-suspenders for the fix above.

    A file whose only signal is a skip-family keyword (no host, no
    doc-prefix, no priority-link, no non-skip family) MUST still be
    dropped — that's the whole point of the veto. The fix only
    immunizes candidates that bring a non-family signal to the party.
    """
    fp = BoundaryFingerprint(
        control_families=frozenset({"AU"}),
        crm_skip_families=frozenset({"AU"}),
    )
    score, sigs, _ = score_candidate(
        "Provider_Audit_Logs.docx",
        "/Documents/Provider_Audit_Logs.docx",
        "Audit logs are managed by AWS.",
        fp,
    )
    assert score == 0.0
    assert sigs == []


def test_control_id_in_skip_family_still_drops_when_alone():
    """Control-id match within a skip family alone → still dropped.

    Belt-and-suspenders: an "AU-2_audit_log.docx" file whose ONLY signal
    is the AU-2 control id should be vetoed when AU is skip — the
    matched_non_skip_family flag tracks family membership of matched
    controls (line 857-858).
    """
    fp = BoundaryFingerprint(
        in_scope_control_ids=frozenset({"au-2"}),
        crm_skip_families=frozenset({"AU"}),
    )
    score, sigs, _ = score_candidate(
        "AU-2_audit_log.docx",
        "/Documents/AU-2_audit_log.docx",
        None,
        fp,
    )
    assert score == 0.0
    assert sigs == []


# ---------------------------------------------------------------------------
# 4. Multi-signal additive cap behavior
# ---------------------------------------------------------------------------


def test_multi_signal_additive_score_below_one():
    """Host + control + family + crm-kw + doc-prefix sum stays <= 1.0.

    Verifies the ``min(1.0, score + w_X)`` clamp on every weight
    addition. Without the clamp, a doc that hits all 6 signal tiers
    would score 1.30 (0.40 + 0.30 + 0.20 + 0.15 + 0.15 + 0.10) which is
    nonsense — clamp makes the score interpretable as a probability.
    """
    fp = BoundaryFingerprint(
        host_tokens=frozenset({"server01"}),
        control_families=frozenset({"AC"}),
        in_scope_control_ids=frozenset({"ac-2"}),
        crm_keywords={"ac-2": frozenset({"gitlab"})},
        doc_number_prefixes=frozenset({"USD-001"}),
        control_ccis={"ac-2": ("ac-2.1", "ac-2.2")},
    )
    score, sigs, _ = score_candidate(
        "USD-001_AC-2_server01.docx",
        "/Docs/USD-001_AC-2_server01.docx",
        "Account management policy for server01, integrated with gitlab.",
        fp,
    )
    # All 5 tiers fire — score clamped at 1.0 max.
    assert score <= 1.0
    # At least 4 signals present (host, control, family, crm-kw, doc-prefix).
    assert len(sigs) >= 4
    assert score >= SCORE_PRECHECK_THRESHOLD  # easily above pre-check


# ---------------------------------------------------------------------------
# 5. CRM keyword behavior — skip-family interaction
# ---------------------------------------------------------------------------


def test_crm_keyword_skipped_when_family_in_skip_list():
    """CRM keywords belonging to skip-family controls are silently ignored.

    Line 880-881: ``if _family_of(ctrl_id) in fingerprint.crm_skip_families:
    continue``. A CRM narrative for AU-2 that mentions "splunk" must not
    add CRM-kw weight when the AU family is provider-owned.
    """
    fp = BoundaryFingerprint(
        crm_keywords={"au-2": frozenset({"splunk"})},
        crm_skip_families=frozenset({"AU"}),
    )
    score, sigs, _ = score_candidate(
        "Splunk_Setup.docx",
        "/Documents/Splunk_Setup.docx",
        "Splunk forwarder configuration",
        fp,
    )
    # AU is skip → splunk CRM keyword silently ignored. No other signal
    # fires. Score must be zero.
    assert score == 0.0
    assert sigs == []


def test_crm_keyword_empty_token_set_no_crash():
    """Empty token set under a control id → no signal, no crash.

    Defensive — a CRM row with the keyword extractor emitting [] (e.g.
    narrative was all stopwords) must not raise or false-positive.
    """
    fp = BoundaryFingerprint(crm_keywords={"ac-2": frozenset()})
    score, sigs, _ = score_candidate(
        "anything.docx", "/docs/anything.docx", "hello world", fp
    )
    assert score == 0.0
    assert sigs == []


# ---------------------------------------------------------------------------
# 6. Doc-prefix matching — case insensitivity + name-only scope
# ---------------------------------------------------------------------------


def test_doc_prefix_match_is_case_insensitive():
    """Doc-prefix matching lowercases both sides (line 897)."""
    fp = BoundaryFingerprint(doc_number_prefixes=frozenset({"usd-100"}))
    score, sigs, _ = score_candidate(
        "USD-100_Network_Architecture.docx",
        "/Documents/USD-100_Network_Architecture.docx",
        None,
        fp,
    )
    assert score >= _W_DOC_PREFIX - 0.001
    assert "doc-prefix:usd-100" in sigs


def test_doc_prefix_in_path_only_NOT_matched():
    """Doc-prefix check is on ``name`` only, not path (line 896-897).

    A file in a "/USD-100/" folder but with a different filename should
    NOT receive the doc-prefix boost. Pins this current behavior — if
    you want path-too matching, change the check and update this test.
    """
    fp = BoundaryFingerprint(doc_number_prefixes=frozenset({"usd-100"}))
    score, sigs, _ = score_candidate(
        "Readme.txt",
        "/Documents/USD-100/Readme.txt",
        None,
        fp,
    )
    assert score == 0.0
    assert "doc-prefix:usd-100" not in sigs


# ---------------------------------------------------------------------------
# 7. _whole_word_in — boundary check stops substring false positives
# ---------------------------------------------------------------------------


def test_whole_word_short_token_no_substring_false_positive():
    """``ac`` (2 chars) does NOT match inside ``track`` or ``backup``.

    Pins the documented rationale (sweep.py:934-948) — a bare ``in``
    check would fire those false positives, killing precision on short
    tokens.
    """
    assert not _whole_word_in("ac", "track changes for backup")
    assert _whole_word_in("ac", "ac account control")  # actual whole word


def test_whole_word_phrase_uses_substring():
    """Multi-word tokens (with a space) drop the boundary check.

    Phrases ≥ 4 chars are low-false-positive (no plausible substring
    coincidence) — line 943-946. ``"account management"`` should match
    inside ``"account management policy v3"``.
    """
    assert _whole_word_in("account management", "account management policy v3")


def test_whole_word_empty_token_returns_false():
    """Empty token short-circuits — line 941-942."""
    assert not _whole_word_in("", "any blob here")
    assert not _whole_word_in("", "")


# ---------------------------------------------------------------------------
# 8. Narrative-token extraction — stopwords + length filter
# ---------------------------------------------------------------------------


def test_extract_narrative_tokens_strips_stopwords_and_short():
    """CRM narrative extraction enforces stopwords + ``len >= 4``.

    Pins the **narrative**-path floor at 4 chars. The SC-merge path in
    ``build_boundary_fingerprint`` uses an asymmetric ``len >= 3``
    (sweep.py:615-621, 2026-06-07) because real env labels like
    ``iat``/``vpc``/``aws`` are 3 chars and load-bearing. Both paths
    share the same stopword set. Inventory tokens (Evidence.host_inventory
    JSON) remain unfiltered — they came from structured extraction, not
    prose. If a future patch unifies the two LLM-sourced paths, this test
    + ``test_pending_mode_filters_short_and_stopword_extracted_tokens``
    in test_sweep_fingerprint.py will both move together.
    """
    narrative = "The system is a complex piece of infrastructure with Splunk and AWS."
    tokens = _extract_narrative_tokens(narrative)
    # 4-char-plus, no stopwords. ``the``, ``is``, ``a``, ``of`` drop on
    # both length and stopword filters.
    assert "splunk" in tokens
    assert "aws" not in tokens  # 3 chars — below length floor
    assert "the" not in tokens
    assert "is" not in tokens


def test_extract_narrative_tokens_dedupes_preserving_order():
    """Same token appearing twice surfaces once; first-seen wins."""
    tokens = _extract_narrative_tokens("Splunk runs on splunk forwarder splunk node")
    assert tokens.count("splunk") == 1


def test_extract_narrative_tokens_respects_limit():
    """``limit`` caps the output (default 50)."""
    narrative = " ".join(f"token{i:04d}" for i in range(120))
    tokens = _extract_narrative_tokens(narrative, limit=10)
    assert len(tokens) == 10


def test_narrative_stopwords_includes_common_filler():
    """Sanity — the stopword list actually has stopwords in it.

    A typo in ``_NARRATIVE_STOPWORDS = frozenset(...)`` (e.g. wrapping a
    string instead of a tuple of strings) would yield a per-character
    set. This catches that class of mistake.
    """
    # Pick a handful of words that MUST be in any reasonable stopword set.
    for w in ("the", "and", "for", "with"):
        assert w in _NARRATIVE_STOPWORDS, (
            f"expected {w!r} in _NARRATIVE_STOPWORDS — possible iteration "
            f"bug (string vs tuple)"
        )


# ---------------------------------------------------------------------------
# 9. Priority-link prefix — cap-once behavior with nested bookmarks
# ---------------------------------------------------------------------------


def test_priority_link_caps_once_across_overlapping_prefixes():
    """File inside two overlapping bookmarks (parent + child) only scores once.

    Per sweep.py:902-916, the priority weight is added with a ``break``
    after the first hit — without that, bookmarking both ``/Policies``
    and ``/Policies/Network`` would double-charge any file in
    ``/Policies/Network/*``.
    """
    fp = BoundaryFingerprint(
        priority_path_prefixes=frozenset({
            "/sites/x/shared documents/policies",
            "/sites/x/shared documents/policies/network",
        }),
        label_by_priority_prefix={
            "/sites/x/shared documents/policies": "Policies",
            "/sites/x/shared documents/policies/network": "NetworkPolicies",
        },
    )
    score, sigs, _ = score_candidate(
        "Firewall.docx",
        "/sites/x/shared documents/policies/network/Firewall.docx",
        None,
        fp,
    )
    priority_sigs = [s for s in sigs if s.startswith("priority:")]
    assert len(priority_sigs) == 1
    assert score == pytest.approx(_W_PRIORITY_LINK, abs=0.001)


# ---------------------------------------------------------------------------
# 10. Snippet=None defensive — must not crash, must not match
# ---------------------------------------------------------------------------


def test_snippet_none_does_not_crash():
    """``snippet=None`` is a normal walker state (no content fetched)."""
    fp = BoundaryFingerprint(host_tokens=frozenset({"server01"}))
    # No match — name/path don't mention server01.
    score, _, _ = score_candidate("Readme.txt", "/x/Readme.txt", None, fp)
    assert score == 0.0
    # Match via name only — still works without a snippet.
    score, sigs, _ = score_candidate(
        "server01.txt", "/x/server01.txt", None, fp
    )
    assert score >= _W_HOST - 0.001


# ---------------------------------------------------------------------------
# 11. Control-id regex normalization — case + paren notation
# ---------------------------------------------------------------------------


def test_control_id_paren_notation_normalizes_to_dot():
    """``AC-2(1)`` in a filename matches ``ac-2.1`` in in_scope_control_ids."""
    fp = BoundaryFingerprint(
        in_scope_control_ids=frozenset({"ac-2.1"}),
        control_families=frozenset({"AC"}),
        control_ccis={"ac-2.1": ("ac-2.1",)},
    )
    score, sigs, ccis = score_candidate(
        "AC-2(1)_Account_Management.docx",
        "/Documents/AC-2(1)_Account_Management.docx",
        None,
        fp,
    )
    # Control hit (+0.30). Family AC keywords don't fire on this filename
    # (no "account" by itself in the family-keyword list necessarily; the
    # control hit alone is the contract under test).
    assert score >= _W_CONTROL_ID - 0.001
    assert "control:ac-2.1" in sigs
    assert "ac-2.1" in ccis
