"""Deterministic evidence → objective tagger.

Three high-signal heuristics, no LLM, no embeddings. The point is to
give the assessor a *precise* starting set of artifacts per CCI
without inventing relationships that aren't in the text:

1. **Doc-number match (highest confidence, 0.9).** If a USD doc
   number is present in either the evidence ``doc_number`` or its
   extracted text, we tag every ``Objective`` whose
   ``implementation_guidance``, ``assessment_procedures``, or prior
   column-U text mentions that doc number. This is the
   column-U-driven path described in the ``find-evidence`` plugin
   command — prior assessments are the best source of valid doc
   references.

2. **STIG findings → CCI direct link (highest confidence, 0.95).**
   When a STIG/Nessus extractor produces ``StigFindingRow``s with
   embedded ``CCI-######`` references, we tag the matching
   ``Objective`` directly — no keyword guess required. Inline
   ``CCI-######`` tokens in evidence text are ALSO picked up, but
   **only when ``evidence.kind`` is one of the structured-finding
   kinds** (STIG_CKL / STIG_CKLB / STIG_XCCDF / NESSUS). Policy
   PDFs/DOCX that casually quote a CCI no longer earn a 0.95-
   confidence tag — they remain discoverable via Tier 1 (doc
   number) and Tier 3 (control ID). 2026 STIG content still
   reliably scrapes from CKL/XCCDF/Nessus bodies because all four
   structured-finding kinds are admitted by the gate, and the
   structured ``cci_refs`` branch is ungated for every kind.

3. **Control-ID-in-text (medium confidence, 0.5; added 2026-06-04).**
   Policy docs and prior CCIS rows often quote a control ID
   ("AC-2", "IA-5(1)") without a USD number or a CCI token. We scan
   the extracted **text body only** for
   ``[A-Z]{2}-\\d{1,2}(?:\\(\\d+\\))?`` tokens and tag the matched
   Control's **primary CCI** (the child Objective with the lowest
   ``objective_id``). The LLM bundler groups per-Control so a single
   primary-CCI tag surfaces the artifact to every sibling CCI without
   inflating tag counts. Bounded by control_id, not control family.
   Lower confidence than the high-signal paths above so the Controls
   UI sort still surfaces CCI / doc-number matches first.

   2026-06-10 ("REL all 0.70" fix): the **relevance** of a Tier 3 tag
   is no longer the flat 0.7 it was stamped at since inception. The
   control-ID regex hit is a deterministic *confidence* signal (the body
   really does name the control) but says nothing about how relevant the
   artifact is to the control's substance — a one-line "see AC-2 policy"
   and a 12-page account-management SOP both matched the same token and
   both showed "REL 0.70", leaving the Controls UI / evidence ranker
   unable to order them. Relevance is now scaled by the TF-IDF cosine
   similarity between the artifact body and the matched control's
   requirement text (``relevance = FLOOR + (CEIL - FLOOR) * cosine``;
   see ``_TIER3_RELEVANCE_FLOOR`` / ``_TIER3_RELEVANCE_CEIL``).
   Confidence stays 0.5 — the regex either matched or it didn't.

   The 2026-06-07 change that survives: **text-only** —
   ``evidence.path`` is no longer scanned, because a filename like
   ``AC-2_RA-5_SC-7_kitchen_sink.pdf`` was a one-rename attack
   surface for harvesting tags without saying anything about the
   controls. The same 2026-06-07 batch also tried "primary-CCI only"
   (one tag for the matched Control's first child instead of all
   children) to fix a perceived "Tier 3 spray"; that was **reverted
   2026-06-10**. Because assessment runs per-CCI and each per-CCI
   evidence bundle queries ``EvidenceTag.objective_id == <one CCI>``,
   tagging only the primary child meant every non-primary CCI of a
   matched Control found zero artifacts ("only the first CCI shows
   artifacts"). We now fan out to **every** child Objective of the
   matched Control again. The relevance is no longer flat — it is the
   TF-IDF cosine band (see ``_TIER3_RELEVANCE_FLOOR/CEIL``), so the UI
   sort and LLM bundle stay ordered without dropping coverage.

4. **Evidence-type → control mapping (medium confidence, 0.6; added
   2026-06-04).** Some artifacts have no doc number, no CCI token,
   and no control ID anywhere — but the *shape* of the file tells us
   what control it satisfies. An xlsx whose first sheet has
   ``hostname / serial number / manufacturer`` columns is a HW asset
   inventory; that maps deterministically to CM-8. The xlsx extractor
   stamps ``metadata["evidence_type"]`` with one of
   ``hw_inventory | sw_inventory | asset_inventory`` and we route it
   to the controls in :data:`EVIDENCE_TYPE_TO_CONTROLS`. We look up
   each mapped Control and tag **all** of its child Objectives (CCIs)
   — same fan-out as Tier 3 (reverted 2026-06-10), so per-CCI
   bundles for every CCI of the control find the artifact. New
   formats slot in by extending the dict; no schema change needed.

History: a fourth "family + keyword" tier existed and was removed
2026-06-04. It produced 99.87% of all auto-tags at 0.35 confidence
because ``_objectives_by_family("AC")`` returns *every* CCI-level
objective under the AC family (~600 rows), so a single policy doc
that casually mentioned "AC-2" caused 2,000+ tag rows. Net effect was
"every file maps to every control" in the Controls UI. The Tier 3
path above replaces it with a strictly bounded version — one
control's children instead of one family's children.

2026-06-07: Tier 2's text-scrape (``_CCI_RE.finditer(text)``) was
narrowed to fire only for ``_STRUCTURED_FINDING_KINDS``. Before, a
policy PDF that quoted "per CCI-000015 above" earned a 0.95-confidence
tag — same band as a real CKL ``<CCI_REF>`` — and crowded high-signal
artifacts out of the LLM bundle (sorted by relevance×confidence and
truncated to MAX_ARTIFACTS=6). The structured ``stig_findings[].cci_refs``
branch is unchanged and still fires for every kind, so any extractor
that parses CCI lists from any file format keeps tagging.
"""

from __future__ import annotations

import logging
import re
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Iterable

from sqlmodel import Session, select

from ..engine.invalidation import invalidate_assessments_for_objectives
from ..models import Control, Evidence, EvidenceKind, EvidenceTag, Objective
from .extractors._stig_common import StigFindingRow
from .extractors.base import collect_doc_numbers

log = logging.getLogger(__name__)

# Tier 4 — evidence-type → control mapping. Asset-list / HW / SW xlsx
# extractors stamp ``metadata["evidence_type"]`` with one of these keys; the
# tagger walks the mapped control IDs and tags each Control's child
# Objectives. CM-8 (system component inventory) is the anchor for any
# inventory-shaped artifact; SW inventories also satisfy CM-7(5) (whitelisting
# scope), CM-10 (software usage), and CM-11 (user-installed software). Extend
# this dict to add new evidence types (e.g. "fw_policy" → ["ac-4", "sc-7"]).
# 2026-06-10: REVERTED the 2026-06-07 "Tier 4 spray" narrowing. That fix had
# shrunk sw_inventory from ["cm-8", "cm-7.5", "cm-10", "cm-11"] to ["cm-8"]
# only — but it conflated two separate problems. The real spray bug was the
# *family* path (removed 2026-06-04) that tagged ~600 objectives per family;
# Tier 4 already maps to a small, deliberate control set. Narrowing the dict
# AND the per-control emit loop to a single primary CCI meant a SW inventory
# only surfaced on CM-8's first child objective — so the per-CCI assessment
# bundle for CM-7(5)/CM-10/CM-11 (and CM-8's other CCIs) found zero artifacts.
# That is the "only the first CCI of every control shows artifacts" report.
# A SW inventory is direct evidence for authorized-software scope (CM-7(5)),
# software-usage restrictions (CM-10), and user-installed-software policy
# (CM-11), not just the component inventory (CM-8). Extend this dict to add
# new evidence types (e.g. "fw_policy" → ["ac-4", "sc-7"]).
EVIDENCE_TYPE_TO_CONTROLS: dict[str, list[str]] = {
    "hw_inventory": ["cm-8"],
    "sw_inventory": ["cm-8", "cm-7.5", "cm-10", "cm-11"],
    "asset_inventory": ["cm-8"],
    # 2026-06-10 (BUG B): an account / roles / user-access matrix (e.g.
    # "O&I Roles & User Accounts.xlsx" — an AD/O365 user export or a
    # program-authored access matrix) carries no doc number, no CCI token, and
    # no control ID in its cells, so Tiers 1-3 produced zero tags and the file
    # was invisible to account-management controls. The xlsx extractor now
    # classifies it as "account_matrix" by its column shape (2+ identity
    # signals: User/Role/Privilege/Group/...); route it to AC-2 (account
    # management), AC-6 (least privilege), and IA-2 (user identification &
    # authentication). Fan-out to every child CCI matches HW/SW handling.
    "account_matrix": ["ac-2", "ac-6", "ia-2"],
    # Lever C (2026-06-11): bounded family-pure content-shape mappings. Each
    # bijects to a tiny control set that the document type IS the literal
    # artifact for, so a Tier-4 0.6 corroboration tag is high-precision recall,
    # never a verdict flip. Detected by the xlsx classifier from distinctive,
    # core-anchored column shapes (see extractors/xlsx.py _classify_asset_workbook)
    # and only when NO existing inventory/account/asset shape matched, so the
    # current classifications are byte-for-byte unchanged.
    #
    #   * "poam" → CA-5. A Plan of Action & Milestones workbook (weakness rows,
    #     scheduled-completion dates, residual-risk, milestones) is the exact
    #     artifact CA-5 requires the org to maintain. Single CA-family control.
    #   * "training_record" → AT-2 / AT-3 / AT-4. A training/awareness completion
    #     roster (course + completion-date columns) is the literal evidence for
    #     AT-4 (training records) and corroborates AT-2 (awareness) / AT-3
    #     (role-based). Whole AT family, ≤4 controls, family-pure.
    "poam": ["ca-5"],
    "training_record": ["at-2", "at-3", "at-4"],
}

# Diagram/image kind rule: a network/boundary/architecture diagram is, by
# common sense, evidence for the boundary + data-flow control family — but a
# diagram can't carry a CCI token, so Tiers 1-3 leave it untagged and it
# vanishes from those control pages. When a DIAGRAM/IMAGE artifact's
# filename/title (or extracted shape text) signals a boundary diagram, we
# fan it out to these controls via _objectives_for_control_ids (no hardcoded
# CCIs — mirrors Tier 4). Filename-gated + a modest 0.5 confidence: a diagram
# is corroboration the boundary is documented, not proof a control is met.
#   sc-7  boundary protection      ca-3  system interconnections
#   ac-4  information flow          pl-8  security/architecture
_DIAGRAM_BOUNDARY_KEYWORDS: tuple[str, ...] = (
    "network", "boundary", "topology", "architecture", "dataflow",
    "data flow", "data-flow", "diagram", "enclave", "dmz", "segmentation",
)
_DIAGRAM_BOUNDARY_CONTROLS: tuple[str, ...] = ("sc-7", "ca-3", "ac-4", "pl-8")

# Tier 4.5 — tool/daemon name → control mapping (2026, deterministic recall).
# A huge share of real CTP (Control Test Procedure) evidence is terse terminal
# output named after the TOOL it tests: ``CTP-010_xrdp_step7.txt``,
# ``CTP-014_aide_step10.txt``, ``CTP-019_chrony_step7.txt``. The tool name IS a
# near-definitional control signal (xrdp = remote desktop = AC-17; aide = file
# integrity = SI-7), but it carries no doc number / CCI / control-ID token, so
# Tiers 1-3 produce nothing and the file falls to the expensive LLM judge —
# which often abstains on a lone fragment. Encoding the canonical tool→control
# lineage as a deterministic tier (a) guarantees the correct family reaches the
# control page (recall, the load-bearing priority) and (b) clears the Tier-5
# low-tag gate so the file skips ~15 judge calls (speed). This is NOT a guess:
# these are DISA-STIG / NIST-canonical tool roles, the same domain knowledge an
# assessor applies by reading the filename.
#
# Matching is WHOLE-WORD on the filename + title + a head slice of the body, so
# "vault" the HashiCorp daemon matches but "vaulted" prose does not. Tokens that
# are genuinely single-purpose daemons map at source="auto" (high precision);
# polysemous tokens (sudo/ssh/vault — common words or multi-role) map at
# source="auto_review" so a human confirms rather than the tag standing as
# silent proof. Fan-out to every child CCI mirrors Tier 4.
#
# Each value is (control_ids, ambiguous). ``ambiguous=True`` → auto_review.
_TOOL_NAME_TO_CONTROLS: dict[str, tuple[tuple[str, ...], bool]] = {
    # --- single-purpose daemons (high precision → auto) ---
    "aide": (("si-7", "cm-3"), False),
    "tripwire": (("si-7", "cm-3"), False),
    "chrony": (("au-8",), False),
    "chronyd": (("au-8",), False),
    "ntpd": (("au-8",), False),
    "clamav": (("si-3",), False),
    "clamscan": (("si-3",), False),
    "freshclam": (("si-3",), False),
    "auditd": (("au-2", "au-12"), False),
    "rsyslog": (("au-4", "au-9"), False),
    "selinux": (("ac-3", "ac-6"), False),
    "firewalld": (("sc-7",), False),
    "nftables": (("sc-7",), False),
    "iptables": (("sc-7",), False),
    "xrdp": (("ac-17",), False),
    "xvnc": (("ac-17",), False),
    "faillock": (("ac-7",), False),
    "pam_faillock": (("ac-7",), False),
    "pwquality": (("ia-5",), False),
    "fapolicyd": (("cm-7.5",), False),
    "usbguard": (("ac-19", "mp-7"), False),
    "sssd": (("ia-2", "ia-5"), False),
    # --- polysemous / multi-role (→ auto_review, human confirms) ---
    # "fips" appears constantly in compliance prose ("FIPS 140-2 validated...")
    # unrelated to a specific SC-13 crypto-module config, so it must NOT
    # auto-tag — route to human review.
    "fips": (("sc-13",), True),
    "vault": (("ia-5", "sc-12", "sc-28"), True),
    "sudo": (("ac-6",), True),
    "sudoers": (("ac-6",), True),
    "ssh": (("ac-17", "ia-5"), True),
    "sshd": (("ac-17", "ia-5"), True),
    "grub": (("ac-3",), True),
}

# Whole-word matcher built once from the table's keys. Word boundaries on both
# sides so "ssh" matches "ssh"/"sshd"(separately keyed) but not "flashing"; "."
# is escaped implicitly (no dots in keys). Sorted longest-first is irrelevant
# for a set-membership scan but we tokenize the haystack instead of regex-OR for
# clarity + speed on short bodies.
_TOOL_NAME_TOKEN_RE = re.compile(r"[a-z_][a-z0-9_]{2,}")

# Only the filename/title + this many leading chars of the body are scanned, so
# a tool name buried deep in a long unrelated log doesn't mis-tag the whole
# file. CTP evidence puts the tool in the name and the first command line.
_TOOL_NAME_BODY_HEAD_CHARS = 2000


_CCI_RE = re.compile(r"CCI-\d{6}", re.IGNORECASE)
# Control IDs in the 800-53 catalog look like "AC-2" or "IA-5(1)" — two
# uppercase letters, dash, 1-2 digits, optional parenthesised enhancement
# number. The leading \b prevents matching the tail of "FOO-AC-2"; the
# trailing (?!\d) keeps "AC-2345" from being read as "AC-2" but still
# permits "AC-2_policy.pdf" (filename case — underscore is a word char so
# a trailing \b would fail there).
_CONTROL_ID_RE = re.compile(r"\b([A-Z]{2}-\d{1,2}(?:\(\d+\))?)(?!\d)")

# Tier 3 relevance band (2026-06-10 "REL all 0.70" fix). A control-ID regex
# hit is a binary *confidence* signal (0.5, unchanged) but the *relevance* of
# the artifact to the control's substance varies enormously — a one-line "see
# AC-2 policy" reference and a 12-page account-management SOP both match the
# same token and used to be stamped at the identical flat relevance=0.7,
# leaving the Controls UI sort and the evidence ranker unable to order them.
# Relevance is now the TF-IDF cosine of the artifact body against the matched
# control's requirement text, mapped into [FLOOR, CEIL]:
#
#   relevance = FLOOR + (CEIL - FLOOR) * cosine
#
# FLOOR (0.35) == evidence_ranker.RankerConfig.corroboration_floor: a
# zero-overlap bare mention lands exactly on the corroboration floor, so
# classify_overflow treats it as non-decisive corroboration — a Tier 3 tag
# that says nothing about the control's substance can never *solely* drive a
# verdict. CEIL (0.75) sits strictly below Tier 4's 0.8 so a content-shape
# match (a real inventory column layout) still outranks even a perfectly
# worded bare text mention, preserving the tier ordering the Controls UI sort
# and the LLM bundle depend on.
_TIER3_RELEVANCE_FLOOR = 0.35
_TIER3_RELEVANCE_CEIL = 0.75

# Tier 3 catalog-doc guard (2026-06-10, BUG A). A catalog/index artifact — a
# CRM, a Statement of Applicability, a control-tailoring workbook exported to
# text — *lists* dozens of control IDs without being substantive evidence for
# any one of them. Before this guard, Tier 3 scraped every listed control ID
# and fanned a bare-mention tag to ALL of them, so "every control referenced
# the same artifact" and (because each control's bundle now held a low-cosine
# tag) "every control came back Non-Compliant" (BUG A — 87 artifacts, blanket
# NC). The guard does NOT cap artifacts-per-control (that is desired — a
# control may cite many artifacts); it caps controls-per-artifact for *index*
# docs only, by admitting just the controls this artifact is actually
# substantive about:
#
#   * is_catalog = (distinct control IDs in body) >= _TIER3_CATALOG_THRESHOLD.
#     A normal policy/procedure doc names a handful of controls; only an index
#     names a dozen+.
#   * Non-catalog docs are UNCHANGED — every matched control is emitted
#     (recall-preserving; the common case must not regress).
#   * Catalog docs admit only controls whose body-vs-requirement cosine clears
#     a RELATIVE drop-off (>= _TIER3_CATALOG_RELATIVE_FACTOR × max cosine) AND
#     an absolute floor (>= _TIER3_CATALOG_MIN_COSINE), capped at the top
#     _TIER3_CATALOG_TOPK by cosine. A pure listing (no real similarity to any
#     control — max cosine <= 0) admits NOTHING: a catalog that merely names
#     controls is not evidence for them.
_TIER3_CATALOG_THRESHOLD = 12
_TIER3_CATALOG_TOPK = 8
_TIER3_CATALOG_RELATIVE_FACTOR = 0.5
_TIER3_CATALOG_MIN_COSINE = 0.02

# Tier 5 semantic recall backstop (2026-06-10, BUG B sibling). Some real
# evidence names no doc number, no CCI, no control ID, and matches no known
# content shape — yet is plainly relevant to a handful of controls by its
# prose alone (an account-management SOP that never writes the string "AC-2",
# a contingency-plan narrative that never writes "CP-2"). Tiers 1-4 produce
# zero or near-zero tags for it. Tier 5 runs ONLY as a low-tag backstop —
# gated on (existing tags < _TIER5_MIN_EXISTING) so it never fires for an
# artifact the deterministic tiers already placed — and scores the artifact
# body against EVERY framework control's requirement text via the same TF-IDF
# cosine used by Tier 3. It admits only controls clearing a relative drop-off
# (>= _TIER5_RELATIVE_FACTOR × max) AND an absolute floor, capped at top-K.
# Strong matches (>= _TIER5_STRONG_FACTOR × max) are source="auto"; weaker
# admitted matches are source="auto_review" so the reviewer can see they were
# inferred semantically, not deterministically. Confidence is low
# (_TIER5_CONFIDENCE) — this is a recall safety net, never a high-signal path.
_TIER5_MIN_EXISTING = 2
_TIER5_TOPK = 8
_TIER5_RELATIVE_FACTOR = 0.5
_TIER5_MIN_COSINE = 0.05
_TIER5_STRONG_FACTOR = 0.8
_TIER5_CONFIDENCE = 0.3
# Substance gate for the DETERMINISTIC Tier 5 (TF-IDF) path only. Pure
# topical-word overlap on a one-line fragment ("Baseline configuration enforced
# via GPO. See policy.") is not evidence of anything — only the LLM judge can
# tell a casual mention from a real account-management SOP, which is exactly why
# the LLM backstop exists. The deterministic floor is an OUTAGE fallback; when it
# runs at all it must refuse to infer a control from a body too short to carry
# real evidence. Real Tier 5 targets (SOPs, contingency-plan narratives) have
# 100+ distinct significant tokens; the precision-test fragments have 7 and 15.
# 25 sits safely in that gap. The LLM judge is unaffected — it can read a short
# body and abstain on its own.
_TIER5_MIN_BODY_TOKENS = 25
# Tier 5 relevance reuses the Tier 3 band so a semantically-inferred tag sorts
# in the same [FLOOR, CEIL] space as a control-ID tag of equal cosine.

# Tier 5-LLM "smart backstop" (2026-06-10). When an LLM client is available,
# the deterministic TF-IDF Tier 5 above is REPLACED by an LLM judge: TF-IDF
# still pre-selects the candidate controls (cheap, deterministic, bounds the
# call count), but the *accept/abstain* decision is the model's, not a cosine
# threshold's. This raises precision over raw TF-IDF — the model can reject a
# candidate that shares vocabulary but doesn't address the control's substance,
# and can accept one whose wording diverges from the catalog text. It runs
# under the SAME low-tag gate as Tier 5 (only under-tagged artifacts) so a
# well-covered doc never pays for an LLM call.
#
# Cost is bounded three ways: (1) the low-tag gate means most artifacts skip it
# entirely; (2) TF-IDF pre-select caps candidates at _LLM_TIER_CANDIDATE_TOPK
# and drops any control below _LLM_TIER_CANDIDATE_MIN_COSINE (don't ask the
# model about zero-overlap controls); (3) the artifact body is ONE cached
# ephemeral system block, so candidates 2..N read it at ~10% input rate.
#
# Precision over recall (feedback_precision_over_recall): a candidate is tagged
# only when the judge score clears _LLM_TIER_ACCEPT_SCORE. Parse failures and
# genuine "can't tell" verdicts come back as a low score and are dropped — an
# abstention never becomes a tag. Graceful degradation (mirrors the sweep
# judge): a per-candidate API/network error is caught and counted; if EVERY
# candidate call errored (dead key, network down — not genuine abstention) the
# tier falls back to the deterministic TF-IDF Tier 5 so we degrade to prior
# behavior rather than silently dropping the backstop. A partial success
# (at least one real verdict) is trusted as-is — we do NOT re-add TF-IDF noise
# on top of a working judge.
_LLM_TIER_MIN_EXISTING = _TIER5_MIN_EXISTING  # same low-tag gate as TF-IDF Tier 5
_LLM_TIER_CANDIDATE_TOPK = 20  # how many controls TF-IDF hands the judge
_LLM_TIER_CANDIDATE_MIN_COSINE = 0.02  # don't judge zero-overlap controls
_LLM_TIER_ACCEPT_SCORE = 0.6  # judge score >= this → tag; below → abstain/drop

# ---------------------------------------------------------------------------
# Hybrid RAG candidate generation (2026-06-22). The single TF-IDF cosine
# pre-select starved the judge on the eMASS Body-of-Evidence corpus: terse
# config/terminal text ("sestatus enforcing", "pam_faillock") shares ~zero
# tokens with NIST control prose, so the correct control never entered the
# top-K and the judge was never asked → 42 files tagged to ZERO controls.
#
# The fix is a MULTI-LANE candidate union fused by Reciprocal Rank Fusion
# (RRF), then a tight cap, then the SAME judge gate (precision preserved).
# Lanes (each contributes its own ranked top-N; a control surfacing in >=2
# lanes gets the RRF boost; the judge still confirms every tag):
#   1. sparse   — TF-IDF cosine of the raw body vs control text (exact
#                 identifiers, the original lane).
#   2. hyde     — TF-IDF cosine of an LLM-REWRITTEN "control prose" version
#                 of the body vs control text. Bridges the vocabulary gap on
#                 a gateway with no embeddings endpoint: policy-text vs
#                 policy-text has real lexical overlap where raw config did
#                 not. This is the highest-value lane for the failing corpus.
#   3. dense    — embedding cosine, ONLY when a real (non-TF-IDF) embeddings
#                 provider is available (OpenAI key / sentence-transformers).
#                 Skipped silently otherwise so it never duplicates sparse.
#   4. triage   — control families/IDs named directly by the HyDE prose
#                 (parsed control-ID tokens) as an independent voter.
#   5. folder   — the eMASS family-folder token (01.AC -> AC ...) as a
#                 RECALL safety net: guarantees the right family's controls
#                 reach the judge even if every content lane misses. One
#                 voter of five; the judge gates it so it cannot mis-tag.
# RRF k=60 (standard). Cap is eval-tuned (too many candidates hurt judge
# precision via hard negatives; too few hurt recall).
_RRF_K = 60
_RAG_PER_LANE_TOPN = 15  # each lane contributes its top-N before fusion
_RAG_FUSED_CAP = 15  # max candidates handed to the judge after fusion
_CONTROL_ID_IN_TEXT_RE = re.compile(r"\b([A-Z]{2})-(\d{1,2})(?:\((\d+)\))?", re.I)
_LLM_TIER_CONFIDENCE = 0.55  # method confidence: a real semantic judgment with
# abstention — above TF-IDF Tier 5 (0.3) and control-ID Tier 3 (0.5), below the
# deterministic content-shape Tier 4 (0.6). Relevance (not confidence) carries
# the per-tag strength, mapped from the judge score into the Tier 3 band below.
# Raised 8000/4000 → 16000/8000 (2026-06-10): the judge was scoring relevance
# off a 12 KB sliver of long evidence decks/matrices, so a relevant passage in
# the dropped middle could push a true match below the 0.6 accept floor →
# under-tagged docs. The artifact body is cached in the system block (one cache
# write per doc, reused across all candidate controls), so a wider window costs
# input tokens once per artifact, not once per (artifact × control). Accuracy
# lever, not a model swap — the configured Haiku judge stays.
_LLM_TIER_ARTIFACT_HEAD_CHARS = 16000  # body cap fed to the cached system block
_LLM_TIER_ARTIFACT_TAIL_CHARS = 8000  # …plus a tail so late-doc content survives

# Per-artifact judge fan-out (2026-06-11 ingest-speed fix). The judge calls for
# the (up to _LLM_TIER_CANDIDATE_TOPK) candidate controls are independent I/O —
# previously run strictly sequentially, so an under-tagged doc paid 20×
# round-trip latency on the ingest hot path (the sidecar.log "POST .../messages
# 200 OK" stream the user saw scroll for minutes). The judge_relevance calls go
# through the same thread-safe httpx SDK the SharePoint sweep already fans out
# (see evidence/sources/sweep_judge.py::judge_candidates_concurrent), so we
# mirror that bounded-pool pattern here. 16 matches the sweep's worker count —
# the tagger pool is per-file inside the (serialized) ingest loop, so at the
# _LLM_TIER_CANDIDATE_TOPK=20 ceiling this collapses 20 sequential calls to
# ~1 (cache seed) + 19/16 ≈ 2.2 call-times. Precision is unchanged: the same
# candidates get the same prompts and the same 0.6 accept floor; only the
# wall-clock to gather the verdicts shrinks.
_LLM_TIER_JUDGE_WORKERS = 16

# Tier 2 text-scrape gate (added 2026-06-07). Inline ``CCI-######`` tokens
# are structural in STIG/Nessus output (CKL ``<CCI_REF>`` children, XCCDF
# rule metadata, Nessus plugin output) but are casual quotes in policy and
# procedure docs. Gating the text-scrape — NOT the structured
# ``stig_findings`` branch — keeps narrative-text fallback for STIG-shaped
# artifacts whose extractor missed a CCI inside ``finding_details``, while
# denying 0.95-confidence tags to policy PDFs that merely mention a CCI
# for context. Recall is preserved: such PDFs remain discoverable via
# Tier 1 (doc number) and Tier 3 (control ID).
_STRUCTURED_FINDING_KINDS = frozenset({
    EvidenceKind.STIG_CKL,
    EvidenceKind.STIG_CKLB,
    EvidenceKind.STIG_XCCDF,
    EvidenceKind.NESSUS,
})

# Kind-implies-objective rule for vulnerability scans. STIG checklists tag to
# their controls "for free" because their findings carry CCI_REF tokens; a
# Nessus/ACAS ``.nessus`` almost never carries inline CCIs (it has plugin IDs
# + host data), so it otherwise produces ZERO deterministic tags and the
# control's evidence list comes up empty. But the existence of a credentialed
# vulnerability scan IS, by definition, the evidence RA-5 a asks for ("the
# organization scans for vulnerabilities in the information system"). So we
# deterministically anchor every NESSUS scan to RA-5's CCI-001054. This is the
# scan analogue of a STIG's CCI_REF: kind alone establishes the mapping, no
# text scrape required. The scan's host data still flows to the coverage
# cross-check separately; this rule is what makes the artifact appear on the
# RA-5 control page and reach the LLM/kernel as real per-objective evidence.
_NESSUS_RA5_CCI = "CCI-001054"

# ---------------------------------------------------------------------------
# Corpus augmentation (2026-06-22) — control-family technical-synonym glosses.
#
# NIST control prose is policy-speak ("enforces approved authorizations for
# logical access"); real evidence is machine-state ("sestatus → enforcing").
# The TF-IDF/HyDE lanes match the evidence body against each control's text, so
# a control whose text never contains the technical vocabulary the evidence
# uses scores near zero. We append a SHORT gloss of the concrete artifacts a
# control family is actually demonstrated by, so the lexical lanes get a real
# overlap signal.
#
# Design guardrails (from the design review — both critics flagged the
# cross-tagging risk):
#   * Keyed by control FAMILY (the bounded, stable unit). A gloss is added to a
#     control only if its family matches.
#   * HIGH-SPECIFICITY ONLY. Each gloss term is a concrete technical artifact
#     (a command, daemon, config file, mechanism) that belongs to ONE family —
#     NOT a generic concept ("encryption", "access") that several families
#     share, which would erode TF-IDF's discrimination and cause cross-tagging.
#   * SHORT. A handful of tokens per family so the gloss can never dominate the
#     control's real requirement text in the single-string TF-IDF document
#     (the vectorizer is whole-string; we keep the gloss a small fraction of
#     the control body). A gloss-only lexical hit is weak by construction; the
#     0.6 judge gate still has the final say, so a gloss can never itself tag.
#   * DETERMINISTic + auditable (a static table), unlike the dynamic HyDE lane
#     — they compose: HyDE expands the query, the gloss expands the corpus.
#
# Extend by adding a family → space-joined technical terms entry. Keep terms
# family-exclusive; if a term fits two families, it is too generic — drop it.
_CONTROL_FAMILY_GLOSS: dict[str, str] = {
    "ac": (
        "selinux sestatus getenforce enforcing targeted policy mandatory "
        "access control rbac sudoers pam_faillock faillock account lockout "
        "deny unlock_time xrdp rdp remote session timeout screen lock "
        "tmout idle disconnect podman docker container privileged rootless"
    ),
    "au": (
        "auditd auditctl ausearch aureport audit rules syslog rsyslog "
        "journald logrotate audisp log forwarding splunk audit events "
        "watch syscall logging audit trail"
    ),
    "ia": (
        "pwquality pam_pwquality password complexity minlen dcredit ucredit "
        "ocredit lcredit faildelay krb5 kerberos ipa freeipa ldap sssd "
        "multifactor mfa smartcard piv certificate authentication"
    ),
    "sc": (
        "firewalld iptables nftables firewall zone tls openssl cipher "
        "fips vault seal unseal encryption rest transit boundary dmz "
        "vpn ipsec stunnel gpg luks dm-crypt cryptographic key"
    ),
    "si": (
        # Malicious-code + flaw-remediation artifacts ONLY. Integrity-baseline
        # tools (aide/tripwire/baseline) live in CM; vuln-scan terms live in
        # RA — kept family-exclusive to preserve TF-IDF discrimination.
        "clamav clamscan freshclam antivirus malware signature "
        "tripwire-alert quarantine patch update remediation flaw"
    ),
    "cm": (
        # Configuration-management artifacts ONLY. Owns aide/baseline (file
        # integrity baseline IS configuration integrity) and package inventory;
        # scap/oscap/vulnerability moved to RA (assessment), not duplicated.
        "aide baseline configuration drift stig hardening "
        "gpo registry rpm package inventory rpm-qa installed dpkg "
        "least functionality disabled services ports protocols"
    ),
    "cp": (
        "backup restore rsync snapshot bacula veeam recovery rpo rto "
        "failover replication contingency cold warm hot site"
    ),
    "ra": (
        # Vulnerability-scan / risk-assessment artifacts ONLY. Owns
        # scap/oscap/vulnerability (the scanning act) — CM owns the hardened
        # config those scans check against.
        "nessus acas scap oscap vulnerability scan cve plugin findings "
        "risk assessment scan results credentialed"
    ),
}


def _augment_control_text(control_id: str, base_text: str) -> str:
    """Append the family gloss (if any) to a control's reference text.

    ``control_id`` is the catalog form (``ac-2`` / ``ac-2.1``); the family is
    its leading segment. The gloss is appended AFTER the real requirement text
    so the control's own wording dominates the TF-IDF document and the gloss is
    a corroborating tail, never the primary signal. No gloss for the family →
    returns ``base_text`` unchanged.
    """
    fam = control_id.split("-", 1)[0].lower()
    gloss = _CONTROL_FAMILY_GLOSS.get(fam)
    if not gloss:
        return base_text
    if not base_text:
        return gloss
    # Guard against the gloss dominating a terse control (e.g. a one-sentence
    # enhancement): if the gloss would be a large fraction of the combined
    # document, truncate it so the control's OWN requirement text stays the
    # primary TF-IDF signal. The vectorizer is whole-string, so an unbounded
    # gloss on a short control could let config-vocabulary match the stub as
    # strongly as its substantive parent. Cap the gloss to the base length.
    if len(gloss) > len(base_text):
        gloss = gloss[: len(base_text)].rsplit(" ", 1)[0]
    return f"{base_text}\n{gloss}"


@dataclass
class TaggingResult:
    """Summary of one evidence file's tag attachments."""

    evidence_id: int
    tags_created: int
    doc_number_hits: int
    cci_hits: int
    control_id_hits: int = 0  # Tier 3 — bounded-by-control matches
    evidence_type_hits: int = 0  # Tier 4 — content-classified xlsx auto-mapping
    tool_name_hits: int = 0  # Tier 4.5 — tool/daemon-name → control deterministic map
    semantic_hits: int = 0  # Tier 5 — TF-IDF semantic recall backstop (low-tag only)
    llm_hits: int = 0  # Tier 5-LLM — judge-accepted backstop (replaces TF-IDF Tier 5)
    family_hits: int = 0  # retained for back-compat; family path removed 2026-06-04
    # --- Measure-first instrumentation (added 2026-06-11, verdict-neutral) ---
    # These count *how the LLM gate was exercised*, not tags emitted, so we can
    # answer "what fraction of documents reach the Tier-5 judge?" without a
    # bespoke profiling run. None of these fields change a single verdict — they
    # are pure observation. ``tier1_4_tags`` is the distinct-objective tag count
    # present when the Tier-5 low-tag gate was evaluated (i.e. ``len(existing)``
    # at gate time); a doc with ``tier1_4_tags >= _TIER5_MIN_EXISTING`` was fully
    # served by the deterministic tiers and never consulted the LLM.
    tier1_4_tags: int = 0  # distinct objectives tagged by Tiers 1-4 at gate time
    gate_cleared_by_det: bool = False  # True = deterministic tiers cleared the gate
    judge_invoked: bool = False  # True = _tag_via_llm was called (gate passed + client)
    judge_attempted: int = 0  # candidate controls actually sent to the judge
    judge_accepted: int = 0  # candidates the judge accepted (== llm_hits per-control)
    judge_errored: int = 0  # judge calls that raised (API/network), not abstentions
    # Tier-5 escalation re-judge (added 2026-06-24, verdict-neutral). When the
    # cheap judge cleanly abstained on a substantive, non-command-error body, a
    # stronger model re-judges once. These count that second pass; the per-control
    # accepts are ALSO folded into judge_attempted/judge_accepted/llm_hits above
    # (accumulated, not overwritten) so the corpus ratios stay correct.
    judge_escalated: bool = False  # True = a stronger-model re-judge actually ran
    judge_escalated_accepted: int = 0  # controls the escalation pass accepted


def _existing_pairs(session: Session, evidence_id: int) -> set[int]:
    """Objective IDs already tagged for this evidence (avoid duplicates)."""
    existing = session.exec(
        select(EvidenceTag.objective_id).where(EvidenceTag.evidence_id == evidence_id)
    ).all()
    return set(existing)


def _objectives_mentioning_doc(
    session: Session,
    doc_number: str,
    *,
    framework_id: int | None = None,
) -> list[Objective]:
    """Objectives whose guidance/procedures mention a USD doc number.

    Prior assessors wrote USD references four different ways — canonical
    (``USD00022222``), de-padded (``USD22222``), and either form with a
    hyphen or space between ``USD`` and the digits. SQLite LIKE is
    literal, so we expand to all four patterns. The OR over two columns
    × four patterns is still one indexed query per call.

    ``framework_id`` (added 2026-06-07) scopes the result to Objectives whose
    Control belongs to that framework. NULL = global (boundary-doc upload
    path); when set, JOINs through Control. Objective has no direct
    ``framework_id`` column (see models.py:294) so the JOIN is required.
    """
    canon = doc_number  # "USD00022222"
    short = doc_number.lstrip("USD").lstrip("0") or "0"  # "22222"
    variants = [
        f"%{canon}%",  # USD00022222
        f"%USD{short}%",  # USD22222
        f"%USD-{short}%",  # USD-22222 (most common prior-assessor form)
        f"%USD {short}%",  # USD 22222
        f"%USD-0{short}%",  # USD-022222 (partial zero-pad seen in older docs)
    ]
    clauses = []
    for v in variants:
        clauses.append(Objective.implementation_guidance.like(v))  # type: ignore[union-attr]
        clauses.append(Objective.assessment_procedures.like(v))  # type: ignore[union-attr]
    # OR-fold without a python reduce import — start from the first clause.
    where_expr = clauses[0]
    for c in clauses[1:]:
        where_expr = where_expr | c
    stmt = select(Objective).where(where_expr)
    if framework_id is not None:
        stmt = stmt.join(Control, Control.id == Objective.control_id_fk).where(
            Control.framework_id == framework_id
        )
    return list(session.exec(stmt).all())


def _objectives_by_cci(
    session: Session,
    cci_ids: Iterable[str],
    *,
    framework_id: int | None = None,
) -> list[Objective]:
    """Objectives whose ``objective_id`` exactly matches a CCI label.

    ``framework_id`` (added 2026-06-07) scopes the result to Objectives whose
    Control belongs to that framework. NULL = global (boundary-doc upload
    path); when set, JOINs through Control. Objective has no direct
    ``framework_id`` column (see models.py:294) so the JOIN is required —
    ``control_id_fk`` and ``Control.framework_id`` are both indexed so the
    join cost is negligible.
    """
    canon = sorted({c.upper() for c in cci_ids if c})
    if not canon:
        return []
    stmt = select(Objective).where(Objective.objective_id.in_(canon))  # type: ignore[attr-defined]
    if framework_id is not None:
        stmt = stmt.join(Control, Control.id == Objective.control_id_fk).where(
            Control.framework_id == framework_id
        )
    return list(session.exec(stmt).all())


def _normalize_control_id(raw: str) -> str:
    """Render a regex-matched control token in catalog form.

    OSCAL-loaded catalogs store controls as ``ac-2`` and enhancements as
    ``ac-2.1`` — lowercase, dot notation. Our regex matches the human form
    ``AC-2`` / ``AC-2(1)``; normalize both shape and case here so the IN
    lookup actually hits. Bug found 2026-06-04 — without this the Tier 3
    path silently returned zero matches for every doc.
    """
    s = raw.strip().lower()
    # AC-2(1) → ac-2.1
    s = re.sub(r"\((\d+)\)", r".\1", s)
    return s


def _objectives_for_control_ids(
    session: Session,
    control_ids: Iterable[str],
    *,
    framework_id: int | None = None,
) -> list[tuple[str, Objective]]:
    """Child objectives of any Control whose ``control_id`` matches.

    Strictly bounded — we look up Controls by exact ``control_id`` and
    return their direct child Objectives via ``control_id_fk``. We
    never expand to siblings in the family. Returns ``(control_id,
    objective)`` pairs so the caller can render an accurate rationale
    ("Control ID AC-2 referenced ...") without a second query.

    The display key in the returned tuple is the catalog form (``ac-2``);
    the route layer / rationale builder is free to uppercase it for the
    UI. Keeping it canonical here avoids confusing later joins.

    ``framework_id`` (added 2026-06-07) scopes the initial Control SELECT to
    one framework. The downstream Objective SELECT is then naturally
    framework-scoped because ``control_by_id`` only contains the right
    framework's Control ids — no second WHERE clause needed.
    """
    canon = sorted({_normalize_control_id(c) for c in control_ids if c})
    if not canon:
        return []
    control_stmt = select(Control).where(Control.control_id.in_(canon))  # type: ignore[attr-defined]
    if framework_id is not None:
        control_stmt = control_stmt.where(Control.framework_id == framework_id)
    controls = list(session.exec(control_stmt).all())
    if not controls:
        return []
    control_by_id = {c.id: c.control_id for c in controls if c.id is not None}
    if not control_by_id:
        return []
    objs = list(
        session.exec(
            select(Objective).where(
                Objective.control_id_fk.in_(list(control_by_id.keys()))  # type: ignore[attr-defined]
            )
        ).all()
    )
    return [(control_by_id[o.control_id_fk], o) for o in objs if o.control_id_fk in control_by_id]


def _all_objectives_by_control(
    session: Session, *, framework_id: int | None = None
) -> dict[str, list[Objective]]:
    """Every Control's child Objectives, keyed by catalog ``control_id``.

    The Tier 5 semantic backstop scores an artifact body against *every*
    control's requirement text, so it needs the full control → children map
    in one query rather than per-control lookups. ``framework_id`` scopes the
    Control SELECT to the active framework lens (NULL = span all frameworks,
    the boundary-doc default — same convention as the other lookups).

    Returns ``{control_id: [Objective, ...]}``. A Control with no child
    Objectives is omitted (nothing to tag). The two SELECTs (controls, then
    their objectives by ``control_id_fk IN (...)``) mirror
    :func:`_objectives_for_control_ids` so the join cost and framework scoping
    are identical — both indexed columns.
    """
    control_stmt = select(Control)
    if framework_id is not None:
        control_stmt = control_stmt.where(Control.framework_id == framework_id)
    controls = list(session.exec(control_stmt).all())
    control_by_pk = {c.id: c.control_id for c in controls if c.id is not None}
    if not control_by_pk:
        return {}
    objs = list(
        session.exec(
            select(Objective).where(
                Objective.control_id_fk.in_(list(control_by_pk.keys()))  # type: ignore[attr-defined]
            )
        ).all()
    )
    by_control: dict[str, list[Objective]] = {}
    for o in objs:
        cid = control_by_pk.get(o.control_id_fk)
        if cid is None:
            continue
        by_control.setdefault(cid, []).append(o)
    return by_control


def _control_reference_text(objectives: list[Objective]) -> str:
    """Concatenate the requirement substance of one Control's objectives.

    Tier 3 relevance is the cosine of the artifact body against *what the
    control actually requires*. We build that reference text from each child
    objective's ``text`` (the requirement statement) plus its
    ``implementation_guidance`` when present. ``assessment_procedures`` is
    deliberately excluded — it describes how an assessor *verifies* the control
    (workbook Col K style "examine / interview / test" language), not the
    control's subject matter. Folding it into the relevance signal would reward
    artifacts that quote verification boilerplate over artifacts that actually
    implement the control — the same Col-K leakage the narrative validator
    guards against (assess_control.md rule #2). Returns "" when no objective
    carries any text, in which case the caller scores relevance at the floor.
    """
    # Sort by objective_id so the concatenation order is a pure function of the
    # control's children, not of arbitrary DB row order — same determinism
    # requirement as the corpus build in _tier3_relevance_scores (2026-06-10).
    parts: list[str] = []
    for o in sorted(objectives, key=lambda obj: obj.objective_id or ""):
        if o.text:
            parts.append(o.text)
        if o.implementation_guidance:
            parts.append(o.implementation_guidance)
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Terminal-capture noise normalization (2026-06-11).
#
# The most decisive config evidence in a real assessment arrives as raw
# ``script(1)`` / terminal captures of ``sshd_config``, ``auditd`` rules,
# ``sudo`` policy, etc. Those dumps are saturated with ANSI escape sequences,
# carriage-return redraws, and stray C0 control bytes. TF-IDF L2-normalizes
# each row over its whole vocabulary, so thousands of unique escape-garbage
# tokens inflate the denominator and crush the cosine of EVERY real token
# toward zero — every control falls below ``_LLM_TIER_CANDIDATE_MIN_COSINE``,
# the LLM judge is never even asked, and the artifact silently drops to
# RULE_NO_EVIDENCE → forced NON_COMPLIANT. Stripping the noise before the
# vectorizer (and before the cached LLM body) restores the lexical signal that
# the right controls actually carry. Catalog/control text never contains these
# bytes, so this only ever cleans the artifact side.
_ANSI_CSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_ANSI_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_ANSI_OTHER_RE = re.compile(r"\x1b[@-Z\\-_()#]")
_C0_NOISE_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _strip_terminal_noise(text: str) -> str:
    """Remove ANSI escapes / CR redraws / stray control bytes from a capture.

    Cheap fast-path: if there is no ESC and no CR, the text is already clean
    (the common case — extracted PDF/DOCX/XLSX text carries neither), so we
    return it untouched and pay nothing. Only ``script(1)``-style terminal
    captures hit the full normalization. Never raises — a similarity nicety
    must not abort an ingest.
    """
    if not text or ("\x1b" not in text and "\r" not in text):
        return text
    out = _ANSI_CSI_RE.sub("", text)
    out = _ANSI_OSC_RE.sub("", out)
    out = _ANSI_OTHER_RE.sub("", out)
    out = out.replace("\r\n", "\n").replace("\r", "\n")
    out = _C0_NOISE_RE.sub(" ", out)
    return out


# Distinct ≥3-char alphabetic-led tokens — the substance measure the
# deterministic Tier 5 gate uses. Counts identity, not length: a one-line
# fragment with repeated words still scores low, a real SOP scores 100+.
_TIER5_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9]{2,}")


def _distinct_significant_tokens(text: str) -> int:
    """Count distinct ≥3-char significant tokens after noise stripping."""
    cleaned = _strip_terminal_noise(text or "")
    return len({m.group(0).lower() for m in _TIER5_TOKEN_RE.finditer(cleaned)})


# Tier-5 escalation guards (2026-06-24). A clean Haiku all-abstain on an
# under-tagged file triggers ONE Opus re-judge — but only when the body is real
# evidence, not a transcript of a command that never ran. Two design rules
# settled by architecture review + external second opinions:
#   * Do NOT use a "success-signal allow-list" (it would exclude valid non-zero
#     evidence like ``capsh | grep cap_sys_chroot`` rc=1 = good CM-7 evidence).
#   * Do NOT treat ``Permission denied`` / a bare non-zero exit as a command
#     error — in security evidence those are PROOF a control enforces (a blocked
#     connection, a locked file). The disqualifier is the script FAILING TO RUN,
#     not the script running and returning a restrictive result.
# So the guard matches only FAILURE-TO-EXECUTE signals: the interpreter/shell
# could not launch the command (typo, missing arg, bad path, syntax error).
_FAILURE_TO_EXECUTE_RES = (
    re.compile(r"\bcommand not found\b", re.IGNORECASE),
    re.compile(r"\[FATAL\]"),
    re.compile(r"\bmissing\b.*\bargument\b", re.IGNORECASE),
    re.compile(r"\bunrecognized option\b", re.IGNORECASE),
    re.compile(r"\bsyntax error\b", re.IGNORECASE),
    re.compile(r"\bNo such file or directory\b", re.IGNORECASE),
    re.compile(r"\bNot a directory\b", re.IGNORECASE),
)
# A token that signals the command actually produced real output / ran to
# completion — when present alongside an error, the body is NOT "error-only"
# (e.g. a long config dump that also happens to contain the word "fatal").
_SUCCESSFUL_OUTPUT_RES = (
    re.compile(r"\brc[:=]\s*['\"]?0\b", re.IGNORECASE),     # result.rc: '0'
    re.compile(r"\bchanged:\s*\[", re.IGNORECASE),           # ansible changed: [host]
    re.compile(r"\bok:\s*\[", re.IGNORECASE),                # ansible ok: [host]
    re.compile(r"\bactive\s*\(running\)", re.IGNORECASE),    # systemctl status
    re.compile(r"\bis-active\b.*\bactive\b", re.IGNORECASE),
)


def _is_command_error_only(text: str) -> bool:
    """True when the body's only signal is a command that FAILED TO EXECUTE.

    Used as a deterministic escalation rail: a file like
    ``[FATAL] Missing playbook argument`` clears the 25-token substance gate
    (its ANSI scaffolding alone is >25 tokens) yet contains NO observed control
    state — escalating it to a stronger, more generous judge risks a false
    positive on a genuinely-empty file. This guard suppresses that escalation.

    Returns True iff a failure-to-execute signal is present AND no successful
    command output is present. ``Permission denied`` and bare non-zero exit
    codes are deliberately NOT failure-to-execute signals (they are valid
    enforcement evidence), so a transcript whose only "error" is a denial is
    NOT classified as command-error-only and remains eligible to escalate.
    """
    if not text:
        return False
    cleaned = _strip_terminal_noise(text)
    if not any(rx.search(cleaned) for rx in _FAILURE_TO_EXECUTE_RES):
        return False
    # A real command also ran (success signal present) → not error-only.
    if any(rx.search(cleaned) for rx in _SUCCESSFUL_OUTPUT_RES):
        return False
    return True


# Structural escalation rail: a body with too few real content lines is noise,
# not evidence. The 0-byte file is already blocked upstream by ``text.strip()``;
# this catches a 1-3 line fragment that clears the token gate via repetition.
_ESCALATION_MIN_LINES = 4


def _too_few_lines_to_escalate(text: str) -> bool:
    """True when the stripped body has fewer than _ESCALATION_MIN_LINES of content."""
    cleaned = _strip_terminal_noise(text or "")
    nonblank = [ln for ln in cleaned.splitlines() if ln.strip()]
    return len(nonblank) < _ESCALATION_MIN_LINES


def _tier3_relevance_scores(
    artifact_text: str, control_texts: list[str]
) -> list[float]:
    """Cosine similarity of the artifact body to each control's requirement text.

    Fits one :class:`TfidfVectorizer` over ``[artifact_text, *control_texts]``
    and returns the cosine of row 0 (the artifact) against each control row, in
    the same order as ``control_texts``. TF-IDF rows are L2-normalized so the
    cosine is computed via the shared zero-norm-safe
    :func:`narrative_embeddings._cosine` helper, keeping the math identical to
    the validator's embedding fallback.

    **Determinism contract (2026-06-10 reproducibility fix).** The returned
    score for a given ``(artifact_text, control_texts[i])`` pair is a pure
    function of those two strings ONLY — it must not vary with how many other
    controls are in the batch, the order they arrive in, or any global/mutable
    corpus. Two things guarantee that here:

    1. The vectorizer is fit on a fixed, fully-explicit corpus derived solely
       from this call's inputs (``[artifact_text, *control_texts]``). Nothing
       outside the call leaks into the vocabulary or the idf weights.
    2. The vectorizer's tokenizer and vocabulary build are themselves
       order-stable: ``TfidfVectorizer`` sorts its vocabulary lexically and a
       pinned ``token_pattern`` removes any locale/version token-split drift.
       We do NOT compare row 0 against a fit that includes unrelated batch
       members beyond ``control_texts`` — so adding/removing an unrelated
       control never changes an existing pair's cosine.

    The per-control idf does depend on the artifact text + the controls fit
    together (that is inherent to TF-IDF and is what makes the score a *relative*
    relevance), but that set is identical on any re-run with the same inputs, so
    the result is reproducible run-to-run — the property an auditor re-running
    the assessment requires.

    Degrades to an all-zeros list (length ``len(control_texts)``) on any
    failure — sklearn missing on the frozen-bundle path (``ImportError``),
    empty/whitespace artifact text, or a degenerate vocabulary that yields an
    empty matrix (``ValueError``). An all-zeros result maps every Tier 3 tag to
    the relevance FLOOR, which is the correct conservative behavior: we still
    record the deterministic control-ID match (confidence 0.5) but treat it as
    corroboration-only until a real similarity signal is available. Never
    raises — a similarity nicety must not abort a whole folder ingest.
    """
    n = len(control_texts)
    if n == 0:
        return []
    # Strip terminal-capture noise (ANSI/CR/C0) before the vectorizer fit so a
    # ``script(1)`` config dump's escape garbage cannot dilute the L2 denominator
    # and crush every real token's cosine below the candidate floor. Control
    # text never carries these bytes, so only the artifact side is cleaned.
    artifact_text = _strip_terminal_noise(artifact_text)
    if not (artifact_text and artifact_text.strip()):
        return [0.0] * n
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer

        from ..engine.narrative_embeddings import _cosine

        # Pin every knob that could introduce run-to-run or batch-order drift.
        # ``token_pattern`` is set explicitly (sklearn's default, restated) so a
        # future default change can't silently re-tokenize and shift cosines;
        # the vectorizer is otherwise deterministic given a fixed input list.
        # The corpus is the call's explicit inputs in their given order — the
        # caller (tag_evidence) already builds ``control_texts`` in a sorted
        # ``cid`` order, so positional alignment with the emit loop is stable.
        vec = TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            min_df=1,
            max_df=1.0,
            token_pattern=r"(?u)\b\w\w+\b",
        )
        matrix = vec.fit_transform([artifact_text, *control_texts]).toarray()
    except (ImportError, ValueError):
        return [0.0] * n
    artifact_vec = matrix[0]
    return [float(_cosine(artifact_vec, matrix[i])) for i in range(1, n + 1)]


# ---------------------------------------------------------------------------
# Tier 5-LLM "smart backstop" — judge replaces the TF-IDF Tier 5 when a client
# is available. TF-IDF pre-selects candidate controls (cheap, bounds the call
# count); the accept/abstain decision is the model's.
# ---------------------------------------------------------------------------


def _llm_artifact_body(text: str) -> str:
    """Head+tail slice of the artifact body for the cached system block.

    The body is the expensive, reused token span — it lives in ONE cached
    ephemeral block so candidates 2..N read it at ~10% input rate. A long
    artifact is clipped to a head plus a tail (rather than head-only) so
    late-document content — an appendix table, a sign-off matrix — still
    reaches the judge. The elision marker tells the model the middle was cut so
    it doesn't treat the seam as adjacency.
    """
    body = _strip_terminal_noise(text).strip()
    head_cap = _LLM_TIER_ARTIFACT_HEAD_CHARS
    tail_cap = _LLM_TIER_ARTIFACT_TAIL_CHARS
    if len(body) <= head_cap + tail_cap:
        return body
    return f"{body[:head_cap]}\n\n[... middle of document elided ...]\n\n{body[-tail_cap:]}"


_LLM_JUDGE_RUBRIC = """\
You are a NIST 800-53 control assessor. The evidence artifact below was \
extracted from a real document. You will then be asked, one control at a time, \
how directly this artifact provides evidence for that control's requirement.

Reply with a JSON object and nothing else:

  {"score": <0.0-1.0>, "reasoning": "<<=320 chars; quote the specific line/setting/section that grounds the score>"}

When you accept (score the artifact as real evidence), the reasoning MUST quote \
the concrete span that justifies it — the exact config directive, table row, \
procedure step, or sentence — not a paraphrase. This is what the assessor cites \
back to a 3PAO, so "tracks content, not just the tag." When you abstain, say \
briefly what was missing.

Scoring rubric:
  1.0  - artifact directly implements or documents the control's substance
         (e.g. an account-management procedure for AC-2, a user/role matrix)
  0.7  - artifact materially addresses the control even if it never names it
  0.4  - artifact mentions the topic but is not substantive evidence
  0.1  - barely related; right domain, wrong control
  0.0  - unrelated to the control

Be strict and precise. Abstain by scoring low (<=0.4) when you genuinely \
cannot tell — never inflate a score to be helpful. A wrong tag costs the \
assessor more than a missed one. Judge ONLY from the artifact text shown; do \
not assume facts that are not present.

EVIDENCE-TYPE ROUTING (apply exactly one branch):

[A] If the evidence is a TERMINAL TRANSCRIPT (text, shell output, logs):
    Score 0.0 if the transcript shows the command did not execute as
    intended: command-not-found, missing/invalid argument, usage/help
    banner, syntax error, fatal initialization error, or an interpreter
    failing to load the script. Filenames, comments, and stated intent
    to run a control are NOT evidence. Score >= 0.6 ONLY when the
    output actively demonstrates a compliance state.

    Non-zero exit codes and "Permission denied" are VALID evidence when
    they demonstrate a control property (e.g., capability absent,
    access restricted, module blocked). The disqualifier is the script
    failing to run, not the script running and returning a restrictive
    result.

[B] If the evidence is an IMAGE (screenshot, dashboard, console UI; the
    artifact body begins with a [vision] description):
    Score on the PRESENCE of a deployed compliance mechanism visible
    in the UI (e.g., Rancher policy view, Splunk index, MFA enrollment
    screen, configured retention setting). A failed or incomplete
    verification step within the screenshot does NOT reduce the score
    if the underlying mechanism is visibly deployed and configured.
    Score >= 0.6 when the mechanism is identifiable and its
    configuration is legible.

Do not blend the two branches. Terminal failure-to-execute is
disqualifying; image verification-step failure is not."""


def _build_llm_brief(title: str, body: str) -> list[dict]:
    """Cached ephemeral system block: rubric + the (clipped) artifact body.

    Mirrors :func:`sweep_judge.build_boundary_brief`, but inverted: the sweep
    judge caches the *boundary* and varies the candidate file; here the
    *artifact* is the constant and we vary the candidate control. The artifact
    body is therefore what goes in the cache_control:ephemeral block so every
    per-control call after the first reads it cheaply.
    """
    text = f"{_LLM_JUDGE_RUBRIC}\n\n=== EVIDENCE ARTIFACT: {title} ===\n{body}\n=== END ARTIFACT ==="
    return [{"type": "text", "text": text, "cache_control": {"type": "ephemeral"}}]


# Per-candidate control requirement text is clipped so one verbose control
# (many enhancements + guidance) can't dominate the per-call user turn. The
# artifact body — the big span — is cached in the system block, so the variable
# user turn should stay small.
_LLM_TIER_CONTROL_TEXT_CHARS = 2500


def _llm_candidate_user_text(cid: str, ref_text: str) -> str:
    """The per-control turn: name the control, show its requirement, ask to score."""
    req = (ref_text or "").strip()
    if len(req) > _LLM_TIER_CONTROL_TEXT_CHARS:
        req = req[:_LLM_TIER_CONTROL_TEXT_CHARS] + "…"
    if not req:
        req = "(no catalog requirement text available)"
    return (
        f"Control: {cid.upper()}\n"
        f"Control requirement:\n{req}\n\n"
        "Score how directly the evidence artifact (in the system prompt above) "
        "provides evidence for THIS control. Reply with the JSON object only."
    )


# ---------------------------------------------------------------------------
# Hybrid RAG candidate generation — lanes + RRF fusion
# ---------------------------------------------------------------------------

# In-process embedded-catalog cache. narrative_embeddings re-embeds every
# call and has no cache; embedding ~1000 controls per under-tagged file would
# be ruinous. Cache the control-vector matrix per (framework_id, corpus-hash,
# provider) so the catalog is embedded once and reused across files. Cleared
# implicitly when the process restarts (catalog changes require a restart
# anyway, same lifecycle as the decision cache).
# key -> (cids, {cid: vector}). The vectors are stored cid-keyed so a cache
# hit remaps by cid (content-keyed alignment), never positionally re-zipped
# against a possibly-different cid order.
#
# Bounded LRU (OrderedDict) — NOT an unbounded dict. The v2.0 always-on
# in-boundary service never restarts, and a fresh entry is created per distinct
# control corpus (multi-framework DBs, catalog edits/reloads without restart,
# re-ingest after a catalog change). Each entry holds ~1000 control vectors, so
# an unbounded dict would leak over a long-running service. A handful of live
# catalogs is the realistic working set; evict least-recently-used past the cap.
_EMBED_CATALOG_MAX = 8
_EMBED_CATALOG_CACHE: "OrderedDict[tuple, tuple[list[str], dict[str, Any]]]" = (
    OrderedDict()
)


def _rank_to_rrf(ranked_cids: list[str]) -> dict[str, float]:
    """Reciprocal Rank Fusion contribution for one lane's ranked cid list.

    ``score(cid) = 1 / (k + rank)``, rank 0-based. A control near the top of
    a lane contributes more; absence from a lane contributes nothing. Summed
    across lanes by the caller, so a control surfacing in multiple lanes
    accumulates — the agreement boost that makes RRF robust.
    """
    return {cid: 1.0 / (_RRF_K + i) for i, cid in enumerate(ranked_cids)}


def _lane_sparse(text: str, cids: list[str], control_texts: list[str]) -> list[str]:
    """Sparse lane: TF-IDF cosine of the raw body vs each control's text."""
    if not text or not text.strip():
        return []
    cos = _tier3_relevance_scores(text, control_texts)
    ranked = sorted(zip(cids, cos), key=lambda t: (-t[1], t[0]))
    return [cid for cid, c in ranked if c > 0.0][:_RAG_PER_LANE_TOPN]


def _lane_hyde(
    hyde_prose: str, cids: list[str], control_texts: list[str]
) -> list[str]:
    """HyDE lane: TF-IDF cosine of the LLM-rewritten control prose vs catalog.

    The big win for vocabulary mismatch — ``hyde_prose`` is already written in
    policy language, so it overlaps control text where the raw config did not.
    Empty prose (HyDE call failed) → empty lane (degrade, don't fabricate).
    """
    if not hyde_prose or not hyde_prose.strip():
        return []
    cos = _tier3_relevance_scores(hyde_prose, control_texts)
    ranked = sorted(zip(cids, cos), key=lambda t: (-t[1], t[0]))
    return [cid for cid, c in ranked if c > 0.0][:_RAG_PER_LANE_TOPN]


def _lane_dense(
    text: str,
    cids: list[str],
    control_texts: list[str],
    *,
    framework_id: int | None,
) -> list[str]:
    """Dense lane: embedding cosine — ONLY with a real embeddings provider.

    Skipped (returns []) when the only available provider is the TF-IDF
    fallback, because that would just duplicate the sparse lane. Uses the
    per-catalog embed cache so controls are embedded once per process.
    Best-effort: any failure → empty lane.
    """
    if not text or not text.strip():
        return []
    try:
        from ..engine import narrative_embeddings as ne

        provider = ne.resolve_provider()
        # Skip the TF-IDF fallback provider — sparse already covers lexical.
        if provider.__class__.__name__ == "TfidfFallbackProvider":
            return []
        # Content digest (not hash()) so the key is collision-safe and stable.
        # Pair each control's text with its cid in the cache so vectors are
        # remapped by cid on a hit — NEVER positionally re-zipped against a
        # possibly-different cid order (the misalignment trap: same text set,
        # different cid order, would attribute every vector to the wrong
        # control). digest covers both the texts AND their cid pairing.
        import hashlib

        digest = hashlib.sha1(
            "\x1e".join(f"{c}\x1f{t}" for c, t in zip(cids, control_texts)).encode(
                "utf-8", "replace"
            )
        ).hexdigest()
        corpus_key = (framework_id, digest, provider.__class__.__name__)
        cached = _EMBED_CATALOG_CACHE.get(corpus_key)
        if cached is None:
            vecs = provider.embed(control_texts)
            vec_by_cid = dict(zip(cids, vecs))
            _EMBED_CATALOG_CACHE[corpus_key] = (list(cids), vec_by_cid)
            # Bounded LRU: evict the oldest entry past the cap.
            while len(_EMBED_CATALOG_CACHE) > _EMBED_CATALOG_MAX:
                _EMBED_CATALOG_CACHE.popitem(last=False)
        else:
            _cids_cached, vec_by_cid = cached
            _EMBED_CATALOG_CACHE.move_to_end(corpus_key)  # mark as recently used
        artifact_vec = provider.embed([text])[0]
        # Score by cid lookup — alignment is content-keyed, not positional.
        scored = [
            (cid, ne._cosine(artifact_vec, vec_by_cid[cid]))
            for cid in cids
            if cid in vec_by_cid
        ]
        ranked = sorted(scored, key=lambda t: (-t[1], t[0]))
        return [cid for cid, c in ranked if c > 0.0][:_RAG_PER_LANE_TOPN]
    except Exception:  # noqa: BLE001 — dense is optional; never abort tagging
        log.debug("dense lane unavailable; skipping", exc_info=True)
        return []


def _lane_triage(hyde_prose: str, valid_cids: set[str]) -> list[str]:
    """Triage lane: control IDs the HyDE prose names directly.

    The LLM expansion often names families/IDs ("...mandatory access control,
    AC-3, AC-6..."). Parse those tokens, normalize to catalog form, and emit
    any that exist in this framework's control set. An independent voter — it
    does not depend on lexical/embedding similarity at all.
    """
    if not hyde_prose:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for m in _CONTROL_ID_IN_TEXT_RE.finditer(hyde_prose):
        fam, num, enh = m.group(1).lower(), m.group(2), m.group(3)
        cid = f"{fam}-{int(num)}" + (f".{int(enh)}" if enh else "")
        if cid in valid_cids and cid not in seen:
            seen.add(cid)
            out.append(cid)
    return out[:_RAG_PER_LANE_TOPN]


def _family_from_path(path: str | None) -> str | None:
    """Extract the eMASS family token (01.AC -> 'ac') from an evidence path.

    Matches the strict ``NN.XX`` BoE convention anywhere in the path (works
    for both ``file://.../01.AC/...`` and ``zip://...!/02.AU/...``). Returns
    the lowercase family code, or None when no such token is present (ad-hoc
    paths contribute nothing — this lane is gated to the convention).
    """
    if not path:
        return None
    for m in re.finditer(r"[/!]\d{2}\.([A-Za-z]{2})[/_.]", path):
        return m.group(1).lower()
    return None


def _lane_folder(path: str | None, all_by_control: dict[str, list[Objective]]) -> list[str]:
    """Folder lane (recall safety net): controls in the path's eMASS family.

    If the evidence sits under e.g. ``07.IA/``, every IA-family control is a
    candidate the judge will be asked about — so a file the content lanes
    whiffed on still gets its correct family in front of the judge. The judge
    gates each one, so this raises recall without risking a wrong tag.
    """
    fam = _family_from_path(path)
    if not fam:
        return []
    out = [cid for cid in all_by_control if cid.split("-", 1)[0] == fam]
    return sorted(out)[:_RAG_PER_LANE_TOPN]


def _generate_candidates(
    text: str,
    *,
    hyde_prose: str,
    evidence_path: str | None,
    all_by_control: dict[str, list[Objective]],
    cids: list[str],
    control_texts: list[str],
    framework_id: int | None,
    tool_candidate_cids: set[str] | None = None,
) -> list[str]:
    """Run all lanes, fuse with RRF, return the capped candidate cid list.

    The single place candidates are chosen before the judge loop. Replaces the
    old TF-IDF-only pre-select. Deterministic: lanes are order-stable and RRF
    ties break by cid.

    ``tool_candidate_cids`` (design E): control IDs nominated by the Tier-4.5
    tool-name map. These are FORCE-INCLUDED ahead of the RRF cap so the judge
    always gets to confirm/reject a tool-suggested control (e.g. xrdp→AC-17),
    instead of the tool tier emitting a blind tag. Only IDs present in this
    framework's catalog (``valid``) are injected; cap-exempt so a real tool
    signal is never dropped by the 15-candidate ceiling.
    """
    valid = set(cids)
    lanes = [
        _lane_sparse(text, cids, control_texts),
        _lane_hyde(hyde_prose, cids, control_texts),
        _lane_dense(text, cids, control_texts, framework_id=framework_id),
        _lane_triage(hyde_prose, valid),
        _lane_folder(evidence_path, all_by_control),
    ]
    fused: dict[str, float] = {}
    for lane in lanes:
        for cid, contrib in _rank_to_rrf(lane).items():
            fused[cid] = fused.get(cid, 0.0) + contrib
    # Sort by fused score desc, ties by cid for determinism; cap tightly.
    ranked = sorted(fused.items(), key=lambda kv: (-kv[1], kv[0]))
    candidates = [cid for cid, _ in ranked[:_RAG_FUSED_CAP]]
    if not candidates:
        # Every lane came up empty (zero lexical overlap, no HyDE prose, no
        # embeddings provider, no eMASS folder token). Preserve the original
        # LLM-tier contract: an under-tagged artifact that reached this point
        # STILL gets judged — the semantic judge is the only backstop left for
        # text whose tokens don't overlap any control's wording. Fall back to
        # the top-K controls by raw sparse cosine (deterministic by cid when all
        # cosines are zero), exactly as the pre-RAG code did.
        cos = _tier3_relevance_scores(text, control_texts)
        by_cos = sorted(zip(cids, cos), key=lambda t: (-t[1], t[0]))
        candidates = [cid for cid, _ in by_cos[:_RAG_FUSED_CAP]]

    # Design E: force tool-nominated controls in front of the judge (cap-exempt,
    # deduped, framework-valid only). The judge then confirms or rejects each on
    # the file's actual content — recall from the tool map, precision from the
    # judge. Prepended so they're judged first (cache already warm after cand 0).
    if tool_candidate_cids:
        existing = set(candidates)
        inject = [c for c in sorted(tool_candidate_cids) if c in valid and c not in existing]
        candidates = inject + candidates
    return candidates


def _tag_via_llm(
    text: str,
    *,
    client: Any,
    judge_model: str | None,
    all_by_control: dict[str, list[Objective]],
    artifact_title: str,
    add,
    hyde_prose: str = "",
    evidence_path: str | None = None,
    framework_id: int | None = None,
    augment_corpus: bool = True,
    tool_candidate_cids: set[str] | None = None,
) -> tuple[int, int, int]:
    """LLM smart-backstop: hybrid-RAG pre-select, judge accept/abstain, tag.

    Returns ``(llm_hits, attempted, errored)`` where ``attempted`` is the
    number of candidate controls actually sent to the judge and ``errored`` is
    how many of those raised an API/network error. The caller uses
    ``attempted > 0 and errored == attempted`` (every call failed — dead key,
    network down, not genuine abstention) to decide whether to fall back to the
    deterministic TF-IDF Tier 5. A partial success is trusted as-is.

    ``add`` is the ``_add`` closure from :func:`tag_evidence` — the sole
    EvidenceTag construction site — so source/framework stamping and the
    duplicate guard stay in one place.
    """
    cids = sorted(all_by_control.keys())
    if not cids:
        return 0, 0, 0
    # Corpus augmentation: append each control family's technical-synonym gloss
    # so the lexical lanes get an overlap signal between machine-state evidence
    # and policy-speak control text. Gated (default on); the gloss only feeds
    # CANDIDATE SELECTION — the judge still gates every tag, so a gloss-driven
    # candidate that isn't truly relevant is rejected at 0.6.
    if augment_corpus:
        control_texts = [
            _augment_control_text(cid, _control_reference_text(all_by_control[cid]))
            for cid in cids
        ]
    else:
        control_texts = [
            _control_reference_text(all_by_control[cid]) for cid in cids
        ]
    text_by_cid = dict(zip(cids, control_texts))

    # Hybrid-RAG candidate generation (replaces the TF-IDF-only pre-select).
    # Multiple lanes (sparse + HyDE + dense + triage + folder) fused by RRF,
    # then capped — so the correct control reaches the judge even when raw
    # config text has zero lexical overlap with catalog prose. The judge's
    # accept gate below is unchanged, so precision is preserved while recall
    # rises. The old "1-3 candidates squeak over the floor → fallback never
    # fires → judge starved" bug is structurally gone: RRF always returns a
    # populated, ranked set when any lane produced a hit.
    candidate_cids = _generate_candidates(
        text,
        hyde_prose=hyde_prose,
        evidence_path=evidence_path,
        all_by_control=all_by_control,
        cids=cids,
        control_texts=control_texts,
        framework_id=framework_id,
        tool_candidate_cids=tool_candidate_cids,
    )
    if not candidate_cids:
        return 0, 0, 0
    candidates = [(cid, text_by_cid[cid]) for cid in candidate_cids]

    brief = _build_llm_brief(artifact_title, _llm_artifact_body(text))

    # --- Phase 1: judge every candidate (parallel I/O) ---------------------
    # The judge calls are independent and account for ~all of this function's
    # wall-clock. Running them sequentially made an under-tagged doc pay
    # len(candidates)× round-trip latency on the ingest hot path. We fan them
    # out across a bounded thread pool (the httpx SDK is thread-safe — the same
    # client is fanned out by the SharePoint sweep), preserving the per-call
    # contract exactly: each candidate sees the same brief + the same
    # _llm_candidate_user_text, so scores/abstentions are identical to the
    # sequential version. Only the gather order changes — and we re-impose the
    # original candidate order in Phase 2 so tagging stays deterministic.
    #
    # Prompt-cache preservation: the brief's artifact body is one ephemeral
    # cache block. The FIRST judge call writes that cache; calls 2..N read it
    # at ~10% input rate. If we fired all N at once they'd race and every
    # worker would miss the cache (≈ worker-count× the artifact input cost).
    # So we run candidate 0 synchronously to seed the cache, THEN fan out the
    # rest — warm cache, full parallelism.
    def _judge(cid: str, ref_text: str) -> tuple[str, float | None, str, Any]:
        user_text = _llm_candidate_user_text(cid, ref_text)
        try:
            score, reasoning, _usage = client.judge_relevance(
                brief, user_text, model=judge_model
            )
            return cid, score, reasoning, None
        except Exception as exc:  # noqa: BLE001 — degrade, never abort an ingest
            return cid, None, "", exc

    # Index-aligned results so Phase 2 applies tags in the original (deterministic)
    # candidate order regardless of completion order.
    judged: list[tuple[str, float | None, str, Any] | None] = [None] * len(candidates)
    judged[0] = _judge(candidates[0][0], candidates[0][1])  # seed the cache

    rest = candidates[1:]
    if rest:
        workers = max(1, min(_LLM_TIER_JUDGE_WORKERS, len(rest)))
        with ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="tagger-judge"
        ) as pool:
            futs = {
                pool.submit(_judge, c[0], c[1]): i
                for i, c in enumerate(rest, start=1)
            }
            for fut in as_completed(futs):
                judged[futs[fut]] = fut.result()

    # --- Phase 2: apply verdicts sequentially (deterministic, single-thread) -
    # add() is the sole EvidenceTag construction site and is NOT thread-safe, so
    # all mutation happens here on the calling thread, in candidate order.
    llm_hits = 0
    attempted = 0
    errored = 0
    for entry in judged:
        if entry is None:  # pragma: no cover — every slot is filled above
            continue
        cid, score, reasoning, exc = entry
        attempted += 1
        if exc is not None:
            # API/network error (NOT a parse abstention — judge_relevance returns
            # a 0.0 score for those without raising). Count it; if every candidate
            # errors the caller falls back to TF-IDF Tier 5.
            errored += 1
            log.warning(
                "LLM tagger judge call failed for evidence %r control %s: %s",
                artifact_title,
                cid,
                exc,
            )
            continue
        if score is not None and score < 0.0:
            # Negative sentinel = judge_relevance retried once and STILL couldn't
            # parse the envelope. That's an ERROR (truncated/garbled output), NOT
            # a genuine "not relevant" abstention — count it as errored so a
            # parse-storm across all candidates trips the TF-IDF fallback instead
            # of silently dropping every tag. (A single such candidate still just
            # drops, same net effect as before, but now it's attributed correctly.)
            errored += 1
            log.warning(
                "LLM tagger judge parse-failed (after retry) for evidence %r "
                "control %s: %s",
                artifact_title,
                cid,
                reasoning,
            )
            continue
        if score is None or score < _LLM_TIER_ACCEPT_SCORE:
            # Below threshold. Drop — precision over recall: an abstention never
            # becomes a tag.
            continue
        relevance = round(
            _TIER3_RELEVANCE_FLOOR
            + (_TIER3_RELEVANCE_CEIL - _TIER3_RELEVANCE_FLOOR) * score,
            3,
        )
        why = (reasoning or "").strip()
        for obj in all_by_control[cid]:
            if obj.id is None:
                continue
            add(
                obj.id,
                relevance=relevance,
                confidence=_LLM_TIER_CONFIDENCE,
                source="llm",
                rationale=(
                    f"LLM semantic backstop for {cid.upper()} "
                    f"(score {score:.2f}; no control ID or CCI in body)."
                    + (f" Evidence: {why}" if why else "")
                ),
            )
            llm_hits += 1
    return llm_hits, attempted, errored


def tag_evidence(
    session: Session,
    evidence: Evidence,
    text: str,
    stig_findings: list[StigFindingRow] | None = None,
    *,
    cci_refs: list[str] | None = None,
    evidence_type: str | None = None,
    evidence_type_signals: list[str] | None = None,
    framework_id: int | None = None,
    client: Any | None = None,
    judge_model: str | None = None,
    escalation_model: str | None = None,
    augment_corpus: bool = True,
    tool_candidate_cids: set[str] | None = None,
) -> TaggingResult:
    """Apply doc-number, CCI-direct, control-ID, evidence-type, and (as a
    low-tag backstop) semantic-recall tags.

    Caller is responsible for committing the session. We accumulate
    new rows and add them, but leave the transaction boundary to the
    orchestrator so a whole folder ingest can be one transaction.

    ``cci_refs`` (Lever B, added 2026-06-11) carries already-validated
    ``CCI-######`` tokens harvested from a dedicated CCI column in a generic
    evidence workbook (see ``extractors.xlsx``). These route to the SAME
    ungated 0.95 Tier-2 branch as STIG/Nessus structured ``cci_refs`` — a
    workbook that names its CCIs in a column is as authoritative for
    attribution as a checklist's ``CCI_REF`` field. Unlike the inline
    text-scrape (gated to :data:`_STRUCTURED_FINDING_KINDS`), this path is
    ungated because the extractor already constrained collection to a
    header-allow-listed column and value-validated every token with the
    canonical ``CCI-\\d{6}`` regex, so a stray/free-text CCI mention can't
    reach it. No ``StigFinding`` ORM row is fabricated for these (the artifact
    is not a STIG), keeping the StigFinding table / asset cross-check clean.

    ``evidence_type`` / ``evidence_type_signals`` are emitted by extractors
    that can classify a file by its content shape (e.g. the xlsx extractor
    recognizing a HW asset list). When set, the Tier 4 path routes the
    evidence to the controls in :data:`EVIDENCE_TYPE_TO_CONTROLS`.

    ``framework_id`` stamps every created :class:`EvidenceTag` with the
    active framework lens AND (added 2026-06-07) scopes the four-tier
    lookup to Objectives whose Control belongs to that framework. NULL is
    the framework-agnostic default (boundary-doc uploads with no workbook
    context); when NULL, lookups span every framework in the DB — historical
    behavior preserved. Before the 2026-06-07 scoping change the kwarg only
    stamped, leaking tags across frameworks when the same CCI was loaded
    under multiple revisions (e.g. r4 + r5 in the same DB): a single
    ``<CCI_REF>`` produced one tag per framework's copy of that CCI,
    burning slots in the LLM bundle and inflating the Controls UI count.

    ``client`` / ``judge_model`` (added 2026-06-10) enable the Tier 5 "smart
    backstop": when an LLM client is supplied, the under-tagged-artifact path
    asks the judge model (default ``cfg.llm_judge_model`` = Haiku) whether the
    artifact is relevant to each TF-IDF-pre-selected candidate control, and
    only accepts confident judgments (``source="llm"``). When ``client`` is
    None the deterministic TF-IDF Tier 5 runs unchanged (preserves the offline
    path and existing tests). The LLM tier never caps artifacts-per-control —
    it fans every accepted control out to all of its child CCIs, same as the
    deterministic tiers.
    """
    if evidence.id is None:
        raise ValueError("tag_evidence requires a persisted Evidence (id is None)")

    existing = _existing_pairs(session, evidence.id)
    created = 0
    doc_hits = 0
    cci_hits = 0
    control_id_hits = 0
    evidence_type_hits = 0
    tool_name_hits = 0
    semantic_hits = 0
    llm_hits = 0
    # Measure-first instrumentation (verdict-neutral). Populated as the tiers
    # run; emitted in one grep-able log line at the Tier-5 gate so an ingest of
    # the under-tagged corpus reveals how often the deterministic tiers alone
    # clear the gate vs. how often the LLM judge is consulted.
    tier1_4_tags = 0
    gate_cleared_by_det = False
    judge_invoked = False
    judge_attempted = 0
    judge_accepted = 0
    judge_errored = 0
    judge_escalated = False
    judge_escalated_accepted = 0
    # Track objectives that received a new tag this call so we can invalidate
    # their stale Assessment rows in one UPDATE at the end (e.g. a CCI that
    # short-circuited via rule_no_evidence before this artifact landed must
    # be re-reviewed). Snapshot at the helper because `_add` is the sole
    # construction site for EvidenceTag in this module.
    newly_tagged_objective_ids: set[int] = set()

    def _add(
        obj_id: int,
        *,
        relevance: float,
        confidence: float,
        rationale: str,
        source: str = "auto",
    ) -> None:
        nonlocal created
        if obj_id in existing:
            return
        existing.add(obj_id)
        newly_tagged_objective_ids.add(obj_id)
        session.add(
            EvidenceTag(
                evidence_id=evidence.id,
                objective_id=obj_id,
                relevance=relevance,
                confidence=confidence,
                source=source,
                rationale=rationale,
                framework_id=framework_id,
            )
        )
        created += 1

    # 1. Doc number — the evidence's own canonical number plus any
    #    extras found in the text body (multi-doc PDFs do happen).
    doc_numbers: list[str] = []
    if evidence.doc_number:
        doc_numbers.append(evidence.doc_number)
    for extra in collect_doc_numbers(text or ""):
        if extra not in doc_numbers:
            doc_numbers.append(extra)
    for dn in doc_numbers:
        for obj in _objectives_mentioning_doc(session, dn, framework_id=framework_id):
            if obj.id is None:
                continue
            _add(
                obj.id,
                relevance=1.0,
                confidence=0.9,
                rationale=f"Doc number {dn} cited in objective guidance/procedures.",
            )
            doc_hits += 1

    # 2. CCI direct refs (from STIG/Nessus findings or scraped from text).
    cci_set: set[str] = set()
    if stig_findings:
        for f in stig_findings:
            if f.cci_refs:
                for part in f.cci_refs.split(","):
                    part = part.strip().upper()
                    if part:
                        cci_set.add(part)
    # Lever B (2026-06-11): validated CCI tokens from a dedicated CCI column in
    # a generic evidence workbook. Ungated — the extractor already scoped these
    # to a header-allow-listed column and CCI-####-validated each token, so they
    # are as authoritative as a STIG finding's CCI_REF. Merged here so they flow
    # through the same 0.95 emit loop below.
    if cci_refs:
        for c in cci_refs:
            c = c.strip().upper()
            if c:
                cci_set.add(c)
    # Kind-gate (added 2026-06-07): only scrape inline CCI tokens from text
    # when the evidence file is a structured STIG/Nessus artifact. Policy
    # PDFs that casually quote a CCI no longer earn a 0.95-confidence Tier 2
    # tag — they remain discoverable via Tier 1 (doc number) and Tier 3
    # (control ID). STIG-shaped artifacts whose extractor missed a CCI inside
    # finding_details free-text still get the narrative-text fallback.
    if evidence.kind in _STRUCTURED_FINDING_KINDS:
        for m in _CCI_RE.finditer(text or ""):
            cci_set.add(m.group(0).upper())
    if cci_set:
        for obj in _objectives_by_cci(session, cci_set, framework_id=framework_id):
            if obj.id is None:
                continue
            _add(
                obj.id,
                relevance=1.0,
                confidence=0.95,
                rationale=f"Direct CCI reference ({obj.objective_id}) found in evidence.",
            )
            cci_hits += 1

    # 2b. Kind-implies-objective for vulnerability scans. A NESSUS/ACAS scan
    #     anchors to RA-5 (CCI-001054) by KIND — the scan's existence is the
    #     evidence RA-5 a requires, and .nessus files don't carry inline CCIs
    #     to ride the Tier-2 scrape above. Resolved + emitted through the same
    #     helpers as Tier 2 so framework stamping, de-dup, and assessment
    #     invalidation are identical. _add de-dups, so if the scan already
    #     tagged CCI-001054 above (rare inline CCI), this is a no-op. Runs
    #     before the Tier-5 low-tag gate so the scan counts as a deterministic
    #     anchor and doesn't needlessly invoke the LLM backstop.
    if evidence.kind == EvidenceKind.NESSUS:
        for obj in _objectives_by_cci(
            session, {_NESSUS_RA5_CCI}, framework_id=framework_id
        ):
            if obj.id is None:
                continue
            _add(
                obj.id,
                relevance=1.0,
                confidence=0.9,
                rationale=(
                    "Nessus/ACAS vulnerability scan present — satisfies RA-5 "
                    f"({obj.objective_id}), the organization scans for "
                    "vulnerabilities."
                ),
            )
            cci_hits += 1

    # 3. Control-ID-in-text (Tier 3, added 2026-06-04 — bounded replacement
    #    for the removed family-keyword path).
    #
    #    2026-06-07 ("path-only deceptive filename" fix): we no longer scan
    #    ``evidence.path``. A filename like ``AC-2_policy.pdf`` with an empty
    #    or unrelated body was tagged at the same 0.7/0.5 band as a real
    #    text citation — users could game the tagger by renaming a deck to
    #    ``AC-2_RA-5_SC-7_kitchen_sink.pdf`` and harvest tags for every
    #    control they wanted credit on. Requiring the body to mention the
    #    control ID forces the artifact to actually *say something* about
    #    the control before we attribute it.
    #
    #    2026-06-07 ("Tier 3 spray" fix) — REVERTED 2026-06-10: the spray
    #    fix tagged only the **primary CCI** (lowest objective_id) per
    #    Control on the assumption that the LLM bundler groups evidence
    #    per Control (one prompt sees all CCIs for one Control), so one
    #    tag on the primary CCI would surface the artifact for every
    #    sibling. That batched-per-Control bundler was never shipped —
    #    ``build_tagged_evidence_with_payload`` queries
    #    ``WHERE objective_id == <one CCI>`` and the assess loop runs
    #    per-CCI. So primary-CCI-only tagging STARVED every sibling CCI:
    #    they got an empty bundle → ``rule_no_evidence`` → confident
    #    Non-Compliant even when the Control genuinely had evidence (the
    #    "only the first CCI of each Control shows artifacts" bug). Under
    #    the real per-CCI architecture, each CCI needs its own tag, so we
    #    fan the control-level match out to EVERY child CCI at the same
    #    cosine-derived relevance. The deceptive-filename guard above
    #    still holds (we only fan out when the body actually mentions the
    #    control ID); the spray fix's tag-count concern is moot because
    #    per-CCI bundles need exactly these rows. Re-tag (re-run sweep)
    #    for the fix to reach already-ingested evidence.
    control_id_set: set[str] = set()
    for m in _CONTROL_ID_RE.finditer(text or ""):
        control_id_set.add(m.group(1).upper())
    if control_id_set:
        by_control: dict[str, list[Objective]] = {}
        for cid, obj in _objectives_for_control_ids(
            session, control_id_set, framework_id=framework_id
        ):
            if obj.id is None:
                continue
            by_control.setdefault(cid, []).append(obj)
        # One TF-IDF fit per artifact across all matched controls. Build the
        # per-control reference text in a stable cid order so the cosine list
        # lines up positionally with the emit loop below (2026-06-10 fix).
        # ``sorted`` is load-bearing for determinism: ``by_control`` is keyed by
        # insertion order, which follows arbitrary DB row order; without the
        # sort the TF-IDF corpus order — and therefore each control's cosine —
        # would drift run-to-run. The emit loop zips over these same sorted
        # cids, so positional alignment is preserved.
        cids = sorted(by_control.keys())
        control_texts = [_control_reference_text(by_control[cid]) for cid in cids]
        cosines = _tier3_relevance_scores(text or "", control_texts)

        # Catalog-doc guard (BUG A, 2026-06-10). A catalog/index artifact (CRM,
        # SoA, tailoring workbook → text) lists dozens of control IDs without
        # being substantive evidence for any one of them. Detect it by the sheer
        # count of distinct control IDs named in the body and, for catalogs
        # ONLY, restrict the emitted controls to the ones this artifact is
        # actually similar to. This caps controls-per-artifact for index docs —
        # it never caps artifacts-per-control (a control may still cite many
        # artifacts; that is desired).
        is_catalog = len(control_id_set) >= _TIER3_CATALOG_THRESHOLD
        admitted: set[str] | None = None  # None = emit all (non-catalog path)
        if is_catalog:
            max_cos = max(cosines, default=0.0)
            if max_cos <= 0.0:
                # Pure listing — no similarity to any control. A catalog that
                # merely names controls is not evidence for them; admit nothing.
                admitted = set()
            else:
                rel_floor = max(
                    _TIER3_CATALOG_RELATIVE_FACTOR * max_cos,
                    _TIER3_CATALOG_MIN_COSINE,
                )
                qualifying = [
                    (cid, cos)
                    for cid, cos in zip(cids, cosines)
                    if cos >= rel_floor
                ]
                # Top-K by cosine (desc), ties broken by cid for determinism.
                qualifying.sort(key=lambda pair: (-pair[1], pair[0]))
                admitted = {cid for cid, _ in qualifying[:_TIER3_CATALOG_TOPK]}

        for cid, cosine in zip(cids, cosines):
            if admitted is not None and cid not in admitted:
                continue
            # Cosine is computed once at the Control level — every child CCI
            # of this Control shares it, since the match was a control-ID
            # mention, not a per-CCI signal.
            relevance = round(
                _TIER3_RELEVANCE_FLOOR
                + (_TIER3_RELEVANCE_CEIL - _TIER3_RELEVANCE_FLOOR) * cosine,
                3,
            )
            for obj in by_control[cid]:
                if obj.id is None:
                    continue
                _add(
                    obj.id,
                    relevance=relevance,
                    confidence=0.5,
                    rationale=(
                        f"Control ID {cid.upper()} referenced in evidence text "
                        f"(text relevance {cosine:.2f})."
                    ),
                )
                control_id_hits += 1

    # 4. Evidence-type → control mapping (Tier 4, added 2026-06-04). When an
    #    extractor has classified the file by content shape (e.g. xlsx with
    #    "hostname / serial number / manufacturer" → hw_inventory), route to
    #    the controls in EVIDENCE_TYPE_TO_CONTROLS. Confidence 0.6 sits
    #    between the control-ID tier (0.5, weaker because a stray "AC-2"
    #    mention isn't proof of relevance) and the CCI/doc tiers (0.9+); a
    #    real inventory column layout is a strong-but-not-definitive signal
    #    that the file satisfies the inventory controls.
    #
    #    2026-06-07 ("Tier 4 spray" fix) — REVERTED 2026-06-10 for the same
    #    reason as Tier 3: primary-CCI-only tagging assumed a per-Control
    #    LLM bundle that was never shipped, so it starved every sibling CCI
    #    under the real per-CCI assess loop. We fan the evidence-type match
    #    out to EVERY child CCI of each mapped Control. The tag-count
    #    concern (sw_inventory × four controls × N children) is moot —
    #    those are exactly the rows the per-CCI bundles need, and the
    #    confidence band (0.6) keeps them as corroboration, not proof.
    if evidence_type and evidence_type in EVIDENCE_TYPE_TO_CONTROLS:
        signals_label = (
            ", ".join(evidence_type_signals) if evidence_type_signals else "content shape"
        )
        by_control: dict[str, list[Objective]] = {}
        for cid, obj in _objectives_for_control_ids(
            session,
            EVIDENCE_TYPE_TO_CONTROLS[evidence_type],
            framework_id=framework_id,
        ):
            if obj.id is None:
                continue
            by_control.setdefault(cid, []).append(obj)
        for cid, objs in by_control.items():
            for obj in objs:
                if obj.id is None:
                    continue
                _add(
                    obj.id,
                    relevance=0.8,
                    confidence=0.6,
                    rationale=(
                        f"Auto-classified as {evidence_type.replace('_', ' ')} "
                        f"(detected columns: {signals_label}) — mapped to {cid.upper()}."
                    ),
                )
                evidence_type_hits += 1

    # 4b. Diagram/image boundary rule. A DIAGRAM/IMAGE artifact that looks like
    #     a network/boundary/architecture diagram (by filename, title, or
    #     extracted shape text) is corroborating evidence for the boundary +
    #     data-flow control family. Diagrams carry no CCI token, so without this
    #     they'd tag nothing and disappear from those control pages. Fan out to
    #     the boundary controls via the same helper Tier 4 uses (no hardcoded
    #     CCIs). Keyword-gated for precision; 0.5 confidence (a diagram documents
    #     the boundary, it doesn't prove the control is implemented). Anything
    #     that matches no keyword still flows to Tier 5 / the zero-tag warning.
    if evidence.kind in (EvidenceKind.DIAGRAM, EvidenceKind.IMAGE):
        haystack = " ".join(
            part for part in (evidence.title, evidence.path, text) if part
        ).lower()
        if any(kw in haystack for kw in _DIAGRAM_BOUNDARY_KEYWORDS):
            for cid, obj in _objectives_for_control_ids(
                session, _DIAGRAM_BOUNDARY_CONTROLS, framework_id=framework_id
            ):
                if obj.id is None:
                    continue
                _add(
                    obj.id,
                    relevance=0.6,
                    confidence=0.5,
                    rationale=(
                        f"Network/boundary diagram ({evidence.kind.value}) — "
                        f"corroborates {cid.upper()} boundary documentation."
                    ),
                )
                control_id_hits += 1

    # 4.5. Tool/daemon-name → control NOMINATION (2026; revised after A/B).
    #      Terse CTP terminal-output evidence is named for the TOOL it tests
    #      (xrdp/aide/chrony/...), a near-definitional control SIGNAL that carries
    #      no doc/CCI/control-ID token. An earlier version EMITTED these as
    #      deterministic tags AND counted them toward the Tier-5 gate — a measured
    #      A/B showed that was net-WORSE: it suppressed the LLM judge (so the
    #      judge's content-correct controls were lost) and polysemous tokens
    #      (ssh/sudo/vault/...) sprayed a fixed cluster that REPLACED correct
    #      tags. A tool name is a HYPOTHESIS, not a fact, so it belongs in the
    #      judge's candidate set, not the output.
    #
    #      New behavior (design E+A):
    #      * Collect the tool-mapped control IDs here but DO NOT emit and DO NOT
    #        count toward the gate. They are injected as JUDGE CANDIDATES (so the
    #        judge confirms/rejects each against the file's actual content) and,
    #        for SINGLE-PURPOSE tools only, used as a post-judge recall FLOOR when
    #        the judge accepts nothing (or runs offline).
    #      * ``tool_candidate_cids_derived`` = every matched tool's controls
    #        (judge bias). A caller MAY pass ``tool_candidate_cids`` to OVERRIDE
    #        this derivation (tests pin a specific candidate independent of body
    #        tokens); when None we derive from the path/title/body as usual.
    #      * ``tool_floor_cids`` = controls from UNAMBIGUOUS (single-purpose)
    #        tools only — the safe set eligible for the deterministic floor. This
    #        is ALWAYS derived from real tokens (never the override), so a test
    #        injecting a candidate doesn't accidentally widen the offline floor.
    tool_candidate_cids_derived: set[str] = set()
    tool_floor_cids: set[str] = set()
    tool_floor_tools: dict[str, set[str]] = {}  # cid -> {single-purpose tools}
    tool_haystack_parts = [
        part for part in (evidence.path, evidence.title) if part
    ]
    if text and text.strip():
        tool_haystack_parts.append(text[:_TOOL_NAME_BODY_HEAD_CHARS])
    tool_haystack = " ".join(tool_haystack_parts).lower()
    if tool_haystack:
        seen_tokens = set(_TOOL_NAME_TOKEN_RE.findall(tool_haystack))
        for tool in _TOOL_NAME_TO_CONTROLS:
            if tool not in seen_tokens:
                continue
            cids, ambiguous = _TOOL_NAME_TO_CONTROLS[tool]
            for cid in cids:
                tool_candidate_cids_derived.add(cid)
                if not ambiguous:
                    tool_floor_cids.add(cid)
                    tool_floor_tools.setdefault(cid, set()).add(tool)
    # Caller override takes precedence for JUDGE candidates only (not the floor).
    tool_candidate_cids_effective = (
        set(tool_candidate_cids)
        if tool_candidate_cids is not None
        else tool_candidate_cids_derived
    )

    # 5. Semantic recall backstop (Tier 5, added 2026-06-10). Some real
    #    evidence names no doc number, no CCI, no control ID, and matches no
    #    known content shape — yet is plainly relevant to a few controls by its
    #    prose alone (an account-management SOP that never writes "AC-2"). Tiers
    #    1-4 leave it under-tagged. Tier 5 runs ONLY as a low-tag backstop —
    #    gated on the COUNT OF EXISTING TAGS (not artifacts-per-control) so it
    #    never fires for an artifact the deterministic tiers already placed —
    #    and scores the body against EVERY framework control's requirement text
    #    via the same TF-IDF cosine Tier 3 uses. It admits only controls
    #    clearing a relative drop-off (>= factor × max) AND an absolute floor,
    #    capped at top-K. Strong matches (>= STRONG_FACTOR × max) are
    #    source="auto"; weaker admitted matches are source="auto_review" so the
    #    reviewer can see they were inferred semantically, not deterministically.
    #    This is recall preservation, NOT a controls-per-artifact cap on the
    #    deterministic tiers — those always emit every match they find.
    # Snapshot the gate-deciding count BEFORE Tier 5 can add anything. This is
    # the distinct-objective tag total the deterministic tiers (1-4) produced;
    # the LLM is consulted only when it falls below the low-tag threshold.
    tier1_4_tags = len(existing)
    gate_cleared_by_det = tier1_4_tags >= _TIER5_MIN_EXISTING
    if len(existing) < _TIER5_MIN_EXISTING and text and text.strip():
        all_by_control = _all_objectives_by_control(session, framework_id=framework_id)
        if all_by_control:
            # 5-LLM. Smart backstop: when an LLM client is available, let the
            # judge model decide relevance for the under-tagged artifact instead
            # of the blunt TF-IDF cosine. _tag_via_llm TF-IDF-pre-selects the
            # top candidate controls, asks the judge per candidate, and only
            # emits confident (source="llm") tags — abstaining otherwise. It
            # returns (hits, attempted, errored) so we can tell a confident
            # "nothing relevant" (don't fall back) from an API outage (do).
            run_tfidf = True
            if client is not None:
                artifact_title = (
                    evidence.title
                    or (evidence.path.rsplit("/", 1)[-1] if evidence.path else "")
                    or str(evidence.id)
                )
                # HyDE query-expansion: rewrite the raw body into NIST control
                # prose ONCE per under-tagged artifact. Feeds the hyde + triage
                # RAG lanes. Best-effort — "" on failure degrades to the other
                # lanes (sparse/dense/folder still run). Gated identically to
                # the judge (only under-tagged artifacts pay for it).
                hyde_prose = ""
                expand = getattr(client, "expand_to_control_prose", None)
                if callable(expand):
                    try:
                        hyde_prose = expand(text, model=judge_model) or ""
                    except Exception:  # noqa: BLE001 — never abort tagging
                        log.debug("HyDE expansion raised; continuing", exc_info=True)
                llm_hits, attempted, errored = _tag_via_llm(
                    text,
                    client=client,
                    judge_model=judge_model,
                    all_by_control=all_by_control,
                    artifact_title=artifact_title,
                    add=_add,
                    hyde_prose=hyde_prose,
                    evidence_path=evidence.path,
                    framework_id=framework_id,
                    augment_corpus=augment_corpus,
                    tool_candidate_cids=tool_candidate_cids_effective or None,
                )
                # Instrumentation only — does not alter any verdict. judge_invoked
                # marks that the gate passed AND a client was present (the doc
                # actually reached the judge); attempted/accepted/errored mirror
                # _tag_via_llm's return for the under-tagged-corpus measurement.
                judge_invoked = True
                judge_attempted = attempted
                judge_accepted = llm_hits
                judge_errored = errored

                # Tier-5 ESCALATION (2026-06-24). The cheap judge (Haiku) was
                # handed the correct candidate (tool-injected xrdp→AC-17,
                # chrony→AU-8, …) yet scored every one < 0.6 on ANSI-noisy
                # terminal transcripts a stronger model reads correctly. When the
                # Haiku pass is a CLEAN all-abstain — it actually ran (attempted>0),
                # accepted nothing (llm_hits==0), and did NOT error (errored==0,
                # so this is a confident "nothing fit", not an outage) — re-judge
                # ONCE with the stronger escalation model. Three rails keep this
                # from tagging a genuinely-empty file:
                #   1. structural: a body with < _ESCALATION_MIN_LINES of content.
                #   2. failure-to-execute: a transcript whose only signal is a
                #      command that never ran ([FATAL]/command-not-found/bad arg).
                #      NB: "Permission denied"/non-zero exit are VALID evidence and
                #      are deliberately NOT treated as command errors.
                #   3. the rubric's [A] branch tells the judge to score such
                #      failures 0.0 — model-level defense in depth behind 1+2.
                # None escalation_model (offline/eval default) disables this
                # entirely — we must check it BEFORE the call, else judge_model
                # None would fall through to the client's constructor model.
                if (
                    escalation_model
                    and escalation_model != judge_model
                    and attempted > 0
                    and llm_hits == 0
                    and errored == 0
                    and not _too_few_lines_to_escalate(text)
                    and not _is_command_error_only(text)
                ):
                    esc_hits, esc_attempted, esc_errored = _tag_via_llm(
                        text,
                        client=client,
                        judge_model=escalation_model,
                        all_by_control=all_by_control,
                        artifact_title=artifact_title,
                        add=_add,  # same closure → existing-set dedup, no double tag
                        hyde_prose=hyde_prose,  # reuse; don't pay HyDE twice
                        evidence_path=evidence.path,
                        framework_id=framework_id,
                        augment_corpus=augment_corpus,
                        tool_candidate_cids=tool_candidate_cids_effective or None,
                    )
                    judge_escalated = True
                    judge_escalated_accepted = esc_hits
                    # Accumulate (NOT overwrite) so corpus ratios stay correct.
                    llm_hits += esc_hits
                    judge_attempted += esc_attempted
                    judge_accepted += esc_hits
                    judge_errored += esc_errored

                # Trust partial LLM success. Only fall back to the deterministic
                # TF-IDF backstop when EVERY judge call errored (network/API
                # outage) — never when the judge simply abstained on every
                # candidate. An all-abstain result is a confident "nothing here
                # is relevant"; spraying TF-IDF guesses on top would defeat the
                # precision the LLM tier exists to provide. Uses the post-
                # escalation totals so a successful Opus pass correctly suppresses
                # the TF-IDF fallback.
                run_tfidf = judge_attempted > 0 and judge_errored == judge_attempted
            if not run_tfidf:
                all_by_control = {}  # skip the TF-IDF block below
            # Substance gate (deterministic path only). A body too short to carry
            # real evidence must not have a control INFERRED from topical word
            # overlap — that is the LLM judge's job, not the outage fallback's.
            # Reuses the empty-dict skip so max_cos→0.0 and nothing is emitted.
            elif _distinct_significant_tokens(text) < _TIER5_MIN_BODY_TOKENS:
                all_by_control = {}
            t5_cids = sorted(all_by_control.keys())
            t5_texts = [_control_reference_text(all_by_control[cid]) for cid in t5_cids]
            t5_cos = _tier3_relevance_scores(text, t5_texts)
            max_cos = max(t5_cos, default=0.0)
            if max_cos > 0.0:
                rel_floor = max(
                    _TIER5_RELATIVE_FACTOR * max_cos, _TIER5_MIN_COSINE
                )
                strong_floor = _TIER5_STRONG_FACTOR * max_cos
                qualifying = [
                    (cid, cos)
                    for cid, cos in zip(t5_cids, t5_cos)
                    if cos >= rel_floor
                ]
                # Top-K by cosine (desc), ties broken by cid for determinism.
                qualifying.sort(key=lambda pair: (-pair[1], pair[0]))
                for cid, cosine in qualifying[:_TIER5_TOPK]:
                    relevance = round(
                        _TIER3_RELEVANCE_FLOOR
                        + (_TIER3_RELEVANCE_CEIL - _TIER3_RELEVANCE_FLOOR) * cosine,
                        3,
                    )
                    src = "auto" if cosine >= strong_floor else "auto_review"
                    for obj in all_by_control[cid]:
                        if obj.id is None:
                            continue
                        _add(
                            obj.id,
                            relevance=relevance,
                            confidence=_TIER5_CONFIDENCE,
                            source=src,
                            rationale=(
                                f"Semantic match to {cid.upper()} "
                                f"(text relevance {cosine:.2f}; no control ID "
                                f"or CCI in body — inferred from prose)."
                            ),
                        )
                        semantic_hits += 1

    # 4.5-floor (design A). Tool names are nominated as judge candidates above
    # (design E), NOT emitted blind — so the judge confirms/rejects each against
    # the file's real content. But a SINGLE-PURPOSE daemon (aide/xrdp/chrony/…)
    # is near-definitional, and we must not regress the recall win: when the
    # judge NEVER RAN (offline / gate cleared by other deterministic tiers), a
    # single-purpose tool's control with NO tag from any tier gets a
    # low-confidence auto_review FLOOR so the file never silently drops its
    # canonical control. Gated to UNAMBIGUOUS tools only (tool_floor_cids) —
    # polysemous tokens never emit, they only ever nominate. Checks the live tag
    # state (existing objective ids).
    #
    # CRITICAL refinement (two SME reviews): floor ONLY when the judge did NOT
    # actually evaluate the control. A single-purpose tool's control is injected
    # as a judge candidate (design E), so if the judge RAN (`judge_invoked`),
    # an untagged control means the judge LOOKED and REJECTED it (< 0.6) — likely
    # because the file content invalidates the tool (e.g. "xrdp was removed").
    # Overriding an active judge rejection with a blind floor would reintroduce
    # the very false-positive spray we just engineered away. So the floor is a
    # strict UPTIME fallback: it fires only when `not judge_invoked` (client
    # offline, or the gate was cleared by other deterministic tiers so the judge
    # never ran) — never to second-guess a judge that did its job.
    if tool_floor_cids and not judge_invoked:
        # Resolve the single-purpose tools' controls to objectives. A control is
        # considered ALREADY-COVERED if ANY of its objectives is in ``existing``
        # (tagged by any tier); only controls with ZERO existing tags get the
        # floor. Group objectives by control first so the any-objective-tagged
        # check is per-control, not per-objective.
        floor_objs: dict[str, list[Objective]] = {}
        for cid, obj in _objectives_for_control_ids(
            session, sorted(tool_floor_cids), framework_id=framework_id
        ):
            if obj.id is not None:
                floor_objs.setdefault(cid, []).append(obj)
        for cid, objs in floor_objs.items():
            if any(o.id in existing for o in objs):
                continue  # judge or another tier already covered this control
            tools_label = ", ".join(sorted(tool_floor_tools.get(cid, ())))
            for obj in objs:
                if obj.id is None or obj.id in existing:
                    continue
                _add(
                    obj.id,
                    relevance=0.6,
                    confidence=_TIER5_CONFIDENCE,
                    source="auto_review",
                    rationale=(
                        f"Single-purpose tool '{tools_label}' detected and the "
                        f"judge added no tag for {cid.upper()} — emitted as a "
                        "recall floor (review)."
                    ),
                )
                tool_name_hits += 1

    # Invalidate any stale Assessment rows whose CCI just gained a tag —
    # without this, rule_no_evidence verdicts written before this artifact
    # landed silently persist (cache replays the stale Non-Compliant). The
    # helper only flips rows where needs_review is currently False, so a
    # row already in the review queue with a more specific reason is left
    # alone. Caller commits.
    if newly_tagged_objective_ids:
        invalidate_assessments_for_objectives(session, newly_tagged_objective_ids)

    # Measure-first log line (verdict-neutral). One grep-able record per evidence
    # file so a corpus ingest can be reduced with `grep tier5_judge` to answer
    # "what fraction of documents reach the LLM judge, and of those, how many
    # does it accept vs. abstain on?" — the metric driving the <10%-to-LLM goal.
    # det_cleared=True means Tiers 1-4 alone satisfied the low-tag gate (no LLM).
    log.info(
        "tier5_judge evidence_id=%s det_tags=%d det_cleared=%s judge_invoked=%s "
        "judge_attempted=%d judge_accepted=%d judge_errored=%d judge_escalated=%s "
        "judge_escalated_accepted=%d",
        evidence.id,
        tier1_4_tags,
        gate_cleared_by_det,
        judge_invoked,
        judge_attempted,
        judge_accepted,
        judge_errored,
        judge_escalated,
        judge_escalated_accepted,
    )

    return TaggingResult(
        evidence_id=evidence.id,
        tags_created=created,
        doc_number_hits=doc_hits,
        cci_hits=cci_hits,
        control_id_hits=control_id_hits,
        evidence_type_hits=evidence_type_hits,
        tool_name_hits=tool_name_hits,
        semantic_hits=semantic_hits,
        llm_hits=llm_hits,
        tier1_4_tags=tier1_4_tags,
        gate_cleared_by_det=gate_cleared_by_det,
        judge_invoked=judge_invoked,
        judge_attempted=judge_attempted,
        judge_accepted=judge_accepted,
        judge_errored=judge_errored,
        judge_escalated=judge_escalated,
        judge_escalated_accepted=judge_escalated_accepted,
    )
