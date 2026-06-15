"""Fixture loaders and assertion helpers for the tagger precision/recall eval.

This module owns the seeding + assertion machinery every case file in
``cases/`` runs through. Three principles drive the design:

1. **Self-contained catalogs per case.** Each case file ships its own
   minimal ``Framework`` / ``Control`` / ``Objective`` rows. No shared
   fixture, no module-scoped DB. One case = one in-memory SQLite. This
   makes "AC-2 mention tags exactly N children" assertions exact and
   catalog-version-independent — the real 800-53r4 catalog has ~1000
   objectives, and pinning a count against that drifts the moment a
   catalog reload changes the row count. Trade-off is a few extra JSON
   lines per case; we accept that to keep the assertions exact.

2. **Reuse the boundary-eval Evidence-on-disk pattern.** The tagger
   reads ``text`` as a string parameter (no file IO inside
   ``tag_evidence``) but we still write the inline ``text`` to a tmp
   file and point ``Evidence.extracted_text_path`` at it. Keeps the
   fixture realistic and lets a future case round-trip through an
   extractor without a schema change. Mirrors
   ``tests/eval/boundary/_fixtures.py::_load_doc_evidence``.

3. **Structured assertion failures, not bare asserts.** Each
   ``_assert_*`` helper produces a diagnostic block that names the
   objective_id and tier-attribution diff in one pytest output. The
   goal is "case-file author can debug from pytest output alone";
   bare ``assert x == y`` on a 30-tag set is unreadable.

Why no LLM stub helpers
-----------------------
Tagger is fully deterministic — no LLM, no embeddings, no network. The
``tests/eval/_stubs.py`` ``StubLlmClient`` machinery used by the
assessor and boundary harnesses is intentionally NOT imported here.
What this module reuses from those harnesses is the parametrize-by-
filename pattern and the in-memory SQLite pattern, not the stub queue.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from cybersecurity_assessor.evidence.extractors._stig_common import StigFindingRow
from cybersecurity_assessor.evidence.tagger import TaggingResult
from cybersecurity_assessor.models import (
    Control,
    Evidence,
    EvidenceKind,
    EvidenceTag,
    FindingStatus,
    Framework,
    Objective,
)

__all__ = [
    "_make_session",
    "_load_catalog",
    "_load_evidence",
    "_build_stig_findings",
    "_assert_tier_hits",
    "_assert_tag_count",
    "_assert_tags_present",
    "_assert_tags_absent",
]


# Filename extension → EvidenceKind. The tagger doesn't inspect ``kind``
# directly (it routes purely on text content + evidence_type + path) but a
# realistic kind keeps seed data faithful and lets future cases assert on
# kind-conditional behavior without re-seeding.
_KIND_BY_SUFFIX: dict[str, EvidenceKind] = {
    ".pdf": EvidenceKind.PDF,
    ".docx": EvidenceKind.DOCX,
    ".pptx": EvidenceKind.PPTX,
    ".xlsx": EvidenceKind.XLSX,
    ".txt": EvidenceKind.TEXT,
    ".ckl": EvidenceKind.STIG_CKL,
    ".cklb": EvidenceKind.STIG_CKLB,
    ".nessus": EvidenceKind.NESSUS,
}


# ---------------------------------------------------------------------------
# Session + catalog seeding
# ---------------------------------------------------------------------------


def _make_session() -> tuple[Session, Any]:
    """Spin up an in-memory SQLite with the assessor schema realized.

    StaticPool keeps the single connection alive across the test so the
    in-memory DB (which dies on connection close) persists for the
    duration of one case. Identical pattern to
    ``tests/eval/boundary/test_boundary_extraction.py::_make_session``.
    """
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    return Session(engine), engine


def _load_catalog(case: dict[str, Any], session: Session) -> dict[str, int]:
    """Seed Framework + Controls + Objectives from ``case["catalog"]``.

    Case-file catalog block shape::

        {
          "catalog": {
            "framework": {"framework_id": "NIST-800-53r4", "name": "...", "version": "Rev 4"},
            "controls":  [{"control_id": "ac-2", "title": "...", "family": "AC"}],
            "objectives":[{"control_id": "ac-2", "objective_id": "CCI-000015",
                           "text": "...", "implementation_guidance": "...",
                           "assessment_procedures": "..."}]
          }
        }

    Multiple frameworks are also supported — the same catalog block can
    declare a ``frameworks`` list (plural) for cases pinning the
    cross-framework leak failure mode. When ``frameworks`` is present,
    ``framework`` is ignored and the returned map uses the first entry's
    ``framework_id`` string as the ``"framework"`` key.

    Returns a name→PK map so the runner can translate ``case["framework_id"]``
    (a string identifier) to the int PK that ``tag_evidence`` and
    ``EvidenceTag.framework_id`` take.

    Why per-case catalog instead of loading the real one:
    the real 800-53r4 catalog has ~1000 objectives. "AC-2 mention tags
    exactly N children" only stays meaningful if N is anchored to a
    minimal catalog we own. A catalog version bump that adds an AC-2
    enhancement would silently flip every Tier-3 assertion otherwise.
    """
    catalog = case.get("catalog") or {}
    id_map: dict[str, int] = {}

    # Allow either "framework" (single, common) or "frameworks" (plural,
    # for cross-framework leak pins).
    framework_blocks = catalog.get("frameworks") or (
        [catalog["framework"]] if "framework" in catalog else []
    )
    if not framework_blocks:
        raise ValueError(
            "case catalog missing both 'framework' and 'frameworks' blocks"
        )

    # framework_id (string) → Framework row PK
    fw_pk_by_str_id: dict[str, int] = {}
    for fw_block in framework_blocks:
        fw = Framework(
            name=fw_block.get("name", "Test Framework"),
            version=fw_block.get("version", "test"),
            framework_id=fw_block["framework_id"],
        )
        session.add(fw)
        session.commit()
        session.refresh(fw)
        assert fw.id is not None  # post-refresh invariant
        fw_pk_by_str_id[fw_block["framework_id"]] = fw.id

    # First framework wins the bare "framework" key for backward-compat.
    id_map["framework"] = fw_pk_by_str_id[framework_blocks[0]["framework_id"]]
    # Also expose per-framework lookup so cross-framework cases can name
    # the second framework explicitly in ``case["framework_id"]``.
    for k, v in fw_pk_by_str_id.items():
        id_map[k] = v

    # Controls — (framework_id_str, control_id) → Control row PK. The
    # control_id-string lookup is keyed by tuple so two frameworks can
    # both declare ``ac-2`` without colliding.
    ctrl_pk_by_key: dict[tuple[str, str], int] = {}
    for ctrl_block in catalog.get("controls", []):
        # ``framework_id`` on a control defaults to the first framework
        # if not specified — keeps single-framework cases terse.
        fw_str_id = ctrl_block.get(
            "framework_id", framework_blocks[0]["framework_id"]
        )
        ctrl = Control(
            framework_id=fw_pk_by_str_id[fw_str_id],
            control_id=ctrl_block["control_id"],
            title=ctrl_block.get("title", ctrl_block["control_id"]),
            family=ctrl_block.get(
                "family",
                # Best-effort: pull "AC" out of "ac-2" / "ac-2.1".
                ctrl_block["control_id"].split("-", 1)[0].upper(),
            ),
        )
        session.add(ctrl)
        session.commit()
        session.refresh(ctrl)
        assert ctrl.id is not None
        ctrl_pk_by_key[(fw_str_id, ctrl_block["control_id"])] = ctrl.id

    # Objectives — child rows of Control. Same per-framework key as above.
    for obj_block in catalog.get("objectives", []):
        fw_str_id = obj_block.get(
            "framework_id", framework_blocks[0]["framework_id"]
        )
        ctrl_pk = ctrl_pk_by_key[(fw_str_id, obj_block["control_id"])]
        obj = Objective(
            control_id_fk=ctrl_pk,
            objective_id=obj_block["objective_id"],
            source=obj_block.get("source", "CCI"),
            text=obj_block.get("text", ""),
            implementation_guidance=obj_block.get("implementation_guidance"),
            assessment_procedures=obj_block.get("assessment_procedures"),
        )
        session.add(obj)
    session.commit()

    return id_map


# ---------------------------------------------------------------------------
# Evidence + STIG seeding
# ---------------------------------------------------------------------------


def _load_evidence(
    case: dict[str, Any], session: Session, tmp_path: Path
) -> Evidence:
    """Seed one Evidence row + write its text to ``tmp_path/<filename>.txt``.

    Case-file evidence block shape::

        {
          "evidence": {
            "filename": "policy.pdf",       # required, drives kind + path URI
            "doc_number": "USD00022222",    # optional, fed to Tier 1
            "kind": "PDF",                  # optional, override _KIND_BY_SUFFIX
            "text": "AC-2 policy...",       # optional, tagger reads it directly
            "path_override": "..."          # optional, override the
                                            # ``file:///fixtures/...`` URI; the
                                            # Tier 3 path-only pin uses this
                                            # to put a control ID in the URI
                                            # without polluting the text body
          }
        }

    Returns the persisted Evidence (with .id set) ready to pass to
    ``tag_evidence``. Caller seeds ``stig_findings`` separately via
    ``_build_stig_findings`` because they are passed as a list of dataclass
    instances, not persisted rows.
    """
    ev_block = case["evidence"]
    filename = ev_block["filename"]  # KeyError = case file bug, fail loud
    text = ev_block.get("text", "")
    suffix = Path(filename).suffix.lower()
    ev_kind = _KIND_BY_SUFFIX.get(suffix, EvidenceKind.OTHER)
    # Optional explicit kind override (rare — only when a case wants to
    # decouple ``filename`` extension from ``Evidence.kind``).
    if "kind" in ev_block:
        ev_kind = EvidenceKind(ev_block["kind"].lower())

    # Write the inline text to a tmp file so extracted_text_path is realistic.
    # The tagger itself does NOT read this file (it takes ``text`` directly),
    # but a future eval slice that exercises the extract→tag pipeline can
    # reuse the same fixture without a schema change.
    text_path = tmp_path / f"{filename}.txt"
    text_path.write_text(text, encoding="utf-8")

    sha = ev_block.get("sha256") or hashlib.sha256(
        text.encode("utf-8")
    ).hexdigest()

    # ``path`` is a URI; the tagger scans this with _CONTROL_ID_RE for Tier 3
    # path-based matches. ``path_override`` lets a case put a control ID in
    # the URI without also putting it in the text body (the pin case for
    # "control-ID in filename only").
    path = ev_block.get("path_override") or f"file:///fixtures/{filename}"

    ev = Evidence(
        path=path,
        sha256=sha,
        kind=ev_kind,
        size_bytes=len(text.encode("utf-8")),
        extracted_text_path=str(text_path),
        title=ev_block.get("title") or filename,
        doc_number=ev_block.get("doc_number"),
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)
    return ev


def _build_stig_findings(
    stig_blocks: list[dict[str, Any]],
) -> list[StigFindingRow]:
    """Translate ``case["evidence"]["stig_findings"]`` into dataclass rows.

    Case-file stig-finding block shape::

        {"rule_id": "SV-12345r1_rule", "status": "Open",
         "cci_refs": "CCI-000015, CCI-000016",
         "severity": "medium", "finding_details": "...", "comments": "..."}

    ``status`` is the string form of ``FindingStatus`` (e.g. "Open",
    "Not_A_Finding"); the dataclass accepts the enum so we convert.
    Empty list returns empty list — Tier 2 sees no findings.
    """
    findings: list[StigFindingRow] = []
    for block in stig_blocks:
        findings.append(
            StigFindingRow(
                rule_id=block["rule_id"],
                status=FindingStatus(block.get("status", "Open")),
                rule_version=block.get("rule_version"),
                cci_refs=block.get("cci_refs"),
                severity=block.get("severity"),
                finding_details=block.get("finding_details"),
                comments=block.get("comments"),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------


def _assert_tier_hits(
    result: TaggingResult, expected: dict[str, int]
) -> None:
    """Assert ``TaggingResult`` per-tier counters match the case spec.

    Only keys present in ``expected`` are checked — a case can pin
    only the tier(s) it cares about and ignore the rest. Empty dict
    is a no-op (a case that asserts only on the tag set).

    Tier-hit attribution is the cheapest regression signal we have:
    a CCI mistakenly tagged via Tier 2 instead of Tier 3 produces
    the same tags but shifts the hit counters, which would slip past
    a tag-set-only assertion. Catches "_CCI_RE accidentally matches
    a control ID format" or "Tier 4 dict edit silently widens spray".
    """
    mismatches: list[str] = []
    for key, want in expected.items():
        got = getattr(result, key, None)
        if got is None:
            mismatches.append(f"  unknown tier_hits key: {key!r}")
        elif got != want:
            mismatches.append(f"  {key}: expected {want}, got {got}")
    if mismatches:
        raise AssertionError(
            "tier_hits mismatch:\n" + "\n".join(mismatches)
            + f"\n  full result: {result!r}"
        )


def _assert_tag_count(
    session: Session, evidence_id: int, expected_count: int | None
) -> None:
    """Assert the total ``EvidenceTag`` row count for this evidence.

    ``None`` skips the check (a case can pin only ``tier_hits`` /
    ``tags_must_include``). When set, this is the recall ceiling — if
    a regression widens tagging beyond the intended count, the diff
    surfaces here even if every named ``tags_must_include`` entry is
    still present.
    """
    if expected_count is None:
        return
    rows = session.exec(
        select(EvidenceTag).where(EvidenceTag.evidence_id == evidence_id)
    ).all()
    if len(rows) == expected_count:
        return
    # Diagnostic: list the actual tags by objective_id so the author
    # can see what spilled in / fell out without re-running with --pdb.
    obj_ids = sorted(r.objective_id for r in rows)
    raise AssertionError(
        f"tag_count mismatch: expected {expected_count}, got {len(rows)}\n"
        f"  tagged objective row PKs: {obj_ids}"
    )


def _assert_tags_present(
    session: Session,
    evidence_id: int,
    must_include: list[dict[str, Any]],
) -> None:
    """Assert each ``must_include`` entry exists with matching attributes.

    Each entry is a partial-match dict. ``objective_id`` is required (the
    string ID like ``"CCI-000015"``, not the row PK); other keys are
    optional and only checked when present:

        ``source``             — "auto" | "manual" | "llm"
        ``relevance``          — float (exact match, no tolerance)
        ``confidence``         — float (exact match, no tolerance)
        ``rationale_contains`` — substring match against ``rationale``
        ``framework_id``       — int (the Framework row PK)

    The "partial-match" design lets a case pin just the objective set
    (recall test) OR pin tier-attribution by also naming
    ``source``/``relevance``/``confidence``/``rationale_contains``.
    """
    rows = session.exec(
        select(EvidenceTag, Objective)
        .join(Objective, Objective.id == EvidenceTag.objective_id)
        .where(EvidenceTag.evidence_id == evidence_id)
    ).all()
    # Build lookup keyed by ``objective_id`` STRING (case-file friendly).
    # A single string ID can map to multiple rows when two frameworks both
    # declare the same CCI — the cross-framework leak pin exercises this.
    by_obj_str_id: dict[str, list[EvidenceTag]] = {}
    for tag, obj in rows:
        by_obj_str_id.setdefault(obj.objective_id, []).append(tag)

    failures: list[str] = []
    for entry in must_include:
        want_obj_str = entry["objective_id"]
        candidates = by_obj_str_id.get(want_obj_str, [])
        if not candidates:
            failures.append(
                f"  missing tag for objective_id={want_obj_str!r}; "
                f"tagged objectives: {sorted(by_obj_str_id.keys())}"
            )
            continue
        # If the entry constrains framework_id, filter candidates by it.
        if "framework_id" in entry:
            candidates = [
                t for t in candidates if t.framework_id == entry["framework_id"]
            ]
            if not candidates:
                failures.append(
                    f"  no tag for objective_id={want_obj_str!r} matched "
                    f"framework_id={entry['framework_id']!r}"
                )
                continue

        # Pick the first matching candidate and validate optional attrs.
        # If a case needs to assert N tags for the same objective_id (e.g.
        # cross-framework leak with two framework rows), declare two
        # entries differing only by framework_id.
        cand = candidates[0]
        if "source" in entry and cand.source != entry["source"]:
            failures.append(
                f"  {want_obj_str} source: expected {entry['source']!r}, "
                f"got {cand.source!r}"
            )
        if "relevance" in entry and cand.relevance != entry["relevance"]:
            failures.append(
                f"  {want_obj_str} relevance: expected {entry['relevance']}, "
                f"got {cand.relevance}"
            )
        # Band pins for content-dependent scores (Tier 3 TF-IDF cosine,
        # 2026-06-10): exact cosine floats are brittle across sklearn
        # versions, so a case pins the [min, max] band the relevance must
        # fall in (anchored on _TIER3_RELEVANCE_FLOOR / _CEIL) instead.
        if "relevance_min" in entry and (
            cand.relevance is None or cand.relevance < entry["relevance_min"]
        ):
            failures.append(
                f"  {want_obj_str} relevance: expected >= "
                f"{entry['relevance_min']}, got {cand.relevance}"
            )
        if "relevance_max" in entry and (
            cand.relevance is None or cand.relevance > entry["relevance_max"]
        ):
            failures.append(
                f"  {want_obj_str} relevance: expected <= "
                f"{entry['relevance_max']}, got {cand.relevance}"
            )
        if "confidence" in entry and cand.confidence != entry["confidence"]:
            failures.append(
                f"  {want_obj_str} confidence: expected {entry['confidence']}, "
                f"got {cand.confidence}"
            )
        if "rationale_contains" in entry:
            needle = entry["rationale_contains"]
            if not cand.rationale or needle not in cand.rationale:
                failures.append(
                    f"  {want_obj_str} rationale missing substring "
                    f"{needle!r}; got {cand.rationale!r}"
                )

    if failures:
        raise AssertionError(
            "tags_must_include failures:\n" + "\n".join(failures)
        )


def _assert_tags_absent(
    session: Session,
    evidence_id: int,
    must_not_include: list[dict[str, Any]],
) -> None:
    """Assert NONE of the ``must_not_include`` entries got tagged.

    Each entry is a partial-match dict keyed by ``objective_id``
    (string). If ``framework_id`` is set on the entry, only that
    specific framework instance is checked — useful for the
    framework-filter pin where we want to assert "AC-2 is tagged
    under r4 but NOT under r5" once the filter lands.

    Catches the spray failure modes: a case can declare "AC-2 mention
    does NOT tag AC-3's child objectives" and pin that the bounded-by-
    control invariant hasn't regressed to the removed family path.
    """
    if not must_not_include:
        return
    rows = session.exec(
        select(EvidenceTag, Objective)
        .join(Objective, Objective.id == EvidenceTag.objective_id)
        .where(EvidenceTag.evidence_id == evidence_id)
    ).all()

    failures: list[str] = []
    for entry in must_not_include:
        forbidden_str = entry["objective_id"]
        offending = [
            tag for tag, obj in rows if obj.objective_id == forbidden_str
        ]
        if "framework_id" in entry:
            offending = [
                t for t in offending if t.framework_id == entry["framework_id"]
            ]
        if offending:
            fids = sorted({t.framework_id for t in offending})
            failures.append(
                f"  leaked tag for forbidden objective_id={forbidden_str!r} "
                f"(framework_id(s): {fids})"
            )
    if failures:
        raise AssertionError(
            "tags_must_not_include failures:\n" + "\n".join(failures)
        )
