"""Tests for Assessment freshness invalidation.

Pins two contracts on
``cybersecurity_assessor.engine.invalidation.invalidate_assessments_for_objectives``
and one contract on the tagger that drives it:

1. **Only-flip-if-currently-False invariant.** The helper must NOT
   clobber rows whose ``needs_review`` is already True. Reviewers may have
   set ``review_reason`` to a more specific token (``low-confidence``,
   ``unverified-cites``, etc.); our generic
   ``"evidence-changed-since-assessment"`` reason has weaker signal than
   theirs.

2. **Rowcount honesty.** Returns the number of rows actually touched —
   ``0`` when the objective has no prior assessment or every assessment
   was already in the review queue.

3. **Tagger end-to-end.** When ``tag_evidence`` creates new EvidenceTag
   rows for an Objective, any pre-existing Assessment for that Objective
   is flagged with ``review_reason="evidence-changed-since-assessment"``.
   This is the regression test for the stale ``rule_no_evidence`` bug:
   CCI-000056 was assessed Non-Compliant at 04:20:34 then evidence landed
   at 04:22:23; without the auto-invalidation the decision-cache happily
   replayed the stale verdict forever.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.engine.invalidation import (  # noqa: E402
    EVIDENCE_CHANGED_REASON,
    invalidate_assessments_for_objectives,
)
from cybersecurity_assessor.evidence.tagger import tag_evidence  # noqa: E402
from cybersecurity_assessor.models import (  # noqa: E402
    Assessment,
    ComplianceStatus,
    Control,
    Evidence,
    EvidenceKind,
    Framework,
    NarrativeClass,
    Objective,
    Workbook,
)


def _utc() -> datetime:
    return datetime.now(timezone.utc)


def _engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    return engine


def _seed_minimal_tree(session: Session, tmp_path: Path) -> tuple[int, int, int]:
    """Seed Framework + Control + Objective + Workbook; return their ids."""
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)

    c = Control(framework_id=fw.id, control_id="ac-2", title="AC-2", family="AC")
    session.add(c)
    session.commit()
    session.refresh(c)

    o = Objective(
        control_id_fk=c.id,
        objective_id="CCI-000015",
        source="CCI",
        text="The organization automates account management.",
    )
    session.add(o)
    session.commit()
    session.refresh(o)

    wb_path = tmp_path / "demo.xlsx"
    wb_path.write_bytes(b"x")
    wb = Workbook(path=str(wb_path), filename=wb_path.name, framework_id=fw.id)
    session.add(wb)
    session.commit()
    session.refresh(wb)

    return fw.id, o.id, wb.id


def _assessment(
    *, workbook_id: int, objective_id: int, needs_review: bool, review_reason: str | None = None
) -> Assessment:
    return Assessment(
        workbook_id=workbook_id,
        objective_id=objective_id,
        excel_row=1,
        status=ComplianceStatus.NON_COMPLIANT,
        tester="test",
        date_tested=_utc(),
        narrative_q="x",
        narrative_class=NarrativeClass.AMBIGUOUS,
        needs_review=needs_review,
        review_reason=review_reason,
    )


def test_invalidate_flips_only_rows_currently_not_in_review(tmp_path: Path) -> None:
    """The only-flip-if-False invariant.

    Seeds two assessments on TWO distinct objectives (one Assessment per
    (workbook, objective) is enforced by uq_assessment_workbook_objective): one
    trusted (needs_review=False, no reason) and one already-flagged
    (needs_review=True, custom reason). Calls the helper for BOTH objectives.
    The trusted row must flip; the flagged row's reason must NOT be overwritten.
    """
    engine = _engine()
    with Session(engine) as s:
        _fw, obj_id, wb_id = _seed_minimal_tree(s, tmp_path)
        # Second objective under the same control so both can carry their own
        # Assessment without violating the (workbook, objective) uniqueness.
        o2 = Objective(
            control_id_fk=s.get(Objective, obj_id).control_id_fk,
            objective_id="CCI-000016",
            source="CCI",
            text="Second objective for the invariant test.",
        )
        s.add(o2)
        s.commit()
        s.refresh(o2)
        obj_id2 = o2.id

        trusted = _assessment(workbook_id=wb_id, objective_id=obj_id, needs_review=False)
        already_flagged = _assessment(
            workbook_id=wb_id,
            objective_id=obj_id2,
            needs_review=True,
            review_reason="low-confidence",
        )
        s.add(trusted)
        s.add(already_flagged)
        s.commit()
        s.refresh(trusted)
        s.refresh(already_flagged)
        trusted_id = trusted.id
        already_flagged_id = already_flagged.id

        rowcount = invalidate_assessments_for_objectives(s, {obj_id, obj_id2})
        s.commit()

        assert rowcount == 1, (
            "Only the trusted row should flip; already-flagged row must be ignored"
        )

        s.expire_all()
        trusted_after = s.get(Assessment, trusted_id)
        flagged_after = s.get(Assessment, already_flagged_id)

        assert trusted_after is not None and flagged_after is not None
        assert trusted_after.needs_review is True
        assert trusted_after.review_reason == EVIDENCE_CHANGED_REASON
        # The reviewer's more-specific reason must survive untouched.
        assert flagged_after.needs_review is True
        assert flagged_after.review_reason == "low-confidence", (
            "invalidation clobbered a reviewer-set reason — only-flip-if-False "
            "invariant has regressed"
        )


def test_invalidate_returns_zero_when_no_matching_rows(tmp_path: Path) -> None:
    """Objective with no Assessment → rowcount 0, no error."""
    engine = _engine()
    with Session(engine) as s:
        _fw, obj_id, _wb_id = _seed_minimal_tree(s, tmp_path)
        # No assessments seeded for this objective.
        rowcount = invalidate_assessments_for_objectives(s, {obj_id})
        s.commit()
        assert rowcount == 0


def test_invalidate_exempts_evidence_independent_verdicts(tmp_path: Path) -> None:
    """CRM-inherited / rule-deterministic rows are NOT flagged; LLM rows ARE.

    A CRM-inherited (or rule_8b NA) verdict's basis is evidence-INDEPENDENT —
    uploading a local artifact can't change inheritance or a scope exclusion.
    Flagging those "evidence-changed" was the bug that flipped every inherited
    control to needs-review on any evidence upload. Only evidence-derived
    verdicts (llm / rule_no_evidence / cache / NULL legacy) get flagged.
    """
    from cybersecurity_assessor.models import VerdictSource

    engine = _engine()
    with Session(engine) as s:
        _fw, obj_id, wb_id = _seed_minimal_tree(s, tmp_path)
        ctrl_fk = s.get(Objective, obj_id).control_id_fk

        def _obj(cci: str) -> int:
            o = Objective(control_id_fk=ctrl_fk, objective_id=cci, source="CCI", text=cci)
            s.add(o)
            s.commit()
            s.refresh(o)
            return o.id

        obj_inh = obj_id
        obj_rule = _obj("CCI-000016")
        obj_llm = _obj("CCI-000017")
        obj_legacy = _obj("CCI-000018")

        def _seed(oid: int, vs) -> int:
            a = _assessment(workbook_id=wb_id, objective_id=oid, needs_review=False)
            a.verdict_source = vs
            s.add(a)
            s.commit()
            s.refresh(a)
            return a.id

        inh_id = _seed(obj_inh, VerdictSource.CRM_INHERITED)
        rule_id = _seed(obj_rule, VerdictSource.RULE_8B)
        llm_id = _seed(obj_llm, VerdictSource.LLM_ACCEPT)
        legacy_id = _seed(obj_legacy, None)  # legacy NULL → still flagged

        rowcount = invalidate_assessments_for_objectives(
            s, {obj_inh, obj_rule, obj_llm, obj_legacy}
        )
        s.commit()
        s.expire_all()

        # Evidence-independent → exempt.
        assert s.get(Assessment, inh_id).needs_review is False
        assert s.get(Assessment, rule_id).needs_review is False
        # Evidence-derived (and NULL legacy) → flagged.
        assert s.get(Assessment, llm_id).needs_review is True
        assert s.get(Assessment, legacy_id).needs_review is True
        assert rowcount == 2


def test_invalidate_empty_iterable_is_no_op(tmp_path: Path) -> None:
    """Calling with an empty set must short-circuit and not emit a query."""
    engine = _engine()
    with Session(engine) as s:
        # Set up an assessment that would otherwise be flippable, to prove
        # the empty-input early-return really kicks in.
        _fw, obj_id, wb_id = _seed_minimal_tree(s, tmp_path)
        s.add(_assessment(workbook_id=wb_id, objective_id=obj_id, needs_review=False))
        s.commit()

        rowcount = invalidate_assessments_for_objectives(s, set())
        s.commit()
        assert rowcount == 0

        s.expire_all()
        a = s.exec(select(Assessment).where(Assessment.objective_id == obj_id)).first()
        assert a is not None and a.needs_review is False, (
            "empty-input call should not touch any assessment"
        )


def test_tagger_invalidates_prior_assessment_after_new_tag(tmp_path: Path) -> None:
    """End-to-end: tag_evidence → invalidate.

    Seeds an Objective with a prior trusted Assessment, then ingests a new
    Evidence whose extracted text mentions CCI-000015 directly (Tier-2
    CCI-direct path, confidence 0.95). The tagger must:
      1. Create the EvidenceTag row (sanity check that the tag fired).
      2. Flag the prior Assessment as needs_review with the
         "evidence-changed-since-assessment" reason.

    This is the exact regression scenario from the audit run that
    motivated the invalidation helper.
    """
    engine = _engine()
    with Session(engine) as s:
        _fw, obj_id, wb_id = _seed_minimal_tree(s, tmp_path)

        # Pre-existing Non-Compliant verdict — the kind rule_no_evidence
        # stamps when zero artifacts are tagged.
        prior = _assessment(workbook_id=wb_id, objective_id=obj_id, needs_review=False)
        s.add(prior)
        s.commit()
        s.refresh(prior)
        prior_id = prior.id

        # New evidence lands seconds after the verdict was written. The
        # extractor returns text with a direct CCI reference, which Tier 2
        # of the tagger matches verbatim against Objective.objective_id.
        # Use a STIG kind so Tier 2's text-scrape branch fires under the
        # 2026-06-07 kind-gate. Invalidation is what's under test here; the
        # specific tagger tier that creates the tag is incidental.
        ev_path = tmp_path / "account_mgmt_scan.ckl"
        ev_path.write_bytes(b"placeholder")
        ev = Evidence(
            path=str(ev_path),
            sha256="deadbeef" * 8,
            kind=EvidenceKind.STIG_CKL,
            size_bytes=len(b"placeholder"),
            workbook_id=wb_id,
        )
        s.add(ev)
        s.commit()
        s.refresh(ev)

        extracted_text = (
            "Account Management Policy. This document satisfies CCI-000015 "
            "by describing the automated account-management workflow."
        )
        result = tag_evidence(s, ev, extracted_text)
        s.commit()

        # Sanity: the CCI-direct tier fired exactly once for this CCI.
        assert result.cci_hits >= 1, "tagger did not match the CCI-direct reference"
        assert result.tags_created >= 1

        s.expire_all()
        prior_after = s.get(Assessment, prior_id)
        assert prior_after is not None
        assert prior_after.needs_review is True, (
            "tagger did not invalidate prior assessment — stale-verdict bug "
            "from feedback_evidence_sufficiency / audit run has regressed"
        )
        assert prior_after.review_reason == EVIDENCE_CHANGED_REASON


def test_tagger_no_new_tags_does_not_invalidate(tmp_path: Path) -> None:
    """If tag_evidence finds nothing new, no invalidation fires.

    The closure tracks ``newly_tagged_objective_ids`` and only calls the
    helper when that set is non-empty. Evidence with no CCI / doc / control
    token must leave existing Assessments untouched.
    """
    engine = _engine()
    with Session(engine) as s:
        _fw, obj_id, wb_id = _seed_minimal_tree(s, tmp_path)

        prior = _assessment(workbook_id=wb_id, objective_id=obj_id, needs_review=False)
        s.add(prior)
        s.commit()
        s.refresh(prior)
        prior_id = prior.id

        # Generic text, no CCI / USD / control-ID tokens.
        ev_path = tmp_path / "vendor_whitepaper.pdf"
        ev_path.write_bytes(b"x")
        ev = Evidence(
            path=str(ev_path),
            sha256="cafebabe" * 8,
            kind=EvidenceKind.PDF,
            size_bytes=1,
            workbook_id=wb_id,
        )
        s.add(ev)
        s.commit()
        s.refresh(ev)

        result = tag_evidence(s, ev, "Generic marketing copy with no compliance references.")
        s.commit()

        assert result.tags_created == 0

        s.expire_all()
        prior_after = s.get(Assessment, prior_id)
        assert prior_after is not None
        assert prior_after.needs_review is False, (
            "tagger fired invalidation despite creating zero tags"
        )
        assert prior_after.review_reason is None
