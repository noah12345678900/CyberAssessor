"""Tier-5 Haiku->Opus escalation re-judge + vision presence rubric (FIX_BRIEF).

These tests pin the TWO proposed changes from ``_oldrun_tmp/FIX_BRIEF.md`` that
drive the 17 zero-tag CTP files down to ~12 taggable while keeping the 5
genuinely-empty files at zero:

  * Change 1 -- a gated Opus escalation re-judge. When the Haiku judge ran on an
    under-tagged file and produced a CLEAN all-abstain (``judge_accepted == 0``,
    ``attempted > 0``, ``errored == 0``) AND the body is substantive AND the body
    is NOT a bare command-error, re-run the judge ONCE with the configured Opus
    escalation model and merge its accepts.
  * Change 2 -- a vision presence-vs-effectiveness rubric line: a failed
    verification sub-step does not negate a visibly-deployed mechanism; score
    presence.

The KEY precision test is ``test_command_error_file_does_not_escalate`` (#3): the
real ``[FATAL] Missing playbook argument`` body (aide_step10, id=80) measures 31
distinct significant tokens, so it CLEARS the 25-token ``_TIER5_MIN_BODY_TOKENS``
substance gate. The substance gate alone therefore does NOT protect the empties;
only the deterministic ``_is_command_error_only`` rail does. That is why the
brief mandates the explicit command-error guard, and why this file pins it.

================================ INTERFACE ASSUMPTIONS ========================
The production code for Change 1 does not exist yet. These tests are written
against the INTENDED interface from the brief. Each not-yet-real contract is
marked inline with ``# REQUIRES: <change>``. The implementer must honor:

A. ``config.AppConfig`` gains a field ``llm_judge_escalation_model: str | None``
   (default ``"claude-4-8-opus"``; ``None`` disables escalation entirely).

B. ``TaggingResult`` gains two verdict-neutral instrumentation fields:
       ``judge_escalated: bool = False``        (an Opus re-judge actually ran)
       ``judge_escalated_accepted: int = 0``    (controls the Opus pass accepted)

C. ``tag_evidence`` accepts a new keyword ``escalation_model: str | None = None``.
   When set AND the Haiku pass is a clean all-abstain on a substantive,
   non-command-error body, ``tag_evidence`` re-invokes ``_tag_via_llm`` ONCE with
   ``judge_model=escalation_model``, reusing the SAME ``client`` and
   ``tool_candidate_cids`` (the brief also says reuse the same HyDE prose; that is
   an internal detail these tests do not assert on). Escalation tags are still
   ``source="llm"`` and still pass through the same ``_add`` dedup guard.
   ASSUMPTION: the escalation model is plumbed via a NEW ``escalation_model``
   kwarg rather than read from config inside ``tag_evidence``. If the implementer
   instead reads ``load_config().llm_judge_escalation_model`` directly, the
   escalation tests below should be adapted to monkeypatch the loaded config; the
   *contract* each test pins (when escalation fires / does not fire) is unchanged.

D. A module-level helper ``_is_command_error_only(text: str) -> bool`` exists in
   ``cybersecurity_assessor.evidence.tagger`` and returns True for a body whose
   only signal is a shell/ansible error with no observed control state
   (``[FATAL]``, ``command not found``, ``No such file or directory``,
   ``Not a directory``, ``Missing playbook argument``, ``Permission denied``),
   and False for a body that also carries successful command output.

The stub judge is keyed on the ``model=`` arg (mirrors the real
``client.judge_relevance(system_blocks, user_text, *, model=None)`` signature),
so a single stub returns Haiku scores for the Haiku model and Opus scores for
the escalation model -- exactly the two-model behavior the escalation exercises.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from cybersecurity_assessor import models  # noqa: F401,E402  -- registers tables
from cybersecurity_assessor.evidence import ingest as _ingest_mod  # noqa: E402
from cybersecurity_assessor.evidence.ingest import ingest_folder  # noqa: E402
from cybersecurity_assessor.evidence.tagger import (  # noqa: E402
    _LLM_JUDGE_RUBRIC,
    tag_evidence,
)
from cybersecurity_assessor.models import (  # noqa: E402
    Control,
    Evidence,
    EvidenceKind,
    EvidenceTag,
    Framework,
    Objective,
)
from cybersecurity_assessor.models import Workbook as WorkbookModel  # noqa: E402

# The escalation model used throughout. Matches the brief's default
# (config.py:121 anthropic_model == "claude-4-8-opus", already wired/proven).
_OPUS = "claude-4-8-opus"
_HAIKU = "claude-haiku-4-5-20251001"

# Real bodies pulled from _oldrun_tmp/zero17.json so the fixtures match what the
# pipeline actually saw in production (not synthetic stand-ins).
# aide_step10 (id=80): the FATAL command-error file. 31 distinct significant
# tokens -> CLEARS the 25-token substance gate. THIS is the precision trap.
_AIDE_FATAL_BODY = (
    "Script started on 2026-05-18 22:37:16+00:00\n"
    "[cybertestadmin@enterprise-services-installer CTP-014_aide]$ "
    "source /opt/paas/bin/setVaultPassword.sh\n"
    "Please enter the password for the Ansible Vault:\n"
    "[cybertestadmin@enterprise-services-installer CTP-014_aide]$ umask 0007\n"
    "[cybertestadmin@enterprise-services-installer CTP-014_aide]$ "
    "HOSTS=paas-vdi-01 /opt/paas/bin/runAnsiblePlaybook.sh\n"
    "22:37:53 [FATAL]  Missing playbook argument.\n"
    "[cybertestadmin@enterprise-services-installer CTP-014_aide]$ exit\n"
    "Script done on 2026-05-18 22:38:18+00:00\n"
)

# A substantive, NON-error body for the controls that SHOULD escalate. Modeled on
# xrdp_step7 (id=32): a successful `more xrdp.service` showing the unit deployed.
# No doc-number / CCI / control-ID token, so Tiers 1-4 emit nothing and the
# Tier-5 gate opens; long enough to clear the substance gate.
_XRDP_DEPLOYED_BODY = (
    "ansible-playbook RunCommand more "
    "/etc/systemd/system/multi-user.target.wants/xrdp.service\n"
    "result.rc: '0'\nresult.stderr: ''\nresult.stdout:\n"
    "[Unit] Description=xrdp daemon remote desktop protocol service\n"
    "[Service] ExecStart=/usr/sbin/xrdp --nodaemon running enabled active "
    "listening encrypted remote access session established for managed virtual "
    "desktop hosts vdi devvdi across the enterprise boundary confirmed installed "
    "package xrdp version present systemd unit wants target multi user verified "
    "operational deployment evidence collected during control test procedure run."
)


# ---------------------------------------------------------------------------
# Two-model stub judge: keyed on the ``model=`` argument
# ---------------------------------------------------------------------------
class _TwoModelJudge:
    """A stub LLM client whose verdict depends on which model is asked.

    ``scores_by_model``: model-string -> {cid(upper): score}. A cid missing from
    a model's map scores 0.0 (a confident "not relevant" abstention) for that
    model. This is how we make Haiku abstain (0.0) while Opus accepts (0.8) on
    the SAME candidate -- the exact partition the escalation re-judge depends on.

    Records ``calls`` as ``(model, cid)`` tuples so a test can prove the Opus
    pass actually ran (and that escalation did NOT run when it must not).
    """

    def __init__(self, scores_by_model: dict[str | None, dict[str, float]]):
        self.scores_by_model = {
            m: {c.upper(): s for c, s in scores.items()}
            for m, scores in scores_by_model.items()
        }
        self.calls: list[tuple[str | None, str]] = []

    def judge_relevance(self, system_blocks, user_text, *, model=None):
        # Recover the control id from the candidate user turn's first line
        # ("Control: AC-17 ..."), mirroring _llm_candidate_user_text's format.
        first = user_text.split("\n", 1)[0]
        cid = first.removeprefix("Control:").strip().split()[0].upper()
        self.calls.append((model, cid))
        score = self.scores_by_model.get(model, {}).get(cid, 0.0)
        return score, f"reason-{model}-{cid}", None

    @property
    def models_called(self) -> set[str | None]:
        return {m for m, _ in self.calls}


# ---------------------------------------------------------------------------
# Catalog / session fixtures (mirror test_tool_name_autotag.py house style)
# ---------------------------------------------------------------------------
@pytest.fixture
def session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def catalog(session) -> dict[str, list[int]]:
    """Seed AC-17 (+ AU-8 negative) each with TWO child objectives.

    Two children means an accepted control yields exactly two EvidenceTag rows
    (one per CCI) -- so the dedup test can prove an Opus re-accept of an
    already-Haiku-accepted control adds ZERO new rows.
    """
    fw = Framework(name="NIST SP 800-53", version="Rev 5")
    session.add(fw)
    session.commit()
    session.refresh(fw)

    by_control: dict[str, list[int]] = {}
    for ctl_id, family in [
        ("ac-17", "AC"),
        ("au-8", "AU"),
        ("ac-3", "AC"),   # backstop: a sub-0.6 "best rejected" candidate
        ("ca-2", "CA"),   # backstop: the quarantine control
    ]:
        ctrl = Control(
            framework_id=fw.id,
            control_id=ctl_id,
            title=f"{ctl_id.upper()} title",
            family=family,
        )
        session.add(ctrl)
        session.commit()
        session.refresh(ctrl)
        ids: list[int] = []
        for n in (1, 2):
            obj = Objective(
                control_id_fk=ctrl.id,
                objective_id=f"{ctl_id}.{n}",
                source="AP",
                text=f"objective text for {ctl_id}.{n}",
            )
            session.add(obj)
            session.commit()
            session.refresh(obj)
            ids.append(obj.id)
        by_control[ctl_id] = ids
    return by_control


def _evidence(session, body_path: str, *, kind=EvidenceKind.TEXT) -> Evidence:
    e = Evidence(
        path=body_path,
        sha256=f"sha-{body_path}",
        kind=kind,
        size_bytes=1000,
        title=body_path.rsplit("/", 1)[-1],
        doc_number=None,
    )
    session.add(e)
    session.flush()
    return e


def _llm_tags(session, evidence_id: int) -> list[EvidenceTag]:
    return session.exec(
        select(EvidenceTag)
        .where(EvidenceTag.evidence_id == evidence_id)
        .where(EvidenceTag.source == "llm")
    ).all()


# ===========================================================================
# 1. Escalation FIRES on a clean Haiku abstain + substantive body
# ===========================================================================
def test_escalation_fires_on_clean_abstain_and_substantive_body(session, catalog):
    """Haiku abstains (0.0) on AC-17; Opus escalation accepts (0.8) -> tagged.

    The whole point of Change 1: an under-tagged file that the Haiku judge
    cleanly rejected (attempted>0, accepted==0, errored==0) on a substantive
    body gets ONE more shot from Opus, and Opus's accept is merged as source=llm.
    """
    e = _evidence(session, "C:/fake/CTP-010_xrdp_step7.txt")
    judge = _TwoModelJudge(
        {
            _HAIKU: {"ac-17": 0.0},  # Haiku rejects the correct control
            _OPUS: {"ac-17": 0.8},  # Opus accepts on re-judge
        }
    )
    # REQUIRES: Change 1 -- tag_evidence(escalation_model=...) kwarg.
    result = tag_evidence(
        session,
        e,
        text=_XRDP_DEPLOYED_BODY,
        client=judge,
        judge_model=_HAIKU,
        escalation_model=_OPUS,
        tool_candidate_cids={"ac-17"},
    )

    # Both models were consulted; the escalation pass actually ran on Opus.
    assert _HAIKU in judge.models_called, "Haiku pass must run first"
    assert _OPUS in judge.models_called, "Opus escalation pass must run on abstain"

    # REQUIRES: Change 1 -- TaggingResult.judge_escalated / judge_escalated_accepted.
    assert result.judge_escalated is True
    assert result.judge_escalated_accepted >= 1

    tags = _llm_tags(session, e.id)
    tagged = {t.objective_id for t in tags}
    for oid in catalog["ac-17"]:
        assert oid in tagged, "Opus-accepted AC-17 child must be tagged source=llm"
    assert all(t.source == "llm" for t in tags)


# ===========================================================================
# 2. Escalation does NOT fire when Haiku already accepted >= 1
# ===========================================================================
def test_no_escalation_when_haiku_accepted_at_least_one(session, catalog):
    """Haiku accepts AC-17 -> the file is no longer all-abstain -> no Opus pass.

    Escalation is scoped to UNDER-tagged / all-abstain files; a file the cheap
    Haiku judge already covered must not pay for Opus.
    """
    e = _evidence(session, "C:/fake/CTP-010_xrdp_step7.txt")
    judge = _TwoModelJudge(
        {
            _HAIKU: {"ac-17": 0.8},  # Haiku already accepts
            _OPUS: {"ac-17": 0.99},  # would accept too, but must never be asked
        }
    )
    # REQUIRES: Change 1 -- escalation_model kwarg.
    result = tag_evidence(
        session,
        e,
        text=_XRDP_DEPLOYED_BODY,
        client=judge,
        judge_model=_HAIKU,
        escalation_model=_OPUS,
        tool_candidate_cids={"ac-17"},
    )

    assert _OPUS not in judge.models_called, (
        "Opus must NOT be consulted when Haiku already accepted a control"
    )
    # REQUIRES: Change 1 -- judge_escalated field.
    assert result.judge_escalated is False
    assert _llm_tags(session, e.id), "Haiku's own accept still persists"


# ===========================================================================
# 3. KEY PRECISION TEST: command-error file does NOT escalate
# ===========================================================================
def test_command_error_file_does_not_escalate(session, catalog):
    """The real [FATAL] aide_step10 body (31 tokens) must NOT escalate to Opus.

    This is the case the 25-token substance gate FAILS to catch (31 > 25), so
    without the ``_is_command_error_only`` rail the file would reach Opus, and a
    more-generous Opus pass could AFFIRM AC-17/SI-7 from the bare 'aide' token --
    a false-COMPLIANT on a failed command. The deterministic command-error guard
    suppresses ESCALATION (no Opus affirming tag). NOTE: the file is STILL
    located (see test_command_error_file_is_located_nonaffirming) -- it just must
    never earn an affirming source="llm" tag via escalation.
    """
    e = _evidence(session, "C:/fake/CTP-014_aide_step10.txt")
    judge = _TwoModelJudge(
        {
            _HAIKU: {"ac-17": 0.0},  # Haiku correctly rejects (production reality)
            _OPUS: {"ac-17": 0.95},  # Opus WOULD over-accept -- must not be asked
        }
    )
    result = tag_evidence(
        session,
        e,
        text=_AIDE_FATAL_BODY,
        client=judge,
        judge_model=_HAIKU,
        escalation_model=_OPUS,
        tool_candidate_cids={"ac-17"},
    )

    assert _OPUS not in judge.models_called, (
        "command-error file must NOT reach the Opus escalation pass"
    )
    assert result.judge_escalated is False
    # The CRITICAL precision invariant: a failed command never earns an
    # AFFIRMING (source="llm") tag. (It MAY be LOCATED as located_nonaffirming;
    # that is asserted separately and is NOT compliant evidence.)
    assert _llm_tags(session, e.id) == [], (
        "a [FATAL] command-error file must NEVER earn an affirming source=llm "
        "tag, even though a tool name (aide) is present"
    )


def test_command_error_file_is_located_nonaffirming(session, catalog):
    """LOCATE-don't-drop: a [FATAL] file whose tool maps to a CATALOG control is
    TAGGED ``located_nonaffirming`` (not dropped), so the artifact is citable
    under its control -- but never as affirming/compliant evidence.

    The judge ran and rejected (production reality for these files); the
    single-purpose floor therefore emits the located-non-affirming disposition
    rather than vanishing the file (the user-flagged bug). Uses a body whose
    tool token (``xrdp``) maps to a control SEEDED in the catalog (AC-17) so the
    floor can resolve objectives -- aide->SI-7/CM-3 aren't seeded here.
    """
    from cybersecurity_assessor.evidence.tagger import _SOURCE_LOCATED_NONAFFIRMING

    # xrdp is single-purpose -> AC-17 (seeded). Body is a command that FAILED to
    # execute, so it must be located-non-affirming, not affirming. The body
    # carries a bare ``xrdp`` token (as the real CTP-010_xrdp_step12.txt does --
    # ``systemctl status xrdp``) so the tool-floor derivation matches; the
    # command itself errors out (command not found), so it is non-affirming.
    fatal_xrdp = (
        "Script started on 2026-05-18 21:40:27+00:00\n"
        "[cybertestadmin@host CTP-010]$ systemctl status xrdp\n"
        "sudo: systemctl: command not found\n"
        "[cybertestadmin@host CTP-010]$ exit\n"
    )
    e = _evidence(session, "C:/fake/CTP-010_xrdp_step12.txt")
    judge = _TwoModelJudge(
        {
            _HAIKU: {"ac-17": 0.0},  # judge ran and rejected
            _OPUS: {"ac-17": 0.0},  # escalation suppressed anyway (command error)
        }
    )
    tag_evidence(
        session,
        e,
        text=fatal_xrdp,
        client=judge,
        judge_model=_HAIKU,
        escalation_model=_OPUS,
        # No override -> derive tool_floor from the body ('xrdp' -> AC-17).
    )

    all_tags = session.exec(
        select(EvidenceTag).where(EvidenceTag.evidence_id == e.id)
    ).all()
    # LOCATED: AC-17 children tagged, but with the non-affirming disposition.
    tagged = {t.objective_id for t in all_tags}
    for oid in catalog["ac-17"]:
        assert oid in tagged, "command-error file must be LOCATED to AC-17, not dropped"
    assert all(
        t.source == _SOURCE_LOCATED_NONAFFIRMING
        for t in all_tags
        if t.objective_id in catalog["ac-17"]
    ), "located AC-17 tags must carry the located_nonaffirming source"
    # NON-AFFIRMING: never an affirming source.
    assert not _llm_tags(session, e.id), "must not be affirming source=llm"
    assert not any(t.source == "auto" for t in all_tags), "must not be source=auto"


def test_is_command_error_only_classifies_brief_phrases():
    """``_is_command_error_only`` recognizes the brief's error phrases.

    Pins the deterministic rail directly (unit-level), so a regression in the
    helper is caught even if the escalation wiring changes. Mirrors how the
    validator phrase tables are unit-tested.
    """
    # REQUIRES: Change 1 -- _is_command_error_only helper in tagger.py.
    from cybersecurity_assessor.evidence.tagger import _is_command_error_only

    # Real command-error bodies (zero17 ids 80, 123, 113, 31) -> True.
    assert _is_command_error_only(_AIDE_FATAL_BODY) is True
    assert _is_command_error_only(
        "22:15:23 [FATAL]  Missing playbook argument."
    ) is True
    assert _is_command_error_only(
        "bash: /opt/paas/bin/runCmd.sh: Not a directory"
    ) is True
    assert _is_command_error_only(
        "sudo: firwall-cmd: command not found"
    ) is True
    assert _is_command_error_only(
        "cat: /etc/missing: No such file or directory"
    ) is True

    # A body with REAL successful command output -> False (must be allowed to
    # escalate). The xrdp deployed body shows result.rc '0' + a unit file.
    assert _is_command_error_only(_XRDP_DEPLOYED_BODY) is False


# ===========================================================================
# 4. Escalation does NOT fire when the escalation model is None
# ===========================================================================
def test_no_escalation_when_escalation_model_is_none(session, catalog):
    """escalation_model=None (offline/eval default) -> pure E+A, no Opus pass.

    The brief makes None the safe default so the offline/eval path is unchanged.
    A clean Haiku abstain with no escalation model must stay a clean abstain.
    """
    e = _evidence(session, "C:/fake/CTP-010_xrdp_step7.txt")
    judge = _TwoModelJudge(
        {
            _HAIKU: {"ac-17": 0.0},
            _OPUS: {"ac-17": 0.9},  # present but must never be asked
        }
    )
    # REQUIRES: Change 1 -- escalation_model default None disables escalation.
    result = tag_evidence(
        session,
        e,
        text=_XRDP_DEPLOYED_BODY,
        client=judge,
        judge_model=_HAIKU,
        escalation_model=None,
        tool_candidate_cids={"ac-17"},
    )

    assert _OPUS not in judge.models_called
    assert result.judge_escalated is False
    assert _llm_tags(session, e.id) == [], "no escalation -> Haiku abstain stands"


# ===========================================================================
# 5. Escalation does not double-tag an already-accepted control
# ===========================================================================
def test_escalation_does_not_double_tag(session, catalog):
    """Mixed: Haiku accepts AC-17, abstains AU-8; Opus would accept BOTH.

    Because Haiku already accepted >=1, the file is NOT all-abstain and escalation
    must not run at all -- but even in the defensive case where an implementer
    chooses to escalate only the still-abstained candidates, the ``_add`` dedup
    guard (keyed on objective_id via the ``existing`` set) must prevent any
    duplicate (objective_id) row for AC-17. We assert exactly two AC-17 rows
    (one per child CCI), never four.
    """
    e = _evidence(session, "C:/fake/CTP-010_xrdp_step7.txt")
    judge = _TwoModelJudge(
        {
            _HAIKU: {"ac-17": 0.8, "au-8": 0.0},
            _OPUS: {"ac-17": 0.99, "au-8": 0.99},
        }
    )
    # REQUIRES: Change 1 -- escalation_model kwarg.
    tag_evidence(
        session,
        e,
        text=_XRDP_DEPLOYED_BODY,
        client=judge,
        judge_model=_HAIKU,
        escalation_model=_OPUS,
        tool_candidate_cids={"ac-17", "au-8"},
    )

    ac17_rows = [
        t for t in _llm_tags(session, e.id) if t.objective_id in catalog["ac-17"]
    ]
    assert len(ac17_rows) == 2, "exactly one llm tag per AC-17 child CCI -- no dups"
    objective_ids = [t.objective_id for t in ac17_rows]
    assert sorted(objective_ids) == sorted(catalog["ac-17"])
    assert len(set(objective_ids)) == len(objective_ids), "no duplicate objective_id"


# ===========================================================================
# 6. Vision presence-vs-effectiveness rubric string present (Change 2)
# ===========================================================================
def test_vision_presence_rubric_clause_present():
    """The judge rubric carries the presence-vs-effectiveness clause (Change 2).

    String-contains test, mirroring how validator phrase tables are pinned. The
    clause must (a) say a failed/error verification sub-step does not negate a
    visibly-deployed mechanism, and (b) instruct scoring the PRESENCE of the
    deployed mechanism -- so a FAIL.png screenshot of a deployed Rancher/Splunk
    console still scores, while a bare [FATAL] terminal with no visible mechanism
    does not.
    """
    rubric = _LLM_JUDGE_RUBRIC.lower()
    # REQUIRES: Change 2 -- append the presence-vs-effectiveness line to the rubric.
    assert "presence" in rubric, "rubric must instruct scoring PRESENCE"
    assert "mechanism" in rubric, "rubric must reference the deployed mechanism"
    # The defining contrast: a failed/error sub-step does not negate deployment.
    assert ("fail" in rubric or "failed" in rubric or "error" in rubric), (
        "rubric must acknowledge a failed/error verification sub-step"
    )
    assert ("deployed" in rubric or "visible" in rubric or "visibly" in rubric), (
        "rubric must scope the clause to a visibly-deployed mechanism"
    )


# ===========================================================================
# 7. Empties stay zero through the full offline ingest_folder path
# ===========================================================================
@pytest.fixture
def _force_offline_tagger(monkeypatch):
    """Force the tagger OFFLINE (no LLM judge) -- mirrors test_tool_name_autotag.

    Offline = no client = no Haiku judge and no Opus escalation, so this pins the
    deterministic floor behavior (the existing E+A offline-floor contract) is not
    regressed by the escalation change. ``_build_tagger_llm`` returns
    ``(None, None, "disabled")`` exactly as the autotag suite forces it.
    """
    monkeypatch.setattr(
        _ingest_mod, "_build_tagger_llm", lambda: (None, None, "disabled")
    )


@pytest.fixture
def wb_id(session) -> int:
    wb = WorkbookModel(path="/tmp/esc.xlsx", filename="esc.xlsx")
    session.add(wb)
    session.commit()
    session.refresh(wb)
    return wb.id


def test_empties_stay_zero_offline(
    session, catalog, wb_id, tmp_path, _force_offline_tagger
):
    """0-byte file AND a [FATAL] command-error file -> zero tags offline.

    Full ``ingest_folder`` offline path. Neither empty produces a tag: the
    0-byte file is skipped by the substance gate; the [FATAL] aide body is
    blocked by the command-error rail (offline there is no judge to over-accept,
    but the deterministic floor must also stay silent on a command-error body).
    No regression to the existing E+A offline floor.
    """
    (tmp_path / "CTP-020_spaceLowAudit_steps9-18.txt").write_text(
        "", encoding="utf-8"
    )
    (tmp_path / "CTP-014_aide_step10.txt").write_text(
        _AIDE_FATAL_BODY, encoding="utf-8"
    )

    summary = ingest_folder(session, tmp_path, workbook_id=wb_id)
    assert summary.errors == []

    tags = session.exec(select(EvidenceTag)).all()
    assert tags == [], (
        "a 0-byte file and a [FATAL] command-error file must both yield zero "
        "tags through the offline ingest path"
    )


def test_vault_polysemous_still_emits_nothing_offline(
    session, catalog, wb_id, tmp_path, _force_offline_tagger
):
    """Regression guard: the polysemous 'vault' token still emits nothing offline.

    The escalation change must not disturb the existing nominate-only precision
    rule (covered in test_tool_name_autotag.py). With no AC-17 leak path and no
    judge, the vault file tags nothing -- pinned here so the escalation work does
    not accidentally relax the offline floor.
    """
    (tmp_path / "CTP-022_vault.txt").write_text(
        "vault operator init\nvault status: Sealed=false\n", encoding="utf-8"
    )
    ingest_folder(session, tmp_path, workbook_id=wb_id)
    tags = session.exec(select(EvidenceTag)).all()
    # No AC-17 / AU-8 (the only seeded controls) tag from a polysemous vault body.
    tagged = {t.objective_id for t in tags}
    seeded = {oid for ids in catalog.values() for oid in ids}
    assert not (tagged & seeded), "polysemous 'vault' must not tag offline"


# ---------------------------------------------------------------------------
# NEVER-ZERO BACKSTOP (2026-06-24)
# A NON-EMPTY file that ends with zero tags after all tiers + judge + escalation
# must be LOCATED (non-affirming), never silently dropped. Target: the judge's
# best DECLINED candidate if it scored >= 0.3, else the CA-2 quarantine control.
# Only a genuinely EMPTY (size_bytes == 0) file may stay zero.
# ---------------------------------------------------------------------------

_NEUTRAL_BODY = (
    "This terminal capture records an operational procedure executed across "
    "several managed hosts in the enterprise environment during the assessment "
    "window. It documents the steps the tester performed and the resulting "
    "system output collected for review by the assessment team."
)


def _located_tags(session, evidence_id):
    from cybersecurity_assessor.evidence.tagger import _SOURCE_LOCATED_NONAFFIRMING

    return session.exec(
        select(EvidenceTag)
        .where(EvidenceTag.evidence_id == evidence_id)
        .where(EvidenceTag.source == _SOURCE_LOCATED_NONAFFIRMING)
    ).all()


def test_backstop_locates_to_judges_best_declined_candidate(session, catalog):
    """Non-empty file, judge declines all, best reject >= 0.3 -> located to it.

    The judge (both passes) scores AC-3 at 0.45 -- below the 0.6 accept gate, so
    no affirming tag -- but it's the best real candidate. The never-zero backstop
    must floor AC-3 as located_nonaffirming so the file is never zero-tag.
    """
    e = _evidence(session, "C:/fake/CTP-050_generic_procedure.txt")
    judge = _TwoModelJudge(
        {
            _HAIKU: {"ac-3": 0.45},   # declined (<0.6) but the best real signal
            _OPUS: {"ac-3": 0.45},    # escalation also declines -> stays best_rejected
        }
    )
    tag_evidence(
        session,
        e,
        text=_NEUTRAL_BODY,
        client=judge,
        judge_model=_HAIKU,
        escalation_model=_OPUS,
        tool_candidate_cids={"ac-3"},  # force AC-3 in front of the judge
    )
    located = _located_tags(session, e.id)
    tagged = {t.objective_id for t in located}
    for oid in catalog["ac-3"]:
        assert oid in tagged, "backstop must locate the file to AC-3 (best declined candidate)"
    assert not _llm_tags(session, e.id), "a declined candidate must NOT be affirming"
    # Did NOT fall to quarantine when a real candidate existed.
    for oid in catalog["ca-2"]:
        assert oid not in tagged, "should locate to AC-3, not the CA-2 quarantine"


def test_backstop_quarantines_to_ca2_when_no_real_candidate(session, catalog):
    """Non-empty file, judge's best reject < 0.3 -> CA-2 quarantine (located)."""
    e = _evidence(session, "C:/fake/CTP-051_unmappable.txt")
    judge = _TwoModelJudge(
        {
            _HAIKU: {"ac-3": 0.10},   # below the 0.3 backstop floor = no real signal
            _OPUS: {"ac-3": 0.10},
        }
    )
    tag_evidence(
        session,
        e,
        text=_NEUTRAL_BODY,
        client=judge,
        judge_model=_HAIKU,
        escalation_model=_OPUS,
        tool_candidate_cids={"ac-3"},
    )
    located = _located_tags(session, e.id)
    tagged = {t.objective_id for t in located}
    for oid in catalog["ca-2"]:
        assert oid in tagged, "sub-0.3 best reject must quarantine to CA-2"
    for oid in catalog["ac-3"]:
        assert oid not in tagged, "must NOT locate to a 0.10 near-random candidate"


def test_backstop_does_not_fire_when_already_tagged(session, catalog):
    """A file the judge AFFIRMED gets no backstop tag (it's not zero-tag)."""
    e = _evidence(session, "C:/fake/CTP-052_affirmed.txt")
    judge = _TwoModelJudge({_HAIKU: {"ac-17": 0.9}})  # accepted
    tag_evidence(
        session,
        e,
        text=_NEUTRAL_BODY,
        client=judge,
        judge_model=_HAIKU,
        escalation_model=_OPUS,
        tool_candidate_cids={"ac-17"},
    )
    located = _located_tags(session, e.id)
    tagged = {t.objective_id for t in located}
    for oid in catalog["ca-2"]:
        assert oid not in tagged, "affirmed file must not also be quarantined"
    assert _llm_tags(session, e.id), "the affirming AC-17 tag stands"
