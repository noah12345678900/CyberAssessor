"""Tests for the OSCAL loader (rev4/rev5) + control crosswalk auto-builder.

We synthesize tiny OSCAL JSON catalogs in-memory to avoid hitting NIST's
GitHub during CI. The catalogs include:

  - one normal control with a statement
  - one withdrawn enhancement (must be filtered out)
  - one ``SP800-53-enhancement-only`` sentinel (must be filtered out)
  - one control unique to rev5 (proves cross-rev mapping leaves the
    "unmapped" lists populated correctly)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from cybersecurity_assessor.catalogs.crosswalk_loader import load_id_match_crosswalk
from cybersecurity_assessor.catalogs.oscal_loader import load_oscal_catalog
from cybersecurity_assessor.models import Control, ControlCrosswalk, Framework


def _make_oscal(rev: str, *, extra_controls: list[dict] | None = None) -> dict:
    """Return a minimal OSCAL catalog dict suitable for the loader."""
    controls = [
        {
            "id": "ac-1",
            "title": "Policy and Procedures",
            "parts": [
                {
                    "name": "statement",
                    "prose": "Develop, document, and disseminate an AC policy.",
                }
            ],
        },
        {
            "id": "ac-2",
            "title": "Account Management",
            "controls": [
                {
                    "id": "ac-2.1",
                    "title": "Automated System Account Management",
                    "parts": [{"name": "statement", "prose": "Use automated mechanisms."}],
                },
                {
                    "id": "ac-2.10",
                    "title": "Shared / Group Account Credential Termination",
                    "props": [{"name": "status", "value": "withdrawn"}],
                },
            ],
        },
        {
            # Sentinel that exists in OSCAL but has no real content
            "id": "ac-99",
            "title": "Enhancement-only sentinel",
            "class": "SP800-53-enhancement-only",
        },
    ]
    if extra_controls:
        controls.extend(extra_controls)

    return {
        "catalog": {
            "metadata": {
                "title": f"NIST SP 800-53 Rev {rev} (synthetic)",
                "version": f"{rev}.0-test",
            },
            "groups": [
                {
                    "id": "ac",
                    "title": "Access Control",
                    "controls": controls,
                }
            ],
        }
    }


@pytest.fixture
def session(tmp_path: Path):
    db_url = f"sqlite:///{(tmp_path / 'test.db').as_posix()}"
    engine = create_engine(db_url, echo=False)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s
    engine.dispose()


def _write(tmp_path: Path, name: str, payload: dict) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def test_oscal_loader_filters_withdrawn_and_sentinels(session, tmp_path):
    cat = _write(tmp_path, "rev5.json", _make_oscal("5"))
    fw = load_oscal_catalog(session, path=cat, rev="5")

    controls = session.exec(
        select(Control).where(Control.framework_id == fw.id)
    ).all()
    ids = sorted(c.control_id for c in controls)

    # ac-1, ac-2, ac-2.1 — NOT ac-2.10 (withdrawn) and NOT ac-99 (sentinel)
    assert ids == ["ac-1", "ac-2", "ac-2.1"]
    families = {c.family for c in controls}
    assert families == {"AC"}


def test_oscal_loader_rev4_uses_rev4_defaults(session, tmp_path):
    # Synthesize a "rev4" catalog with NO metadata title so we exercise the
    # default-title fallback path keyed on rev.
    payload = _make_oscal("4")
    del payload["catalog"]["metadata"]["title"]
    cat = _write(tmp_path, "rev4.json", payload)

    fw = load_oscal_catalog(session, path=cat, rev="4")
    assert fw.name == "NIST SP 800-53 Rev 4"


def test_oscal_loader_rejects_bad_rev(session, tmp_path):
    cat = _write(tmp_path, "junk.json", _make_oscal("5"))
    with pytest.raises(ValueError, match="Unsupported NIST 800-53 revision"):
        load_oscal_catalog(session, path=cat, rev="3")


def test_oscal_loader_is_idempotent(session, tmp_path):
    cat = _write(tmp_path, "rev5.json", _make_oscal("5"))

    fw1 = load_oscal_catalog(session, path=cat, rev="5")
    n1 = len(session.exec(select(Control).where(Control.framework_id == fw1.id)).all())

    fw2 = load_oscal_catalog(session, path=cat, rev="5")
    n2 = len(session.exec(select(Control).where(Control.framework_id == fw2.id)).all())

    assert fw1.id == fw2.id
    assert n1 == n2


def test_crosswalk_auto_maps_by_id_with_rev5_extras(session, tmp_path):
    rev4 = _write(tmp_path, "rev4.json", _make_oscal("4"))
    rev5_extras = [
        {
            "id": "pt-1",
            "title": "PII Processing and Transparency Policy",
            "parts": [{"name": "statement", "prose": "PT family is rev5-only."}],
        }
    ]
    rev5 = _write(tmp_path, "rev5.json", _make_oscal("5", extra_controls=rev5_extras))

    fw4 = load_oscal_catalog(session, path=rev4, rev="4")
    fw5 = load_oscal_catalog(session, path=rev5, rev="5")

    result = load_id_match_crosswalk(
        session, from_framework_id=fw4.id, to_framework_id=fw5.id
    )

    # ac-1, ac-2, ac-2.1 — three shared controls
    assert result.pairs_created == 3
    assert result.unmapped_from == []  # rev4 had no rev4-only controls
    assert "pt-1" in result.unmapped_to  # rev5-only

    # Re-running is idempotent
    result2 = load_id_match_crosswalk(
        session, from_framework_id=fw4.id, to_framework_id=fw5.id
    )
    assert result2.pairs_created == 0
    assert result2.pairs_already_present == 3

    rows = session.exec(select(ControlCrosswalk)).all()
    assert len(rows) == 3
    assert {r.source for r in rows} == {"auto-id-match"}


def test_crosswalk_rejects_same_framework(session, tmp_path):
    cat = _write(tmp_path, "rev5.json", _make_oscal("5"))
    fw = load_oscal_catalog(session, path=cat, rev="5")
    with pytest.raises(ValueError, match="must differ"):
        load_id_match_crosswalk(
            session, from_framework_id=fw.id, to_framework_id=fw.id
        )


def test_crosswalk_rejects_missing_framework(session, tmp_path):
    cat = _write(tmp_path, "rev5.json", _make_oscal("5"))
    fw = load_oscal_catalog(session, path=cat, rev="5")
    with pytest.raises(ValueError, match="not found"):
        load_id_match_crosswalk(
            session, from_framework_id=fw.id, to_framework_id=9999
        )
