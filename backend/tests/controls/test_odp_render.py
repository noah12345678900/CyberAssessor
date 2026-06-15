"""Tests for ``controls.odp_render.resolve_odps``.

The render layer is the contract every consumer (route handler, SAR
exporter, future UI editor) goes through. Three things it must get
right:

1. All three placeholder syntaxes — Rev 4 ``{$N$}``, Rev 5
   ``ac-XX_odp.NN``, and the OSCAL wrapper
   ``{{ insert: param, X }}`` — substitute correctly from a single
   stored row each.
2. Empty stored values stay UNRESOLVED (treated as "slot exists but
   not assigned"), not silently rendered as the empty string. The
   workbook intentionally encodes blanks this way for sparse controls.
3. When multiple ``OdpAssignment`` rows match the same ``odp_id``
   (e.g. workbook value vs. FedRAMP overlay), the most recent
   ``ingested_at`` wins — deterministic, no precedence inference.

Each test uses an in-memory SQLite session and seeds only the
``OdpAssignment`` rows it needs.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from cybersecurity_assessor import models  # noqa: F401  -- registers tables
from cybersecurity_assessor.controls.odp_render import resolve_odps
from cybersecurity_assessor.models import OdpAssignment

FW = "NIST-800-53r4"


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


def _add(
    session: Session,
    *,
    control_id: str,
    odp_id: str,
    value: str,
    assigned_from: str = "DoW Enterprise",
    ingested_at: datetime | None = None,
    oscal_param_id: str | None = None,
    slot_index: int | None = None,
    slot_total: int | None = None,
    framework_version: str = FW,
    source_ingest: str = "CCIS-workbook",
) -> OdpAssignment:
    row = OdpAssignment(
        framework_version=framework_version,
        control_id=control_id,
        odp_id=odp_id,
        assigned_from=assigned_from,
        value=value,
        source_ingest=source_ingest,
        ingested_at=ingested_at or datetime.now(timezone.utc),
        oscal_param_id=oscal_param_id,
        slot_index=slot_index,
        slot_total=slot_total,
    )
    session.add(row)
    session.commit()
    return row


# ---------------------------------------------------------------------------
# Each of the three placeholder syntaxes resolves
# ---------------------------------------------------------------------------


def test_rev4_placeholder_substitutes(session):
    _add(session, control_id="ac-2", odp_id="{$37$}", value="ISSM or ISSO")
    rendered, unresolved = resolve_odps(
        session, FW, "ac-2", "Requires approvals by {$37$} for requests."
    )
    assert rendered == "Requires approvals by ISSM or ISSO for requests."
    assert unresolved == []


def test_rev5_bare_placeholder_substitutes(session):
    _add(session, control_id="ac-2", odp_id="ac-02_odp.03", value="annually")
    rendered, unresolved = resolve_odps(
        session, FW, "ac-2", "Reviews accounts ac-02_odp.03 at a minimum."
    )
    assert rendered == "Reviews accounts annually at a minimum."
    assert unresolved == []


def test_oscal_wrapper_substitutes_via_bridge(session):
    """OSCAL wrapper form requires the ``oscal_param_id`` bridge column
    populated at ingest. Without the bridge, the render layer can't
    know that ``ac-2_prm_2`` and the workbook's ``{$37$}`` refer to
    the same slot."""
    _add(
        session,
        control_id="ac-2",
        odp_id="{$37$}",
        value="ISSM or ISSO",
        oscal_param_id="ac-2_prm_2",
    )
    rendered, unresolved = resolve_odps(
        session,
        FW,
        "ac-2",
        "Requires approvals by {{ insert: param, ac-2_prm_2 }} for requests.",
    )
    assert rendered == "Requires approvals by ISSM or ISSO for requests."
    assert unresolved == []


# ---------------------------------------------------------------------------
# Empty value is treated as unresolved, never rendered as ""
# ---------------------------------------------------------------------------


def test_empty_value_renders_as_unresolved(session):
    """An empty-string value means "slot exists in the workbook but
    the program hasn't assigned a value yet". Rendering "" inline
    would produce things like "Requires approvals by  for..." with a
    visible double space — the placeholder MUST stay visible instead
    so the assessor knows there's an unfilled slot."""
    _add(session, control_id="ac-2", odp_id="{$36$}", value="")
    rendered, unresolved = resolve_odps(
        session, FW, "ac-2", "Identifies {$36$} information system accounts."
    )
    assert rendered == "Identifies {$36$} information system accounts."
    assert unresolved == ["{$36$}"]


def test_empty_oscal_value_renders_as_unresolved(session):
    """Same rule applies to the OSCAL wrapper path — empty value
    surfaces the bare param id (not the wrapper) so the UI badge
    is concise."""
    _add(
        session,
        control_id="ac-2",
        odp_id="{$36$}",
        value="",
        oscal_param_id="ac-2_prm_1",
    )
    rendered, unresolved = resolve_odps(
        session,
        FW,
        "ac-2",
        "Identifies {{ insert: param, ac-2_prm_1 }} accounts.",
    )
    # The wrapper stays literal in the rendered text, but the
    # unresolved list tracks the bare param id.
    assert "{{ insert: param, ac-2_prm_1 }}" in rendered
    assert unresolved == ["ac-2_prm_1"]


# ---------------------------------------------------------------------------
# Multi-row most-recent-wins
# ---------------------------------------------------------------------------


def test_most_recent_ingest_wins_for_same_odp(session):
    """Two overlays touch the same ODP. The more recent ``ingested_at``
    wins. Deterministic, no precedence inference."""
    now = datetime.now(timezone.utc)
    _add(
        session,
        control_id="ac-2",
        odp_id="{$39$}",
        value="24 hours",
        assigned_from="DoW Enterprise",
        ingested_at=now - timedelta(hours=2),
    )
    _add(
        session,
        control_id="ac-2",
        odp_id="{$39$}",
        value="1 hour",
        assigned_from="FedRAMP HBL",
        ingested_at=now,
    )
    rendered, unresolved = resolve_odps(
        session, FW, "ac-2", "Notifies managers within {$39$}."
    )
    assert rendered == "Notifies managers within 1 hour."
    assert unresolved == []


def test_ingest_tie_breaks_on_assigned_from_string(session):
    """When ``ingested_at`` ties exactly (e.g. two rows from the same
    ingest run), the sort is total via ``assigned_from``. The exact
    winner matters less than that the function is deterministic — no
    "random" coin-flip path."""
    same_time = datetime.now(timezone.utc)
    _add(
        session,
        control_id="ac-2",
        odp_id="{$39$}",
        value="A-value",
        assigned_from="A-source",
        ingested_at=same_time,
    )
    _add(
        session,
        control_id="ac-2",
        odp_id="{$39$}",
        value="Z-value",
        assigned_from="Z-source",
        ingested_at=same_time,
    )
    rendered, _ = resolve_odps(session, FW, "ac-2", "x {$39$} y")
    # max() of tuple → lexicographically greater wins on the tie.
    assert rendered == "x Z-value y"


# ---------------------------------------------------------------------------
# Unresolved tracking — preservation of first-occurrence order, dedup
# ---------------------------------------------------------------------------


def test_unresolved_preserves_first_occurrence_order_and_dedups(session):
    """Multiple unknown placeholders → unresolved list in the order
    they first appeared in the template, deduped on subsequent
    appearances."""
    template = "A {$10$} B {$11$} C {$10$} D {$12$}"
    rendered, unresolved = resolve_odps(session, FW, "ac-1", template)
    # Nothing was substituted — template unchanged.
    assert rendered == template
    # First-occurrence order, no duplicate of {$10$}.
    assert unresolved == ["{$10$}", "{$11$}", "{$12$}"]


def test_mixed_template_resolves_what_it_can_lists_what_it_cant(session):
    """A real template mixes resolved + unresolved. Verify the two
    halves don't interfere — substituted slots disappear from
    ``unresolved`` and the rest still surface."""
    _add(session, control_id="ac-2", odp_id="{$37$}", value="ISSM or ISSO")
    rendered, unresolved = resolve_odps(
        session,
        FW,
        "ac-2",
        "Identify {$36$}; Approve via {$37$}; Notify in {$39$}.",
    )
    assert "Approve via ISSM or ISSO" in rendered
    assert "{$36$}" in rendered
    assert "{$39$}" in rendered
    assert unresolved == ["{$36$}", "{$39$}"]


# ---------------------------------------------------------------------------
# Framework / control scoping
# ---------------------------------------------------------------------------


def test_other_framework_row_does_not_leak(session):
    """An ODP stored under ``NIST-800-53r5`` must not satisfy a render
    request for ``NIST-800-53r4`` even though the odp_id token is the
    same. Framework isolation is a PK column."""
    _add(
        session,
        framework_version="NIST-800-53r5",
        control_id="ac-2",
        odp_id="{$37$}",
        value="r5-only value",
    )
    rendered, unresolved = resolve_odps(session, FW, "ac-2", "x {$37$} y")
    assert rendered == "x {$37$} y"
    assert unresolved == ["{$37$}"]


def test_other_control_row_does_not_leak(session):
    """Same framework, different control. ODPs are scoped to the
    declaring control."""
    _add(session, control_id="ac-3", odp_id="{$37$}", value="leaked")
    rendered, unresolved = resolve_odps(session, FW, "ac-2", "x {$37$} y")
    assert rendered == "x {$37$} y"
    assert unresolved == ["{$37$}"]


# ---------------------------------------------------------------------------
# Empty / null templates
# ---------------------------------------------------------------------------


def test_empty_template_short_circuits(session):
    rendered, unresolved = resolve_odps(session, FW, "ac-2", "")
    assert rendered == ""
    assert unresolved == []


def test_template_without_placeholders_short_circuits_query(session):
    """Cheap pre-check: if no placeholders match the tokenizer at all,
    the function returns immediately without issuing the DB query.
    Verified via output equality (covers the fast path) — direct query
    count would require a connection-level spy."""
    template = "This control statement has zero placeholders to resolve."
    rendered, unresolved = resolve_odps(session, FW, "ac-2", template)
    assert rendered == template
    assert unresolved == []


# ---------------------------------------------------------------------------
# Catalog-agnostic OSCAL re-bridge via slot_index / slot_total
# ---------------------------------------------------------------------------


def test_oscal_resolves_via_slot_bridge_when_cache_is_null(session):
    """Simulates the post-catalog-reload case: the workbook was ingested
    with positional alignment, but the row's cached ``oscal_param_id`` is
    NULL (e.g. the workbook predates the bridge column). The render layer
    re-derives the param order from the CURRENT template and looks up by
    ``slot_index``. ``slot_total`` matches the catalog param count, so
    the positional mapping is safe."""
    _add(
        session,
        control_id="ac-2",
        odp_id="{$37$}",
        value="ISSM or ISSO",
        oscal_param_id=None,  # cache miss
        slot_index=0,
        slot_total=1,
    )
    rendered, unresolved = resolve_odps(
        session,
        FW,
        "ac-2",
        "Approvals by {{ insert: param, ac-2_prm_2 }} required.",
    )
    assert rendered == "Approvals by ISSM or ISSO required."
    assert unresolved == []


def test_oscal_resolves_via_slot_bridge_when_cache_is_stale(session):
    """The cache points at a param id the catalog no longer uses (e.g.
    catalog reload renamed ``ac-2_prm_2`` to ``ac-02_odp.02``). The
    cached id is now a dead string; the slot position still holds. The
    fallback re-derives the right id from the current template."""
    _add(
        session,
        control_id="ac-2",
        odp_id="{$37$}",
        value="ISSM or ISSO",
        oscal_param_id="ac-2_prm_OLD",  # catalog no longer references this
        slot_index=0,
        slot_total=1,
    )
    rendered, unresolved = resolve_odps(
        session,
        FW,
        "ac-2",
        "Approvals by {{ insert: param, ac-02_odp.02 }} required.",
    )
    assert rendered == "Approvals by ISSM or ISSO required."
    assert unresolved == []


def test_sparse_workbook_slot_bridge_still_works(session):
    """The win that ``slot_total`` buys over ``len(by_slot)``: the
    workbook DECLARED 4 slots but only filled 2. The catalog has 4
    OSCAL params. ``len(by_slot) == 2`` would incorrectly abstain;
    ``workbook_slot_total == 4 == len(template_oscal_params)`` correctly
    allows the bridge for the slots that ARE filled."""
    _add(
        session,
        control_id="ac-2",
        odp_id="{$10$}",
        value="filled-slot-0",
        oscal_param_id=None,
        slot_index=0,
        slot_total=4,
    )
    _add(
        session,
        control_id="ac-2",
        odp_id="{$13$}",
        value="filled-slot-3",
        oscal_param_id=None,
        slot_index=3,
        slot_total=4,
    )
    rendered, unresolved = resolve_odps(
        session,
        FW,
        "ac-2",
        "A {{ insert: param, ac-2_prm_1 }} "
        "B {{ insert: param, ac-2_prm_2 }} "
        "C {{ insert: param, ac-2_prm_3 }} "
        "D {{ insert: param, ac-2_prm_4 }}",
    )
    # Slot 0 and slot 3 resolve; slots 1 and 2 stay unresolved.
    assert "A filled-slot-0" in rendered
    assert "D filled-slot-3" in rendered
    assert "{{ insert: param, ac-2_prm_2 }}" in rendered
    assert "{{ insert: param, ac-2_prm_3 }}" in rendered
    assert unresolved == ["ac-2_prm_2", "ac-2_prm_3"]


def test_slot_bridge_abstains_on_count_mismatch(session):
    """``slot_total`` (3) doesn't match the catalog param count (4) —
    positional alignment is unsafe (a slot was added or removed across
    revisions). Fallback abstains; the placeholder stays visible and the
    bare param id surfaces in ``unresolved``. This is the genuine
    cross-revision case that v0.3's FrameworkEquivalence will cure."""
    _add(
        session,
        control_id="ac-2",
        odp_id="{$10$}",
        value="should-not-leak",
        oscal_param_id=None,
        slot_index=0,
        slot_total=3,  # workbook says 3 slots
    )
    rendered, unresolved = resolve_odps(
        session,
        FW,
        "ac-2",
        # ...but the catalog template declares 4 params
        "{{ insert: param, ac-2_prm_1 }} / "
        "{{ insert: param, ac-2_prm_2 }} / "
        "{{ insert: param, ac-2_prm_3 }} / "
        "{{ insert: param, ac-2_prm_4 }}",
    )
    assert "should-not-leak" not in rendered
    assert unresolved == [
        "ac-2_prm_1",
        "ac-2_prm_2",
        "ac-2_prm_3",
        "ac-2_prm_4",
    ]


def test_slot_bridge_abstains_when_slot_total_is_null(session):
    """Back-compat: rows ingested before ``slot_total`` existed have it
    as NULL. The fallback must abstain (not crash, not silently use
    ``len(by_slot)``). Same behavior as a count mismatch — placeholder
    stays visible. The next re-ingest of the originating workbook
    backfills the column."""
    _add(
        session,
        control_id="ac-2",
        odp_id="{$37$}",
        value="legacy-row",
        oscal_param_id=None,
        slot_index=0,
        slot_total=None,  # legacy row
    )
    rendered, unresolved = resolve_odps(
        session,
        FW,
        "ac-2",
        "Approvals by {{ insert: param, ac-2_prm_2 }} required.",
    )
    assert "legacy-row" not in rendered
    assert "{{ insert: param, ac-2_prm_2 }}" in rendered
    assert unresolved == ["ac-2_prm_2"]


# ---------------------------------------------------------------------------
# bold_format — wrap substituted values for downstream renderers
# ---------------------------------------------------------------------------


def test_bold_format_markdown_wraps_resolved_values(session):
    """``bold_format="markdown"`` is what routes/controls.py passes for the
    Control Detail UI. Substituted values come back as ``**value**`` so the
    React component can split on the pattern and emit <strong>. The original
    placeholder syntax is consumed — the wrapping is only around the
    SUBSTITUTED text, not the surrounding template prose."""
    _add(session, control_id="ac-2", odp_id="{$37$}", value="ISSM or ISSO")
    rendered, unresolved = resolve_odps(
        session,
        FW,
        "ac-2",
        "Requires approvals by {$37$} for requests.",
        bold_format="markdown",
    )
    assert rendered == "Requires approvals by **ISSM or ISSO** for requests."
    assert unresolved == []


def test_bold_format_html_wraps_resolved_values(session):
    """``bold_format="html"`` is what reports/sar.py passes — ReportLab's
    Paragraph interprets ``<b>...</b>`` inline, so the DOCX renders the
    program's answer in bold visually distinct from the template prose."""
    _add(session, control_id="ac-2", odp_id="{$37$}", value="ISSM or ISSO")
    rendered, _ = resolve_odps(
        session,
        FW,
        "ac-2",
        "Requires approvals by {$37$} for requests.",
        bold_format="html",
    )
    assert rendered == "Requires approvals by <b>ISSM or ISSO</b> for requests."


def test_bold_format_does_not_wrap_unresolved_placeholders(session):
    """Only RESOLVED values get the wrapper. Unresolved placeholders stay
    as their raw token so the existing unresolved-odps badge still has
    something to point at and the UI doesn't display ``**{$36$}**``."""
    _add(session, control_id="ac-2", odp_id="{$37$}", value="ISSM or ISSO")
    rendered, unresolved = resolve_odps(
        session,
        FW,
        "ac-2",
        "Identify {$36$}; Approve via {$37$}.",
        bold_format="markdown",
    )
    assert "**ISSM or ISSO**" in rendered
    # {$36$} stays bare so the renderer/badge can find it.
    assert "{$36$}" in rendered
    assert "**{$36$}**" not in rendered
    assert unresolved == ["{$36$}"]


def test_bold_format_wraps_oscal_wrapper_substitution(session):
    """The wrapper applies on the OSCAL ``{{ insert: param, X }}`` path too —
    that's the dominant form in catalog-shipped statements, so SAR output
    depends on it more than the bare {$N$} form."""
    _add(
        session,
        control_id="ac-2",
        odp_id="{$37$}",
        value="ISSM or ISSO",
        oscal_param_id="ac-2_prm_2",
    )
    rendered, _ = resolve_odps(
        session,
        FW,
        "ac-2",
        "Approvals by {{ insert: param, ac-2_prm_2 }} required.",
        bold_format="html",
    )
    assert rendered == "Approvals by <b>ISSM or ISSO</b> required."


def test_bold_format_wraps_slot_bridge_fallback(session):
    """The slot-bridge fallback (cache miss / catalog reload) must also wrap.
    Otherwise SAR output goes inconsistent the moment a workbook predates
    the oscal_param_id cache column."""
    _add(
        session,
        control_id="ac-2",
        odp_id="{$37$}",
        value="ISSM or ISSO",
        oscal_param_id=None,  # cache miss → slot bridge
        slot_index=0,
        slot_total=1,
    )
    rendered, _ = resolve_odps(
        session,
        FW,
        "ac-2",
        "Approvals by {{ insert: param, ac-2_prm_2 }} required.",
        bold_format="html",
    )
    assert rendered == "Approvals by <b>ISSM or ISSO</b> required."


def test_oscal_cache_and_slot_agree_on_realistic_ingest_state(session):
    """In any coherent ingest state, ``oscal_param_id`` and ``slot_index``
    are derived from the SAME positional alignment, so they always agree.
    Two rows here, each with cache + slot pointing at their correct
    positions; verify both resolve cleanly. Documents the realistic
    invariant (vs. the impossible "cache says X, slot says Y" case)."""
    _add(
        session,
        control_id="ac-2",
        odp_id="{$36$}",
        value="value-zero",
        oscal_param_id="ac-2_prm_1",
        slot_index=0,
        slot_total=2,
    )
    _add(
        session,
        control_id="ac-2",
        odp_id="{$37$}",
        value="value-one",
        oscal_param_id="ac-2_prm_2",
        slot_index=1,
        slot_total=2,
    )
    rendered, unresolved = resolve_odps(
        session,
        FW,
        "ac-2",
        "A {{ insert: param, ac-2_prm_1 }} B {{ insert: param, ac-2_prm_2 }}",
    )
    assert rendered == "A value-zero B value-one"
    assert unresolved == []
