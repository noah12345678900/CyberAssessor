"""OSCAL ``profile.modify.alters[].adds[]`` parser.

Pure, no DB I/O. Used by both FedRAMP loaders (20x and legacy Rev5) to
project FedRAMP-specific Requirement/Guidance prose onto child-Framework
shadow Control rows. OSCAL-generic — no FedRAMP-specific naming — so other
overlay-over-catalog paths can reuse the same module verbatim later.

Shape recap (https://pages.nist.gov/OSCAL/concepts/layer/profile/profile/):

  profile:
    modify:
      alters[]:
        - control-id: "ac-2.1"
          adds[]:
            - parts[]:                      # part-injecting add
                - id: "ac-2.1_req"
                  name: "statement"
                  props: [{name: "label", value: "Requirement"}]
                  prose: "FedRAMP-specific text…"
                  parts[]: …                # nested
            - props[]: …                    # prop-only add (no parts) — metadata
              by-id: "ac-2.1_smt"

A "part-injecting" add carries ``parts[]`` and contributes prose. A
"prop-only" add carries only ``props[]`` (method / response-point /
assessment metadata) — counted but not rendered.
"""

from __future__ import annotations

from typing import Any

# Markdown heading used to separate inherited parent statement from the
# overlay prose. Stable across both loaders so tests can grep for it.
FEDRAMP_ADDITIONS_HEADING = "### FedRAMP Additions"


def extract_alters(profile_doc: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Return ``profile.modify.alters[]`` or ``[]``.

    Defensive ``.get(..., {}) or {}`` chaining silently returns ``[]``
    when the document is missing ``profile``, ``modify``, or ``alters``
    (the FedRAMP 20x rules doc has no ``profile`` at all, so this guard
    keeps callers from special-casing it).
    """
    if not profile_doc:
        return []
    prof = profile_doc.get("profile", {}) or {}
    modify = prof.get("modify", {}) or {}
    alters = modify.get("alters", []) or []
    return [a for a in alters if isinstance(a, dict)]


def partition_alter(
    alter: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split an alter's ``adds[]`` into ``(part_adds, prop_only_adds)``.

    Part-injecting adds carry ``parts[]`` (regardless of whether they
    also carry ``props[]``). Prop-only adds carry no ``parts``. Empty
    adds (neither parts nor props) are silently dropped — they
    contribute nothing.
    """
    part_adds: list[dict[str, Any]] = []
    prop_only_adds: list[dict[str, Any]] = []
    for add in alter.get("adds", []) or []:
        if not isinstance(add, dict):
            continue
        parts = add.get("parts") or []
        props = add.get("props") or []
        if parts:
            part_adds.append(add)
        elif props:
            prop_only_adds.append(add)
        # else: empty add, skip
    return part_adds, prop_only_adds


def _label_for_part(part: dict[str, Any]) -> str | None:
    """Return the first ``props[name=='label']`` value, or None."""
    for p in part.get("props", []) or []:
        if not isinstance(p, dict):
            continue
        if p.get("name") == "label":
            v = p.get("value")
            if v:
                return str(v)
    return None


def _render_part(part: dict[str, Any], *, depth: int) -> str:
    """Render a single OSCAL part subtree to Markdown.

    Top-level parts (``depth == 0``) become ``## {title}`` headings;
    nested parts use a bold label prefix (``**Requirement:**``,
    ``**Guidance:**``) derived from ``props[name=='label']`` so the
    result is grep-friendly. Returns empty string when the part has
    neither prose nor renderable children.
    """
    prose = (part.get("prose") or "").strip()
    children = part.get("parts") or []

    rendered_children: list[str] = []
    for child in children:
        if not isinstance(child, dict):
            continue
        chunk = _render_part(child, depth=depth + 1)
        if chunk:
            rendered_children.append(chunk)

    # Drop empty parts entirely — no heading, no whitespace.
    if not prose and not rendered_children:
        return ""

    pieces: list[str] = []

    if depth == 0:
        title = (part.get("title") or "").strip()
        if not title:
            # Fall back to the label prop, then the part id, then a generic
            # placeholder — never silently emit "## ".
            title = _label_for_part(part) or (part.get("id") or "Part")
        pieces.append(f"## {title}")
        if prose:
            pieces.append(prose)
    else:
        label = _label_for_part(part)
        if label and prose:
            pieces.append(f"**{label}:** {prose}")
        elif label:
            pieces.append(f"**{label}:**")
        elif prose:
            pieces.append(prose)

    pieces.extend(rendered_children)
    return "\n\n".join(pieces)


def render_parts_markdown(parts: list[dict[str, Any]] | None) -> str:
    """Render a list of OSCAL parts to Markdown.

    Top-level parts are joined by blank lines. Returns empty string
    when every part is prose-less (e.g. all empty wrappers).
    """
    if not parts:
        return ""
    chunks: list[str] = []
    for part in parts:
        if not isinstance(part, dict):
            continue
        chunk = _render_part(part, depth=0)
        if chunk:
            chunks.append(chunk)
    return "\n\n".join(chunks)


def synthesize_statement(
    control_id: str,
    part_adds: list[dict[str, Any]],
    inherited: str | None,
) -> str:
    """Synthesise the shadow Control's ``statement`` field.

    When ``inherited`` is non-empty, the result is:

        {inherited}

        ---

        ### FedRAMP Additions

        {rendered parts}

    When ``inherited`` is ``None`` (or empty) — i.e. this is a
    whole-new-control synthesis where no parent Control exists — the
    inherited prefix and ``---`` separator are dropped so the shadow
    row's statement starts straight at the FedRAMP heading.

    Fully derived from source ⇒ byte-equal regeneration on reload, so
    the loader's upsert can compare statements for idempotency without
    a UNIQUE constraint.
    """
    all_parts: list[dict[str, Any]] = []
    for add in part_adds:
        for p in add.get("parts") or []:
            if isinstance(p, dict):
                all_parts.append(p)
    rendered = render_parts_markdown(all_parts)
    fedramp_block = f"{FEDRAMP_ADDITIONS_HEADING}\n\n{rendered}" if rendered else FEDRAMP_ADDITIONS_HEADING

    inherited_clean = (inherited or "").strip()
    if inherited_clean:
        return f"{inherited_clean}\n\n---\n\n{fedramp_block}"
    return fedramp_block
