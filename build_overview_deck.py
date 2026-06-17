"""Generate the executive overview deck for Cybersecurity Assessor.

One-off content builder (python-pptx). Run with the backend venv:
    backend/.venv/Scripts/python.exe build_overview_deck.py
Writes Cybersecurity_Assessor_Overview.pptx next to this script.
"""

from __future__ import annotations

from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.util import Emu, Inches, Pt

# ---- palette (deep navy / cyan accent / slate) ----------------------------
NAVY = RGBColor(0x0B, 0x1F, 0x3A)
NAVY2 = RGBColor(0x13, 0x2A, 0x4D)
CYAN = RGBColor(0x29, 0xB6, 0xD8)
CYAN_DK = RGBColor(0x12, 0x7B, 0x97)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
LIGHT = RGBColor(0xE8, 0xEF, 0xF5)
SLATE = RGBColor(0x5A, 0x6B, 0x80)
INK = RGBColor(0x1A, 0x23, 0x30)
GREEN = RGBColor(0x2E, 0xA0, 0x6A)
AMBER = RGBColor(0xE0, 0x8A, 0x1E)

W, H = Inches(13.333), Inches(7.5)

prs = Presentation()
prs.slide_width = W
prs.slide_height = H
BLANK = prs.slide_layouts[6]


def _bg(slide, color):
    slide.background.fill.solid()
    slide.background.fill.fore_color.rgb = color


def _rect(slide, l, t, w, h, fill, line=None, line_w=None):
    from pptx.enum.shapes import MSO_SHAPE

    sp = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, l, t, w, h)
    sp.fill.solid()
    sp.fill.fore_color.rgb = fill
    if line is None:
        sp.line.fill.background()
    else:
        sp.line.color.rgb = line
        sp.line.width = line_w or Pt(1)
    sp.shadow.inherit = False
    return sp


def _round(slide, l, t, w, h, fill, line=None, line_w=None):
    from pptx.enum.shapes import MSO_SHAPE

    sp = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, l, t, w, h)
    sp.fill.solid()
    sp.fill.fore_color.rgb = fill
    if line is None:
        sp.line.fill.background()
    else:
        sp.line.color.rgb = line
        sp.line.width = line_w or Pt(1.25)
    sp.shadow.inherit = False
    return sp


def _text(slide, l, t, w, h, runs, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP,
          space_after=6, line_spacing=1.05):
    """runs: list of paragraphs; each paragraph is list of (text, size, color, bold, italic)."""
    tb = slide.shapes.add_textbox(l, t, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    for i, para in enumerate(runs):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        p.space_after = Pt(space_after)
        p.line_spacing = line_spacing
        for (txt, size, color, bold, italic) in para:
            r = p.add_run()
            r.text = txt
            r.font.size = Pt(size)
            r.font.color.rgb = color
            r.font.bold = bold
            r.font.italic = italic
            r.font.name = "Segoe UI"
    return tb


def _chip(slide, l, t, w, h, label, fill, txtcolor=WHITE, size=11):
    c = _round(slide, l, t, w, h, fill)
    tf = c.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run()
    r.text = label
    r.font.size = Pt(size)
    r.font.bold = True
    r.font.color.rgb = txtcolor
    r.font.name = "Segoe UI"
    return c


def _accentbar(slide):
    _rect(slide, 0, 0, W, Inches(0.12), CYAN)


# ===========================================================================
# Slide 1 — Title
# ===========================================================================
s = prs.slides.add_slide(BLANK)
_bg(s, NAVY)
_rect(s, 0, 0, W, Inches(0.18), CYAN)
_rect(s, 0, H - Inches(0.12), W, Inches(0.12), CYAN_DK)
# accent block
_round(s, Inches(0.9), Inches(2.0), Inches(0.22), Inches(2.2), CYAN)
_text(s, Inches(1.3), Inches(1.9), Inches(11), Inches(1.4),
      [[("Cybersecurity Assessor", 46, WHITE, True, False)]])
_text(s, Inches(1.32), Inches(2.95), Inches(11), Inches(1.0),
      [[("A reasoning engine that assesses like a human expert — and validates every call with AI.",
         22, CYAN, False, False)]])
_text(s, Inches(1.32), Inches(3.85), Inches(11), Inches(1.4),
      [[("Turn months of manual control assessment into days. Defensible verdicts, cited",
         16, LIGHT, False, False)],
       [("evidence, and an auditable trail — running entirely on your own workstation.",
         16, LIGHT, False, False)]])
_chip(s, Inches(1.32), Inches(5.4), Inches(2.3), Inches(0.5), "NIST SP 800-53 + 6 more", CYAN_DK)
_chip(s, Inches(3.8), Inches(5.4), Inches(2.0), Inches(0.5), "Offline / CUI-safe", NAVY2, CYAN)
_chip(s, Inches(6.0), Inches(5.4), Inches(1.9), Inches(0.5), "eMASS-native", NAVY2, CYAN)
_text(s, Inches(1.3), Inches(6.5), Inches(11), Inches(0.5),
      [[("Self-contained Windows desktop application  ·  v2.0.1", 13, SLATE, False, False)]])


# ===========================================================================
# Slide 2 — The problem
# ===========================================================================
s = prs.slides.add_slide(BLANK)
_bg(s, WHITE)
_accentbar(s)
_text(s, Inches(0.8), Inches(0.5), Inches(11.7), Inches(0.9),
      [[("Control assessment is the bottleneck to authorization", 32, NAVY, True, False)]])
_text(s, Inches(0.8), Inches(1.35), Inches(11.7), Inches(0.5),
      [[("Every ATO, IATT, and continuous-monitoring cycle hinges on the same slow, manual work.",
         16, SLATE, False, False)]])

pains = [
    ("Hundreds of controls, by hand",
     "Assessors read each control, hunt for the right artifact, and hand-write a justification — for hundreds of CCIs, every cycle."),
    ("Evidence scattered everywhere",
     "Policies, STIG checklists, scans, screenshots, and diagrams live across SharePoint, shares, and inboxes — finding the right one eats hours."),
    ("Findings that don't hold up",
     "Weak citations and inconsistent narratives get bounced by a 3PAO or JAB reviewer, forcing expensive rework late in the process."),
    ("Sensitive data can't leave",
     "CUI and program data can't be pasted into a public AI tool — so teams stay manual while the rest of the world automates."),
]
cards_y = Inches(2.1)
cw, gap = Inches(5.75), Inches(0.4)
for i, (h, b) in enumerate(pains):
    col = i % 2
    rowi = i // 2
    x = Inches(0.8) + (cw + gap) * col
    y = cards_y + (Inches(2.05)) * rowi
    _round(s, x, y, cw, Inches(1.8), LIGHT)
    _rect(s, x, y, Inches(0.12), Inches(1.8), AMBER)
    _text(s, x + Inches(0.35), y + Inches(0.22), cw - Inches(0.6), Inches(0.5),
          [[(h, 18, NAVY, True, False)]])
    _text(s, x + Inches(0.35), y + Inches(0.78), cw - Inches(0.6), Inches(0.9),
          [[(b, 13, INK, False, False)]], line_spacing=1.1)


# ===========================================================================
# Slide 3 — How it works (the kernel descriptor)
# ===========================================================================
s = prs.slides.add_slide(BLANK)
_bg(s, NAVY)
_rect(s, 0, 0, W, Inches(0.12), CYAN)
_text(s, Inches(0.8), Inches(0.45), Inches(11.7), Inches(0.9),
      [[("How it works: AI speed, kernel-grade rigor", 32, WHITE, True, False)]])
_text(s, Inches(0.8), Inches(1.3), Inches(11.7), Inches(0.5),
      [[("We didn't bolt a chatbot onto a spreadsheet. We built a reasoning engine that mimics how a senior assessor works — then has the LLM check it.",
         15, CYAN, False, False)]])

# pipeline boxes
steps = [
    ("1 · Ingest", "Reads your eMASS CCIS workbook plus every evidence artifact — documents, scans, STIG checklists, network diagrams, screenshots.", CYAN_DK),
    ("2 · Correlate", "A proprietary 5-tier evidence engine links each artifact to the exact control it proves — by document number, CCI, control ID, content type, then ML relevance.", CYAN_DK),
    ("3 · Reason", "Rules modeled on assessor judgment auto-resolve the clear cases — inheritance, scope-exclusion, provider-owned — with no LLM call and no guessing.", CYAN_DK),
    ("4 · Validate", "The judgment calls go to the LLM, which proposes a cited verdict — then a second deterministic pass validates it before it's ever accepted.", CYAN_DK),
    ("5 · Write back", "Verdicts, dates, and narratives written straight into the eMASS workbook — formatting, comments, and data validation fully preserved.", CYAN_DK),
]
bx = Inches(0.8)
bw = Inches(2.3)
bgap = Inches(0.16)
by = Inches(2.15)
bh = Inches(2.5)
for i, (title, body, col) in enumerate(steps):
    x = bx + (bw + bgap) * i
    _round(s, x, by, bw, bh, NAVY2, line=CYAN, line_w=Pt(1))
    _rect(s, x, by, bw, Inches(0.5), col)
    _text(s, x + Inches(0.12), by + Inches(0.04), bw - Inches(0.24), Inches(0.42),
          [[(title, 15, WHITE, True, False)]], anchor=MSO_ANCHOR.MIDDLE)
    _text(s, x + Inches(0.18), by + Inches(0.62), bw - Inches(0.36), Inches(1.8),
          [[(body, 11, LIGHT, False, False)]], line_spacing=1.1)

# kernel descriptor strip
_round(s, Inches(0.8), Inches(5.0), Inches(11.73), Inches(1.9), NAVY2, line=CYAN, line_w=Pt(1.25))
_rect(s, Inches(0.8), Inches(5.0), Inches(0.16), Inches(1.9), CYAN)
_text(s, Inches(1.15), Inches(5.15), Inches(11.1), Inches(0.5),
      [[("The Assessment Engine — reason like an assessor, verify like an auditor", 18, CYAN, True, False)]])
_text(s, Inches(1.15), Inches(5.62), Inches(11.1), Inches(1.2),
      [[("At the core is a proprietary reasoning engine that encodes how an experienced assessor actually works — which evidence matters, when a "
         "control is inherited, when scope excludes it, when the proof simply isn't there. It resolves everything it can prove on its own, then "
         "hands only the true judgment calls to the LLM as a second opinion — and re-validates that opinion before accepting it. ",
         13, LIGHT, False, False)],
       [("Two layers of intelligence, one defensible answer: human-like reasoning for speed, deterministic + LLM validation for trust. When the evidence is ambiguous, it abstains rather than guess.",
         13, WHITE, True, False)]], line_spacing=1.1)


# ===========================================================================
# Slide 3b — Proprietary / cutting-edge engine internals
# ===========================================================================
s = prs.slides.add_slide(BLANK)
_bg(s, WHITE)
_accentbar(s)
_text(s, Inches(0.8), Inches(0.45), Inches(11.7), Inches(0.8),
      [[("Under the hood: proprietary intelligence", 32, NAVY, True, False)]])
_text(s, Inches(0.8), Inches(1.3), Inches(11.7), Inches(0.5),
      [[("Three engines that learn and adapt — not off-the-shelf prompting.", 16, SLATE, False, False)]])

eng = [
    ("Machine-learning evidence sweep",
     "Boundary-aware SharePoint triage",
     "Point it at a 4,000-file SharePoint site and it surfaces the ~30 files that belong to THIS system — reading only metadata and search snippets, never downloading. It scores every candidate against the system's host inventory, control-family keywords, and the responsibility matrix, and proposes the control each one proves before a single byte is pulled."),
    ("A model that learns your judgment",
     "Online behavioral learning",
     "Every time an assessor includes or rejects a swept file, an online machine-learning model updates the scoring weights toward that behavior. The engine literally learns what THIS team treats as relevant evidence, and gets sharper with every assessment — no retraining cycle, no data leaving the workstation."),
    ("A lie detector for vendor spreadsheets",
     "Adversarial CRM anomaly detection",
     "When a cloud vendor says 'we handle this control,' the system can auto-pass it — a huge time-saver, IF the spreadsheet is honest. This engine vets every vendor responsibility matrix for 'too good to be true' claims: almost-everything-inherited, copy-pasted boilerplate, or claims that contradict your own scans. It compares each matrix to every one seen before and flags the outliers — so the system never rubber-stamps a control on a bad spreadsheet."),
]
ey = Inches(2.0)
ew = Inches(3.84)
egap = Inches(0.1)
for i, (title, tag, body) in enumerate(eng):
    x = Inches(0.8) + (ew + egap) * i
    _round(s, x, ey, ew, Inches(4.6), NAVY)
    _rect(s, x, ey, ew, Inches(0.08), CYAN)
    _text(s, x + Inches(0.3), ey + Inches(0.28), ew - Inches(0.6), Inches(0.95),
          [[(title, 16, WHITE, True, False)]], line_spacing=1.02)
    _chip(s, x + Inches(0.3), ey + Inches(1.32), ew - Inches(0.6), Inches(0.42), tag, CYAN_DK, WHITE, 10.5)
    _text(s, x + Inches(0.3), ey + Inches(1.92), ew - Inches(0.6), Inches(2.55),
          [[(body, 11, LIGHT, False, False)]], line_spacing=1.12)
_text(s, Inches(0.8), Inches(6.75), Inches(11.7), Inches(0.4),
      [[("All learning happens locally — your evidence and your team's judgment never leave the workstation.",
         12.5, CYAN_DK, False, True)]])


# ===========================================================================
# Slide 4 — Feature grid
# ===========================================================================
s = prs.slides.add_slide(BLANK)
_bg(s, WHITE)
_accentbar(s)
_text(s, Inches(0.8), Inches(0.45), Inches(11.7), Inches(0.8),
      [[("What it does", 32, NAVY, True, False)]])

feats = [
    ("Multi-framework", "NIST 800-53, 800-171, CSF 2.0, ISO 27001, CIS v8, PCI DSS, and SOC 2 — one engine, seven frameworks."),
    ("Reads every artifact", "PDF, Word, PowerPoint, Excel, STIG .ckl/.cklb/XCCDF, Nessus/ACAS scans, Visio diagrams, and screenshots."),
    ("OCR built in", "Pulls text out of config screenshots (MFA, GPO, lockout screens) so image evidence actually counts — fully offline."),
    ("Cited narratives", "Every verdict names the exact document, section, and STIG rule it relies on — no invented citations."),
    ("Multi-boundary aware", "Splits responsibility per cloud tenant (e.g. AWS GovCloud vs. Azure Government) with attribution that can't cross boundaries."),
    ("eMASS round-trip", "Reads the CCIS export and writes results back in place — comments, conditional formatting, and data validation survive."),
    ("Auto POA&M", "Generates Plan of Action & Milestones entries for gaps, grounded in the actual finding and severity-based timelines."),
    ("Full audit trail", "Records the precise evidence snippet behind every decision, so a reviewer can replay exactly what the assessor saw."),
    ("Customer responsibility", "Ingests Customer Responsibility Matrices and auto-resolves inherited / provider / shared controls."),
]
gx, gy = Inches(0.8), Inches(1.45)
gw, gh = Inches(3.84), Inches(1.7)
ggap = Inches(0.1)
for i, (h, b) in enumerate(feats):
    col = i % 3
    rowi = i // 3
    x = gx + (gw + ggap) * col
    y = gy + (gh + ggap) * rowi
    _round(s, x, y, gw, gh, LIGHT)
    _rect(s, x, y, gw, Inches(0.07), CYAN)
    _text(s, x + Inches(0.25), y + Inches(0.18), gw - Inches(0.5), Inches(0.45),
          [[(h, 15.5, NAVY, True, False)]])
    _text(s, x + Inches(0.25), y + Inches(0.66), gw - Inches(0.5), Inches(0.95),
          [[(b, 11.5, INK, False, False)]], line_spacing=1.1)


# ===========================================================================
# Slide 5 — Why it's different
# ===========================================================================
s = prs.slides.add_slide(BLANK)
_bg(s, WHITE)
_accentbar(s)
_text(s, Inches(0.8), Inches(0.45), Inches(11.7), Inches(0.8),
      [[("Why it's different", 32, NAVY, True, False)]])
_text(s, Inches(0.8), Inches(1.3), Inches(11.7), Inches(0.5),
      [[("Not a chatbot bolted onto compliance. A purpose-built assessment engine.", 16, SLATE, False, False)]])

diffs = [
    ("Proprietary reasoning engine",
     "Not prompt-wrapping. A purpose-built engine that encodes assessor judgment, learns your team's behavior, and uses the LLM as a checked second opinion."),
    ("Learns locally, privately",
     "On-device machine learning adapts to how your team works — and your CUI, evidence, and judgment never leave the workstation. Offline-capable, OCR included."),
    ("Defensible by construction",
     "Every verdict is LLM-proposed, rule-validated, and traced to specific evidence — and abstains when unsure. Built to survive 3PAO / JAB scrutiny."),
    ("Speaks eMASS natively",
     "Consumes the real CCIS workbook and writes results back in place — no re-keying, no broken formatting, no separate system to maintain."),
]
dy = Inches(2.0)
dw = Inches(5.75)
dgap = Inches(0.4)
for i, (h, b) in enumerate(diffs):
    col = i % 2
    rowi = i // 2
    x = Inches(0.8) + (dw + dgap) * col
    y = dy + Inches(2.2) * rowi
    _round(s, x, y, dw, Inches(1.95), NAVY)
    _rect(s, x, y, Inches(0.12), Inches(1.95), CYAN)
    _text(s, x + Inches(0.4), y + Inches(0.25), dw - Inches(0.7), Inches(0.5),
          [[(h, 19, WHITE, True, False)]])
    _text(s, x + Inches(0.4), y + Inches(0.85), dw - Inches(0.7), Inches(1.0),
          [[(b, 13, LIGHT, False, False)]], line_spacing=1.15)


# ===========================================================================
# Slide 5b — ROI / estimated savings per assessment
# ===========================================================================
s = prs.slides.add_slide(BLANK)
_bg(s, WHITE)
_accentbar(s)
_text(s, Inches(0.8), Inches(0.45), Inches(11.7), Inches(0.8),
      [[("What one assessment is worth", 32, NAVY, True, False)]])
_text(s, Inches(0.8), Inches(1.3), Inches(11.7), Inches(0.5),
      [[("Estimated savings on a single full-system ATO package.*", 16, SLATE, False, False)]])

roi = [
    ("~240 hrs", "saved per assessment", "≈ 6 assessor work-weeks returned to the team"),
    ("~$42,000", "saved per assessment", "fully-burdened assessor labor, one package"),
    ("~80%", "less assessment time", "clear cases auto-resolve; experts handle the rest"),
    ("Days", "not months", "compress the authorization timeline to ATO"),
]
rx = Inches(0.8)
rw = Inches(2.85)
rgap = Inches(0.13)
for i, (big, mid, small) in enumerate(roi):
    x = rx + (rw + rgap) * i
    _round(s, x, Inches(2.05), rw, Inches(2.5), NAVY)
    _rect(s, x, Inches(2.05), rw, Inches(0.1), CYAN)
    _text(s, x, Inches(2.35), rw, Inches(0.85),
          [[(big, 38, CYAN, True, False)]], align=PP_ALIGN.CENTER)
    _text(s, x + Inches(0.2), Inches(3.2), rw - Inches(0.4), Inches(0.5),
          [[(mid, 14, WHITE, True, False)]], align=PP_ALIGN.CENTER)
    _text(s, x + Inches(0.25), Inches(3.7), rw - Inches(0.5), Inches(0.8),
          [[(small, 11.5, LIGHT, False, False)]], align=PP_ALIGN.CENTER, line_spacing=1.1)

# methodology / asterisk box
_round(s, Inches(0.8), Inches(4.85), Inches(11.73), Inches(1.75), LIGHT)
_rect(s, Inches(0.8), Inches(4.85), Inches(0.12), Inches(1.75), AMBER)
_text(s, Inches(1.1), Inches(5.0), Inches(11.2), Inches(1.6),
      [[("* Illustrative estimate, not a guarantee.", 12.5, NAVY, True, False)],
       [("Basis: a full-system ATO of ~300 controls (~700+ CCIs). Manual baseline ~1 assessor-hour per control "
         "(≈300 hrs); with the tool, deterministic auto-resolution + AI-assisted assessment cut hands-on effort "
         "by ~80% (≈60 hrs). Dollar figure uses a ~$175/hr fully-burdened cleared-assessor rate "
         "(blend of GS-equivalent contractor and senior 3PAO).",
         11.5, INK, False, False)],
       [("Actual savings vary by system size, baseline, evidence quality, and team. Your numbers will differ — these are planning estimates only.",
         11.5, SLATE, False, True)]], line_spacing=1.12)


# ===========================================================================
# Slide 6 — Proof / close
# ===========================================================================
s = prs.slides.add_slide(BLANK)
_bg(s, NAVY)
_rect(s, 0, 0, W, Inches(0.12), CYAN)
_text(s, Inches(0.8), Inches(0.7), Inches(11.7), Inches(0.9),
      [[("Built for the people who own the ATO", 32, WHITE, True, False)]])

# stat row
stats = [
    ("7", "frameworks supported"),
    ("23", "evidence file formats read"),
    ("5-tier", "evidence-to-control engine"),
    ("100%", "on-prem / offline-capable"),
]
sx = Inches(0.8)
sw = Inches(2.85)
sgap = Inches(0.13)
for i, (big, small) in enumerate(stats):
    x = sx + (sw + sgap) * i
    _round(s, x, Inches(1.9), sw, Inches(1.5), NAVY2, line=CYAN, line_w=Pt(1))
    _text(s, x, Inches(2.05), sw, Inches(0.8),
          [[(big, 40, CYAN, True, False)]], align=PP_ALIGN.CENTER)
    _text(s, x, Inches(2.85), sw, Inches(0.5),
          [[(small, 13, LIGHT, False, False)]], align=PP_ALIGN.CENTER)

# bottom line
_round(s, Inches(0.8), Inches(3.9), Inches(11.73), Inches(1.5), NAVY2, line=CYAN, line_w=Pt(1.25))
_text(s, Inches(1.2), Inches(4.15), Inches(11.0), Inches(1.1),
      [[("The bottom line", 18, CYAN, True, False)],
       [("Cybersecurity Assessor compresses the slowest, most error-prone phase of authorization into a fast, "
         "repeatable, auditable workflow — without ever sending your data off the workstation.",
         15, WHITE, False, False)]], line_spacing=1.18)

_text(s, Inches(0.8), Inches(5.75), Inches(11.7), Inches(0.6),
      [[("Self-contained Windows installer  ·  No separate runtime  ·  Bring your own AI key", 14, CYAN, True, False)]])
_text(s, Inches(0.8), Inches(6.4), Inches(11.7), Inches(0.5),
      [[("Cybersecurity Assessor — assess with confidence, defend with evidence.", 13, SLATE, False, True)]])


out = Path(__file__).resolve().parent / "Cybersecurity_Assessor_Overview.pptx"
prs.save(str(out))
print("WROTE", out, f"({out.stat().st_size // 1024} KB, {len(prs.slides.__iter__.__self__._sldIdLst)} slides)")
