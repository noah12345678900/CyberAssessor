"""Generate the executive overview deck for Cybersecurity Assessor.

One-off content builder (python-pptx). Run with the backend venv:
    backend/.venv/Scripts/python.exe build_overview_deck.py
Writes Cybersecurity_Assessor_Overview.pptx next to this script.

Palette is Nuon brand (navy + blue), pulled from the marketing site CSS.
"""

from __future__ import annotations

from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.util import Inches, Pt

# ---- Nuon palette (navy / blue accent) ------------------------------------
NAVY = RGBColor(0x0A, 0x25, 0x40)        # --navy
NAVY_DEEP = RGBColor(0x06, 0x1A, 0x30)   # --navy-deep
NAVY2 = RGBColor(0x10, 0x2E, 0x52)       # card-on-dark
NAVY3 = RGBColor(0x0F, 0x33, 0x66)       # gradient mid
BLUE = RGBColor(0x25, 0x63, 0xEB)        # --blue
BLUE_BRIGHT = RGBColor(0x3B, 0x82, 0xF6) # --blue-bright
SKY = RGBColor(0x60, 0xA5, 0xFA)         # light blue accent
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
LIGHT = RGBColor(0xE7, 0xEF, 0xFB)       # pale blue text on dark
SOFT = RGBColor(0xF6, 0xF9, 0xFC)        # --bg-soft (card on light)
LINE = RGBColor(0xE5, 0xEB, 0xF3)        # --line
SLATE = RGBColor(0x5B, 0x6B, 0x85)       # --muted
INK = RGBColor(0x1A, 0x25, 0x40)         # --ink
GREEN = RGBColor(0x16, 0xA3, 0x4A)
AMBER = RGBColor(0xE0, 0x8A, 0x1E)
MIST = RGBColor(0xC8, 0xD4, 0xE8)        # footnote on dark

W, H = Inches(13.333), Inches(7.5)

prs = Presentation()
prs.slide_width = W
prs.slide_height = H
BLANK = prs.slide_layouts[6]


# ---------------------------------------------------------------------------
# primitives
# ---------------------------------------------------------------------------
def _bg(slide, color):
    slide.background.fill.solid()
    slide.background.fill.fore_color.rgb = color


def _grad_bg(slide, c1, c2, angle=90):
    """Full-bleed gradient rectangle (added first => sits behind content)."""
    sp = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, W, H)
    sp.fill.gradient()
    try:
        sp.fill.gradient_angle = angle
    except Exception:
        pass
    stops = sp.fill.gradient_stops
    stops[0].color.rgb = c1
    stops[0].position = 0.0
    stops[1].color.rgb = c2
    stops[1].position = 1.0
    sp.line.fill.background()
    sp.shadow.inherit = False
    return sp


def _rect(slide, l, t, w, h, fill, line=None, line_w=None):
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


def _grad_rect(slide, l, t, w, h, c1, c2, angle=0):
    sp = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, l, t, w, h)
    sp.fill.gradient()
    try:
        sp.fill.gradient_angle = angle
    except Exception:
        pass
    stops = sp.fill.gradient_stops
    stops[0].color.rgb = c1
    stops[0].position = 0.0
    stops[1].color.rgb = c2
    stops[1].position = 1.0
    sp.line.fill.background()
    sp.shadow.inherit = False
    return sp


def _round(slide, l, t, w, h, fill, line=None, line_w=None, radius=0.08):
    sp = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, l, t, w, h)
    try:
        sp.adjustments[0] = radius
    except Exception:
        pass
    sp.fill.solid()
    sp.fill.fore_color.rgb = fill
    if line is None:
        sp.line.fill.background()
    else:
        sp.line.color.rgb = line
        sp.line.width = line_w or Pt(1.25)
    sp.shadow.inherit = False
    return sp


def _grad_round(slide, l, t, w, h, c1, c2, angle=45, line=None, line_w=None, radius=0.08):
    sp = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, l, t, w, h)
    try:
        sp.adjustments[0] = radius
    except Exception:
        pass
    sp.fill.gradient()
    try:
        sp.fill.gradient_angle = angle
    except Exception:
        pass
    stops = sp.fill.gradient_stops
    stops[0].color.rgb = c1
    stops[0].position = 0.0
    stops[1].color.rgb = c2
    stops[1].position = 1.0
    if line is None:
        sp.line.fill.background()
    else:
        sp.line.color.rgb = line
        sp.line.width = line_w or Pt(1.25)
    sp.shadow.inherit = False
    return sp


def _text(slide, l, t, w, h, runs, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP,
          space_after=6, line_spacing=1.05):
    """runs: list of paragraphs; each paragraph is a list of run tuples.

    A run tuple is (text, size, color, bold, italic) or, to make the run a
    hyperlink, (text, size, color, bold, italic, url).
    """
    tb = slide.shapes.add_textbox(l, t, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    for i, para in enumerate(runs):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        p.space_after = Pt(space_after)
        p.line_spacing = line_spacing
        for run in para:
            txt, size, color, bold, italic = run[:5]
            url = run[5] if len(run) > 5 else None
            r = p.add_run()
            r.text = txt
            r.font.size = Pt(size)
            r.font.color.rgb = color
            r.font.bold = bold
            r.font.italic = italic
            r.font.name = "Segoe UI"
            if url:
                r.hyperlink.address = url
    return tb


def _chip(slide, l, t, w, h, label, fill, txtcolor=WHITE, size=11, line=None):
    c = _round(slide, l, t, w, h, fill, line=line, line_w=Pt(1), radius=0.5)
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
    _grad_rect(slide, 0, 0, W, Inches(0.14), BLUE, BLUE_BRIGHT, angle=0)


def _kicker(slide, l, t, label, color=BLUE):
    _text(slide, l, t, Inches(6), Inches(0.35),
          [[(label.upper(), 12, color, True, False)]])


# ===========================================================================
# Slide 1 — Title
# ===========================================================================
s = prs.slides.add_slide(BLANK)
_grad_bg(s, NAVY_DEEP, NAVY3, angle=60)
_grad_rect(s, 0, 0, W, Inches(0.16), BLUE_BRIGHT, BLUE, angle=0)
_rect(s, 0, H - Inches(0.1), W, Inches(0.1), BLUE)

# soft glow accent circle (fully on-slide, low-contrast)
_grad_round(s, Inches(8.75), Inches(1.55), Inches(4.4), Inches(4.4),
            NAVY2, NAVY_DEEP, angle=45, radius=0.5)

# accent rail
_grad_round(s, Inches(0.9), Inches(1.95), Inches(0.18), Inches(2.35),
            BLUE_BRIGHT, BLUE, angle=90, radius=0.5)

_kicker(s, Inches(1.32), Inches(1.55), "Nuon  ·  AI-driven control assessment")
_text(s, Inches(1.3), Inches(1.95), Inches(11), Inches(1.4),
      [[("Cybersecurity Assessor", 48, WHITE, True, False)]])
_text(s, Inches(1.32), Inches(3.0), Inches(10.6), Inches(1.0),
      [[("Deterministic reasoning, machine learning, and AI validation working in tandem to assess like a human expert.",
         22, SKY, False, False)]])
_text(s, Inches(1.32), Inches(3.95), Inches(10.4), Inches(1.4),
      [[("Turn months of manual control assessment into days. Defensible verdicts, cited",
         16, LIGHT, False, False)],
       [("evidence, and an auditable trail — running entirely inside your own enclave.",
         16, LIGHT, False, False)]])

# classification spectrum chips
_chip(s, Inches(1.32), Inches(5.25), Inches(1.9), Inches(0.46), "UNCLASSIFIED", NAVY2, SKY, 10.5, line=BLUE)
_chip(s, Inches(3.34), Inches(5.25), Inches(1.1), Inches(0.46), "CUI", NAVY2, SKY, 10.5, line=BLUE)
_chip(s, Inches(4.56), Inches(5.25), Inches(1.4), Inches(0.46), "SECRET", NAVY2, SKY, 10.5, line=BLUE)
_chip(s, Inches(6.08), Inches(5.25), Inches(2.0), Inches(0.46), "TOP SECRET / SCI", BLUE, WHITE, 10.5)

# capability chips
_chip(s, Inches(1.32), Inches(5.95), Inches(2.5), Inches(0.5), "7 frameworks · eMASS-native", NAVY2, LIGHT, 11, line=BLUE)
_chip(s, Inches(3.96), Inches(5.95), Inches(2.5), Inches(0.5), "Runs in-enclave · no SaaS", NAVY2, LIGHT, 11, line=BLUE)

_text(s, Inches(1.3), Inches(6.75), Inches(11), Inches(0.5),
      [[("Self-contained Windows desktop application  ·  v2.0.1", 13, MIST, False, False)]])


# ===========================================================================
# Slide 2 — The problem
# ===========================================================================
s = prs.slides.add_slide(BLANK)
_bg(s, WHITE)
_accentbar(s)
_kicker(s, Inches(0.8), Inches(0.5), "The problem", AMBER)
_text(s, Inches(0.8), Inches(0.85), Inches(11.7), Inches(0.9),
      [[("Control assessment is the bottleneck to authorization", 32, NAVY, True, False)]])
_text(s, Inches(0.8), Inches(1.65), Inches(11.7), Inches(0.5),
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
     "CUI and classified program data can't be pasted into a public AI tool — so teams stay manual while the rest of the world automates."),
]
cards_y = Inches(2.35)
cw, gap = Inches(5.75), Inches(0.4)
for i, (h, b) in enumerate(pains):
    col = i % 2
    rowi = i // 2
    x = Inches(0.8) + (cw + gap) * col
    y = cards_y + (Inches(2.0)) * rowi
    _round(s, x, y, cw, Inches(1.78), SOFT, line=LINE, line_w=Pt(1))
    _grad_round(s, x, y, Inches(0.14), Inches(1.78), AMBER, RGBColor(0xF2, 0xB1, 0x55), angle=90, radius=0.5)
    _text(s, x + Inches(0.4), y + Inches(0.22), cw - Inches(0.65), Inches(0.5),
          [[(h, 18, NAVY, True, False)]])
    _text(s, x + Inches(0.4), y + Inches(0.78), cw - Inches(0.65), Inches(0.9),
          [[(b, 13, INK, False, False)]], line_spacing=1.12)


# ===========================================================================
# Slide 3 — Classification & privacy boundary  (NEW)
# ===========================================================================
s = prs.slides.add_slide(BLANK)
_grad_bg(s, NAVY_DEEP, NAVY3, angle=60)
_grad_rect(s, 0, 0, W, Inches(0.14), BLUE_BRIGHT, BLUE, angle=0)
_kicker(s, Inches(0.8), Inches(0.45), "Built for every enclave", SKY)
_text(s, Inches(0.8), Inches(0.8), Inches(11.7), Inches(0.8),
      [[("From Unclassified to Top Secret — your data never leaves", 30, WHITE, True, False)]])
_text(s, Inches(0.8), Inches(1.55), Inches(11.7), Inches(0.5),
      [[("The same engine runs from a CUI dev box to a TS/SCI accreditation. Only the AI endpoint changes.",
         15, SKY, False, False)]])

# classification spectrum bar
seg_labels = ["UNCLASSIFIED", "CUI", "SECRET", "TOP SECRET / SCI"]
seg_w = [Inches(3.0), Inches(2.4), Inches(2.9), Inches(3.43)]
sx = Inches(0.8)
sy = Inches(2.25)
sh = Inches(0.62)
seg_fills = [NAVY2, NAVY2, BLUE, BLUE_BRIGHT]
seg_txt = [SKY, SKY, WHITE, WHITE]
for lab, wseg, fill, tc in zip(seg_labels, seg_w, seg_fills, seg_txt):
    seg = _round(s, sx, sy, wseg - Inches(0.1), sh, fill, line=BLUE, line_w=Pt(1), radius=0.5)
    tf = seg.text_frame
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run()
    r.text = lab
    r.font.size = Pt(12.5)
    r.font.bold = True
    r.font.color.rgb = tc
    r.font.name = "Segoe UI"
    sx = sx + wseg

# three privacy pillars
priv = [
    ("Lives inside your enclave",
     "Installs and runs entirely on the assessor's workstation — no SaaS, no portal, no account. Your eMASS workbook and every artifact stay on the network they already live on. Air-gap friendly."),
    ("You choose the AI boundary",
     "Point it at the model approved for your environment: a commercial key for unclassified work, or a GovCloud / in-boundary endpoint for higher enclaves. The only outbound call is to the endpoint you designate."),
    ("Nothing phones home",
     "No telemetry, no analytics, no evidence upload. On-device learning means the model adapts to your team locally — your CUI, evidence, and the judgment it learns from never leave the box."),
]
py = Inches(3.25)
pw = Inches(3.84)
pgap = Inches(0.1)
for i, (title, body) in enumerate(priv):
    x = Inches(0.8) + (pw + pgap) * i
    _round(s, x, py, pw, Inches(3.0), NAVY2, line=BLUE, line_w=Pt(1), radius=0.06)
    _grad_rect(s, x, py, pw, Inches(0.09), BLUE_BRIGHT, BLUE, angle=0)
    _text(s, x + Inches(0.32), py + Inches(0.3), pw - Inches(0.6), Inches(0.7),
          [[(title, 17, WHITE, True, False)]], line_spacing=1.02)
    _text(s, x + Inches(0.32), py + Inches(1.1), pw - Inches(0.6), Inches(1.8),
          [[(body, 11.5, LIGHT, False, False)]], line_spacing=1.14)

_text(s, Inches(0.8), Inches(6.55), Inches(11.7), Inches(0.5),
      [[("Deterministic-only mode runs with no AI endpoint at all — rule-based resolution for fully air-gapped systems.",
         12.5, SKY, False, True)]])


# ===========================================================================
# Slide 4 — How it works (the pipeline + kernel descriptor)
# ===========================================================================
s = prs.slides.add_slide(BLANK)
_grad_bg(s, NAVY_DEEP, NAVY3, angle=60)
_grad_rect(s, 0, 0, W, Inches(0.14), BLUE_BRIGHT, BLUE, angle=0)
_kicker(s, Inches(0.8), Inches(0.4), "How it works", SKY)
_text(s, Inches(0.8), Inches(0.74), Inches(11.7), Inches(0.8),
      [[("AI speed, kernel-grade rigor", 32, WHITE, True, False)]])
_text(s, Inches(0.8), Inches(1.5), Inches(11.7), Inches(0.5),
      [[("We didn't bolt a chatbot onto a spreadsheet. We built a reasoning engine that mimics how a senior assessor works — then has the LLM check it.",
         14, SKY, False, False)]])

steps = [
    ("1 · Ingest", "Reads your eMASS CCIS workbook plus every evidence artifact — documents, scans, STIG checklists, network diagrams, and screenshots."),
    ("2 · Correlate", "A proprietary 5-tier evidence engine links each artifact to the exact control it proves — by document number, CCI, control ID, content type, then ML relevance."),
    ("3 · Reason", "Rules modeled on assessor judgment auto-resolve the clear cases — inheritance, scope-exclusion, provider-owned — with no LLM call and no guessing."),
    ("4 · Validate", "The judgment calls go to the LLM, which proposes a cited verdict — then a second deterministic pass validates it before it's ever accepted."),
    ("5 · Write back", "Verdicts, dates, and narratives written straight into the eMASS workbook — formatting, comments, and data validation fully preserved."),
]
bx = Inches(0.8)
bw = Inches(2.3)
bgap = Inches(0.16)
by = Inches(2.25)
bh = Inches(2.45)
for i, (title, body) in enumerate(steps):
    x = bx + (bw + bgap) * i
    _round(s, x, by, bw, bh, NAVY2, line=BLUE, line_w=Pt(1), radius=0.06)
    _grad_rect(s, x, by, bw, Inches(0.5), BLUE, BLUE_BRIGHT, angle=0)
    _text(s, x + Inches(0.14), by + Inches(0.04), bw - Inches(0.28), Inches(0.42),
          [[(title, 15, WHITE, True, False)]], anchor=MSO_ANCHOR.MIDDLE)
    _text(s, x + Inches(0.2), by + Inches(0.64), bw - Inches(0.4), Inches(1.75),
          [[(body, 11, LIGHT, False, False)]], line_spacing=1.12)

# kernel descriptor strip
_round(s, Inches(0.8), Inches(5.05), Inches(11.73), Inches(1.9), NAVY2, line=BLUE, line_w=Pt(1.25), radius=0.06)
_grad_rect(s, Inches(0.8), Inches(5.05), Inches(0.18), Inches(1.9), BLUE_BRIGHT, BLUE, angle=90)
_text(s, Inches(1.18), Inches(5.2), Inches(11.1), Inches(0.5),
      [[("The Assessment Engine — reason like an assessor, verify like an auditor", 18, SKY, True, False)]])
_text(s, Inches(1.18), Inches(5.67), Inches(11.1), Inches(1.2),
      [[("At the core is a proprietary reasoning engine that encodes how an experienced assessor actually works — which evidence matters, when a "
         "control is inherited, when scope excludes it, when the proof simply isn't there. It resolves everything it can prove on its own, then "
         "hands only the true judgment calls to the LLM as a second opinion — and re-validates that opinion before accepting it. ",
         13, LIGHT, False, False)],
       [("Two layers of intelligence, one defensible answer: human-like reasoning for speed, deterministic + LLM validation for trust. When the evidence is ambiguous, it abstains rather than guess.",
         13, WHITE, True, False)]], line_spacing=1.1)


# ===========================================================================
# Slide 5 — Under the hood: proprietary engine internals
# ===========================================================================
s = prs.slides.add_slide(BLANK)
_bg(s, WHITE)
_accentbar(s)
_kicker(s, Inches(0.8), Inches(0.45), "Under the hood")
_text(s, Inches(0.8), Inches(0.8), Inches(11.7), Inches(0.8),
      [[("Three engines that learn and adapt", 32, NAVY, True, False)]])
_text(s, Inches(0.8), Inches(1.6), Inches(11.7), Inches(0.5),
      [[("Not off-the-shelf prompting — proprietary intelligence, all running locally.", 16, SLATE, False, False)]])

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
ey = Inches(2.25)
ew = Inches(3.84)
egap = Inches(0.1)
for i, (title, tag, body) in enumerate(eng):
    x = Inches(0.8) + (ew + egap) * i
    _grad_round(s, x, ey, ew, Inches(4.35), NAVY, NAVY3, angle=60, radius=0.05)
    _grad_rect(s, x, ey, ew, Inches(0.09), BLUE_BRIGHT, BLUE, angle=0)
    _text(s, x + Inches(0.3), ey + Inches(0.28), ew - Inches(0.6), Inches(0.95),
          [[(title, 16, WHITE, True, False)]], line_spacing=1.02)
    _chip(s, x + Inches(0.3), ey + Inches(1.28), ew - Inches(0.6), Inches(0.42), tag, BLUE, WHITE, 10.5)
    _text(s, x + Inches(0.3), ey + Inches(1.88), ew - Inches(0.6), Inches(2.4),
          [[(body, 11, LIGHT, False, False)]], line_spacing=1.12)
_text(s, Inches(0.8), Inches(6.8), Inches(11.7), Inches(0.4),
      [[("All learning happens locally — your evidence and your team's judgment never leave the workstation.",
         12.5, BLUE, False, True)]])


# ===========================================================================
# Slide 6 — Feature grid
# ===========================================================================
s = prs.slides.add_slide(BLANK)
_bg(s, WHITE)
_accentbar(s)
_kicker(s, Inches(0.8), Inches(0.45), "What it does")
_text(s, Inches(0.8), Inches(0.8), Inches(11.7), Inches(0.8),
      [[("One engine, end to end", 32, NAVY, True, False)]])

feats = [
    ("Multi-framework", "NIST 800-53, 800-171 (CMMC), CSF 2.0, ISO 27001, CIS v8, PCI DSS, and SOC 2 — one engine, seven frameworks."),
    ("Reads every artifact", "PDF, Word, PowerPoint, Excel, STIG .ckl/.cklb/XCCDF, Nessus/ACAS scans, Visio diagrams, and screenshots."),
    ("OCR built in", "Pulls text out of config screenshots (MFA, GPO, lockout screens) so image evidence actually counts — fully offline."),
    ("Cited narratives", "Every verdict names the exact document, section, and STIG rule it relies on — no invented citations."),
    ("Multi-boundary aware", "Splits responsibility per cloud tenant (e.g. AWS GovCloud vs. Azure Government) with attribution that can't cross boundaries."),
    ("eMASS round-trip", "Reads the CCIS export and writes results back in place — comments, conditional formatting, and data validation survive."),
    ("Auto POA&M", "Generates Plan of Action & Milestones entries for gaps, grounded in the actual finding and severity-based timelines."),
    ("Full audit trail", "Records the precise evidence snippet behind every decision, so a reviewer can replay exactly what the assessor saw."),
    ("Customer responsibility", "Ingests Customer Responsibility Matrices and auto-resolves inherited / provider / shared controls."),
]
gx, gy = Inches(0.8), Inches(1.7)
gw, gh = Inches(3.84), Inches(1.62)
ggap = Inches(0.1)
for i, (h, b) in enumerate(feats):
    col = i % 3
    rowi = i // 3
    x = gx + (gw + ggap) * col
    y = gy + (gh + ggap) * rowi
    _round(s, x, y, gw, gh, SOFT, line=LINE, line_w=Pt(1), radius=0.06)
    _grad_rect(s, x, y, gw, Inches(0.08), BLUE, BLUE_BRIGHT, angle=0)
    _text(s, x + Inches(0.28), y + Inches(0.2), gw - Inches(0.5), Inches(0.45),
          [[(h, 15.5, NAVY, True, False)]])
    _text(s, x + Inches(0.28), y + Inches(0.64), gw - Inches(0.5), Inches(0.9),
          [[(b, 11.5, INK, False, False)]], line_spacing=1.1)


# ===========================================================================
# Slide 7 — Why it's different
# ===========================================================================
s = prs.slides.add_slide(BLANK)
_bg(s, WHITE)
_accentbar(s)
_kicker(s, Inches(0.8), Inches(0.45), "Why it's different")
_text(s, Inches(0.8), Inches(0.8), Inches(11.7), Inches(0.8),
      [[("A purpose-built assessment engine", 32, NAVY, True, False)]])
_text(s, Inches(0.8), Inches(1.6), Inches(11.7), Inches(0.5),
      [[("Not a chatbot bolted onto compliance.", 16, SLATE, False, False)]])

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
dy = Inches(2.15)
dw = Inches(5.75)
dgap = Inches(0.4)
for i, (h, b) in enumerate(diffs):
    col = i % 2
    rowi = i // 2
    x = Inches(0.8) + (dw + dgap) * col
    y = dy + Inches(2.15) * rowi
    _grad_round(s, x, y, dw, Inches(1.95), NAVY, NAVY3, angle=60, radius=0.06)
    _grad_round(s, x, y, Inches(0.14), Inches(1.95), BLUE_BRIGHT, BLUE, angle=90, radius=0.5)
    _text(s, x + Inches(0.42), y + Inches(0.25), dw - Inches(0.72), Inches(0.5),
          [[(h, 19, WHITE, True, False)]])
    _text(s, x + Inches(0.42), y + Inches(0.85), dw - Inches(0.72), Inches(1.0),
          [[(b, 13, LIGHT, False, False)]], line_spacing=1.15)


# ===========================================================================
# Slide 8 — ROI / estimated savings per assessment
# ===========================================================================
s = prs.slides.add_slide(BLANK)
_bg(s, WHITE)
_accentbar(s)
_kicker(s, Inches(0.8), Inches(0.45), "Return on investment")
_text(s, Inches(0.8), Inches(0.8), Inches(11.7), Inches(0.8),
      [[("What one assessment is worth", 32, NAVY, True, False)]])
_text(s, Inches(0.8), Inches(1.6), Inches(11.7), Inches(0.5),
      [[("Computed from the app's built-in Metrics benchmarks, on a single full-system ATO package.*", 16, SLATE, False, False)]])

roi = [
    ("$700 / control", 26, "manual A&A benchmark", "≈ $233 per CCI average"),
    ("~$180K", 38, "saved per assessment", "manual A&A labor the tool auto-resolves at that rate"),
    ("~2,080 hrs", 34, "assessor time saved", "≈ 52 assessor work-weeks off the A&A effort"),
    ("~80%", 38, "less hands-on effort", "clear cases auto-resolve; experts review the rest"),
]
rx = Inches(0.8)
rw = Inches(2.85)
rgap = Inches(0.13)
for i, (big, big_sz, mid, small) in enumerate(roi):
    x = rx + (rw + rgap) * i
    _grad_round(s, x, Inches(2.2), rw, Inches(2.45), NAVY, NAVY3, angle=60, radius=0.07)
    _grad_rect(s, x, Inches(2.2), rw, Inches(0.1), BLUE_BRIGHT, BLUE, angle=0)
    _text(s, x, Inches(2.5), rw, Inches(0.85),
          [[(big, big_sz, SKY, True, False)]], align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
    _text(s, x + Inches(0.2), Inches(3.35), rw - Inches(0.4), Inches(0.5),
          [[(mid, 14, WHITE, True, False)]], align=PP_ALIGN.CENTER)
    _text(s, x + Inches(0.25), Inches(3.85), rw - Inches(0.5), Inches(0.8),
          [[(small, 11.5, LIGHT, False, False)]], align=PP_ALIGN.CENTER, line_spacing=1.1)

# methodology / asterisk box
_round(s, Inches(0.8), Inches(4.95), Inches(11.73), Inches(1.75), SOFT, line=LINE, line_w=Pt(1), radius=0.06)
_grad_round(s, Inches(0.8), Inches(4.95), Inches(0.12), Inches(1.75), AMBER, RGBColor(0xF2, 0xB1, 0x55), angle=90, radius=0.5)
_text(s, Inches(1.1), Inches(5.08), Inches(11.2), Inches(1.62),
      [[("* Illustrative estimate, not a guarantee — uses the same benchmarks the app's Metrics tab ships with.", 12.5, NAVY, True, False)],
       [("Basis: a full-system FedRAMP Moderate ATO (~325 controls, ~975 CCIs). Manual A&A benchmark = $700/control "
         "(≈ $233/CCI at ~3 CCIs/control) and 8 hrs/control — the FedRAMP Mod 3PAO range ($150K–$300K, ", 11.5, INK, False, False),
         ("GAO-24-106591", 11.5, BLUE, False, False, "https://www.gao.gov/products/GAO-24-106591"),
         (") over ~325 controls, and the industry-standard 8 hr/control per ", 11.5, INK, False, False),
         ("NIST SP 800-53A", 11.5, BLUE, False, False, "https://csrc.nist.gov/pubs/sp/800/53/a/r5/final"),
         (". Deterministic auto-resolution + AI-assisted assessment remove ~80% of hands-on effort: ≈$180K and "
         "≈2,080 hrs of internal labor, against an outsourced 3PAO engagement of $150–300K it largely replaces.",
         11.5, INK, False, False)],
       [("Actual savings vary by system size, baseline, evidence quality, and team. Your numbers will differ — these are planning estimates only.",
         11.5, SLATE, False, True)]], line_spacing=1.1)


# ===========================================================================
# Slide 9 — Proof / close
# ===========================================================================
s = prs.slides.add_slide(BLANK)
_grad_bg(s, NAVY_DEEP, NAVY3, angle=60)
_grad_rect(s, 0, 0, W, Inches(0.14), BLUE_BRIGHT, BLUE, angle=0)
_rect(s, 0, H - Inches(0.1), W, Inches(0.1), BLUE)
_kicker(s, Inches(0.8), Inches(0.6), "The bottom line", SKY)
_text(s, Inches(0.8), Inches(0.95), Inches(11.7), Inches(0.9),
      [[("Built for the people who own the ATO", 32, WHITE, True, False)]])

stats = [
    ("7", "frameworks supported"),
    ("23", "evidence file formats read"),
    ("5-tier", "evidence-to-control engine"),
    ("U → TS", "every classification enclave"),
]
sx = Inches(0.8)
sw = Inches(2.85)
sgap = Inches(0.13)
for i, (big, small) in enumerate(stats):
    x = sx + (sw + sgap) * i
    _round(s, x, Inches(2.05), sw, Inches(1.5), NAVY2, line=BLUE, line_w=Pt(1), radius=0.07)
    _text(s, x, Inches(2.2), sw, Inches(0.8),
          [[(big, 38, SKY, True, False)]], align=PP_ALIGN.CENTER)
    _text(s, x, Inches(3.0), sw, Inches(0.5),
          [[(small, 12.5, LIGHT, False, False)]], align=PP_ALIGN.CENTER)

_grad_round(s, Inches(0.8), Inches(4.0), Inches(11.73), Inches(1.5), NAVY2, NAVY, angle=60, line=BLUE, line_w=Pt(1.25), radius=0.06)
_grad_rect(s, Inches(0.8), Inches(4.0), Inches(0.16), Inches(1.5), BLUE_BRIGHT, BLUE, angle=90)
_text(s, Inches(1.2), Inches(4.22), Inches(11.0), Inches(1.1),
      [[("Cybersecurity Assessor compresses the slowest, most error-prone phase of authorization into a fast, "
         "repeatable, auditable workflow — without ever sending your data off the workstation.",
         15, WHITE, False, False)]], line_spacing=1.18)

_text(s, Inches(0.8), Inches(5.8), Inches(11.7), Inches(0.6),
      [[("Self-contained Windows installer  ·  No separate runtime  ·  Bring your own AI key", 14, SKY, True, False)]])
_text(s, Inches(0.8), Inches(6.45), Inches(11.7), Inches(0.5),
      [[("Cybersecurity Assessor — assess with confidence, defend with evidence.  ·  Nuon", 13, MIST, False, True)]])


out = Path(__file__).resolve().parent / "Cybersecurity_Assessor_Overview.pptx"
prs.save(str(out))
print("WROTE", out, f"({out.stat().st_size // 1024} KB, {len(prs.slides.__iter__.__self__._sldIdLst)} slides)")
