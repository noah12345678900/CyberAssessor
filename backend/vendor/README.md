# Vendored binaries

This directory holds large third-party binaries that the installer bundles but
that are **not committed to git** (see `.gitignore`). Re-acquire them on a fresh
checkout before building the sidecar.

## tesseract/ — Tesseract OCR (Apache-2.0)

Bundled so image-of-text evidence (MFA / GPO / lockout screenshots) and
scan-only PDFs OCR **offline on a fresh install** — no admin MSI, no PATH edit.
The sidecar resolves it at runtime via `extractors/_ocr.py`
(`<exe>/_internal/tesseract/` when frozen).

**Source:** UB-Mannheim Windows build, v5.4.0.20240606
<https://github.com/UB-Mannheim/tesseract/releases>

### Re-vendor steps

1. Download `tesseract-ocr-w64-setup-5.4.0.20240606.exe` from the release above.
2. Install it (per-user is fine — no admin needed). Default location:
   `%LOCALAPPDATA%\Programs\Tesseract-OCR`. When the installer asks, **English
   only** — uncheck "Additional language data" / "Additional script data".
3. Copy the runtime pieces into `backend/vendor/tesseract/`:
   - `tesseract.exe`
   - every `*.dll` from the install root (they are transitively coupled —
     copy them all; trimming breaks recognition)
   - `tessdata/eng.traineddata`
   (Skip the dozens of `*.exe` training/dev tools and `osd.traineddata` — not
   needed for the recognition path.)
4. Verify: `tesseract.exe <some-png> stdout` prints recognized text.

Expected footprint: ~164MB (the `libtesseract-5` + ICU core is irreducible).

The PyInstaller spec (`backend/cybersec-server.spec`) raises a build-time error
if this tree is missing, so a packaging run can't silently ship without OCR.
