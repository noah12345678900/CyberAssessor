# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec for the ccis-assessor sidecar.
#
# OUTPUT LAYOUT — onedir (intentional, not onefile)
# --------------------------------------------------
# The Phase 2a spike (see project_ccis_assessor_installer_prereqs.md)
# measured onefile cold start at 19.7s and warm start at 15.6s, both
# blowing past the 15s Electron CCIS_PORT handshake budget in
# ui/electron/main.ts. Onefile extracts the entire bundled tree to
# %TEMP% on every launch — unavoidable cost ~15s for a ~117MB bundle on
# a corporate endpoint with AV file-scanning enabled. Onedir keeps the
# unpacked tree on disk next to the exe so launch ≈ normal Python start.
#
# ENTRY POINT — external wrapper
# --------------------------------------------------
# PyInstaller can only target a file path, not a `package.module` name —
# and when given a file inside a package (e.g. cybersecurity_assessor/
# __main__.py or cybersecurity_assessor/server.py) it strips the package
# context and the file's `from . import ...` lines fail at runtime with
# `ImportError: attempted relative import with no known parent package`.
# `cybersec_server_entry.py` lives at backend/ root, outside the package,
# so the analyzer pulls cybersecurity_assessor in as a proper package
# with all its relative imports intact.
#
# HIDDENIMPORTS
# --------------------------------------------------
# uvicorn re-imports the app by string at runtime
# (`uvicorn.Config("cybersecurity_assessor.server:app", ...)` in
# server.py::_serve_with_handshake), so the analyzer can't trace those
# modules from the entry script. We mix two strategies:
#   1. `collect_submodules('cybersecurity_assessor')` — catches every
#      package module, including routes/, evidence/, engine/, etc.
#      Robust against new modules added later.
#   2. Explicit list of high-risk re-imports below. Belt-and-braces for
#      the names uvicorn / SQLAlchemy / Alembic look up by string.
#
# DATAS
# --------------------------------------------------
# `collect_all('cybersecurity_assessor')` pulls every non-.py file inside
# the package — most importantly the alembic/versions/*.py migration
# files (loaded by importlib.resources in migrations.py) and any future
# bundled YAML/JSON. keyring and truststore each ship Windows backend
# data files that aren't reachable through normal imports.

from PyInstaller.utils.hooks import (
    collect_all,
    collect_data_files,
    collect_submodules,
)

datas = []
binaries = []
hiddenimports = [
    # uvicorn's runtime string-import target
    "cybersecurity_assessor.server",
    # SQLModel / SQLAlchemy dialect registry resolves these by string
    "sqlalchemy.dialects.sqlite",
    # Alembic env hook imports the package's metadata target
    "cybersecurity_assessor.migrations",
    # OCR: pytesseract + pypdfium2 are lazy-imported inside extractors/_ocr.py,
    # so the static analyzer can't trace them from the entry script. pypdfium2's
    # native pdfium.dll is normally pulled by the pyinstaller-hooks-contrib hook
    # (hook-pypdfium2_raw), but we name both modules explicitly so scan-PDF OCR
    # doesn't silently break if that contrib hook is ever absent/downgraded.
    "pytesseract",
    "pypdfium2",
    "pypdfium2_raw",
]

# Pull the whole package (modules + data files + any C extensions).
pkg_datas, pkg_binaries, pkg_hiddenimports = collect_all("cybersecurity_assessor")
datas += pkg_datas
binaries += pkg_binaries
hiddenimports += pkg_hiddenimports
hiddenimports += collect_submodules("cybersecurity_assessor")

# Pillow (image extractor) and defusedxml (diagram .vsdx/.svg extractor) are
# imported LAZILY inside their extractor functions, so PyInstaller's static
# analysis can't see them from the entry script. collect_all pulls PIL's C
# extensions + plugin modules (image format codecs resolved by string at
# runtime); defusedxml is pure-Python but also lazy-imported. Without these
# the frozen sidecar would raise ImportError the first time an image or
# diagram is ingested.
for _pkg in ("PIL", "defusedxml"):
    _d, _b, _h = collect_all(_pkg)
    datas += _d
    binaries += _b
    hiddenimports += _h

# Windows credential backend data + truststore platform tables.
datas += collect_data_files("keyring")
datas += collect_data_files("truststore")

# Bundled Tesseract OCR (vendor/tesseract/) — tesseract.exe + its runtime DLLs
# + tessdata/eng.traineddata. Shipped so image-of-text evidence (MFA / GPO /
# lockout screenshots) and scan-only PDFs OCR OFFLINE on a fresh install with
# zero user setup — no admin MSI, no PATH edits. extractors/_ocr.py resolves
# this to ``<exe>/_internal/tesseract/`` via sys._MEIPASS at runtime. We add
# the whole tree as data (NOT collect_dynamic_libs) because tesseract.exe
# shells out as a subprocess — PyInstaller must not try to treat its DLLs as
# Python C-extensions; they just need to sit next to the exe. ~164MB (the
# libtesseract-5 + ICU core is irreducible; DLLs are transitively coupled and
# trimming breaks recognition — verified empirically).
import os as _os

_TESS_DIR = _os.path.join(SPECPATH, "vendor", "tesseract")
if _os.path.isdir(_TESS_DIR):
    for _root, _dirs, _files in _os.walk(_TESS_DIR):
        for _f in _files:
            _abs = _os.path.join(_root, _f)
            _rel = _os.path.relpath(_root, _TESS_DIR)
            # Destination under the bundle: tesseract/  or  tesseract/tessdata/.
            # Force FORWARD slashes — PyInstaller's data dest is a POSIX-style
            # relative path; a Windows backslash here is version-dependent and
            # can flatten tessdata/eng.traineddata into a single file literally
            # named "tessdata\eng.traineddata", which breaks TESSDATA_PREFIX
            # lookup at runtime. Normalizing is harmless where it already worked.
            if _rel == ".":
                _dest = "tesseract"
            else:
                _dest = "tesseract/" + _rel.replace(_os.sep, "/")
            datas.append((_abs, _dest))
else:  # pragma: no cover - build-time guard
    raise SystemExit(
        f"Bundled Tesseract not found at {_TESS_DIR} — OCR would be unavailable "
        f"in the frozen build. Vendor it before packaging (see _ocr.py)."
    )


a = Analysis(
    ["cybersec_server_entry.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,  # ONEDIR: binaries go into COLLECT, not the exe
    name="cybersec-server",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    # UPX disabled — corporate AV / EDR routinely false-positives on
    # UPX-packed binaries (high entropy, no signed publisher).
    # The onedir layout already keeps the exe small (~5MB stub); UPX
    # would shave a few hundred KB at the cost of an EDR quarantine
    # incident waiting to happen.
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="cybersec-server",
)
