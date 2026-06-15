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
]

# Pull the whole package (modules + data files + any C extensions).
pkg_datas, pkg_binaries, pkg_hiddenimports = collect_all("cybersecurity_assessor")
datas += pkg_datas
binaries += pkg_binaries
hiddenimports += pkg_hiddenimports
hiddenimports += collect_submodules("cybersecurity_assessor")

# Windows credential backend data + truststore platform tables.
datas += collect_data_files("keyring")
datas += collect_data_files("truststore")


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
