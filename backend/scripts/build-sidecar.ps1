# Build + smoke-test the ccis-assessor sidecar binary.
#
# Used by the v2.0 installer pipeline and by hand before tagging a
# release. Produces a self-contained onedir bundle at
#   backend/dist/cybersec-server/
# with cybersec-server.exe at the root and all support files (DLLs,
# Python stdlib, alembic migrations, package data) under _internal/.
# Total ~245MB unpacked, ~35MB exe.
#
# Onedir (not onefile) because the Phase 2a feasibility spike measured
# onefile cold start at 19.7s — blowing past the 15s Electron handshake
# budget in ui/electron/main.ts. See cybersec-server.spec for the
# rationale and tests/test_packaged_sidecar.py for the regression gate.
#
# Usage (from repo root or backend/):
#   pwsh ./backend/scripts/build-sidecar.ps1
#   pwsh ./backend/scripts/build-sidecar.ps1 -SkipSmoke    # build only
#   pwsh ./backend/scripts/build-sidecar.ps1 -Clean        # rm dist+build first
#
# Requires: uv installed and the `packaging` extra synced into the
# backend/.venv. The script will attempt the sync itself if PyInstaller
# isn't present, but a real CI worker should pre-sync to avoid Nexus
# SSL surprises (the corporate Nexus mirror needs --native-tls).

[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$SkipSmoke
)

$ErrorActionPreference = "Stop"

# Resolve backend/ regardless of CWD so the script works from anywhere.
$BackendDir = Resolve-Path (Join-Path $PSScriptRoot "..")
$SpecPath   = Join-Path $BackendDir "cybersec-server.spec"
$DistDir    = Join-Path $BackendDir "dist\cybersec-server"
$ExePath    = Join-Path $DistDir "cybersec-server.exe"
$SmokeScript = Join-Path $PSScriptRoot "smoke_test_sidecar.py"

Push-Location $BackendDir
try {
    if ($Clean) {
        Write-Host "==> Cleaning dist/ and build/" -ForegroundColor Cyan
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path $BackendDir "dist")
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path $BackendDir "build")
    }

    # Sanity-check PyInstaller is reachable in the synced venv. A friendlier
    # error than the cryptic "command not found" PyInstaller gives.
    Write-Host "==> Checking PyInstaller availability" -ForegroundColor Cyan
    $check = uv run --no-sync python -c "import PyInstaller; print(PyInstaller.__version__)" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Error "PyInstaller not found. Run: uv sync --native-tls --extra packaging --extra sources --extra excel"
        exit 1
    }
    Write-Host "    PyInstaller $check" -ForegroundColor DarkGray

    Write-Host "==> Building sidecar (onedir) from $($SpecPath | Split-Path -Leaf)" -ForegroundColor Cyan
    uv run --no-sync pyinstaller --noconfirm --clean $SpecPath
    if ($LASTEXITCODE -ne 0) {
        Write-Error "PyInstaller build failed (exit $LASTEXITCODE)"
        exit $LASTEXITCODE
    }

    if (-not (Test-Path $ExePath)) {
        Write-Error "Build claimed success but $ExePath was not produced"
        exit 1
    }

    $sizeMB = [math]::Round((Get-Item $ExePath).Length / 1MB, 1)
    $distSize = [math]::Round(((Get-ChildItem -Recurse $DistDir | Measure-Object -Property Length -Sum).Sum) / 1MB, 1)
    Write-Host "    exe:    $sizeMB MB" -ForegroundColor DarkGray
    Write-Host "    bundle: $distSize MB ($DistDir)" -ForegroundColor DarkGray

    if ($SkipSmoke) {
        Write-Host "==> Skipping smoke test (-SkipSmoke)" -ForegroundColor Yellow
        exit 0
    }

    Write-Host "==> Smoke-testing bundled sidecar" -ForegroundColor Cyan
    # Use plain `python` rather than `uv run` so the smoke test sees the
    # bundled exe with a clean environment — closer to how Electron will
    # actually launch it. The smoke script is stdlib-only by design.
    python $SmokeScript $ExePath
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Smoke test failed (exit $LASTEXITCODE)"
        exit $LASTEXITCODE
    }

    Write-Host "==> Build complete: $ExePath" -ForegroundColor Green
} finally {
    Pop-Location
}
