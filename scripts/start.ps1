# Cybersecurity Assessor - dev-mode launcher.
#
# Starts Vite (the renderer dev server) in a minimized window, waits for
# port 5173 to respond, then runs Electron in the foreground. Electron's
# main process spawns the Python sidecar itself, so we only manage two
# processes here: Vite + Electron.
#
# When Electron exits, we kill the Vite process tree so nothing is left
# hanging. The console window auto-closes a few seconds after Electron
# quits so users don't have to dismiss it.

$ErrorActionPreference = 'Stop'

$Repo = Split-Path -Parent $PSScriptRoot
$UiDir = Join-Path $Repo 'ui'

Write-Host "Cybersecurity Assessor launcher" -ForegroundColor Cyan
Write-Host "Repo: $Repo"

# Ensure npm global shims (pnpm.cmd) are on PATH. The npm-global dir is not on
# the user's persistent PATH on this workstation, so a fresh shell (e.g. the
# Start Menu shortcut) can't find pnpm. Prepend it for this session only.
$NpmGlobalDir = Join-Path $env:APPDATA 'npm'
if (Test-Path $NpmGlobalDir) {
    $env:Path = "$NpmGlobalDir;$env:Path"
}

# --- 1. Start Vite in a minimized cmd window ----------------------------------
# Using cmd.exe wrapper so pnpm.cmd resolves cleanly on PATH. /k keeps the
# window open if vite crashes so the user can see the error; Stop-Process
# at the end still kills it.
$viteWindowTitle = "Cybersecurity Assessor :: Vite (close to stop dev server)"
Write-Host "Starting Vite dev server (minimized)..." -ForegroundColor Yellow
$vite = Start-Process -FilePath 'cmd.exe' `
    -ArgumentList '/k', "title $viteWindowTitle && pnpm --filter ui dev" `
    -WorkingDirectory $Repo `
    -WindowStyle Minimized `
    -PassThru

# --- 2. Wait for Vite to come up ---------------------------------------------
Write-Host "Waiting for Vite on http://127.0.0.1:5173 ..." -ForegroundColor Yellow
$deadline = (Get-Date).AddSeconds(60)
$ready = $false
while ((Get-Date) -lt $deadline) {
    try {
        $r = Invoke-WebRequest -Uri 'http://127.0.0.1:5173/' -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch {
        # not up yet; keep polling
    }
    Start-Sleep -Milliseconds 500
}

if (-not $ready) {
    Write-Host "Vite did not respond within 60s - check the Vite window for errors." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "Vite ready." -ForegroundColor Green

# --- 3. Launch Electron in the foreground ------------------------------------
Write-Host "Launching Electron..." -ForegroundColor Yellow
Push-Location $UiDir
try {
    & cmd.exe /c 'pnpm dev:electron'
} finally {
    Pop-Location
}

# --- 4. Clean up Vite + its node children ------------------------------------
Write-Host "Electron closed - stopping Vite..." -ForegroundColor Yellow
function Stop-ProcessTree([int]$ParentPid) {
    try {
        Get-CimInstance Win32_Process -Filter "ParentProcessId=$ParentPid" -ErrorAction SilentlyContinue |
            ForEach-Object { Stop-ProcessTree $_.ProcessId }
        Stop-Process -Id $ParentPid -Force -ErrorAction SilentlyContinue
    } catch {}
}

if ($vite -and -not $vite.HasExited) {
    Stop-ProcessTree $vite.Id
}

Write-Host "Done. Closing in 3s..." -ForegroundColor Green
Start-Sleep -Seconds 3
