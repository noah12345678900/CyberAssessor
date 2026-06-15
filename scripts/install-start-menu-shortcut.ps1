# Installs (or refreshes) a Start Menu shortcut that launches the
# Cybersecurity Assessor via scripts/start.ps1. Idempotent — re-run to
# update the target/icon after moving the repo.

$ErrorActionPreference = 'Stop'

$repo         = Split-Path -Parent $PSScriptRoot
$script       = Join-Path $repo 'scripts\start.ps1'
$icon         = Join-Path $repo 'ui\public\logo.ico'
$shortcutPath = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Cybersecurity Assessor.lnk'

if (-not (Test-Path $script)) {
    throw "Launcher missing: $script"
}

$wsh = New-Object -ComObject WScript.Shell
$sc = $wsh.CreateShortcut($shortcutPath)
$sc.TargetPath       = 'powershell.exe'
$sc.Arguments        = "-NoProfile -ExecutionPolicy Bypass -File `"$script`""
$sc.WorkingDirectory = $repo
if (Test-Path $icon) { $sc.IconLocation = $icon }
$sc.Description      = 'Launch the Cybersecurity Assessor (Electron UI + Python sidecar)'
$sc.WindowStyle      = 1  # Normal window
$sc.Save()

Write-Host "Created Start Menu shortcut:" -ForegroundColor Green
Write-Host "  Path     : $shortcutPath"
Write-Host "  Target   : $($sc.TargetPath) $($sc.Arguments)"
Write-Host "  WorkDir  : $($sc.WorkingDirectory)"
Write-Host "  Icon     : $($sc.IconLocation)"
Write-Host ""
Write-Host "Press the Windows key and type 'Cybersecurity Assessor' to launch." -ForegroundColor Cyan
