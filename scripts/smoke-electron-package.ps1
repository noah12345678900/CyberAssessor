[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExePath,
    [int]$TimeoutSeconds = 90
)

$ErrorActionPreference = 'Stop'
$exe = (Resolve-Path -LiteralPath $ExePath).Path
$releaseDir = Split-Path -Parent (Split-Path -Parent $exe)
$stdoutPath = Join-Path $releaseDir 'electron-smoke-v218-final.stdout.log'
$stderrPath = Join-Path $releaseDir 'electron-smoke-v218-final.stderr.log'

function Read-SharedText([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return ''
    }
    $stream = New-Object System.IO.FileStream(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite
    )
    try {
        $reader = New-Object System.IO.StreamReader($stream)
        try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally {
        $stream.Dispose()
    }
}

$proc = Start-Process -FilePath $exe -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath

try {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 500
        $stdout = Read-SharedText $stdoutPath
        $sidecarReady = $stdout.Contains('[main] sidecar ready at http://127.0.0.1:')
        $rendererReady = $stdout.Contains('[main] renderer ready')
    } while ((-not ($sidecarReady -and $rendererReady)) -and [DateTime]::UtcNow -lt $deadline)

    if (-not ($sidecarReady -and $rendererReady)) {
        $stderr = Read-SharedText $stderrPath
        throw "Packaged Electron smoke failed.`nSTDOUT:`n$stdout`nSTDERR:`n$stderr"
    }

    $match = [regex]::Match($stdout, 'sidecar ready at (http://127\.0\.0\.1:\d+)')
    if (-not $match.Success) {
        throw 'Packaged Electron smoke could not parse the sidecar URL.'
    }
    $health = Invoke-RestMethod -Uri ($match.Groups[1].Value + '/healthz') -TimeoutSec 10
    if ($health.status -ne 'ok' -or $health.version -ne '2.1.8') {
        throw "Unexpected packaged health response: $($health | ConvertTo-Json -Compress)"
    }

    Write-Output "sidecar_ready=true"
    Write-Output "renderer_ready=true"
    Write-Output "health_version=$($health.version)"
} finally {
    if (-not $proc.HasExited) {
        & taskkill.exe /PID $proc.Id /T /F | Out-Null
    }
}
