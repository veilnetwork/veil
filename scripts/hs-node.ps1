<#
.SYNOPSIS
    Run an veil node with persistent log file for hot-standby testing.

.DESCRIPTION
    Thin wrapper around `veil-cli node run --foreground` that redirects
    stderr to a known log file under the config directory.  Non-elevated.
    The log file is what scripts/hs-driver.ps1 inspects during scenarios.

    Leave this running in one PowerShell window; run hs-driver.ps1 from
    another.  Ctrl-C stops the node cleanly.

.PARAMETER ConfigPath
    Path to the node's config.toml.  Log is written next to it as
    `veil.log`.

.PARAMETER Binary
    Override the veil-cli binary path.  Defaults to the release build
    under the repo root.

.EXAMPLE
    pwsh .\scripts\hs-node.ps1 -ConfigPath .\win\config.toml
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [string]$Binary = ''
)

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $PSCommandPath
$RepoRoot  = Split-Path -Parent $ScriptDir

if (-not $Binary) {
    $releaseBin = Join-Path $RepoRoot 'target\release\veil-cli.exe'
    $debugBin   = Join-Path $RepoRoot 'target\debug\veil-cli.exe'
    if      (Test-Path $releaseBin) { $Binary = $releaseBin }
    elseif  (Test-Path $debugBin)   { $Binary = $debugBin }
    else    { throw "veil-cli.exe not found. Build with: cargo build --release -p veilcore --bin veil-cli" }
}

if (-not (Test-Path $ConfigPath)) {
    throw "config file not found: $ConfigPath"
}
$ConfigPath = (Resolve-Path $ConfigPath).Path
$ConfigDir  = Split-Path -Parent $ConfigPath
$LogFile    = Join-Path $ConfigDir 'veil.log'

$LogErr = "$LogFile.err"
Write-Host "[hs-node] binary:  $Binary"
Write-Host "[hs-node] config:  $ConfigPath"
Write-Host "[hs-node] logfile: $LogFile   (stdout)"
Write-Host "[hs-node] errfile: $LogErr    (stderr -- where veil writes its log)"
Write-Host "[hs-node] Ctrl-C to stop."
Write-Host ''

# Use Start-Process with file-redirected stdout/stderr instead of the
# `& $Binary 2>&1 | Tee-Object` pattern.  Windows PowerShell 5.1 routes
# native-command stderr through its ErrorRecord pipeline, which formats
# every stderr line as "veil-cli.exe : [...] NativeCommandError" in
# the console -- cosmetic but jarring.  Start-Process writes stderr
# verbatim to a file, bypassing that machinery entirely.  veil-cli's
# default `logs = "stderr"` setting means the INFO/WARN lines land in
# `.err`; we tail that file to the console so the operator still sees
# live output.
#
# Cleanup: when the tail loop exits (Ctrl-C on Get-Content), we stop the
# veil-cli process.  The `trap` below fires on script termination.

$proc = Start-Process -FilePath $Binary `
    -ArgumentList @('--config', $ConfigPath, 'node', 'run', '--foreground') `
    -RedirectStandardOutput $LogFile `
    -RedirectStandardError  $LogErr `
    -NoNewWindow -PassThru

trap {
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
}

# Poll until both log files exist, then tail the stderr stream.  veil
# creates both files within milliseconds of startup.
$waited = 0
while (-not (Test-Path $LogErr) -and $waited -lt 50) {
    Start-Sleep -Milliseconds 100
    $waited++
}
try {
    Get-Content -Path $LogErr -Wait -Tail 0
} finally {
    if (-not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
}
