<#
.SYNOPSIS
    Local multi-node veil devnet manager (Windows / PowerShell).

.DESCRIPTION
    PowerShell counterpart of `scripts/devnet.sh`.  Generates N node
    configs under `$env:DEVNET_DIR` (default `$env:LOCALAPPDATA\veil-devnet`),
    starts each node via `veil-cli node run --foreground` in a background
    job, and provides start/stop/status/smoke helpers.

    Each node binds:
      - admin: TCP-loopback (Epic 451.7) — `admin.port` + `admin.token` written
        next to the config file (Epic 451.6c default).
      - peers: `tcp://127.0.0.1:920{N}`.
      - ipc: TCP-loopback (Epic 451.6b) — `ipc.port` + `ipc.token` next to config.

.PARAMETER Command
    start | stop | status | logs | smoke

.PARAMETER Nodes
    Number of nodes to spin up (default 3).

.PARAMETER Node
    Node index for `logs` (default 0).

.EXAMPLE
    pwsh .\scripts\devnet.ps1 start -Nodes 5
    pwsh .\scripts\devnet.ps1 status
    pwsh .\scripts\devnet.ps1 smoke
    pwsh .\scripts\devnet.ps1 logs 0
    pwsh .\scripts\devnet.ps1 stop
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('start', 'stop', 'status', 'logs', 'smoke', 'help')]
    [string]$Command = 'help',

    [int]$Nodes = 3,

    [int]$Node = 0
)

$ErrorActionPreference = 'Stop'

# ── Configuration ───────────────────────────────────────────────────────────

$ScriptDir   = Split-Path -Parent $PSCommandPath
$RepoRoot    = Split-Path -Parent $ScriptDir
$DevnetDir   = if ($env:DEVNET_DIR) { $env:DEVNET_DIR } else { Join-Path $env:LOCALAPPDATA 'veil-devnet' }
$BasePeerPort = 9200    # node-0 → 9200, node-1 → 9201, ...
$Binary      = Join-Path $RepoRoot 'target\release\veil-cli.exe'
$BinaryDebug = Join-Path $RepoRoot 'target\debug\veil-cli.exe'

# ── Helpers ─────────────────────────────────────────────────────────────────

function Write-Info($msg) { Write-Host "[devnet] $msg" }

function Get-NodeDir($n)    { Join-Path $DevnetDir "node-$n" }
function Get-ConfigFile($n) { Join-Path (Get-NodeDir $n) 'config.toml' }
function Get-PidFile($n)    { Join-Path (Get-NodeDir $n) 'veil.pid' }
function Get-LogFile($n)    { Join-Path (Get-NodeDir $n) 'veil.log' }

function Resolve-Binary {
    if (Test-Path $Binary)      { return $Binary }
    if (Test-Path $BinaryDebug) { return $BinaryDebug }
    Write-Info 'veil-cli not found — building (release)...'
    Push-Location $RepoRoot
    try {
        & cargo build --release --features allow-empty-seeds -p veilcore --bin veil-cli
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    } finally {
        Pop-Location
    }
    if (-not (Test-Path $Binary)) { throw "Build succeeded but binary not found at $Binary" }
    return $Binary
}

function Test-NodeRunning($n) {
    $pidFile = Get-PidFile $n
    if (-not (Test-Path $pidFile)) { return $false }
    $procId = [int](Get-Content $pidFile -Raw).Trim()
    try {
        $null = Get-Process -Id $procId -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# ── generate_config ─────────────────────────────────────────────────────────

function New-NodeConfig($n, $bin) {
    $dir = Get-NodeDir $n
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $config = Get-ConfigFile $n
    $peerPort = $BasePeerPort + $n

    # Generate fresh identity + nonce + default admin_socket (TCP on Windows
    # since 451.14, see handlers.rs::default_admin_socket_uri).  `config init`
    # takes the target path as a positional argument, NOT --config.
    & $bin config init $config --force
    if ($LASTEXITCODE -ne 0) { throw "config init failed for node-$n" }

    # Enable IPC TCP backend (Epic 451.6b).  Subsequent commands use the
    # --config global flag to target the freshly written file.
    & $bin --config $config config set ipc.enabled true
    & $bin --config $config config set ipc.socket_uri "tcp://127.0.0.1:0"

    # Add a TCP listener on this node's dedicated peer port.
    & $bin --config $config listen add "tcp://127.0.0.1:$peerPort"
    if ($LASTEXITCODE -ne 0) { throw "listen add failed for node-$n" }

    Write-Info "Generated config for node-$n (peer listen tcp://127.0.0.1:$peerPort)"
}

# ── start ───────────────────────────────────────────────────────────────────

function Invoke-Start {
    $bin = Resolve-Binary
    if (-not (Test-Path $DevnetDir)) { New-Item -ItemType Directory -Force -Path $DevnetDir | Out-Null }

    for ($n = 0; $n -lt $Nodes; $n++) {
        New-NodeConfig $n $bin
    }

    for ($n = 0; $n -lt $Nodes; $n++) {
        if (Test-NodeRunning $n) {
            $existing = (Get-Content (Get-PidFile $n) -Raw).Trim()
            Write-Info "node-$n already running (pid $existing)"
            continue
        }
        $cfg = Get-ConfigFile $n
        $log = Get-LogFile $n
        # Start-Process gives us a real process handle for PID tracking.
        # `WindowStyle Hidden` keeps the desktop tidy; the process still logs to $log.
        $proc = Start-Process -FilePath $bin `
            -ArgumentList @('--config', $cfg, 'node', 'run', '--foreground') `
            -RedirectStandardOutput $log `
            -RedirectStandardError "$log.err" `
            -WindowStyle Hidden `
            -PassThru
        $proc.Id | Out-File -FilePath (Get-PidFile $n) -Encoding ascii
        Write-Info "Started node-$n (pid $($proc.Id))"
    }

    Write-Info "Devnet started ($Nodes nodes).  Run 'devnet.ps1 status' to check."
}

# ── stop ────────────────────────────────────────────────────────────────────

function Invoke-Stop {
    if (-not (Test-Path $DevnetDir)) {
        Write-Info "No devnet directory found at $DevnetDir"
        return
    }
    $stopped = 0
    Get-ChildItem -Path $DevnetDir -Filter 'veil.pid' -Recurse | ForEach-Object {
        $procId = [int](Get-Content $_.FullName -Raw).Trim()
        try {
            Stop-Process -Id $procId -Force -ErrorAction Stop
            Write-Info "Stopped pid $procId"
            $stopped++
        } catch {
            # process already gone — fine
        }
        Remove-Item -Force $_.FullName
    }
    if ($stopped -gt 0) {
        Write-Info "Stopped $stopped node(s)."
    } else {
        Write-Info "No running nodes found."
    }
}

# ── status ──────────────────────────────────────────────────────────────────

function Invoke-Status {
    if (-not (Test-Path $DevnetDir)) {
        Write-Info 'No devnet directory found.'; return
    }
    $running = 0
    Get-ChildItem -Path $DevnetDir -Filter 'veil.pid' -Recurse | ForEach-Object {
        $node = (Split-Path -Leaf $_.Directory.FullName)
        $procId = [int](Get-Content $_.FullName -Raw).Trim()
        try {
            $null = Get-Process -Id $procId -ErrorAction Stop
            Write-Info "${node}: running (pid $procId)"
            $running++
        } catch {
            Write-Info "${node}: STOPPED (stale pid $procId)"
        }
    }
    if ($running -eq 0) { Write-Info 'No nodes running.' }
}

# ── logs ────────────────────────────────────────────────────────────────────

function Invoke-Logs {
    $log = Get-LogFile $Node
    if (-not (Test-Path $log)) { throw "No log file for node-$Node at $log" }
    Get-Content $log -Wait -Tail 50
}

# ── smoke ───────────────────────────────────────────────────────────────────

function Invoke-Smoke {
    Write-Info 'Running smoke test...'
    if (-not (Test-NodeRunning 0)) {
        throw "node-0 is not running.  Start the devnet first: devnet.ps1 start"
    }
    $bin = Resolve-Binary

    # Wait up to 30s for node-0's admin sidecars to appear (admin.port + admin.token
    # next to the config file — Epic 451.6c default).
    $configDir = Get-NodeDir 0
    $portFile  = Join-Path $configDir 'admin.port'
    $tokenFile = Join-Path $configDir 'admin.token'
    $waited = 0
    while (-not ((Test-Path $portFile) -and (Test-Path $tokenFile)) -and $waited -lt 30) {
        Start-Sleep -Seconds 1
        $waited++
    }
    if (-not (Test-Path $portFile)) { throw "admin.port not found after ${waited}s at $portFile" }

    $result = & $bin --config (Get-ConfigFile 0) node show 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Admin query failed: $result" }
    Write-Info 'node-0 responded to admin query.'

    # Probe every node with retries.
    $ok = 0; $fail = 0
    Get-ChildItem -Path $DevnetDir -Filter 'veil.pid' -Recurse | ForEach-Object {
        $node = (Split-Path -Leaf $_.Directory.FullName)
        $n = [int]($node -replace 'node-', '')
        $reachable = $false
        for ($attempt = 0; $attempt -lt 30; $attempt++) {
            $null = & $bin --config (Get-ConfigFile $n) node show 2>&1
            if ($LASTEXITCODE -eq 0) { $reachable = $true; break }
            Start-Sleep -Seconds 1
        }
        if ($reachable) {
            Write-Info "  ${node}: OK"
            $ok++
        } else {
            Write-Info "  ${node}: FAIL"
            $fail++
        }
    }

    if ($fail -eq 0) {
        Write-Info "Smoke test PASSED ($ok nodes healthy)."
    } else {
        throw "Smoke test FAILED: $fail node(s) unreachable."
    }
}

# ── dispatch ────────────────────────────────────────────────────────────────

switch ($Command) {
    'start'  { Invoke-Start }
    'stop'   { Invoke-Stop }
    'status' { Invoke-Status }
    'logs'   { Invoke-Logs }
    'smoke'  { Invoke-Smoke }
    default {
        Get-Help $PSCommandPath -Detailed
    }
}
