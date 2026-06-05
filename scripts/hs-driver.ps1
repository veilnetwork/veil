<#
.SYNOPSIS
    Drive Epic 459 hot-standby scenarios against an already-running
    two-node Windows fixture.

.DESCRIPTION
    Run hs-node.ps1 in a separate window on BOTH hosts first, wait for
    the session to establish, then run this script from the "initiator"
    host.  The initiator drives the scenarios; the peer just logs events
    which you inspect manually (or copy back via file share).

    Scenarios covered:
      - scenario1  (manual swap via `node swap-transport`)     -- no admin
      - scenario2  (firewall block -> auto-trigger)             -- ADMIN
      - scenario3  (flap damping, 2-min toggle loop)           -- ADMIN
      - scenario4  (admin-surface forgery resistance)          -- no admin
      - all        (run 1 + 4, skip 2/3 unless elevated)
      - report     (print a summary of observed log events)

    Each scenario records "before" / "after" counters for these log
    keys on the local node:
      session.transport_swapped
      session.hot_standby.trigger_raised
      session.hot_standby.auto_swap_trigger
      session.hot_standby.flap_damped
      session.hot_standby.alt_uri_auto_discovered
      handshake.success
      session.close

    Results are appended to `<config-dir>\hs-report.txt` and also
    printed to console.

.PARAMETER Scenario
    scenario1 | scenario2 | scenario3 | scenario4 | all | report

.PARAMETER ConfigPath
    Path to this host's config.toml.  The log file is expected to live
    next to it as `veil.log` (this is what hs-node.ps1 writes).

.PARAMETER PeerIp
    IP address of the remote veil node (e.g. 192.168.1.46).

.PARAMETER PeerNodeId
    64-hex node_id of the remote peer.  Read with:
        veil-cli --config <remote-config> node show | Select-String node_id

.PARAMETER PeerPrimaryPort
    Remote primary listener port.  Default 9310.

.PARAMETER PeerAltPort
    Remote alternate listener port.  Default 9311.  Used as --alt-uri
    in scenario1 and as the port blocked by the firewall in scenario2.

.PARAMETER Binary
    Override veil-cli path.  Defaults to the repo's release build.

.EXAMPLE
    # On laptop (initiator), station is 192.168.1.46:
    pwsh .\scripts\hs-driver.ps1 -Scenario all `
        -ConfigPath .\win\config.toml `
        -PeerIp 192.168.1.46 `
        -PeerNodeId 3f7c00bf9cd6196bee2380c13dd2f95249021fa222c58393c7fd389def2780d6

.NOTES
    Scenarios 2 and 3 rely on the rx_stall trigger (c.2) firing after
    `session.idle_timeout_secs * 2/3` seconds of quiet on the session.
    With the default idle_timeout_secs = 90, that's a 60-second wait
    before rx_stall raises, plus a few seconds for warm-probe dial.
    To speed up live testing, you can override the timeout on BOTH
    hosts by adding this to config.toml before starting hs-node.ps1:

        [session]
        idle_timeout_secs = 20

    With that, rx_stall fires at ~13s and the whole scenario-flap run
    drops from ~9 minutes to ~2 minutes.  Revert the override for
    production.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('scenario1', 'scenario2', 'scenario3', 'scenario4',
                 'all', 'report')]
    [string]$Scenario,

    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [Parameter(Mandatory = $true)]
    [string]$PeerIp,

    [Parameter(Mandatory = $true)]
    [string]$PeerNodeId,

    [int]$PeerPrimaryPort = 9310,
    [int]$PeerAltPort     = 9311,

    [string]$Binary = ''
)

$ErrorActionPreference = 'Stop'

# Windows PowerShell 5.1 treats any stderr output from a native command as
# a terminating error under EAP=Stop.  veil-cli's `node show` / `sessions
# list` / `swap-transport` can emit diagnostics to stderr even on success.
# Wrap native calls in a helper that runs them with EAP=Continue so those
# messages become normal output instead of exceptions.
function Invoke-Cli {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$CliArgs)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $Binary @CliArgs 2>&1
        return ,$output   # force array return; caller decides how to slice
    } finally {
        $ErrorActionPreference = $prev
    }
}

# -- Setup -------------------------------------------------------------------

$ScriptDir = Split-Path -Parent $PSCommandPath
$RepoRoot  = Split-Path -Parent $ScriptDir

if (-not $Binary) {
    $releaseBin = Join-Path $RepoRoot 'target\release\veil-cli.exe'
    $debugBin   = Join-Path $RepoRoot 'target\debug\veil-cli.exe'
    if      (Test-Path $releaseBin) { $Binary = $releaseBin }
    elseif  (Test-Path $debugBin)   { $Binary = $debugBin }
    else    { throw "veil-cli.exe not found.  Build first." }
}

if (-not (Test-Path $ConfigPath)) { throw "config not found: $ConfigPath" }
$ConfigPath = (Resolve-Path $ConfigPath).Path
$ConfigDir  = Split-Path -Parent $ConfigPath
# veil-cli's `logs = "stderr"` default sends all log events to
# stderr, which hs-node.ps1 redirects to `veil.log.err`.  The plain
# `veil.log` file holds stdout only (almost always empty) -- we look
# at .err first, fall back to .log if .err is missing.
$LogFile    = Join-Path $ConfigDir 'veil.log.err'
if (-not (Test-Path $LogFile)) {
    $LogFile = Join-Path $ConfigDir 'veil.log'
}
$ReportFile = Join-Path $ConfigDir 'hs-report.txt'

$FwRuleName = 'veil-hs-driver'

# -- Helpers -----------------------------------------------------------------

function Write-Info  ($msg) { Write-Host "[hs-driver] $msg" -ForegroundColor Cyan }
function Write-Pass  ($msg) { Write-Host "  + $msg"         -ForegroundColor Green }
function Write-Fail  ($msg) { Write-Host "  - $msg"         -ForegroundColor Red }
function Write-Warn2 ($msg) { Write-Host "  ! $msg"         -ForegroundColor Yellow }

function Out-Report ($line) {
    $line | Tee-Object -FilePath $ReportFile -Append | Out-Null
}

function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Count-LogEvent ($pattern) {
    if (-not (Test-Path $LogFile)) { return 0 }
    return (Select-String -Path $LogFile -Pattern $pattern -AllMatches).Matches.Count
}

# Capture counters for a set of interesting events.
function Snapshot-Counters {
    return [pscustomobject]@{
        swapped        = Count-LogEvent 'session\.transport_swapped'
        trigger_raised = Count-LogEvent 'session\.hot_standby\.trigger_raised'
        auto_swap      = Count-LogEvent 'session\.hot_standby\.auto_swap_trigger'
        flap_damped    = Count-LogEvent 'session\.hot_standby\.flap_damped'
        alt_uri_auto   = Count-LogEvent 'session\.hot_standby\.alt_uri_auto_discovered'
        handshake_ok   = Count-LogEvent 'handshake\.success'
        session_close  = Count-LogEvent 'session\.close'
    }
}

function Emit-Delta ($tag, $before, $after) {
    $fields = 'swapped','trigger_raised','auto_swap','flap_damped',
              'alt_uri_auto','handshake_ok','session_close'
    Out-Report ""
    Out-Report "[$tag] event-count delta:"
    foreach ($f in $fields) {
        $delta = $after.$f - $before.$f
        $line  = "  {0,-20} {1,4} -> {2,4}   ({3:+#;-#;0})" -f $f, $before.$f, $after.$f, $delta
        Out-Report $line
        Write-Host $line
    }
}

function Get-SessionsList {
    $out = Invoke-Cli '--config' $ConfigPath 'sessions' 'list'
    return ($out | Out-String)
}

function Wait-For-Session ($timeoutSec = 60) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        $out = Invoke-Cli '--config' $ConfigPath 'node' 'show'
        $m   = $out | Select-String -Pattern '^sessions_active:\s*(\d+)'
        if ($m -and [int]$m.Matches.Groups[1].Value -ge 1) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Require-Elevation ($name) {
    if (-not (Test-IsElevated)) {
        Write-Warn2 "$name requires an elevated PowerShell (Run as Administrator).  Skipping."
        return $false
    }
    return $true
}

function Remove-FwRule {
    Get-NetFirewallRule -DisplayName $FwRuleName -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
}

function Set-FwRule ($port) {
    Remove-FwRule
    # Discover the actual remote address of the active TCP connection
    # to $port.  Relying on the operator-supplied $PeerIp can miss when
    # the config uses a hostname (e.g. "station.local") that resolves
    # to a DIFFERENT IPv4/IPv6 than what the operator typed -- firewall
    # rule then doesn't match the live socket.
    $conn = Get-NetTCPConnection -RemotePort $port -State Established `
        -ErrorAction SilentlyContinue | Select-Object -First 1
    $addrs = @()
    if ($conn) {
        $addrs += $conn.RemoteAddress
        Write-Info "  live TCP connection remote = $($conn.RemoteAddress)"
    }
    # Also add the operator-supplied $PeerIp (may differ from the live
    # connection's remote when both are reachable).
    if ($PeerIp -and ($addrs -notcontains $PeerIp)) {
        $addrs += $PeerIp
    }
    if (-not $addrs) {
        throw "no established TCP connection on port $port and no PeerIp -- firewall rule cannot target anything"
    }
    New-NetFirewallRule -DisplayName $FwRuleName `
        -Direction Outbound -Action Block `
        -Protocol TCP -RemotePort $port `
        -RemoteAddress $addrs -Profile Any | Out-Null
    Write-Info "  firewall rule blocking outbound to $($addrs -join ', ') :$port"
}

# -- Scenario 1 -- manual swap via admin command -----------------------------

function Invoke-Scenario1 {
    Write-Info 'Scenario 1 -- manual swap via node swap-transport'
    Out-Report "=== Scenario 1 (manual swap) @ $(Get-Date -Format s) ==="

    if (-not (Wait-For-Session 30)) {
        Write-Fail 'no active session -- start hs-node.ps1 on both hosts first'
        Out-Report 'ABORT: no active session'
        return
    }

    $before = Snapshot-Counters
    Out-Report 'sessions list BEFORE:'
    Out-Report (Get-SessionsList)

    $altUri = "tcp://${PeerIp}:${PeerAltPort}"
    Write-Info "invoking: node swap-transport --peer $($PeerNodeId.Substring(0,12))... --alt-uri $altUri"
    $cmdOut = Invoke-Cli '--config' $ConfigPath 'node' 'swap-transport' `
        '--peer' $PeerNodeId '--alt-uri' $altUri
    $rc = $LASTEXITCODE
    Out-Report "command exit=$rc output=$cmdOut"

    if ($rc -ne 0) {
        Write-Fail "swap-transport failed with exit=$rc -- $cmdOut"
        return
    }
    Write-Pass 'swap-transport returned successfully'

    Start-Sleep -Seconds 2
    $after = Snapshot-Counters
    Emit-Delta 'scenario1' $before $after

    Out-Report 'sessions list AFTER:'
    Out-Report (Get-SessionsList)

    if (($after.swapped - $before.swapped) -ge 1) {
        Write-Pass "session.transport_swapped delta = $($after.swapped - $before.swapped)"
    } else {
        Write-Fail 'session.transport_swapped did NOT fire'
    }
    if (($after.handshake_ok - $before.handshake_ok) -eq 0) {
        Write-Pass 'no new handshake.success -- session preserved'
    } else {
        Write-Fail "unexpected handshake.success delta = $($after.handshake_ok - $before.handshake_ok)"
    }
}

# -- Scenario 2 -- firewall block on alt-port triggers auto-swap -------------

function Invoke-Scenario2 {
    Write-Info 'Scenario 2 -- firewall block on primary port -> auto-trigger'
    if (-not (Require-Elevation 'scenario2')) { return }
    Out-Report "=== Scenario 2 (firewall block) @ $(Get-Date -Format s) ==="

    if (-not (Wait-For-Session 30)) {
        Write-Fail 'no active session -- start hs-node.ps1 on both hosts first'
        return
    }

    # Inspect sessions list to find which port is currently primary.
    $sessionsOut = Get-SessionsList
    Out-Report 'sessions list BEFORE:'
    Out-Report $sessionsOut
    $primaryPort = $PeerPrimaryPort
    if ($sessionsOut -match ":([0-9]+)\s") {
        $primaryPort = [int]$Matches[1]
    }
    Write-Info "observed primary port = $primaryPort; blocking outbound TCP to ${PeerIp}:$primaryPort"

    $before = Snapshot-Counters
    Set-FwRule $primaryPort
    try {
        # Default session.idle_timeout_secs = 90; c.2 rx_stall fires at
        # 2/3 of that (60s).  Write-error trigger needs ~3 writes to
        # fail in a row.  With an idle session (no chat traffic), the
        # rx_stall path is the only one that fires -- so we must wait
        # at least past the 60s threshold.  90s gives headroom for log
        # flush and warm-probe dial.
        Write-Info 'waiting up to 90s for hot-standby trigger / swap...'
        $deadline = (Get-Date).AddSeconds(90)
        $observed = $false
        while ((Get-Date) -lt $deadline) {
            $now = Snapshot-Counters
            if ($now.trigger_raised -gt $before.trigger_raised `
                -or $now.auto_swap -gt $before.auto_swap `
                -or $now.swapped -gt $before.swapped) {
                $observed = $true; break
            }
            Start-Sleep -Milliseconds 500
        }
    } finally {
        Remove-FwRule
        Write-Info 'firewall rule removed'
    }

    Start-Sleep -Seconds 2
    $after = Snapshot-Counters
    Emit-Delta 'scenario2' $before $after

    if ($observed) {
        Write-Pass 'hot_standby trigger or auto-swap observed within 30s'
    } else {
        Write-Fail 'no hot_standby event observed -- trigger did not fire'
    }
    Out-Report 'sessions list AFTER:'
    Out-Report (Get-SessionsList)
}

# -- Scenario 3 -- flap damping ----------------------------------------------

function Invoke-Scenario3 {
    Write-Info 'Scenario 3 -- flap damping under repeated firewall toggles'
    if (-not (Require-Elevation 'scenario3')) { return }
    Out-Report "=== Scenario 3 (flap damping) @ $(Get-Date -Format s) ==="

    if (-not (Wait-For-Session 30)) {
        Write-Fail 'no active session -- start hs-node.ps1 on both hosts first'
        return
    }

    $before = Snapshot-Counters
    $port   = $PeerPrimaryPort
    Remove-FwRule
    try {
        # Each block window must be long enough for the rx_stall
        # threshold (idle_timeout * 2/3 = 60s at defaults) plus warm-
        # probe RTT before we unblock.  75s block + 15s unblock x 6
        # cycles = 9 min total, saturates max_swaps_per_minute = 4
        # comfortably and exercises the flap_damped code path.
        for ($i = 0; $i -lt 6; $i++) {
            Write-Info ("toggle {0}/6 -- block 75s" -f ($i + 1))
            Set-FwRule $port
            Start-Sleep -Seconds 75
            Remove-FwRule
            Write-Info '         unblock 15s'
            Start-Sleep -Seconds 15
        }
    } finally { Remove-FwRule }

    $after = Snapshot-Counters
    Emit-Delta 'scenario3' $before $after

    $swaps = $after.swapped - $before.swapped
    if ($swaps -le 8) {
        Write-Pass "swap count $swaps is within 2x max_swaps_per_minute (8)"
    } else {
        Write-Fail "swap count $swaps exceeds 2x max_swaps_per_minute -- damping leaked"
    }
    if (($after.flap_damped - $before.flap_damped) -gt 0) {
        Write-Pass "flap_damped delta = $($after.flap_damped - $before.flap_damped)"
    } else {
        Write-Warn2 'no flap_damped events -- cadence may be too slow to saturate'
    }
}

# -- Scenario 4 -- forgery resistance (admin surface) -------------------------

function Invoke-Scenario4 {
    Write-Info 'Scenario 4 -- forgery resistance on admin surface'
    Out-Report "=== Scenario 4 (forgery) @ $(Get-Date -Format s) ==="

    if (-not (Wait-For-Session 30)) {
        Write-Fail 'no active session -- start hs-node.ps1 on both hosts first'
        return
    }

    $before = Snapshot-Counters

    $fakePeer = ('ff' * 32)
    Write-Info 'case (a): swap-transport against unknown peer_id'
    $out = Invoke-Cli '--config' $ConfigPath 'node' 'swap-transport' `
        '--peer' $fakePeer '--alt-uri' "tcp://${PeerIp}:${PeerAltPort}"
    $rcA = $LASTEXITCODE
    Out-Report "case (a) exit=$rcA output=$out"
    if ($rcA -ne 0) { Write-Pass "rejected unknown peer_id (exit=$rcA)" }
    else            { Write-Fail 'unknown peer_id was NOT rejected' }

    Write-Info 'case (b): swap-transport with malformed alt-uri'
    $out = Invoke-Cli '--config' $ConfigPath 'node' 'swap-transport' `
        '--peer' $PeerNodeId '--alt-uri' 'not-a-uri://garbage'
    $rcB = $LASTEXITCODE
    Out-Report "case (b) exit=$rcB output=$out"
    if ($rcB -ne 0) { Write-Pass "rejected malformed URI (exit=$rcB)" }
    else            { Write-Fail 'malformed URI was NOT rejected' }

    Write-Info 'case (c): session still alive after rejections'
    $sessionsOut = Get-SessionsList
    $activeRows  = ($sessionsOut -split "`n") | Where-Object { $_ -match '\tactive\t' }
    if ($activeRows.Count -ge 1) {
        Write-Pass "still have $($activeRows.Count) active session(s)"
    } else {
        Write-Fail 'session vanished after forgery attempts'
    }

    $after = Snapshot-Counters
    Emit-Delta 'scenario4' $before $after
}

# -- report -- summary of what the log shows ---------------------------------

function Invoke-Report {
    Write-Info 'Log-event summary'
    if (-not (Test-Path $LogFile)) {
        Write-Fail "log file not found: $LogFile"
        return
    }
    $snap = Snapshot-Counters
    Out-Report "=== Report @ $(Get-Date -Format s) ==="
    Out-Report "  session.transport_swapped                     = $($snap.swapped)"
    Out-Report "  session.hot_standby.trigger_raised            = $($snap.trigger_raised)"
    Out-Report "  session.hot_standby.auto_swap_trigger         = $($snap.auto_swap)"
    Out-Report "  session.hot_standby.flap_damped               = $($snap.flap_damped)"
    Out-Report "  session.hot_standby.alt_uri_auto_discovered   = $($snap.alt_uri_auto)"
    Out-Report "  handshake.success                             = $($snap.handshake_ok)"
    Out-Report "  session.close                                 = $($snap.session_close)"
    foreach ($f in 'swapped','trigger_raised','auto_swap','flap_damped',
                   'alt_uri_auto','handshake_ok','session_close') {
        Write-Host ("  {0,-40} {1,4}" -f $f, $snap.$f)
    }
    Write-Info "sessions list:"
    Write-Host (Get-SessionsList)
}

# -- dispatch ----------------------------------------------------------------

Write-Info "log file: $LogFile"
Write-Info "report:   $ReportFile"

switch ($Scenario) {
    'scenario1' { Invoke-Scenario1 }
    'scenario2' { Invoke-Scenario2 }
    'scenario3' { Invoke-Scenario3 }
    'scenario4' { Invoke-Scenario4 }
    'all' {
        Invoke-Scenario1
        Start-Sleep -Seconds 3
        Invoke-Scenario4
        Start-Sleep -Seconds 3
        if (Test-IsElevated) {
            Invoke-Scenario2
            Start-Sleep -Seconds 5
            Invoke-Scenario3
        } else {
            Write-Warn2 'skipping scenario2/scenario3 -- not elevated'
        }
        Write-Host ''
        Invoke-Report
    }
    'report' { Invoke-Report }
}

Write-Info 'done'
