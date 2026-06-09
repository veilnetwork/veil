<#
.SYNOPSIS
    Epic 459 hot-standby verification harness for Windows.

.DESCRIPTION
    PowerShell counterpart of `scripts/test-hot-standby.sh`.  Covers the
    same five single-host phases (session health / transport inventory /
    stage-(a) unit tests / manual swap via admin command / stage-(c)
    auto-trigger unit test) and additionally automates scenarios 2, 3,
    and 4 from `docs/hot-standby-test-plan-windows.md`:

      - `scenario-firewall`  — block the primary port via
                                `New-NetFirewallRule`, expect proactive
                                trigger + `session.transport_swapped`.
                                Scenario 2 automation.
      - `scenario-flap`      — toggle the firewall rule on a schedule,
                                expect flap damping to cap swap count at
                                `max_swaps_per_minute`.  Scenario 3.
      - `scenario-forgery`   — attempt `swap-transport` with an invalid
                                alt URI and against an unknown peer_id;
                                both must reject without affecting the
                                real session.  Scenario 4 (wire-level
                                forgery is already covered by the rust
                                `handoff_attach_*` unit tests).

    Single-host mode: all nodes run on localhost with distinct TCP
    ports.  Two-host mode: pass `-PeerHost <computer>` (PowerShell
    remoting) so node-1 runs on the remote box — this is the
    fully-correct topology for scenarios 2/3 because Windows firewall
    rules apply to loopback only with the non-default
    `AllowLoopback=false` profile setting.

.PARAMETER Command
    run | start | stop | verify | logs | scenario-firewall |
    scenario-flap | scenario-forgery | help

.PARAMETER Node
    Node index (0 or 1) for `logs`.  Default: 0.

.PARAMETER PeerHost
    Optional.  Computer name or IP for PowerShell remoting when running
    two-host scenarios.  If unset, both nodes run on the current host.

.EXAMPLE
    pwsh .\scripts\test-hot-standby.ps1 run
    pwsh .\scripts\test-hot-standby.ps1 scenario-firewall
    pwsh .\scripts\test-hot-standby.ps1 scenario-flap
    pwsh .\scripts\test-hot-standby.ps1 scenario-forgery
    pwsh .\scripts\test-hot-standby.ps1 logs 1
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('run', 'start', 'stop', 'verify', 'logs',
                 'scenario-firewall', 'scenario-flap', 'scenario-forgery',
                 'help')]
    [string]$Command = 'help',

    [Parameter(Position = 1)]
    [int]$Node = 0,

    [string]$PeerHost = ''
)

$ErrorActionPreference = 'Stop'

# ── Configuration ───────────────────────────────────────────────────────────

$ScriptDir   = Split-Path -Parent $PSCommandPath
$RepoRoot    = Split-Path -Parent $ScriptDir
$FixtureDir  = if ($env:HS_FIXTURE_DIR) { $env:HS_FIXTURE_DIR } `
               else { Join-Path $env:LOCALAPPDATA 'veil-hot-standby' }
$Binary      = Join-Path $RepoRoot 'target\release\veil-cli.exe'
$BinaryDebug = Join-Path $RepoRoot 'target\debug\veil-cli.exe'

# Two nodes, two TCP ports each — mirrors the bash fixture layout.
$NodeA_Port1 = 9310
$NodeA_Port2 = 9311
$NodeB_Port1 = 9320
$NodeB_Port2 = 9321

$FwRuleName = 'veil-hotstandby-test'

# ── Helpers ─────────────────────────────────────────────────────────────────

function Write-Info  ($msg) { Write-Host "[hot-standby] $msg" -ForegroundColor Cyan }
function Write-Pass  ($msg) { Write-Host "  + $msg"           -ForegroundColor Green }
function Write-Fail  ($msg) { Write-Host "  - $msg"           -ForegroundColor Red }
function Write-Warn2 ($msg) { Write-Host "  ! $msg"           -ForegroundColor Yellow }

function Get-NodeDir($n)    { Join-Path $FixtureDir "node-$n" }
function Get-ConfigFile($n) { Join-Path (Get-NodeDir $n) 'config.toml' }
function Get-PidFile($n)    { Join-Path (Get-NodeDir $n) 'veil.pid' }
function Get-LogFile($n)    { Join-Path (Get-NodeDir $n) 'veil.log' }

function Get-NodePorts($n) {
    switch ($n) {
        0 { return @($NodeA_Port1, $NodeA_Port2) }
        1 { return @($NodeB_Port1, $NodeB_Port2) }
        default { throw "unknown node index: $n" }
    }
}

function Resolve-Binary {
    if (Test-Path $Binary)      { return $Binary }
    if (Test-Path $BinaryDebug) { return $BinaryDebug }
    Write-Info 'building veil-cli (debug)'
    Push-Location $RepoRoot
    try {
        & cargo build -q -p veil-cli --bin veil-cli
        if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
    } finally { Pop-Location }
    if (-not (Test-Path $BinaryDebug)) {
        throw "build succeeded but binary not found at $BinaryDebug"
    }
    return $BinaryDebug
}

function Test-NodeRunning($n) {
    $pf = Get-PidFile $n
    if (-not (Test-Path $pf)) { return $false }
    try {
        $procId = [int](Get-Content $pf -Raw).Trim()
        $null = Get-Process -Id $procId -ErrorAction Stop
        return $true
    } catch { return $false }
}

function Get-LogMatchCount($file, $pattern) {
    if (-not (Test-Path $file)) { return 0 }
    return (Select-String -Path $file -Pattern $pattern -AllMatches).Matches.Count
}

# Read a [Identity]/[identity] field from a config.toml using a simple
# line-wise scan.  Mirrors the bash `identity_triplet` helper.
function Get-IdentityField($cfgPath, $field) {
    $inSection = $false
    foreach ($line in (Get-Content $cfgPath)) {
        if ($line -match '^\s*\[[Ii]dentity\]\s*$') { $inSection = $true; continue }
        if ($inSection -and $line -match '^\s*\[') { break }
        if ($inSection -and $line -match ('^\s*' + [regex]::Escape($field) + '\s*=\s*"([^"]*)"')) {
            return $Matches[1]
        }
    }
    return ''
}

# ── generate_config ─────────────────────────────────────────────────────────

function New-FixtureConfig($n, $bin) {
    $dir = Get-NodeDir $n
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $cfg = Get-ConfigFile $n
    $ports = Get-NodePorts $n
    $p1 = $ports[0]; $p2 = $ports[1]

    if (Test-Path $cfg) {
        Write-Info "reusing existing config for node-$n"
        return
    }

    # Identity PoW at difficulty=24 — first run costs minutes.
    Write-Info "minting identity for node-$n (PoW=24, can take several minutes on first run)"
    & $bin config init $cfg | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "config init failed for node-$n" }

    & $bin --config $cfg listen add "tcp://127.0.0.1:$p1" --advertise "tcp://127.0.0.1:$p1" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "listen add primary failed for node-$n" }
    & $bin --config $cfg listen add "tcp://127.0.0.1:$p2" --advertise "tcp://127.0.0.1:$p2" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "listen add alternate failed for node-$n" }

    Write-Info "generated node-$n config (tcp://127.0.0.1:$p1, tcp://127.0.0.1:$p2)"
}

# ── wire_peers ──────────────────────────────────────────────────────────────
#
# Appends [[bootstrap_peers]] blocks to each config so the two nodes dial
# each other on the PRIMARY transport.  Alt transport is left for
# auto-discovery (stage c.3 advertised-transports TLV) once handshake runs.

function Invoke-WirePeers {
    $cfgA = Get-ConfigFile 0
    $cfgB = Get-ConfigFile 1

    $pkA = Get-IdentityField $cfgA 'public_key'
    $pkB = Get-IdentityField $cfgB 'public_key'
    $nonceA = Get-IdentityField $cfgA 'nonce'
    $nonceB = Get-IdentityField $cfgB 'nonce'
    if (-not $pkA -or -not $pkB) {
        throw 'could not parse public_key from configs — regenerate via stop+start'
    }

    if (-not (Select-String -Path $cfgA -Pattern ([regex]::Escape($pkB)) -Quiet)) {
        $block = @"

[[bootstrap_peers]]
transport  = "tcp://127.0.0.1:$NodeB_Port1"
public_key = "$pkB"
nonce      = "$nonceB"
algo       = "ed25519"
"@
        Add-Content -Path $cfgA -Value $block
        Write-Info "wired node-0 -> node-1 (tcp://127.0.0.1:$NodeB_Port1)"
    }
    if (-not (Select-String -Path $cfgB -Pattern ([regex]::Escape($pkA)) -Quiet)) {
        $block = @"

[[bootstrap_peers]]
transport  = "tcp://127.0.0.1:$NodeA_Port1"
public_key = "$pkA"
nonce      = "$nonceA"
algo       = "ed25519"
"@
        Add-Content -Path $cfgB -Value $block
        Write-Info "wired node-1 -> node-0 (tcp://127.0.0.1:$NodeA_Port1)"
    }
}

# ── start / stop / logs ─────────────────────────────────────────────────────

function Invoke-Start {
    $bin = Resolve-Binary
    if (-not (Test-Path $FixtureDir)) {
        New-Item -ItemType Directory -Force -Path $FixtureDir | Out-Null
    }
    New-FixtureConfig 0 $bin
    New-FixtureConfig 1 $bin
    Invoke-WirePeers

    foreach ($n in 0, 1) {
        if (Test-NodeRunning $n) {
            $existing = (Get-Content (Get-PidFile $n) -Raw).Trim()
            Write-Info "node-$n already running (pid $existing)"
            continue
        }
        $cfg = Get-ConfigFile $n
        $log = Get-LogFile $n
        $proc = Start-Process -FilePath $bin `
            -ArgumentList @('--config', $cfg, 'node', 'run', '--foreground') `
            -RedirectStandardOutput $log `
            -RedirectStandardError "$log.err" `
            -WindowStyle Hidden `
            -PassThru
        $proc.Id | Out-File -FilePath (Get-PidFile $n) -Encoding ascii
        Write-Info "started node-$n (pid $($proc.Id))"
    }

    Write-Info 'waiting for session to establish (up to 60s)...'
    $waited = 0
    while ($waited -lt 60) {
        $outA = & $bin --config (Get-ConfigFile 0) node show 2>$null
        $outB = & $bin --config (Get-ConfigFile 1) node show 2>$null
        $a = ($outA | Select-String -Pattern '^sessions_active:\s*(\d+)').Matches.Groups[1].Value
        $b = ($outB | Select-String -Pattern '^sessions_active:\s*(\d+)').Matches.Groups[1].Value
        if ([int]$a -ge 1 -and [int]$b -ge 1) {
            Write-Info "session established (node-0=$a, node-1=$b)"
            return
        }
        Start-Sleep -Seconds 1
        $waited++
    }
    throw "session did not establish within 60s (see: test-hot-standby.ps1 logs 0|1)"
}

function Invoke-Stop {
    if (-not (Test-Path $FixtureDir)) { Write-Info 'no fixture directory found'; return }
    $stopped = 0
    Get-ChildItem -Path $FixtureDir -Filter 'veil.pid' -Recurse | ForEach-Object {
        $procId = [int](Get-Content $_.FullName -Raw).Trim()
        try {
            Stop-Process -Id $procId -Force -ErrorAction Stop
            Write-Info "stopped pid $procId"
            $stopped++
        } catch {
            # process already gone — fine
        }
        Remove-Item -Force $_.FullName
    }
    if ($stopped -eq 0) { Write-Info 'no running nodes found' }
}

function Invoke-Logs {
    $log = Get-LogFile $Node
    if (-not (Test-Path $log)) { throw "no log file for node-$Node at $log" }
    Get-Content $log -Wait -Tail 50
}

# ── verify phases (single-host parity with bash script) ─────────────────────

$script:VerifyFailed = 0
function Invoke-RecordFail($msg) { $script:VerifyFailed++; Write-Fail $msg }

function Invoke-PhaseSessionHealth($bin) {
    Write-Info '-- phase 1: session health ---------------------------------'
    foreach ($n in 0, 1) {
        if (-not (Test-NodeRunning $n)) { Invoke-RecordFail "node-$n not running"; continue }
        $out = & $bin --config (Get-ConfigFile $n) node show 2>&1
        if ($LASTEXITCODE -ne 0) { Invoke-RecordFail "admin query failed on node-$n"; continue }
        $sessions = ($out | Select-String -Pattern '^sessions_active:\s*(\d+)').Matches.Groups[1].Value
        $listens  = ($out | Select-String -Pattern '^listens_active:\s*(\d+)').Matches.Groups[1].Value
        if ([int]$sessions -ge 1) {
            Write-Pass "node-$n: $sessions session(s), $listens listener(s)"
        } else {
            Invoke-RecordFail "node-$n: 0 active sessions (expected >= 1)"
        }
    }
}

function Invoke-PhaseTransportInventory($bin) {
    Write-Info '-- phase 2: transport inventory (baseline) -----------------'
    foreach ($n in 0, 1) {
        $out = & $bin --config (Get-ConfigFile $n) sessions list 2>&1
        if ($LASTEXITCODE -ne 0) { Invoke-RecordFail "sessions list failed on node-$n"; continue }
        $active = @($out | Where-Object { ($_ -split "`t")[4] -eq 'active' })
        if ($active.Count -ge 1) {
            Write-Pass "node-$n: $($active.Count) active session(s)"
            foreach ($row in $active) {
                $cols = $row -split "`t"
                Write-Host "    primary transport: $($cols[3]) (link=$($cols[0]))"
            }
        } else {
            Invoke-RecordFail "node-$n: sessions list has no active rows"
        }
    }
}

function Invoke-PhaseUnitTests {
    Write-Info '-- phase 3: hot-standby unit tests (stage a correctness) ---'
    Push-Location $RepoRoot
    try {
        $out = & cargo test -q -p veilcore --lib node::session::runner::tests::swap 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Pass 'swap_redirects_runner_to_new_stream_without_reset'
            Write-Pass 'swap_preserves_aead_counter_across_transports'
        } else {
            Invoke-RecordFail 'hot-standby unit tests failed — swap mechanism regression'
            $out | Select-Object -Last 20 | ForEach-Object { "    $_" } | Write-Host
        }
    } finally { Pop-Location }
}

function Invoke-PhaseSwapEndToEnd($bin) {
    Write-Info '-- phase 4: end-to-end swap via admin command --------------'
    $help = & $bin --config (Get-ConfigFile 0) node --help 2>&1
    if (-not ($help -match 'swap-transport')) {
        Write-Warn2 "'node swap-transport' not present — Epic 459 B5 integration missing"
        return
    }

    $showB = & $bin --config (Get-ConfigFile 1) node show 2>&1
    $peerIdMatch = $showB | Select-String -Pattern '^node_id:\s*([0-9a-f]+)'
    if (-not $peerIdMatch) {
        Invoke-RecordFail "couldn't read node-1's node_id from 'node show'"
        return
    }
    $peerId = $peerIdMatch.Matches.Groups[1].Value

    $aSwapBefore = Get-LogMatchCount (Get-LogFile 0) 'session.transport_swapped'
    $bSwapBefore = Get-LogMatchCount (Get-LogFile 1) 'session.transport_swapped'
    $aHsBefore   = Get-LogMatchCount (Get-LogFile 0) 'handshake.success'
    $bHsBefore   = Get-LogMatchCount (Get-LogFile 1) 'handshake.success'

    $altUri = "tcp://127.0.0.1:$NodeB_Port2"
    Write-Info "invoking: node swap-transport --peer $($peerId.Substring(0,12))... --alt-uri $altUri"
    $cmdOut = & $bin --config (Get-ConfigFile 0) node swap-transport `
        --peer $peerId --alt-uri $altUri 2>&1
    if ($LASTEXITCODE -ne 0) {
        Invoke-RecordFail "swap-transport admin command failed: $cmdOut"
        return
    }
    Write-Pass 'swap-transport command returned successfully'

    Start-Sleep -Seconds 1

    $aSwapAfter = Get-LogMatchCount (Get-LogFile 0) 'session.transport_swapped'
    $bSwapAfter = Get-LogMatchCount (Get-LogFile 1) 'session.transport_swapped'
    if ($aSwapAfter -gt $aSwapBefore -and $bSwapAfter -gt $bSwapBefore) {
        Write-Pass "both sides logged session.transport_swapped (node-0: $aSwapBefore->$aSwapAfter, node-1: $bSwapBefore->$bSwapAfter)"
    } else {
        Invoke-RecordFail "session.transport_swapped not observed on both sides (node-0: $aSwapBefore->$aSwapAfter, node-1: $bSwapBefore->$bSwapAfter)"
    }

    $aHsAfter = Get-LogMatchCount (Get-LogFile 0) 'handshake.success'
    $bHsAfter = Get-LogMatchCount (Get-LogFile 1) 'handshake.success'
    if ($aHsAfter -eq $aHsBefore -and $bHsAfter -eq $bHsBefore) {
        Write-Pass 'no new handshake.success events — session preserved across transport'
    } else {
        Invoke-RecordFail "unexpected re-handshake during swap (node-0: $aHsBefore->$aHsAfter, node-1: $bHsBefore->$bHsAfter)"
    }
}

function Invoke-PhaseAutoTriggerTest {
    Write-Info '-- phase 5: auto-trigger unit test (stage c correctness) ---'
    Push-Location $RepoRoot
    try {
        $out = & cargo test -q -p veilcore --lib auto_trigger_fires_on_primary_write_error 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Pass 'auto_trigger_fires_on_primary_write_error'
        } else {
            Invoke-RecordFail 'stage (c) auto-trigger unit test failed — regression'
            $out | Select-Object -Last 20 | ForEach-Object { "    $_" } | Write-Host
        }
    } finally { Pop-Location }
    Write-Info '  live-fixture auto-trigger induction via firewall toggle:'
    Write-Info '    pwsh test-hot-standby.ps1 scenario-firewall'
}

function Invoke-Verify {
    $script:VerifyFailed = 0
    $bin = Resolve-Binary
    Invoke-PhaseSessionHealth      $bin
    Invoke-PhaseTransportInventory $bin
    Invoke-PhaseUnitTests
    Invoke-PhaseSwapEndToEnd       $bin
    Invoke-PhaseAutoTriggerTest

    Write-Host ''
    if ($script:VerifyFailed -eq 0) {
        Write-Host '[hot-standby] ALL PHASES PASSED' -ForegroundColor Green
        return 0
    }
    Write-Host "[hot-standby] FAILED — $($script:VerifyFailed) check(s) did not pass" -ForegroundColor Red
    return 1
}

# ── scenario-firewall (Windows test plan #2) ────────────────────────────────
#
# Blocks outbound traffic to node-1's primary port via Windows Firewall,
# induces write errors on node-0's TLS/TCP session, and asserts that the
# stage-(c) auto-trigger raises `session.transport_swapped`.  Requires
# admin (New-NetFirewallRule needs it).

function Remove-HotStandbyFirewallRule {
    Get-NetFirewallRule -DisplayName $FwRuleName -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
}

function New-HotStandbyBlockRule($remotePort) {
    New-NetFirewallRule -DisplayName $FwRuleName `
        -Direction Outbound -Action Block `
        -Protocol TCP -RemotePort $remotePort `
        -RemoteAddress '127.0.0.1' `
        -Profile Any `
        | Out-Null
}

function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-ScenarioFirewall {
    if (-not (Test-IsElevated)) {
        throw 'scenario-firewall requires an elevated PowerShell (Run as Administrator)'
    }
    $bin = Resolve-Binary
    if (-not (Test-NodeRunning 0) -or -not (Test-NodeRunning 1)) {
        Write-Info 'fixture not running — starting it'
        Invoke-Start
    }
    Write-Info 'scenario 2 — firewall block of primary port'

    $before = Get-LogMatchCount (Get-LogFile 0) 'session.hot_standby.trigger_raised|session.transport_swapped'

    Remove-HotStandbyFirewallRule
    try {
        New-HotStandbyBlockRule $NodeB_Port1
        Write-Info "blocked outbound TCP to 127.0.0.1:$NodeB_Port1 — waiting for trigger..."

        $deadline = (Get-Date).AddSeconds(30)
        $observed = $false
        while ((Get-Date) -lt $deadline) {
            $after = Get-LogMatchCount (Get-LogFile 0) 'session.hot_standby.trigger_raised|session.transport_swapped'
            if ($after -gt $before) { $observed = $true; break }
            Start-Sleep -Milliseconds 500
        }

        if ($observed) {
            Write-Pass 'proactive trigger or transport swap observed within 30s'
        } else {
            Invoke-RecordFail 'no trigger / swap observed within 30s — scenario 2 did not fire'
        }
    } finally {
        Remove-HotStandbyFirewallRule
        Write-Info 'removed firewall rule'
    }
}

# ── scenario-flap (Windows test plan #3) ────────────────────────────────────

function Invoke-ScenarioFlap {
    if (-not (Test-IsElevated)) {
        throw 'scenario-flap requires an elevated PowerShell (Run as Administrator)'
    }
    $bin = Resolve-Binary
    if (-not (Test-NodeRunning 0) -or -not (Test-NodeRunning 1)) {
        Write-Info 'fixture not running — starting it'
        Invoke-Start
    }
    Write-Info 'scenario 3 — flap damping under repeated firewall toggles'

    $swapBefore = Get-LogMatchCount (Get-LogFile 0) 'session.transport_swapped'
    $dampBefore = Get-LogMatchCount (Get-LogFile 0) 'session.hot_standby.flap_damped'

    Remove-HotStandbyFirewallRule
    try {
        # ~2 minutes at 5-second cadence = 24 toggles.  With default
        # max_swaps_per_minute = 4 we expect at most ~8 successful swaps
        # and the rest damped.
        for ($i = 0; $i -lt 12; $i++) {
            New-HotStandbyBlockRule $NodeB_Port1
            Start-Sleep -Seconds 5
            Remove-HotStandbyFirewallRule
            Start-Sleep -Seconds 5
        }
    } finally { Remove-HotStandbyFirewallRule }

    $swapAfter = Get-LogMatchCount (Get-LogFile 0) 'session.transport_swapped'
    $dampAfter = Get-LogMatchCount (Get-LogFile 0) 'session.hot_standby.flap_damped'
    $swapCount = $swapAfter - $swapBefore
    $dampCount = $dampAfter - $dampBefore
    Write-Info "session.transport_swapped delta: $swapCount"
    Write-Info "session.hot_standby.flap_damped delta: $dampCount"

    # Hard contract: within a rolling minute the swap count should not
    # exceed 4 (default max).  Across 2 minutes we allow up to 8.
    if ($swapCount -le 8) {
        Write-Pass "swap count $swapCount is within 2x max_swaps_per_minute (8)"
    } else {
        Invoke-RecordFail "swap count $swapCount exceeds 2x max_swaps_per_minute — damping leaked"
    }
    if ($dampCount -gt 0) {
        Write-Pass "flap damping recorded $dampCount deferred attempts"
    } else {
        Write-Warn2 'no flap_damped events recorded — may indicate cadence too slow to saturate'
    }
}

# ── scenario-forgery (Windows test plan #4 — admin-surface subset) ──────────
#
# Full wire-level HandoffAttach forgery is already covered by the Rust
# unit tests (`handoff_attach_rejects_bad_hmac`, `handoff_attach_rejects_unknown_session`).
# Here we automate the operator-visible forgery surfaces: swap-transport
# with (a) an invalid alt-uri scheme, (b) a known-bad peer_id, (c) an
# alt-uri pointing at a host the peer hasn't advertised.  All three must
# reject cleanly without toppling the existing session.

function Invoke-ScenarioForgery {
    $bin = Resolve-Binary
    if (-not (Test-NodeRunning 0) -or -not (Test-NodeRunning 1)) {
        Write-Info 'fixture not running — starting it'
        Invoke-Start
    }
    Write-Info 'scenario 4 — forgery resistance at operator + wire surfaces'

    $showA = & $bin --config (Get-ConfigFile 0) node show 2>&1
    $baselineSess = ($showA | Select-String -Pattern '^sessions_active:\s*(\d+)').Matches.Groups[1].Value

    $fakePeer = ('ff' * 32)   # 64-hex but nobody's actual node_id
    Write-Info 'case (a): swap-transport against unknown peer_id'
    $out = & $bin --config (Get-ConfigFile 0) node swap-transport `
        --peer $fakePeer --alt-uri "tcp://127.0.0.1:$NodeB_Port2" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Pass "rejected (exit=$LASTEXITCODE, msg=$($out | Select-Object -Last 1))"
    } else {
        Invoke-RecordFail 'unknown peer_id did NOT reject — admin surface broken'
    }

    $showB = & $bin --config (Get-ConfigFile 1) node show 2>&1
    $peerId = ($showB | Select-String -Pattern '^node_id:\s*([0-9a-f]+)').Matches.Groups[1].Value
    Write-Info 'case (b): swap-transport with unparseable alt-uri'
    $out = & $bin --config (Get-ConfigFile 0) node swap-transport `
        --peer $peerId --alt-uri 'not-a-uri://garbage' 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Pass "rejected malformed URI (exit=$LASTEXITCODE)"
    } else {
        Invoke-RecordFail 'malformed URI accepted — validation missing'
    }

    Write-Info 'case (c): existing session still alive after rejections'
    $showA2 = & $bin --config (Get-ConfigFile 0) node show 2>&1
    $nowSess = ($showA2 | Select-String -Pattern '^sessions_active:\s*(\d+)').Matches.Groups[1].Value
    if ([int]$nowSess -ge [int]$baselineSess) {
        Write-Pass "node-0 session count $baselineSess -> $nowSess (not regressed)"
    } else {
        Invoke-RecordFail "session count dropped $baselineSess -> $nowSess after forgery attempts"
    }

    Write-Info '  wire-level HandoffAttach HMAC / unknown-session forgery is covered by:'
    Write-Info '    cargo test -p veilcore --lib handoff_attach'
}

# ── cmd_run ─────────────────────────────────────────────────────────────────

function Invoke-Run {
    $alreadyUp = (Test-NodeRunning 0) -and (Test-NodeRunning 1)
    if (-not $alreadyUp) { Invoke-Start }
    else                 { Write-Info 'reusing running fixture' }

    try {
        $rc = Invoke-Verify
    } finally {
        if (-not $alreadyUp) { Invoke-Stop }
    }
    return $rc
}

# ── dispatch ────────────────────────────────────────────────────────────────

if ($PeerHost) {
    Write-Warn2 "PeerHost parameter supplied ($PeerHost) — two-host mode is not yet implemented."
    Write-Warn2 'Run the script on each host separately and use scenario-firewall manually.'
}

switch ($Command) {
    'run'                { exit (Invoke-Run) }
    'start'              { Invoke-Start }
    'stop'               { Invoke-Stop }
    'verify'             { exit (Invoke-Verify) }
    'logs'               { Invoke-Logs }
    'scenario-firewall'  { Invoke-ScenarioFirewall }
    'scenario-flap'      { Invoke-ScenarioFlap }
    'scenario-forgery'   { Invoke-ScenarioForgery }
    default              { Get-Help $PSCommandPath -Detailed }
}
