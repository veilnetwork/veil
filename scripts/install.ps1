<#
.SYNOPSIS
    veil installer for Windows — fetch prebuilt binaries, then guide you to a running node.

.DESCRIPTION
    Downloads sha256-verified release binaries from GitHub and installs them to
    %USERPROFILE%\.veil\bin (added to your user PATH). No Rust toolchain needed.

    One-liner (latest, node only):
        irm https://raw.githubusercontent.com/veilnetwork/veil/main/scripts/install.ps1 | iex

    With options, pass them through a scriptblock:
        & ([scriptblock]::Create((irm https://raw.githubusercontent.com/veilnetwork/veil/main/scripts/install.ps1))) -All
    ...or save the file and run:  .\install.ps1 -All -Version 1.4.0

    When piped to `iex`, configure via environment variables instead of flags:
        $env:VEIL_COMPONENTS = 'veil-cli,ogate'
        $env:VEIL_VERSION    = '1.4.0'
        irm .../install.ps1 | iex

.NOTES
    Components: veil-cli (node), ogate (TUN gateway), oproxy-client, oproxy-server.
#>
[CmdletBinding()]
param(
    [string]   $Components = $(if ($env:VEIL_COMPONENTS) { $env:VEIL_COMPONENTS } else { 'veil-cli' }),
    [switch]   $All,
    [string]   $Version    = $(if ($env:VEIL_VERSION) { $env:VEIL_VERSION } else { 'latest' }),
    [string]   $BinDir     = $(if ($env:VEIL_BIN) { $env:VEIL_BIN } else { "$env:USERPROFILE\.veil\bin" }),
    [string]   $Repo       = $(if ($env:VEIL_REPO) { $env:VEIL_REPO } else { 'veilnetwork/veil' }),
    [switch]   $NoModifyPath,
    [switch]   $NoVerify,
    [switch]   $RequireSignature,
    [switch]   $Quickstart,
    [switch]   $Help
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$AllComponents = @('veil-cli','ogate','oproxy-client','oproxy-server')

function Say  ($m) { Write-Host "veil: $m" -ForegroundColor Cyan }
function Ok   ($m) { Write-Host "  ok " -ForegroundColor Green -NoNewline; Write-Host $m }
function Info ($m) { Write-Host "  $m" }
function Warn ($m) { Write-Warning $m }
function Die  ($m) { Write-Host "error: $m" -ForegroundColor Red; exit 1 }

# ── Release-manifest signature (F2: supply-chain authenticity) ───────────────
# Mirrors the Unix installer (scripts/install.sh). The sha256 manifest binds
# binary -> hash but only proves manifest and binary AGREE; an attacker who can
# replace the release assets (or a mirror) can serve a malicious .exe WITH a
# matching manifest. A detached Ed25519 signature over the manifest, checked
# against a key PINNED here, raises the bar to "forge the operator's release
# key". Verified with openssl (independent of the downloaded binary, so a
# malicious binary cannot self-attest).
#
# Windows has no native Ed25519 verifier, so this uses `openssl` (>= 3.0) if it
# is on PATH. When openssl is absent / too old / no signature is published, the
# installer WARNS and falls back to sha256-only (no regression vs the prior
# channel-trust behaviour) — unless -RequireSignature forces a hard failure.

# Pinned Ed25519 release public key (openssl PEM). Keep in sync with
# scripts/install.sh `pinned_release_pubkey`. Runtime override:
# $env:VEIL_RELEASE_PUBKEY_PEM (e.g. a testnet key).
function Get-PinnedReleasePubkey {
    if ($env:VEIL_RELEASE_PUBKEY_PEM) { return $env:VEIL_RELEASE_PUBKEY_PEM }
    return @"
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAdvlFTSCogeqOOtL3TnkZZ14Eq9waNDBU+yTfubasRXs=
-----END PUBLIC KEY-----
"@
}

# OpenSSL >= 3.0 supports one-shot Ed25519 via `pkeyutl -rawin`. Returns the
# openssl command name if capable, else $null.
function Get-Ed25519Openssl {
    $ossl = Get-Command openssl -ErrorAction SilentlyContinue
    if (-not $ossl) { return $null }
    try { $ver = (& openssl version) 2>$null } catch { return $null }
    if ($ver -match '^OpenSSL\s+[345]\.') { return $ossl.Source }
    return $null
}

# Verify the detached Ed25519 signature over the sha256 manifest. Fail-closed
# when a key is pinned and the signature is missing/invalid AND
# -RequireSignature is set (or always on a verify FAILURE); warn-and-continue
# when no key is pinned or no capable openssl is present.
function Verify-ManifestSignature ($shaPath, $base, $triple, $tmp) {
    $pem = Get-PinnedReleasePubkey
    if (-not ($pem -replace '\s', '')) {
        if ($RequireSignature) { Die "-RequireSignature given, but this installer has no pinned release key. See docs/en/release-signing.md." }
        Warn "release manifest is NOT signature-verified (no pinned key) — authenticity rests on TLS to the download host. See docs/en/release-signing.md."
        return
    }
    $ossl = Get-Ed25519Openssl
    if (-not $ossl) {
        if ($RequireSignature) { Die "-RequireSignature needs OpenSSL >= 3.0 on PATH to verify the Ed25519 release signature (none found)." }
        Warn "cannot verify release signature: OpenSSL >= 3.0 not found on PATH. Falling back to sha256-only. Install OpenSSL 3.x or pass -RequireSignature to enforce."
        return
    }
    $sigPath = Join-Path $tmp 'sha256.txt.sig'
    try { Invoke-WebRequest -Uri "$base/sha256-$triple.txt.sig" -OutFile $sigPath -UseBasicParsing }
    catch { Die "a release key is pinned but no sha256-$triple.txt.sig was published — refusing to install an unverified manifest." }
    $pemPath = Join-Path $tmp 'relkey.pem'
    Set-Content -Path $pemPath -Value $pem -NoNewline
    & $ossl pkeyutl -verify -pubin -inkey $pemPath -rawin -in $shaPath -sigfile $sigPath 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Ok 'release manifest signature verified (Ed25519)'
    } else {
        Die "release manifest signature INVALID — ABORTING. The sha256 manifest does not verify against the pinned release key; the download channel or the release artifacts may be compromised. Do NOT run anything."
    }
}

if ($Help) {
@"
veil installer (Windows)

  -Components <list>   Comma list: veil-cli,ogate,oproxy-client,oproxy-server  (default: veil-cli)
  -All                 Install every binary
  -Version <X.Y.Z>     Specific release (default: latest)
  -BinDir <dir>        Install location (default: %USERPROFILE%\.veil\bin)
  -Repo <owner/repo>   Source repo (default: veilnetwork/veil)
  -NoModifyPath        Don't touch the user PATH
  -NoVerify            Skip sha256 verification (not recommended)
  -RequireSignature    Hard-fail unless the release manifest carries a valid
                       Ed25519 signature (needs openssl 3.x on PATH)
  -Quickstart          Init + start a node after install
  -Help                This help

Examples:
  .\install.ps1
  .\install.ps1 -All
  .\install.ps1 -Components ogate,oproxy-server -Version 1.4.0
"@ | Write-Host
    return
}

# ── Resolve components ──────────────────────────────────────────────────────
if ($All) { $Components = ($AllComponents -join ',') }
$wanted = $Components.Split(',',[StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() }
foreach ($c in $wanted) {
    if ($AllComponents -notcontains $c) { Die "unknown component '$c' (choices: $($AllComponents -join ', '))" }
}
if (-not $wanted) { Die 'no components selected' }

# ── Platform -> triple ──────────────────────────────────────────────────────
# On ARM64 Windows, a 32-bit/emulated host process reports the emulated arch in
# PROCESSOR_ARCHITECTURE; PROCESSOR_ARCHITEW6432 holds the true arch when set.
$arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
switch ($arch) {
    'AMD64' { $triple = 'x86_64-pc-windows-msvc' }
    'ARM64' { $triple = 'aarch64-pc-windows-msvc' }
    default {
        Die @"
no prebuilt Windows binary for architecture '$arch' (x86_64/AMD64 and ARM64 are published).
Build from source:  git clone https://github.com/$Repo; cargo build --release
"@
    }
}

# ── Resolve release tag ─────────────────────────────────────────────────────
if ($Version -eq 'latest') {
    Say "resolving latest release of $Repo ..."
    try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
                                  -Headers @{ 'User-Agent' = 'veil-installer' }
        $tag = $rel.tag_name
    } catch { $tag = $null }
    if (-not $tag) {
        Die @"
could not determine the latest release (none published yet?).
Retry with an explicit version:  -Version X.Y.Z
Releases: https://github.com/$Repo/releases
"@
    }
} else {
    $tag = "v$($Version.TrimStart('v'))"
}

Say "installer starting (repo $Repo)"
Info "platform: $triple"
Info "release:  $tag"
Info "target:   $BinDir"
Info "install:  $($wanted -join ', ')"

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$base = "https://github.com/$Repo/releases/download/$tag"
$tmp  = Join-Path ([IO.Path]::GetTempPath()) ("veil-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$shaFile = $null

try {
    # Download the sha256 manifest once (lines reference bare names: veil-cli, ...).
    if (-not $NoVerify) {
        # FAIL-CLOSED (supply-chain): a missing manifest or a missing entry is a
        # HARD ERROR — pre-fix both only warned and installed the binary
        # unverified. Pass -NoVerify to opt out explicitly.
        $shaFile = Join-Path $tmp 'sha256.txt'
        try { Invoke-WebRequest -Uri "$base/sha256-$triple.txt" -OutFile $shaFile -UseBasicParsing }
        catch { Die "no sha256-$triple.txt published — refusing to install an unverified binary. Re-run with -NoVerify to override." }
        # Authenticate the manifest (Ed25519 over sha256-$triple.txt) before
        # trusting any hash in it. Warn-fallback unless -RequireSignature.
        Verify-ManifestSignature $shaFile $base $triple $tmp
    }

    foreach ($bin in $wanted) {
        $asset = "$bin-$triple.exe"
        $url   = "$base/$asset"
        $out   = Join-Path $tmp "$bin.exe"
        Info "downloading $asset"
        try { Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing }
        catch { Die "download failed: $url`n(is '$bin' published for $triple in $tag?)" }

        if (-not $NoVerify) {
            $line = Select-String -Path $shaFile -Pattern "(?m)^\s*([0-9a-fA-F]{64})\s+$([regex]::Escape($bin))(\.exe)?\s*$" |
                    Select-Object -First 1
            if (-not $line) { Die "$bin not listed in sha256-$triple.txt — refusing to install an unverified binary. Re-run with -NoVerify to override." }
            $want = $line.Matches[0].Groups[1].Value.ToLower()
            $got  = (Get-FileHash -Algorithm SHA256 -Path $out).Hash.ToLower()
            if ($want -ne $got) { Die "sha256 MISMATCH for $bin`n  expected $want`n  got      $got`nAborting." }
            Ok "$bin sha256 verified"
        }

        Copy-Item -Force $out (Join-Path $BinDir "$bin.exe")
        Ok "installed $bin -> $BinDir\$bin.exe"
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

# ── PATH (user scope) ───────────────────────────────────────────────────────
if (-not $NoModifyPath) {
    $userPath = [Environment]::GetEnvironmentVariable('Path','User')
    if (($userPath -split ';') -notcontains $BinDir) {
        $newPath = if ($userPath) { "$userPath;$BinDir" } else { $BinDir }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Info "added $BinDir to your user PATH (open a new terminal to pick it up)"
    }
    if (($env:Path -split ';') -notcontains $BinDir) { $env:Path = "$env:Path;$BinDir" }
}

# ── Guidance ────────────────────────────────────────────────────────────────
function Selected($n) { return ($wanted -contains $n) }
Write-Host ""
Write-Host "[OK] veil installed." -ForegroundColor Green
Write-Host "binaries in $BinDir" -ForegroundColor DarkGray

if (Selected 'veil-cli') {
@"

Run a node (the 60-second path):
   veil-cli config init          # fresh identity + config
   veil-cli node run             # start in the background
   veil-cli node show            # node id, uptime, peers
   veil-cli node stop            # stop it

Pick your role:
   * Client / leaf (default) — connects out, no public address:
       veil-cli config init --profile mobile
   * Server / relay — public listener others bootstrap from:
       veil-cli config init --profile censorship-target --difficulty 24
       # then open the port and: veil-cli node run

Windows service (auto-start on boot):
   veil-cli service --help       # register/unregister with the SCM
"@ | Write-Host
}
if (Selected 'ogate') {
@"

ogate — IP over veil (needs a TUN/wintun adapter, Administrator):
   ogate gen-config -o ogate.toml
   ogate up --config ogate.toml     # run as Administrator
   docs: docs/en/ogate.md
"@ | Write-Host
}
if (Selected 'oproxy-client') {
@"

oproxy-client — local SOCKS5/HTTP proxy into the veil:
   oproxy-client --gen-config > oproxy-client.toml
   oproxy-client --config oproxy-client.toml
"@ | Write-Host
}
if (Selected 'oproxy-server') {
@"

oproxy-server — veil exit / proxy server:
   oproxy-server --gen-config > oproxy-server.toml
   oproxy-server --config oproxy-server.toml
"@ | Write-Host
}

@"

Docs & help:  veil-cli --help  |  https://github.com/$Repo/blob/master/docs/en/install.md
Uninstall:    remove $BinDir and the PATH entry (System > Environment Variables)
"@ | Write-Host

# ── Optional quickstart ─────────────────────────────────────────────────────
if ((Selected 'veil-cli') -and $Quickstart) {
    $cli = Join-Path $BinDir 'veil-cli.exe'
    Say "initialising node config ..."
    & $cli config init
    if ($LASTEXITCODE -eq 0) {
        Say "starting node ..."
        & $cli node run
        Start-Sleep -Seconds 2
        & $cli node show
    }
}
