<#
.SYNOPSIS
  Build veil_media.dll for win-x64 from a from-source WebRTC checkout.

.DESCRIPTION
  The Windows twin of linux/build_veil_media_so_linux.sh, and it works the same
  way for the same reason: rather than reinventing the two dozen flags WebRTC
  compiles with (clang-cl, the __Cr libc++ namespace, -std=c++20, the winsysroot
  it downloads), it reads call.cc's EXACT command out of compile_commands.json
  and swaps only the source file. A veil TU compiled with anything else links
  but crosses an ABI boundary at the first std::string it passes.

  Produces a self-contained DLL: the veil call media engine + the
  webrtc::Transport shim + the Media Foundation camera + the GDI screen
  capturer + a codec-stripped WebRTC, all statically linked, exporting ONLY the
  veil_media_* extern-C ABI. Audio uses WebRTC's built-in Core Audio ADM, so
  there is no Windows-specific audio code to build.

  veil_media_send_datagram / veil_media_set_recv_callback are provided by
  veil_win_datagram_thunk.cc, which GetProcAddress'es them out of the already
  loaded veilclient_ffi.dll. That is why this build has no dependency on a Rust
  build output: linking them properly would need veilclient_ffi.lib, an
  artifact produced on a different machine by a different toolchain, for two
  function pointers. The thunks are excluded from the export table below.

  Requires: a Windows host, the WebRTC checkout built for win-x64 with
  --export-compile-commands, and llvm-nm/lld-link from that checkout's
  third_party/llvm-build.

  ⚠️ NEVER RUN. Written without a Windows host to test on, alongside the
  Media Foundation camera and the GDI screen capturer it compiles. The shape
  is the proven Linux recipe; the Windows specifics are from documentation.
  Expect to fix this script before it produces a DLL, and treat the first
  successful call as the real test.

.PARAMETER WebrtcSrc
  The WebRTC `src` directory. Default: $env:WEBRTC_SRC or C:\webrtc\src

.PARAMETER WebrtcOut
  Build directory relative to WebrtcSrc. Default: out\win-x64

.PARAMETER Dest
  Where to write veil_media.dll. Default: this script's directory.
#>
[CmdletBinding()]
param(
  [string]$WebrtcSrc = $(if ($env:WEBRTC_SRC) { $env:WEBRTC_SRC } else { 'C:\webrtc\src' }),
  [string]$WebrtcOut = 'out\win-x64',
  [string]$Dest = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'

$srcDir = (Resolve-Path (Join-Path $PSScriptRoot '..\src')).Path
$outDir = Join-Path $WebrtcSrc $WebrtcOut
$ccJson = Join-Path $outDir 'compile_commands.json'

if (-not (Test-Path $ccJson)) {
  throw "no $ccJson - build win-x64 libwebrtc with --export-compile-commands first"
}

New-Item -ItemType Directory -Force -Path $Dest | Out-Null
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("veil_media_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
  # call.cc's command is the template every veil TU is compiled with.
  $entries = Get-Content -Raw $ccJson | ConvertFrom-Json
  $template = $entries | Where-Object { $_.file -replace '\\', '/' -like '*call/call.cc' } | Select-Object -First 1
  if (-not $template) { throw 'call/call.cc is not in compile_commands.json' }
  $templateCmd = if ($template.command) { $template.command } else { $template.arguments -join ' ' }
  $templateFile = $template.file

  # The compiler is the first token; keep it, it is the checkout's own clang-cl.
  $compiler = ($templateCmd -split '\s+')[0]
  $compilerDir = Split-Path -Parent (Join-Path $template.directory $compiler)

  function Compile-Tu {
    param([string]$Source, [string]$Object)
    $cmd = $templateCmd
    # Swap the source. Both the bare path and any /Fo output are rewritten;
    # everything else - defines, includes, sysroot, warning flags - is kept
    # exactly as WebRTC compiled its own translation unit.
    $cmd = $cmd -replace [regex]::Escape($templateFile), ($Source -replace '\\', '/')
    $cmd = $cmd -replace '(?i)/Fo\S+', ('/Fo"' + $Object + '"')
    $cmd = $cmd -replace '(?i)-o\s+\S+', ('-o "' + $Object + '"')
    # VEIL_MEDIA_HAVE_WEBRTC switches the engine from the ABI-only stub to the
    # real implementation; -I<src> finds veil_camera.h and friends.
    $cmd = $cmd -replace '^(\S+)', ('$1 -DVEIL_MEDIA_HAVE_WEBRTC=1 -I"' + $srcDir + '"')
    Write-Host "==> compiling $(Split-Path -Leaf $Source)"
    Push-Location $template.directory
    try {
      cmd.exe /c $cmd
      if ($LASTEXITCODE -ne 0) { throw "compile failed: $Source" }
    } finally {
      Pop-Location
    }
  }

  $tus = @(
    'veil_media_engine.cc',
    'veil_transport_shim.cc',
    'veil_video_note.cc',
    'veil_mf_camera.cc',
    'veil_gdi_screen.cc',
    'veil_win_datagram_thunk.cc'
  )
  $objects = @()
  foreach ($tu in $tus) {
    $obj = Join-Path $tmp ([System.IO.Path]::GetFileNameWithoutExtension($tu) + '.obj')
    Compile-Tu -Source (Join-Path $srcDir $tu) -Object $obj
    $objects += $obj
  }

  # Export control. A .def is generated rather than hand-written so a new
  # veil_media_* entry point cannot be added to the ABI and silently not
  # exported - which is exactly the failure scripts/check-media-symbols.sh
  # exists to catch, twelve commits too late.
  $nm = Join-Path $compilerDir 'llvm-nm.exe'
  if (-not (Test-Path $nm)) { $nm = 'llvm-nm.exe' }
  # The two datagram entry points are thunks into veilclient_ffi.dll, not part
  # of this DLL's ABI. Exporting them would put a second definition of the
  # client's own symbols into the process's export namespace.
  $thunks = @('veil_media_send_datagram', 'veil_media_set_recv_callback')
  $exported = & $nm --defined-only $objects |
    ForEach-Object { ($_ -split '\s+')[-1] } |
    Where-Object { $_ -like 'veil_media_*' -and $thunks -notcontains $_ } |
    Sort-Object -Unique
  if (-not $exported) { throw 'no veil_media_* symbols in the objects - the engine compiled as the stub' }
  $def = Join-Path $tmp 'veil_media.def'
  "EXPORTS" | Set-Content -Path $def
  $exported | ForEach-Object { "  $_" } | Add-Content -Path $def
  Write-Host "==> exporting $($exported.Count) veil_media_* symbols"

  # Chromium ships its own libc++ built into the __Cr namespace; the MSVC STL
  # would clash with it, so bring WebRTC's objects and nothing else.
  $cxxObjs = Get-ChildItem -Recurse -Filter '*.obj' -Path `
    (Join-Path $outDir 'obj\buildtools\third_party\libc++'), `
    (Join-Path $outDir 'obj\buildtools\third_party\libc++abi') `
    -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }

  $webrtcLib = Join-Path $outDir 'obj\webrtc.lib'
  if (-not (Test-Path $webrtcLib)) { throw "no $webrtcLib - run ninja -C $WebrtcOut webrtc" }

  $linker = Join-Path $compilerDir 'lld-link.exe'
  if (-not (Test-Path $linker)) { $linker = 'lld-link.exe' }
  $dll = Join-Path $Dest 'veil_media.dll'

  # mf*/dmo*/strmiids: Media Foundation capture. gdi32/user32: the screen
  # capturer. ole32/oleaut32: COM for both. The rest is what WebRTC's own
  # win-x64 target links.
  $systemLibs = @(
    'mfplat.lib', 'mf.lib', 'mfreadwrite.lib', 'mfuuid.lib',
    'gdi32.lib', 'user32.lib', 'ole32.lib', 'oleaut32.lib',
    'advapi32.lib', 'winmm.lib', 'ws2_32.lib', 'secur32.lib', 'shell32.lib',
    'dmoguids.lib', 'wmcodecdspuuid.lib', 'msdmo.lib', 'strmiids.lib',
    'iphlpapi.lib', 'crypt32.lib', 'dxgi.lib', 'd3d11.lib'
  )

  Write-Host '==> linking veil_media.dll'
  $linkArgs = @('/DLL', "/OUT:$dll", "/DEF:$def", '/MACHINE:X64', '/OPT:REF', '/OPT:ICF') +
    $objects + @($webrtcLib) + $cxxObjs + $systemLibs
  & $linker @linkArgs
  if ($LASTEXITCODE -ne 0) { throw 'link failed' }

  Write-Host "==> done: $dll ($([math]::Round((Get-Item $dll).Length / 1MB, 1)) MB)"
  Write-Host "exported veil_media_* symbols: $($exported.Count)"
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
