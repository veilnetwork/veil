# SPDX-License-Identifier: MIT
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('veil-mf-format-' + [guid]::NewGuid().ToString('N'))
$oldInclude = $env:INCLUDE
$oldLib = $env:LIB
New-Item -ItemType Directory $tmp | Out-Null
try {
  $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
  $vs = & $vswhere -latest -products '*' -property installationPath | Select-Object -First 1
  $tools = Get-ChildItem (Join-Path $vs 'VC\Tools\MSVC') -Directory |
    Sort-Object Name -Descending | Select-Object -First 1
  $kits = (Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots').KitsRoot10
  $version = Get-ChildItem (Join-Path $kits 'Lib') -Directory |
    Where-Object { $_.Name -like '10.*' } | Sort-Object Name -Descending | Select-Object -First 1
  $includes = @((Join-Path $tools.FullName 'include')) +
    @('ucrt', 'shared', 'um') | ForEach-Object {
      if ($_ -in @('ucrt', 'shared', 'um')) { Join-Path $kits ('Include\' + $version.Name + '\' + $_) }
      else { $_ }
    }
  $env:INCLUDE = $includes -join ';'
  $env:LIB = @((Join-Path $tools.FullName 'lib\x64'),
    (Join-Path $version.FullName 'um\x64'), (Join-Path $version.FullName 'ucrt\x64')) -join ';'
  $compiler = Join-Path $tools.FullName 'bin\Hostx64\x64\cl.exe'
  $binary = Join-Path $tmp 'mf-camera-format.exe'
  $object = Join-Path $tmp 'mf-camera-format.obj'
  & $compiler /nologo /std:c++17 /EHsc /W4 /WX /MD "/I$(Join-Path $root 'src')" `
    (Join-Path $PSScriptRoot 'mf_camera_format_smoke.cc') "/Fo$object" "/Fe$binary" `
    /link mfplat.lib mfuuid.lib ole32.lib
  if ($LASTEXITCODE -ne 0) { throw 'camera format smoke compilation failed' }
  & $binary
  if ($LASTEXITCODE -ne 0) { throw 'camera format smoke failed' }
} finally {
  $env:INCLUDE = $oldInclude
  $env:LIB = $oldLib
  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
