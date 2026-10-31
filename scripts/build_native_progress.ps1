param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or -not $vs) { throw 'Native UI regression requires the hosted runner MSVC x86 toolchain' }
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvarsall.bat'
New-Item -ItemType Directory -Force $OutputDirectory | Out-Null
# Compile only a test DLL in this job's artifact directory. The package uses
# the default x86 platform, so the custom action must use that architecture.
$build = Join-Path $OutputDirectory 'build-progress.cmd'
$source = Join-Path $PSScriptRoot 'native_progress.c'
$definition = Join-Path $PSScriptRoot 'native_progress.def'
$lines = @('@echo off', "call `"$vcvars`" x86", 'if errorlevel 1 exit /b %errorlevel%',
  "cl.exe /nologo /W4 /WX /LD /TC `"$source`" /link msi.lib /DEF:`"$definition`" /OUT:NativeProgress.dll", 'exit /b %errorlevel%')
[IO.File]::WriteAllLines($build, $lines, [Text.Encoding]::ASCII)
Push-Location $OutputDirectory
try {
  & $env:ComSpec /d /c $build
  if ($LASTEXITCODE -ne 0) { throw "Native progress custom action build failed: $LASTEXITCODE" }
} finally { Pop-Location }
if (-not (Test-Path (Join-Path $OutputDirectory 'NativeProgress.dll'))) { throw 'Native progress DLL missing' }
