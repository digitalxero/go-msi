$ErrorActionPreference = 'Stop'
$output = $env:COMPATIBILITY_OUTPUT
$logs = Join-Path $output 'logs'
New-Item -ItemType Directory -Force $logs | Out-Null
Start-Transcript -Path (Join-Path $logs 'windows.log') -Force
function Assert-Same([string]$Original, [string]$Extracted) {
  if ((Get-FileHash $Original).Hash -ne (Get-FileHash $Extracted).Hash) { throw "Payload differs: $Extracted" }
}
function Run-MSI([string]$Arguments) {
  $process = Start-Process msiexec.exe -Wait -PassThru -ArgumentList $Arguments
  if ($process.ExitCode -ne 0) { throw "Windows Installer failed: $($process.ExitCode)" }
}
$fixture = Join-Path $output 'fixture'
$work = Join-Path $env:TEMP ('msi-compat-' + [guid]::NewGuid())
New-Item -ItemType Directory $work | Out-Null
$msi = Join-Path $fixture 'compat.msi'
try {
  go run ./internal/compatfixture $fixture
  if ($LASTEXITCODE -ne 0) { throw 'Fixture generator failed' }
  $iceLog = Join-Path $logs 'ice-validation.log'
  if (Test-Path $iceLog) { Remove-Item $iceLog }
  & $env:UPB_MSIVAL2 $msi $env:UPB_DARICE_CUB -f -l $iceLog
  if ($LASTEXITCODE -ne 0) { throw 'Full Microsoft Darice ICE validation failed' }
  if (-not (Test-Path $iceLog)) { throw 'ICE report missing' }
  if ((Get-Content $iceLog -Raw) -match '(?im)(\bICE\d+\b[^\r\n]*\bError\b|\bError\b[^\r\n]*\bICE\d+\b)') { throw 'ICE errors; see report' }
  $admin = Join-Path $work 'admin'
  Run-MSI "/a `"$msi`" /qn /norestart TARGETDIR=`"$admin`" /L*V `"$(Join-Path $logs 'admin.log')`""
  foreach ($name in @('compat.exe', 'message.txt')) {
    $found = @(Get-ChildItem $admin -Filter $name -Recurse)
    if ($found.Count -ne 1) { throw "Expected one $name from administrative extraction" }
    Assert-Same (Join-Path $fixture "payload\$name") $found[0].FullName
  }
  $installed = Join-Path $work 'installed'
  Run-MSI "/i `"$msi`" /qn /norestart INSTALLFOLDER=`"$installed`" /L*V `"$(Join-Path $logs 'install.log')`""
  foreach ($name in @('compat.exe', 'message.txt')) { Assert-Same (Join-Path $fixture "payload\$name") (Join-Path $installed $name) }
  if ((& (Join-Path $installed 'compat.exe')).Trim() -ne 'MSI_COMPATIBILITY_OK') { throw 'Installed executable failed' }
  Run-MSI "/x `"$msi`" /qn /norestart /L*V `"$(Join-Path $logs 'uninstall.log')`""
  if (Test-Path (Join-Path $installed 'compat.exe')) { throw 'Uninstall left executable behind' }
  $bytes = [System.IO.File]::ReadAllBytes($msi)
  $corrupt = Join-Path $work 'corrupt.msi'
  [System.IO.File]::WriteAllBytes($corrupt, $bytes[0..31])
  $process = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/a `"$corrupt`" /qn /norestart TARGETDIR=`"$(Join-Path $work 'bad')`" /L*V `"$(Join-Path $logs 'corruption-negative.log')`""
  if ($process.ExitCode -eq 0) { throw 'Windows Installer accepted a truncated MSI' }
  'MSI_OFFICIAL_COMPATIBILITY_OK'
} finally {
  if (Test-Path $msi) { Start-Process msiexec.exe -Wait -ArgumentList "/x `"$msi`" /qn /norestart" | Out-Null }
  Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
  Stop-Transcript
}
