$ErrorActionPreference = 'Stop'
$tools = Join-Path $env:CI_PROJECT_DIR '.tools'
$logs = Join-Path $env:COMPATIBILITY_OUTPUT 'logs'
New-Item -ItemType Directory -Force $tools, $logs | Out-Null
Start-Transcript -Path (Join-Path $logs 'windows-sdk-provisioning.log') -Force
try {
# Official Windows SDK 10.0.26100.9457 immutable installer, linked by Microsoft's SDK download table.
$sdkSetup = Join-Path $tools 'winsdksetup.exe'
Invoke-WebRequest 'https://download.microsoft.com/download/46742ab5-6592-4968-a793-129e7f3bc55a/KIT_BUNDLE_WINDOWSSDK_MEDIACREATION/winsdksetup.exe' -OutFile $sdkSetup
if ((Get-FileHash $sdkSetup -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'b0bdbad38ae74c40ccae8cdbcf229807627fba2bc3100be28301c4ba884f755e') { throw 'SDK installer checksum mismatch' }
if ((Get-AuthenticodeSignature $sdkSetup).Status -ne 'Valid') { throw 'SDK installer Authenticode signature is invalid' }
$sdkLog = Join-Path $logs 'sdk-install.log'
$p = Start-Process $sdkSetup -Wait -PassThru -ArgumentList "/quiet /norestart /features OptionId.MSIInstallTools OptionId.SigningTools OptionId.UWPManaged /log `"$sdkLog`""
if ($p.ExitCode -notin @(0, 3010)) { throw "SDK installation failed: $($p.ExitCode)" }
$sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
# Require the versioned packaging tools; never silently select an older installed SDK.
$sdkBin = Join-Path $sdkRoot 'bin\10.0.26100.0\x64'
foreach ($tool in @('makeappx.exe', 'signtool.exe')) {
  $path = Join-Path $sdkBin $tool
  if (-not (Test-Path $path)) { throw "Required SDK tool missing: $path" }
  (Get-Item $path).VersionInfo | Format-List | Out-File (Join-Path $logs "$tool-version.txt")
}
$env:PATH = $sdkBin + ';' + $env:PATH
# Installer validation tools are sometimes outside the versioned packaging-tools directory.
$msival = Get-ChildItem $sdkRoot -Filter msival2.exe -Recurse | Where-Object { $_.FullName -notmatch '\\(arm|arm64)\\' } | Select-Object -First 1
$darice = Get-ChildItem $sdkRoot -Filter darice.cub -Recurse | Select-Object -First 1
if (-not $msival -or -not $darice) { throw 'Windows Installer SDK installation did not provide msival2.exe and Darice.cub; official ICE validation is required' }
$env:UPB_MSIVAL2 = $msival.FullName
$env:UPB_DARICE_CUB = $darice.FullName
Get-FileHash $msival.FullName, $darice.FullName | Format-Table | Out-File (Join-Path $logs 'ice-tools.txt')
if ($env:GITHUB_ENV) {
  "UPB_MSIVAL2=$($msival.FullName)" | Out-File $env:GITHUB_ENV -Append -Encoding utf8
  "UPB_DARICE_CUB=$($darice.FullName)" | Out-File $env:GITHUB_ENV -Append -Encoding utf8
  $sdkBin | Out-File $env:GITHUB_PATH -Append -Encoding utf8
}
} finally {
  Stop-Transcript
}
