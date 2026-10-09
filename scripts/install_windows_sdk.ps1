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
# The SDK ships the validation tools as a separate MSI, rather than installing
# msival2.exe directly into the Kits tree. Install the package from this SDK
# version and keep its tools in an isolated administrative image.
$msivalPackage = Join-Path $sdkRoot 'bin\10.0.26100.0\x86\MsiVal2-x86_en-us.msi'
if (-not (Test-Path $msivalPackage)) { throw "SDK MsiVal2 installer missing: $msivalPackage" }
# Orca supplies the COM validation engine used by MsiVal2. Install both packages
# from the pinned SDK so the executable and registered engine stay in sync.
$orcaPackage = Join-Path $sdkRoot 'bin\10.0.26100.0\x86\Orca-x86_en-us.msi'
foreach ($package in @($msivalPackage, $orcaPackage)) {
  if (-not (Test-Path $package)) { throw "SDK validation package missing: $package" }
  $installLog = Join-Path $logs (([System.IO.Path]::GetFileNameWithoutExtension($package)) + '-install.log')
  $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/i `"$package`" /qn /norestart /L*V `"$installLog`""
  if ($p.ExitCode -notin @(0, 3010)) { throw "SDK validation package installation failed: $package ($($p.ExitCode))" }
}
# Probe the 32-bit COM registration in the same architecture as MsiVal2.
# Preserve the HRESULT so a setup failure cannot masquerade as an ICE failure.
$comProbe = @'
try {
  # EvalCom2 exposes C/C++ interfaces; the SDK registers its documented CLSID,
  # without a top-level automation ProgID mapping.
  $type = [Type]::GetTypeFromCLSID([guid]'{6E5E1910-8053-4660-B795-6B612E29BC58}', $true)
  $engine = [Activator]::CreateInstance($type)
  [Runtime.InteropServices.Marshal]::ReleaseComObject($engine) | Out-Null
  'EVALCOM2_READY'
} catch {
  $cause = $_.Exception.GetBaseException()
  Write-Error ("EvalCom2 activation failed: {0} (HRESULT 0x{1:X8})" -f $cause.Message, $cause.HResult)
  exit 1
}
'@
$encodedProbe = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($comProbe))
& "$env:WINDIR\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Sta -EncodedCommand $encodedProbe 2>&1 | Tee-Object -FilePath (Join-Path $logs 'evalcom2-preflight.log')
if ($LASTEXITCODE -ne 0) { throw '32-bit EvalCom2 activation failed; see preflight log' }
$msivalRoot = Join-Path $tools 'msival2'
$msivalExtractLog = Join-Path $logs 'msival2-extract.log'
$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList "/a `"$msivalPackage`" /qn /norestart TARGETDIR=`"$msivalRoot`" /L*V `"$msivalExtractLog`""
if ($p.ExitCode -notin @(0, 3010)) { throw "MsiVal2 extraction failed: $($p.ExitCode)" }
$msival = @(Get-ChildItem $msivalRoot -Filter msival2.exe -Recurse)
$darice = @(Get-ChildItem $msivalRoot -Filter darice.cub -Recurse)
if ($msival.Count -ne 1 -or $darice.Count -ne 1) { throw 'MsiVal2 package must provide exactly one msival2.exe and Darice.cub; official ICE validation is required' }
$msival = $msival[0]
$darice = $darice[0]
$env:UPB_MSIVAL2 = $msival.FullName
$env:UPB_DARICE_CUB = $darice.FullName
Get-FileHash $msivalPackage, $orcaPackage, $msival.FullName, $darice.FullName | Format-Table | Out-File (Join-Path $logs 'ice-tools.txt')
if ($env:GITHUB_ENV) {
  "UPB_MSIVAL2=$($msival.FullName)" | Out-File $env:GITHUB_ENV -Append -Encoding utf8
  "UPB_DARICE_CUB=$($darice.FullName)" | Out-File $env:GITHUB_ENV -Append -Encoding utf8
  $sdkBin | Out-File $env:GITHUB_PATH -Append -Encoding utf8
}
} finally {
  Stop-Transcript
}
