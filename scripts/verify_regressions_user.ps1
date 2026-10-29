param([Parameter(Mandatory)][string]$Fixture)
$ErrorActionPreference = 'Stop'
$log = Join-Path $Fixture 'user-proof.log'
Start-Transcript -Path $log -Force
function Get-SHA256([string]$Path) {
  $stream = [IO.File]::OpenRead($Path)
  $hash = [Security.Cryptography.SHA256]::Create()
  try { return [BitConverter]::ToString($hash.ComputeHash($stream)) }
  finally { $hash.Dispose(); $stream.Dispose() }
}
try {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'User process is elevated' }
  if (@($identity.Groups.Value) -contains 'S-1-5-32-544') { throw 'User belongs to Administrators' }
  if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA -ne 1) { throw 'UAC must be enabled' }
  foreach ($root in @('HKLM:', 'HKCU:')) {
    $policy = Get-ItemProperty "$root\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
    if ($policy.AlwaysInstallElevated -eq 1) { throw 'AlwaysInstallElevated would invalidate proof' }
  }
  # CreateProcessWithLogonW preserves the parent's environment. Resolve the
  # freshly loaded profile by this token's SID instead of inheriting runneradmin.
  $profile = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($identity.User.Value)").ProfileImagePath
  $profile = [Environment]::ExpandEnvironmentVariables($profile)
  if (-not (Test-Path $profile)) { throw 'Standard-user profile was not loaded' }
  $env:PSModulePath = "$profile\Documents\WindowsPowerShell\Modules;" + [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine') + ";$PSHOME\Modules"
  $env:USERPROFILE = $profile
  $env:LOCALAPPDATA = Join-Path $profile 'AppData\Local'
  $env:APPDATA = Join-Path $profile 'AppData\Roaming'
  $env:TEMP = Join-Path $env:LOCALAPPDATA 'Temp'
  $env:TMP = $env:TEMP
  if ((Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\Installer').DisableMSI -ne 0) { throw 'Disposable runner must allow ordinary per-user MSI installation' }
  Write-Host "STANDARD_USER_TOKEN sid=$($identity.User.Value) profile=$profile elevated=False administratorMember=False"
  $manifest = Get-Content (Join-Path $Fixture 'manifest.json') -Encoding UTF8 -Raw | ConvertFrom-Json
  $expected = $manifest.user
  $installer = New-Object -ComObject WindowsInstaller.Installer
  $package = Join-Path $Fixture 'user.msi'
  $summary = $installer.SummaryInformation($package, 0)
  if ([int]$summary.Property(15) -ne 10) { throw 'Persisted user summary must be 2|8' }
  $target = Join-Path $env:LOCALAPPDATA 'MSI Regression'
  $installLog = Join-Path $Fixture 'user-install.log'
  $removeLog = Join-Path $Fixture 'user-remove.log'
  $process = Start-Process msiexec.exe -ArgumentList "/i `"$package`" /qn /norestart INSTALLFOLDER=`"$target`" /L*V `"$installLog`"" -Wait -PassThru
  if ($process.ExitCode -ne 0) { throw "Standard-user install failed: $($process.ExitCode)" }
  $products = @($installer.RelatedProducts($expected.upgrade))
  if ($products.Count -ne 1 -or $products[0] -ne $expected.code) { throw 'Expected exactly one per-user product' }
  if ($installer.ProductInfo($expected.code, 'ProductName') -cne $expected.product) { throw 'Installed Unicode product name changed' }
  if ($installer.ProductInfo($expected.code, 'Publisher') -cne $expected.manufacturer) { throw 'Installed Unicode manufacturer changed' }
  $executable = Join-Path $target 'app.exe'
  if ((Get-SHA256 $executable) -ne (Get-SHA256 (Join-Path $Fixture 'user.exe'))) { throw 'Per-user executable differs' }
  if ((& $executable).Trim() -ne 'OLDER') { throw 'Per-user executable did not run' }
  $marker = Join-Path $target 'ca.txt'
  if ((Get-Content $marker -Raw).Trim() -ne $identity.User.Value) { throw 'NoImpersonate action did not run as the standard user' }
  if ((Get-ItemProperty 'HKCU:\Software\GoMSIRegression').Installed -ne '1') { throw 'HKCU resource was not installed' }
  # This fixture uses a runtime INSTALLFOLDER override and a registry KeyPath;
  # maintenance must receive that same override instead of the TARGETDIR default.
  $process = Start-Process msiexec.exe -ArgumentList "/x `"$package`" /qn /norestart INSTALLFOLDER=`"$target`" /L*V `"$removeLog`"" -Wait -PassThru
  if ($process.ExitCode -ne 0) { throw "Standard-user removal failed: $($process.ExitCode)" }
  if (@($installer.RelatedProducts($expected.upgrade)).Count -ne 0) { throw 'Per-user product remains registered' }
  if (Test-Path $executable) { throw 'Per-user executable remains after removal' }
  if (Get-ItemProperty 'HKCU:\Software\GoMSIRegression' -Name Installed -ErrorAction SilentlyContinue) { throw 'HKCU resource remains' }
  Write-Host "STANDARD_USER_INSTALL_REMOVE_OK sid=$($identity.User.Value) NoImpersonateSid=$(Get-Content $marker -Raw)"
} catch {
  Write-Host ($_ | Out-String)
  throw
} finally {
  Stop-Transcript
}
