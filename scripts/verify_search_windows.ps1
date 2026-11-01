$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ice_reports.ps1')
$fixture = Join-Path $env:COMPATIBILITY_OUTPUT 'appsearch'
New-Item -ItemType Directory -Force $fixture | Out-Null
Start-Transcript -Path (Join-Path $fixture 'native-proof.log') -Force
$installer = New-Object -ComObject WindowsInstaller.Installer
$registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry32)
$manifest = $null
function Get-SavedPath {
  $key = $registry.OpenSubKey($manifest.registry)
  if ($null -eq $key) { return $null }
  try { return $key.GetValue('InstallFolder') } finally { $key.Dispose() }
}
function Assert-Path([string]$Actual, [string]$Expected) {
  if ([string]::IsNullOrEmpty($Actual) -or $Actual.TrimEnd([char]92) -ine $Expected.TrimEnd([char]92)) {
    throw "Expected path [$Expected], got [$Actual]"
  }
}
function Run-MSI([string]$Operation, [int]$Version, [string]$LogName, [string]$Override = '') {
  $package = Join-Path $fixture "v$Version.msi"
  $log = Join-Path $fixture "$LogName.log"
  $arguments = "/$Operation `"$package`" /qn /norestart /L*V `"$log`""
  if ($Override) { $arguments += " INSTALLFOLDER=`"$Override`"" }
  $p = Start-Process msiexec.exe -ArgumentList $arguments -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "$LogName failed: msiexec exit $($p.ExitCode); see $log" }
  $text = Get-Content $log -Raw
  if ($text -notmatch '(?m)^Action ended [^\r\n]*AppSearch\. Return value 1\.') { throw "$LogName did not complete AppSearch" }
  if ($text -match 'Unknown table.*Signature|Note: 1: 2228') { throw "$LogName contains an unknown table error" }
  $appSearch = [regex]::Match($text, '(?m)^Action start [^\r\n]*: AppSearch\.').Index
  $costing = [regex]::Match($text, '(?m)^Action start [^\r\n]*: CostInitialize\.')
  if (-not $costing.Success -or $appSearch -ge $costing.Index) { throw "$LogName AppSearch did not precede costing" }
  if (-not $Override -and $text -match 'PROPERTY CHANGE: Adding SAVED_PATH property') {
    $recovery = [regex]::Match($text, '(?m)^Action start [^\r\n]*: RestoreSavedFolderInstallExecuteSequence\.')
    if (-not $recovery.Success -or $recovery.Index -ge $costing.Index) { throw "$LogName saved path was not restored before costing" }
  }
}
function Assert-Installed([int]$Version, [string]$Target) {
  $payload = Join-Path $Target 'payload.txt'
  if (-not (Test-Path -LiteralPath $payload) -or [IO.File]::ReadAllText($payload) -cne "$Version.0.0") { throw "Missing/changed v$Version payload at $Target" }
  Assert-Path (Get-SavedPath) $Target
  $products = @($installer.RelatedProducts($manifest.upgrade))
  if ($products.Count -ne 1 -or $products[0] -ne $manifest.codes[$Version - 1]) { throw "Expected exactly one v$Version product, got $products" }
}
function Assert-Removed([string]$Target) {
  if (Test-Path -LiteralPath (Join-Path $Target 'payload.txt')) { throw "Uninstall left payload at $Target" }
  if ($null -ne (Get-SavedPath)) { throw 'Uninstall left saved registry value' }
  if (@($installer.RelatedProducts($manifest.upgrade)).Count -ne 0) { throw 'Uninstall left registered products' }
}
try {
  go run ./internal/searchfixture $fixture
  if ($LASTEXITCODE -ne 0) { throw 'Raw AppSearch fixture generator failed' }
  $manifest = Get-Content (Join-Path $fixture 'manifest.json') -Raw | ConvertFrom-Json
  if ($null -ne (Get-SavedPath) -or @($installer.RelatedProducts($manifest.upgrade)).Count -ne 0) { throw 'Raw AppSearch proof requires a fresh fixture state' }
  foreach ($version in @(1, 2)) {
    $package = Join-Path $fixture "v$version.msi"
    $db = $installer.OpenDatabase($package, 0)
    # Native SQL proves both the complete schema and zero rows exist on disk.
    $view = $db.OpenView('SELECT `Signature`, `FileName`, `MinVersion`, `MaxVersion`, `MinSize`, `MaxSize`, `MinDate`, `MaxDate`, `Languages` FROM `Signature`')
    $view.Execute()
    if ($null -ne $view.Fetch()) { throw 'Raw search fixture contains a fake file signature' }
    $view.Close()
    $iceLog = Join-Path $fixture "v$version-ice.log"
    & $env:UPB_MSIVAL2 $package $env:UPB_DARICE_CUB -f -l $iceLog
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $iceLog)) { throw "v$version full Darice failed" }
    if (-not [string]::IsNullOrEmpty((Read-IceReport $iceLog))) { throw "v$version Darice report is not clean" }
  }
  Write-Host 'NATIVE_APPSEARCH_EMPTY_SIGNATURE_SCHEMA_FULL_DARICE_OK'

  $default = Join-Path ${env:ProgramFiles(x86)} $manifest.directory
  if (Test-Path -LiteralPath $default) { throw 'Default target already exists' }
  Run-MSI 'i' 1 'fresh-no-value'
  Assert-Installed 1 $default
  Run-MSI 'x' 1 'fresh-recovered-uninstall'
  Assert-Removed $default
  Write-Host 'NATIVE_APPSEARCH_FRESH_NO_VALUE_INSTALL_RECOVERED_UNINSTALL_OK'

  $existing = Join-Path $fixture 'existing-value'
  New-Item -ItemType Directory -Force $existing | Out-Null
  $key = $registry.CreateSubKey($manifest.registry)
  try { $key.SetValue('InstallFolder', $existing, [Microsoft.Win32.RegistryValueKind]::String) } finally { $key.Dispose() }
  Run-MSI 'i' 1 'existing-value-install'
  Assert-Installed 1 $existing
  if (Test-Path -LiteralPath (Join-Path $default 'payload.txt')) { throw 'Raw lookup ignored saved directory' }
  Run-MSI 'x' 1 'existing-value-recovered-uninstall'
  Assert-Removed $existing
  Write-Host 'NATIVE_APPSEARCH_EXISTING_RAW_VALUE_INSTALL_RECOVERED_UNINSTALL_OK'

  $redirected = Join-Path $fixture 'redirected'
  Run-MSI 'i' 1 'redirected-v1-install' $redirected
  Assert-Installed 1 $redirected
  Run-MSI 'i' 2 'redirected-v2-upgrade-no-property'
  Assert-Installed 2 $redirected
  if ($installer.ProductState($manifest.codes[0]) -ne -1) { throw 'Upgrade left v1 registered' }
  Run-MSI 'x' 2 'redirected-v2-recovered-uninstall'
  Assert-Removed $redirected
  Write-Host 'NATIVE_APPSEARCH_REDIRECTED_MAJOR_UPGRADE_NO_REPEATED_PROPERTY_OK'

  $oldTarget = Join-Path $fixture 'override-old'
  $newTarget = Join-Path $fixture 'override-new'
  Run-MSI 'i' 1 'override-v1-install' $oldTarget
  Assert-Installed 1 $oldTarget
  Run-MSI 'i' 2 'override-v2-upgrade' $newTarget
  Assert-Installed 2 $newTarget
  if (Test-Path -LiteralPath (Join-Path $oldTarget 'payload.txt')) { throw 'Override upgrade left old payload' }
  Run-MSI 'x' 2 'override-v2-recovered-uninstall'
  Assert-Removed $newTarget
  Write-Host 'NATIVE_APPSEARCH_EXPLICIT_OVERRIDE_PRECEDENCE_RECOVERED_UNINSTALL_OK'
  Write-Host 'GO_MSI_APPSEARCH_NATIVE_REGRESSIONS_OK'
} finally {
  if ($null -ne $manifest) {
    foreach ($code in $manifest.codes) {
      if ($installer.ProductState($code) -ne -1) { Start-Process msiexec.exe -ArgumentList "/x $code /qn /norestart" -Wait | Out-Null }
    }
    $registry.DeleteSubKeyTree($manifest.registry, $false)
  }
  $registry.Dispose()
  Stop-Transcript
}
