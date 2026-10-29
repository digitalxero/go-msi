$ErrorActionPreference = 'Stop'
$fixture = Join-Path $env:COMPATIBILITY_OUTPUT 'regressions'
New-Item -ItemType Directory -Force $fixture | Out-Null
Start-Transcript -Path (Join-Path $fixture 'native-proof.log') -Force
$userName = 'msitest' + [guid]::NewGuid().ToString('N').Substring(0, 10)
$createdUser = $false
$installer = New-Object -ComObject WindowsInstaller.Installer
function Run-MSI([string]$Arguments) {
  $process = Start-Process msiexec.exe -ArgumentList $Arguments -Wait -PassThru
  return $process.ExitCode
}
function Assert-Product([string]$Kind) {
  $expected = $manifest.$Kind
  $products = @($installer.RelatedProducts($expected.upgrade))
  if ($products.Count -ne 1 -or $products[0] -ne $expected.code) { throw "Expected exactly one $Kind product, got $products" }
  if ($installer.ProductInfo($expected.code, 'ProductName') -cne $expected.product) { throw 'Installed product name changed' }
  if ($installer.ProductInfo($expected.code, 'Publisher') -cne $expected.manufacturer) { throw 'Installed manufacturer changed' }
  $executable = Join-Path $target 'app.exe'
  if ((Get-FileHash $executable).Hash -ne (Get-FileHash (Join-Path $fixture "$Kind.exe")).Hash) { throw "$Kind executable bytes changed" }
  if ((& $executable).Trim() -ne $expected.payload) { throw "$Kind executable payload changed" }
}
try {
  go run ./internal/regressionfixture $fixture
  if ($LASTEXITCODE -ne 0) { throw 'Regression fixture generator failed' }
  $manifest = Get-Content (Join-Path $fixture 'manifest.json') -Encoding UTF8 -Raw | ConvertFrom-Json
  foreach ($kind in @('newer', 'blocked', 'allowed', 'user')) {
    $package = Join-Path $fixture "$kind.msi"
    $summary = $installer.SummaryInformation($package, 0)
    if (([int]$summary.Property(1) -band 0xffff) -ne 65001) { throw "$kind summary codepage differs" }
    if ($summary.Property(3) -cne $manifest.$kind.product) { throw "$kind Unicode Subject changed" }
    if ($summary.Property(4) -cne $manifest.$kind.manufacturer) { throw "$kind Unicode Author changed" }
    $wordCount = if ($kind -eq 'user') { 10 } else { 2 }
    if ([int]$summary.Property(15) -ne $wordCount) { throw "$kind summary privilege bits differ" }
    $iceLog = Join-Path $fixture "$kind-ice.log"
    & $env:UPB_MSIVAL2 $package $env:UPB_DARICE_CUB -f -l $iceLog
    if ($LASTEXITCODE -ne 0) { throw "$kind Darice validation failed" }
    if (-not (Test-Path $iceLog)) { throw "$kind ICE report missing" }
    if ((Get-Content $iceLog -Raw) -match '(?im)(\bICE\d+\b[^\r\n]*\bError\b|\bError\b[^\r\n]*\bICE\d+\b)') { throw "$kind ICE errors" }
  }
  $target = Join-Path $fixture 'machine-install'
  $newer = Join-Path $fixture 'newer.msi'
  $blocked = Join-Path $fixture 'blocked.msi'
  $allowed = Join-Path $fixture 'allowed.msi'
  $rc = Run-MSI "/i `"$newer`" /qn /norestart INSTALLFOLDER=`"$target`" /L*V `"$fixture\newer-install.log`""
  if ($rc -ne 0) { throw "Newer install failed: $rc" }
  Assert-Product 'newer'
  $before = (Get-FileHash (Join-Path $target 'app.exe')).Hash
  $rc = Run-MSI "/i `"$blocked`" /qn /norestart INSTALLFOLDER=`"$target`" /L*V `"$fixture\blocked-install.log`""
  if ($rc -ne 1603) { throw "Expected default silent downgrade rejection (1603), got $rc" }
  Assert-Product 'newer'
  if ((Get-FileHash (Join-Path $target 'app.exe')).Hash -ne $before) { throw 'Rejected downgrade changed NEWER executable' }
  Write-Host 'SILENT_DOWNGRADE_REJECTED_ONE_PRODUCT_UNCHANGED_NEWER_OK'
  $rc = Run-MSI "/i `"$allowed`" /qn /norestart INSTALLFOLDER=`"$target`" /L*V `"$fixture\allowed-install.log`""
  if ($rc -ne 0) { throw "Explicitly allowed downgrade failed: $rc" }
  Assert-Product 'allowed'
  $rc = Run-MSI "/x `"$allowed`" /qn /norestart /L*V `"$fixture\machine-remove.log`""
  if ($rc -ne 0) { throw "Machine removal failed: $rc" }
  if (@($installer.RelatedProducts($manifest.allowed.upgrade)).Count -ne 0) { throw 'Machine product remains' }
  if (Test-Path (Join-Path $target 'app.exe')) { throw 'Machine executable remains' }
  Write-Host 'EXPLICIT_DOWNGRADE_AND_UNICODE_INSTALL_REMOVE_OK'

  # A fresh local account has neither an administrator token nor membership.
  # Test files live outside runner-private TEMP, and this account can only
  # modify this disposable proof directory. No runas/elevation verb is used.
  $userFixture = Join-Path $env:PUBLIC ('msi-user-' + [guid]::NewGuid())
  New-Item -ItemType Directory $userFixture | Out-Null
  Copy-Item "$fixture\user.msi", "$fixture\user.exe", "$fixture\manifest.json", "$PSScriptRoot\verify_regressions_user.ps1" $userFixture
  $password = ConvertTo-SecureString ('Msi!9a' + [guid]::NewGuid().ToString('N')) -AsPlainText -Force
  New-LocalUser -Name $userName -Password $password -AccountNeverExpires | Out-Null
  $createdUser = $true
  $user = Get-LocalUser $userName
  if (@(Get-LocalGroupMember -SID 'S-1-5-32-545').SID.Value -notcontains $user.SID.Value) { Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user }
  if (@(Get-LocalGroupMember -SID 'S-1-5-32-544').SID.Value -contains $user.SID.Value) { throw 'Test account is an administrator' }
  & icacls.exe $userFixture /grant "*$($user.SID.Value):(OI)(CI)M"
  if ($LASTEXITCODE -ne 0) { throw 'Test account cannot access proof files' }
  $credential = [pscredential]::new("$env:COMPUTERNAME\$userName", $password)
  $powershell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
  $process = Start-Process $powershell -Credential $credential -LoadUserProfile -WorkingDirectory $userFixture -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$userFixture\verify_regressions_user.ps1`" -Fixture `"$userFixture`"" -Wait -PassThru
  Copy-Item "$userFixture\*.log" $fixture -ErrorAction Continue
  if ($process.ExitCode -ne 0) { throw "Non-admin proof process failed: $($process.ExitCode)" }
  if ((Get-Content "$fixture\user-proof.log" -Raw) -notmatch 'STANDARD_USER_INSTALL_REMOVE_OK') { throw 'Non-admin success receipt missing' }
  Write-Host 'GO_MSI_UPSTREAM_REGRESSIONS_OK'
} finally {
  if ($createdUser) { Remove-LocalUser -Name $userName }
  Stop-Transcript
}
