$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ice_reports.ps1')
$fixture = Join-Path $env:COMPATIBILITY_OUTPUT 'authoring'
New-Item -ItemType Directory -Force $fixture | Out-Null
Start-Transcript -Path (Join-Path $fixture 'native-proof.log') -Force
$installer = New-Object -ComObject WindowsInstaller.Installer
$scenarioFailures = [Collections.Generic.List[string]]::new()
function Invoke-Scenario([string]$Name, [scriptblock]$Work) {
  try { & $Work } catch {
    $scenarioFailures.Add("$Name : $($_.Exception.Message)")
    Write-Host "NATIVE_SCENARIO_FAILED $Name`n$($_ | Out-String)"
  }
}
function Run-MSI([string]$Arguments) {
  $p = Start-Process msiexec.exe -ArgumentList $Arguments -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "msiexec failed ($($p.ExitCode)): $Arguments" }
}
function Assert-Payload([string]$Path, [string]$Expected) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing payload: $Path" }
  if ([IO.File]::ReadAllText($Path) -cne $Expected) { throw "Changed payload: $Path" }
}
function Assert-Unregistered([string]$Code) {
  if ($installer.ProductState($Code) -ne -1) { throw "Product still registered: $Code" }
}
function Save-Dialog([IntPtr]$Window, [string]$Name) {
  $contents = [NativeMsiUI]::Contents($Window)
  $contents | Out-File (Join-Path $fixture "$Name.txt") -Encoding utf8
  Write-Host "$Name`n$contents"
  $r = [NativeMsiUI]::Bounds($Window)
  $bitmap = [Drawing.Bitmap]::new($r.Right - $r.Left, $r.Bottom - $r.Top)
  $graphics = [Drawing.Graphics]::FromImage($bitmap)
  $dc = $graphics.GetHdc()
  try {
    if (-not [NativeMsiUI]::Capture($Window, $dc)) { throw 'PrintWindow failed' }
  } finally { $graphics.ReleaseHdc($dc); $graphics.Dispose() }
  try { $bitmap.Save((Join-Path $fixture "$Name.png"), [Drawing.Imaging.ImageFormat]::Png) } finally { $bitmap.Dispose() }
}
function Wait-Dialog([string]$Title, [string]$Content) {
  $deadline = [datetime]::UtcNow.AddSeconds(60)
  do {
    $w = [NativeMsiUI]::Find($Title)
    if ($w -ne [IntPtr]::Zero -and [NativeMsiUI]::Contents($w).Contains($Content)) { return $w }
    Start-Sleep -Milliseconds 100
  } while ([datetime]::UtcNow -lt $deadline)
  if ($w -ne [IntPtr]::Zero) { Save-Dialog $w 'unexpected-dialog' }
  throw "Native dialog did not reach: $Title / $Content"
}
function Click-Dialog([IntPtr]$Window, [string]$Caption) {
  if (-not [NativeMsiUI]::Click($Window,$Caption)) { throw "Native button not enabled/found: $Caption" }
  Start-Sleep -Milliseconds 300
}
function Run-Wizard([string]$Kind, [string]$Mode) {
  $package = Join-Path $fixture "$Kind/package.msi"
  $target = Join-Path $fixture "$Mode-install"
  $title = "Go MSI $Kind Setup"
  $log = Join-Path $fixture "$Mode-ui.log"
  # /qf is the real authored full UI. /qn and MsiSetExternalUI are not used.
  $p = Start-Process msiexec.exe -ArgumentList "/i `"$package`" /qf /norestart INSTALLFOLDER=`"$target`" /L*V `"$log`"" -PassThru
  try {
    $w = Wait-Dialog $title 'Native UI regression license'
    Save-Dialog $w "$Mode-welcome"
    if ($Mode -eq 'cancel-welcome') {
      Click-Dialog $w 'Cancel'
    } else {
      # Before acceptance Install must not advance. Click it and prove the
      # welcome screen remains, then accept and invoke the same control.
      Click-Dialog $w 'Install'
      $w = Wait-Dialog $title 'Native UI regression license'
      Click-Dialog $w 'I accept the terms in the license agreement'
      Click-Dialog $w 'Install'
      $w = Wait-Dialog $title "Installing Go MSI $Kind"
      Save-Dialog $w "$Mode-progress"
      if ($Mode -eq 'cancel-progress' -or $Mode -eq 'success') {
        Click-Dialog $w 'Cancel'
        $confirmation = Wait-Dialog $title 'Are you sure you want to cancel setup?'
        Save-Dialog $confirmation "$Mode-cancel-confirmation"
        if ($Mode -eq 'success') {
          Click-Dialog $confirmation 'No'
          $w = Wait-Dialog $title "Installing Go MSI $Kind"
          Save-Dialog $w 'success-continued-after-cancel-no'
        } else { Click-Dialog $confirmation 'Yes' }
      }
    }
    $terminal = switch ($Mode) {
      'success' { "Completed the Go MSI $Kind Setup" }
      'error' { "Go MSI $Kind Setup ended prematurely" }
      default { "Go MSI $Kind Setup was interrupted" }
    }
    if ($Mode -eq 'error') {
      # The authored type-19 action displays an engine error message first.
      $messageTitle = "Go MSI $Kind"
      $message = Wait-Dialog $messageTitle 'Intentional native UI regression failure'
      Save-Dialog $message 'error-message'
      Click-Dialog $message 'OK'
    }
    $w = Wait-Dialog $title $terminal
    Save-Dialog $w "$Mode-terminal"
    Click-Dialog $w 'Finish'
    if (-not $p.WaitForExit(30000)) { throw 'Wizard failed to exit after Finish' }
    $p.Refresh()
    $expected = if ($Mode -eq 'success') { 0 } elseif ($Mode -eq 'error') { 1603 } else { 1602 }
    if ($p.ExitCode -ne $expected) { throw "$Mode exit $($p.ExitCode), expected $expected" }
    $text = Get-Content $log -Raw
    if ($Mode -ne 'cancel-welcome' -and $text -notmatch 'Action start .*ExecuteAction') { throw 'ExecuteAction never ran' }
    if ($Mode -eq 'success') {
      Assert-Payload (Join-Path $target 'payload.txt') $Kind
      Run-MSI "/x `"$package`" /qn /norestart /L*V `"$fixture\ui-remove.log`""
    }
    Assert-Unregistered $manifest.$Kind.code
    if (Test-Path (Join-Path $target 'payload.txt')) { throw "$Mode left payload behind" }
    Write-Host "NATIVE_FULL_UI_$($Mode.ToUpper().Replace('-','_'))_OK"
  } finally {
    if (-not $p.HasExited) {
      # Close only this job's wizard. Keep failure logs and screenshots.
      $w = [NativeMsiUI]::Find($title)
      if ($w -ne [IntPtr]::Zero) { [void][NativeMsiUI]::Click($w,'Cancel'); [void][NativeMsiUI]::Click($w,'Finish') }
      if (-not $p.WaitForExit(10000)) { $p.Kill() }
    }
    if ($installer.ProductState($manifest.$Kind.code) -ne -1) {
      Start-Process msiexec.exe -Wait -ArgumentList "/x `"$package`" /qn /norestart" | Out-Null
    }
  }
}
# The pinned SDK's ICE30 fails on lowercase accented names, even after native
# re-encoding. A native case-only copy passes. Audit that exact transformation,
# validate every ICE on it, and prove ICE30 rejects an introduced collision.
# The original package still has to install/read/remove its exact requested names.
function Edit-ControlNames([string]$Path, [bool]$Collision) {
  $database = $installer.OpenDatabase($Path,1)
  $view = $database.OpenView('SELECT `File`, `FileName` FROM `File`')
  $view.Execute()
  $names = @()
  while ($record = $view.Fetch()) {
    $names += @{ File = $record.StringData(1); Name = $record.StringData(2).ToUpperInvariant() }
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
  }
  $view.Close()
  [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
  foreach ($entry in $names) {
    $update = $database.OpenView('UPDATE `File` SET `FileName` = ? WHERE `File` = ?')
    $record = $installer.CreateRecord(2)
    $record.StringData(1) = if ($Collision) { $names[0].Name } else { $entry.Name }
    $record.StringData(2) = $entry.File
    $update.Execute($record)
    $update.Close()
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($update)
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
  }
  $database.Commit()
  [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
}
function Test-UnicodeICEControls([string]$Package, [string]$Kind) {
  $positive = Join-Path $fixture "$Kind-case-control.msi"
  Copy-Item $Package $positive
  Edit-ControlNames $positive $false
  go run ./internal/verifyicecontrol $Package $positive
  if ($LASTEXITCODE -ne 0) { throw "$Kind case-only table/Summary audit failed" }
  $positiveLog = Join-Path $fixture "$Kind-case-control-ice.log"
  & $env:UPB_MSIVAL2 $positive $env:UPB_DARICE_CUB -f -l $positiveLog
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $positiveLog)) { throw "$Kind case-control Darice failed" }
  if (-not [string]::IsNullOrEmpty((Read-IceReport $positiveLog))) { throw "$Kind case-control Darice report is not clean" }
  $negative = Join-Path $fixture "$Kind-collision-control.msi"
  Copy-Item $positive $negative
  Edit-ControlNames $negative $true
  $negativeLog = Join-Path $fixture "$Kind-collision-control-ice.log"
  & $env:UPB_MSIVAL2 $negative $env:UPB_DARICE_CUB -f -l $negativeLog
  if ($LASTEXITCODE -eq 0 -or -not (Test-Path $negativeLog)) { throw "$Kind collision control was not rejected" }
  if ((Get-Content $negativeLog -Raw -Encoding Unicode) -notmatch '(?im)^ICE30\s+ERROR\s') { throw "$Kind negative control did not detect the collision with ICE30" }
  Write-Host "NATIVE_UNICODE_ICE30_CASE_CONTROL_AND_COLLISION_REJECTION_OK $Kind"
}

try {
  $nativeBuild = Join-Path $fixture 'native-progress'
  & (Join-Path $PSScriptRoot 'build_native_progress.ps1') -OutputDirectory $nativeBuild
  go run ./internal/authoringfixture $fixture (Join-Path $nativeBuild 'NativeProgress.dll')
  if ($LASTEXITCODE -ne 0) { throw 'Authoring fixture generator failed' }
  $manifest = Get-Content (Join-Path $fixture 'manifest.json') -Raw -Encoding utf8 | ConvertFrom-Json
  $iceFailures = @()
  foreach ($kind in @('repair-a','repair-b','aliases','ui-success','ui-cancel','ui-error','names','shortcuts','names-unicode','names-dot')) {
    $package = Join-Path $fixture "$kind/package.msi"
    $summary = $installer.SummaryInformation($package,0)
    if ($summary.Property(9) -cne $manifest.$kind.packageCode) { throw "$kind PackageCode differs through native API" }
    $iceLog = Join-Path $fixture "$kind-ice.log"
    & $env:UPB_MSIVAL2 $package $env:UPB_DARICE_CUB -f -l $iceLog
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $iceLog)) { $iceFailures += "$kind Darice failed (exit $LASTEXITCODE)" }
    if (Test-Path $iceLog) {
      $report = Read-IceReport $iceLog
      $knownCaseFailure = $kind -in @('names','names-unicode') -and $report -match '^ICE30\s+UNKNOWN\s+ICE Internal Error 23\. API Returned: 259\.$'
      if ($knownCaseFailure) {
        Invoke-Scenario "$kind-ICE30-native-controls" { Test-UnicodeICEControls $package $kind }
      } elseif ($report -match '(?im)(\bICE\d+\b[^\r\n]*\bError\b|\bError\b[^\r\n]*\bICE\d+\b|ICE Internal Error)') {
        $iceFailures += "$kind ICE errors or incomplete validation"
      }
    }
  }

  Add-Type -Path (Join-Path $PSScriptRoot 'native_ui_driver.cs')
  Add-Type -AssemblyName System.Drawing
  Write-Host "Native UI session $([Diagnostics.Process]::GetCurrentProcess().SessionId), user $env:USERNAME"
  Invoke-Scenario 'ui-success' { Run-Wizard 'ui-success' 'success' }
  Invoke-Scenario 'ui-cancel-welcome' { Run-Wizard 'ui-cancel' 'cancel-welcome' }
  Invoke-Scenario 'ui-cancel-progress' { Run-Wizard 'ui-cancel' 'cancel-progress' }
  Invoke-Scenario 'ui-error' { Run-Wizard 'ui-error' 'error' }

  Invoke-Scenario 'repair' {
    $a = Join-Path $fixture 'repair-a/package.msi'
    $b = Join-Path $fixture 'repair-b/package.msi'
    $code = $manifest.'repair-a'.code
    $target = Join-Path $fixture 'repair-install'
    if ($manifest.'repair-a'.packageCode -eq $manifest.'repair-b'.packageCode) { throw 'Changed payload kept PackageCode' }
    try {
      Run-MSI "/i `"$a`" /qn /norestart INSTALLFOLDER=`"$target`" /L*V `"$fixture\repair-a-install.log`""
      Assert-Payload (Join-Path $target 'payload.txt') 'repair-a'
      Run-MSI "/i `"$b`" /qn /norestart REINSTALL=ALL REINSTALLMODE=vomus INSTALLFOLDER=`"$target`" /L*V `"$fixture\repair-b-recache.log`""
      Assert-Payload (Join-Path $target 'payload.txt') 'repair-b'
      $cached = $installer.ProductInfo($code,'LocalPackage')
      if ($installer.SummaryInformation($cached,0).Property(9) -cne $manifest.'repair-b'.packageCode) { throw 'Installer cache did not adopt new PackageCode' }
      Remove-Item (Join-Path $target 'payload.txt')
      Run-MSI "/fa $code /qn /norestart /L*V `"$fixture\repair-b-source.log`""
      Assert-Payload (Join-Path $target 'payload.txt') 'repair-b'
      Write-Host 'NATIVE_PACKAGECODE_RECACHE_SOURCE_REPAIR_OK'
    } finally { Run-MSI "/x $code /qn /norestart /L*V `"$fixture\repair-remove.log`"" }
    Assert-Unregistered $code
    if (Test-Path (Join-Path $target 'payload.txt')) { throw 'Repair uninstall left payload' }
  }

  Invoke-Scenario 'aliases' {
    $package = Join-Path $fixture 'aliases/package.msi'
    $target = Join-Path $fixture 'alias-install'
    try {
      Run-MSI "/i `"$package`" /qn /norestart SHORTFILENAMES=1 INSTALLFOLDER=`"$target`" /L*V `"$fixture\alias-install.log`""
      # Read effective short names from the emitted tables; each distinct payload
      # must survive in the shared file/directory namespace.
      foreach ($row in $manifest.aliases.files) {
        $name = $row.FileName.Split('|')[0]
        $long = $row.FileName.Split('|')[-1]
        $dir = $target
        if ($row.Component_ -eq 'Child') {
          $child = @($manifest.aliases.directories | Where-Object Directory -eq 'LongDirectory')[0].DefaultDir.Split('|')[0]
          $dir = Join-Path $target $child
        }
        Assert-Payload (Join-Path $dir $name) $manifest.aliases.payloads.$long
      }
      Write-Host 'NATIVE_SHORTFILENAMES_DISTINCT_FILES_AND_DIRECTORIES_OK'
    } finally { Run-MSI "/x `"$package`" /qn /norestart SHORTFILENAMES=1 /L*V `"$fixture\alias-remove.log`"" }
    Assert-Unregistered $manifest.aliases.code
    if (Test-Path $target) {
      if (@(Get-ChildItem $target -Recurse -File -Force).Count -ne 0) { throw "Alias uninstall left files: $(@(Get-ChildItem $target -Recurse -File -Force).FullName -join ' , ')" }
    }
  }

  foreach ($nameKind in @('names','names-unicode','names-dot')) {
    Invoke-Scenario "$nameKind-install-remove" {
      $package = Join-Path $fixture "$nameKind/package.msi"
      $target = Join-Path $fixture "$nameKind-install"
      try {
        Run-MSI "/i `"$package`" /qn /norestart INSTALLFOLDER=`"$target`" /L*V `"$fixture\$nameKind-install.log`""
        foreach ($payload in $manifest.$nameKind.payloads.psobject.Properties) {
          Assert-Payload (Join-Path $target $payload.Name) $payload.Value
        }
      } finally { Run-MSI "/x `"$package`" /qn /norestart /L*V `"$fixture\$nameKind-remove.log`"" }
      Assert-Unregistered $manifest.$nameKind.code
      if ((Test-Path $target) -and @(Get-ChildItem $target -Recurse -File -Force).Count -ne 0) { throw "$nameKind uninstall left files" }
      Write-Host "NATIVE_EXACT_REQUESTED_NAMES_INSTALL_REMOVE_OK $nameKind"
    }
  }

  Invoke-Scenario 'shortcuts' {
    $package = Join-Path $fixture 'shortcuts/package.msi'
    $target = Join-Path $fixture 'shortcut-install'
    try {
      Run-MSI "/i `"$package`" /qn /norestart SHORTFILENAMES=1 INSTALLFOLDER=`"$target`" /L*V `"$fixture\shortcut-install.log`""
      foreach ($row in $manifest.shortcuts.files) {
        if ($row.Component_ -eq 'LinkTarget') { continue }
        $name = $row.FileName.Split('|')[0]
        $long = $row.FileName.Split('|')[-1]
        Assert-Payload (Join-Path $target $name) $manifest.shortcuts.payloads.$long
      }
      $link = Join-Path $target $manifest.shortcuts.shortcuts[0].Name.Split('|')[0]
      if (-not (Test-Path -LiteralPath $link)) { throw "Shortcut missing: $link" }
      if ((Get-Item -LiteralPath $link).Length -lt 76) { throw 'Shortcut has no shell link header' }
      $header = [IO.File]::ReadAllBytes($link)
      if ([BitConverter]::ToUInt32($header,0) -ne 76) { throw 'Shortcut was replaced by a payload' }
      Write-Host 'NATIVE_SHORT_FILENAMES_PAYLOAD_AND_SHORTCUT_COEXIST_OK'
    } finally { Run-MSI "/x `"$package`" /qn /norestart SHORTFILENAMES=1 /L*V `"$fixture\shortcut-remove.log`"" }
    Assert-Unregistered $manifest.shortcuts.code
    if (Test-Path $target) {
      if (@(Get-ChildItem $target -Recurse -File -Force).Count -ne 0) { throw 'Shortcut uninstall left files' }
    }
  }

  $allFailures = @($iceFailures) + $scenarioFailures.ToArray()
  if ($allFailures.Count -ne 0) { throw ($allFailures -join '; ') }
  Write-Host 'GO_MSI_AUTHORING_NATIVE_REGRESSIONS_OK'
} finally { Stop-Transcript }
