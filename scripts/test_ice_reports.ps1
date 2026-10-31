$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ice_reports.ps1')
. (Join-Path $PSScriptRoot 'ice_unicode_controls.ps1')
$work = Join-Path ([IO.Path]::GetTempPath()) ('ice-report-test-' + [guid]::NewGuid())
New-Item -ItemType Directory $work | Out-Null
try {
  $report = Join-Path $work 'report.log'
  [IO.File]::WriteAllBytes($report, [byte[]]@())
  if (-not [string]::IsNullOrEmpty((Read-IceReport $report))) { throw 'Empty ICE report was not clean' }
  $text = 'ICE30        UNKNOWN   ICE Internal Error 23. API Returned: 259.'
  $noBom = [Text.UnicodeEncoding]::new($false,$false)
  [IO.File]::WriteAllText($report, "$text`r`n", $noBom)
  if ((Read-IceReport $report) -cne $text) { throw 'UTF-16LE without BOM was misread' }
  [IO.File]::WriteAllText($report, "$text`r`n", [Text.Encoding]::Unicode)
  if ((Read-IceReport $report) -cne $text) { throw 'UTF-16LE BOM was misread' }
  Remove-Item $report
  $rejected = $false
  try { Read-IceReport $report } catch { $rejected = $true }
  if (-not $rejected) { throw 'Missing ICE report was accepted' }
  Write-Host 'ICE_EMPTY_UTF16_AND_MISSING_REPORT_REGRESSIONS_OK'
  $ascii = @{ Name = 'B6E0~1.CON|.CONFIG' }
  $accented = @{ Name = 'RSUM~1.TXT|RÉSUMÉ.TXT' }
  foreach ($names in @(@($ascii,$accented),@($accented,$ascii))) {
    if ((Select-UnicodeCollisionName $names) -cne $accented.Name) { throw 'Collision selection depends on row order' }
  }
  foreach ($names in @(@($ascii),@($accented,@{Name='CAFÉ.TXT'}))) {
    $rejected = $false
    try { Select-UnicodeCollisionName $names } catch { $rejected = $true }
    if (-not $rejected) { throw 'Ambiguous or missing accented collision name accepted' }
  }
  Write-Host 'UNICODE_COLLISION_ROW_ORDER_AND_AMBIGUITY_REGRESSIONS_OK'
  $lfn = "ICE30        ERROR     The target file 'RÉSUMÉ.TXT' is installed by two components on an LFN system: 'A' and 'B'."
  Assert-UnicodeCollisionReport $lfn
  foreach ($invalidReport in @($lfn.Replace('RÉSUMÉ.TXT','OTHER.TXT'), $lfn.Replace('LFN','SFN'), "$lfn`nICE30 UNKNOWN ICE Internal Error 23", '')) {
    $rejected = $false
    try { Assert-UnicodeCollisionReport $invalidReport } catch { $rejected = $true }
    if (-not $rejected) { throw 'ASCII-only, SFN-only, incomplete or missing collision evidence accepted' }
  }
  Write-Host 'UNICODE_LFN_COLLISION_REPORT_REGRESSIONS_OK'


} finally { Remove-Item $work -Recurse -Force }
