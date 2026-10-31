$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ice_reports.ps1')
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
} finally { Remove-Item $work -Recurse -Force }
