# The bounded native fixtures contain exactly one accented FileName value.
# Select it independently of the native SQL view's row order.
function Select-UnicodeCollisionName([object[]]$Names) {
  $unicodeNames = @($Names | Where-Object { $_.Name -match '[^\x00-\x7F]' })
  if ($unicodeNames.Count -ne 1) { throw 'Unicode collision control requires exactly one accented filename' }
  return $unicodeNames[0].Name
}

function Assert-UnicodeCollisionReport([string]$Report) {
  if ($Report -match '(?im)UNKNOWN|ICE Internal Error') { throw 'Negative control validation is incomplete' }
  if ($Report -notmatch '(?im)^ICE30\s+ERROR\s+[^\r\n]*[^\x00-\x7F][^\r\n]*\bLFN system\b') {
    throw 'Negative control did not detect the accented LFN collision with ICE30'
  }
}
