# MsiVal2 writes UTF-16LE without a BOM and writes a zero-byte file on success.
# ReadAllText returns an empty string for that file; Get-Content can return null.
function Read-IceReport([string]$Path) {
  return [IO.File]::ReadAllText($Path, [Text.Encoding]::Unicode).Trim()
}
