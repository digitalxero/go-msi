#!/usr/bin/env bash
# Patch apply smoke test: install the base MSI, apply the .msp patch, and verify
# the patched file content + the new file appear — all against Wine's msiexec
# (the closest available stand-in for native Windows Installer). The GitHub CI
# windows-latest job runs the same install/apply with the real msiexec.
# Requires docker; builds the go-msix-wine image on demand.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> building base.msi, upgraded.msi, patch.msp"
(cd "$ROOT" && go run ./internal/genpatch "$WORK")

if ! command -v docker >/dev/null; then
    echo "patch_smoke_wine: docker not available" >&2
    exit 3
fi
if ! docker image inspect go-msix-wine >/dev/null 2>&1; then
    printf 'FROM ubuntu:24.04\nENV DEBIAN_FRONTEND=noninteractive WINEDEBUG=-all\nRUN apt-get update && apt-get install -y --no-install-recommends wine64 && rm -rf /var/lib/apt/lists/*\n' \
        | docker build -t go-msix-wine -
fi

docker run --rm -v "$WORK:/work" -w /work -e WINEPREFIX=/tmp/wineprefix -e WINEDEBUG=-all go-msix-wine sh -c '
set -e
W=/usr/lib/wine/wine64
$W wineboot --init >/dev/null 2>&1

$W msiexec /i base.msi /qn
A=$(find /tmp/wineprefix/drive_c -iname a.exe | head -1)
[ -n "$A" ] || { echo "FAIL: base install did not place a.exe" >&2; exit 1; }
grep -q "ORIGINAL" "$A" || { echo "FAIL: base a.exe content unexpected" >&2; exit 1; }
echo "install base ok"

$W msiexec /p patch.msp /qn
grep -q "PATCHED" "$A" || { echo "FAIL: a.exe was not patched" >&2; exit 1; }
C=$(find /tmp/wineprefix/drive_c -iname c.dat | head -1)
[ -n "$C" ] || { echo "FAIL: patch did not add c.dat" >&2; exit 1; }
grep -q "brand-new" "$C" || { echo "FAIL: c.dat content unexpected" >&2; exit 1; }
echo "apply patch ok"
'
echo "patch_smoke_wine: ALL CHECKS PASSED"
