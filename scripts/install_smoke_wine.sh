#!/usr/bin/env bash
# Install/uninstall smoke test of go-msi MSI output against Wine's msiexec (the
# closest available stand-in for native Windows Installer). Installs the
# file-only base.msi produced by internal/genpatch. Requires docker; builds the
# go-msix-wine image on demand.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> building sample MSI (genpatch base.msi)"
(cd "$ROOT" && go run ./internal/genpatch "$WORK")

if ! command -v docker >/dev/null; then
    echo "install_smoke_wine: docker not available" >&2
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
echo "install ok"
A=$(find /tmp/wineprefix/drive_c -iname a.exe | head -1)
[ -n "$A" ] || { echo "FAIL: installed files not found" >&2; exit 1; }
grep -q "ORIGINAL" "$A" || { echo "FAIL: a.exe content mismatch" >&2; exit 1; }
$W msiexec /x "{C0FFEE00-1111-2222-3333-444444444444}" /qn
echo "uninstall ok"
[ -z "$(find /tmp/wineprefix/drive_c -iname a.exe)" ] || { echo "FAIL: files left after uninstall" >&2; exit 1; }
'
echo "install_smoke_wine: ALL CHECKS PASSED"
