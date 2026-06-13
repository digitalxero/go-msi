#!/usr/bin/env bash
# External cross-check of go-msix MSI output against real-world tooling:
#   msiinfo / msidump / msiextract (msitools) and cabextract (libmspack).
# Uses native tools when installed; otherwise falls back to the
# go-msix-verify Docker image (built on demand from ubuntu:24.04).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

RUN() { :; }
if command -v msiinfo >/dev/null && command -v msiextract >/dev/null && command -v cabextract >/dev/null; then
    echo "==> using native msitools/cabextract"
    RUN() { (cd "$WORK" && "$@"); }
elif command -v docker >/dev/null; then
    echo "==> using dockerized msitools/cabextract (go-msix-verify image)"
    if ! docker image inspect go-msix-verify >/dev/null 2>&1; then
        printf 'FROM ubuntu:24.04\nRUN apt-get update && apt-get install -y --no-install-recommends msitools cabextract && rm -rf /var/lib/apt/lists/*\n' \
            | docker build -t go-msix-verify -
    fi
    RUN() { docker run --rm -v "$WORK:/work" -w /work go-msix-verify "$@"; }
else
    echo "verify_msi: neither msitools+cabextract nor docker available" >&2
    exit 3
fi

fail() { echo "FAIL: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Comprehensive sample (NewMSIPackage with Registry/Shortcut/Icon/Binary,
# services, upgrades, search, custom actions, the canned UI, multi-media cabs
# and an embedded language transform) cross-checked against real tooling.
# ---------------------------------------------------------------------------
echo "==> building sample MSI"
(cd "$ROOT" && go run ./internal/genmsi "$WORK/p3.msi")

echo "==> msiinfo tables (P3)"
RUN msiinfo tables p3.msi | tee "$WORK/tables_p3.txt"
for t in Registry Shortcut Icon Binary Component Feature FeatureComponents File _Validation; do
    grep -qx "$t" "$WORK/tables_p3.txt" || fail "P3 table $t missing"
done

echo "==> msidump P3 tables as idt"
mkdir -p "$WORK/dump_p3"
RUN sh -c 'cd dump_p3 && msidump ../p3.msi >/dev/null'

# Registry.idt: header is 3 lines (column names, types, key spec). The shipped
# empty-Registry regression made it exactly 3 lines; assert there is real data.
[ "$(grep -c . "$WORK/dump_p3/Registry.idt")" -gt 3 ] || fail "Registry table is empty (regression)"
# A real HKLM (Root==2) row for Software\GoMSIX with the InstallDir value.
grep -P '\t2\tSoftware\\GoMSIX\t' "$WORK/dump_p3/Registry.idt" >/dev/null \
    || fail "Registry HKLM row for Software\\GoMSIX missing"
grep -q 'InstallDir' "$WORK/dump_p3/Registry.idt" || fail "Registry InstallDir value missing"
grep -q '1.2.3' "$WORK/dump_p3/Registry.idt" || fail "Registry Version value missing"

# Shortcut.idt must carry a data row referencing the shortcut Name.
[ "$(grep -c . "$WORK/dump_p3/Shortcut.idt")" -gt 3 ] || fail "Shortcut table is empty (regression)"
grep -q 'Go MSIX P3 App.lnk' "$WORK/dump_p3/Shortcut.idt" || fail "Shortcut row missing"
grep -q 'AppIcon' "$WORK/dump_p3/Shortcut.idt" || fail "Shortcut Icon_ ref missing"
# Shortcut must be placed in ProgramMenuFolder (InDirectory), not INSTALLFOLDER,
# and that standard directory must be present in the Directory table.
grep -qP '\tProgramMenuFolder\t' "$WORK/dump_p3/Shortcut.idt" || fail "Shortcut not placed in ProgramMenuFolder"
grep -qP '^ProgramMenuFolder\tTARGETDIR\t' "$WORK/dump_p3/Directory.idt" || fail "ProgramMenuFolder not in Directory table"

# Icon side stream must extract to non-empty bytes (binary column round-trips).
RUN sh -c 'msiinfo extract p3.msi Icon.AppIcon > AppIcon.out'
[ -s "$WORK/AppIcon.out" ] || fail "Icon.AppIcon side stream is empty"

# Binary.idt must carry a data row, and the Binary.AppData side stream must
# extract to non-empty bytes (Binary table + its CFB object-column round-trip).
[ "$(grep -c . "$WORK/dump_p3/Binary.idt")" -gt 3 ] || fail "Binary table is empty (regression)"
grep -q 'AppData' "$WORK/dump_p3/Binary.idt" || fail "Binary AppData row missing"
RUN sh -c 'msiinfo extract p3.msi Binary.AppData > AppData.out'
[ -s "$WORK/AppData.out" ] || fail "Binary.AppData side stream is empty"

# ---------------------------------------------------------------------------
# P4 cross-check (services, major upgrade, AppSearch) on the same new-API
# sample. genmsi-new emits a ServiceInstall/ServiceControl, a MajorUpgrade and
# an AppSearch; assert real tooling sees the rows and the conditionally-injected
# standard actions.
# ---------------------------------------------------------------------------
echo "==> P4 tables present"
for t in ServiceInstall ServiceControl MsiServiceConfig Upgrade LaunchCondition AppSearch RegLocator; do
    grep -qx "$t" "$WORK/tables_p3.txt" || fail "P4 table $t missing"
done

# ServiceInstall row: the service name + the Normal|Vital error control (0x8001=32769).
[ "$(grep -c . "$WORK/dump_p3/ServiceInstall.idt")" -gt 3 ] || fail "ServiceInstall table is empty"
grep -q 'GoMsixSvc' "$WORK/dump_p3/ServiceInstall.idt" || fail "ServiceInstall row missing"
grep -P '\t32769\t' "$WORK/dump_p3/ServiceInstall.idt" >/dev/null || fail "ServiceInstall ErrorControl Normal|Vital missing"

# Upgrade: both synthesized detect rows.
grep -q 'WIX_UPGRADE_DETECTED' "$WORK/dump_p3/Upgrade.idt" || fail "Upgrade detect-remove row missing"
grep -q 'WIX_DOWNGRADE_DETECTED' "$WORK/dump_p3/Upgrade.idt" || fail "Upgrade detect-newer row missing"
grep -q 'SecureCustomProperties.*WIX_DOWNGRADE_DETECTED;WIX_UPGRADE_DETECTED' "$WORK/dump_p3/Property.idt" \
    || fail "SecureCustomProperties must list both ActionProperty names (sorted)"

# AppSearch row + its RegLocator.
grep -q 'GOMSIX_INSTALLDIR' "$WORK/dump_p3/AppSearch.idt" || fail "AppSearch row missing"

# Conditionally-injected standard actions in InstallExecuteSequence.
for a in InstallServices StartServices StopServices DeleteServices \
         FindRelatedProducts MigrateFeatureStates RemoveExistingProducts AppSearch LaunchConditions; do
    grep -qP "^$a\t" "$WORK/dump_p3/InstallExecuteSequence.idt" || fail "InstallExecuteSequence missing $a"
done

# P5: a custom action row + its resolved sequence schedule. genmsi-new emits a
# deferred EXE-from-Binary CA (Type 3074 = 2|0x400|0x800) scheduled after
# InstallFiles (4000 -> 4001) with condition "NOT Installed".
[ "$(grep -c . "$WORK/dump_p3/CustomAction.idt")" -gt 3 ] || fail "CustomAction table is empty"
grep -qP '^GoMsixConfigure\t3074\tAppData\t--configure' "$WORK/dump_p3/CustomAction.idt" \
    || fail "CustomAction GoMsixConfigure row (type/source/target) missing or wrong"
grep -qP '^GoMsixConfigure\tNOT Installed\t4001\r?$' "$WORK/dump_p3/InstallExecuteSequence.idt" \
    || fail "custom action not scheduled after InstallFiles with its condition"

# P6: the canned minimal UI. genmsi-new calls WithMinimalUI(), which emits the
# Dialog/Control/ControlEvent/EventMapping/TextStyle/UIText tables and schedules
# WelcomeDlg/ProgressDlg in InstallUISequence.
for t in Dialog Control ControlEvent EventMapping TextStyle UIText; do
    grep -qx "$t" "$WORK/tables_p3.txt" || fail "P6 UI table $t missing"
done
for dlg in WelcomeDlg ProgressDlg ExitDialog FatalError UserExit; do
    grep -qP "^$dlg\t" "$WORK/dump_p3/Dialog.idt" || fail "canned dialog $dlg missing"
done
grep -qP '^WelcomeDlg\t\t1297\r?$' "$WORK/dump_p3/InstallUISequence.idt" || fail "WelcomeDlg not scheduled at 1297"
grep -qP '^ProgressDlg\t\t1298\r?$' "$WORK/dump_p3/InstallUISequence.idt" || fail "ProgressDlg not scheduled at 1298"
# The EndDialog ControlEvent on the welcome Install button.
grep -qP '^WelcomeDlg\tInstall\tEndDialog\tReturn' "$WORK/dump_p3/ControlEvent.idt" || fail "WelcomeDlg Install EndDialog event missing"
# DefaultUIFont property contributed by the canned UI.
grep -qP '^DefaultUIFont\tDlgFont' "$WORK/dump_p3/Property.idt" || fail "DefaultUIFont property missing"

# P7: genmsi-new uses WithCabSplitThreshold so the payload is split across two
# embedded cabinets. Assert both Media rows and both cabs decode cleanly, and
# that msiextract reassembles every file across the cabs.
[ "$(grep -c . "$WORK/dump_p3/Media.idt")" -ge 5 ] || fail "expected >=2 Media rows (multi-cab)"
grep -qP '^1\t\d+\t\t#cab1.cab' "$WORK/dump_p3/Media.idt" || fail "Media disk 1 (#cab1.cab) missing"
grep -qP '^2\t\d+\t\t#cab2.cab' "$WORK/dump_p3/Media.idt" || fail "Media disk 2 (#cab2.cab) missing"

echo "==> cabextract -t on both P7 embedded cabs"
for cab in cab1.cab cab2.cab; do
    RUN sh -c "msiinfo extract p3.msi $cab > p3_$cab"
    RUN cabextract -t "p3_$cab" | tee "$WORK/cabtest_$cab.txt"
    grep -q 'All done, no errors' "$WORK/cabtest_$cab.txt" || fail "P7 cabextract found errors in $cab"
done

echo "==> msiextract reassembles files across both cabs"
mkdir -p "$WORK/p3out"
RUN sh -c 'msiextract -C p3out p3.msi >/dev/null'
[ -f "$WORK/p3out/Go MSIX P3 App/app.exe" ] || fail "app.exe not extracted (cab1)"
[ -f "$WORK/p3out/Go MSIX P3 App/MyLongLibraryName.dll" ] || fail "MyLongLibraryName.dll not extracted (cab2)"
[ "$(wc -c < "$WORK/p3out/Go MSIX P3 App/MyLongLibraryName.dll")" = 70000 ] || fail "dll size mismatch across cabs"

# ---------------------------------------------------------------------------
# P9 multi-language + embedded transform cross-check. genmsi-new sets the primary
# language to en-US (1033) and embeds a German (1031) language transform, so the
# Template lists both LCIDs and the package still dumps/extracts cleanly with the
# embedded sub-storage present. (The transform's apply correctness is covered by
# the pure-Go generate->apply round-trip oracle; msitools has no MST inspector.)
# ---------------------------------------------------------------------------
echo "==> P9 multi-language Template + ProductLanguage"
RUN msiinfo suminfo p3.msi | tee "$WORK/suminfo_p3.txt"
grep -q 'Template: x64;1033,1031' "$WORK/suminfo_p3.txt" || fail "P9 Template does not list 1033,1031"
grep -qP '^ProductLanguage\t1033\r?$' "$WORK/dump_p3/Property.idt" || fail "P9 ProductLanguage 1033 missing"
grep -qP '^GOMSIX_GREETING\tWelcome\r?$' "$WORK/dump_p3/Property.idt" || fail "P9 base GOMSIX_GREETING missing"
echo "    Template lists 1033,1031; ProductLanguage=1033 (German transform embedded as :1031)"

# ---------------------------------------------------------------------------
# P8 Authenticode signing cross-check: build a signed sample MSI and verify it
# with osslsigncode (an independent oracle that recomputes the MSI imprint).
# ---------------------------------------------------------------------------
echo "==> building signed sample MSI"
(cd "$ROOT" && go run ./internal/gensignedmsi "$WORK")
[ -f "$WORK/signed.msi" ] || fail "signed.msi not produced"

SIGN_RUN=""
if command -v osslsigncode >/dev/null; then
    SIGN_RUN() { (cd "$WORK" && osslsigncode "$@"); }
    SIGN_RUN=native
elif command -v docker >/dev/null; then
    if ! docker image inspect go-msix-sign >/dev/null 2>&1; then
        printf 'FROM go-msix-verify\nRUN apt-get update && apt-get install -y --no-install-recommends osslsigncode && rm -rf /var/lib/apt/lists/*\n' \
            | docker build -t go-msix-sign - || true
    fi
    if docker image inspect go-msix-sign >/dev/null 2>&1; then
        SIGN_RUN() { docker run --rm -v "$WORK:/work" -w /work go-msix-sign osslsigncode "$@"; }
        SIGN_RUN=docker
    fi
fi

if [ -n "$SIGN_RUN" ]; then
    echo "==> osslsigncode verify (recomputes the MSI imprint)"
    SIGN_RUN verify -in signed.msi -CAfile signer.pem | tee "$WORK/sigverify.txt" || true
    grep -q 'Succeeded' "$WORK/sigverify.txt" || fail "osslsigncode did not verify the signed MSI"
    # The imprint osslsigncode recomputes must equal the one in the signature.
    cur=$(grep 'Current DigitalSignature' "$WORK/sigverify.txt" | grep -oE '[0-9A-Fa-f]{64}')
    calc=$(grep 'Calculated DigitalSignature' "$WORK/sigverify.txt" | grep -oE '[0-9A-Fa-f]{64}')
    [ -n "$cur" ] && [ "$cur" = "$calc" ] || fail "MSI imprint mismatch (osslsigncode recomputed a different digest)"
    echo "    imprint match: $cur"
else
    echo "==> osslsigncode unavailable; skipping signature cross-check (pure-Go VerifyMSI already ran in gensignedmsi)"
fi

# ---------------------------------------------------------------------------
# P10 patch (.msp) cross-check. genpatch builds base.msi, upgraded.msi and the
# patch.msp between them. msitools (libmsi) reads our patch fully — summary,
# the patch tables, and the embedded cabinet — so these are hard assertions.
# Real apply is covered by `task patch-smoke-wine` (Wine) and the windows-latest
# CI job; the pure-Go generate->apply oracle gates correctness in unit tests.
# ---------------------------------------------------------------------------
echo "==> building patch sample (base + upgraded + .msp)"
(cd "$ROOT" && go run ./internal/genpatch "$WORK")
[ -f "$WORK/patch.msp" ] || fail "patch.msp not produced"

echo "==> P10 patch summary"
RUN msiinfo suminfo patch.msp | tee "$WORK/msp_suminfo.txt"
grep -q 'Title: Patch' "$WORK/msp_suminfo.txt" || fail "patch summary Title is not 'Patch'"
grep -q 'Last author: :P0;:#P0' "$WORK/msp_suminfo.txt" || fail "patch PID8 transform list missing"
grep -Eq 'Template: \{[0-9A-F-]{36}\}' "$WORK/msp_suminfo.txt" || fail "patch PID7 target ProductCode missing"
grep -Eq 'Revision number \(UUID\): \{[0-9A-F-]{36}\}' "$WORK/msp_suminfo.txt" || fail "patch code (PID9) missing"

echo "==> P10 patch tables"
RUN msiinfo tables patch.msp | tee "$WORK/msp_tables.txt"
grep -qx 'MsiPatchMetadata' "$WORK/msp_tables.txt" || fail "MsiPatchMetadata missing from patch"
grep -qx 'MsiPatchSequence' "$WORK/msp_tables.txt" || fail "MsiPatchSequence missing from patch"
RUN msiinfo export patch.msp MsiPatchMetadata | tee "$WORK/msp_meta.txt"
grep -qP '\tClassification\tUpdate' "$WORK/msp_meta.txt" || fail "MsiPatchMetadata Classification missing"
RUN msiinfo export patch.msp MsiPatchSequence | tee "$WORK/msp_seq.txt"
grep -q 'GoMsixPatchDemo' "$WORK/msp_seq.txt" || fail "MsiPatchSequence family missing"

echo "==> P10 patch cabinet decodes (cabextract -t)"
RUN sh -c 'msiinfo extract patch.msp patch.cab > patch_cab.bin'
RUN cabextract -t patch_cab.bin | tee "$WORK/msp_cabtest.txt"
grep -q 'All done, no errors' "$WORK/msp_cabtest.txt" || fail "patch cabinet failed cabextract -t"
echo "    patch.msp: Title=Patch, transforms :P0;:#P0, MsiPatch* tables, cab clean"

echo "verify_msi: ALL CHECKS PASSED"
