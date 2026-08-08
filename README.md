# go-msi

A pure-Go library for creating **Windows Installer** packages — `.msi` databases,
`.mst` transforms, and `.msp` patches — with Authenticode signing. No CGO, no
Windows SDK, no external tools required; it works on any platform Go targets.

## Features

- Build MSI packages entirely in Go: spec-true CFB v3 container, string pool,
  column-major table streams, `_Validation`, SummaryInformation, and embedded
  MSZIP cabinets — cross-checked against msitools (`msiinfo`/`msidump`/
  `msiextract`) and libmspack (`cabextract`).
- Interface-based, Builder-IS-Implementation API: directory trees, multi-
  component / multi-feature models, registry, shortcuts, icons/binary streams,
  services, major/minor upgrades, AppSearch/locators, custom actions +
  sequencing, a full UI subsystem with a canned minimal wizard, and multi-media /
  external / spanned cabinets.
- Multi-language MSIs, standalone `.mst` transforms, and embedded per-language
  transforms (verified by a generate→apply round-trip oracle).
- Windows Installer patches (`.msp`) for small + minor updates, applied by the
  real `msiexec` in CI (and Wine locally).
- Authenticode-sign MSIs in pure Go (RSA/ECDSA, optional RFC3161 timestamp),
  cross-checked with `osslsigncode`.
- ICE validation by default (27 dedicated rules + generic category/foreign-key
  validation over ~80 cataloged tables), with an auditable coverage table.
- Deterministic, reproducible output.

### Non-goals

- LZX cabinet compression (MSZIP is fully supported by Windows Installer).
- `\x05MsiDigitalSignatureEx` metadata pre-hash (signtool omits it by default).
- Binary-delta (PatchAPI) patching and major-upgrade/schema-reorganizing patches.
- Merge modules (`.msm`) — the module tables are cataloged for ICE validation but
  go-msi does not author `.msm` files.

For MSIX/APPX packaging, see the companion module
[`go.digitalxero.dev/go-msix`](https://go.digitalxero.dev/go-msix).

## Install

```
go get go.digitalxero.dev/go-msi
```

## Usage

This builds an MSI that installs `app.exe` into `C:\Program Files\My App` and adds
a **My App** shortcut to the Start Menu.

```go
package main

import (
	"os"

	msi "go.digitalxero.dev/go-msi"
)

func main() {
	// Configure the package on the builder, then Build + WriteMSI.
	b := msi.NewPackage().
		WithProductName("My App").
		WithManufacturer("My Company").
		WithVersion("1.0.0").
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithUpgradeCode("{ABCDEF01-2345-6789-ABCD-EF0123456789}").
		// Root the install under the target platform's Program Files folder.
		// Without this the install root hangs off TARGETDIR instead.
		InstallToProgramFiles()

	app, err := msi.FileSourceFromPath("app.exe")
	if err != nil {
		panic(err)
	}

	// "My App" now resolves to C:\Program Files\My App.
	c := b.RootDirectory("INSTALLFOLDER", "My App").
		Component("Main").AssociateToFeature("MainFeature")
	c.WithFile("app.exe", app)

	// An advertised Start Menu shortcut. Advertised targets the feature, so
	// Windows Installer repairs the app if the key file goes missing.
	c.Shortcut("My App.lnk", "").
		InDirectory("ProgramMenuFolder").
		Description("Launch My App").
		Advertised("MainFeature")

	b.Feature("MainFeature").WithTitle("Main Feature").WithLevel(1)

	pkg, err := b.Build()
	if err != nil {
		panic(err)
	}

	f, _ := os.Create("MyApp.msi")
	defer f.Close()
	_ = pkg.WriteMSI(f)
}
```

Install and uninstall it silently:

```powershell
# Install with no UI, logging verbosely.
msiexec /i MyApp.msi /qn /norestart /l*v install.log

# Uninstall silently, by package or by ProductCode.
msiexec /x MyApp.msi /qn /norestart
msiexec /x {12345678-1234-1234-1234-123456789ABC} /qn /norestart
```

A per-machine install writes to `C:\Program Files`, so run these from an
elevated prompt — `/qn` suppresses the UAC prompt along with the rest of the UI,
and an unelevated silent install fails with error 1925.

To install somewhere else, set `INSTALLFOLDER`:

```powershell
msiexec /i MyApp.msi /qn INSTALLFOLDER="D:\Apps\My App"
```

Note that `TARGETDIR=` does **not** redirect a package built with
`InstallToProgramFiles()` — Windows Installer resolves the Program Files folders
from the system, not from `TARGETDIR`. Packages that skip the opt-in keep their
install root under `TARGETDIR` and stay redirectable that way.

Because the default platform is `Platform_x64`, `InstallToProgramFiles()` picks
`ProgramFiles64Folder` (`C:\Program Files`). A `Platform_Intel` package gets
`ProgramFilesFolder`, which is `C:\Program Files (x86)` on 64-bit Windows — see
[Target platform](#target-platform).

`AddTree(fsys, attachPointDirID, featureID)` harvests a filesystem tree (one
component per file by default, each associated with `featureID`). The emitted MSI
carries the standard action set across all five
sequence tables at the canonical WiX sequence numbers, generated component GUIDs,
8.3 `short|long` file names, a populated `_Validation` table, and an embedded
MSZIP cabinet whose members are keyed by the File-table primary keys.

ICE validation runs by default on `Build()`/`WriteMSI()`; error-severity findings
fail the build (`WithSkipValidation()` is the escape hatch). Use
`msi.NewValidator().WithAllICEs().Build()` for explicit runs.

### Target platform

`WithPlatform` sets the architecture recorded in the SummaryInformation
`Template` property. The default is `Platform_x64`.

```go
pkg := msi.NewPackage(). /* … */ WithPlatform(msi.Platform_Arm64)
```

| Constant | Template token | Target | Minimum installer |
| --- | --- | --- | --- |
| `Platform_Intel` | `Intel` | x86, 32-bit | 2.0 |
| `Platform_Intel64` | `Intel64` | Itanium / IA-64 | 2.0 |
| `Platform_x64` | `x64` | x86-64 (AMD64 / EM64T) | 2.0 |
| `Platform_Arm` | `Arm` | ARM, 32-bit | 5.0 |
| `Platform_Arm64` | `Arm64` | AArch64 | 5.0 |

`Platform_Intel64` means **Itanium**, not x86-64 — Intel's modern "Intel 64"
branding refers to AMD64, but the Windows Installer token does not. AMD64
packages use `Platform_x64`. These five are the only tokens Windows Installer
accepts; there is no `amd64` or `neutral` (the latter is an MSIX architecture).

The platform also drives:

- the minimum Windows Installer version in `PageCount` (PID 14) — Arm and Arm64
  require 5.0 rather than the 2.0 baseline;
- `msidbComponentAttributes64bit` on components of a 64-bit package, so their
  files land in the 64-bit locations and their registry rows bypass WOW6432Node
  redirection;
- which Program Files folder `InstallToProgramFiles()` selects —
  `ProgramFiles64Folder` for 64-bit platforms, `ProgramFilesFolder` otherwise.

Both defer to explicit configuration: a component with its own `WithAttributes`
call, or an install directory whose parent the caller declared, is left exactly
as authored. ICE80 then cross-checks the result, failing the build if 64-bit
content (64-bit components, the `*64Folder` directories, 64-bit script custom
actions, or 64-bit registry searches) appears in a package whose `Template`
declares a 32-bit platform.

### Signing (Authenticode)

```go
signer, _ := msi.NewSigner().
    WithPFX("codesign.pfx", "password").
    WithTimestampURL("http://timestamp.digicert.com").
    Build()
pkg := msi.NewPackage(). /* … */ WithSigner(signer)
// pkg.WriteMSI(out) emits a \x05DigitalSignature stream; msi.Verify(r) verifies it.
```

### Transforms (MST) and patches (MSP)

```go
// Standalone transform between two packages:
tr, _ := msi.NewTransform().From(base).To(target).Build()
tr.WriteMST(out)

// Embedded per-language transform:
pkg.WithLanguage(msi.LangCode_enUS).
    WithLanguageTransform(msi.LangCode_deDE, func(de msi.PackageBuilder) {
        de.WithProductName("Meine Anwendung")
    })

// Patch (.msp) between an original and an upgraded product:
patch, _ := msi.NewPatch().From(base).To(upgraded).
    WithClassification("Update").AllowRemoval(true).
    WithPatchFamily("MyAppPatches", "1.0.1").Build()
patch.WriteMSP(out) // applied with: msiexec /p patch.msp
```

## Verification

Generated output is verified at several layers, all green in CI:

- **Unit/round-trip** — write → read-back table-by-table; deterministic-build and
  ICE-clean meta-tests; a pure-Go generate→apply oracle for transforms and
  patches.
- **External tooling** (`task verify-msi`) — `msiinfo`/`msidump`/`msiextract`,
  `cabextract -t`, and `osslsigncode verify` (which independently recomputes the
  signature imprint).
- **Real installer** — a `windows-latest` CI job installs the base MSI and applies
  the `.msp` with the real `msiexec`; locally `task smoke-wine` /
  `task patch-smoke-wine` do install / patch-apply against Wine.

## Requirements

- Go 1.25 or later.

## License

See [LICENSE](LICENSE) for details.
