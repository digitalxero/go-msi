# Windows Installer compatibility

The required `windows-compatibility` job builds a real Windows executable and an
MSI through the public builder, then runs Microsoft's complete Darice ICE suite.
Windows Installer must administratively extract, install and uninstall that MSI.
Extracted and installed files must match their original hashes, the installed
executable must print `MSI_COMPATIBILITY_OK`, and a truncated MSI must be rejected.
The existing Linux signature/table checks and Windows signature/patch jobs are
retained.

The fixture generator can run from this module directory:

```sh
GOWORK=off go run ./internal/compatfixture /tmp/msi-compatibility/fixture
```

The Windows job uses Go 1.26.4 and Windows SDK 10.0.26100.9457. The official SDK
installer has SHA-256
`b0bdbad38ae74c40ccae8cdbcf229807627fba2bc3100be28301c4ba884f755e`
and must have a valid Microsoft Authenticode signature. The job installs the
SDK’s separate `MsiVal2-x86_en-us.msi` and `Orca-x86_en-us.msi` packages so the
COM validation engine is registered, then extracts the MsiVal2 package to obtain
the validation executable and suite. Missing `msival2.exe` or
`Darice.cub` fails provisioning; no ICE selection or error suppression is used.
Tool hashes/versions, fixture files, and setup/ICE/installation logs are uploaded
even when a check fails. Installation occurs only on a disposable elevated
Windows runner.

Sources: [Microsoft ICE](https://learn.microsoft.com/en-us/windows/win32/msi/using-internal-consistency-evaluators),
[MsiVal2](https://learn.microsoft.com/en-us/windows/win32/msi/msival2-exe),
[COM validation engine](https://learn.microsoft.com/en-us/windows/win32/msi/validation-automation),
[Windows Installer command line](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options),
[Windows SDK downloads](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/).

The same required job runs `scripts/verify_regressions_windows.ps1`. It builds
Unicode packages (accented, Japanese, and Cyrillic metadata),
checks summary values through Windows Installer COM, and runs the complete
Darice ICE suite on each package. Native silent installation must reject a
2.0.0 to default-policy 1.0.0 downgrade with error 1603, retain exactly one
related product, and preserve both the hash and `NEWER` output of its executable.
An explicit downgrade with a newer-product removal rule must then install
`OLDER`, leave exactly one product, and uninstall cleanly.

The per-user proof creates a temporary local standard account. The child process
checks that it is neither elevated nor an Administrators member, UAC is enabled,
and AlwaysInstallElevated is absent. It installs into that user's LocalAppData,
checks the installed Unicode metadata, HKCU registry resource, executable bytes
and execution, then removes the package and checks product/resource removal.
The fixture supplies the same explicit `INSTALLFOLDER` during install and remove:
its registry component KeyPath does not persist the directory override.
A deferred `NoImpersonate` EXE custom action must report that standard user's
SID, proving this package does not depend on system custom-action privileges.
Unrepresentable summary metadata, including supplementary characters, must fail
without producing a partial package. The proof logs and MSI fixtures are included
in the compatibility artifact.
The reusable CI workflow also gates automatic main-branch tag/release creation,
so the release job waits for these native checks.

Windows Server blocks unmanaged non-elevated MSI installs by default. On the
non-domain-joined disposable GitHub runner, the proof temporarily sets
`DisableMSI=0` to allow ordinary per-user installation and restores the exact
previous value (or absence) in `finally`. UAC remains enabled and
AlwaysInstallElevated remains disabled. The child resolves its actual loaded
profile from its token SID, avoiding the administrator's inherited environment.
This setup does not grant elevation or administrator membership to that user.
See [Microsoft DisableMSI policy](https://learn.microsoft.com/en-us/windows/win32/msi/disablemsi).

## Package identity and Windows destination names

`WriteMSI` derives PackageCode from a versioned SHA-256 manifest of the complete
unsigned package: table and string-pool streams, summary metadata, embedded
cabinets, Binary/Icon data and embedded language-transform storages. External
cabinet names and content digests participate too. Each manifest entry frames its
name, length and digest; entries sort by name. Revision uses a fixed valid GUID
while hashing to avoid self-reference, then receives the derived uppercase GUID.
ProductCode, UpgradeCode and component GUID derivation are unchanged.

Summary create/save times use the existing fixed 2020-01-01 UTC build epoch and
are included, as are the cabinet's reproducible metadata bytes. Source filesystem
timestamps do not determine package identity. Authenticode certificates,
signatures and signing-server timestamps are added **after** PackageCode and are
excluded: signing or re-signing identical installer content retains PackageCode,
though signed MSI bytes can differ. Identical unsigned reproducible inputs retain
both PackageCode and MSI bytes. Embedded cabinets stage to temporary files once
so identity, signing and output consume the same bytes with bounded memory.

Ordinary file/directory names reject Windows device basenames (including names
with extensions and COM/LPT superscript 1, 2 and 3 variants), trailing periods and
trailing spaces. Names are rejected, never silently changed. Representable
Unicode and leading-dot names remain supported. Directory `DefaultDir` accepts
MSI `target[:source]` syntax, optional `short|long` pairs and the `.` sentinel;
its ordinary name parts undergo the same checks. Literal and explicit short
names are reserved before generated aliases across sibling files, directories
and shortcuts.
Case-only sibling duplicates and duplicate explicit aliases are errors. The `.`
target sentinel shares its parent's namespace; standard Windows directory
properties retain their independently resolved namespaces.

Native CI builds a test-only x86 DLL with the hosted MSVC toolchain. It reports
progress through `MsiProcessMessage` and honors cancellation; no external UI
handler replaces the authored dialogs.

Native CI (`scripts/verify_authoring_windows.ps1`) checks changed-payload recache
and source repair with stable product/component identities; installs, reads and
removes short-name payloads with `SHORTFILENAMES=1` authored for consistent
install/maintenance behavior; preserves Unicode/leading-dot
names with long names enabled; and drives real full-UI license acceptance,
progress, success, welcome/progress cancellation, and error dialogs. Progress
cancellation opens a modal confirmation: No continues installation and Yes exits. It retains
native API assertions, full Darice ICE reports, dialog text/screenshots and MSI
logs in `official-msi-compatibility`. The existing downgrade, ordinary-user SID,
Unicode metadata, patch and signature gates continue to run. AllowDowngrades
still only disables the newer-product block; removing newer products requires a
separate authored Upgrade row.
