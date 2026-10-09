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
and must have a valid Microsoft Authenticode signature. Missing `msival2.exe` or
`Darice.cub` fails provisioning; no ICE selection or error suppression is used.
Tool hashes/versions, fixture files, and setup/ICE/installation logs are uploaded
even when a check fails. Installation occurs only on a disposable elevated
Windows runner.

Sources: [Microsoft ICE](https://learn.microsoft.com/en-us/windows/win32/msi/using-internal-consistency-evaluators),
[MsiVal2](https://learn.microsoft.com/en-us/windows/win32/msi/msival2-exe),
[Windows Installer command line](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options),
[Windows SDK downloads](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/).
