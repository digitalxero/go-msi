package msi_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	msi "go.digitalxero.dev/go-msi"
)

func TestWindowsPEVersionMatchesNativeResource(t *testing.T) {
	// Compare the generated File.Version with Windows' own version reader
	// using a real system executable, rather than our synthetic PE fixture.
	output, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `$v = (Get-Item "$env:SystemRoot\System32\cmd.exe").VersionInfo; '{0}.{1}.{2}.{3}' -f $v.FileMajorPart,$v.FileMinorPart,$v.FileBuildPart,$v.FilePrivatePart`).CombinedOutput()
	require.NoError(t, err, "%s", output)
	b := msi.NewPackage().WithProductName("Native PE version").WithManufacturer("Test").WithVersion("1.0.0").WithPlatform(msi.Platform_x64)
	b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("Main").WithFilePath("cmd.exe", filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"))
	b.Feature("Main").WithLevel(1)
	pkg, err := b.Build()
	require.NoError(t, err)
	var data bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&data))
	db, err := msi.Open(bytes.NewReader(data.Bytes()))
	require.NoError(t, err)
	rows, err := db.Table("File")
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, strings.TrimSpace(string(output)), rows[0]["Version"])
	assert.NotEmpty(t, rows[0]["Language"])
}

func TestWindowsPEVersionSurvivesMajorUpgrade(t *testing.T) {
	if os.Getenv("GO_MSI_WINDOWS_INSTALL_TEST") != "1" {
		t.Skip("set GO_MSI_WINDOWS_INSTALL_TEST=1 to run the native install/upgrade regression")
	}
	native, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", `$v = (Get-Item "$env:SystemRoot\System32\cmd.exe").VersionInfo; '{0}.{1}.{2}.{3}' -f $v.FileMajorPart,$v.FileMinorPart,$v.FileBuildPart,$v.FilePrivatePart`).CombinedOutput()
	require.NoError(t, err, "%s", native)
	guid := func() string {
		var value [16]byte
		_, err := rand.Read(value[:])
		require.NoError(t, err)
		return fmt.Sprintf("{%X-%X-%X-%X-%X}", value[:4], value[4:6], value[6:8], value[8:10], value[10:])
	}
	upgrade := guid()
	work := t.TempDir()
	installed := filepath.Join(work, "installed")
	source := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	runMSI := func(args ...string) {
		t.Helper()
		output, err := exec.Command("msiexec.exe", args...).CombinedOutput()
		if failure, ok := err.(*exec.ExitError); ok && failure.ExitCode() == 3010 {
			return
		}
		if err != nil {
			logs, _ := filepath.Glob(filepath.Join(work, "*.log"))
			for _, log := range logs {
				data, _ := os.ReadFile(log)
				t.Logf("%s:\n%s", log, data)
			}
		}
		require.NoError(t, err, "%s", output)
	}
	for i, version := range []string{"1.0.0", "1.0.1"} {
		product := guid()
		b := msi.NewPackage().WithProductName("go-msi PE upgrade regression").WithManufacturer("Test").WithVersion(version).WithPlatform(msi.Platform_x64).WithAllUsers(true).WithProductCode(product).WithUpgradeCode(upgrade)
		file := b.RootDirectory("INSTALLFOLDER", "PEUpgrade").Component("Main").AssociateToFeature("Main").WithFilePath("cmd.exe", source)
		if i == 0 {
			// The old package has an explicitly versioned file; the new
			// package must detect that version to avoid the reported deletion.
			file.WithVersion(strings.TrimSpace(string(native)))
		}
		b.Feature("Main").WithLevel(1)
		b.MajorUpgrade()
		pkg, err := b.Build()
		require.NoError(t, err)
		var data bytes.Buffer
		require.NoError(t, pkg.WriteMSI(&data))
		path := filepath.Join(work, version+".msi")
		require.NoError(t, os.WriteFile(path, data.Bytes(), 0o600))
		t.Cleanup(func() {
			// Removing the old product after a successful upgrade returns
			// 1605 (already removed); cleanup also covers partial failures.
			_ = exec.Command("msiexec.exe", "/x", product, "/qn", "/norestart").Run()
		})
		runMSI("/i", path, "/qn", "/norestart", "INSTALLFOLDER="+installed, "/l*v", filepath.Join(work, version+".log"))
		expected, err := os.ReadFile(source)
		require.NoError(t, err)
		actual, err := os.ReadFile(filepath.Join(installed, "cmd.exe"))
		require.NoError(t, err, "executable must survive version %s", version)
		assert.Equal(t, expected, actual)
		if i == 1 {
			runMSI("/x", product, "/qn", "/norestart", "/l*v", filepath.Join(work, "uninstall.log"))
			_, err := os.Stat(filepath.Join(installed, "cmd.exe"))
			assert.True(t, os.IsNotExist(err), "uninstall must remove the upgraded executable")
		}
	}
}
