package msi_test

import (
	"bytes"
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
