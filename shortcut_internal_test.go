package msi

// shortcut_internal_test.go — Shortcut directory placement (InDirectory).

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestShortcut_InDirectory_PlacesAndCreatesStandardFolder verifies that a
// shortcut is emitted in the directory set via InDirectory (not hardcoded
// INSTALLFOLDER) and that a referenced standard directory is auto-created in the
// Directory table rooted at TARGETDIR.
func TestShortcut_InDirectory_PlacesAndCreatesStandardFolder(t *testing.T) {
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("SC Dir").
		WithManufacturer("go-msix").
		WithVersion("1.0.0")
	c := b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F")
	c.WithFile("app.exe", []byte("MZ"))
	c.Shortcut("App.lnk", "[#app.exe]").
		InDirectory("ProgramMenuFolder").
		Description("Launch App")
	// A second shortcut with no InDirectory must still default to INSTALLFOLDER.
	c.Shortcut("AppHere.lnk", "[#app.exe]")
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))

	db, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	// Shortcut.Directory_ reflects InDirectory (or the INSTALLFOLDER default).
	scTbl, err := db.GetTable("Shortcut")
	require.NoError(t, err)
	dirByName := map[string]string{}
	for _, r := range scTbl.rows() {
		v := r.values()
		name, _ := v[2].(string)
		dir, _ := v[1].(string)
		dirByName[name] = dir
	}
	assert.Equal(t, "ProgramMenuFolder", dirByName["App.lnk"], "shortcut placed in ProgramMenuFolder")
	assert.Equal(t, "INSTALLFOLDER", dirByName["AppHere.lnk"], "default placement is INSTALLFOLDER")

	// The standard directory was auto-created under TARGETDIR.
	dirTbl, err := db.GetTable("Directory")
	require.NoError(t, err)
	var found bool
	for _, r := range dirTbl.rows() {
		v := r.values()
		if id, _ := v[0].(string); id == "ProgramMenuFolder" {
			found = true
			assert.Equal(t, "TARGETDIR", v[1], "ProgramMenuFolder parent is TARGETDIR")
			assert.Equal(t, ".", v[2], "standard directory DefaultDir is .")
		}
	}
	assert.True(t, found, "ProgramMenuFolder row added to Directory table")
}
