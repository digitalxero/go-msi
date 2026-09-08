package msi

// These tests use the internal MSI reader to verify serialized shortcut fields.

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
	c.WithFile("app.exe", FileSourceFromBytes([]byte("MZ")))
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

func TestShortcut_WorkingDirectory_RoundTrip(t *testing.T) {
	for _, tt := range []struct {
		name       string
		properties []string
		want       string
	}{
		{name: "default component directory", want: "BINDIR"},
		{name: "explicit install directory", properties: []string{"INSTALLFOLDER"}, want: "INSTALLFOLDER"},
		{name: "standard directory", properties: []string{"PersonalFolder"}, want: "PersonalFolder"},
		{name: "custom property", properties: []string{"APPWORKDIR"}, want: "APPWORKDIR"},
		{name: "empty uses default", properties: []string{""}, want: "BINDIR"},
		{name: "last call wins", properties: []string{"PersonalFolder", "INSTALLFOLDER"}, want: "INSTALLFOLDER"},
		{name: "clear restores default", properties: []string{"PersonalFolder", ""}, want: "BINDIR"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := NewPackage().
				WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
				WithProductName("Shortcut Working Directory").
				WithManufacturer("Example Co").
				WithVersion("1.0.0").
				WithProperty("APPWORKDIR", `C:\Work`)
			install := b.RootDirectory("INSTALLFOLDER", "App")
			c := install.Subdirectory("BINDIR", "bin").Component("Main").AssociateToFeature("F")
			c.WithFile("app.exe", FileSourceFromBytes([]byte("MZ")))
			for _, name := range []string{"App.lnk", "Advertised.lnk"} {
				sc := c.Shortcut(name, "[BINDIR]app.exe").InDirectory("ProgramMenuFolder")
				for _, property := range tt.properties {
					assert.Same(t, sc, sc.WorkingDirectory(property), "setter preserves the builder")
				}
				sc.Arguments("--launch")
				if name == "Advertised.lnk" {
					sc.Advertised("F")
				}
			}
			// The compatibility API gets the same default for this nested component.
			c.WithShortcut("Compat.lnk", "[BINDIR]app.exe")
			// Another component must use its own directory, not the previous one's.
			other := install.Component("Other").AssociateToFeature("F")
			other.WithFile("other.exe", FileSourceFromBytes([]byte("MZ")))
			other.Shortcut("Other.lnk", "[INSTALLFOLDER]other.exe")
			b.Feature("F").WithLevel(1)

			pkg, err := b.Build()
			require.NoError(t, err)
			var buf bytes.Buffer
			require.NoError(t, pkg.WriteMSI(&buf))
			db, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
			require.NoError(t, err)
			scTbl, err := db.GetTable("Shortcut")
			require.NoError(t, err)
			require.Len(t, scTbl.rows(), 4)
			for _, name := range []string{"App.lnk", "Advertised.lnk"} {
				row := findRow(t, scTbl, 2, name)
				assert.Equal(t, "ProgramMenuFolder", row[1], "shortcut placement is independent")
				assert.Equal(t, tt.want, row[11], "Start in uses a raw directory/property name")
				assert.Equal(t, "--launch", row[5])
				if name == "Advertised.lnk" {
					assert.Equal(t, "F", row[4])
				} else {
					assert.Equal(t, "[BINDIR]app.exe", row[4])
				}
			}
			assert.Equal(t, "BINDIR", findRow(t, scTbl, 2, "Compat.lnk")[11])
			assert.Equal(t, "INSTALLFOLDER", findRow(t, scTbl, 2, "Other.lnk")[11])

			dirTbl, err := db.GetTable("Directory")
			require.NoError(t, err)
			if tt.want == "PersonalFolder" {
				row := findRow(t, dirTbl, 0, "PersonalFolder")
				assert.Equal(t, "TARGETDIR", row[1])
				assert.Equal(t, ".", row[2])
			}
			for _, row := range dirTbl.rows() {
				assert.NotEqual(t, "APPWORKDIR", row.values()[0], "custom properties are not synthesized as directories")
			}
		})
	}
}
