package msi_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	msi "go.digitalxero.dev/go-msi"
)

func openExamplePackage(t *testing.T, b msi.PackageBuilder) msi.Database {
	t.Helper()
	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	db, err := msi.Open(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	return db
}

func readerTestPackage() msi.PackageBuilder {
	b := msi.NewPackage().
		WithProductName("Reader App").
		WithManufacturer("Reader Co").
		WithVersion("2.3.4").
		WithProductCode("{11111111-2222-3333-4444-555555555555}").
		WithUpgradeCode("{66666666-7777-8888-9999-AAAAAAAAAAAA}").
		WithPlatform(msi.Platform_Arm64).
		WithProperty("MYPROP", "hello")
	c := b.RootDirectory("INSTALLFOLDER", "Reader App").Component("Main").AssociateToFeature("MainFeature")
	c.WithFile("app.exe", msi.FileSourceFromBytes([]byte("MZ reader payload")))
	b.Feature("MainFeature").WithTitle("Main Feature").WithLevel(1)
	b.MajorUpgrade()
	return b
}

func TestOpen_TablesAndRows(t *testing.T) {
	db := openExamplePackage(t, readerTestPackage())

	tables := db.Tables()
	assert.Contains(t, tables, "Property")
	assert.Contains(t, tables, "Component")
	assert.Contains(t, tables, "Upgrade")
	assert.NotContains(t, tables, "_Tables", "the system catalog is folded into the schema")

	props, err := db.Table("Property")
	require.NoError(t, err)
	byName := map[string]any{}
	for _, r := range props {
		byName[r["Property"].(string)] = r["Value"]
	}
	assert.Equal(t, "Reader App", byName["ProductName"])
	assert.Equal(t, "2.3.4", byName["ProductVersion"])
	assert.Equal(t, "hello", byName["MYPROP"])
	assert.Equal(t, "{66666666-7777-8888-9999-AAAAAAAAAAAA}", byName["UpgradeCode"])

	comps, err := db.Table("Component")
	require.NoError(t, err)
	require.Len(t, comps, 1)
	assert.Equal(t, "Main", comps[0]["Component"])
	assert.Equal(t, "INSTALLFOLDER", comps[0]["Directory_"])
	assert.IsType(t, int16(0), comps[0]["Attributes"])
	assert.Nil(t, comps[0]["Condition"], "a NULL cell reads as nil")
	files, err := db.Table("File")
	require.NoError(t, err)
	require.Len(t, files, 1)
	assert.Equal(t, files[0]["File"], comps[0]["KeyPath"], "the first file is the component key path")
	assert.IsType(t, int32(0), files[0]["FileSize"])

	upgrades, err := db.Table("Upgrade")
	require.NoError(t, err)
	assert.Len(t, upgrades, 2, "MajorUpgrade emits a remove-older and a detect-newer row")
	for _, r := range upgrades {
		assert.Equal(t, "{66666666-7777-8888-9999-AAAAAAAAAAAA}", r["UpgradeCode"])
	}

	_, err = db.Table("NoSuchTable")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "NoSuchTable")
}

func TestOpen_Summary(t *testing.T) {
	db := openExamplePackage(t, readerTestPackage())
	s := db.Summary()
	assert.Equal(t, "Arm64;1033", s.Template())
	assert.Equal(t, "Reader App", s.Subject())
	assert.Equal(t, "Reader Co", s.Author())
	assert.Equal(t, "Installation Database", s.Title())
	assert.Equal(t, "Installer", s.Keywords())
	assert.Regexp(t, `^\{[0-9A-F-]{36}\}$`, s.Revision())
	assert.Equal(t, 500, s.PageCount(), "Arm64 requires Windows Installer 5.0")
	assert.Equal(t, 2, s.WordCount())
	assert.NotEmpty(t, s.CreatingApp())
	assert.False(t, s.SaveTime().IsZero())
}

func TestOpen_RejectsNonMSI(t *testing.T) {
	_, err := msi.Open(bytes.NewReader([]byte("not a compound file")))
	require.Error(t, err)
}
