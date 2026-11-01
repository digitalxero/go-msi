package msi_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	msi "go.digitalxero.dev/go-msi"
)

func TestAppSearchSerializesEmptySignatureTable(t *testing.T) {
	cases := map[string]func(msi.PackageBuilder){
		"registry raw": func(b msi.PackageBuilder) {
			b.Search("SAVED_PATH").InRegistry(msi.RegistryRootHKLM, `Software\GoMSISearch`, "InstallFolder").AsRawValue()
		},
		"registry directory": func(b msi.PackageBuilder) {
			b.Search("SAVED_PATH").InRegistry(msi.RegistryRootHKLM, `Software\GoMSISearch`, "InstallFolder").AsDirectory()
		},
		"ini raw": func(b msi.PackageBuilder) {
			b.Search("SAVED_PATH").InIniFile("settings.ini", "Install", "Path", 0).AsRawValue()
		},
		"component directory": func(b msi.PackageBuilder) {
			b.Search("SAVED_PATH").ByComponentID("{12345678-1234-4234-8234-123456789ABC}").AsDirectory()
		},
		"directory": func(b msi.PackageBuilder) {
			b.Search("SAVED_PATH").InDirectory(`C:\GoMSISearch`, 0).Done()
		},
	}
	for name, configure := range cases {
		t.Run(name, func(t *testing.T) {
			b := authoringPackage("payload")
			configure(b)
			_, db := authoredBytes(t, b)
			assert.Contains(t, db.Tables(), "Signature")
			rows, err := db.Table("Signature")
			require.NoError(t, err, "the table must exist even without a file-signature row")
			assert.Empty(t, rows, "dummy signatures would change lookup semantics")
			search, err := db.Table("AppSearch")
			require.NoError(t, err)
			require.Len(t, search, 1)
			assert.Equal(t, "SAVED_PATH", search[0]["Property"])
		})
	}
}

func TestAppSearchPreservesRawLocatorAndFileSignatureRows(t *testing.T) {
	b := authoringPackage("payload")
	b.Search("SAVED_PATH").InRegistry(msi.RegistryRootHKLM, `Software\GoMSISearch`, "InstallFolder").AsRawValue()
	b.Search("MATCHED_FILE").InDirectory(`C:\GoMSISearch`, 1).MatchingFile("app.exe").
		WithVersion("1.0.0", "2.0.0").WithSize(10, 100).WithLanguages("1033").Done()
	_, db := authoredBytes(t, b)
	search, err := db.Table("AppSearch")
	require.NoError(t, err)
	require.Len(t, search, 2)
	signatures := map[string]any{}
	for _, row := range search {
		signatures[row["Property"].(string)] = row["Signature_"]
	}
	rows, err := db.Table("Signature")
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, msi.Row{
		"Signature": signatures["MATCHED_FILE"], "FileName": "app.exe",
		"MinVersion": "1.0.0", "MaxVersion": "2.0.0", "MinSize": int32(10), "MaxSize": int32(100),
		"MinDate": nil, "MaxDate": nil, "Languages": "1033",
	}, rows[0])
	assert.NotEqual(t, signatures["SAVED_PATH"], rows[0]["Signature"])
	locators, err := db.Table("RegLocator")
	require.NoError(t, err)
	require.Len(t, locators, 1)
	assert.Equal(t, msi.Row{
		"Signature_": signatures["SAVED_PATH"], "Root": int16(2), "Key": `Software\GoMSISearch`,
		"Name": "InstallFolder", "Type": int16(2),
	}, locators[0])
}

func TestNoAppSearchDoesNotAddSearchSchema(t *testing.T) {
	_, db := authoredBytes(t, authoringPackage("payload"))
	for _, table := range []string{"AppSearch", "Signature", "RegLocator", "IniLocator", "CompLocator", "DrLocator"} {
		assert.NotContains(t, db.Tables(), table)
		_, err := db.Table(table)
		assert.Error(t, err)
	}
	for _, table := range []string{"InstallUISequence", "InstallExecuteSequence"} {
		rows, err := db.Table(table)
		require.NoError(t, err)
		for _, row := range rows {
			assert.NotEqual(t, "AppSearch", row["Action"])
		}
	}
}
