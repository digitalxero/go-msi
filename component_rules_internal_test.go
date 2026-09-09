package msi

// component_rules_internal_test.go
// Tests for the component-level contracts the compiler and the ICE rules
// enforce: release-stable component GUIDs, the RegistryKeyPath attribute,
// ICE18/ICE92 reading the real KeyPath column, ICE80's 32-bit-directory half,
// sibling 8.3 short names, and builder-owned Property rejection.

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// componentGUIDs builds the package and returns Component -> ComponentId.
func componentGUIDs(t *testing.T, b PackageBuilder) map[string]string {
	t.Helper()
	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	db, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	tbl, err := db.GetTable("Component")
	require.NoError(t, err)
	out := map[string]string{}
	for _, r := range tbl.rows() {
		v := r.values()
		out[v[0].(string)] = v[1].(string)
	}
	return out
}

func releasePackage(version, productCode string, plat Platform, upgradeCode string) PackageBuilder {
	b := NewPackage().
		WithProductName("Stable App").
		WithManufacturer("Tester").
		WithVersion(version).
		WithProductCode(productCode)
	if upgradeCode != "" {
		b = b.WithUpgradeCode(upgradeCode)
	}
	if plat != platformUnset {
		b = b.WithPlatform(plat)
	}
	c := b.RootDirectory("INSTALLFOLDER", "Stable App").Component("Main").AssociateToFeature("F")
	c.WithFile("app.exe", FileSourceFromBytes([]byte("MZ")))
	b.Feature("F").WithLevel(1)
	return b
}

// TestComponentGUID_StableAcrossReleases is the Windows Installer component
// rule: the same resource at the same location keeps its GUID from one release
// (new ProductCode, new version) to the next, as long as the UpgradeCode is
// shared. Without it an uninstall of the old release removes the new one's
// files.
func TestComponentGUID_StableAcrossReleases(t *testing.T) {
	const upgrade = "{66666666-7777-8888-9999-AAAAAAAAAAAA}"
	v1 := componentGUIDs(t, releasePackage("1.0.0", "{11111111-2222-3333-4444-555555555555}", platformUnset, upgrade))
	v2 := componentGUIDs(t, releasePackage("1.1.0", "{22222222-2222-3333-4444-555555555555}", platformUnset, upgrade))
	require.NotEmpty(t, v1["Main"])
	assert.Equal(t, v1["Main"], v2["Main"], "component GUID must survive a release with a new ProductCode")

	// The x86 and x64 builds of a product share an UpgradeCode but install
	// distinct resources, so their components must not share GUIDs.
	x86 := componentGUIDs(t, releasePackage("1.0.0", "{11111111-2222-3333-4444-555555555555}", Platform_Intel, upgrade))
	assert.NotEqual(t, v1["Main"], x86["Main"], "platform must be part of the component GUID seed")

	// No UpgradeCode: the ProductCode is the only identity and is used instead.
	noUp1 := componentGUIDs(t, releasePackage("1.0.0", "{11111111-2222-3333-4444-555555555555}", platformUnset, ""))
	noUp2 := componentGUIDs(t, releasePackage("1.0.0", "{11111111-2222-3333-4444-555555555555}", platformUnset, ""))
	noUp3 := componentGUIDs(t, releasePackage("1.0.0", "{33333333-2222-3333-4444-555555555555}", platformUnset, ""))
	assert.Equal(t, noUp1["Main"], noUp2["Main"])
	assert.NotEqual(t, noUp1["Main"], noUp3["Main"])
}

// TestRegistryKeyPath_SetsAttribute proves AsKeyPath produces a component the
// installer reads as registry-keyed: KeyPath is the Registry PK and
// Attributes carries msidbComponentAttributesRegistryKeyPath, whether or not
// the caller set attributes explicitly.
func TestRegistryKeyPath_SetsAttribute(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprintf("explicitAttrs=%v", explicit), func(t *testing.T) {
			b := NewPackage().
				WithProductName("Reg App").WithManufacturer("Tester").WithVersion("1.0.0").
				WithProductCode("{11111111-2222-3333-4444-555555555555}")
			c := b.RootDirectory("INSTALLFOLDER", "Reg App").Component("RegComp").AssociateToFeature("F")
			if explicit {
				c.WithAttributes(msidbComponentAttributesPermanent)
			}
			c.RegistryKey(RegistryRootHKLM, `Software\RegApp`).Value("Installed", "1").AsKeyPath()
			b.Feature("F").WithLevel(1)

			pkg, err := b.Build()
			require.NoError(t, err)
			var buf bytes.Buffer
			require.NoError(t, pkg.WriteMSI(&buf))
			db, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
			require.NoError(t, err)

			regTbl, err := db.GetTable("Registry")
			require.NoError(t, err)
			require.Len(t, regTbl.rows(), 1)
			regID := regTbl.rows()[0].values()[0].(string)

			compTbl, err := db.GetTable("Component")
			require.NoError(t, err)
			require.Len(t, compTbl.rows(), 1)
			v := compTbl.rows()[0].values()
			attrs := v[3].(int16)
			assert.NotZero(t, attrs&msidbComponentAttributesRegistryKeyPath, "RegistryKeyPath bit must be set, got 0x%X", attrs)
			assert.Equal(t, regID, v[iceComponentKeyPathColumn], "KeyPath must be the Registry row PK")
			if explicit {
				assert.NotZero(t, attrs&msidbComponentAttributesPermanent, "explicit attributes are kept")
				assert.Zero(t, attrs&msidbComponentAttributes64bit, "explicit attributes are not overridden by the platform default")
			} else {
				assert.NotZero(t, attrs&msidbComponentAttributes64bit, "x64 default still applies")
			}

			// The full validator must agree the package is clean (ICE18 in particular).
			ctx := newIceContext(db, msiSummaryInfo{Template: "x64;1033"})
			for _, f := range runICE18(ctx) {
				t.Errorf("unexpected ICE18 finding: %s", f.Message())
			}
		})
	}
}

// compRowKP is compRow with a KeyPath.
func compRowKP(name, dir string, attrs int16, keyPath string) []any {
	return []any{name, "{AAAA2222-3333-4444-5555-666677778888}", dir, attrs, nil, keyPath}
}

func TestICE18_KeyPathResolvesByAttributes(t *testing.T) {
	file := iceTableWithRows(t, "File", iceFileRow("F1", 0))
	// Registry, Root, Key, Name, Value, Component_.
	reg := iceTableWithRows(t, "Registry", []any{"R1", int16(2), `Software\App`, "V", "1", "C1"})
	regOther := iceTableWithRows(t, "Registry", []any{"R1", int16(2), `Software\App`, "V", "1", "C2"})

	t.Run("file keypath without bit is clean", func(t *testing.T) {
		comp := iceTableWithRows(t, "Component", compRowKP("C1", "INSTALLFOLDER", 0, "F1"))
		assert.Empty(t, runRule(t, runICE18, comp, file))
	})
	t.Run("registry keypath with bit is clean", func(t *testing.T) {
		comp := iceTableWithRows(t, "Component", compRowKP("C1", "INSTALLFOLDER", msidbComponentAttributesRegistryKeyPath, "R1"))
		assert.Empty(t, runRule(t, runICE18, comp, file, reg))
	})
	t.Run("registry keypath without bit is an error", func(t *testing.T) {
		comp := iceTableWithRows(t, "Component", compRowKP("C1", "INSTALLFOLDER", 0, "R1"))
		f := runRule(t, runICE18, comp, file, reg)
		require.Len(t, f, 1)
		assert.Equal(t, SeverityError, f[0].Severity())
		assert.Contains(t, f[0].Message(), "File")
	})
	t.Run("file keypath with bit set is an error", func(t *testing.T) {
		comp := iceTableWithRows(t, "Component", compRowKP("C1", "INSTALLFOLDER", msidbComponentAttributesRegistryKeyPath, "F1"))
		f := runRule(t, runICE18, comp, file, reg)
		require.Len(t, f, 1)
		assert.Contains(t, f[0].Message(), "Registry")
	})
	t.Run("registry keypath owned by another component is an error", func(t *testing.T) {
		comp := iceTableWithRows(t, "Component", compRowKP("C1", "INSTALLFOLDER", msidbComponentAttributesRegistryKeyPath, "R1"))
		assert.Len(t, runRule(t, runICE18, comp, file, regOther), 1)
	})
	t.Run("file keypath owned by another component is an error", func(t *testing.T) {
		comp := iceTableWithRows(t, "Component", compRowKP("C2", "INSTALLFOLDER", 0, "F1"))
		assert.Len(t, runRule(t, runICE18, comp, file), 1)
	})
	t.Run("odbc keypath is skipped when the table is absent", func(t *testing.T) {
		comp := iceTableWithRows(t, "Component", compRowKP("C1", "INSTALLFOLDER", msidbComponentAttributesODBCDataSource, "DSN1"))
		assert.Empty(t, runRule(t, runICE18, comp, file))
	})
}

// TestICE92_ReadsKeyPathColumn: a component with files, no GUID but a KeyPath
// is acceptable to ICE92; the rule used to read the Condition column and so
// could never see the KeyPath.
func TestICE92_ReadsKeyPathColumn(t *testing.T) {
	file := iceTableWithRows(t, "File", iceFileRow("F1", 0))
	withKP := iceTableWithRows(t, "Component", []any{"C1", nil, "INSTALLFOLDER", int16(0), nil, "F1"})
	assert.Empty(t, runRule(t, runICE92, withKP, file))
	withoutKP := iceTableWithRows(t, "Component", []any{"C1", nil, "INSTALLFOLDER", int16(0), nil, nil})
	assert.NotEmpty(t, runRule(t, runICE92, withoutKP, file))
}

func TestICE80_64BitComponentIn32BitDirectory(t *testing.T) {
	run := func(t *testing.T, template string, tables ...msiTable) []Finding {
		t.Helper()
		b := newMSIDatabaseBuilder()
		for _, tbl := range tables {
			b.WithTable(tbl)
		}
		db, err := b.Build()
		require.NoError(t, err)
		return runICE80(newIceContext(db, msiSummaryInfo{Template: template}))
	}
	for _, dir := range []string{"ProgramFilesFolder", "CommonFilesFolder", "SystemFolder"} {
		t.Run(dir, func(t *testing.T) {
			comp := iceTableWithRows(t, "Component", compRow("C1", "", dir, msidbComponentAttributes64bit))
			f := run(t, "x64;1033", comp)
			require.Len(t, f, 1, "64-bit component in %s must be ICE80 even in an x64 package", dir)
			assert.Equal(t, "Directory_", f[0].Column())
			assert.Equal(t, SeverityError, f[0].Severity())
		})
	}
	t.Run("32-bit component in 32-bit directory is clean", func(t *testing.T) {
		comp := iceTableWithRows(t, "Component", compRow("C1", "", "ProgramFilesFolder", 0))
		assert.Empty(t, run(t, "x64;1033", comp))
	})
	t.Run("64-bit component in 64-bit directory is clean", func(t *testing.T) {
		comp := iceTableWithRows(t, "Component", compRow("C1", "", "ProgramFiles64Folder", msidbComponentAttributes64bit))
		assert.Empty(t, run(t, "x64;1033", comp))
	})
	t.Run("template half still fires", func(t *testing.T) {
		comp := iceTableWithRows(t, "Component", compRow("C1", "", "ProgramFiles64Folder", msidbComponentAttributes64bit))
		assert.NotEmpty(t, run(t, "Intel;1033", comp))
	})
}

// TestShortNames_SiblingDirectoriesAndFilesShareANamespace: children of one
// directory (subdirectories and files alike) must get distinct 8.3 names.
func TestShortNames_SiblingDirectoriesAndFilesShareANamespace(t *testing.T) {
	b := NewPackage().
		WithProductName("Short App").WithManufacturer("Tester").WithVersion("1.0.0").
		WithProductCode("{11111111-2222-3333-4444-555555555555}")
	root := b.RootDirectory("INSTALLFOLDER", "Short App")
	root.Subdirectory("DirA", "MyLongDirectoryA")
	root.Subdirectory("DirB", "MyLongDirectoryB")
	root.Subdirectory("DirC", "MyLongFileNameDir")
	c := root.Component("Main").AssociateToFeature("F")
	c.WithFile("MyLongFileName.txt", FileSourceFromBytes([]byte("x")))
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	db, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	shortOf := func(column string) string {
		short, _, _ := strings.Cut(column, "|")
		return short
	}
	dirTbl, err := db.GetTable("Directory")
	require.NoError(t, err)
	shorts := map[string]string{}
	for _, r := range dirTbl.rows() {
		v := r.values()
		shorts[v[0].(string)] = shortOf(v[2].(string))
	}
	fileTbl, err := db.GetTable("File")
	require.NoError(t, err)
	require.Len(t, fileTbl.rows(), 1)
	fileShort := shortOf(fileTbl.rows()[0].values()[2].(string))

	assert.Equal(t, "MYLONG~1", shorts["DirA"])
	assert.Equal(t, "MYLONG~2", shorts["DirB"], "sibling directories must not share a short name")
	assert.NotEqual(t, shorts["DirC"], fileShort, "a file and a subdirectory in the same directory must not share a short name")
	assert.True(t, strings.HasPrefix(shorts["DirC"], "MYLONG~"))
	assert.True(t, strings.HasPrefix(fileShort, "MYLONG~"))
}

func TestCompile_RejectsBuilderOwnedProperties(t *testing.T) {
	for _, key := range msiBuilderOwnedProperties {
		t.Run(key, func(t *testing.T) {
			p := &msiPackage{
				productName:  "Prop Test",
				manufacturer: "Tester",
				version:      "1.0.0",
				productCode:  "{12345678-1234-1234-1234-123456789ABC}",
				upgradeCode:  "{ABCDEF01-2345-6789-ABCD-EF0123456789}",
				allUsers:     true,
				props:        map[string]string{key: "x"},
				dirEntries: map[string]*dirEntry{
					"TARGETDIR": {id: "TARGETDIR", defaultDir: "SourceDir"},
				},
			}
			_, err := compileMSIPackage(p)
			require.Error(t, err)
			assert.Contains(t, err.Error(), fmt.Sprintf("property %q is set by the package builder", key))
		})
	}

	t.Run("ProductLanguage override is allowed", func(t *testing.T) {
		p := &msiPackage{
			productName:  "Prop Test",
			manufacturer: "Tester",
			version:      "1.0.0",
			productCode:  "{12345678-1234-1234-1234-123456789ABC}",
			props:        map[string]string{"ProductLanguage": "1031"},
			dirEntries: map[string]*dirEntry{
				"TARGETDIR": {id: "TARGETDIR", defaultDir: "SourceDir"},
			},
		}
		db, err := compileMSIPackage(p)
		require.NoError(t, err)
		propTbl, err := db.GetTable("Property")
		require.NoError(t, err)
		var langs []string
		for _, r := range propTbl.rows() {
			if v := r.values(); v[0] == "ProductLanguage" {
				langs = append(langs, v[1].(string))
			}
		}
		assert.Equal(t, []string{"1031"}, langs)
	})
}
