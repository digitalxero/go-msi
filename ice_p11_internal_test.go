package msi

// msi_ice_p11_internal_test.go — P11 ICE coverage goldens. Adding a never-emitted
// table's schema to the catalog extends the generic ICE03 category+FK validator
// to it; these tests prove that real validation fires (bad FK/category) and that
// a clean row passes, using synthetic databases (there is no public builder for
// these tables).

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// iceTableWithRows builds a catalog table populated with the given rows
// (each a []any of cell values in column order).
func iceTableWithRows(t *testing.T, name string, rows ...[]any) msiTable {
	t.Helper()
	tbl := createMSITableFromCatalog(name)
	for _, vals := range rows {
		row := newMSIRowBuilder().WithColumns(tbl.columns()...).WithValues(vals...).Build()
		require.NoErrorf(t, tbl.addRow(row), "addRow %s %v", name, vals)
	}
	return tbl
}

// iceDBWith builds a database from the given tables and runs ICE03 over it,
// returning only the ICE03 findings for the named table.
func runICE03For(t *testing.T, table string, tables ...msiTable) []Finding {
	t.Helper()
	b := newMSIDatabaseBuilder()
	for _, tbl := range tables {
		b.WithTable(tbl)
	}
	db, err := b.Build()
	require.NoError(t, err)
	ctx := newIceContext(db, msiSummaryInfo{})
	var out []Finding
	for _, f := range runICE03(ctx) {
		if f.ICE() == "ICE03" && f.Table() == table {
			out = append(out, f)
		}
	}
	return out
}

func findingForColumn(findings []Finding, column string) Finding {
	for _, f := range findings {
		if f.Column() == column {
			return f
		}
	}
	return nil
}

func TestICE03_Class_ForeignKey(t *testing.T) {
	const clsid = "{11112222-3333-4444-5555-666677778888}"
	comp := iceTableWithRows(t, "Component",
		[]any{"CompA", "{AAAA2222-3333-4444-5555-666677778888}", "INSTALLFOLDER", int16(0), nil, nil})
	feat := iceTableWithRows(t, "Feature",
		[]any{"FeatA", nil, "Feat", nil, int16(0), int16(1), nil, int16(0)})

	classRow := func(component string) []any {
		return []any{clsid, "LocalServer32", component, nil, nil, nil, nil, nil, nil, nil, nil, "FeatA", nil}
	}

	// Bad: Component_ "CompB" does not exist in the Component table.
	bad := iceTableWithRows(t, "Class", classRow("CompB"))
	findings := runICE03For(t, "Class", bad, comp, feat)
	f := findingForColumn(findings, "Component_")
	require.NotNil(t, f, "dangling Class.Component_ must be an ICE03 finding")
	assert.Equal(t, SeverityError, f.Severity())

	// Clean: Component_ "CompA" resolves, Feature_ "FeatA" resolves.
	good := iceTableWithRows(t, "Class", classRow("CompA"))
	assert.Empty(t, runICE03For(t, "Class", good, comp, feat), "resolved FKs are ICE03-clean")
}

func TestICE03_Extension_ForeignKey(t *testing.T) {
	comp := iceTableWithRows(t, "Component",
		[]any{"CompA", "{AAAA2222-3333-4444-5555-666677778888}", "INSTALLFOLDER", int16(0), nil, nil})
	feat := iceTableWithRows(t, "Feature",
		[]any{"FeatA", nil, "Feat", nil, int16(0), int16(1), nil, int16(0)})

	// Extension(Extension, Component_, ProgId_, MIME_, Feature_); Feature_ dangles.
	bad := iceTableWithRows(t, "Extension", []any{"txt", "CompA", nil, nil, "NoSuchFeature"})
	findings := runICE03For(t, "Extension", bad, comp, feat)
	require.NotNil(t, findingForColumn(findings, "Feature_"), "dangling Extension.Feature_ must be flagged")

	good := iceTableWithRows(t, "Extension", []any{"txt", "CompA", nil, nil, "FeatA"})
	assert.Empty(t, runICE03For(t, "Extension", good, comp, feat))
}

func TestICE03_ODBCAttribute_DriverForeignKey(t *testing.T) {
	comp := iceTableWithRows(t, "Component",
		[]any{"CompA", "{AAAA2222-3333-4444-5555-666677778888}", "INSTALLFOLDER", int16(0), nil, nil})
	file := iceTableWithRows(t, "File",
		[]any{"filDriver", "CompA", "driver.dll", int32(10), nil, nil, nil, int16(1)})
	driver := iceTableWithRows(t, "ODBCDriver",
		[]any{"DrvA", "CompA", "My Driver", "filDriver", nil})

	// ODBCAttribute.Driver_ "DrvB" does not exist in ODBCDriver.
	bad := iceTableWithRows(t, "ODBCAttribute", []any{"DrvB", "CPTimeout", "60"})
	findings := runICE03For(t, "ODBCAttribute", bad, driver, comp, file)
	require.NotNil(t, findingForColumn(findings, "Driver_"), "dangling ODBCAttribute.Driver_ must be flagged")

	good := iceTableWithRows(t, "ODBCAttribute", []any{"DrvA", "CPTimeout", "60"})
	assert.Empty(t, runICE03For(t, "ODBCAttribute", good, driver, comp, file))
}

func TestICE03_Font_FileForeignKey(t *testing.T) {
	comp := iceTableWithRows(t, "Component",
		[]any{"CompA", "{AAAA2222-3333-4444-5555-666677778888}", "INSTALLFOLDER", int16(0), nil, nil})
	file := iceTableWithRows(t, "File",
		[]any{"filFont", "CompA", "arial.ttf", int32(10), nil, nil, nil, int16(1)})

	bad := iceTableWithRows(t, "Font", []any{"filMissing", "Arial"})
	require.NotNil(t, findingForColumn(runICE03For(t, "Font", bad, file, comp), "File_"),
		"dangling Font.File_ must be flagged")

	good := iceTableWithRows(t, "Font", []any{"filFont", "Arial"})
	assert.Empty(t, runICE03For(t, "Font", good, file, comp))
}

func TestICE03_ModuleComponents_ForeignKeys(t *testing.T) {
	comp := iceTableWithRows(t, "Component",
		[]any{"CompA", "{AAAA2222-3333-4444-5555-666677778888}", "INSTALLFOLDER", int16(0), nil, nil})
	sig := iceTableWithRows(t, "ModuleSignature",
		[]any{"MyModule.GUID", int16(1033), "1.0.0"})

	// ModuleComponents(Component, ModuleID, Language); Component "CompZ" dangles.
	bad := iceTableWithRows(t, "ModuleComponents", []any{"CompZ", "MyModule.GUID", int16(1033)})
	findings := runICE03For(t, "ModuleComponents", bad, comp, sig)
	require.NotNil(t, findingForColumn(findings, "Component"), "dangling ModuleComponents.Component must be flagged")

	good := iceTableWithRows(t, "ModuleComponents", []any{"CompA", "MyModule.GUID", int16(1033)})
	assert.Empty(t, runICE03For(t, "ModuleComponents", good, comp, sig))
}

// runRule builds a database from the given tables and runs one ICE rule.
func runRule(t *testing.T, fn func(*iceContext) []Finding, tables ...msiTable) []Finding {
	t.Helper()
	b := newMSIDatabaseBuilder()
	for _, tbl := range tables {
		b.WithTable(tbl)
	}
	db, err := b.Build()
	require.NoError(t, err)
	return fn(newIceContext(db, msiSummaryInfo{}))
}

func compRow(name, guid, dir string, attrs int16) []any {
	var g any
	if guid != "" {
		g = guid
	}
	return []any{name, g, dir, attrs, nil, nil}
}

func TestICE08_DuplicateComponentId(t *testing.T) {
	guid := "{AAAA2222-3333-4444-5555-666677778888}"
	dup := iceTableWithRows(t, "Component",
		compRow("C1", guid, "INSTALLFOLDER", 0),
		compRow("C2", guid, "INSTALLFOLDER", 0))
	assert.NotEmpty(t, runRule(t, runICE08, dup), "duplicate ComponentId must be ICE08")

	uniq := iceTableWithRows(t, "Component",
		compRow("C1", guid, "INSTALLFOLDER", 0),
		compRow("C2", "{BBBB2222-3333-4444-5555-666677778888}", "INSTALLFOLDER", 0))
	assert.Empty(t, runRule(t, runICE08, uniq))
}

func TestICE16_ProductNameLength(t *testing.T) {
	long := iceTableWithRows(t, "Property", []any{"ProductName", strings.Repeat("x", 64)})
	assert.NotEmpty(t, runRule(t, runICE16, long), "ProductName > 63 chars must be ICE16")
	ok := iceTableWithRows(t, "Property", []any{"ProductName", strings.Repeat("x", 63)})
	assert.Empty(t, runRule(t, runICE16, ok))
}

func TestICE21_OrphanComponent(t *testing.T) {
	comp := iceTableWithRows(t, "Component", compRow("C1", "", "INSTALLFOLDER", 0))
	assert.NotEmpty(t, runRule(t, runICE21, comp), "unreferenced component must be ICE21")

	fc := iceTableWithRows(t, "FeatureComponents", []any{"F1", "C1"})
	assert.Empty(t, runRule(t, runICE21, comp, fc))
}

func TestICE24_ProductPropertyFormats(t *testing.T) {
	bad := iceTableWithRows(t, "Property",
		[]any{"ProductCode", "not-a-guid"},
		[]any{"ProductVersion", "notaversion"},
		[]any{"ProductLanguage", "english"})
	assert.Len(t, runRule(t, runICE24, bad), 3, "bad ProductCode/Version/Language each flagged")

	good := iceTableWithRows(t, "Property",
		[]any{"ProductCode", "{12345678-1234-1234-1234-1234567890AB}"},
		[]any{"ProductVersion", "1.0.0"},
		[]any{"ProductLanguage", "1033"})
	assert.Empty(t, runRule(t, runICE24, good))
}

func TestICE45_ReservedAttributeBits(t *testing.T) {
	bad := iceTableWithRows(t, "Component", compRow("C1", "", "INSTALLFOLDER", 0x4000))
	assert.NotEmpty(t, runRule(t, runICE45, bad), "reserved Component.Attributes bit must be ICE45")
	good := iceTableWithRows(t, "Component", compRow("C1", "", "INSTALLFOLDER", 0x10))
	assert.Empty(t, runRule(t, runICE45, good))
}

func TestICE09_SystemFolderComponent(t *testing.T) {
	notPerm := iceTableWithRows(t, "Component", compRow("C1", "", "SystemFolder", 0))
	f := runRule(t, runICE09, notPerm)
	require.NotEmpty(t, f, "non-permanent system-folder component must be ICE09")
	assert.Equal(t, SeverityWarning, f[0].Severity())

	perm := iceTableWithRows(t, "Component", compRow("C1", "", "SystemFolder", 0x10))
	assert.Empty(t, runRule(t, runICE09, perm))
}

func TestICE74_UpgradeActionProperty(t *testing.T) {
	// (ActionProperty is an UpperCase column, so the builder already rejects a
	// lowercase value at insert time; ICE74's remaining check is membership in
	// SecureCustomProperties.)
	upper := iceTableWithRows(t, "Upgrade",
		[]any{"{99992222-3333-4444-5555-666677778888}", "1.0.0", "2.0.0", nil, int32(0), nil, "WIX_UPGRADE"})

	// Not listed in SecureCustomProperties -> error.
	assert.NotEmpty(t, runRule(t, runICE74, upper), "ActionProperty not in SecureCustomProperties must be ICE74")

	// Listed -> clean.
	secure := iceTableWithRows(t, "Property", []any{"SecureCustomProperties", "WIX_UPGRADE"})
	assert.Empty(t, runRule(t, runICE74, upper, secure))
}

func TestICE33_AdvertisingRegistry(t *testing.T) {
	// Registry(Registry, Root, Key, Name, Value, Component_); Root 0 = HKCR.
	bad := iceTableWithRows(t, "Registry",
		[]any{"reg1", int16(0), `CLSID\{...}\InprocServer32`, nil, "x", "C1"})
	f := runRule(t, runICE33, bad)
	require.NotEmpty(t, f, "HKCR CLSID registry key must be ICE33")
	assert.Equal(t, SeverityWarning, f[0].Severity())

	// A normal HKLM application key is fine.
	good := iceTableWithRows(t, "Registry",
		[]any{"reg1", int16(2), `Software\MyApp`, "InstallDir", "[INSTALLFOLDER]", "C1"})
	assert.Empty(t, runRule(t, runICE33, good))
}

func TestICE83_AssemblyNeedsName(t *testing.T) {
	// MsiAssembly(Component_, Feature_, File_Manifest, File_Application, Attributes).
	asm := iceTableWithRows(t, "MsiAssembly",
		[]any{"AsmComp", "FeatA", nil, nil, int16(0)})
	assert.NotEmpty(t, runRule(t, runICE83, asm), "assembly without MsiAssemblyName must be ICE83")

	name := iceTableWithRows(t, "MsiAssemblyName",
		[]any{"AsmComp", "Name", "MyAssembly"})
	assert.Empty(t, runRule(t, runICE83, asm, name))
}
