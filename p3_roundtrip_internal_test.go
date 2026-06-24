package msi

// msi_p3_roundtrip_internal_test.go
// White-box (package msix) round-trip CONTENT tests for the new public
// NewPackage() compile path and the P3 tables (Registry, Shortcut, Icon,
// Binary, Component, FeatureComponents).
//
// These tests build a package through the PUBLIC builder API WITHOUT
// WithSkipValidation, emit it with WriteMSI, then read the bytes straight back
// with the package-private readMSIDatabase and assert the EXACT cell content of
// every P3 row. They are the regression guard for the empty-Registry/empty-
// Shortcut bug (swallowed addRow errors) and for the reader's binary-column
// round trip: the original TestP3Builders only asserted buf.Len()>100 and used
// WithSkipValidation, so a zero-row Registry table shipped undetected.
//
// They live in package msix (not msix_test) because readMSIDatabase, msiTable
// and the row/cell accessors are unexported.

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildP3RoundTripPackage builds a package exercising every P3 table through
// the public API and returns the emitted MSI bytes plus the read-back database.
// It deliberately does NOT call WithSkipValidation so the in-build ICE pass and
// every addRow error path run for real.
func buildP3RoundTripPackage(t *testing.T) (msiDatabase, []byte) {
	t.Helper()

	iconData := []byte{0x00, 0x01, 0x02, 0x03, 0xFF}
	binData := []byte("helper-binary\x00payload")

	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithUpgradeCode("{ABCDEF01-2345-6789-ABCD-EF0123456789}").
		WithProductName("P3 RoundTrip").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		Icon("AppIcon", FileSourceFromBytes(iconData)).Binary(

		"Helper", FileSourceFromBytes(

			binData))

	install := b.RootDirectory("INSTALLFOLDER", "P3App")
	comp := install.Component("Main").AssociateToFeature("MainFeature")
	comp.WithFile("app.exe", FileSourceFromBytes([]byte("MZ main executable")))

	// RegistryKey path with multiple typed values + AsKeyPath. encodeRegistryValue
	// maps string->as-is, int->#decimal, []byte->#xHEX.
	comp.RegistryKey(RegistryRootHKLM, `Software\Acme`).
		Value("Version", "1.0").
		Value("Count", 42).
		Value("Blob", []byte{1, 2, 3}).
		AsKeyPath()

	// Flat WithRegistry path (HKCU) funnels into the same registryEntries slice.
	comp.WithRegistry(RegistryRootHKCU, `Software\Acme`, "User", "x")

	// Non-advertised shortcut with an icon: Target is a Formatted [#File] ref,
	// Icon_/IconIndex set, Hotkey NULL, ShowCmd 1.
	comp.Shortcut("App.lnk", "[#app.exe]").
		Arguments("/start").
		Description("Launch P3 RoundTrip").
		Icon("AppIcon", 3)

	b.Feature("MainFeature").
		WithTitle("Main Feature").
		WithDescription("Primary feature").
		WithDisplay(1).
		WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err, "Build must succeed for a valid P3 package")

	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf),
		"WriteMSI must succeed (proves addRow errors are NOT swallowed and tables populate)")

	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err, "readMSIDatabase must round-trip a P3 package (proves binary columns read back)")
	require.NoError(t, readDB.validate())

	return readDB, buf.Bytes()
}

// findRow returns the first row whose cell at keyIdx equals key.
func findRow(t *testing.T, tbl msiTable, keyIdx int, key string) []any {
	t.Helper()
	for _, r := range tbl.rows() {
		vals := r.values()
		if keyIdx < len(vals) {
			if s, ok := vals[keyIdx].(string); ok && s == key {
				return vals
			}
		}
	}
	t.Fatalf("no row in table with cell[%d]==%q", keyIdx, key)
	return nil
}

func TestCompileP3_RegistryRowContent(t *testing.T) {
	readDB, _ := buildP3RoundTripPackage(t)

	regTbl, err := readDB.GetTable("Registry")
	require.NoError(t, err)

	// THE shipped bug: Registry table had ZERO rows. We declared 4 reg values
	// (Version, Count, Blob via RegistryKey + User via flat WithRegistry).
	rows := regTbl.rows()
	require.Len(t, rows, 4, "Registry must have all 4 rows (regression: shipped with 0)")
	require.Greater(t, len(rows), 0, "Registry must not be empty (the exact shipped defect)")

	// Registry columns: [Registry(PK), Root, Key, Name, Value, Component_].
	// Find rows by their Name cell (index 3).
	verRow := findRow(t, regTbl, 3, "Version")
	assert.Equal(t, int16(2), verRow[1], "Root for HKLM must be int16(2), NOT the named RegistryRoot type")
	assert.Equal(t, `Software\Acme`, verRow[2])
	assert.Equal(t, "1.0", verRow[4], "string registry value stored as-is")
	assert.Equal(t, "Main", verRow[5], "Component_ FK")

	countRow := findRow(t, regTbl, 3, "Count")
	assert.Equal(t, int16(2), countRow[1])
	assert.Equal(t, "#42", countRow[4], "int registry value encodes as #decimal")

	blobRow := findRow(t, regTbl, 3, "Blob")
	assert.Equal(t, "#x010203", blobRow[4], "[]byte registry value encodes as #xHEX")

	userRow := findRow(t, regTbl, 3, "User")
	assert.Equal(t, int16(1), userRow[1], "flat WithRegistry HKCU Root must be int16(1)")
	assert.Equal(t, "x", userRow[4])
}

func TestCompileP3_ShortcutRowContent(t *testing.T) {
	readDB, _ := buildP3RoundTripPackage(t)

	scTbl, err := readDB.GetTable("Shortcut")
	require.NoError(t, err)
	rows := scTbl.rows()
	require.Len(t, rows, 1, "Shortcut must have its single row (regression: shipped with 0)")

	// Shortcut columns: [Shortcut(PK), Directory_, Name, Component_, Target,
	// Arguments, Description, Hotkey, Icon_, IconIndex, ShowCmd, WkDir].
	v := rows[0].values()
	assert.Equal(t, "INSTALLFOLDER", v[1], "Directory_")
	assert.Equal(t, "App.lnk", v[2], "Name")
	assert.Equal(t, "Main", v[3], "Component_")
	assert.Equal(t, "[#app.exe]", v[4], "Target is the verbatim Formatted [#File] ref for a non-advertised shortcut")
	assert.Equal(t, "/start", v[5], "Arguments")
	assert.Equal(t, "Launch P3 RoundTrip", v[6], "Description")
	assert.Nil(t, v[7], "Hotkey must be NULL (no hotkey support), not a stored 0")
	assert.Equal(t, "AppIcon", v[8], "Icon_")
	assert.Equal(t, int16(3), v[9], "IconIndex must be the int16 value set on the icon")
	assert.Equal(t, int16(1), v[10], "ShowCmd is int16(1)")
}

func TestCompileP3_ShortcutNullIconWhenUnset(t *testing.T) {
	// A shortcut with no Icon() call must round-trip Icon_/IconIndex as NULL,
	// not a stored 0 / empty-string.
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("SC Null Icon").
		WithManufacturer("go-msix").
		WithVersion("1.0.0")
	install := b.RootDirectory("INSTALLFOLDER", "App")
	comp := install.Component("Main").AssociateToFeature("F")
	comp.WithFile("app.exe", FileSourceFromBytes([]byte("MZ")))
	comp.Shortcut("Plain.lnk", "[#app.exe]")
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))

	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	scTbl, err := readDB.GetTable("Shortcut")
	require.NoError(t, err)
	require.Len(t, scTbl.rows(), 1)
	v := scTbl.rows()[0].values()
	assert.Nil(t, v[8], "Icon_ must be NULL when no icon set")
	assert.Nil(t, v[9], "IconIndex must be NULL when no icon set")
}

func TestCompileP3_AdvertisedShortcutTargetIsFeature(t *testing.T) {
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("SC Advertised").
		WithManufacturer("go-msix").
		WithVersion("1.0.0")
	install := b.RootDirectory("INSTALLFOLDER", "App")
	comp := install.Component("Main").AssociateToFeature("MainFeature")
	comp.WithFile("app.exe", FileSourceFromBytes([]byte("MZ")))
	comp.Shortcut("Adv.lnk", "[#app.exe]").Advertised("MainFeature")
	b.Feature("MainFeature").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))

	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	scTbl, err := readDB.GetTable("Shortcut")
	require.NoError(t, err)
	require.Len(t, scTbl.rows(), 1)
	v := scTbl.rows()[0].values()
	assert.Equal(t, "MainFeature", v[4], "advertised shortcut Target must be the feature name")
}

func TestCompileP3_IconBinaryPayloadRoundTrip(t *testing.T) {
	readDB, _ := buildP3RoundTripPackage(t)

	iconTbl, err := readDB.GetTable("Icon")
	require.NoError(t, err)
	require.Len(t, iconTbl.rows(), 1)
	iv := iconTbl.rows()[0].values()
	assert.Equal(t, "AppIcon", iv[0])
	gotIcon, ok := iv[1].([]byte)
	require.True(t, ok, "Icon.Data must read back as []byte, got %T", iv[1])
	assert.Equal(t, []byte{0x00, 0x01, 0x02, 0x03, 0xFF}, gotIcon,
		"Icon payload bytes must round-trip exactly (reader side-stream resolution)")

	binTbl, err := readDB.GetTable("Binary")
	require.NoError(t, err)
	require.Len(t, binTbl.rows(), 1)
	bv := binTbl.rows()[0].values()
	assert.Equal(t, "Helper", bv[0])
	gotBin, ok := bv[1].([]byte)
	require.True(t, ok, "Binary.Data must read back as []byte, got %T", bv[1])
	assert.Equal(t, []byte("helper-binary\x00payload"), gotBin,
		"Binary payload bytes must round-trip exactly")
}

func TestCompileP3_ComponentAndFeatureComponents(t *testing.T) {
	readDB, _ := buildP3RoundTripPackage(t)

	compTbl, err := readDB.GetTable("Component")
	require.NoError(t, err)
	require.Len(t, compTbl.rows(), 1)
	// Component columns: [Component(PK), ComponentId, Directory_, Attributes, Condition, KeyPath].
	cv := compTbl.rows()[0].values()
	assert.Equal(t, "Main", cv[0], "Component PK")
	assert.Equal(t, "INSTALLFOLDER", cv[2], "Component.Directory_")
	// AsKeyPath wired the registry PK as the component KeyPath; it must be a
	// non-empty "reg.."-style string (a Registry primary key), not a file ID.
	kp, ok := cv[5].(string)
	require.True(t, ok, "KeyPath must be a string, got %T", cv[5])
	assert.Contains(t, kp, "reg", "AsKeyPath must point Component.KeyPath at a Registry row PK")

	fcTbl, err := readDB.GetTable("FeatureComponents")
	require.NoError(t, err)
	require.Len(t, fcTbl.rows(), 1)
	// FeatureComponents columns: [Feature_, Component_].
	fcv := fcTbl.rows()[0].values()
	assert.Equal(t, "MainFeature", fcv[0])
	assert.Equal(t, "Main", fcv[1])
}

// TestCompileP3_AddRowErrorsPropagate locks in that addRow errors are no longer
// swallowed: a Registry cell whose Go type the row validator rejects (a named
// enum left un-narrowed) must surface as a hard compile error, not a silently
// dropped row. We exercise the boundary directly through the table builder the
// compiler uses, asserting the contract that the compile path relies on.
func TestCompileP3_AddRowErrorsPropagate(t *testing.T) {
	regTbl := createMSITableFromCatalog("Registry")

	// Passing the named RegistryRoot type (NOT int16) into the Root Integer
	// column must be REJECTED by addRow. This is exactly the cell the compiler
	// now converts with int16(); if anyone re-introduces the raw enum the
	// compile will fail loudly here.
	badRow := newMSIRowBuilder().WithColumns(regTbl.columns()...).
		WithValues("reg00", RegistryRootHKLM, `Software\X`, "N", "V", "Comp").Build()
	err := regTbl.addRow(badRow)
	require.Error(t, err, "a raw RegistryRoot-typed Root cell must be rejected by addRow")
	assert.Contains(t, err.Error(), "Root")

	// The int16-narrowed cell (what the compiler emits) must be accepted.
	goodRow := newMSIRowBuilder().WithColumns(regTbl.columns()...).
		WithValues("reg00", int16(RegistryRootHKLM), `Software\X`, "N", "V", "Comp").Build()
	require.NoError(t, regTbl.addRow(goodRow), "int16-narrowed Root cell must be accepted")
}
