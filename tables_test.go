package msi

// msi_tables_test.go
// Internal tests (package msix) for the unexported MSI table layer: MSITYPE
// bitfields, real table-stream serialization (column-major, cell encodings,
// primary-key row sorting), the canonical table catalog and the _Validation
// table generation. Golden values come from the format spec (Wine msipriv.h /
// table.c, rust-msi column.rs test vectors).

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMSIColumnTypeBits_GoldenValues(t *testing.T) {
	tests := []struct {
		name string
		col  msiColumn
		want uint16
	}{
		{
			name: "s72 key",
			col:  newMSIColumnBuilder().WithType(msiColIdentifier).WithWidth(72).AsKey().Build(),
			want: 0x2D48,
		},
		{
			name: "s64 key",
			col:  newMSIColumnBuilder().WithType(msiColIdentifier).WithWidth(64).AsKey().Build(),
			want: 0x2D40,
		},
		{
			name: "s38 key",
			col:  newMSIColumnBuilder().WithType(msiColIdentifier).WithWidth(38).AsKey().Build(),
			want: 0x2D26,
		},
		{
			name: "s32 key",
			col:  newMSIColumnBuilder().WithType(msiColIdentifier).WithWidth(32).AsKey().Build(),
			want: 0x2D20,
		},
		{
			name: "L255",
			col:  newMSIColumnBuilder().WithType(msiColText).WithWidth(255).AsNullable().AsLocalizable().Build(),
			want: 0x1FFF,
		},
		{
			name: "s255",
			col:  newMSIColumnBuilder().WithType(msiColText).WithWidth(255).Build(),
			want: 0x0DFF,
		},
		{
			name: "S255",
			col:  newMSIColumnBuilder().WithType(msiColText).WithWidth(255).AsNullable().Build(),
			want: 0x1DFF,
		},
		{
			name: "s0",
			col:  newMSIColumnBuilder().WithType(msiColText).Build(),
			want: 0x0D00,
		},
		{
			name: "S0",
			col:  newMSIColumnBuilder().WithType(msiColText).AsNullable().Build(),
			want: 0x1D00,
		},
		{
			name: "l0",
			col:  newMSIColumnBuilder().WithType(msiColText).AsLocalizable().Build(),
			want: 0x0F00,
		},
		{
			name: "l255",
			col:  newMSIColumnBuilder().WithType(msiColFilename).WithWidth(255).AsLocalizable().Build(),
			want: 0x0FFF,
		},
		{
			name: "L64",
			col:  newMSIColumnBuilder().WithType(msiColText).WithWidth(64).AsNullable().AsLocalizable().Build(),
			want: 0x1F40,
		},
		{
			name: "S38 guid",
			col:  newMSIColumnBuilder().WithType(msiColGUID).WithWidth(38).AsNullable().Build(),
			want: 0x1D26,
		},
		{
			name: "i2",
			col:  newMSIColumnBuilder().WithType(msiColInteger).WithWidth(2).Build(),
			want: 0x0502,
		},
		{
			name: "i2 key",
			col:  newMSIColumnBuilder().WithType(msiColInteger).WithWidth(2).AsKey().Build(),
			want: 0x2502,
		},
		{
			name: "I2",
			col:  newMSIColumnBuilder().WithType(msiColInteger).WithWidth(2).AsNullable().Build(),
			want: 0x1502,
		},
		{
			name: "i4",
			col:  newMSIColumnBuilder().WithType(msiColDoubleInteger).WithWidth(4).Build(),
			want: 0x0104,
		},
		{
			name: "I4",
			col:  newMSIColumnBuilder().WithType(msiColDoubleInteger).WithWidth(4).AsNullable().Build(),
			want: 0x1104,
		},
		{
			name: "v0",
			col:  newMSIColumnBuilder().WithType(msiColBinary).Build(),
			want: 0x0900,
		},
		{
			name: "V0",
			col:  newMSIColumnBuilder().WithType(msiColBinary).AsNullable().Build(),
			want: 0x1900,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equalf(t, tc.want, tc.col.typeBits(), "want 0x%04X got 0x%04X", tc.want, tc.col.typeBits())
		})
	}
}

func TestMSIColumnTypeToMSIType_DeprecatedButCorrect(t *testing.T) {
	assert.Equal(t, int16(0x0502), msiColumnTypeToMSIType(msiColInteger))
	assert.Equal(t, int16(0x0104), msiColumnTypeToMSIType(msiColDoubleInteger))
	assert.Equal(t, int16(0x0900), msiColumnTypeToMSIType(msiColBinary))
	assert.Equal(t, int16(0x0D00), msiColumnTypeToMSIType(msiColText))
	assert.Equal(t, int16(0x0D00), msiColumnTypeToMSIType(msiColIdentifier))
}

// TestSerializeRealTableData_SpecWorkedExample reproduces the spec's worked
// Property-table example byte-for-byte, including the requirement that rows
// are sorted by the string key's POOL ID (not lexicographically): rows are
// inserted in reverse order and must come out sorted.
func TestSerializeRealTableData_SpecWorkedExample(t *testing.T) {
	tbl := newMSITableBuilder().WithName("Property").WithColumns(
		newMSIColumnBuilder().WithName("Property").WithType(msiColIdentifier).WithWidth(72).AsKey().Build(),
		newMSIColumnBuilder().WithName("Value").WithType(msiColText).AsLocalizable().Build(),
	).Build()

	pool := newMSIStringPool(1252)
	require.Equal(t, uint32(1), pool.addString("Property"))
	require.Equal(t, uint32(2), pool.addString("Value"))
	require.Equal(t, uint32(3), pool.addString("ProductName"))
	require.Equal(t, uint32(4), pool.addString("Foo"))
	require.Equal(t, uint32(5), pool.addString("ProductVersion"))
	require.Equal(t, uint32(6), pool.addString("1.0.0"))

	// Insert out of order: ProductVersion (pool ID 5) before ProductName (3).
	require.NoError(t, tbl.addRow(newMSIRowBuilderFromTable(tbl).WithValues("ProductVersion", "1.0.0").Build()))
	require.NoError(t, tbl.addRow(newMSIRowBuilderFromTable(tbl).WithValues("ProductName", "Foo").Build()))

	got, err := serializeRealTableData(tbl, pool)
	require.NoError(t, err)
	assert.Equal(t, []byte{
		0x03, 0x00, 0x05, 0x00, // col 1 Property: refs 3, 5 (sorted by pool ID)
		0x04, 0x00, 0x06, 0x00, // col 2 Value: refs 4, 6
	}, got)
}

func TestSerializeRealTableData_CellEncodingsAndNulls(t *testing.T) {
	tbl := newMSITableBuilder().WithName("T").WithColumns(
		newMSIColumnBuilder().WithName("K").WithType(msiColIdentifier).WithWidth(72).AsKey().Build(),
		newMSIColumnBuilder().WithName("A").WithType(msiColInteger).WithWidth(2).AsNullable().Build(),
		newMSIColumnBuilder().WithName("B").WithType(msiColDoubleInteger).WithWidth(4).AsNullable().Build(),
		newMSIColumnBuilder().WithName("C").WithType(msiColText).WithWidth(255).AsNullable().Build(),
	).Build()

	pool := newMSIStringPool(1252)
	require.Equal(t, uint32(1), pool.addString("k1"))
	require.Equal(t, uint32(2), pool.addString("k2"))
	require.Equal(t, uint32(3), pool.addString("v"))

	// Row with all-NULL non-key cells, and one with the rust-msi test vectors
	// (int16 0x123 -> 23 81, int32 0x1234567 -> 67 45 23 81).
	require.NoError(t, tbl.addRow(newMSIRowBuilderFromTable(tbl).WithValues("k1", nil, nil, nil).Build()))
	require.NoError(t, tbl.addRow(newMSIRowBuilderFromTable(tbl).WithValues("k2", int16(0x123), int32(0x1234567), "v").Build()))

	got, err := serializeRealTableData(tbl, pool)
	require.NoError(t, err)
	assert.Equal(t, []byte{
		0x01, 0x00, 0x02, 0x00, // col K: refs 1, 2
		0x00, 0x00, 0x23, 0x81, // col A: NULL int16 = raw 0; 0x123+0x8000
		0x00, 0x00, 0x00, 0x00, 0x67, 0x45, 0x23, 0x81, // col B: NULL int32 = raw 0; 0x1234567^0x80000000
		0x00, 0x00, 0x03, 0x00, // col C: NULL string = ref 0; ref 3
	}, got)
}

func TestSerializeRealTableData_NegativeAndZeroIntegers(t *testing.T) {
	tbl := newMSITableBuilder().WithName("T").WithColumns(
		newMSIColumnBuilder().WithName("K").WithType(msiColInteger).WithWidth(2).AsKey().Build(),
		newMSIColumnBuilder().WithName("D").WithType(msiColDoubleInteger).WithWidth(4).AsNullable().Build(),
	).Build()
	pool := newMSIStringPool(1252)

	// int16 -1 -> ff 7f; int16 0 -> 00 80 (distinct from NULL); int32 -1 -> ff ff ff 7f.
	require.NoError(t, tbl.addRow(newMSIRowBuilderFromTable(tbl).WithValues(int16(-1), int32(-1)).Build()))
	require.NoError(t, tbl.addRow(newMSIRowBuilderFromTable(tbl).WithValues(int16(0), nil).Build()))

	got, err := serializeRealTableData(tbl, pool)
	require.NoError(t, err)
	assert.Equal(t, []byte{
		0xFF, 0x7F, 0x00, 0x80, // col K: -1 sorts before 0 (stored 0x7FFF < 0x8000)
		0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00, 0x00, // col D: -1; NULL
	}, got)
}

// TestSerializeRealTableData_SortNullKeyFirst checks the comparator on an
// int16 key: NULL (stored 0) sorts first, then logical order via the +0x8000
// transform. The key column is made nullable purely to admit a NULL key cell.
func TestSerializeRealTableData_SortNullKeyFirst(t *testing.T) {
	tbl := newMSITableBuilder().WithName("T").WithColumns(
		newMSIColumnBuilder().WithName("Seq").WithType(msiColInteger).WithWidth(2).AsKey().AsNullable().Build(),
		newMSIColumnBuilder().WithName("Val").WithType(msiColText).WithWidth(255).AsNullable().Build(),
	).Build()

	pool := newMSIStringPool(1252)
	require.Equal(t, uint32(1), pool.addString("a"))
	require.Equal(t, uint32(2), pool.addString("b"))
	require.Equal(t, uint32(3), pool.addString("c"))

	require.NoError(t, tbl.addRow(newMSIRowBuilderFromTable(tbl).WithValues(int16(5), "a").Build()))
	require.NoError(t, tbl.addRow(newMSIRowBuilderFromTable(tbl).WithValues(nil, "b").Build()))
	require.NoError(t, tbl.addRow(newMSIRowBuilderFromTable(tbl).WithValues(int16(-1), "c").Build()))

	got, err := serializeRealTableData(tbl, pool)
	require.NoError(t, err)
	assert.Equal(t, []byte{
		0x00, 0x00, 0xFF, 0x7F, 0x05, 0x80, // col Seq: NULL, -1, 5
		0x02, 0x00, 0x03, 0x00, 0x01, 0x00, // col Val: b, c, a
	}, got)
}

func TestSerializeRealTableData_MultiColumnKeySort(t *testing.T) {
	tbl := newMSITableBuilder().WithName("T").WithColumns(
		newMSIColumnBuilder().WithName("A").WithType(msiColIdentifier).WithWidth(72).AsKey().Build(),
		newMSIColumnBuilder().WithName("N").WithType(msiColInteger).WithWidth(2).AsKey().Build(),
	).Build()

	pool := newMSIStringPool(1252)
	require.Equal(t, uint32(1), pool.addString("x"))
	require.Equal(t, uint32(2), pool.addString("y"))

	// (y,1) then (x,2) then (x,1): expect (x,1), (x,2), (y,1).
	require.NoError(t, tbl.addRow(newMSIRowBuilderFromTable(tbl).WithValues("y", int16(1)).Build()))
	require.NoError(t, tbl.addRow(newMSIRowBuilderFromTable(tbl).WithValues("x", int16(2)).Build()))
	require.NoError(t, tbl.addRow(newMSIRowBuilderFromTable(tbl).WithValues("x", int16(1)).Build()))

	got, err := serializeRealTableData(tbl, pool)
	require.NoError(t, err)
	assert.Equal(t, []byte{
		0x01, 0x00, 0x01, 0x00, 0x02, 0x00, // col A: x, x, y
		0x01, 0x80, 0x02, 0x80, 0x01, 0x80, // col N: 1, 2, 1
	}, got)
}

func TestSerializeRealTableData_DuplicatePrimaryKeyRejected(t *testing.T) {
	tbl := newMSITableBuilder().WithName("T").WithColumns(
		newMSIColumnBuilder().WithName("K").WithType(msiColIdentifier).WithWidth(72).AsKey().Build(),
		newMSIColumnBuilder().WithName("V").WithType(msiColText).AsNullable().Build(),
	).Build()

	pool := newMSIStringPool(1252)
	pool.addString("k")
	pool.addString("v1")
	pool.addString("v2")

	require.NoError(t, tbl.addRow(newMSIRowBuilderFromTable(tbl).WithValues("k", "v1").Build()))
	require.NoError(t, tbl.addRow(newMSIRowBuilderFromTable(tbl).WithValues("k", "v2").Build()))

	_, err := serializeRealTableData(tbl, pool)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate primary key")
}

func TestSerializeRealTableData_ReservedIntegerValuesRejected(t *testing.T) {
	pool := newMSIStringPool(1252)

	i2tbl := newMSITableBuilder().WithName("T").WithColumns(
		newMSIColumnBuilder().WithName("K").WithType(msiColInteger).WithWidth(2).AsKey().Build(),
	).Build()
	require.NoError(t, i2tbl.addRow(newMSIRowBuilderFromTable(i2tbl).WithValues(int16(-32768)).Build()))
	_, err := serializeRealTableData(i2tbl, pool)
	require.Error(t, err, "int16 -32768 stores as 0 == NULL and must be rejected")

	i4tbl := newMSITableBuilder().WithName("T").WithColumns(
		newMSIColumnBuilder().WithName("K").WithType(msiColDoubleInteger).WithWidth(4).AsKey().Build(),
	).Build()
	require.NoError(t, i4tbl.addRow(newMSIRowBuilderFromTable(i4tbl).WithValues(int32(-2147483648)).Build()))
	_, err = serializeRealTableData(i4tbl, pool)
	require.Error(t, err, "int32 -2147483648 stores as 0 == NULL and must be rejected")
}

func TestSerializeRealTableData_EmptyTableProducesNoBytes(t *testing.T) {
	pool := newMSIStringPool(1252)
	got, err := serializeRealTableData(createMSIPropertyTable(), pool)
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestSerializeRealTableData_BinaryCell(t *testing.T) {
	tbl := newMSITableBuilder().WithName("Binary").WithColumns(
		newMSIColumnBuilder().WithName("Name").WithType(msiColIdentifier).WithWidth(72).AsKey().Build(),
		newMSIColumnBuilder().WithName("Data").WithType(msiColBinary).AsNullable().Build(),
	).Build()

	pool := newMSIStringPool(1252)
	require.Equal(t, uint32(1), pool.addString("blob1"))
	require.Equal(t, uint32(2), pool.addString("blob2"))

	require.NoError(t, tbl.addRow(newMSIRowBuilderFromTable(tbl).WithValues("blob1", []byte{0xDE, 0xAD}).Build()))
	require.NoError(t, tbl.addRow(newMSIRowBuilderFromTable(tbl).WithValues("blob2", nil).Build()))

	got, err := serializeRealTableData(tbl, pool)
	require.NoError(t, err)
	assert.Equal(t, []byte{
		0x01, 0x00, 0x02, 0x00, // col Name: refs 1, 2
		0x01, 0x00, 0x00, 0x00, // col Data: present = 1, NULL = 0
	}, got)
}

// TestCatalogFactoriesMatchCatalog verifies every table factory derives
// exactly from the canonical catalog: same column names, order (positions
// 1..n contiguous), category, width, key/nullable/localizable flags.
func TestCatalogFactoriesMatchCatalog(t *testing.T) {
	factories := []struct {
		name    string
		factory func() msiTable
	}{
		{msiPropTableName, createMSIPropertyTable},
		{msiDirTableName, createMSIDirectoryTable},
		{msiCompTableName, createMSIComponentTable},
		{msiFeatTableName, createMSIFeatureTable},
		{msiFeatCompTableName, createMSIFeatureComponentsTable},
		{msiFileTableName, createMSIFileTable},
		{msiMediaTableName, createMSIMediaTable},
		{msiInstallExecSeqTableName, createMSIInstallExecuteSequenceTable},
		{msiInstallUISeqTableName, createMSIInstallUISequenceTable},
		{msiAdminExecSeqTableName, createMSIAdminExecuteSequenceTable},
		{msiAdminUISeqTableName, createMSIAdminUISequenceTable},
		{msiAdvtExecSeqTableName, createMSIAdvtExecuteSequenceTable},
		{msiValidationTableName, createMSIValidationTable},
		// P3 starters
		{"Registry", createMSIRegistryTable},
		{"Shortcut", createMSIShortcutTable},
		{"Icon", createMSIIconTable},
		{"Binary", createMSIBinaryTable},
		{"MsiFileHash", createMSIMsiFileHashTable},
		{"RemoveRegistry", createMSIRemoveRegistryTable},
		{"RemoveFile", createMSIRemoveFileTable},
		{"CreateFolder", createMSICreateFolderTable},
		{"Environment", createMSIEnvironmentTable},
		// P4 — services, upgrades, search, error/actiontext
		{"ServiceInstall", createMSIServiceInstallTable},
		{"ServiceControl", createMSIServiceControlTable},
		{"MsiServiceConfig", createMSIMsiServiceConfigTable},
		{"MsiServiceConfigFailureActions", createMSIMsiServiceConfigFailureActionsTable},
		{"Upgrade", createMSIUpgradeTable},
		{"LaunchCondition", createMSILaunchConditionTable},
		{"Signature", createMSISignatureTable},
		{"AppSearch", createMSIAppSearchTable},
		{"RegLocator", createMSIRegLocatorTable},
		{"IniLocator", createMSIIniLocatorTable},
		{"CompLocator", createMSICompLocatorTable},
		{"DrLocator", createMSIDrLocatorTable},
		{"Error", createMSIErrorTable},
		{"ActionText", createMSIActionTextTable},
		{"CustomAction", createMSICustomActionTable},
		// P6 — UI tables
		{"Dialog", createMSIDialogTable},
		{"Control", createMSIControlTable},
		{"ControlEvent", createMSIControlEventTable},
		{"ControlCondition", createMSIControlConditionTable},
		{"EventMapping", createMSIEventMappingTable},
		{"TextStyle", createMSITextStyleTable},
		{"UIText", createMSIUITextTable},
		{"RadioButton", createMSIRadioButtonTable},
		{"ListBox", createMSIListBoxTable},
		{"ComboBox", createMSIComboBoxTable},
		{"ListView", createMSIListViewTable},
		{"CheckBox", createMSICheckBoxTable},
		{"Billboard", createMSIBillboardTable},
		{"BBControl", createMSIBBControlTable},
		// P10 — patch tables
		{"Patch", createMSIPatchTable},
		{"PatchPackage", createMSIPatchPackageTable},
		{"MsiPatchHeaders", createMSIMsiPatchHeadersTable},
		{"MsiPatchMetadata", createMSIMsiPatchMetadataTable},
		{"MsiPatchSequence", createMSIMsiPatchSequenceTable},
		// P11 — COM / advertising tables
		{"Class", createMSIClassTable},
		{"ProgId", createMSIProgIdTable},
		{"Extension", createMSIExtensionTable},
		{"Verb", createMSIVerbTable},
		{"MIME", createMSIMIMETable},
		{"TypeLib", createMSITypeLibTable},
		{"AppId", createMSIAppIdTable},
		{"PublishComponent", createMSIPublishComponentTable},
		// P11 — assembly / font / ODBC tables
		{"MsiAssembly", createMSIMsiAssemblyTable},
		{"MsiAssemblyName", createMSIMsiAssemblyNameTable},
		{"Font", createMSIFontTable},
		{"ODBCDataSource", createMSIODBCDataSourceTable},
		{"ODBCDriver", createMSIODBCDriverTable},
		{"ODBCTranslator", createMSIODBCTranslatorTable},
		{"ODBCAttribute", createMSIODBCAttributeTable},
		{"ODBCSourceAttribute", createMSIODBCSourceAttributeTable},
		// P11 — file-ops / registration / security tables
		{"DuplicateFile", createMSIDuplicateFileTable},
		{"MoveFile", createMSIMoveFileTable},
		{"IniFile", createMSIIniFileTable},
		{"RemoveIniFile", createMSIRemoveIniFileTable},
		{"IsolatedComponent", createMSIIsolatedComponentTable},
		{"BindImage", createMSIBindImageTable},
		{"SelfReg", createMSISelfRegTable},
		{"ReserveCost", createMSIReserveCostTable},
		{"Complus", createMSIComplusTable},
		{"LockPermissions", createMSILockPermissionsTable},
		{"MsiLockPermissionsEx", createMSIMsiLockPermissionsExTable},
		{"MsiDigitalCertificate", createMSIMsiDigitalCertificateTable},
		{"MsiDigitalSignature", createMSIMsiDigitalSignatureTable},
		{"MsiEmbeddedChainer", createMSIMsiEmbeddedChainerTable},
		{"MsiEmbeddedUI", createMSIMsiEmbeddedUITable},
		// P11 — merge-module tables
		{"ModuleSignature", createMSIModuleSignatureTable},
		{"ModuleComponents", createMSIModuleComponentsTable},
		{"ModuleDependency", createMSIModuleDependencyTable},
		{"ModuleExclusion", createMSIModuleExclusionTable},
		{"ModuleConfiguration", createMSIModuleConfigurationTable},
		{"ModuleSubstitution", createMSIModuleSubstitutionTable},
		{"ModuleIgnoreTable", createMSIModuleIgnoreTableTable},
		{"ModuleInstallExecuteSequence", createMSIModuleInstallExecuteSequenceTable},
		{"ModuleInstallUISequence", createMSIModuleInstallUISequenceTable},
		{"ModuleAdminExecuteSequence", createMSIModuleAdminExecuteSequenceTable},
		{"ModuleAdminUISequence", createMSIModuleAdminUISequenceTable},
	}

	catalogNames := make([]string, 0, len(allMSICatalogTables()))
	for _, def := range allMSICatalogTables() {
		catalogNames = append(catalogNames, def.name)
	}

	for _, f := range factories {
		t.Run(f.name, func(t *testing.T) {
			assert.Contains(t, catalogNames, f.name, "factory table must be in the catalog")

			def, ok := msiCatalogTable(f.name)
			require.True(t, ok)

			tbl := f.factory()
			require.Equal(t, def.name, tbl.name())

			cols := tbl.columns()
			require.Equal(t, len(def.columns), len(cols))
			for i, col := range cols {
				cc := def.columns[i]
				assert.Equal(t, i+1, cc.position, "catalog positions must be 1..n contiguous")
				assert.Equal(t, cc.name, col.name())
				assert.Equal(t, cc.colType, col.typ())
				assert.Equal(t, cc.width, col.width())
				assert.Equal(t, cc.key, col.isKey())
				assert.Equal(t, cc.nullable, col.isNullable())
				assert.Equal(t, cc.localizable, col.isLocalizable())
			}

			// Key columns must come first (MSI requires key columns leading).
			seenNonKey := false
			for _, col := range cols {
				if col.isKey() {
					assert.False(t, seenNonKey, "key columns must precede non-key columns")
				} else {
					seenNonKey = true
				}
			}
		})
	}

	// Every catalog table has a factory above (both directions covered).
	assert.Equal(t, len(factories), len(allMSICatalogTables()))
}

// TestCatalogTypeBits_GoldenValues spot-checks the _Columns Type values the
// catalog-derived schemas produce against the spec's canonical table.
func TestCatalogTypeBits_GoldenValues(t *testing.T) {
	want := map[string]map[string]uint16{
		msiPropTableName: {
			"Property": 0x2D48, // s72 key
			"Value":    0x0F00, // l0
		},
		msiDirTableName: {
			"Directory":        0x2D48, // s72 key
			"Directory_Parent": 0x1D48, // S72
			"DefaultDir":       0x0FFF, // l255
		},
		msiCompTableName: {
			"Component":   0x2D48, // s72 key
			"ComponentId": 0x1D26, // S38
			"Directory_":  0x0D48, // s72
			"Attributes":  0x0502, // i2
			"Condition":   0x1FFF, // L255
			"KeyPath":     0x1D48, // S72
		},
		msiFeatTableName: {
			"Feature": 0x2D26, // s38 key
			"Title":   0x1F40, // L64
			"Display": 0x1502, // I2
			"Level":   0x0502, // i2
		},
		msiFileTableName: {
			"File":     0x2D48, // s72 key
			"FileName": 0x0FFF, // l255
			"FileSize": 0x0104, // i4
			"Language": 0x1D14, // S20
			"Sequence": 0x0502, // i2
		},
		msiMediaTableName: {
			"DiskId":       0x2502, // i2 key
			"LastSequence": 0x0502, // i2
			"Cabinet":      0x1DFF, // S255
			"VolumeLabel":  0x1D20, // S32
		},
		msiInstallExecSeqTableName: {
			"Action":    0x2D48, // s72 key
			"Condition": 0x1FFF, // L255
			"Sequence":  0x1502, // I2
		},
		msiValidationTableName: {
			"Table":     0x2D20, // s32 key
			"Column":    0x2D20, // s32 key
			"Nullable":  0x0D04, // s4
			"MinValue":  0x1104, // I4
			"MaxValue":  0x1104, // I4
			"KeyTable":  0x1DFF, // S255
			"KeyColumn": 0x1502, // I2
			"Category":  0x1D20, // S32
			"Set":       0x1DFF, // S255
		},
	}

	for tableName, colWant := range want {
		tbl := createMSITableFromCatalog(tableName)
		for _, col := range tbl.columns() {
			w, ok := colWant[col.name()]
			if !ok {
				continue
			}
			assert.Equalf(t, w, col.typeBits(), "%s.%s want 0x%04X got 0x%04X", tableName, col.name(), w, col.typeBits())
		}
	}
}

func TestSystemTableSchemas(t *testing.T) {
	tt := createMSITablesTable()
	require.Len(t, tt.columns(), 1)
	assert.Equal(t, "Name", tt.columns()[0].name())
	assert.Equal(t, uint16(0x2D40), tt.columns()[0].typeBits(), "_Tables.Name is s64 key")

	ct := createMSIColumnsTable()
	require.Len(t, ct.columns(), 4)
	assert.Equal(t, uint16(0x2D40), ct.columns()[0].typeBits(), "_Columns.Table is s64 key")
	assert.Equal(t, uint16(0x2502), ct.columns()[1].typeBits(), "_Columns.Number is i2 key")
	assert.Equal(t, uint16(0x0D40), ct.columns()[2].typeBits(), "_Columns.Name is s64")
	assert.Equal(t, uint16(0x0502), ct.columns()[3].typeBits(), "_Columns.Type is i2")
}

func TestPopulateMSIValidationRows(t *testing.T) {
	custom := newMSITableBuilder().WithName("CustomTable").WithColumns(
		newMSIColumnBuilder().WithName("Id").WithType(msiColIdentifier).WithWidth(72).AsKey().Build(),
	).Build()

	tables := map[string]msiTable{
		msiPropTableName: createMSIPropertyTable(),
		msiFileTableName: createMSIFileTable(),
		"CustomTable":    custom, // not in catalog: skipped without error
	}

	vt, err := populateMSIValidationRows(tables)
	require.NoError(t, err)
	require.Equal(t, msiValidationTableName, vt.name())

	// Property (2 cols) + File (8 cols) + _Validation itself (10 cols) = 20.
	require.Len(t, vt.rows(), 20)

	find := func(table, column string) []any {
		t.Helper()
		for _, r := range vt.rows() {
			vals := r.values()
			if vals[0] == table && vals[1] == column {
				return vals
			}
		}
		t.Fatalf("no _Validation row for %s.%s", table, column)
		return nil
	}

	// Property.Value: non-nullable Text, no range, no foreign key, no set.
	vals := find(msiPropTableName, "Value")
	assert.Equal(t, "N", vals[2])
	assert.Nil(t, vals[3]) // MinValue NULL
	assert.Nil(t, vals[4]) // MaxValue NULL
	assert.Nil(t, vals[5]) // KeyTable NULL
	assert.Nil(t, vals[6]) // KeyColumn NULL
	assert.Equal(t, "Text", vals[7])
	assert.Nil(t, vals[8]) // Set NULL
	assert.Equal(t, "String value for property. Never null or empty.", vals[9])

	// File.FileSize: numeric range present, Category NULL per the docs
	// (numeric columns express their range via MinValue/MaxValue).
	vals = find(msiFileTableName, "FileSize")
	assert.Equal(t, "N", vals[2])
	assert.Equal(t, int32(0), vals[3])
	assert.Equal(t, int32(2147483647), vals[4])
	assert.Nil(t, vals[7]) // Category NULL

	// File.Version: foreign key into File column 1, category Version.
	vals = find(msiFileTableName, "Version")
	assert.Equal(t, "Y", vals[2])
	assert.Equal(t, msiFileTableName, vals[5])
	assert.Equal(t, int16(1), vals[6])
	assert.Equal(t, "Version", vals[7])

	// _Validation.KeyColumn describes itself: nullable, range 1..32.
	vals = find(msiValidationTableName, "KeyColumn")
	assert.Equal(t, "Y", vals[2])
	assert.Equal(t, int32(1), vals[3])
	assert.Equal(t, int32(32), vals[4])
	assert.Nil(t, vals[7])

	// _Validation.Nullable: Set is "Y;N".
	vals = find(msiValidationTableName, "Nullable")
	assert.Equal(t, "N", vals[2])
	assert.Equal(t, "Y;N", vals[8])

	// No rows leaked for the custom table.
	for _, r := range vt.rows() {
		assert.NotEqual(t, "CustomTable", r.values()[0])
	}
}

func TestPopulateMSIValidationRows_ValidationAlreadyPresentNotDuplicated(t *testing.T) {
	tables := map[string]msiTable{
		msiValidationTableName: createMSIValidationTable(),
	}
	vt, err := populateMSIValidationRows(tables)
	require.NoError(t, err)
	assert.Len(t, vt.rows(), 10, "_Validation rows must not be emitted twice")
}

func TestPopulateMSIValidationRows_SerializesWithSpecTypeBits(t *testing.T) {
	// End-to-end sanity: the generated rows validate and serialize without
	// error once their strings are interned.
	vt, err := populateMSIValidationRows(map[string]msiTable{
		msiPropTableName: createMSIPropertyTable(),
	})
	require.NoError(t, err)

	pool := newMSIStringPool(1252)
	for _, r := range vt.rows() {
		for _, v := range r.values() {
			if s, ok := v.(string); ok && s != "" {
				pool.addString(s)
			}
		}
	}
	data, err := serializeRealTableData(vt, pool)
	require.NoError(t, err)
	// Row size: 2 (Table) + 2 (Column) + 2 (Nullable) + 4 + 4 + 2 + 2 + 2 + 2 + 2 = 24.
	assert.Equal(t, 24*len(vt.rows()), len(data))
}

func TestColumnValidate_GUID(t *testing.T) {
	col := newMSIColumnBuilder().WithName("G").WithType(msiColGUID).WithWidth(38).Build()

	assert.NoError(t, col.validate("{12345678-1234-1234-1234-123456789ABC}"))
	assert.NoError(t, col.validate("{00000000-0000-0000-0000-000000000000}"))

	assert.Error(t, col.validate("{12345678-1234-1234-1234-123456789abc}"), "lowercase hex is invalid")
	assert.Error(t, col.validate("12345678-1234-1234-1234-123456789ABC"), "braces are mandatory")
	assert.Error(t, col.validate("{12345678123412341234123456789ABC}"), "hyphens are mandatory")
	assert.Error(t, col.validate("{12345678-1234-1234-1234-123456789AB}"), "wrong length")
	assert.Error(t, col.validate("{12345678-1234-1234-1234-123456789ABG}"), "non-hex digit")
	assert.Error(t, col.validate(""), "empty == NULL is invalid on a non-nullable column")
}

func TestColumnValidate_Version(t *testing.T) {
	col := newMSIColumnBuilder().WithName("V").WithType(msiColVersion).WithWidth(72).Build()

	assert.NoError(t, col.validate("1"))
	assert.NoError(t, col.validate("1.2"))
	assert.NoError(t, col.validate("1.2.3"))
	assert.NoError(t, col.validate("1.2.3.4"))
	assert.NoError(t, col.validate("65535.65535.65535.65535"))
	assert.NoError(t, col.validate("0.0.0.0"))

	assert.Error(t, col.validate("65536"), "field above 65535")
	assert.Error(t, col.validate("1.2.3.4.5"), "more than 4 fields")
	assert.Error(t, col.validate(".12"), "empty leading field")
	assert.Error(t, col.validate("1..2"), "empty middle field")
	assert.Error(t, col.validate("1.2."), "empty trailing field")
	assert.Error(t, col.validate("abc"), "non-numeric")
	assert.Error(t, col.validate("1.2.3-beta"), "non-numeric field")
	assert.Error(t, col.validate(""), "empty == NULL is invalid on a non-nullable column")

	// Empty string on a NULLABLE Version column is NULL, hence valid
	// (File.Version is blank for unversioned files).
	nullable := newMSIColumnBuilder().WithName("V").WithType(msiColVersion).WithWidth(72).AsNullable().Build()
	assert.NoError(t, nullable.validate(""))
	assert.NoError(t, nullable.validate(nil))
}

func TestColumnValidate_Cabinet(t *testing.T) {
	col := newMSIColumnBuilder().WithName("C").WithType(msiColCabinet).WithWidth(255).AsNullable().Build()

	assert.NoError(t, col.validate("#cab1"), "embedded stream reference")
	assert.NoError(t, col.validate("#Cab1"), "embedded stream names are case-sensitive identifiers")
	assert.NoError(t, col.validate("disk1.cab"))
	assert.NoError(t, col.validate("data.cab"))
	assert.NoError(t, col.validate("noext"))

	assert.Error(t, col.validate("#1cab"), "identifier cannot start with a digit")
	assert.Error(t, col.validate("waytoolongname.cab"), "name part over 8 chars")
	assert.Error(t, col.validate("name.cabx"), "extension over 3 chars")
	assert.Error(t, col.validate("a.b.c"), "multiple dots")
	assert.Error(t, col.validate("na me.cab"), "space in short name")
	assert.Error(t, col.validate("data|x.cab"), "invalid character")
}

func TestColumnValidate_PointerAndEmptyNullSemantics(t *testing.T) {
	nonNull := newMSIColumnBuilder().WithName("T").WithType(msiColText).WithWidth(255).Build()
	nullable := newMSIColumnBuilder().WithName("T").WithType(msiColText).WithWidth(255).AsNullable().Build()

	assert.Error(t, nonNull.validate(nil))
	assert.Error(t, nonNull.validate(""), "empty string is NULL in MSI")
	assert.Error(t, nonNull.validate((*string)(nil)))
	assert.NoError(t, nullable.validate(nil))
	assert.NoError(t, nullable.validate(""))
	assert.NoError(t, nullable.validate((*string)(nil)))

	s := "hello"
	assert.NoError(t, nonNull.validate(&s))

	intCol := newMSIColumnBuilder().WithName("I").WithType(msiColInteger).WithWidth(2).AsNullable().Build()
	var ip *int16
	assert.NoError(t, intCol.validate(ip))
	v := int16(7)
	assert.NoError(t, intCol.validate(&v))
	assert.Error(t, intCol.validate("seven"))
}
