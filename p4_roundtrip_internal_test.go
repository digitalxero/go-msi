package msi

// msi_p4_roundtrip_internal_test.go
// White-box (package msix) round-trip CONTENT tests for P4 tables: services
// (ServiceInstall/ServiceControl + MsiServiceConfig/FailureActions), upgrades
// (Upgrade/LaunchCondition/MajorUpgrade) and the AppSearch/locator subsystem.
//
// Each test builds a package through the PUBLIC builder API WITHOUT
// WithSkipValidation, emits with WriteMSI, reads the bytes straight back with
// readMSIDatabase, and asserts exact cell content (enum cells as int32/int16,
// nullable cells as nil, FK strings). They are the regression guard that the
// new builders actually emit rows (not empty tables) and that enum cells are
// narrowed at the boundary.

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildP4ServicePackage builds a component carrying a full service definition
// (install + control + delayed-auto-start config + failure actions) and returns
// the read-back database.
func buildP4ServicePackage(t *testing.T) msiDatabase {
	t.Helper()

	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithUpgradeCode("{ABCDEF01-2345-6789-ABCD-EF0123456789}").
		WithProductName("P4 Service").
		WithManufacturer("go-msix").
		WithVersion("1.0.0")

	comp := b.RootDirectory("INSTALLFOLDER", "P4App").
		Component("Svc").AssociateToFeature("MainFeature")
	comp.WithFile("svc.exe", []byte("MZ service host"))

	comp.ServiceInstall("MySvc").
		WithDisplayName("My Service").
		WithType(ServiceTypeOwnProcess).
		WithStartType(ServiceStartAuto).
		WithErrorControl(ServiceErrorNormal).
		Vital(true).
		WithStartName("LocalSystem").
		WithDescription("Demo service").
		WithDelayedAutoStart().
		FailureActions().
		WithResetPeriod(86400).
		Restart(60000).
		Restart(60000).
		None(0).
		Done()

	comp.ServiceControl("MySvc").
		OnInstall().Start().Stop().
		OnUninstall().Stop().Delete().
		Wait(true)

	b.Feature("MainFeature").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err, "Build must succeed for a valid service package")

	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))

	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.NoError(t, readDB.validate())
	return readDB
}

func TestCompileP4_ServiceInstallRowContent(t *testing.T) {
	readDB := buildP4ServicePackage(t)

	siTbl, err := readDB.GetTable("ServiceInstall")
	require.NoError(t, err)
	rows := siTbl.rows()
	require.Len(t, rows, 1, "ServiceInstall must have its single row (not empty)")

	// Columns: [ServiceInstall(PK), Name, DisplayName, ServiceType, StartType,
	// ErrorControl, LoadOrderGroup, Dependencies, StartName, Password, Arguments,
	// Component_, Description].
	v := rows[0].values()
	assert.Equal(t, "MySvc", v[1], "Name")
	assert.Equal(t, "My Service", v[2], "DisplayName")
	assert.Equal(t, int32(0x10), v[3], "ServiceType OwnProcess as int32 (i4 column)")
	assert.Equal(t, int32(2), v[4], "StartType Auto as int32")
	assert.Equal(t, int32(0x8001), v[5], "ErrorControl Normal|Vital(0x8000) as int32")
	assert.Nil(t, v[6], "LoadOrderGroup unset -> NULL")
	assert.Nil(t, v[7], "Dependencies unset -> NULL")
	assert.Equal(t, "LocalSystem", v[8], "StartName")
	assert.Nil(t, v[9], "Password unset -> NULL")
	assert.Equal(t, "Svc", v[11], "Component_ FK")
	assert.Equal(t, "Demo service", v[12], "Description")
}

func TestCompileP4_MsiServiceConfigDelayedAutoStart(t *testing.T) {
	readDB := buildP4ServicePackage(t)

	cfgTbl, err := readDB.GetTable("MsiServiceConfig")
	require.NoError(t, err)
	rows := cfgTbl.rows()
	require.Len(t, rows, 1, "MsiServiceConfig row for delayed auto start")

	// Columns: [MsiServiceConfig(PK), Name, Event, ConfigType, Argument, Component_].
	v := rows[0].values()
	assert.Equal(t, "MySvc", v[1], "service Name")
	assert.Equal(t, int16(1), v[2], "Event install bit")
	assert.Equal(t, int16(3), v[3], "ConfigType SERVICE_CONFIG_DELAYED_AUTO_START_INFO")
	assert.Equal(t, "1", v[4], "Argument enables delayed auto start")
	assert.Equal(t, "Svc", v[5], "Component_ FK")
}

func TestCompileP4_MsiServiceConfigFailureActions(t *testing.T) {
	readDB := buildP4ServicePackage(t)

	failTbl, err := readDB.GetTable("MsiServiceConfigFailureActions")
	require.NoError(t, err)
	rows := failTbl.rows()
	require.Len(t, rows, 1)

	// Columns: [MsiServiceConfigFailureActions(PK), Name, Event, ResetPeriod,
	// RebootMessage, Command, Actions, DelayActions, Component_].
	v := rows[0].values()
	assert.Equal(t, "MySvc", v[1])
	assert.Equal(t, int16(1), v[2], "Event install bit")
	assert.Equal(t, int32(86400), v[3], "ResetPeriod seconds (i4)")
	assert.Nil(t, v[4], "RebootMessage unset -> NULL")
	assert.Nil(t, v[5], "Command unset -> NULL")
	assert.Equal(t, "1[~]1[~]0", v[6], "Actions: restart, restart, none")
	assert.Equal(t, "60000[~]60000[~]0", v[7], "DelayActions ms list")
	assert.Equal(t, "Svc", v[8], "Component_ FK")
}

func TestCompileP4_ServiceControlRowContent(t *testing.T) {
	readDB := buildP4ServicePackage(t)

	scTbl, err := readDB.GetTable("ServiceControl")
	require.NoError(t, err)
	rows := scTbl.rows()
	require.Len(t, rows, 1, "ServiceControl must have its single row (not empty)")

	// Columns: [ServiceControl(PK), Name, Event, Arguments, Wait, Component_].
	// OnInstall().Start().Stop() -> 0x1|0x2 = 0x3; OnUninstall().Stop().Delete()
	// -> 0x20|0x80 = 0xA0; total 0xA3.
	v := rows[0].values()
	assert.Equal(t, "MySvc", v[1], "Name")
	assert.Equal(t, int16(0xA3), v[2], "Event accumulates install+uninstall bits")
	assert.Nil(t, v[3], "Arguments unset -> NULL")
	assert.Equal(t, int16(1), v[4], "Wait(true) -> 1")
	assert.Equal(t, "Svc", v[5], "Component_ FK")
}

func TestCompileP4_MajorUpgradeRows(t *testing.T) {
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithUpgradeCode("{ABCDEF01-2345-6789-ABCD-EF0123456789}").
		WithProductName("P4 Upgrade").
		WithManufacturer("go-msix").
		WithVersion("2.0.0").
		MajorUpgrade().
		DowngradeErrorMessage("Newer version present.").
		Done()

	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").
		WithFile("app.exe", []byte("MZ"))
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.NoError(t, readDB.validate())

	// Two Upgrade rows: detect-remove-older (WIX_UPGRADE_DETECTED) and
	// detect-only-newer (WIX_DOWNGRADE_DETECTED).
	upTbl, err := readDB.GetTable("Upgrade")
	require.NoError(t, err)
	rows := upTbl.rows()
	require.Len(t, rows, 2, "MajorUpgrade must synthesize both detect rows")

	// Columns: [UpgradeCode, VersionMin, VersionMax, Language, Attributes, Remove, ActionProperty].
	older := findRow(t, upTbl, 6, "WIX_UPGRADE_DETECTED")
	assert.Equal(t, "{ABCDEF01-2345-6789-ABCD-EF0123456789}", older[0], "UpgradeCode")
	assert.Nil(t, older[1], "older VersionMin is NULL (open lower bound)")
	assert.Equal(t, "2.0.0", older[2], "older VersionMax = current version")
	assert.Equal(t, int32(UpgradeMigrateFeatures), older[4], "older Attributes = MigrateFeatures")

	newer := findRow(t, upTbl, 6, "WIX_DOWNGRADE_DETECTED")
	assert.Equal(t, "2.0.0", newer[1], "newer VersionMin = current version")
	assert.Nil(t, newer[2], "newer VersionMax is NULL")
	assert.Equal(t, int32(UpgradeOnlyDetect), newer[4], "newer Attributes = OnlyDetect")

	// LaunchCondition blocking the downgrade.
	lcTbl, err := readDB.GetTable("LaunchCondition")
	require.NoError(t, err)
	lcRows := lcTbl.rows()
	require.Len(t, lcRows, 1)
	assert.Equal(t, "NOT WIX_DOWNGRADE_DETECTED", lcRows[0].values()[0])
	assert.Equal(t, "Newer version present.", lcRows[0].values()[1])

	// SecureCustomProperties contains both action properties (sorted).
	propTbl, err := readDB.GetTable("Property")
	require.NoError(t, err)
	scp := findRow(t, propTbl, 0, "SecureCustomProperties")
	assert.Equal(t, "WIX_DOWNGRADE_DETECTED;WIX_UPGRADE_DETECTED", scp[1],
		"SecureCustomProperties lists both ActionProperty names, sorted")
}

func TestCompileP4_LowLevelUpgradeAndLaunchCondition(t *testing.T) {
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithUpgradeCode("{ABCDEF01-2345-6789-ABCD-EF0123456789}").
		WithProductName("P4 Upgrade LL").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		LaunchCondition("Privileged", "Administrator privileges are required.")

	b.Upgrade("{99999999-8888-7777-6666-555555555555}").
		DetectRange("1.0.0", "2.0.0").
		Inclusive(true, false).
		MigrateFeatures().
		ActionProperty("OLDVERSIONFOUND")

	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").
		WithFile("app.exe", []byte("MZ"))
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	upTbl, err := readDB.GetTable("Upgrade")
	require.NoError(t, err)
	require.Len(t, upTbl.rows(), 1)
	v := upTbl.rows()[0].values()
	assert.Equal(t, "{99999999-8888-7777-6666-555555555555}", v[0])
	assert.Equal(t, "1.0.0", v[1], "VersionMin")
	assert.Equal(t, "2.0.0", v[2], "VersionMax")
	assert.Equal(t, int32(UpgradeVersionMinInclusive|UpgradeMigrateFeatures), v[4], "Attributes accumulate")
	assert.Equal(t, "OLDVERSIONFOUND", v[6], "ActionProperty (UpperCase)")

	lcTbl, err := readDB.GetTable("LaunchCondition")
	require.NoError(t, err)
	require.Len(t, lcTbl.rows(), 1)
	assert.Equal(t, "Privileged", lcTbl.rows()[0].values()[0])
}

func TestCompileP4_AppSearchRegistryAndSignature(t *testing.T) {
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("P4 Search").
		WithManufacturer("go-msix").
		WithVersion("1.0.0")

	// A raw-value registry search.
	b.Search("REGPROP").
		InRegistry(RegistryRootHKLM, `Software\Acme`, "InstallPath").
		AsRawValue()

	// A directory-locating registry search narrowed to a file by Signature.
	b.Search("FILEPROP").
		InRegistry(RegistryRootHKLM, `Software\Acme`, "Dir").
		MatchingFile("app.exe").
		WithVersion("1.0.0", "2.0.0").
		Done()

	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").
		WithFile("app.exe", []byte("MZ"))
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.NoError(t, readDB.validate())

	// AppSearch: two property->signature rows.
	asTbl, err := readDB.GetTable("AppSearch")
	require.NoError(t, err)
	require.Len(t, asTbl.rows(), 2)
	reg := findRow(t, asTbl, 0, "REGPROP")
	assert.Equal(t, "sig00", reg[1], "first search uses sig00")
	file := findRow(t, asTbl, 0, "FILEPROP")
	assert.Equal(t, "sig01", file[1], "second search uses sig01")

	// RegLocator: sig00 raw value, sig01 directory (because of MatchingFile).
	rlTbl, err := readDB.GetTable("RegLocator")
	require.NoError(t, err)
	require.Len(t, rlTbl.rows(), 2)
	// Columns: [Signature_, Root, Key, Name, Type].
	rl0 := findRow(t, rlTbl, 0, "sig00")
	assert.Equal(t, int16(2), rl0[1], "Root HKLM as int16(2)")
	assert.Equal(t, `Software\Acme`, rl0[2])
	assert.Equal(t, "InstallPath", rl0[3])
	assert.Equal(t, int16(2), rl0[4], "Type raw value")
	rl1 := findRow(t, rlTbl, 0, "sig01")
	assert.Equal(t, int16(0), rl1[4], "MatchingFile makes the locator a directory search")

	// Signature: sig01 file match with a version range.
	sigTbl, err := readDB.GetTable("Signature")
	require.NoError(t, err)
	require.Len(t, sigTbl.rows(), 1)
	sv := sigTbl.rows()[0].values()
	assert.Equal(t, "sig01", sv[0])
	assert.Equal(t, "app.exe", sv[1], "FileName")
	assert.Equal(t, "1.0.0", sv[2], "MinVersion")
	assert.Equal(t, "2.0.0", sv[3], "MaxVersion")
	assert.Nil(t, sv[4], "MinSize NULL")
}

func TestCompileP4_AppSearchComponentAndDirectory(t *testing.T) {
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("P4 Search 2").
		WithManufacturer("go-msix").
		WithVersion("1.0.0")

	b.Search("COMPPROP").
		ByComponentID("{55555555-6666-7777-8888-999999999999}").
		AsDirectory()

	b.Search("DIRPROP").
		InDirectory("bin", 2).
		MatchingFile("tool.exe").
		WithSize(1, 1000000).
		Done()

	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").
		WithFile("app.exe", []byte("MZ"))
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.NoError(t, readDB.validate())

	clTbl, err := readDB.GetTable("CompLocator")
	require.NoError(t, err)
	require.Len(t, clTbl.rows(), 1)
	cl := clTbl.rows()[0].values()
	assert.Equal(t, "sig00", cl[0])
	assert.Equal(t, "{55555555-6666-7777-8888-999999999999}", cl[1], "ComponentId GUID")
	assert.Equal(t, int16(0), cl[2], "AsDirectory type")

	drTbl, err := readDB.GetTable("DrLocator")
	require.NoError(t, err)
	require.Len(t, drTbl.rows(), 1)
	dr := drTbl.rows()[0].values()
	assert.Equal(t, "sig01", dr[0])
	assert.Nil(t, dr[1], "Parent NULL")
	assert.Equal(t, "bin", dr[2], "Path")
	assert.Equal(t, int16(2), dr[3], "Depth")

	sigTbl, err := readDB.GetTable("Signature")
	require.NoError(t, err)
	require.Len(t, sigTbl.rows(), 1)
	sv := sigTbl.rows()[0].values()
	assert.Equal(t, "tool.exe", sv[1])
	assert.Equal(t, int32(1), sv[4], "MinSize")
	assert.Equal(t, int32(1000000), sv[5], "MaxSize")
}

// seqActionSeq returns the sequence number of the named action in the given
// sequence table, or -1 if the action is absent.
func seqActionSeq(t *testing.T, db msiDatabase, table, action string) int16 {
	t.Helper()
	tbl, err := db.GetTable(table)
	require.NoError(t, err)
	for _, r := range tbl.rows() {
		v := r.values()
		// Sequence table columns: [Action, Condition, Sequence].
		if name, ok := v[0].(string); ok && name == action {
			seq, ok := v[2].(int16)
			require.True(t, ok, "Sequence cell must be int16, got %T", v[2])
			return seq
		}
	}
	return -1
}

func TestCompileP4_ConditionalActionsInjected(t *testing.T) {
	readDB := buildP4ServicePackage(t) // has ServiceInstall + ServiceControl

	ies := "InstallExecuteSequence"
	assert.Equal(t, int16(5800), seqActionSeq(t, readDB, ies, "InstallServices"), "InstallServices @5800 when ServiceInstall present")
	assert.Equal(t, int16(5900), seqActionSeq(t, readDB, ies, "StartServices"), "StartServices @5900")
	assert.Equal(t, int16(1900), seqActionSeq(t, readDB, ies, "StopServices"), "StopServices @1900")
	assert.Equal(t, int16(2000), seqActionSeq(t, readDB, ies, "DeleteServices"), "DeleteServices @2000")

	// The service package has no Upgrade/AppSearch/LaunchCondition, so those
	// conditional actions must be ABSENT.
	assert.Equal(t, int16(-1), seqActionSeq(t, readDB, ies, "FindRelatedProducts"), "no Upgrade => no FindRelatedProducts")
	assert.Equal(t, int16(-1), seqActionSeq(t, readDB, ies, "RemoveExistingProducts"), "no Upgrade => no RemoveExistingProducts")
	assert.Equal(t, int16(-1), seqActionSeq(t, readDB, ies, "AppSearch"), "no AppSearch table => no AppSearch action")
}

func TestCompileP4_MajorUpgradeActionsScheduled(t *testing.T) {
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithUpgradeCode("{ABCDEF01-2345-6789-ABCD-EF0123456789}").
		WithProductName("P4 Upgrade Actions").
		WithManufacturer("go-msix").
		WithVersion("2.0.0").
		MajorUpgrade().RemoveAfter("InstallValidate").Done()
	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").
		WithFile("app.exe", []byte("MZ"))
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	ies := "InstallExecuteSequence"
	assert.Equal(t, int16(200), seqActionSeq(t, readDB, ies, "FindRelatedProducts"))
	assert.Equal(t, int16(1200), seqActionSeq(t, readDB, ies, "MigrateFeatureStates"))
	assert.Equal(t, int16(1450), seqActionSeq(t, readDB, ies, "RemoveExistingProducts"), "RemoveAfter(InstallValidate) -> 1450")

	// In the UI sequence FindRelatedProducts is present, services are not.
	ius := "InstallUISequence"
	assert.Equal(t, int16(200), seqActionSeq(t, readDB, ius, "FindRelatedProducts"))
	assert.Equal(t, int16(-1), seqActionSeq(t, readDB, ius, "InstallServices"), "services are IES-only")
}

func TestCompileP4_NoConditionalActionsForFilesOnly(t *testing.T) {
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("Files Only").
		WithManufacturer("go-msix").
		WithVersion("1.0.0")
	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").
		WithFile("app.exe", []byte("MZ"))
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	ies := "InstallExecuteSequence"
	for _, a := range []string{"InstallServices", "StartServices", "FindRelatedProducts", "RemoveExistingProducts", "AppSearch", "LaunchConditions"} {
		assert.Equal(t, int16(-1), seqActionSeq(t, readDB, ies, a), "files-only package must not inject %s", a)
	}
}

// iceFindingsFor runs all ICE rules against the given database and returns the
// findings for the requested ICE id.
func iceFindingsFor(db msiDatabase, summary msiSummaryInfo, ice string) []Finding {
	ctx := newIceContext(db, summary)
	var out []Finding
	// SeverityInfo floor: surface findings of every severity (incl. warnings).
	for _, f := range runAllRules(ctx, nil, true, nil, SeverityInfo) {
		if f.ICE() == ice {
			out = append(out, f)
		}
	}
	return out
}

// upgradeOnlyDB builds a minimal database carrying just the rows a rule needs,
// using the catalog factories directly (white-box golden construction).
func upgradeGoldenDB(t *testing.T, up [][]any, ies [][]any, props map[string]string) msiDatabase {
	t.Helper()
	db := newMSIDatabaseBuilder()
	if props != nil {
		db.WithProperties(props)
	}
	if up != nil {
		tbl := createMSITableFromCatalog("Upgrade")
		for _, vals := range up {
			row := newMSIRowBuilder().WithColumns(tbl.columns()...).WithValues(vals...).Build()
			require.NoError(t, tbl.addRow(row))
		}
		db.WithTable(tbl)
	}
	for _, row := range ies {
		db.WithSequenceAction(msiInstallExecSeqTableName, row[0].(string), nil, row[1].(int16))
	}
	built, err := db.Build()
	require.NoError(t, err)
	return built
}

func TestICE61_VersionRangeReversed_Golden(t *testing.T) {
	// VersionMin > VersionMax must produce an ICE61 error.
	bad := upgradeGoldenDB(t, [][]any{
		{"{ABCDEF01-2345-6789-ABCD-EF0123456789}", "2.0.0", "1.0.0", "", int32(UpgradeMigrateFeatures), "", "OLDFOUND"},
	}, nil, map[string]string{"SecureCustomProperties": "OLDFOUND"})
	findings := iceFindingsFor(bad, msiSummaryInfo{}, "ICE61")
	require.NotEmpty(t, findings, "reversed version range must trip ICE61")
	assert.Equal(t, SeverityError, findings[0].Severity())

	// A correctly ordered range must be clean.
	good := upgradeGoldenDB(t, [][]any{
		{"{ABCDEF01-2345-6789-ABCD-EF0123456789}", "1.0.0", "2.0.0", "", int32(UpgradeMigrateFeatures), "", "OLDFOUND"},
	}, nil, map[string]string{"SecureCustomProperties": "OLDFOUND"})
	assert.Empty(t, iceFindingsFor(good, msiSummaryInfo{}, "ICE61"), "ordered range must be ICE61-clean")
}

func TestICE63_MissingRemoveExistingProducts_Golden(t *testing.T) {
	// A remove-row Upgrade with no RemoveExistingProducts action -> ICE63 error.
	bad := upgradeGoldenDB(t, [][]any{
		{"{ABCDEF01-2345-6789-ABCD-EF0123456789}", "", "2.0.0", "", int32(UpgradeMigrateFeatures), "", "OLDFOUND"},
	}, [][]any{
		{"InstallValidate", int16(1400)},
	}, map[string]string{"SecureCustomProperties": "OLDFOUND"})
	findings := iceFindingsFor(bad, msiSummaryInfo{}, "ICE63")
	require.NotEmpty(t, findings, "remove row without RemoveExistingProducts must trip ICE63")
	hasErr := false
	for _, f := range findings {
		if f.Severity() == SeverityError {
			hasErr = true
		}
	}
	assert.True(t, hasErr, "ICE63 missing-RemoveExistingProducts must be an error")

	// With RemoveExistingProducts scheduled after InstallValidate -> clean.
	good := upgradeGoldenDB(t, [][]any{
		{"{ABCDEF01-2345-6789-ABCD-EF0123456789}", "", "2.0.0", "", int32(UpgradeMigrateFeatures), "", "OLDFOUND"},
	}, [][]any{
		{"InstallValidate", int16(1400)},
		{"RemoveExistingProducts", int16(1525)},
	}, map[string]string{"SecureCustomProperties": "OLDFOUND"})
	for _, f := range iceFindingsFor(good, msiSummaryInfo{}, "ICE63") {
		assert.NotEqual(t, SeverityError, f.Severity(), "well-formed upgrade must not produce an ICE63 error")
	}
}

func TestICE63_ActionPropertyNotSecure_Golden(t *testing.T) {
	// ActionProperty missing from SecureCustomProperties -> ICE63 warning.
	db := upgradeGoldenDB(t, [][]any{
		{"{ABCDEF01-2345-6789-ABCD-EF0123456789}", "", "2.0.0", "", int32(UpgradeMigrateFeatures), "", "OLDFOUND"},
	}, [][]any{
		{"InstallValidate", int16(1400)},
		{"RemoveExistingProducts", int16(1525)},
	}, map[string]string{"ProductName": "X"}) // no SecureCustomProperties
	ctx := newIceContext(db, msiSummaryInfo{})
	var warned bool
	for _, f := range runAllRules(ctx, nil, true, nil, SeverityInfo) {
		if f.ICE() == "ICE63" && f.Column() == "ActionProperty" {
			warned = true
		}
	}
	assert.True(t, warned, "ActionProperty not in SecureCustomProperties must warn (ICE63)")
}

func TestCompileP4_MajorUpgradeIsICEClean(t *testing.T) {
	// A real MajorUpgrade package built through the public API must validate
	// clean (no error-severity ICE findings) under WithAllICEs.
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithUpgradeCode("{ABCDEF01-2345-6789-ABCD-EF0123456789}").
		WithProductName("Clean Upgrade").
		WithManufacturer("go-msix").
		WithVersion("2.0.0").
		MajorUpgrade().Done()
	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").
		WithFile("app.exe", []byte("MZ"))
	b.Feature("F").WithLevel(1)

	// Build runs validate-by-default; success means no error-severity findings.
	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
}

func TestCompileP4_NoServiceTablesWhenUnused(t *testing.T) {
	// A files-only package must NOT emit any service tables (absence = the
	// tables simply do not appear).
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("No Services").
		WithManufacturer("go-msix").
		WithVersion("1.0.0")
	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").
		WithFile("app.exe", []byte("MZ"))
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	for _, name := range []string{"ServiceInstall", "ServiceControl", "MsiServiceConfig", "MsiServiceConfigFailureActions"} {
		_, err := readDB.GetTable(name)
		assert.Error(t, err, "%s must be absent in a service-free package", name)
	}
}
