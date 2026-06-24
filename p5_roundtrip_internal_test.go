package msi

// msi_p5_roundtrip_internal_test.go
// White-box round-trip CONTENT tests for P5 CustomAction table emission: build
// via the public API without WithSkipValidation, WriteMSI, readMSIDatabase, and
// assert exact Type/Source/Target cells (Type computed from base | in-script |
// modifiers).

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildP5CAPackage builds a package with a representative set of custom actions
// and returns the read-back database.
func buildP5CAPackage(t *testing.T) msiDatabase {
	t.Helper()

	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("P5 CA").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").Binary(

		"CaDll", FileSourceFromBytes(

			[]byte("MZ fake dll")))

	// SetProperty (type 51): Source=property, Target=value.
	b.CustomAction("SetFoo").SetProperty("FOO", "bar")

	// Deferred EXE-from-Binary (type 2 | InScript 0x400 = 0x402 = 1026),
	// NoImpersonate (|0x800 = 0x802 -> total 0x402|0x800 = 0xC02 = 3074).
	b.CustomAction("RunHelper").
		EXEFromBinary("CaDll", "--install").
		Deferred().
		NoImpersonate()

	// Error message (type 19): Source empty, Target = message.
	b.CustomAction("FailIt").ErrorMessage("Installation failed.")

	// SetDirectory (type 35): Source=directory key, Target=path.
	b.CustomAction("RetargetDir").SetDirectory("INSTALLFOLDER", "[ProgramFilesFolder]MyApp")

	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").WithFile(

		"app.exe", FileSourceFromBytes(

			[]byte("MZ")))

	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err, "Build must succeed for valid custom actions")

	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))

	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.NoError(t, readDB.validate())
	return readDB
}

func TestCompileP5_CustomActionRowContent(t *testing.T) {
	readDB := buildP5CAPackage(t)

	caTbl, err := readDB.GetTable("CustomAction")
	require.NoError(t, err)
	require.Len(t, caTbl.rows(), 4)

	// Columns: [Action, Type, Source, Target, ExtendedType].
	set := findRow(t, caTbl, 0, "SetFoo")
	assert.Equal(t, int16(51), set[1], "SetProperty type 51")
	assert.Equal(t, "FOO", set[2], "Source = property name")
	assert.Equal(t, "bar", set[3], "Target = value")
	assert.Nil(t, set[4], "ExtendedType NULL")

	run := findRow(t, caTbl, 0, "RunHelper")
	// type 2 | InScript 0x400 | NoImpersonate 0x800 = 0xC02 = 3074
	assert.Equal(t, int16(0x0C02), run[1], "EXE/Binary deferred no-impersonate Type")
	assert.Equal(t, "CaDll", run[2], "Source = Binary key")
	assert.Equal(t, "--install", run[3], "Target = command line")

	fail := findRow(t, caTbl, 0, "FailIt")
	assert.Equal(t, int16(19), fail[1], "Error type 19")
	assert.Nil(t, fail[2], "Error Source NULL")
	assert.Equal(t, "Installation failed.", fail[3])

	dir := findRow(t, caTbl, 0, "RetargetDir")
	assert.Equal(t, int16(35), dir[1], "SetDirectory type 35")
	assert.Equal(t, "INSTALLFOLDER", dir[2])
	assert.Equal(t, "[ProgramFilesFolder]MyApp", dir[3])
}

func TestCompileP5_RollbackCommitTypes(t *testing.T) {
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("P5 RC").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").Binary(

		"Bin", FileSourceFromBytes(

			[]byte("x")))

	b.CustomAction("Roll").EXEFromBinary("Bin", "/rollback").Rollback()
	b.CustomAction("Comm").EXEFromBinary("Bin", "/commit").Commit()
	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").WithFile(
		"a.exe", FileSourceFromBytes(
			[]byte("MZ")))

	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	caTbl, err := readDB.GetTable("CustomAction")
	require.NoError(t, err)
	// Rollback = 2 | 0x500 = 0x502 = 1282; Commit = 2 | 0x600 = 0x602 = 1538.
	assert.Equal(t, int16(0x0502), findRow(t, caTbl, 0, "Roll")[1], "Rollback in-script bits")
	assert.Equal(t, int16(0x0602), findRow(t, caTbl, 0, "Comm")[1], "Commit in-script bits")
}

// p5SeqOf returns the sequence of a custom action in a table, or -1 if absent.
func p5SeqOf(t *testing.T, db msiDatabase, table, action string) int16 {
	t.Helper()
	tbl, err := db.GetTable(table)
	require.NoError(t, err)
	for _, r := range tbl.rows() {
		v := r.values()
		if name, ok := v[0].(string); ok && name == action {
			s, _ := v[2].(int16)
			return s
		}
	}
	return -1
}

func TestCompileP5_ScheduleAfterBeforeAt(t *testing.T) {
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("P5 Sched").
		WithManufacturer("go-msix").
		WithVersion("1.0.0")

	// After InstallFiles(4000): next standard action is WriteRegistryValues(4200),
	// so the first slot is 4001.
	b.CustomAction("AfterFiles").SetProperty("A", "1").
		ScheduleAfter(InstallExecuteSequence, "InstallFiles", "")
	// A second CA after the same anchor must get a distinct slot (4002).
	b.CustomAction("AfterFiles2").SetProperty("B", "2").
		ScheduleAfter(InstallExecuteSequence, "InstallFiles", "NOT Installed")
	// Before InstallFinalize(6600): largest used below it is PublishProduct(6400),
	// so the slot is 6599.
	b.CustomAction("BeforeFinalize").SetProperty("C", "3").
		ScheduleBefore(InstallExecuteSequence, "InstallFinalize", "")
	// Explicit sequence.
	b.CustomAction("AtFixed").SetProperty("D", "4").
		ScheduleAt(InstallExecuteSequence, 2500, "")

	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").WithFile(
		"a.exe", FileSourceFromBytes(
			[]byte("MZ")))

	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.NoError(t, readDB.validate())

	ies := "InstallExecuteSequence"
	assert.Equal(t, int16(4001), p5SeqOf(t, readDB, ies, "AfterFiles"), "after InstallFiles -> 4001")
	assert.Equal(t, int16(4002), p5SeqOf(t, readDB, ies, "AfterFiles2"), "second after same anchor -> 4002")
	assert.Equal(t, int16(6599), p5SeqOf(t, readDB, ies, "BeforeFinalize"), "before InstallFinalize -> 6599")
	assert.Equal(t, int16(2500), p5SeqOf(t, readDB, ies, "AtFixed"), "explicit At -> 2500")

	// The conditioned CA must carry its condition.
	seqTbl, err := readDB.GetTable(ies)
	require.NoError(t, err)
	for _, r := range seqTbl.rows() {
		v := r.values()
		if v[0] == "AfterFiles2" {
			assert.Equal(t, "NOT Installed", v[1], "condition round-trips")
		}
	}
}

func TestCompileP5_ScheduleMissingAnchorErrors(t *testing.T) {
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("P5 Bad Anchor").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		WithSkipValidation()
	// InstallServices is NOT in the schedule (no services), so anchoring to it
	// must fail loudly rather than silently dropping the schedule.
	b.CustomAction("Orphan").SetProperty("X", "1").
		ScheduleAfter(InstallExecuteSequence, "InstallServices", "")
	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").WithFile(
		"a.exe", FileSourceFromBytes(
			[]byte("MZ")))

	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	err = pkg.WriteMSI(&buf)
	require.Error(t, err, "scheduling against a missing anchor must error")
	assert.Contains(t, err.Error(), "InstallServices")
}

func TestCompileP5_CustomActionDoesNotBreakParity(t *testing.T) {
	// A files-only package's InstallExecuteSequence must be unchanged by the
	// presence of the P5 code path (no custom actions declared).
	readDB := buildP5CAPackageFilesOnly(t)
	ies, err := readDB.GetTable("InstallExecuteSequence")
	require.NoError(t, err)
	// The exact base IES action set (19 rows) must be present, none added.
	require.Len(t, ies.rows(), len(msiInstallExecuteActions))
}

func buildP5CAPackageFilesOnly(t *testing.T) msiDatabase {
	t.Helper()
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("Files Only P5").
		WithManufacturer("go-msix").
		WithVersion("1.0.0")
	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").WithFile(
		"a.exe", FileSourceFromBytes(
			[]byte("MZ")))

	b.Feature("F").WithLevel(1)
	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	return readDB
}

// caGoldenDB builds a database with explicit CustomAction rows and sequence-table
// rows (white-box golden construction for the CA ICEs).
func caGoldenDB(t *testing.T, cas [][]any, seqRows map[string][][]any) msiDatabase {
	t.Helper()
	db := newMSIDatabaseBuilder()
	if len(cas) > 0 {
		tbl := createMSITableFromCatalog("CustomAction")
		for _, vals := range cas {
			row := newMSIRowBuilder().WithColumns(tbl.columns()...).WithValues(vals...).Build()
			require.NoError(t, tbl.addRow(row))
		}
		db.WithTable(tbl)
	}
	for table, rows := range seqRows {
		for _, r := range rows {
			db.WithSequenceAction(table, r[0].(string), nil, r[1].(int16))
		}
	}
	built, err := db.Build()
	require.NoError(t, err)
	return built
}

func TestICE68_UnknownTypeAndNoImpersonate(t *testing.T) {
	// Base type 0 is not a recognized custom action type -> ICE68 error.
	bad := caGoldenDB(t, [][]any{
		{"BadCA", int16(0), "", "x", nil},
	}, nil)
	errs := iceFindingsFor(bad, msiSummaryInfo{}, "ICE68")
	require.NotEmpty(t, errs)
	assert.Equal(t, SeverityError, errs[0].Severity())

	// NoImpersonate (0x800) without the in-script bit on a SetProperty (51) -> warning.
	warn := caGoldenDB(t, [][]any{
		{"ImmediateNoImp", int16(51 | 0x800), "FOO", "bar", nil},
	}, nil)
	wfindings := iceFindingsFor(warn, msiSummaryInfo{}, "ICE68")
	require.NotEmpty(t, wfindings)
	assert.Equal(t, SeverityWarning, wfindings[0].Severity())

	// A clean deferred type-1 with NoImpersonate (valid) -> no ICE68 finding.
	good := caGoldenDB(t, [][]any{
		{"DeferredOK", int16(1 | 0x400 | 0x800), "Bin", "Entry", nil},
	}, nil)
	assert.Empty(t, iceFindingsFor(good, msiSummaryInfo{}, "ICE68"))
}

func TestICE72_AdvtSequenceTypeRestriction(t *testing.T) {
	// A DLL custom action (type 1) scheduled in AdvtExecuteSequence -> ICE72 error.
	bad := caGoldenDB(t, [][]any{
		{"DllCA", int16(1), "Bin", "Entry", nil},
	}, map[string][][]any{
		msiAdvtExecSeqTableName: {{"DllCA", int16(1450)}},
	})
	errs := iceFindingsFor(bad, msiSummaryInfo{}, "ICE72")
	require.NotEmpty(t, errs)
	assert.Equal(t, SeverityError, errs[0].Severity())

	// A SetProperty (type 51) in AdvtExecuteSequence is allowed -> clean.
	good := caGoldenDB(t, [][]any{
		{"SetProp", int16(51), "FOO", "bar", nil},
	}, map[string][][]any{
		msiAdvtExecSeqTableName: {{"SetProp", int16(1450)}},
	})
	assert.Empty(t, iceFindingsFor(good, msiSummaryInfo{}, "ICE72"))
}

func TestICE77_InScriptSequencing(t *testing.T) {
	// A deferred CA (type 1 | 0x400) scheduled BEFORE InstallInitialize -> ICE77 error.
	bad := caGoldenDB(t, [][]any{
		{"DeferredCA", int16(1 | 0x400), "Bin", "Entry", nil},
	}, map[string][][]any{
		msiInstallExecSeqTableName: {
			{"InstallInitialize", int16(1500)},
			{"DeferredCA", int16(1200)}, // before InstallInitialize
			{"InstallFinalize", int16(6600)},
		},
	})
	errs := iceFindingsFor(bad, msiSummaryInfo{}, "ICE77")
	require.NotEmpty(t, errs)
	assert.Equal(t, SeverityError, errs[0].Severity())

	// Same CA scheduled between InstallInitialize and InstallFinalize -> clean.
	good := caGoldenDB(t, [][]any{
		{"DeferredCA", int16(1 | 0x400), "Bin", "Entry", nil},
	}, map[string][][]any{
		msiInstallExecSeqTableName: {
			{"InstallInitialize", int16(1500)},
			{"DeferredCA", int16(4100)},
			{"InstallFinalize", int16(6600)},
		},
	})
	assert.Empty(t, iceFindingsFor(good, msiSummaryInfo{}, "ICE77"))
}

func TestCompileP5_DeferredCAIsICEClean(t *testing.T) {
	// A deferred CA scheduled after InstallFiles via the public API must validate
	// clean (no error-severity ICE findings) under validate-by-default.
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("Clean CA").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").Binary(

		"Bin", FileSourceFromBytes(

			[]byte("MZ")))

	b.CustomAction("DoWork").
		EXEFromBinary("Bin", "--work").
		Deferred().
		ScheduleAfter(InstallExecuteSequence, "InstallFiles", "NOT Installed")
	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").WithFile(
		"a.exe", FileSourceFromBytes(
			[]byte("MZ")))

	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err, "deferred CA after InstallFiles must be ICE-clean")
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
}

func TestCompileP5_NoCustomActionTableWhenUnused(t *testing.T) {
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("No CA").
		WithManufacturer("go-msix").
		WithVersion("1.0.0")
	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").WithFile(
		"a.exe", FileSourceFromBytes(
			[]byte("MZ")))

	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	_, err = readDB.GetTable("CustomAction")
	assert.Error(t, err, "CustomAction table absent when no custom actions declared")
}
