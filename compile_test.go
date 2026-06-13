package msi

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// White-box tests for the compiler (same package so we can construct
// *msiPackage directly and call the unexported compileMSIPackage).
// These complement the public msix_test package tests.

func TestCompileMSIPackage_DirectoriesOnly(t *testing.T) {
	p := &msiPackage{
		productName:  "Compile Dir Test",
		manufacturer: "Tester",
		version:      "1.0.0",
		dirEntries: map[string]*dirEntry{
			"TARGETDIR":     {id: "TARGETDIR", defaultDir: "SourceDir"},
			"INSTALLFOLDER": {id: "INSTALLFOLDER", parent: "TARGETDIR", defaultDir: "CompileDirTest"},
			"SUB":           {id: "SUB", parent: "INSTALLFOLDER", defaultDir: "Sub"},
		},
		// no components/files/features yet — dirs + props only is valid for this slice
	}

	db, err := compileMSIPackage(p)
	require.NoError(t, err)
	require.NotNil(t, db)

	// The returned db must list the directories we fed it (plus the core
	// tables that msiDatabaseBuilder always adds).
	tables := db.Tables()
	// sort for the assertion
	sort.Strings(tables)
	require.Contains(t, tables, "Directory")
	require.Contains(t, tables, "_Validation")

	dirTbl, err := db.GetTable("Directory")
	require.NoError(t, err)
	require.NotEmpty(t, dirTbl.rows(), "directories should have been emitted")

	// We should have exactly the three we declared (the builder may have
	// added none extra in this skeleton compile).
	require.Len(t, dirTbl.rows(), 3)
}

func TestCompileMSIPackage_PropertiesAndIdentity(t *testing.T) {
	p := &msiPackage{
		productCode:  "{12345678-1234-1234-1234-123456789ABC}",
		upgradeCode:  "{ABCDEF01-2345-6789-ABCD-EF0123456789}",
		productName:  "Prop Test",
		manufacturer: "go-msix",
		version:      "2.3.4",
		allUsers:     true,
		props:        map[string]string{"Custom": "Value"},
		dirEntries: map[string]*dirEntry{
			"TARGETDIR": {id: "TARGETDIR", defaultDir: "SourceDir"},
		},
	}

	db, err := compileMSIPackage(p)
	require.NoError(t, err)

	propTbl, err := db.GetTable("Property")
	require.NoError(t, err)
	require.NotEmpty(t, propTbl.rows())

	// Spot-check a few that the compiler is responsible for wiring.
	found := map[string]bool{}
	for _, r := range propTbl.rows() {
		vals := r.values()
		if len(vals) >= 2 {
			if k, ok := vals[0].(string); ok {
				found[k] = true
			}
		}
	}
	require.True(t, found["ProductName"])
	require.True(t, found["ALLUSERS"])
	require.True(t, found["UpgradeCode"])
	require.True(t, found["Custom"])
}

func TestCompileMSIPackage_ComponentsAndFiles(t *testing.T) {
	// Exercise the component + file population added in this slice.
	// We supply a component with an explicit file; the compiler should
	// derive a file ID, set a KeyPath if none given, emit the File row,
	// and create a Media row because files are present.
	p := &msiPackage{
		productName:  "CompFile Test",
		manufacturer: "Tester",
		version:      "1.0",
		productCode:  "{12345678-1234-1234-1234-123456789ABC}",
		dirEntries: map[string]*dirEntry{
			"TARGETDIR":     {id: "TARGETDIR", defaultDir: "SourceDir"},
			"INSTALLFOLDER": {id: "INSTALLFOLDER", parent: "TARGETDIR", defaultDir: "App"},
		},
		compEntries: map[string]*compEntry{
			"Main": {
				id:    "Main",
				dirID: "INSTALLFOLDER",
				files: []attachedFile{
					{name: "app.exe", data: []byte("MZpayload")},
				},
			},
		},
	}

	db, err := compileMSIPackage(p)
	require.NoError(t, err)

	// Component table
	compTbl, err := db.GetTable("Component")
	require.NoError(t, err)
	require.Len(t, compTbl.rows(), 1)

	// File table + contents available for cab
	fileTbl, err := db.GetTable("File")
	require.NoError(t, err)
	require.Len(t, fileTbl.rows(), 1)

	fc := db.FileContents()
	require.Len(t, fc, 1, "WithFile inside compile must have staged the payload for the cabinet")

	// Media because we had files
	mediaTbl, err := db.GetTable("Media")
	require.NoError(t, err)
	require.NotEmpty(t, mediaTbl.rows())
}

// TestCompileMSIPackage_RegistryRowsEmitted is the regression guard for the
// empty-Registry bug: the Root cell was a named enum (RegistryRoot) that the
// row validator rejected, and the addRow error was swallowed, so the Registry
// table shipped with ZERO rows. Both the RegistryKey().Value() path and the
// flat WithRegistry path funnel into p.registryEntries, so this exercises both.
func TestCompileMSIPackage_RegistryRowsEmitted(t *testing.T) {
	p := &msiPackage{
		productName:  "Reg Test",
		manufacturer: "Tester",
		version:      "1.0",
		productCode:  "{12345678-1234-1234-1234-123456789ABC}",
		dirEntries: map[string]*dirEntry{
			"TARGETDIR":     {id: "TARGETDIR", defaultDir: "SourceDir"},
			"INSTALLFOLDER": {id: "INSTALLFOLDER", parent: "TARGETDIR", defaultDir: "App"},
		},
		compEntries: map[string]*compEntry{
			"Main": {id: "Main", dirID: "INSTALLFOLDER"},
		},
		registryEntries: []registryEntry{
			{root: RegistryRootHKLM, key: `Software\MyApp`, name: "Version", value: "1.0", component: "Main"},
			{root: RegistryRootHKLM, key: `Software\MyApp`, name: "Data", value: []byte{1, 2, 3}, component: "Main"},
			{root: RegistryRootHKCU, key: `Software\MyApp`, name: "FlatVal", value: 42, component: "Main"},
		},
	}

	db, err := compileMSIPackage(p)
	require.NoError(t, err)

	regTbl, err := db.GetTable("Registry")
	require.NoError(t, err)
	require.Len(t, regTbl.rows(), 3, "all three registry entries must be emitted (NOT zero)")

	// Column order: Registry, Root, Key, Name, Value, Component_.
	byName := map[string][]any{}
	for _, r := range regTbl.rows() {
		vals := r.values()
		require.GreaterOrEqual(t, len(vals), 6)
		// Root cell MUST be a plain int16, never the named RegistryRoot type.
		root, ok := vals[1].(int16)
		require.Truef(t, ok, "Root cell must be int16, got %T", vals[1])
		name, _ := vals[3].(string)
		byName[name] = vals
		_ = root
	}

	require.Equal(t, int16(RegistryRootHKLM), byName["Version"][1])
	require.Equal(t, "1.0", byName["Version"][4])

	require.Equal(t, int16(RegistryRootHKLM), byName["Data"][1])
	require.Equal(t, "#x010203", byName["Data"][4], "[]byte registry value must encode as #xHEX")

	require.Equal(t, int16(RegistryRootHKCU), byName["FlatVal"][1])
	require.Equal(t, "#42", byName["FlatVal"][4], "int registry value must encode as #decimal")
}

// TestCompileMSIPackage_ShortcutNullSemantics verifies the Shortcut emission
// uses NULL (not stored 0) for Hotkey, and NULL Icon_/IconIndex when no icon is
// set, while a shortcut WITH an icon carries the icon name and int16 index.
func TestCompileMSIPackage_ShortcutNullSemantics(t *testing.T) {
	p := &msiPackage{
		productName:  "SC Test",
		manufacturer: "Tester",
		version:      "1.0",
		productCode:  "{12345678-1234-1234-1234-123456789ABC}",
		dirEntries: map[string]*dirEntry{
			"TARGETDIR":     {id: "TARGETDIR", defaultDir: "SourceDir"},
			"INSTALLFOLDER": {id: "INSTALLFOLDER", parent: "TARGETDIR", defaultDir: "App"},
		},
		compEntries: map[string]*compEntry{
			"Main": {id: "Main", dirID: "INSTALLFOLDER"},
		},
		shortcutEntries: []shortcutEntry{
			{name: "WithIcon.lnk", target: "[#MainExe]", component: "Main", iconName: "MyIcon", iconIndex: 3},
			{name: "NoIcon.lnk", target: "[#MainExe]", component: "Main"},
		},
	}

	db, err := compileMSIPackage(p)
	require.NoError(t, err)

	scTbl, err := db.GetTable("Shortcut")
	require.NoError(t, err)
	require.Len(t, scTbl.rows(), 2, "both shortcuts must be emitted")

	// Column order: Shortcut, Directory_, Name, Component_, Target, Arguments,
	// Description, Hotkey, Icon_, IconIndex, ShowCmd, WkDir.
	byName := map[string][]any{}
	for _, r := range scTbl.rows() {
		vals := r.values()
		require.GreaterOrEqual(t, len(vals), 12)
		byName[vals[2].(string)] = vals
	}

	withIcon := byName["WithIcon.lnk"]
	require.Equal(t, "[#MainExe]", withIcon[4], "Target passes through verbatim for non-advertised")
	require.Nil(t, withIcon[7], "Hotkey must be NULL, not a stored 0")
	require.Equal(t, "MyIcon", withIcon[8])
	require.Equal(t, int16(3), withIcon[9], "IconIndex must be int16 when an icon is set")
	require.Equal(t, int16(1), withIcon[10], "ShowCmd is int16(1)")

	noIcon := byName["NoIcon.lnk"]
	require.Nil(t, noIcon[7], "Hotkey must be NULL")
	require.Nil(t, noIcon[8], "Icon_ must be NULL when no icon")
	require.Nil(t, noIcon[9], "IconIndex must be NULL when no icon")
	require.Equal(t, int16(1), noIcon[10])
}

// TestCompileMSIPackage_RegistryAddRowErrorsPropagate proves the swallowed-error
// anti-pattern is gone: a registry row whose component FK references a missing
// component must surface as a hard compile error, not a silently dropped row.
func TestCompileMSIPackage_RegistryAddRowErrorsPropagate(t *testing.T) {
	// A registry Value that cannot be encoded to a valid Text cell is hard to
	// construct (encodeRegistryValue is total), so instead we force an invalid
	// non-nullable cell by giving an empty Key (Key is a non-nullable RegPath).
	p := &msiPackage{
		productName:  "Reg Err Test",
		manufacturer: "Tester",
		version:      "1.0",
		productCode:  "{12345678-1234-1234-1234-123456789ABC}",
		dirEntries: map[string]*dirEntry{
			"TARGETDIR":     {id: "TARGETDIR", defaultDir: "SourceDir"},
			"INSTALLFOLDER": {id: "INSTALLFOLDER", parent: "TARGETDIR", defaultDir: "App"},
		},
		compEntries: map[string]*compEntry{
			"Main": {id: "Main", dirID: "INSTALLFOLDER"},
		},
		registryEntries: []registryEntry{
			{root: RegistryRootHKLM, key: "", name: "Bad", value: "x", component: "Main"},
		},
	}

	_, err := compileMSIPackage(p)
	require.Error(t, err, "an invalid Registry row must fail compile, not be silently dropped")
	require.Contains(t, err.Error(), "Registry row")
}

// TestICE26_MissingAction_Golden is a minimal golden test for P2 ICE engine.
// We create a sequence table with zero rows (something the public compile
// path never produces) and directly invoke the ICE26 rule (registered in
// Tier 1) to assert it produces the expected error finding. This
// demonstrates the "per-ICE golden violation tests using internal test
// package" requirement.
func TestICE26_MissingAction_Golden(t *testing.T) {
	// Build a minimal table with the correct schema but no rows.
	seqTbl := createMSIInstallExecuteSequenceTable()
	// (no rows added — this is the violation)

	// Minimal context (the rule only calls rowsOf for the seq table).
	ctx := &iceContext{
		db: &fakeDBForTest{t: seqTbl},
	}

	findings := runICE26(ctx)

	var ice26 *msiFinding
	for _, f := range findings {
		if f.ICE() == "ICE26" && f.Severity() == SeverityError {
			if mf, ok := f.(*msiFinding); ok && mf.Table() == msiInstallExecSeqTableName {
				ice26 = mf
				break
			}
		}
	}
	require.NotNil(t, ice26, "expected ICE26 error finding for empty sequence table")
	require.Equal(t, msiInstallExecSeqTableName, ice26.Table())
	require.Contains(t, ice26.Message(), "empty")
}

// canonicalSeqActions maps each sequence table to its canonical action list.
func canonicalSeqActions() map[string][]msiSequenceRow {
	return map[string][]msiSequenceRow{
		msiInstallExecSeqTableName: msiInstallExecuteActions,
		msiInstallUISeqTableName:   msiInstallUIActions,
		msiAdminExecSeqTableName:   msiAdminExecuteActions,
		msiAdminUISeqTableName:     msiAdminUIActions,
		msiAdvtExecSeqTableName:    msiAdvtExecuteActions,
	}
}

// buildSeqDB constructs an msiDatabase containing all five sequence tables.
// The mutate callback (if non-nil) is invoked per (table, action) and returns
// the sequence number to use plus whether to emit the row at all. This lets a
// test omit or renumber a single canonical action while keeping every other
// table fully populated (so they don't trip the empty-table check).
func buildSeqDB(t *testing.T, mutate func(table string, a msiSequenceRow) (seq int16, emit bool)) msiDatabase {
	t.Helper()
	b := newMSIDatabaseBuilder()
	for _, tbl := range []string{
		msiInstallExecSeqTableName,
		msiInstallUISeqTableName,
		msiAdminExecSeqTableName,
		msiAdminUISeqTableName,
		msiAdvtExecSeqTableName,
	} {
		for _, a := range canonicalSeqActions()[tbl] {
			seq, emit := a.sequence, true
			if mutate != nil {
				seq, emit = mutate(tbl, a)
			}
			if emit {
				b.WithSequenceAction(tbl, a.action, nil, seq)
			}
		}
	}
	db, err := b.Build()
	require.NoError(t, err)
	return db
}

// TestICE26_AllCanonicalActions_Clean proves a fully-populated set of sequence
// tables yields no ICE26 findings (regression guard that the new content check
// does not false-positive on valid emission).
func TestICE26_AllCanonicalActions_Clean(t *testing.T) {
	db := buildSeqDB(t, nil)
	ctx := newIceContext(db, msiSummaryInfo{})
	findings := runICE26(ctx)
	require.Empty(t, findings, "fully-populated canonical sequence tables must be ICE26-clean")
}

// TestICE26_MissingCanonicalAction_Golden proves the rule actually validates the
// required action set (not just non-emptiness): omit InstallFiles from the
// InstallExecuteSequence table and assert a SeverityError finding naming it.
func TestICE26_MissingCanonicalAction_Golden(t *testing.T) {
	db := buildSeqDB(t, func(table string, a msiSequenceRow) (int16, bool) {
		if table == msiInstallExecSeqTableName && a.action == "InstallFiles" {
			return 0, false // omit
		}
		return a.sequence, true
	})
	ctx := newIceContext(db, msiSummaryInfo{})
	findings := runICE26(ctx)

	var found *msiFinding
	for _, f := range findings {
		mf, ok := f.(*msiFinding)
		if ok && mf.ICE() == "ICE26" && mf.Severity() == SeverityError &&
			mf.Table() == msiInstallExecSeqTableName &&
			strings.Contains(mf.Message(), "required action") &&
			strings.Contains(mf.Message(), "InstallFiles") {
			found = mf
			break
		}
	}
	require.NotNil(t, found, "ICE26 must report the missing canonical action InstallFiles")
}

// TestICE26_WrongSequenceNumber_Golden proves the rule checks the sequence
// number, not just presence: move InstallFiles to a non-canonical number.
func TestICE26_WrongSequenceNumber_Golden(t *testing.T) {
	db := buildSeqDB(t, func(table string, a msiSequenceRow) (int16, bool) {
		if table == msiInstallExecSeqTableName && a.action == "InstallFiles" {
			return a.sequence + 1, true // wrong sequence
		}
		return a.sequence, true
	})
	ctx := newIceContext(db, msiSummaryInfo{})
	findings := runICE26(ctx)

	var found *msiFinding
	for _, f := range findings {
		mf, ok := f.(*msiFinding)
		if ok && mf.ICE() == "ICE26" && mf.Severity() == SeverityError &&
			mf.Table() == msiInstallExecSeqTableName &&
			strings.Contains(mf.Message(), "InstallFiles") &&
			strings.Contains(mf.Message(), "sequence") {
			found = mf
			break
		}
	}
	require.NotNil(t, found, "ICE26 must report InstallFiles at the wrong sequence number")
}

// TestSeverityFilter_FloorOrdering is the regression test for the previously
// inverted severity filter. A floor of SeverityInfo returns all findings;
// SeverityWarning keeps Warning+Error (NOT just Warning); SeverityError keeps
// only Error.
func TestSeverityFilter_FloorOrdering(t *testing.T) {
	// A tiny fake rule set is not reachable here (allICERules is fixed), so we
	// exercise the filter through a context that yields a known mix: ICE39 on a
	// bad RevisionNumber (Error) plus a non-200 PageCount (Warning), and an
	// otherwise clean DB so no other Error findings appear.
	db := buildSeqDB(t, nil) // all canonical actions -> ICE26 clean
	sum := msiSummaryInfo{RevisionNumber: "not-a-guid", PageCount: 150}

	run := func(floor Severity) []Finding {
		v := &msiValidator{
			ices:        map[string]bool{},
			all:         true,
			exclude:     map[string]bool{},
			minSeverity: floor,
		}
		return v.validateInternal(db, sum)
	}

	countBySev := func(fs []Finding) (info, warn, err int) {
		for _, f := range fs {
			switch f.Severity() {
			case SeverityInfo:
				info++
			case SeverityWarning:
				warn++
			case SeverityError:
				err++
			}
		}
		return
	}

	_, warnInfo, errInfo := countBySev(run(SeverityInfo))
	require.GreaterOrEqual(t, warnInfo, 1, "Info floor must include the PageCount Warning")
	require.GreaterOrEqual(t, errInfo, 1, "Info floor must include the RevisionNumber Error")

	_, warnWarn, errWarn := countBySev(run(SeverityWarning))
	require.GreaterOrEqual(t, warnWarn, 1, "Warning floor must KEEP Warnings")
	require.GreaterOrEqual(t, errWarn, 1, "Warning floor must KEEP Errors (regression: inverted filter dropped them)")

	infoErr, warnErr, errErr := countBySev(run(SeverityError))
	require.Equal(t, 0, infoErr, "Error floor must drop Info")
	require.Equal(t, 0, warnErr, "Error floor must drop Warnings")
	require.GreaterOrEqual(t, errErr, 1, "Error floor must keep Errors")
}

// TestWithMaxSeverity_DeprecatedAliasMatchesWithMinSeverity asserts the
// deprecated WithMaxSeverity sets the same floor as WithMinSeverity.
func TestWithMaxSeverity_DeprecatedAliasMatchesWithMinSeverity(t *testing.T) {
	a, err := NewValidator().WithAllICEs().WithMaxSeverity(SeverityWarning).Build()
	require.NoError(t, err)
	b, err := NewValidator().WithAllICEs().WithMinSeverity(SeverityWarning).Build()
	require.NoError(t, err)
	require.Equal(t, a.(*msiValidator).minSeverity, b.(*msiValidator).minSeverity)
	require.Equal(t, SeverityWarning, a.(*msiValidator).minSeverity)
}

// TestICE39_BadRevisionNumber_Golden asserts ICE39 flags an invalid
// RevisionNumber and passes a valid braced GUID.
func TestICE39_BadRevisionNumber_Golden(t *testing.T) {
	bad := newIceContext(&fakeDBForTest{t: createMSIInstallExecuteSequenceTable()}, msiSummaryInfo{RevisionNumber: "not-a-guid", PageCount: 200})
	findings := runICE39(bad)
	var errFinding *msiFinding
	for _, f := range findings {
		mf, ok := f.(*msiFinding)
		if ok && mf.ICE() == "ICE39" && mf.Severity() == SeverityError &&
			strings.Contains(mf.Message(), "RevisionNumber") {
			errFinding = mf
			break
		}
	}
	require.NotNil(t, errFinding, "ICE39 must flag an invalid RevisionNumber")

	good := newIceContext(&fakeDBForTest{t: createMSIInstallExecuteSequenceTable()}, msiSummaryInfo{RevisionNumber: "{12345678-1234-1234-1234-123456789ABC}", PageCount: 200})
	gf := runICE39(good)
	for _, f := range gf {
		require.NotEqual(t, SeverityError, f.Severity(), "valid braced GUID must produce no ICE39 error: %s", f.Error())
	}
}

// TestRegisteredICEs_NoStubRules guards against re-introducing a no-op rule as
// a registered ICE and pins the implemented count to the honest inventory.
func TestRegisteredICEs_NoStubRules(t *testing.T) {
	ids := map[string]bool{}
	for _, r := range allICERules() {
		require.NotNil(t, r.fn, "rule %s has a nil fn", r.id)
		ids[r.id] = true
	}
	require.False(t, ids["ICE06"], "ICE06 was a no-op stub and must not be registered")

	expected := []string{
		"ICE02", "ICE03", "ICE05", "ICE18", "ICE26", "ICE30", "ICE39", "ICE92",
		// P4 tier-2 upgrade ICEs
		"ICE61", "ICE63",
		// P5 tier-3 custom-action ICEs
		"ICE68", "ICE72", "ICE77",
		// P6 tier-4 UI ICEs
		"ICE17", "ICE27", "ICE34",
		// P7 tier-5 media ICE
		"ICE07",
		// P11 tier-6 emitted-table closers
		"ICE08", "ICE09", "ICE16", "ICE21", "ICE24", "ICE45", "ICE74",
		// P11 tier-6 dedicated never-emitted-table ICEs
		"ICE33", "ICE83",
	}
	require.Len(t, allICERules(), len(expected), "registered ICE count must match the honest implemented inventory")
	for _, id := range expected {
		require.True(t, ids[id], "expected implemented rule %s to be registered", id)
	}
}

// fakeDBForTest is a tiny msiDatabase impl for golden rule tests.
type fakeDBForTest struct{ t msiTable }

func (f *fakeDBForTest) GetTable(name string) (msiTable, error) {
	if name == msiInstallExecSeqTableName {
		return f.t, nil
	}
	return nil, fmt.Errorf("not found")
}
func (f *fakeDBForTest) Tables() []string                { return []string{msiInstallExecSeqTableName} }
func (f *fakeDBForTest) FileContents() map[string][]byte { return nil }
func (f *fakeDBForTest) validate() error                 { return nil }

// TestMSIPackage_FlatReproParity_rtTestData exercises P1G2-051: construct an
// equivalent model using the public NewPackage API (plus explicit "flat"
// names to match legacy) and assert byte-identical output vs the legacy
// Builder.BuildMSI path on the canonical rtTest data. The alignment changes
// (target file ID seeds, ensureRoot, feature emission, pkgCode v5, tree dir
// order) make the driven With* calls + values + insertion order (thus string
// pool + streams) match.
func TestMSIPackage_FlatReproParity_rtTestData(t *testing.T) {
	// Build the flat reference package via the public NewPackage API and
	// compare it, table-by-table, against the independently-constructed expected
	// database (the canonical row/GUID/sequence layout for the rt fixture). This
	// replaces the old new-vs-legacy byte comparison now that the legacy BuildMSI
	// path has been removed.
	newBytes := buildRTMSI(t)

	expectedDB := buildRTExpectedDB(t)

	readDB, err := readMSIDatabase(bytes.NewReader(newBytes))
	require.NoError(t, err)
	require.NoError(t, readDB.validate())

	// Compare listed tables (same as rt roundtrip tests).
	for _, name := range rtListedTables {
		wantTbl, err := expectedDB.GetTable(name)
		require.NoError(t, err)
		gotTbl, err := readDB.GetTable(name)
		require.NoError(t, err)

		wantRows := normalizedSortedRows(wantTbl)
		gotRows := normalizedSortedRows(gotTbl)
		if !assert.Equal(t, wantRows, gotRows, "table %s rows differ", name) {
			t.Logf("table %s: want %d rows, got %d", name, len(wantRows), len(gotRows))
		}
	}

	// File contents (cab payload keys = fids) should match.
	wantFC := expectedDB.FileContents()
	gotFC := readDB.FileContents()
	require.Equal(t, wantFC, gotFC, "FileContents (cab members) must match")

	// Determinism: a second build is byte-identical.
	require.True(t, bytes.Equal(newBytes, buildRTMSI(t)),
		"NewPackage output must be deterministic (byte-identical across builds)")
}
