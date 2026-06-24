package msi

// msi_mst_internal_test.go — P9.3/P9.4 MST builder + generate→apply oracle.

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// p9BasePackage builds a small package with explicit properties A/B/C, used as
// the base of the transform diffs below.
func p9BasePackage(t *testing.T) *msiPackage {
	t.Helper()
	b := NewPackage().
		WithProductCode("{AAAAAAAA-1111-2222-3333-444444444444}").
		WithUpgradeCode("{BBBBBBBB-1111-2222-3333-444444444444}").
		WithProductName("Base").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		WithProperty("PROPA", "1").
		WithProperty("PROPB", "2").
		WithProperty("PROPC", "3")
	b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F").WithFile(
		"a.exe", FileSourceFromBytes(
			[]byte("MZ")))

	b.Feature("F").WithLevel(1)
	pkg, err := b.Build()
	require.NoError(t, err)
	return pkg.(*msiPackage)
}

// rowSetOfDB reduces a database to table -> (key -> cells), skipping the catalog.
func rowSetOfDB(db msiDatabase) map[string]map[string][]any {
	out := map[string]map[string][]any{}
	for _, name := range db.Tables() {
		if name == msiTablesTableName || name == msiColumnsTableName {
			continue
		}
		tbl, _ := db.GetTable(name)
		cols := tbl.columns()
		keyIdx := keyColumnIndexes(cols)
		m := map[string][]any{}
		for _, r := range tbl.rows() {
			vals := padCells(r.values(), len(cols))
			m[transformRowKey(vals, cols, keyIdx)] = vals
		}
		out[name] = m
	}
	return out
}

func rowSetOfApplied(applied map[string]transformedTable) map[string]map[string][]any {
	out := map[string]map[string][]any{}
	for name, tt := range applied {
		if name == msiTablesTableName || name == msiColumnsTableName {
			continue
		}
		keyIdx := keyColumnIndexes(tt.cols)
		m := map[string][]any{}
		for _, vals := range tt.rows {
			m[transformRowKey(vals, tt.cols, keyIdx)] = vals
		}
		out[name] = m
	}
	return out
}

// assertRowSetsEqual fails with a precise message on the first divergence.
func assertRowSetsEqual(t *testing.T, want, got map[string]map[string][]any) {
	t.Helper()
	for name, wrows := range want {
		grows, ok := got[name]
		require.Truef(t, ok, "table %s missing after apply", name)
		require.Lenf(t, grows, len(wrows), "table %s row count differs", name)
		for key, wvals := range wrows {
			gvals, ok := grows[key]
			require.Truef(t, ok, "table %s missing row %q after apply", name, key)
			require.Lenf(t, gvals, len(wvals), "table %s row %q cell count differs", name, key)
			for i := range wvals {
				assert.Truef(t, cellsEqual(wvals[i], gvals[i]),
					"table %s row %q col %d: want %v (%T), got %v (%T)",
					name, key, i, wvals[i], wvals[i], gvals[i], gvals[i])
			}
		}
	}
	for name := range got {
		_, ok := want[name]
		assert.Truef(t, ok, "table %s appeared after apply but not in target", name)
	}
}

// buildTransform compiles base→target and returns the concrete transform.
func buildTransform(t *testing.T, base, target *msiPackage) *msiTransform {
	t.Helper()
	tr, err := NewTransform().From(base).To(target).Build()
	require.NoError(t, err)
	return tr.(*msiTransform)
}

func TestMST_ApplyRoundTrip_Update(t *testing.T) {
	base := p9BasePackage(t)

	// Target: change PROPB's value (an UPDATE).
	tb := NewPackage().
		WithProductCode("{AAAAAAAA-1111-2222-3333-444444444444}").
		WithUpgradeCode("{BBBBBBBB-1111-2222-3333-444444444444}").
		WithProductName("Base").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		WithProperty("PROPA", "1").
		WithProperty("PROPB", "CHANGED").
		WithProperty("PROPC", "3")
	tb.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F").WithFile(
		"a.exe", FileSourceFromBytes(
			[]byte("MZ")))

	tb.Feature("F").WithLevel(1)
	tpkg, err := tb.Build()
	require.NoError(t, err)
	target := tpkg.(*msiPackage)

	tr := buildTransform(t, base, target)

	// There must be a Property delta stream.
	assert.True(t, hasDeltaStream(tr.streams, "Property"), "Property change yields a delta stream")

	applied, err := applyMSITransform(tr.baseDB, tr.streams)
	require.NoError(t, err)
	assertRowSetsEqual(t, rowSetOfDB(tr.targetDB), rowSetOfApplied(applied))
}

func TestMST_ApplyRoundTrip_InsertAndDelete(t *testing.T) {
	base := p9BasePackage(t)

	// Target: drop PROPC (DELETE), add PROPD (INSERT), keep A/B.
	tb := NewPackage().
		WithProductCode("{AAAAAAAA-1111-2222-3333-444444444444}").
		WithUpgradeCode("{BBBBBBBB-1111-2222-3333-444444444444}").
		WithProductName("Base").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		WithProperty("PROPA", "1").
		WithProperty("PROPB", "2").
		WithProperty("PROPD", "4")
	tb.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F").WithFile(
		"a.exe", FileSourceFromBytes(
			[]byte("MZ")))

	tb.Feature("F").WithLevel(1)
	tpkg, err := tb.Build()
	require.NoError(t, err)
	target := tpkg.(*msiPackage)

	tr := buildTransform(t, base, target)
	applied, err := applyMSITransform(tr.baseDB, tr.streams)
	require.NoError(t, err)
	assertRowSetsEqual(t, rowSetOfDB(tr.targetDB), rowSetOfApplied(applied))
}

func TestMST_NoChange_EmptyDelta(t *testing.T) {
	base := p9BasePackage(t)
	// Target identical to base.
	target := p9BasePackage(t)
	tr := buildTransform(t, base, target)
	// No table delta streams; only summary + _StringPool + _StringData.
	assert.False(t, hasDeltaStream(tr.streams, "Property"))
	applied, err := applyMSITransform(tr.baseDB, tr.streams)
	require.NoError(t, err)
	assertRowSetsEqual(t, rowSetOfDB(tr.targetDB), rowSetOfApplied(applied))
}

func TestMST_WriteMST_StructuralShape(t *testing.T) {
	base := p9BasePackage(t)
	tb := NewPackage().
		WithProductCode("{AAAAAAAA-1111-2222-3333-444444444444}").
		WithUpgradeCode("{BBBBBBBB-1111-2222-3333-444444444444}").
		WithProductName("Base").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		WithProperty("PROPA", "1").
		WithProperty("PROPB", "CHANGED").
		WithProperty("PROPC", "3")
	tb.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F").WithFile(
		"a.exe", FileSourceFromBytes(
			[]byte("MZ")))

	tb.Feature("F").WithLevel(1)
	tpkg, err := tb.Build()
	require.NoError(t, err)

	tr, err := NewTransform().
		From(base).
		To(tpkg.(*msiPackage)).
		WithValidation(TransformValidateProduct | TransformValidateUpgradeCode).
		Build()
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, tr.WriteMST(&buf))

	// It is a CFB: read its raw streams back and assert the transform shape.
	streams, err := readMSIRawStreams(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	var hasSummary, hasPool, hasData, hasProperty bool
	for _, s := range streams {
		switch {
		case s.name == msiSummaryStreamName:
			hasSummary = true
		default:
			name, isTable := decodeMSIStreamName(s.name)
			if !isTable {
				continue
			}
			switch name {
			case msiStringPoolStreamName:
				hasPool = true
			case msiStringDataStreamName:
				hasData = true
			case "Property":
				hasProperty = true
			}
		}
	}
	assert.True(t, hasSummary, "\\x05SummaryInformation present")
	assert.True(t, hasPool, "_StringPool present")
	assert.True(t, hasData, "_StringData present")
	assert.True(t, hasProperty, "Property delta stream present")

	// And the transform summary parses with our lineage RevisionNumber.
	sum, err := readMSISummaryInfo(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	assert.Contains(t, sum.RevisionNumber, "{AAAAAAAA-1111-2222-3333-444444444444}")
	assert.Contains(t, sum.RevisionNumber, "{BBBBBBBB-1111-2222-3333-444444444444}")
}

func hasDeltaStream(streams []msiStream, table string) bool {
	for _, s := range streams {
		name, isTable := decodeMSIStreamName(s.name)
		if isTable && name == table {
			return true
		}
	}
	return false
}
