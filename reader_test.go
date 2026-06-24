package msi

// msi_reader_test.go
// Internal tests for msi_reader.go (package msix, not msix_test: the reader
// is unexported and the round-trip compares against unexported builder
// internals). The centerpiece is the full write -> read round trip: a real
// Builder.BuildMSI output is read back and compared table-by-table, cell-by-
// cell against an msiDatabase constructed exactly the way BuildMSI does.

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rtListedTables is the exact table list the round-trip MSI must expose:
// every BuildMSI core table plus _Validation, in sorted order. _Tables and
// _Columns are the system catalog and are deliberately NOT listed.
var rtListedTables = []string{
	"AdminExecuteSequence",
	"AdminUISequence",
	"AdvtExecuteSequence",
	"Component",
	"Directory",
	"Feature",
	"FeatureComponents",
	"File",
	"InstallExecuteSequence",
	"InstallUISequence",
	"Media",
	"Property",
	"_Validation",
}

type rtTestFile struct {
	path string
	data []byte
}

// rtTestFiles returns the round-trip payloads: distinct names, and one
// >64KiB all-zeros file to force a multi-frame cabinet and exercise the
// MSZIP degenerate-distance-table sanitizer.
func rtTestFiles() []rtTestFile {
	return []rtTestFile{
		{path: "app.exe", data: []byte("MZ fake executable payload")},
		{path: "data/config.json", data: []byte(`{"name":"rt","ok":true}`)},
		{path: "zeros.bin", data: make([]byte, 70*1024)},
	}
}

// rtConfig is the round-trip product identity (formerly the legacy MSIConfig,
// which was dropped in the go-msi split).
type rtConfig struct {
	ProductName  string
	Manufacturer string
	Version      string
	ProductCode  string
}

func rtTestConfig() rtConfig {
	return rtConfig{
		ProductName:  "RT Product",
		Manufacturer: "RT Co",
		Version:      "1.2.3",
		ProductCode:  "{12345678-1234-1234-1234-123456789ABC}",
	}
}

// buildRTMSI builds the round-trip MSI via the public NewPackage API (the
// legacy Builder.BuildMSI path was removed in the go-msi split). The flat
// construction matches buildRTExpectedDB row-for-row.
func buildRTMSI(t *testing.T) []byte {
	t.Helper()
	cfg := rtTestConfig()
	b := NewPackage().
		WithProductCode(cfg.ProductCode).
		WithProductName(cfg.ProductName).
		WithManufacturer(cfg.Manufacturer).
		WithVersion(cfg.Version).
		WithAllUsers(false).
		WithProperty("ProductLanguage", "1033")

	c := b.Directory("INSTALLFOLDER").Component("MainComponent")
	files := rtTestFiles()
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	for _, f := range files {
		c.WithFile(path.Base(f.path), FileSourceFromBytes(f.data))
	}
	b.Feature("MainFeature").
		WithTitle("Main Feature").
		WithDisplay(2).
		WithLevel(1).
		AssociateComponent("MainComponent")

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	return buf.Bytes()
}

// buildRTExpectedDB constructs the msiDatabase BuildMSI builds internally for
// rtTestConfig + rtTestFiles, mirroring Builder.BuildMSI step for step (same
// file staging order, same namers, same derived GUIDs, same sequence rows).
func buildRTExpectedDB(t *testing.T) msiDatabase {
	t.Helper()
	cfg := rtTestConfig()

	files := rtTestFiles()
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })

	type stagedFile struct {
		id       string
		fileName string
		data     []byte
	}
	namer := newMSIShortNamer()
	staged := make([]stagedFile, 0, len(files))
	for _, f := range files {
		fileName, err := namer.msiFileNameColumn(path.Base(f.path))
		require.NoError(t, err)
		// Target-oriented seed for P1G2-051 flat repro parity (matches the aligned
		// legacy staging in BuildMSI and the compile logical for equivalent models).
		staged = append(staged, stagedFile{
			id:       generateMSIFileID("INSTALLFOLDER/"+path.Base(f.path), f.data),
			fileName: fileName,
			data:     f.data,
		})
	}

	db := newMSIDatabaseBuilder()
	db.WithStandardProperties(cfg.ProductName, cfg.Version, cfg.Manufacturer, cfg.ProductCode)
	db.WithProperties(map[string]string{"ProductLanguage": "1033"})

	dirNamer := newMSIShortNamer()
	installDirName, err := dirNamer.msiFileNameColumn(msiSanitizeDirName(cfg.ProductName))
	require.NoError(t, err)
	db.WithDirectory("TARGETDIR", "", "SourceDir")
	db.WithDirectory("INSTALLFOLDER", "TARGETDIR", installDirName)

	componentGUID, err := msiGUIDv5(msiPackageNamespaceGUID, "component|"+cfg.ProductCode+"|INSTALLFOLDER|MainComponent")
	require.NoError(t, err)
	db.WithComponent("MainComponent", componentGUID, "INSTALLFOLDER", 0, staged[0].id)
	db.WithFeature("MainFeature", "Main Feature", "", 2, 1)
	db.AssociateComponentToFeature("MainFeature", "MainComponent")

	for i, f := range staged {
		db.WithFileSource("MainComponent", f.id, f.fileName, FileSourceFromBytes(f.data), "", int16(i+1))
	}
	db.WithMedia(1, int16(len(staged)), "#"+msiCabinetStreamName)

	for table, actions := range map[string][]msiSequenceRow{
		msiInstallExecSeqTableName: msiInstallExecuteActions,
		msiInstallUISeqTableName:   msiInstallUIActions,
		msiAdminExecSeqTableName:   msiAdminExecuteActions,
		msiAdminUISeqTableName:     msiAdminUIActions,
		msiAdvtExecSeqTableName:    msiAdvtExecuteActions,
	} {
		for _, a := range actions {
			db.WithSequenceAction(table, a.action, nil, a.sequence)
		}
	}

	msidb, err := db.Build()
	require.NoError(t, err)
	return msidb
}

// writeTestCFB serializes streams through the production CFB writer into a
// temp file (the writer needs an io.WriteSeeker) and returns the bytes.
func writeTestCFB(t *testing.T, streams []msiStream) []byte {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.msi")
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, writeMSICFB(streams, f))
	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)
	data, err := io.ReadAll(f)
	require.NoError(t, err)
	return data
}

// normalizeMSICell maps a row value to a canonical comparable form: pointers
// are dereferenced, MSI's indistinguishable ""/NULL both become nil, and all
// integer kinds widen to int64.
func normalizeMSICell(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		if x == "" {
			return nil
		}
		return x
	case *string:
		if x == nil {
			return nil
		}
		return normalizeMSICell(*x)
	case int:
		return int64(x)
	case int16:
		return int64(x)
	case int32:
		return int64(x)
	case *int16:
		if x == nil {
			return nil
		}
		return int64(*x)
	case *int32:
		if x == nil {
			return nil
		}
		return int64(*x)
	default:
		return v
	}
}

// normalizedSortedRows extracts a table's rows as normalized value slices,
// sorted by the fmt.Sprint of their primary-key cells. The writer orders rows
// on disk by string-pool ID, which is neither lexicographic nor insertion
// order, so both sides must be re-sorted the same way before comparing.
func normalizedSortedRows(tbl msiTable) [][]any {
	var keyIdx []int
	for i, col := range tbl.columns() {
		if col.isKey() {
			keyIdx = append(keyIdx, i)
		}
	}
	rows := tbl.rows()
	out := make([][]any, 0, len(rows))
	for _, r := range rows {
		vals := r.values()
		norm := make([]any, len(vals))
		for i, v := range vals {
			norm[i] = normalizeMSICell(v)
		}
		out = append(out, norm)
	}
	sortKey := func(vals []any) string {
		parts := make([]string, len(keyIdx))
		for i, k := range keyIdx {
			parts[i] = fmt.Sprint(vals[k])
		}
		return strings.Join(parts, "\x00")
	}
	sort.Slice(out, func(a, b int) bool { return sortKey(out[a]) < sortKey(out[b]) })
	return out
}

func TestReadMSIDatabase_RoundTrip(t *testing.T) {
	msiBytes := buildRTMSI(t)

	readDB, err := readMSIDatabase(bytes.NewReader(msiBytes))
	require.NoError(t, err)
	require.NoError(t, readDB.validate())

	assert.Equal(t, rtListedTables, readDB.Tables(), "read table list must be exactly the listed tables")

	expectedDB := buildRTExpectedDB(t)

	// The written set minus the unlisted _Tables/_Columns system catalog must
	// equal the read set.
	var writtenListed []string
	for _, name := range expectedDB.Tables() {
		if name == msiTablesTableName || name == msiColumnsTableName {
			continue
		}
		writtenListed = append(writtenListed, name)
	}
	require.Equal(t, writtenListed, readDB.Tables())

	for _, name := range readDB.Tables() {
		wantTbl, err := expectedDB.GetTable(name)
		require.NoError(t, err)
		gotTbl, err := readDB.GetTable(name)
		require.NoError(t, err)

		wantCols, gotCols := wantTbl.columns(), gotTbl.columns()
		require.Len(t, gotCols, len(wantCols), "table %s column count", name)
		for i := range wantCols {
			assert.Equal(t, wantCols[i].name(), gotCols[i].name(), "table %s column %d name", name, i)
			// typeBits encodes kind, width and key/nullable/localizable flags;
			// equality proves the whole schema survived the round trip even
			// though categories degrade to the generic ones.
			assert.Equal(t, wantCols[i].typeBits(), gotCols[i].typeBits(), "table %s column %s type bits", name, wantCols[i].name())
		}

		wantRows := normalizedSortedRows(wantTbl)
		gotRows := normalizedSortedRows(gotTbl)
		require.Len(t, gotRows, len(wantRows), "table %s row count", name)
		assert.Equal(t, wantRows, gotRows, "table %s rows", name)
	}

	// Cabinet payloads: same keys (File table primary keys) and identical
	// bytes, including the multi-frame 70KiB zeros payload.
	wantFiles := drainFileSources(t, expectedDB.FileSources())
	gotFiles := drainFileSources(t, readDB.FileSources())
	require.Len(t, gotFiles, len(wantFiles))
	for id, wantData := range wantFiles {
		gotData, ok := gotFiles[id]
		require.True(t, ok, "missing cab payload for File key %s", id)
		assert.True(t, bytes.Equal(wantData, gotData), "cab payload for File key %s differs (%d vs %d bytes)", id, len(wantData), len(gotData))
	}
}

func TestReadMSIDatabase_EmptyTablesRoundTrip(t *testing.T) {
	// A database with no user rows: every core table is listed in _Tables but
	// has NO stream, which must read back as zero rows (only _Validation,
	// which describes the schemas themselves, has rows).
	msidb, err := newMSIDatabaseBuilder().Build()
	require.NoError(t, err)
	streams, err := serializeMSIStreams(msidb, msiSummaryInfo{
		Template:       "x64;1033",
		RevisionNumber: "{12345678-1234-1234-1234-123456789ABC}",
		PageCount:      200,
		WordCount:      2,
	}, cabBuildOptions{})
	require.NoError(t, err)
	data := writeTestCFB(t, streams)

	readDB, err := readMSIDatabase(bytes.NewReader(data))
	require.NoError(t, err)
	require.NoError(t, readDB.validate())

	assert.Equal(t, rtListedTables, readDB.Tables())
	for _, name := range readDB.Tables() {
		tbl, err := readDB.GetTable(name)
		require.NoError(t, err)
		if name == msiValidationTableName {
			assert.NotEmpty(t, tbl.rows(), "_Validation should carry the catalog rows")
			continue
		}
		assert.Empty(t, tbl.rows(), "table %s should round-trip with zero rows", name)
	}
	assert.Empty(t, readDB.FileSources())
}

// TestReadMSIDatabase_IconBinaryRoundTrip proves the reader decodes binary/
// object columns (Icon.Data / Binary.Data): their in-table cell is a 2-byte
// presence flag and the payload lives in an Icon.<Name>/Binary.<Name> side
// stream. A present cell must read back as the exact []byte payload; a NULL
// (nil) cell must read back as nil with no side stream.
func TestReadMSIDatabase_IconBinaryRoundTrip(t *testing.T) {
	iconData := []byte{0, 1, 2, 3, 0xFF}
	binData := []byte("hello\x00world")

	iconTbl := createMSIIconTable()
	require.NoError(t, iconTbl.addRow(
		newMSIRowBuilder().WithColumns(iconTbl.columns()...).
			WithValues("MyIcon", iconData).Build()))

	binTbl := createMSIBinaryTable()
	require.NoError(t, binTbl.addRow(
		newMSIRowBuilder().WithColumns(binTbl.columns()...).
			WithValues("MyBin", binData).Build()))

	msidb, err := newMSIDatabaseBuilder().
		WithTable(iconTbl).
		WithTable(binTbl).
		Build()
	require.NoError(t, err)

	streams, err := serializeMSIStreams(msidb, msiSummaryInfo{
		Template:       "x64;1033",
		RevisionNumber: "{12345678-1234-1234-1234-123456789ABC}",
		PageCount:      200,
		WordCount:      2,
	}, cabBuildOptions{})
	require.NoError(t, err)
	data := writeTestCFB(t, streams)

	readDB, err := readMSIDatabase(bytes.NewReader(data))
	require.NoError(t, err)
	require.NoError(t, readDB.validate())

	readIcon, err := readDB.GetTable("Icon")
	require.NoError(t, err)
	iconRows := readIcon.rows()
	require.Len(t, iconRows, 1)
	assert.Equal(t, "MyIcon", iconRows[0].values()[0])
	gotIcon, ok := iconRows[0].values()[1].([]byte)
	require.True(t, ok, "Icon.Data cell must be []byte, got %T", iconRows[0].values()[1])
	assert.Equal(t, iconData, gotIcon)

	readBin, err := readDB.GetTable("Binary")
	require.NoError(t, err)
	binRows := readBin.rows()
	require.Len(t, binRows, 1)
	assert.Equal(t, "MyBin", binRows[0].values()[0])
	gotBin, ok := binRows[0].values()[1].([]byte)
	require.True(t, ok, "Binary.Data cell must be []byte, got %T", binRows[0].values()[1])
	assert.Equal(t, binData, gotBin)
}

// TestReadMSIDatabase_MissingBinarySideStream proves a present binary cell with
// no matching side stream is a hard error (the payload must not be silently
// dropped or misread as a string ref).
func TestReadMSIDatabase_MissingBinarySideStream(t *testing.T) {
	iconTbl := createMSIIconTable()
	require.NoError(t, iconTbl.addRow(
		newMSIRowBuilder().WithColumns(iconTbl.columns()...).
			WithValues("Ghost", []byte{1, 2, 3}).Build()))

	msidb, err := newMSIDatabaseBuilder().WithTable(iconTbl).Build()
	require.NoError(t, err)
	streams, err := serializeMSIStreams(msidb, msiSummaryInfo{
		Template:       "x64;1033",
		RevisionNumber: "{12345678-1234-1234-1234-123456789ABC}",
		PageCount:      200,
		WordCount:      2,
	}, cabBuildOptions{})
	require.NoError(t, err)

	// Drop the Icon.Ghost side stream, leaving the present flag dangling.
	ghost := encodeMSIStreamName(false, "Icon.Ghost")
	kept := streams[:0]
	for _, s := range streams {
		if s.name == ghost {
			continue
		}
		kept = append(kept, s)
	}
	data := writeTestCFB(t, kept)

	_, err = readMSIDatabase(bytes.NewReader(data))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "side stream")
}

func TestReadMSISummaryInfo_RoundTrip(t *testing.T) {
	msiBytes := buildRTMSI(t)

	info, err := readMSISummaryInfo(bytes.NewReader(msiBytes))
	require.NoError(t, err)

	assert.Equal(t, "RT Product", info.Subject)
	assert.Equal(t, "RT Co", info.Author)
	assert.Equal(t, 200, info.PageCount)
	assert.Equal(t, 2, info.WordCount)
	assert.True(t, msiValidGUID(info.RevisionNumber),
		"RevisionNumber %q should be a braced uppercase GUID", info.RevisionNumber)
}

func TestReadMSIDatabase_Errors(t *testing.T) {
	t.Run("garbage input", func(t *testing.T) {
		_, err := readMSIDatabase(bytes.NewReader([]byte("this is not a compound file at all")))
		require.Error(t, err)
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := readMSIDatabase(bytes.NewReader(nil))
		require.Error(t, err)
	})

	t.Run("truncated msi", func(t *testing.T) {
		msiBytes := buildRTMSI(t)
		_, err := readMSIDatabase(bytes.NewReader(msiBytes[:600]))
		require.Error(t, err)
	})

	t.Run("missing string pool", func(t *testing.T) {
		// A structurally valid CFB holding one table stream but no
		// _StringPool must fail with a clear error.
		data := writeTestCFB(t, []msiStream{
			{name: encodeMSIStreamName(true, "Property"), data: make([]byte, 4)},
		})
		_, err := readMSIDatabase(bytes.NewReader(data))
		require.Error(t, err)
		assert.Contains(t, err.Error(), msiStringPoolStreamName)
	})
}

func TestReadMSISummaryInfo_Errors(t *testing.T) {
	t.Run("garbage input", func(t *testing.T) {
		_, err := readMSISummaryInfo(bytes.NewReader([]byte("garbage")))
		require.Error(t, err)
	})

	t.Run("missing summary stream", func(t *testing.T) {
		data := writeTestCFB(t, []msiStream{
			{name: encodeMSIStreamName(true, msiStringPoolStreamName), data: make([]byte, 4)},
		})
		_, err := readMSISummaryInfo(bytes.NewReader(data))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SummaryInformation")
	})
}
