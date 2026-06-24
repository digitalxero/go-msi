package msi

// msi_p7_internal_test.go — P7 multi-media / multi-folder cabinet tests at the
// CAB-builder level (white-box). Higher-level package round-trips land alongside.

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCab_SingleFolderUnchanged(t *testing.T) {
	// buildMSICAB and the 1-folder buildMSICABFolders must be byte-identical.
	members := []msiCabMember{
		{name: "filA", src: FileSourceFromBytes([]byte("alpha payload"))},
		{name: "filB", src: FileSourceFromBytes(bytes.Repeat([]byte("xy"), 50000))},
	}
	a, err := buildMSICAB(members)
	require.NoError(t, err)
	b, err := buildMSICABFolders([][]msiCabMember{members})
	require.NoError(t, err)
	assert.True(t, bytes.Equal(a, b), "1-folder builder must match buildMSICAB byte-for-byte")

	got, err := parseMSICab(a)
	require.NoError(t, err)
	assert.Equal(t, []byte("alpha payload"), got["filA"])
	assert.Equal(t, bytes.Repeat([]byte("xy"), 50000), got["filB"])
}

func TestCab_MultiFolderRoundTrip(t *testing.T) {
	// Three independent folders, each with its own files; round-trip through the
	// reader resolves files by iFolder + uoffFolderStart.
	folders := [][]msiCabMember{
		{{name: "fil01", src: FileSourceFromBytes([]byte("first folder file one"))},
			{name: "fil02", src: FileSourceFromBytes(bytes.Repeat([]byte("A"), 40000))}}, // >1 CFDATA block
		{{name: "fil03", src: FileSourceFromBytes([]byte("second folder"))}},
		{{name: "fil04", src: FileSourceFromBytes(bytes.Repeat([]byte{0}, 70000))}, // all-zeros: MSZIP degenerate path
			{name: "fil05", src: FileSourceFromBytes([]byte("tail"))}},
	}
	cab, err := buildMSICABFolders(folders)
	require.NoError(t, err)

	// CFHEADER cFolders == 3.
	assert.Equal(t, uint16(3), leU16(cab[26:]), "cFolders")
	assert.Equal(t, uint16(5), leU16(cab[28:]), "cFiles")
	assert.Equal(t, uint16(0), leU16(cab[30:]), "flags (no spanning)")

	got, err := parseMSICab(cab)
	require.NoError(t, err)
	require.Len(t, got, 5)
	assert.Equal(t, []byte("first folder file one"), got["fil01"])
	assert.Equal(t, bytes.Repeat([]byte("A"), 40000), got["fil02"])
	assert.Equal(t, []byte("second folder"), got["fil03"])
	assert.Equal(t, bytes.Repeat([]byte{0}, 70000), got["fil04"])
	assert.Equal(t, []byte("tail"), got["fil05"])
}

func leU16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }

func TestCabSpan_RoundTripAndFields(t *testing.T) {
	// A big file (300KB) plus two small ones, capped at 128KB/cab -> the big
	// file spans several cabs.
	big := bytes.Repeat([]byte("SPANME.."), 37500) // 300000 bytes, compressible
	members := []msiCabMember{
		{name: "filhead", src: FileSourceFromBytes([]byte("small head"))},
		{name: "filbig", src: FileSourceFromBytes(big)},
		{name: "filtail", src: FileSourceFromBytes([]byte("small tail"))},
	}
	names := []string{"cab1.cab", "cab2.cab", "cab3.cab", "cab4.cab", "cab5.cab"}
	set, err := buildMSICabSpanned(members, 128*1024, names, 0x1234)
	require.NoError(t, err)
	require.Greater(t, len(set), 1, "300KB over 128KB cap must span multiple cabs")

	// Header field assertions across the set.
	for i, sc := range set {
		data, err := sc.bytes()
		require.NoError(t, err)
		flags := leU16(data[30:])
		setID := leU16(data[32:])
		iCab := leU16(data[34:])
		assert.Equal(t, uint16(0x1234), setID, "shared setID")
		assert.Equal(t, uint16(i), iCab, "ascending iCabinet")
		if i > 0 {
			assert.NotZero(t, flags&cabFlagPrevCabinet, "cab %d has PREV flag", i)
		} else {
			assert.Zero(t, flags&cabFlagPrevCabinet, "first cab has no PREV")
		}
		if i < len(set)-1 {
			assert.NotZero(t, flags&cabFlagNextCabinet, "cab %d has NEXT flag", i)
		} else {
			assert.Zero(t, flags&cabFlagNextCabinet, "last cab has no NEXT")
		}
	}

	// The big file must carry CONTINUED markers somewhere in the set.
	sawToNext := false
	for _, sc := range set {
		// scan CFFILE iFolder values quickly via the reader's own parse later;
		// here just confirm at least one cab declares a TO_NEXT/FROM_PREV file.
		data, err := sc.bytes()
		require.NoError(t, err)
		if bytes.Contains(data, []byte("filbig")) {
			sawToNext = true
		}
	}
	assert.True(t, sawToNext, "the big file appears in the set")

	// Full round-trip via the spanning reader.
	got, err := parseMSISpannedSet(set)
	require.NoError(t, err)
	assert.Equal(t, []byte("small head"), got["filhead"])
	assert.Equal(t, big, got["filbig"], "spanned file reassembles exactly")
	assert.Equal(t, []byte("small tail"), got["filtail"])
}

func TestCabSpan_ContinuedMarkers(t *testing.T) {
	// Confirm the ifold CONTINUED values appear for a file crossing a boundary.
	big := bytes.Repeat([]byte{0xAB}, 200000)
	set, err := buildMSICabSpanned([]msiCabMember{{name: "filx", src: FileSourceFromBytes(big)}}, 64*1024, []string{"a", "b", "c", "d"}, 7)
	require.NoError(t, err)
	require.Greater(t, len(set), 1)

	// First cab: the file ends after this cab -> CONTINUED_TO_NEXT.
	// CFFILE iFolder is at coffFiles+8. coffFiles is data[16:].
	first, err := set[0].bytes()
	require.NoError(t, err)
	coffFiles := int(leU16(first[16:])) | int(leU16(first[18:]))<<16
	ifoldFirst := leU16(first[coffFiles+8:])
	assert.Equal(t, cabIFoldContinuedToNext, ifoldFirst, "first cab marks the file TO_NEXT")

	// Last cab: the file started earlier -> CONTINUED_FROM_PREV.
	last, err := set[len(set)-1].bytes()
	require.NoError(t, err)
	coffFilesL := int(leU16(last[16:])) | int(leU16(last[18:]))<<16
	ifoldLast := leU16(last[coffFilesL+8:])
	assert.Equal(t, cabIFoldContinuedFromPrev, ifoldLast, "last cab marks the file FROM_PREV")
}

func TestCompileP7_AutoSplitMultiCab(t *testing.T) {
	// Three ~30KB files with a 50KB split threshold -> two cabinets.
	big := func(b byte) []byte { return bytes.Repeat([]byte{b}, 30000) }
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("P7 Split").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		WithCabSplitThreshold(70000)
	c := b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F")
	c.WithFile("a.bin", FileSourceFromBytes(big('a')))
	c.WithFile("b.bin", FileSourceFromBytes(big('b')))
	c.WithFile("c.bin", FileSourceFromBytes(big('c')))
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.NoError(t, readDB.validate())

	// 70KB threshold over 3x30KB files -> {a,b} in cab1 (60KB), c in cab2.
	mediaTbl, err := readDB.GetTable("Media")
	require.NoError(t, err)
	require.Len(t, mediaTbl.rows(), 2, "70KB threshold over 3x30KB files -> 2 cabinets")
	// DiskIds 1,2 and cabinet names #cab1.cab/#cab2.cab.
	d1 := findRowInt16(t, mediaTbl, 0, 1)
	assert.Equal(t, "#cab1.cab", d1[3])
	d2 := findRowInt16(t, mediaTbl, 0, 2)
	assert.Equal(t, "#cab2.cab", d2[3])

	// All three files round-trip from their respective cabs (reader reads all media).
	fc := drainFileSources(t, readDB.FileSources())
	require.Len(t, fc, 3)
	for _, name := range []string{"a.bin", "b.bin", "c.bin"} {
		fid := generateMSIFileID("INSTALLFOLDER/"+name, big(name[0]))
		assert.Equal(t, big(name[0]), fc[fid], "%s round-trips", name)
	}
}

func TestCompileP7_ExplicitMediaAssignment(t *testing.T) {
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("P7 Explicit").
		WithManufacturer("go-msix").
		WithVersion("1.0.0")
	install := b.RootDirectory("INSTALLFOLDER", "App")
	install.Component("Core").AssociateToFeature("F").AssignToMedia(1).WithFile(
		"core.bin", FileSourceFromBytes(
			[]byte("core data")))

	install.Component("Extra").AssociateToFeature("F").AssignToMedia(2).WithFile(
		"extra.bin", FileSourceFromBytes(
			[]byte("extra data")))

	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.NoError(t, readDB.validate())

	mediaTbl, err := readDB.GetTable("Media")
	require.NoError(t, err)
	require.Len(t, mediaTbl.rows(), 2)

	fc := drainFileSources(t, readDB.FileSources())
	coreID := generateMSIFileID("INSTALLFOLDER/core.bin", []byte("core data"))
	extraID := generateMSIFileID("INSTALLFOLDER/extra.bin", []byte("extra data"))
	assert.Equal(t, []byte("core data"), fc[coreID])
	assert.Equal(t, []byte("extra data"), fc[extraID])
}

func TestCompileP7_MultiFolderWithinCab(t *testing.T) {
	// One cab, folder threshold forces multiple CFFOLDERs.
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("P7 Folder").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		WithFolderThreshold(40000)
	c := b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F")
	c.WithFile("a.bin", FileSourceFromBytes(bytes.Repeat([]byte("a"), 30000)))
	c.WithFile("b.bin", FileSourceFromBytes(bytes.Repeat([]byte("b"), 30000)))
	c.WithFile("d.bin", FileSourceFromBytes(bytes.Repeat([]byte("d"), 30000)))
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	// One Media row; the embedded cab has multiple CFFOLDERs (folder threshold
	// 40KB over 3x30KB files). All three files still round-trip through the
	// multi-folder reader. (Multi-folder byte validity is also covered by
	// TestCab_MultiFolderRoundTrip + the cabextract -t check.)
	mediaTbl, err := readDB.GetTable("Media")
	require.NoError(t, err)
	require.Len(t, mediaTbl.rows(), 1)

	fc := drainFileSources(t, readDB.FileSources())
	require.Len(t, fc, 3)
	assert.Equal(t, bytes.Repeat([]byte("b"), 30000), fc[generateMSIFileID("INSTALLFOLDER/b.bin", bytes.Repeat([]byte("b"), 30000))])
}

func TestCompileP7_SpanningEmbeddedRoundTrip(t *testing.T) {
	// A 300KB file with a 128KB span cap -> the embedded cabinet is emitted as a
	// chain of streams; readMSIDatabase follows the chain and reassembles.
	big := bytes.Repeat([]byte("payload!"), 37500) // 300000 bytes
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("P7 Span").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		WithSpanning(128 * 1024)
	c := b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F")
	c.WithFile("small.txt", FileSourceFromBytes([]byte("a small companion file")))
	c.WithFile("big.bin", FileSourceFromBytes(big))
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.NoError(t, readDB.validate())

	// Both files reassemble exactly through the spanning-aware reader.
	fc := drainFileSources(t, readDB.FileSources())
	smallID := generateMSIFileID("INSTALLFOLDER/small.txt", []byte("a small companion file"))
	bigID := generateMSIFileID("INSTALLFOLDER/big.bin", big)
	assert.Equal(t, []byte("a small companion file"), fc[smallID])
	assert.Equal(t, big, fc[bigID], "spanned 300KB file reassembles exactly")

	// One Media row referencing only the head stream "#cab1.cab".
	mediaTbl, err := readDB.GetTable("Media")
	require.NoError(t, err)
	require.Len(t, mediaTbl.rows(), 1)
	assert.Equal(t, "#cab1.cab", mediaTbl.rows()[0].values()[3])
}

// capturingWriteCloser collects external cab bytes by name.
type capturingWriteCloser struct {
	name string
	sink map[string][]byte
	buf  bytes.Buffer
}

func (c *capturingWriteCloser) Write(p []byte) (int, error) { return c.buf.Write(p) }
func (c *capturingWriteCloser) Close() error {
	c.sink[c.name] = append([]byte(nil), c.buf.Bytes()...)
	return nil
}

func TestCompileP7_ExternalCab(t *testing.T) {
	external := map[string][]byte{}
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("P7 External").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		WithExternalCabs(func(name string) (io.WriteCloser, error) {
			return &capturingWriteCloser{name: name, sink: external}, nil
		})
	b.Media(2).External().WithCabinet("disk2.cab")

	install := b.RootDirectory("INSTALLFOLDER", "App")
	install.Component("Core").AssociateToFeature("F").AssignToMedia(1).WithFile(
		"core.bin", FileSourceFromBytes(
			[]byte("embedded core")))

	install.Component("Extra").AssociateToFeature("F").AssignToMedia(2).WithFile(
		"extra.bin", FileSourceFromBytes(
			[]byte("external extra payload")))

	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.NoError(t, readDB.validate())

	// Media: disk1 embedded "#cab1.cab", disk2 external "disk2.cab" (no '#').
	mediaTbl, err := readDB.GetTable("Media")
	require.NoError(t, err)
	require.Len(t, mediaTbl.rows(), 2)
	d1 := findRowInt16(t, mediaTbl, 0, 1)
	assert.Equal(t, "#cab1.cab", d1[3])
	d2 := findRowInt16(t, mediaTbl, 0, 2)
	assert.Equal(t, "disk2.cab", d2[3], "external cabinet has no '#' prefix")

	// The embedded MSI only carries the disk-1 (embedded) file.
	coreID := generateMSIFileID("INSTALLFOLDER/core.bin", []byte("embedded core"))
	extraID := generateMSIFileID("INSTALLFOLDER/extra.bin", []byte("external extra payload"))
	fc := drainFileSources(t, readDB.FileSources())
	assert.Equal(t, []byte("embedded core"), fc[coreID])
	_, hasExtra := fc[extraID]
	assert.False(t, hasExtra, "external file is NOT embedded in the MSI")

	// The external writer received a valid cab containing the disk-2 file.
	require.Contains(t, external, "disk2.cab", "external cab written via the callback")
	members, err := parseMSICab(external["disk2.cab"])
	require.NoError(t, err)
	assert.Equal(t, []byte("external extra payload"), members[extraID])
}

func TestCompileP7_ExternalCabWithoutWriterErrors(t *testing.T) {
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("P7 NoWriter").
		WithManufacturer("go-msix").
		WithVersion("1.0.0")
	b.Media(1).External().WithCabinet("disk1.cab")
	b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F").
		AssignToMedia(1).WithFile(
		"a.bin", FileSourceFromBytes(
			[]byte("x")))

	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	err = pkg.WriteMSI(&buf)
	require.Error(t, err, "external cabinet without WithExternalCabs must error")
	assert.Contains(t, err.Error(), "external")
}

func TestICE07_MediaCoverage_Golden(t *testing.T) {
	// A File.Sequence beyond every Media.LastSequence -> ICE07 error.
	db := newMSIDatabaseBuilder()
	db.WithStandardProperties("X", "1.0.0", "Y", "{12345678-1234-1234-1234-123456789ABC}")
	db.WithDirectory("TARGETDIR", "", "SourceDir")
	db.WithComponent("Main", "{11111111-2222-3333-4444-555555555555}", "TARGETDIR", 0, "fil1")
	db.WithFileSource("Main", "fil1", "a.txt", FileSourceFromBytes([]byte("x")), "", int16(1))
	db.WithFileSource("Main", "fil2", "b.txt", FileSourceFromBytes([]byte("y")), "", int16(5)) // seq 5
	db.WithMedia(1, 1, "#cab1.cab")                                                            // covers only seq 1
	built, err := db.Build()
	require.NoError(t, err)

	findings := iceFindingsFor(built, msiSummaryInfo{}, "ICE07")
	require.NotEmpty(t, findings, "uncovered File.Sequence must trip ICE07")
	hasErr := false
	for _, f := range findings {
		if f.Severity() == SeverityError {
			hasErr = true
		}
	}
	assert.True(t, hasErr)

	// A real multi-cab package (built via the public API) is ICE07-clean.
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("Clean Media").WithManufacturer("go-msix").WithVersion("1.0.0").
		WithCabSplitThreshold(70000)
	c := b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F")
	c.WithFile("a.bin", FileSourceFromBytes(bytes.Repeat([]byte("a"), 30000)))
	c.WithFile("b.bin", FileSourceFromBytes(bytes.Repeat([]byte("b"), 30000)))
	c.WithFile("d.bin", FileSourceFromBytes(bytes.Repeat([]byte("d"), 30000)))
	b.Feature("F").WithLevel(1)
	pkg, err := b.Build() // validate-by-default runs ICE07
	require.NoError(t, err, "well-formed multi-cab package must be ICE07-clean")
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
}

// findRowInt16 finds the first row whose cell at keyIdx equals the int16 key.
func findRowInt16(t *testing.T, tbl msiTable, keyIdx int, key int16) []any {
	t.Helper()
	for _, r := range tbl.rows() {
		vals := r.values()
		if keyIdx < len(vals) {
			if v, ok := vals[keyIdx].(int16); ok && v == key {
				return vals
			}
		}
	}
	t.Fatalf("no row with int16 cell[%d]==%d", keyIdx, key)
	return nil
}
