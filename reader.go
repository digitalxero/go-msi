package msi

// msi_reader.go
// Pure-Go reader for Windows Installer (.msi) compound files: the exact
// inverse of msi_cfbwriter.go / msi_cab.go.
//
// Decoding pipeline (mirrors the writer; cross-checked against Wine
// dlls/msi/table.c):
//  1. Open the CFB and decode every stream name with decodeMSIStreamName;
//     the U+4840 prefix separates table streams from data (cabinet) streams,
//     and \x05-prefixed control streams are stored literally.
//  2. Rebuild the shared string pool from _StringPool/_StringData. Its
//     long-refs flag fixes the on-disk width of every string cell (2 or 3
//     bytes) for ALL table streams, so it must be parsed first.
//  3. Decode _Columns with its fixed, hardcoded schema (Wine _Columns_cols:
//     Table string key, Number i2 key, Name string, Type i2). The Type cell
//     carries the raw MSITYPE bitfield, stored with the standard i2 ^0x8000
//     transform, which yields each user column's kind, width and flags.
//  4. Decode _Tables (single string key column) for the list of exposed
//     tables, then every listed table stream COLUMN-MAJOR: all rows'
//     column-1 cells first, then column-2, ... Row count = stream length /
//     row byte width; a listed table with no stream has zero rows.
//  5. Resolve Media rows whose Cabinet value starts with "#" to embedded
//     cabinet streams and expose each member as a streaming FileSource (decoded
//     on demand), keyed by cab member name == File table primary key.
//
// Column categories cannot be recovered from the type bits (an Identifier
// and a Formatted column serialize identically), so read-back schemas use
// the generic categories only: msiColText for strings, msiColInteger for i2,
// msiColDoubleInteger for i4, msiColBinary for binary/object columns.
// typeBits() still round-trips exactly because it derives from kind + width +
// flags, all of which are preserved. Binary/object columns (Icon.Data,
// Binary.Data) decode to msiColBinary: the in-table cell is a 2-byte presence
// flag and the payload is read back from the Icon.<Name>/Binary.<Name> side
// streams into the cell's []byte.

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/abemedia/go-cfb"
)

const (
	// msiStringPoolStreamName / msiStringDataStreamName are the decoded names
	// of the string pool streams (stored table-prefixed like every table).
	msiStringPoolStreamName = "_StringPool"
	msiStringDataStreamName = "_StringData"
	// msiSummaryInfoStreamName is stored literally, never name-encoded.
	msiSummaryInfoStreamName = "\x05SummaryInformation"
)

// readMSIDatabase parses a complete MSI database from r: schemas from
// _Columns, the table list from _Tables, every listed table's rows, and the
// payload bytes of every embedded cabinet referenced by the Media table.
// The returned database is read-only; it exposes exactly the tables listed
// in _Tables (the _Tables/_Columns system catalog and the string pool are
// consumed, not exposed).
func readMSIDatabase(r io.ReaderAt) (msiDatabase, error) {
	tableStreams, dataStreams, err := readMSICFBStreams(r)
	if err != nil {
		return nil, err
	}

	poolStream, ok := tableStreams[msiStringPoolStreamName]
	if !ok {
		return nil, fmt.Errorf("msix: msi database has no %s stream", msiStringPoolStreamName)
	}
	pool, err := parseMSIStringPool(poolStream, tableStreams[msiStringDataStreamName])
	if err != nil {
		return nil, fmt.Errorf("msix: parsing string pool: %w", err)
	}

	// _Columns first: every other table's row width depends on its schema.
	schemas, err := readMSIColumnSchemas(tableStreams[msiColumnsTableName], pool)
	if err != nil {
		return nil, err
	}
	listed, err := readMSITableList(tableStreams[msiTablesTableName], pool)
	if err != nil {
		return nil, err
	}

	// Cross-check: _Tables and _Columns must describe the same table set.
	listedSet := make(map[string]bool, len(listed))
	for _, name := range listed {
		listedSet[name] = true
	}
	schemaNames := make([]string, 0, len(schemas))
	for name := range schemas {
		schemaNames = append(schemaNames, name)
	}
	sort.Strings(schemaNames)
	for _, name := range schemaNames {
		if !listedSet[name] {
			return nil, fmt.Errorf("msix: table %s has columns in %s but is not listed in %s", name, msiColumnsTableName, msiTablesTableName)
		}
	}

	tables := make(map[string]msiTable, len(listed))
	for _, name := range listed {
		cols, ok := schemas[name]
		if !ok {
			return nil, fmt.Errorf("msix: table %s is listed in %s but has no columns in %s", name, msiTablesTableName, msiColumnsTableName)
		}
		tbl := newMSITableBuilder().WithName(name).WithColumns(cols...).Build()
		// A listed table with no stream is an empty table (zero rows).
		rows, err := decodeMSITableStream(name, cols, tableStreams[name], pool)
		if err != nil {
			return nil, err
		}
		// Resolve binary/object cells (decoded as a present placeholder) back to
		// their side-stream payload bytes before building the rows, so addRow's
		// validate() runs on the final []byte. The side-stream member name is the
		// table's Name primary-key column joined with '.' (Icon.<Name> /
		// Binary.<Name>); for Icon/Binary that key column is vals[0].
		if err := resolveMSIBinaryCells(name, cols, rows, dataStreams); err != nil {
			return nil, err
		}
		for i, vals := range rows {
			row := newMSIRowBuilder().WithColumns(cols...).WithValues(vals...).Build()
			if err := tbl.addRow(row); err != nil {
				return nil, fmt.Errorf("msix: table %s row %d: %w", name, i, err)
			}
		}
		tables[name] = tbl
	}

	fileSources, err := buildMSICabFileSources(tables, dataStreams)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(tables))
	for name := range tables {
		names = append(names, name)
	}
	sort.Strings(names)

	return &msiReadDB{tables: tables, names: names, fileSources: fileSources}, nil
}

// readMSISummaryInfo parses the \x05SummaryInformation property set of the
// MSI at r.
func readMSISummaryInfo(r io.ReaderAt) (msiSummaryInfo, error) {
	reader, err := cfb.NewReader(r)
	if err != nil {
		return msiSummaryInfo{}, fmt.Errorf("msix: opening msi compound file: %w", err)
	}
	st, err := reader.OpenStream(msiSummaryInfoStreamName)
	if err != nil {
		return msiSummaryInfo{}, fmt.Errorf("msix: msi has no SummaryInformation stream: %w", err)
	}
	data, err := io.ReadAll(st.Open())
	if err != nil {
		return msiSummaryInfo{}, fmt.Errorf("msix: reading SummaryInformation stream: %w", err)
	}
	info, err := parseMSISummaryStream(data)
	if err != nil {
		return msiSummaryInfo{}, fmt.Errorf("msix: parsing SummaryInformation stream: %w", err)
	}
	return info, nil
}

// readMSICFBStreams opens the compound file and returns its streams keyed by
// DECODED name, split into table streams (leading U+4840 unit) and data
// streams (pair-packed without the prefix: cabinets, Binary/Icon payloads).
// \x05-prefixed control streams (SummaryInformation, DigitalSignature) belong
// to neither class and are skipped.
func readMSICFBStreams(r io.ReaderAt) (tableStreams map[string][]byte, dataStreams map[string]*cfb.Stream, err error) {
	reader, err := cfb.NewReader(r)
	if err != nil {
		return nil, nil, fmt.Errorf("msix: opening msi compound file: %w", err)
	}
	tableStreams = make(map[string][]byte)
	dataStreams = make(map[string]*cfb.Stream)
	for _, e := range reader.Entries {
		st, ok := e.(*cfb.Stream)
		if !ok {
			continue
		}
		name, isTable := decodeMSIStreamName(st.Name)
		if !isTable && name != "" && name[0] == 5 {
			continue // control stream, read via readMSISummaryInfo et al.
		}
		if isTable {
			// Table streams are small and structural; buffer them eagerly (the
			// schema/row decode needs them whole). Cabinet/side data streams stay
			// lazy: their (potentially huge) payload is read on demand via ReadAt.
			data, err := io.ReadAll(st.Open())
			if err != nil {
				return nil, nil, fmt.Errorf("msix: reading stream %q: %w", name, err)
			}
			tableStreams[name] = data
		} else {
			dataStreams[name] = st
		}
	}
	return tableStreams, dataStreams, nil
}

// readMSIColumnSchemas decodes the _Columns stream with its fixed schema and
// regroups the rows into per-table column lists ordered by column Number
// (validated to run contiguously from 1).
func readMSIColumnSchemas(stream []byte, pool *msiStringPool) (map[string][]msiColumn, error) {
	rows, err := decodeMSITableStream(msiColumnsTableName, createMSIColumnsTable().columns(), stream, pool)
	if err != nil {
		return nil, err
	}

	type numberedColumn struct {
		number int
		col    msiColumn
	}
	byTable := make(map[string][]numberedColumn)
	for i, vals := range rows {
		table, ok := vals[0].(string)
		if !ok {
			return nil, fmt.Errorf("msix: %s row %d has a NULL Table cell", msiColumnsTableName, i)
		}
		number, ok := vals[1].(int16)
		if !ok || number < 1 {
			return nil, fmt.Errorf("msix: %s row %d (table %s) has an invalid Number cell", msiColumnsTableName, i, table)
		}
		name, ok := vals[2].(string)
		if !ok {
			return nil, fmt.Errorf("msix: %s row %d (table %s) has a NULL Name cell", msiColumnsTableName, i, table)
		}
		bits, ok := vals[3].(int16)
		if !ok {
			return nil, fmt.Errorf("msix: %s row %d (%s.%s) has a NULL Type cell", msiColumnsTableName, i, table, name)
		}
		col, err := msiColumnFromTypeBits(name, uint16(bits))
		if err != nil {
			return nil, fmt.Errorf("msix: %s row %d (%s.%s): %w", msiColumnsTableName, i, table, name, err)
		}
		byTable[table] = append(byTable[table], numberedColumn{number: int(number), col: col})
	}

	schemas := make(map[string][]msiColumn, len(byTable))
	for table, ncols := range byTable {
		sort.Slice(ncols, func(a, b int) bool { return ncols[a].number < ncols[b].number })
		cols := make([]msiColumn, len(ncols))
		for i, nc := range ncols {
			if nc.number != i+1 {
				return nil, fmt.Errorf("msix: table %s columns are not numbered contiguously from 1 (column number %d at position %d)", table, nc.number, i+1)
			}
			cols[i] = nc.col
		}
		schemas[table] = cols
	}
	return schemas, nil
}

// readMSITableList decodes the _Tables stream (one string key column) into
// the on-disk order of listed table names.
func readMSITableList(stream []byte, pool *msiStringPool) ([]string, error) {
	rows, err := decodeMSITableStream(msiTablesTableName, createMSITablesTable().columns(), stream, pool)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(rows))
	seen := make(map[string]bool, len(rows))
	for i, vals := range rows {
		name, ok := vals[0].(string)
		if !ok {
			return nil, fmt.Errorf("msix: %s row %d has a NULL Name cell", msiTablesTableName, i)
		}
		if seen[name] {
			return nil, fmt.Errorf("msix: %s lists table %s twice", msiTablesTableName, name)
		}
		seen[name] = true
		names = append(names, name)
	}
	return names, nil
}

// msiColumnFromTypeBits rebuilds a column from the _Columns Type bitfield.
// The fine-grained category (Identifier, Formatted, Guid, ...) is not encoded
// in the bits, so string columns come back as the generic msiColText — a
// stricter category could reject values it cannot re-validate. Binary/object
// columns (STRING bit without the 0x0400 nonbinary bit) decode to the generic
// msiColBinary: their in-table cell is a 2-byte presence flag and the actual
// payload is resolved from the matching side stream (Icon.<Name>/Binary.<Name>)
// by readMSIDatabase.
func msiColumnFromTypeBits(name string, bits uint16) (msiColumn, error) {
	b := newMSIColumnBuilder().WithName(name).WithWidth(int(bits & msiTypeDataSizeMask))
	switch {
	case bits&msiTypeString != 0 && bits&msiTypeNonBinary != 0:
		b = b.WithType(msiColText)
	case bits&msiTypeString != 0:
		// Binary/object column: STRING bit set, NONBINARY clear. Width is 0;
		// the on-disk cell is a 2-byte presence flag.
		b = b.WithType(msiColBinary)
	default:
		switch bits & msiTypeDataSizeMask {
		case 2:
			b = b.WithType(msiColInteger)
		case 4:
			b = b.WithType(msiColDoubleInteger)
		default:
			return nil, fmt.Errorf("integer column with unsupported width %d (type bits 0x%04X)", bits&msiTypeDataSizeMask, bits)
		}
	}
	if bits&msiTypeKey != 0 {
		b = b.AsKey()
	}
	if bits&msiTypeNullable != 0 {
		b = b.AsNullable()
	}
	if bits&msiTypeLocalizable != 0 {
		b = b.AsLocalizable()
	}
	return b.Build(), nil
}

// msiCellWidth returns the exact on-disk byte width of one cell, matching
// writeEncodedMSITableValue: int16/binary 2, int32 4, string ref 2 (3 under
// long pool refs).
func msiCellWidth(col msiColumn, longRefs bool) int {
	switch col.typ() {
	case msiColInteger, msiColBinary:
		// A binary in-table cell is the 2-byte presence flag (identical to
		// int16 and independent of long-ref pools); the payload is a side stream.
		return 2
	case msiColDoubleInteger, msiColDateTime:
		return 4
	default:
		if longRefs {
			return 3
		}
		return 2
	}
}

// decodeMSITableStream is the inverse of serializeRealTableData: it slices a
// COLUMN-MAJOR table stream (all rows' column-1 cells, then column-2, ...)
// into row-major decoded values. A nil/empty stream decodes to zero rows;
// row count = stream length / row byte width, which must divide exactly.
func decodeMSITableStream(tableName string, cols []msiColumn, stream []byte, pool *msiStringPool) ([][]any, error) {
	if len(stream) == 0 {
		return nil, nil
	}
	longRefs := pool.isLongRefs()
	widths := make([]int, len(cols))
	rowWidth := 0
	for i, col := range cols {
		widths[i] = msiCellWidth(col, longRefs)
		rowWidth += widths[i]
	}
	if rowWidth == 0 {
		return nil, fmt.Errorf("msix: table %s has no columns but a %d-byte stream", tableName, len(stream))
	}
	if len(stream)%rowWidth != 0 {
		return nil, fmt.Errorf("msix: table %s stream is %d bytes, not a multiple of its %d-byte row width", tableName, len(stream), rowWidth)
	}
	numRows := len(stream) / rowWidth

	rows := make([][]any, numRows)
	for i := range rows {
		rows[i] = make([]any, len(cols))
	}
	off := 0
	for ci, col := range cols {
		w := widths[ci]
		for ri := 0; ri < numRows; ri++ {
			val, err := decodeMSITableCell(stream[off:off+w], col, pool)
			if err != nil {
				return nil, fmt.Errorf("msix: table %s column %s row %d: %w", tableName, col.name(), ri, err)
			}
			rows[ri][ci] = val
			off += w
		}
	}
	return rows, nil
}

// decodeMSITableCell is the inverse of storedMSICellValue for one cell:
// stored 0 is NULL for every kind; int16 cells undo ^0x8000, int32 cells undo
// ^0x80000000, string cells resolve their 1-based pool ref.
func decodeMSITableCell(cell []byte, col msiColumn, pool *msiStringPool) (any, error) {
	switch col.typ() {
	case msiColInteger:
		raw := binary.LittleEndian.Uint16(cell)
		if raw == 0 {
			return nil, nil
		}
		return int16(raw ^ 0x8000), nil
	case msiColDoubleInteger, msiColDateTime:
		raw := binary.LittleEndian.Uint32(cell)
		if raw == 0 {
			return nil, nil
		}
		return int32(raw ^ 0x80000000), nil
	case msiColBinary:
		// The in-table cell is a 2-byte presence flag (see storedMSICellValue:
		// non-nil []byte -> 1). 0 means NULL (no side stream). A present flag
		// yields a non-nil placeholder that readMSIDatabase replaces with the
		// payload bytes from the matching side stream; we cannot resolve the
		// stream here because the table name and dataStreams are not in scope.
		raw := binary.LittleEndian.Uint16(cell)
		if raw == 0 {
			return nil, nil
		}
		return []byte{}, nil
	default:
		var ref uint32
		if len(cell) == 3 {
			ref = uint32(cell[0]) | uint32(cell[1])<<8 | uint32(cell[2])<<16
		} else {
			ref = uint32(binary.LittleEndian.Uint16(cell))
		}
		if ref == 0 {
			return nil, nil
		}
		// Live pooled strings are never empty (ID 0 is the only null/empty),
		// so "" here means the ref points at a hole or past the pool.
		s := pool.getString(ref)
		if s == "" {
			return nil, fmt.Errorf("string ref %d is not a live string pool entry", ref)
		}
		return s, nil
	}
}

// resolveMSIBinaryCells replaces the present-placeholder ([]byte{}) value of
// every msiColBinary cell with the bytes of its side stream, the inverse of
// serializeMSIStreams' Icon.<Name>/Binary.<Name> emission. NULL binary cells
// (nil, no side stream) are left untouched. A present flag with no matching
// side stream is a hard error (the payload would otherwise be lost silently).
//
// The side-stream member name is "<table>.<Name>" where Name is the table's
// primary-key (first) column value; this matches the writer, which only emits
// side streams for the Icon and Binary tables. Non-binary tables have no
// msiColBinary column, so this is a no-op for them (including the system
// catalog tables _Columns/_Tables, which carry no binary columns).
func resolveMSIBinaryCells(tableName string, cols []msiColumn, rows [][]any, dataStreams map[string]*cfb.Stream) error {
	binIdx := -1
	for i, col := range cols {
		if col.typ() == msiColBinary {
			binIdx = i
			break
		}
	}
	if binIdx < 0 {
		return nil
	}
	for ri, vals := range rows {
		placeholder, ok := vals[binIdx].([]byte)
		if !ok || placeholder == nil {
			// NULL binary cell: no side stream, nothing to resolve.
			continue
		}
		key, ok := vals[0].(string)
		if !ok || key == "" {
			return fmt.Errorf("msix: table %s row %d has a binary cell but a NULL/non-string Name key, cannot resolve its side stream", tableName, ri)
		}
		streamName := tableName + "." + key
		st, ok := dataStreams[streamName]
		if !ok {
			return fmt.Errorf("msix: table %s row %d (Name=%q) has a present binary cell but no %q side stream", tableName, ri, key, streamName)
		}
		payload, err := io.ReadAll(st.Open())
		if err != nil {
			return fmt.Errorf("msix: table %s row %d reading side stream %q: %w", tableName, ri, streamName, err)
		}
		vals[binIdx] = payload
	}
	return nil
}

// parseMSICab unpacks an MSZIP cabinet (one or more independent CFFOLDERs) into
// member-name -> payload bytes. Cab-set spanning (CFHDR_PREV/NEXT) is handled by
// the caller via parseMSICabRaw; this single-cab helper rejects spanning flags.
// Layout walked here ([MS-CAB]; offsets relative to the cab start):
//
//	CFHEADER  0:"MSCF", 16:coffFiles u32, 26:cFolders u16, 28:cFiles u16, 30:flags u16
//	CFFOLDER  36+8*i: coffCabStart u32, cCFData u16, typeCompress u16 (1 = MSZIP)
//	CFFILE   @coffFiles: cbFile u32, uoffFolderStart u32, iFolder u16,
//	          date/time/attribs u16 each, NUL-terminated name
//	CFDATA   @coffCabStart: csum u32, cbData u16, cbUncomp u16, ab[cbData]
//	          where ab = "CK" + one complete deflate stream per frame
func parseMSICab(data []byte) (map[string][]byte, error) {
	const (
		cabFileHdrSize = 16
		cabMSZIP       = 1
	)
	if len(data) < cabHeaderSize+cabFolderSize || !bytes.Equal(data[0:4], []byte("MSCF")) {
		return nil, fmt.Errorf("msix: stream is not an MSCF cabinet")
	}
	coffFiles := int64(binary.LittleEndian.Uint32(data[16:]))
	cFolders := int(binary.LittleEndian.Uint16(data[26:]))
	cFiles := int(binary.LittleEndian.Uint16(data[28:]))
	flags := binary.LittleEndian.Uint16(data[30:])
	if cFolders < 1 {
		return nil, fmt.Errorf("msix: cabinet declares %d folders", cFolders)
	}
	if flags != 0 {
		return nil, fmt.Errorf("msix: cabinet header flags 0x%04X (reserve areas / multi-cab sets) are not supported by parseMSICab", flags)
	}

	// CFFOLDER table.
	type folderHdr struct {
		coffData int64
		cCFData  int
	}
	folders := make([]folderHdr, cFolders)
	for fi := 0; fi < cFolders; fi++ {
		base := int64(cabHeaderSize + cabFolderSize*fi)
		if base+cabFolderSize > int64(len(data)) {
			return nil, fmt.Errorf("msix: cabinet CFFOLDER %d is truncated", fi)
		}
		typeCompress := binary.LittleEndian.Uint16(data[base+6:])
		if typeCompress != cabMSZIP {
			return nil, fmt.Errorf("msix: cabinet folder %d compression type %d; only MSZIP (1) is supported", fi, typeCompress)
		}
		folders[fi] = folderHdr{
			coffData: int64(binary.LittleEndian.Uint32(data[base:])),
			cCFData:  int(binary.LittleEndian.Uint16(data[base+4:])),
		}
	}

	// CFFILE entries.
	type cabFileEntry struct {
		name    string
		size    uint32
		uoff    uint32
		iFolder int
	}
	files := make([]cabFileEntry, 0, cFiles)
	pos := coffFiles
	for i := 0; i < cFiles; i++ {
		if pos < 0 || pos+cabFileHdrSize > int64(len(data)) {
			return nil, fmt.Errorf("msix: cabinet CFFILE %d header is truncated", i)
		}
		cbFile := binary.LittleEndian.Uint32(data[pos:])
		uoff := binary.LittleEndian.Uint32(data[pos+4:])
		iFolder := binary.LittleEndian.Uint16(data[pos+8:])
		if int(iFolder) >= cFolders {
			return nil, fmt.Errorf("msix: cabinet CFFILE %d references folder %d of %d", i, iFolder, cFolders)
		}
		nameEnd := bytes.IndexByte(data[pos+cabFileHdrSize:], 0)
		if nameEnd < 0 {
			return nil, fmt.Errorf("msix: cabinet CFFILE %d name is not NUL-terminated", i)
		}
		name := string(data[pos+cabFileHdrSize : pos+cabFileHdrSize+int64(nameEnd)])
		files = append(files, cabFileEntry{name: name, size: cbFile, uoff: uoff, iFolder: int(iFolder)})
		pos += cabFileHdrSize + int64(nameEnd) + 1
	}

	// Decompress each folder independently.
	folderData := make([][]byte, cFolders)
	for fi, fh := range folders {
		fd, err := inflateMSICabFolder(data, fh.coffData, fh.cCFData)
		if err != nil {
			return nil, fmt.Errorf("msix: cabinet folder %d: %w", fi, err)
		}
		folderData[fi] = fd
	}

	out := make(map[string][]byte, len(files))
	for _, f := range files {
		fd := folderData[f.iFolder]
		end := uint64(f.uoff) + uint64(f.size)
		if end > uint64(len(fd)) {
			return nil, fmt.Errorf("msix: cabinet member %q spans bytes %d-%d but folder %d holds only %d", f.name, f.uoff, end, f.iFolder, len(fd))
		}
		out[f.name] = append([]byte(nil), fd[f.uoff:end]...)
	}
	return out, nil
}

// inflateMSICabFolder decompresses one folder's CFDATA chain (cCFData blocks
// starting at coffData) into its uncompressed byte stream.
func inflateMSICabFolder(data []byte, coffData int64, cCFData int) ([]byte, error) {
	const cabDataHdrSize = 8
	var folder []byte
	pos := coffData
	for i := 0; i < cCFData; i++ {
		if pos < 0 || pos+cabDataHdrSize > int64(len(data)) {
			return nil, fmt.Errorf("CFDATA %d header is truncated", i)
		}
		csum := binary.LittleEndian.Uint32(data[pos:])
		cbData := int64(binary.LittleEndian.Uint16(data[pos+4:]))
		cbUncomp := int(binary.LittleEndian.Uint16(data[pos+6:]))
		if pos+cabDataHdrSize+cbData > int64(len(data)) {
			return nil, fmt.Errorf("CFDATA %d payload is truncated", i)
		}
		ab := data[pos+cabDataHdrSize : pos+cabDataHdrSize+cbData]
		if csum != 0 {
			if got := cabChecksum(data[pos+4:pos+8], cabChecksum(ab, 0)); got != csum {
				return nil, fmt.Errorf("CFDATA %d checksum mismatch: stored 0x%08X, computed 0x%08X", i, csum, got)
			}
		}
		frame, err := msiInflateMSZIPFrame(ab)
		if err != nil {
			return nil, fmt.Errorf("CFDATA %d: %w", i, err)
		}
		if len(frame) != cbUncomp {
			return nil, fmt.Errorf("CFDATA %d inflated to %d bytes, header declares %d", i, len(frame), cbUncomp)
		}
		folder = append(folder, frame...)
		pos += cabDataHdrSize + cbData
	}
	return folder, nil
}

// msiInflateMSZIPFrame inflates one CFDATA ab payload: the 2-byte "CK"
// signature followed by a complete, independent deflate stream (buildMSICAB
// never back-references across frames, so no 32 KiB history window needs to
// be carried between blocks).
func msiInflateMSZIPFrame(ab []byte) ([]byte, error) {
	if len(ab) < 2 || ab[0] != 'C' || ab[1] != 'K' {
		return nil, fmt.Errorf("MSZIP block lacks the CK signature")
	}
	fr := flate.NewReader(bytes.NewReader(ab[2:]))
	defer fr.Close()
	out, err := io.ReadAll(fr)
	if err != nil {
		return nil, fmt.Errorf("inflating MSZIP block: %w", err)
	}
	return out, nil
}

// msiReadDB is the read-only msiDatabase produced by readMSIDatabase.
type msiReadDB struct {
	tables      map[string]msiTable
	names       []string // sorted
	fileSources map[string]FileSource
}

func (d *msiReadDB) GetTable(name string) (msiTable, error) {
	t, ok := d.tables[name]
	if !ok {
		return nil, fmt.Errorf("table %s not found", name)
	}
	return t, nil
}

func (d *msiReadDB) Tables() []string {
	return append([]string(nil), d.names...)
}

func (d *msiReadDB) FileSources() map[string]FileSource {
	out := make(map[string]FileSource, len(d.fileSources))
	for k, v := range d.fileSources {
		out[k] = v
	}
	return out
}

func (d *msiReadDB) validate() error {
	for _, name := range d.names {
		if err := d.tables[name].validate(); err != nil {
			return fmt.Errorf("table %s validation failed: %w", name, err)
		}
	}
	return nil
}
