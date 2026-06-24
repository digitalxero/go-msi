package msi

// msi_cfbwriter.go
// Serializes a finalized msiDatabase into the streams of a real Windows
// Installer CFB and writes them with go-cfb.
//
// Layout rules (verified against Wine dlls/msi, msitools and rust-msi):
//   - CFB v3 (512-byte sectors): what msi.dll itself produces and every tool
//     in the wild reads.
//   - Root storage CLSID {000C1084-0000-0000-C000-000000000046} marks the
//     file as an MSI database (msitools refuses files without it).
//   - ALL table streams — including _StringPool/_StringData/_Tables/_Columns/
//     _Validation — are stored under pair-packed names with the U+4840 table
//     prefix. Embedded cabinet streams use pair-packed names WITHOUT the
//     prefix (Wine opens them via encode_streamname(FALSE, name)).
//     \x05SummaryInformation is stored literally.
//   - Empty tables get no stream (a missing stream reads back as an empty
//     table); they stay listed in _Tables/_Columns.
//   - String interning order is deterministic (sorted table names, row
//     insertion order, column order) and finishes before any table stream is
//     serialized so the long-refs decision is final.

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/abemedia/go-cfb"
)

// msiRootCLSID is the MSI database root-storage CLSID
// {000C1084-0000-0000-C000-000000000046} in its on-disk serialization
// (Data1 LE, Data2 LE, Data3 LE, Data4 raw).
var msiRootCLSID = [16]byte{0x84, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}

// msiSummaryStreamName is the literal (never pair-packed) name of the
// \x05SummaryInformation property-set stream, shared by MSI and MST files.
const msiSummaryStreamName = "\x05SummaryInformation"

// msiTransformCLSID is the root-storage CLSID of an MSI transform (.mst):
// {000C1082-0000-0000-C000-000000000046} (vs {000C1084-…} for a database).
var msiTransformCLSID = [16]byte{0x82, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}

// msiPatchCLSID is the root-storage CLSID of an MSI patch (.msp):
// {000C1086-0000-0000-C000-000000000046}.
var msiPatchCLSID = [16]byte{0x86, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}

// msiCabinetStreamName is the logical (decoded) name of the single embedded
// cabinet stream; the Media table references it as "#" + this name.
const msiCabinetStreamName = "cab1.cab"

// msiStream is one named CFB stream ready to be written. name is the final
// (already encoded) stream name. Exactly one of data / writeTo is set: small
// streams (tables, string pools, summary, Icon/Binary side streams) carry their
// bytes in data; large streamed streams (embedded cabinets) carry writeTo, which
// emits the content into any sink (the CFB StreamWriter when writing, the hash
// when computing the Authenticode imprint) without ever buffering it whole.
type msiStream struct {
	name    string
	data    []byte
	writeTo func(io.Writer) error
}

// cabBuildOptions carries the P7 cabinet controls into the serializer: how to
// split a cabinet into CFFOLDERs, and where to write external cabinets.
type cabBuildOptions struct {
	folderThreshold int64
	externalWriter  func(name string) (io.WriteCloser, error)
	spanCap         int64 // >0: split an oversized embedded cab into a spanned set
}

// serializeMSIStreams converts the database plus summary metadata into the
// complete, ordered list of CFB streams for the MSI. The same list can be
// written any number of times (deterministic; required for two-pass signing).
func serializeMSIStreams(db msiDatabase, summary msiSummaryInfo, opts cabBuildOptions) ([]msiStream, error) {
	var streams []msiStream

	// 1. \x05SummaryInformation (literal name, never encoded).
	summaryData, err := buildMSISummaryStream(summary)
	if err != nil {
		return nil, fmt.Errorf("msi: summary stream: %w", err)
	}
	streams = append(streams, msiStream{name: msiSummaryStreamName, data: summaryData})

	tableNames := db.Tables() // sorted

	// 2. Intern every string from every table, in deterministic order, so the
	// pool's long-refs decision is final before any table stream serializes.
	pool := newMSIStringPool(0)
	for _, tname := range tableNames {
		tbl, err := db.GetTable(tname)
		if err != nil {
			return nil, err
		}
		pool.addString(tname)
		for _, col := range tbl.columns() {
			pool.addString(col.name())
		}
		for _, r := range tbl.rows() {
			for _, v := range r.values() {
				if s, ok := v.(string); ok {
					pool.addString(s)
				}
			}
		}
	}

	// 3. One stream per non-empty table, under encoded (table-prefixed) names.
	for _, tname := range tableNames {
		tbl, _ := db.GetTable(tname)
		if len(tbl.rows()) == 0 {
			continue
		}
		if err := validateMSIStreamName(true, tname); err != nil {
			return nil, fmt.Errorf("msi: table %s: %w", tname, err)
		}
		data, err := serializeRealTableData(tbl, pool)
		if err != nil {
			return nil, fmt.Errorf("msi: serialize table %s: %w", tname, err)
		}
		streams = append(streams, msiStream{name: encodeMSIStreamName(true, tname), data: data})
	}

	// P3: for Icon and Binary tables (which have msiColBinary "Data" column),
	// the cell in table is presence flag (1/0); the actual payload lives in
	// a side CFB stream named without table prefix, e.g. "Icon.MyIcon" or
	// "Binary.MyBin" (pair-packed, no 0x4840).
	for _, tname := range []string{"Icon", "Binary"} {
		tbl, err := db.GetTable(tname)
		if err != nil {
			continue
		}
		for _, r := range tbl.rows() {
			vals := r.values()
			if len(vals) < 2 {
				continue
			}
			name, ok1 := vals[0].(string)
			data, ok2 := vals[1].([]byte)
			if !ok1 || !ok2 || len(data) == 0 {
				continue
			}
			streamName := encodeMSIStreamName(false, tname+"."+name)
			streams = append(streams, msiStream{name: streamName, data: append([]byte(nil), data...)})
		}
	}

	// 4. _StringPool/_StringData (encoded with the table prefix, like every
	// other table stream).
	poolBytes, err := pool.poolBytes()
	if err != nil {
		return nil, fmt.Errorf("msi: string pool: %w", err)
	}
	streams = append(streams,
		msiStream{name: encodeMSIStreamName(true, "_StringPool"), data: poolBytes},
		msiStream{name: encodeMSIStreamName(true, "_StringData"), data: pool.dataBytes()},
	)

	// 5. Cabinets: one per Media row (members are the File-table primary keys in
	// File.Sequence order; msiexec matches cab member names against the File
	// column and requires sequence order). Embedded cabinets ("#name") become
	// CFB streams; external cabinets are written via opts.externalWriter.
	cabStreams, err := buildMSICabStreams(db, opts)
	if err != nil {
		return nil, err
	}
	streams = append(streams, cabStreams...)

	return streams, nil
}

// buildMSICabStreams builds every cabinet referenced by the Media table and
// returns the embedded ones as CFB streams (external cabinets are written via
// opts.externalWriter). Falls back to a single "cab1.cab" when there is no Media
// table (back-compat). The single-embedded-cab path is byte-identical to the
// historical writer.
func buildMSICabStreams(db msiDatabase, opts cabBuildOptions) ([]msiStream, error) {
	mediaTbl, err := db.GetTable(msiMediaTableName)
	if err != nil {
		// No Media table: legacy single-cab fallback.
		members, mErr := msiCabMembers(db)
		if mErr != nil {
			return nil, mErr
		}
		if len(members) == 0 {
			return nil, nil
		}
		return embedCab(msiCabinetStreamName, members, opts)
	}

	// Gather files (seq, key, data) once.
	type fileMember struct {
		seq    int16
		member msiCabMember
	}
	var files []fileMember
	if fileTbl, fErr := db.GetTable(msiFileTableName); fErr == nil {
		sources := db.FileSources()
		for _, r := range fileTbl.rows() {
			vals := r.values()
			if len(vals) < 8 {
				return nil, fmt.Errorf("msi: malformed File row (%d cells)", len(vals))
			}
			fileID, _ := vals[0].(string)
			seq, _ := vals[7].(int16)
			src, ok := sources[fileID]
			if !ok {
				return nil, fmt.Errorf("msi: no staged content for File %q", fileID)
			}
			files = append(files, fileMember{seq: seq, member: msiCabMember{name: fileID, src: src}})
		}
		sort.SliceStable(files, func(i, j int) bool { return files[i].seq < files[j].seq })
	}

	// Media rows sorted by LastSequence to form contiguous (prev, last] ranges.
	type mediaRow struct {
		lastSeq int16
		cabinet string
	}
	var media []mediaRow
	for _, r := range mediaTbl.rows() {
		vals := r.values()
		if len(vals) < 4 {
			continue
		}
		last, _ := vals[1].(int16)
		cab, _ := vals[3].(string)
		media = append(media, mediaRow{lastSeq: last, cabinet: cab})
	}
	sort.SliceStable(media, func(i, j int) bool { return media[i].lastSeq < media[j].lastSeq })

	var out []msiStream
	prevLast := int16(0)
	for _, m := range media {
		if m.cabinet == "" {
			prevLast = m.lastSeq
			continue
		}
		var members []msiCabMember
		for _, f := range files {
			if f.seq > prevLast && f.seq <= m.lastSeq {
				members = append(members, f.member)
			}
		}
		prevLast = m.lastSeq
		if len(members) == 0 {
			continue
		}

		external := !strings.HasPrefix(m.cabinet, "#")
		logical := m.cabinet
		if !external {
			logical = m.cabinet[1:]
		}

		if external {
			if opts.externalWriter == nil {
				return nil, fmt.Errorf("msi: Media cabinet %q is external but no external cab writer was set (WithExternalCabs)", m.cabinet)
			}
			if wErr := writeExternalCab(opts.externalWriter, logical, members, opts); wErr != nil {
				return nil, wErr
			}
			continue
		}

		streams, eErr := embedCab(logical, members, opts)
		if eErr != nil {
			return nil, eErr
		}
		out = append(out, streams...)
	}
	return out, nil
}

// embedCab builds a cabinet from members and returns it as one embedded CFB
// stream — or, when spanning is enabled and the payload exceeds the cap, as a
// chain of embedded streams (logicalName, logicalName~1, …) linked by
// CFHDR_PREV/NEXT. The Media row references only the first stream; the reader
// follows the chain.
func embedCab(logicalName string, members []msiCabMember, opts cabBuildOptions) ([]msiStream, error) {
	var total int64
	for _, m := range members {
		total += m.src.Size()
	}
	if opts.spanCap > 0 && total > opts.spanCap {
		names := spannedStreamNames(logicalName, members, opts.spanCap)
		set, err := buildMSICabSpanned(members, opts.spanCap, names, 0x4D53) // 'MS'
		if err != nil {
			return nil, err
		}
		out := make([]msiStream, 0, len(set))
		for _, sc := range set {
			if err := validateMSIStreamName(false, sc.name); err != nil {
				return nil, fmt.Errorf("msi: spanned cabinet stream %q: %w", sc.name, err)
			}
			out = append(out, msiStream{name: encodeMSIStreamName(false, sc.name), writeTo: sc.writeTo})
		}
		return out, nil
	}

	if err := validateMSIStreamName(false, logicalName); err != nil {
		return nil, fmt.Errorf("msi: cabinet stream %q: %w", logicalName, err)
	}
	folders := cabFoldersFromMembers(members, opts)
	return []msiStream{{
		name: encodeMSIStreamName(false, logicalName),
		writeTo: func(w io.Writer) error {
			return streamMSICABFolders(w, folders, newFileCabStage)
		},
	}}, nil
}

// spannedStreamNames derives the chain of physical cabinet stream names for a
// spanned set. The first equals the Media cabinet name; continuations append ~N.
func spannedStreamNames(base string, members []msiCabMember, cap int64) []string {
	var total int64
	for _, m := range members {
		total += m.src.Size()
	}
	n := int((total + cap - 1) / cap)
	if n < 1 {
		n = 1
	}
	n += 2 // headroom: block-rounding can add a cab
	names := make([]string, n)
	names[0] = base
	for i := 1; i < n; i++ {
		names[i] = fmt.Sprintf("%s_%d", base, i) // '_' is in the MSI stream-name alphabet
	}
	return names
}

// cabFoldersFromMembers groups members into CFFOLDERs by the folder threshold
// (one folder when the threshold is 0 — byte-identical to buildMSICAB).
func cabFoldersFromMembers(members []msiCabMember, opts cabBuildOptions) [][]msiCabMember {
	if opts.folderThreshold <= 0 {
		return [][]msiCabMember{members}
	}
	return splitMembersIntoFolders(members, opts.folderThreshold)
}

// splitMembersIntoFolders groups members into folders, starting a new folder
// once the current folder's accumulated uncompressed size would exceed the
// threshold (each folder keeps at least one member).
func splitMembersIntoFolders(members []msiCabMember, threshold int64) [][]msiCabMember {
	var folders [][]msiCabMember
	var cur []msiCabMember
	var curSize int64
	for _, m := range members {
		if len(cur) > 0 && curSize+m.src.Size() > threshold {
			folders = append(folders, cur)
			cur = nil
			curSize = 0
		}
		cur = append(cur, m)
		curSize += m.src.Size()
	}
	if len(cur) > 0 {
		folders = append(folders, cur)
	}
	return folders
}

// writeExternalCab streams a cabinet straight into the external writer and
// closes it. The external sink need not be seekable: streamMSICABFolders
// resolves cbCabinet via its own per-folder temp before the first byte is
// written, so the cabinet is never buffered whole in memory.
func writeExternalCab(write func(name string) (io.WriteCloser, error), name string, members []msiCabMember, opts cabBuildOptions) error {
	w, err := write(name)
	if err != nil {
		return fmt.Errorf("msi: opening external cabinet %q: %w", name, err)
	}
	if err := streamMSICABFolders(w, cabFoldersFromMembers(members, opts), newFileCabStage); err != nil {
		w.Close()
		return fmt.Errorf("msi: writing external cabinet %q: %w", name, err)
	}
	return w.Close()
}

// msiCabMembers extracts (File key, payload) pairs from the File table in
// ascending Sequence order.
func msiCabMembers(db msiDatabase) ([]msiCabMember, error) {
	fileTbl, err := db.GetTable(msiFileTableName)
	if err != nil {
		return nil, nil // no File table at all -> no cab
	}
	sources := db.FileSources()

	type seqMember struct {
		seq    int16
		member msiCabMember
	}
	var entries []seqMember
	for _, r := range fileTbl.rows() {
		vals := r.values()
		if len(vals) < 8 {
			return nil, fmt.Errorf("msi: malformed File row (%d cells)", len(vals))
		}
		fileID, _ := vals[0].(string)
		seq, _ := vals[7].(int16)
		src, ok := sources[fileID]
		if !ok {
			return nil, fmt.Errorf("msi: no staged content for File %q", fileID)
		}
		entries = append(entries, seqMember{seq: seq, member: msiCabMember{name: fileID, src: src}})
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].seq < entries[j].seq })

	members := make([]msiCabMember, len(entries))
	for i, e := range entries {
		members[i] = e.member
	}
	return members, nil
}

// writeMSICFB writes the streams into a v3 compound file with the MSI root
// CLSID. The writer needs an io.WriteSeeker (FAT/header patching); BuildMSI
// passes a temp file.
// msiSubStorage is a child storage written inside the MSI root storage — used
// for embedded language transforms (sub-storage named after the decimal LCID,
// CLSID = msiTransformCLSID, holding that transform's stream set).
type msiSubStorage struct {
	name    string
	clsid   [16]byte
	streams []msiStream
}

func writeMSICFB(streams []msiStream, w io.WriteSeeker) error {
	return writeMSICFBWithSubStorages(streams, nil, msiRootCLSID, w)
}

// writeMSICFBWithCLSID writes the streams into a CFBv3 file whose root storage
// carries the given CLSID. MSI databases use msiRootCLSID ({000C1084-…});
// standalone transforms (.mst) use msiTransformCLSID ({000C1082-…}).
func writeMSICFBWithCLSID(streams []msiStream, clsid [16]byte, w io.WriteSeeker) error {
	return writeMSICFBWithSubStorages(streams, nil, clsid, w)
}

// writeMSICFBWithSubStorages writes the root streams plus any child storages
// (embedded language transforms) into a CFBv3 file. The default (nil subs) path
// is byte-identical to the historical single-storage writer.
func writeMSICFBWithSubStorages(streams []msiStream, subs []msiSubStorage, clsid [16]byte, w io.WriteSeeker) error {
	cfbw := cfb.NewWriterV3(w)
	cfbw.CLSID = clsid

	if err := writeMSIStreamsInto(cfbw.StorageWriter, streams); err != nil {
		return err
	}

	for _, sub := range subs {
		sw, err := cfbw.CreateStorage(sub.name)
		if err != nil {
			return fmt.Errorf("msi: create sub-storage %q: %w", sub.name, err)
		}
		sw.CLSID = sub.clsid
		if err := writeMSIStreamsInto(sw, sub.streams); err != nil {
			return fmt.Errorf("msi: sub-storage %q: %w", sub.name, err)
		}
	}

	if err := cfbw.Close(); err != nil {
		return fmt.Errorf("msi: close cfb: %w", err)
	}
	return nil
}

// realizeStreamedCabStreams materializes every streamed stream (writeTo != nil)
// to its own temp file once, replacing writeTo with one that replays the temp.
// It is used before signing so each cabinet is compressed once and then re-read
// for both the imprint hash and the CFB write, rather than recompressed per
// pass. The returned cleanup removes the temps and must run after the CFB write.
func realizeStreamedCabStreams(streams []msiStream) ([]msiStream, func(), error) {
	var temps []string
	cleanup := func() {
		for _, n := range temps {
			os.Remove(n)
		}
	}
	out := make([]msiStream, len(streams))
	copy(out, streams)
	for i := range out {
		if out[i].writeTo == nil {
			continue
		}
		f, err := os.CreateTemp("", "go-msix-cabstream-*")
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		temps = append(temps, f.Name())
		if err := out[i].writeTo(f); err != nil {
			f.Close()
			cleanup()
			return nil, func() {}, err
		}
		if err := f.Close(); err != nil {
			cleanup()
			return nil, func() {}, err
		}
		name := f.Name()
		out[i].writeTo = func(w io.Writer) error {
			rf, err := os.Open(name)
			if err != nil {
				return err
			}
			defer rf.Close()
			_, err = io.Copy(w, rf)
			return err
		}
	}
	return out, cleanup, nil
}

// writeMSIStreamsInto creates and fills each stream under the given storage.
// Streamed streams (writeTo != nil, e.g. embedded cabinets) are emitted directly
// into the CFB StreamWriter — which flushes per sector — so the payload is never
// buffered whole; small streams write their in-memory bytes as before.
func writeMSIStreamsInto(sw *cfb.StorageWriter, streams []msiStream) error {
	for _, s := range streams {
		st, err := sw.CreateStream(s.name)
		if err != nil {
			return fmt.Errorf("msi: create stream %q: %w", s.name, err)
		}
		if s.writeTo != nil {
			if err := s.writeTo(st); err != nil {
				st.Close()
				return fmt.Errorf("msi: write stream %q: %w", s.name, err)
			}
		} else if _, err := st.Write(s.data); err != nil {
			st.Close()
			return fmt.Errorf("msi: write stream %q: %w", s.name, err)
		}
		if err := st.Close(); err != nil {
			return fmt.Errorf("msi: close stream %q: %w", s.name, err)
		}
	}
	return nil
}
