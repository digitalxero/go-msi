package msi

// reader_cabsource.go
// Streaming FileSource implementations for the reader: a member's payload is
// decoded from its embedded cabinet on demand (one 32 KiB MSZIP frame at a
// time), so reading an existing MSI never materializes a whole decompressed
// folder — let alone the whole payload — in memory. The compressed cabinet
// itself is read through the CFB stream's io.ReaderAt in CFDATA-block slices,
// never wholesale.
//
// The decode reuses cabChecksum and msiInflateMSZIPFrame, so the bytes are
// identical to the buffered parseMSICab/parseMSISpannedSet path.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/abemedia/go-cfb"
)

const cabDataHdrSize = 8

// readAtFull reads exactly len(p) bytes at off, tolerating the io.EOF an
// io.ReaderAt may return alongside a full read at the end of the stream.
func readAtFull(ra io.ReaderAt, p []byte, off int64) error {
	n, err := ra.ReadAt(p, off)
	if n == len(p) {
		return nil
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return err
}

// cabFolderReader streams one MSZIP folder's decompressed bytes, reading and
// inflating one CFDATA block at a time from ra (no whole-folder buffer).
type cabFolderReader struct {
	ra        io.ReaderAt
	pos       int64 // file offset of the next CFDATA block
	remaining int   // CFDATA blocks left
	frame     []byte
	frameOff  int
}

func newCabFolderReader(ra io.ReaderAt, coffData int64, cCFData int) *cabFolderReader {
	return &cabFolderReader{ra: ra, pos: coffData, remaining: cCFData}
}

func (r *cabFolderReader) Read(p []byte) (int, error) {
	for r.frameOff >= len(r.frame) {
		if r.remaining <= 0 {
			return 0, io.EOF
		}
		var hdr [cabDataHdrSize]byte
		if err := readAtFull(r.ra, hdr[:], r.pos); err != nil {
			return 0, fmt.Errorf("CFDATA header: %w", err)
		}
		csum := binary.LittleEndian.Uint32(hdr[0:])
		cbData := int64(binary.LittleEndian.Uint16(hdr[4:]))
		cbUncomp := int(binary.LittleEndian.Uint16(hdr[6:]))
		ab := make([]byte, cbData)
		if err := readAtFull(r.ra, ab, r.pos+cabDataHdrSize); err != nil {
			return 0, fmt.Errorf("CFDATA payload: %w", err)
		}
		if csum != 0 {
			if got := cabChecksum(hdr[4:8], cabChecksum(ab, 0)); got != csum {
				return 0, fmt.Errorf("CFDATA checksum mismatch: stored 0x%08X, computed 0x%08X", csum, got)
			}
		}
		frame, err := msiInflateMSZIPFrame(ab)
		if err != nil {
			return 0, err
		}
		if len(frame) != cbUncomp {
			return 0, fmt.Errorf("CFDATA inflated to %d bytes, header declares %d", len(frame), cbUncomp)
		}
		r.frame = frame
		r.frameOff = 0
		r.pos += cabDataHdrSize + cbData
		r.remaining--
	}
	n := copy(p, r.frame[r.frameOff:])
	r.frameOff += n
	return n, nil
}

// cabMemberSource is a FileSource backed by one member's byte range within a
// single embedded cabinet's MSZIP folder.
type cabMemberSource struct {
	ra       io.ReaderAt
	coffData int64
	cCFData  int
	uoff     uint32
	size     uint32
}

func (c *cabMemberSource) Size() int64 { return int64(c.size) }

func (c *cabMemberSource) Open() (io.ReadCloser, error) {
	fr := newCabFolderReader(c.ra, c.coffData, c.cCFData)
	if c.uoff > 0 {
		if _, err := io.CopyN(io.Discard, fr, int64(c.uoff)); err != nil {
			return nil, err
		}
	}
	return io.NopCloser(io.LimitReader(fr, int64(c.size))), nil
}

// spannedFolderLoc locates one physical cabinet's single folder in a spanned set.
type spannedFolderLoc struct {
	ra       io.ReaderAt
	coffData int64
	cCFData  int
}

// spannedFolderReader streams the concatenation of a spanned set's per-cabinet
// folders (in iCabinet order) as one logical decompressed stream.
type spannedFolderReader struct {
	folders []spannedFolderLoc
	i       int
	cur     *cabFolderReader
}

func (r *spannedFolderReader) Read(p []byte) (int, error) {
	for {
		if r.cur == nil {
			if r.i >= len(r.folders) {
				return 0, io.EOF
			}
			f := r.folders[r.i]
			r.cur = newCabFolderReader(f.ra, f.coffData, f.cCFData)
		}
		n, err := r.cur.Read(p)
		if n > 0 {
			return n, nil
		}
		if err == io.EOF {
			r.cur = nil
			r.i++
			continue
		}
		if err != nil {
			return 0, err
		}
	}
}

// spannedMemberSource is a FileSource for a member whose byte range lies in the
// global concatenation of a spanned set's folders.
type spannedMemberSource struct {
	folders    []spannedFolderLoc
	globalUoff int64
	size       uint32
}

func (s *spannedMemberSource) Size() int64 { return int64(s.size) }

func (s *spannedMemberSource) Open() (io.ReadCloser, error) {
	fr := &spannedFolderReader{folders: s.folders}
	if s.globalUoff > 0 {
		if _, err := io.CopyN(io.Discard, fr, s.globalUoff); err != nil {
			return nil, err
		}
	}
	return io.NopCloser(io.LimitReader(fr, int64(s.size))), nil
}

// folderUncompressedSize sums a folder's CFDATA cbUncomp fields by reading only
// the 8-byte block headers (no decompression) — used to place spanned members.
func folderUncompressedSize(ra io.ReaderAt, coffData int64, cCFData int) (int64, error) {
	var total int64
	pos := coffData
	for i := 0; i < cCFData; i++ {
		var hdr [cabDataHdrSize]byte
		if err := readAtFull(ra, hdr[:], pos); err != nil {
			return 0, fmt.Errorf("CFDATA %d header: %w", i, err)
		}
		cbData := int64(binary.LittleEndian.Uint16(hdr[4:]))
		total += int64(binary.LittleEndian.Uint16(hdr[6:]))
		pos += cabDataHdrSize + cbData
	}
	return total, nil
}

// cabFolderLoc / cabFileLoc are the parsed locators for a single cabinet.
type cabFolderLoc struct {
	coffData int64
	cCFData  int
}

type cabFileLoc struct {
	name  string
	size  uint32
	uoff  uint32
	ifold uint16
}

// parseCabHeaderRA parses a single (non-spanned) cabinet's CFHEADER/CFFOLDER/
// CFFILE structure via ra, reading only the header region (not the CFDATA).
func parseCabHeaderRA(ra io.ReaderAt, size int64) ([]cabFolderLoc, []cabFileLoc, error) {
	const (
		cabFileHdrSize = 16
		cabMSZIP       = 1
	)
	if size < cabHeaderSize+cabFolderSize {
		return nil, nil, fmt.Errorf("msix: stream is not an MSCF cabinet")
	}
	var hdr [cabHeaderSize]byte
	if err := readAtFull(ra, hdr[:], 0); err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(hdr[0:4], []byte("MSCF")) {
		return nil, nil, fmt.Errorf("msix: stream is not an MSCF cabinet")
	}
	coffFiles := int64(binary.LittleEndian.Uint32(hdr[16:]))
	cFolders := int(binary.LittleEndian.Uint16(hdr[26:]))
	cFiles := int(binary.LittleEndian.Uint16(hdr[28:]))
	flags := binary.LittleEndian.Uint16(hdr[30:])
	if cFolders < 1 {
		return nil, nil, fmt.Errorf("msix: cabinet declares %d folders", cFolders)
	}
	if flags != 0 {
		return nil, nil, fmt.Errorf("msix: cabinet header flags 0x%04X (reserve areas / multi-cab sets) are not supported", flags)
	}

	folders := make([]cabFolderLoc, cFolders)
	minCoff := size
	for fi := 0; fi < cFolders; fi++ {
		base := int64(cabHeaderSize + cabFolderSize*fi)
		var fb [cabFolderSize]byte
		if err := readAtFull(ra, fb[:], base); err != nil {
			return nil, nil, fmt.Errorf("msix: cabinet CFFOLDER %d is truncated", fi)
		}
		if typeCompress := binary.LittleEndian.Uint16(fb[6:]); typeCompress != cabMSZIP {
			return nil, nil, fmt.Errorf("msix: cabinet folder %d compression type %d; only MSZIP (1) is supported", fi, typeCompress)
		}
		coffData := int64(binary.LittleEndian.Uint32(fb[0:]))
		folders[fi] = cabFolderLoc{coffData: coffData, cCFData: int(binary.LittleEndian.Uint16(fb[4:]))}
		if coffData < minCoff {
			minCoff = coffData
		}
	}

	if coffFiles < cabHeaderSize || coffFiles > minCoff || minCoff > size {
		return nil, nil, fmt.Errorf("msix: cabinet CFFILE region [%d,%d) is out of range", coffFiles, minCoff)
	}
	region := make([]byte, minCoff-coffFiles)
	if err := readAtFull(ra, region, coffFiles); err != nil {
		return nil, nil, err
	}
	files := make([]cabFileLoc, 0, cFiles)
	pos := 0
	for i := 0; i < cFiles; i++ {
		if pos+cabFileHdrSize > len(region) {
			return nil, nil, fmt.Errorf("msix: cabinet CFFILE %d header is truncated", i)
		}
		cbFile := binary.LittleEndian.Uint32(region[pos:])
		uoff := binary.LittleEndian.Uint32(region[pos+4:])
		iFolder := binary.LittleEndian.Uint16(region[pos+8:])
		if int(iFolder) >= cFolders {
			return nil, nil, fmt.Errorf("msix: cabinet CFFILE %d references folder %d of %d", i, iFolder, cFolders)
		}
		nameEnd := bytes.IndexByte(region[pos+cabFileHdrSize:], 0)
		if nameEnd < 0 {
			return nil, nil, fmt.Errorf("msix: cabinet CFFILE %d name is not NUL-terminated", i)
		}
		name := string(region[pos+cabFileHdrSize : pos+cabFileHdrSize+nameEnd])
		files = append(files, cabFileLoc{name: name, size: cbFile, uoff: uoff, ifold: iFolder})
		pos += cabFileHdrSize + nameEnd + 1
	}
	return folders, files, nil
}

// spannedCabHeader is one physical spanned cabinet's parsed header.
type spannedCabHeader struct {
	coffData int64
	cCFData  int
	files    []cabFileLoc
	nextName string
	hasNext  bool
}

// parseSpannedCabHeaderRA parses one physical cabinet of a spanned set (single
// folder, PREV/NEXT chain strings) via ra, reading only the header region.
func parseSpannedCabHeaderRA(ra io.ReaderAt, size int64) (spannedCabHeader, error) {
	const cabFileHdrSize = 16
	var h spannedCabHeader
	if size < cabHeaderSize+cabFolderSize {
		return h, fmt.Errorf("msix: stream is not an MSCF cabinet")
	}
	var hdr [cabHeaderSize]byte
	if err := readAtFull(ra, hdr[:], 0); err != nil {
		return h, err
	}
	if !bytes.Equal(hdr[0:4], []byte("MSCF")) {
		return h, fmt.Errorf("msix: stream is not an MSCF cabinet")
	}
	coffFiles := int64(binary.LittleEndian.Uint32(hdr[16:]))
	cFiles := int(binary.LittleEndian.Uint16(hdr[28:]))
	flags := binary.LittleEndian.Uint16(hdr[30:])
	if coffFiles < cabHeaderSize || coffFiles > size {
		return h, fmt.Errorf("msix: spanned cabinet coffFiles %d out of range", coffFiles)
	}

	// Region [cabHeaderSize, coffFiles): PREV/NEXT strings then the CFFOLDER.
	strRegion := make([]byte, coffFiles-cabHeaderSize)
	if err := readAtFull(ra, strRegion, cabHeaderSize); err != nil {
		return h, err
	}
	hdrExtra := int64(0)
	if flags&cabFlagPrevCabinet != 0 {
		adv, err := skipTwoCStrings(strRegion, hdrExtra)
		if err != nil {
			return h, fmt.Errorf("msix: spanned cabinet prev strings: %w", err)
		}
		hdrExtra += adv
	}
	if flags&cabFlagNextCabinet != 0 {
		nameEnd := bytes.IndexByte(strRegion[hdrExtra:], 0)
		if nameEnd < 0 {
			return h, fmt.Errorf("msix: spanned cabinet next name unterminated")
		}
		h.nextName = string(strRegion[hdrExtra : hdrExtra+int64(nameEnd)])
		h.hasNext = true
		adv, err := skipTwoCStrings(strRegion, hdrExtra)
		if err != nil {
			return h, fmt.Errorf("msix: spanned cabinet next strings: %w", err)
		}
		hdrExtra += adv
	}

	if hdrExtra+cabFolderSize > int64(len(strRegion)) {
		return h, fmt.Errorf("msix: spanned cabinet CFFOLDER truncated")
	}
	h.coffData = int64(binary.LittleEndian.Uint32(strRegion[hdrExtra:]))
	h.cCFData = int(binary.LittleEndian.Uint16(strRegion[hdrExtra+4:]))

	if h.coffData < coffFiles || h.coffData > size {
		return h, fmt.Errorf("msix: spanned cabinet coffData %d out of range", h.coffData)
	}
	filesRegion := make([]byte, h.coffData-coffFiles)
	if err := readAtFull(ra, filesRegion, coffFiles); err != nil {
		return h, err
	}
	pos := 0
	h.files = make([]cabFileLoc, 0, cFiles)
	for i := 0; i < cFiles; i++ {
		if pos+cabFileHdrSize > len(filesRegion) {
			return h, fmt.Errorf("msix: spanned cabinet CFFILE %d truncated", i)
		}
		cbFile := binary.LittleEndian.Uint32(filesRegion[pos:])
		uoff := binary.LittleEndian.Uint32(filesRegion[pos+4:])
		ifold := binary.LittleEndian.Uint16(filesRegion[pos+8:])
		nameEnd := bytes.IndexByte(filesRegion[pos+cabFileHdrSize:], 0)
		if nameEnd < 0 {
			return h, fmt.Errorf("msix: spanned cabinet CFFILE %d name unterminated", i)
		}
		name := string(filesRegion[pos+cabFileHdrSize : pos+cabFileHdrSize+nameEnd])
		h.files = append(h.files, cabFileLoc{name: name, size: cbFile, uoff: uoff, ifold: ifold})
		pos += cabFileHdrSize + nameEnd + 1
	}
	return h, nil
}

// buildSingleCabSources adds a FileSource per member of a single embedded
// cabinet to out, each decoding its byte range from cab on demand.
func buildSingleCabSources(cab *cfb.Stream, out map[string]FileSource) error {
	folders, files, err := parseCabHeaderRA(cab, cab.Size)
	if err != nil {
		return err
	}
	for _, f := range files {
		fl := folders[f.ifold]
		out[f.name] = &cabMemberSource{ra: cab, coffData: fl.coffData, cCFData: fl.cCFData, uoff: f.uoff, size: f.size}
	}
	return nil
}

// buildSpannedCabSources walks a spanned set via the NEXT chain and adds a
// streaming FileSource per member to out, placing each by its first-appearance
// global offset (computed from per-folder uncompressed sizes, no decompression).
func buildSpannedCabSources(firstName string, first *cfb.Stream, dataStreams map[string]*cfb.Stream, out map[string]FileSource) error {
	type phys struct {
		st  *cfb.Stream
		hdr spannedCabHeader
	}
	var cabs []phys
	var folderLocs []spannedFolderLoc
	seen := map[string]bool{}
	curName, cur := firstName, first
	for {
		if seen[curName] {
			return fmt.Errorf("msix: spanned cabinet chain cycles at %q", curName)
		}
		seen[curName] = true
		hdr, err := parseSpannedCabHeaderRA(cur, cur.Size)
		if err != nil {
			return fmt.Errorf("msix: spanned cabinet %q: %w", curName, err)
		}
		cabs = append(cabs, phys{st: cur, hdr: hdr})
		folderLocs = append(folderLocs, spannedFolderLoc{ra: cur, coffData: hdr.coffData, cCFData: hdr.cCFData})
		if !hdr.hasNext {
			break
		}
		nd, ok := dataStreams[hdr.nextName]
		if !ok {
			return fmt.Errorf("msix: spanned cabinet %q references missing continuation stream %q", firstName, hdr.nextName)
		}
		curName, cur = hdr.nextName, nd
	}

	type info struct {
		size       uint32
		globalUoff int64
		known      bool
	}
	infos := map[string]*info{}
	var order []string
	var streamLen int64
	for ci := range cabs {
		cabStart := streamLen
		for _, f := range cabs[ci].hdr.files {
			in := infos[f.name]
			if in == nil {
				in = &info{size: f.size}
				infos[f.name] = in
				order = append(order, f.name)
			}
			if !in.known && f.ifold != cabIFoldContinuedFromPrev && f.ifold != cabIFoldContinuedPrevAndNext {
				in.globalUoff = cabStart + int64(f.uoff)
				in.known = true
			}
		}
		sz, err := folderUncompressedSize(cabs[ci].st, cabs[ci].hdr.coffData, cabs[ci].hdr.cCFData)
		if err != nil {
			return fmt.Errorf("msix: spanned cabinet %d folder size: %w", ci, err)
		}
		streamLen += sz
	}
	for _, name := range order {
		in := infos[name]
		if !in.known {
			return fmt.Errorf("msix: spanned cabinet member %q never starts in the set", name)
		}
		out[name] = &spannedMemberSource{folders: folderLocs, globalUoff: in.globalUoff, size: in.size}
	}
	return nil
}

// buildMSICabFileSources resolves every embedded cabinet referenced from the
// Media table into streaming FileSources keyed by cab member name (== File
// primary key), without decompressing any payload.
func buildMSICabFileSources(tables map[string]msiTable, dataStreams map[string]*cfb.Stream) (map[string]FileSource, error) {
	fileSources := make(map[string]FileSource)
	media, ok := tables[msiMediaTableName]
	if !ok {
		return fileSources, nil
	}
	cabinetIdx := -1
	for i, col := range media.columns() {
		if col.name() == "Cabinet" {
			cabinetIdx = i
			break
		}
	}
	if cabinetIdx < 0 {
		return fileSources, nil
	}
	for _, row := range media.rows() {
		vals := row.values()
		if cabinetIdx >= len(vals) {
			continue
		}
		cabinet, _ := vals[cabinetIdx].(string)
		if !strings.HasPrefix(cabinet, "#") {
			continue // NULL or external cabinet file: nothing embedded
		}
		streamName := cabinet[1:]
		cabStream, ok := dataStreams[streamName]
		if !ok {
			return nil, fmt.Errorf("msix: Media cabinet %q references missing data stream %q", cabinet, streamName)
		}
		spanned := false
		if cabStream.Size >= 32 {
			var fb [2]byte
			if err := readAtFull(cabStream, fb[:], 30); err == nil {
				spanned = binary.LittleEndian.Uint16(fb[:])&cabFlagNextCabinet != 0
			}
		}
		if spanned {
			if err := buildSpannedCabSources(streamName, cabStream, dataStreams, fileSources); err != nil {
				return nil, err
			}
		} else if err := buildSingleCabSources(cabStream, fileSources); err != nil {
			return nil, fmt.Errorf("msix: cabinet stream %q: %w", streamName, err)
		}
	}
	return fileSources, nil
}
