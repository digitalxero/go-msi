package msi

// msi_cab_span.go — P7.4 MS-CAB set spanning. A single logical MSZIP folder is
// split across N physical cabinets so each cabinet stays within a size cap; a
// file whose data crosses a boundary is marked with the ifold CONTINUED values
// and the cabinets carry the CFHDR_PREV/NEXT chain (shared setID, ascending
// iCabinet, szCabinetPrev/Next).
//
// HONESTY NOTE: cabextract/msiextract cannot reassemble a spanned set without
// orchestrating the whole chain, so this is NOT end-to-end CI-verifiable on
// Linux. It is validated structurally: our own reader (parseMSISpannedSet)
// round-trips it, and tests assert the PREV/NEXT flags, setID, iCabinet, and the
// ifold CONTINUED values. Windows install is a manual check. Keeping files
// within a single cabinet (the default) is recommended.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// spannedCab is one physical cabinet in a set. The write side sets writeTo (the
// cabinet is streamed into any sink on demand, never fully buffered); the read
// side (and tests that want the bytes) set data. bytes() yields whichever is set.
type spannedCab struct {
	name    string                // logical cab name (e.g. "cab1.cab")
	data    []byte                // read-side / materialized bytes
	writeTo func(io.Writer) error // write-side streaming emitter
}

// bytes materializes the physical cabinet (draining the streaming emitter when
// the write side produced one). Used by the reader's reassembler and by tests.
func (sc spannedCab) bytes() ([]byte, error) {
	if sc.writeTo != nil {
		var b bytes.Buffer
		if err := sc.writeTo(&b); err != nil {
			return nil, err
		}
		return b.Bytes(), nil
	}
	return sc.data, nil
}

// cabMemRange is one member's global uncompressed byte range in the logical folder.
type cabMemRange struct {
	m          msiCabMember
	start, end int64
}

// cabSpanFile is one CFFILE entry within a physical spanned cabinet.
type cabSpanFile struct {
	name    string
	cbFile  uint32
	uoff    uint32
	iFolder uint16
}

// buildMSICabSpanned splits the concatenation of members into one logical MSZIP
// folder whose CFDATA blocks are distributed across physical cabinets, each
// holding at most maxUncompressedPerCab bytes (rounded to whole 32 KiB blocks).
// names must provide one logical name per resulting cabinet; if too few are
// given the function errors. setID ties the set together.
func buildMSICabSpanned(members []msiCabMember, maxUncompressedPerCab int64, names []string, setID uint16) ([]spannedCab, error) {
	if len(members) == 0 {
		return nil, fmt.Errorf("msi cab span: no members")
	}
	if maxUncompressedPerCab < msiCabBlockSize {
		return nil, fmt.Errorf("msi cab span: per-cab cap %d is below one block (%d)", maxUncompressedPerCab, msiCabBlockSize)
	}
	blocksPerCab := int(maxUncompressedPerCab / msiCabBlockSize)
	if blocksPerCab < 1 {
		blocksPerCab = 1
	}

	// Global member byte ranges and total uncompressed size.
	ranges := make([]cabMemRange, len(members))
	var total int64
	for i, m := range members {
		if m.name == "" {
			return nil, fmt.Errorf("msi cab span: empty member name")
		}
		sz := m.src.Size()
		ranges[i] = cabMemRange{m: m, start: total, end: total + sz}
		total += sz
	}

	// Number of 32 KiB blocks for the whole folder, then number of physical cabs.
	totalBlocks := int((total + msiCabBlockSize - 1) / msiCabBlockSize)
	if totalBlocks == 0 {
		totalBlocks = 1
	}
	numCabs := (totalBlocks + blocksPerCab - 1) / blocksPerCab
	if numCabs < 1 {
		numCabs = 1
	}
	if numCabs > len(names) {
		return nil, fmt.Errorf("msi cab span: need %d cabinet names but %d provided", numCabs, len(names))
	}

	out := make([]spannedCab, 0, numCabs)
	for ci := 0; ci < numCabs; ci++ {
		blockLo := ci * blocksPerCab
		blockHi := blockLo + blocksPerCab
		if blockHi > totalBlocks {
			blockHi = totalBlocks
		}
		cabStart := int64(blockLo) * msiCabBlockSize
		cabEnd := int64(blockHi) * msiCabBlockSize
		if cabEnd > total {
			cabEnd = total
		}

		// Members overlapping [cabStart, cabEnd) → CFFILE entries with CONTINUED
		// markers and folder-local offsets.
		var files []cabSpanFile
		for _, r := range ranges {
			if r.start >= cabEnd || r.end <= cabStart {
				continue
			}
			startsBefore := r.start < cabStart
			endsAfter := r.end > cabEnd
			var ifold uint16
			switch {
			case startsBefore && endsAfter:
				ifold = cabIFoldContinuedPrevAndNext
			case startsBefore:
				ifold = cabIFoldContinuedFromPrev
			case endsAfter:
				ifold = cabIFoldContinuedToNext
			default:
				ifold = 0 // wholly within this cab's single folder
			}
			uoff := int64(0)
			if r.start > cabStart {
				uoff = r.start - cabStart
			}
			files = append(files, cabSpanFile{name: r.m.name, cbFile: uint32(r.m.src.Size()), uoff: uint32(uoff), iFolder: ifold})
		}

		// Header strings + flags.
		var flags uint16
		var szPrev, szNext string
		if ci > 0 {
			flags |= cabFlagPrevCabinet
			szPrev = names[ci-1]
		}
		if ci < numCabs-1 {
			flags |= cabFlagNextCabinet
			szNext = names[ci+1]
		}

		// Capture this physical cabinet's plan; the bytes are produced lazily and
		// streamed into whatever sink consumes the stream (CFB writer / hasher).
		filesC, flagsC, iCab, prevC, nextC := files, flags, uint16(ci), szPrev, szNext
		csC, ceC := cabStart, cabEnd
		out = append(out, spannedCab{
			name: names[ci],
			writeTo: func(w io.Writer) error {
				return streamSpannedCab(w, filesC, ranges, csC, ceC, flagsC, setID, iCab, prevC, nextC, newFileCabStage)
			},
		})
	}
	return out, nil
}

// spannedRangeReader yields the global uncompressed byte range [lo, hi) of the
// logical folder by opening only the member sources that overlap it, one at a
// time — the streaming analogue of buildSpannedDataRegion's read closure.
type spannedRangeReader struct {
	ranges []cabMemRange
	pos    int64
	hi     int64
	i      int
	cur    io.ReadCloser
}

func newSpannedRangeReader(ranges []cabMemRange, lo, hi int64) *spannedRangeReader {
	return &spannedRangeReader{ranges: ranges, pos: lo, hi: hi}
}

func (r *spannedRangeReader) Read(p []byte) (int, error) {
	for {
		if r.pos >= r.hi {
			return 0, io.EOF
		}
		if r.cur == nil {
			for r.i < len(r.ranges) && r.ranges[r.i].end <= r.pos {
				r.i++
			}
			if r.i >= len(r.ranges) || r.pos < r.ranges[r.i].start {
				return 0, io.EOF
			}
			rc, err := r.ranges[r.i].m.src.Open()
			if err != nil {
				return 0, fmt.Errorf("msi cab span: opening member %s: %w", r.ranges[r.i].m.name, err)
			}
			if skip := r.pos - r.ranges[r.i].start; skip > 0 {
				if _, err := io.CopyN(io.Discard, rc, skip); err != nil {
					rc.Close()
					return 0, err
				}
			}
			r.cur = rc
		}
		rng := r.ranges[r.i]
		lim := int64(len(p))
		if rem := rng.end - r.pos; lim > rem {
			lim = rem
		}
		if rem := r.hi - r.pos; lim > rem {
			lim = rem
		}
		n, err := r.cur.Read(p[:lim])
		if n > 0 {
			r.pos += int64(n)
			if r.pos >= rng.end {
				r.cur.Close()
				r.cur = nil
				r.i++
			}
			return n, nil
		}
		if err == io.EOF {
			r.cur.Close()
			r.cur = nil
			r.i++
			continue
		}
		if err != nil {
			r.cur.Close()
			r.cur = nil
			return 0, err
		}
	}
}

func (r *spannedRangeReader) Close() error {
	if r.cur != nil {
		err := r.cur.Close()
		r.cur = nil
		return err
	}
	return nil
}

// streamSpannedDataRegion frames the global byte range [lo, hi) (block-aligned at
// lo) into CFDATA records written to w, reading from the member ranges via a
// range-limited streaming reader (no materialization). Returns the region byte
// length and block count. Byte-identical to buildSpannedDataRegion.
func streamSpannedDataRegion(w io.Writer, ranges []cabMemRange, lo, hi int64) (int64, int, error) {
	src := newSpannedRangeReader(ranges, lo, hi)
	defer src.Close()

	frame := make([]byte, msiCabBlockSize)
	var regionLen int64
	blocks := 0
	for pos := lo; pos < hi; pos += msiCabBlockSize {
		n := int(msiCabBlockSize)
		if pos+int64(n) > hi {
			n = int(hi - pos)
		}
		if _, err := io.ReadFull(src, frame[:n]); err != nil {
			return 0, 0, fmt.Errorf("msi cab span: reading member data: %w", err)
		}
		ab, err := msiMSZIPBlock(frame[:n])
		if err != nil {
			return 0, 0, err
		}
		var hdr [4]byte
		binary.LittleEndian.PutUint16(hdr[0:], uint16(len(ab)))
		binary.LittleEndian.PutUint16(hdr[2:], uint16(n))
		csum := cabChecksum(hdr[:], cabChecksum(ab, 0))
		var rec [8]byte
		binary.LittleEndian.PutUint32(rec[0:], csum)
		copy(rec[4:], hdr[:])
		if _, err := w.Write(rec[:]); err != nil {
			return 0, 0, err
		}
		if _, err := w.Write(ab); err != nil {
			return 0, 0, err
		}
		regionLen += int64(8 + len(ab))
		blocks++
	}
	return regionLen, blocks, nil
}

// streamSpannedCab writes one physical cabinet (single folder) into dst, staging
// the compressed CFDATA region via newStage so cbCabinet is known before the
// CFHEADER is emitted. Byte-identical to the historical assembleSpannedCab.
func streamSpannedCab(dst io.Writer, files []cabSpanFile, ranges []cabMemRange, cabStart, cabEnd int64, flags, setID, iCabinet uint16, szPrev, szNext string, newStage func() (cabStage, error)) error {
	// Reserve-area is absent; PREV/NEXT strings (if any) follow the fixed header.
	var prevBytes, nextBytes []byte
	if flags&cabFlagPrevCabinet != 0 {
		prevBytes = append([]byte(szPrev), 0, 0) // szCabinetPrev\0 szDiskPrev\0
	}
	if flags&cabFlagNextCabinet != 0 {
		nextBytes = append([]byte(szNext), 0, 0) // szCabinetNext\0 szDiskNext\0
	}
	hdrExtra := len(prevBytes) + len(nextBytes)

	var filesSection uint32
	for _, f := range files {
		filesSection += cabPerFileHdr + uint32(len(f.name)) + 1
	}
	coffFiles := uint32(cabHeaderSize + hdrExtra + cabFolderSize)
	coffData := coffFiles + filesSection

	stage, err := newStage()
	if err != nil {
		return err
	}
	defer stage.cleanup()
	regionLen, blocks, err := streamSpannedDataRegion(stage, ranges, cabStart, cabEnd)
	if err != nil {
		return err
	}

	cbCabinet := uint64(coffData) + uint64(regionLen)
	if cbCabinet > 0x7FFFFFFF {
		return fmt.Errorf("msi cab span: physical cabinet size %d exceeds the format limit", cbCabinet)
	}

	var buf bytes.Buffer
	buf.WriteString("MSCF")
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	binary.Write(&buf, binary.LittleEndian, uint32(cbCabinet))
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	binary.Write(&buf, binary.LittleEndian, coffFiles)
	binary.Write(&buf, binary.LittleEndian, uint32(0))
	buf.WriteByte(3)
	buf.WriteByte(1)
	binary.Write(&buf, binary.LittleEndian, uint16(1)) // cFolders (one per physical cab)
	binary.Write(&buf, binary.LittleEndian, uint16(len(files)))
	binary.Write(&buf, binary.LittleEndian, flags)
	binary.Write(&buf, binary.LittleEndian, setID)
	binary.Write(&buf, binary.LittleEndian, iCabinet)
	buf.Write(prevBytes)
	buf.Write(nextBytes)

	// CFFOLDER
	binary.Write(&buf, binary.LittleEndian, coffData)
	binary.Write(&buf, binary.LittleEndian, uint16(blocks))
	binary.Write(&buf, binary.LittleEndian, uint16(cabCompMSZIP))

	// CFFILE entries
	for _, f := range files {
		binary.Write(&buf, binary.LittleEndian, f.cbFile)
		binary.Write(&buf, binary.LittleEndian, f.uoff)
		binary.Write(&buf, binary.LittleEndian, f.iFolder)
		binary.Write(&buf, binary.LittleEndian, uint16(cabDosDate))
		binary.Write(&buf, binary.LittleEndian, uint16(cabDosTime))
		binary.Write(&buf, binary.LittleEndian, uint16(cabAttrArchive))
		buf.WriteString(f.name)
		buf.WriteByte(0)
	}

	if _, err := dst.Write(buf.Bytes()); err != nil {
		return err
	}

	r, err := stage.reader()
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, r); err != nil {
		return err
	}
	return nil
}

// parseMSISpannedSet reassembles a spanned cabinet set (ordered by iCabinet)
// into member-name -> payload. Each physical cab has exactly one folder; the
// folders concatenate (in iCabinet order) into the logical stream, and members
// are sliced by their first-appearance global offset + cbFile.
func parseMSISpannedSet(cabs []spannedCab) (map[string][]byte, error) {
	if len(cabs) == 0 {
		return nil, fmt.Errorf("msi cab span: empty set")
	}

	type fileInfo struct {
		size       uint32
		globalUoff int64
		known      bool
	}
	infos := map[string]*fileInfo{}
	order := []string{}

	var stream []byte
	for ci, sc := range cabs {
		data, err := sc.bytes()
		if err != nil {
			return nil, fmt.Errorf("msi cab span: cab %d bytes: %w", ci, err)
		}
		if len(data) < cabHeaderSize+cabFolderSize || !bytes.Equal(data[0:4], []byte("MSCF")) {
			return nil, fmt.Errorf("msi cab span: cab %d is not MSCF", ci)
		}
		coffFiles := int64(binary.LittleEndian.Uint32(data[16:]))
		cFiles := int(binary.LittleEndian.Uint16(data[28:]))
		flags := binary.LittleEndian.Uint16(data[30:])

		// Skip the PREV/NEXT header strings to reach the CFFOLDER.
		hdrExtra := int64(0)
		strpos := int64(cabHeaderSize)
		if flags&cabFlagPrevCabinet != 0 {
			adv, err := skipTwoCStrings(data, strpos)
			if err != nil {
				return nil, fmt.Errorf("msi cab span: cab %d prev strings: %w", ci, err)
			}
			hdrExtra += adv
			strpos += adv
		}
		if flags&cabFlagNextCabinet != 0 {
			adv, err := skipTwoCStrings(data, strpos)
			if err != nil {
				return nil, fmt.Errorf("msi cab span: cab %d next strings: %w", ci, err)
			}
			hdrExtra += adv
		}

		folderBase := int64(cabHeaderSize) + hdrExtra
		coffData := int64(binary.LittleEndian.Uint32(data[folderBase:]))
		cCFData := int(binary.LittleEndian.Uint16(data[folderBase+4:]))

		cabStart := int64(len(stream))
		folderData, err := inflateMSICabFolder(data, coffData, cCFData)
		if err != nil {
			return nil, fmt.Errorf("msi cab span: cab %d folder: %w", ci, err)
		}

		// CFFILE entries.
		pos := coffFiles
		for i := 0; i < cFiles; i++ {
			cbFile := binary.LittleEndian.Uint32(data[pos:])
			uoff := binary.LittleEndian.Uint32(data[pos+4:])
			ifold := binary.LittleEndian.Uint16(data[pos+8:])
			nameEnd := bytes.IndexByte(data[pos+16:], 0)
			if nameEnd < 0 {
				return nil, fmt.Errorf("msi cab span: cab %d CFFILE %d name unterminated", ci, i)
			}
			name := string(data[pos+16 : pos+16+int64(nameEnd)])
			pos += 16 + int64(nameEnd) + 1

			fi := infos[name]
			if fi == nil {
				fi = &fileInfo{size: cbFile}
				infos[name] = fi
				order = append(order, name)
			}
			// First appearance with a real start (not CONTINUED_FROM_PREV) sets
			// the global offset.
			if !fi.known && ifold != cabIFoldContinuedFromPrev && ifold != cabIFoldContinuedPrevAndNext {
				fi.globalUoff = cabStart + int64(uoff)
				fi.known = true
			}
		}

		stream = append(stream, folderData...)
	}

	out := make(map[string][]byte, len(order))
	for _, name := range order {
		fi := infos[name]
		if !fi.known {
			return nil, fmt.Errorf("msi cab span: member %q never starts in the set", name)
		}
		end := fi.globalUoff + int64(fi.size)
		if end > int64(len(stream)) {
			return nil, fmt.Errorf("msi cab span: member %q range %d-%d exceeds stream %d", name, fi.globalUoff, end, len(stream))
		}
		out[name] = append([]byte(nil), stream[fi.globalUoff:end]...)
	}
	return out, nil
}

// skipTwoCStrings returns the byte length of two consecutive NUL-terminated
// strings starting at pos.
func skipTwoCStrings(data []byte, pos int64) (int64, error) {
	adv := int64(0)
	for n := 0; n < 2; n++ {
		end := bytes.IndexByte(data[pos+adv:], 0)
		if end < 0 {
			return 0, fmt.Errorf("unterminated string")
		}
		adv += int64(end) + 1
	}
	return adv, nil
}
