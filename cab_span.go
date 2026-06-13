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
)

// spannedCab is one physical cabinet in a set.
type spannedCab struct {
	name string // logical cab name (e.g. "cab1.cab")
	data []byte
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
		ranges[i] = cabMemRange{m: m, start: total, end: total + int64(len(m.data))}
		total += int64(len(m.data))
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
			files = append(files, cabSpanFile{name: r.m.name, cbFile: uint32(len(r.m.data)), uoff: uint32(uoff), iFolder: ifold})
		}

		// CFDATA region for this cab: blocks [blockLo, blockHi) of the global
		// concatenation. Build by feeding the relevant byte range through the
		// same framing as buildMSICabDataRegion (block-aligned, so no mid-block
		// split).
		region, blocks, err := buildSpannedDataRegion(ranges, cabStart, cabEnd)
		if err != nil {
			return nil, err
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

		cab, err := assembleSpannedCab(files, region, blocks, flags, setID, uint16(ci), szPrev, szNext)
		if err != nil {
			return nil, err
		}
		out = append(out, spannedCab{name: names[ci], data: cab})
	}
	return out, nil
}

// buildSpannedDataRegion frames the global byte range [lo, hi) (block-aligned at
// lo) into CFDATA records, reading from the member ranges without materializing
// the whole concatenation.
func buildSpannedDataRegion(ranges []cabMemRange, lo, hi int64) ([]byte, int, error) {
	read := func(at int64, n int) []byte {
		buf := make([]byte, 0, n)
		for _, r := range ranges {
			if at >= r.end {
				continue
			}
			if at < r.start {
				break
			}
			off := at - r.start
			avail := int64(len(r.m.data)) - off
			take := int64(n) - int64(len(buf))
			if take > avail {
				take = avail
			}
			buf = append(buf, r.m.data[off:off+take]...)
			at += take
			if len(buf) >= n {
				break
			}
		}
		return buf
	}

	var out bytes.Buffer
	blocks := 0
	for pos := lo; pos < hi; pos += msiCabBlockSize {
		n := int(msiCabBlockSize)
		if pos+int64(n) > hi {
			n = int(hi - pos)
		}
		frame := read(pos, n)
		ab, err := msiMSZIPBlock(frame)
		if err != nil {
			return nil, 0, err
		}
		var hdr [4]byte
		binary.LittleEndian.PutUint16(hdr[0:], uint16(len(ab)))
		binary.LittleEndian.PutUint16(hdr[2:], uint16(len(frame)))
		csum := cabChecksum(hdr[:], cabChecksum(ab, 0))
		binary.Write(&out, binary.LittleEndian, csum)
		out.Write(hdr[:])
		out.Write(ab)
		blocks++
	}
	return out.Bytes(), blocks, nil
}

// assembleSpannedCab writes one physical cabinet (single folder) with the given
// CFFILE entries, CFDATA region, header flags and PREV/NEXT names.
func assembleSpannedCab(files []cabSpanFile, region []byte, blocks int, flags, setID, iCabinet uint16, szPrev, szNext string) ([]byte, error) {
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
	cbCabinet := uint64(coffData) + uint64(len(region))
	if cbCabinet > 0x7FFFFFFF {
		return nil, fmt.Errorf("msi cab span: physical cabinet size %d exceeds the format limit", cbCabinet)
	}

	buf := bytes.NewBuffer(make([]byte, 0, cbCabinet))
	buf.WriteString("MSCF")
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(cbCabinet))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, coffFiles)
	binary.Write(buf, binary.LittleEndian, uint32(0))
	buf.WriteByte(3)
	buf.WriteByte(1)
	binary.Write(buf, binary.LittleEndian, uint16(1)) // cFolders (one per physical cab)
	binary.Write(buf, binary.LittleEndian, uint16(len(files)))
	binary.Write(buf, binary.LittleEndian, flags)
	binary.Write(buf, binary.LittleEndian, setID)
	binary.Write(buf, binary.LittleEndian, iCabinet)
	buf.Write(prevBytes)
	buf.Write(nextBytes)

	// CFFOLDER
	binary.Write(buf, binary.LittleEndian, coffData)
	binary.Write(buf, binary.LittleEndian, uint16(blocks))
	binary.Write(buf, binary.LittleEndian, uint16(cabCompMSZIP))

	// CFFILE entries
	for _, f := range files {
		binary.Write(buf, binary.LittleEndian, f.cbFile)
		binary.Write(buf, binary.LittleEndian, f.uoff)
		binary.Write(buf, binary.LittleEndian, f.iFolder)
		binary.Write(buf, binary.LittleEndian, uint16(cabDosDate))
		binary.Write(buf, binary.LittleEndian, uint16(cabDosTime))
		binary.Write(buf, binary.LittleEndian, uint16(cabAttrArchive))
		buf.WriteString(f.name)
		buf.WriteByte(0)
	}

	buf.Write(region)
	return buf.Bytes(), nil
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
		data := sc.data
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

// getSpanNextName extracts szCabinetNext from a spanned cabinet header (after
// the fixed header and any szCabinetPrev/szDiskPrev strings), reporting whether
// the NEXT flag is set.
func getSpanNextName(data []byte) (string, bool) {
	if len(data) < cabHeaderSize {
		return "", false
	}
	flags := binary.LittleEndian.Uint16(data[30:])
	if flags&cabFlagNextCabinet == 0 {
		return "", false
	}
	pos := int64(cabHeaderSize)
	if flags&cabFlagPrevCabinet != 0 {
		adv, err := skipTwoCStrings(data, pos)
		if err != nil {
			return "", false
		}
		pos += adv
	}
	end := bytes.IndexByte(data[pos:], 0)
	if end < 0 {
		return "", false
	}
	return string(data[pos : pos+int64(end)]), true
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
