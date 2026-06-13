package msi

// msi_cab.go
// MS-CAB writer for the cabinet embedded in an MSI. Single folder, MSZIP
// compression, spec-exact CFDATA checksums.
//
// Format references (verified against both):
//   - Microsoft Cabinet Format: https://learn.microsoft.com/en-us/previous-versions/bb267310(v=vs.85)
//   - libmspack (cab.h, cabd.c, mszipd.c) for the checksum algorithm and the
//     MSZIP block constraints.
//
// MSI binding rules (learn.microsoft.com .../including-a-cabinet-file-in-an-installation):
// cab member names must EXACTLY equal the File table primary keys
// (case-sensitive) and members must be stored in File.Sequence order — the
// caller provides members already ordered by sequence.

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
)

type msiCabMember struct {
	name string // File table primary key (identifier; never a path)
	data []byte
}

const (
	msiCabBlockSize = 0x8000 // MSZIP frame: exactly 32768 uncompressed bytes except the last block
	// A conforming MSZIP block may exceed the uncompressed size by at most
	// 12 bytes including the 'CK' signature (libmspack cab.h). A stored-mode
	// deflate fallback always fits: 2 ('CK') + 5 (stored hdr) + 32768 = 32775.
	msiCabMaxBlockData = msiCabBlockSize + 12
	msiCabMaxFileSize  = 0x7FFF8000 // [MS-CAB] §2.5 cbFile limit
)

// cabChecksum is the MS-CAB checksum: XOR of little-endian 32-bit words with
// the 0-3 tail bytes packed first-byte-highest ([a,b,c] -> a<<16|b<<8|c).
// There is NO rotation. The CFDATA csum covers cbData+cbUncomp+abData: compute
// checksum(ab, 0) first, then fold in the 4 header bytes with that as seed
// (XOR makes the order irrelevant).
func cabChecksum(p []byte, seed uint32) uint32 {
	cs := seed
	n := len(p) &^ 3
	for i := 0; i < n; i += 4 {
		cs ^= binary.LittleEndian.Uint32(p[i:])
	}
	var tail uint32
	switch len(p) & 3 {
	case 3:
		tail = uint32(p[n])<<16 | uint32(p[n+1])<<8 | uint32(p[n+2])
	case 2:
		tail = uint32(p[n])<<8 | uint32(p[n+1])
	case 1:
		tail = uint32(p[n])
	}
	return cs ^ tail
}

const (
	cabHeaderSize  = 36
	cabFolderSize  = 8
	cabPerFileHdr  = 16
	cabCompMSZIP   = 1
	cabDosDate     = 0x0021 // 1980-01-01 (valid month/day; fixed for reproducibility)
	cabDosTime     = 0
	cabAttrArchive = 0x20
)

// CFHEADER flags and the CFFILE iFolder CONTINUED markers (MS-CAB), used by the
// multi-cab spanning builder (P7.4).
const (
	cabFlagPrevCabinet uint16 = 0x0001
	cabFlagNextCabinet uint16 = 0x0002

	cabIFoldContinuedFromPrev    uint16 = 0xFFFD
	cabIFoldContinuedToNext      uint16 = 0xFFFE
	cabIFoldContinuedPrevAndNext uint16 = 0xFFFF
)

// buildMSICAB builds a single-folder MSZIP cabinet from members already ordered
// by File.Sequence (the common case). Byte-identical to the historical writer.
func buildMSICAB(members []msiCabMember) ([]byte, error) {
	if len(members) == 0 {
		return nil, fmt.Errorf("msi cab: no members (caller must skip cab creation entirely)")
	}
	return buildMSICABFolders([][]msiCabMember{members})
}

// buildMSICABFolders builds one MSZIP cabinet containing N independent CFFOLDERs
// (each its own compressed stream). With a single folder it is byte-identical to
// buildMSICAB. Returns an error (not a truncated cab) on any structural overflow.
func buildMSICABFolders(folders [][]msiCabMember) ([]byte, error) {
	if len(folders) == 0 {
		return nil, fmt.Errorf("msi cab: no folders")
	}
	if len(folders) > 0xFFFF {
		return nil, fmt.Errorf("msi cab: %d folders exceeds the 65535 per-cabinet limit", len(folders))
	}

	totalFiles := 0
	for _, f := range folders {
		totalFiles += len(f)
	}
	if totalFiles == 0 {
		return nil, fmt.Errorf("msi cab: no members (caller must skip cab creation entirely)")
	}
	if totalFiles > 0xFFFF {
		return nil, fmt.Errorf("msi cab: %d members exceeds the 65535 per-cabinet limit", totalFiles)
	}

	type folderData struct {
		region  []byte
		blocks  int
		members []msiCabMember
	}
	fds := make([]folderData, len(folders))
	var filesSection uint32
	for fi, mem := range folders {
		if len(mem) == 0 {
			return nil, fmt.Errorf("msi cab: folder %d has no members", fi)
		}
		var totalData uint64
		for _, m := range mem {
			if m.name == "" {
				return nil, fmt.Errorf("msi cab: empty member name")
			}
			if uint64(len(m.data)) > msiCabMaxFileSize {
				return nil, fmt.Errorf("msi cab: member %s is %d bytes, exceeding the 0x7FFF8000 cbFile limit", m.name, len(m.data))
			}
			totalData += uint64(len(m.data))
			filesSection += cabPerFileHdr + uint32(len(m.name)) + 1
		}
		numBlocks := (totalData + msiCabBlockSize - 1) / msiCabBlockSize
		if numBlocks > 0xFFFF {
			return nil, fmt.Errorf("msi cab: folder %d needs %d CFDATA blocks, exceeding the 65535 limit", fi, numBlocks)
		}
		region, blocks, err := buildMSICabDataRegion(mem, totalData)
		if err != nil {
			return nil, err
		}
		fds[fi] = folderData{region: region, blocks: blocks, members: mem}
	}

	coffFiles := uint32(cabHeaderSize + cabFolderSize*len(folders))
	dataStart := coffFiles + filesSection
	var totalRegion uint64
	for _, fd := range fds {
		totalRegion += uint64(len(fd.region))
	}
	cbCabinet := uint64(dataStart) + totalRegion
	if cbCabinet > 0x7FFFFFFF {
		return nil, fmt.Errorf("msi cab: total cabinet size %d exceeds the format limit", cbCabinet)
	}

	buf := bytes.NewBuffer(make([]byte, 0, cbCabinet))

	// CFHEADER
	buf.WriteString("MSCF")
	binary.Write(buf, binary.LittleEndian, uint32(0)) // reserved1
	binary.Write(buf, binary.LittleEndian, uint32(cbCabinet))
	binary.Write(buf, binary.LittleEndian, uint32(0)) // reserved2
	binary.Write(buf, binary.LittleEndian, coffFiles)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // reserved3
	buf.WriteByte(3)                                  // versionMinor
	buf.WriteByte(1)                                  // versionMajor
	binary.Write(buf, binary.LittleEndian, uint16(len(folders)))
	binary.Write(buf, binary.LittleEndian, uint16(totalFiles))
	binary.Write(buf, binary.LittleEndian, uint16(0)) // flags
	binary.Write(buf, binary.LittleEndian, uint16(1)) // setID (constant; single-cab set)
	binary.Write(buf, binary.LittleEndian, uint16(0)) // iCabinet

	// CFFOLDER per folder (coffCabStart accumulates over prior folders' regions).
	off := dataStart
	for _, fd := range fds {
		binary.Write(buf, binary.LittleEndian, off)
		binary.Write(buf, binary.LittleEndian, uint16(fd.blocks))
		binary.Write(buf, binary.LittleEndian, uint16(cabCompMSZIP))
		off += uint32(len(fd.region))
	}

	// CFFILE entries, grouped by folder; uoffFolderStart is cumulative within the
	// owning folder's uncompressed stream.
	for fi, fd := range fds {
		var uoff uint32
		for _, m := range fd.members {
			binary.Write(buf, binary.LittleEndian, uint32(len(m.data))) // cbFile
			binary.Write(buf, binary.LittleEndian, uoff)                // uoffFolderStart
			binary.Write(buf, binary.LittleEndian, uint16(fi))          // iFolder
			binary.Write(buf, binary.LittleEndian, uint16(cabDosDate))
			binary.Write(buf, binary.LittleEndian, uint16(cabDosTime))
			binary.Write(buf, binary.LittleEndian, uint16(cabAttrArchive))
			buf.WriteString(m.name)
			buf.WriteByte(0)
			uoff += uint32(len(m.data))
		}
	}

	for _, fd := range fds {
		buf.Write(fd.region)
	}
	return buf.Bytes(), nil
}

// buildMSICabDataRegion produces the concatenated CFDATA records for one
// MSZIP folder, chunking the logical concatenation of member payloads into
// 32 KiB frames without materializing the full concatenation.
func buildMSICabDataRegion(members []msiCabMember, totalData uint64) ([]byte, int, error) {
	var out bytes.Buffer
	blocks := 0

	mi := 0 // member index
	mo := 0 // intra-member offset
	var consumed uint64
	frame := make([]byte, 0, msiCabBlockSize)

	for consumed < totalData {
		// Fill one frame from the member cursor.
		frame = frame[:0]
		for len(frame) < msiCabBlockSize && mi < len(members) {
			d := members[mi].data
			avail := len(d) - mo
			if avail <= 0 {
				mi++
				mo = 0
				continue
			}
			take := msiCabBlockSize - len(frame)
			if take > avail {
				take = avail
			}
			frame = append(frame, d[mo:mo+take]...)
			mo += take
			if mo >= len(d) {
				mi++
				mo = 0
			}
		}
		if len(frame) == 0 {
			break
		}
		consumed += uint64(len(frame))

		ab, err := msiMSZIPBlock(frame)
		if err != nil {
			return nil, 0, err
		}

		var hdr [4]byte
		binary.LittleEndian.PutUint16(hdr[0:], uint16(len(ab)))    // cbData
		binary.LittleEndian.PutUint16(hdr[2:], uint16(len(frame))) // cbUncomp
		csum := cabChecksum(hdr[:], cabChecksum(ab, 0))

		binary.Write(&out, binary.LittleEndian, csum)
		out.Write(hdr[:])
		out.Write(ab)
		blocks++
	}

	return out.Bytes(), blocks, nil
}

// msiMSZIPBlock compresses one frame as an MSZIP block: 'CK' + one complete
// deflate stream. Each block is an independent deflate stream (decoders carry
// the 32 KiB history window across blocks, but an encoder that never
// back-references across blocks is universally decodable).
//
// The deflate payload is passed through msiSanitizeMSZIPStream: Go's flate
// can emit single-code distance tables that strict cab decoders (libmspack,
// likely native FDI) reject; those frames are re-encoded as fixed-Huffman
// blocks. Falls back to stored deflate (inherently table-free) when either
// form would exceed the +12 byte MSZIP growth guarantee.
func msiMSZIPBlock(frame []byte) ([]byte, error) {
	compress := func(level int) ([]byte, error) {
		var zbuf bytes.Buffer
		zw, err := flate.NewWriter(&zbuf, level)
		if err != nil {
			return nil, err
		}
		if _, err := zw.Write(frame); err != nil {
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		return zbuf.Bytes(), nil
	}

	payload, err := compress(flate.DefaultCompression)
	if err != nil {
		return nil, fmt.Errorf("msi cab: mszip compress: %w", err)
	}
	payload, err = msiSanitizeMSZIPStream(payload)
	if err != nil {
		return nil, fmt.Errorf("msi cab: mszip sanitize: %w", err)
	}
	if len(payload)+2 > msiCabMaxBlockData {
		// Incompressible (or pathological post-sanitize) frame: stored
		// deflate always fits in 32775 bytes and carries no Huffman tables.
		if payload, err = compress(flate.NoCompression); err != nil {
			return nil, fmt.Errorf("msi cab: mszip stored fallback: %w", err)
		}
		if len(payload)+2 > msiCabMaxBlockData {
			return nil, fmt.Errorf("msi cab: internal error: stored block is %d bytes", len(payload)+2)
		}
	}
	return append([]byte("CK"), payload...), nil
}
