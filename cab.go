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
	"io"
	"os"
)

type msiCabMember struct {
	name string     // File table primary key (identifier; never a path)
	src  FileSource // re-openable payload; opened once per cabinet build
}

// memberSeqReader yields the logical concatenation of the members' payloads,
// opening each source exactly when first needed and closing it at EOF. Only one
// member source is open at a time, so the cabinet is framed without ever holding
// a whole payload in memory.
type memberSeqReader struct {
	members []msiCabMember
	i       int
	cur     io.ReadCloser
}

func (r *memberSeqReader) Read(p []byte) (int, error) {
	for {
		if r.cur == nil {
			if r.i >= len(r.members) {
				return 0, io.EOF
			}
			c, err := r.members[r.i].src.Open()
			if err != nil {
				return 0, fmt.Errorf("msi cab: opening member %s: %w", r.members[r.i].name, err)
			}
			r.cur = c
		}
		n, err := r.cur.Read(p)
		if n > 0 {
			return n, nil
		}
		if err == io.EOF {
			r.cur.Close()
			r.cur = nil
			r.i++
			continue
		}
		if err != nil {
			return 0, err
		}
		// n == 0, err == nil: read again from the same source.
	}
}

func (r *memberSeqReader) Close() error {
	if r.cur != nil {
		err := r.cur.Close()
		r.cur = nil
		return err
	}
	return nil
}

// cabStage stages one folder's compressed CFDATA region so its total length is
// known before the CFHEADER (which carries cbCabinet) is written, then replays
// it into the cabinet. The author write path uses an on-disk temp file
// (memory-bounded); the []byte convenience wrappers use an in-memory buffer.
type cabStage interface {
	io.Writer
	reader() (io.Reader, error) // fresh reader over everything written so far
	cleanup()
}

type memCabStage struct{ buf bytes.Buffer }

func (m *memCabStage) Write(p []byte) (int, error) { return m.buf.Write(p) }
func (m *memCabStage) reader() (io.Reader, error)  { return bytes.NewReader(m.buf.Bytes()), nil }
func (m *memCabStage) cleanup()                    {}

func newMemCabStage() (cabStage, error) { return &memCabStage{}, nil }

type fileCabStage struct{ f *os.File }

func newFileCabStage() (cabStage, error) {
	f, err := os.CreateTemp("", "go-msix-cab-*")
	if err != nil {
		return nil, fmt.Errorf("msi cab: temp region: %w", err)
	}
	return &fileCabStage{f: f}, nil
}

func (s *fileCabStage) Write(p []byte) (int, error) { return s.f.Write(p) }
func (s *fileCabStage) reader() (io.Reader, error) {
	if _, err := s.f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return s.f, nil
}
func (s *fileCabStage) cleanup() {
	name := s.f.Name()
	s.f.Close()
	os.Remove(name)
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
// by File.Sequence (the common case) and returns it as bytes. Byte-identical to
// the historical writer; a thin convenience wrapper over the streaming writer.
func buildMSICAB(members []msiCabMember) ([]byte, error) {
	if len(members) == 0 {
		return nil, fmt.Errorf("msi cab: no members (caller must skip cab creation entirely)")
	}
	return buildMSICABFolders([][]msiCabMember{members})
}

// buildMSICABFolders builds one MSZIP cabinet (N independent CFFOLDERs) and
// returns it as bytes. Convenience wrapper over streamMSICABFolders using an
// in-memory region stage; production callers stream via streamMSICABFolders.
func buildMSICABFolders(folders [][]msiCabMember) ([]byte, error) {
	var buf bytes.Buffer
	if err := streamMSICABFolders(&buf, folders, newMemCabStage); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// streamMSICABFolders writes one MSZIP cabinet (N independent CFFOLDERs, each
// its own compressed stream) into dst, a forward-only sink. Because the CFHEADER
// carries cbCabinet (total size) at the front and dst cannot be seeked, each
// folder's compressed CFDATA region is first staged via newStage (an on-disk
// temp for the author path) so its length — the only field not known from member
// sizes up front — is learned before the header is emitted. Member payloads are
// streamed through 32 KiB frames and never fully held in memory. Byte-identical
// to the historical buffered writer.
func streamMSICABFolders(dst io.Writer, folders [][]msiCabMember, newStage func() (cabStage, error)) error {
	if len(folders) == 0 {
		return fmt.Errorf("msi cab: no folders")
	}
	if len(folders) > 0xFFFF {
		return fmt.Errorf("msi cab: %d folders exceeds the 65535 per-cabinet limit", len(folders))
	}

	totalFiles := 0
	for _, f := range folders {
		totalFiles += len(f)
	}
	if totalFiles == 0 {
		return fmt.Errorf("msi cab: no members (caller must skip cab creation entirely)")
	}
	if totalFiles > 0xFFFF {
		return fmt.Errorf("msi cab: %d members exceeds the 65535 per-cabinet limit", totalFiles)
	}

	type folderData struct {
		stage     cabStage
		regionLen int64
		blocks    int
		members   []msiCabMember
	}
	fds := make([]folderData, len(folders))
	defer func() {
		for i := range fds {
			if fds[i].stage != nil {
				fds[i].stage.cleanup()
			}
		}
	}()

	var filesSection uint32
	for fi, mem := range folders {
		if len(mem) == 0 {
			return fmt.Errorf("msi cab: folder %d has no members", fi)
		}
		var totalData uint64
		for _, m := range mem {
			if m.name == "" {
				return fmt.Errorf("msi cab: empty member name")
			}
			sz := m.src.Size()
			if uint64(sz) > msiCabMaxFileSize {
				return fmt.Errorf("msi cab: member %s is %d bytes, exceeding the 0x7FFF8000 cbFile limit", m.name, sz)
			}
			totalData += uint64(sz)
			filesSection += cabPerFileHdr + uint32(len(m.name)) + 1
		}
		numBlocks := (totalData + msiCabBlockSize - 1) / msiCabBlockSize
		if numBlocks > 0xFFFF {
			return fmt.Errorf("msi cab: folder %d needs %d CFDATA blocks, exceeding the 65535 limit", fi, numBlocks)
		}
		stage, err := newStage()
		if err != nil {
			return err
		}
		fds[fi].stage = stage
		regionLen, blocks, err := streamCabDataRegion(stage, mem, totalData)
		if err != nil {
			return err
		}
		fds[fi].regionLen = regionLen
		fds[fi].blocks = blocks
		fds[fi].members = mem
	}

	coffFiles := uint32(cabHeaderSize + cabFolderSize*len(folders))
	dataStart := coffFiles + filesSection
	var totalRegion uint64
	for _, fd := range fds {
		totalRegion += uint64(fd.regionLen)
	}
	cbCabinet := uint64(dataStart) + totalRegion
	if cbCabinet > 0x7FFFFFFF {
		return fmt.Errorf("msi cab: total cabinet size %d exceeds the format limit", cbCabinet)
	}

	// Header section (CFHEADER + CFFOLDER + CFFILE) is bounded by file count, not
	// payload size; assemble it in memory, then emit before the staged regions.
	var hb bytes.Buffer

	// CFHEADER
	hb.WriteString("MSCF")
	binary.Write(&hb, binary.LittleEndian, uint32(0)) // reserved1
	binary.Write(&hb, binary.LittleEndian, uint32(cbCabinet))
	binary.Write(&hb, binary.LittleEndian, uint32(0)) // reserved2
	binary.Write(&hb, binary.LittleEndian, coffFiles)
	binary.Write(&hb, binary.LittleEndian, uint32(0)) // reserved3
	hb.WriteByte(3)                                   // versionMinor
	hb.WriteByte(1)                                   // versionMajor
	binary.Write(&hb, binary.LittleEndian, uint16(len(folders)))
	binary.Write(&hb, binary.LittleEndian, uint16(totalFiles))
	binary.Write(&hb, binary.LittleEndian, uint16(0)) // flags
	binary.Write(&hb, binary.LittleEndian, uint16(1)) // setID (constant; single-cab set)
	binary.Write(&hb, binary.LittleEndian, uint16(0)) // iCabinet

	// CFFOLDER per folder (coffCabStart accumulates over prior folders' regions).
	off := dataStart
	for _, fd := range fds {
		binary.Write(&hb, binary.LittleEndian, off)
		binary.Write(&hb, binary.LittleEndian, uint16(fd.blocks))
		binary.Write(&hb, binary.LittleEndian, uint16(cabCompMSZIP))
		off += uint32(fd.regionLen)
	}

	// CFFILE entries, grouped by folder; uoffFolderStart is cumulative within the
	// owning folder's uncompressed stream.
	for fi, fd := range fds {
		var uoff uint32
		for _, m := range fd.members {
			binary.Write(&hb, binary.LittleEndian, uint32(m.src.Size())) // cbFile
			binary.Write(&hb, binary.LittleEndian, uoff)                 // uoffFolderStart
			binary.Write(&hb, binary.LittleEndian, uint16(fi))           // iFolder
			binary.Write(&hb, binary.LittleEndian, uint16(cabDosDate))
			binary.Write(&hb, binary.LittleEndian, uint16(cabDosTime))
			binary.Write(&hb, binary.LittleEndian, uint16(cabAttrArchive))
			hb.WriteString(m.name)
			hb.WriteByte(0)
			uoff += uint32(m.src.Size())
		}
	}

	if _, err := dst.Write(hb.Bytes()); err != nil {
		return err
	}

	// Replay each folder's staged CFDATA region into the cabinet.
	for _, fd := range fds {
		r, err := fd.stage.reader()
		if err != nil {
			return err
		}
		if _, err := io.Copy(dst, r); err != nil {
			return err
		}
	}
	return nil
}

// streamCabDataRegion writes the concatenated CFDATA records for one MSZIP
// folder into w, framing the logical concatenation of the member payloads into
// 32 KiB blocks read sequentially across the member sources (one open at a
// time). It returns the byte length of the region and the block count. Frame
// boundaries, MSZIP compression, and CFDATA checksums are identical to the
// historical writer, so the output bytes are unchanged.
func streamCabDataRegion(w io.Writer, members []msiCabMember, totalData uint64) (int64, int, error) {
	src := &memberSeqReader{members: members}
	defer src.Close()

	frame := make([]byte, msiCabBlockSize)
	var regionLen int64
	blocks := 0
	var consumed uint64

	for consumed < totalData {
		want := msiCabBlockSize
		if rem := totalData - consumed; rem < uint64(want) {
			want = int(rem)
		}
		if _, err := io.ReadFull(src, frame[:want]); err != nil {
			return 0, 0, fmt.Errorf("msi cab: reading member data: %w", err)
		}
		consumed += uint64(want)

		ab, err := msiMSZIPBlock(frame[:want])
		if err != nil {
			return 0, 0, err
		}

		var hdr [4]byte
		binary.LittleEndian.PutUint16(hdr[0:], uint16(len(ab))) // cbData
		binary.LittleEndian.PutUint16(hdr[2:], uint16(want))    // cbUncomp
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
