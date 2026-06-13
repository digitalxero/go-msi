package msi

// msi_stringpool.go
// MSI shared string pool: the _StringPool and _StringData streams.
// Byte-compatible with Wine (dlls/msi/string.c), msitools and rust-msi.
//
// Format (little-endian):
//   _StringPool:
//     u32 header = codepage, with bit 31 set when table rows use long
//                  (3-byte) string refs
//     then one 4-byte slot per string ID, starting at ID 1:
//       u16 byteLength, u16 refCount             -- normal entry (length <= 0xFFFF)
//       u16 0, u16 0                             -- hole: consumes an ID, no data
//       u16 0, u16 refCount, u32 realByteLength  -- big string (> 0xFFFF bytes);
//                                                   spans two slots, ONE ID
//   _StringData:
//     bare concatenation of every entry's bytes in string-ID order — no
//     terminators, no padding; the pool lengths slice it.
//
// String ID 0 is reserved for null/empty and never has a pool entry:
// addString("") returns 0 and refFor("") is 0. Live strings always carry
// refCount >= 1 (a 0-length/0-refcount slot is hole framing and a
// 0-length/nonzero-refcount slot is the big-string marker); refcounts are
// clamped to 0xFFFF on write rather than wrapped.
//
// Codepage: strings are stored as their raw Go UTF-8 bytes and byteLength is
// measured on those bytes. Following Wine/msitools/WiX, a freshly created
// database declares the neutral codepage 0 (CP_ACP), which is only
// deterministic for pure-ASCII data — so when the declared codepage is 0 and
// any pooled string contains a non-ASCII byte, the header is emitted as 65001
// (UTF-8) instead: accepted by Windows (IsValidCodePage), Wine, msitools and
// rust-msi, and lossless for the bytes we store. An explicit non-zero codepage
// passed to newMSIStringPool is emitted verbatim; callers declaring a legacy
// ANSI codepage (e.g. 1252) must supply strings already encoded in it — never
// declare 1252 over UTF-8 bytes.
//
// Long string refs: per Wine, the flag is set iff the pool slot count
// including the reserved ID 0 exceeds 0xFFFF (i.e. the highest assigned ID is
// >= 0xFFFF). The flag is global to the whole database: callers must add every
// string BEFORE reading isLongRefs or serializing any table stream.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// longStringRefsBit marks bit 31 of the _StringPool header u32.
	longStringRefsBit uint32 = 1 << 31
	// utf8MSICodepage is the UTF-8 codepage id (CP_UTF8).
	utf8MSICodepage uint32 = 65001
	// maxShortStringLen is the largest byte length a normal 4-byte pool entry
	// can describe; longer strings use the 8-byte big-string form.
	maxShortStringLen = 0xFFFF
	// maxMSIRefCount is the largest refcount a u16 pool field can hold;
	// larger counts are clamped (never wrapped — a wrap to 0 would corrupt
	// the hole/big-string framing).
	maxMSIRefCount uint32 = 0xFFFF
	// maxMSIPoolSlots is Wine's maxcount threshold: when the slot count
	// including the reserved ID 0 exceeds it, long (3-byte) refs are used.
	maxMSIPoolSlots = 0xFFFF
)

type msiStringPool struct {
	// codepage is the DECLARED codepage without the long-refs bit; see
	// headerCodepage for the value actually written.
	codepage uint32
	// entries[0] is the reserved null entry (ID 0) and is never written.
	entries []msiStringPoolEntry
	// strToRef maps a string value to its (first) 1-based ID for dedup.
	strToRef map[string]uint32
	// longRefs forces long refs on (set when parsing a header with bit 31);
	// isLongRefs may also derive the flag from the slot count.
	longRefs bool
	// nonASCII records whether any pooled string contains a byte >= 0x80.
	nonASCII bool
}

type msiStringPoolEntry struct {
	data     []byte
	refCount uint32 // uint32 internally so overflow can be clamped, not wrapped
}

// isHole reports whether the entry is a hole: it consumes a string ID but has
// no value and contributes nothing to _StringData (real MSIs contain holes
// after a string is deleted; this writer only produces them via parsing).
func (e *msiStringPoolEntry) isHole() bool {
	return e.refCount == 0 && len(e.data) == 0
}

func newMSIStringPool(codepage uint32) *msiStringPool {
	return &msiStringPool{
		codepage: codepage &^ longStringRefsBit,
		entries:  make([]msiStringPoolEntry, 1), // index 0 reserved for null/empty
		strToRef: make(map[string]uint32),
		longRefs: codepage&longStringRefsBit != 0,
	}
}

// addString interns s and returns its 1-based string ID, incrementing the
// refcount when s is already pooled. The empty string is NEVER pooled: it maps
// to the reserved ID 0 (a 0-length live entry would be misparsed as a
// big-string marker and desynchronize the whole pool).
func (p *msiStringPool) addString(s string) uint32 {
	if s == "" {
		return 0
	}
	if ref, ok := p.strToRef[s]; ok {
		p.entries[ref].refCount++
		return ref
	}
	ref := uint32(len(p.entries))
	p.entries = append(p.entries, msiStringPoolEntry{data: []byte(s), refCount: 1})
	p.strToRef[s] = ref
	p.noteBytes(s)
	return ref
}

// noteBytes updates the non-ASCII tracking used by headerCodepage.
func (p *msiStringPool) noteBytes(s string) {
	if p.nonASCII {
		return
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			p.nonASCII = true
			return
		}
	}
}

// refCount returns the current refcount for a ref (0 for ID 0, holes and
// unknown refs).
func (p *msiStringPool) refCount(ref uint32) uint32 {
	if ref == 0 || ref >= uint32(len(p.entries)) {
		return 0
	}
	return p.entries[ref].refCount
}

// isLongRefs reports whether string refs in table rows must be written as
// 3 bytes instead of 2. Wine's rule: slot count including the reserved ID 0
// (= highest ID + 1) > 0xFFFF, so ID 0xFFFF is already long. The flag is
// global to the database — call this only after every addString and use the
// same value for _StringPool and every table stream.
func (p *msiStringPool) isLongRefs() bool {
	return p.longRefs || len(p.entries) > maxMSIPoolSlots
}

// headerCodepage returns the u32 written at the head of _StringPool: the
// effective codepage with bit 31 set for long refs. A declared codepage of 0
// (neutral, CP_ACP) is upgraded to 65001 when any string is non-ASCII, since
// neutral is only deterministic for pure-ASCII data (see file header).
func (p *msiStringPool) headerCodepage() uint32 {
	cp := p.codepage
	if cp == 0 && p.nonASCII {
		cp = utf8MSICodepage
	}
	if p.isLongRefs() {
		cp |= longStringRefsBit
	}
	return cp
}

// poolBytes returns the bytes of the _StringPool stream.
func (p *msiStringPool) poolBytes() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, 4+4*len(p.entries)))
	var slot [8]byte
	binary.LittleEndian.PutUint32(slot[:4], p.headerCodepage())
	buf.Write(slot[:4])

	for i := 1; i < len(p.entries); i++ {
		e := &p.entries[i]
		if e.isHole() {
			// Two zero u16s: consumes the ID, no data.
			buf.Write([]byte{0, 0, 0, 0})
			continue
		}
		refs := e.refCount
		if refs > maxMSIRefCount {
			refs = maxMSIRefCount
		}
		if len(e.data) > maxShortStringLen {
			// Big string: [u16 0][u16 refCount][u32le realLength] — two slots,
			// one string ID (Wine string.c:631-637; rust-msi stringpool.rs).
			// msitools' saver emits a different (buggy) layout; do NOT copy it.
			if uint64(len(e.data)) > uint64(^uint32(0)) {
				return nil, fmt.Errorf("msix: string id %d is %d bytes, exceeding the u32 limit of the MSI string pool", i, len(e.data))
			}
			if refs == 0 {
				refs = 1 // framing: length 0 + refcount 0 would read as a hole
			}
			binary.LittleEndian.PutUint16(slot[0:], 0)
			binary.LittleEndian.PutUint16(slot[2:], uint16(refs))
			binary.LittleEndian.PutUint32(slot[4:], uint32(len(e.data)))
			buf.Write(slot[:8])
			continue
		}
		binary.LittleEndian.PutUint16(slot[0:], uint16(len(e.data)))
		binary.LittleEndian.PutUint16(slot[2:], uint16(refs))
		buf.Write(slot[:4])
	}
	return buf.Bytes(), nil
}

// dataBytes returns the bytes of the _StringData stream: the entries' raw
// bytes concatenated in string-ID order, no terminators, no padding.
func (p *msiStringPool) dataBytes() []byte {
	total := 0
	for i := 1; i < len(p.entries); i++ {
		total += len(p.entries[i].data)
	}
	out := make([]byte, 0, total)
	for i := 1; i < len(p.entries); i++ {
		out = append(out, p.entries[i].data...)
	}
	return out
}

// getString returns the string for a ref ("" for ID 0, holes and unknown refs).
func (p *msiStringPool) getString(ref uint32) string {
	if ref == 0 || ref >= uint32(len(p.entries)) {
		return ""
	}
	return string(p.entries[ref].data)
}

// numStrings returns the number of unique live strings in the pool (holes and
// the reserved ID 0 are not counted).
func (p *msiStringPool) numStrings() int {
	return len(p.strToRef)
}

// refFor returns the 1-based ref for s if previously registered via addString
// (or parsed). Does not change refcounts. Returns 0 for the empty string and
// for unknown strings.
func (p *msiStringPool) refFor(s string) uint32 {
	if s == "" {
		return 0
	}
	if ref, ok := p.strToRef[s]; ok {
		return ref
	}
	return 0
}

// codePage returns the effective codepage as written to the header (including
// the long-ref bit when set).
func (p *msiStringPool) codePage() uint32 {
	return p.headerCodepage()
}

// forEachString calls fn for every live entry in ascending string-ID order.
// Holes consume an ID but have no value and are skipped; ID 0 (null/empty)
// has no entry. Iteration order is deterministic.
func (p *msiStringPool) forEachString(fn func(ref uint32, value string)) {
	for i := 1; i < len(p.entries); i++ {
		e := &p.entries[i]
		if e.isHole() {
			continue
		}
		fn(uint32(i), string(e.data))
	}
}

// parseMSIStringPool is the full inverse of poolBytes/dataBytes: it rebuilds a
// pool from the raw _StringPool and _StringData streams, restoring the
// codepage, the long-refs flag, holes and big strings. Per Wine, a pool stream
// of 4 bytes or fewer implies codepage 0 (CP_ACP), short refs and no entries.
func parseMSIStringPool(poolBytes, dataBytes []byte) (*msiStringPool, error) {
	p := newMSIStringPool(0)
	if len(poolBytes) <= 4 {
		if len(dataBytes) != 0 {
			return nil, fmt.Errorf("msix: _StringPool has no entries but _StringData holds %d bytes", len(dataBytes))
		}
		return p, nil
	}

	header := binary.LittleEndian.Uint32(poolBytes[:4])
	p.codepage = header &^ longStringRefsBit
	p.longRefs = header&longStringRefsBit != 0

	rest := poolBytes[4:]
	if len(rest)%4 != 0 {
		return nil, fmt.Errorf("msix: _StringPool size %d is not 4 + a multiple of 4", len(poolBytes))
	}

	offset := 0
	for i := 0; i < len(rest); i += 4 {
		length := uint64(binary.LittleEndian.Uint16(rest[i:]))
		refs := uint32(binary.LittleEndian.Uint16(rest[i+2:]))
		if length == 0 && refs == 0 {
			// Hole: consumes a string ID, contributes no data.
			p.entries = append(p.entries, msiStringPoolEntry{})
			continue
		}
		if length == 0 {
			// Big-string marker: the next 4-byte slot is the u32 real length;
			// both slots together consume ONE string ID.
			if i+8 > len(rest) {
				return nil, errors.New("msix: _StringPool ends inside a big-string entry")
			}
			length = uint64(binary.LittleEndian.Uint32(rest[i+4:]))
			if length == 0 {
				return nil, errors.New("msix: _StringPool big-string entry declares zero length")
			}
			i += 4
		}
		if length > uint64(len(dataBytes)-offset) {
			return nil, fmt.Errorf("msix: _StringData too short: string id %d needs %d bytes, %d left", len(p.entries), length, len(dataBytes)-offset)
		}
		value := string(dataBytes[offset : offset+int(length)])
		offset += int(length)

		ref := uint32(len(p.entries))
		p.entries = append(p.entries, msiStringPoolEntry{data: []byte(value), refCount: refs})
		if _, ok := p.strToRef[value]; !ok {
			p.strToRef[value] = ref
		}
		p.noteBytes(value)
	}
	if offset != len(dataBytes) {
		return nil, fmt.Errorf("msix: _StringData has %d trailing bytes not covered by _StringPool", len(dataBytes)-offset)
	}
	return p, nil
}
