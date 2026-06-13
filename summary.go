package msi

// msi_summary.go implements the OLE property set serialized into the
// \x05SummaryInformation stream at the root of an MSI compound file.
//
// Layout (all little-endian, verified against MS-OLEPS, Wine suminfo.c,
// msitools and rust-msi):
//
//	offset  size  field
//	0       28    PropertySetStream header (byte order, format, OS version,
//	              CLSID, property-set count)
//	28      20    FMTID_SummaryInformation + absolute section offset (always 48)
//	48      var   single section: cbSection, cProperties, PID/offset table,
//	              then the 4-byte-aligned property values

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
)

// Variant type tags used by the summary property set (MS-OLEPS TypedPropertyValue).
const (
	msiVTI2       uint32 = 2  // 16-bit signed integer, zero-padded to 4 bytes
	msiVTI4       uint32 = 3  // 32-bit signed integer
	msiVTLPStr    uint32 = 30 // codepage string: u32 size (incl. NUL), bytes, pad to 4
	msiVTFiletime uint32 = 64 // u64 count of 100ns intervals since 1601-01-01 UTC
)

// Summary information property IDs (Microsoft "Summary Information Stream
// Property Set"). PIDs 0, 17 and >= 20 must never be emitted: Wine's reader
// aborts parsing of all remaining properties when it sees one.
const (
	msiPIDCodepage       uint32 = 1  // VT_I2
	msiPIDTitle          uint32 = 2  // VT_LPSTR
	msiPIDSubject        uint32 = 3  // VT_LPSTR (ProductName)
	msiPIDAuthor         uint32 = 4  // VT_LPSTR (Manufacturer)
	msiPIDKeywords       uint32 = 5  // VT_LPSTR
	msiPIDComments       uint32 = 6  // VT_LPSTR
	msiPIDTemplate       uint32 = 7  // VT_LPSTR, REQUIRED ("x64;1033" etc.)
	msiPIDLastSavedBy    uint32 = 8  // VT_LPSTR (patches: the ":"-prefixed transform list)
	msiPIDRevisionNumber uint32 = 9  // VT_LPSTR, REQUIRED (PackageCode / patch-code GUID)
	msiPIDCreateTime     uint32 = 12 // VT_FILETIME
	msiPIDSaveTime       uint32 = 13 // VT_FILETIME
	msiPIDPageCount      uint32 = 14 // VT_I4, REQUIRED (minimum MSI version * 100)
	msiPIDWordCount      uint32 = 15 // VT_I4, REQUIRED (source flags bit field)
	msiPIDCharacterCount uint32 = 16 // VT_I4 (transforms: low word validation, high word error flags)
	msiPIDCreatingApp    uint32 = 18 // VT_LPSTR
	msiPIDSecurity       uint32 = 19 // VT_I4 (2 = read-only recommended)
)

const (
	// msiSummaryByteOrder is the mandatory OLEPS byte-order mark (0xFFFE).
	msiSummaryByteOrder uint16 = 0xFFFE
	// msiSummaryOSVer mirrors Wine/msitools output ("build 5, platform id 2").
	msiSummaryOSVer uint32 = 0x00020005
	// msiSummarySectionOffset is where the single section always starts:
	// 28-byte header + 20-byte FMTID/offset pair.
	msiSummarySectionOffset uint32 = 48
	// msiSummaryDefaultCodepage is the ANSI codepage written when none is set;
	// it governs the encoding of VT_LPSTR values in this stream only.
	msiSummaryDefaultCodepage = 1252
	// msiFiletimeEpochSeconds is the number of seconds between the FILETIME
	// epoch (1601-01-01 UTC) and the Unix epoch (1970-01-01 UTC).
	msiFiletimeEpochSeconds = 11644473600
)

// msiSummaryFmtID is FMTID_SummaryInformation {F29F85E0-4FF9-1068-AB91-08002B27B3D9}
// in Windows GUID wire order (Data1..Data3 little-endian, Data4 as-is).
var msiSummaryFmtID = [16]byte{
	0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10,
	0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9,
}

// msiSummaryInfo holds the properties serialized into \x05SummaryInformation.
// Zero-valued optional fields are omitted from the stream; the properties
// Microsoft marks REQUIRED for installation packages (Template, RevisionNumber,
// PageCount, WordCount) are always emitted, as is the Codepage, which must
// precede any string property.
type msiSummaryInfo struct {
	Codepage       int       // PID 1; 0 means the 1252 default
	Title          string    // PID 2; conventionally "Installation Database"
	Subject        string    // PID 3; ProductName
	Author         string    // PID 4; Manufacturer
	Keywords       string    // PID 5; conventionally "Installer"
	Comments       string    // PID 6
	Template       string    // PID 7; "<platform>;<langid>", e.g. "x64;1033"
	LastSavedBy    string    // PID 8; patches: the ":"-prefixed transform list; omitted when ""
	RevisionNumber string    // PID 9; PackageCode, braced uppercase GUID
	CreatingApp    string    // PID 18; tool name and version
	CreateTime     time.Time // PID 12; omitted when zero
	SaveTime       time.Time // PID 13; omitted when zero
	PageCount      int       // PID 14; 200 for x86/x64, 500 for Arm64
	WordCount      int       // PID 15; 2 = compressed source, long file names
	CharacterCount int       // PID 16; transforms: low word validation flags, high word error flags; omitted when 0
	Security       int       // PID 19; 2 = read-only recommended; omitted when 0

	// OmitPageCount drops PID 14 entirely (patches: the min-installer-version
	// meaning moves to WordCount/PID 15, and PID 14 is null).
	OmitPageCount bool
}

// msiSummaryProp pairs a property ID with its fully encoded TypedPropertyValue.
// Every encoded value is a multiple of 4 bytes, so back-to-back values stay
// 4-byte aligned.
type msiSummaryProp struct {
	pid uint32
	val []byte
}

// buildMSISummaryStream serializes info into the exact byte layout of the
// \x05SummaryInformation stream. Output is deterministic: the same info always
// produces identical bytes. Properties are emitted in ascending PID order with
// the codepage (PID 1) first.
func buildMSISummaryStream(info msiSummaryInfo) ([]byte, error) {
	props, err := msiSummaryProps(info)
	if err != nil {
		return nil, err
	}

	// Section size: 8-byte section header + PID/offset table + values.
	valuesStart := uint32(8 + 8*len(props))
	cbSection := valuesStart
	for _, p := range props {
		cbSection += uint32(len(p.val))
	}

	out := make([]byte, 0, msiSummarySectionOffset+cbSection)

	// PropertySetStream header (28 bytes).
	out = binary.LittleEndian.AppendUint16(out, msiSummaryByteOrder) // wByteOrder
	out = binary.LittleEndian.AppendUint16(out, 0)                   // wFormat (version 0)
	out = binary.LittleEndian.AppendUint32(out, msiSummaryOSVer)     // dwOSVer
	out = append(out, make([]byte, 16)...)                           // clsID (all zero)
	out = binary.LittleEndian.AppendUint32(out, 1)                   // NumPropertySets

	// FMTID + section offset (20 bytes).
	out = append(out, msiSummaryFmtID[:]...)
	out = binary.LittleEndian.AppendUint32(out, msiSummarySectionOffset)

	// Section header and PID/offset table; offsets are relative to the
	// section start, not the stream start.
	out = binary.LittleEndian.AppendUint32(out, cbSection)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(props)))
	off := valuesStart
	for _, p := range props {
		out = binary.LittleEndian.AppendUint32(out, p.pid)
		out = binary.LittleEndian.AppendUint32(out, off)
		off += uint32(len(p.val))
	}

	for _, p := range props {
		out = append(out, p.val...)
	}

	return out, nil
}

// msiSummaryProps converts info into encoded properties in ascending PID order.
func msiSummaryProps(info msiSummaryInfo) ([]msiSummaryProp, error) {
	props := make([]msiSummaryProp, 0, 14)

	addString := func(pid uint32, s string, required bool) error {
		if s == "" && !required {
			return nil
		}
		if err := validateMSISummaryString(s); err != nil {
			return fmt.Errorf("summary property %d: %w", pid, err)
		}
		props = append(props, msiSummaryProp{pid: pid, val: encodeMSISummaryLPStr(s)})
		return nil
	}
	addI4 := func(pid uint32, v int, required bool) error {
		if v == 0 && !required {
			return nil
		}
		if v < math.MinInt32 || v > math.MaxInt32 {
			return fmt.Errorf("summary property %d: value %d does not fit in int32", pid, v)
		}
		props = append(props, msiSummaryProp{pid: pid, val: encodeMSISummaryI4(int32(v))})
		return nil
	}
	addTime := func(pid uint32, t time.Time) error {
		if t.IsZero() {
			return nil
		}
		if t.UTC().Unix() < -msiFiletimeEpochSeconds {
			return fmt.Errorf("summary property %d: time %s predates the FILETIME epoch (1601-01-01)", pid, t.UTC())
		}
		props = append(props, msiSummaryProp{pid: pid, val: encodeMSISummaryFiletime(t)})
		return nil
	}

	// PID 1 (codepage) must come first; it governs every VT_LPSTR below.
	codepage := info.Codepage
	if codepage == 0 {
		codepage = msiSummaryDefaultCodepage
	}
	if codepage < 0 || codepage > math.MaxUint16 {
		return nil, fmt.Errorf("summary codepage %d out of range", info.Codepage)
	}
	props = append(props, msiSummaryProp{pid: msiPIDCodepage, val: encodeMSISummaryI2(uint16(codepage))})

	if err := addString(msiPIDTitle, info.Title, false); err != nil {
		return nil, err
	}
	if err := addString(msiPIDSubject, info.Subject, false); err != nil {
		return nil, err
	}
	if err := addString(msiPIDAuthor, info.Author, false); err != nil {
		return nil, err
	}
	if err := addString(msiPIDKeywords, info.Keywords, false); err != nil {
		return nil, err
	}
	if err := addString(msiPIDComments, info.Comments, false); err != nil {
		return nil, err
	}
	if err := addString(msiPIDTemplate, info.Template, true); err != nil {
		return nil, err
	}
	if err := addString(msiPIDLastSavedBy, info.LastSavedBy, false); err != nil {
		return nil, err
	}
	if err := addString(msiPIDRevisionNumber, info.RevisionNumber, true); err != nil {
		return nil, err
	}
	if err := addTime(msiPIDCreateTime, info.CreateTime); err != nil {
		return nil, err
	}
	if err := addTime(msiPIDSaveTime, info.SaveTime); err != nil {
		return nil, err
	}
	if !info.OmitPageCount {
		if err := addI4(msiPIDPageCount, info.PageCount, true); err != nil {
			return nil, err
		}
	}
	if err := addI4(msiPIDWordCount, info.WordCount, true); err != nil {
		return nil, err
	}
	if err := addI4(msiPIDCharacterCount, info.CharacterCount, false); err != nil {
		return nil, err
	}
	if err := addString(msiPIDCreatingApp, info.CreatingApp, false); err != nil {
		return nil, err
	}
	if err := addI4(msiPIDSecurity, info.Security, false); err != nil {
		return nil, err
	}

	return props, nil
}

// validateMSISummaryString rejects strings that cannot be serialized losslessly:
// VT_LPSTR values are NUL-terminated 8-bit strings in the PID 1 codepage, so
// embedded NULs are impossible and non-ASCII UTF-8 bytes would be misread
// under codepage 1252.
func validateMSISummaryString(s string) error {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == 0:
			return errors.New("string must not contain NUL bytes")
		case c > 0x7F:
			return errors.New("string must be ASCII (summary strings are stored in the ANSI codepage)")
		}
	}

	return nil
}

// encodeMSISummaryI2 encodes a VT_I2 value: type tag, 16-bit value, two zero
// pad bytes (the MS-OLEPS-normative form; readers only consume the low word).
func encodeMSISummaryI2(v uint16) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b[0:], msiVTI2)
	binary.LittleEndian.PutUint16(b[4:], v)

	return b
}

// encodeMSISummaryI4 encodes a VT_I4 value: type tag and 32-bit value.
func encodeMSISummaryI4(v int32) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b[0:], msiVTI4)
	binary.LittleEndian.PutUint32(b[4:], uint32(v))

	return b
}

// encodeMSISummaryLPStr encodes a VT_LPSTR value: type tag, byte count
// including the NUL terminator (excluding padding), the bytes, the NUL, then
// zero padding to a 4-byte multiple.
func encodeMSISummaryLPStr(s string) []byte {
	cb := len(s) + 1
	b := make([]byte, 8+(cb+3)&^3)
	binary.LittleEndian.PutUint32(b[0:], msiVTLPStr)
	binary.LittleEndian.PutUint32(b[4:], uint32(cb))
	copy(b[8:], s) // the NUL terminator and padding are already zero

	return b
}

// encodeMSISummaryFiletime encodes a VT_FILETIME value: type tag and u64
// count of 100ns intervals since 1601-01-01 UTC.
func encodeMSISummaryFiletime(t time.Time) []byte {
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b[0:], msiVTFiletime)
	binary.LittleEndian.PutUint64(b[4:], msiFiletimeFromTime(t))

	return b
}

// msiFiletimeFromTime converts t to a Windows FILETIME: the number of 100ns
// intervals since 1601-01-01 00:00:00 UTC. t must not predate that epoch.
func msiFiletimeFromTime(t time.Time) uint64 {
	t = t.UTC()

	return uint64(t.Unix()+msiFiletimeEpochSeconds)*10_000_000 + uint64(t.Nanosecond()/100)
}

// msiFiletimeToTime converts a Windows FILETIME back to a UTC time.Time.
// Sub-100ns precision is not representable in FILETIME, so conversions round
// trip only at 100ns granularity.
func msiFiletimeToTime(ft uint64) time.Time {
	sec := int64(ft/10_000_000) - msiFiletimeEpochSeconds
	nsec := int64(ft%10_000_000) * 100

	return time.Unix(sec, nsec).UTC()
}

// parseMSISummaryStream is the tolerant inverse of buildMSISummaryStream.
// It validates the byte-order mark and FMTID (the checks Wine's reader
// enforces), follows the section offset, and decodes every property it
// recognizes; unknown PIDs and unknown variant types are skipped. Structural
// corruption (truncated data, out-of-range offsets) is an error.
func parseMSISummaryStream(data []byte) (msiSummaryInfo, error) {
	var info msiSummaryInfo

	if uint64(len(data)) < uint64(msiSummarySectionOffset)+8 {
		return info, fmt.Errorf("summary stream too short: %d bytes", len(data))
	}
	if bom := binary.LittleEndian.Uint16(data[0:2]); bom != msiSummaryByteOrder {
		return info, fmt.Errorf("summary stream byte-order mark 0x%04X, want 0x%04X", bom, msiSummaryByteOrder)
	}
	if !bytes.Equal(data[28:44], msiSummaryFmtID[:]) {
		return info, errors.New("summary stream FMTID is not FMTID_SummaryInformation")
	}

	secOff := binary.LittleEndian.Uint32(data[44:48])
	if uint64(secOff)+8 > uint64(len(data)) {
		return info, fmt.Errorf("summary section offset %d out of range", secOff)
	}
	section := data[secOff:]

	count := binary.LittleEndian.Uint32(section[4:8])
	if 8+8*uint64(count) > uint64(len(section)) {
		return info, fmt.Errorf("summary property table truncated: %d properties", count)
	}

	for i := uint64(0); i < uint64(count); i++ {
		pid := binary.LittleEndian.Uint32(section[8+8*i:])
		off := binary.LittleEndian.Uint32(section[12+8*i:])

		val, err := decodeMSISummaryValue(section, off)
		if err != nil {
			return info, fmt.Errorf("summary property %d: %w", pid, err)
		}
		if val == nil {
			continue // unknown variant type, tolerated
		}

		assignMSISummaryProperty(&info, pid, val)
	}

	return info, nil
}

// decodeMSISummaryValue decodes the TypedPropertyValue at the given
// section-relative offset. It returns an int for VT_I2/VT_I4, a string for
// VT_LPSTR, a time.Time for VT_FILETIME, or nil for unknown variant types.
func decodeMSISummaryValue(section []byte, off uint32) (any, error) {
	if uint64(off)+8 > uint64(len(section)) {
		return nil, fmt.Errorf("value offset %d out of range", off)
	}
	vt := binary.LittleEndian.Uint32(section[off:])
	body := section[off+4:]

	switch vt {
	case msiVTI2:
		// Read only the low word; Wine sign-extends the high word, MS-OLEPS
		// zero-pads it. Either way the value lives in the low 16 bits.
		return int(binary.LittleEndian.Uint16(body)), nil
	case msiVTI4:
		return int(int32(binary.LittleEndian.Uint32(body))), nil
	case msiVTFiletime:
		if len(body) < 8 {
			return nil, errors.New("FILETIME value truncated")
		}

		return msiFiletimeToTime(binary.LittleEndian.Uint64(body)), nil
	case msiVTLPStr:
		cb := binary.LittleEndian.Uint32(body)
		if uint64(cb)+4 > uint64(len(body)) {
			return nil, fmt.Errorf("string value of %d bytes truncated", cb)
		}
		s := body[4 : 4+cb]
		if n := bytes.IndexByte(s, 0); n >= 0 {
			s = s[:n] // drop the NUL terminator and anything after it
		}

		return string(s), nil
	default:
		return nil, nil
	}
}

// assignMSISummaryProperty stores a decoded value into the matching field.
// Unknown PIDs and type mismatches are ignored.
func assignMSISummaryProperty(info *msiSummaryInfo, pid uint32, val any) {
	switch pid {
	case msiPIDCodepage:
		if v, ok := val.(int); ok {
			info.Codepage = v
		}
	case msiPIDTitle:
		if s, ok := val.(string); ok {
			info.Title = s
		}
	case msiPIDSubject:
		if s, ok := val.(string); ok {
			info.Subject = s
		}
	case msiPIDAuthor:
		if s, ok := val.(string); ok {
			info.Author = s
		}
	case msiPIDKeywords:
		if s, ok := val.(string); ok {
			info.Keywords = s
		}
	case msiPIDComments:
		if s, ok := val.(string); ok {
			info.Comments = s
		}
	case msiPIDTemplate:
		if s, ok := val.(string); ok {
			info.Template = s
		}
	case msiPIDLastSavedBy:
		if s, ok := val.(string); ok {
			info.LastSavedBy = s
		}
	case msiPIDCharacterCount:
		if v, ok := val.(int); ok {
			info.CharacterCount = v
		}
	case msiPIDRevisionNumber:
		if s, ok := val.(string); ok {
			info.RevisionNumber = s
		}
	case msiPIDCreateTime:
		if t, ok := val.(time.Time); ok {
			info.CreateTime = t
		}
	case msiPIDSaveTime:
		if t, ok := val.(time.Time); ok {
			info.SaveTime = t
		}
	case msiPIDPageCount:
		if v, ok := val.(int); ok {
			info.PageCount = v
		}
	case msiPIDWordCount:
		if v, ok := val.(int); ok {
			info.WordCount = v
		}
	case msiPIDCreatingApp:
		if s, ok := val.(string); ok {
			info.CreatingApp = s
		}
	case msiPIDSecurity:
		if v, ok := val.(int); ok {
			info.Security = v
		}
	}
}
