package msi

// msi_streamprefix.go
// MSI stream-name encoding for use inside the CFB container.
//
// Every stream stored in a .msi CFB (except the \x05-prefixed control streams)
// carries an "encoded" name: pairs of characters from a 64-character alphabet
// are packed into single UTF-16 code units in the range 0x3800-0x47FF, a lone
// trailing character becomes a unit in 0x4800-0x483F, and characters outside
// the alphabet pass through unchanged. Table data streams (one per table,
// including _Tables, _Columns, _Validation, _StringPool and _StringData)
// additionally carry the single prefix code unit 0x4840; data streams listed
// in the _Streams pseudo-table (embedded cabinets, Binary/Icon payloads named
// "Table.Key1[.Key2...]") are pair-packed WITHOUT the prefix. Readers (Wine,
// msitools, rust-msi, Windows Installer) distinguish the two classes by the
// first code unit.
//
// Packing arithmetic (Wine dlls/msi/table.c encode_streamname/decode_streamname,
// rust-msi src/internal/streamname.rs):
//   pair (c1, c2): unit = 0x3800 + v1 + (v2 << 6)   -- FIRST char in the LOW 6 bits
//   single c:      unit = 0x4800 + v
// where v is the 6-bit alphabet value of the character. Pairing never spans a
// non-encodable character; encoding resumes after the passthrough rune.
//
// \x05SummaryInformation, \x05DigitalSignature and \x05MsiDigitalSignatureEx
// are stored literally and must bypass the encoder entirely.

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	// msiNameAlphabet is the 64-character MSI name alphabet in 6-bit value
	// order: '0'-'9' (0-9), 'A'-'Z' (10-35), 'a'-'z' (36-61), '.' (62), '_' (63).
	msiNameAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"

	// msiNamePairBase starts the packed-pair code-unit range 0x3800-0x47FF.
	msiNamePairBase = 0x3800
	// msiNameSingleBase starts the lone-character code-unit range 0x4800-0x483F.
	msiNameSingleBase = 0x4800
	// msiNameTablePrefix is the single code unit prepended to the encoded name
	// of every table stream (UTF-8 bytes E4 A1 80).
	msiNameTablePrefix rune = 0x4840

	// msiMaxEncodedNameUnits is the CFB directory-entry name limit: 64 bytes
	// including the 2-byte NUL terminator = 31 UTF-16 code units for the
	// encoded name, INCLUDING the 0x4840 prefix when present.
	msiMaxEncodedNameUnits = 31
)

var (
	errMSIStreamNameEmpty   = errors.New("msix: msi stream name must not be empty")
	errMSIStreamNameTooLong = errors.New("msix: encoded msi stream name exceeds 31 UTF-16 code units")
)

// msiB64Value returns the 6-bit alphabet value for r, or -1 when r is not
// encodable (anything outside the 64-character set, including all runes
// >= 0x80, passes through the encoder unchanged).
func msiB64Value(r rune) int {
	switch {
	case r >= '0' && r <= '9':
		return int(r - '0')
	case r >= 'A' && r <= 'Z':
		return int(r-'A') + 10
	case r >= 'a' && r <= 'z':
		return int(r-'a') + 36
	case r == '.':
		return 62
	case r == '_':
		return 63
	}
	return -1
}

// msiB64Rune is the inverse of msiB64Value for v in 0..63.
func msiB64Rune(v int) rune {
	return rune(msiNameAlphabet[v&0x3F])
}

// encodeMSIStreamName encodes a logical stream name into the on-disk CFB name.
// When table is true the 0x4840 table-prefix code unit is prepended (table
// data streams, _StringPool, _StringData, ...); when false the name is
// pair-packed without the prefix (cabinet and Binary/Icon data streams).
// Names beginning with \x05 (control streams such as \x05SummaryInformation)
// are returned verbatim. The empty name encodes to the empty string; callers
// should reject it via validateMSIStreamName before writing.
func encodeMSIStreamName(table bool, name string) string {
	if name == "" {
		return ""
	}
	if name[0] == 5 {
		// \x05SummaryInformation, \x05DigitalSignature, etc. are stored literally.
		return name
	}
	var b strings.Builder
	if table {
		b.WriteRune(msiNameTablePrefix)
	}
	rs := []rune(name)
	for i := 0; i < len(rs); {
		v1 := msiB64Value(rs[i])
		if v1 < 0 {
			// Raw passthrough; pairing never spans a non-encodable rune.
			b.WriteRune(rs[i])
			i++
			continue
		}
		if i+1 < len(rs) {
			if v2 := msiB64Value(rs[i+1]); v2 >= 0 {
				b.WriteRune(rune(msiNamePairBase + v1 + v2<<6))
				i += 2
				continue
			}
		}
		b.WriteRune(rune(msiNameSingleBase + v1))
		i++
	}
	return b.String()
}

// decodeMSIStreamName is the exact inverse of encodeMSIStreamName: a leading
// 0x4840 unit marks (and is stripped from) a table stream, units in
// 0x3800-0x47FF expand to two alphabet characters (first char in the low 6
// bits), units in 0x4800-0x483F expand to one, and everything else — including
// a NON-leading 0x4840 and the \x05-prefixed control-stream names — passes
// through unchanged.
func decodeMSIStreamName(encoded string) (name string, isTable bool) {
	rest := encoded
	if r, size := utf8.DecodeRuneInString(encoded); r == msiNameTablePrefix {
		isTable = true
		rest = encoded[size:]
	}
	var b strings.Builder
	for _, r := range rest {
		switch {
		case r >= msiNamePairBase && r < msiNameSingleBase:
			v := int(r) - msiNamePairBase
			b.WriteRune(msiB64Rune(v & 0x3F))
			b.WriteRune(msiB64Rune((v >> 6) & 0x3F))
		case r >= msiNameSingleBase && r < msiNameSingleBase+64:
			b.WriteRune(msiB64Rune(int(r) - msiNameSingleBase))
		default:
			b.WriteRune(r)
		}
	}
	return b.String(), isTable
}

// validateMSIStreamName reports whether name may be written as a CFB stream
// name. It rejects empty names, names whose encoded form (including the table
// prefix) exceeds 31 UTF-16 code units, names containing the CFB-illegal
// characters '/', '\', ':' or '!' (the alphabet never produces them, but raw
// passthrough could), and non-table names whose first rune is U+4840 (they
// would be misread as table streams). \x05-prefixed control-stream names are
// exempt from everything except the length limit.
func validateMSIStreamName(table bool, name string) error {
	if name == "" {
		return errMSIStreamNameEmpty
	}
	if name[0] == 5 {
		if msiUTF16Len(name) > msiMaxEncodedNameUnits {
			return errMSIStreamNameTooLong
		}
		return nil
	}
	if !table {
		if r, _ := utf8.DecodeRuneInString(name); r == msiNameTablePrefix {
			return fmt.Errorf("msix: non-table msi stream name %q starts with U+4840 and would be misread as a table stream", name)
		}
	}
	for _, r := range name {
		switch r {
		case '/', '\\', ':', '!':
			return fmt.Errorf("msix: msi stream name %q contains CFB-illegal character %q", name, r)
		}
	}
	if msiUTF16Len(encodeMSIStreamName(table, name)) > msiMaxEncodedNameUnits {
		return errMSIStreamNameTooLong
	}
	return nil
}

// msiUTF16Len returns the number of UTF-16 code units needed to represent s
// (runes above the BMP count as a surrogate pair).
func msiUTF16Len(s string) int {
	n := 0
	for _, r := range s {
		n++
		if r > 0xFFFF {
			n++
		}
	}
	return n
}

// encodeMSITableName encodes a table stream name (back-compat wrapper for
// encodeMSIStreamName(true, name)).
func encodeMSITableName(name string) string {
	return encodeMSIStreamName(true, name)
}

// decodeMSITableName decodes an encoded stream name, dropping the table flag
// (back-compat wrapper for decodeMSIStreamName).
func decodeMSITableName(encoded string) string {
	name, _ := decodeMSIStreamName(encoded)
	return name
}
