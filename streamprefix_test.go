package msi

// msi_streamprefix_test.go
// Golden-vector and roundtrip tests for the MSI stream-name encoding.
// The expected code units below are the verified vectors from Wine
// (table.c encode_streamname) / rust-msi (streamname.rs tests).
// These are internal tests (package msix) because the helpers are unexported.

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// utf16String converts expected UTF-16 code units into the equivalent Go string.
func utf16String(units []uint16) string {
	return string(utf16.Decode(units))
}

func TestEncodeMSIStreamName_GoldenVectors(t *testing.T) {
	cases := []struct {
		name  string
		table bool
		units []uint16
	}{
		{"_Tables", true, []uint16{0x4840, 0x3F7F, 0x4164, 0x422F, 0x4836}},
		{"_Columns", true, []uint16{0x4840, 0x3B3F, 0x43F2, 0x4438, 0x45B1}},
		{"_StringPool", true, []uint16{0x4840, 0x3F3F, 0x4577, 0x446C, 0x3E6A, 0x44B2, 0x482F}},
		{"_StringData", true, []uint16{0x4840, 0x3F3F, 0x4577, 0x446C, 0x3B6A, 0x45E4, 0x4824}},
		{"_Validation", true, []uint16{0x4840, 0x3FFF, 0x43E4, 0x41EC, 0x45E4, 0x44AC, 0x4831}},
		{"Property", true, []uint16{0x4840, 0x4559, 0x44F2, 0x4568, 0x4737}},
		{"File", true, []uint16{0x4840, 0x430F, 0x422F}},
		{"cab1", false, []uint16{0x4126, 0x3865}},
		{"Binary.bannrbmp", false, []uint16{0x430B, 0x4131, 0x4735, 0x417E, 0x4464, 0x4571, 0x4425, 0x4833}},
		{"App.exe", false, []uint16{0x44CA, 0x47B3, 0x46E8, 0x4828}},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s_table=%v", tc.name, tc.table), func(t *testing.T) {
			want := utf16String(tc.units)
			got := encodeMSIStreamName(tc.table, tc.name)
			assert.Equal(t, want, got, "encoded code units for %q", tc.name)

			dec, isTable := decodeMSIStreamName(got)
			assert.Equal(t, tc.name, dec, "decode of encode(%q)", tc.name)
			assert.Equal(t, tc.table, isTable, "table flag for %q", tc.name)
		})
	}
}

func TestEncodeMSIStreamName_GoldenUTF8Bytes(t *testing.T) {
	// Exact UTF-8 bytes of the Go strings handed to the CFB layer (spec 1.6).
	assert.Equal(t, "\xe4\xa1\x80\xe3\xbd\xbf\xe4\x85\xa4\xe4\x88\xaf\xe4\xa0\xb6",
		encodeMSIStreamName(true, "_Tables"))
	assert.Equal(t, "\xe4\xa1\x80\xe3\xbc\xbf\xe4\x95\xb7\xe4\x91\xac\xe3\xb9\xaa\xe4\x92\xb2\xe4\xa0\xaf",
		encodeMSIStreamName(true, "_StringPool"))
	assert.Equal(t, "\xe4\xa1\x80\xe4\x95\x99\xe4\x93\xb2\xe4\x95\xa8\xe4\x9c\xb7",
		encodeMSIStreamName(true, "Property"))
	assert.Equal(t, "\xe4\xa1\x80\xe4\x8c\x8f\xe4\x88\xaf",
		encodeMSIStreamName(true, "File"))
	assert.Equal(t, "\xe4\x84\xa6\xe3\xa1\xa5",
		encodeMSIStreamName(false, "cab1"))
}

func TestMSIStreamName_Roundtrip(t *testing.T) {
	cases := []string{
		"Property",
		"InstallExecuteSequence",
		"_Tables",
		"_Columns",
		"_Validation",
		"Directory",
		"File",
		"FeatureComponents",
		"My.Table_With.Dots_123",
		"a",        // single odd char
		"ab",       // exactly one pair
		"abc",      // pair + single
		"My Table", // space is raw passthrough between encodable runs
		"a b",      // passthrough breaks pairing
		"Tab-le",   // '-' passthrough
		"naïve",    // rune >= 0x80 passthrough
		"漢字Stream", // CJK passthrough
	}
	for _, name := range cases {
		for _, table := range []bool{true, false} {
			enc := encodeMSIStreamName(table, name)
			dec, isTable := decodeMSIStreamName(enc)
			assert.Equal(t, name, dec, "roundtrip for %q (table=%v)", name, table)
			assert.Equal(t, table, isTable, "table flag for %q (table=%v)", name, table)
			if table {
				assert.True(t, strings.HasPrefix(enc, "䡀"),
					"table stream %q must carry the 0x4840 prefix", name)
			}
		}
	}

	// A name containing U+4840 roundtrips only as a TABLE stream (the prefix
	// is stripped once, the raw inner unit passes through); as a non-table
	// name the leading raw unit would be misread as the marker, which is why
	// validateMSIStreamName rejects that combination.
	enc := encodeMSIStreamName(true, "䡀InsideName")
	dec, isTable := decodeMSIStreamName(enc)
	assert.Equal(t, "䡀InsideName", dec)
	assert.True(t, isTable)
}

func TestMSIStreamName_PairPackingArithmetic(t *testing.T) {
	// Hand-checked from the spec: '_'=63, 'T'=29 -> 0x3800+63+(29<<6)=0x3F7F;
	// trailing 's'=54 -> 0x4800+54=0x4836.
	enc := encodeMSIStreamName(false, "_T")
	require.Equal(t, []rune{0x3F7F}, []rune(enc))
	enc = encodeMSIStreamName(false, "s")
	require.Equal(t, []rune{0x4836}, []rune(enc))
}

func TestMSIStreamName_SpecialStreamsBypass(t *testing.T) {
	specials := []string{
		"\x05SummaryInformation",
		"\x05DigitalSignature",
		"\x05MsiDigitalSignatureEx",
	}
	for _, name := range specials {
		// Never encoded, regardless of the table flag.
		assert.Equal(t, name, encodeMSIStreamName(false, name))
		assert.Equal(t, name, encodeMSIStreamName(true, name))
		// And they survive decode unchanged (no unit falls in 0x3800-0x483F).
		dec, isTable := decodeMSIStreamName(name)
		assert.Equal(t, name, dec)
		assert.False(t, isTable)
	}
}

func TestMSIStreamName_DecodeLenientPassthrough(t *testing.T) {
	// A raw, never-encoded ASCII name decodes to itself (all units passthrough).
	dec, isTable := decodeMSIStreamName("cab1")
	assert.Equal(t, "cab1", dec)
	assert.False(t, isTable)

	// A non-leading 0x4840 passes through verbatim; only the first unit is the marker.
	dec, isTable = decodeMSIStreamName("䡀䡀")
	assert.Equal(t, "䡀", dec)
	assert.True(t, isTable)

	// Empty input.
	dec, isTable = decodeMSIStreamName("")
	assert.Equal(t, "", dec)
	assert.False(t, isTable)
}

func TestMSIStreamName_EmptyName(t *testing.T) {
	assert.Equal(t, "", encodeMSIStreamName(true, ""))
	assert.Equal(t, "", encodeMSIStreamName(false, ""))
	assert.ErrorIs(t, validateMSIStreamName(true, ""), errMSIStreamNameEmpty)
	assert.ErrorIs(t, validateMSIStreamName(false, ""), errMSIStreamNameEmpty)
}

func TestMSIStreamName_BackCompatWrappers(t *testing.T) {
	for _, name := range []string{"Property", "_Tables", "My.Table_123"} {
		enc := encodeMSITableName(name)
		assert.Equal(t, encodeMSIStreamName(true, name), enc)
		assert.Equal(t, name, decodeMSITableName(enc))
	}
	assert.Equal(t, "\x05SummaryInformation", encodeMSITableName("\x05SummaryInformation"))
	assert.Equal(t, "\x05SummaryInformation", decodeMSITableName("\x05SummaryInformation"))
	assert.Equal(t, "", encodeMSITableName(""))
}

func TestValidateMSIStreamName_LengthLimit(t *testing.T) {
	// 60 alphabet chars = 30 pairs; + prefix = 31 units -> the table-name maximum.
	name60 := strings.Repeat("ab", 30)
	require.Len(t, name60, 60)
	assert.NoError(t, validateMSIStreamName(true, name60))
	// 61 chars = 30 pairs + 1 single + prefix = 32 units -> too long.
	assert.ErrorIs(t, validateMSIStreamName(true, name60+"c"), errMSIStreamNameTooLong)

	// Without the prefix, 62 chars = 31 units fit; 63 do not.
	name62 := strings.Repeat("ab", 31)
	require.Len(t, name62, 62)
	assert.NoError(t, validateMSIStreamName(false, name62))
	assert.ErrorIs(t, validateMSIStreamName(false, name62+"c"), errMSIStreamNameTooLong)

	// Non-BMP passthrough runes count as TWO units (surrogate pair at the CFB
	// layer): 15 emoji = 30 units + prefix = 31 ok; 16 emoji = 33 -> too long.
	emoji15 := strings.Repeat("\U0001F600", 15)
	assert.NoError(t, validateMSIStreamName(true, emoji15))
	assert.ErrorIs(t, validateMSIStreamName(true, emoji15+"\U0001F600"), errMSIStreamNameTooLong)
}

func TestValidateMSIStreamName_IllegalNames(t *testing.T) {
	// CFB-illegal characters would be raw passthrough; reject them.
	for _, bad := range []string{"a/b", "a\\b", "a:b", "a!b"} {
		assert.Error(t, validateMSIStreamName(false, bad), "name %q", bad)
		assert.Error(t, validateMSIStreamName(true, bad), "name %q", bad)
	}

	// A non-table name starting with U+4840 would be misread as a table stream.
	assert.Error(t, validateMSIStreamName(false, "䡀foo"))
	// The same leading rune is fine when the name IS a table stream.
	assert.NoError(t, validateMSIStreamName(true, "䡀foo"))

	// Specials are exempt (stored literally) but still length-limited.
	assert.NoError(t, validateMSIStreamName(false, "\x05SummaryInformation"))
	assert.ErrorIs(t,
		validateMSIStreamName(false, "\x05"+strings.Repeat("x", 31)),
		errMSIStreamNameTooLong)
}
