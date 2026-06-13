package msi

// Internal tests (package msix) because the summary writer is unexported.

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// summaryGoldenHex is the spec's worked example: properties
// {1:1252, 2:"Installation Database", 7:"x64;1033",
// 9:"{907E4F96-D667-4404-AB6E-031891D03136}", 14:200, 15:2}
// serialized to a 228-byte stream with cbSection = 0xB4.
const summaryGoldenHex = "" +
	"feff0000050002000000000000000000" + // 0x00
	"000000000000000001000000e0859ff2" + // 0x10
	"f94f6810ab9108002b27b3d930000000" + // 0x20
	"b4000000060000000100000038000000" + // 0x30
	"02000000400000000700000060000000" + // 0x40
	"09000000740000000e000000a4000000" + // 0x50
	"0f000000ac00000002000000e4040000" + // 0x60
	"1e00000016000000496e7374616c6c61" + // 0x70
	"74696f6e204461746162617365000000" + // 0x80
	"1e000000090000007836343b31303333" + // 0x90
	"000000001e000000270000007b393037" + // 0xA0
	"45344639362d443636372d343430342d" + // 0xB0
	"414236452d3033313839314430333133" + // 0xC0
	"367d000003000000c800000003000000" + // 0xD0
	"02000000" //                          0xE0

func summaryGoldenInfo() msiSummaryInfo {
	return msiSummaryInfo{
		Codepage:       1252,
		Title:          "Installation Database",
		Template:       "x64;1033",
		RevisionNumber: "{907E4F96-D667-4404-AB6E-031891D03136}",
		PageCount:      200,
		WordCount:      2,
	}
}

func TestMSISummaryGoldenWorkedExample(t *testing.T) {
	golden, err := hex.DecodeString(summaryGoldenHex)
	require.NoError(t, err)
	require.Len(t, golden, 228, "spec worked example must be 228 bytes")

	data, err := buildMSISummaryStream(summaryGoldenInfo())
	require.NoError(t, err)
	assert.Equal(t, golden, data, "stream must match the spec worked example byte for byte")
}

func TestMSISummaryHeaderFields(t *testing.T) {
	data, err := buildMSISummaryStream(summaryGoldenInfo())
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(data), 56)

	// PropertySetStream header.
	assert.Equal(t, []byte{0xFE, 0xFF}, data[0:2], "wByteOrder")
	assert.Equal(t, []byte{0x00, 0x00}, data[2:4], "wFormat")
	assert.Equal(t, uint32(0x00020005), binary.LittleEndian.Uint32(data[4:8]), "dwOSVer")
	assert.Equal(t, make([]byte, 16), data[8:24], "clsID must be all zero")
	assert.Equal(t, uint32(1), binary.LittleEndian.Uint32(data[24:28]), "NumPropertySets")

	// FMTID_SummaryInformation in GUID wire order, then the section offset.
	wantFmtID := []byte{
		0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10,
		0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9,
	}
	assert.Equal(t, wantFmtID, data[28:44], "FMTID")
	assert.Equal(t, uint32(48), binary.LittleEndian.Uint32(data[44:48]), "section offset")
}

func TestMSISummarySectionLayout(t *testing.T) {
	data, err := buildMSISummaryStream(summaryGoldenInfo())
	require.NoError(t, err)

	section := data[48:]
	assert.Equal(t, uint32(0xB4), binary.LittleEndian.Uint32(section[0:4]), "cbSection")
	assert.Equal(t, uint32(len(data)-48), binary.LittleEndian.Uint32(section[0:4]), "cbSection covers the whole section")
	assert.Equal(t, uint32(6), binary.LittleEndian.Uint32(section[4:8]), "cProperties")

	// PID/offset table: ascending PIDs, offsets relative to the section start.
	wantTable := []struct{ pid, off uint32 }{
		{1, 0x38}, {2, 0x40}, {7, 0x60}, {9, 0x74}, {14, 0xA4}, {15, 0xAC},
	}
	for i, want := range wantTable {
		pid := binary.LittleEndian.Uint32(section[8+8*i:])
		off := binary.LittleEndian.Uint32(section[12+8*i:])
		assert.Equal(t, want.pid, pid, "table entry %d PID", i)
		assert.Equal(t, want.off, off, "table entry %d offset", i)
	}

	// Codepage: VT_I2 with the high word zero-padded (MS-OLEPS normative form).
	assert.Equal(t, []byte{0x02, 0x00, 0x00, 0x00, 0xE4, 0x04, 0x00, 0x00}, section[0x38:0x40], "PID 1 VT_I2 1252")

	// Title: VT_LPSTR, cb includes the NUL but not the padding, padded to 4.
	assert.Equal(t, uint32(30), binary.LittleEndian.Uint32(section[0x40:0x44]), "PID 2 type tag")
	assert.Equal(t, uint32(22), binary.LittleEndian.Uint32(section[0x44:0x48]), "PID 2 cb = len + NUL")
	assert.Equal(t, []byte("Installation Database\x00\x00\x00"), section[0x48:0x60], "PID 2 bytes, NUL, 2 pad bytes")

	// Template: 9-byte payload padded with 3 zero bytes.
	assert.Equal(t, uint32(9), binary.LittleEndian.Uint32(section[0x64:0x68]), "PID 7 cb")
	assert.Equal(t, []byte("x64;1033\x00\x00\x00\x00"), section[0x68:0x74], "PID 7 bytes, NUL, 3 pad bytes")

	// RevisionNumber: 39-byte payload padded with 1 zero byte.
	assert.Equal(t, uint32(39), binary.LittleEndian.Uint32(section[0x78:0x7C]), "PID 9 cb")
	assert.Equal(t, []byte("{907E4F96-D667-4404-AB6E-031891D03136}\x00\x00"), section[0x7C:0xA4], "PID 9 bytes, NUL, 1 pad byte")

	// PageCount and WordCount: VT_I4.
	assert.Equal(t, []byte{0x03, 0x00, 0x00, 0x00, 0xC8, 0x00, 0x00, 0x00}, section[0xA4:0xAC], "PID 14 VT_I4 200")
	assert.Equal(t, []byte{0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}, section[0xAC:0xB4], "PID 15 VT_I4 2")
}

func TestMSISummaryRoundtripFull(t *testing.T) {
	info := msiSummaryInfo{
		Codepage:       1252,
		Title:          "Installation Database",
		Subject:        "Test Product",
		Author:         "Test Manufacturer",
		Keywords:       "Installer",
		Comments:       "This installer database contains the logic and data required to install Test Product.",
		Template:       "x64;1033",
		RevisionNumber: "{907E4F96-D667-4404-AB6E-031891D03136}",
		CreatingApp:    "go-msix 1.0",
		CreateTime:     time.Date(2026, 6, 11, 12, 34, 56, 7_891_200, time.UTC),
		SaveTime:       time.Date(2026, 6, 11, 13, 0, 0, 0, time.UTC),
		PageCount:      200,
		WordCount:      2,
		Security:       2,
	}

	data, err := buildMSISummaryStream(info)
	require.NoError(t, err)

	parsed, err := parseMSISummaryStream(data)
	require.NoError(t, err)

	assert.Equal(t, info.Codepage, parsed.Codepage)
	assert.Equal(t, info.Title, parsed.Title)
	assert.Equal(t, info.Subject, parsed.Subject)
	assert.Equal(t, info.Author, parsed.Author)
	assert.Equal(t, info.Keywords, parsed.Keywords)
	assert.Equal(t, info.Comments, parsed.Comments)
	assert.Equal(t, info.Template, parsed.Template)
	assert.Equal(t, info.RevisionNumber, parsed.RevisionNumber)
	assert.Equal(t, info.CreatingApp, parsed.CreatingApp)
	assert.True(t, info.CreateTime.Equal(parsed.CreateTime), "CreateTime: want %s, got %s", info.CreateTime, parsed.CreateTime)
	assert.True(t, info.SaveTime.Equal(parsed.SaveTime), "SaveTime: want %s, got %s", info.SaveTime, parsed.SaveTime)
	assert.Equal(t, info.PageCount, parsed.PageCount)
	assert.Equal(t, info.WordCount, parsed.WordCount)
	assert.Equal(t, info.Security, parsed.Security)
}

func TestMSISummaryRoundtripMinimal(t *testing.T) {
	info := msiSummaryInfo{
		Template:       "Intel;1033",
		RevisionNumber: "{12345678-1234-1234-1234-123456789ABC}",
		PageCount:      200,
		WordCount:      2,
	}

	data, err := buildMSISummaryStream(info)
	require.NoError(t, err)

	parsed, err := parseMSISummaryStream(data)
	require.NoError(t, err)

	// The codepage is always emitted, defaulting to 1252.
	assert.Equal(t, 1252, parsed.Codepage)
	assert.Equal(t, info.Template, parsed.Template)
	assert.Equal(t, info.RevisionNumber, parsed.RevisionNumber)
	assert.Equal(t, info.PageCount, parsed.PageCount)
	assert.Equal(t, info.WordCount, parsed.WordCount)

	// Optional zero-valued properties are omitted entirely.
	assert.Empty(t, parsed.Title)
	assert.Empty(t, parsed.Subject)
	assert.Empty(t, parsed.Author)
	assert.Empty(t, parsed.Keywords)
	assert.Empty(t, parsed.Comments)
	assert.Empty(t, parsed.CreatingApp)
	assert.True(t, parsed.CreateTime.IsZero())
	assert.True(t, parsed.SaveTime.IsZero())
	assert.Zero(t, parsed.Security)

	// Exactly 5 properties on disk: codepage + the 4 REQUIRED ones.
	assert.Equal(t, uint32(5), binary.LittleEndian.Uint32(data[52:56]), "cProperties")
}

func TestMSISummaryRequiredEmittedEvenWhenZero(t *testing.T) {
	// Template, RevisionNumber, PageCount and WordCount are REQUIRED and must
	// be present even with zero values.
	data, err := buildMSISummaryStream(msiSummaryInfo{})
	require.NoError(t, err)

	assert.Equal(t, uint32(5), binary.LittleEndian.Uint32(data[52:56]), "cProperties")

	section := data[48:]
	pids := make([]uint32, 5)
	for i := range pids {
		pids[i] = binary.LittleEndian.Uint32(section[8+8*i:])
	}
	assert.Equal(t, []uint32{1, 7, 9, 14, 15}, pids, "codepage first, then the REQUIRED PIDs, ascending")
}

func TestMSISummaryDeterminism(t *testing.T) {
	info := msiSummaryInfo{
		Title:          "Installation Database",
		Subject:        "Product",
		Author:         "Manufacturer",
		Template:       "x64;1033",
		RevisionNumber: "{907E4F96-D667-4404-AB6E-031891D03136}",
		CreateTime:     time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		SaveTime:       time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		PageCount:      200,
		WordCount:      2,
		Security:       2,
	}

	first, err := buildMSISummaryStream(info)
	require.NoError(t, err)

	for i := 0; i < 10; i++ {
		next, err := buildMSISummaryStream(info)
		require.NoError(t, err)
		require.Equal(t, first, next, "identical info must serialize to identical bytes")
	}
}

func TestMSISummaryFiletimeVectors(t *testing.T) {
	vectors := []struct {
		name string
		t    time.Time
		ft   uint64
	}{
		{"FILETIME epoch", time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC), 0},
		{"Unix epoch", time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC), 116444736000000000},
		{"Y2K", time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), 125911584000000000},
		{"with 100ns fraction", time.Date(2000, 1, 1, 0, 0, 0, 100, time.UTC), 125911584000000001},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			assert.Equal(t, v.ft, msiFiletimeFromTime(v.t), "msiFiletimeFromTime")
			assert.True(t, msiFiletimeToTime(v.ft).Equal(v.t), "msiFiletimeToTime: want %s, got %s", v.t, msiFiletimeToTime(v.ft))
		})
	}
}

func TestMSISummaryFiletimeEncoding(t *testing.T) {
	// VT_FILETIME on disk: type tag 64, then u64 little-endian.
	val := encodeMSISummaryFiletime(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	require.Len(t, val, 12)
	assert.Equal(t, uint32(64), binary.LittleEndian.Uint32(val[0:4]), "type tag")
	assert.Equal(t, uint64(125911584000000000), binary.LittleEndian.Uint64(val[4:12]), "FILETIME value")
}

func TestMSISummaryBuildErrors(t *testing.T) {
	valid := summaryGoldenInfo()

	t.Run("non-ASCII string", func(t *testing.T) {
		info := valid
		info.Author = "Müller GmbH"
		_, err := buildMSISummaryStream(info)
		assert.Error(t, err)
	})

	t.Run("NUL in string", func(t *testing.T) {
		info := valid
		info.Title = "bad\x00title"
		_, err := buildMSISummaryStream(info)
		assert.Error(t, err)
	})

	t.Run("codepage out of range", func(t *testing.T) {
		info := valid
		info.Codepage = 70000
		_, err := buildMSISummaryStream(info)
		assert.Error(t, err)

		info.Codepage = -1
		_, err = buildMSISummaryStream(info)
		assert.Error(t, err)
	})

	t.Run("time before FILETIME epoch", func(t *testing.T) {
		info := valid
		info.CreateTime = time.Date(1600, 12, 31, 23, 59, 59, 0, time.UTC)
		_, err := buildMSISummaryStream(info)
		assert.Error(t, err)
	})

	t.Run("int32 overflow", func(t *testing.T) {
		overflow := int64(math.MaxInt32) + 1
		if int64(int(overflow)) != overflow {
			t.Skip("int is 32 bits on this platform; overflow is unrepresentable")
		}
		info := valid
		info.PageCount = int(overflow)
		_, err := buildMSISummaryStream(info)
		assert.Error(t, err)
	})
}

func TestMSISummaryParseErrors(t *testing.T) {
	golden, err := hex.DecodeString(summaryGoldenHex)
	require.NoError(t, err)

	t.Run("too short", func(t *testing.T) {
		_, err := parseMSISummaryStream(golden[:40])
		assert.Error(t, err)
	})

	t.Run("bad byte-order mark", func(t *testing.T) {
		data := append([]byte(nil), golden...)
		data[0] = 0xFF
		data[1] = 0xFE
		_, err := parseMSISummaryStream(data)
		assert.Error(t, err)
	})

	t.Run("bad FMTID", func(t *testing.T) {
		data := append([]byte(nil), golden...)
		data[28] ^= 0xFF
		_, err := parseMSISummaryStream(data)
		assert.Error(t, err)
	})

	t.Run("section offset out of range", func(t *testing.T) {
		data := append([]byte(nil), golden...)
		binary.LittleEndian.PutUint32(data[44:48], uint32(len(data)))
		_, err := parseMSISummaryStream(data)
		assert.Error(t, err)
	})

	t.Run("property table truncated", func(t *testing.T) {
		data := append([]byte(nil), golden...)
		binary.LittleEndian.PutUint32(data[52:56], 1000)
		_, err := parseMSISummaryStream(data)
		assert.Error(t, err)
	})

	t.Run("value offset out of range", func(t *testing.T) {
		data := append([]byte(nil), golden...)
		// First table entry's offset (PID 1) at stream offset 60.
		binary.LittleEndian.PutUint32(data[60:64], uint32(len(data)))
		_, err := parseMSISummaryStream(data)
		assert.Error(t, err)
	})

	t.Run("string value truncated", func(t *testing.T) {
		data := append([]byte(nil), golden...)
		// Title cb field lives at section offset 0x44 (stream offset 48+0x44).
		binary.LittleEndian.PutUint32(data[48+0x44:], 10000)
		_, err := parseMSISummaryStream(data)
		assert.Error(t, err)
	})
}

func TestMSISummaryParseTolerance(t *testing.T) {
	t.Run("unknown PID skipped", func(t *testing.T) {
		data, err := buildMSISummaryStream(summaryGoldenInfo())
		require.NoError(t, err)

		// Rewrite the Title table entry's PID (stream offset 64) to an
		// unknown one; the value stays valid so parsing must continue.
		binary.LittleEndian.PutUint32(data[64:68], 99)

		parsed, err := parseMSISummaryStream(data)
		require.NoError(t, err)
		assert.Empty(t, parsed.Title, "renamed property must not populate Title")
		assert.Equal(t, "x64;1033", parsed.Template, "later properties still parsed")
		assert.Equal(t, 200, parsed.PageCount)
	})

	t.Run("unknown variant type skipped", func(t *testing.T) {
		data, err := buildMSISummaryStream(summaryGoldenInfo())
		require.NoError(t, err)

		// Rewrite the codepage value's type tag (section offset 0x38) to an
		// unknown variant type.
		binary.LittleEndian.PutUint32(data[48+0x38:], 0x1F)

		parsed, err := parseMSISummaryStream(data)
		require.NoError(t, err)
		assert.Zero(t, parsed.Codepage, "unknown type must not populate Codepage")
		assert.Equal(t, "Installation Database", parsed.Title, "later properties still parsed")
	})

	t.Run("type mismatch for known PID skipped", func(t *testing.T) {
		data, err := buildMSISummaryStream(summaryGoldenInfo())
		require.NoError(t, err)

		// Point the PageCount table entry's value offset (stream offset 92)
		// at the Title string value: a VT_LPSTR where VT_I4 is expected.
		binary.LittleEndian.PutUint32(data[92:96], 0x40)

		parsed, err := parseMSISummaryStream(data)
		require.NoError(t, err)
		assert.Zero(t, parsed.PageCount, "mismatched type must not populate PageCount")
		assert.Equal(t, 2, parsed.WordCount, "later properties still parsed")
	})
}
