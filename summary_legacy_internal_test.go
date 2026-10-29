package msi

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLegacySummaryCodepagesOpen(t *testing.T) {
	cases := []struct {
		cp   int
		name string
		wire []byte
	}{
		{1250, "Łódź", []byte{0xa3, 0xf3, 0x64, 0x9f}},
		{1251, "Привет", []byte{0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2}},
		{932, "日本語", []byte{0x93, 0xfa, 0x96, 0x7b, 0x8c, 0xea}},
		{936, "中文", []byte{0xd6, 0xd0, 0xce, 0xc4}},
		{949, "한국", []byte{0xc7, 0xd1, 0xb1, 0xb9}},
		{950, "中文", []byte{0xa4, 0xa4, 0xa4, 0xe5}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// An independent byte vector verifies the decoder, not only round trips.
			decoded, err := decodeSummaryString(append(tc.wire, 0), tc.cp)
			require.NoError(t, err)
			assert.Equal(t, tc.name, decoded)
			db, err := newMSIDatabaseBuilder().Build()
			require.NoError(t, err)
			streams, err := serializeMSIStreams(db, msiSummaryInfo{Codepage: tc.cp, Subject: tc.name, Author: tc.name, Template: "x64;1033"}, cabBuildOptions{})
			require.NoError(t, err)
			opened, err := Open(bytes.NewReader(writeTestCFB(t, streams)))
			require.NoError(t, err)
			assert.Equal(t, tc.name, opened.Summary().Subject())
			assert.Equal(t, tc.name, opened.Summary().Author())
		})
	}
}

func TestUnknownAndNeutralSummaryCodepageTolerance(t *testing.T) {
	for _, cp := range []uint16{0, 1234} {
		db, err := newMSIDatabaseBuilder().Build()
		require.NoError(t, err)
		streams, err := serializeMSIStreams(db, msiSummaryInfo{Codepage: 1252, Subject: "café", Template: "x64;1033"}, cabBuildOptions{})
		require.NoError(t, err)
		for i := range streams {
			if streams[i].name != msiSummaryInfoStreamName {
				continue
			}
			// PID 1 is the first authored property. Change only its code page.
			data := streams[i].data
			section := data[48:]
			off := binary.LittleEndian.Uint32(section[12:])
			binary.LittleEndian.PutUint16(section[off+4:], cp)
		}
		opened, err := Open(bytes.NewReader(writeTestCFB(t, streams)))
		require.NoError(t, err)
		assert.Equal(t, "caf\xe9", opened.Summary().Subject(), "unknown encodings preserve bytes rather than reject the package")
	}
}
