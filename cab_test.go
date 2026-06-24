package msi

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// inflateAll decodes one complete deflate stream.
func inflateAll(t *testing.T, stream []byte) []byte {
	t.Helper()
	r := flate.NewReader(bytes.NewReader(stream))
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	return out
}

// parseCabFrames walks the CFDATA records of a single-folder cab, verifies
// every checksum, inflates every MSZIP frame, and returns the concatenated
// uncompressed folder data.
func parseCabFrames(t *testing.T, cab []byte) []byte {
	t.Helper()
	require.Equal(t, "MSCF", string(cab[:4]))
	cbCabinet := binary.LittleEndian.Uint32(cab[8:])
	require.Equal(t, int(cbCabinet), len(cab), "cbCabinet must equal real file size")

	coffData := binary.LittleEndian.Uint32(cab[36:])
	cCFData := binary.LittleEndian.Uint16(cab[40:])
	compType := binary.LittleEndian.Uint16(cab[42:])
	require.Equal(t, uint16(1), compType, "MSZIP folder")

	var out []byte
	off := coffData
	for b := 0; b < int(cCFData); b++ {
		csum := binary.LittleEndian.Uint32(cab[off:])
		cbData := binary.LittleEndian.Uint16(cab[off+4:])
		cbUncomp := binary.LittleEndian.Uint16(cab[off+6:])
		ab := cab[off+8 : off+8+uint32(cbData)]

		calc := cabChecksum(cab[off+4:off+8], cabChecksum(ab, 0))
		assert.Equal(t, csum, calc, "CFDATA checksum, block %d", b)

		require.Equal(t, "CK", string(ab[:2]), "MSZIP signature, block %d", b)
		frame := inflateAll(t, ab[2:])
		require.Equal(t, int(cbUncomp), len(frame), "frame size, block %d", b)
		require.LessOrEqual(t, len(frame), msiCabBlockSize)

		out = append(out, frame...)
		off += 8 + uint32(cbData)
	}
	return out
}

func TestBuildMSICAB_RoundTrip(t *testing.T) {
	payloadA := []byte("hello cab world\n")
	payloadB := make([]byte, 70000) // all zeros: triggers the degenerate-distance case
	payloadC := make([]byte, 40000)
	for i := range payloadC {
		payloadC[i] = byte(i * 7) // repeating pattern: also degenerate-prone
	}

	cab, err := buildMSICAB([]msiCabMember{
		{name: "filA", src: FileSourceFromBytes(payloadA)},
		{name: "filB", src: FileSourceFromBytes(payloadB)},
		{name: "filC", src: FileSourceFromBytes(payloadC)},
	})
	require.NoError(t, err)

	folder := parseCabFrames(t, cab)
	want := append(append(append([]byte(nil), payloadA...), payloadB...), payloadC...)
	require.Equal(t, want, folder, "folder data must round-trip")

	// CFFILE offsets must be cumulative in member order.
	coffFiles := binary.LittleEndian.Uint32(cab[16:])
	cFiles := binary.LittleEndian.Uint16(cab[28:])
	require.Equal(t, uint16(3), cFiles)
	off := coffFiles
	wantOffsets := []uint32{0, uint32(len(payloadA)), uint32(len(payloadA) + len(payloadB))}
	for i := 0; i < int(cFiles); i++ {
		cbFile := binary.LittleEndian.Uint32(cab[off:])
		uoff := binary.LittleEndian.Uint32(cab[off+4:])
		assert.Equal(t, wantOffsets[i], uoff, "uoffFolderStart of member %d", i)
		_ = cbFile
		off += 16
		end := bytes.IndexByte(cab[off:], 0)
		off += uint32(end) + 1
	}
}

func TestBuildMSICAB_Errors(t *testing.T) {
	_, err := buildMSICAB(nil)
	assert.Error(t, err, "empty member list must error")

	_, err = buildMSICAB([]msiCabMember{{name: "", src: FileSourceFromBytes([]byte("x"))}})
	assert.Error(t, err, "empty member name must error")
}

func TestMSZIPSanitize_PassesCleanStreams(t *testing.T) {
	// Mixed text data: Go emits a healthy multi-distance dynamic block.
	data := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog. "), 100)
	var zbuf bytes.Buffer
	zw, _ := flate.NewWriter(&zbuf, flate.DefaultCompression)
	zw.Write(data)
	zw.Close()

	out, err := msiSanitizeMSZIPStream(zbuf.Bytes())
	require.NoError(t, err)
	assert.Equal(t, zbuf.Bytes(), out, "healthy streams pass through byte-identical")
	assert.Equal(t, data, inflateAll(t, out))
}

func TestMSZIPSanitize_RewritesDegenerateDistanceTables(t *testing.T) {
	cases := map[string][]byte{
		"zeros": make([]byte, 32768),
		"one-cycle": func() []byte {
			b := make([]byte, 32768)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}(),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			var zbuf bytes.Buffer
			zw, _ := flate.NewWriter(&zbuf, flate.DefaultCompression)
			zw.Write(data)
			zw.Close()

			res, err := mszipDecodeStream(zbuf.Bytes())
			require.NoError(t, err)
			require.True(t, res.degenerate, "test premise: Go emits a single-code distance table here")

			out, err := msiSanitizeMSZIPStream(zbuf.Bytes())
			require.NoError(t, err)
			assert.NotEqual(t, zbuf.Bytes(), out, "degenerate stream must be re-encoded")
			assert.Equal(t, data, inflateAll(t, out), "re-encoded stream must inflate to identical data")

			// The fixed-Huffman re-encode must not itself be degenerate.
			res2, err := mszipDecodeStream(out)
			require.NoError(t, err)
			assert.False(t, res2.degenerate)
		})
	}
}

func TestMSZIPSanitize_StoredBlocksPassThrough(t *testing.T) {
	data := []byte("incompressible-ish tiny payload")
	var zbuf bytes.Buffer
	zw, _ := flate.NewWriter(&zbuf, flate.NoCompression)
	zw.Write(data)
	zw.Close()

	out, err := msiSanitizeMSZIPStream(zbuf.Bytes())
	require.NoError(t, err)
	assert.Equal(t, zbuf.Bytes(), out)
	assert.Equal(t, data, inflateAll(t, out))
}

func TestMSZIPFixedEncode_TokenFidelity(t *testing.T) {
	// Hand-built token stream: literals, a short match, a max-length match
	// at max distance, decoded by the stdlib inflater.
	var tokens []mszipToken
	seed := []byte("abcdefgh")
	for _, c := range seed {
		tokens = append(tokens, mszipLiteral(c))
	}
	tokens = append(tokens, mszipMatch(3, 8))   // "abc"
	tokens = append(tokens, mszipMatch(258, 4)) // long overlapping match
	stream := mszipEncodeFixed(tokens)

	got := inflateAll(t, stream)
	want := append([]byte(nil), seed...)
	want = append(want, "abc"...)
	for i := 0; i < 258; i++ {
		want = append(want, want[len(want)-4])
	}
	require.Equal(t, want, got)
}
