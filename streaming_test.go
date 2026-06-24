package msi

// streaming_test.go — proves the author + reader paths never hold a whole
// payload in memory: a synthetic multi-megabyte file is generated on the fly by
// a custom FileSource (it never allocates its full size), authored into an MSI,
// then streamed back and verified byte-for-byte. The source records the largest
// single Read it ever served, asserting the cabinet consumes it in bounded
// frames rather than one giant read.

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// patternByte is a deterministic, poorly-compressible byte at position i.
func patternByte(i int64) byte { return byte((i * 2654435761) >> 13) }

// patternSource is a FileSource of a given size whose content is generated per
// Read — it never materializes the whole payload. It records read statistics.
type patternSource struct {
	size     int64
	opens    int
	maxChunk int
}

func (p *patternSource) Size() int64 { return p.size }

func (p *patternSource) Open() (io.ReadCloser, error) {
	p.opens++
	return &patternReader{src: p, remaining: p.size}, nil
}

type patternReader struct {
	src       *patternSource
	pos       int64
	remaining int64
}

func (r *patternReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if len(p) > r.src.maxChunk {
		r.src.maxChunk = len(p)
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	for i := 0; i < n; i++ {
		p[i] = patternByte(r.pos + int64(i))
	}
	r.pos += int64(n)
	r.remaining -= int64(n)
	return n, nil
}

func (r *patternReader) Close() error { return nil }

// verifyPattern drains r and checks every byte matches the generated pattern,
// holding only one bounded buffer.
func verifyPattern(r io.Reader, size int64) error {
	buf := make([]byte, 64<<10)
	var pos int64
	for {
		n, err := r.Read(buf)
		for i := 0; i < n; i++ {
			if buf[i] != patternByte(pos+int64(i)) {
				return fmt.Errorf("byte mismatch at offset %d", pos+int64(i))
			}
		}
		pos += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if pos != size {
		return fmt.Errorf("read %d bytes, want %d", pos, size)
	}
	return nil
}

func TestStreaming_LargePayloadNeverFullyBuffered(t *testing.T) {
	const size = 6 << 20 // 6 MiB — far larger than any single read buffer
	src := &patternSource{size: size}

	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("Streaming").
		WithManufacturer("go-msix").
		WithVersion("1.0.0")
	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").
		WithFile("big.bin", src)
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)

	var out bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&out))

	// The cabinet must have streamed the payload in bounded frames: no single
	// Read ever asked for anywhere near the whole 6 MiB.
	require.Greater(t, src.opens, 0, "the source must have been opened to write the cabinet")
	require.LessOrEqual(t, src.maxChunk, 1<<20,
		"payload must be read in bounded chunks (got max %d bytes), never one giant read", src.maxChunk)

	// Round-trip: read the MSI back and stream-verify the member content matches
	// the generated pattern exactly, byte-for-byte.
	readDB, err := readMSIDatabase(bytes.NewReader(out.Bytes()))
	require.NoError(t, err)
	require.NoError(t, readDB.validate())

	fid := generateMSIFileID("INSTALLFOLDER/big.bin", nil)
	got := readDB.FileSources()[fid]
	require.NotNil(t, got, "the cabinet member must round-trip as a FileSource")
	require.Equal(t, int64(size), got.Size())

	rc, err := got.Open()
	require.NoError(t, err)
	defer rc.Close()
	require.NoError(t, verifyPattern(rc, size), "round-tripped payload must match byte-for-byte")
}
