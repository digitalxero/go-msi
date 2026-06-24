package msi

// filesource.go
// FileSource is the streaming payload abstraction that lets go-msi author and
// read MSIs without ever holding a whole payload file in memory. A source is
// SIZED (the length is known at compile time, used for the File-table size cell
// and media/cabinet planning) and RE-OPENABLE (Open may be called more than
// once: the base compile plus each embedded language transform re-compile, and
// — when signing — once to hash the embedded cabinet and again to copy it into
// the CFB). Every Open must yield the full content from the start, independent
// of any prior Open.
//
// FileSource values are stored on builder structs that clone.go deep-copies
// reflectively; interface-typed fields are shared shallowly, which is correct
// precisely because a source is re-openable and stateless across Opens.

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
)

// FileSource is a re-openable, sized source of a payload file's bytes.
type FileSource interface {
	// Size returns the exact byte length that Open yields. It must agree with
	// the content for byte-identical output (File.FileSize cell + cabinet).
	Size() int64
	// Open returns a fresh reader positioned at the start of the content.
	Open() (io.ReadCloser, error)
}

// FileSourceFromBytes wraps an in-memory payload. The slice is copied
// defensively, matching the capture-at-call-time semantics the old
// []byte-based API guaranteed.
func FileSourceFromBytes(data []byte) FileSource {
	return &bytesSource{data: append([]byte(nil), data...)}
}

// FileSourceFromPath sources content from an OS file. Size is taken via os.Stat
// at construction; each Open does os.Open. The file must remain present and
// unchanged until WriteMSI completes.
func FileSourceFromPath(path string) (FileSource, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("msi: file source %q: %w", path, err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("msi: file source %q is a directory", path)
	}
	return &pathSource{path: path, size: fi.Size()}, nil
}

// FileSourceFromFS sources content from an fs.FS entry. Size is taken via
// fs.Stat at construction; each Open does fsys.Open. The fs.FS and entry must
// remain valid until WriteMSI completes.
func FileSourceFromFS(fsys fs.FS, name string) (FileSource, error) {
	fi, err := fs.Stat(fsys, name)
	if err != nil {
		return nil, fmt.Errorf("msi: file source %q: %w", name, err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("msi: file source %q is a directory", name)
	}
	return &fsSource{fsys: fsys, name: name, size: fi.Size()}, nil
}

// FileSourceFromOpener wraps a custom re-openable reader factory of known size
// (e.g. an object-store stream). open must yield the full content from the
// start on every call.
func FileSourceFromOpener(open func() (io.ReadCloser, error), size int64) FileSource {
	return &openerSource{open: open, size: size}
}

type bytesSource struct{ data []byte }

func (b *bytesSource) Size() int64 { return int64(len(b.data)) }
func (b *bytesSource) Open() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(b.data)), nil
}

type pathSource struct {
	path string
	size int64
}

func (p *pathSource) Size() int64                  { return p.size }
func (p *pathSource) Open() (io.ReadCloser, error) { return os.Open(p.path) }

type fsSource struct {
	fsys fs.FS
	name string
	size int64
}

func (f *fsSource) Size() int64                  { return f.size }
func (f *fsSource) Open() (io.ReadCloser, error) { return f.fsys.Open(f.name) }

type openerSource struct {
	open func() (io.ReadCloser, error)
	size int64
}

func (o *openerSource) Size() int64 { return o.size }
func (o *openerSource) Open() (io.ReadCloser, error) {
	if o.open == nil {
		return nil, fmt.Errorf("msi: nil file source opener")
	}
	return o.open()
}

// readAllFromSource drains a source into a byte slice. Used by the read/patch
// fallbacks and by tests; never on the streaming author hot path.
func readAllFromSource(src FileSource) ([]byte, error) {
	rc, err := src.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// bytesMapToSources wraps an in-memory fileID->bytes map as fileID->FileSource,
// used where an already-materialized byte map (reader, patch work DB) feeds the
// source-based interface.
func bytesMapToSources(m map[string][]byte) map[string]FileSource {
	out := make(map[string]FileSource, len(m))
	for k, v := range m {
		out[k] = &bytesSource{data: v}
	}
	return out
}
