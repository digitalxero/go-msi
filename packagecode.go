package msi

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"sort"
)

// A fixed valid Revision removes self-reference. Every other summary property,
// including the reproducible build times, participates in package identity.
const packageCodePlaceholder = "{00000000-0000-0000-0000-000000000000}"

// packageContentCode hashes a framed, sorted manifest of the unsigned storage.
// Stream names, sizes and SHA-256 digests are framed separately, so neither
// concatenation boundaries nor renaming equal-content streams can alias.
// Signature/timestamp data is added later and deliberately excluded.
func packageContentCode(streams []msiStream, subs []msiSubStorage, external []msiStream) (string, error) {
	h := sha256.New()
	h.Write([]byte("go-msi package content v1\x00"))
	if err := hashPackageStorage(h, streams, subs, msiRootCLSID); err != nil {
		return "", err
	}
	h.Write([]byte("external cabinets\x00"))
	if err := hashPackageStorage(h, external, nil, [16]byte{}); err != nil {
		return "", err
	}
	return msiGUIDv5(msiPackageNamespaceGUID, fmt.Sprintf("package-content-v1|%x", h.Sum(nil)))
}

func hashPackageField(h hash.Hash, data []byte) {
	var size [8]byte
	binary.LittleEndian.PutUint64(size[:], uint64(len(data)))
	h.Write(size[:])
	h.Write(data)
}

func hashPackageStorage(h hash.Hash, streams []msiStream, subs []msiSubStorage, clsid [16]byte) error {
	hashPackageField(h, clsid[:])
	streams = append([]msiStream(nil), streams...)
	sort.Slice(streams, func(i, j int) bool { return streams[i].name < streams[j].name })
	for _, s := range streams {
		hashPackageField(h, []byte("stream"))
		hashPackageField(h, []byte(s.name))
		digest := sha256.New()
		var size int64
		if s.writeTo != nil {
			counter := &packageDigestWriter{Writer: digest}
			if err := s.writeTo(counter); err != nil {
				return fmt.Errorf("msi: PackageCode stream %q: %w", s.name, err)
			}
			size = counter.size
		} else {
			size = int64(len(s.data))
			digest.Write(s.data)
		}
		var length [8]byte
		binary.LittleEndian.PutUint64(length[:], uint64(size))
		hashPackageField(h, length[:])
		hashPackageField(h, digest.Sum(nil))
	}
	subs = append([]msiSubStorage(nil), subs...)
	sort.Slice(subs, func(i, j int) bool { return subs[i].name < subs[j].name })
	for _, sub := range subs {
		hashPackageField(h, []byte("storage"))
		hashPackageField(h, []byte(sub.name))
		if err := hashPackageStorage(h, sub.streams, nil, sub.clsid); err != nil {
			return err
		}
	}
	hashPackageField(h, []byte("end storage"))
	return nil
}

type packageDigestWriter struct {
	io.Writer
	size int64
}

func (w *packageDigestWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	w.size += int64(n)
	return n, err
}

type packageExternalWriter struct {
	io.WriteCloser
	digest   hash.Hash
	name     string
	receipts *[]msiStream
}

func (w *packageExternalWriter) Write(p []byte) (int, error) {
	n, err := w.WriteCloser.Write(p)
	w.digest.Write(p[:n])
	return n, err
}
func (w *packageExternalWriter) Close() error {
	if err := w.WriteCloser.Close(); err != nil {
		return err
	}
	*w.receipts = append(*w.receipts, msiStream{name: w.name, data: w.digest.Sum(nil)})
	return nil
}
