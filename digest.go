package msi

import (
	"crypto"
	"fmt"
	"hash"
	"io"
	"unicode/utf16"
)

// msi_digest.go — P8 Authenticode imprint for an MSI (OLE compound file).
//
// The imprint is a single hash updated with the CONTENT bytes of every stream,
// walking storages recursively; within a storage the children are visited in
// "MSI name order", and after a storage's children its 16-byte CLSID is folded
// in. The signature streams are excluded so the signed file reproduces the same
// imprint. A flat MSI has only the root storage, so the imprint is
// hash(stream contents in MSI order) followed by the root CLSID.
//
// MSI name order (cross-checked vs osslsigncode msi.c / Mozilla relic): compare
// the raw UTF-16LE name bytes over the min length; on a prefix tie the LONGER
// name sorts FIRST. This is NOT the CFB red-black-tree collation.

// msiSignatureStreamName is the standard Authenticode signature stream; it (and
// the DSE stream) are excluded from the imprint.
const (
	msiSignatureStreamName   = "\x05DigitalSignature"
	msiSignatureExStreamName = "\x05MsiDigitalSignatureEx"
)

// utf16leName returns the UTF-16LE byte encoding of a stream name (as stored in
// the compound file directory).
func utf16leName(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// lessMSIStreamName reports whether a sorts before b in MSI name order: byte-wise
// over the UTF-16LE encodings up to the shorter length, then the LONGER name
// first on a prefix tie.
func lessMSIStreamName(a, b string) bool {
	ab := utf16leName(a)
	bb := utf16leName(b)
	n := len(ab)
	if len(bb) < n {
		n = len(bb)
	}
	for i := 0; i < n; i++ {
		if ab[i] != bb[i] {
			return ab[i] < bb[i]
		}
	}
	// Equal over the shared prefix: the longer name sorts first.
	return len(ab) > len(bb)
}

// computeMSIImprint hashes the (flat) MSI's stream contents in MSI name order,
// then folds in the root storage CLSID. The signature streams are excluded.
func computeMSIImprint(streams []msiStream, rootCLSID [16]byte, hashAlg crypto.Hash) ([]byte, error) {
	return computeMSIImprintWithSubStorages(streams, nil, rootCLSID, hashAlg)
}

// computeMSIImprintWithSubStorages computes the Authenticode MSI imprint over a
// root storage that may contain child storages (embedded language transforms).
// Within each storage, children (streams AND sub-storages) are visited in MSI
// name order; stream contents are hashed, sub-storages are recursed, and each
// storage's own 16-byte CLSID is appended after its children. The two signature
// streams are excluded. With no sub-storages this is byte-identical to the flat
// form (all stream data in name order, then the root CLSID).
func computeMSIImprintWithSubStorages(streams []msiStream, subs []msiSubStorage, rootCLSID [16]byte, hashAlg crypto.Hash) ([]byte, error) {
	h := hashAlg.New()
	if err := hashMSIStorage(h, streams, subs, rootCLSID); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// msiImprintChild is one ordered child of a storage during imprint hashing:
// either a stream (data or a streamed writeTo) or a sub-storage (sub).
type msiImprintChild struct {
	name    string
	data    []byte
	writeTo func(io.Writer) error
	sub     *msiSubStorage
}

// hashMSIStorage folds one storage's children (in MSI name order) then its CLSID
// into h. Embedded transform sub-storages do not themselves nest further.
// Streamed streams (writeTo != nil, e.g. embedded cabinets) feed the hash the
// same content bytes they write to the CFB, without buffering them whole.
func hashMSIStorage(h hash.Hash, streams []msiStream, subs []msiSubStorage, clsid [16]byte) error {
	children := make([]msiImprintChild, 0, len(streams)+len(subs))
	for _, s := range streams {
		if s.name == msiSignatureStreamName || s.name == msiSignatureExStreamName {
			continue
		}
		children = append(children, msiImprintChild{name: s.name, data: s.data, writeTo: s.writeTo})
	}
	for i := range subs {
		children = append(children, msiImprintChild{name: subs[i].name, sub: &subs[i]})
	}

	// Insertion-stable sort by MSI name order (slices are tiny; deterministic).
	for i := 1; i < len(children); i++ {
		for j := i; j > 0 && lessMSIStreamName(children[j].name, children[j-1].name); j-- {
			children[j], children[j-1] = children[j-1], children[j]
		}
	}

	for _, c := range children {
		switch {
		case c.sub != nil:
			if err := hashMSIStorage(h, c.sub.streams, nil, c.sub.clsid); err != nil {
				return err
			}
		case c.writeTo != nil:
			if err := c.writeTo(h); err != nil {
				return fmt.Errorf("msi: hashing stream %q: %w", c.name, err)
			}
		default:
			h.Write(c.data)
		}
	}
	h.Write(clsid[:])
	return nil
}
