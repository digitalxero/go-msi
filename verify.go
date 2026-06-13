package msi

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"time"

	"github.com/abemedia/go-cfb"
)

// msi_verify.go — P8 signature verification. Reads the raw compound-file streams,
// recomputes the Authenticode imprint, and verifies the \x05DigitalSignature
// SignedData against it.

// Signature describes a verified MSI Authenticode signature.
type Signature interface {
	Certificate() *x509.Certificate
	HashAlgorithm() crypto.Hash
	SigningTime() time.Time
	// TimestampTime returns the RFC3161 timestamp and whether one is present.
	TimestampTime() (time.Time, bool)
	Imprint() []byte
}

type msiSignatureInfo struct {
	p *parsedMSISignature
}

func (s *msiSignatureInfo) Certificate() *x509.Certificate { return s.p.cert }
func (s *msiSignatureInfo) HashAlgorithm() crypto.Hash     { return s.p.hash }
func (s *msiSignatureInfo) SigningTime() time.Time         { return s.p.signingTime }
func (s *msiSignatureInfo) TimestampTime() (time.Time, bool) {
	return s.p.timestamp, s.p.hasTimestamp
}
func (s *msiSignatureInfo) Imprint() []byte { return s.p.imprint }

// readMSIRawStreams returns every stream of the compound file with its RAW (as
// stored) name and bytes — including control streams. This is what the imprint
// is computed over (the names determine MSI sort order; the signature streams
// are excluded by name in computeMSIImprint).
func readMSIRawStreams(r io.ReaderAt) ([]msiStream, error) {
	reader, err := cfb.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("msi verify: opening compound file: %w", err)
	}
	var out []msiStream
	for _, e := range reader.Entries {
		st, ok := e.(*cfb.Stream)
		if !ok {
			continue
		}
		data, err := io.ReadAll(st.Open())
		if err != nil {
			return nil, fmt.Errorf("msi verify: reading stream %q: %w", st.Name, err)
		}
		out = append(out, msiStream{name: st.Name, data: data})
	}
	return out, nil
}

// readMSIRawSubStorages returns the root storage's child storages (embedded
// language transforms) with their CLSID and raw streams, for the recursive
// imprint and round-trip tests. Returns nil when there are none.
func readMSIRawSubStorages(r io.ReaderAt) ([]msiSubStorage, error) {
	reader, err := cfb.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("msi verify: opening compound file: %w", err)
	}
	var out []msiSubStorage
	for _, e := range reader.Entries {
		stg, ok := e.(*cfb.Storage)
		if !ok {
			continue
		}
		sub := msiSubStorage{name: stg.Name, clsid: stg.CLSID}
		for _, child := range stg.Entries {
			st, ok := child.(*cfb.Stream)
			if !ok {
				continue
			}
			data, err := io.ReadAll(st.Open())
			if err != nil {
				return nil, fmt.Errorf("msi verify: reading sub-storage %q stream %q: %w", stg.Name, st.Name, err)
			}
			sub.streams = append(sub.streams, msiStream{name: st.Name, data: data})
		}
		out = append(out, sub)
	}
	return out, nil
}

// Verify verifies the Authenticode signature of an MSI: it recomputes the
// imprint over the compound-file streams and confirms the embedded
// \x05DigitalSignature is cryptographically valid and signs that exact imprint.
// It returns an error if the MSI is unsigned, malformed, or the signature/imprint
// does not match. (Certificate-chain TRUST is the caller's policy; this checks
// signature integrity + imprint binding.)
func Verify(r io.ReaderAt) (Signature, error) {
	streams, err := readMSIRawStreams(r)
	if err != nil {
		return nil, err
	}

	var sigBytes []byte
	for _, s := range streams {
		if s.name == msiSignatureStreamName {
			sigBytes = s.data
			break
		}
	}
	if sigBytes == nil {
		return nil, fmt.Errorf("msi verify: the MSI is not signed (no \\x05DigitalSignature stream)")
	}

	parsed, err := parseMSISignedData(sigBytes)
	if err != nil {
		return nil, err
	}

	subs, err := readMSIRawSubStorages(r)
	if err != nil {
		return nil, err
	}

	// Recompute the imprint over the streams + embedded sub-storages (signature
	// streams excluded) and confirm it matches the imprint the signature commits
	// to.
	recomputed := computeMSIImprintWithSubStorages(streams, subs, msiRootCLSID, parsed.hash)
	if !bytesEqual(recomputed, parsed.imprint) {
		return nil, fmt.Errorf("msi verify: imprint mismatch — the MSI was modified after signing")
	}

	return &msiSignatureInfo{p: parsed}, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
