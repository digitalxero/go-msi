package msi

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"os"

	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

// These ASN.1/PFX helpers are duplicated from the go-msix package so go-msi is a
// fully standalone module with no dependency on go-msix (full separation of
// concerns). They are the small shared Authenticode primitives the MSI signer
// needs; the MSI-specific SignedData structures live in authenticode_cms.go.

// oidSpcIndirectData: 1.3.6.1.4.1.311.2.1.4
var oidSpcIndirectData = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}

// oidSHA256: 2.16.840.1.101.3.4.2.1
var oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

// oidSpcSipInfo: 1.3.6.1.4.1.311.2.1.30
var oidSpcSipInfo = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 30}

// digestInfo holds the algorithm and digest value for SpcIndirectDataContent.
type digestInfo struct {
	Algorithm algorithmIdentifier
	Digest    []byte
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// LoadPFX loads a PFX/P12 file and returns the certificate, private key, and any
// chain certificates.
func LoadPFX(path string, password string) (*x509.Certificate, crypto.Signer, []*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("msi: reading PFX: %w", err)
	}
	key, cert, chain, err := gopkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("msi: decoding PFX: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, nil, fmt.Errorf("msi: PFX private key does not implement crypto.Signer")
	}
	return cert, signer, chain, nil
}
