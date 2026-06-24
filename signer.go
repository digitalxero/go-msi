package msi

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"
)

// signer.go — P8 public MSI signer (Builder-IS-Implementation). Produces the
// \x05DigitalSignature stream for an MSI from a certificate + key, optionally
// RFC3161-timestamped.

// SignerBuilder configures an MSI Authenticode signer.
type SignerBuilder interface {
	WithCertificate(cert *x509.Certificate, key crypto.Signer, chain []*x509.Certificate) SignerBuilder
	WithPFX(path, password string) SignerBuilder
	WithTimestampURL(url string) SignerBuilder
	WithHTTPClient(c *http.Client) SignerBuilder
	WithHashAlgorithm(h crypto.Hash) SignerBuilder
	WithDescription(desc string) SignerBuilder
	Build() (Signer, error)
}

// Signer signs an MSI imprint, producing the \x05DigitalSignature stream bytes.
type Signer interface {
	// signImprint is internal (the package applies it during WriteMSI); the
	// interface is exported so callers can hold a built signer.
	hashAlgorithm() crypto.Hash
	signImprint(imprint []byte) ([]byte, error)
}

func NewSigner() SignerBuilder {
	return &msiSigner{hash: crypto.SHA256, httpClient: http.DefaultClient}
}

// WithSigner attaches an MSI signer to the package (opt-in).
func (p *msiPackage) WithSigner(s Signer) PackageBuilder {
	p.signer = s
	return p
}

type msiSigner struct {
	cert         *x509.Certificate
	key          crypto.Signer
	chain        []*x509.Certificate
	pfxPath      string
	pfxPassword  string
	timestampURL string
	httpClient   *http.Client
	hash         crypto.Hash
	description  string
	errs         []error
}

func (s *msiSigner) WithCertificate(cert *x509.Certificate, key crypto.Signer, chain []*x509.Certificate) SignerBuilder {
	s.cert, s.key, s.chain = cert, key, chain
	return s
}

func (s *msiSigner) WithPFX(path, password string) SignerBuilder {
	s.pfxPath, s.pfxPassword = path, password
	return s
}

func (s *msiSigner) WithTimestampURL(url string) SignerBuilder {
	s.timestampURL = url
	return s
}

func (s *msiSigner) WithHTTPClient(c *http.Client) SignerBuilder {
	s.httpClient = c
	return s
}

func (s *msiSigner) WithHashAlgorithm(h crypto.Hash) SignerBuilder {
	s.hash = h
	return s
}

func (s *msiSigner) WithDescription(desc string) SignerBuilder {
	s.description = desc
	return s
}

func (s *msiSigner) Build() (Signer, error) {
	if s.pfxPath != "" && s.cert == nil {
		cert, key, chain, err := LoadPFX(s.pfxPath, s.pfxPassword)
		if err != nil {
			return nil, err
		}
		s.cert, s.key, s.chain = cert, key, chain
	}
	if s.cert == nil || s.key == nil {
		return nil, fmt.Errorf("msi sign: a certificate and key are required (WithCertificate or WithPFX)")
	}
	if _, err := digestAlgorithmOID(s.hash); err != nil {
		return nil, err
	}
	if s.httpClient == nil {
		s.httpClient = http.DefaultClient
	}
	return s, nil
}

func (s *msiSigner) hashAlgorithm() crypto.Hash { return s.hash }

// signImprint builds the \x05DigitalSignature SignedData for the given imprint.
func (s *msiSigner) signImprint(imprint []byte) ([]byte, error) {
	spcDER, spcContents, err := buildMSISpcIndirectData(imprint, s.hash)
	if err != nil {
		return nil, err
	}
	params := signedDataParams{
		spcDER:      spcDER,
		spcContents: spcContents,
		cert:        s.cert,
		key:         s.key,
		chain:       s.chain,
		hash:        s.hash,
		signingTime: time.Now().UTC(),
		description: s.description,
	}
	if s.timestampURL != "" {
		return buildMSISignedDataTimestamped(params, s.httpClient, s.timestampURL)
	}
	return buildMSISignedData(params)
}

// msiSignStreams appends the \x05DigitalSignature stream computed over the given
// streams + any embedded sub-storages (+ recursive CLSIDs) using the signer.
// Called from the WriteMSI paths after serialization; the signature stream is
// excluded from the imprint, so adding it does not change the imprint.
func msiSignStreams(streams []msiStream, subs []msiSubStorage, signer Signer) ([]msiStream, error) {
	imprint, err := computeMSIImprintWithSubStorages(streams, subs, msiRootCLSID, signer.hashAlgorithm())
	if err != nil {
		return nil, err
	}
	sig, err := signer.(*msiSigner).signImprint(imprint)
	if err != nil {
		return nil, err
	}
	return append(streams, msiStream{name: msiSignatureStreamName, data: sig}), nil
}
