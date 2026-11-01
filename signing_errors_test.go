package msi_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	msi "go.digitalxero.dev/go-msi"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func signingCertificate(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(28), Subject: pkix.Name{CommonName: "Signing classification"},
		NotBefore:   time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:    time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

func requireSigningFailure(t *testing.T, err error) *msi.SigningError {
	t.Helper()
	require.Error(t, err)
	var signing *msi.SigningError
	require.ErrorAs(t, fmt.Errorf("consumer: %w", err), &signing)
	require.NotNil(t, signing.Unwrap())
	assert.ErrorIs(t, err, signing.Unwrap())
	return signing
}

func requireNotSigningFailure(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	var signing *msi.SigningError
	assert.False(t, errors.As(err, &signing))
}

func TestSigningErrorTimestampHTTP500WithPFX(t *testing.T) {
	cert, key := signingCertificate(t)
	pfx, err := pkcs12.Modern.Encode(key, cert, nil, "password")
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "signer.pfx")
	require.NoError(t, os.WriteFile(path, pfx, 0o600))
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/timestamp-query", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	signer, err := msi.NewSigner().WithPFX(path, "password").WithTimestampURL(server.URL).Build()
	require.NoError(t, err)
	pkg, err := authoringPackage("payload").WithSigner(signer).Build()
	require.NoError(t, err)
	var out bytes.Buffer
	requireSigningFailure(t, pkg.WriteMSI(&out))
	assert.EqualValues(t, 1, requests.Load())
	assert.Empty(t, out.Bytes())
}

type signingRoundTripper func(*http.Request) (*http.Response, error)

func (f signingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type signingErrorReader struct{ cause error }

func (r signingErrorReader) Read([]byte) (int, error) { return 0, r.cause }

func TestSigningErrorPreservesTimestampCauses(t *testing.T) {
	cert, key := signingCertificate(t)
	cause := errors.New("timestamp transport failed")
	client := &http.Client{Transport: signingRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, cause
	})}
	signer, err := msi.NewSigner().WithCertificate(cert, key, nil).
		WithTimestampURL("https://timestamp.invalid").WithHTTPClient(client).Build()
	require.NoError(t, err)
	pkg, err := authoringPackage("payload").WithSigner(signer).Build()
	require.NoError(t, err)
	err = pkg.WriteMSI(io.Discard)
	signing := requireSigningFailure(t, err)
	assert.ErrorIs(t, err, cause)
	assert.ErrorIs(t, signing.Unwrap(), cause)
	var requestError *url.Error
	require.ErrorAs(t, err, &requestError)
	assert.Same(t, cause, requestError.Err)

	// A parse failure also retains its concrete underlying ASN.1 error type.
	client.Transport = signingRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte{0x30}))}, nil
	})
	err = pkg.WriteMSI(io.Discard)
	requireSigningFailure(t, err)
	var syntaxError asn1.SyntaxError
	assert.ErrorAs(t, err, &syntaxError)

	client.Transport = signingRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(signingErrorReader{cause: io.ErrUnexpectedEOF})}, nil
	})
	err = pkg.WriteMSI(io.Discard)
	requireSigningFailure(t, err)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

type classificationKey struct {
	crypto.Signer
	cause error
	calls int
}

func (k *classificationKey) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	k.calls++
	if k.cause != nil {
		return nil, k.cause
	}
	return k.Signer.Sign(r, digest, opts)
}

func TestSigningErrorPreservesPrivateKeyCause(t *testing.T) {
	cert, key := signingCertificate(t)
	cause := errors.New("private key unavailable")
	failing := &classificationKey{Signer: key, cause: cause}
	signer, err := msi.NewSigner().WithCertificate(cert, failing, nil).Build()
	require.NoError(t, err)
	pkg, err := authoringPackage("payload").WithSigner(signer).Build()
	require.NoError(t, err)
	err = pkg.WriteMSI(io.Discard)
	requireSigningFailure(t, err)
	assert.ErrorIs(t, err, cause)
	assert.Equal(t, 1, failing.calls)
}

type classificationWriter struct {
	cause error
	calls int
}

func (w *classificationWriter) Write([]byte) (int, error) {
	w.calls++
	return 0, w.cause
}

func TestSigningErrorExcludesOutputWriter(t *testing.T) {
	for _, signed := range []bool{false, true} {
		t.Run(fmt.Sprintf("signed=%v", signed), func(t *testing.T) {
			builder := authoringPackage("payload")
			cert, key := signingCertificate(t)
			tracked := &classificationKey{Signer: key}
			if signed {
				signer, err := msi.NewSigner().WithCertificate(cert, tracked, nil).Build()
				require.NoError(t, err)
				builder.WithSigner(signer)
			}
			pkg, err := builder.Build()
			require.NoError(t, err)
			cause := errors.New("output unavailable")
			writer := &classificationWriter{cause: cause}
			err = pkg.WriteMSI(writer)
			requireNotSigningFailure(t, err)
			assert.ErrorIs(t, err, cause)
			assert.Positive(t, writer.calls)
			if signed {
				assert.Equal(t, 1, tracked.calls, "signing succeeded before destination failed")
			}
		})
	}
}

func TestSigningErrorExcludesPayloadSources(t *testing.T) {
	cert, key := signingCertificate(t)
	tracked := &classificationKey{Signer: key}
	signer, err := msi.NewSigner().WithCertificate(cert, tracked, nil).Build()
	require.NoError(t, err)
	cause := errors.New("payload unavailable")
	for _, binary := range []bool{false, true} {
		t.Run(fmt.Sprintf("binary=%v", binary), func(t *testing.T) {
			builder := authoringPackage("payload").WithSigner(signer)
			source := msi.FileSourceFromOpener(func() (io.ReadCloser, error) { return nil, cause }, 10)
			if binary {
				builder.Binary("Failing", source)
			} else {
				builder.Directory("INSTALLFOLDER").Component("Failing").AssociateToFeature("Main").WithFile("failing.txt", source)
			}
			pkg, err := builder.Build()
			require.NoError(t, err)
			var out bytes.Buffer
			err = pkg.WriteMSI(&out)
			requireNotSigningFailure(t, err)
			assert.ErrorIs(t, err, cause)
			assert.Empty(t, out.Bytes())
			assert.Zero(t, tracked.calls)
		})
	}
}

func TestSigningErrorExcludesSummarySerialization(t *testing.T) {
	cert, key := signingCertificate(t)
	tracked := &classificationKey{Signer: key}
	signer, err := msi.NewSigner().WithCertificate(cert, tracked, nil).Build()
	require.NoError(t, err)
	pkg, err := authoringPackage("payload").WithProductName("Unsupported \U0001F600").WithSigner(signer).Build()
	require.NoError(t, err)
	var out bytes.Buffer
	requireNotSigningFailure(t, pkg.WriteMSI(&out))
	assert.Empty(t, out.Bytes())
	assert.Zero(t, tracked.calls)
}

func TestSigningPreservesPackageCodeAndSignature(t *testing.T) {
	unsigned, unsignedDB := authoredBytes(t, authoringPackage("payload"))
	cert, key := signingCertificate(t)
	signer, err := msi.NewSigner().WithCertificate(cert, key, nil).Build()
	require.NoError(t, err)
	signed, signedDB := authoredBytes(t, authoringPackage("payload").WithSigner(signer))
	assert.NotEqual(t, unsigned, signed)
	assert.Equal(t, unsignedDB.Summary().Revision(), signedDB.Summary().Revision())
	verified, err := msi.Verify(bytes.NewReader(signed))
	require.NoError(t, err)
	assert.True(t, cert.Equal(verified.Certificate()))
}
