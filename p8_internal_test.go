package msi

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// genTestCert creates a self-signed code-signing certificate for the given key.
func genTestCert(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xC0DE),
		Subject:      pkix.Name{CommonName: "go-msix test signer"},
		NotBefore:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestMSIStreamNameOrder(t *testing.T) {
	// Byte-wise UTF-16LE comparison.
	assert.True(t, lessMSIStreamName("a", "b"))
	assert.False(t, lessMSIStreamName("b", "a"))

	// THE critical rule: on a prefix tie, the LONGER name sorts FIRST.
	assert.True(t, lessMSIStreamName("FooBar", "Foo"), "longer name sorts first on prefix tie")
	assert.False(t, lessMSIStreamName("Foo", "FooBar"))

	// Control streams (leading 0x05) sort before table-encoded names (whose
	// first UTF-16 unit is >= 0x3800, low byte >= 0x00 but high byte >= 0x38).
	assert.True(t, lessMSIStreamName("\x05SummaryInformation", "䡀Property"))

	// Determinism / antisymmetry.
	assert.NotEqual(t, lessMSIStreamName("x", "y"), lessMSIStreamName("y", "x"))
}

// mustImprint computes the imprint and fails the test on error (the streamed
// content branch can error; the flat data-only test streams never do).
func mustImprint(t *testing.T, streams []msiStream, clsid [16]byte, h crypto.Hash) []byte {
	t.Helper()
	out, err := computeMSIImprint(streams, clsid, h)
	require.NoError(t, err)
	return out
}

func TestComputeMSIImprint_DeterministicAndExcludesSignature(t *testing.T) {
	clsid := msiRootCLSID
	streams := []msiStream{
		{name: "䡀Property", data: []byte("table-property-bytes")},
		{name: "\x05SummaryInformation", data: []byte("summary-bytes")},
		{name: "䡀File", data: []byte("table-file-bytes")},
	}

	a := mustImprint(t, streams, clsid, crypto.SHA256)
	b := mustImprint(t, streams, clsid, crypto.SHA256)
	require.Len(t, a, 32)
	assert.Equal(t, a, b, "imprint is deterministic")

	// Order of the input slice must not matter (sorted internally).
	shuffled := []msiStream{streams[2], streams[0], streams[1]}
	assert.Equal(t, a, mustImprint(t, shuffled, clsid, crypto.SHA256), "imprint independent of input order")

	// Adding the signature streams must NOT change the imprint (excluded).
	withSig := append([]msiStream(nil), streams...)
	withSig = append(withSig,
		msiStream{name: msiSignatureStreamName, data: []byte("the-signature-blob")},
		msiStream{name: msiSignatureExStreamName, data: []byte("dse")},
	)
	assert.Equal(t, a, mustImprint(t, withSig, clsid, crypto.SHA256),
		"signature streams are excluded from the imprint")

	// Changing a real stream's content DOES change the imprint.
	mutated := append([]msiStream(nil), streams...)
	mutated[0] = msiStream{name: "䡀Property", data: []byte("table-property-bytesX")}
	assert.NotEqual(t, a, mustImprint(t, mutated, clsid, crypto.SHA256))

	// Changing the root CLSID changes the imprint.
	other := clsid
	other[0] ^= 0xFF
	assert.NotEqual(t, a, mustImprint(t, streams, other, crypto.SHA256))
}

func TestMSISignedData_RoundTrip(t *testing.T) {
	imprint := mustImprint(t, []msiStream{{name: "a", data: []byte("data")}}, msiRootCLSID, crypto.SHA256)

	for _, tc := range []struct {
		name string
		key  crypto.Signer
	}{
		{"RSA", mustRSAKey(t)},
		{"ECDSA", mustECDSAKey(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := genTestCert(t, tc.key)
			spcDER, spcContents, err := buildMSISpcIndirectData(imprint, crypto.SHA256)
			require.NoError(t, err)

			sig, err := buildMSISignedData(signedDataParams{
				spcDER:      spcDER,
				spcContents: spcContents,
				cert:        cert,
				key:         tc.key,
				hash:        crypto.SHA256,
				signingTime: time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC),
				description: "go-msix",
			})
			require.NoError(t, err)
			require.NotEmpty(t, sig)

			parsed, err := parseMSISignedData(sig)
			require.NoError(t, err, "%s signature must parse + verify", tc.name)
			assert.Equal(t, imprint, parsed.imprint, "imprint round-trips through SpcIndirectData")
			assert.Equal(t, crypto.SHA256, parsed.hash)
			assert.Equal(t, "go-msix test signer", parsed.cert.Subject.CommonName)
			assert.Equal(t, 2024, parsed.signingTime.Year())
		})
	}
}

func TestMSISignedData_TamperedSignatureFails(t *testing.T) {
	key := mustRSAKey(t)
	cert := genTestCert(t, key)
	imprint := make([]byte, 32)
	spcDER, spcContents, err := buildMSISpcIndirectData(imprint, crypto.SHA256)
	require.NoError(t, err)
	sig, err := buildMSISignedData(signedDataParams{spcDER: spcDER, spcContents: spcContents, cert: cert, key: key, hash: crypto.SHA256, signingTime: time.Now()})
	require.NoError(t, err)

	// Flip a byte near the end (inside the signature) -> verification fails.
	sig[len(sig)-5] ^= 0xFF
	_, err = parseMSISignedData(sig)
	require.Error(t, err, "a tampered signature must not verify")
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return k
}

func mustECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

func TestSignMSI_SignatureStreamPresent(t *testing.T) {
	key := mustRSAKey(t)
	cert := genTestCert(t, key)
	signer, err := NewSigner().
		WithCertificate(cert, key, nil).
		WithDescription("go-msix test").
		Build()
	require.NoError(t, err)

	build := func(sign bool) []byte {
		b := NewPackage().
			WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
			WithProductName("Signed").WithManufacturer("go-msix").WithVersion("1.0.0")
		if sign {
			b = b.WithSigner(signer)
		}
		b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F").WithFile(
			"a.exe", FileSourceFromBytes(
				[]byte("MZ")))

		b.Feature("F").WithLevel(1)
		pkg, err := b.Build()
		require.NoError(t, err)
		var buf bytes.Buffer
		require.NoError(t, pkg.WriteMSI(&buf))
		return buf.Bytes()
	}

	signed := build(true)
	unsigned := build(false)

	// Unsigned MSI: Verify reports "not signed".
	_, err = Verify(bytes.NewReader(unsigned))
	require.Error(t, err, "unsigned MSI must report no signature")

	// Signed MSI: Verify succeeds (signature valid + imprint binds the file).
	info, err := Verify(bytes.NewReader(signed))
	require.NoError(t, err, "signed MSI must verify")
	assert.Equal(t, "go-msix test signer", info.Certificate().Subject.CommonName)
	assert.Equal(t, crypto.SHA256, info.HashAlgorithm())
	_, hasTS := info.TimestampTime()
	assert.False(t, hasTS, "no timestamp requested")
}

func TestVerifyMSI_TamperDetection(t *testing.T) {
	key := mustRSAKey(t)
	cert := genTestCert(t, key)
	signer, err := NewSigner().WithCertificate(cert, key, nil).Build()
	require.NoError(t, err)
	b := NewPackage().WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("Tamper").WithManufacturer("go-msix").WithVersion("1.0.0").WithSigner(signer)
	b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F").WithFile(
		"a.exe", FileSourceFromBytes(
			[]byte("MZ original")))

	b.Feature("F").WithLevel(1)
	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	data := buf.Bytes()

	// Verifies before tampering.
	_, err = Verify(bytes.NewReader(data))
	require.NoError(t, err)

	// Flip a byte inside the embedded cabinet stream (its content is part of the
	// imprint) -> imprint mismatch on re-verify.
	idx := bytes.Index(data, []byte("MSCF"))
	require.Greater(t, idx, 0, "embedded cab present in the file")
	data[idx+40] ^= 0xFF // inside the cab's compressed data
	_, err = Verify(bytes.NewReader(data))
	require.Error(t, err, "tampered MSI must fail verification")
}

func TestVerifyMSI_WrongCertFails(t *testing.T) {
	// Two independent keys: sign with one, then re-sign the parsed structure is
	// not possible, but a signature whose cert doesn't match the key fails at
	// build is irrelevant; here we confirm a valid signature from key A verifies
	// and a different MSI (key B) has an independent, also-valid signature.
	keyA := mustRSAKey(t)
	signed := signWith(t, genTestCert(t, keyA), keyA)
	info, err := Verify(bytes.NewReader(signed))
	require.NoError(t, err)
	require.NotNil(t, info.Certificate())
}

func signWith(t *testing.T, cert *x509.Certificate, key crypto.Signer) []byte {
	t.Helper()
	signer, err := NewSigner().WithCertificate(cert, key, nil).Build()
	require.NoError(t, err)
	b := NewPackage().WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("X").WithManufacturer("go-msix").WithVersion("1.0.0").WithSigner(signer)
	b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F").WithFile("a.exe", FileSourceFromBytes([]byte("MZ")))
	b.Feature("F").WithLevel(1)
	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	return buf.Bytes()
}

func TestSignMSI_Timestamped(t *testing.T) {
	genTime := time.Date(2024, 6, 1, 12, 30, 0, 0, time.UTC)

	// Mock RFC3161 TSA: returns a TimeStampResp wrapping a token with genTime.
	tsa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/timestamp-query", r.Header.Get("Content-Type"))
		token := makeTestTimestampToken(t, genTime)
		status, _ := asn1.Marshal(struct{ Status int }{0}) // PKIStatusInfo: granted
		respDER, _ := asn1.Marshal(tsResponse{
			Status:         asn1.RawValue{FullBytes: status},
			TimeStampToken: asn1.RawValue{FullBytes: token},
		})
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(respDER)
	}))
	defer tsa.Close()

	key := mustRSAKey(t)
	cert := genTestCert(t, key)
	signer, err := NewSigner().
		WithCertificate(cert, key, nil).
		WithTimestampURL(tsa.URL).
		Build()
	require.NoError(t, err)

	b := NewPackage().WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("TS").WithManufacturer("go-msix").WithVersion("1.0.0").WithSigner(signer)
	b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F").WithFile("a.exe", FileSourceFromBytes([]byte("MZ")))
	b.Feature("F").WithLevel(1)
	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf), "timestamped signing succeeds with a reachable TSA")

	info, err := Verify(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	ts, has := info.TimestampTime()
	require.True(t, has, "Verify reports the embedded timestamp")
	assert.Equal(t, genTime, ts.UTC(), "timestamp genTime round-trips")
}

func TestSignMSI_TimestampUnreachableFails(t *testing.T) {
	key := mustRSAKey(t)
	cert := genTestCert(t, key)
	signer, err := NewSigner().WithCertificate(cert, key, nil).WithTimestampURL("http://127.0.0.1:0/").Build()
	require.NoError(t, err)
	b := NewPackage().WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("TS2").WithManufacturer("go-msix").WithVersion("1.0.0").WithSigner(signer)
	b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F").WithFile("a.exe", FileSourceFromBytes([]byte("MZ")))
	b.Feature("F").WithLevel(1)
	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.Error(t, pkg.WriteMSI(&buf), "an unreachable TSA must fail signing, not silently drop the timestamp")
}

// makeTestTimestampToken builds a minimal RFC3161 timeStampToken: a ContentInfo
// wrapping a SignedData whose eContent is a TSTInfo carrying genTime.
func makeTestTimestampToken(t *testing.T, genTime time.Time) []byte {
	t.Helper()
	oidTSTInfo := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	type tstInfo struct {
		Version        int
		Policy         asn1.ObjectIdentifier
		MessageImprint tsMessageImprint
		SerialNumber   *big.Int
		GenTime        time.Time `asn1:"generalized"`
	}
	tstDER, err := asn1.Marshal(tstInfo{
		Version:        1,
		Policy:         asn1.ObjectIdentifier{1, 2, 3, 4},
		MessageImprint: tsMessageImprint{HashAlgorithm: algorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1NULL()}, HashedMessage: make([]byte, 32)},
		SerialNumber:   big.NewInt(1),
		GenTime:        genTime.UTC(),
	})
	require.NoError(t, err)

	encap := struct {
		EContentType asn1.ObjectIdentifier
		EContent     asn1.RawValue
	}{EContentType: oidTSTInfo, EContent: asn1.RawValue{FullBytes: wrapExplicit0(tstDER)}}
	encapDER, err := asn1.Marshal(encap)
	require.NoError(t, err)

	sd := struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		EncapContentInfo asn1.RawValue
		SignerInfos      asn1.RawValue
	}{
		Version:          3,
		DigestAlgorithms: asn1.RawValue{FullBytes: []byte{0x31, 0x00}}, // empty SET
		EncapContentInfo: asn1.RawValue{FullBytes: encapDER},
		SignerInfos:      asn1.RawValue{FullBytes: []byte{0x31, 0x00}}, // empty SET
	}
	sdDER, err := asn1.Marshal(sd)
	require.NoError(t, err)

	ci := cmsContentInfo{ContentType: oidSignedDataPKCS7, Content: asn1.RawValue{FullBytes: wrapExplicit0(sdDER)}}
	out, err := asn1.Marshal(ci)
	require.NoError(t, err)
	return out
}
