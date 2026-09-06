// Command gensignedmsi builds a self-signed-certificate-signed sample MSI for
// the external osslsigncode cross-check in scripts/verify_msi.sh. It writes
// <out>/signed.msi and <out>/signer.pem (the signing certificate, for
// `osslsigncode verify -CAfile`).
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	msix "go.digitalxero.dev/go-msi"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gensignedmsi <output-dir>")
		os.Exit(2)
	}
	outDir := os.Args[1]

	// RSA: the algorithm Windows Authenticode reliably accepts for MSI
	// signatures, so the external oracles (osslsigncode + the windows-signature
	// CI job) exercise the path real signers use. The chain is root CA -> leaf
	// because Windows chain policy rejects a self-signed CA=true leaf with
	// TRUST_E_BASIC_CONSTRAINTS ("basic constraint extension has not been
	// observed").
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	fail(err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0x90D51101),
		Subject:               pkix.Name{CommonName: "go-msix sample root CA", Organization: []string{"go-msix"}},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	fail(err)
	rootCert, err := x509.ParseCertificate(rootDER)
	fail(err)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	fail(err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0x90D51102),
		Subject:               pkix.Name{CommonName: "go-msix sample signer", Organization: []string{"go-msix"}},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, rootCert, key.Public(), rootKey)
	fail(err)
	cert, err := x509.ParseCertificate(certDER)
	fail(err)

	signer, err := msix.NewSigner().
		WithCertificate(cert, key, []*x509.Certificate{rootCert}).
		WithDescription("go-msix sample signed MSI").
		Build()
	fail(err)

	b := msix.NewPackage().
		WithProductCode("{33333333-4444-5555-6666-777777777777}").
		WithProductName("Go MSIX Signed Sample").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		WithSigner(signer)
	comp := b.RootDirectory("INSTALLFOLDER", "Go MSIX Signed Sample").
		Component("Main").AssociateToFeature("Main")
	comp.WithFile("app.exe", msix.FileSourceFromBytes([]byte("MZ signed sample payload")))
	b.Feature("Main").WithTitle("Main").WithLevel(1)

	pkg, err := b.Build()
	fail(err)

	mf, err := os.Create(filepath.Join(outDir, "signed.msi"))
	fail(err)
	defer mf.Close()
	fail(pkg.WriteMSI(mf))

	// Self-verify (pure Go) before handing off to osslsigncode.
	signed, err := os.ReadFile(filepath.Join(outDir, "signed.msi"))
	fail(err)
	if _, err := msix.Verify(bytes.NewReader(signed)); err != nil {
		fail(fmt.Errorf("pure-Go Verify failed: %w", err))
	}

	// signer.pem/signer.cer hold the ROOT: it is the trust anchor for both
	// `osslsigncode verify -CAfile` and Windows Import-Certificate; the leaf
	// and its chain travel inside the signature itself.
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	fail(os.WriteFile(filepath.Join(outDir, "signer.pem"), pemBytes, 0o644))
	fail(os.WriteFile(filepath.Join(outDir, "signer.cer"), rootDER, 0o644))

	fmt.Println("wrote signed.msi + signer.pem + signer.cer; pure-Go Verify OK")
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "gensignedmsi:", err)
		os.Exit(1)
	}
}
