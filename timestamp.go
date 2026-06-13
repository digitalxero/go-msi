package msi

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"fmt"
	"io"
	"net/http"
)

// timestamp.go — P8 RFC3161 timestamping. The signer's encryptedDigest is hashed
// and sent to a TSA; the returned token is embedded as the unsigned attribute
// 1.3.6.1.4.1.311.3.3.1 on the SignerInfo.

// oidTimestampTokenMS is the Microsoft RFC3161 timestamp unsigned-attribute OID.
var oidTimestampTokenMS = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}

type tsMessageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

type tsRequest struct {
	Version        int
	MessageImprint tsMessageImprint
	CertReq        bool `asn1:"optional"`
}

type tsResponse struct {
	Status         asn1.RawValue
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// fetchRFC3161Token requests a timestamp over encDigest and returns the
// timeStampToken (a ContentInfo) DER.
func fetchRFC3161Token(client *http.Client, url string, encDigest []byte, hash crypto.Hash) ([]byte, error) {
	algOID, err := digestAlgorithmOID(hash)
	if err != nil {
		return nil, err
	}
	h := hash.New()
	h.Write(encDigest)
	imprint := h.Sum(nil)

	reqDER, err := asn1.Marshal(tsRequest{
		Version: 1,
		MessageImprint: tsMessageImprint{
			HashAlgorithm: algorithmIdentifier{Algorithm: algOID, Parameters: asn1NULL()},
			HashedMessage: imprint,
		},
		CertReq: true,
	})
	if err != nil {
		return nil, fmt.Errorf("msi sign: marshal TimeStampReq: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(reqDER))
	if err != nil {
		return nil, fmt.Errorf("msi sign: timestamp request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("msi sign: timestamp POST: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("msi sign: reading timestamp response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("msi sign: timestamp server returned HTTP %d", resp.StatusCode)
	}

	var tsResp tsResponse
	if _, err := asn1.Unmarshal(body, &tsResp); err != nil {
		return nil, fmt.Errorf("msi sign: parse TimeStampResp: %w", err)
	}
	if len(tsResp.TimeStampToken.FullBytes) == 0 {
		return nil, fmt.Errorf("msi sign: timestamp response carries no token (status rejected?)")
	}
	return tsResp.TimeStampToken.FullBytes, nil
}

// buildTimestampUnsignedAttrs wraps a timestamp token in the [1] IMPLICIT
// unsigned-attributes SET for embedding in a SignerInfo.
func buildTimestampUnsignedAttrs(token []byte) []byte {
	attr := mustMarshal(cmsAttribute{
		Type:   oidTimestampTokenMS,
		Values: asn1.RawValue{FullBytes: derSetRaw([][]byte{token})},
	})
	set := derSet([][]byte{attr})
	set[0] = 0xA1 // [1] IMPLICIT
	return set
}

// buildMSISignedDataTimestamped builds a SignedData and embeds an RFC3161
// timestamp token as an unsigned attribute on the SignerInfo.
func buildMSISignedDataTimestamped(p signedDataParams, client *http.Client, tsURL string) ([]byte, error) {
	embeddedAttrs, signature, sigAlg, err := computeMSISignerSignature(p)
	if err != nil {
		return nil, err
	}
	token, err := fetchRFC3161Token(client, tsURL, signature, p.hash)
	if err != nil {
		return nil, err
	}
	unsigned := buildTimestampUnsignedAttrs(token)
	return assembleMSISignedData(p, embeddedAttrs, signature, sigAlg, unsigned)
}
