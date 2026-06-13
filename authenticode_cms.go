package msi

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"sort"
	"time"
)

// authenticode_cms.go — P8 minimal Authenticode SignedData for MSI. Hand-rolled
// because the inner ContentInfo.contentType must be SpcIndirectData (not
// pkcs7-data, which go.mozilla.org/pkcs7 hardcodes). Cross-checked against
// osslsigncode msi.c / signtool output; osslsigncode verify is the CI oracle.

// OIDs.
var (
	oidSignedDataPKCS7 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidAttrContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDig  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSpcSpOpusInfo   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}
	oidSpcStatementT   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 11}
	oidSpcIndividual   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 21}

	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECPublicKey   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// msiSipGUID is the MSI SIP GUID stored in SpcSipInfo.
var msiSipGUID = []byte{0xf1, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}

// digestAlgorithmOID maps a hash to its AlgorithmIdentifier OID.
func digestAlgorithmOID(h crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch h {
	case crypto.SHA1:
		return oidSHA1, nil
	case crypto.SHA256:
		return oidSHA256, nil
	case crypto.SHA384:
		return oidSHA384, nil
	case crypto.SHA512:
		return oidSHA512, nil
	}
	return nil, fmt.Errorf("msi sign: unsupported hash %v", h)
}

// ----- SpcIndirectDataContent (MSI) -----

type msiSpcSipInfo struct {
	Version int
	SipGUID []byte
	R1      int
	R2      int
	R3      int
	R4      int
	R5      int
}

type msiSpcAttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value msiSpcSipInfo `asn1:"tag:0,explicit"`
}

type msiSpcIndirectDataContent struct {
	Data          msiSpcAttributeTypeAndValue
	MessageDigest digestInfo
}

// buildMSISpcIndirectData returns the DER of the SpcIndirectDataContent and its
// CONTENTS octets (the bytes inside the outer SEQUENCE), over which the
// messageDigest signed attribute is computed.
func buildMSISpcIndirectData(imprint []byte, hash crypto.Hash) (der, contents []byte, err error) {
	algOID, err := digestAlgorithmOID(hash)
	if err != nil {
		return nil, nil, err
	}
	idc := msiSpcIndirectDataContent{
		Data: msiSpcAttributeTypeAndValue{
			Type:  oidSpcSipInfo,
			Value: msiSpcSipInfo{Version: 1, SipGUID: msiSipGUID},
		},
		MessageDigest: digestInfo{
			Algorithm: algorithmIdentifier{Algorithm: algOID, Parameters: asn1NULL()},
			Digest:    imprint,
		},
	}
	der, err = asn1.Marshal(idc)
	if err != nil {
		return nil, nil, fmt.Errorf("msi sign: marshal SpcIndirectData: %w", err)
	}
	// Strip the outer SEQUENCE tag+length to get the contents octets.
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil, nil, fmt.Errorf("msi sign: re-parse SpcIndirectData: %w", err)
	}
	return der, raw.Bytes, nil
}

func asn1NULL() asn1.RawValue {
	return asn1.RawValue{FullBytes: []byte{0x05, 0x00}}
}

// ----- SignedData -----

type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue // [0] EXPLICIT built manually via wrapExplicit0
}

type cmsIssuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type cmsAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

// signedDataParams collects everything needed to build the SignedData.
type signedDataParams struct {
	spcDER      []byte // SpcIndirectDataContent DER (eContent)
	spcContents []byte // its contents octets (for messageDigest)
	cert        *x509.Certificate
	key         crypto.Signer
	chain       []*x509.Certificate
	hash        crypto.Hash
	signingTime time.Time
	description string
}

// buildMSISignedData assembles the full PKCS#7/CMS SignedData DER for an MSI
// Authenticode signature (no timestamp).
func buildMSISignedData(p signedDataParams) ([]byte, error) {
	embeddedAttrs, signature, sigAlg, err := computeMSISignerSignature(p)
	if err != nil {
		return nil, err
	}
	return assembleMSISignedData(p, embeddedAttrs, signature, sigAlg, nil)
}

// computeMSISignerSignature builds the signed attributes (re-tagged [0] for
// embedding) and signs them, returning the embedded-attrs bytes, the signature
// (encryptedDigest), and the signature algorithm.
func computeMSISignerSignature(p signedDataParams) (embeddedAttrs, signature []byte, sigAlg algorithmIdentifier, err error) {
	mdHasher := p.hash.New()
	mdHasher.Write(p.spcContents)
	messageDigest := mdHasher.Sum(nil)

	attrs, err := buildSignedAttributes(messageDigest, p.signingTime, p.description)
	if err != nil {
		return nil, nil, algorithmIdentifier{}, err
	}
	// DER SET (tag 0x31) for signing; re-tagged [0] IMPLICIT (0xA0) for embedding.
	signedAttrsSet := derSet(attrs)
	embeddedAttrs = make([]byte, len(signedAttrsSet))
	copy(embeddedAttrs, signedAttrsSet)
	embeddedAttrs[0] = 0xA0

	h := p.hash.New()
	h.Write(signedAttrsSet)
	digest := h.Sum(nil)
	signature, sigAlg, err = signDigest(p.key, p.hash, digest)
	return embeddedAttrs, signature, sigAlg, err
}

// assembleMSISignedData builds the ContentInfo/SignedData around precomputed
// signer pieces, optionally adding the [1] IMPLICIT unsigned attributes (timestamp).
func assembleMSISignedData(p signedDataParams, embeddedAttrs, signature []byte, sigAlg algorithmIdentifier, unsignedAttrs []byte) ([]byte, error) {
	algOID, err := digestAlgorithmOID(p.hash)
	if err != nil {
		return nil, err
	}
	digestAlg := algorithmIdentifier{Algorithm: algOID, Parameters: asn1NULL()}

	// SignerInfo assembled manually so the optional [1] IMPLICIT unsigned
	// attributes can be appended.
	versionDER := mustMarshal(1)
	issuerSerialDER := mustMarshal(cmsIssuerAndSerial{Issuer: asn1.RawValue{FullBytes: p.cert.RawIssuer}, SerialNumber: p.cert.SerialNumber})
	digestAlgDER := mustMarshal(digestAlg)
	sigAlgDER := mustMarshal(sigAlg)
	sigOctet := mustMarshal(signature)

	var siBody []byte
	siBody = append(siBody, versionDER...)
	siBody = append(siBody, issuerSerialDER...)
	siBody = append(siBody, digestAlgDER...)
	siBody = append(siBody, embeddedAttrs...)
	siBody = append(siBody, sigAlgDER...)
	siBody = append(siBody, sigOctet...)
	if len(unsignedAttrs) > 0 {
		siBody = append(siBody, unsignedAttrs...)
	}
	signerInfoDER := append(derTagLen(0x30, len(siBody)), siBody...)

	// Certificates [0] IMPLICIT SET OF certificate.
	certSetItems := [][]byte{p.cert.Raw}
	for _, c := range p.chain {
		certSetItems = append(certSetItems, c.Raw)
	}
	certificates := derSetRaw(certSetItems)
	certificates[0] = 0xA0 // [0] IMPLICIT

	// encapContentInfo { eContentType = SpcIndirectData, eContent [0] EXPLICIT spcDER }.
	encap := struct {
		EContentType asn1.ObjectIdentifier
		EContent     asn1.RawValue
	}{
		EContentType: oidSpcIndirectData,
		EContent:     asn1.RawValue{FullBytes: wrapExplicit0(p.spcDER)},
	}
	encapDER, err := asn1.Marshal(encap)
	if err != nil {
		return nil, fmt.Errorf("msi sign: marshal encapContentInfo: %w", err)
	}

	signedData := struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		EncapContentInfo asn1.RawValue
		Certificates     asn1.RawValue
		SignerInfos      asn1.RawValue
	}{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{FullBytes: derSetRaw([][]byte{mustMarshal(digestAlg)})},
		EncapContentInfo: asn1.RawValue{FullBytes: encapDER},
		Certificates:     asn1.RawValue{FullBytes: certificates},
		SignerInfos:      asn1.RawValue{FullBytes: derSetRaw([][]byte{signerInfoDER})},
	}
	signedDataDER, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, fmt.Errorf("msi sign: marshal SignedData: %w", err)
	}

	ci := cmsContentInfo{
		ContentType: oidSignedDataPKCS7,
		Content:     asn1.RawValue{FullBytes: wrapExplicit0(signedDataDER)},
	}
	out, err := asn1.Marshal(ci)
	if err != nil {
		return nil, fmt.Errorf("msi sign: marshal ContentInfo: %w", err)
	}
	return out, nil
}

// buildSignedAttributes returns the individual Attribute DERs (unsorted).
func buildSignedAttributes(messageDigest []byte, signingTime time.Time, description string) ([][]byte, error) {
	var attrs [][]byte

	// contentType = SpcIndirectData
	ctVal, _ := asn1.Marshal(oidSpcIndirectData)
	attrs = append(attrs, mustMarshal(cmsAttribute{Type: oidAttrContentType, Values: asn1.RawValue{FullBytes: derSetRaw([][]byte{ctVal})}}))

	// messageDigest
	mdVal, _ := asn1.Marshal(messageDigest)
	attrs = append(attrs, mustMarshal(cmsAttribute{Type: oidAttrMessageDig, Values: asn1.RawValue{FullBytes: derSetRaw([][]byte{mdVal})}}))

	// signingTime (UTCTime)
	stVal, err := asn1.Marshal(signingTime.UTC())
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, mustMarshal(cmsAttribute{Type: oidAttrSigningTime, Values: asn1.RawValue{FullBytes: derSetRaw([][]byte{stVal})}}))

	// SpcStatementType = individualCodeSigning
	stmt := struct {
		Types []asn1.ObjectIdentifier
	}{Types: []asn1.ObjectIdentifier{oidSpcIndividual}}
	stmtVal, _ := asn1.Marshal(stmt)
	attrs = append(attrs, mustMarshal(cmsAttribute{Type: oidSpcStatementT, Values: asn1.RawValue{FullBytes: derSetRaw([][]byte{stmtVal})}}))

	// SpcSpOpusInfo (optional description)
	opus := buildOpusInfo(description)
	attrs = append(attrs, mustMarshal(cmsAttribute{Type: oidSpcSpOpusInfo, Values: asn1.RawValue{FullBytes: derSetRaw([][]byte{opus})}}))

	return attrs, nil
}

// buildOpusInfo builds an SpcSpOpusInfo { programName [0] EXPLICIT, ... }.
func buildOpusInfo(description string) []byte {
	if description == "" {
		// empty SEQUENCE
		out, _ := asn1.Marshal(struct{}{})
		return out
	}
	// programName [0] EXPLICIT SpcString, where SpcString unicode [0] IMPLICIT BMPString.
	// We encode the description as a [0] IMPLICIT (unicode) BMPString.
	bmp := encodeBMPString(description)
	spcStr := asn1.RawValue{Class: 2, Tag: 0, IsCompound: false, Bytes: bmp}
	spcStrDER, _ := asn1.Marshal(spcStr) // [0] IMPLICIT primitive
	programName := asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: spcStrDER}
	pnDER, _ := asn1.Marshal(programName)
	out, _ := asn1.Marshal(asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: pnDER})
	return out
}

func encodeBMPString(s string) []byte {
	var b bytes.Buffer
	for _, r := range s {
		b.WriteByte(byte(r >> 8))
		b.WriteByte(byte(r))
	}
	return b.Bytes()
}

// signDigest signs a precomputed digest with the key, returning the signature
// and the signatureAlgorithm identifier.
func signDigest(key crypto.Signer, hash crypto.Hash, digest []byte) ([]byte, algorithmIdentifier, error) {
	switch key.Public().(type) {
	case *rsa.PublicKey:
		sig, err := key.Sign(rand.Reader, digest, hash)
		if err != nil {
			return nil, algorithmIdentifier{}, fmt.Errorf("msi sign: rsa sign: %w", err)
		}
		return sig, algorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1NULL()}, nil
	case *ecdsa.PublicKey:
		sig, err := key.Sign(rand.Reader, digest, hash)
		if err != nil {
			return nil, algorithmIdentifier{}, fmt.Errorf("msi sign: ecdsa sign: %w", err)
		}
		return sig, algorithmIdentifier{Algorithm: oidECPublicKey}, nil
	}
	return nil, algorithmIdentifier{}, fmt.Errorf("msi sign: unsupported key type %T", key.Public())
}

// ----- DER SET helpers -----

// derSet wraps already-marshaled elements in a DER SET (tag 0x31), sorting them
// by their encoding as DER requires.
func derSet(elements [][]byte) []byte {
	return derSetTagged(elements, 0x31)
}

// derSetRaw is like derSet but used where a SET OF is needed (same encoding).
func derSetRaw(elements [][]byte) []byte {
	return derSetTagged(elements, 0x31)
}

func derSetTagged(elements [][]byte, tag byte) []byte {
	sorted := make([][]byte, len(elements))
	copy(sorted, elements)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i], sorted[j]) < 0 })
	var body []byte
	for _, e := range sorted {
		body = append(body, e...)
	}
	return append(derTagLen(tag, len(body)), body...)
}

// derTagLen returns a DER tag + length prefix.
func derTagLen(tag byte, n int) []byte {
	if n < 0x80 {
		return []byte{tag, byte(n)}
	}
	var lenBytes []byte
	x := n
	for x > 0 {
		lenBytes = append([]byte{byte(x & 0xFF)}, lenBytes...)
		x >>= 8
	}
	out := []byte{tag, byte(0x80 | len(lenBytes))}
	return append(out, lenBytes...)
}

// wrapExplicit0 wraps content in a [0] EXPLICIT (context, constructed) tag.
func wrapExplicit0(content []byte) []byte {
	return append(derTagLen(0xA0, len(content)), content...)
}

func mustMarshal(v any) []byte {
	out, err := asn1.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("msi sign: marshal %T: %v", v, err))
	}
	return out
}

// ----- parsing / verification -----

type parsedMSISignature struct {
	cert          *x509.Certificate
	chain         []*x509.Certificate
	hash          crypto.Hash
	imprint       []byte // from SpcIndirectData.MessageDigest.Digest
	signingTime   time.Time
	timestamp     time.Time
	hasTimestamp  bool
	spcContents   []byte
	messageDigest []byte // messageDigest signed attribute
}

type pkcs7ContentInfoParse struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type pkcs7SignedDataParse struct {
	Version          int
	DigestAlgorithms asn1.RawValue `asn1:"set"`
	EncapContentInfo encapInfoParse
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      asn1.RawValue `asn1:"set"`
}

type encapInfoParse struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signerInfoParse struct {
	Version          int
	IssuerAndSerial  cmsIssuerAndSerial
	DigestAlgorithm  algorithmIdentifier
	AuthAttributes   asn1.RawValue `asn1:"optional,tag:0"`
	SigAlgorithm     algorithmIdentifier
	EncryptedDigest  []byte
	UnauthAttributes asn1.RawValue `asn1:"optional,tag:1"`
}

// parseMSISignedData parses and cryptographically verifies an MSI
// \x05DigitalSignature blob: it checks the signer's signature over the signed
// attributes and that the messageDigest attribute matches the SpcIndirectData
// content. It does NOT check the imprint against the file (the caller does that).
func parseMSISignedData(der []byte) (*parsedMSISignature, error) {
	var ci pkcs7ContentInfoParse
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("msi verify: ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedDataPKCS7) {
		return nil, fmt.Errorf("msi verify: outer contentType is not signedData")
	}
	var sd pkcs7SignedDataParse
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("msi verify: SignedData: %w", err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidSpcIndirectData) {
		return nil, fmt.Errorf("msi verify: eContentType is not SpcIndirectData")
	}

	// SpcIndirectData: extract imprint + its contents octets.
	spcDER := sd.EncapContentInfo.EContent.Bytes
	var idc msiSpcIndirectDataContent
	if _, err := asn1.Unmarshal(spcDER, &idc); err != nil {
		return nil, fmt.Errorf("msi verify: SpcIndirectData: %w", err)
	}
	var spcRaw asn1.RawValue
	if _, err := asn1.Unmarshal(spcDER, &spcRaw); err != nil {
		return nil, fmt.Errorf("msi verify: SpcIndirectData raw: %w", err)
	}

	// Certificates.
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil || len(certs) == 0 {
		return nil, fmt.Errorf("msi verify: certificates: %w", err)
	}

	// SignerInfo (single signer).
	var si signerInfoParse
	if _, err := asn1.Unmarshal(sd.SignerInfos.Bytes, &si); err != nil {
		return nil, fmt.Errorf("msi verify: SignerInfo: %w", err)
	}

	// Match the signer certificate by issuer + serial.
	var signer *x509.Certificate
	for _, c := range certs {
		if bytes.Equal(c.RawIssuer, si.IssuerAndSerial.Issuer.FullBytes) && c.SerialNumber.Cmp(si.IssuerAndSerial.SerialNumber) == 0 {
			signer = c
			break
		}
	}
	if signer == nil {
		signer = certs[0]
	}

	hash, err := hashFromOID(si.DigestAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}

	// Verify the signature over the signed attributes (re-tagged as a SET).
	if len(si.AuthAttributes.FullBytes) == 0 {
		return nil, fmt.Errorf("msi verify: missing signed attributes")
	}
	signedAttrsSet := make([]byte, len(si.AuthAttributes.FullBytes))
	copy(signedAttrsSet, si.AuthAttributes.FullBytes)
	signedAttrsSet[0] = 0x31 // [0] IMPLICIT -> SET for the signature computation
	h := hash.New()
	h.Write(signedAttrsSet)
	digest := h.Sum(nil)
	if err := verifySignature(signer.PublicKey, hash, digest, si.EncryptedDigest); err != nil {
		return nil, fmt.Errorf("msi verify: signature: %w", err)
	}

	// Extract messageDigest + signingTime attributes; check messageDigest.
	attrs, err := parseAttributes(si.AuthAttributes.Bytes)
	if err != nil {
		return nil, err
	}
	mdAttr, ok := attrs[oidAttrMessageDig.String()]
	if !ok {
		return nil, fmt.Errorf("msi verify: missing messageDigest attribute")
	}
	var md []byte
	if _, err := asn1.Unmarshal(mdAttr, &md); err != nil {
		return nil, fmt.Errorf("msi verify: messageDigest value: %w", err)
	}
	mdCheck := hash.New()
	mdCheck.Write(spcRaw.Bytes)
	if !bytes.Equal(md, mdCheck.Sum(nil)) {
		return nil, fmt.Errorf("msi verify: messageDigest does not match SpcIndirectData content")
	}

	res := &parsedMSISignature{
		cert:          signer,
		chain:         certs,
		hash:          hash,
		imprint:       idc.MessageDigest.Digest,
		spcContents:   spcRaw.Bytes,
		messageDigest: md,
	}
	if stAttr, ok := attrs[oidAttrSigningTime.String()]; ok {
		var st time.Time
		if _, err := asn1.Unmarshal(stAttr, &st); err == nil {
			res.signingTime = st
		}
	}

	// RFC3161 timestamp (unsigned attribute).
	if len(si.UnauthAttributes.Bytes) > 0 {
		if uattrs, err := parseAttributes(si.UnauthAttributes.Bytes); err == nil {
			if tok, ok := uattrs[oidTimestampTokenMS.String()]; ok {
				res.hasTimestamp = true
				if gt, err := parseTimestampGenTime(tok); err == nil {
					res.timestamp = gt
				}
			}
		}
	}
	return res, nil
}

// parseTimestampGenTime extracts the genTime from an RFC3161 timeStampToken
// (a ContentInfo wrapping a SignedData whose eContent is a TSTInfo).
func parseTimestampGenTime(token []byte) (time.Time, error) {
	var ci pkcs7ContentInfoParse
	if _, err := asn1.Unmarshal(token, &ci); err != nil {
		return time.Time{}, err
	}
	var sd pkcs7SignedDataParse
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return time.Time{}, err
	}
	tstDER := sd.EncapContentInfo.EContent.Bytes
	if len(tstDER) == 0 {
		return time.Time{}, fmt.Errorf("no TSTInfo")
	}
	var tst struct {
		Version        int
		Policy         asn1.ObjectIdentifier
		MessageImprint asn1.RawValue
		SerialNumber   *big.Int
		GenTime        time.Time       `asn1:"generalized"`
		Rest           []asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(tstDER, &tst); err != nil {
		return time.Time{}, err
	}
	return tst.GenTime, nil
}

// parseAttributes returns a map of attribute OID -> the first value's DER (the
// inner SET's first element) from a SET OF Attribute body.
func parseAttributes(setBody []byte) (map[string][]byte, error) {
	out := map[string][]byte{}
	rest := setBody
	for len(rest) > 0 {
		var attrRaw asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &attrRaw)
		if err != nil {
			return nil, fmt.Errorf("msi verify: attribute: %w", err)
		}
		var attr struct {
			Type   asn1.ObjectIdentifier
			Values asn1.RawValue `asn1:"set"`
		}
		if _, err := asn1.Unmarshal(attrRaw.FullBytes, &attr); err != nil {
			return nil, fmt.Errorf("msi verify: attribute fields: %w", err)
		}
		// First value of the SET.
		var first asn1.RawValue
		if _, err := asn1.Unmarshal(attr.Values.Bytes, &first); err != nil {
			return nil, fmt.Errorf("msi verify: attribute value: %w", err)
		}
		out[attr.Type.String()] = first.FullBytes
	}
	return out, nil
}

func hashFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidSHA1):
		return crypto.SHA1, nil
	case oid.Equal(oidSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512):
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("msi verify: unknown digest algorithm %v", oid)
}

func verifySignature(pub any, hash crypto.Hash, digest, sig []byte) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, hash, digest, sig)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return fmt.Errorf("ecdsa signature invalid")
		}
		return nil
	}
	return fmt.Errorf("unsupported public key %T", pub)
}
