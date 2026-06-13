package msi

// msi_guid.go
// RFC 4122 GUID helpers for MSI authoring.
// MSI requires GUIDs (ProductCode, UpgradeCode, Component GUIDs, ...) to be
// in braced, uppercase, hyphenated form: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}.
// Random (v4) GUIDs are used where a fresh identity is wanted; name-based (v5,
// SHA-1) GUIDs are used to derive stable component/product GUIDs from a
// namespace plus a name so that rebuilds produce identical packages.

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
)

// msiPackageNamespaceGUID is a fixed, arbitrary namespace GUID used as the
// default namespace when deriving deterministic (v5) component and product
// GUIDs for this package. It must never change, or derived GUIDs would change
// across builds.
const msiPackageNamespaceGUID = "{91ADBD60-BDC5-4508-A116-C080D8BC7F9C}"

// msiNewGUIDv4 returns a new random RFC 4122 version 4 GUID in braced
// uppercase form, e.g. "{0F8FAD5B-D9CB-469F-A165-70867728950E}".
func msiNewGUIDv4() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", fmt.Errorf("msi guid: reading random bytes: %w", err)
	}
	b[6] = (b[6] & 0x0F) | 0x40 // version 4
	b[8] = (b[8] & 0x3F) | 0x80 // RFC 4122 variant
	return msiFormatGUID(b), nil
}

// msiGUIDv5 returns the RFC 4122 version 5 (SHA-1 name-based) GUID for the
// given namespace GUID and name, in braced uppercase form. The namespace may
// be braced or unbraced but must be hyphenated. The result is deterministic:
// the same namespace and name always yield the same GUID.
func msiGUIDv5(namespace, name string) (string, error) {
	ns, err := msiParseGUID(namespace)
	if err != nil {
		return "", err
	}
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)

	var b [16]byte
	copy(b[:], sum[:16])
	b[6] = (b[6] & 0x0F) | 0x50 // version 5
	b[8] = (b[8] & 0x3F) | 0x80 // RFC 4122 variant
	return msiFormatGUID(b), nil
}

// msiValidGUID reports whether s is a strictly formatted MSI GUID:
// braced, hyphenated {8-4-4-4-12}, uppercase hexadecimal only.
func msiValidGUID(s string) bool {
	if len(s) != 38 || s[0] != '{' || s[37] != '}' {
		return false
	}
	for i := 1; i < 37; i++ {
		switch i {
		case 9, 14, 19, 24:
			if s[i] != '-' {
				return false
			}
		default:
			c := s[i]
			if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
				return false
			}
		}
	}
	return true
}

// msiParseGUID parses a braced or unbraced hyphenated GUID string into its
// 16-byte RFC 4122 network-order (big-endian) representation. The textual
// form hex-decodes directly into network order: time_low, time_mid,
// time_hi_and_version, clock_seq, and node appear most significant byte
// first. Hex digits of either case are accepted.
func msiParseGUID(s string) ([16]byte, error) {
	var b [16]byte
	t := s
	if len(t) >= 2 && t[0] == '{' && t[len(t)-1] == '}' {
		t = t[1 : len(t)-1]
	}
	if len(t) != 36 || t[8] != '-' || t[13] != '-' || t[18] != '-' || t[23] != '-' {
		return b, fmt.Errorf("msi guid: malformed GUID %q", s)
	}
	raw, err := hex.DecodeString(t[0:8] + t[9:13] + t[14:18] + t[19:23] + t[24:36])
	if err != nil {
		return b, fmt.Errorf("msi guid: malformed GUID %q: %w", s, err)
	}
	copy(b[:], raw)
	return b, nil
}

// msiFormatGUID formats a 16-byte network-order GUID as braced uppercase
// {8-4-4-4-12}. %X on a byte slice always emits two uppercase hex digits per
// byte, so every group has a fixed width.
func msiFormatGUID(b [16]byte) string {
	return fmt.Sprintf("{%X-%X-%X-%X-%X}", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
