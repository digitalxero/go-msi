package msi

// msi_guid_test.go
// Tests for the RFC 4122 GUID helpers. These test unexported helpers, so they
// live in the internal package.

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// guidV5Reference is a tiny independent reference implementation of RFC 4122
// version 5 used to cross-check msiGUIDv5. The namespace must be unbraced
// hyphenated lowercase or uppercase hex.
func guidV5Reference(t *testing.T, namespace, name string) string {
	t.Helper()
	raw, err := hex.DecodeString(namespace[0:8] + namespace[9:13] + namespace[14:18] + namespace[19:23] + namespace[24:36])
	require.NoError(t, err)
	require.Len(t, raw, 16)

	h := sha1.New()
	h.Write(raw)
	h.Write([]byte(name))
	sum := h.Sum(nil)[:16]
	sum[6] = (sum[6] & 0x0F) | 0x50
	sum[8] = (sum[8] & 0x3F) | 0x80
	return fmt.Sprintf("{%X-%X-%X-%X-%X}", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

func TestMSINewGUIDv4Format(t *testing.T) {
	g, err := msiNewGUIDv4()
	require.NoError(t, err)
	assert.True(t, msiValidGUID(g), "v4 GUID %q must be strictly valid", g)
	// "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}": version nibble at index 15,
	// variant nibble at index 20.
	assert.Equal(t, byte('4'), g[15], "version nibble of %q", g)
	assert.Contains(t, []byte{'8', '9', 'A', 'B'}, g[20], "variant nibble of %q", g)
}

func TestMSINewGUIDv4Uniqueness(t *testing.T) {
	const iterations = 1000
	seen := make(map[string]struct{}, iterations)
	for i := 0; i < iterations; i++ {
		g, err := msiNewGUIDv4()
		require.NoError(t, err)
		_, dup := seen[g]
		require.False(t, dup, "duplicate v4 GUID %q after %d generations", g, i)
		seen[g] = struct{}{}
	}
}

func TestMSIGUIDv5KnownVector(t *testing.T) {
	// RFC 4122 DNS namespace + "www.example.com" is the classic v5 example:
	// 2ed6657d-e927-568b-95e1-2665a8aea6a2.
	const nsDNS = "{6BA7B810-9DAD-11D1-80B4-00C04FD430C8}"
	g, err := msiGUIDv5(nsDNS, "www.example.com")
	require.NoError(t, err)
	assert.Equal(t, "{2ED6657D-E927-568B-95E1-2665A8AEA6A2}", g)
}

func TestMSIGUIDv5MatchesReference(t *testing.T) {
	cases := []struct {
		namespace string
		name      string
	}{
		{msiPackageNamespaceGUID, "ProductCode/MyApp/1.2.3"},
		{msiPackageNamespaceGUID, "Component/INSTALLDIR/app.exe"},
		{msiPackageNamespaceGUID, ""},
		{"{6BA7B810-9DAD-11D1-80B4-00C04FD430C8}", "www.example.com"},
		{"{6BA7B810-9DAD-11D1-80B4-00C04FD430C8}", "日本語ユニコード"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := msiGUIDv5(tc.namespace, tc.name)
			require.NoError(t, err)
			want := guidV5Reference(t, tc.namespace[1:len(tc.namespace)-1], tc.name)
			assert.Equal(t, want, got)
			assert.True(t, msiValidGUID(got), "v5 GUID %q must be strictly valid", got)
			assert.Equal(t, byte('5'), got[15], "version nibble of %q", got)
			assert.Contains(t, []byte{'8', '9', 'A', 'B'}, got[20], "variant nibble of %q", got)
		})
	}
}

func TestMSIGUIDv5Deterministic(t *testing.T) {
	first, err := msiGUIDv5(msiPackageNamespaceGUID, "stable-name")
	require.NoError(t, err)
	for i := 0; i < 10; i++ {
		again, err := msiGUIDv5(msiPackageNamespaceGUID, "stable-name")
		require.NoError(t, err)
		assert.Equal(t, first, again)
	}

	other, err := msiGUIDv5(msiPackageNamespaceGUID, "different-name")
	require.NoError(t, err)
	assert.NotEqual(t, first, other)
}

func TestMSIGUIDv5AcceptsUnbracedAndLowercaseNamespace(t *testing.T) {
	braced, err := msiGUIDv5("{6BA7B810-9DAD-11D1-80B4-00C04FD430C8}", "x")
	require.NoError(t, err)
	unbraced, err := msiGUIDv5("6BA7B810-9DAD-11D1-80B4-00C04FD430C8", "x")
	require.NoError(t, err)
	lower, err := msiGUIDv5("6ba7b810-9dad-11d1-80b4-00c04fd430c8", "x")
	require.NoError(t, err)
	assert.Equal(t, braced, unbraced)
	assert.Equal(t, braced, lower)
}

func TestMSIGUIDv5InvalidNamespace(t *testing.T) {
	for _, ns := range []string{
		"",
		"not-a-guid",
		"{6BA7B810-9DAD-11D1-80B4-00C04FD430C}",   // group too short
		"{6BA7B810_9DAD_11D1_80B4_00C04FD430C8}",  // wrong separators
		"{6BA7B810-9DAD-11D1-80B4-00C04FD430CG}",  // non-hex
		"{6BA7B810-9DAD-11D1-80B4-00C04FD430C8 }", // trailing junk
	} {
		_, err := msiGUIDv5(ns, "name")
		assert.Error(t, err, "namespace %q must be rejected", ns)
	}
}

func TestMSIValidGUID(t *testing.T) {
	cases := []struct {
		in    string
		valid bool
	}{
		{"{6BA7B810-9DAD-11D1-80B4-00C04FD430C8}", true},
		{"{00000000-0000-0000-0000-000000000000}", true},
		{"{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}", true},
		{msiPackageNamespaceGUID, true},
		{"", false},
		{"6BA7B810-9DAD-11D1-80B4-00C04FD430C8", false},    // missing braces
		{"{6ba7b810-9dad-11d1-80b4-00c04fd430c8}", false},  // lowercase hex
		{"{6BA7B810-9DAD-11D1-80B4-00C04FD430C}", false},   // too short
		{"{6BA7B810-9DAD-11D1-80B4-00C04FD430C88}", false}, // too long
		{"{6BA7B8109-DAD-11D1-80B4-00C04FD430C8}", false},  // hyphen misplaced
		{"{6BA7B810 9DAD 11D1 80B4 00C04FD430C8}", false},  // spaces not hyphens
		{"{6BA7B810-9DAD-11D1-80B4-00C04FD430CG}", false},  // non-hex char
		{"(6BA7B810-9DAD-11D1-80B4-00C04FD430C8)", false},  // wrong brackets
	}
	for _, tc := range cases {
		assert.Equal(t, tc.valid, msiValidGUID(tc.in), "msiValidGUID(%q)", tc.in)
	}
}

func TestMSIPackageNamespaceGUIDIsValid(t *testing.T) {
	assert.True(t, msiValidGUID(msiPackageNamespaceGUID))
}
