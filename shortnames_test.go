package msi

// msi_shortnames_test.go
// Tests for 8.3 short-name generation for the MSI Filename column. These test
// unexported helpers, so they live in the internal package.

import (
	"fmt"
	"hash/fnv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shortNameHashReference independently computes the 4-hex-digit XOR-folded
// 32-bit FNV-1a hash used by the short-name fallback path.
func shortNameHashReference(name string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	v := h.Sum32()
	return fmt.Sprintf("%04X", uint16(v>>16)^uint16(v))
}

func TestMSIFileNameColumnPassthrough(t *testing.T) {
	for _, name := range []string{
		"app.exe",
		"README.TXT",
		"README",
		"a",
		"A1B2C3D4.XYZ",
		"file~1.txt",
		"!#$%&'()", // every extra punctuation class char is allowed
		"-@^_`{}~",
		"MiXeD.cAs",
	} {
		t.Run(name, func(t *testing.T) {
			n := newMSIShortNamer()
			got, err := n.msiFileNameColumn(name)
			require.NoError(t, err)
			assert.Equal(t, name, got, "valid 8.3 name must pass through unchanged")
		})
	}
}

func TestMSIFileNameColumnTooLong(t *testing.T) {
	n := newMSIShortNamer()
	got, err := n.msiFileNameColumn("MyLibraryFile.dll")
	require.NoError(t, err)
	assert.Equal(t, "MYLIBR~1.DLL|MyLibraryFile.dll", got)
}

func TestMSIFileNameColumnCollisionLadder(t *testing.T) {
	n := newMSIShortNamer()
	// 99 long names sharing the MYLIBR prefix exhaust MYLIBR~1..9 and then
	// MYLI~10..99; the 100th falls back to the FNV-1a hash form.
	for i := 1; i <= 99; i++ {
		long := fmt.Sprintf("MyLibraryFile%03d.dll", i)
		got, err := n.msiFileNameColumn(long)
		require.NoError(t, err)
		var short string
		if i <= 9 {
			short = fmt.Sprintf("MYLIBR~%d.DLL", i)
		} else {
			short = fmt.Sprintf("MYLI~%d.DLL", i)
		}
		assert.Equal(t, short+"|"+long, got, "name %d in the ladder", i)
	}

	long := "MyLibraryFile100.dll"
	got, err := n.msiFileNameColumn(long)
	require.NoError(t, err)
	assert.Equal(t, shortNameHashReference(long)+"~1.DLL|"+long, got)
}

func TestMSIFileNameColumnInvalidCharStripping(t *testing.T) {
	n := newMSIShortNamer()
	got, err := n.msiFileNameColumn("hello world.txt")
	require.NoError(t, err)
	assert.Equal(t, "HELLOW~1.TXT|hello world.txt", got)
}

func TestMSIFileNameColumnMultipleDots(t *testing.T) {
	n := newMSIShortNamer()
	got, err := n.msiFileNameColumn("a.b.c.txt")
	require.NoError(t, err)
	assert.Equal(t, "ABC~1.TXT|a.b.c.txt", got)
}

func TestMSIFileNameColumnNoExtension(t *testing.T) {
	n := newMSIShortNamer()
	got, err := n.msiFileNameColumn("ThisIsALongFileName")
	require.NoError(t, err)
	assert.Equal(t, "THISIS~1|ThisIsALongFileName", got)
}

func TestMSIFileNameColumnLongExtension(t *testing.T) {
	n := newMSIShortNamer()
	got, err := n.msiFileNameColumn("config.json")
	require.NoError(t, err)
	assert.Equal(t, "CONFIG~1.JSO|config.json", got)
}

func TestMSIFileNameColumnLeadingDot(t *testing.T) {
	n := newMSIShortNamer()
	// Empty base after splitting at the dot: falls back to the hash form.
	got, err := n.msiFileNameColumn(".gitignore")
	require.NoError(t, err)
	assert.Equal(t, shortNameHashReference(".gitignore")+"~1.GIT|.gitignore", got)
}

func TestMSIFileNameColumnUnicode(t *testing.T) {
	n := newMSIShortNamer()
	// No valid short-name characters survive filtering: hash fallback.
	got, err := n.msiFileNameColumn("日本語.txt")
	require.NoError(t, err)
	assert.Equal(t, shortNameHashReference("日本語.txt")+"~1.TXT|日本語.txt", got)

	// Mixed unicode and ASCII keeps the ASCII characters.
	got, err = n.msiFileNameColumn("résumé-file.doc")
	require.NoError(t, err)
	assert.Equal(t, "RSUM-F~1.DOC|résumé-file.doc", got)
}

func TestMSIFileNameColumnPassthroughReservesShortName(t *testing.T) {
	n := newMSIShortNamer()
	// A literal valid 8.3 name occupies its slot in the used set...
	got, err := n.msiFileNameColumn("ABC~1.TXT")
	require.NoError(t, err)
	assert.Equal(t, "ABC~1.TXT", got)

	// ...so a later generated name must skip to ~2.
	got, err = n.msiFileNameColumn("a.b.c.txt")
	require.NoError(t, err)
	assert.Equal(t, "ABC~2.TXT|a.b.c.txt", got)
}

func TestMSIFileNameColumnDeterministic(t *testing.T) {
	names := []string{
		"MyLibraryFile.dll",
		"MyLibraryFileToo.dll",
		"hello world.txt",
		"app.exe",
		"a.b.c.txt",
		"config.json",
		"日本語.txt",
		"ThisIsALongFileName",
	}
	run := func() []string {
		n := newMSIShortNamer()
		out := make([]string, 0, len(names))
		for _, name := range names {
			got, err := n.msiFileNameColumn(name)
			require.NoError(t, err)
			out = append(out, got)
		}
		return out
	}
	first := run()
	for i := 0; i < 5; i++ {
		assert.Equal(t, first, run(), "same insertion order must yield identical output")
	}
}

func TestMSIFileNameColumnRejectsInvalidNames(t *testing.T) {
	for _, name := range []string{
		"",
		".",
		"..",
		"dir/file.txt",
		`dir\file.txt`,
		"what?.txt",
		"a:b.txt",
		"a*b.txt",
		`a"b.txt`,
		"a<b.txt",
		"a>b.txt",
		"a|b.txt",
		"tab\tname.txt",
		"nul\x00name.txt",
	} {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			n := newMSIShortNamer()
			_, err := n.msiFileNameColumn(name)
			assert.Error(t, err, "name %q must be rejected", name)
		})
	}
}

func TestMSIFileNameColumnNotShortNames(t *testing.T) {
	// Long names that are legal but not valid 8.3 names must produce pairs.
	for _, name := range []string{
		"app .exe",        // space
		"app.exe.bak",     // two dots
		"toolongbase.txt", // base > 8
		"file.jsonx",      // ext > 3
		"app+plus.txt",    // '+' not allowed in short names
		"trailingdot.",    // trailing dot
		"file=eq.txt",     // '=' not allowed in short names
	} {
		t.Run(name, func(t *testing.T) {
			n := newMSIShortNamer()
			got, err := n.msiFileNameColumn(name)
			require.NoError(t, err)
			require.Contains(t, got, "|", "expected short|long pair for %q", name)
			assert.NotEqual(t, name, got)
		})
	}
}
