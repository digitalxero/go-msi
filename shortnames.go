package msi

// msi_shortnames.go
// 8.3 short-name generation for the MSI Filename column data type
// (https://learn.microsoft.com/en-us/windows/win32/msi/filename), used by the
// File table Filename column and the Directory table DefaultDir column.
// The column holds either a bare short name ("README.TXT") when the long name
// is already a valid 8.3 name, or a "shortname|longname" pair otherwise.
// Short names must be unique within a directory, so an msiShortNamer tracks
// the names already issued for one directory. Generation is deterministic for
// a given insertion order of long names.

import (
	"fmt"
	"hash/fnv"
	"strings"
)

// msiShortNameExtraChars are the punctuation characters permitted in an 8.3
// short filename in addition to letters and digits. Notably absent compared
// to long names: space, dot (only the single separator dot is allowed),
// '+', ',', ';', '=', '[' and ']'.
const msiShortNameExtraChars = "!#$%&'()-@^_`{}~"

// msiLongNameInvalidChars are the characters forbidden in the long-name part
// of an MSI Filename column value.
const msiLongNameInvalidChars = `\/:*?"<>|`

// msiShortNamer issues 8.3 short names that are unique within a single
// directory. Create one per directory with newMSIShortNamer. It is not safe
// for concurrent use; MSI table emission is single-threaded and deterministic
// by design.
type msiShortNamer struct {
	used map[string]struct{} // uppercase short names already issued
}

// newMSIShortNamer returns an msiShortNamer with an empty used-name set.
func newMSIShortNamer() *msiShortNamer {
	return &msiShortNamer{used: make(map[string]struct{})}
}

// msiFileNameColumn returns the MSI Filename column value for longName:
// the long name alone when it is already a valid 8.3 short name, or a
// "SHORTN~1.EXT|longname.ext" pair otherwise. The short form (or the
// passthrough name, uppercased) is registered in the per-directory used set
// so later names in the same directory never collide with it.
func (n *msiShortNamer) msiFileNameColumn(longName string) (string, error) {
	if err := msiValidateLongName(longName); err != nil {
		return "", err
	}
	if msiIsValidShortName(longName) {
		n.used[strings.ToUpper(longName)] = struct{}{}
		return longName, nil
	}
	short, err := n.generateShortName(longName)
	if err != nil {
		return "", err
	}
	n.used[short] = struct{}{}
	return short + "|" + longName, nil
}

// generateShortName derives an uppercase 8.3 short name for longName that is
// not present in the used set. Strategy, per classic Windows short-name
// generation adapted for MSI:
//  1. base truncated to 6 valid chars + "~N" for N=1..9
//  2. base truncated to 4 valid chars + "~N" for N=10..99
//  3. 4-hex-digit FNV-1a hash of the long name + "~N" for N=1..99
//
// The extension is the first 3 valid characters of the last extension.
func (n *msiShortNamer) generateShortName(longName string) (string, error) {
	base, ext := msiSplitLongName(longName)
	upBase := msiFilterShortChars(strings.ToUpper(base))
	upExt := msiFilterShortChars(strings.ToUpper(ext))
	if len(upExt) > 3 {
		upExt = upExt[:3]
	}
	suffix := ""
	if upExt != "" {
		suffix = "." + upExt
	}

	if upBase != "" {
		base6 := upBase
		if len(base6) > 6 {
			base6 = base6[:6]
		}
		for i := 1; i <= 9; i++ {
			if cand := fmt.Sprintf("%s~%d%s", base6, i, suffix); !n.isUsed(cand) {
				return cand, nil
			}
		}
		base4 := upBase
		if len(base4) > 4 {
			base4 = base4[:4]
		}
		for i := 10; i <= 99; i++ {
			if cand := fmt.Sprintf("%s~%d%s", base4, i, suffix); !n.isUsed(cand) {
				return cand, nil
			}
		}
	}

	// Hash fallback: also the primary path when the base has no valid
	// characters at all (e.g. fully non-ASCII names).
	hashBase := msiShortNameHash(longName)
	for i := 1; i <= 99; i++ {
		if cand := fmt.Sprintf("%s~%d%s", hashBase, i, suffix); !n.isUsed(cand) {
			return cand, nil
		}
	}
	return "", fmt.Errorf("msi shortname: unable to generate a unique 8.3 name for %q", longName)
}

func (n *msiShortNamer) isUsed(name string) bool {
	_, ok := n.used[name]
	return ok
}

// msiValidateLongName checks longName against the MSI Filename column rules
// for long names: it must be non-empty, not "." or "..", and must not contain
// path separators, control characters, or any of \ / : * ? " < > |.
func msiValidateLongName(longName string) error {
	if longName == "" || longName == "." || longName == ".." {
		return fmt.Errorf("msi shortname: invalid file name %q", longName)
	}
	for i := 0; i < len(longName); i++ {
		c := longName[i]
		if c < 0x20 || strings.IndexByte(msiLongNameInvalidChars, c) >= 0 {
			return fmt.Errorf("msi shortname: invalid character %q in file name %q", c, longName)
		}
	}
	return nil
}

// msiIsValidShortName reports whether s is already a valid 8.3 short name:
// a non-empty base of at most 8 characters, optionally followed by a single
// dot and an extension of 1 to 3 characters, all characters being letters,
// digits, or msiShortNameExtraChars (mixed case is allowed; spaces are not).
func msiIsValidShortName(s string) bool {
	base, ext := s, ""
	if dot := strings.IndexByte(s, '.'); dot >= 0 {
		if strings.IndexByte(s[dot+1:], '.') >= 0 {
			return false // more than one dot
		}
		base, ext = s[:dot], s[dot+1:]
		if ext == "" {
			return false // trailing dot
		}
	}
	if len(base) == 0 || len(base) > 8 || len(ext) > 3 {
		return false
	}
	for i := 0; i < len(base); i++ {
		if !msiIsShortNameChar(base[i]) {
			return false
		}
	}
	for i := 0; i < len(ext); i++ {
		if !msiIsShortNameChar(ext[i]) {
			return false
		}
	}
	return true
}

// msiIsShortNameChar reports whether c may appear in an 8.3 short name.
func msiIsShortNameChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	default:
		return strings.IndexByte(msiShortNameExtraChars, c) >= 0
	}
}

// msiSplitLongName splits a long name into base and extension at the last
// dot. Names without a dot, or ending in a dot, have an empty extension;
// names starting with their only dot (".gitignore") have an empty base.
func msiSplitLongName(longName string) (base, ext string) {
	if dot := strings.LastIndexByte(longName, '.'); dot >= 0 {
		return longName[:dot], longName[dot+1:]
	}
	return longName, ""
}

// msiFilterShortChars removes every byte that is not valid in an 8.3 short
// name. Multi-byte UTF-8 sequences are removed entirely since none of their
// bytes are in the allowed ASCII set.
func msiFilterShortChars(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if msiIsShortNameChar(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// msiShortNameHash returns 4 uppercase hex digits derived from the 32-bit
// FNV-1a hash of name, XOR-folded to 16 bits. Deterministic for a given name.
func msiShortNameHash(name string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	v := h.Sum32()
	return fmt.Sprintf("%04X", uint16(v>>16)^uint16(v))
}
