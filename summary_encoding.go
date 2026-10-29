package msi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

// Windows-1252 differs from Latin-1 only in this range. Undefined byte values
// retain their corresponding control characters, matching Windows conversion.
var summaryCP1252 = []rune("€\u0081‚ƒ„…†‡ˆ‰Š‹Œ\u008dŽ\u008f\u0090‘’“”•–—˜™š›œ\u009džŸ")

// CodePageString uses a byte count even for CP_WINUNICODE (MS-OLEPS 2.5).
// Return bytes without the final single-byte NUL added by encodeMSISummaryLPStr.
func encodeSummaryString(s string, cp int) (string, error) {
	switch cp {
	case 65001:
		return s, nil
	case 1200:
		b := make([]byte, 0, 2*len(s)+1)
		for _, u := range utf16.Encode([]rune(s)) {
			b = binary.LittleEndian.AppendUint16(b, u)
		}
		return string(append(b, 0)), nil
	case 1252:
		b := make([]byte, 0, len(s))
		for _, r := range s {
			if r < 128 || (r >= 160 && r <= 255) {
				b = append(b, byte(r))
				continue
			}
			found := false
			for i, mapped := range summaryCP1252 {
				if mapped == r {
					b = append(b, byte(128+i))
					found = true
					break
				}
			}
			if !found {
				return "", fmt.Errorf("character %U cannot be encoded in summary codepage 1252", r)
			}
		}
		return string(b), nil
	default:
		return "", fmt.Errorf("unsupported summary codepage %d", cp)
	}
}

func decodeSummaryString(b []byte, cp int) (string, error) {
	switch cp {
	case 1200:
		if len(b)%2 != 0 {
			return "", fmt.Errorf("UTF-16 summary string has odd byte count %d", len(b))
		}
		units := make([]uint16, 0, len(b)/2)
		for i := 0; i < len(b); i += 2 {
			u := binary.LittleEndian.Uint16(b[i:])
			if u == 0 {
				break
			}
			units = append(units, u)
		}
		for i := 0; i < len(units); i++ {
			if units[i] >= 0xD800 && units[i] <= 0xDBFF {
				if i+1 >= len(units) || units[i+1] < 0xDC00 || units[i+1] > 0xDFFF {
					return "", fmt.Errorf("invalid UTF-16 summary surrogate")
				}
				i++
			} else if units[i] >= 0xDC00 && units[i] <= 0xDFFF {
				return "", fmt.Errorf("invalid UTF-16 summary surrogate")
			}
		}
		return string(utf16.Decode(units)), nil
	case 1252, 65001:
		if n := bytes.IndexByte(b, 0); n >= 0 {
			b = b[:n]
		}
		if cp == 65001 {
			if !utf8.Valid(b) {
				return "", fmt.Errorf("invalid UTF-8 summary string")
			}
			return string(b), nil
		}
		out := make([]rune, 0, len(b))
		for _, c := range b {
			r := rune(c)
			if c >= 128 && c < 160 {
				r = summaryCP1252[c-128]
			}
			out = append(out, r)
		}
		return string(out), nil
	default:
		return "", fmt.Errorf("unsupported summary codepage %d", cp)
	}
}
