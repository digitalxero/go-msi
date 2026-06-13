package msi

// msi_mszip.go
// MSZIP frame sanitizer.
//
// Go's compress/flate emits RFC 1951 §3.2.7 "single code" distance tables
// (one distance code of bit length 1, an intentionally incomplete table) for
// data whose matches all share one distance — e.g. all-zero payloads or
// short repeating patterns, both common in real installers. zlib accepts
// those tables, but libmspack (cabextract, many AV engines) rejects them
// with INF_ERR_DISTANCETBL, and Microsoft's own FCI never produces them, so
// native FDI behavior is unverified. A cab containing such a block is
// therefore not safely portable.
//
// msiSanitizeMSZIPStream parses a frame's deflate stream; when every dynamic
// block has a sound distance table the stream is returned unchanged
// (byte-identical). Otherwise the whole frame is re-emitted as a single
// fixed-Huffman block from the decoded token stream — Go's match finding is
// preserved, only the entropy coding changes, and fixed blocks carry no
// Huffman table headers at all.

import (
	"fmt"
)

// --- token representation ---

// A deflate token: literals are 0..255; matches encode length<<16 | distance
// with length 3..258 and distance 1..32768.
type mszipToken uint32

func mszipLiteral(b byte) mszipToken { return mszipToken(b) }

func mszipMatch(length, dist int) mszipToken {
	return mszipToken(length<<16 | dist)
}

func (t mszipToken) isMatch() bool          { return t > 0xFF }
func (t mszipToken) literal() byte          { return byte(t) }
func (t mszipToken) lengthDist() (l, d int) { return int(t >> 16), int(t & 0xFFFF) }

// --- bit reader (LSB-first, per RFC 1951) ---

type mszipBitReader struct {
	data []byte
	pos  int    // next byte index
	bits uint32 // bit buffer, LSB = next bit
	n    uint   // bits in buffer
}

func (r *mszipBitReader) readBits(count uint) (uint32, error) {
	for r.n < count {
		if r.pos >= len(r.data) {
			return 0, fmt.Errorf("mszip: unexpected end of deflate stream")
		}
		r.bits |= uint32(r.data[r.pos]) << r.n
		r.pos++
		r.n += 8
	}
	v := r.bits & ((1 << count) - 1)
	r.bits >>= count
	r.n -= count
	return v, nil
}

// alignByte discards bits up to the next byte boundary.
func (r *mszipBitReader) alignByte() {
	drop := r.n % 8
	r.bits >>= drop
	r.n -= drop
}

// --- canonical Huffman decoding ---

// mszipHuffman decodes canonical Huffman codes from a code-length list.
// Incomplete tables (e.g. the single-code distance case) decode fine; only
// codes actually present resolve to symbols.
type mszipHuffman struct {
	// counts[l] = number of codes of length l; symbols sorted by (length, symbol).
	counts  [16]int
	symbols []int
}

func newMSZIPHuffman(lengths []int) *mszipHuffman {
	h := &mszipHuffman{}
	for _, l := range lengths {
		if l > 0 {
			h.counts[l]++
		}
	}
	for l := 1; l <= 15; l++ {
		for sym, sl := range lengths {
			if sl == l {
				h.symbols = append(h.symbols, sym)
			}
		}
	}
	return h
}

// numCodes returns how many symbols have a nonzero length.
func (h *mszipHuffman) numCodes() int { return len(h.symbols) }

// decode reads one symbol, MSB-first per RFC 1951.
func (h *mszipHuffman) decode(r *mszipBitReader) (int, error) {
	code, first, index := 0, 0, 0
	for l := 1; l <= 15; l++ {
		b, err := r.readBits(1)
		if err != nil {
			return 0, err
		}
		code |= int(b)
		count := h.counts[l]
		if code-first < count {
			return h.symbols[index+code-first], nil
		}
		index += count
		first = (first + count) << 1
		code <<= 1
	}
	return 0, fmt.Errorf("mszip: invalid huffman code")
}

// --- RFC 1951 constant tables ---

var (
	mszipLengthBase  = [29]int{3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258}
	mszipLengthExtra = [29]uint{0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0}
	mszipDistBase    = [30]int{1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577}
	mszipDistExtra   = [30]uint{0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13}
	mszipCLOrder     = [19]int{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15}
)

func mszipFixedLitLengths() []int {
	lens := make([]int, 288)
	for i := 0; i < 144; i++ {
		lens[i] = 8
	}
	for i := 144; i < 256; i++ {
		lens[i] = 9
	}
	for i := 256; i < 280; i++ {
		lens[i] = 7
	}
	for i := 280; i < 288; i++ {
		lens[i] = 8
	}
	return lens
}

func mszipFixedDistLengths() []int {
	lens := make([]int, 30)
	for i := range lens {
		lens[i] = 5
	}
	return lens
}

// --- deflate stream -> tokens ---

// mszipDecodeResult is the parsed form of one complete deflate stream.
type mszipDecodeResult struct {
	tokens     []mszipToken
	degenerate bool // any dynamic block had a single-code distance table
	produced   int  // total uncompressed bytes
}

func mszipDecodeStream(stream []byte) (*mszipDecodeResult, error) {
	r := &mszipBitReader{data: stream}
	res := &mszipDecodeResult{}

	for {
		bfinal, err := r.readBits(1)
		if err != nil {
			return nil, err
		}
		btype, err := r.readBits(2)
		if err != nil {
			return nil, err
		}

		switch btype {
		case 0: // stored
			r.alignByte()
			lenv, err := r.readBits(16)
			if err != nil {
				return nil, err
			}
			nlen, err := r.readBits(16)
			if err != nil {
				return nil, err
			}
			if lenv != ^nlen&0xFFFF {
				return nil, fmt.Errorf("mszip: stored block length complement mismatch")
			}
			for i := 0; i < int(lenv); i++ {
				b, err := r.readBits(8)
				if err != nil {
					return nil, err
				}
				res.tokens = append(res.tokens, mszipLiteral(byte(b)))
				res.produced++
			}

		case 1, 2: // fixed / dynamic huffman
			var lit, dist *mszipHuffman
			if btype == 1 {
				lit = newMSZIPHuffman(mszipFixedLitLengths())
				dist = newMSZIPHuffman(mszipFixedDistLengths())
			} else {
				lit, dist, err = mszipReadDynamicTables(r)
				if err != nil {
					return nil, err
				}
				if dist.numCodes() < 2 {
					res.degenerate = true
				}
			}
			if err := mszipDecodeBlockBody(r, lit, dist, res); err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("mszip: invalid deflate block type 3")
		}

		if bfinal == 1 {
			return res, nil
		}
	}
}

func mszipReadDynamicTables(r *mszipBitReader) (lit, dist *mszipHuffman, err error) {
	hlit, err := r.readBits(5)
	if err != nil {
		return nil, nil, err
	}
	hdist, err := r.readBits(5)
	if err != nil {
		return nil, nil, err
	}
	hclen, err := r.readBits(4)
	if err != nil {
		return nil, nil, err
	}
	nlit, ndist, ncl := int(hlit)+257, int(hdist)+1, int(hclen)+4

	clLens := make([]int, 19)
	for i := 0; i < ncl; i++ {
		v, err := r.readBits(3)
		if err != nil {
			return nil, nil, err
		}
		clLens[mszipCLOrder[i]] = int(v)
	}
	cl := newMSZIPHuffman(clLens)

	lens := make([]int, 0, nlit+ndist)
	for len(lens) < nlit+ndist {
		sym, err := cl.decode(r)
		if err != nil {
			return nil, nil, err
		}
		switch {
		case sym < 16:
			lens = append(lens, sym)
		case sym == 16:
			if len(lens) == 0 {
				return nil, nil, fmt.Errorf("mszip: repeat code with no previous length")
			}
			n, err := r.readBits(2)
			if err != nil {
				return nil, nil, err
			}
			last := lens[len(lens)-1]
			for i := 0; i < int(n)+3; i++ {
				lens = append(lens, last)
			}
		case sym == 17:
			n, err := r.readBits(3)
			if err != nil {
				return nil, nil, err
			}
			for i := 0; i < int(n)+3; i++ {
				lens = append(lens, 0)
			}
		default: // 18
			n, err := r.readBits(7)
			if err != nil {
				return nil, nil, err
			}
			for i := 0; i < int(n)+11; i++ {
				lens = append(lens, 0)
			}
		}
	}
	if len(lens) != nlit+ndist {
		return nil, nil, fmt.Errorf("mszip: code length run overflows table")
	}
	return newMSZIPHuffman(lens[:nlit]), newMSZIPHuffman(lens[nlit:]), nil
}

func mszipDecodeBlockBody(r *mszipBitReader, lit, dist *mszipHuffman, res *mszipDecodeResult) error {
	for {
		sym, err := lit.decode(r)
		if err != nil {
			return err
		}
		switch {
		case sym < 256:
			res.tokens = append(res.tokens, mszipLiteral(byte(sym)))
			res.produced++
		case sym == 256:
			return nil
		case sym <= 285:
			code := sym - 257
			extra, err := r.readBits(mszipLengthExtra[code])
			if err != nil {
				return err
			}
			length := mszipLengthBase[code] + int(extra)

			dsym, err := dist.decode(r)
			if err != nil {
				return err
			}
			if dsym >= 30 {
				return fmt.Errorf("mszip: invalid distance symbol %d", dsym)
			}
			dextra, err := r.readBits(mszipDistExtra[dsym])
			if err != nil {
				return err
			}
			d := mszipDistBase[dsym] + int(dextra)
			if d > res.produced {
				return fmt.Errorf("mszip: match distance %d exceeds produced output %d", d, res.produced)
			}
			res.tokens = append(res.tokens, mszipMatch(length, d))
			res.produced += length
		default:
			return fmt.Errorf("mszip: invalid literal/length symbol %d", sym)
		}
	}
}

// --- tokens -> fixed-Huffman deflate stream ---

type mszipBitWriter struct {
	out  []byte
	bits uint32
	n    uint
}

// writeBits writes count bits LSB-first (extra bits, headers).
func (w *mszipBitWriter) writeBits(v uint32, count uint) {
	w.bits |= v << w.n
	w.n += count
	for w.n >= 8 {
		w.out = append(w.out, byte(w.bits))
		w.bits >>= 8
		w.n -= 8
	}
}

// writeCode writes a Huffman code MSB-first per RFC 1951 §3.1.1.
func (w *mszipBitWriter) writeCode(code uint32, count uint) {
	var rev uint32
	for i := uint(0); i < count; i++ {
		rev = rev<<1 | (code>>i)&1
	}
	w.writeBits(rev, count)
}

func (w *mszipBitWriter) flush() []byte {
	if w.n > 0 {
		w.out = append(w.out, byte(w.bits))
		w.bits, w.n = 0, 0
	}
	return w.out
}

// mszipFixedLitCode returns the fixed-Huffman code and bit count for a
// literal/length symbol (RFC 1951 §3.2.6).
func mszipFixedLitCode(sym int) (code uint32, bits uint) {
	switch {
	case sym < 144:
		return uint32(0x30 + sym), 8
	case sym < 256:
		return uint32(0x190 + sym - 144), 9
	case sym < 280:
		return uint32(sym - 256), 7
	default:
		return uint32(0xC0 + sym - 280), 8
	}
}

// mszipLengthSymbol maps a match length 3..258 to (symbol, extra bits, extra
// value). Length 258 hits base[28] first, yielding the canonical symbol 285
// with zero extra bits rather than 284+31.
func mszipLengthSymbol(length int) (sym int, extra uint, extraVal uint32) {
	for i := 28; i >= 0; i-- {
		if length >= mszipLengthBase[i] {
			return 257 + i, mszipLengthExtra[i], uint32(length - mszipLengthBase[i])
		}
	}
	return 0, 0, 0
}

// mszipDistSymbol maps a distance 1..32768 to (symbol, extra bits, extra value).
func mszipDistSymbol(d int) (sym int, extra uint, extraVal uint32) {
	for i := 29; i >= 0; i-- {
		if d >= mszipDistBase[i] {
			return i, mszipDistExtra[i], uint32(d - mszipDistBase[i])
		}
	}
	return 0, 0, 0
}

// mszipEncodeFixed emits the token stream as one fixed-Huffman deflate block
// with BFINAL set.
func mszipEncodeFixed(tokens []mszipToken) []byte {
	w := &mszipBitWriter{out: make([]byte, 0, 1024)}
	w.writeBits(1, 1) // BFINAL
	w.writeBits(1, 2) // BTYPE=01 fixed

	for _, t := range tokens {
		if !t.isMatch() {
			code, bits := mszipFixedLitCode(int(t.literal()))
			w.writeCode(code, bits)
			continue
		}
		length, d := t.lengthDist()
		sym, extra, extraVal := mszipLengthSymbol(length)
		code, bits := mszipFixedLitCode(sym)
		w.writeCode(code, bits)
		if extra > 0 {
			w.writeBits(extraVal, extra)
		}
		dsym, dext, dextVal := mszipDistSymbol(d)
		w.writeCode(uint32(dsym), 5)
		if dext > 0 {
			w.writeBits(dextVal, dext)
		}
	}

	code, bits := mszipFixedLitCode(256) // end of block
	w.writeCode(code, bits)
	return w.flush()
}

// msiSanitizeMSZIPStream returns stream unchanged when it is safe for strict
// decoders, or a token-equivalent fixed-Huffman re-encoding when any dynamic
// block carries a degenerate distance table.
func msiSanitizeMSZIPStream(stream []byte) ([]byte, error) {
	res, err := mszipDecodeStream(stream)
	if err != nil {
		return nil, err
	}
	if !res.degenerate {
		return stream, nil
	}
	return mszipEncodeFixed(res.tokens), nil
}
