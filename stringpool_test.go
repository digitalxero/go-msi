package msi

// msi_stringpool_test.go
// Golden-byte, framing and roundtrip tests for the _StringPool/_StringData
// serializer and parser. The golden vectors are the worked examples from the
// format spec, cross-checked against rust-msi's stringpool.rs unit tests.
// These are internal tests (package msix) because the pool is unexported.

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMSIStringPool_Basic(t *testing.T) {
	p := newMSIStringPool(1252)

	ref1 := p.addString("Hello")
	ref2 := p.addString("World")
	ref3 := p.addString("Hello") // should reuse + incref

	require.Equal(t, uint32(1), ref1)
	require.Equal(t, uint32(2), ref2)
	require.Equal(t, ref1, ref3)

	assert.Equal(t, 2, p.numStrings())
	assert.Equal(t, uint32(2), p.refCount(ref1)) // Hello incref'ed
	assert.Equal(t, uint32(1), p.refCount(ref2))

	assert.Equal(t, "Hello", p.getString(ref1))
	assert.Equal(t, "World", p.getString(ref2))
	assert.Equal(t, ref1, p.refFor("Hello"))
	assert.Equal(t, uint32(0), p.refFor("missing"))

	assert.Equal(t, []byte("HelloWorld"), p.dataBytes())
}

func TestMSIStringPool_GoldenHelloWorld(t *testing.T) {
	// Spec 2.7 worked example: cp1252, "Hello" x2 refs then "World" x1 ref.
	p := newMSIStringPool(1252)
	p.addString("Hello")
	p.addString("Hello")
	p.addString("World")

	pool, err := p.poolBytes()
	require.NoError(t, err)
	assert.Equal(t, []byte{
		0xE4, 0x04, 0x00, 0x00, // u32le 1252, bit 31 clear (short refs)
		0x05, 0x00, 0x02, 0x00, // ID 1: len=5 refs=2 -> "Hello"
		0x05, 0x00, 0x01, 0x00, // ID 2: len=5 refs=1 -> "World"
	}, pool)
	assert.Equal(t, []byte("HelloWorld"), p.dataBytes())
}

func TestMSIStringPool_GoldenFooQuux(t *testing.T) {
	// rust-msi write_string_pool test vector: "Foo" x2, "Quux" x1, cp1252.
	p := newMSIStringPool(1252)
	p.addString("Foo")
	p.addString("Foo")
	p.addString("Quux")

	pool, err := p.poolBytes()
	require.NoError(t, err)
	assert.Equal(t, []byte{
		0xE4, 0x04, 0x00, 0x00,
		0x03, 0x00, 0x02, 0x00,
		0x04, 0x00, 0x01, 0x00,
	}, pool)
	assert.Equal(t, []byte("FooQuux"), p.dataBytes())
}

func TestMSIStringPool_GoldenBigString(t *testing.T) {
	// rust-msi deserialize_string_over_64k vector: cp65001, one 70000-byte
	// string with 1 ref -> [u16 0][u16 1][u32le 70000] (70000 = 0x11170).
	big := strings.Repeat("x", 70000)
	p := newMSIStringPool(65001)
	require.Equal(t, uint32(1), p.addString(big))

	pool, err := p.poolBytes()
	require.NoError(t, err)
	assert.Equal(t, []byte{
		0xE9, 0xFD, 0x00, 0x00, // u32le 65001
		0x00, 0x00, 0x01, 0x00, // big-string marker: len=0, refs=1
		0x70, 0x11, 0x01, 0x00, // u32le 70000
	}, pool)
	assert.Len(t, p.dataBytes(), 70000)
}

func TestMSIStringPool_BigStringRoundtripAndIDs(t *testing.T) {
	// A big string spans two pool slots but consumes ONE string ID: the next
	// string gets the next consecutive ID.
	big := strings.Repeat("B", 0x10000) // 65536 bytes, one past the short-form max
	p := newMSIStringPool(0)
	require.Equal(t, uint32(1), p.addString(big))
	require.Equal(t, uint32(2), p.addString("after"))
	p.addString("after") // refs=2

	poolB, err := p.poolBytes()
	require.NoError(t, err)
	dataB := p.dataBytes()
	require.Len(t, dataB, 0x10000+5)

	q, err := parseMSIStringPool(poolB, dataB)
	require.NoError(t, err)
	assert.Equal(t, big, q.getString(1))
	assert.Equal(t, uint32(1), q.refCount(1))
	assert.Equal(t, "after", q.getString(2))
	assert.Equal(t, uint32(2), q.refCount(2))
	assert.Equal(t, 2, q.numStrings())
	assert.False(t, q.isLongRefs())

	// Reserialization is byte-identical.
	poolB2, err := q.poolBytes()
	require.NoError(t, err)
	assert.Equal(t, poolB, poolB2)
	assert.Equal(t, dataB, q.dataBytes())
}

func TestMSIStringPool_BoundaryLength0xFFFF(t *testing.T) {
	// Length 0xFFFF still fits the short form (Wine uses sz < 0x10000).
	s := strings.Repeat("y", 0xFFFF)
	p := newMSIStringPool(0)
	p.addString(s)

	pool, err := p.poolBytes()
	require.NoError(t, err)
	require.Len(t, pool, 8) // header + one short entry
	assert.Equal(t, []byte{0xFF, 0xFF, 0x01, 0x00}, pool[4:8])

	q, err := parseMSIStringPool(pool, p.dataBytes())
	require.NoError(t, err)
	assert.Equal(t, s, q.getString(1))
}

func TestMSIStringPool_EmptyStringNeverPooled(t *testing.T) {
	// An interned "" would serialize as len=0/refs=1, which readers parse as a
	// big-string marker and desynchronize on. It must map to the reserved ID 0.
	p := newMSIStringPool(0)
	assert.Equal(t, uint32(0), p.addString(""))
	assert.Equal(t, uint32(0), p.addString(""))
	assert.Equal(t, uint32(0), p.refFor(""))
	assert.Equal(t, 0, p.numStrings())
	assert.Equal(t, "", p.getString(0))

	pool, err := p.poolBytes()
	require.NoError(t, err)
	assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, pool) // header only, codepage 0
	assert.Empty(t, p.dataBytes())
}

func TestMSIStringPool_HoleHandling(t *testing.T) {
	// A (0,0) slot is a hole: it consumes a string ID and zero data bytes.
	pool := []byte{
		0xE4, 0x04, 0x00, 0x00, // cp1252
		0x00, 0x00, 0x00, 0x00, // ID 1: hole
		0x02, 0x00, 0x03, 0x00, // ID 2: len=2 refs=3 -> "Hi"
	}
	data := []byte("Hi")

	p, err := parseMSIStringPool(pool, data)
	require.NoError(t, err)
	assert.Equal(t, 1, p.numStrings())
	assert.Equal(t, "", p.getString(1))
	assert.Equal(t, uint32(0), p.refCount(1))
	assert.Equal(t, "Hi", p.getString(2))
	assert.Equal(t, uint32(3), p.refCount(2))
	assert.Equal(t, uint32(2), p.refFor("Hi"))

	// forEachString skips holes but preserves IDs and order.
	var ids []uint32
	var vals []string
	p.forEachString(func(ref uint32, value string) {
		ids = append(ids, ref)
		vals = append(vals, value)
	})
	assert.Equal(t, []uint32{2}, ids)
	assert.Equal(t, []string{"Hi"}, vals)

	// Holes survive reserialization byte-for-byte.
	pool2, err := p.poolBytes()
	require.NoError(t, err)
	assert.Equal(t, pool, pool2)
	assert.Equal(t, data, p.dataBytes())
}

func TestMSIStringPool_LongRefPromotion(t *testing.T) {
	// Wine's rule: longRefs iff slot count including reserved ID 0 > 0xFFFF,
	// i.e. the flag flips when ID 0xFFFF is assigned (the 65535th string).
	p := newMSIStringPool(0)
	for i := 0; i < 0xFFFE; i++ {
		p.addString(fmt.Sprintf("s%05x", i))
	}
	assert.False(t, p.isLongRefs(), "highest ID 0xFFFE -> maxcount 0xFFFF -> still short")
	assert.Zero(t, p.codePage()&longStringRefsBit)

	require.Equal(t, uint32(0xFFFF), p.addString("the-promoting-string"))
	assert.True(t, p.isLongRefs(), "highest ID 0xFFFF -> maxcount 0x10000 -> long")
	assert.NotZero(t, p.codePage()&longStringRefsBit)

	pool, err := p.poolBytes()
	require.NoError(t, err)
	assert.Equal(t, longStringRefsBit, uint32(pool[3])<<24&longStringRefsBit,
		"header bit 31 must be set")

	// The flag survives a parse roundtrip (from the slot count and the header).
	q, err := parseMSIStringPool(pool, p.dataBytes())
	require.NoError(t, err)
	assert.True(t, q.isLongRefs())
}

func TestMSIStringPool_LongRefsForcedByHeader(t *testing.T) {
	// A parsed header with bit 31 set forces long refs even when the pool is
	// far below the slot threshold.
	pool := []byte{
		0xE4, 0x04, 0x00, 0x80, // cp1252 | longStringRefsBit
		0x01, 0x00, 0x01, 0x00, // ID 1: "a"
	}
	p, err := parseMSIStringPool(pool, []byte("a"))
	require.NoError(t, err)
	assert.True(t, p.isLongRefs())
	assert.Equal(t, uint32(1252)|longStringRefsBit, p.codePage())

	pool2, err := p.poolBytes()
	require.NoError(t, err)
	assert.Equal(t, pool, pool2)
}

func TestMSIStringPool_RefCountClamp(t *testing.T) {
	// Refcounts above 0xFFFF are clamped, never wrapped (a wrap to 0 would
	// turn the entry into hole/big-string framing).
	p := newMSIStringPool(0)
	p.addString("x")
	p.entries[1].refCount = 0x12345

	pool, err := p.poolBytes()
	require.NoError(t, err)
	require.Len(t, pool, 8)
	assert.Equal(t, []byte{0x01, 0x00, 0xFF, 0xFF}, pool[4:8])
}

func TestMSIStringPool_CodepageNeutralAndUTF8(t *testing.T) {
	// Declared 0 stays neutral while every string is pure ASCII.
	p := newMSIStringPool(0)
	p.addString("ascii only")
	assert.Equal(t, uint32(0), p.codePage())
	pool, err := p.poolBytes()
	require.NoError(t, err)
	assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, pool[:4])

	// Declared 0 + any non-ASCII string -> honest UTF-8 header (65001), since
	// we always store raw UTF-8 bytes and neutral is only safe for ASCII.
	p = newMSIStringPool(0)
	p.addString("héllo")
	assert.Equal(t, uint32(65001), p.codePage())
	pool, err = p.poolBytes()
	require.NoError(t, err)
	assert.Equal(t, []byte{0xE9, 0xFD, 0x00, 0x00}, pool[:4])
	// byteLength counts encoded (UTF-8) bytes: 'é' is two bytes.
	assert.Equal(t, []byte{0x06, 0x00, 0x01, 0x00}, pool[4:8])

	// An explicit codepage is emitted verbatim.
	p = newMSIStringPool(65001)
	assert.Equal(t, uint32(65001), p.codePage())
	p = newMSIStringPool(932)
	p.addString("日本語")
	assert.Equal(t, uint32(932), p.codePage())
}

func TestParseMSIStringPool_EmptyAndShortPools(t *testing.T) {
	// Per Wine, a pool of <= 4 bytes implies codepage 0, short refs, no entries.
	for _, pool := range [][]byte{nil, {}, {0xE4, 0x04, 0x00, 0x00}} {
		p, err := parseMSIStringPool(pool, nil)
		require.NoError(t, err)
		assert.Equal(t, uint32(0), p.codePage())
		assert.False(t, p.isLongRefs())
		assert.Equal(t, 0, p.numStrings())
	}

	// ...but data bytes with no entries to cover them are an error.
	_, err := parseMSIStringPool(nil, []byte("orphan"))
	assert.Error(t, err)
}

func TestParseMSIStringPool_MalformedInputs(t *testing.T) {
	// Entry region not a multiple of 4.
	_, err := parseMSIStringPool([]byte{0xE4, 0x04, 0x00, 0x00, 0x05, 0x00}, nil)
	assert.Error(t, err)

	// Big-string marker as the last slot (missing the u32 length extension).
	_, err = parseMSIStringPool([]byte{
		0xE4, 0x04, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00,
	}, nil)
	assert.Error(t, err)

	// Big-string entry declaring zero length (would desync on reserialize).
	_, err = parseMSIStringPool([]byte{
		0xE4, 0x04, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}, nil)
	assert.Error(t, err)

	// _StringData shorter than the pool lengths require.
	_, err = parseMSIStringPool([]byte{
		0xE4, 0x04, 0x00, 0x00,
		0x05, 0x00, 0x01, 0x00,
	}, []byte("Hi"))
	assert.Error(t, err)

	// _StringData with trailing bytes not covered by the pool (Wine errors
	// when datasize != offset).
	_, err = parseMSIStringPool([]byte{
		0xE4, 0x04, 0x00, 0x00,
		0x05, 0x00, 0x01, 0x00,
	}, []byte("HelloX"))
	assert.Error(t, err)
}

func TestMSIStringPool_DeterministicFuzzRoundtrip(t *testing.T) {
	// Deterministically generate a few hundred strings (ASCII + multibyte +
	// duplicates + one big string), serialize, parse back, compare everything,
	// and require byte-identical reserialization.
	rng := rand.New(rand.NewSource(42))
	alphabet := []rune("abcdefghijklmnopqrstuvwxyzABC0123456789._- äöü漢字😀")

	p := newMSIStringPool(0)
	for i := 0; i < 400; i++ {
		n := 1 + rng.Intn(40)
		var sb strings.Builder
		for j := 0; j < n; j++ {
			sb.WriteRune(alphabet[rng.Intn(len(alphabet))])
		}
		s := sb.String()
		p.addString(s)
		for extra := rng.Intn(3); extra > 0; extra-- {
			p.addString(s) // bump refcounts deterministically
		}
	}
	big := strings.Repeat("Z", 0x10001)
	p.addString(big)

	poolB, err := p.poolBytes()
	require.NoError(t, err)
	dataB := p.dataBytes()

	q, err := parseMSIStringPool(poolB, dataB)
	require.NoError(t, err)

	assert.Equal(t, p.numStrings(), q.numStrings())
	assert.Equal(t, p.codePage(), q.codePage())
	assert.Equal(t, p.isLongRefs(), q.isLongRefs())

	count := 0
	p.forEachString(func(ref uint32, value string) {
		count++
		assert.Equal(t, value, q.getString(ref), "string id %d", ref)
		assert.Equal(t, p.refCount(ref), q.refCount(ref), "refcount id %d", ref)
		assert.Equal(t, ref, q.refFor(value), "refFor id %d", ref)
	})
	assert.Equal(t, p.numStrings(), count)

	poolB2, err := q.poolBytes()
	require.NoError(t, err)
	assert.Equal(t, poolB, poolB2, "reserialized _StringPool must be byte-identical")
	assert.Equal(t, dataB, q.dataBytes(), "reserialized _StringData must be byte-identical")
}
