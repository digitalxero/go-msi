package msi

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSerializedStringCountsMatchTableReferences(t *testing.T) {
	db, _ := buildP3RoundTripPackage(t)
	streams, err := serializeMSIStreams(db, msiSummaryInfo{}, cabBuildOptions{})
	require.NoError(t, err)
	data := make(map[string][]byte)
	for _, stream := range streams {
		data[stream.name] = stream.data
	}
	pool, err := parseMSIStringPool(data[encodeMSIStreamName(true, "_StringPool")], data[encodeMSIStreamName(true, "_StringData")])
	require.NoError(t, err)
	counts := make(map[uint32]uint32)
	// Count actual encoded string IDs independently, including both catalogs
	// and _Validation. Binary presence flags and integers are not references.
	for _, name := range db.Tables() {
		table, err := db.GetTable(name)
		require.NoError(t, err)
		stream := data[encodeMSIStreamName(true, name)]
		offset := 0
		for _, column := range table.columns() {
			width := msiCellWidth(column, pool.isLongRefs())
			for range table.rows() {
				if column.typ() != msiColInteger && column.typ() != msiColDoubleInteger && column.typ() != msiColDateTime && column.typ() != msiColBinary {
					ref := uint32(binary.LittleEndian.Uint16(stream[offset:]))
					if width == 3 {
						ref |= uint32(stream[offset+2]) << 16
					}
					if ref != 0 {
						counts[ref]++
					}
				}
				offset += width
			}
		}
		assert.Equal(t, len(stream), offset, name)
	}
	pool.forEachString(func(ref uint32, value string) {
		assert.Equal(t, counts[ref], pool.refCount(ref), "string %q", value)
		assert.Positive(t, counts[ref], "unreferenced string %q", value)
	})
	assert.Zero(t, pool.refFor("_Tables"), "implicit catalog names are not table cells")
}
