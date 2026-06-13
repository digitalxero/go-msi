package msi

// msi_transform_encode_internal_test.go — P9.2 transform row encode/decode.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// transformTestPool builds a pool pre-interned with the given strings (plus the
// reserved empty ID 0), suitable for encode/decode round-trips.
func transformTestPool(strs ...string) *msiStringPool {
	p := newMSIStringPool(utf8MSICodepage)
	for _, s := range strs {
		p.addString(s)
	}
	return p
}

// transformCols returns the columns of a real catalog table for tests.
func transformCols(t *testing.T, table string) []msiColumn {
	t.Helper()
	tbl := createMSITableFromCatalog(table)
	require.NotNil(t, tbl, "catalog table %s", table)
	return tbl.columns()
}

func TestTransformEncode_InsertRoundTrip(t *testing.T) {
	// Property(Property TEXT key, Value TEXT). Insert a new property row.
	cols := transformCols(t, "Property")
	pool := transformTestPool("INSTALLLEVEL", "3")

	rows := []transformRow{
		{op: transformInsert, cells: []any{"INSTALLLEVEL", "3"}},
	}
	stream, err := encodeTransformTableStream(cols, rows, pool)
	require.NoError(t, err)

	// First two bytes are the mask: full-row, num_cols in the high byte.
	require.GreaterOrEqual(t, len(stream), 2)
	mask := uint16(stream[0]) | uint16(stream[1])<<8
	assert.Equal(t, uint16(1), mask&1, "insert sets the full-row low bit")
	assert.Equal(t, len(cols), int(mask>>8), "high byte is the column count")

	got, err := decodeTransformTableStream(cols, stream, pool)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, transformInsert, got[0].op)
	assert.Equal(t, "INSTALLLEVEL", got[0].cells[0])
	assert.Equal(t, "3", got[0].cells[1])
}

func TestTransformEncode_DeleteRoundTrip(t *testing.T) {
	cols := transformCols(t, "Property")
	pool := transformTestPool("OBSOLETE")

	rows := []transformRow{
		{op: transformDelete, cells: []any{"OBSOLETE", nil}},
	}
	stream, err := encodeTransformTableStream(cols, rows, pool)
	require.NoError(t, err)

	// Delete row: mask 0 then only the key cell. Property key is one string ref.
	mask := uint16(stream[0]) | uint16(stream[1])<<8
	assert.Equal(t, uint16(0), mask, "delete uses a zero mask")
	width := msiCellWidth(cols[0], pool.isLongRefs())
	assert.Equal(t, 2+width, len(stream), "delete writes only the key cell after the mask")

	got, err := decodeTransformTableStream(cols, stream, pool)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, transformDelete, got[0].op)
	assert.Equal(t, "OBSOLETE", got[0].cells[0])
	assert.Nil(t, got[0].cells[1], "non-key cells are absent in a delete")
}

func TestTransformEncode_UpdateRoundTrip(t *testing.T) {
	// Property: change Value of an existing key. Column 1 (Value, non-key) is
	// the only changed cell; column 0 (key) is always carried.
	cols := transformCols(t, "Property")
	pool := transformTestPool("ARPCOMMENTS", "new value")

	changed := make([]bool, len(cols))
	changed[1] = true
	rows := []transformRow{
		{op: transformUpdate, cells: []any{"ARPCOMMENTS", "new value"}, changed: changed},
	}
	stream, err := encodeTransformTableStream(cols, rows, pool)
	require.NoError(t, err)

	mask := uint16(stream[0]) | uint16(stream[1])<<8
	assert.Equal(t, uint16(0), mask&1, "update never sets the full-row bit")
	assert.NotEqual(t, uint16(0), mask, "update mask is non-zero")
	assert.Equal(t, uint16(1<<1), mask, "bit for column index 1 (Value) is set")

	got, err := decodeTransformTableStream(cols, stream, pool)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, transformUpdate, got[0].op)
	assert.Equal(t, "ARPCOMMENTS", got[0].cells[0], "key carried")
	assert.Equal(t, "new value", got[0].cells[1], "changed value carried")
	require.NotNil(t, got[0].changed)
	assert.True(t, got[0].changed[1])
	assert.False(t, got[0].changed[0])
}

func TestTransformEncode_IntegerCellsRoundTrip(t *testing.T) {
	// FeatureComponents has only string keys; use Media for an int column.
	// Media(DiskId i2 key, LastSequence i2, Cabinet, VolumeLabel, Source,
	// DiskPrompt...). Update LastSequence (an int16 non-key column).
	cols := transformCols(t, "Media")
	// Find the LastSequence column index.
	lastSeq := -1
	for i, c := range cols {
		if c.name() == "LastSequence" {
			lastSeq = i
		}
	}
	require.GreaterOrEqual(t, lastSeq, 0)

	pool := transformTestPool()
	changed := make([]bool, len(cols))
	changed[lastSeq] = true
	cells := make([]any, len(cols))
	cells[0] = int16(1) // DiskId key
	cells[lastSeq] = int16(42)
	rows := []transformRow{{op: transformUpdate, cells: cells, changed: changed}}

	stream, err := encodeTransformTableStream(cols, rows, pool)
	require.NoError(t, err)
	got, err := decodeTransformTableStream(cols, stream, pool)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, int16(1), got[0].cells[0])
	assert.Equal(t, int16(42), got[0].cells[lastSeq])
}

func TestTransformEncode_MultipleRows(t *testing.T) {
	cols := transformCols(t, "Property")
	pool := transformTestPool("A", "1", "B", "C", "2")

	chg := make([]bool, len(cols))
	chg[1] = true
	rows := []transformRow{
		{op: transformInsert, cells: []any{"A", "1"}},
		{op: transformDelete, cells: []any{"B", nil}},
		{op: transformUpdate, cells: []any{"C", "2"}, changed: chg},
	}
	stream, err := encodeTransformTableStream(cols, rows, pool)
	require.NoError(t, err)
	got, err := decodeTransformTableStream(cols, stream, pool)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, transformInsert, got[0].op)
	assert.Equal(t, transformDelete, got[1].op)
	assert.Equal(t, transformUpdate, got[2].op)
	assert.Equal(t, "C", got[2].cells[0])
	assert.Equal(t, "2", got[2].cells[1])
}
