package msi

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func wideTestColumns(count int) []msiColumn {
	cols := make([]msiColumn, count)
	for i := range cols {
		builder := newMSIColumnBuilder().WithName(fmt.Sprintf("Col%d", i)).WithType(msiColInteger)
		if i == 0 {
			builder.AsKey()
		}
		cols[i] = builder.Build()
	}
	return cols
}

func TestMSITableColumnLimit(t *testing.T) {
	for _, count := range []int{31, 32, 256} {
		for _, populated := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/populated=%t", count, populated), func(t *testing.T) {
				cols := wideTestColumns(count)
				table := newMSITableBuilder().WithName("Wide").WithColumns(cols...).Build()
				if populated {
					cells := make([]any, count)
					for i := range cells {
						cells[i] = int16(i + 1)
					}
					require.NoError(t, table.addRow(newMSIRowBuilder().WithColumns(cols...).WithValues(cells...).Build()))
				}
				_, encodeErr := serializeRealTableData(table, newMSIStringPool(0))
				if count == 31 {
					require.NoError(t, table.validate())
					require.NoError(t, encodeErr)
				} else {
					require.ErrorContains(t, table.validate(), "limit of 31")
					require.ErrorContains(t, encodeErr, "limit of 31")
				}
			})
		}
	}
}

func TestTransformColumnLimit(t *testing.T) {
	cols := wideTestColumns(32)
	for _, op := range []transformOp{transformInsert, transformUpdate, transformDelete} {
		_, _, err := transformRowMask(cols, transformRow{op: op})
		require.ErrorContains(t, err, "limit of 31")
	}
	_, err := encodeTransformTableStream(cols, nil, newMSIStringPool(0))
	require.ErrorContains(t, err, "limit of 31", "empty transforms also validate schemas")
}

func TestTransformWideUpdatePreservesHighColumns(t *testing.T) {
	cols := wideTestColumns(31)
	for _, index := range []int{15, 16, 30} {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			cells, changed := make([]any, 31), make([]bool, 31)
			cells[0], cells[index], changed[index] = int16(1), int16(99), true
			pool := newMSIStringPool(0)
			stream, err := encodeTransformTableStream(cols, []transformRow{{op: transformUpdate, cells: cells, changed: changed}}, pool)
			require.NoError(t, err)
			rows, err := decodeTransformTableStream(cols, stream, pool)
			require.NoError(t, err)
			require.Len(t, rows, 1)
			assert.Equal(t, int16(99), rows[0].cells[index])
		})
	}
}
