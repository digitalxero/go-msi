package msi

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// msi_transform_encode.go — P9 MST transform row encoding/decoding.
//
// A transform table stream is ROW-MAJOR (unlike the column-major base table
// streams): each row is a 16-bit little-endian mask followed by the cells of
// the columns the mask marks present, each cell in its normal on-disk width
// (int16=2, int32=4, string=2 or 3 by the long-ref flag). String cells
// reference the TRANSFORM's OWN string pool — an .mst carries its own
// _StringPool/_StringData and the cell integers are IDs into that pool, which
// the applier resolves and re-interns into the base database (confirmed against
// Wine dlls/msi/table.c table_load_transform + msi_table_apply_transform).
//
// Mask semantics (Wine table_load_transform):
//
//	mask = rawdata[n] | rawdata[n+1]<<8
//	if (mask & 1):   full row — num_cols = mask>>8; columns 0..num_cols-1 are
//	                 all present in order (INSERT / whole-row replace).
//	else if mask==0: only key columns are present (DELETE — keys identify the
//	                 row to drop).
//	else:            bitmask — column i is present iff it is a key OR
//	                 (mask & (1<<i)); the non-key set bits mark the changed
//	                 cells (UPDATE).
//
// Bit 0 doubles as the full-row discriminator, so an UPDATE never sets it; if a
// non-key column at index 0 changes we fall back to a full-row replace (which
// carries every cell and is always correct).

// transformOp is the kind of delta a transform row encodes.
type transformOp int

const (
	transformInsert transformOp = iota // whole row present (mask&1 set)
	transformUpdate                    // bitmask of changed non-key columns
	transformDelete                    // mask == 0, key columns only
)

// transformRow is one delta row for a single table in a transform stream.
type transformRow struct {
	op transformOp
	// cells holds one entry per column (len == number of columns). For insert
	// every entry is meaningful; for update the key cells plus the changed cells
	// are meaningful (unchanged non-key entries are ignored); for delete only
	// the key cells are used.
	cells []any
	// changed marks the non-key columns that differ (update only); len==numCols.
	// nil for insert and delete.
	changed []bool
}

// transformRowMask computes the 16-bit mask for one delta row and the ordered
// list of column indexes whose cells must be serialized after it.
func transformRowMask(cols []msiColumn, r transformRow) (uint16, []int, error) {
	switch r.op {
	case transformDelete:
		var present []int
		for i, c := range cols {
			if c.isKey() {
				present = append(present, i)
			}
		}
		return 0, present, nil

	case transformInsert:
		if len(cols) > 0xff {
			return 0, nil, fmt.Errorf("transform: %d columns exceed the 255-column full-row mask limit", len(cols))
		}
		present := make([]int, len(cols))
		for i := range cols {
			present[i] = i
		}
		return uint16(len(cols))<<8 | 1, present, nil

	default: // transformUpdate
		var mask uint16
		for i, c := range cols {
			if c.isKey() {
				continue
			}
			if i < len(r.changed) && r.changed[i] {
				if i == 0 {
					// Bit 0 is the full-row discriminator: a non-key column 0
					// cannot be expressed by the bitmask, so replace the row.
					return transformRowMask(cols, transformRow{op: transformInsert, cells: r.cells})
				}
				mask |= 1 << uint(i)
			}
		}
		var present []int
		for i, c := range cols {
			if c.isKey() || mask&(1<<uint(i)) != 0 {
				present = append(present, i)
			}
		}
		return mask, present, nil
	}
}

// encodeTransformTableStream serializes a table's delta rows into a transform
// table stream. String cells must already be interned in pool.
func encodeTransformTableStream(cols []msiColumn, rows []transformRow, pool *msiStringPool) ([]byte, error) {
	longRefs := pool.isLongRefs()
	var buf bytes.Buffer
	for ri, r := range rows {
		mask, present, err := transformRowMask(cols, r)
		if err != nil {
			return nil, fmt.Errorf("transform row %d: %w", ri, err)
		}
		var hdr [2]byte
		binary.LittleEndian.PutUint16(hdr[:], mask)
		buf.Write(hdr[:])
		for _, ci := range present {
			var val any
			if ci < len(r.cells) {
				val = r.cells[ci]
			}
			if err := writeEncodedMSITableValue(&buf, val, cols[ci].typ(), pool, longRefs); err != nil {
				return nil, fmt.Errorf("transform row %d column %s: %w", ri, cols[ci].name(), err)
			}
		}
	}
	return buf.Bytes(), nil
}

// decodeTransformTableStream is the inverse of encodeTransformTableStream: it
// walks the row-major stream and returns one transformRow per delta. cells is
// always allocated to len(cols); only the present columns are filled.
func decodeTransformTableStream(cols []msiColumn, stream []byte, pool *msiStringPool) ([]transformRow, error) {
	longRefs := pool.isLongRefs()
	widths := make([]int, len(cols))
	for i, c := range cols {
		widths[i] = msiCellWidth(c, longRefs)
	}

	var rows []transformRow
	off := 0
	for off < len(stream) {
		if off+2 > len(stream) {
			return nil, fmt.Errorf("transform stream truncated reading mask at offset %d", off)
		}
		mask := binary.LittleEndian.Uint16(stream[off:])
		off += 2

		var (
			op      transformOp
			present []int
			changed []bool
		)
		switch {
		case mask&1 != 0:
			op = transformInsert
			n := int(mask >> 8)
			if n > len(cols) {
				return nil, fmt.Errorf("transform full-row mask claims %d columns but the table has %d", n, len(cols))
			}
			for i := 0; i < n; i++ {
				present = append(present, i)
			}
		case mask == 0:
			op = transformDelete
			for i, c := range cols {
				if c.isKey() {
					present = append(present, i)
				}
			}
		default:
			op = transformUpdate
			changed = make([]bool, len(cols))
			for i, c := range cols {
				bitSet := mask&(1<<uint(i)) != 0
				if c.isKey() || bitSet {
					present = append(present, i)
				}
				if bitSet && !c.isKey() {
					changed[i] = true
				}
			}
		}

		cells := make([]any, len(cols))
		for _, ci := range present {
			w := widths[ci]
			if off+w > len(stream) {
				return nil, fmt.Errorf("transform stream truncated reading column %s at offset %d (need %d bytes)", cols[ci].name(), off, w)
			}
			val, err := decodeMSITableCell(stream[off:off+w], cols[ci], pool)
			if err != nil {
				return nil, fmt.Errorf("transform column %s: %w", cols[ci].name(), err)
			}
			cells[ci] = val
			off += w
		}
		rows = append(rows, transformRow{op: op, cells: cells, changed: changed})
	}
	return rows, nil
}
