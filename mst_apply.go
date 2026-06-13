package msi

import (
	"fmt"
	"sort"
)

// msi_mst_apply.go — P9.4 transform apply, the generate→apply round-trip oracle.
//
// applyMSITransform replays a transform's delta streams onto a base database
// model and returns the resulting per-table row sets. It mirrors what msiexec
// does (insert/update/delete by primary key) but works purely in-memory so the
// test suite can assert MST(base→target) applied to base == target without any
// external installer. It is intentionally unexported: production code emits
// transforms (WriteMST / embedded :LCID), msiexec applies them.

// transformedTable is a base table after a transform has been applied: its
// columns plus the surviving/added rows as decoded value slices.
type transformedTable struct {
	cols []msiColumn
	rows [][]any
}

// applyMSITransform applies the transform stream set to baseDB and returns the
// resulting table set keyed by table name. Tables the transform does not touch
// are carried through from the base unchanged.
func applyMSITransform(baseDB msiDatabase, mstStreams []msiStream) (map[string]transformedTable, error) {
	// Parse the transform's own string pool from its streams.
	var poolBytes, dataBytes []byte
	deltaStreams := map[string][]byte{}
	for _, s := range mstStreams {
		name, isTable := decodeMSIStreamName(s.name)
		if !isTable {
			continue // \x05SummaryInformation and the like
		}
		switch name {
		case msiStringPoolStreamName:
			poolBytes = s.data
		case msiStringDataStreamName:
			dataBytes = s.data
		default:
			deltaStreams[name] = s.data
		}
	}
	if poolBytes == nil {
		return nil, fmt.Errorf("msi transform: no _StringPool stream")
	}
	pool, err := parseMSIStringPool(poolBytes, dataBytes)
	if err != nil {
		return nil, fmt.Errorf("msi transform: parsing string pool: %w", err)
	}

	// Seed the result from the base: every base table, rows copied.
	result := map[string]transformedTable{}
	for _, name := range baseDB.Tables() {
		tbl, _ := baseDB.GetTable(name)
		cols := tbl.columns()
		var rows [][]any
		for _, r := range tbl.rows() {
			rows = append(rows, padCells(r.values(), len(cols)))
		}
		result[name] = transformedTable{cols: cols, rows: rows}
	}

	// Apply each delta stream in deterministic (sorted) order.
	deltaNames := make([]string, 0, len(deltaStreams))
	for n := range deltaStreams {
		deltaNames = append(deltaNames, n)
	}
	sort.Strings(deltaNames)

	for _, name := range deltaNames {
		// _Tables/_Columns deltas carry the schema for added tables (patches);
		// the oracle resolves added-table schema from the catalog below rather
		// than replaying the catalog itself.
		if name == msiTablesTableName || name == msiColumnsTableName {
			continue
		}
		base, ok := result[name]
		if !ok {
			// A table the patch transform adds (e.g. Patch/PatchPackage): take
			// its schema from the catalog.
			if _, known := msiCatalogTable(name); !known {
				return nil, fmt.Errorf("msi transform: delta for unknown table %s", name)
			}
			base = transformedTable{cols: createMSITableFromCatalog(name).columns()}
		}
		ops, err := decodeTransformTableStream(base.cols, deltaStreams[name], pool)
		if err != nil {
			return nil, fmt.Errorf("msi transform: decoding delta %s: %w", name, err)
		}
		rows, err := applyTableDelta(base.cols, base.rows, ops)
		if err != nil {
			return nil, fmt.Errorf("msi transform: applying delta %s: %w", name, err)
		}
		base.rows = rows
		result[name] = base
	}
	return result, nil
}

// applyTableDelta replays insert/update/delete ops onto a table's rows, keyed by
// primary key, and returns the rows in deterministic (sorted-key) order.
func applyTableDelta(cols []msiColumn, baseRows [][]any, ops []transformRow) ([][]any, error) {
	keyIdx := keyColumnIndexes(cols)
	byKey := map[string][]any{}
	for _, r := range baseRows {
		byKey[transformRowKey(r, cols, keyIdx)] = padCells(r, len(cols))
	}

	for _, op := range ops {
		key := transformRowKey(op.cells, cols, keyIdx)
		switch op.op {
		case transformDelete:
			delete(byKey, key)
		case transformInsert:
			byKey[key] = padCells(op.cells, len(cols))
		case transformUpdate:
			row, ok := byKey[key]
			if !ok {
				return nil, fmt.Errorf("update targets a row not present (key %q)", key)
			}
			row = padCells(row, len(cols))
			for i := range cols {
				if i < len(op.changed) && op.changed[i] {
					row[i] = op.cells[i]
				}
			}
			byKey[key] = row
		}
	}

	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([][]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, byKey[k])
	}
	return out, nil
}

// transformRowKey builds a row's key string, falling back to the full tuple
// when the table declares no key columns.
func transformRowKey(vals []any, cols []msiColumn, keyIdx []int) string {
	idx := keyIdx
	if len(idx) == 0 {
		idx = make([]int, len(cols))
		for i := range cols {
			idx[i] = i
		}
	}
	return rowKeyString(vals, idx)
}
