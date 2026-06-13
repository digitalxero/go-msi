package msi

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
)

// msi_mst.go — P9 standalone MST transform builder.
//
// An .mst is a CFB (root CLSID {000C1082-…}) holding a transform
// \x05SummaryInformation, the transform's own _StringPool/_StringData, and one
// row-major delta stream (see msi_transform_encode.go) per CHANGED table. We
// generate a transform by diffing two compiled package models (we own both
// sides, so no foreign-MSI parsing is needed). Scope is SAME-SCHEMA transforms
// (the language / minor-update case): base and target must declare the same
// tables and columns; only row data may differ. Whole-table add/remove and
// new-file cabinets are out of scope (the latter is a patch/P10 concern).

// TransformValidation is the PID14 validation bitfield of a transform; it tells
// msiexec which identity fields of the target database the transform's
// RevisionNumber must match before it will apply.
type TransformValidation int32

const (
	TransformValidateLanguage      TransformValidation = 0x0001
	TransformValidateProduct       TransformValidation = 0x0002
	TransformValidatePlatform      TransformValidation = 0x0004
	TransformValidateMajorVersion  TransformValidation = 0x0008
	TransformValidateMinorVersion  TransformValidation = 0x0010
	TransformValidateUpdateVersion TransformValidation = 0x0020
	TransformValidateUpgradeCode   TransformValidation = 0x0800
)

// TransformBuilder builds a standalone MSI transform from a base→target diff.
type TransformBuilder interface {
	From(base Package) TransformBuilder
	To(target Package) TransformBuilder
	WithValidation(flags TransformValidation) TransformBuilder
	Build() (Transform, error)
}

// Transform is a built transform; WriteMST emits the standalone .mst file.
type Transform interface {
	WriteMST(w io.Writer) error
}

// NewTransform returns a builder for a base→target transform.
func NewTransform() TransformBuilder { return &msiTransform{} }

type msiTransform struct {
	base, target *msiPackage
	validation   TransformValidation

	// Populated by Build (and reused by WriteMST / the apply oracle).
	baseDB   msiDatabase
	targetDB msiDatabase
	streams  []msiStream
}

func (t *msiTransform) From(base Package) TransformBuilder {
	if p, ok := base.(*msiPackage); ok {
		t.base = p
	}
	return t
}

func (t *msiTransform) To(target Package) TransformBuilder {
	if p, ok := target.(*msiPackage); ok {
		t.target = p
	}
	return t
}

func (t *msiTransform) WithValidation(flags TransformValidation) TransformBuilder {
	t.validation = flags
	return t
}

func (t *msiTransform) Build() (Transform, error) {
	if t.base == nil || t.target == nil {
		return nil, fmt.Errorf("msi transform: both From(base) and To(target) are required")
	}
	if _, err := t.base.Build(); err != nil {
		return nil, fmt.Errorf("msi transform: base: %w", err)
	}
	if _, err := t.target.Build(); err != nil {
		return nil, fmt.Errorf("msi transform: target: %w", err)
	}

	baseDB, err := compileMSIPackage(t.base)
	if err != nil {
		return nil, fmt.Errorf("msi transform: compiling base: %w", err)
	}
	targetDB, err := compileMSIPackage(t.target)
	if err != nil {
		return nil, fmt.Errorf("msi transform: compiling target: %w", err)
	}
	t.baseDB, t.targetDB = baseDB, targetDB

	streams, err := buildMSITransformStreams(baseDB, targetDB, t.summaryInfo())
	if err != nil {
		return nil, err
	}
	t.streams = streams
	return t, nil
}

func (t *msiTransform) WriteMST(w io.Writer) error {
	if t.streams == nil {
		if _, err := t.Build(); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp("", "go-msix-*.mst")
	if err != nil {
		return fmt.Errorf("msi transform: temp for cfb: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	defer tmp.Close()

	if err := writeMSICFBWithCLSID(t.streams, msiTransformCLSID, tmp); err != nil {
		return fmt.Errorf("msi transform: emitting CFB: %w", err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("msi transform: seek temp: %w", err)
	}
	if _, err := io.Copy(w, tmp); err != nil {
		return fmt.Errorf("msi transform: copy cfb to output: %w", err)
	}
	return nil
}

// summaryInfo builds the transform \x05SummaryInformation: PID7 Template is the
// target platform;lang, PID9 RevisionNumber is the base→target lineage, PID14
// PageCount carries the validation flags.
func (t *msiTransform) summaryInfo() msiSummaryInfo {
	lineage := t.base.productCode + t.base.version + ";" +
		t.target.productCode + t.target.version + ";" + t.target.upgradeCode
	return msiSummaryInfo{
		Codepage:       1252,
		Title:          "Transform",
		Author:         t.target.manufacturer,
		Template:       msiTemplateString(t.target),
		RevisionNumber: lineage,
		// PID8 (Last Saved By): for a transform this is the platform and language
		// the database should have AFTER the transform is applied (i.e. the new
		// Template). Windows' patch sequencer requires it ("last author info
		// property is missing from transform" / error 1648 otherwise). The patch
		// transforms do not change platform/language, so it equals the Template.
		LastSavedBy: msiTemplateString(t.target),
		CreatingApp: "go-msix",
		CreateTime:  msiBuildTime,
		SaveTime:    msiBuildTime,
		// PID14 PageCount carries the transform's required Windows Installer
		// schema version. It MUST be present: msiexec rejects a transform whose
		// summary has no version with error 2758 ("Transform doesn't contain an
		// MSI version"), making a patch's transform invalid / not applicable.
		PageCount: msiSchemaVersion,
		// Transform validation/error flags live in PID16 (CharacterCount). Per
		// MSDN the UPPER word holds the validation flags and the LOWER word the
		// error-condition flags.
		CharacterCount: transformCharacterCount(t.validation),
		WordCount:      0,
		Security:       2,
	}
}

// msiSchemaVersion is the Windows Installer schema version written to the
// SummaryInformation PageCount (PID14) of databases and transforms (200 = the
// baseline schema, broadly compatible).
const msiSchemaVersion = 200

// transformCharacterCount packs the PID16 CharacterCount word. Per MSDN
// (Character Count Summary): the UPPER 16 bits hold the transform validation
// flags and the LOWER 16 bits hold the error-condition flags. We keep the error
// word zero: the generated transforms apply cleanly (no add/del of existing/
// missing rows or tables), and a non-zero low word would be misread as
// validation flags by Wine (which reads validation from the low word), breaking
// the local Wine smoke. Windows validates via the high word.
func transformCharacterCount(v TransformValidation) int {
	return (int(v) & 0xffff) << 16
}

// buildMSITransformStreams diffs base→target and serializes the transform CFB
// stream set: summary, the per-changed-table delta streams, and the transform's
// own string pool. Same-schema scope (language transforms): the table set and
// columns must be identical, and the _Tables/_Columns catalog is excluded.
func buildMSITransformStreams(baseDB, targetDB msiDatabase, summary msiSummaryInfo) ([]msiStream, error) {
	if err := assertSameSchema(baseDB, targetDB); err != nil {
		return nil, err
	}
	return assembleTransformStreams(baseDB, targetDB, summary, false)
}

// buildPatchTransformStreams is the schema-additive transform used by patches:
// the target may introduce whole new tables (e.g. Patch/PatchPackage), so the
// _Tables/_Columns catalog IS diffed (added tables get their schema deltas) and
// no same-schema assertion is made.
func buildPatchTransformStreams(baseDB, targetDB msiDatabase, summary msiSummaryInfo) ([]msiStream, error) {
	return assembleTransformStreams(baseDB, targetDB, summary, true)
}

// assembleTransformStreams diffs base→target and serializes the transform CFB
// stream set. includeCatalog controls whether _Tables/_Columns participate in
// the diff (true for patches that add tables; false for same-schema transforms).
func assembleTransformStreams(baseDB, targetDB msiDatabase, summary msiSummaryInfo, includeCatalog bool) ([]msiStream, error) {
	// 1. Diff every table into delta rows.
	type tableDelta struct {
		name string
		cols []msiColumn
		rows []transformRow
	}
	var deltas []tableDelta
	for _, name := range transformDiffTables(baseDB, targetDB, includeCatalog) {
		baseTbl, _ := baseDB.GetTable(name)
		targetTbl, _ := targetDB.GetTable(name)
		cols := tableColumnsFor(baseTbl, targetTbl)
		rows, err := diffMSITable(cols, baseTbl, targetTbl)
		if err != nil {
			return nil, fmt.Errorf("msi transform: diff table %s: %w", name, err)
		}
		if len(rows) > 0 {
			deltas = append(deltas, tableDelta{name: name, cols: cols, rows: rows})
		}
	}

	// 2. Intern every string the delta cells will serialize, so the transform
	// pool's long-ref decision is final before any stream is encoded.
	pool := newMSIStringPool(0)
	for _, d := range deltas {
		for _, r := range d.rows {
			_, present, err := transformRowMask(d.cols, r)
			if err != nil {
				return nil, fmt.Errorf("msi transform: table %s: %w", d.name, err)
			}
			for _, ci := range present {
				if ci < len(r.cells) {
					if s, ok := r.cells[ci].(string); ok && s != "" {
						pool.addString(s)
					}
				}
			}
		}
	}

	// 3. Summary stream (literal control name).
	streams := []msiStream{}
	summaryData, err := buildMSISummaryStream(summary)
	if err != nil {
		return nil, fmt.Errorf("msi transform: summary: %w", err)
	}
	streams = append(streams, msiStream{name: msiSummaryStreamName, data: summaryData})

	// 4. One delta stream per changed table (table-prefixed encoded name).
	for _, d := range deltas {
		data, err := encodeTransformTableStream(d.cols, d.rows, pool)
		if err != nil {
			return nil, fmt.Errorf("msi transform: encode table %s: %w", d.name, err)
		}
		streams = append(streams, msiStream{name: encodeMSIStreamName(true, d.name), data: data})
	}

	// 5. The transform's own _StringPool/_StringData.
	poolBytes, err := pool.poolBytes()
	if err != nil {
		return nil, fmt.Errorf("msi transform: string pool: %w", err)
	}
	streams = append(streams,
		msiStream{name: encodeMSIStreamName(true, "_StringPool"), data: poolBytes},
		msiStream{name: encodeMSIStreamName(true, "_StringData"), data: pool.dataBytes()},
	)
	return streams, nil
}

// transformDiffTables is the sorted union of the two databases' tables. With
// includeCatalog false the _Tables/_Columns catalog is excluded (same-schema
// transforms); with it true the catalog is diffed too, so a patch transform can
// add whole new tables (their _Tables/_Columns rows become insert deltas).
func transformDiffTables(baseDB, targetDB msiDatabase, includeCatalog bool) []string {
	set := map[string]bool{}
	for _, n := range baseDB.Tables() {
		set[n] = true
	}
	for _, n := range targetDB.Tables() {
		set[n] = true
	}
	if !includeCatalog {
		delete(set, msiTablesTableName)
		delete(set, msiColumnsTableName)
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func tableColumnsFor(baseTbl, targetTbl msiTable) []msiColumn {
	if baseTbl != nil {
		return baseTbl.columns()
	}
	return targetTbl.columns()
}

// assertSameSchema enforces the SAME-SCHEMA scope: identical table set (minus
// the catalog) and identical columns (name + type) per table.
func assertSameSchema(baseDB, targetDB msiDatabase) error {
	for _, name := range transformDiffTables(baseDB, targetDB, false) {
		bt, bErr := baseDB.GetTable(name)
		tt, tErr := targetDB.GetTable(name)
		if bErr != nil || tErr != nil {
			return fmt.Errorf("msi transform: table %s is present in only one side; whole-table add/remove is not supported (same-schema transforms only)", name)
		}
		bc, tc := bt.columns(), tt.columns()
		if len(bc) != len(tc) {
			return fmt.Errorf("msi transform: table %s column count differs (%d vs %d); same-schema transforms only", name, len(bc), len(tc))
		}
		for i := range bc {
			if bc[i].name() != tc[i].name() || bc[i].typ() != tc[i].typ() {
				return fmt.Errorf("msi transform: table %s column %d differs; same-schema transforms only", name, i)
			}
		}
	}
	return nil
}

// diffMSITable produces the delta rows turning baseTbl into targetTbl, keyed by
// the tables' primary key. Rows are emitted in deterministic (sorted-key) order.
func diffMSITable(cols []msiColumn, baseTbl, targetTbl msiTable) ([]transformRow, error) {
	keyIdx := keyColumnIndexes(cols)
	baseByKey := rowsByKey(baseTbl, keyIdx)
	targetByKey := rowsByKey(targetTbl, keyIdx)

	keys := sortedUnionKeys(baseByKey, targetByKey)
	var out []transformRow
	for _, k := range keys {
		bv, inBase := baseByKey[k]
		tv, inTarget := targetByKey[k]
		switch {
		case inTarget && !inBase:
			out = append(out, transformRow{op: transformInsert, cells: padCells(tv, len(cols))})
		case inBase && !inTarget:
			out = append(out, transformRow{op: transformDelete, cells: padCells(bv, len(cols))})
		default:
			changed := make([]bool, len(cols))
			any := false
			for i := range cols {
				if isKeyIdx(keyIdx, i) {
					continue
				}
				if !cellsEqual(cellAt(bv, i), cellAt(tv, i)) {
					changed[i] = true
					any = true
				}
			}
			if any {
				out = append(out, transformRow{op: transformUpdate, cells: padCells(tv, len(cols)), changed: changed})
			}
		}
	}
	return out, nil
}

func keyColumnIndexes(cols []msiColumn) []int {
	var idx []int
	for i, c := range cols {
		if c.isKey() {
			idx = append(idx, i)
		}
	}
	return idx
}

func isKeyIdx(keyIdx []int, i int) bool {
	for _, k := range keyIdx {
		if k == i {
			return true
		}
	}
	return false
}

// rowsByKey maps each row to a canonical key string built from its key columns.
// With no key columns, the full value tuple is the key (so identical rows match
// and any change reads as delete+insert).
func rowsByKey(tbl msiTable, keyIdx []int) map[string][]any {
	out := map[string][]any{}
	if tbl == nil {
		return out
	}
	for _, r := range tbl.rows() {
		vals := r.values()
		idx := keyIdx
		if len(idx) == 0 {
			idx = make([]int, len(vals))
			for i := range vals {
				idx[i] = i
			}
		}
		out[rowKeyString(vals, idx)] = vals
	}
	return out
}

func rowKeyString(vals []any, keyIdx []int) string {
	parts := make([]string, 0, len(keyIdx))
	for _, i := range keyIdx {
		parts = append(parts, cellKeyToken(cellAt(vals, i)))
	}
	// A length-prefixed join avoids ambiguity between tuple boundaries.
	var b []byte
	for _, p := range parts {
		b = append(b, []byte(strconv.Itoa(len(p)))...)
		b = append(b, ':')
		b = append(b, []byte(p)...)
		b = append(b, '|')
	}
	return string(b)
}

func cellKeyToken(v any) string {
	switch x := v.(type) {
	case nil:
		return "\x00null"
	case string:
		return "s" + x
	case int16:
		return "i" + strconv.Itoa(int(x))
	case int32:
		return "I" + strconv.Itoa(int(x))
	case []byte:
		return "b" + string(x)
	default:
		return fmt.Sprintf("?%v", x)
	}
}

func sortedUnionKeys(a, b map[string][]any) []string {
	set := map[string]bool{}
	for k := range a {
		set[k] = true
	}
	for k := range b {
		set[k] = true
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func cellAt(vals []any, i int) any {
	if i < len(vals) {
		return vals[i]
	}
	return nil
}

func padCells(vals []any, n int) []any {
	out := make([]any, n)
	copy(out, vals)
	return out
}

// cellsEqual compares two decoded cell values for transform-diff purposes.
func cellsEqual(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	switch av := a.(type) {
	case []byte:
		bv, ok := b.([]byte)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if av[i] != bv[i] {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}
