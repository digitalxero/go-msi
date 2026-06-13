package msi

// msi_tables.go
// Adapted (with modifications) from the tables/ package in the sibling project
// /home/djgilcrease/projects/msi/ (github.com/djgilcrease/go-msi).
// Original design used public interfaces + builder pattern (aligns with project
// "Builder IS Implementation" and "public components are interfaces" guidelines).
// Changes for this project:
// - Symbols kept unexported (package-private) for the MSI storage layer.
// - Removed external AlekSi/pointer dependency; use any/pointer semantics.
// - Uses "any" per style guide.
// - Will be extended with real MSI on-disk row/string-ref encoding on top of these schemas.
// - Core Create* factories for the minimal viable installer are included.
// - Full list of factories from the sibling is preserved for future completeness
//   (many are not yet wired into the minimal BuildMSI path).

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// --- Column types and builders (adapted) ---

type msiColumnType int

const (
	msiColUnknown msiColumnType = iota
	msiColText
	msiColUpperCase
	msiColLowerCase
	msiColInteger
	msiColDoubleInteger
	msiColDateTime
	msiColIdentifier
	msiColProperty
	msiColFilename
	msiColWildCardFilename
	msiColPath
	msiColPaths
	msiColAnyPath
	msiColDefaultDir
	msiColRegPath
	msiColFormatted
	msiColFormattedSDDLText
	msiColTemplate
	msiColCondition
	msiColGUID
	msiColVersion
	msiColLanguage
	msiColBinary
	msiColCustomSource
	msiColCabinet
	msiColShortcut
)

var msiColToString = map[msiColumnType]string{
	msiColText:              "Text",
	msiColUpperCase:         "UpperCase",
	msiColLowerCase:         "LowerCase",
	msiColInteger:           "Integer",
	msiColDoubleInteger:     "DoubleInteger",
	msiColDateTime:          "DateTime",
	msiColIdentifier:        "Identifier",
	msiColProperty:          "Property",
	msiColFilename:          "Filename",
	msiColWildCardFilename:  "WildCardFilename",
	msiColPath:              "Path",
	msiColPaths:             "Paths",
	msiColAnyPath:           "AnyPath",
	msiColDefaultDir:        "DefaultDir",
	msiColRegPath:           "RegPath",
	msiColFormatted:         "Formatted",
	msiColFormattedSDDLText: "FormattedSDDLText",
	msiColTemplate:          "Template",
	msiColCondition:         "Condition",
	msiColGUID:              "GUID",
	msiColVersion:           "Version",
	msiColLanguage:          "Language",
	msiColBinary:            "Binary",
	msiColCustomSource:      "CustomSource",
	msiColCabinet:           "Cabinet",
	msiColShortcut:          "Shortcut",
}

func (ct msiColumnType) String() string { return msiColToString[ct] }

func (ct msiColumnType) zero() any {
	switch ct {
	case msiColInteger:
		var v int16
		return &v
	case msiColDoubleInteger:
		var v int32
		return &v
	case msiColDateTime:
		var v time.Time
		return &v
	case msiColBinary:
		return []byte(nil)
	default:
		var v string
		return &v
	}
}

// MSITYPE bit constants for the _Columns Type bitfield (Wine msipriv.h:49-64).
// The 0x0400 bit has no name in msipriv.h but is emitted by real writers
// (Wine sql.y data_type, rust-msi COL_NONBINARY_BIT) for string and int16
// columns; it disambiguates a width-0 string (0x0D00) from a binary column
// (0x0900). MSITYPE_TEMPORARY (0x4000) and MSITYPE_UNKNOWN (0x8000) must never
// be persisted (0x8000 would corrupt the +0x8000 on-disk cell transform).
const (
	msiTypeDataSizeMask uint16 = 0x00FF
	msiTypeValid        uint16 = 0x0100
	msiTypeLocalizable  uint16 = 0x0200
	msiTypeNonBinary    uint16 = 0x0400
	msiTypeString       uint16 = 0x0800
	msiTypeNullable     uint16 = 0x1000
	msiTypeKey          uint16 = 0x2000
)

type msiColumn interface {
	name() string
	typ() msiColumnType
	width() int
	isKey() bool
	isNullable() bool
	isLocalizable() bool
	// typeBits returns the exact MSITYPE bitfield for this column as written
	// (logically) into the _Columns Type cell: low byte = declared width
	// (chars for strings, bytes for ints), plus VALID, LOCALIZABLE, the 0x0400
	// "nonbinary" bit, STRING, NULLABLE and KEY flags.
	typeBits() uint16
	validate(data any) error
	isValid(data any) bool
}

type msiColumnBuilder interface {
	WithName(string) msiColumnBuilder
	WithType(msiColumnType) msiColumnBuilder
	WithWidth(int) msiColumnBuilder
	AsKey() msiColumnBuilder
	AsNullable() msiColumnBuilder
	AsLocalizable() msiColumnBuilder
	Build() msiColumn
}

func newMSIColumnBuilder() msiColumnBuilder { return &msiColumnData{} }

type msiColumnData struct {
	n           string
	ct          msiColumnType
	w           int
	key         bool
	nullable    bool
	localizable bool
}

func (c *msiColumnData) WithName(s string) msiColumnBuilder        { c.n = s; return c }
func (c *msiColumnData) WithType(t msiColumnType) msiColumnBuilder { c.ct = t; return c }
func (c *msiColumnData) WithWidth(w int) msiColumnBuilder          { c.w = w; return c }
func (c *msiColumnData) AsKey() msiColumnBuilder                   { c.key = true; return c }
func (c *msiColumnData) AsNullable() msiColumnBuilder              { c.nullable = true; return c }
func (c *msiColumnData) AsLocalizable() msiColumnBuilder           { c.localizable = true; return c }
func (c *msiColumnData) Build() msiColumn                          { return c }

func (c *msiColumnData) name() string        { return c.n }
func (c *msiColumnData) typ() msiColumnType  { return c.ct }
func (c *msiColumnData) width() int          { return c.w }
func (c *msiColumnData) isKey() bool         { return c.key }
func (c *msiColumnData) isNullable() bool    { return c.nullable }
func (c *msiColumnData) isLocalizable() bool { return c.localizable }

// typeBits composes the MSITYPE bitfield exactly as Wine's sql.y / rust-msi's
// column.rs do when writing a schema:
//
//	int16  -> 0x0002 | 0x0400          (SHORT/INT)
//	int32  -> 0x0004                   (LONG; no 0x0400)
//	binary -> 0x0800                   (OBJECT; no 0x0400, no width)
//	string -> 0x0800 | 0x0400 | width  (CHAR(n))
//
// then ORs VALID (0x0100) always, LOCALIZABLE (0x0200), NULLABLE (0x1000) and
// KEY (0x2000) as flagged. Examples: s72 key = 0x2D48, L255 = 0x1FFF,
// i2 = 0x0502, I4 = 0x1104, v0 = 0x0900.
func (c *msiColumnData) typeBits() uint16 {
	var bits uint16
	switch c.ct {
	case msiColInteger:
		bits = 0x0002 | msiTypeNonBinary
	case msiColDoubleInteger, msiColDateTime:
		bits = 0x0004
	case msiColBinary:
		bits = msiTypeString
	default:
		bits = msiTypeString | msiTypeNonBinary | (uint16(c.w) & msiTypeDataSizeMask)
	}
	bits |= msiTypeValid
	if c.localizable {
		bits |= msiTypeLocalizable
	}
	if c.nullable {
		bits |= msiTypeNullable
	}
	if c.key {
		bits |= msiTypeKey
	}
	return bits
}

func (c *msiColumnData) isValid(data any) bool {
	return c.validate(data) == nil
}

// msiGUIDPattern is the strict MSI GUID category (Microsoft Learn msi/guid):
// exactly {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}, uppercase hex, braces and
// hyphens mandatory, length exactly 38.
var msiGUIDPattern = regexp.MustCompile(`^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$`)

// msiIdentifierPattern is the MSI Identifier category (Microsoft Learn
// msi/identifier): letters, digits, underscores or periods; must begin with a
// letter or an underscore.
var msiIdentifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)

// validateMSIVersionString checks the MSI Version category (Microsoft Learn
// msi/version): 1-4 dot-separated decimal fields, each 0..65535, no empty
// fields (".12" is invalid).
func validateMSIVersionString(val string) error {
	parts := strings.Split(val, ".")
	if len(parts) > 4 {
		return fmt.Errorf("version %q has more than 4 fields", val)
	}
	for _, p := range parts {
		if p == "" {
			return fmt.Errorf("version %q has an empty field", val)
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return fmt.Errorf("version %q has a non-numeric field %q", val, p)
		}
		if n > 65535 {
			return fmt.Errorf("version %q field %q exceeds 65535", val, p)
		}
	}
	return nil
}

// validateMSICabinetString checks the MSI Cabinet category (Microsoft Learn
// msi/cabinet): a leading '#' means the remainder is an Identifier naming an
// embedded CFB stream; otherwise it is an external cabinet file name in strict
// 8.3 short-name syntax (name 1-8 chars, optional '.' + 1-3 char extension,
// no short-name-invalid characters).
func validateMSICabinetString(val string) error {
	if strings.HasPrefix(val, "#") {
		if !msiIdentifierPattern.MatchString(val[1:]) {
			return fmt.Errorf("cabinet %q: stream name after '#' is not a valid identifier", val)
		}
		return nil
	}
	parts := strings.Split(val, ".")
	if len(parts) > 2 {
		return fmt.Errorf("cabinet %q: more than one '.' in 8.3 name", val)
	}
	if len(parts[0]) < 1 || len(parts[0]) > 8 {
		return fmt.Errorf("cabinet %q: name part must be 1-8 characters", val)
	}
	if len(parts) == 2 && (len(parts[1]) < 1 || len(parts[1]) > 3) {
		return fmt.Errorf("cabinet %q: extension must be 1-3 characters", val)
	}
	// Characters invalid in short names: the common filename set plus the
	// short-name-only set and spaces/control characters.
	if strings.ContainsAny(val, "/\\?|><:*\"+,;=[] ") {
		return fmt.Errorf("cabinet %q: contains characters invalid in an 8.3 name", val)
	}
	return nil
}

func (c *msiColumnData) validate(data any) error {
	// Dereference pointer values so they validate like their pointees; a nil
	// typed pointer is NULL.
	switch p := data.(type) {
	case *string:
		if p == nil {
			data = nil
		} else {
			data = *p
		}
	case *int16:
		if p == nil {
			data = nil
		} else {
			data = *p
		}
	case *int32:
		if p == nil {
			data = nil
		} else {
			data = *p
		}
	case *time.Time:
		if p == nil {
			data = nil
		} else {
			data = *p
		}
	}
	// MSI does not distinguish the empty string from NULL (both are string
	// ref 0 on disk), so "" follows the NULL rules.
	if s, ok := data.(string); ok && s == "" {
		data = nil
	}
	if data == nil {
		if !c.nullable {
			return fmt.Errorf("column %s is non-nullable and data is empty", c.n)
		}
		return nil
	}

	switch val := data.(type) {
	case string:
		switch c.ct {
		case msiColInteger, msiColDoubleInteger, msiColDateTime, msiColBinary:
			return fmt.Errorf("data %s is invalid for column type: %s", val, c.ct)
		case msiColUpperCase:
			if strings.ToUpper(val) != val {
				return fmt.Errorf("data %s is invalid for column type: %s", val, c.ct)
			}
		case msiColLowerCase:
			if strings.ToLower(val) != val {
				return fmt.Errorf("data %s is invalid for column type: %s", val, c.ct)
			}
		case msiColGUID:
			if !msiGUIDPattern.MatchString(val) {
				return fmt.Errorf("data %s is invalid for column type: %s", val, c.ct)
			}
		case msiColVersion:
			if err := validateMSIVersionString(val); err != nil {
				return fmt.Errorf("data %s is invalid for column type %s: %w", val, c.ct, err)
			}
		case msiColCabinet:
			if err := validateMSICabinetString(val); err != nil {
				return fmt.Errorf("data %s is invalid for column type %s: %w", val, c.ct, err)
			}
		}
	case int16:
		if c.ct != msiColInteger {
			return fmt.Errorf("data %v is invalid for column type: %s", val, c.ct)
		}
	case int32:
		if c.ct != msiColDoubleInteger {
			return fmt.Errorf("data %v is invalid for column type: %s", val, c.ct)
		}
	case time.Time:
		if c.ct != msiColDateTime {
			return fmt.Errorf("data %v is invalid for column type: %s", val, c.ct)
		}
	case []byte:
		if c.ct != msiColBinary {
			return fmt.Errorf("data %v is invalid for column type: %s", val, c.ct)
		}
	default:
		return fmt.Errorf("unknown data type: %T for column type: %s", data, c.ct)
	}
	return nil
}

// --- Row ---

type msiRowBuilder interface {
	WithColumns(...msiColumn) msiRowBuilder
	WithValues(...any) msiRowBuilder
	Build() msiRow
}

type msiRow interface {
	columns() []msiColumn
	keyColumns() map[int]msiColumn
	values() []any
	valueAt(idx int) (any, error)
	SetValueAt(idx int, value any) error
	validate() error
}

func newMSIRowBuilder() msiRowBuilder {
	return &msiRowData{_nameIdx: make(map[string]int), _keyColumns: make(map[int]msiColumn)}
}

func newMSIRowBuilderFromTable(t msiTable) msiRowBuilder {
	return newMSIRowBuilder().WithColumns(t.columns()...)
}

type msiRowData struct {
	cols        []msiColumn
	_keyColumns map[int]msiColumn
	vals        []any
	_nameIdx    map[string]int
}

func (r *msiRowData) WithColumns(cols ...msiColumn) msiRowBuilder {
	r.cols = cols
	r._nameIdx = make(map[string]int)
	r._keyColumns = make(map[int]msiColumn)
	for i, c := range cols {
		r._nameIdx[c.name()] = i
		if c.isKey() {
			r._keyColumns[i] = c
		}
	}
	return r
}

func (r *msiRowData) WithValues(vs ...any) msiRowBuilder {
	r.vals = vs
	return r
}

func (r *msiRowData) Build() msiRow {
	for i, v := range r.vals {
		if i >= len(r.cols) {
			break
		}
		switch vv := v.(type) {
		case int:
			switch r.cols[i].typ() {
			case msiColInteger:
				r.vals[i] = int16(vv)
			case msiColDoubleInteger:
				r.vals[i] = int32(vv)
			}
		}
	}
	return r
}

func (r *msiRowData) columns() []msiColumn          { return r.cols }
func (r *msiRowData) keyColumns() map[int]msiColumn { return r._keyColumns }
func (r *msiRowData) values() []any                 { return append([]any(nil), r.vals...) }
func (r *msiRowData) valueAt(idx int) (any, error) {
	if idx < 0 || idx >= len(r.vals) {
		return nil, fmt.Errorf("index out of range")
	}
	return r.vals[idx], nil
}

func (r *msiRowData) SetValueAt(idx int, value any) error {
	if idx < 0 || idx >= len(r.vals) {
		return fmt.Errorf("index out of range")
	}
	column := r.cols[idx]
	if err := column.validate(value); err != nil {
		return fmt.Errorf("data %v for column %s is invalid", value, column.name())
	}
	r.vals[idx] = value
	return nil
}

func (r *msiRowData) validate() error {
	for i, c := range r.cols {
		var v any
		if i < len(r.vals) {
			v = r.vals[i]
		}
		if err := c.validate(v); err != nil {
			return fmt.Errorf("data %v for column %s is invalid: %w", v, c.name(), err)
		}
	}
	return nil
}

// --- Table (schema + rows) ---

type msiTableBuilder interface {
	WithName(string) msiTableBuilder
	WithColumns(...msiColumn) msiTableBuilder
	WithValidateFunc(func(msiTable) error) msiTableBuilder
	Build() msiTable
}

type msiTable interface {
	name() string
	addRow(msiRow) error
	rows() []msiRow
	columns() []msiColumn
	validate() error
	// serialize is the sibling custom format (useful for roundtrip tests of the table layer itself).
	serialize() ([]byte, error)
}

func newMSITableBuilder() msiTableBuilder { return &msiTableData{} }

type msiTableData struct {
	n         string
	cols      []msiColumn
	_rows     []msiRow
	_validate func(msiTable) error
}

func (t *msiTableData) WithName(s string) msiTableBuilder { t.n = s; return t }
func (t *msiTableData) WithColumns(cols ...msiColumn) msiTableBuilder {
	t.cols = append(t.cols, cols...)
	return t
}
func (t *msiTableData) WithValidateFunc(f func(msiTable) error) msiTableBuilder {
	t._validate = f
	return t
}
func (t *msiTableData) Build() msiTable { return t }

func (t *msiTableData) name() string         { return t.n }
func (t *msiTableData) columns() []msiColumn { return t.cols }
func (t *msiTableData) rows() []msiRow       { return t._rows }

func (t *msiTableData) addRow(r msiRow) error {
	if err := r.validate(); err != nil {
		return err
	}
	if len(r.values()) != len(t.cols) {
		return fmt.Errorf("row has incorrect number of values")
	}
	t._rows = append(t._rows, r)
	return nil
}

func (t *msiTableData) validate() error {
	if t.n == "" {
		return fmt.Errorf("table name cannot be empty")
	}
	if len(t.cols) == 0 {
		return fmt.Errorf("table must have at least one column")
	}
	for _, r := range t._rows {
		if err := r.validate(); err != nil {
			return err
		}
	}
	if t._validate != nil {
		return t._validate(t)
	}
	return nil
}

// serialize (custom format from sibling, kept for table-layer tests)
func (t *msiTableData) serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := writeMSITableString(buf, t.n); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(t.cols))); err != nil {
		return nil, err
	}
	for _, c := range t.cols {
		if err := writeMSITableString(buf, c.name()); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.LittleEndian, uint16(c.typ())); err != nil {
			return nil, err
		}
		var isKey uint8
		if c.isKey() {
			isKey = 1
		}
		if err := binary.Write(buf, binary.LittleEndian, isKey); err != nil {
			return nil, err
		}
		var isNull uint8
		if c.isNullable() {
			isNull = 1
		}
		if err := binary.Write(buf, binary.LittleEndian, isNull); err != nil {
			return nil, err
		}
	}
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(t._rows))); err != nil {
		return nil, err
	}
	for _, r := range t._rows {
		for i, v := range r.values() {
			if err := writeMSITableValue(buf, v, t.cols[i].typ()); err != nil {
				return nil, err
			}
		}
	}
	return buf.Bytes(), nil
}

func writeMSITableString(w io.Writer, s string) error {
	if s != "" {
		if _, err := w.Write([]byte(s)); err != nil {
			return err
		}
	}
	return binary.Write(w, binary.LittleEndian, byte(0))
}

func writeMSITableValue(w io.Writer, v any, ct msiColumnType) error {
	switch val := v.(type) {
	case string:
		return writeMSITableString(w, val)
	case *string:
		if val != nil {
			return writeMSITableString(w, *val)
		}
		return binary.Write(w, binary.LittleEndian, byte(0))
	case int16:
		return binary.Write(w, binary.LittleEndian, val)
	case *int16:
		if val != nil {
			return binary.Write(w, binary.LittleEndian, *val)
		}
		return binary.Write(w, binary.LittleEndian, byte(0))
	case int32:
		return binary.Write(w, binary.LittleEndian, val)
	case *int32:
		if val != nil {
			return binary.Write(w, binary.LittleEndian, *val)
		}
		return binary.Write(w, binary.LittleEndian, byte(0))
	case []byte:
		if err := binary.Write(w, binary.LittleEndian, uint32(len(val))); err != nil {
			return err
		}
		_, err := w.Write(val)
		return err
	case nil:
		return binary.Write(w, binary.LittleEndian, byte(0))
	default:
		return fmt.Errorf("unknown column value type %T for %s", v, ct)
	}
}

// --- Core table factories (schemas derived from the canonical catalog in msi_table_catalog.go) ---

const (
	msiPropTableName           = "Property"
	msiDirTableName            = "Directory"
	msiCompTableName           = "Component"
	msiFeatTableName           = "Feature"
	msiFeatCompTableName       = "FeatureComponents"
	msiFileTableName           = "File"
	msiMediaTableName          = "Media"
	msiInstallExecSeqTableName = "InstallExecuteSequence"
	msiInstallUISeqTableName   = "InstallUISequence"
	msiAdminExecSeqTableName   = "AdminExecuteSequence"
	msiAdminUISeqTableName     = "AdminUISequence"
	msiAdvtExecSeqTableName    = "AdvtExecuteSequence"
	msiTablesTableName         = "_Tables"
	msiColumnsTableName        = "_Columns"
)

// createMSITableFromCatalog builds a table schema (no rows) from the canonical
// catalog definition in msi_table_catalog.go, the single source of truth for
// column names, order, widths, key/nullable/localizable flags and categories.
// It panics if name is not in the catalog: factories are compile-time wiring,
// so a miss is a programming error, not a runtime condition.
func createMSITableFromCatalog(name string) msiTable {
	def, ok := msiCatalogTable(name)
	if !ok {
		panic(fmt.Sprintf("msix: table %q is not in the MSI table catalog", name))
	}
	cols := make([]msiColumn, 0, len(def.columns))
	for _, cc := range def.columns {
		b := newMSIColumnBuilder().WithName(cc.name).WithType(cc.colType).WithWidth(cc.width)
		if cc.key {
			b = b.AsKey()
		}
		if cc.nullable {
			b = b.AsNullable()
		}
		if cc.localizable {
			b = b.AsLocalizable()
		}
		cols = append(cols, b.Build())
	}
	return newMSITableBuilder().WithName(def.name).WithColumns(cols...).Build()
}

func createMSIPropertyTable() msiTable {
	return createMSITableFromCatalog(msiPropTableName)
}

func createMSIDirectoryTable() msiTable {
	return createMSITableFromCatalog(msiDirTableName)
}

func createMSIComponentTable() msiTable {
	return createMSITableFromCatalog(msiCompTableName)
}

func createMSIFeatureTable() msiTable {
	return createMSITableFromCatalog(msiFeatTableName)
}

func createMSIFeatureComponentsTable() msiTable {
	return createMSITableFromCatalog(msiFeatCompTableName)
}

func createMSIFileTable() msiTable {
	return createMSITableFromCatalog(msiFileTableName)
}

func createMSIMediaTable() msiTable {
	return createMSITableFromCatalog(msiMediaTableName)
}

func createMSIInstallExecuteSequenceTable() msiTable {
	return createMSITableFromCatalog(msiInstallExecSeqTableName)
}

func createMSIInstallUISequenceTable() msiTable {
	return createMSITableFromCatalog(msiInstallUISeqTableName)
}

func createMSIAdminExecuteSequenceTable() msiTable {
	return createMSITableFromCatalog(msiAdminExecSeqTableName)
}

func createMSIAdminUISequenceTable() msiTable {
	return createMSITableFromCatalog(msiAdminUISeqTableName)
}

func createMSIAdvtExecuteSequenceTable() msiTable {
	return createMSITableFromCatalog(msiAdvtExecSeqTableName)
}

// createMSITablesTable and createMSIColumnsTable are the system tables the
// writer populates from user tables. Their schemas are hardcoded in every
// reader (Wine table.c _Tables_cols/_Columns_cols) and are deliberately NOT
// in the catalog: they are never listed in _Tables and have no rows in
// _Columns or _Validation.
func createMSITablesTable() msiTable {
	return newMSITableBuilder().WithName(msiTablesTableName).WithColumns(
		newMSIColumnBuilder().WithName("Name").WithType(msiColIdentifier).WithWidth(64).AsKey().Build(),
	).Build()
}

func createMSIColumnsTable() msiTable {
	return newMSITableBuilder().WithName(msiColumnsTableName).WithColumns(
		newMSIColumnBuilder().WithName("Table").WithType(msiColIdentifier).WithWidth(64).AsKey().Build(),
		newMSIColumnBuilder().WithName("Number").WithType(msiColInteger).WithWidth(2).AsKey().Build(),
		newMSIColumnBuilder().WithName("Name").WithType(msiColIdentifier).WithWidth(64).Build(),
		newMSIColumnBuilder().WithName("Type").WithType(msiColInteger).WithWidth(2).Build(),
	).Build()
}

// P3 starters (use catalog now that defs added).
func createMSIRegistryTable() msiTable {
	return createMSITableFromCatalog("Registry")
}
func createMSIShortcutTable() msiTable {
	return createMSITableFromCatalog("Shortcut")
}
func createMSIIconTable() msiTable {
	return createMSITableFromCatalog("Icon")
}
func createMSIBinaryTable() msiTable {
	return createMSITableFromCatalog("Binary")
}
func createMSIMsiFileHashTable() msiTable {
	return createMSITableFromCatalog("MsiFileHash")
}
func createMSIRemoveRegistryTable() msiTable {
	return createMSITableFromCatalog("RemoveRegistry")
}
func createMSIRemoveFileTable() msiTable {
	return createMSITableFromCatalog("RemoveFile")
}
func createMSICreateFolderTable() msiTable {
	return createMSITableFromCatalog("CreateFolder")
}
func createMSIEnvironmentTable() msiTable {
	return createMSITableFromCatalog("Environment")
}

// P4 — Services, upgrades, launch conditions, AppSearch/locators, Error/ActionText.
func createMSIServiceInstallTable() msiTable {
	return createMSITableFromCatalog("ServiceInstall")
}
func createMSIServiceControlTable() msiTable {
	return createMSITableFromCatalog("ServiceControl")
}
func createMSIMsiServiceConfigTable() msiTable {
	return createMSITableFromCatalog("MsiServiceConfig")
}
func createMSIMsiServiceConfigFailureActionsTable() msiTable {
	return createMSITableFromCatalog("MsiServiceConfigFailureActions")
}
func createMSIUpgradeTable() msiTable {
	return createMSITableFromCatalog("Upgrade")
}
func createMSILaunchConditionTable() msiTable {
	return createMSITableFromCatalog("LaunchCondition")
}
func createMSISignatureTable() msiTable {
	return createMSITableFromCatalog("Signature")
}
func createMSIAppSearchTable() msiTable {
	return createMSITableFromCatalog("AppSearch")
}
func createMSIRegLocatorTable() msiTable {
	return createMSITableFromCatalog("RegLocator")
}
func createMSIIniLocatorTable() msiTable {
	return createMSITableFromCatalog("IniLocator")
}
func createMSICompLocatorTable() msiTable {
	return createMSITableFromCatalog("CompLocator")
}
func createMSIDrLocatorTable() msiTable {
	return createMSITableFromCatalog("DrLocator")
}
func createMSIErrorTable() msiTable {
	return createMSITableFromCatalog("Error")
}
func createMSIActionTextTable() msiTable {
	return createMSITableFromCatalog("ActionText")
}
func createMSICustomActionTable() msiTable {
	return createMSITableFromCatalog("CustomAction")
}

// P6 — UI tables.
func createMSIDialogTable() msiTable           { return createMSITableFromCatalog("Dialog") }
func createMSIControlTable() msiTable          { return createMSITableFromCatalog("Control") }
func createMSIControlEventTable() msiTable     { return createMSITableFromCatalog("ControlEvent") }
func createMSIControlConditionTable() msiTable { return createMSITableFromCatalog("ControlCondition") }
func createMSIEventMappingTable() msiTable     { return createMSITableFromCatalog("EventMapping") }
func createMSITextStyleTable() msiTable        { return createMSITableFromCatalog("TextStyle") }
func createMSIUITextTable() msiTable           { return createMSITableFromCatalog("UIText") }
func createMSIRadioButtonTable() msiTable      { return createMSITableFromCatalog("RadioButton") }
func createMSIListBoxTable() msiTable          { return createMSITableFromCatalog("ListBox") }
func createMSIComboBoxTable() msiTable         { return createMSITableFromCatalog("ComboBox") }
func createMSIListViewTable() msiTable         { return createMSITableFromCatalog("ListView") }
func createMSICheckBoxTable() msiTable         { return createMSITableFromCatalog("CheckBox") }
func createMSIBillboardTable() msiTable        { return createMSITableFromCatalog("Billboard") }
func createMSIBBControlTable() msiTable        { return createMSITableFromCatalog("BBControl") }

// P11 — COM / advertising tables (never emitted; cataloged for ICE coverage).
func createMSIClassTable() msiTable            { return createMSITableFromCatalog("Class") }
func createMSIProgIdTable() msiTable           { return createMSITableFromCatalog("ProgId") }
func createMSIExtensionTable() msiTable        { return createMSITableFromCatalog("Extension") }
func createMSIVerbTable() msiTable             { return createMSITableFromCatalog("Verb") }
func createMSIMIMETable() msiTable             { return createMSITableFromCatalog("MIME") }
func createMSITypeLibTable() msiTable          { return createMSITableFromCatalog("TypeLib") }
func createMSIAppIdTable() msiTable            { return createMSITableFromCatalog("AppId") }
func createMSIPublishComponentTable() msiTable { return createMSITableFromCatalog("PublishComponent") }

// P11 — assembly / font / ODBC tables.
func createMSIMsiAssemblyTable() msiTable     { return createMSITableFromCatalog("MsiAssembly") }
func createMSIMsiAssemblyNameTable() msiTable { return createMSITableFromCatalog("MsiAssemblyName") }
func createMSIFontTable() msiTable            { return createMSITableFromCatalog("Font") }
func createMSIODBCDataSourceTable() msiTable  { return createMSITableFromCatalog("ODBCDataSource") }
func createMSIODBCDriverTable() msiTable      { return createMSITableFromCatalog("ODBCDriver") }
func createMSIODBCTranslatorTable() msiTable  { return createMSITableFromCatalog("ODBCTranslator") }
func createMSIODBCAttributeTable() msiTable   { return createMSITableFromCatalog("ODBCAttribute") }
func createMSIODBCSourceAttributeTable() msiTable {
	return createMSITableFromCatalog("ODBCSourceAttribute")
}

// P11 — file-ops / registration / security tables.
func createMSIDuplicateFileTable() msiTable { return createMSITableFromCatalog("DuplicateFile") }
func createMSIMoveFileTable() msiTable      { return createMSITableFromCatalog("MoveFile") }
func createMSIIniFileTable() msiTable       { return createMSITableFromCatalog("IniFile") }
func createMSIRemoveIniFileTable() msiTable { return createMSITableFromCatalog("RemoveIniFile") }
func createMSIIsolatedComponentTable() msiTable {
	return createMSITableFromCatalog("IsolatedComponent")
}
func createMSIBindImageTable() msiTable       { return createMSITableFromCatalog("BindImage") }
func createMSISelfRegTable() msiTable         { return createMSITableFromCatalog("SelfReg") }
func createMSIReserveCostTable() msiTable     { return createMSITableFromCatalog("ReserveCost") }
func createMSIComplusTable() msiTable         { return createMSITableFromCatalog("Complus") }
func createMSILockPermissionsTable() msiTable { return createMSITableFromCatalog("LockPermissions") }
func createMSIMsiLockPermissionsExTable() msiTable {
	return createMSITableFromCatalog("MsiLockPermissionsEx")
}
func createMSIMsiDigitalCertificateTable() msiTable {
	return createMSITableFromCatalog("MsiDigitalCertificate")
}
func createMSIMsiDigitalSignatureTable() msiTable {
	return createMSITableFromCatalog("MsiDigitalSignature")
}
func createMSIMsiEmbeddedChainerTable() msiTable {
	return createMSITableFromCatalog("MsiEmbeddedChainer")
}
func createMSIMsiEmbeddedUITable() msiTable { return createMSITableFromCatalog("MsiEmbeddedUI") }

// P11 — merge-module tables.
func createMSIModuleSignatureTable() msiTable  { return createMSITableFromCatalog("ModuleSignature") }
func createMSIModuleComponentsTable() msiTable { return createMSITableFromCatalog("ModuleComponents") }
func createMSIModuleDependencyTable() msiTable { return createMSITableFromCatalog("ModuleDependency") }
func createMSIModuleExclusionTable() msiTable  { return createMSITableFromCatalog("ModuleExclusion") }
func createMSIModuleConfigurationTable() msiTable {
	return createMSITableFromCatalog("ModuleConfiguration")
}
func createMSIModuleSubstitutionTable() msiTable {
	return createMSITableFromCatalog("ModuleSubstitution")
}
func createMSIModuleIgnoreTableTable() msiTable {
	return createMSITableFromCatalog("ModuleIgnoreTable")
}
func createMSIModuleInstallExecuteSequenceTable() msiTable {
	return createMSITableFromCatalog("ModuleInstallExecuteSequence")
}
func createMSIModuleInstallUISequenceTable() msiTable {
	return createMSITableFromCatalog("ModuleInstallUISequence")
}
func createMSIModuleAdminExecuteSequenceTable() msiTable {
	return createMSITableFromCatalog("ModuleAdminExecuteSequence")
}
func createMSIModuleAdminUISequenceTable() msiTable {
	return createMSITableFromCatalog("ModuleAdminUISequence")
}

// P10 — patch tables.
func createMSIPatchTable() msiTable            { return createMSITableFromCatalog("Patch") }
func createMSIPatchPackageTable() msiTable     { return createMSITableFromCatalog("PatchPackage") }
func createMSIMsiPatchHeadersTable() msiTable  { return createMSITableFromCatalog("MsiPatchHeaders") }
func createMSIMsiPatchMetadataTable() msiTable { return createMSITableFromCatalog("MsiPatchMetadata") }
func createMSIMsiPatchSequenceTable() msiTable { return createMSITableFromCatalog("MsiPatchSequence") }

// populateCoreRequiredTables ensures the minimal set exists (mirrors sibling DatabaseBuilder.Build logic).
func populateCoreRequiredTables(tables map[string]msiTable) {
	if _, ok := tables[msiPropTableName]; !ok {
		tables[msiPropTableName] = createMSIPropertyTable()
	}
	if _, ok := tables[msiDirTableName]; !ok {
		tables[msiDirTableName] = createMSIDirectoryTable()
	}
	if _, ok := tables[msiCompTableName]; !ok {
		tables[msiCompTableName] = createMSIComponentTable()
	}
	if _, ok := tables[msiFeatTableName]; !ok {
		tables[msiFeatTableName] = createMSIFeatureTable()
	}
	if _, ok := tables[msiFeatCompTableName]; !ok {
		tables[msiFeatCompTableName] = createMSIFeatureComponentsTable()
	}
	if _, ok := tables[msiFileTableName]; !ok {
		tables[msiFileTableName] = createMSIFileTable()
	}
	if _, ok := tables[msiMediaTableName]; !ok {
		tables[msiMediaTableName] = createMSIMediaTable()
	}
	if _, ok := tables[msiInstallExecSeqTableName]; !ok {
		tables[msiInstallExecSeqTableName] = createMSIInstallExecuteSequenceTable()
	}
	if _, ok := tables[msiInstallUISeqTableName]; !ok {
		tables[msiInstallUISeqTableName] = createMSIInstallUISequenceTable()
	}
	if _, ok := tables[msiAdminExecSeqTableName]; !ok {
		tables[msiAdminExecSeqTableName] = createMSIAdminExecuteSequenceTable()
	}
	if _, ok := tables[msiAdminUISeqTableName]; !ok {
		tables[msiAdminUISeqTableName] = createMSIAdminUISequenceTable()
	}
	if _, ok := tables[msiAdvtExecSeqTableName]; !ok {
		tables[msiAdvtExecSeqTableName] = createMSIAdvtExecuteSequenceTable()
	}
}

// addProperty is a helper used by higher layers.
func addProperty(propTable msiTable, name, value string) error {
	row := newMSIRowBuilder().
		WithColumns(propTable.columns()...).
		WithValues(name, value).
		Build()
	return propTable.addRow(row)
}

// msiColumnTypeToMSIType maps an internal column type to the MSITYPE bitfield
// of a width-0, non-key, non-nullable, non-localizable column of that
// category (string -> 0x0D00, int16 -> 0x0502, int32 -> 0x0104, binary ->
// 0x0900).
//
// Deprecated: the category alone cannot carry the column's width, KEY,
// NULLABLE or LOCALIZABLE flags that the _Columns Type cell requires; use
// msiColumn.typeBits() instead.
func msiColumnTypeToMSIType(ct msiColumnType) int16 {
	col := newMSIColumnBuilder().WithType(ct).Build()
	return int16(col.typeBits())
}

// storedMSICellValue returns the raw on-disk cell value for val in a column of
// category ct (Wine table.c int_to_table_storage; rust-msi column.rs
// write_value):
//
//	int16  v   -> uint16(v) ^ 0x8000      (-32768 is rejected: it would store 0 = NULL)
//	int32  v   -> uint32(v) ^ 0x80000000  (-2147483648 is rejected: it would store 0 = NULL)
//	string s   -> 1-based string pool ref ("" and NULL -> 0)
//	binary b   -> 1 when data is present, 0 when NULL (data lives in a side stream)
//	NULL       -> 0
//
// The same raw values drive both serialization and the primary-key row sort.
func storedMSICellValue(val any, ct msiColumnType, pool *msiStringPool) (uint32, error) {
	// Dereference pointers; nil pointers are NULL.
	switch p := val.(type) {
	case *string:
		if p == nil {
			val = nil
		} else {
			val = *p
		}
	case *int16:
		if p == nil {
			val = nil
		} else {
			val = *p
		}
	case *int32:
		if p == nil {
			val = nil
		} else {
			val = *p
		}
	}

	switch ct {
	case msiColInteger:
		var v int16
		switch x := val.(type) {
		case nil:
			return 0, nil
		case int16:
			v = x
		case int:
			if x < -32767 || x > 32767 {
				return 0, fmt.Errorf("int16 value %d out of range -32767..32767", x)
			}
			v = int16(x)
		default:
			return 0, fmt.Errorf("value %v (%T) is invalid for an int16 column", val, val)
		}
		if v == -32768 {
			return 0, fmt.Errorf("int16 value -32768 is reserved for NULL")
		}
		return uint32(uint16(v) ^ 0x8000), nil

	case msiColDoubleInteger, msiColDateTime:
		var v int32
		switch x := val.(type) {
		case nil:
			return 0, nil
		case int32:
			v = x
		case int:
			if x < -2147483647 || x > 2147483647 {
				return 0, fmt.Errorf("int32 value %d out of range -2147483647..2147483647", x)
			}
			v = int32(x)
		default:
			return 0, fmt.Errorf("value %v (%T) is invalid for an int32 column", val, val)
		}
		if v == -2147483648 {
			return 0, fmt.Errorf("int32 value -2147483648 is reserved for NULL")
		}
		return uint32(v) ^ 0x80000000, nil

	case msiColBinary:
		switch x := val.(type) {
		case nil:
			return 0, nil
		case []byte:
			if x == nil {
				return 0, nil
			}
			return 1, nil
		default:
			return 0, fmt.Errorf("value %v (%T) is invalid for a binary column", val, val)
		}

	default:
		// string-like (Identifier, Text, Filename, GUID, Version, Property,
		// DefaultDir, etc.). NULL and "" are both string ref 0.
		switch x := val.(type) {
		case nil:
			return 0, nil
		case string:
			if x == "" {
				return 0, nil
			}
			ref := pool.refFor(x)
			if ref == 0 {
				return 0, fmt.Errorf("string %q is not interned in the string pool", x)
			}
			return ref, nil
		default:
			return 0, fmt.Errorf("value %v (%T) is invalid for a string column", val, val)
		}
	}
}

// serializeRealTableData serializes the table's rows to the real Windows
// Installer table stream format (for storage inside the CFB).
// Layout: column-major (all rows' column-1 cells, then column-2, ...), with
// exact cell widths (string = 2, or 3 with long pool refs; int16 = 2 with
// ^0x8000; int32 = 4 with ^0x80000000; binary = 2; NULL int = stored 0; NULL
// or empty string = ref 0). Every cell - including NULL - is written, because
// readers derive row count as stream_size / row_size.
//
// Rows are sorted ascending by the tuple of key-column raw STORED cell values
// (key columns in declaration order): string keys compare by pool ID, not
// lexicographically; NULL (stored 0) sorts first. Readers binary-search rows,
// so unsorted tables are seen as invalid by msiexec. Duplicate full key
// tuples are rejected. Empty tables produce no bytes (the stream is omitted).
func serializeRealTableData(tbl msiTable, pool *msiStringPool) ([]byte, error) {
	cols := tbl.columns()
	rowsList := tbl.rows()
	if len(rowsList) == 0 {
		return nil, nil
	}

	var keyIdx []int
	for i, c := range cols {
		if c.isKey() {
			keyIdx = append(keyIdx, i)
		}
	}

	// Snapshot each row's values once and precompute its stored key tuple.
	type rowEntry struct {
		vals []any
		key  []uint32
	}
	entries := make([]rowEntry, len(rowsList))
	for i, row := range rowsList {
		vals := row.values()
		key := make([]uint32, len(keyIdx))
		for k, ci := range keyIdx {
			var val any
			if ci < len(vals) {
				val = vals[ci]
			}
			stored, err := storedMSICellValue(val, cols[ci].typ(), pool)
			if err != nil {
				return nil, fmt.Errorf("table %s key column %s: %w", tbl.name(), cols[ci].name(), err)
			}
			key[k] = stored
		}
		entries[i] = rowEntry{vals: vals, key: key}
	}

	sort.SliceStable(entries, func(a, b int) bool {
		return compareMSIKeyTuples(entries[a].key, entries[b].key) < 0
	})
	if len(keyIdx) > 0 {
		for i := 1; i < len(entries); i++ {
			if compareMSIKeyTuples(entries[i-1].key, entries[i].key) == 0 {
				return nil, fmt.Errorf("table %s: duplicate primary key", tbl.name())
			}
		}
	}

	var buf bytes.Buffer
	longRefs := pool.isLongRefs()
	for colIdx, col := range cols {
		ct := col.typ()
		for _, e := range entries {
			var val any
			if colIdx < len(e.vals) {
				val = e.vals[colIdx]
			}
			if err := writeEncodedMSITableValue(&buf, val, ct, pool, longRefs); err != nil {
				return nil, fmt.Errorf("table %s column %s: %w", tbl.name(), col.name(), err)
			}
		}
	}
	return buf.Bytes(), nil
}

// compareMSIKeyTuples compares two stored key tuples element-wise (unsigned),
// matching Wine table.c compare_record: the first differing key column
// decides; NULL (stored 0) sorts before everything.
func compareMSIKeyTuples(a, b []uint32) int {
	for i := range a {
		if i >= len(b) {
			break
		}
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

// writeEncodedMSITableValue writes one cell in its exact on-disk width:
// int16/binary -> 2 bytes, int32 -> 4 bytes, string -> 2 bytes (3 with long
// pool refs), all little-endian.
func writeEncodedMSITableValue(w io.Writer, val any, ct msiColumnType, pool *msiStringPool, longRefs bool) error {
	stored, err := storedMSICellValue(val, ct, pool)
	if err != nil {
		return err
	}

	switch ct {
	case msiColDoubleInteger, msiColDateTime:
		return binary.Write(w, binary.LittleEndian, stored)
	case msiColInteger, msiColBinary:
		return binary.Write(w, binary.LittleEndian, uint16(stored))
	default:
		if longRefs {
			b := []byte{byte(stored), byte(stored >> 8), byte(stored >> 16)}
			_, err := w.Write(b)
			return err
		}
		// Short-ref mode: Wine flips to long refs once the highest assigned
		// ID reaches 0xFFFF, so a short ref must be <= 0xFFFE.
		if stored >= maxMSIPoolSlots {
			return fmt.Errorf("string ref %d does not fit in 2 bytes (pool is not using long refs)", stored)
		}
		return binary.Write(w, binary.LittleEndian, uint16(stored))
	}
}
