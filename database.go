package msi

// msi_database.go
// High-level builder for populating the MSI database tables prior to CFB
// emission. Adapted (with heavy modification) from the database/ package in
// the sibling project /home/djgilcrease/projects/msi/ (github.com/djgilcrease/go-msi).
//
// Build() finalizes the database: it ensures the core required tables exist,
// generates the _Validation rows for every catalog-known table present, and
// populates the _Tables/_Columns system catalog from the final table set.
// All row-insertion errors raised by the stricter column validation are
// accumulated and surfaced from Build() instead of being silently dropped.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

// msiDatabaseBuilder collects tables and file payload data for later CAB
// embedding. All methods chain; errors are deferred to Build().
type msiDatabaseBuilder interface {
	WithTable(t msiTable) msiDatabaseBuilder
	WithStandardProperties(productName, productVersion, manufacturer, productCode string) msiDatabaseBuilder
	WithProperties(props map[string]string) msiDatabaseBuilder
	WithDirectory(name, parentName, defaultDir string) msiDatabaseBuilder
	WithComponent(name, guid, directory string, attributes int16, keyPath any) msiDatabaseBuilder
	WithFile(component, fileID, fileName string, data []byte, version string, sequence int16) msiDatabaseBuilder
	WithFeature(name, title, description string, display, level int16) msiDatabaseBuilder
	AssociateComponentToFeature(featureID, componentID string) msiDatabaseBuilder
	WithSequenceAction(table, action string, condition any, sequence int16) msiDatabaseBuilder
	WithMedia(diskID, lastSequence int16, cabinet string) msiDatabaseBuilder
	Build() (msiDatabase, error)
}

// msiDatabase gives access to the populated tables and file contents.
type msiDatabase interface {
	GetTable(name string) (msiTable, error)
	// Tables returns all table names in sorted (deterministic) order.
	Tables() []string
	// FileContents returns map of fileID -> raw bytes (for CAB staging).
	// The keys are the IDs used in the File table "File" column.
	FileContents() map[string][]byte
	validate() error
}

type msiDB struct {
	tables       map[string]msiTable
	fileContents map[string][]byte
	errs         []error
}

func newMSIDatabaseBuilder() msiDatabaseBuilder {
	return &msiDB{
		tables:       make(map[string]msiTable),
		fileContents: make(map[string][]byte),
	}
}

// fail records a deferred error surfaced from Build().
func (d *msiDB) fail(err error) {
	if err != nil {
		d.errs = append(d.errs, err)
	}
}

// table returns the named table, creating it via factory when absent.
func (d *msiDB) table(name string, factory func() msiTable) msiTable {
	t, ok := d.tables[name]
	if !ok {
		t = factory()
		d.tables[name] = t
	}
	return t
}

// addRow validates and inserts a row, deferring any error to Build().
func (d *msiDB) addRow(t msiTable, values ...any) {
	row := newMSIRowBuilder().
		WithColumns(t.columns()...).
		WithValues(values...).
		Build()
	if err := t.addRow(row); err != nil {
		d.fail(fmt.Errorf("table %s: %w", t.name(), err))
	}
}

func (d *msiDB) WithTable(t msiTable) msiDatabaseBuilder {
	d.tables[t.name()] = t
	return d
}

func (d *msiDB) WithStandardProperties(productName, productVersion, manufacturer, productCode string) msiDatabaseBuilder {
	return d.WithProperties(map[string]string{
		"ProductName":    productName,
		"ProductVersion": productVersion,
		"Manufacturer":   manufacturer,
		"ProductCode":    productCode,
	})
}

func (d *msiDB) WithProperties(props map[string]string) msiDatabaseBuilder {
	t := d.table(msiPropTableName, createMSIPropertyTable)
	// Deterministic insertion order.
	keys := make([]string, 0, len(props))
	for k := range props {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		d.addRow(t, k, props[k])
	}
	return d
}

func (d *msiDB) WithDirectory(name, parentName, defaultDir string) msiDatabaseBuilder {
	t := d.table(msiDirTableName, createMSIDirectoryTable)
	var parent any
	if parentName != "" {
		parent = parentName
	}
	d.addRow(t, name, parent, defaultDir)
	return d
}

func (d *msiDB) WithComponent(name, guid, directory string, attributes int16, keyPath any) msiDatabaseBuilder {
	t := d.table(msiCompTableName, createMSIComponentTable)
	var g any
	if guid != "" {
		g = guid
	}
	d.addRow(t, name, g, directory, attributes, nil, keyPath)
	return d
}

func (d *msiDB) WithFile(component, fileID, fileName string, data []byte, version string, sequence int16) msiDatabaseBuilder {
	t := d.table(msiFileTableName, createMSIFileTable)
	var ver any
	if version != "" {
		ver = version
	}
	d.addRow(t, fileID, component, fileName, int32(len(data)), ver, nil, nil, sequence)
	d.fileContents[fileID] = append([]byte(nil), data...)
	return d
}

func (d *msiDB) WithFeature(name, title, description string, display, level int16) msiDatabaseBuilder {
	t := d.table(msiFeatTableName, createMSIFeatureTable)
	var ttl, desc any
	if title != "" {
		ttl = title
	}
	if description != "" {
		desc = description
	}
	d.addRow(t, name, nil, ttl, desc, display, level, nil, int16(0))
	return d
}

func (d *msiDB) AssociateComponentToFeature(featureID, componentID string) msiDatabaseBuilder {
	t := d.table(msiFeatCompTableName, createMSIFeatureComponentsTable)
	d.addRow(t, featureID, componentID)
	return d
}

// WithSequenceAction adds one action row to the named sequence table
// (InstallExecuteSequence, InstallUISequence, AdminExecuteSequence,
// AdminUISequence or AdvtExecuteSequence). condition must be nil or a string.
func (d *msiDB) WithSequenceAction(table, action string, condition any, sequence int16) msiDatabaseBuilder {
	factories := map[string]func() msiTable{
		msiInstallExecSeqTableName: createMSIInstallExecuteSequenceTable,
		msiInstallUISeqTableName:   createMSIInstallUISequenceTable,
		msiAdminExecSeqTableName:   createMSIAdminExecuteSequenceTable,
		msiAdminUISeqTableName:     createMSIAdminUISequenceTable,
		msiAdvtExecSeqTableName:    createMSIAdvtExecuteSequenceTable,
	}
	factory, ok := factories[table]
	if !ok {
		d.fail(fmt.Errorf("unknown sequence table %q", table))
		return d
	}
	t := d.table(table, factory)
	d.addRow(t, action, condition, sequence)
	return d
}

func (d *msiDB) WithMedia(diskID, lastSequence int16, cabinet string) msiDatabaseBuilder {
	t := d.table(msiMediaTableName, createMSIMediaTable)
	var cab any
	if cabinet != "" {
		cab = cabinet
	}
	d.addRow(t, diskID, lastSequence, nil, cab, nil, nil)
	return d
}

func (d *msiDB) Build() (msiDatabase, error) {
	if len(d.errs) > 0 {
		return nil, fmt.Errorf("msi database population failed: %w (first of %d errors)", d.errs[0], len(d.errs))
	}

	populateCoreRequiredTables(d.tables)

	// _Validation rows for every catalog-known table present (plus itself).
	validation, err := populateMSIValidationRows(d.tables)
	if err != nil {
		return nil, fmt.Errorf("msi: building _Validation: %w", err)
	}
	d.tables[msiValidationTableName] = validation

	if err := d.populateSystemCatalog(); err != nil {
		return nil, err
	}

	if err := d.validate(); err != nil {
		return nil, err
	}
	return d, nil
}

// populateSystemCatalog fills _Tables and _Columns from the final table set.
// The system tables themselves are NOT listed (matching real MSIs, where
// _Tables/_Columns/_StringPool/_StringData are implicit); _Validation IS a
// normal persistent table and is listed.
func (d *msiDB) populateSystemCatalog() error {
	tablesTbl := createMSITablesTable()
	columnsTbl := createMSIColumnsTable()

	for _, name := range d.sortedUserTables() {
		t := d.tables[name]
		row := newMSIRowBuilder().WithColumns(tablesTbl.columns()...).WithValues(name).Build()
		if err := tablesTbl.addRow(row); err != nil {
			return fmt.Errorf("_Tables: %w", err)
		}
		for i, col := range t.columns() {
			// The Type cell carries the raw MSITYPE bitfield; it is always
			// < 0x8000 so the int16 conversion is lossless and the standard
			// i2 sign-bit transform stores it as bits+0x8000 on disk,
			// matching real MSIs (e.g. s72 key column reads back 0xAD48).
			crow := newMSIRowBuilder().WithColumns(columnsTbl.columns()...).
				WithValues(name, int16(i+1), col.name(), int16(col.typeBits())).Build()
			if err := columnsTbl.addRow(crow); err != nil {
				return fmt.Errorf("_Columns: %w", err)
			}
		}
	}

	d.tables[msiTablesTableName] = tablesTbl
	d.tables[msiColumnsTableName] = columnsTbl
	return nil
}

// sortedUserTables returns all table names except the _Tables/_Columns system
// catalog itself, sorted.
func (d *msiDB) sortedUserTables() []string {
	names := make([]string, 0, len(d.tables))
	for n := range d.tables {
		if n == msiTablesTableName || n == msiColumnsTableName {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (d *msiDB) GetTable(name string) (msiTable, error) {
	t, ok := d.tables[name]
	if !ok {
		return nil, fmt.Errorf("table %s not found", name)
	}
	return t, nil
}

func (d *msiDB) Tables() []string {
	names := make([]string, 0, len(d.tables))
	for n := range d.tables {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (d *msiDB) FileContents() map[string][]byte {
	// return copy to avoid mutation
	out := make(map[string][]byte, len(d.fileContents))
	for k, v := range d.fileContents {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

func (d *msiDB) validate() error {
	for _, name := range d.Tables() {
		t := d.tables[name]
		if err := t.validate(); err != nil {
			return fmt.Errorf("table %s validation failed: %w", t.name(), err)
		}
	}
	return nil
}

// generateMSIFileID produces a valid, stable MSI Identifier for a file's
// primary key in the File table: "fil" + 32 hex chars of SHA-256 over the
// package path and content. Hashing the path as well as the content keeps two
// identical payloads at different paths from colliding on the primary key.
// generateMSIFileID derives a File-table primary key from the file's logical
// path ALONE — deliberately NOT its content. A File key is a stable identity:
// the same path keeps the same key across versions, which is required for
// patching (a small/minor patch updates the existing File row in place rather
// than churning its primary key) and matches how authored MSIs behave. Paths
// are unique within a package, so path-only keys stay collision-free; content
// identity lives in MsiFileHash and the cabinet, not the key. The data
// parameter is retained for call-site compatibility and is intentionally unused.
func generateMSIFileID(packagePath string, data []byte) string {
	_ = data
	h := sha256.New()
	h.Write([]byte(packagePath))
	sum := h.Sum(nil)
	return "fil" + hex.EncodeToString(sum[:16])
}
