package msi

import (
	"fmt"
	"io"
	"time"
)

// Database is a read-only view of a Windows Installer database, opened with
// Open. It exposes every table the package lists (the system catalog tables
// _Tables and _Columns are folded into the schema and not listed) with each
// row decoded into its column values, plus the SummaryInformation stream.
//
// It is intended for inspecting and testing generated packages: asserting on
// Property values, Component attributes, Upgrade rows or the declared
// platform is far more precise than searching the raw bytes. Cell values are
// string for string columns, int16 or int32 for integer columns, []byte for
// binary/object columns, and nil for a NULL cell.
type Database interface {
	// Tables returns the names of every listed table in sorted order.
	Tables() []string
	// Table returns the rows of the named table in on-disk order. It returns an
	// error when the package does not list that table.
	Table(name string) ([]Row, error)
	// Summary returns the package's SummaryInformation stream.
	Summary() SummaryInfo
}

// Row is one decoded table row keyed by column name.
type Row map[string]any

// SummaryInfo is the decoded SummaryInformation stream of a package.
type SummaryInfo interface {
	// Template is PID 7, "<platform>;<langid>" (for example "x64;1033"), or a
	// ProductCode list for a patch.
	Template() string
	// Title is PID 2, conventionally "Installation Database".
	Title() string
	// Subject is PID 3, conventionally the ProductName.
	Subject() string
	// Author is PID 4, conventionally the Manufacturer.
	Author() string
	// Keywords is PID 5, conventionally "Installer".
	Keywords() string
	// Comments is PID 6.
	Comments() string
	// Revision is PID 9, the PackageCode as a braced uppercase GUID (for a
	// patch, its GUID followed by the ProductCodes it applies to).
	Revision() string
	// CreatingApp is PID 18, the tool that wrote the package.
	CreatingApp() string
	// CreateTime and SaveTime are PID 12 and 13; zero when omitted.
	CreateTime() time.Time
	SaveTime() time.Time
	// PageCount is PID 14, the minimum Windows Installer version (200 for
	// Intel/Intel64/x64, 500 for Arm/Arm64); 0 when omitted.
	PageCount() int
	// WordCount is PID 15, the source/filename flags (2 = compressed source,
	// long file names).
	WordCount() int
	// CodePage is PID 1; 0 means the 1252 default.
	CodePage() int
	// Security is PID 19 (2 = read-only recommended); 0 when omitted.
	Security() int
}

// Open reads the database and SummaryInformation of the MSI (or MSP) at r.
// The whole database is decoded eagerly, so the returned Database no longer
// depends on r.
func Open(r io.ReaderAt) (Database, error) {
	db, err := readMSIDatabase(r)
	if err != nil {
		return nil, fmt.Errorf("msi open: reading database: %w", err)
	}
	sum, err := readMSISummaryInfo(r)
	if err != nil {
		return nil, fmt.Errorf("msi open: reading summary information: %w", err)
	}
	return &readOnlyDatabase{db: db, summary: readOnlySummary{info: sum}}, nil
}

type readOnlyDatabase struct {
	db      msiDatabase
	summary readOnlySummary
}

func (d *readOnlyDatabase) Tables() []string { return d.db.Tables() }

func (d *readOnlyDatabase) Table(name string) ([]Row, error) {
	tbl, err := d.db.GetTable(name)
	if err != nil {
		return nil, fmt.Errorf("msi open: %w", err)
	}
	cols := tbl.columns()
	rows := tbl.rows()
	out := make([]Row, 0, len(rows))
	for _, r := range rows {
		vals := r.values()
		row := make(Row, len(cols))
		for i, c := range cols {
			var v any
			if i < len(vals) {
				v = vals[i]
			}
			row[c.name()] = v
		}
		out = append(out, row)
	}
	return out, nil
}

func (d *readOnlyDatabase) Summary() SummaryInfo { return d.summary }

type readOnlySummary struct {
	info msiSummaryInfo
}

func (s readOnlySummary) Template() string      { return s.info.Template }
func (s readOnlySummary) Title() string         { return s.info.Title }
func (s readOnlySummary) Subject() string       { return s.info.Subject }
func (s readOnlySummary) Author() string        { return s.info.Author }
func (s readOnlySummary) Keywords() string      { return s.info.Keywords }
func (s readOnlySummary) Comments() string      { return s.info.Comments }
func (s readOnlySummary) Revision() string      { return s.info.RevisionNumber }
func (s readOnlySummary) CreatingApp() string   { return s.info.CreatingApp }
func (s readOnlySummary) CreateTime() time.Time { return s.info.CreateTime }
func (s readOnlySummary) SaveTime() time.Time   { return s.info.SaveTime }
func (s readOnlySummary) PageCount() int        { return s.info.PageCount }
func (s readOnlySummary) WordCount() int        { return s.info.WordCount }
func (s readOnlySummary) CodePage() int         { return s.info.Codepage }
func (s readOnlySummary) Security() int         { return s.info.Security }
