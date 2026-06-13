package msi

import (
	"fmt"
	"io"
	"os"
)

// Severity indicates the severity of an ICE finding. Only SeverityError
// findings cause Build/WriteMSI (or legacy BuildMSI) to fail when
// validation is enabled.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityError
)

// Finding describes one ICE validation result. It implements the error
// interface so it can be returned/inspected as an error. All public
// validation surfaces return []Finding (possibly empty) + error (for
// I/O or read failures).
type Finding interface {
	ICE() string
	Severity() Severity
	Table() string
	Column() string
	RowKeys() []string
	Message() string
	Error() string
}

// msiFinding is the private implementation of Finding (and error).
type msiFinding struct {
	ice     string
	sev     Severity
	table   string
	column  string
	rowKeys []string
	message string
}

func (f *msiFinding) ICE() string        { return f.ice }
func (f *msiFinding) Severity() Severity { return f.sev }
func (f *msiFinding) Table() string      { return f.table }
func (f *msiFinding) Column() string     { return f.column }
func (f *msiFinding) RowKeys() []string  { return f.rowKeys }
func (f *msiFinding) Message() string    { return f.message }
func (f *msiFinding) Error() string {
	if f.table != "" || f.column != "" {
		return fmt.Sprintf("%s: %s (table=%s column=%s)", f.ice, f.message, f.table, f.column)
	}
	return fmt.Sprintf("%s: %s", f.ice, f.message)
}

// ValidatorBuilder configures which ICEs to run and how to report them.
// Per the project style guide this is the Builder-IS-Implementation pattern:
// the concrete type implements both the builder interface and (after Build)
// the runtime Validator interface. All public surface is the interface.
type ValidatorBuilder interface {
	WithICE(iceID string) ValidatorBuilder
	WithAllICEs() ValidatorBuilder
	WithoutICE(iceID string) ValidatorBuilder
	// WithMinSeverity sets the severity floor: only findings whose severity is
	// at or above sev are reported. The default floor is SeverityInfo (report
	// everything). Use SeverityError to surface only error-severity findings.
	WithMinSeverity(sev Severity) ValidatorBuilder
	// WithMaxSeverity is retained for source compatibility.
	//
	// Deprecated: use WithMinSeverity. This sets the MINIMUM severity to
	// report (the severity floor), matching WithMinSeverity exactly.
	WithMaxSeverity(sev Severity) ValidatorBuilder
	Build() (Validator, error)
}

// Validator runs ICE validation against an MSI (either in-memory via
// io.ReaderAt or from a file on disk). Validate returns findings (which may
// include non-error severities) plus an error only for I/O or parse failures.
// When used via the package builder's validation (see SkipValidation), only
// SeverityError findings cause a failure.
type Validator interface {
	Validate(r io.ReaderAt) ([]Finding, error)
	ValidateFile(path string) ([]Finding, error)
}

type msiValidator struct {
	ices    map[string]bool
	all     bool
	exclude map[string]bool
	// minSeverity is the severity floor: findings with Severity >= minSeverity
	// are reported. Default SeverityInfo (report everything).
	minSeverity Severity
}

func NewValidator() ValidatorBuilder {
	return &msiValidator{
		ices:        make(map[string]bool),
		exclude:     make(map[string]bool),
		minSeverity: SeverityInfo,
	}
}

func (b *msiValidator) WithICE(iceID string) ValidatorBuilder {
	b.ices[iceID] = true
	return b
}

func (b *msiValidator) WithAllICEs() ValidatorBuilder {
	b.all = true
	return b
}

func (b *msiValidator) WithoutICE(iceID string) ValidatorBuilder {
	b.exclude[iceID] = true
	return b
}

func (b *msiValidator) WithMinSeverity(sev Severity) ValidatorBuilder {
	b.minSeverity = sev
	return b
}

// WithMaxSeverity is a deprecated alias for WithMinSeverity (it sets the
// severity floor). Kept so existing callers stay source-compatible.
func (b *msiValidator) WithMaxSeverity(sev Severity) ValidatorBuilder {
	b.minSeverity = sev
	return b
}

func (b *msiValidator) Build() (Validator, error) {
	// Copy config into the runtime instance (Builder IS Implementation).
	v := &msiValidator{
		ices:        make(map[string]bool, len(b.ices)),
		all:         b.all,
		exclude:     make(map[string]bool, len(b.exclude)),
		minSeverity: b.minSeverity,
	}
	for k := range b.ices {
		v.ices[k] = true
	}
	for k := range b.exclude {
		v.exclude[k] = true
	}
	return v, nil
}

func (v *msiValidator) Validate(r io.ReaderAt) ([]Finding, error) {
	db, err := readMSIDatabase(r)
	if err != nil {
		return nil, fmt.Errorf("msi validator: reading database: %w", err)
	}
	sum, err := readMSISummaryInfo(r)
	if err != nil {
		return nil, fmt.Errorf("msi validator: reading summary: %w", err)
	}

	ctx := newIceContext(db, sum)
	findings := runAllRules(ctx, v.ices, v.all, v.exclude, v.minSeverity)
	return findings, nil
}

func (v *msiValidator) ValidateFile(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("msi validator: opening %s: %w", path, err)
	}
	defer f.Close()
	return v.Validate(f)
}

// validateInternal is the efficient in-build path (used by PackageBuilder
// and later by legacy BuildMSI). It bypasses ReaderAt roundtrips.
func (v *msiValidator) validateInternal(db msiDatabase, summary msiSummaryInfo) []Finding {
	ctx := newIceContext(db, summary)
	return runAllRules(ctx, v.ices, v.all, v.exclude, v.minSeverity)
}
