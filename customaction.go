package msi

import "fmt"

// msi_customaction.go — P5 CustomAction support. The public API exposes typed
// constructors (no raw Type integers): each constructor sets the base type and
// the Source/Target cells, and modifier methods OR in the option bits. The final
// CustomAction.Type (int16) is base | in-script-mode | modifiers, computed at the
// cell boundary in emitMSICustomActionTable.
//
// Scheduling into the sequence tables is resolved by msi_sequences.go.

// SequenceTable identifies one of the five standard MSI sequence tables (used by
// custom-action scheduling). Its string value is the table name.
type SequenceTable string

const (
	InstallExecuteSequence SequenceTable = "InstallExecuteSequence"
	InstallUISequence      SequenceTable = "InstallUISequence"
	AdminExecuteSequence   SequenceTable = "AdminExecuteSequence"
	AdminUISequence        SequenceTable = "AdminUISequence"
	AdvtExecuteSequence    SequenceTable = "AdvtExecuteSequence"
)

// CustomAction base types (low 6 bits of Type). Internal — selected via the
// typed constructors.
const (
	caTypeDLLBinary      int16 = 1
	caTypeEXEBinary      int16 = 2
	caTypeJScriptBinary  int16 = 5
	caTypeVBScriptBinary int16 = 6
	caTypeDLLFile        int16 = 17
	caTypeEXEFile        int16 = 18
	caTypeError          int16 = 19
	caTypeJScriptFile    int16 = 21
	caTypeVBScriptFile   int16 = 22
	caTypeEXEDirectory   int16 = 34
	caTypeSetDirectory   int16 = 35
	caTypeJScriptInline  int16 = 37
	caTypeVBScriptInline int16 = 38
	caTypeEXEProperty    int16 = 50
	caTypeSetProperty    int16 = 51
)

// In-script execution modes (mutually exclusive). Deferred = InScript(0x400);
// Rollback = InScript|0x100 = 0x500; Commit = InScript|0x200 = 0x600.
const (
	caInScriptNone     int16 = 0
	caInScriptDeferred int16 = 0x400
	caInScriptRollback int16 = 0x400 | 0x100
	caInScriptCommit   int16 = 0x400 | 0x200
)

// Modifier option bits (OR-ed into Type).
const (
	caModContinue      int16 = 0x40
	caModAsync         int16 = 0x80
	caModNoImpersonate int16 = 0x800
	caMod64BitScript   int16 = 0x1000
	caModHideTarget    int16 = 0x2000
)

// CustomActionBuilder configures one CustomAction row and its sequence
// schedule(s). Exactly one type constructor should be called; modifiers and
// schedules may be chained.
type CustomActionBuilder interface {
	// Binary-table-backed code (Source = Binary key).
	DLLFromBinary(binaryKey, entryPoint string) CustomActionBuilder
	EXEFromBinary(binaryKey, cmdLine string) CustomActionBuilder
	JScriptFromBinary(binaryKey, function string) CustomActionBuilder
	VBScriptFromBinary(binaryKey, function string) CustomActionBuilder
	// File-table-backed code (Source = File key).
	DLLFromFile(fileKey, entryPoint string) CustomActionBuilder
	EXEFromFile(fileKey, cmdLine string) CustomActionBuilder
	// Directory/Property-sourced EXE.
	EXEFromDirectory(directoryKey, cmdLine string) CustomActionBuilder
	EXEFromProperty(property, cmdLine string) CustomActionBuilder
	// Data/control actions.
	ErrorMessage(text string) CustomActionBuilder
	SetProperty(property, value string) CustomActionBuilder
	SetDirectory(directoryKey, path string) CustomActionBuilder
	// Inline script in the Target cell.
	JScriptInline(code string) CustomActionBuilder
	VBScriptInline(code string) CustomActionBuilder

	// Modifiers.
	Deferred() CustomActionBuilder
	Rollback() CustomActionBuilder
	Commit() CustomActionBuilder
	NoImpersonate() CustomActionBuilder
	Async() CustomActionBuilder
	ContinueOnError() CustomActionBuilder
	HideTarget() CustomActionBuilder
	Is64BitScript() CustomActionBuilder

	// Scheduling (each call appends one schedule; condition "" means none).
	ScheduleAfter(table SequenceTable, anchor, condition string) CustomActionBuilder
	ScheduleBefore(table SequenceTable, anchor, condition string) CustomActionBuilder
	ScheduleAt(table SequenceTable, sequence int16, condition string) CustomActionBuilder
}

// ----- model -----

type caRel int

const (
	caRelAfter caRel = iota
	caRelBefore
	caRelAt
)

type caSchedule struct {
	table     SequenceTable
	anchor    string
	rel       caRel
	sequence  int16
	condition string
}

type customActionEntry struct {
	id        string
	baseType  int16
	inScript  int16
	modifiers int16
	source    string
	target    string
	schedules []caSchedule
}

// finalType computes the CustomAction.Type cell value.
func (e *customActionEntry) finalType() int16 {
	return e.baseType | e.inScript | e.modifiers
}

// ----- PackageBuilder method -----

func (p *msiPackage) CustomAction(id string) CustomActionBuilder {
	p.customActions = append(p.customActions, customActionEntry{id: id})
	return &customActionHandle{pkg: p, idx: len(p.customActions) - 1}
}

type customActionHandle struct {
	pkg *msiPackage
	idx int
}

func (h *customActionHandle) entry() *customActionEntry { return &h.pkg.customActions[h.idx] }

func (h *customActionHandle) setType(base int16, source, target string) CustomActionBuilder {
	e := h.entry()
	e.baseType = base
	e.source = source
	e.target = target
	return h
}

func (h *customActionHandle) DLLFromBinary(binaryKey, entryPoint string) CustomActionBuilder {
	return h.setType(caTypeDLLBinary, binaryKey, entryPoint)
}
func (h *customActionHandle) EXEFromBinary(binaryKey, cmdLine string) CustomActionBuilder {
	return h.setType(caTypeEXEBinary, binaryKey, cmdLine)
}
func (h *customActionHandle) JScriptFromBinary(binaryKey, function string) CustomActionBuilder {
	return h.setType(caTypeJScriptBinary, binaryKey, function)
}
func (h *customActionHandle) VBScriptFromBinary(binaryKey, function string) CustomActionBuilder {
	return h.setType(caTypeVBScriptBinary, binaryKey, function)
}
func (h *customActionHandle) DLLFromFile(fileKey, entryPoint string) CustomActionBuilder {
	return h.setType(caTypeDLLFile, fileKey, entryPoint)
}
func (h *customActionHandle) EXEFromFile(fileKey, cmdLine string) CustomActionBuilder {
	return h.setType(caTypeEXEFile, fileKey, cmdLine)
}
func (h *customActionHandle) EXEFromDirectory(directoryKey, cmdLine string) CustomActionBuilder {
	return h.setType(caTypeEXEDirectory, directoryKey, cmdLine)
}
func (h *customActionHandle) EXEFromProperty(property, cmdLine string) CustomActionBuilder {
	return h.setType(caTypeEXEProperty, property, cmdLine)
}
func (h *customActionHandle) ErrorMessage(text string) CustomActionBuilder {
	return h.setType(caTypeError, "", text)
}
func (h *customActionHandle) SetProperty(property, value string) CustomActionBuilder {
	return h.setType(caTypeSetProperty, property, value)
}
func (h *customActionHandle) SetDirectory(directoryKey, path string) CustomActionBuilder {
	return h.setType(caTypeSetDirectory, directoryKey, path)
}
func (h *customActionHandle) JScriptInline(code string) CustomActionBuilder {
	return h.setType(caTypeJScriptInline, "", code)
}
func (h *customActionHandle) VBScriptInline(code string) CustomActionBuilder {
	return h.setType(caTypeVBScriptInline, "", code)
}

func (h *customActionHandle) Deferred() CustomActionBuilder {
	h.entry().inScript = caInScriptDeferred
	return h
}
func (h *customActionHandle) Rollback() CustomActionBuilder {
	h.entry().inScript = caInScriptRollback
	return h
}
func (h *customActionHandle) Commit() CustomActionBuilder {
	h.entry().inScript = caInScriptCommit
	return h
}
func (h *customActionHandle) NoImpersonate() CustomActionBuilder {
	h.entry().modifiers |= caModNoImpersonate
	return h
}
func (h *customActionHandle) Async() CustomActionBuilder {
	h.entry().modifiers |= caModAsync
	return h
}
func (h *customActionHandle) ContinueOnError() CustomActionBuilder {
	h.entry().modifiers |= caModContinue
	return h
}
func (h *customActionHandle) HideTarget() CustomActionBuilder {
	h.entry().modifiers |= caModHideTarget
	return h
}
func (h *customActionHandle) Is64BitScript() CustomActionBuilder {
	h.entry().modifiers |= caMod64BitScript
	return h
}

func (h *customActionHandle) ScheduleAfter(table SequenceTable, anchor, condition string) CustomActionBuilder {
	h.entry().schedules = append(h.entry().schedules, caSchedule{table: table, anchor: anchor, rel: caRelAfter, condition: condition})
	return h
}
func (h *customActionHandle) ScheduleBefore(table SequenceTable, anchor, condition string) CustomActionBuilder {
	h.entry().schedules = append(h.entry().schedules, caSchedule{table: table, anchor: anchor, rel: caRelBefore, condition: condition})
	return h
}
func (h *customActionHandle) ScheduleAt(table SequenceTable, sequence int16, condition string) CustomActionBuilder {
	h.entry().schedules = append(h.entry().schedules, caSchedule{table: table, rel: caRelAt, sequence: sequence, condition: condition})
	return h
}

// ----- emission -----

// emitMSICustomActionTable emits the CustomAction table (Type computed at the
// cell boundary; Source/Target "" map to NULL; ExtendedType is always NULL in
// this version). Scheduling into the sequence tables is handled separately by
// scheduleCustomActions.
func emitMSICustomActionTable(p *msiPackage, db msiDatabaseBuilder) error {
	if len(p.customActions) == 0 {
		return nil
	}
	tbl := createMSITableFromCatalog("CustomAction")
	for _, e := range p.customActions {
		row := newMSIRowBuilder().WithColumns(tbl.columns()...).WithValues(
			e.id, e.finalType(), e.source, e.target, nil,
		).Build()
		if err := tbl.addRow(row); err != nil {
			return fmt.Errorf("msi compile: CustomAction row %s: %w", e.id, err)
		}
	}
	db.WithTable(tbl)
	return nil
}
