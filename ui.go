package msi

import "fmt"

// msi_ui.go — P6 UI authoring. This slice (P6.2) covers TextStyle and UIText;
// the Dialog/Control builders are added in the same file in P6.3.

// TextStyle StyleBits flags.
const (
	textStyleBold      int16 = 1
	textStyleItalic    int16 = 2
	textStyleUnderline int16 = 4
	textStyleStrike    int16 = 8
)

// TextStyleBuilder configures one TextStyle row (a named font used by dialog
// text controls).
type TextStyleBuilder interface {
	// WithColor sets the text color from 8-bit RGB components.
	WithColor(r, g, b uint8) TextStyleBuilder
	Bold() TextStyleBuilder
	Italic() TextStyleBuilder
	Underline() TextStyleBuilder
	Strike() TextStyleBuilder
	// Done returns to the parent PackageBuilder for chaining.
	Done() PackageBuilder
}

type textStyleEntry struct {
	name      string
	faceName  string
	size      int16
	color     *int32
	styleBits int16
}

type uiTextEntry struct {
	key  string
	text string
}

// ----- PackageBuilder methods -----

func (p *msiPackage) TextStyle(name, faceName string, size int16) TextStyleBuilder {
	p.textStyleEntries = append(p.textStyleEntries, textStyleEntry{name: name, faceName: faceName, size: size})
	return &textStyleHandle{pkg: p, idx: len(p.textStyleEntries) - 1}
}

func (p *msiPackage) UIText(key, text string) PackageBuilder {
	p.uiTextEntries = append(p.uiTextEntries, uiTextEntry{key: key, text: text})
	return p
}

type textStyleHandle struct {
	pkg *msiPackage
	idx int
}

func (h *textStyleHandle) entry() *textStyleEntry { return &h.pkg.textStyleEntries[h.idx] }

func (h *textStyleHandle) WithColor(r, g, b uint8) TextStyleBuilder {
	c := int32(r) | int32(g)<<8 | int32(b)<<16
	h.entry().color = &c
	return h
}
func (h *textStyleHandle) Bold() TextStyleBuilder {
	h.entry().styleBits |= textStyleBold
	return h
}
func (h *textStyleHandle) Italic() TextStyleBuilder {
	h.entry().styleBits |= textStyleItalic
	return h
}
func (h *textStyleHandle) Underline() TextStyleBuilder {
	h.entry().styleBits |= textStyleUnderline
	return h
}
func (h *textStyleHandle) Strike() TextStyleBuilder {
	h.entry().styleBits |= textStyleStrike
	return h
}
func (h *textStyleHandle) Done() PackageBuilder { return h.pkg }

// ===== P6.3 — Dialogs and controls =====

// ControlType is a Control.Type string (case-sensitive, per Microsoft Learn).
type ControlType string

const (
	ControlText              ControlType = "Text"
	ControlPushButton        ControlType = "PushButton"
	ControlLine              ControlType = "Line"
	ControlBitmap            ControlType = "Bitmap"
	ControlIcon              ControlType = "Icon"
	ControlProgressBar       ControlType = "ProgressBar"
	ControlCheckBox          ControlType = "CheckBox"
	ControlEdit              ControlType = "Edit"
	ControlPathEdit          ControlType = "PathEdit"
	ControlMaskedEdit        ControlType = "MaskedEdit"
	ControlScrollableText    ControlType = "ScrollableText"
	ControlRadioButtonGroup  ControlType = "RadioButtonGroup"
	ControlComboBox          ControlType = "ComboBox"
	ControlListBox           ControlType = "ListBox"
	ControlListView          ControlType = "ListView"
	ControlSelectionTree     ControlType = "SelectionTree"
	ControlDirectoryCombo    ControlType = "DirectoryCombo"
	ControlDirectoryList     ControlType = "DirectoryList"
	ControlGroupBox          ControlType = "GroupBox"
	ControlVolumeCostList    ControlType = "VolumeCostList"
	ControlVolumeSelectCombo ControlType = "VolumeSelectCombo"
	ControlBillboardType     ControlType = "Billboard"
	ControlHyperlink         ControlType = "Hyperlink"
)

// validControlTypes is the recognized control-type set (used by ICE17).
var validControlTypes = map[string]bool{
	"Text": true, "PushButton": true, "Line": true, "Bitmap": true, "Icon": true,
	"ProgressBar": true, "CheckBox": true, "Edit": true, "PathEdit": true,
	"MaskedEdit": true, "ScrollableText": true, "RadioButtonGroup": true,
	"ComboBox": true, "ListBox": true, "ListView": true, "SelectionTree": true,
	"DirectoryCombo": true, "DirectoryList": true, "GroupBox": true,
	"VolumeCostList": true, "VolumeSelectCombo": true, "Billboard": true, "Hyperlink": true,
}

// DialogAttr / ControlAttr are the Dialog.Attributes / Control.Attributes bits.
type DialogAttr int32

const (
	DialogVisible        DialogAttr = 1
	DialogModal          DialogAttr = 2
	DialogMinimize       DialogAttr = 4
	DialogSysModal       DialogAttr = 8
	DialogKeepModeless   DialogAttr = 16
	DialogTrackDiskSpace DialogAttr = 32
	DialogError          DialogAttr = 0x10000
)

type ControlAttr int32

const (
	ControlVisible     ControlAttr = 1
	ControlEnabled     ControlAttr = 2
	ControlSunken      ControlAttr = 4
	ControlIndirect    ControlAttr = 8
	ControlInteger     ControlAttr = 16
	ControlTransparent ControlAttr = 0x10000
	ControlNoPrefix    ControlAttr = 0x20000
	ControlBitmapAttr  ControlAttr = 0x40000
	ControlIconAttr    ControlAttr = 0x80000
	ControlNoWrap      ControlAttr = 0x80000
)

// DialogBuilder configures one Dialog row plus its controls and (optionally) its
// schedule in InstallUISequence.
type DialogBuilder interface {
	WithTitle(title string) DialogBuilder
	WithSize(width, height int16) DialogBuilder
	WithPosition(hCentering, vCentering int16) DialogBuilder
	Modal() DialogBuilder
	AsError() DialogBuilder
	WithAttributes(attrs ...DialogAttr) DialogBuilder
	WithFirstControl(id string) DialogBuilder
	WithDefaultControl(id string) DialogBuilder
	WithCancelControl(id string) DialogBuilder
	// ScheduleInUI schedules this dialog in InstallUISequence at sequence (with
	// an optional condition). Spawned/navigated dialogs need no schedule.
	ScheduleInUI(sequence int16, condition string) DialogBuilder
	Control(id string, t ControlType) ControlBuilder
	Done() PackageBuilder
}

// ControlBuilder configures one Control row plus its events, conditions, event
// mappings, and list/radio entries.
type ControlBuilder interface {
	At(x, y int16) ControlBuilder
	Size(width, height int16) ControlBuilder
	WithText(text string) ControlBuilder
	WithProperty(property string) ControlBuilder
	WithAttributes(attrs ...ControlAttr) ControlBuilder
	TabNext(controlID string) ControlBuilder
	WithHelp(help string) ControlBuilder
	// OnEvent adds a ControlEvent row (condition "" = always).
	OnEvent(event, argument, condition string) ControlBuilder
	// WithControlCondition adds a ControlCondition row (action: Show/Hide/Enable/Disable/Default).
	WithControlCondition(action, condition string) ControlBuilder
	// Subscribe adds an EventMapping row (the control updates Attribute on Event).
	Subscribe(event, attribute string) ControlBuilder
	// AddListItem adds a ListBox/ComboBox/ListView entry (routed by control type).
	AddListItem(value, text string) ControlBuilder
	// AddRadioButton adds a RadioButton entry (for a RadioButtonGroup control).
	AddRadioButton(value, text string, x, y, width, height int16) ControlBuilder
	// EndControl returns to the parent DialogBuilder.
	EndControl() DialogBuilder
}

// ----- model -----

type dialogEntry struct {
	id                                          string
	hCentering, vCentering, width, height       int16
	attributes                                  int32
	title                                       string
	controlFirst, controlDefault, controlCancel string
	controls                                    []controlEntry
	hasSequence                                 bool
	sequence                                    int16
	condition                                   string
}

type controlEntry struct {
	id          string
	typ         string
	x, y        int16
	width       int16
	height      int16
	attributes  int32
	property    string
	text        string
	controlNext string
	help        string
	events      []controlEventEntry
	conditions  []controlConditionEntry
	mappings    []eventMappingEntry
	listItems   []uiListItem
	radios      []uiRadioButton
}

type controlEventEntry struct {
	event, argument, condition string
}
type controlConditionEntry struct {
	action, condition string
}
type eventMappingEntry struct {
	event, attribute string
}
type uiListItem struct {
	value, text string
}
type uiRadioButton struct {
	value, text         string
	x, y, width, height int16
}

// ----- PackageBuilder.Dialog -----

func (p *msiPackage) Dialog(id string) DialogBuilder {
	p.dialogEntries = append(p.dialogEntries, dialogEntry{
		id:         id,
		width:      370,
		height:     270,
		hCentering: 50,
		vCentering: 50,
		attributes: int32(DialogVisible | DialogModal),
	})
	return &dialogHandle{pkg: p, idx: len(p.dialogEntries) - 1}
}

type dialogHandle struct {
	pkg *msiPackage
	idx int
}

func (h *dialogHandle) entry() *dialogEntry { return &h.pkg.dialogEntries[h.idx] }

func (h *dialogHandle) WithTitle(title string) DialogBuilder { h.entry().title = title; return h }
func (h *dialogHandle) WithSize(w, hh int16) DialogBuilder {
	h.entry().width = w
	h.entry().height = hh
	return h
}
func (h *dialogHandle) WithPosition(hc, vc int16) DialogBuilder {
	h.entry().hCentering = hc
	h.entry().vCentering = vc
	return h
}
func (h *dialogHandle) Modal() DialogBuilder {
	h.entry().attributes |= int32(DialogModal)
	return h
}
func (h *dialogHandle) AsError() DialogBuilder {
	h.entry().attributes |= int32(DialogError)
	return h
}
func (h *dialogHandle) WithAttributes(attrs ...DialogAttr) DialogBuilder {
	var v int32
	for _, a := range attrs {
		v |= int32(a)
	}
	h.entry().attributes = v
	return h
}
func (h *dialogHandle) WithFirstControl(id string) DialogBuilder {
	h.entry().controlFirst = id
	return h
}
func (h *dialogHandle) WithDefaultControl(id string) DialogBuilder {
	h.entry().controlDefault = id
	return h
}
func (h *dialogHandle) WithCancelControl(id string) DialogBuilder {
	h.entry().controlCancel = id
	return h
}
func (h *dialogHandle) ScheduleInUI(sequence int16, condition string) DialogBuilder {
	e := h.entry()
	e.hasSequence = true
	e.sequence = sequence
	e.condition = condition
	return h
}
func (h *dialogHandle) Control(id string, t ControlType) ControlBuilder {
	e := h.entry()
	e.controls = append(e.controls, controlEntry{
		id:         id,
		typ:        string(t),
		attributes: int32(ControlVisible | ControlEnabled),
	})
	if e.controlFirst == "" {
		e.controlFirst = id // first declared control starts tab order by default
	}
	return &controlHandle{pkg: h.pkg, didx: h.idx, cidx: len(e.controls) - 1}
}
func (h *dialogHandle) Done() PackageBuilder { return h.pkg }

type controlHandle struct {
	pkg  *msiPackage
	didx int
	cidx int
}

func (h *controlHandle) entry() *controlEntry {
	return &h.pkg.dialogEntries[h.didx].controls[h.cidx]
}

func (h *controlHandle) At(x, y int16) ControlBuilder {
	h.entry().x = x
	h.entry().y = y
	return h
}
func (h *controlHandle) Size(w, hh int16) ControlBuilder {
	h.entry().width = w
	h.entry().height = hh
	return h
}
func (h *controlHandle) WithText(text string) ControlBuilder { h.entry().text = text; return h }
func (h *controlHandle) WithProperty(property string) ControlBuilder {
	h.entry().property = property
	return h
}
func (h *controlHandle) WithAttributes(attrs ...ControlAttr) ControlBuilder {
	var v int32
	for _, a := range attrs {
		v |= int32(a)
	}
	h.entry().attributes = v
	return h
}
func (h *controlHandle) TabNext(controlID string) ControlBuilder {
	h.entry().controlNext = controlID
	return h
}
func (h *controlHandle) WithHelp(help string) ControlBuilder { h.entry().help = help; return h }
func (h *controlHandle) OnEvent(event, argument, condition string) ControlBuilder {
	h.entry().events = append(h.entry().events, controlEventEntry{event: event, argument: argument, condition: condition})
	return h
}
func (h *controlHandle) WithControlCondition(action, condition string) ControlBuilder {
	h.entry().conditions = append(h.entry().conditions, controlConditionEntry{action: action, condition: condition})
	return h
}
func (h *controlHandle) Subscribe(event, attribute string) ControlBuilder {
	h.entry().mappings = append(h.entry().mappings, eventMappingEntry{event: event, attribute: attribute})
	return h
}
func (h *controlHandle) AddListItem(value, text string) ControlBuilder {
	h.entry().listItems = append(h.entry().listItems, uiListItem{value: value, text: text})
	return h
}
func (h *controlHandle) AddRadioButton(value, text string, x, y, w, hh int16) ControlBuilder {
	h.entry().radios = append(h.entry().radios, uiRadioButton{value: value, text: text, x: x, y: y, width: w, height: hh})
	return h
}
func (h *controlHandle) EndControl() DialogBuilder {
	return &dialogHandle{pkg: h.pkg, idx: h.didx}
}

// ----- emission -----

// emitMSITextStyleAndUIText emits the TextStyle and UIText tables.
func emitMSITextStyleAndUIText(p *msiPackage, db msiDatabaseBuilder) error {
	if len(p.textStyleEntries) > 0 {
		tbl := createMSITableFromCatalog("TextStyle")
		for _, e := range p.textStyleEntries {
			var styleBits any
			if e.styleBits != 0 {
				styleBits = e.styleBits
			}
			row := newMSIRowBuilder().WithColumns(tbl.columns()...).WithValues(
				e.name, e.faceName, e.size, nullInt32(e.color), styleBits,
			).Build()
			if err := tbl.addRow(row); err != nil {
				return fmt.Errorf("msi compile: TextStyle row %s: %w", e.name, err)
			}
		}
		db.WithTable(tbl)
	}

	if len(p.uiTextEntries) > 0 {
		tbl := createMSITableFromCatalog("UIText")
		for _, e := range p.uiTextEntries {
			row := newMSIRowBuilder().WithColumns(tbl.columns()...).WithValues(e.key, e.text).Build()
			if err := tbl.addRow(row); err != nil {
				return fmt.Errorf("msi compile: UIText row %s: %w", e.key, err)
			}
		}
		db.WithTable(tbl)
	}
	return nil
}

// synthesizeMinimalUI expands the canned WixUI_Minimal model when WithMinimalUI
// was requested. Implemented in msi_ui_canned.go (P6.4); a no-op until then.
func synthesizeMinimalUI(p *msiPackage) {
	if !p.useMinimalUI {
		return
	}
	expandMinimalUI(p)
}

// emitMSIUITables emits the Dialog/Control/ControlEvent/ControlCondition/
// EventMapping tables plus the per-control list tables (ListBox/ComboBox/
// ListView/RadioButton), and schedules dialogs into InstallUISequence. List
// tables are emitted only when a control of the matching type contributes rows.
func emitMSIUITables(p *msiPackage, db msiDatabaseBuilder) error {
	if len(p.dialogEntries) == 0 {
		return nil
	}
	dlgTbl := createMSITableFromCatalog("Dialog")
	ctlTbl := createMSITableFromCatalog("Control")
	evTbl := createMSITableFromCatalog("ControlEvent")
	ccTbl := createMSITableFromCatalog("ControlCondition")
	emTbl := createMSITableFromCatalog("EventMapping")
	lbTbl := createMSITableFromCatalog("ListBox")
	cbTbl := createMSITableFromCatalog("ComboBox")
	lvTbl := createMSITableFromCatalog("ListView")
	rbTbl := createMSITableFromCatalog("RadioButton")
	var haveEv, haveCc, haveEm, haveLB, haveCB, haveLV, haveRB bool

	for _, d := range p.dialogEntries {
		drow := newMSIRowBuilder().WithColumns(dlgTbl.columns()...).WithValues(
			d.id, d.hCentering, d.vCentering, d.width, d.height, d.attributes,
			d.title, d.controlFirst, d.controlDefault, d.controlCancel,
		).Build()
		if err := dlgTbl.addRow(drow); err != nil {
			return fmt.Errorf("msi compile: Dialog row %s: %w", d.id, err)
		}

		for _, c := range d.controls {
			crow := newMSIRowBuilder().WithColumns(ctlTbl.columns()...).WithValues(
				d.id, c.id, c.typ, c.x, c.y, c.width, c.height, c.attributes,
				c.property, c.text, c.controlNext, c.help,
			).Build()
			if err := ctlTbl.addRow(crow); err != nil {
				return fmt.Errorf("msi compile: Control row %s/%s: %w", d.id, c.id, err)
			}

			for i, e := range c.events {
				erow := newMSIRowBuilder().WithColumns(evTbl.columns()...).WithValues(
					d.id, c.id, e.event, e.argument, e.condition, int16(i+1),
				).Build()
				if err := evTbl.addRow(erow); err != nil {
					return fmt.Errorf("msi compile: ControlEvent %s/%s/%s: %w", d.id, c.id, e.event, err)
				}
				haveEv = true
			}
			for _, cc := range c.conditions {
				row := newMSIRowBuilder().WithColumns(ccTbl.columns()...).WithValues(
					d.id, c.id, cc.action, cc.condition,
				).Build()
				if err := ccTbl.addRow(row); err != nil {
					return fmt.Errorf("msi compile: ControlCondition %s/%s: %w", d.id, c.id, err)
				}
				haveCc = true
			}
			for _, m := range c.mappings {
				row := newMSIRowBuilder().WithColumns(emTbl.columns()...).WithValues(
					d.id, c.id, m.event, m.attribute,
				).Build()
				if err := emTbl.addRow(row); err != nil {
					return fmt.Errorf("msi compile: EventMapping %s/%s: %w", d.id, c.id, err)
				}
				haveEm = true
			}

			for i, li := range c.listItems {
				order := int16(i + 1)
				switch c.typ {
				case string(ControlListBox):
					row := newMSIRowBuilder().WithColumns(lbTbl.columns()...).WithValues(c.property, order, li.value, li.text).Build()
					if err := lbTbl.addRow(row); err != nil {
						return fmt.Errorf("msi compile: ListBox %s: %w", c.property, err)
					}
					haveLB = true
				case string(ControlComboBox):
					row := newMSIRowBuilder().WithColumns(cbTbl.columns()...).WithValues(c.property, order, li.value, li.text).Build()
					if err := cbTbl.addRow(row); err != nil {
						return fmt.Errorf("msi compile: ComboBox %s: %w", c.property, err)
					}
					haveCB = true
				case string(ControlListView):
					row := newMSIRowBuilder().WithColumns(lvTbl.columns()...).WithValues(c.property, order, li.value, li.text, nil).Build()
					if err := lvTbl.addRow(row); err != nil {
						return fmt.Errorf("msi compile: ListView %s: %w", c.property, err)
					}
					haveLV = true
				}
			}
			for i, rb := range c.radios {
				row := newMSIRowBuilder().WithColumns(rbTbl.columns()...).WithValues(
					c.property, int16(i+1), rb.value, rb.x, rb.y, rb.width, rb.height, rb.text, "",
				).Build()
				if err := rbTbl.addRow(row); err != nil {
					return fmt.Errorf("msi compile: RadioButton %s: %w", c.property, err)
				}
				haveRB = true
			}
		}

		if d.hasSequence {
			var cond any
			if d.condition != "" {
				cond = d.condition
			}
			db.WithSequenceAction(msiInstallUISeqTableName, d.id, cond, d.sequence)
		}
	}

	db.WithTable(dlgTbl)
	db.WithTable(ctlTbl)
	if haveEv {
		db.WithTable(evTbl)
	}
	if haveCc {
		db.WithTable(ccTbl)
	}
	if haveEm {
		db.WithTable(emTbl)
	}
	if haveLB {
		db.WithTable(lbTbl)
	}
	if haveCB {
		db.WithTable(cbTbl)
	}
	if haveLV {
		db.WithTable(lvTbl)
	}
	if haveRB {
		db.WithTable(rbTbl)
	}
	return nil
}
