package msi

// msi_p6_roundtrip_internal_test.go
// White-box round-trip CONTENT tests for P6 UI tables.

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompileP6_CustomDialog(t *testing.T) {
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("P6 Dialog").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		WithSkipValidation() // UI ICEs land in P6.5; skip until then

	dlg := b.Dialog("MyDlg").WithTitle("Hello").WithSize(370, 270)
	dlg.Control("Title", ControlText).At(20, 15).Size(330, 20).WithText("Welcome").
		WithAttributes(ControlVisible, ControlTransparent).
		EndControl()
	dlg.Control("AcceptCheck", ControlCheckBox).At(20, 100).Size(330, 18).
		WithProperty("ACCEPTED").WithText("I accept").
		EndControl()
	dlg.Control("Choice", ControlRadioButtonGroup).At(20, 130).Size(330, 50).
		WithProperty("CHOICE").
		AddRadioButton("typical", "Typical", 0, 0, 100, 18).
		AddRadioButton("custom", "Custom", 0, 20, 100, 18).
		EndControl()
	dlg.Control("Install", ControlPushButton).At(290, 240).Size(60, 20).
		WithText("Install").
		OnEvent("EndDialog", "Return", "").
		EndControl()
	dlg.WithDefaultControl("Install").WithCancelControl("Install").
		ScheduleInUI(1298, "")

	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").WithFile("a.exe", []byte("MZ"))
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.NoError(t, readDB.validate())

	// Dialog row.
	dlgTbl, err := readDB.GetTable("Dialog")
	require.NoError(t, err)
	require.Len(t, dlgTbl.rows(), 1)
	dv := dlgTbl.rows()[0].values()
	assert.Equal(t, "MyDlg", dv[0])
	assert.Equal(t, int16(370), dv[3], "Width")
	assert.Equal(t, int32(3), dv[5], "Attributes Visible|Modal default")
	assert.Equal(t, "Hello", dv[6], "Title")
	assert.Equal(t, "Title", dv[7], "Control_First defaults to first control")
	assert.Equal(t, "Install", dv[8], "Control_Default")

	// Control rows: 4 controls.
	ctlTbl, err := readDB.GetTable("Control")
	require.NoError(t, err)
	require.Len(t, ctlTbl.rows(), 4)
	title := findRow(t, ctlTbl, 1, "Title")
	assert.Equal(t, "Text", title[2], "Type")
	assert.Equal(t, int32(int32(ControlVisible)|int32(ControlTransparent)), title[7], "transparent text attrs")
	assert.Equal(t, "Welcome", title[9], "Text")

	// ControlEvent for the Install button.
	evTbl, err := readDB.GetTable("ControlEvent")
	require.NoError(t, err)
	require.Len(t, evTbl.rows(), 1)
	ev := evTbl.rows()[0].values()
	assert.Equal(t, "Install", ev[1])
	assert.Equal(t, "EndDialog", ev[2])
	assert.Equal(t, "Return", ev[3])

	// RadioButton entries for CHOICE.
	rbTbl, err := readDB.GetTable("RadioButton")
	require.NoError(t, err)
	require.Len(t, rbTbl.rows(), 2)
	typ := findRow(t, rbTbl, 2, "typical")
	assert.Equal(t, "CHOICE", typ[0], "Property")
	assert.Equal(t, int16(1), typ[1], "Order")
	assert.Equal(t, "Typical", typ[7], "Text")

	// Dialog scheduled in InstallUISequence.
	assert.Equal(t, int16(1298), p5SeqOf(t, readDB, "InstallUISequence", "MyDlg"))
}

func TestCompileP6_MinimalUI(t *testing.T) {
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("P6 Minimal UI").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		WithMinimalUI().
		WithLicenseText("My EULA text.")

	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").WithFile("a.exe", []byte("MZ"))
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err, "canned minimal UI must validate clean under default ICEs")
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.NoError(t, readDB.validate())

	// The five canned dialogs.
	dlgTbl, err := readDB.GetTable("Dialog")
	require.NoError(t, err)
	got := map[string]bool{}
	for _, r := range dlgTbl.rows() {
		got[r.values()[0].(string)] = true
	}
	for _, id := range []string{"WelcomeDlg", "ProgressDlg", "ExitDialog", "FatalError", "UserExit"} {
		assert.True(t, got[id], "canned dialog %s present", id)
	}

	// License text propagated into WelcomeDlg's License control.
	ctlTbl, err := readDB.GetTable("Control")
	require.NoError(t, err)
	lic := findRow(t, ctlTbl, 1, "License")
	assert.Equal(t, "My EULA text.", lic[9], "WithLicenseText override")

	// WelcomeDlg + ProgressDlg scheduled in InstallUISequence.
	assert.Equal(t, int16(1297), p5SeqOf(t, readDB, "InstallUISequence", "WelcomeDlg"))
	assert.Equal(t, int16(1298), p5SeqOf(t, readDB, "InstallUISequence", "ProgressDlg"))

	// DefaultUIFont property + TextStyle present.
	propTbl, err := readDB.GetTable("Property")
	require.NoError(t, err)
	font := findRow(t, propTbl, 0, "DefaultUIFont")
	assert.Equal(t, "DlgFont", font[1])
	tsTbl, err := readDB.GetTable("TextStyle")
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(tsTbl.rows()), 2)

	// EventMapping for the progress bar / status text.
	emTbl, err := readDB.GetTable("EventMapping")
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(emTbl.rows()), 2)
}

func TestCompileP6_DoubleWriteNoDuplication(t *testing.T) {
	// A second WriteMSI on the same package must not duplicate compile-time
	// synthesized rows (canned UI dialogs, MajorUpgrade rows).
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithUpgradeCode("{ABCDEF01-2345-6789-ABCD-EF0123456789}").
		WithProductName("P6 Double").
		WithManufacturer("go-msix").
		WithVersion("2.0.0").
		WithMinimalUI().
		MajorUpgrade().Done()
	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").WithFile("a.exe", []byte("MZ"))
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)

	var buf1, buf2 bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf1))
	require.NoError(t, pkg.WriteMSI(&buf2))

	db2, err := readMSIDatabase(bytes.NewReader(buf2.Bytes()))
	require.NoError(t, err)
	dlgTbl, err := db2.GetTable("Dialog")
	require.NoError(t, err)
	assert.Len(t, dlgTbl.rows(), 5, "second WriteMSI must not duplicate canned dialogs")
	upTbl, err := db2.GetTable("Upgrade")
	require.NoError(t, err)
	assert.Len(t, upTbl.rows(), 2, "second WriteMSI must not duplicate MajorUpgrade rows")

	// Both writes produce byte-identical output.
	assert.True(t, bytes.Equal(buf1.Bytes(), buf2.Bytes()), "repeated WriteMSI must be deterministic")
}

// p6UIPackage builds a package with one scheduled dialog, returning the
// read-back database. configure mutates the dialog before build.
func p6UIPackage(t *testing.T, configure func(d DialogBuilder)) msiDatabase {
	t.Helper()
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("P6 ICE").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		WithSkipValidation()
	d := b.Dialog("D").WithSize(370, 270).ScheduleInUI(1297, "")
	configure(d)
	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").WithFile("a.exe", []byte("MZ"))
	b.Feature("F").WithLevel(1)
	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	return readDB
}

func TestICE17_InvalidTypeAndEmptyList_Golden(t *testing.T) {
	// Unrecognized control type -> ICE17 error.
	bad := p6UIPackage(t, func(d DialogBuilder) {
		d.Control("X", ControlType("Frobnicate")).At(1, 1).Size(10, 10).EndControl()
	})
	errs := iceFindingsFor(bad, msiSummaryInfo{}, "ICE17")
	require.NotEmpty(t, errs)
	assert.Equal(t, SeverityError, errs[0].Severity())

	// RadioButtonGroup with no radio entries -> ICE17 error.
	empty := p6UIPackage(t, func(d DialogBuilder) {
		d.Control("RBG", ControlRadioButtonGroup).At(1, 1).Size(100, 50).WithProperty("CHOICE").EndControl()
	})
	assert.NotEmpty(t, iceFindingsFor(empty, msiSummaryInfo{}, "ICE17"))

	// A valid Text control -> no ICE17 finding.
	good := p6UIPackage(t, func(d DialogBuilder) {
		d.Control("T", ControlText).At(1, 1).Size(100, 20).WithText("hi").EndControl()
	})
	assert.Empty(t, iceFindingsFor(good, msiSummaryInfo{}, "ICE17"))
}

func TestICE17_DanglingTabOrder_Golden(t *testing.T) {
	bad := p6UIPackage(t, func(d DialogBuilder) {
		d.Control("A", ControlPushButton).At(1, 1).Size(50, 20).WithText("A").TabNext("Nope").EndControl()
	})
	errs := iceFindingsFor(bad, msiSummaryInfo{}, "ICE17")
	require.NotEmpty(t, errs)
	found := false
	for _, f := range errs {
		if f.Column() == "Control_Next" {
			found = true
		}
	}
	assert.True(t, found, "dangling Control_Next must trip ICE17")
}

func TestICE27_BadDialogAndAction_Golden(t *testing.T) {
	// NewDialog to a non-existent dialog -> ICE27 error.
	bad := p6UIPackage(t, func(d DialogBuilder) {
		d.Control("B", ControlPushButton).At(1, 1).Size(50, 20).WithText("Go").
			OnEvent("NewDialog", "GhostDlg", "").EndControl()
	})
	errs := iceFindingsFor(bad, msiSummaryInfo{}, "ICE27")
	require.NotEmpty(t, errs)
	assert.Equal(t, SeverityError, errs[0].Severity())

	// EndDialog Return is fine -> no ICE27.
	good := p6UIPackage(t, func(d DialogBuilder) {
		d.Control("B", ControlPushButton).At(1, 1).Size(50, 20).WithText("OK").
			OnEvent("EndDialog", "Return", "").EndControl()
	})
	assert.Empty(t, iceFindingsFor(good, msiSummaryInfo{}, "ICE27"))
}

func TestICE34_OrphanRadioGroup_Golden(t *testing.T) {
	// RadioButton rows whose property has no RadioButtonGroup control (the radios
	// were attached to a Text control) -> ICE34 error.
	bad := p6UIPackage(t, func(d DialogBuilder) {
		d.Control("T", ControlText).At(1, 1).Size(100, 50).WithProperty("CHOICE").
			AddRadioButton("a", "A", 0, 0, 50, 18).EndControl()
	})
	errs := iceFindingsFor(bad, msiSummaryInfo{}, "ICE34")
	require.NotEmpty(t, errs)
	assert.Equal(t, SeverityError, errs[0].Severity())

	// Proper RadioButtonGroup control -> clean.
	good := p6UIPackage(t, func(d DialogBuilder) {
		d.Control("RBG", ControlRadioButtonGroup).At(1, 1).Size(100, 50).WithProperty("CHOICE").
			AddRadioButton("a", "A", 0, 0, 50, 18).EndControl()
	})
	assert.Empty(t, iceFindingsFor(good, msiSummaryInfo{}, "ICE34"))
}

func TestCompileP6_CustomDialogIsICEClean(t *testing.T) {
	// The hand-authored dialog from TestCompileP6_CustomDialog, but WITHOUT
	// WithSkipValidation: it must validate clean under the full ICE set.
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("P6 Clean Dialog").
		WithManufacturer("go-msix").
		WithVersion("1.0.0")
	dlg := b.Dialog("MyDlg").WithTitle("Hello").WithSize(370, 270)
	dlg.Control("Title", ControlText).At(20, 15).Size(330, 20).WithText("Welcome").EndControl()
	dlg.Control("Choice", ControlRadioButtonGroup).At(20, 130).Size(330, 50).WithProperty("CHOICE").
		AddRadioButton("typical", "Typical", 0, 0, 100, 18).EndControl()
	dlg.Control("Install", ControlPushButton).At(290, 240).Size(60, 20).WithText("Install").
		OnEvent("EndDialog", "Return", "").EndControl()
	dlg.WithDefaultControl("Install").WithCancelControl("Install").ScheduleInUI(1298, "")
	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").WithFile("a.exe", []byte("MZ"))
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err, "well-formed custom dialog must be ICE-clean")
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
}

func TestCompileP6_TextStyleAndUIText(t *testing.T) {
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("P6 Text").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		UIText("bytes", "[1] bytes")

	b.TextStyle("DlgFont", "Tahoma", 8).Done()
	b.TextStyle("TitleFont", "Tahoma", 9).Bold().WithColor(0, 0, 128).Done()

	b.RootDirectory("INSTALLFOLDER", "App").
		Component("Main").AssociateToFeature("F").WithFile("a.exe", []byte("MZ"))
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	readDB, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.NoError(t, readDB.validate())

	tsTbl, err := readDB.GetTable("TextStyle")
	require.NoError(t, err)
	require.Len(t, tsTbl.rows(), 2)
	// Columns: [TextStyle, FaceName, Size, Color, StyleBits].
	dlg := findRow(t, tsTbl, 0, "DlgFont")
	assert.Equal(t, "Tahoma", dlg[1])
	assert.Equal(t, int16(8), dlg[2])
	assert.Nil(t, dlg[3], "no color -> NULL")
	assert.Nil(t, dlg[4], "no style bits -> NULL")

	title := findRow(t, tsTbl, 0, "TitleFont")
	assert.Equal(t, int16(9), title[2])
	assert.Equal(t, int32(128<<16), title[3], "blue (b=128) -> 0x800000")
	assert.Equal(t, int16(1), title[4], "Bold style bit")

	uiTbl, err := readDB.GetTable("UIText")
	require.NoError(t, err)
	require.Len(t, uiTbl.rows(), 1)
	assert.Equal(t, "bytes", uiTbl.rows()[0].values()[0])
	assert.Equal(t, "[1] bytes", uiTbl.rows()[0].values()[1])
}
