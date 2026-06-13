package msi

// msi_ui_canned.go — P6.4 canned minimal interactive UI (a WixUI_Minimal-style
// wizard: welcome + license acceptance, progress, and the terminal
// exit/error/cancel dialogs, with DefaultUIFont/TextStyle and stock UIText).
//
// HONESTY NOTE: this produces a STRUCTURALLY valid, ICE-clean, msiexec-loadable
// UI. Actual on-screen rendering and exact wizard flow are verified manually on
// Windows, not in CI (msitools cannot render dialogs). It is a "minimal
// interactive UI", not a byte-for-byte reproduction of WiX's WixUI_Minimal.

// WithMinimalUI installs the canned minimal interactive wizard. The expansion
// runs at compile time (so it sees the final product identity). Idempotent.
func (p *msiPackage) WithMinimalUI() PackageBuilder {
	p.useMinimalUI = true
	return p
}

// WithLicenseText overrides the license text shown by the canned UI's welcome
// dialog (default: a short placeholder).
func (p *msiPackage) WithLicenseText(text string) PackageBuilder {
	p.licenseText = text
	return p
}

const defaultMinimalLicenseText = "Please read the accompanying license agreement. By selecting \"I accept\" you agree to its terms."

// expandMinimalUI populates the package UI model with the canned wizard. Guarded
// so a second WriteMSI (which re-compiles) does not duplicate the rows.
func expandMinimalUI(p *msiPackage) {
	if p.minimalUIExpanded {
		return
	}
	p.minimalUIExpanded = true

	// Default font + text styles.
	if p.props == nil {
		p.props = map[string]string{}
	}
	if _, ok := p.props["DefaultUIFont"]; !ok {
		p.props["DefaultUIFont"] = "DlgFont"
	}
	p.textStyleEntries = append(p.textStyleEntries,
		textStyleEntry{name: "DlgFont", faceName: "Tahoma", size: 8},
		textStyleEntry{name: "DlgFontBold", faceName: "Tahoma", size: 8, styleBits: textStyleBold},
	)

	// Stock UI text used by EventMapping subscriptions.
	p.uiTextEntries = append(p.uiTextEntries,
		uiTextEntry{key: "bytes", text: "bytes"},
		uiTextEntry{key: "Cancel", text: "Cancel"},
	)

	license := p.licenseText
	if license == "" {
		license = defaultMinimalLicenseText
	}

	// --- WelcomeDlg: welcome + license acceptance ---
	welcome := dialogEntry{
		id: "WelcomeDlg", hCentering: 50, vCentering: 50, width: 370, height: 270,
		attributes:     int32(DialogVisible | DialogModal),
		title:          "[ProductName] Setup",
		controlFirst:   "Install",
		controlDefault: "Install",
		controlCancel:  "Cancel",
		hasSequence:    true, sequence: 1297,
		controls: []controlEntry{
			cText("Title", 15, 15, 340, 20, "{\\DlgFontBold}Welcome to the [ProductName] Setup"),
			cText("License", 15, 45, 340, 150, license).withAttrs(ControlVisible, ControlSunken),
			cCheck("Accept", 15, 205, 340, 18, "AgreeToLicense", "I &accept the terms in the license agreement"),
			cButton("Install", 236, 243, 56, 17, "&Install").
				withEvent("EndDialog", "Return", "AgreeToLicense = \"1\""),
			cButton("Cancel", 304, 243, 56, 17, "Cancel").
				withEvent("EndDialog", "Exit", ""),
		},
	}

	// --- ProgressDlg: progress bar + status, shown during ExecuteAction ---
	progress := dialogEntry{
		id: "ProgressDlg", hCentering: 50, vCentering: 50, width: 370, height: 270,
		attributes:     int32(DialogVisible | DialogModal | DialogTrackDiskSpace),
		title:          "[ProductName] Setup",
		controlFirst:   "Cancel",
		controlCancel:  "Cancel",
		controlDefault: "Cancel",
		hasSequence:    true, sequence: 1298,
		controls: []controlEntry{
			cText("Title", 20, 15, 330, 20, "{\\DlgFontBold}Installing [ProductName]"),
			cText("StatusText", 35, 100, 320, 20, "").withMapping("ActionText", "Text"),
			cProgress("ProgressBar", 35, 125, 300, 12).withMapping("SetProgress", "Progress"),
			cButton("Cancel", 304, 243, 56, 17, "Cancel").
				withEvent("EndDialog", "Exit", ""),
		},
	}

	// --- Terminal dialogs (spawned by the engine on exit/error/cancel) ---
	exit := dialogEntry{
		id: "ExitDialog", hCentering: 50, vCentering: 50, width: 370, height: 270,
		attributes:     int32(DialogVisible | DialogModal),
		title:          "[ProductName] Setup",
		controlFirst:   "Finish",
		controlDefault: "Finish",
		controlCancel:  "Finish",
		controls: []controlEntry{
			cText("Title", 15, 15, 340, 20, "{\\DlgFontBold}Completed the [ProductName] Setup"),
			cText("Description", 15, 50, 340, 40, "Click the Finish button to exit the Setup."),
			cButton("Finish", 236, 243, 56, 17, "&Finish").
				withEvent("EndDialog", "Return", ""),
		},
	}
	fatal := dialogEntry{
		id: "FatalError", hCentering: 50, vCentering: 50, width: 370, height: 270,
		attributes:     int32(DialogVisible | DialogModal | DialogError),
		title:          "[ProductName] Setup",
		controlFirst:   "Finish",
		controlDefault: "Finish",
		controlCancel:  "Finish",
		controls: []controlEntry{
			cText("Title", 15, 15, 340, 20, "{\\DlgFontBold}[ProductName] Setup ended prematurely"),
			cText("Description", 15, 50, 340, 40, "[ProductName] setup ended prematurely because of an error."),
			cButton("Finish", 236, 243, 56, 17, "&Finish").
				withEvent("EndDialog", "Exit", ""),
		},
	}
	userExit := dialogEntry{
		id: "UserExit", hCentering: 50, vCentering: 50, width: 370, height: 270,
		attributes:     int32(DialogVisible | DialogModal),
		title:          "[ProductName] Setup",
		controlFirst:   "Finish",
		controlDefault: "Finish",
		controlCancel:  "Finish",
		controls: []controlEntry{
			cText("Title", 15, 15, 340, 20, "{\\DlgFontBold}[ProductName] Setup was interrupted"),
			cText("Description", 15, 50, 340, 40, "[ProductName] setup was interrupted. No changes were made."),
			cButton("Finish", 236, 243, 56, 17, "&Finish").
				withEvent("EndDialog", "Exit", ""),
		},
	}

	p.dialogEntries = append(p.dialogEntries, welcome, progress, exit, fatal, userExit)
}

// ----- compact control constructors used by the canned UI -----

func cText(id string, x, y, w, h int16, text string) controlEntry {
	return controlEntry{id: id, typ: string(ControlText), x: x, y: y, width: w, height: h,
		attributes: int32(ControlVisible), text: text}
}

func cButton(id string, x, y, w, h int16, text string) controlEntry {
	return controlEntry{id: id, typ: string(ControlPushButton), x: x, y: y, width: w, height: h,
		attributes: int32(ControlVisible | ControlEnabled), text: text}
}

func cCheck(id string, x, y, w, h int16, property, text string) controlEntry {
	return controlEntry{id: id, typ: string(ControlCheckBox), x: x, y: y, width: w, height: h,
		attributes: int32(ControlVisible | ControlEnabled), property: property, text: text}
}

func cProgress(id string, x, y, w, h int16) controlEntry {
	return controlEntry{id: id, typ: string(ControlProgressBar), x: x, y: y, width: w, height: h,
		attributes: int32(ControlVisible)}
}

func (c controlEntry) withAttrs(attrs ...ControlAttr) controlEntry {
	var v int32
	for _, a := range attrs {
		v |= int32(a)
	}
	c.attributes = v
	return c
}

func (c controlEntry) withEvent(event, argument, condition string) controlEntry {
	c.events = append(c.events, controlEventEntry{event: event, argument: argument, condition: condition})
	return c
}

func (c controlEntry) withMapping(event, attribute string) controlEntry {
	c.mappings = append(c.mappings, eventMappingEntry{event: event, attribute: attribute})
	return c
}
