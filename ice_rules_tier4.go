package msi

import "fmt"

// msi_ice_rules_tier4.go — P6 UI ICE rules (ICE17, ICE27, ICE34).
//   ICE17 — Control.Type is a recognized control type; list/radio controls have
//           matching entries; Control_Next (tab order) references an existing
//           control in the same dialog.
//   ICE27 — ControlEvent NewDialog/SpawnDialog arguments reference existing
//           dialogs; DoAction references an existing custom or standard action.
//   ICE34 — every RadioButton group Property is backed by a RadioButtonGroup
//           control.

func registerTier4Rules() []iceRule {
	return []iceRule{
		{id: "ICE17", fn: runICE17, tables: []string{"Control"}},
		{id: "ICE27", fn: runICE27, tables: []string{"ControlEvent"}},
		{id: "ICE34", fn: runICE34, tables: []string{"RadioButton"}},
	}
}

var tier4Rules = registerTier4Rules()

// uiPropertySet returns the set of Property values (column 0) in a list table.
func uiPropertySet(ctx *iceContext, table string) map[string]bool {
	out := map[string]bool{}
	for _, r := range ctx.rowsOf(table) {
		if v := r.values(); len(v) > 0 {
			if p, ok := v[0].(string); ok {
				out[p] = true
			}
		}
	}
	return out
}

func runICE17(ctx *iceContext) []Finding {
	var findings []Finding

	radioProps := uiPropertySet(ctx, "RadioButton")
	listBoxProps := uiPropertySet(ctx, "ListBox")
	comboProps := uiPropertySet(ctx, "ComboBox")
	listViewProps := uiPropertySet(ctx, "ListView")

	// controls per dialog for tab-order checks.
	controlsByDialog := map[string]map[string]bool{}
	for _, r := range ctx.rowsOf("Control") {
		v := r.values()
		if len(v) < 2 {
			continue
		}
		dlg, _ := v[0].(string)
		ctl, _ := v[1].(string)
		if controlsByDialog[dlg] == nil {
			controlsByDialog[dlg] = map[string]bool{}
		}
		controlsByDialog[dlg][ctl] = true
	}

	for _, r := range ctx.rowsOf("Control") {
		v := r.values()
		if len(v) < 12 {
			continue
		}
		dlg, _ := v[0].(string)
		ctl, _ := v[1].(string)
		typ, _ := v[2].(string)
		prop, _ := v[8].(string)
		next, _ := v[10].(string)

		if !validControlTypes[typ] {
			findings = append(findings, &msiFinding{
				ice: "ICE17", sev: SeverityError, table: "Control", column: "Type", rowKeys: rowPKs(r),
				message: fmt.Sprintf("control %s/%s has unrecognized Type %q", dlg, ctl, typ),
			})
		}

		switch typ {
		case string(ControlRadioButtonGroup):
			if prop == "" || !radioProps[prop] {
				findings = append(findings, &msiFinding{
					ice: "ICE17", sev: SeverityError, table: "Control", column: "Property", rowKeys: rowPKs(r),
					message: fmt.Sprintf("RadioButtonGroup %s/%s has no RadioButton entries for property %q", dlg, ctl, prop),
				})
			}
		case string(ControlListBox):
			if prop == "" || !listBoxProps[prop] {
				findings = append(findings, &msiFinding{ice: "ICE17", sev: SeverityError, table: "Control", column: "Property", rowKeys: rowPKs(r), message: fmt.Sprintf("ListBox %s/%s has no ListBox entries for property %q", dlg, ctl, prop)})
			}
		case string(ControlComboBox):
			if prop == "" || !comboProps[prop] {
				findings = append(findings, &msiFinding{ice: "ICE17", sev: SeverityError, table: "Control", column: "Property", rowKeys: rowPKs(r), message: fmt.Sprintf("ComboBox %s/%s has no ComboBox entries for property %q", dlg, ctl, prop)})
			}
		case string(ControlListView):
			if prop == "" || !listViewProps[prop] {
				findings = append(findings, &msiFinding{ice: "ICE17", sev: SeverityError, table: "Control", column: "Property", rowKeys: rowPKs(r), message: fmt.Sprintf("ListView %s/%s has no ListView entries for property %q", dlg, ctl, prop)})
			}
		}

		if next != "" && !controlsByDialog[dlg][next] {
			findings = append(findings, &msiFinding{
				ice: "ICE17", sev: SeverityError, table: "Control", column: "Control_Next", rowKeys: rowPKs(r),
				message: fmt.Sprintf("control %s/%s tab order points to non-existent control %q", dlg, ctl, next),
			})
		}
	}
	return findings
}

func runICE27(ctx *iceContext) []Finding {
	var findings []Finding

	dialogs := map[string]bool{}
	for _, r := range ctx.rowsOf("Dialog") {
		if v := r.values(); len(v) > 0 {
			if d, ok := v[0].(string); ok {
				dialogs[d] = true
			}
		}
	}
	actions := iceAllActionNames(ctx)

	for _, r := range ctx.rowsOf("ControlEvent") {
		v := r.values()
		if len(v) < 4 {
			continue
		}
		event, _ := v[2].(string)
		arg, _ := v[3].(string)

		switch event {
		case "NewDialog", "SpawnDialog", "SpawnWaitDialog":
			if !dialogs[arg] {
				findings = append(findings, &msiFinding{
					ice: "ICE27", sev: SeverityError, table: "ControlEvent", column: "Argument", rowKeys: rowPKs(r),
					message: fmt.Sprintf("%s references non-existent dialog %q", event, arg),
				})
			}
		case "DoAction":
			if !actions[arg] {
				findings = append(findings, &msiFinding{
					ice: "ICE27", sev: SeverityError, table: "ControlEvent", column: "Argument", rowKeys: rowPKs(r),
					message: fmt.Sprintf("DoAction references unknown action %q (not a custom or scheduled action)", arg),
				})
			}
		}
	}
	return findings
}

func runICE34(ctx *iceContext) []Finding {
	var findings []Finding

	// Properties used by RadioButtonGroup controls.
	rbgProps := map[string]bool{}
	for _, r := range ctx.rowsOf("Control") {
		v := r.values()
		if len(v) >= 9 {
			if typ, _ := v[2].(string); typ == string(ControlRadioButtonGroup) {
				if prop, _ := v[8].(string); prop != "" {
					rbgProps[prop] = true
				}
			}
		}
	}

	checked := map[string]bool{}
	for _, r := range ctx.rowsOf("RadioButton") {
		v := r.values()
		if len(v) == 0 {
			continue
		}
		prop, _ := v[0].(string)
		if prop == "" || checked[prop] {
			continue
		}
		checked[prop] = true
		if !rbgProps[prop] {
			findings = append(findings, &msiFinding{
				ice: "ICE34", sev: SeverityError, table: "RadioButton", column: "Property", rowKeys: rowPKs(r),
				message: fmt.Sprintf("RadioButton group %q has no RadioButtonGroup control", prop),
			})
		}
	}
	return findings
}

// iceAllActionNames returns the set of action names known to the package: every
// CustomAction plus every action scheduled in any of the five sequence tables.
func iceAllActionNames(ctx *iceContext) map[string]bool {
	out := map[string]bool{}
	for name := range customActionTypes(ctx) {
		out[name] = true
	}
	for _, table := range []string{
		msiInstallExecSeqTableName, msiInstallUISeqTableName,
		msiAdminExecSeqTableName, msiAdminUISeqTableName, msiAdvtExecSeqTableName,
	} {
		for _, r := range ctx.rowsOf(table) {
			if v := r.values(); len(v) > 0 {
				if a, ok := v[0].(string); ok {
					out[a] = true
				}
			}
		}
	}
	return out
}
