package msi

import "fmt"

// msi_ice_rules_tier3.go — P5 custom-action ICE rules (ICE68, ICE72, ICE77).
// Real, golden-tested validations (no stubs):
//   ICE68 — CustomAction.Type base type is recognized; NoImpersonate without the
//           in-script (deferred) bit is ignored (warning).
//   ICE72 — AdvtExecuteSequence may only schedule custom actions of base type
//           19 (error), 35 (set directory), or 51 (set property).
//   ICE77 — deferred/rollback/commit (in-script) custom actions must be
//           sequenced strictly between InstallInitialize and InstallFinalize in
//           the Install/Admin execute sequences.

func registerTier3Rules() []iceRule {
	return []iceRule{
		{id: "ICE68", fn: runICE68, tables: []string{"CustomAction"}},
		{id: "ICE72", fn: runICE72, tables: []string{"CustomAction"}},
		{id: "ICE77", fn: runICE77, tables: []string{"CustomAction"}},
	}
}

var tier3Rules = registerTier3Rules()

// knownCustomActionBaseTypes is the set of recognized CustomAction base types
// (Type & 0x3F).
var knownCustomActionBaseTypes = map[int16]bool{
	1: true, 2: true, 5: true, 6: true, 7: true,
	17: true, 18: true, 19: true, 21: true, 22: true,
	34: true, 35: true, 37: true, 38: true,
	50: true, 51: true, 53: true, 54: true,
}

const (
	caBitInScript      int16 = 0x400
	caBitNoImpersonate int16 = 0x800
	caBaseMask         int16 = 0x3F
)

func runICE68(ctx *iceContext) []Finding {
	var findings []Finding
	for _, r := range ctx.rowsOf("CustomAction") {
		v := r.values()
		if len(v) < 2 {
			continue
		}
		typ := iceInt16(v[1])
		base := typ & caBaseMask
		if !knownCustomActionBaseTypes[base] {
			findings = append(findings, &msiFinding{
				ice: "ICE68", sev: SeverityError, table: "CustomAction", column: "Type", rowKeys: rowPKs(r),
				message: fmt.Sprintf("unrecognized custom action base type %d (Type %d)", base, typ),
			})
		}
		if typ&caBitNoImpersonate != 0 && typ&caBitInScript == 0 {
			findings = append(findings, &msiFinding{
				ice: "ICE68", sev: SeverityWarning, table: "CustomAction", column: "Type", rowKeys: rowPKs(r),
				message: "NoImpersonate is ignored on a non-deferred (immediate) custom action",
			})
		}
	}
	return findings
}

func runICE72(ctx *iceContext) []Finding {
	var findings []Finding
	types := customActionTypes(ctx)
	if len(types) == 0 {
		return nil
	}
	for _, r := range ctx.rowsOf(msiAdvtExecSeqTableName) {
		v := r.values()
		action, _ := v[0].(string)
		typ, ok := types[action]
		if !ok {
			continue // a standard action, not a custom action
		}
		base := typ & caBaseMask
		if base != 19 && base != 35 && base != 51 {
			findings = append(findings, &msiFinding{
				ice: "ICE72", sev: SeverityError, table: msiAdvtExecSeqTableName, column: "Action", rowKeys: rowPKs(r),
				message: fmt.Sprintf("custom action %q (base type %d) is not allowed in AdvtExecuteSequence (only types 19, 35, 51)", action, base),
			})
		}
	}
	return findings
}

func runICE77(ctx *iceContext) []Finding {
	var findings []Finding
	types := customActionTypes(ctx)
	if len(types) == 0 {
		return nil
	}
	for _, table := range []string{msiInstallExecSeqTableName, msiAdminExecSeqTableName} {
		initSeq, hasInit := iceSequenceOf(ctx, table, "InstallInitialize")
		finSeq, hasFin := iceSequenceOf(ctx, table, "InstallFinalize")
		for _, r := range ctx.rowsOf(table) {
			v := r.values()
			action, _ := v[0].(string)
			typ, isCA := types[action]
			if !isCA || typ&caBitInScript == 0 {
				continue // only in-script (deferred/rollback/commit) custom actions
			}
			seq := iceInt16(v[2])
			if !hasInit || !hasFin || seq <= initSeq || seq >= finSeq {
				findings = append(findings, &msiFinding{
					ice: "ICE77", sev: SeverityError, table: table, column: "Action", rowKeys: rowPKs(r),
					message: fmt.Sprintf("in-script custom action %q (seq %d) must be sequenced between InstallInitialize and InstallFinalize", action, seq),
				})
			}
		}
	}
	return findings
}

// customActionTypes maps each CustomAction.Action to its Type cell.
func customActionTypes(ctx *iceContext) map[string]int16 {
	m := map[string]int16{}
	for _, r := range ctx.rowsOf("CustomAction") {
		v := r.values()
		if len(v) >= 2 {
			if name, ok := v[0].(string); ok {
				m[name] = iceInt16(v[1])
			}
		}
	}
	return m
}

// iceInt16 reads an int16/int32 cell as int16 (0 for other types).
func iceInt16(v any) int16 {
	switch x := v.(type) {
	case int16:
		return x
	case int32:
		return int16(x)
	}
	return 0
}
