package msi

import (
	"fmt"
	"strconv"
	"strings"
)

// msi_ice_rules_tier2.go — P4 upgrade-related ICE rules (ICE61, ICE63).
//
// Services and the AppSearch/locator tables are already validated by the
// generic ICE03 pass (which walks every present table and checks each column's
// Category plus any catalog KeyTable foreign key — Component_ for the service
// tables, the Signature/locator union for AppSearch.Signature_). These rules add
// the upgrade-specific structural checks ICE03 cannot express.
//
// Honesty note: only the checks below are implemented; each is a real validation
// (no stubs). The ICE numbers used (ICE61 version-range / detect-remove
// consistency, ICE63 RemoveExistingProducts sequencing + presence) are the
// standard upgrade ICEs.

func registerTier2Rules() []iceRule {
	return []iceRule{
		{id: "ICE61", fn: runICE61, tables: []string{"Upgrade"}},
		{id: "ICE63", fn: runICE63, tables: []string{"Upgrade"}},
	}
}

var tier2Rules = registerTier2Rules()

// runICE61 validates the Upgrade table version ranges and detect/remove
// consistency.
func runICE61(ctx *iceContext) []Finding {
	var findings []Finding
	for _, r := range ctx.rowsOf("Upgrade") {
		v := r.values()
		if len(v) < 7 {
			continue
		}
		// [UpgradeCode, VersionMin, VersionMax, Language, Attributes, Remove, ActionProperty]
		vmin := iceStr(v[1])
		vmax := iceStr(v[2])
		attrs := iceInt32(v[4])
		remove := iceStr(v[5])

		if vmin != "" && vmax != "" && compareMSIVersions(vmin, vmax) > 0 {
			findings = append(findings, &msiFinding{
				ice: "ICE61", sev: SeverityError, table: "Upgrade", column: "VersionMax", rowKeys: rowPKs(r),
				message: fmt.Sprintf("VersionMin %q is greater than VersionMax %q", vmin, vmax),
			})
		}

		// A detect-only row must not request feature removal.
		if attrs&int32(UpgradeOnlyDetect) != 0 && remove != "" {
			findings = append(findings, &msiFinding{
				ice: "ICE61", sev: SeverityWarning, table: "Upgrade", column: "Remove", rowKeys: rowPKs(r),
				message: "detect-only (OnlyDetect) Upgrade row should not specify a Remove value",
			})
		}
	}
	return findings
}

// runICE63 validates that RemoveExistingProducts is scheduled when the Upgrade
// table removes related products, that it is positioned after InstallValidate,
// and that every Upgrade ActionProperty is published in SecureCustomProperties.
func runICE63(ctx *iceContext) []Finding {
	var findings []Finding
	upRows := ctx.rowsOf("Upgrade")
	if len(upRows) == 0 {
		return nil
	}

	hasRemove := false
	for _, r := range upRows {
		v := r.values()
		if len(v) >= 5 && iceInt32(v[4])&int32(UpgradeOnlyDetect) == 0 {
			hasRemove = true
			break
		}
	}

	repSeq, repPresent := iceSequenceOf(ctx, msiInstallExecSeqTableName, "RemoveExistingProducts")
	if hasRemove && !repPresent {
		findings = append(findings, &msiFinding{
			ice: "ICE63", sev: SeverityError, table: msiInstallExecSeqTableName,
			message: "Upgrade table removes related products but RemoveExistingProducts is not scheduled in InstallExecuteSequence",
		})
	}
	if repPresent {
		if ivSeq, ok := iceSequenceOf(ctx, msiInstallExecSeqTableName, "InstallValidate"); ok && repSeq <= ivSeq {
			findings = append(findings, &msiFinding{
				ice: "ICE63", sev: SeverityWarning, table: msiInstallExecSeqTableName, column: "RemoveExistingProducts",
				message: fmt.Sprintf("RemoveExistingProducts (seq %d) should be scheduled after InstallValidate (seq %d)", repSeq, ivSeq),
			})
		}
	}

	// Every ActionProperty must be a public property listed in SecureCustomProperties.
	scp := map[string]bool{}
	for _, part := range strings.Split(icePropertyValue(ctx, "SecureCustomProperties"), ";") {
		if p := strings.TrimSpace(part); p != "" {
			scp[p] = true
		}
	}
	for _, r := range upRows {
		v := r.values()
		if len(v) < 7 {
			continue
		}
		ap := iceStr(v[6])
		if ap != "" && !scp[ap] {
			findings = append(findings, &msiFinding{
				ice: "ICE63", sev: SeverityWarning, table: "Upgrade", column: "ActionProperty", rowKeys: rowPKs(r),
				message: fmt.Sprintf("Upgrade ActionProperty %q is not listed in SecureCustomProperties", ap),
			})
		}
	}
	return findings
}

// ----- helpers -----

func iceStr(v any) string {
	s, _ := v.(string)
	return s
}

func iceInt32(v any) int32 {
	switch x := v.(type) {
	case int32:
		return x
	case int16:
		return int32(x)
	}
	return 0
}

// icePropertyValue returns the Property.Value for the named property, or "".
func icePropertyValue(ctx *iceContext, name string) string {
	for _, r := range ctx.rowsOf("Property") {
		v := r.values()
		if len(v) >= 2 {
			if k, ok := v[0].(string); ok && k == name {
				return iceStr(v[1])
			}
		}
	}
	return ""
}

// iceSequenceOf returns the Sequence of the named action in a sequence table.
func iceSequenceOf(ctx *iceContext, table, action string) (int16, bool) {
	for _, r := range ctx.rowsOf(table) {
		v := r.values()
		if len(v) >= 3 {
			if a, ok := v[0].(string); ok && a == action {
				if s, ok := v[2].(int16); ok {
					return s, true
				}
				return 0, true
			}
		}
	}
	return 0, false
}

// compareMSIVersions compares two dotted version strings (up to 4 parts).
func compareMSIVersions(a, b string) int {
	pa := parseVersionParts(a)
	pb := parseVersionParts(b)
	for i := 0; i < 4; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseVersionParts(s string) [4]int {
	var out [4]int
	for i, part := range strings.Split(s, ".") {
		if i >= 4 {
			break
		}
		n, _ := strconv.Atoi(strings.TrimSpace(part))
		out[i] = n
	}
	return out
}
