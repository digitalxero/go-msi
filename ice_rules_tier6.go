package msi

import (
	"fmt"
	"strconv"
	"strings"
)

// msi_ice_rules_tier6.go — P11 ICE closure. Real, golden-tested rules that close
// the gap for tables go-msix emits, plus dedicated rules for the never-emitted
// advertising/assembly/merge-module tables (P11.6). Generic category + foreign
// key validation for every cataloged table is already handled by ICE03; the
// rules here are the checks ICE03 cannot express. None fire on a well-formed
// go-msix package (guarded by the build-time WithAllICEs meta-test).

func registerTier6Rules() []iceRule {
	return []iceRule{
		// Emitted-table closers (P11.5).
		{id: "ICE08", fn: runICE08, tables: []string{"Component"}},
		{id: "ICE09", fn: runICE09, tables: []string{"Component"}},
		{id: "ICE16", fn: runICE16, tables: []string{"Property"}},
		{id: "ICE21", fn: runICE21, tables: []string{"Component", "FeatureComponents"}},
		{id: "ICE24", fn: runICE24, tables: []string{"Property"}},
		{id: "ICE45", fn: runICE45, tables: []string{"Component", "File"}},
		{id: "ICE74", fn: runICE74, tables: []string{"Upgrade", "Property"}},
		// Dedicated never-emitted-table ICEs (P11.6).
		{id: "ICE33", fn: runICE33, tables: []string{"Registry"}},
		{id: "ICE83", fn: runICE83, tables: []string{"MsiAssembly"}},
	}
}

var tier6Rules = registerTier6Rules()

// --- ICE08: duplicate ComponentId GUIDs in the Component table ---

func runICE08(ctx *iceContext) []Finding {
	var findings []Finding
	seen := map[string]string{} // guid -> first component
	for _, r := range ctx.rowsOf("Component") {
		v := r.values()
		if len(v) < 2 {
			continue
		}
		comp, _ := v[0].(string)
		guid, ok := v[1].(string)
		if !ok || guid == "" {
			continue // null ComponentId is an ICE92 concern, not ICE08
		}
		if first, dup := seen[guid]; dup {
			findings = append(findings, &msiFinding{
				ice: "ICE08", sev: SeverityError, table: "Component", column: "ComponentId", rowKeys: rowPKs(r),
				message: fmt.Sprintf("duplicate ComponentId %s shared by components %q and %q", guid, first, comp),
			})
			continue
		}
		seen[guid] = comp
	}
	return findings
}

// --- ICE09: components installed to a system directory should be permanent ---

const msidbComponentAttributesPermanent int16 = 0x10

var msiSystemDirectories = map[string]bool{
	"SystemFolder": true, "System64Folder": true, "WindowsFolder": true,
	"FontsFolder": true, "System16Folder": true,
}

func runICE09(ctx *iceContext) []Finding {
	var findings []Finding
	for _, r := range ctx.rowsOf("Component") {
		v := r.values()
		if len(v) < 4 {
			continue
		}
		dir, _ := v[2].(string)
		if !msiSystemDirectories[dir] {
			continue
		}
		if iceInt16(v[3])&msidbComponentAttributesPermanent == 0 {
			comp, _ := v[0].(string)
			findings = append(findings, &msiFinding{
				ice: "ICE09", sev: SeverityWarning, table: "Component", column: "Attributes", rowKeys: rowPKs(r),
				message: fmt.Sprintf("component %q installs to the system directory %q but is not marked Permanent", comp, dir),
			})
		}
	}
	return findings
}

// --- ICE16: ProductName must be at most 63 characters ---

func runICE16(ctx *iceContext) []Finding {
	name := icePropertyValue(ctx, "ProductName")
	if len(name) > 63 {
		return []Finding{&msiFinding{
			ice: "ICE16", sev: SeverityError, table: "Property", column: "Value",
			message: fmt.Sprintf("ProductName is %d characters; the maximum is 63", len(name)),
		}}
	}
	return nil
}

// --- ICE21: every Component must be referenced by FeatureComponents ---

func runICE21(ctx *iceContext) []Finding {
	components := ctx.rowsOf("Component")
	if len(components) == 0 {
		return nil
	}
	referenced := map[string]bool{}
	for _, r := range ctx.rowsOf("FeatureComponents") {
		v := r.values()
		if len(v) >= 2 {
			if c, ok := v[1].(string); ok {
				referenced[c] = true
			}
		}
	}
	var findings []Finding
	for _, r := range components {
		v := r.values()
		comp, _ := v[0].(string)
		if comp != "" && !referenced[comp] {
			findings = append(findings, &msiFinding{
				ice: "ICE21", sev: SeverityError, table: "Component", column: "Component", rowKeys: rowPKs(r),
				message: fmt.Sprintf("component %q is not referenced by any feature (orphan Component)", comp),
			})
		}
	}
	return findings
}

// --- ICE24: product identity property formats ---

func runICE24(ctx *iceContext) []Finding {
	if len(ctx.rowsOf("Property")) == 0 {
		return nil
	}
	var findings []Finding
	add := func(prop, msg string) {
		findings = append(findings, &msiFinding{
			ice: "ICE24", sev: SeverityError, table: "Property", column: "Value",
			message: fmt.Sprintf("%s: %s", prop, msg),
		})
	}
	props := icePropertyMap(ctx)
	if pc, ok := props["ProductCode"]; ok && !msiGUIDPattern.MatchString(pc) {
		add("ProductCode", "must be a valid uppercase braced GUID")
	}
	if uc, ok := props["UpgradeCode"]; ok && uc != "" && !msiGUIDPattern.MatchString(uc) {
		add("UpgradeCode", "must be a valid uppercase braced GUID")
	}
	if pv, ok := props["ProductVersion"]; ok {
		if err := validateMSIVersionString(pv); err != nil {
			add("ProductVersion", err.Error())
		}
	}
	if pl, ok := props["ProductLanguage"]; ok && pl != "" {
		if _, err := strconv.Atoi(pl); err != nil {
			add("ProductLanguage", "must be a numeric language identifier")
		}
	}
	return findings
}

// --- ICE45: reserved Attributes bits must be zero ---

// Documented valid Attributes masks (Microsoft Learn). Bits outside the mask are
// reserved and must be zero.
const (
	iceComponentAttributesValid int16 = 0x1FFF // through msidbComponentAttributes64bit/...
	iceFileAttributesValid      int16 = 0x3E07 // ReadOnly|Hidden|System|Vital|Checksum|PatchAdded|Noncompressed|Compressed
)

func runICE45(ctx *iceContext) []Finding {
	var findings []Finding
	check := func(table, column string, idx int, valid int16) {
		for _, r := range ctx.rowsOf(table) {
			v := r.values()
			if idx >= len(v) {
				continue
			}
			attr := iceInt16(v[idx])
			if attr&^valid != 0 {
				findings = append(findings, &msiFinding{
					ice: "ICE45", sev: SeverityError, table: table, column: column, rowKeys: rowPKs(r),
					message: fmt.Sprintf("%s.%s = 0x%X sets reserved bits (valid mask 0x%X)", table, column, uint16(attr), uint16(valid)),
				})
			}
		}
	}
	check("Component", "Attributes", 3, iceComponentAttributesValid)
	check("File", "Attributes", 6, iceFileAttributesValid)
	return findings
}

// --- ICE74: Upgrade ActionProperty must be a secure public property ---

func runICE74(ctx *iceContext) []Finding {
	upgrades := ctx.rowsOf("Upgrade")
	if len(upgrades) == 0 {
		return nil
	}
	var findings []Finding
	secure := map[string]bool{}
	for _, p := range strings.Split(icePropertyValue(ctx, "SecureCustomProperties"), ";") {
		if p = strings.TrimSpace(p); p != "" {
			secure[p] = true
		}
	}
	for _, r := range upgrades {
		v := r.values()
		if len(v) < 7 {
			continue
		}
		ap, _ := v[6].(string)
		if ap == "" {
			continue
		}
		if ap != strings.ToUpper(ap) {
			findings = append(findings, &msiFinding{
				ice: "ICE74", sev: SeverityError, table: "Upgrade", column: "ActionProperty", rowKeys: rowPKs(r),
				message: fmt.Sprintf("Upgrade.ActionProperty %q must be an uppercase public property", ap),
			})
		} else if !secure[ap] {
			findings = append(findings, &msiFinding{
				ice: "ICE74", sev: SeverityError, table: "Upgrade", column: "ActionProperty", rowKeys: rowPKs(r),
				message: fmt.Sprintf("Upgrade.ActionProperty %q must be listed in SecureCustomProperties", ap),
			})
		}
	}
	return findings
}

// --- ICE33: advertising data belongs in the advertising tables, not Registry ---

// msiAdvertisingKeyPrefixes are HKCR sub-keys whose data should be authored in
// the Class/ProgId/Extension/Verb/MIME/TypeLib/AppId tables (so the data is
// advertised and repaired correctly) rather than written directly to Registry.
var msiAdvertisingKeyPrefixes = []string{
	"clsid\\", "appid\\", "typelib\\", "interface\\", "mime\\",
	"component categories\\",
}

func runICE33(ctx *iceContext) []Finding {
	var findings []Finding
	for _, r := range ctx.rowsOf("Registry") {
		v := r.values()
		if len(v) < 3 {
			continue
		}
		root := iceInt16(v[1])
		if root != 0 { // HKEY_CLASSES_ROOT only
			continue
		}
		key, _ := v[2].(string)
		lk := strings.ToLower(strings.TrimLeft(key, "\\"))
		flagged := strings.HasPrefix(lk, ".") // a file-extension key
		if !flagged {
			for _, p := range msiAdvertisingKeyPrefixes {
				if strings.HasPrefix(lk, p) {
					flagged = true
					break
				}
			}
		}
		if flagged {
			findings = append(findings, &msiFinding{
				ice: "ICE33", sev: SeverityWarning, table: "Registry", column: "Key", rowKeys: rowPKs(r),
				message: fmt.Sprintf("HKCR registry key %q stores advertising data that belongs in the Class/ProgId/Extension/Verb/MIME/TypeLib tables", key),
			})
		}
	}
	return findings
}

// --- ICE83: every assembly component must have MsiAssemblyName entries ---

func runICE83(ctx *iceContext) []Finding {
	assemblies := ctx.rowsOf("MsiAssembly")
	if len(assemblies) == 0 {
		return nil
	}
	named := map[string]bool{}
	for _, r := range ctx.rowsOf("MsiAssemblyName") {
		v := r.values()
		if len(v) >= 1 {
			if c, ok := v[0].(string); ok {
				named[c] = true
			}
		}
	}
	var findings []Finding
	for _, r := range assemblies {
		v := r.values()
		comp, _ := v[0].(string)
		if comp != "" && !named[comp] {
			findings = append(findings, &msiFinding{
				ice: "ICE83", sev: SeverityError, table: "MsiAssembly", column: "Component_", rowKeys: rowPKs(r),
				message: fmt.Sprintf("assembly component %q has no MsiAssemblyName entries (the strong name cannot be resolved)", comp),
			})
		}
	}
	return findings
}

// --- helpers ---

// icePropertyMap returns all Property rows as a name->value map.
func icePropertyMap(ctx *iceContext) map[string]string {
	m := map[string]string{}
	for _, r := range ctx.rowsOf("Property") {
		v := r.values()
		if len(v) >= 2 {
			if k, ok := v[0].(string); ok {
				s, _ := v[1].(string)
				m[k] = s
			}
		}
	}
	return m
}
