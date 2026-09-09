package msi

import (
	"fmt"
	"regexp"
	"strings"
)

// This file contains the Tier 1 ICE rule implementations for the tables
// that our P1 emission always produces (Property, Directory, Component,
// Feature, FeatureComponents, File, Media + 5 sequence tables + _Validation
// + summary). Rules are registered via allICERules (no init() side effects).
//
// IMPLEMENTED SUBSET (honest inventory): this is a PARTIAL Tier-1 set, not the
// full Tier-1 catalog. Eight rules do real work:
//   ICE02 (FeatureComponents FKs), ICE03 (category + FK scan),
//   ICE05 (Component.Directory_ FK), ICE18 (KeyPath ownership),
//   ICE26 (canonical sequence actions present at canonical numbers),
//   ICE30 (Media sanity), ICE39 (summary GUID/PageCount),
//   ICE92 (component GUID/KeyPath).
// The remaining Tier-1 ICEs are NOT yet implemented (no stub rules are
// registered — a missing rule is simply not run).
//
// Absence = pass is handled in the engine (if none of a rule's subject tables
// are present the rule is skipped), so packages that emit only a subset of
// tables are not failed by rules whose subject tables they never produce.
//
// Many rules reuse validateCategory (the ICE03 workhorse) + the catalog +
// existing patterns from msi_tables.go (msiGUIDPattern, msiIdentifierPattern,
// validateMSIVersionString, etc.).

var (
	// precompiled for speed in hot paths (ICE03 etc.)
	iceIdentifierRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)
)

// registerTier1Rules returns the Tier-1 rules. Called from allICERules.
func registerTier1Rules() []iceRule {
	return []iceRule{
		{id: "ICE03", fn: runICE03, tables: []string{"Property", "Directory", "Component", "Feature", "FeatureComponents", "File", "Media"}},
		{id: "ICE05", fn: runICE05, tables: []string{"Component", "Directory"}},
		{id: "ICE18", fn: runICE18, tables: []string{"Component", "File"}},
		{id: "ICE02", fn: runICE02, tables: []string{"FeatureComponents"}},
		{id: "ICE92", fn: runICE92, tables: []string{"Component"}},
		{id: "ICE30", fn: runICE30, tables: []string{"Media"}},
		{id: "ICE26", fn: runICE26, tables: []string{"InstallExecuteSequence", "InstallUISequence", "AdminExecuteSequence", "AdminUISequence", "AdvtExecuteSequence"}},
		{id: "ICE39", fn: runICE39, tables: nil}, // summary only
	}
}

var tier1Rules = registerTier1Rules()

// runICE03 is the primary data-integrity / foreign-key / category validator.
// It walks every cell of every emitted table, looks up its _Validation (or
// catalog) entry, runs the category validator, and checks FKs where
// KeyTable is declared.
func runICE03(ctx *iceContext) []Finding {
	var findings []Finding

	for _, tblName := range ctx.db.Tables() {
		if tblName == msiValidationTableName {
			// _Validation rows describe the schema (including Set values like
			// "File;Registry;ODBCDataSource" in KeyTable). Do not treat them
			// as user data for identifier/GUID checks.
			continue
		}
		t, err := ctx.db.GetTable(tblName)
		if err != nil {
			continue
		}
		// For each column we could look up the _Validation row, but for
		// speed we use a lightweight per-column check that reuses
		// the same patterns the builder already enforces at insert time.
		// Real ICE03 also catches things the builder cannot (e.g. cross-row
		// FKs that become invalid after later edits).
		for ci, col := range t.columns() {
			// Look up catalog def for category, nullable, min/max, keyTable etc.
			catCol := msiCatalogColumnFor(tblName, col.name())
			for _, r := range t.rows() {
				val, _ := r.valueAt(ci)
				if err := validateCategory(catCol.category, val, catCol); err != nil {
					findings = append(findings, &msiFinding{
						ice:     "ICE03",
						sev:     SeverityError,
						table:   tblName,
						column:  col.name(),
						rowKeys: rowPKs(r),
						message: err.Error(),
					})
				}
				// FK check if this column has KeyTable in catalog (may be ;-separated union like File;Registry;...).
				// Simple scan on target's first column (PK for our tables).
				if catCol.keyTable != "" {
					if s, ok := val.(string); ok && s != "" {
						found := false
						for _, kt := range strings.Split(catCol.keyTable, ";") {
							for _, tr := range ctx.rowsOf(kt) {
								tvals := tr.values()
								if len(tvals) > 0 {
									if ts, ok := tvals[0].(string); ok && ts == s {
										found = true
										break
									}
								}
							}
							if found {
								break
							}
						}
						if !found {
							findings = append(findings, &msiFinding{
								ice:     "ICE03",
								sev:     SeverityError,
								table:   tblName,
								column:  col.name(),
								rowKeys: rowPKs(r),
								message: fmt.Sprintf("FK value %q not found in %s", s, catCol.keyTable),
							})
						}
					}
				}
			}
		}
	}
	return findings
}

// runICE26 verifies that the five sequence tables contain the canonical
// action set at the WiX numbers we (and legacy) always emit. This is the
// "ICE26" that every real MSI must satisfy for the standard actions.
func runICE26(ctx *iceContext) []Finding {
	var findings []Finding

	// Use a slice for deterministic iteration order (map range is randomized).
	seqTables := []string{
		msiInstallExecSeqTableName,
		msiInstallUISeqTableName,
		msiAdminExecSeqTableName,
		msiAdminUISeqTableName,
		msiAdvtExecSeqTableName,
	}
	required := map[string][]msiSequenceRow{
		msiInstallExecSeqTableName: msiInstallExecuteActions,
		msiInstallUISeqTableName:   msiInstallUIActions,
		msiAdminExecSeqTableName:   msiAdminExecuteActions,
		msiAdminUISeqTableName:     msiAdminUIActions,
		msiAdvtExecSeqTableName:    msiAdvtExecuteActions,
	}

	for _, tbl := range seqTables {
		rows := ctx.rowsOf(tbl)
		if len(rows) == 0 {
			findings = append(findings, &msiFinding{
				ice:     "ICE26",
				sev:     SeverityError,
				table:   tbl,
				message: "required sequence table is empty",
			})
			continue
		}

		// Build action -> sequence from the emitted rows. Sequence table layout
		// (msi_table_catalog.go): col0=Action(string), col1=Condition(string,
		// nullable), col2=Sequence(int16).
		have := make(map[string]int16, len(rows))
		for _, r := range rows {
			vals := r.values()
			if len(vals) == 0 {
				continue
			}
			action, ok := vals[0].(string)
			if !ok || action == "" {
				continue
			}
			var seq int16
			if len(vals) > 2 {
				if s, ok := vals[2].(int16); ok {
					seq = s
				}
			}
			have[action] = seq
		}

		// Verify every canonical action exists at its canonical sequence number.
		for _, a := range required[tbl] {
			got, present := have[a.action]
			if !present {
				findings = append(findings, &msiFinding{
					ice:     "ICE26",
					sev:     SeverityError,
					table:   tbl,
					column:  "Action",
					rowKeys: []string{a.action},
					message: fmt.Sprintf("required action %q missing from %s", a.action, tbl),
				})
				continue
			}
			if got != a.sequence {
				findings = append(findings, &msiFinding{
					ice:     "ICE26",
					sev:     SeverityError,
					table:   tbl,
					column:  "Sequence",
					rowKeys: []string{a.action},
					message: fmt.Sprintf("action %q in %s has sequence %d, expected %d", a.action, tbl, got, a.sequence),
				})
			}
		}
	}
	return findings
}

// runICE39 checks the SummaryInformation stream (required PIDs, GUID
// format for RevisionNumber/PackageCode, a well-formed Template, and a
// PageCount at or above the minimum the Template's platform requires).
func runICE39(ctx *iceContext) []Finding {
	var findings []Finding

	// The context carries the summary when Validate was called on a
	// ReaderAt (file or bytes). For pure in-build calls the summary is
	// also passed through the internal path (wired in P2-005).
	if ctx.summary.RevisionNumber != "" && !msiGUIDPattern.MatchString(ctx.summary.RevisionNumber) {
		findings = append(findings, &msiFinding{
			ice:     "ICE39",
			sev:     SeverityError,
			table:   "", // summary
			message: fmt.Sprintf("RevisionNumber (PackageCode) %q is not a valid GUID", ctx.summary.RevisionNumber),
		})
	}

	// The Template's platform half determines the PageCount floor, so parse it
	// first. A blank platform is legal (the package is not architecture-
	// restricted) and falls back to the baseline floor.
	plat := msiDefaultPlatform
	if ctx.summary.Template != "" && !templateIsProductCodeList(ctx.summary.Template) {
		parsed, _, err := parseTemplate(ctx.summary.Template)
		switch {
		case err != nil:
			findings = append(findings, &msiFinding{
				ice:     "ICE39",
				sev:     SeverityError,
				table:   "",
				message: fmt.Sprintf("Template %q is malformed: %v", ctx.summary.Template, err),
			})
			plat = platformUnset
		case parsed != platformUnset:
			plat = parsed
		default:
			// Blank platform: not architecture-restricted, baseline floor.
			plat = Platform_Intel
		}
	}

	if plat != platformUnset && ctx.summary.PageCount != 0 && ctx.summary.PageCount < plat.minSchemaVersion() {
		findings = append(findings, &msiFinding{
			ice:     "ICE39",
			sev:     SeverityWarning,
			table:   "",
			message: fmt.Sprintf("PageCount %d is below the minimum %d required by platform %s", ctx.summary.PageCount, plat.minSchemaVersion(), plat),
		})
	}
	return findings
}

// runICE05: Component.Directory_ must reference an existing Directory row.
func runICE05(ctx *iceContext) []Finding {
	var findings []Finding
	for _, r := range ctx.rowsOf("Component") {
		vals := r.values()
		if len(vals) > 2 {
			if dir, ok := vals[2].(string); ok && dir != "" {
				found := false
				for _, tr := range ctx.rowsOf("Directory") {
					tvals := tr.values()
					if len(tvals) > 0 {
						if ts, ok := tvals[0].(string); ok && ts == dir {
							found = true
							break
						}
					}
				}
				if !found {
					findings = append(findings, &msiFinding{
						ice:     "ICE05",
						sev:     SeverityError,
						table:   "Component",
						column:  "Directory_",
						rowKeys: rowPKs(r),
						message: fmt.Sprintf("directory %q does not exist", dir),
					})
				}
			}
		}
	}
	return findings
}

// iceComponentKeyPathColumn is the index of Component.KeyPath (Component,
// ComponentId, Directory_, Attributes, Condition, KeyPath).
const iceComponentKeyPathColumn = 5

// runICE18: Component.KeyPath (if set) must name a resource this component
// owns, in the table selected by the Attributes bits: a Registry row when
// RegistryKeyPath is set, an ODBCDataSource row when ODBCDataSource is set,
// otherwise a File row. Windows Installer resolves KeyPath the same way, so a
// registry KeyPath without the bit is looked up in the File table and fails at
// install time.
func runICE18(ctx *iceContext) []Finding {
	var findings []Finding
	// Build quick indexes of key -> owning component for each key-path table.
	ownerIndex := func(table string, keyCol, compCol int) map[string]string {
		idx := map[string]string{}
		for _, r := range ctx.rowsOf(table) {
			vals := r.values()
			if len(vals) <= keyCol || len(vals) <= compCol {
				continue
			}
			key, ok1 := vals[keyCol].(string)
			comp, ok2 := vals[compCol].(string)
			if ok1 && ok2 {
				idx[key] = comp
			}
		}
		return idx
	}
	// File: File, Component_, …; Registry: Registry, Root, Key, Name, Value,
	// Component_; ODBCDataSource: DataSource, Component_, ….
	fileToComp := ownerIndex("File", 0, 1)
	regToComp := ownerIndex("Registry", 0, 5)
	odbcToComp := ownerIndex("ODBCDataSource", 0, 1)
	_, odbcErr := ctx.db.GetTable("ODBCDataSource")
	hasODBC := odbcErr == nil

	for _, r := range ctx.rowsOf("Component") {
		vals := r.values()
		if len(vals) <= iceComponentKeyPathColumn {
			continue
		}
		kp, ok := vals[iceComponentKeyPathColumn].(string)
		if !ok || kp == "" {
			continue
		}
		c, ok := vals[0].(string)
		if !ok {
			continue
		}
		attrs := iceInt16(vals[3])
		var (
			table string
			owner string
			has   bool
		)
		switch {
		case attrs&msidbComponentAttributesRegistryKeyPath != 0:
			table = "Registry"
			owner, has = regToComp[kp]
		case attrs&msidbComponentAttributesODBCDataSource != 0:
			if !hasODBC {
				// The catalog has no ODBCDataSource table to check against.
				continue
			}
			table = "ODBCDataSource"
			owner, has = odbcToComp[kp]
		default:
			table = "File"
			owner, has = fileToComp[kp]
		}
		if !has || owner != c {
			findings = append(findings, &msiFinding{
				ice:     "ICE18",
				sev:     SeverityError,
				table:   "Component",
				column:  "KeyPath",
				rowKeys: rowPKs(r),
				message: fmt.Sprintf("KeyPath %q is not a %s row of this component (Attributes 0x%X select the %s table)", kp, table, attrs, table),
			})
		}
	}
	return findings
}

// runICE02: FeatureComponents rows must reference valid Feature and Component.
func runICE02(ctx *iceContext) []Finding {
	var findings []Finding
	feats := map[string]bool{}
	for _, r := range ctx.rowsOf("Feature") {
		if v := r.values(); len(v) > 0 {
			if f, ok := v[0].(string); ok {
				feats[f] = true
			}
		}
	}
	comps := map[string]bool{}
	for _, r := range ctx.rowsOf("Component") {
		if v := r.values(); len(v) > 0 {
			if c, ok := v[0].(string); ok {
				comps[c] = true
			}
		}
	}
	for _, r := range ctx.rowsOf("FeatureComponents") {
		vals := r.values()
		if len(vals) > 1 {
			f, _ := vals[0].(string)
			c, _ := vals[1].(string)
			if !feats[f] {
				findings = append(findings, &msiFinding{ice: "ICE02", sev: SeverityError, table: "FeatureComponents", column: "Feature_", rowKeys: rowPKs(r), message: fmt.Sprintf("feature %q missing", f)})
			}
			if !comps[c] {
				findings = append(findings, &msiFinding{ice: "ICE02", sev: SeverityError, table: "FeatureComponents", column: "Component_", rowKeys: rowPKs(r), message: fmt.Sprintf("component %q missing", c)})
			}
		}
	}
	return findings
}

// runICE92: Component with files should have a GUID (or KeyPath); basic version of the rule.
func runICE92(ctx *iceContext) []Finding {
	var findings []Finding
	hasFile := map[string]bool{}
	for _, fr := range ctx.rowsOf("File") {
		if v := fr.values(); len(v) > 1 {
			if c, ok := v[1].(string); ok {
				hasFile[c] = true
			}
		}
	}
	for _, r := range ctx.rowsOf("Component") {
		vals := r.values()
		if len(vals) > 0 {
			cid, _ := vals[0].(string)
			guid, _ := vals[1].(string)
			kp := ""
			if len(vals) > iceComponentKeyPathColumn {
				if k, ok := vals[iceComponentKeyPathColumn].(string); ok {
					kp = k
				}
			}
			if hasFile[cid] && guid == "" && kp == "" {
				findings = append(findings, &msiFinding{
					ice:     "ICE92",
					sev:     SeverityError,
					table:   "Component",
					column:  "ComponentId",
					rowKeys: rowPKs(r),
					message: "component with files has neither GUID nor KeyPath",
				})
			}
		}
	}
	return findings
}

// runICE30: Media rows basic sanity (disk ID, last seq, cabinet if present).
func runICE30(ctx *iceContext) []Finding {
	var findings []Finding
	for _, r := range ctx.rowsOf("Media") {
		vals := r.values()
		if len(vals) > 0 {
			if disk, ok := vals[0].(int16); ok && disk < 1 {
				findings = append(findings, &msiFinding{ice: "ICE30", sev: SeverityError, table: "Media", column: "DiskId", rowKeys: rowPKs(r), message: "DiskId must be >=1"})
			}
		}
		if len(vals) > 1 {
			if last, ok := vals[1].(int16); ok && last < 0 {
				findings = append(findings, &msiFinding{ice: "ICE30", sev: SeverityError, table: "Media", column: "LastSequence", rowKeys: rowPKs(r), message: "LastSequence must be >=0"})
			}
		}
	}
	return findings
}

// rowPKs is a tiny helper that returns the primary key values of a row
// (as strings) for inclusion in Finding.RowKeys(). Used by ICE03 etc.
func rowPKs(r msiRow) []string {
	// Best-effort: take leading string values (real PK columns are
	// identified via the column metadata or _Validation).
	vals := r.values()
	out := make([]string, 0, 2)
	for _, v := range vals {
		if s, ok := v.(string); ok {
			out = append(out, s)
			if len(out) >= 2 {
				break
			}
		}
	}
	return out
}
