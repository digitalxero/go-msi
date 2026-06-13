package msi

import (
	"fmt"
	"strconv"
	"strings"
)

// iceRule describes one ICE rule for the registry. Rules are pure functions
// that receive an iceContext and return findings (empty slice = pass for
// that rule). The "tables" list is used for absence=pass optimization: if
// none of the rule's subject tables are present in the DB, the rule is
// skipped entirely (so a rule whose subject tables a package never emits does
// not fail that package).
type iceRule struct {
	id     string
	fn     func(*iceContext) []Finding
	tables []string // subject tables; empty means always run (e.g. summary ICEs)
}

// allICERules returns the complete set of registered rules (Tier 1 + future).
// No init() magic; called explicitly by the validator/engine. This list is
// the single source of truth for which ICEs exist.
func allICERules() []iceRule {
	// Tier 1 rules live in msi_ice_rules_tier1.go (registerTier1Rules); Tier 2
	// (P4 upgrade ICEs) in msi_ice_rules_tier2.go; Tier 3 (P5 custom-action ICEs)
	// in msi_ice_rules_tier3.go. Future tiers append here.
	rules := append([]iceRule(nil), tier1Rules...)
	rules = append(rules, tier2Rules...)
	rules = append(rules, tier3Rules...)
	rules = append(rules, tier4Rules...)
	rules = append(rules, tier5Rules...)
	rules = append(rules, tier6Rules...)
	return rules
}

// iceContext provides query helpers over a loaded msiDatabase + optional
// summary (for file validation we read both; for in-build validation we
// pass the internal structures directly to avoid re-serialization).
// All helpers are deterministic and respect the sorted row order from the
// builder/reader.
type iceContext struct {
	db      msiDatabase
	summary msiSummaryInfo // zero value is OK for rules that don't need it
}

// newIceContext constructs a context. For file-based validation the caller
// will have already read the DB and summary via the P0 reader.
func newIceContext(db msiDatabase, summary msiSummaryInfo) *iceContext {
	return &iceContext{
		db:      db,
		summary: summary,
	}
}

// rowsOf returns all rows for a table (or empty slice if absent). This is
// the primary "absence = pass" primitive: callers check len==0 early.
func (c *iceContext) rowsOf(table string) []msiRow {
	t, err := c.db.GetTable(table)
	if err != nil {
		return nil
	}
	return t.rows()
}

// msiCatalogColumnFor looks up the full catalog def for a table.col (for category, keyTable, min/max etc).
// Falls back to a default if not found.
func msiCatalogColumnFor(table, colName string) msiCatalogColumn {
	if def, ok := msiCatalogTable(table); ok {
		for _, c := range def.columns {
			if c.name == colName {
				return c
			}
		}
	}
	// fallback
	return msiCatalogColumn{name: colName, category: "Text", nullable: true}
}

// validateCategory is the ICE03 workhorse. It implements validation for
// all ~25 MSDN column categories using the catalog metadata + existing
// helpers from msi_tables.go. NULL/empty follows MSI semantics ("" == NULL).
// Returns error describing the violation (for use in findings).
func validateCategory(cat string, val any, col msiCatalogColumn) error {
	// Dereference pointers like the column validator does.
	switch p := val.(type) {
	case *string:
		if p == nil {
			val = nil
		} else {
			val = *p
		}
	case *int16:
		if p == nil {
			val = nil
		} else {
			val = *p
		}
	case *int32:
		if p == nil {
			val = nil
		} else {
			val = *p
		}
	}
	if s, ok := val.(string); ok && s == "" {
		val = nil
	}

	if val == nil {
		if !col.nullable {
			return fmt.Errorf("column %s is non-nullable", col.name)
		}
		return nil
	}

	switch cat {
	case "Identifier":
		if s, ok := val.(string); ok {
			if !msiIdentifierPattern.MatchString(s) {
				return fmt.Errorf("invalid Identifier %q", s)
			}
		}
	case "Guid":
		if s, ok := val.(string); ok {
			if !msiGUIDPattern.MatchString(s) {
				return fmt.Errorf("invalid Guid %q", s)
			}
		}
	case "Version":
		if s, ok := val.(string); ok {
			if err := validateMSIVersionString(s); err != nil {
				return err
			}
		}
	case "Filename", "DefaultDir", "WildCardFilename":
		if s, ok := val.(string); ok {
			// For DefaultDir/FileName, allow short|long or bare; basic check via cabinet-like or identifier
			// Full shortname validation is in msi_shortnames, here basic format.
			if strings.Contains(s, "|") {
				parts := strings.SplitN(s, "|", 2)
				for _, p := range parts {
					if err := validateBasicFilename(p); err != nil {
						return fmt.Errorf("bad %s part %q: %w", cat, p, err)
					}
				}
			} else if err := validateBasicFilename(s); err != nil {
				return fmt.Errorf("bad %s %q: %w", cat, s, err)
			}
		}
	case "Cabinet":
		if s, ok := val.(string); ok {
			if err := validateMSICabinetString(s); err != nil {
				return err
			}
		}
	case "Condition", "Text", "Formatted", "Template", "Property", "CustomSource":
		// These categories are essentially free-form; reject only embedded
		// control characters that would corrupt the .idt/stream encoding.
		if s, ok := val.(string); ok {
			if strings.ContainsAny(s, "\x00\x01\x02") {
				return fmt.Errorf("invalid %s value with control chars", cat)
			}
		}
	case "UpperCase":
		if s, ok := val.(string); ok {
			if s != strings.ToUpper(s) {
				return fmt.Errorf("%s value %q is not uppercase", cat, s)
			}
		}
	case "Language":
		// Comma separated numbers, allow.
		if s, ok := val.(string); ok {
			for _, p := range strings.Split(s, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					if _, err := strconv.Atoi(p); err != nil {
						return fmt.Errorf("bad Language %q", s)
					}
				}
			}
		}
	case "Integer", "DoubleInteger":
		// Ranges checked via Min/Max in catalog if present.
		if col.minValue != nil || col.maxValue != nil {
			var i int64
			switch v := val.(type) {
			case int16:
				i = int64(v)
			case int32:
				i = int64(v)
			case string:
				// rare
				fmt.Sscanf(v, "%d", &i)
			}
			if col.minValue != nil && i < int64(*col.minValue) {
				return fmt.Errorf("value %d below min %d", i, *col.minValue)
			}
			if col.maxValue != nil && i > int64(*col.maxValue) {
				return fmt.Errorf("value %d above max %d", i, *col.maxValue)
			}
		}
	default:
		// Other cats (Path, RegPath etc.) are lenient for Tier1 on our tables.
	}
	return nil
}

func validateBasicFilename(s string) error {
	if len(s) == 0 || len(s) > 255 {
		return fmt.Errorf("length out of range")
	}
	if strings.ContainsAny(s, "/\\?*\"<>|") {
		return fmt.Errorf("contains invalid chars")
	}
	return nil
}

// runAllRules executes the registered rules (filtered by the validator's
// ice selection) against the context and returns the collected findings
// filtered to those with Severity >= minSev (the severity floor). A floor
// of SeverityInfo reports everything; SeverityError reports only errors.
func runAllRules(ctx *iceContext, selected map[string]bool, all bool, exclude map[string]bool, minSev Severity) []Finding {
	var out []Finding
	for _, rule := range allICERules() {
		if exclude[rule.id] {
			continue
		}
		if !all && len(selected) > 0 && !selected[rule.id] {
			continue
		}
		// absence = pass optimization: skip rules whose subject tables are absent
		if len(rule.tables) > 0 {
			present := false
			for _, tn := range rule.tables {
				if _, err := ctx.db.GetTable(tn); err == nil {
					present = true
					break
				}
			}
			if !present {
				continue
			}
		}
		findings := rule.fn(ctx)
		for _, f := range findings {
			// Report findings at or ABOVE the severity floor. Higher numeric =
			// more severe (Info=0 < Warning=1 < Error=2), so a floor of
			// SeverityWarning keeps Warning+Error and drops Info.
			if f.Severity() >= minSev {
				out = append(out, f)
			}
		}
	}
	return out
}
