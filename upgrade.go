package msi

import (
	"fmt"
	"sort"
	"strings"
)

// msi_upgrade.go — P4 Upgrade, LaunchCondition and the WiX-style MajorUpgrade
// convenience. Public surface is interface-only (Builder-IS-Implementation).
//
// MajorUpgrade is resolved at compile time (synthesizeMajorUpgrade) from the
// package's UpgradeCode and Version so it can read the final identity values;
// it appends Upgrade + LaunchCondition rows and contributes the ActionProperty
// names to SecureCustomProperties.

// UpgradeAttributes is the Upgrade.Attributes bit field.
type UpgradeAttributes int32

const (
	// UpgradeMigrateFeatures migrates the feature states of the removed product.
	UpgradeMigrateFeatures UpgradeAttributes = 0x1
	// UpgradeOnlyDetect detects a related product without removing it.
	UpgradeOnlyDetect UpgradeAttributes = 0x2
	// UpgradeIgnoreRemoveFailure continues if removal of the related product fails.
	UpgradeIgnoreRemoveFailure UpgradeAttributes = 0x4
	// UpgradeVersionMinInclusive makes VersionMin an inclusive bound.
	UpgradeVersionMinInclusive UpgradeAttributes = 0x100
	// UpgradeVersionMaxInclusive makes VersionMax an inclusive bound.
	UpgradeVersionMaxInclusive UpgradeAttributes = 0x200
	// UpgradeLanguagesExclusive treats the Language column as a list to exclude.
	UpgradeLanguagesExclusive UpgradeAttributes = 0x400
)

const (
	msiDefaultUpgradeDetectedProperty   = "WIX_UPGRADE_DETECTED"
	msiDefaultDowngradeDetectedProperty = "WIX_DOWNGRADE_DETECTED"
	msiDefaultDowngradeMessage          = "A newer version of this product is already installed."
)

// UpgradeBuilder configures one Upgrade-table row (a related-product detect /
// remove rule). Use ActionProperty to name the public UPPERCASE property set to
// the detected ProductCode list.
type UpgradeBuilder interface {
	DetectRange(versionMin, versionMax string) UpgradeBuilder
	// Inclusive sets whether VersionMin / VersionMax are inclusive bounds.
	Inclusive(min, max bool) UpgradeBuilder
	WithLanguage(language string) UpgradeBuilder
	WithAttributes(attrs UpgradeAttributes) UpgradeBuilder
	OnlyDetect() UpgradeBuilder
	MigrateFeatures() UpgradeBuilder
	IgnoreRemoveFailure() UpgradeBuilder
	Remove(features string) UpgradeBuilder
	ActionProperty(prop string) UpgradeBuilder
}

// MajorUpgradeBuilder configures the WiX-style major-upgrade behaviour.
type MajorUpgradeBuilder interface {
	// AllowDowngrades disables downgrade detection/blocking (no detect-newer row,
	// no LaunchCondition).
	AllowDowngrades() MajorUpgradeBuilder
	// DowngradeErrorMessage sets the LaunchCondition message shown when a newer
	// version is already installed.
	DowngradeErrorMessage(message string) MajorUpgradeBuilder
	// AllowSameVersionUpgrades treats an equal ProductVersion as an upgrade
	// (the remove range becomes inclusive of the current version).
	AllowSameVersionUpgrades() MajorUpgradeBuilder
	// RemoveAfter schedules RemoveExistingProducts after the named action.
	// Accepts "InstallValidate", "InstallInitialize" (default), "InstallExecute",
	// or "InstallFinalize".
	RemoveAfter(action string) MajorUpgradeBuilder
	// Done returns to the parent PackageBuilder for further chaining.
	Done() PackageBuilder
}

// ----- model -----

type upgradeEntry struct {
	upgradeCode    string
	versionMin     string
	versionMax     string
	language       string
	attributes     int32
	remove         string
	actionProperty string
}

type launchConditionEntry struct {
	condition   string
	description string
}

type majorUpgradeCfg struct {
	allowDowngrades       bool
	downgradeErrorMessage string
	allowSameVersion      bool
	removeAfter           string
}

// ----- PackageBuilder methods -----

func (p *msiPackage) LaunchCondition(condition, description string) PackageBuilder {
	p.launchConditions = append(p.launchConditions, launchConditionEntry{
		condition: condition, description: description,
	})
	return p
}

func (p *msiPackage) Upgrade(upgradeCode string) UpgradeBuilder {
	p.upgradeEntries = append(p.upgradeEntries, upgradeEntry{upgradeCode: upgradeCode})
	return &upgradeHandle{pkg: p, idx: len(p.upgradeEntries) - 1}
}

func (p *msiPackage) MajorUpgrade() MajorUpgradeBuilder {
	if p.majorUpgrade == nil {
		p.majorUpgrade = &majorUpgradeCfg{}
	}
	return &majorUpgradeHandle{pkg: p}
}

// ----- UpgradeBuilder handle -----

type upgradeHandle struct {
	pkg *msiPackage
	idx int
}

func (h *upgradeHandle) entry() *upgradeEntry { return &h.pkg.upgradeEntries[h.idx] }

func (h *upgradeHandle) DetectRange(versionMin, versionMax string) UpgradeBuilder {
	h.entry().versionMin = versionMin
	h.entry().versionMax = versionMax
	return h
}

func (h *upgradeHandle) Inclusive(min, max bool) UpgradeBuilder {
	if min {
		h.entry().attributes |= int32(UpgradeVersionMinInclusive)
	} else {
		h.entry().attributes &^= int32(UpgradeVersionMinInclusive)
	}
	if max {
		h.entry().attributes |= int32(UpgradeVersionMaxInclusive)
	} else {
		h.entry().attributes &^= int32(UpgradeVersionMaxInclusive)
	}
	return h
}

func (h *upgradeHandle) WithLanguage(language string) UpgradeBuilder {
	h.entry().language = language
	return h
}

func (h *upgradeHandle) WithAttributes(attrs UpgradeAttributes) UpgradeBuilder {
	h.entry().attributes |= int32(attrs)
	return h
}

func (h *upgradeHandle) OnlyDetect() UpgradeBuilder {
	h.entry().attributes |= int32(UpgradeOnlyDetect)
	return h
}

func (h *upgradeHandle) MigrateFeatures() UpgradeBuilder {
	h.entry().attributes |= int32(UpgradeMigrateFeatures)
	return h
}

func (h *upgradeHandle) IgnoreRemoveFailure() UpgradeBuilder {
	h.entry().attributes |= int32(UpgradeIgnoreRemoveFailure)
	return h
}

func (h *upgradeHandle) Remove(features string) UpgradeBuilder {
	h.entry().remove = features
	return h
}

func (h *upgradeHandle) ActionProperty(prop string) UpgradeBuilder {
	h.entry().actionProperty = prop
	return h
}

// ----- MajorUpgradeBuilder handle -----

type majorUpgradeHandle struct {
	pkg *msiPackage
}

func (h *majorUpgradeHandle) cfg() *majorUpgradeCfg { return h.pkg.majorUpgrade }

func (h *majorUpgradeHandle) AllowDowngrades() MajorUpgradeBuilder {
	h.cfg().allowDowngrades = true
	return h
}

func (h *majorUpgradeHandle) DowngradeErrorMessage(message string) MajorUpgradeBuilder {
	h.cfg().downgradeErrorMessage = message
	return h
}

func (h *majorUpgradeHandle) AllowSameVersionUpgrades() MajorUpgradeBuilder {
	h.cfg().allowSameVersion = true
	return h
}

func (h *majorUpgradeHandle) RemoveAfter(action string) MajorUpgradeBuilder {
	h.cfg().removeAfter = action
	return h
}

func (h *majorUpgradeHandle) Done() PackageBuilder {
	return h.pkg
}

// ----- compile-time synthesis -----

// synthesizeMajorUpgrade expands a configured MajorUpgrade into concrete Upgrade
// and LaunchCondition entries on the package (mirroring the WiX default). The
// ActionProperty names land in SecureCustomProperties via
// mergeSecureCustomProperties (derived from the persisted upgradeEntries). No-op
// when MajorUpgrade was not used, and idempotent across re-compiles.
func synthesizeMajorUpgrade(p *msiPackage) {
	cfg := p.majorUpgrade
	if cfg == nil {
		return
	}
	// Idempotency: compileMSIPackage may run more than once for a package (e.g.
	// two WriteMSI calls); never append the synthesized rows twice.
	if p.majorUpgradeExpanded {
		return
	}
	p.majorUpgradeExpanded = true

	// (1) detect-and-remove-older: VersionMax = current version, exclusive by
	// default (strictly older). MigrateFeatures preserves user selections.
	olderAttrs := int32(UpgradeMigrateFeatures)
	if cfg.allowSameVersion {
		olderAttrs |= int32(UpgradeVersionMaxInclusive)
	}
	p.upgradeEntries = append(p.upgradeEntries, upgradeEntry{
		upgradeCode:    p.upgradeCode,
		versionMin:     "", // open lower bound (NULL)
		versionMax:     p.version,
		attributes:     olderAttrs,
		actionProperty: msiDefaultUpgradeDetectedProperty,
	})

	// (2) detect-only-newer (downgrade prevention) unless explicitly allowed.
	if !cfg.allowDowngrades {
		p.upgradeEntries = append(p.upgradeEntries, upgradeEntry{
			upgradeCode:    p.upgradeCode,
			versionMin:     p.version, // exclusive lower bound (strictly newer)
			versionMax:     "",
			attributes:     int32(UpgradeOnlyDetect),
			actionProperty: msiDefaultDowngradeDetectedProperty,
		})

		msg := cfg.downgradeErrorMessage
		if msg == "" {
			msg = msiDefaultDowngradeMessage
		}
		p.launchConditions = append(p.launchConditions, launchConditionEntry{
			condition:   "NOT " + msiDefaultDowngradeDetectedProperty,
			description: msg,
		})
	}
}

// mergeSecureCustomProperties combines any user-provided SecureCustomProperties
// value with every Upgrade ActionProperty into one sorted, deduplicated,
// semicolon-separated list. Derived from the persisted model (not a transient
// synthesis result), so it is stable across re-compiles. Returns "" when empty.
func mergeSecureCustomProperties(p *msiPackage) string {
	seen := map[string]bool{}
	var all []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		all = append(all, s)
	}
	if existing, ok := p.props["SecureCustomProperties"]; ok {
		for _, part := range strings.Split(existing, ";") {
			add(part)
		}
	}
	for _, e := range p.upgradeEntries {
		add(e.actionProperty)
	}
	sort.Strings(all)
	return strings.Join(all, ";")
}

// emitMSIUpgradeTables emits the Upgrade and LaunchCondition tables. Nullable
// string cells pass through ("" maps to NULL); Attributes is a plain int32.
func emitMSIUpgradeTables(p *msiPackage, db msiDatabaseBuilder) error {
	if len(p.upgradeEntries) > 0 {
		upTbl := createMSITableFromCatalog("Upgrade")
		for i, e := range p.upgradeEntries {
			row := newMSIRowBuilder().WithColumns(upTbl.columns()...).WithValues(
				e.upgradeCode, e.versionMin, e.versionMax, e.language,
				e.attributes, e.remove, e.actionProperty,
			).Build()
			if err := upTbl.addRow(row); err != nil {
				return fmt.Errorf("msi compile: Upgrade row %d (%s): %w", i, e.upgradeCode, err)
			}
		}
		db.WithTable(upTbl)
	}

	if len(p.launchConditions) > 0 {
		lcTbl := createMSITableFromCatalog("LaunchCondition")
		for _, e := range p.launchConditions {
			row := newMSIRowBuilder().WithColumns(lcTbl.columns()...).WithValues(
				e.condition, e.description,
			).Build()
			if err := lcTbl.addRow(row); err != nil {
				return fmt.Errorf("msi compile: LaunchCondition row %q: %w", e.condition, err)
			}
		}
		db.WithTable(lcTbl)
	}

	return nil
}
