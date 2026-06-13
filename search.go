package msi

import (
	"fmt"
	"sort"
)

// msi_search.go — P4 AppSearch / file-signature search subsystem: AppSearch,
// Signature, RegLocator, IniLocator, CompLocator, DrLocator. Public surface is
// interface-only (Builder-IS-Implementation).
//
// Every Search(property) produces one AppSearch row plus exactly one locator
// row, both keyed by a generated Signature_ id. MatchingFile additionally emits
// a Signature row sharing that id (the locator finds the directory, the
// Signature narrows to a file).

// Search locator result types (RegLocator/IniLocator/CompLocator Type column).
const (
	msiLocatorTypeDirectory int16 = 0
	msiLocatorTypeFile      int16 = 1
	msiLocatorTypeRawValue  int16 = 2
)

// SearchBuilder begins one AppSearch that sets a property from a registry, INI,
// installed-component, or directory-tree search.
type SearchBuilder interface {
	InRegistry(root RegistryRoot, key, name string) RegistrySearchBuilder
	InIniFile(fileName, section, key string, field int16) IniSearchBuilder
	ByComponentID(componentID string) ComponentSearchBuilder
	InDirectory(path string, depth int16) DirectorySearchBuilder
}

// RegistrySearchBuilder finalizes a registry search (RegLocator). The result
// type defaults to a raw registry value; MatchingFile instead matches a file in
// the located directory (and emits a Signature row).
type RegistrySearchBuilder interface {
	AsDirectory() PackageBuilder
	AsFile() PackageBuilder
	AsRawValue() PackageBuilder
	MatchingFile(fileName string) FileSignatureBuilder
}

// IniSearchBuilder finalizes an INI search (IniLocator).
type IniSearchBuilder interface {
	AsDirectory() PackageBuilder
	AsFile() PackageBuilder
	AsRawValue() PackageBuilder
	MatchingFile(fileName string) FileSignatureBuilder
}

// ComponentSearchBuilder finalizes a component search (CompLocator).
type ComponentSearchBuilder interface {
	AsDirectory() PackageBuilder
	AsFile() PackageBuilder
	MatchingFile(fileName string) FileSignatureBuilder
}

// DirectorySearchBuilder finalizes a directory-tree search (DrLocator), usually
// paired with MatchingFile to identify a file under the searched path.
type DirectorySearchBuilder interface {
	MatchingFile(fileName string) FileSignatureBuilder
	Done() PackageBuilder
}

// FileSignatureBuilder constrains the Signature row that matches a file found by
// a locator (version/size/language ranges).
type FileSignatureBuilder interface {
	WithVersion(min, max string) FileSignatureBuilder
	WithSize(min, max int32) FileSignatureBuilder
	WithLanguages(languages string) FileSignatureBuilder
	Done() PackageBuilder
}

// ----- model -----

type appSearchEntry struct {
	property  string
	signature string
}

type regLocatorEntry struct {
	signature  string
	root       int16
	key        string
	name       string
	searchType *int16
}

type iniLocatorEntry struct {
	signature  string
	fileName   string
	section    string
	key        string
	field      *int16
	searchType *int16
}

type compLocatorEntry struct {
	signature   string
	componentID string
	searchType  *int16
}

type drLocatorEntry struct {
	signature string
	parent    string
	path      string
	depth     *int16
}

type signatureEntry struct {
	signature              string
	fileName               string
	minVersion, maxVersion string
	minSize, maxSize       *int32
	minDate, maxDate       *int32
	languages              string
}

// ----- PackageBuilder method -----

func (p *msiPackage) Search(property string) SearchBuilder {
	return &searchHandle{pkg: p, property: property}
}

func (p *msiPackage) nextSignatureID() string {
	id := fmt.Sprintf("sig%02d", len(p.appSearchEntries))
	return id
}

// ----- SearchBuilder handle -----

type searchHandle struct {
	pkg      *msiPackage
	property string
}

func (h *searchHandle) addAppSearch() string {
	sig := h.pkg.nextSignatureID()
	h.pkg.appSearchEntries = append(h.pkg.appSearchEntries, appSearchEntry{
		property: h.property, signature: sig,
	})
	return sig
}

func (h *searchHandle) InRegistry(root RegistryRoot, key, name string) RegistrySearchBuilder {
	sig := h.addAppSearch()
	t := msiLocatorTypeRawValue
	h.pkg.regLocators = append(h.pkg.regLocators, regLocatorEntry{
		signature: sig, root: int16(root), key: key, name: name, searchType: &t,
	})
	return &regSearchHandle{pkg: h.pkg, idx: len(h.pkg.regLocators) - 1, sig: sig}
}

func (h *searchHandle) InIniFile(fileName, section, key string, field int16) IniSearchBuilder {
	sig := h.addAppSearch()
	t := msiLocatorTypeRawValue
	f := field
	h.pkg.iniLocators = append(h.pkg.iniLocators, iniLocatorEntry{
		signature: sig, fileName: fileName, section: section, key: key, field: &f, searchType: &t,
	})
	return &iniSearchHandle{pkg: h.pkg, idx: len(h.pkg.iniLocators) - 1, sig: sig}
}

func (h *searchHandle) ByComponentID(componentID string) ComponentSearchBuilder {
	sig := h.addAppSearch()
	t := msiLocatorTypeFile
	h.pkg.compLocators = append(h.pkg.compLocators, compLocatorEntry{
		signature: sig, componentID: componentID, searchType: &t,
	})
	return &compSearchHandle{pkg: h.pkg, idx: len(h.pkg.compLocators) - 1, sig: sig}
}

func (h *searchHandle) InDirectory(path string, depth int16) DirectorySearchBuilder {
	sig := h.addAppSearch()
	d := depth
	h.pkg.drLocators = append(h.pkg.drLocators, drLocatorEntry{
		signature: sig, path: path, depth: &d,
	})
	return &drSearchHandle{pkg: h.pkg, sig: sig}
}

// addSignature appends a Signature row sharing the locator's id and returns a
// FileSignatureBuilder bound to it.
func (p *msiPackage) addSignature(sig, fileName string) *fileSignatureHandle {
	p.signatureEntries = append(p.signatureEntries, signatureEntry{signature: sig, fileName: fileName})
	return &fileSignatureHandle{pkg: p, idx: len(p.signatureEntries) - 1}
}

// ----- locator handles -----

type regSearchHandle struct {
	pkg *msiPackage
	idx int
	sig string
}

func (h *regSearchHandle) setType(t int16) PackageBuilder {
	h.pkg.regLocators[h.idx].searchType = &t
	return h.pkg
}
func (h *regSearchHandle) AsDirectory() PackageBuilder { return h.setType(msiLocatorTypeDirectory) }
func (h *regSearchHandle) AsFile() PackageBuilder      { return h.setType(msiLocatorTypeFile) }
func (h *regSearchHandle) AsRawValue() PackageBuilder  { return h.setType(msiLocatorTypeRawValue) }
func (h *regSearchHandle) MatchingFile(fileName string) FileSignatureBuilder {
	// Locator finds the directory; the Signature narrows to the file.
	t := msiLocatorTypeDirectory
	h.pkg.regLocators[h.idx].searchType = &t
	return h.pkg.addSignature(h.sig, fileName)
}

type iniSearchHandle struct {
	pkg *msiPackage
	idx int
	sig string
}

func (h *iniSearchHandle) setType(t int16) PackageBuilder {
	h.pkg.iniLocators[h.idx].searchType = &t
	return h.pkg
}
func (h *iniSearchHandle) AsDirectory() PackageBuilder { return h.setType(msiLocatorTypeDirectory) }
func (h *iniSearchHandle) AsFile() PackageBuilder      { return h.setType(msiLocatorTypeFile) }
func (h *iniSearchHandle) AsRawValue() PackageBuilder  { return h.setType(msiLocatorTypeRawValue) }
func (h *iniSearchHandle) MatchingFile(fileName string) FileSignatureBuilder {
	t := msiLocatorTypeDirectory
	h.pkg.iniLocators[h.idx].searchType = &t
	return h.pkg.addSignature(h.sig, fileName)
}

type compSearchHandle struct {
	pkg *msiPackage
	idx int
	sig string
}

func (h *compSearchHandle) setType(t int16) PackageBuilder {
	h.pkg.compLocators[h.idx].searchType = &t
	return h.pkg
}
func (h *compSearchHandle) AsDirectory() PackageBuilder { return h.setType(msiLocatorTypeDirectory) }
func (h *compSearchHandle) AsFile() PackageBuilder      { return h.setType(msiLocatorTypeFile) }
func (h *compSearchHandle) MatchingFile(fileName string) FileSignatureBuilder {
	t := msiLocatorTypeDirectory
	h.pkg.compLocators[h.idx].searchType = &t
	return h.pkg.addSignature(h.sig, fileName)
}

type drSearchHandle struct {
	pkg *msiPackage
	sig string
}

func (h *drSearchHandle) MatchingFile(fileName string) FileSignatureBuilder {
	return h.pkg.addSignature(h.sig, fileName)
}
func (h *drSearchHandle) Done() PackageBuilder { return h.pkg }

type fileSignatureHandle struct {
	pkg *msiPackage
	idx int
}

func (h *fileSignatureHandle) entry() *signatureEntry { return &h.pkg.signatureEntries[h.idx] }

func (h *fileSignatureHandle) WithVersion(min, max string) FileSignatureBuilder {
	h.entry().minVersion = min
	h.entry().maxVersion = max
	return h
}

func (h *fileSignatureHandle) WithSize(min, max int32) FileSignatureBuilder {
	mn, mx := min, max
	h.entry().minSize = &mn
	h.entry().maxSize = &mx
	return h
}

func (h *fileSignatureHandle) WithLanguages(languages string) FileSignatureBuilder {
	h.entry().languages = languages
	return h
}

func (h *fileSignatureHandle) Done() PackageBuilder { return h.pkg }

// ----- emission -----

// nullInt16 / nullInt32 convert a possibly-nil pointer to the any the row
// builder expects (nil => NULL cell, value => typed int).
func nullInt16(p *int16) any {
	if p == nil {
		return nil
	}
	return *p
}

func nullInt32(p *int32) any {
	if p == nil {
		return nil
	}
	return *p
}

// emitMSISearchTables emits Signature, AppSearch and the locator tables for the
// package's search model. Order is fixed for deterministic output.
func emitMSISearchTables(p *msiPackage, db msiDatabaseBuilder) error {
	if len(p.signatureEntries) > 0 {
		// Sort by signature id for deterministic emission independent of which
		// builder added the Signature row.
		entries := append([]signatureEntry(nil), p.signatureEntries...)
		sort.Slice(entries, func(i, j int) bool { return entries[i].signature < entries[j].signature })
		sigTbl := createMSITableFromCatalog("Signature")
		for _, e := range entries {
			row := newMSIRowBuilder().WithColumns(sigTbl.columns()...).WithValues(
				e.signature, e.fileName, e.minVersion, e.maxVersion,
				nullInt32(e.minSize), nullInt32(e.maxSize), nullInt32(e.minDate), nullInt32(e.maxDate),
				e.languages,
			).Build()
			if err := sigTbl.addRow(row); err != nil {
				return fmt.Errorf("msi compile: Signature row %s: %w", e.signature, err)
			}
		}
		db.WithTable(sigTbl)
	}

	if len(p.appSearchEntries) > 0 {
		asTbl := createMSITableFromCatalog("AppSearch")
		for _, e := range p.appSearchEntries {
			row := newMSIRowBuilder().WithColumns(asTbl.columns()...).WithValues(
				e.property, e.signature,
			).Build()
			if err := asTbl.addRow(row); err != nil {
				return fmt.Errorf("msi compile: AppSearch row %s: %w", e.property, err)
			}
		}
		db.WithTable(asTbl)
	}

	if len(p.regLocators) > 0 {
		tbl := createMSITableFromCatalog("RegLocator")
		for _, e := range p.regLocators {
			row := newMSIRowBuilder().WithColumns(tbl.columns()...).WithValues(
				e.signature, e.root, e.key, e.name, nullInt16(e.searchType),
			).Build()
			if err := tbl.addRow(row); err != nil {
				return fmt.Errorf("msi compile: RegLocator row %s: %w", e.signature, err)
			}
		}
		db.WithTable(tbl)
	}

	if len(p.iniLocators) > 0 {
		tbl := createMSITableFromCatalog("IniLocator")
		for _, e := range p.iniLocators {
			row := newMSIRowBuilder().WithColumns(tbl.columns()...).WithValues(
				e.signature, e.fileName, e.section, e.key, nullInt16(e.field), nullInt16(e.searchType),
			).Build()
			if err := tbl.addRow(row); err != nil {
				return fmt.Errorf("msi compile: IniLocator row %s: %w", e.signature, err)
			}
		}
		db.WithTable(tbl)
	}

	if len(p.compLocators) > 0 {
		tbl := createMSITableFromCatalog("CompLocator")
		for _, e := range p.compLocators {
			row := newMSIRowBuilder().WithColumns(tbl.columns()...).WithValues(
				e.signature, e.componentID, nullInt16(e.searchType),
			).Build()
			if err := tbl.addRow(row); err != nil {
				return fmt.Errorf("msi compile: CompLocator row %s: %w", e.signature, err)
			}
		}
		db.WithTable(tbl)
	}

	if len(p.drLocators) > 0 {
		tbl := createMSITableFromCatalog("DrLocator")
		for _, e := range p.drLocators {
			row := newMSIRowBuilder().WithColumns(tbl.columns()...).WithValues(
				e.signature, e.parent, e.path, nullInt16(e.depth),
			).Build()
			if err := tbl.addRow(row); err != nil {
				return fmt.Errorf("msi compile: DrLocator row %s: %w", e.signature, err)
			}
		}
		db.WithTable(tbl)
	}

	return nil
}

// msiSearchPropertyNames returns the sorted set of properties set by AppSearch
// (used by ICE checks / SecureCustomProperties wiring in later slices).
func msiSearchPropertyNames(p *msiPackage) []string {
	if len(p.appSearchEntries) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range p.appSearchEntries {
		if !seen[e.property] {
			seen[e.property] = true
			out = append(out, e.property)
		}
	}
	sort.Strings(out)
	return out
}
