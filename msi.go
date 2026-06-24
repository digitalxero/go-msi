package msi

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
)

// PackageBuilder is the root entry for the public declarative MSI package
// API. All configuration uses chainable With*/Add* methods that return the
// builder interface for further configuration. Per the project style guide,
// this is the "Builder IS Implementation" pattern: the concrete builder
// implements both the builder interface and the primary Package runtime
// interface. Build() finalizes (validation, ID derivation) and returns the
// same value as Package.
//
// The legacy (*Builder).BuildMSI + MSIConfig surface remains unchanged for
// backward compatibility and is documented as deprecated in favor of this API.
// New code should use NewPackage.
type PackageBuilder interface {
	// Core product identity. Required; validated in Build. ProductCode and
	// UpgradeCode (when supplied) must be braced uppercase GUIDs.
	WithProductCode(guid string) PackageBuilder
	WithUpgradeCode(guid string) PackageBuilder
	WithProductName(name string) PackageBuilder
	WithManufacturer(m string) PackageBuilder
	WithVersion(v string) PackageBuilder // major.minor.build preferred
	WithAllUsers(all bool) PackageBuilder

	// Arbitrary properties (e.g. ProductLanguage, ALLUSERS handled via
	// dedicated methods or here).
	WithProperty(key, value string) PackageBuilder

	// Directory tree construction. RootDirectory declares (or re-opens) the
	// logical root install directory (e.g. "INSTALLFOLDER") and returns a
	// DirectoryBuilder for attaching subdirectories and components. The
	// Directory table will be populated with proper parent chains rooted at
	// TARGETDIR during compilation.
	RootDirectory(id, defaultDir string) DirectoryBuilder

	// Directory returns an existing (or newly declared) directory by ID for
	// attaching components/files after the initial tree walk. Enables
	// non-linear construction order.
	Directory(id string) DirectoryBuilder

	// Feature returns (or creates) a top-level or parented feature for
	// multi-feature packages. Use FeatureBuilder to set title/level and to
	// associate components (many-to-many via FeatureComponents).
	Feature(id string) FeatureBuilder

	// AddTree harvests an fs.FS tree (heat-style) under the given attach point
	// directory ID (which must exist or be created by prior RootDirectory/
	// Directory calls), associating every harvested component with featureID
	// (declare it via Feature so the package installs). One Component is created
	// per regular file (with the file as its KeyPath) to avoid MSI component-rule
	// violations in the common case. Directory.DefaultDir and File.FileName
	// receive 8.3 short|long forms via the per-directory shortname generator.
	// Deterministic walk order is used.
	AddTree(fsys fs.FS, attachPointDirID, featureID string) error

	// P3 global assets (icons/binaries referenced by shortcuts/reg etc.). The
	// source is streamed (re-opened, never fully buffered) when its CFB stream
	// is written. Use FileSourceFromBytes/FromPath/FromFS to construct one.
	Icon(name string, src FileSource) PackageBuilder
	Binary(name string, src FileSource) PackageBuilder

	// P4: a launch condition (Condition that must hold for the install to
	// proceed, with the message shown when it fails).
	LaunchCondition(condition, description string) PackageBuilder

	// P4: a low-level Upgrade-table row keyed by the related UpgradeCode. Use
	// MajorUpgrade for the common detect-older/block-downgrade convenience.
	Upgrade(upgradeCode string) UpgradeBuilder

	// P4: WiX-style major-upgrade handling derived from this package's
	// UpgradeCode/Version (remove older, block downgrade, SecureCustomProperties,
	// scheduled FindRelatedProducts/MigrateFeatureStates/RemoveExistingProducts).
	MajorUpgrade() MajorUpgradeBuilder

	// P4: an AppSearch that sets the named property from a registry/INI/component/
	// directory search (with an optional file Signature match).
	Search(property string) SearchBuilder

	// P5: a custom action (typed constructor + modifiers + sequence schedule).
	CustomAction(id string) CustomActionBuilder

	// P6: a named text style (font) for dialog text controls.
	TextStyle(name, faceName string, size int16) TextStyleBuilder

	// P6: a localized UI text string (UIText table).
	UIText(key, text string) PackageBuilder

	// P6: a custom dialog (DialogBuilder for controls/events/conditions).
	Dialog(id string) DialogBuilder

	// P6: install the canned minimal interactive wizard (welcome+license,
	// progress, exit/error/cancel). Structurally valid + ICE-clean; on-screen
	// rendering is a manual Windows check.
	WithMinimalUI() PackageBuilder

	// P6: override the license text shown by the canned UI.
	WithLicenseText(text string) PackageBuilder

	// P7: multi-media / cabinet controls.
	WithCabSplitThreshold(maxUncompressedBytes int64) PackageBuilder
	WithFolderThreshold(maxUncompressedBytes int64) PackageBuilder
	WithExternalCabs(write func(name string) (io.WriteCloser, error)) PackageBuilder
	WithSpanning(maxBytesPerCab int64) PackageBuilder
	Media(diskID int16) MediaBuilder

	// P8: Authenticode-sign the emitted MSI with the given signer (opt-in).
	WithSigner(s Signer) PackageBuilder

	// P9: set the primary ProductLanguage / Template language id (default
	// LangCode_enUS / 1033). Accepts a named LanguageCode or LanguageCode(n).
	WithLanguage(lcid LanguageCode) PackageBuilder

	// P9: embed a language transform for lcid. configure mutates a deep clone of
	// the (built) base into the target for that language; the diff is stored as
	// a sub-storage named after the decimal LCID and the LCID is added to the
	// Template language list.
	WithLanguageTransform(lcid LanguageCode, configure func(t PackageBuilder)) PackageBuilder

	// Build performs final validation (required fields, GUIDs, versions,
	// duplicate detection within directories, etc.), prepares any
	// auto-derived values (GUIDs via msiGUIDv5 where not supplied), and
	// returns the primary Package (the same underlying builder value per
	// the style guide). The returned package can be written via WriteMSI.
	Build() (Package, error)

	// WithSkipValidation disables the automatic ICE validation that runs
	// at the end of Build/WriteMSI (and on the legacy BuildMSI path).
	// The validator is still available for explicit use via
	// NewValidator(). WithAllICEs() etc.
	WithSkipValidation() PackageBuilder
}

// NewPackage returns a fresh PackageBuilder (the concrete unexported
// implementation satisfies both the builder and runtime interfaces).
func NewPackage() PackageBuilder {
	return &msiPackage{
		allUsers:    true,
		props:       make(map[string]string),
		dirEntries:  make(map[string]*dirEntry),
		compEntries: make(map[string]*compEntry),
		featEntries: make(map[string]*featEntry),
	}
}

// Package is the primary runtime interface for a built MSI package model.
// Its main responsibility in P1 is emission via WriteMSI (which compiles the
// model to the internal msiDatabase representation and emits a spec-true CFB
// using the unchanged P0 machinery).
type Package interface {
	// WriteMSI emits a complete, deterministic, _Validation-populated MSI
	// to w. It reuses serializeMSIStreams + writeMSICFB (and the existing
	// cabinet/stringpool/summary paths) so that equivalent flat models
	// produce bit-identical output to the legacy Builder.BuildMSI path.
	WriteMSI(w io.Writer) error
}

// DirectoryBuilder allows declaration of directory hierarchy (parent links
// become Directory.Parent and DefaultDir with 8.3 handling) and attachment of
// components (and therefore files) to a specific directory.
type DirectoryBuilder interface {
	// WithDefaultDir overrides the DefaultDir for this directory (the value
	// that appears in the Directory table and receives short|long treatment).
	WithDefaultDir(defaultDir string) DirectoryBuilder

	// Component declares (or re-opens) a component that will live in this
	// directory (Component.Directory_). Returns a ComponentBuilder for
	// GUID/KeyPath/files/associations.
	Component(id string) ComponentBuilder

	// Subdirectory declares a direct child directory (parent = this dir's ID).
	// Returns the child builder for further configuration. IDs must be unique
	// within the package.
	Subdirectory(id, defaultDir string) DirectoryBuilder
}

// RegistryRoot constants for use with RegistryKey / WithRegistry (P3).
type RegistryRoot int16

const (
	RegistryRootHKMU RegistryRoot = iota - 1
	RegistryRootHKCR
	RegistryRootHKCU
	RegistryRootHKLM
	RegistryRootHKU
)

// ComponentBuilder configures a Component row (GUID derivation, attributes,
// KeyPath, files belonging to it, and feature associations).
type ComponentBuilder interface {
	// WithGUID supplies an explicit Component.ComponentId (must be valid
	// braced GUID or empty to let the compiler derive a stable v5 GUID).
	WithGUID(guid string) ComponentBuilder

	// WithKeyPath sets the KeyPath cell (typically a File primary key string
	// or nil for CreateFolder-style components in later phases).
	WithKeyPath(keyPath any) ComponentBuilder

	// WithAttributes sets the Component.Attributes bitfield (e.g. msidbComponentAttributes64Bit).
	WithAttributes(attrs int16) ComponentBuilder

	// WithFile adds a payload file belonging to this component. The logicalName
	// is relative to the component's directory (used for File.FileName after
	// shortname processing and for the stable file ID seed). The source is
	// re-opened (never fully buffered) when the cabinet is written; its Size is
	// read at compile time. Use FileSourceFromBytes/FromPath/FromFS/FromOpener
	// (or WithFilePath / WithFileFromFS) to construct one.
	WithFile(logicalName string, src FileSource) FileBuilder

	// WithFilePath adds a payload file streamed from an OS path (os.Stat for
	// size, os.Open per read). The file must remain present until WriteMSI.
	WithFilePath(logicalName, path string) FileBuilder

	// WithFileFromFS adds a payload file streamed from an fs.FS entry.
	WithFileFromFS(logicalName string, fsys fs.FS, name string) FileBuilder

	// AssociateToFeature links this component to the named feature
	// (populates FeatureComponents). Safe to call multiple times.
	AssociateToFeature(featureID string) ComponentBuilder

	// P3: registry support via key builder (preferred for multiple values per key,
	// typed values, AsKeyPath). Use RegistryRoot enum values for root.
	RegistryKey(root RegistryRoot, key string) RegistryKeyBuilder

	// P3: basic/compat registry (single value).
	WithRegistry(root RegistryRoot, key, name string, value any) ComponentBuilder

	// P3: shortcut support.
	Shortcut(name, target string) ShortcutBuilder

	// P3: basic/compat shortcut.
	WithShortcut(name, target string) ComponentBuilder

	// P4: Windows service install (ServiceInstall + optional MsiServiceConfig /
	// MsiServiceConfigFailureActions) attached to this component.
	ServiceInstall(name string) ServiceInstallBuilder

	// P4: Windows service control (ServiceControl) attached to this component.
	ServiceControl(name string) ServiceControlBuilder

	// P7: pin this component's files to an explicit cabinet/disk (Media.DiskId).
	AssignToMedia(diskID int16) ComponentBuilder
}

// RegistryKeyBuilder allows building a registry key with multiple typed values
// (Builder-IS-Impl pattern). Values are accumulated and emitted as Registry rows
// sharing the key. AsKeyPath marks the (last) value's Registry PK as the component
// KeyPath.
type RegistryKeyBuilder interface {
	Value(name string, value any) RegistryKeyBuilder
	AsKeyPath() RegistryKeyBuilder
}

// ShortcutBuilder for P3 shortcuts (advertised vs non, icon refs, etc.).
type ShortcutBuilder interface {
	// InDirectory sets the directory the shortcut is created in (the
	// Shortcut.Directory_ column). It may be a directory declared via
	// RootDirectory/Directory or a standard Windows Installer directory such as
	// "ProgramMenuFolder", "DesktopFolder", "StartupFolder" or
	// "StartMenuFolder" — standard directories are added to the Directory table
	// automatically. When unset, the shortcut is created in INSTALLFOLDER.
	InDirectory(dirID string) ShortcutBuilder
	Arguments(args string) ShortcutBuilder
	Description(desc string) ShortcutBuilder
	Icon(name string, index int16) ShortcutBuilder
	// Advertised(targetFeature string) or non-advertised (target file ref)
	Advertised(featureID string) ShortcutBuilder
}

// FeatureBuilder configures Feature rows and the many-to-many links to
// components. Basic parent support is included for P1 (full conditions,
// levels, and display ordering refinements come in later phases with UI).
type FeatureBuilder interface {
	WithTitle(title string) FeatureBuilder
	WithDescription(desc string) FeatureBuilder
	WithDisplay(display int16) FeatureBuilder
	WithLevel(level int16) FeatureBuilder
	WithParent(parentID string) FeatureBuilder

	// AssociateComponent links the feature to a component (inverse of
	// ComponentBuilder.AssociateToFeature).
	AssociateComponent(componentID string) FeatureBuilder
}

// FileBuilder allows per-file attributes (version, vital, etc.) on a file
// added via ComponentBuilder.WithFile. Sequence and cabinet membership are
// assigned by the compiler.
type FileBuilder interface {
	WithVersion(version string) FileBuilder
	// Vital(bool) and other flags can be added here when the File table
	// population in the compiler is wired (P1 scope keeps them minimal).
}

// ----- private implementation ("Builder IS Implementation") -----

type msiPackage struct {
	// identity
	productCode  string
	upgradeCode  string
	productName  string
	manufacturer string
	version      string
	allUsers     bool

	// properties
	props map[string]string

	// model (populated by builders, consumed by compileMSIPackage)
	dirEntries  map[string]*dirEntry
	compEntries map[string]*compEntry
	featEntries map[string]*featEntry

	// P3 tables (Registry/Shortcut/Icon/Binary), emitted by compileMSIPackage.
	registryEntries []registryEntry
	shortcutEntries []shortcutEntry
	iconEntries     []iconEntry
	binaryEntries   []binaryEntry

	// P4 services (ServiceInstall/ServiceControl + MsiServiceConfig/FailureActions).
	serviceInstallEntries []serviceInstallEntry
	serviceControlEntries []serviceControlEntry

	// P4 upgrades + launch conditions.
	upgradeEntries   []upgradeEntry
	launchConditions []launchConditionEntry
	majorUpgrade     *majorUpgradeCfg

	// P4 AppSearch / locators / signatures.
	appSearchEntries []appSearchEntry
	regLocators      []regLocatorEntry
	iniLocators      []iniLocatorEntry
	compLocators     []compLocatorEntry
	drLocators       []drLocatorEntry
	signatureEntries []signatureEntry

	// P5 custom actions.
	customActions []customActionEntry

	// P6 UI.
	textStyleEntries  []textStyleEntry
	uiTextEntries     []uiTextEntry
	dialogEntries     []dialogEntry
	useMinimalUI      bool
	minimalUIExpanded bool
	licenseText       string

	// compile-time synthesis idempotency guard (MajorUpgrade)
	majorUpgradeExpanded bool

	// P7 multi-media / cabinets.
	mediaEntries       []mediaEntry
	cabSplitThreshold  int64
	cabFolderThreshold int64
	cabSpanCap         int64
	externalCabWriter  func(name string) (io.WriteCloser, error)

	// P8 signing (opt-in).
	signer Signer

	// P9 multi-language.
	language           int
	languageTransforms []languageTransform

	// deferred errors (style consistent with internal msiDB)
	errs []error

	// P2 validation escape hatch
	skipValidation bool
}

type iconEntry struct {
	name string
	src  FileSource
}

type binaryEntry struct {
	name string
	src  FileSource
}

type registryEntry struct {
	root      RegistryRoot
	key, name string
	value     any
	component string
}

type shortcutEntry struct {
	name, target, component string
	directory               string // Shortcut.Directory_; defaults to INSTALLFOLDER
	arguments, description  string
	iconName                string
	iconIndex               int16
	advertisedFeature       string
}

type compEntry struct {
	id         string
	dirID      string
	guid       string
	keyPath    any
	attrs      int16
	featAssocs []string
	files      []attachedFile
	// P3
	asKeyPathRegistry bool
	// P7: explicit media assignment (0 = unassigned)
	mediaDisk int16
}

type dirEntry struct {
	id         string
	parent     string
	defaultDir string
}

type featEntry struct {
	id         string
	parent     string
	title      string
	desc       string
	display    int16
	level      int16
	compAssocs []string
}

type attachedFile struct {
	name    string
	src     FileSource
	version string
}

func (p *msiPackage) fail(err error) {
	if err != nil {
		p.errs = append(p.errs, err)
	}
}

// --- PackageBuilder implementation ---

func (p *msiPackage) WithProductCode(guid string) PackageBuilder {
	p.productCode = guid
	return p
}

func (p *msiPackage) WithUpgradeCode(guid string) PackageBuilder {
	p.upgradeCode = guid
	return p
}

func (p *msiPackage) WithProductName(name string) PackageBuilder {
	p.productName = name
	return p
}

func (p *msiPackage) WithManufacturer(m string) PackageBuilder {
	p.manufacturer = m
	return p
}

func (p *msiPackage) WithVersion(v string) PackageBuilder {
	p.version = v
	return p
}

func (p *msiPackage) WithAllUsers(all bool) PackageBuilder {
	p.allUsers = all
	return p
}

func (p *msiPackage) WithProperty(key, value string) PackageBuilder {
	p.props[key] = value
	return p
}

func (p *msiPackage) RootDirectory(id, defaultDir string) DirectoryBuilder {
	if _, ok := p.dirEntries[id]; !ok {
		p.dirEntries[id] = &dirEntry{id: id, defaultDir: defaultDir}
	}
	return &dirHandle{pkg: p, id: id}
}

func (p *msiPackage) Directory(id string) DirectoryBuilder {
	if _, ok := p.dirEntries[id]; !ok {
		p.dirEntries[id] = &dirEntry{id: id}
	}
	return &dirHandle{pkg: p, id: id}
}

func (p *msiPackage) Feature(id string) FeatureBuilder {
	if _, ok := p.featEntries[id]; !ok {
		p.featEntries[id] = &featEntry{id: id, level: 1}
	}
	return &featHandle{pkg: p, id: id}
}

func (p *msiPackage) WithSkipValidation() PackageBuilder {
	p.skipValidation = true
	return p
}

func (p *msiPackage) Icon(name string, src FileSource) PackageBuilder {
	p.iconEntries = append(p.iconEntries, iconEntry{name: name, src: src})
	return p
}

func (p *msiPackage) Binary(name string, src FileSource) PackageBuilder {
	p.binaryEntries = append(p.binaryEntries, binaryEntry{name: name, src: src})
	return p
}

func (p *msiPackage) AddTree(fsys fs.FS, attachPointDirID, featureID string) error {
	if fsys == nil {
		return nil
	}
	// Ensure attach point exists.
	if _, ok := p.dirEntries[attachPointDirID]; !ok {
		p.dirEntries[attachPointDirID] = &dirEntry{id: attachPointDirID, defaultDir: attachPointDirID}
	}

	// Collect then sort for deterministic processing order.
	type walkEntry struct {
		path string
		d    fs.DirEntry
	}
	var collected []walkEntry
	if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == "." || path == "" {
			return nil
		}
		collected = append(collected, walkEntry{path: path, d: d})
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(collected, func(i, j int) bool { return collected[i].path < collected[j].path })

	for _, we := range collected {
		if we.d.IsDir() {
			// Create a directory node for the relative path under attach.
			// ID is attach + "." + sanitized(rel) so parent links form a tree.
			rel := we.path
			dirID := attachPointDirID + "." + sanitizeIDSegment(rel)
			if _, ok := p.dirEntries[dirID]; !ok {
				// parent is the prefix dir (or attach for top level under it)
				parent := attachPointDirID
				if idx := strings.LastIndex(rel, "/"); idx != -1 {
					parent = attachPointDirID + "." + sanitizeIDSegment(rel[:idx])
				}
				p.dirEntries[dirID] = &dirEntry{id: dirID, parent: parent, defaultDir: relBase(rel)}
			}
			continue
		}
		if !we.d.Type().IsRegular() {
			continue
		}
		// Stream the file lazily: fs.Stat for the size now, fs.Open per read at
		// cab-write time — the bytes are never fully buffered here.
		src, err := FileSourceFromFS(fsys, we.path)
		if err != nil {
			p.fail(fmt.Errorf("reading %s: %w", we.path, err))
			continue
		}
		// Determine the leaf directory for this file (parent chain created above).
		rel := we.path
		leafDir := attachPointDirID
		if idx := strings.LastIndex(rel, "/"); idx != -1 {
			leafDir = attachPointDirID + "." + sanitizeIDSegment(rel[:idx])
		}
		// One component per file (default, avoids component-rule pitfalls),
		// associated with featureID so the harvested files actually install.
		base := relBase(rel)
		compID := "c_" + sanitizeIDSegment(rel)
		comp := p.Directory(leafDir).Component(compID)
		if featureID != "" {
			comp = comp.AssociateToFeature(featureID)
		}
		comp.WithFile(base, src)
	}
	return nil
}

func sanitizeIDSegment(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			b = append(b, c)
		} else {
			b = append(b, '_')
		}
	}
	if len(b) == 0 {
		return "d"
	}
	if len(b) > 60 {
		b = b[:60]
	}
	return string(b)
}

func relBase(p string) string {
	if i := strings.LastIndex(p, "/"); i != -1 {
		return p[i+1:]
	}
	return p
}

func (p *msiPackage) Build() (Package, error) {
	if len(p.errs) > 0 {
		return nil, fmt.Errorf("msi package build failed: %w", p.errs[0])
	}

	// Minimal required-field validation (mirrors spirit of effectiveMSIConfig
	// but without Manifest fallbacks — new API is explicit).
	if p.productName == "" {
		return nil, fmt.Errorf("msi: ProductName is required")
	}
	if p.manufacturer == "" {
		return nil, fmt.Errorf("msi: Manufacturer is required")
	}
	if p.version == "" {
		return nil, fmt.Errorf("msi: Version is required")
	}
	if err := validateMSIVersionString(p.version); err != nil {
		return nil, fmt.Errorf("msi: invalid Version %q: %w", p.version, err)
	}
	if p.productCode != "" && !msiValidGUID(p.productCode) {
		return nil, fmt.Errorf("msi: ProductCode %q is not a braced uppercase GUID", p.productCode)
	}
	if p.upgradeCode != "" && !msiValidGUID(p.upgradeCode) {
		return nil, fmt.Errorf("msi: UpgradeCode %q is not a braced uppercase GUID", p.upgradeCode)
	}

	// Later slices add deeper graph validation (cycles, missing parents,
	// duplicate basenames within a dir, keypath rules, etc.).
	return p, nil
}

// --- Package implementation (compile + ICE-validate + CFB emit) ---

func (p *msiPackage) WriteMSI(w io.Writer) error {
	// Re-validate / finalize (Build is idempotent enough for our model).
	if _, err := p.Build(); err != nil {
		return err
	}

	db, err := compileMSIPackage(p)
	if err != nil {
		return fmt.Errorf("msi: compiling package: %w", err)
	}

	// PackageCode: exactly mirror the legacy derivation for flat-repro parity
	// (P1G2-051): "package|"+ProductCode+"|"+Version + ("|"+FilePK for each
	// in the order the File rows were emitted). This makes RevisionNumber
	// (and thus Summary stream) byte-identical for equivalent models. We
	// inspect the File table post-compile (rows are in emission order).
	//
	// This is computed BEFORE validation so ICE39 (and any other summary rule)
	// runs against the REAL package code rather than a placeholder.
	pkgSeed := "package|" + p.productCode + "|" + p.version
	if fileTbl, err := db.GetTable("File"); err == nil {
		for _, r := range fileTbl.rows() {
			if vals := r.values(); len(vals) > 0 {
				if fid, ok := vals[0].(string); ok && fid != "" {
					pkgSeed += "|" + fid
				}
			}
		}
	}
	packageCode, err := msiGUIDv5(msiPackageNamespaceGUID, pkgSeed)
	if err != nil {
		packageCode = "{12345678-1234-1234-1234-123456789ABC}"
	}

	summary := msiSummaryInfo{
		Codepage:       1252,
		Title:          "Installation Database",
		Subject:        p.productName,
		Author:         p.manufacturer,
		Keywords:       "Installer",
		Template:       msiTemplateString(p),
		RevisionNumber: packageCode,
		CreatingApp:    "go-msix",
		CreateTime:     msiBuildTime,
		SaveTime:       msiBuildTime,
		PageCount:      200,
		WordCount:      2,
		Security:       2,
	}

	// P2: automatic ICE validation (validate-by-default). Only error-severity
	// findings cause a failure. SkipValidation is the escape hatch (also
	// exposed on the legacy MSIConfig path in a later wiring step).
	if !p.skipValidation {
		vb := NewValidator().WithAllICEs()
		v, verr := vb.Build()
		if verr != nil {
			return fmt.Errorf("msi: building validator: %w", verr)
		}
		// Use the already-loaded db + the real summary (with the computed
		// package code) for an efficient in-memory check (no extra serialize).
		findings := v.(*msiValidator).validateInternal(db, summary)
		for _, f := range findings {
			if f.Severity() == SeverityError {
				return fmt.Errorf("msi: ICE validation failed: %s", f.Error())
			}
		}
	}

	streams, err := serializeMSIStreams(db, summary, cabBuildOptions{
		folderThreshold: p.cabFolderThreshold,
		externalWriter:  p.externalCabWriter,
		spanCap:         p.cabSpanCap,
	})
	if err != nil {
		return err
	}

	// P9: embedded language transforms — one sub-storage per WithLanguageTransform,
	// named after the decimal LCID, holding that language's base→clone diff. The
	// LCIDs are already reflected in the summary Template (msiTemplateString).
	subStorages, err := p.buildLanguageSubStorages(db)
	if err != nil {
		return err
	}

	// P8: Authenticode signing (opt-in). Appends the \x05DigitalSignature stream
	// computed over the imprint of the streams above + any embedded sub-storages
	// + the (recursive) CLSIDs. The signature stream is excluded from the imprint,
	// so an unsigned build stays byte-identical.
	if p.signer != nil {
		// The imprint hash and the CFB write each consume every streamed cabinet
		// once; materialize those to per-cabinet temps first so a signed build
		// compresses each cabinet only once (re-reading the temp twice) instead
		// of recompressing it for both passes. Unsigned builds skip this and
		// stream each cabinet straight through (single pass).
		var cleanup func()
		streams, cleanup, err = realizeStreamedCabStreams(streams)
		if err != nil {
			return fmt.Errorf("msi: staging cabinets for signing: %w", err)
		}
		defer cleanup()

		streams, err = msiSignStreams(streams, subStorages, p.signer)
		if err != nil {
			return fmt.Errorf("msi: signing: %w", err)
		}
	}

	// Same temp+CFB dance as the legacy path (P0 machinery untouched).
	tmp, err := os.CreateTemp("", "go-msix-*.msi")
	if err != nil {
		return fmt.Errorf("msi: temp for cfb: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	defer tmp.Close()

	if err := writeMSICFBWithSubStorages(streams, subStorages, msiRootCLSID, tmp); err != nil {
		return fmt.Errorf("msi: emitting CFB: %w", err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("msi: seek temp: %w", err)
	}
	if _, err := io.Copy(w, tmp); err != nil {
		return fmt.Errorf("msi: copy cfb to output: %w", err)
	}
	return nil
}

// --- sub-builder handles (also implement their builder interfaces) ---

type dirHandle struct {
	pkg *msiPackage
	id  string
}

func (d *dirHandle) WithDefaultDir(defaultDir string) DirectoryBuilder {
	if e, ok := d.pkg.dirEntries[d.id]; ok {
		e.defaultDir = defaultDir
	}
	return d
}

func (d *dirHandle) Component(id string) ComponentBuilder {
	e, ok := d.pkg.compEntries[id]
	if !ok {
		e = &compEntry{id: id, dirID: d.id}
		d.pkg.compEntries[id] = e
	} else if e.dirID == "" {
		e.dirID = d.id
	}
	return &compHandle{pkg: d.pkg, id: id}
}

func (d *dirHandle) Subdirectory(id, defaultDir string) DirectoryBuilder {
	if _, ok := d.pkg.dirEntries[id]; !ok {
		d.pkg.dirEntries[id] = &dirEntry{id: id, parent: d.id, defaultDir: defaultDir}
	}
	return &dirHandle{pkg: d.pkg, id: id}
}

type compHandle struct {
	pkg *msiPackage
	id  string
}

func (c *compHandle) WithGUID(guid string) ComponentBuilder {
	if e := c.pkg.compEntries[c.id]; e != nil {
		e.guid = guid
	}
	return c
}

func (c *compHandle) WithKeyPath(keyPath any) ComponentBuilder {
	if e := c.pkg.compEntries[c.id]; e != nil {
		e.keyPath = keyPath
	}
	return c
}

func (c *compHandle) WithAttributes(attrs int16) ComponentBuilder {
	if e := c.pkg.compEntries[c.id]; e != nil {
		e.attrs = attrs
	}
	return c
}

func (c *compHandle) WithFile(logicalName string, src FileSource) FileBuilder {
	e := c.pkg.compEntries[c.id]
	if e == nil {
		return &fileHandle{} // defensive; normal path always has entry
	}
	e.files = append(e.files, attachedFile{name: logicalName, src: src})
	return &fileHandle{pkg: c.pkg, compID: c.id, name: logicalName}
}

func (c *compHandle) WithFilePath(logicalName, path string) FileBuilder {
	src, err := FileSourceFromPath(path)
	if err != nil {
		c.pkg.fail(err)
		return &fileHandle{}
	}
	return c.WithFile(logicalName, src)
}

func (c *compHandle) WithFileFromFS(logicalName string, fsys fs.FS, name string) FileBuilder {
	src, err := FileSourceFromFS(fsys, name)
	if err != nil {
		c.pkg.fail(err)
		return &fileHandle{}
	}
	return c.WithFile(logicalName, src)
}

func (c *compHandle) AssociateToFeature(featureID string) ComponentBuilder {
	e := c.pkg.compEntries[c.id]
	if e == nil {
		return c
	}
	for _, f := range e.featAssocs {
		if f == featureID {
			return c
		}
	}
	e.featAssocs = append(e.featAssocs, featureID)
	return c
}

func (c *compHandle) WithRegistry(root RegistryRoot, key, name string, value any) ComponentBuilder {
	c.pkg.registryEntries = append(c.pkg.registryEntries, registryEntry{
		root: root, key: key, name: name, value: value, component: c.id,
	})
	return c
}

func (c *compHandle) WithShortcut(name, target string) ComponentBuilder {
	c.pkg.shortcutEntries = append(c.pkg.shortcutEntries, shortcutEntry{
		name: name, target: target, component: c.id,
	})
	return c
}

func (c *compHandle) RegistryKey(root RegistryRoot, key string) RegistryKeyBuilder {
	return &registryKeyHandle{pkg: c.pkg, root: root, key: key, component: c.id}
}

func (c *compHandle) Shortcut(name, target string) ShortcutBuilder {
	c.pkg.shortcutEntries = append(c.pkg.shortcutEntries, shortcutEntry{name: name, target: target, component: c.id})
	idx := len(c.pkg.shortcutEntries) - 1
	return &shortcutHandle{pkg: c.pkg, idx: idx}
}

// registryKeyHandle implements RegistryKeyBuilder (Builder-IS-Impl).
type registryKeyHandle struct {
	pkg       *msiPackage
	root      RegistryRoot
	key       string
	component string
	// last value for AsKeyPath
}

func (h *registryKeyHandle) Value(name string, value any) RegistryKeyBuilder {
	h.pkg.registryEntries = append(h.pkg.registryEntries, registryEntry{
		root: h.root, key: h.key, name: name, value: value, component: h.component,
	})
	return h
}

func (h *registryKeyHandle) AsKeyPath() RegistryKeyBuilder {
	// Mark the component so compileMSIPackage points its KeyPath at the
	// Registry row PK emitted for this key/value (see msi_compile.go).
	if c := h.pkg.compEntries[h.component]; c != nil {
		c.asKeyPathRegistry = true
	}
	return h
}

// shortcutHandle implements ShortcutBuilder.
type shortcutHandle struct {
	pkg *msiPackage
	idx int
}

func (h *shortcutHandle) InDirectory(dirID string) ShortcutBuilder {
	h.pkg.shortcutEntries[h.idx].directory = dirID
	return h
}

func (h *shortcutHandle) Arguments(args string) ShortcutBuilder {
	h.pkg.shortcutEntries[h.idx].arguments = args
	return h
}

func (h *shortcutHandle) Description(desc string) ShortcutBuilder {
	h.pkg.shortcutEntries[h.idx].description = desc
	return h
}

func (h *shortcutHandle) Icon(name string, index int16) ShortcutBuilder {
	h.pkg.shortcutEntries[h.idx].iconName = name
	h.pkg.shortcutEntries[h.idx].iconIndex = index
	return h
}

func (h *shortcutHandle) Advertised(featureID string) ShortcutBuilder {
	h.pkg.shortcutEntries[h.idx].advertisedFeature = featureID
	return h
}

type featHandle struct {
	pkg *msiPackage
	id  string
}

func (f *featHandle) WithTitle(title string) FeatureBuilder {
	if e := f.pkg.featEntries[f.id]; e != nil {
		e.title = title
	}
	return f
}

func (f *featHandle) WithDescription(desc string) FeatureBuilder {
	if e := f.pkg.featEntries[f.id]; e != nil {
		e.desc = desc
	}
	return f
}

func (f *featHandle) WithDisplay(display int16) FeatureBuilder {
	if e := f.pkg.featEntries[f.id]; e != nil {
		e.display = display
	}
	return f
}

func (f *featHandle) WithLevel(level int16) FeatureBuilder {
	if e := f.pkg.featEntries[f.id]; e != nil {
		e.level = level
	}
	return f
}

func (f *featHandle) WithParent(parentID string) FeatureBuilder {
	if e := f.pkg.featEntries[f.id]; e != nil {
		e.parent = parentID
	}
	return f
}

func (f *featHandle) AssociateComponent(componentID string) FeatureBuilder {
	e := f.pkg.featEntries[f.id]
	if e == nil {
		return f
	}
	for _, c := range e.compAssocs {
		if c == componentID {
			return f
		}
	}
	e.compAssocs = append(e.compAssocs, componentID)
	return f
}

type fileHandle struct {
	pkg    *msiPackage
	compID string
	name   string
}

func (f *fileHandle) WithVersion(version string) FileBuilder {
	// Locate the file entry under the component and annotate.
	if c, ok := f.pkg.compEntries[f.compID]; ok {
		for i := range c.files {
			if c.files[i].name == f.name {
				c.files[i].version = version
				break
			}
		}
	}
	return f
}
