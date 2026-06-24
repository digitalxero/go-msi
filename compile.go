package msi

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strconv"
)

// compileMSIPackage is the bridge from the public declarative model
// (PackageBuilder graph) to the internal msiDatabaseBuilder / msiDatabase
// used by all P0 emission paths (serializeMSIStreams, writeMSICFB, etc.).
//
// The entire point of the compiler is to drive the *existing* WithDirectory,
// WithComponent, WithFile, WithFeature, Associate..., WithMedia,
// WithSequenceAction, WithProperties etc. calls in exactly the same order
// and with exactly the same values that the legacy flat BuildMSI path used,
// so that for equivalent input we get bit-identical .msi bytes (the "flat
// reproduction parity" requirement).
//
// This file owns the tree walk, parent resolution, per-directory shortname
// context, logical path computation for file IDs, deterministic sequencing,
// and the decision of when to synthesize TARGETDIR / INSTALLFOLDER roots for
// compatibility with the old single-dir model.
//
// All heavy lifting for actual row population is done by delegating to the
// unexported msiDatabaseBuilder (which already does error accumulation,
// _Validation, system catalog, etc.).

// emitMSIFileHash gates MsiFileHash table emission from the new compile path.
// It is intentionally false: the legacy BuildMSI golden does not emit
// MsiFileHash, and the flat-repro parity test requires byte-identity with that
// golden. See the DEFERRED note in compileMSIPackage. Flip to true only once the
// legacy path emits MsiFileHash too (so both paths stay byte-identical).
const emitMSIFileHash = false

// compileMSIFileHashRows builds a fully-populated MsiFileHash table for every
// unversioned file across all components (MD5 split into 4 little-endian i4
// HashPart cells, Options=0). It returns nil if there are no unversioned files.
// This is real, validated logic; it is currently only invoked when
// emitMSIFileHash is true (see compileMSIPackage's DEFERRED note for why).
func compileMSIFileHashRows(p *msiPackage) (msiTable, error) {
	hashTbl := createMSITableFromCatalog("MsiFileHash")
	for _, c := range p.compEntries {
		for _, f := range c.files {
			if f.version != "" {
				continue
			}
			rc, err := f.src.Open()
			if err != nil {
				return nil, fmt.Errorf("msi compile: MsiFileHash open %s: %w", f.name, err)
			}
			hsh := md5.New()
			if _, err := io.Copy(hsh, rc); err != nil {
				rc.Close()
				return nil, fmt.Errorf("msi compile: MsiFileHash read %s: %w", f.name, err)
			}
			rc.Close()
			var sum [16]byte
			copy(sum[:], hsh.Sum(nil))
			h1 := int32(binary.LittleEndian.Uint32(sum[0:4]))
			h2 := int32(binary.LittleEndian.Uint32(sum[4:8]))
			h3 := int32(binary.LittleEndian.Uint32(sum[8:12]))
			h4 := int32(binary.LittleEndian.Uint32(sum[12:16]))
			fid := generateMSIFileID(c.dirID+"/"+f.name, nil)
			row := newMSIRowBuilder().WithColumns(hashTbl.columns()...).
				WithValues(fid, int16(0), h1, h2, h3, h4).Build()
			if err := hashTbl.addRow(row); err != nil {
				return nil, fmt.Errorf("msi compile: MsiFileHash row %s: %w", fid, err)
			}
		}
	}
	if len(hashTbl.rows()) == 0 {
		return nil, nil
	}
	return hashTbl, nil
}

// encodeRegistryValue encodes a value for the Registry.Value column per MSI conventions
// (string as-is or formatted; int -> #decimal for DWORD; []byte -> #xHEX for binary; etc.).
func encodeRegistryValue(v any) any {
	if v == nil {
		return nil
	}
	switch x := v.(type) {
	case string:
		return x
	case int:
		return fmt.Sprintf("#%d", x)
	case int16:
		return fmt.Sprintf("#%d", x)
	case int32:
		return fmt.Sprintf("#%d", x)
	case int64:
		return fmt.Sprintf("#%d", x)
	case uint, uint16, uint32, uint64:
		return fmt.Sprintf("#%d", x)
	case []byte:
		return "#x" + hex.EncodeToString(x)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// compileMSIPackage turns a validated *msiPackage into a ready-to-serialize
// msiDatabase. It returns an error for any graph problems (cycles, missing
// parents, duplicate logical basenames within a directory after shortname
// assignment, etc.). The returned database has already had its Build() called
// (so _Validation + _Tables/_Columns are present).
func compileMSIPackage(p *msiPackage) (msiDatabase, error) {
	if p == nil {
		return nil, fmt.Errorf("msi compile: nil package")
	}

	// For flat repro parity (P1G2-051) and to match legacy BuildMSI behavior,
	// synthesize the conventional TARGETDIR + INSTALLFOLDER (using product
	// name for the install dir DefaultDir, which then gets short|long treatment).
	ensureRootDirectories(p, "INSTALLFOLDER", msiSanitizeDirName(p.productName))

	// Ensure any directory referenced by a shortcut exists before the Directory
	// table is emitted. Standard Windows Installer directories (ProgramMenuFolder,
	// DesktopFolder, …) are created on demand under TARGETDIR so shortcuts can be
	// placed in them without the caller declaring them.
	for _, e := range p.shortcutEntries {
		if e.directory != "" {
			ensureStandardDirectory(p, e.directory)
		}
	}

	db := newMSIDatabaseBuilder()

	// P4: expand a configured MajorUpgrade into Upgrade/LaunchCondition entries
	// before property emission, so its ActionProperty names can be merged into
	// SecureCustomProperties below.
	synthesizeMajorUpgrade(p)

	// P6: expand the canned UI before property emission too (it contributes the
	// DefaultUIFont property). The UI tables themselves are emitted later.
	synthesizeMinimalUI(p)

	// 1. Properties from the public model (including the derived ALLUSERS
	// and the explicit WithProperty map). Sort keys for determinism.
	// We build a safe map and never pass empty strings for identity
	// properties: the Property.Value column is non-nullable in the catalog
	// and the internal row validator rejects the empty value (even though
	// the legacy path always derives a ProductCode).
	idProps := map[string]string{}
	if p.productName != "" {
		idProps["ProductName"] = p.productName
	}
	if p.version != "" {
		idProps["ProductVersion"] = p.version
	}
	if p.manufacturer != "" {
		idProps["Manufacturer"] = p.manufacturer
	}
	if p.productCode != "" {
		idProps["ProductCode"] = p.productCode
	}
	// P9: ProductLanguage from the configured LCID (unless the user set it).
	if _, ok := p.props["ProductLanguage"]; !ok {
		idProps["ProductLanguage"] = strconv.Itoa(p.languageOrDefault())
	}
	if len(idProps) > 0 {
		db.WithProperties(idProps)
	}
	if p.allUsers {
		db.WithProperties(map[string]string{"ALLUSERS": "1"})
	}
	if p.upgradeCode != "" {
		db.WithProperties(map[string]string{"UpgradeCode": p.upgradeCode})
	}
	// P4: SecureCustomProperties (synthesized MajorUpgrade ActionProperties +
	// any user-provided value), merged once so the Property PK stays unique.
	if scp := mergeSecureCustomProperties(p); scp != "" {
		db.WithProperties(map[string]string{"SecureCustomProperties": scp})
	}
	if len(p.props) > 0 {
		// copy + sort to keep WithProperties deterministic
		props := make(map[string]string, len(p.props))
		for k, v := range p.props {
			if k == "SecureCustomProperties" {
				// already merged above to avoid a duplicate Property PK
				continue
			}
			props[k] = v
		}
		if len(props) > 0 {
			db.WithProperties(props)
		}
	}

	// 2. Directory tree (parent-first for correct insertion order + stringpool
	// determinism, plus per-dir shortnames). ensureRootDirectories above
	// guarantees the legacy flat roots (TARGETDIR + INSTALLFOLDER) for
	// parity cases. Siblings sorted alpha; parents emitted before children.
	children := map[string][]string{}
	roots := []string{}
	for id, e := range p.dirEntries {
		if e.parent == "" {
			roots = append(roots, id)
		} else if _, ok := p.dirEntries[e.parent]; ok {
			children[e.parent] = append(children[e.parent], id)
		} else {
			// dangling or root-like
			roots = append(roots, id)
		}
	}
	sort.Strings(roots)
	for pid := range children {
		sort.Strings(children[pid])
	}

	// Per-directory shortname generators...
	dirNamers := make(map[string]*msiShortNamer)

	var emitDir func(id string) error
	emitDir = func(id string) error {
		e := p.dirEntries[id]
		dd := e.defaultDir
		if dd == "" {
			dd = id
		}
		var ddColumn string
		if id == "TARGETDIR" {
			// Legacy hardcodes the literal "SourceDir" for TARGETDIR
			// (no short|long applied); only the product-derived install
			// folder goes through the dir namer.
			ddColumn = "SourceDir"
		} else if dd == "." {
			// Standard Windows Installer directories (ProgramMenuFolder,
			// DesktopFolder, …) use the literal "." DefaultDir; it must not go
			// through the 8.3 shortname generator.
			ddColumn = "."
		} else {
			namer := dirNamers[id]
			if namer == nil {
				namer = newMSIShortNamer()
				dirNamers[id] = namer
			}
			var err error
			ddColumn, err = namer.msiFileNameColumn(dd)
			if err != nil {
				return fmt.Errorf("msi compile: Directory %s DefaultDir %q: %w", id, dd, err)
			}
		}
		db.WithDirectory(id, e.parent, ddColumn)
		for _, ch := range children[id] {
			if err := emitDir(ch); err != nil {
				return err
			}
		}
		return nil
	}
	for _, r := range roots {
		if err := emitDir(r); err != nil {
			return nil, err
		}
	}

	// P3: emit Registry tables if populated (before comps so AsKeyPath can set keyPath on compEntry).
	if len(p.registryEntries) > 0 {
		regTbl := createMSITableFromCatalog("Registry")
		for i, e := range p.registryEntries {
			regID := fmt.Sprintf("reg%02d_%s", i, sanitizeIDSegment(e.component))
			val := encodeRegistryValue(e.value)
			// Root is a named enum (type RegistryRoot int16). The row cell
			// validator only narrows the builtin `int` to int16; a named
			// integer type falls through to "unknown data type" and would be
			// rejected. Convert to int16 at the cell boundary so the cell is a
			// plain int16. This covers BOTH the RegistryKey().Value() path and
			// the flat WithRegistry path (both populate p.registryEntries).
			// int16() is lossless because RegistryRoot's underlying type is int16.
			row := newMSIRowBuilder().WithColumns(regTbl.columns()...).
				WithValues(regID, int16(e.root), e.key, e.name, val, e.component).Build()
			if err := regTbl.addRow(row); err != nil {
				return nil, fmt.Errorf("msi compile: Registry row %s: %w", regID, err)
			}
			// if this comp marked for AsKeyPath via registry key, set its keyPath to this reg row PK
			if c := p.compEntries[e.component]; c != nil && c.asKeyPathRegistry {
				c.keyPath = regID
			}
		}
		db.WithTable(regTbl)
	}

	// 3. Components + files (basic wiring for P1G2-031).
	// Components and their attached files are emitted in sorted component ID
	// order for determinism. GUIDs are derived via msiGUIDv5 when not
	// supplied (stable seed including product + dir + comp id). If a
	// component declares files and has no explicit KeyPath we use the ID of
	// its first file (common case, satisfies ICE18/92 for the emitted shape).
	// File IDs use generateMSIFileID over a logical path seed + content
	// (lifts the old "duplicate basenames forbidden across dirs" limitation).
	// Real per-directory shortname application (short|long in the FileName
	// cell and DefaultDir) and full logical-path seeds are completed in the
	// follow-on work for this slice; the names and seeds here are sufficient
	// for table population + roundtrip testing.
	compNames := make([]string, 0, len(p.compEntries))
	for id := range p.compEntries {
		compNames = append(compNames, id)
	}
	sort.Strings(compNames)

	// P7: pre-pass to plan media (file -> DiskId + Sequence) in emission order.
	var orderedFiles []mediaFileRef
	for _, cid := range compNames {
		e := p.compEntries[cid]
		for _, f := range e.files {
			logical := e.dirID + "/" + f.name
			fid := generateMSIFileID(logical, nil)
			orderedFiles = append(orderedFiles, mediaFileRef{fileID: fid, size: f.src.Size(), component: cid})
		}
	}
	seqByFile, mediaPlan, err := planMedia(p, orderedFiles)
	if err != nil {
		return nil, err
	}

	hasFiles := false
	for _, cid := range compNames {
		e := p.compEntries[cid]
		g := e.guid
		if g == "" {
			seed := "component|" + p.productCode + "|" + e.dirID + "|" + cid
			if gg, err := msiGUIDv5(msiPackageNamespaceGUID, seed); err == nil {
				g = gg
			} else {
				g = "{11111111-2222-3333-4444-555555555555}"
			}
		}
		kp := e.keyPath
		if kp == nil && len(e.files) > 0 {
			first := e.files[0]
			logical := e.dirID + "/" + first.name
			kp = generateMSIFileID(logical, nil)
		}
		db.WithComponent(cid, g, e.dirID, e.attrs, kp)

		for _, f := range e.files {
			hasFiles = true
			logical := e.dirID + "/" + f.name
			fid := generateMSIFileID(logical, nil)

			// File.FileName column gets the short|long form from the *directory's*
			// namer (not a global one). This matches how real MSIs and the
			// legacy flat path (per-dir in tree model) behave.
			fnamer := dirNamers[e.dirID]
			if fnamer == nil {
				fnamer = newMSIShortNamer()
				dirNamers[e.dirID] = fnamer
			}
			fileNameColumn, err := fnamer.msiFileNameColumn(f.name)
			if err != nil {
				return nil, fmt.Errorf("msi compile: File %s name %q: %w", fid, f.name, err)
			}

			db.WithFileSource(cid, fid, fileNameColumn, f.src, f.version, seqByFile[fid])
		}
	}

	// Features + FeatureComponents (for legacy flat parity "MainFeature" and
	// user multi-feature models). Emit after comps (matching legacy phase
	// order for stringpool determinism). Associations driven from comp side
	// (model may populate bidirectionally; dedup not strictly needed because
	// PK on the join table, but we emit once).
	featNames := make([]string, 0, len(p.featEntries))
	for id := range p.featEntries {
		featNames = append(featNames, id)
	}
	sort.Strings(featNames)
	for _, fid := range featNames {
		e := p.featEntries[fid]
		db.WithFeature(fid, e.title, e.desc, e.display, e.level)
	}
	// Assocs (after both comps and feats exist). Walk both directions so that
	// user code using either Component.AssociateToFeature *or* Feature.AssociateComponent
	// (as in the rt parity construction) produces the join row.
	seenAssoc := map[string]bool{}
	emitAssoc := func(fid, cid string) {
		key := fid + "\x00" + cid
		if seenAssoc[key] {
			return
		}
		seenAssoc[key] = true
		db.AssociateComponentToFeature(fid, cid)
	}
	for _, cid := range compNames {
		for _, fid := range p.compEntries[cid].featAssocs {
			emitAssoc(fid, cid)
		}
	}
	for _, fid := range featNames {
		for _, cid := range p.featEntries[fid].compAssocs {
			emitAssoc(fid, cid)
		}
	}

	if len(p.shortcutEntries) > 0 {
		scTbl := createMSITableFromCatalog("Shortcut")
		for i, e := range p.shortcutEntries {
			scID := fmt.Sprintf("sc%02d_%s", i, sanitizeIDSegment(e.component))
			// Target is a Formatted column: for a non-advertised shortcut it is a
			// File-key reference like "[#FileKey]" passed through verbatim; for an
			// advertised shortcut it is the Feature name that replaces it.
			target := e.target
			if e.advertisedFeature != "" {
				target = e.advertisedFeature
			}
			// Hotkey/Icon_/IconIndex are nullable: emit NULL (nil) rather than a
			// stored 0 when there is no hotkey / no icon. storedMSICellValue would
			// otherwise encode int16(0) as a real stored 0, misrepresenting
			// "no hotkey" / "no icon index". No hotkey support yet -> always nil.
			var iconName any
			var iconIndex any
			if e.iconName != "" {
				iconName = e.iconName
				iconIndex = e.iconIndex
			}
			dir := e.directory
			if dir == "" {
				dir = "INSTALLFOLDER"
			}
			row := newMSIRowBuilder().WithColumns(scTbl.columns()...).
				WithValues(scID, dir, e.name, e.component, target, e.arguments, e.description, nil, iconName, iconIndex, int16(1), "").Build()
			if err := scTbl.addRow(row); err != nil {
				return nil, fmt.Errorf("msi compile: Shortcut row %s: %w", scID, err)
			}
		}
		db.WithTable(scTbl)
	}

	// P3: Icon and Binary tables (global assets). These embed as discrete CFB
	// side streams stored in a table binary cell, so their bytes are materialized
	// here (bounded — icons/binaries are small author-supplied assets); the bulk
	// streaming win is the cabinet payload, not these.
	if len(p.iconEntries) > 0 {
		iconTbl := createMSITableFromCatalog("Icon")
		for _, e := range p.iconEntries {
			data, err := readAllFromSource(e.src)
			if err != nil {
				return nil, fmt.Errorf("msi compile: Icon %s: %w", e.name, err)
			}
			row := newMSIRowBuilder().WithColumns(iconTbl.columns()...).WithValues(e.name, data).Build()
			if err := iconTbl.addRow(row); err != nil {
				return nil, fmt.Errorf("msi compile: Icon row %s: %w", e.name, err)
			}
		}
		db.WithTable(iconTbl)
	}
	if len(p.binaryEntries) > 0 {
		binTbl := createMSITableFromCatalog("Binary")
		for _, e := range p.binaryEntries {
			data, err := readAllFromSource(e.src)
			if err != nil {
				return nil, fmt.Errorf("msi compile: Binary %s: %w", e.name, err)
			}
			row := newMSIRowBuilder().WithColumns(binTbl.columns()...).WithValues(e.name, data).Build()
			if err := binTbl.addRow(row); err != nil {
				return nil, fmt.Errorf("msi compile: Binary row %s: %w", e.name, err)
			}
		}
		db.WithTable(binTbl)
	}

	// P3: MsiFileHash for unversioned files (MD5 split to 4 i4 HashPart cells).
	//
	// DEFERRED — emitMSIFileHash is currently false. The externally-verified
	// legacy BuildMSI path does NOT emit a MsiFileHash table, and
	// TestMSIPackage_FlatReproParity_rtTestData requires the new flat path to be
	// byte-identical to that legacy output. The rt fixture is entirely
	// unversioned files, so emitting MsiFileHash here would add a table (and its
	// 6 _Validation rows) that legacy lacks, breaking parity. Wiring MsiFileHash
	// into the legacy P0 path is out of scope (it is preserved as the golden), so
	// emission stays off until both paths agree. The row computation below is
	// real (not a stub) and validates against the corrected i4 HashPart catalog;
	// flip emitMSIFileHash to true once the legacy path also emits the table.
	if emitMSIFileHash {
		hashTbl, err := compileMSIFileHashRows(p)
		if err != nil {
			return nil, err
		}
		if hashTbl != nil {
			db.WithTable(hashTbl)
		}
	}

	// P4: service tables (ServiceInstall/ServiceControl + config/failure-actions).
	if err := emitMSIServiceTables(p, db); err != nil {
		return nil, err
	}

	// P4: Upgrade + LaunchCondition tables (incl. synthesized MajorUpgrade rows).
	if err := emitMSIUpgradeTables(p, db); err != nil {
		return nil, err
	}

	// P4: AppSearch / Signature / locator tables.
	if err := emitMSISearchTables(p, db); err != nil {
		return nil, err
	}

	// P5: CustomAction table (scheduling into sequence tables happens below).
	if err := emitMSICustomActionTable(p, db); err != nil {
		return nil, err
	}

	// P6: emit TextStyle/UIText and the dialog/control tables (the canned UI
	// model was already synthesized near the top, before property emission).
	if err := emitMSITextStyleAndUIText(p, db); err != nil {
		return nil, err
	}
	if err := emitMSIUITables(p, db); err != nil {
		return nil, err
	}

	if hasFiles {
		// P7: one Media row per planned cabinet (embedded "#name" or external
		// "name"). The default single-disk plan reproduces the historical
		// (1, N, "#cab1.cab") row exactly.
		for _, m := range mediaPlan {
			cabRef := m.cabinet
			if !m.external {
				cabRef = "#" + m.cabinet
			}
			db.WithMedia(m.diskID, m.lastSequence, cabRef)
		}
	}

	// Always emit the canonical standard actions across all five sequence
	// tables (WiX numbers). This matches the legacy BuildMSI behavior
	// exactly and is required for ICE26 and a functional installer.
	// Custom actions (inserted between neighbors) come in later phases.
	for table, actions := range map[string][]msiSequenceRow{
		msiInstallExecSeqTableName: msiInstallExecuteActions,
		msiInstallUISeqTableName:   msiInstallUIActions,
		msiAdminExecSeqTableName:   msiAdminExecuteActions,
		msiAdminUISeqTableName:     msiAdminUIActions,
		msiAdvtExecSeqTableName:    msiAdvtExecuteActions,
	} {
		for _, a := range actions {
			db.WithSequenceAction(table, a.action, nil, a.sequence)
		}
	}

	// P4: conditional standard actions (services/upgrade/appsearch/launch
	// conditions) injected only when their trigger table is populated. Files-only
	// packages keep the exact base action set (parity + ICE26 preserved).
	injectConditionalActions(p, db)

	// P5: place user custom actions into their target sequence table(s),
	// resolving After/Before/At against the effective schedule above.
	if err := scheduleCustomActions(p, db); err != nil {
		return nil, err
	}

	// Finalize (adds core required tables, _Validation for present tables,
	// system catalog, and runs internal validate()).
	return db.Build()
}

// msiStandardDirectories are the predefined Windows Installer directory
// identifiers that resolve to well-known locations at install time. They live
// directly under TARGETDIR with a DefaultDir of "." (the installer substitutes
// the real path). They are created on demand when referenced (e.g. by a
// shortcut's InDirectory) so callers need not declare them.
var msiStandardDirectories = map[string]bool{
	"ProgramMenuFolder": true, "StartMenuFolder": true, "StartupFolder": true,
	"DesktopFolder": true, "FavoritesFolder": true, "SendToFolder": true,
	"AppDataFolder": true, "LocalAppDataFolder": true, "CommonAppDataFolder": true,
	"PersonalFolder": true, "TemplateFolder": true, "NetHoodFolder": true,
	"PrintHoodFolder": true, "RecentFolder": true, "AdminToolsFolder": true,
	"ProgramFilesFolder": true, "ProgramFiles64Folder": true,
	"CommonFilesFolder": true, "CommonFiles64Folder": true,
	"WindowsFolder": true, "SystemFolder": true, "System64Folder": true,
	"System16Folder": true, "FontsFolder": true, "TempFolder": true,
	"WindowsVolume": true,
}

// ensureStandardDirectory adds a referenced directory to the model if it is not
// already declared and is a recognized standard Windows Installer directory
// (rooted at TARGETDIR, DefaultDir "."). Non-standard, undeclared directories
// are left alone so the FK/category ICEs surface the authoring mistake.
func ensureStandardDirectory(p *msiPackage, dirID string) {
	if p == nil || dirID == "" {
		return
	}
	if _, ok := p.dirEntries[dirID]; ok {
		return
	}
	if msiStandardDirectories[dirID] {
		if _, ok := p.dirEntries["TARGETDIR"]; !ok {
			p.dirEntries["TARGETDIR"] = &dirEntry{id: "TARGETDIR", defaultDir: "SourceDir"}
		}
		p.dirEntries[dirID] = &dirEntry{id: dirID, parent: "TARGETDIR", defaultDir: "."}
	}
}

// ensureRootDirectories guarantees the conventional TARGETDIR and a primary
// install directory exist so that harvesting or a completely empty dir model
// still produces a valid tree. compileMSIPackage calls it unconditionally at
// the top of the walk so that the new path matches the legacy flat roots
// (TARGETDIR + INSTALLFOLDER) required for flat-repro parity.
func ensureRootDirectories(p *msiPackage, installID, installDefault string) {
	if p == nil {
		return
	}
	if _, ok := p.dirEntries["TARGETDIR"]; !ok {
		p.dirEntries["TARGETDIR"] = &dirEntry{id: "TARGETDIR", defaultDir: "SourceDir"}
	}
	if installID != "" {
		if e, ok := p.dirEntries[installID]; !ok || e.parent == "" {
			// create or fix parent link
			if e == nil {
				e = &dirEntry{id: installID}
				p.dirEntries[installID] = e
			}
			e.parent = "TARGETDIR"
			if e.defaultDir == "" {
				e.defaultDir = installDefault
			}
		}
	}
}
