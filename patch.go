package msi

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
)

// msi_patch.go — P10 Windows Installer patch (.msp) generator.
//
// An .msp is a CFB (root CLSID {000C1086-…}) carrying: the base→upgraded
// transform set (a product transform "P0" + a metadata transform "#P0"), the
// patch's own database (MsiPatchMetadata + MsiPatchSequence), and an embedded
// cabinet of the new/changed file payloads. msiexec applies it by replaying the
// transforms onto the installed product database and staging the patch cab.
//
// Scope (user-chosen): small + minor updates, whole-file replacement. The base
// and upgraded packages must share the same ProductCode; the upgraded package
// may add features/components/files but must not remove or reorganize existing
// ones (stable primary keys). Binary-delta patching is a documented non-goal.

// PatchBuilder builds an .msp from the difference between two MSI packages.
type PatchBuilder interface {
	From(base Package) PatchBuilder
	To(upgraded Package) PatchBuilder
	WithPatchCode(guid string) PatchBuilder
	WithClassification(c string) PatchBuilder
	WithDisplayName(name string) PatchBuilder
	WithDescription(desc string) PatchBuilder
	WithManufacturerName(m string) PatchBuilder
	WithTargetProductName(n string) PatchBuilder
	WithMoreInfoURL(u string) PatchBuilder
	AllowRemoval(allow bool) PatchBuilder
	WithPatchFamily(family, sequence string) PatchBuilder
	SupersedeEarlier(b bool) PatchBuilder
	WithMinInstallerVersion(v int) PatchBuilder
	WithObsoletedPatch(guid string) PatchBuilder
	Build() (Patch, error)
}

// Patch is a built patch; WriteMSP emits the standalone .msp file.
type Patch interface {
	WriteMSP(w io.Writer) error
}

// msiPatchNamespaceGUID namespaces deterministic default patch codes.
const msiPatchNamespaceGUID = "{6B9E2F1A-1C7D-4E3B-9A2F-2D5C8E0B14A7}"

// patch transform sub-storage names (on-disk; the colon in the PID8 list is
// added when serializing the summary, never stored in the name).
const (
	msiPatchProductTransformName  = "P0"
	msiPatchMetadataTransformName = "#P0"
	msiPatchCabinetName           = "patch.cab"       // embedded as "#patch.cab"
	msiPatchSourceProperty        = "PATCHNEWPACKAGE" // Media.Source for the patch cab
)

// NewPatch returns a builder for a base→upgraded patch.
func NewPatch() PatchBuilder { return &msiPatch{minInstVer: 4} }

type msiPatch struct {
	base, upgraded *msiPackage

	patchCode      string
	classification string
	displayName    string
	description    string
	manufacturer   string
	targetProduct  string
	moreInfoURL    string
	allowRemoval   bool
	patchFamily    string
	patchSequence  string
	supersede      bool
	minInstVer     int
	obsoleted      []string

	// Populated by Build.
	baseDB      msiDatabase
	upDB        msiDatabase
	minorUpd    bool              // upgraded ProductVersion differs from base
	changes     []patchFileChange // new/changed file payloads, sorted by File id
	patchDiskID int16             // reserved Media DiskId for the patch cab
	streams     []msiStream       // root streams (set in P10.4)
	subs        []msiSubStorage   // P0 + #P0 transforms (set in P10.3/P10.4)
}

// patchFileChange is one file the patch delivers (new or content-changed). The
// payload is carried as a re-openable source (streamed from the upgraded MSI's
// cabinet) so neither version's full file set is ever resident in memory.
type patchFileChange struct {
	fileID   string
	source   FileSource
	isNew    bool
	sequence int16 // assigned in the patch cab order (base max + 1, …)
}

func (p *msiPatch) From(base Package) PatchBuilder {
	if b, ok := base.(*msiPackage); ok {
		p.base = b
	}
	return p
}

func (p *msiPatch) To(upgraded Package) PatchBuilder {
	if u, ok := upgraded.(*msiPackage); ok {
		p.upgraded = u
	}
	return p
}

func (p *msiPatch) WithPatchCode(guid string) PatchBuilder      { p.patchCode = guid; return p }
func (p *msiPatch) WithClassification(c string) PatchBuilder    { p.classification = c; return p }
func (p *msiPatch) WithDisplayName(name string) PatchBuilder    { p.displayName = name; return p }
func (p *msiPatch) WithDescription(desc string) PatchBuilder    { p.description = desc; return p }
func (p *msiPatch) WithManufacturerName(m string) PatchBuilder  { p.manufacturer = m; return p }
func (p *msiPatch) WithTargetProductName(n string) PatchBuilder { p.targetProduct = n; return p }
func (p *msiPatch) WithMoreInfoURL(u string) PatchBuilder       { p.moreInfoURL = u; return p }
func (p *msiPatch) AllowRemoval(allow bool) PatchBuilder        { p.allowRemoval = allow; return p }
func (p *msiPatch) SupersedeEarlier(b bool) PatchBuilder        { p.supersede = b; return p }
func (p *msiPatch) WithMinInstallerVersion(v int) PatchBuilder  { p.minInstVer = v; return p }

func (p *msiPatch) WithPatchFamily(family, sequence string) PatchBuilder {
	p.patchFamily = family
	p.patchSequence = sequence
	return p
}

func (p *msiPatch) WithObsoletedPatch(guid string) PatchBuilder {
	p.obsoleted = append(p.obsoleted, guid)
	return p
}

func (p *msiPatch) Build() (Patch, error) {
	if p.base == nil || p.upgraded == nil {
		return nil, fmt.Errorf("msi patch: both From(base) and To(upgraded) are required")
	}
	if _, err := p.base.Build(); err != nil {
		return nil, fmt.Errorf("msi patch: base: %w", err)
	}
	if _, err := p.upgraded.Build(); err != nil {
		return nil, fmt.Errorf("msi patch: upgraded: %w", err)
	}

	baseDB, err := compileMSIPackage(p.base)
	if err != nil {
		return nil, fmt.Errorf("msi patch: compiling base: %w", err)
	}
	upDB, err := compileMSIPackage(p.upgraded)
	if err != nil {
		return nil, fmt.Errorf("msi patch: compiling upgraded: %w", err)
	}
	p.baseDB, p.upDB = baseDB, upDB

	if err := p.assertPatchScope(); err != nil {
		return nil, err
	}
	p.minorUpd = p.base.version != p.upgraded.version

	if p.patchCode == "" {
		seed := "patch|" + p.base.productCode + "|" + p.base.version + "->" + p.upgraded.version
		code, gerr := msiGUIDv5(msiPatchNamespaceGUID, seed)
		if gerr != nil {
			return nil, fmt.Errorf("msi patch: deriving patch code: %w", gerr)
		}
		p.patchCode = code
	}
	if p.classification == "" {
		p.classification = "Update"
	}

	// File diff + patch cabinet (P10.2). The product/metadata transforms (P10.3)
	// and the .msp assembly (P10.4) build on these.
	if err := p.computeFileChanges(); err != nil {
		return nil, err
	}

	return p, nil
}

// WriteMSP emits the .msp file: the patch summary + own database
// (MsiPatchMetadata/MsiPatchSequence) + the embedded patch cabinet at the root,
// plus the product ("P0") and metadata ("#P0") transform sub-storages.
func (p *msiPatch) WriteMSP(w io.Writer) error {
	if p.baseDB == nil {
		if _, err := p.Build(); err != nil {
			return err
		}
	}

	// Root: patch summary + the .msp's own database tables/pool.
	rootStreams, err := p.buildPatchDatabaseStreams()
	if err != nil {
		return err
	}

	// Root: the embedded patch cabinet ("#patch.cab" -> stream "patch.cab").
	cab, err := p.buildPatchCab()
	if err != nil {
		return err
	}
	if cab != nil {
		rootStreams = append(rootStreams, msiStream{
			name: encodeMSIStreamName(false, msiPatchCabinetName),
			data: cab,
		})
	}

	// Sub-storages: the two transforms (CLSID = transform CLSID).
	productStreams, err := p.buildPatchProductTransform()
	if err != nil {
		return fmt.Errorf("msi patch: product transform: %w", err)
	}
	metaStreams, err := p.buildPatchMetadataTransform()
	if err != nil {
		return fmt.Errorf("msi patch: metadata transform: %w", err)
	}
	subs := []msiSubStorage{
		{name: msiPatchProductTransformName, clsid: msiTransformCLSID, streams: productStreams},
		{name: msiPatchMetadataTransformName, clsid: msiTransformCLSID, streams: metaStreams},
	}

	tmp, err := os.CreateTemp("", "go-msix-*.msp")
	if err != nil {
		return fmt.Errorf("msi patch: temp for cfb: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	defer tmp.Close()

	if err := writeMSICFBWithSubStorages(rootStreams, subs, msiPatchCLSID, tmp); err != nil {
		return fmt.Errorf("msi patch: emitting CFB: %w", err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("msi patch: seek temp: %w", err)
	}
	if _, err := io.Copy(w, tmp); err != nil {
		return fmt.Errorf("msi patch: copy cfb to output: %w", err)
	}
	return nil
}

// summaryInfo builds the .msp \x05SummaryInformation: PID7 Template is the
// target ProductCode(s), PID8 lists the ":"-prefixed transforms, PID9 is the
// patch code (plus any obsoleted patch GUIDs, concatenated), PID14 is omitted
// and PID15 carries the minimum installer version.
func (p *msiPatch) summaryInfo() msiSummaryInfo {
	revision := p.patchCode
	for _, o := range p.obsoleted {
		revision += o // obsolete patch GUIDs are concatenated with no delimiter
	}
	transforms := ":" + msiPatchProductTransformName + ";:" + msiPatchMetadataTransformName
	subject := p.displayName
	if subject == "" {
		subject = p.description
	}
	return msiSummaryInfo{
		Codepage:       1252,
		Title:          "Patch",
		Subject:        subject,
		Author:         p.manufacturer,
		Comments:       p.description,
		Template:       p.base.productCode,
		LastSavedBy:    transforms,
		RevisionNumber: revision,
		CreatingApp:    "go-msix",
		CreateTime:     msiBuildTime,
		SaveTime:       msiBuildTime,
		OmitPageCount:  true,
		WordCount:      p.minInstVer,
		Security:       4,
	}
}

// buildPatchDatabaseStreams serializes the .msp's own database (the patch
// summary + MsiPatchMetadata + optional MsiPatchSequence + the system catalog +
// string pool). It carries no cabinet (the patch cab is appended separately).
func (p *msiPatch) buildPatchDatabaseStreams() ([]msiStream, error) {
	db := newMSIDatabaseBuilder()

	meta := createMSIMsiPatchMetadataTable()
	addMeta := func(prop, val string) error {
		if val == "" {
			return nil
		}
		row := newMSIRowBuilder().WithColumns(meta.columns()...).WithValues(nil, prop, val).Build()
		return meta.addRow(row)
	}
	for _, kv := range [][2]string{
		{"Classification", p.classification},
		{"DisplayName", p.displayName},
		{"Description", p.description},
		{"ManufacturerName", p.manufacturer},
		{"TargetProductName", p.targetProduct},
		{"MoreInfoURL", p.moreInfoURL},
		{"AllowRemoval", boolDigit(p.allowRemoval)},
	} {
		if err := addMeta(kv[0], kv[1]); err != nil {
			return nil, fmt.Errorf("msi patch: MsiPatchMetadata %s: %w", kv[0], err)
		}
	}
	db.WithTable(meta)

	if p.patchFamily != "" {
		seq := createMSIMsiPatchSequenceTable()
		var attrs any
		if p.supersede {
			attrs = int16(0x1)
		}
		sequence := p.patchSequence
		if sequence == "" {
			sequence = "1.0.0"
		}
		row := newMSIRowBuilder().WithColumns(seq.columns()...).
			WithValues(p.patchFamily, nil, sequence, attrs).Build()
		if err := seq.addRow(row); err != nil {
			return nil, fmt.Errorf("msi patch: MsiPatchSequence: %w", err)
		}
		db.WithTable(seq)
	}

	built, err := db.Build()
	if err != nil {
		return nil, fmt.Errorf("msi patch: building patch database: %w", err)
	}
	return serializeMSIStreams(built, p.summaryInfo(), cabBuildOptions{})
}

// boolDigit renders a bool as the MSI "1"/"0" string ("" stays "" via callers
// that skip empty — here false is meaningful, so always return a digit).
func boolDigit(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// assertPatchScope enforces the small/minor-update scope: same ProductCode,
// every base table present in upgraded with identical columns, and no removal of
// existing Components/Features (stable primary keys; additions are allowed).
func (p *msiPatch) assertPatchScope() error {
	if p.base.productCode != p.upgraded.productCode {
		return fmt.Errorf("msi patch: ProductCode must be unchanged for a small/minor patch (base %s, upgraded %s); a major upgrade is not a patch", p.base.productCode, p.upgraded.productCode)
	}
	for _, name := range p.baseDB.Tables() {
		if name == msiTablesTableName || name == msiColumnsTableName {
			continue
		}
		bt, _ := p.baseDB.GetTable(name)
		ut, err := p.upDB.GetTable(name)
		if err != nil {
			return fmt.Errorf("msi patch: table %s present in base but missing in upgraded; patches cannot remove tables", name)
		}
		bc, uc := bt.columns(), ut.columns()
		if len(bc) != len(uc) {
			return fmt.Errorf("msi patch: table %s column count changed (%d -> %d); patches cannot reorganize schema", name, len(bc), len(uc))
		}
		for i := range bc {
			if bc[i].name() != uc[i].name() || bc[i].typ() != uc[i].typ() {
				return fmt.Errorf("msi patch: table %s column %d changed; patches cannot reorganize schema", name, i)
			}
		}
	}
	// No removal of existing components/features (additions are fine).
	for _, tbl := range []string{"Component", "Feature"} {
		if err := p.assertNoKeyRemoval(tbl); err != nil {
			return err
		}
	}
	return nil
}

// assertNoKeyRemoval verifies every primary key present in the base table still
// exists in the upgraded table.
func (p *msiPatch) assertNoKeyRemoval(table string) error {
	bt, berr := p.baseDB.GetTable(table)
	if berr != nil {
		return nil // base doesn't use the table; nothing to preserve
	}
	ut, uerr := p.upDB.GetTable(table)
	if uerr != nil {
		if len(bt.rows()) == 0 {
			return nil
		}
		return fmt.Errorf("msi patch: %s table removed in upgraded; patches cannot remove %s rows", table, table)
	}
	keyIdx := keyColumnIndexes(bt.columns())
	upKeys := map[string]bool{}
	for _, r := range ut.rows() {
		upKeys[rowKeyString(r.values(), keyIdx)] = true
	}
	for _, r := range bt.rows() {
		k := rowKeyString(r.values(), keyIdx)
		if !upKeys[k] {
			return fmt.Errorf("msi patch: %s row %q removed in upgraded; small/minor patches cannot remove %s rows", table, firstStringCell(r.values()), table)
		}
	}
	return nil
}

// computeFileChanges diffs the base and upgraded File tables by content and
// assembles the ordered list of new/changed payloads plus their patch sequence
// numbers (appended above the base's highest File.Sequence) and the reserved
// patch cabinet DiskId.
func (p *msiPatch) computeFileChanges() error {
	baseSrcs := p.baseDB.FileSources()
	upSrcs := p.upDB.FileSources()

	baseIDs := fileIDSet(p.baseDB)

	upTbl, err := p.upDB.GetTable(msiFileTableName)
	if err != nil {
		// No files at all: a metadata-only patch. Nothing to stage.
		return nil
	}

	var ids []string
	for _, r := range upTbl.rows() {
		if id, ok := r.values()[0].(string); ok && id != "" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)

	for _, id := range ids {
		upSrc := upSrcs[id]
		if upSrc == nil {
			return fmt.Errorf("msi patch: upgraded File %q has no staged content", id)
		}
		if !baseIDs[id] {
			p.changes = append(p.changes, patchFileChange{fileID: id, source: upSrc, isNew: true})
			continue
		}
		// Stream-compare the base and upgraded payloads one file at a time: a
		// Size mismatch short-circuits without reading, otherwise the two sources
		// are read in lockstep. Neither MSI's whole file set is ever resident.
		differ, err := fileSourcesDiffer(baseSrcs[id], upSrc)
		if err != nil {
			return fmt.Errorf("msi patch: comparing File %q: %w", id, err)
		}
		if differ {
			p.changes = append(p.changes, patchFileChange{fileID: id, source: upSrc, isNew: false})
		}
	}

	// Assign patch sequence numbers and a Media DiskId in the ranges Windows
	// reserves for patch-inserted rows. The Windows patch sequencer expects a
	// patch transform to insert Media.DiskId >= msiPatchMinDiskID (100) and
	// File/Patch.Sequence >= msiPatchMinSequence (10000) so they do not collide
	// with the base product's media/sequence space; values below these reserved
	// floors are not recognized as patch-inserted. We also keep them above the
	// base's own maxima for safety.
	nextSeq := maxFileSequence(p.baseDB) + 1
	if nextSeq < msiPatchMinSequence {
		nextSeq = msiPatchMinSequence
	}
	for i := range p.changes {
		if nextSeq > 32767 {
			return fmt.Errorf("msi patch: patched file sequence exceeds the 32767 i2 ceiling")
		}
		p.changes[i].sequence = nextSeq
		nextSeq++
	}
	p.patchDiskID = maxMediaDiskID(p.baseDB) + 1
	if p.patchDiskID < msiPatchMinDiskID {
		p.patchDiskID = msiPatchMinDiskID
	}
	return nil
}

// msiPatchMinSequence and msiPatchMinDiskID are the floors Windows reserves for
// rows inserted by a patch transform (File/Patch.Sequence and Media.DiskId
// respectively). See computeFileChanges.
const (
	msiPatchMinSequence int16 = 10000
	msiPatchMinDiskID   int16 = 100
)

// patchCabMembers returns the cabinet members for the staged changes, in patch
// sequence order (cabinet order must match Patch.Sequence).
func (p *msiPatch) patchCabMembers() []msiCabMember {
	members := make([]msiCabMember, 0, len(p.changes))
	for _, c := range p.changes {
		members = append(members, msiCabMember{name: c.fileID, src: c.source})
	}
	return members
}

// fileSourcesDiffer reports whether base and up have different content,
// streaming both: a Size mismatch (or a missing base) short-circuits without
// reading; equal sizes trigger a lockstep byte comparison.
func fileSourcesDiffer(base, up FileSource) (bool, error) {
	if base == nil {
		return true, nil
	}
	if base.Size() != up.Size() {
		return true, nil
	}
	equal, err := sourcesEqualContent(base, up)
	if err != nil {
		return false, err
	}
	return !equal, nil
}

// sourcesEqualContent streams two equal-size sources and reports whether their
// bytes are identical, holding at most one chunk of each in memory.
func sourcesEqualContent(a, b FileSource) (bool, error) {
	ra, err := a.Open()
	if err != nil {
		return false, err
	}
	defer ra.Close()
	rb, err := b.Open()
	if err != nil {
		return false, err
	}
	defer rb.Close()

	const chunk = 64 << 10
	ba := make([]byte, chunk)
	bb := make([]byte, chunk)
	for {
		na, ea := io.ReadFull(ra, ba)
		nb, eb := io.ReadFull(rb, bb)
		if na != nb || !bytes.Equal(ba[:na], bb[:nb]) {
			return false, nil
		}
		aEnd := ea == io.EOF || ea == io.ErrUnexpectedEOF
		if aEnd {
			return true, nil // equal length (sizes matched) and bytes equal so far
		}
		if ea != nil {
			return false, ea
		}
		if eb != nil && eb != io.EOF && eb != io.ErrUnexpectedEOF {
			return false, eb
		}
	}
}

// buildPatchCab builds the embedded patch cabinet from the staged changes.
func (p *msiPatch) buildPatchCab() ([]byte, error) {
	members := p.patchCabMembers()
	if len(members) == 0 {
		return nil, nil
	}
	return buildMSICAB(members)
}

// --- small table helpers ---

// fileIDSet returns the set of File primary keys present in db.
func fileIDSet(db msiDatabase) map[string]bool {
	out := map[string]bool{}
	tbl, err := db.GetTable(msiFileTableName)
	if err != nil {
		return out
	}
	for _, r := range tbl.rows() {
		if id, ok := r.values()[0].(string); ok {
			out[id] = true
		}
	}
	return out
}

// maxFileSequence returns the highest File.Sequence in db (0 if no File table).
func maxFileSequence(db msiDatabase) int16 {
	tbl, err := db.GetTable(msiFileTableName)
	if err != nil {
		return 0
	}
	var max int16
	for _, r := range tbl.rows() {
		if seq, ok := r.values()[7].(int16); ok && seq > max {
			max = seq
		}
	}
	return max
}

// maxMediaDiskID returns the highest Media.DiskId in db (0 if no Media table).
func maxMediaDiskID(db msiDatabase) int16 {
	tbl, err := db.GetTable(msiMediaTableName)
	if err != nil {
		return 0
	}
	var max int16
	for _, r := range tbl.rows() {
		if d, ok := r.values()[0].(int16); ok && d > max {
			max = d
		}
	}
	return max
}

// firstStringCell returns the first string cell of a row, for error messages.
func firstStringCell(vals []any) string {
	for _, v := range vals {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return "?"
}
