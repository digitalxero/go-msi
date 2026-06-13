package msi

// msi_patch_internal_test.go — P10 patch generator (file diff, cab, transforms,
// assembly, structural round-trip).

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	p10ProductCode = "{C0C0C0C0-1111-2222-3333-444444444444}"
	p10UpgradeCode = "{D0D0D0D0-1111-2222-3333-444444444444}"
)

// p10Base builds the originally-shipped product: two files under one component.
func p10Base(t *testing.T) *msiPackage {
	t.Helper()
	b := NewPackage().
		WithProductCode(p10ProductCode).
		WithUpgradeCode(p10UpgradeCode).
		WithProductName("Patch Target").
		WithManufacturer("go-msix").
		WithVersion("1.0.0")
	c := b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F")
	c.WithFile("a.exe", []byte("MZ original a content"))
	c.WithFile("b.dat", []byte("shared b content"))
	b.Feature("F").WithLevel(1)
	pkg, err := b.Build()
	require.NoError(t, err)
	return pkg.(*msiPackage)
}

// p10Upgraded builds the new product: a.exe changed, b.dat unchanged, c.dat new.
// version bumps (a minor update). Same ProductCode/UpgradeCode.
func p10Upgraded(t *testing.T) *msiPackage {
	t.Helper()
	b := NewPackage().
		WithProductCode(p10ProductCode).
		WithUpgradeCode(p10UpgradeCode).
		WithProductName("Patch Target").
		WithManufacturer("go-msix").
		WithVersion("1.0.1")
	c := b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F")
	c.WithFile("a.exe", []byte("MZ NEW a content, longer than before"))
	c.WithFile("b.dat", []byte("shared b content"))
	c.WithFile("c.dat", []byte("brand new c content"))
	b.Feature("F").WithLevel(1)
	pkg, err := b.Build()
	require.NoError(t, err)
	return pkg.(*msiPackage)
}

// fileNameByID maps File primary key -> FileName for a built db.
func fileNameByID(t *testing.T, db msiDatabase) map[string]string {
	t.Helper()
	out := map[string]string{}
	tbl, err := db.GetTable(msiFileTableName)
	require.NoError(t, err)
	for _, r := range tbl.rows() {
		vals := r.values()
		id, _ := vals[0].(string)
		name, _ := vals[2].(string)
		out[id] = name
	}
	return out
}

func TestPatch_FileDiff(t *testing.T) {
	patch, err := NewPatch().
		From(p10Base(t)).
		To(p10Upgraded(t)).
		WithClassification("Update").
		Build()
	require.NoError(t, err)
	mp := patch.(*msiPatch)

	require.Len(t, mp.changes, 2, "a.exe changed + c.dat new (b.dat unchanged is skipped)")

	names := fileNameByID(t, mp.upDB)
	var sawChangedAExe, sawNewCDat bool
	for _, ch := range mp.changes {
		name := names[ch.fileID]
		switch {
		case contains(name, "a.exe"):
			sawChangedAExe = true
			assert.False(t, ch.isNew, "a.exe is a content change, not new")
		case contains(name, "c.dat"):
			sawNewCDat = true
			assert.True(t, ch.isNew, "c.dat is a new file")
		default:
			t.Fatalf("unexpected change for file %q (%s)", ch.fileID, name)
		}
	}
	assert.True(t, sawChangedAExe, "changed a.exe present")
	assert.True(t, sawNewCDat, "new c.dat present")

	// Patch sequences are appended above the base's highest File.Sequence (2),
	// and the reserved patch DiskId is above the base's highest (1).
	for _, ch := range mp.changes {
		assert.Greater(t, ch.sequence, int16(2), "patch sequence appended above base max")
	}
	assert.Equal(t, int16(2), mp.patchDiskID, "reserved patch DiskId is base max + 1")
}

func TestPatch_Cab(t *testing.T) {
	patch, err := NewPatch().From(p10Base(t)).To(p10Upgraded(t)).Build()
	require.NoError(t, err)
	mp := patch.(*msiPatch)

	cab, err := mp.buildPatchCab()
	require.NoError(t, err)
	require.NotEmpty(t, cab)
	assert.Equal(t, []byte("MSCF"), cab[:4], "patch cab has the MS-CAB signature")

	// Members are keyed by File id in sequence order.
	members := mp.patchCabMembers()
	require.Len(t, members, 2)
	ids := map[string]bool{}
	for _, m := range members {
		ids[m.name] = true
	}
	for _, ch := range mp.changes {
		assert.True(t, ids[ch.fileID], "cab carries every changed/new file")
	}
}

func TestPatch_DefaultPatchCodeDerived(t *testing.T) {
	patch, err := NewPatch().From(p10Base(t)).To(p10Upgraded(t)).Build()
	require.NoError(t, err)
	mp := patch.(*msiPatch)
	assert.Regexp(t, `^\{[0-9A-F-]{36}\}$`, mp.patchCode, "default patch code is a braced GUID")
	assert.Equal(t, "Update", mp.classification, "default classification")
}

func TestPatch_RejectsDifferentProductCode(t *testing.T) {
	up := p10Upgraded(t)
	up.productCode = "{FFFFFFFF-1111-2222-3333-444444444444}" // simulate a major upgrade
	_, err := NewPatch().From(p10Base(t)).To(up).Build()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ProductCode must be unchanged")
}

func TestPatch_RejectsComponentRemoval(t *testing.T) {
	// Upgraded drops a component present in the base -> not a valid patch.
	base := p10Base(t)
	// A base with an extra component the upgraded lacks.
	bx := NewPackage().
		WithProductCode(p10ProductCode).WithUpgradeCode(p10UpgradeCode).
		WithProductName("Patch Target").WithManufacturer("go-msix").WithVersion("1.0.0")
	d := bx.RootDirectory("INSTALLFOLDER", "App")
	d.Component("Main").AssociateToFeature("F").WithFile("a.exe", []byte("a"))
	d.Component("Extra").AssociateToFeature("F").WithFile("x.dat", []byte("x"))
	bx.Feature("F").WithLevel(1)
	basePkg, err := bx.Build()
	require.NoError(t, err)

	_, err = NewPatch().From(basePkg.(*msiPackage)).To(base).Build()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot remove")
}

func contains(s, sub string) bool { return bytes.Contains([]byte(s), []byte(sub)) }

func TestPatch_ProductTransformApplies(t *testing.T) {
	patch, err := NewPatch().From(p10Base(t)).To(p10Upgraded(t)).Build()
	require.NoError(t, err)
	mp := patch.(*msiPatch)

	streams, err := mp.buildPatchProductTransform()
	require.NoError(t, err)
	applied, err := applyMSITransform(mp.baseDB, streams)
	require.NoError(t, err)

	// ProductVersion bumped to the upgraded version.
	var gotVersion string
	for _, row := range applied["Property"].rows {
		if row[0] == "ProductVersion" {
			gotVersion, _ = row[1].(string)
		}
	}
	assert.Equal(t, "1.0.1", gotVersion, "product transform bumps ProductVersion")

	// File table: changed a.exe re-sequenced into the patch range with its new
	// size; new c.dat appended with the PatchAdded attribute.
	names := fileNameByID(t, mp.upDB)
	byName := map[string][]any{}
	for _, row := range applied[msiFileTableName].rows {
		id, _ := row[0].(string)
		byName[names[id]] = row
	}
	aRow := findRowForName(byName, "a.exe")
	require.NotNil(t, aRow, "a.exe present after apply")
	assert.Equal(t, int32(len("MZ NEW a content, longer than before")), aRow[3], "a.exe FileSize updated")
	assert.Greater(t, aRow[7].(int16), int16(2), "a.exe re-sequenced into the patch range")

	cRow := findRowForName(byName, "c.dat")
	require.NotNil(t, cRow, "new c.dat present after apply")
	assert.Equal(t, msidbFileAttributesPatchAdded, orInt16(cRow[6], 0)&msidbFileAttributesPatchAdded, "c.dat marked PatchAdded")

	// b.dat (unchanged) keeps its original base sequence (1 or 2).
	bRow := findRowForName(byName, "b.dat")
	require.NotNil(t, bRow)
	assert.LessOrEqual(t, bRow[7].(int16), int16(2), "unchanged b.dat keeps its base sequence")
}

func TestPatch_MetadataTransformApplies(t *testing.T) {
	patch, err := NewPatch().From(p10Base(t)).To(p10Upgraded(t)).Build()
	require.NoError(t, err)
	mp := patch.(*msiPatch)

	streams, err := mp.buildPatchMetadataTransform()
	require.NoError(t, err)
	applied, err := applyMSITransform(mp.baseDB, streams)
	require.NoError(t, err)

	// Patch: one row per staged file.
	require.Len(t, applied["Patch"].rows, 2, "a Patch row per changed/new file")

	// PatchPackage: the patch GUID against the patch media.
	pp := applied["PatchPackage"].rows
	require.Len(t, pp, 1)
	assert.Equal(t, mp.patchCode, pp[0][0], "PatchPackage.PatchId is the patch code")
	assert.Equal(t, mp.patchDiskID, pp[0][1], "PatchPackage.Media_ is the reserved patch DiskId")

	// Media: the patch cabinet row with a Source (patch-only) and embedded name.
	var patchMedia []any
	for _, row := range applied[msiMediaTableName].rows {
		if d, ok := row[0].(int16); ok && d == mp.patchDiskID {
			patchMedia = row
		}
	}
	require.NotNil(t, patchMedia, "patch Media row present")
	assert.Equal(t, "#"+msiPatchCabinetName, patchMedia[3], "patch Media references the embedded cab")
	assert.Equal(t, msiPatchSourceProperty, patchMedia[5], "patch Media has a Source (patch-only)")
}

func TestPatch_WriteMSP_StructuralShape(t *testing.T) {
	patch, err := NewPatch().
		From(p10Base(t)).
		To(p10Upgraded(t)).
		WithClassification("Update").
		WithDisplayName("Patch Target 1.0.1").
		WithManufacturerName("go-msix").
		AllowRemoval(true).
		WithPatchFamily("PatchTargetFamily", "1.0.1").
		SupersedeEarlier(true).
		Build()
	require.NoError(t, err)
	mp := patch.(*msiPatch)

	var buf bytes.Buffer
	require.NoError(t, mp.WriteMSP(&buf))
	data := buf.Bytes()

	// Summary: PID7 target product code, PID8 transform list, PID9 patch code.
	sum, err := readMSISummaryInfo(bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, "Patch", sum.Title)
	assert.Equal(t, p10ProductCode, sum.Template, "PID7 lists the target ProductCode")
	assert.Equal(t, ":P0;:#P0", sum.LastSavedBy, "PID8 lists the :-prefixed transforms")
	assert.Equal(t, mp.patchCode, sum.RevisionNumber, "PID9 is the patch code")

	// Two transform sub-storages, each with the transform CLSID.
	subs, err := readMSIRawSubStorages(bytes.NewReader(data))
	require.NoError(t, err)
	subByName := map[string]msiSubStorage{}
	for _, s := range subs {
		subByName[s.name] = s
		assert.Equal(t, msiTransformCLSID, s.clsid, "sub-storage %s has the transform CLSID", s.name)
	}
	require.Contains(t, subByName, "P0", "product transform present")
	require.Contains(t, subByName, "#P0", "metadata transform present")

	// Root: the .msp's own database carries MsiPatchMetadata + MsiPatchSequence,
	// and the embedded patch cabinet stream is present.
	raw, err := readMSIRawStreams(bytes.NewReader(data))
	require.NoError(t, err)
	var hasMeta, hasSeq, hasCab bool
	for _, s := range raw {
		name, isTable := decodeMSIStreamName(s.name)
		if isTable {
			switch name {
			case "MsiPatchMetadata":
				hasMeta = true
			case "MsiPatchSequence":
				hasSeq = true
			}
		} else if name == msiPatchCabinetName {
			hasCab = true
			assert.Equal(t, []byte("MSCF"), s.data[:4], "patch cab stream is a cabinet")
		}
	}
	assert.True(t, hasMeta, "MsiPatchMetadata in the .msp database")
	assert.True(t, hasSeq, "MsiPatchSequence in the .msp database")
	assert.True(t, hasCab, "embedded patch cabinet stream present")

	// The .msp's own database parses: MsiPatchMetadata Classification + family.
	db, err := readMSIDatabase(bytes.NewReader(data))
	require.NoError(t, err)
	metaTbl, err := db.GetTable("MsiPatchMetadata")
	require.NoError(t, err)
	classification := ""
	for _, r := range metaTbl.rows() {
		if r.values()[1] == "Classification" {
			classification, _ = r.values()[2].(string)
		}
	}
	assert.Equal(t, "Update", classification)

	seqTbl, err := db.GetTable("MsiPatchSequence")
	require.NoError(t, err)
	require.Len(t, seqTbl.rows(), 1)
	assert.Equal(t, "PatchTargetFamily", seqTbl.rows()[0].values()[0])
	assert.Equal(t, int16(0x1), seqTbl.rows()[0].values()[3], "SupersedeEarlier attribute set")
}

func findRowForName(byName map[string][]any, want string) []any {
	for name, row := range byName {
		if contains(name, want) {
			return row
		}
	}
	return nil
}
