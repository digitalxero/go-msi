package msi_test

import (
	"bytes"
	"os"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	msi "go.digitalxero.dev/go-msi"
)

func TestNewMSIPackage_BasicChainingAndBuild(t *testing.T) {
	// Full chain on root + directory + component + feature.
	// This exercises every public builder interface method at least once
	// (except AddTree and WriteMSI which are exercised in later slices).
	b := msi.NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithUpgradeCode("{ABCDEF01-2345-6789-ABCD-EF0123456789}").
		WithProductName("Skeleton Test App").
		WithManufacturer("go-msix test").
		WithVersion("1.2.3").
		WithAllUsers(true).
		WithProperty("Foo", "Bar").
		WithProperty("ProductLanguage", "1033").
		WithSkipValidation() // test construction uses non-matching KeyPath for chaining demo; real data validated elsewhere

	// Root directory + subdir + component under the subdir.
	install := b.RootDirectory("INSTALLFOLDER", "SkeletonTest")
	sub := install.Subdirectory("SUBDIR", "Sub Dir")
	comp := sub.Component("MainComponent").
		WithGUID("{11111111-2222-3333-4444-555555555555}").
		WithKeyPath("filABC").
		WithAttributes(0).
		AssociateToFeature("MainFeature")

	// File addition returns FileBuilder (version etc.).
	_ = comp.WithFile("app.exe", []byte("MZ..."))

	// Feature configuration.
	b.Feature("MainFeature").
		WithTitle("Main Feature").
		WithDescription("Primary feature").
		WithDisplay(1).
		WithLevel(1).
		WithParent("").
		AssociateComponent("MainComponent")

	// Re-fetching an existing dir by ID must work and be the same logical dir.
	again := b.Directory("INSTALLFOLDER")
	_ = again // just proves the method + handle

	pkg, err := b.Build()
	require.NoError(t, err, "Build should succeed for a minimal valid model")
	require.NotNil(t, pkg)

	// Real emission via the new public API + compile + P0 backend.
	// We don't assert byte-exact legacy parity yet (that is P1G2-051 after
	// full shortnames/sequences/flat repro are in the compiler); we just
	// prove that WriteMSI succeeds and produces a plausible MSI CFB.
	var buf bytes.Buffer
	err = pkg.WriteMSI(&buf)
	require.NoError(t, err, "WriteMSI should now emit a real package")
	require.Greater(t, buf.Len(), 200, "emitted MSI should be larger than a trivial header")
}

func TestNewMSIPackage_AddTreeStub(t *testing.T) {
	// AddTree must be callable on the public builder (even though the
	// real fs.WalkDir + auto-component logic is implemented in a later slice).
	b := msi.NewPackage().
		WithProductName("Harvest Stub").
		WithManufacturer("Tester").
		WithVersion("0.0.1")

	err := b.AddTree(nil, "INSTALLFOLDER", "MainFeature") // fsys may be nil for skeleton
	require.NoError(t, err, "skeleton AddTree returns nil (real work later)")
}

func TestNewMSIPackage_BuildValidation(t *testing.T) {
	// Missing required fields -> error (no Manifest fallback in new API).
	b := msi.NewPackage()
	_, err := b.Build()
	require.Error(t, err)
	require.Contains(t, err.Error(), "ProductName is required")

	b = msi.NewPackage().WithProductName("X").WithManufacturer("Y")
	_, err = b.Build()
	require.Error(t, err)
	require.Contains(t, err.Error(), "Version is required")

	// Bad GUIDs are rejected when supplied (reuses existing msiValidGUID).
	b = msi.NewPackage().
		WithProductName("X").
		WithManufacturer("Y").
		WithVersion("1.0").
		WithProductCode("not-a-guid")
	_, err = b.Build()
	require.Error(t, err)
	require.Contains(t, err.Error(), "ProductCode")

	// Bad version rejected via existing validateMSIVersionString.
	b = msi.NewPackage().
		WithProductName("X").
		WithManufacturer("Y").
		WithVersion("1.0.0.0.0") // too many parts
	_, err = b.Build()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid Version")
}

func TestNewMSIPackage_DirectoryAndComponentReuse(t *testing.T) {
	// Component declared via two different DirectoryBuilder handles for the
	// same ID must end up in the same logical component (last dir wins or
	// first registration sticks; current impl keeps first dirID).
	b := msi.NewPackage().
		WithProductName("Reuse").
		WithManufacturer("T").
		WithVersion("1.0")

	d1 := b.RootDirectory("D1", "D1")
	c1 := d1.Component("SharedComp")
	c1.AssociateToFeature("F1")

	d2 := b.Directory("D1") // same ID
	c2 := d2.Component("SharedComp")
	c2.WithGUID("{A1A2A3A4-B1B2-C1C2-D1D2-E1E2E3E4E5E6}").AssociateToFeature("F2")

	pkg, err := b.Build()
	require.NoError(t, err)
	require.NotNil(t, pkg)
	// If we had introspection we would assert the comp has both features
	// and the original dir; for skeleton the fact that Build succeeded
	// without duplicate-PK panics in the model is sufficient.
}

// TestNewMSIPackage_AddTree proves Goal 2 harvesting: nested directory trees,
// one-component-per-file, files under leaf dirs, all flowing through the
// public builders -> compile -> real WriteMSI.
func TestNewMSIPackage_AddTree(t *testing.T) {
	fsys := fstest.MapFS{
		"app.exe":              &fstest.MapFile{Data: []byte("MZ")},
		"docs/readme.txt":      &fstest.MapFile{Data: []byte("hello")},
		"docs/images/logo.png": &fstest.MapFile{Data: []byte{0x89, 'P', 'N', 'G'}},
		"lib/special name.dll": &fstest.MapFile{Data: make([]byte, 123)},
	}

	b := msi.NewPackage().
		WithProductName("Harvest Demo").
		WithManufacturer("go-msix").
		WithVersion("0.9.0").
		WithProductCode("{DEADBEEF-0000-0000-0000-000000000000}")

	err := b.AddTree(fsys, "INSTALLFOLDER", "MainFeature")
	require.NoError(t, err)
	b.Feature("MainFeature").WithTitle("Main Feature").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)

	var buf bytes.Buffer
	err = pkg.WriteMSI(&buf)
	require.NoError(t, err)
	require.Greater(t, buf.Len(), 300, "harvested multi-dir MSI should be substantial")

	// At minimum we know sub-directories were registered because emission succeeded
	// without the old "distinct directories not supported" error from the legacy path.
}

// TestP3Builders exercises the P3 extensions (RegistryKeyBuilder, ShortcutBuilder,
// Icon/Binary on package builder) end-to-end through the PUBLIC API.
//
// It deliberately builds WITHOUT WithSkipValidation and asserts that WriteMSI
// succeeds (proving addRow errors are no longer swallowed and the Registry/
// Shortcut tables actually populate) and that the emitted bytes pass the public
// validator with no Error-severity findings (proving the reader can round-trip
// the Icon/Binary binary columns the validator must read back). The exact cell
// content is asserted white-box in msi_p3_roundtrip_internal_test.go; here we
// guard the public contract. The original version of this test used
// WithSkipValidation and only asserted buf.Len()>100, which let the empty-
// Registry bug ship.
func TestP3Builders(t *testing.T) {
	b := msi.NewPackage().
		WithProductName("P3 Test").
		WithManufacturer("go-msix").
		WithVersion("1.0").
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		Icon("MyIcon", []byte{0x00, 0x01, 0x02, 0x03}).
		Binary("MyBin", []byte("binary data payload"))

	install := b.RootDirectory("INSTALLFOLDER", "P3App")
	comp := install.Component("Main").AssociateToFeature("MainFeature")
	comp.WithFile("MainExe", []byte("MZ payload"))

	// Registry key with values + AsKeyPath
	_ = comp.RegistryKey(msi.RegistryRootHKLM, `Software\MyApp`).
		Value("Version", "1.0").
		Value("Data", []byte{1, 2, 3}).
		AsKeyPath()

	// Shortcut
	comp.Shortcut("MyApp.lnk", "[#MainExe]").
		Arguments("/start").
		Description("Launch MyApp").
		Icon("MyIcon", 0)

	// Also test flat compat (HKLM == 2)
	comp.WithRegistry(msi.RegistryRootHKLM, `Software\MyApp`, "FlatVal", 42)

	b.Feature("MainFeature").WithTitle("Main").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	require.NotNil(t, pkg)

	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf),
		"WriteMSI must succeed without WithSkipValidation (errors no longer swallowed)")
	require.Greater(t, buf.Len(), 100, "P3 features should emit additional tables/streams")

	// The emitted package (with Icon/Binary binary columns) must round-trip
	// through the public validator with no Error findings — this fails if the
	// reader cannot read binary columns back.
	v, err := msi.NewValidator().WithAllICEs().Build()
	require.NoError(t, err)
	findings, err := v.Validate(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err, "validator must read back a P3 package with Icon/Binary")
	for _, f := range findings {
		if f.Severity() == msi.SeverityError {
			t.Errorf("unexpected error-severity ICE finding on P3 package: %s (%s)", f.ICE(), f.Error())
		}
	}
}

// TestMSIValidator_Basic exercises the new public validator surface (P2).
// For the skeleton it always reports clean on a valid MSI produced by the
// public API (real ICE rules + findings come in later slices). Uses only
// the public interface per black-box test style.
func TestMSIValidator_Basic(t *testing.T) {
	// Build a minimal valid MSI using the public API (exercises P1 emission).
	b := msi.NewPackage().
		WithProductName("Validator Test").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithSkipValidation() // ensure Write succeeds; we test validator explicitly below on the bytes

	// Add at least one file so Media + sequences are populated (realistic). The
	// component is associated with a feature so the package is complete (an
	// orphan component is an ICE21 error and would not install).
	b.RootDirectory("INSTALLFOLDER", "ValTest").
		Component("Main").AssociateToFeature("Main").
		WithFile("dummy.txt", []byte("hello"))
	b.Feature("Main").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))

	// Public validator API.
	vb := msi.NewValidator().
		WithAllICEs().
		WithMaxSeverity(msi.SeverityError)
	v, err := vb.Build()
	require.NoError(t, err)
	require.NotNil(t, v)

	// Validate via ReaderAt (bytes.Reader implements it).
	findings, err := v.Validate(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	for _, f := range findings {
		if f.Severity() == msi.SeverityError {
			t.Errorf("unexpected error-severity ICE finding on clean package: %s", f.Error())
		}
	}

	// Also exercise ValidateFile via a temp file (public surface).
	tmp, err := os.CreateTemp("", "go-msix-val-*.msi")
	require.NoError(t, err)
	tmpName := tmp.Name()
	_, err = tmp.Write(buf.Bytes())
	require.NoError(t, err)
	require.NoError(t, tmp.Close())
	defer os.Remove(tmpName)

	findings2, err := v.ValidateFile(tmpName)
	require.NoError(t, err)
	require.Empty(t, findings2)

	// Chaining / builder config still works (no-op in skeleton).
	v2b := msi.NewValidator().WithICE("ICE03").WithoutICE("ICE99")
	_, err = v2b.Build()
	require.NoError(t, err)
}

// TestMSIPackage_ICE39_RunsOnRealPackageCode proves the WriteMSI reorder makes
// ICE39 validate against the real (computed) package code rather than an empty
// placeholder, and that the produced RevisionNumber is a valid braced GUID. It
// builds WITHOUT WithSkipValidation (so the in-build ICE39 actually runs) and
// then re-validates the emitted bytes with WithAllICEs asserting no ICE39
// error findings.
func TestMSIPackage_ICE39_RunsOnRealPackageCode(t *testing.T) {
	b := msi.NewPackage().
		WithProductName("ICE39 Real Code").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}")
	b.RootDirectory("INSTALLFOLDER", "ICE39Test").
		Component("Main").AssociateToFeature("Main").
		WithFile("dummy.txt", []byte("hello"))
	b.Feature("Main").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)

	// No SkipValidation: WriteMSI runs the in-build ICE39 against the real
	// summary (computed package code). It must succeed.
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))

	v, err := msi.NewValidator().WithAllICEs().Build()
	require.NoError(t, err)
	findings, err := v.Validate(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	for _, f := range findings {
		require.NotEqualf(t, "ICE39", f.ICE(),
			"ICE39 must not flag the real computed package code: %s", f.Error())
	}
}
