package msi

// platform_internal_test.go — P11 target-architecture tests. Internal because
// the summary reader, the compiled database and the ICE context are unexported.

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildPlatformMSI compiles a minimal package with configure applied, returning
// the emitted bytes and the parsed database.
func buildPlatformMSI(t *testing.T, configure func(b PackageBuilder)) ([]byte, msiDatabase) {
	t.Helper()
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("P11 Platform").
		WithManufacturer("go-msix").
		WithVersion("1.0.0")
	configure(b)
	b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F").
		WithFile("a.exe", FileSourceFromBytes([]byte("MZ")))
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	db, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	return buf.Bytes(), db
}

func TestPlatformString(t *testing.T) {
	assert.Equal(t, "Intel", Platform_Intel.String())
	assert.Equal(t, "Intel64", Platform_Intel64.String())
	assert.Equal(t, "x64", Platform_x64.String())
	assert.Equal(t, "Arm", Platform_Arm.String())
	assert.Equal(t, "Arm64", Platform_Arm64.String())

	assert.Empty(t, platformUnset.String(), "the zero value has no token")
	assert.Empty(t, Platform(99).String(), "an out-of-range Platform has no token")
	assert.False(t, Platform(99).valid())
}

func TestPlatformIsWin64(t *testing.T) {
	assert.True(t, Platform_x64.isWin64())
	assert.True(t, Platform_Intel64.isWin64(), "Intel64 is Itanium, which is 64-bit")
	assert.True(t, Platform_Arm64.isWin64())

	assert.False(t, Platform_Intel.isWin64())
	assert.False(t, Platform_Arm.isWin64(), "Arm is 32-bit ARM")
}

func TestPlatformMinSchemaVersion(t *testing.T) {
	assert.Equal(t, 200, Platform_Intel.minSchemaVersion())
	assert.Equal(t, 200, Platform_Intel64.minSchemaVersion())
	assert.Equal(t, 200, Platform_x64.minSchemaVersion())
	assert.Equal(t, 500, Platform_Arm.minSchemaVersion())
	assert.Equal(t, 500, Platform_Arm64.minSchemaVersion())
}

func TestParsePlatformRejectsNonMSITokens(t *testing.T) {
	for _, token := range []string{"neutral", "amd64", "x86", "aarch64", "ia64", ""} {
		_, ok := parsePlatform(token)
		assert.False(t, ok, "%q must not be accepted as a Template platform", token)
	}

	// Casing varies in the wild; the five documented tokens are accepted
	// case-insensitively and normalize to canonical spelling.
	for token, want := range map[string]Platform{
		"X64": Platform_x64, "ARM64": Platform_Arm64, "intel": Platform_Intel,
		"Intel64": Platform_Intel64, "arm": Platform_Arm,
	} {
		got, ok := parsePlatform(token)
		require.True(t, ok, "token %q", token)
		assert.Equal(t, want, got, "token %q", token)
	}
}

func TestParseTemplate(t *testing.T) {
	plat, langs, err := parseTemplate("x64;1033,1031")
	require.NoError(t, err)
	assert.Equal(t, Platform_x64, plat)
	assert.Equal(t, []int{1033, 1031}, langs)

	// A blank platform is legal: the package is not architecture-restricted.
	plat, langs, err = parseTemplate(";1033")
	require.NoError(t, err)
	assert.Equal(t, platformUnset, plat)
	assert.Equal(t, []int{1033}, langs)

	// Language 0 means language-neutral.
	_, langs, err = parseTemplate("Arm64;0")
	require.NoError(t, err)
	assert.Equal(t, []int{0}, langs)

	_, _, err = parseTemplate("neutral;1033")
	require.Error(t, err, "neutral is an MSIX architecture, not an MSI one")

	_, _, err = parseTemplate("x64")
	require.Error(t, err, "a Template without ';' is malformed")

	_, _, err = parseTemplate("x64;en-US")
	require.Error(t, err, "language ids must be numeric")
}

func TestTemplateIsProductCodeList(t *testing.T) {
	assert.True(t, templateIsProductCodeList("{12345678-1234-1234-1234-123456789ABC}"))
	assert.True(t, templateIsProductCodeList("{12345678-1234-1234-1234-123456789ABC};{AAAAAAAA-1234-1234-1234-123456789ABC}"))
	assert.False(t, templateIsProductCodeList("x64;1033"))
	assert.False(t, templateIsProductCodeList(";1033"))
}

func TestWithPlatformTemplateAndPageCount(t *testing.T) {
	for _, tc := range []struct {
		plat          Platform
		wantTemplate  string
		wantPageCount int
	}{
		{Platform_Intel, "Intel;1033", 200},
		{Platform_Intel64, "Intel64;1033", 200},
		{Platform_x64, "x64;1033", 200},
		{Platform_Arm, "Arm;1033", 500},
		{Platform_Arm64, "Arm64;1033", 500},
	} {
		t.Run(tc.plat.String(), func(t *testing.T) {
			data, _ := buildPlatformMSI(t, func(b PackageBuilder) { b.WithPlatform(tc.plat) })
			sum, err := readMSISummaryInfo(bytes.NewReader(data))
			require.NoError(t, err)
			assert.Equal(t, tc.wantTemplate, sum.Template, "PID7 Template")
			assert.Equal(t, tc.wantPageCount, sum.PageCount, "PID14 PageCount")
		})
	}
}

func TestWithPlatformDefaultsToX64(t *testing.T) {
	data, _ := buildPlatformMSI(t, func(b PackageBuilder) {})
	sum, err := readMSISummaryInfo(bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, "x64;1033", sum.Template, "an unset platform still emits x64")
	assert.Equal(t, 200, sum.PageCount)
}

func TestWithPlatformCombinesWithLanguage(t *testing.T) {
	data, _ := buildPlatformMSI(t, func(b PackageBuilder) {
		b.WithPlatform(Platform_Arm64).WithLanguage(LangCode_deDE)
	})
	sum, err := readMSISummaryInfo(bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, "Arm64;1031", sum.Template)
}

func TestBuildRejectsUnknownPlatform(t *testing.T) {
	_, err := NewPackage().
		WithProductName("Bad Platform").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		WithPlatform(Platform(42)).
		Build()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Platform(42)")
}

// --- auto-applied 64-bit conventions ---

func platformDirParent(t *testing.T, db msiDatabase, dirID string) string {
	t.Helper()
	tbl, err := db.GetTable("Directory")
	require.NoError(t, err)
	row := findRow(t, tbl, 0, dirID)
	parent, _ := row[1].(string)
	return parent
}

func platformComponentAttrs(t *testing.T, db msiDatabase, comp string) int16 {
	t.Helper()
	tbl, err := db.GetTable("Component")
	require.NoError(t, err)
	return iceInt16(findRow(t, tbl, 0, comp)[3])
}

func TestPlatform64BitComponentAttributeApplied(t *testing.T) {
	for _, tc := range []struct {
		plat      Platform
		want64Bit bool
	}{
		{Platform_Intel, false},
		{Platform_Arm, false},
		{Platform_x64, true},
		{Platform_Intel64, true},
		{Platform_Arm64, true},
	} {
		t.Run(tc.plat.String(), func(t *testing.T) {
			_, db := buildPlatformMSI(t, func(b PackageBuilder) { b.WithPlatform(tc.plat) })
			got64 := platformComponentAttrs(t, db, "Main")&msidbComponentAttributes64bit != 0
			assert.Equal(t, tc.want64Bit, got64, "component 64-bit attribute")
		})
	}
}

func TestInstallRootDefaultsToTargetDir(t *testing.T) {
	// The install root must stay under TARGETDIR by default, or
	// "msiexec TARGETDIR=…" silently stops redirecting the install.
	for _, plat := range []Platform{Platform_Intel, Platform_x64, Platform_Arm64} {
		t.Run(plat.String(), func(t *testing.T) {
			_, db := buildPlatformMSI(t, func(b PackageBuilder) { b.WithPlatform(plat) })
			assert.Equal(t, "TARGETDIR", platformDirParent(t, db, "INSTALLFOLDER"))

			tbl, err := db.GetTable("Directory")
			require.NoError(t, err)
			for _, r := range tbl.rows() {
				dir, _ := r.values()[0].(string)
				assert.NotContains(t, []string{"ProgramFilesFolder", "ProgramFiles64Folder"}, dir,
					"no Program Files folder without InstallToProgramFiles")
			}
		})
	}
}

func TestInstallToProgramFilesPicksPlatformFolder(t *testing.T) {
	for _, tc := range []struct {
		plat       Platform
		wantParent string
	}{
		{Platform_Intel, "ProgramFilesFolder"},
		{Platform_Arm, "ProgramFilesFolder"},
		{Platform_x64, "ProgramFiles64Folder"},
		{Platform_Intel64, "ProgramFiles64Folder"},
		{Platform_Arm64, "ProgramFiles64Folder"},
	} {
		t.Run(tc.plat.String(), func(t *testing.T) {
			_, db := buildPlatformMSI(t, func(b PackageBuilder) {
				b.WithPlatform(tc.plat).InstallToProgramFiles()
			})
			assert.Equal(t, tc.wantParent, platformDirParent(t, db, "INSTALLFOLDER"))
			assert.Equal(t, "TARGETDIR", platformDirParent(t, db, tc.wantParent),
				"the Program Files folder itself is rooted at TARGETDIR")
		})
	}
}

func TestExplicitAttributesSuppressAuto64Bit(t *testing.T) {
	// An explicit WithAttributes is the caller's final word; the platform's
	// 64-bit bit is not OR-ed in on top of it.
	_, db := buildPlatformMSI(t, func(b PackageBuilder) {
		b.WithPlatform(Platform_x64)
		b.Directory("INSTALLFOLDER").Component("Main").WithAttributes(msidbComponentAttributesPermanent)
	})
	attrs := platformComponentAttrs(t, db, "Main")
	assert.Equal(t, msidbComponentAttributesPermanent, attrs)
	assert.Zero(t, attrs&msidbComponentAttributes64bit, "explicit attributes win over the platform default")
}

func TestExplicitInstallParentSuppressesProgramFiles(t *testing.T) {
	// A caller that wired INSTALLFOLDER's parent itself keeps it, even with
	// InstallToProgramFiles set.
	_, db := buildPlatformMSI(t, func(b PackageBuilder) {
		b.WithPlatform(Platform_x64).InstallToProgramFiles()
		b.RootDirectory("TARGETDIR", "SourceDir").Subdirectory("INSTALLFOLDER", "App")
	})
	assert.Equal(t, "TARGETDIR", platformDirParent(t, db, "INSTALLFOLDER"),
		"an explicitly parented install root is not re-homed under Program Files")
}

// --- transform summary: PID7 is the pre-transform state, PID8 the post ---

// platformTransformPackage builds a compiled package for transform tests.
func platformTransformPackage(t *testing.T, plat Platform, lcid LanguageCode) *msiPackage {
	t.Helper()
	b := NewPackage().
		WithProductCode("{AAAAAAAA-1111-2222-3333-444444444444}").
		WithUpgradeCode("{BBBBBBBB-1111-2222-3333-444444444444}").
		WithProductName("Transform Platform").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		WithPlatform(plat).
		WithLanguage(lcid)
	b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F").
		WithFile("a.exe", FileSourceFromBytes([]byte("MZ")))
	b.Feature("F").WithLevel(1)

	pkg, err := b.Build()
	require.NoError(t, err)
	return pkg.(*msiPackage)
}

func TestTransformSummaryTemplateIsBaseAndLastSavedByIsTarget(t *testing.T) {
	// A transform that moves the package from x64/en-US to Arm64/de-DE. PID7
	// describes the database the transform applies TO, PID8 the result.
	base := platformTransformPackage(t, Platform_x64, LangCode_enUS)
	target := platformTransformPackage(t, Platform_Arm64, LangCode_deDE)

	sum := (&msiTransform{base: base, target: target}).summaryInfo()
	assert.Equal(t, "x64;1033", sum.Template, "PID7 is the pre-transform platform;language")
	assert.Equal(t, "Arm64;1031", sum.LastSavedBy, "PID8 is the post-transform platform;language")

	// Either side may raise the schema floor; the transform takes the higher.
	assert.Equal(t, 500, sum.PageCount, "Arm64 on either side requires 5.0")
}

func TestTransformSummaryIdenticalWhenPlatformUnchanged(t *testing.T) {
	// The patch transforms diff two packages of the same platform and language,
	// so PID7 and PID8 still coincide there.
	base := platformTransformPackage(t, Platform_x64, LangCode_enUS)
	target := platformTransformPackage(t, Platform_x64, LangCode_enUS)

	sum := (&msiTransform{base: base, target: target}).summaryInfo()
	assert.Equal(t, "x64;1033", sum.Template)
	assert.Equal(t, sum.Template, sum.LastSavedBy)
	assert.Equal(t, msiSchemaVersion, sum.PageCount)
}

// --- ICE39: the PageCount floor follows the Template platform ---

func TestICE39PageCountFloorIsPlatformDerived(t *testing.T) {
	// 200 satisfies x64 but is below the 500 an Arm64 package requires.
	x64Findings := runICE39(&iceContext{summary: msiSummaryInfo{Template: "x64;1033", PageCount: 200}})
	assert.Empty(t, x64Findings, "200 meets the x64 floor")

	armFindings := runICE39(&iceContext{summary: msiSummaryInfo{Template: "Arm64;1033", PageCount: 200}})
	require.Len(t, armFindings, 1)
	assert.Equal(t, SeverityWarning, armFindings[0].Severity())
	assert.Contains(t, armFindings[0].Error(), "below the minimum 500")

	okFindings := runICE39(&iceContext{summary: msiSummaryInfo{Template: "Arm64;1033", PageCount: 500}})
	assert.Empty(t, okFindings, "500 meets the Arm64 floor")
}

func TestICE39RejectsInvalidTemplatePlatform(t *testing.T) {
	// "neutral" is the MSIX token and was previously accepted silently.
	findings := runICE39(&iceContext{summary: msiSummaryInfo{Template: "neutral;1033", PageCount: 200}})
	require.NotEmpty(t, findings)
	assert.Equal(t, SeverityError, findings[0].Severity())
	assert.Contains(t, findings[0].Error(), "malformed")
}

func TestICE39IgnoresPatchTemplate(t *testing.T) {
	// A patch's PID7 is a ProductCode list, not a platform;language pair.
	findings := runICE39(&iceContext{summary: msiSummaryInfo{
		Template: "{12345678-1234-1234-1234-123456789ABC}",
	}})
	assert.Empty(t, findings)
}

// --- ICE80: 64-bit content must agree with the Template platform ---

func TestICE80FlagsSixtyFourBitContentInThirtyTwoBitPackage(t *testing.T) {
	_, db := buildPlatformMSI(t, func(b PackageBuilder) {
		b.WithPlatform(Platform_x64).InstallToProgramFiles()
	})

	// Re-validate the 64-bit database while claiming a 32-bit Template.
	findings := runICE80(&iceContext{db: db, summary: msiSummaryInfo{Template: "Intel;1033"}})
	require.NotEmpty(t, findings, "a 64-bit package declaring Intel must be flagged")
	for _, f := range findings {
		assert.Equal(t, SeverityError, f.Severity())
		assert.Contains(t, f.Error(), "Template platform is Intel")
	}

	tables := map[string]bool{}
	for _, f := range findings {
		tables[f.Table()] = true
	}
	assert.True(t, tables["Component"], "the 64-bit component attribute is flagged")
	assert.True(t, tables["Directory"], "ProgramFiles64Folder is flagged")
}

func TestICE80PassesForMatchingPlatform(t *testing.T) {
	for _, plat := range []Platform{Platform_Intel, Platform_x64, Platform_Arm, Platform_Arm64} {
		t.Run(plat.String(), func(t *testing.T) {
			_, db := buildPlatformMSI(t, func(b PackageBuilder) {
				b.WithPlatform(plat).InstallToProgramFiles()
			})
			findings := runICE80(&iceContext{db: db, summary: msiSummaryInfo{Template: plat.String() + ";1033"}})
			assert.Empty(t, findings, "a package's own platform must never trip ICE80")
		})
	}
}

func TestICE80IgnoresPatchTemplate(t *testing.T) {
	_, db := buildPlatformMSI(t, func(b PackageBuilder) { b.WithPlatform(Platform_x64) })
	findings := runICE80(&iceContext{db: db, summary: msiSummaryInfo{
		Template: "{12345678-1234-1234-1234-123456789ABC}",
	}})
	assert.Empty(t, findings, "a patch Template carries no platform claim")
}
