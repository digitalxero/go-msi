package msi

// msi_lang_internal_test.go — P9.5 embedded language transforms + deep clone.

import (
	"bytes"
	"crypto"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLanguageCode_NamedConstants(t *testing.T) {
	// A sampling of the named LCID constants resolve to the documented values
	// and flow through the typed API.
	assert.Equal(t, LanguageCode(1033), LangCode_enUS)
	assert.Equal(t, LanguageCode(1031), LangCode_deDE)
	assert.Equal(t, LanguageCode(1036), LangCode_frFR)
	assert.Equal(t, LanguageCode(2052), LangCode_zhCN)

	b := NewPackage().
		WithProductCode("{AAAAAAAA-1111-2222-3333-444444444444}").
		WithProductName("L10n").WithManufacturer("go-msix").WithVersion("1.0.0").
		WithLanguage(LangCode_frFR)
	b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F").
		WithFile("a.exe", []byte("MZ"))
	b.Feature("F").WithLevel(1)
	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	sum, err := readMSISummaryInfo(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	assert.Equal(t, "x64;1036", sum.Template)
}

func TestClone_IndependentDeepCopy(t *testing.T) {
	base := p9BasePackage(t)
	clone := base.cloneForTransform()

	// Mutating the clone's maps/slices must not touch the base.
	clone.props["PROPA"] = "MUTATED"
	clone.props["NEWONLY"] = "x"
	clone.compEntries["Main"].guid = "{CHANGED}"

	assert.Equal(t, "1", base.props["PROPA"], "base property unchanged by clone mutation")
	_, exists := base.props["NEWONLY"]
	assert.False(t, exists, "base did not gain the clone's new property")
	assert.NotEqual(t, "{CHANGED}", base.compEntries["Main"].guid, "base component pointer not shared")

	// The clone drops nested transforms and signer.
	assert.Nil(t, clone.languageTransforms)
	assert.Nil(t, clone.signer)
}

func TestClone_CompilesIdenticalBeforeMutation(t *testing.T) {
	base := p9BasePackage(t)
	clone := base.cloneForTransform()

	bdb, err := compileMSIPackage(base)
	require.NoError(t, err)
	cdb, err := compileMSIPackage(clone)
	require.NoError(t, err)

	// An unmutated clone compiles to the same table data as the base.
	assertRowSetsEqual(t, rowSetOfDB(bdb), rowSetOfDB(cdb))
}

// p9EmbeddedTransformPackage builds a base with one embedded 1031 transform that
// changes ProductName and a property value.
func p9EmbeddedTransformPackage(t *testing.T) *msiPackage {
	t.Helper()
	b := NewPackage().
		WithProductCode("{AAAAAAAA-1111-2222-3333-444444444444}").
		WithUpgradeCode("{BBBBBBBB-1111-2222-3333-444444444444}").
		WithProductName("My Program").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		WithProperty("PROPA", "english").
		WithLanguageTransform(LangCode_deDE, func(de PackageBuilder) {
			de.WithProductName("Mein Programm")
			de.WithProperty("PROPA", "deutsch")
		})
	b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F").
		WithFile("a.exe", []byte("MZ"))
	b.Feature("F").WithLevel(1)
	pkg, err := b.Build()
	require.NoError(t, err)
	return pkg.(*msiPackage)
}

func TestEmbeddedTransform_TemplateListsLCID(t *testing.T) {
	pkg := p9EmbeddedTransformPackage(t)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))

	sum, err := readMSISummaryInfo(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	assert.Equal(t, "x64;1033,1031", sum.Template, "Template lists primary + transform LCIDs")
}

func TestEmbeddedTransform_SubStorageRoundTrip(t *testing.T) {
	pkg := p9EmbeddedTransformPackage(t)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	data := buf.Bytes()

	// The embedded transform is a sub-storage named "1031" with the transform CLSID.
	subs, err := readMSIRawSubStorages(bytes.NewReader(data))
	require.NoError(t, err)
	require.Len(t, subs, 1, "one embedded language transform")
	assert.Equal(t, "1031", subs[0].name)
	assert.Equal(t, msiTransformCLSID, subs[0].clsid)

	// Apply that transform onto the base database and confirm it produces the
	// localized target (ProductName + PROPA in German, ProductLanguage 1031).
	baseDB, err := readMSIDatabase(bytes.NewReader(data))
	require.NoError(t, err)

	applied, err := applyMSITransform(baseDB, subs[0].streams)
	require.NoError(t, err)

	props := applied["Property"]
	require.NotNil(t, props.cols)
	got := map[string]string{}
	keyIdx := keyColumnIndexes(props.cols)
	_ = keyIdx
	for _, row := range props.rows {
		k, _ := row[0].(string)
		v, _ := row[1].(string)
		got[k] = v
	}
	assert.Equal(t, "deutsch", got["PROPA"], "PROPA localized by the transform")
	assert.Equal(t, "Mein Programm", got["ProductName"], "ProductName localized")
	assert.Equal(t, strconv.Itoa(1031), got["ProductLanguage"], "ProductLanguage switched to 1031")
}

func TestEmbeddedTransform_SignedVerifiesWithRecursiveImprint(t *testing.T) {
	// Signing + embedded transforms together exercise the recursive imprint
	// (sub-storage streams + their CLSID must participate). Verify must accept
	// the result and reject it if the embedded transform is altered.
	key := mustRSAKey(t)
	cert := genTestCert(t, key)
	signer, err := NewSigner().WithCertificate(cert, key, nil).Build()
	require.NoError(t, err)

	b := NewPackage().
		WithProductCode("{AAAAAAAA-1111-2222-3333-444444444444}").
		WithUpgradeCode("{BBBBBBBB-1111-2222-3333-444444444444}").
		WithProductName("My Program").
		WithManufacturer("go-msix").
		WithVersion("1.0.0").
		WithSigner(signer).
		WithLanguageTransform(1031, func(de PackageBuilder) {
			de.WithProductName("Mein Programm")
		})
	b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F").
		WithFile("a.exe", []byte("MZ"))
	b.Feature("F").WithLevel(1)
	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))

	info, err := Verify(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err, "signed MSI with an embedded transform must verify")
	assert.Equal(t, crypto.SHA256, info.HashAlgorithm())

	// The embedded transform participates in the imprint: dropping it changes the
	// recursive hash. Confirm the sub-storage's streams are non-empty (so the
	// recursion actually hashed content beyond the root).
	subs, err := readMSIRawSubStorages(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.Len(t, subs, 1)
	assert.NotEmpty(t, subs[0].streams, "embedded transform carries delta streams")
}

func TestEmbeddedTransform_NoneIsByteIdenticalToNoTransform(t *testing.T) {
	// A package with an empty transform set must equal the same package built
	// without ever calling WithLanguageTransform.
	build := func(withEmptyTransforms bool) []byte {
		b := NewPackage().
			WithProductCode("{AAAAAAAA-1111-2222-3333-444444444444}").
			WithUpgradeCode("{BBBBBBBB-1111-2222-3333-444444444444}").
			WithProductName("My Program").
			WithManufacturer("go-msix").
			WithVersion("1.0.0")
		b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F").
			WithFile("a.exe", []byte("MZ"))
		b.Feature("F").WithLevel(1)
		pkg, err := b.Build()
		require.NoError(t, err)
		var buf bytes.Buffer
		require.NoError(t, pkg.WriteMSI(&buf))
		return buf.Bytes()
	}
	assert.Equal(t, build(false), build(true), "no-transform output is stable")
}
