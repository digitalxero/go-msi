package msi

// msi_p9_internal_test.go — P9 multi-language + MST transform tests.

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func buildP9LangMSI(t *testing.T, configure func(b PackageBuilder)) ([]byte, msiDatabase) {
	t.Helper()
	b := NewPackage().
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithProductName("P9 Lang").
		WithManufacturer("go-msix").
		WithVersion("1.0.0")
	configure(b)
	b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("F").
		WithFile("a.exe", []byte("MZ"))
	b.Feature("F").WithLevel(1)
	pkg, err := b.Build()
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pkg.WriteMSI(&buf))
	db, err := readMSIDatabase(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	return buf.Bytes(), db
}

func TestCompileP9_Language(t *testing.T) {
	// German.
	data, db := buildP9LangMSI(t, func(b PackageBuilder) { b.WithLanguage(1031) })

	sum, err := readMSISummaryInfo(bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, "x64;1031", sum.Template, "Template carries the configured LCID")

	propTbl, err := db.GetTable("Property")
	require.NoError(t, err)
	pl := findRow(t, propTbl, 0, "ProductLanguage")
	assert.Equal(t, "1031", pl[1], "ProductLanguage property set from WithLanguage")
}

func TestCompileP9_LanguageDefaults1033(t *testing.T) {
	data, db := buildP9LangMSI(t, func(b PackageBuilder) {})
	sum, err := readMSISummaryInfo(bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, "x64;1033", sum.Template, "default Template is x64;1033")

	propTbl, err := db.GetTable("Property")
	require.NoError(t, err)
	pl := findRow(t, propTbl, 0, "ProductLanguage")
	assert.Equal(t, "1033", pl[1])
}

func TestCompileP9_UserProductLanguageWins(t *testing.T) {
	// An explicit WithProperty must override the WithLanguage-derived value.
	_, db := buildP9LangMSI(t, func(b PackageBuilder) {
		b.WithLanguage(1031).WithProperty("ProductLanguage", "1036")
	})
	propTbl, err := db.GetTable("Property")
	require.NoError(t, err)
	// Exactly one ProductLanguage row, the user's value.
	count := 0
	var val string
	for _, r := range propTbl.rows() {
		if r.values()[0] == "ProductLanguage" {
			count++
			val, _ = r.values()[1].(string)
		}
	}
	assert.Equal(t, 1, count, "no duplicate ProductLanguage row")
	assert.Equal(t, "1036", val, "explicit WithProperty wins")
}
