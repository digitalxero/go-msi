package msi_test

import (
	"bytes"
	"fmt"
	"log"
	"testing/fstest"

	msi "go.digitalxero.dev/go-msi"
)

// cfbMagic is the OLE Compound File header shared by .msi/.mst/.msp files.
var cfbMagic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// buildExamplePackage assembles a minimal, valid single-feature package.
func buildExamplePackage() msi.Package {
	b := msi.NewPackage().
		WithProductName("Example App").
		WithManufacturer("Example Co").
		WithVersion("1.0.0").
		WithProductCode("{11111111-2222-3333-4444-555555555555}").
		WithUpgradeCode("{66666666-7777-8888-9999-AAAAAAAAAAAA}")

	c := b.RootDirectory("INSTALLFOLDER", "Example App").
		Component("Main").AssociateToFeature("MainFeature")
	c.WithFile("app.exe", msi.FileSourceFromBytes([]byte("MZ example payload")))
	b.Feature("MainFeature").WithTitle("Main Feature").WithLevel(1)

	pkg, err := b.Build()
	if err != nil {
		log.Fatal(err)
	}
	return pkg
}

// Build a minimal MSI and write it out. The fluent builder configures the
// product identity, a directory tree, components, files and features; Build
// runs ICE validation and WriteMSI emits the .msi.
func ExampleNewPackage() {
	pkg := buildExamplePackage()

	var buf bytes.Buffer
	if err := pkg.WriteMSI(&buf); err != nil {
		log.Fatal(err)
	}
	fmt.Println("valid MSI:", bytes.HasPrefix(buf.Bytes(), cfbMagic))
	// Output: valid MSI: true
}

// AddTree harvests an fs.FS into the package, creating one component per file
// under the given directory.
func ExamplePackageBuilder_addTree() {
	b := msi.NewPackage().
		WithProductName("Harvested App").
		WithManufacturer("Example Co").
		WithVersion("2.0.0").
		WithProductCode("{22222222-3333-4444-5555-666666666666}")
	b.RootDirectory("INSTALLFOLDER", "Harvested App")

	payload := fstest.MapFS{
		"bin/app.exe":      {Data: []byte("MZ app")},
		"docs/readme.txt":  {Data: []byte("hello")},
		"docs/license.txt": {Data: []byte("MIT")},
	}
	// Harvest the tree; every created component is associated with "MainFeature".
	if err := b.AddTree(payload, "INSTALLFOLDER", "MainFeature"); err != nil {
		log.Fatal(err)
	}
	b.Feature("MainFeature").WithTitle("Main Feature").WithLevel(1)

	pkg, err := b.Build()
	if err != nil {
		log.Fatal(err)
	}
	var buf bytes.Buffer
	if err := pkg.WriteMSI(&buf); err != nil {
		log.Fatal(err)
	}
	fmt.Println("valid MSI:", bytes.HasPrefix(buf.Bytes(), cfbMagic))
	// Output: valid MSI: true
}

// Validate an MSI with the full ICE rule set. A well-formed package has no
// error-severity findings.
func ExampleNewValidator() {
	var buf bytes.Buffer
	if err := buildExamplePackage().WriteMSI(&buf); err != nil {
		log.Fatal(err)
	}

	v, err := msi.NewValidator().WithAllICEs().Build()
	if err != nil {
		log.Fatal(err)
	}
	findings, err := v.Validate(bytes.NewReader(buf.Bytes()))
	if err != nil {
		log.Fatal(err)
	}

	errors := 0
	for _, f := range findings {
		if f.Severity() == msi.SeverityError {
			errors++
		}
	}
	fmt.Println("error findings:", errors)
	// Output: error findings: 0
}

// Build a standalone .mst transform from the difference between two packages.
func ExampleNewTransform() {
	base := buildExamplePackage()

	// A target that differs (e.g. a renamed product).
	tb := msi.NewPackage().
		WithProductName("Example App (Pro)").
		WithManufacturer("Example Co").
		WithVersion("1.0.0").
		WithProductCode("{11111111-2222-3333-4444-555555555555}").
		WithUpgradeCode("{66666666-7777-8888-9999-AAAAAAAAAAAA}")
	c := tb.RootDirectory("INSTALLFOLDER", "Example App").
		Component("Main").AssociateToFeature("MainFeature")
	c.WithFile("app.exe", msi.FileSourceFromBytes([]byte("MZ example payload")))
	tb.Feature("MainFeature").WithTitle("Main Feature").WithLevel(1)
	target, err := tb.Build()
	if err != nil {
		log.Fatal(err)
	}

	tr, err := msi.NewTransform().From(base).To(target).Build()
	if err != nil {
		log.Fatal(err)
	}
	var buf bytes.Buffer
	if err := tr.WriteMST(&buf); err != nil {
		log.Fatal(err)
	}
	fmt.Println("valid MST:", bytes.HasPrefix(buf.Bytes(), cfbMagic))
	// Output: valid MST: true
}

// Embed a per-language transform inside a single multi-language MSI. msiexec
// selects it at install time with TRANSFORMS=:1031.
func ExamplePackageBuilder_withLanguageTransform() {
	b := msi.NewPackage().
		WithProductName("My App").
		WithManufacturer("Example Co").
		WithVersion("1.0.0").
		WithProductCode("{33333333-4444-5555-6666-777777777777}").
		WithLanguage(msi.LangCode_enUS).
		WithLanguageTransform(msi.LangCode_deDE, func(de msi.PackageBuilder) {
			de.WithProductName("Meine Anwendung")
		})
	c := b.RootDirectory("INSTALLFOLDER", "My App").
		Component("Main").AssociateToFeature("MainFeature")
	c.WithFile("app.exe", msi.FileSourceFromBytes([]byte("MZ")))
	b.Feature("MainFeature").WithLevel(1)

	pkg, err := b.Build()
	if err != nil {
		log.Fatal(err)
	}
	var buf bytes.Buffer
	if err := pkg.WriteMSI(&buf); err != nil {
		log.Fatal(err)
	}
	fmt.Println("valid MSI:", bytes.HasPrefix(buf.Bytes(), cfbMagic))
	// Output: valid MSI: true
}

// Build an .msp patch between an originally-shipped product and an upgraded one
// (same ProductCode/UpgradeCode). The patch ships only the changed/new files.
func ExampleNewPatch() {
	base := buildExamplePackage()

	ub := msi.NewPackage().
		WithProductName("Example App").
		WithManufacturer("Example Co").
		WithVersion("1.0.1"). // bumped
		WithProductCode("{11111111-2222-3333-4444-555555555555}").
		WithUpgradeCode("{66666666-7777-8888-9999-AAAAAAAAAAAA}")
	c := ub.RootDirectory("INSTALLFOLDER", "Example App").
		Component("Main").AssociateToFeature("MainFeature")
	c.WithFile("app.exe", msi.FileSourceFromBytes([]byte("MZ example payload v1.0.1 — patched")))
	ub.Feature("MainFeature").WithTitle("Main Feature").WithLevel(1)
	upgraded, err := ub.Build()
	if err != nil {
		log.Fatal(err)
	}

	patch, err := msi.NewPatch().
		From(base).To(upgraded).
		WithClassification("Update").
		WithDisplayName("Example App 1.0.1").
		AllowRemoval(true).
		WithPatchFamily("ExampleAppPatches", "1.0.1").
		Build()
	if err != nil {
		log.Fatal(err)
	}
	var buf bytes.Buffer
	if err := patch.WriteMSP(&buf); err != nil {
		log.Fatal(err)
	}
	fmt.Println("valid MSP:", bytes.HasPrefix(buf.Bytes(), cfbMagic))
	// Output: valid MSP: true
}

// Authenticode-sign the emitted MSI. The signer is attached to the package and
// applied during WriteMSI; Verify checks the signature on the resulting bytes.
func ExampleNewSigner() {
	signer, err := msi.NewSigner().
		WithPFX("codesign.pfx", "password").
		WithTimestampURL("http://timestamp.digicert.com").
		Build()
	if err != nil {
		log.Fatal(err)
	}

	b := msi.NewPackage().
		WithProductName("Signed App").
		WithManufacturer("Example Co").
		WithVersion("1.0.0").
		WithProductCode("{44444444-5555-6666-7777-888888888888}").
		WithSigner(signer)
	c := b.RootDirectory("INSTALLFOLDER", "Signed App").
		Component("Main").AssociateToFeature("MainFeature")
	c.WithFile("app.exe", msi.FileSourceFromBytes([]byte("MZ")))
	b.Feature("MainFeature").WithLevel(1)

	pkg, err := b.Build()
	if err != nil {
		log.Fatal(err)
	}
	var buf bytes.Buffer
	if err := pkg.WriteMSI(&buf); err != nil {
		log.Fatal(err)
	}
	// The signed MSI carries a \x05DigitalSignature stream; verify it:
	if _, err := msi.Verify(bytes.NewReader(buf.Bytes())); err != nil {
		log.Fatal(err)
	}
}
