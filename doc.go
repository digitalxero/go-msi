// Package msi creates Windows Installer artifacts — MSI databases, MST
// transforms, and MSP patches — and signs them, entirely in Go. It needs no
// CGO, no Windows SDK, and no external tools, so it runs on any platform Go
// targets.
//
// # Overview
//
// An MSI is an OLE Compound File (CFB) holding a small relational database of
// tables plus an embedded MSZIP cabinet of file payloads. This package writes
// that format directly: the CFB container, the string pool, column-major table
// streams, the SummaryInformation property set, the _Validation catalog, and
// the cabinet — all deterministic and reproducible, and cross-checked in CI
// against msitools (msiinfo/msidump/msiextract), libmspack (cabextract),
// osslsigncode, and the real msiexec on Windows.
//
// # Entry points
//
//   - [NewPackage] builds an .msi: directory trees, components, features,
//     registry, shortcuts, icons/binary streams, services, upgrades, AppSearch,
//     custom actions, a UI subsystem (and a canned minimal wizard), and
//     multi-media / external / spanned cabinets.
//   - [NewTransform] builds a standalone .mst from the difference between two
//     packages; [PackageBuilder.WithLanguageTransform] embeds per-language
//     transforms inside a single multi-language MSI.
//   - [NewPatch] builds an .msp patch (small + minor updates) between an
//     originally-shipped product and an upgraded one.
//   - [NewSigner] Authenticode-signs the emitted MSI (RSA or ECDSA, optional
//     RFC3161 timestamp); [Verify] checks an existing signature.
//   - [NewValidator] runs ICE validation; it also runs automatically inside
//     [PackageBuilder.Build]/[Package.WriteMSI] (error-severity findings fail
//     the build unless [PackageBuilder.WithSkipValidation] is set).
//
// All public types follow a Builder-IS-Implementation pattern: the builder
// returned by a New* constructor is chainable and its Build method returns the
// runtime interface.
//
// # Quick start
//
//	b := msi.NewPackage().
//		WithProductName("My App").
//		WithManufacturer("My Company").
//		WithVersion("1.0.0").
//		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
//		WithUpgradeCode("{ABCDEF01-2345-6789-ABCD-EF0123456789}")
//
//	c := b.RootDirectory("INSTALLFOLDER", "My App").
//		Component("Main").AssociateToFeature("MainFeature")
//	c.WithFile("app.exe", appBytes)
//	b.Feature("MainFeature").WithTitle("Main Feature").WithLevel(1)
//
//	pkg, err := b.Build()
//	if err != nil {
//		// handle error
//	}
//	out, _ := os.Create("MyApp.msi")
//	defer out.Close()
//	_ = pkg.WriteMSI(out)
//
// See the package examples for signing, transforms, patches, and validation.
//
// # Non-goals
//
// LZX cabinet compression (MSZIP is fully supported by Windows Installer), the
// optional \x05MsiDigitalSignatureEx metadata pre-hash, binary-delta (PatchAPI)
// patching, major-upgrade/schema-reorganizing patches, and authoring merge
// modules (.msm) are out of scope. For MSIX/APPX packaging, see the companion
// module go.digitalxero.dev/go-msix.
package msi
