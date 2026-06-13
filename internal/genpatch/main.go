// Command genpatch builds a base MSI, an upgraded MSI, and the .msp patch
// between them for the external verification harness (scripts/verify_msi.sh and
// the windows-latest CI apply job). It writes <out>/base.msi, <out>/upgraded.msi
// and <out>/patch.msp. The base installs a.exe + b.dat; the patch changes a.exe
// and adds c.dat (a minor update: the ProductVersion bumps 1.0.0 -> 1.0.1).
package main

import (
	"fmt"
	"os"
	"path/filepath"

	msix "go.digitalxero.dev/go-msi"
)

const (
	productCode = "{C0FFEE00-1111-2222-3333-444444444444}"
	upgradeCode = "{C0FFEE01-1111-2222-3333-444444444444}"

	baseAContent = "go-msix patch demo: a.exe ORIGINAL contents\n"
	newAContent  = "go-msix patch demo: a.exe PATCHED contents, now longer\n"
	bContent     = "go-msix patch demo: b.dat unchanged shared data\n"
	cContent     = "go-msix patch demo: c.dat brand-new file added by the patch\n"
)

func base() msix.PackageBuilder {
	b := msix.NewPackage().
		WithProductCode(productCode).
		WithUpgradeCode(upgradeCode).
		WithProductName("Go MSIX Patch Demo").
		WithManufacturer("go-msix").
		WithVersion("1.0.0")
	c := b.RootDirectory("INSTALLFOLDER", "Go MSIX Patch Demo").
		Component("Main").AssociateToFeature("MainFeature")
	c.WithFile("a.exe", []byte(baseAContent))
	c.WithFile("b.dat", []byte(bContent))
	b.Feature("MainFeature").WithTitle("Main Feature").WithLevel(1)
	return b
}

func upgraded() msix.PackageBuilder {
	b := msix.NewPackage().
		WithProductCode(productCode).
		WithUpgradeCode(upgradeCode).
		WithProductName("Go MSIX Patch Demo").
		WithManufacturer("go-msix").
		WithVersion("1.0.1")
	c := b.RootDirectory("INSTALLFOLDER", "Go MSIX Patch Demo").
		Component("Main").AssociateToFeature("MainFeature")
	c.WithFile("a.exe", []byte(newAContent))
	c.WithFile("b.dat", []byte(bContent))
	c.WithFile("c.dat", []byte(cContent))
	b.Feature("MainFeature").WithTitle("Main Feature").WithLevel(1)
	return b
}

func writeMSI(path string, b msix.PackageBuilder) error {
	pkg, err := b.Build()
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pkg.WriteMSI(f)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: genpatch <output-dir>")
		os.Exit(2)
	}
	out := os.Args[1]

	basePkg, err := base().Build()
	fail(err)
	upPkg, err := upgraded().Build()
	fail(err)

	fail(writeMSI(filepath.Join(out, "base.msi"), base()))
	fail(writeMSI(filepath.Join(out, "upgraded.msi"), upgraded()))

	patch, err := msix.NewPatch().
		From(basePkg).
		To(upPkg).
		WithClassification("Update").
		WithDisplayName("Go MSIX Patch Demo 1.0.1").
		WithDescription("Updates a.exe and adds c.dat").
		WithManufacturerName("go-msix").
		WithTargetProductName("Go MSIX Patch Demo").
		AllowRemoval(true).
		WithPatchFamily("GoMsixPatchDemo", "1.0.1").
		SupersedeEarlier(true).
		Build()
	fail(err)

	mspFile, err := os.Create(filepath.Join(out, "patch.msp"))
	fail(err)
	defer mspFile.Close()
	fail(patch.WriteMSP(mspFile))
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "genpatch:", err)
		os.Exit(1)
	}
}
