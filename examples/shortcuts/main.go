// Command shortcuts packages a Windows executable with a Start Menu shortcut.
// The executable must already contain an icon resource for the explicit icon.
// Run from the repository root:
//
//	go run ./examples/shortcuts /path/to/app.exe MyApp.msi
package main

import (
	"fmt"
	"os"

	msi "go.digitalxero.dev/go-msi"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: shortcuts <icon-bearing-app.exe> <output.msi>")
	}
	app, err := msi.FileSourceFromPath(args[0])
	if err != nil {
		return fmt.Errorf("read application: %w", err)
	}

	b := msi.NewPackage().
		WithProductName("My App").
		WithManufacturer("My Company").
		WithVersion("1.0.0").
		WithProductCode("{12345678-1234-1234-1234-123456789ABC}").
		WithUpgradeCode("{ABCDEF01-2345-6789-ABCD-EF0123456789}").
		InstallToProgramFiles()

	c := b.RootDirectory("INSTALLFOLDER", "My App").
		Component("Main").AssociateToFeature("MainFeature")
	c.WithFile("app.exe", app)
	b.Feature("MainFeature").WithTitle("Main Feature").WithLevel(1)

	// Register a separate Icon-table stream. Reusing the application EXE is
	// convenient but increases MSI size; the EXE must contain an icon resource.
	b.Icon("app.exe", app)
	c.Shortcut("My App.lnk", "[INSTALLFOLDER]app.exe").
		InDirectory("ProgramMenuFolder").
		Description("Launch My App").
		Icon("app.exe", 0)
	// "Start in" defaults to c's directory (INSTALLFOLDER). To choose another
	// directory, add WorkingDirectory("PersonalFolder") to the shortcut chain.
	// Advertised is omitted so Target contains the ordinary executable path.

	pkg, err := b.Build()
	if err != nil {
		return fmt.Errorf("build MSI: %w", err)
	}
	out, err := os.Create(args[1])
	if err != nil {
		return fmt.Errorf("create MSI: %w", err)
	}
	writeErr := pkg.WriteMSI(out)
	closeErr := out.Close()
	if writeErr != nil {
		return fmt.Errorf("write MSI: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close MSI: %w", closeErr)
	}
	return nil
}
