// Command genmsi builds a small deterministic sample MSI using the NEW
// public NewPackage() API (NOT the legacy Builder/MSIConfig path), exercising
// the P3 tables (Registry, Shortcut, Icon, Binary) so the external verification harness
// (scripts/verify_msi.sh) can cross-check the new API + P3 emission against
// msitools and cabextract. The legacy sample lives in internal/genmsi.
package main

import (
	"fmt"
	"os"

	msix "go.digitalxero.dev/go-msi"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: genmsi <output.msi>")
		os.Exit(2)
	}

	// A tiny but valid icon payload (distinctive bytes so msiinfo extract of the
	// Icon.AppIcon side stream yields non-empty content the harness can assert).
	icoBytes := make([]byte, 64)
	for i := range icoBytes {
		icoBytes[i] = byte((i * 7) % 251)
	}

	// A distinctive Binary payload so msiinfo extract of the Binary.AppData side
	// stream yields non-empty content the harness can assert (exercises the
	// Binary table + its CFB side stream end-to-end).
	binBytes := []byte("go-msix Binary table payload \x00\x01\x02 end")

	b := msix.NewPackage().
		WithProductName("Go MSIX P3 App").
		WithManufacturer("go-msix").
		WithVersion("1.2.3").
		WithAllUsers(true).
		WithProductCode("{22222222-3333-4444-5555-666666666666}").
		WithUpgradeCode("{77777777-8888-9999-AAAA-BBBBBBBBBBBB}").
		// P7: split the payload across two embedded cabinets (the 70KB dll lands
		// in its own cab) so the harness exercises the multi-cab path.
		WithCabSplitThreshold(50000).
		Icon("AppIcon", msix.FileSourceFromBytes(icoBytes)).
		Binary("AppData", msix.FileSourceFromBytes(binBytes)).
		WithProperty("GOMSIX_GREETING", "Welcome")

	install := b.RootDirectory("INSTALLFOLDER", "Go MSIX P3 App")
	comp := install.Component("MainComponent").AssociateToFeature("MainFeature")

	// A normal exe plus a long-named dll (forces an 8.3 short|long pair) and an
	// all-zeros body (exercises the MSZIP degenerate-distance sanitizer).
	comp.WithFile("app.exe", msix.FileSourceFromBytes([]byte("MZ fake executable payload for P3 verification")))
	comp.WithFile("MyLongLibraryName.dll", msix.FileSourceFromBytes(make([]byte, 70000)))

	// Registry values via the typed key builder (string + a #decimal int).
	comp.RegistryKey(msix.RegistryRootHKLM, `Software\GoMSIX`).
		Value("InstallDir", "[INSTALLFOLDER]").
		Value("Version", "1.2.3")

	// A non-advertised shortcut referencing the exe and the icon.
	comp.Shortcut("Go MSIX P3 App.lnk", "[#app.exe]").
		InDirectory("ProgramMenuFolder").
		Description("Launch Go MSIX P3 App").
		Icon("AppIcon", 0)

	// P4: a Windows service (install + control).
	comp.ServiceInstall("GoMsixSvc").
		WithDisplayName("Go MSIX Sample Service").
		WithStartType(msix.ServiceStartAuto).
		WithErrorControl(msix.ServiceErrorNormal).
		Vital(true).
		WithDescription("Sample service installed by go-msix").
		WithDelayedAutoStart()
	comp.ServiceControl("GoMsixSvc").
		OnInstall().Start().
		OnUninstall().Stop().Delete()

	// P4: an AppSearch reading a registry value into a property.
	b.Search("GOMSIX_INSTALLDIR").
		InRegistry(msix.RegistryRootHKLM, `Software\GoMSIX`, "InstallDir").
		AsRawValue()

	// P4: major-upgrade handling (remove older, block downgrade).
	b.MajorUpgrade().
		DowngradeErrorMessage("A newer version of Go MSIX P3 App is already installed.").
		Done()

	// P5: a deferred custom action (set a property) scheduled after InstallFiles.
	b.CustomAction("GoMsixConfigure").
		EXEFromBinary("AppData", "--configure").
		Deferred().
		NoImpersonate().
		ScheduleAfter(msix.InstallExecuteSequence, "InstallFiles", "NOT Installed")

	// P6: the canned minimal interactive UI (welcome+license, progress, exit).
	b.WithMinimalUI().
		WithLicenseText("Go MSIX sample license. By installing you accept these terms.")

	// P9: primary language (en-US) plus an embedded German language transform.
	// The transform localizes the product name / a property; msiexec selects it
	// with TRANSFORMS=:1031. The Template lists "x64;1033,1031".
	b.WithLanguage(msix.LangCode_enUS).
		WithLanguageTransform(msix.LangCode_deDE, func(de msix.PackageBuilder) {
			de.WithProductName("Go MSIX P3 Anwendung")
			de.WithProperty("GOMSIX_GREETING", "Willkommen")
		})

	b.Feature("MainFeature").
		WithTitle("Main Feature").
		WithDescription("Primary feature").
		WithDisplay(1).
		WithLevel(1)

	pkg, err := b.Build()
	if err != nil {
		fmt.Fprintln(os.Stderr, "genmsi-new: Build:", err)
		os.Exit(1)
	}

	f, err := os.Create(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "genmsi-new:", err)
		os.Exit(1)
	}
	defer f.Close()
	if err := pkg.WriteMSI(f); err != nil {
		fmt.Fprintln(os.Stderr, "genmsi-new: WriteMSI:", err)
		os.Exit(1)
	}
}
