// Command searchfixture authors raw AppSearch packages through the public API.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	msi "go.digitalxero.dev/go-msi"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: searchfixture <output-directory>")
	}
	out, err := filepath.Abs(os.Args[1])
	must(err)
	must(os.MkdirAll(out, 0o755))
	upgrade := "{DB142D07-485C-46DB-B6F4-76D41BB78830}"
	registry := `Software\GoMSIRawSearch30`
	codes := []string{"{BBF78C36-CCEE-42B9-B6C7-A13202300001}", "{BBF78C36-CCEE-42B9-B6C7-A13202300002}"}
	manifest := map[string]any{"upgrade": upgrade, "registry": registry, "directory": "Go MSI Raw Search 30", "codes": codes}
	for i, code := range codes {
		version := fmt.Sprintf("%d.0.0", i+1)
		b := msi.NewPackage().WithProductName("Go MSI Raw Search 30").WithManufacturer("go-msi").
			WithVersion(version).WithProductCode(code).WithUpgradeCode(upgrade).
			WithPlatform(msi.Platform_Intel).WithAllUsers(true).InstallToProgramFiles()
		b.MajorUpgrade().Done()
		component := b.RootDirectory("INSTALLFOLDER", "Go MSI Raw Search 30").Component("Payload").AssociateToFeature("Main")
		component.WithFile("payload.txt", msi.FileSourceFromBytes([]byte(version)))
		component.RegistryKey(msi.RegistryRootHKLM, registry).Value("InstallFolder", "[INSTALLFOLDER]")
		b.Feature("Main").WithTitle("Main").WithLevel(1)
		b.Search("SAVED_PATH").InRegistry(msi.RegistryRootHKLM, registry, "InstallFolder").AsRawValue()
		// Recovery is an authoring decision: preserve explicit caller overrides,
		// and restore before costing for install, major upgrade and uninstall.
		for _, sequence := range []msi.SequenceTable{msi.InstallUISequence, msi.InstallExecuteSequence} {
			b.CustomAction("RestoreSavedFolder"+string(sequence)).SetProperty("INSTALLFOLDER", "[SAVED_PATH]").
				ScheduleAfter(sequence, "AppSearch", "SAVED_PATH AND NOT INSTALLFOLDER")
		}
		pkg, err := b.Build()
		must(err)
		var data bytes.Buffer
		must(pkg.WriteMSI(&data))
		db, err := msi.Open(bytes.NewReader(data.Bytes()))
		must(err)
		rows, err := db.Table("Signature")
		must(err)
		if len(rows) != 0 {
			panic("raw AppSearch must not acquire a file-signature row")
		}
		must(os.WriteFile(filepath.Join(out, fmt.Sprintf("v%d.msi", i+1)), data.Bytes(), 0o644))
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(out, "manifest.json"), data, 0o644))
	fmt.Println("MSI_RAW_SEARCH_FIXTURES_OK")
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
