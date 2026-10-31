// Command authoringfixture generates public-API cases for real Windows tests.
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
		panic("usage: authoringfixture <out>")
	}
	out, err := filepath.Abs(os.Args[1])
	must(err)
	must(os.MkdirAll(out, 0o755))
	manifest := map[string]map[string]any{}
	for i, kind := range []string{"repair-a", "repair-b", "aliases", "ui-success", "ui-cancel", "ui-error", "names", "shortcuts"} {
		code := fmt.Sprintf("{A6223300-4455-4666-8777-%012d}", i+1)
		if kind == "repair-b" {
			code = "{A6223300-4455-4666-8777-000000000001}"
		}
		b := msi.NewPackage().WithProductCode(code).WithUpgradeCode("{718F944D-8901-46A0-B4F3-D2F06C73E029}").WithProductName("Go MSI " + kind).
			WithManufacturer("go-msi regressions").WithVersion("1.0.0").WithAllUsers(true)
		// Repair variants keep all metadata and IDs equal; only same-sized bytes vary.
		if kind == "repair-a" || kind == "repair-b" {
			b.WithProductName("Go MSI repair")
		}
		d := b.RootDirectory("INSTALLFOLDER", "Authoring Regression")
		payloads := map[string]string{}
		add := func(dir msi.DirectoryBuilder, id, name, text string) {
			dir.Component(id).AssociateToFeature("Main").WithFile(name, msi.FileSourceFromBytes([]byte(text)))
			payloads[name] = text
		}
		switch kind {
		case "repair-a", "repair-b":
			add(d, "Payload", "payload.txt", kind)
		case "aliases":
			add(d, "Long", "abcdef1long.txt", "LONG PAYLOAD")
			add(d, "Literal", "abcdef~1.txt", "LITERAL PAYLOAD")
			add(d, "Second", "abcdef2long.txt", "SECOND PAYLOAD")
			child := d.Subdirectory("LongDirectory", "ghijkl1long.txt")
			add(child, "Child", "child.txt", "CHILD PAYLOAD")
			add(d, "DirectoryLiteral", "ghijkl~1.txt", "DIRECTORY SIBLING")
		case "shortcuts":
			add(d, "LongLinkPayload", "abcdef1long.lnk", "PLAIN PAYLOAD WITH LINK EXTENSION")
			add(d, "LiteralLinkPayload", "abcdef~1.lnk", "LITERAL PAYLOAD WITH LINK EXTENSION")
			c := d.Component("LinkTarget").AssociateToFeature("Main")
			c.WithFile("payload.txt", msi.FileSourceFromBytes([]byte("SHORTCUT TARGET")))
			c.Shortcut("abcdef2long.lnk", "Main").Advertised("Main")
		case "names":
			add(d, "Unicode", "résumé.txt", "UNICODE PAYLOAD")
			add(d, "LeadingDot", ".config", "LEADING DOT PAYLOAD")
		default:
			b.WithMinimalUI().WithLicenseText("Native UI regression license. Accept to install.")
			add(d, "Payload", "payload.txt", kind)
			// Keep progress visible and process real MSI messages during this interval.
			// The condition also permits cancellation while the execute sequence runs.
			b.CustomAction("VisibleProgress").EXEFromDirectory("SystemFolder", `"[SystemFolder]cmd.exe" /c ping -n 16 127.0.0.1 > nul`).
				ScheduleAfter(msi.InstallExecuteSequence, "InstallFiles", "NOT Installed")
			if kind == "ui-error" {
				b.CustomAction("ForcedFailure").ErrorMessage("Intentional native UI regression failure").ScheduleBefore(msi.InstallExecuteSequence, "InstallFinalize", "NOT Installed")
			}
		}
		b.Feature("Main").WithTitle("Main").WithLevel(1)
		p, err := b.Build()
		must(err)
		var data bytes.Buffer
		must(p.WriteMSI(&data))
		target := filepath.Join(out, kind, "package.msi")
		must(os.MkdirAll(filepath.Dir(target), 0o755))
		must(os.WriteFile(target, data.Bytes(), 0o644))
		db, err := msi.Open(bytes.NewReader(data.Bytes()))
		must(err)
		files, err := db.Table("File")
		must(err)
		dirs, err := db.Table("Directory")
		must(err)
		var shortcuts []msi.Row
		if kind == "shortcuts" {
			shortcuts, err = db.Table("Shortcut")
			must(err)
		}
		manifest[kind] = map[string]any{"code": code, "packageCode": db.Summary().Revision(), "product": "Go MSI " + kind, "files": files, "directories": dirs, "shortcuts": shortcuts, "payloads": payloads}
	}
	// Public authoring must fail before output, on Windows too.
	for _, name := range []string{"CON", "NUL.txt", "COM1.log", "LPT9", "COM¹.txt", "LPT².log", "COM³", "readme.txt.", "readme.txt "} {
		for _, directory := range []bool{false, true} {
			b := msi.NewPackage().WithProductName("Invalid name").WithManufacturer("go-msi").WithVersion("1.0.0")
			d := b.RootDirectory("INSTALLFOLDER", "Names")
			if directory {
				d = d.Subdirectory("Invalid", name)
				nameFile(d, "valid.txt")
			} else {
				nameFile(d, name)
			}
			b.Feature("Main").WithLevel(1)
			p, err := b.Build()
			must(err)
			var output bytes.Buffer
			if err := p.WriteMSI(&output); err == nil || output.Len() != 0 {
				panic(fmt.Sprintf("invalid name accepted or partial output: %q directory=%v", name, directory))
			}
		}
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(out, "manifest.json"), data, 0o644))
	fmt.Println("AUTHORING_FIXTURES_AND_WINDOWS_NAME_REJECTIONS_OK")
}
func nameFile(d msi.DirectoryBuilder, name string) {
	d.Component("Payload").AssociateToFeature("Main").WithFile(name, msi.FileSourceFromBytes([]byte("name")))
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
