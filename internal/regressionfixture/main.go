// Command regressionfixture authors native Windows regression packages through
// the public API. Every manifest value is checked against Windows Installer.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	msi "go.digitalxero.dev/go-msi"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: regressionfixture <output-directory>")
	}
	out, err := filepath.Abs(os.Args[1])
	must(err)
	must(os.MkdirAll(out, 0o755))
	manifest := map[string]map[string]any{}
	codes := map[string]string{
		"newer":   "{E881B3FD-C7C3-4A5B-A91C-E0B81F6E5E51}",
		"blocked": "{579127D2-C6EC-499E-A297-46F8EAADE8C1}",
		"allowed": "{E98666F6-2BAF-47A5-98D8-795E640CB1F4}",
		"user":    "{54F170F3-F931-4BE8-8CAC-82A7F2F6E3F7}",
	}
	for _, kind := range []string{"newer", "blocked", "allowed", "user"} {
		version, marker := "1.0.0", "OLDER"
		if kind == "newer" {
			version, marker = "2.0.0", "NEWER"
		}
		product, manufacturer := "Müller 日本語 🚀", "Éditeur Привет 🚀"
		upgrade := "{3E1FF310-66B5-4FBA-9F27-25878EBD1C9F}"
		if kind == "user" {
			upgrade = "{BC013F83-2D6B-42F6-992A-9DE3D478165F}"
		}
		payload := filepath.Join(out, kind+".exe")
		cmd := exec.Command("go", "build", "-p", "2", "-trimpath", "-ldflags", "-X main.version="+marker, "-o", payload, "./testdata/regression-payload")
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOMAXPROCS=2", "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		must(cmd.Run())
		b := msi.NewPackage().WithProductCode(codes[kind]).WithProductName(product).WithManufacturer(manufacturer).
			WithVersion(version).WithUpgradeCode(upgrade).WithPlatform(msi.Platform_x64).WithAllUsers(kind != "user")
		major := b.MajorUpgrade()
		if kind == "allowed" {
			major.AllowDowngrades()
			// Existing API deliberately separates allowing from removing newer products.
			b.Upgrade(upgrade).DetectRange(version, "").ActionProperty("REMOVE_NEWER")
		}
		directory := b.RootDirectory("INSTALLFOLDER", "MSI Regression")
		component := directory.Component("App").AssociateToFeature("Main")
		component.WithFilePath("app.exe", payload).WithVersion("")
		if kind == "user" {
			component.RegistryKey(msi.RegistryRootHKCU, `Software\GoMSIRegression`).Value("Installed", "1").AsKeyPath()
			b.CustomAction("UserIdentity").EXEFromDirectory("INSTALLFOLDER", `"[INSTALLFOLDER]app.exe" --custom-action "[INSTALLFOLDER]ca.txt"`).
				Deferred().NoImpersonate().ScheduleAfter(msi.InstallExecuteSequence, "InstallFiles", "NOT Installed")
		}
		b.Feature("Main").WithTitle("Regression").WithLevel(1)
		pkg, err := b.Build()
		must(err)
		target := filepath.Join(out, kind+".msi")
		f, err := os.Create(target)
		must(err)
		must(pkg.WriteMSI(f))
		must(f.Close())
		f, err = os.Open(target)
		must(err)
		db, err := msi.Open(f)
		must(err)
		props, err := db.Table("Property")
		must(err)
		code := ""
		for _, row := range props {
			if row["Property"] == "ProductCode" {
				code = row["Value"].(string)
			}
		}
		if code != codes[kind] {
			panic("persisted ProductCode differs")
		}
		manifest[kind] = map[string]any{"product": product, "manufacturer": manufacturer, "code": code, "upgrade": upgrade, "version": version, "wordCount": db.Summary().WordCount(), "payload": marker}
		must(f.Close())
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(out, "manifest.json"), data, 0o644))
	fmt.Println("MSI_REGRESSION_FIXTURES_OK")
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
