// Command compatfixture builds a real executable and a public-API MSI fixture.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	msi "go.digitalxero.dev/go-msi"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: compatfixture <output-directory>")
		os.Exit(2)
	}
	out, err := filepath.Abs(os.Args[1])
	fail(err)
	payload := filepath.Join(out, "payload")
	fail(os.MkdirAll(payload, 0o755))
	executable := filepath.Join(payload, "compat.exe")
	cmd := exec.Command("go", "build", "-p", "2", "-trimpath", "-o", executable, "./testdata/compatibility/main.go")
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOMAXPROCS=2", "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	fail(cmd.Run())
	dataPath := filepath.Join(payload, "message.txt")
	fail(os.WriteFile(dataPath, []byte("MSI compatibility payload\n"), 0o644))
	b := msi.NewPackage().
		WithProductName("MSI Compatibility").WithManufacturer("Digitalxero").WithVersion("1.0.0").
		WithProductCode("{40E9F13B-993D-42DB-A625-C3214388645F}").
		WithUpgradeCode("{485B6AA0-1B1D-4F91-AC83-C9D45D5836E6}").
		WithPlatform(msi.Platform_x64).WithLanguage(msi.LangCode_enUS).WithAllUsers(true)
	directory := b.RootDirectory("INSTALLFOLDER", "MSI Compatibility")
	for _, name := range []string{"compat.exe", "message.txt"} {
		source, sourceErr := msi.FileSourceFromPath(filepath.Join(payload, name))
		fail(sourceErr)
		directory.Component(name).AssociateToFeature("Main").WithFile(name, source)
	}
	b.Feature("Main").WithTitle("Compatibility").WithLevel(1)
	pkg, err := b.Build()
	fail(err)
	f, err := os.Create(filepath.Join(out, "compat.msi"))
	fail(err)
	fail(pkg.WriteMSI(f))
	fail(f.Close())
	fmt.Println("MSI_FIXTURE_OK")
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
