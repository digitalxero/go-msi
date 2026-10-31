// Command verifyicecontrol audits the SDK's Unicode-case validation copy.
// It must preserve every table value except File.FileName case and every
// Summary property. Original-cased packages are installed separately on Windows.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"

	"github.com/abemedia/go-cfb"
	msi "go.digitalxero.dev/go-msi"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: verifyicecontrol <original.msi> <uppercase-control.msi>")
	}
	original, control := open(os.Args[1]), open(os.Args[2])
	if !reflect.DeepEqual(original.Tables(), control.Tables()) {
		panic("validation control changed table set")
	}
	for _, name := range original.Tables() {
		before, err := original.Table(name)
		must(err)
		after, err := control.Table(name)
		must(err)
		if name == "File" {
			for _, row := range before {
				row["FileName"] = strings.ToUpper(row["FileName"].(string))
			}
		}
		if !reflect.DeepEqual(canonical(before), canonical(after)) {
			panic("validation control changed non-case data in " + name)
		}
	}
	// Both SummaryInfo implementations contain the complete decoded property set.
	// DeepEqual compares all fields, including PackageCode, privilege bits and time.
	if !reflect.DeepEqual(original.Summary(), control.Summary()) {
		panic("validation control changed Summary metadata")
	}
	if !reflect.DeepEqual(dataStreams(os.Args[1]), dataStreams(os.Args[2])) {
		panic("validation control changed cabinet, other data stream or root CLSID")
	}
	fmt.Println("NATIVE_ICE_CONTROL_ONLY_FILENAME_CASE_DIFFERS_OK")
}
func dataStreams(path string) map[string][32]byte {
	f, err := os.Open(path)
	must(err)
	defer f.Close()
	reader, err := cfb.NewReader(f)
	must(err)
	out := map[string][32]byte{"root CLSID": sha256.Sum256(reader.CLSID[:])}
	for _, entry := range reader.Entries {
		stream, ok := entry.(*cfb.Stream)
		if !ok {
			panic("unexpected sub-storage in the bounded Unicode fixture")
		}
		if strings.HasPrefix(stream.Name, "\u4840") {
			continue
		}
		h := sha256.New()
		_, err := io.Copy(h, stream.Open())
		must(err)
		var digest [32]byte
		copy(digest[:], h.Sum(nil))
		out[stream.Name] = digest
	}
	return out
}

func open(path string) msi.Database {
	f, err := os.Open(path)
	must(err)
	defer f.Close()
	db, err := msi.Open(f)
	must(err)
	return db
}
func canonical(rows []msi.Row) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		data, err := json.Marshal(row)
		must(err)
		out = append(out, string(data))
	}
	slices.Sort(out)
	return out
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
