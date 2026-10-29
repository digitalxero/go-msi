//go:build windows

package msi_test

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	"github.com/abemedia/go-cfb"
	msi "go.digitalxero.dev/go-msi"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Use the Unicode Windows Installer API as an independent summary decoder.
func TestNativeUnicodeSummary(t *testing.T) {
	dll := syscall.NewLazyDLL("msi.dll")
	getSummary := dll.NewProc("MsiGetSummaryInformationW")
	getProperty := dll.NewProc("MsiSummaryInfoGetPropertyW")
	closeHandle := dll.NewProc("MsiCloseHandle")
	for _, name := range []string{"ASCII control", "Müller café", "日本語 Привет", "Tools 🚀"} {
		t.Run(name, func(t *testing.T) {
			pkg, err := readerTestPackage().WithProductName(name).WithManufacturer(name).Build()
			require.NoError(t, err)
			target := filepath.Join(t.TempDir(), "unicode.msi")
			f, err := os.Create(target)
			require.NoError(t, err)
			require.NoError(t, pkg.WriteMSI(f))
			require.NoError(t, f.Close())
			path, err := syscall.UTF16PtrFromString(target)
			require.NoError(t, err)
			var handle uint32
			rc, _, _ := getSummary.Call(0, uintptr(unsafe.Pointer(path)), 0, uintptr(unsafe.Pointer(&handle)))
			require.Zero(t, rc, "MsiGetSummaryInformationW")
			defer closeHandle.Call(uintptr(handle))
			for _, property := range []uintptr{3, 4} {
				var dataType uint32
				var integer int32
				buffer := make([]uint16, 1024)
				length := uint32(len(buffer))
				rc, _, _ := getProperty.Call(uintptr(handle), property, uintptr(unsafe.Pointer(&dataType)), uintptr(unsafe.Pointer(&integer)), 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&length)))
				require.Zero(t, rc, "MsiSummaryInfoGetPropertyW PID %d", property)
				assert.Equal(t, uint32(30), dataType, "PID %d variant type", property)
				actual := syscall.UTF16ToString(buffer)
				if !assert.Equal(t, name, actual, "PID %d codepoints: %U (length %d)", property, []rune(actual), length) && property == 3 && name == "Müller café" {
					diagnoseNativeSummary(t, target, name)
				}
			}
		})
	}
}

// Compare failing wire data with Windows Installer's own persisted output.
func diagnoseNativeSummary(t *testing.T, original, name string) {
	t.Helper()
	dll := syscall.NewLazyDLL("msi.dll")
	open := dll.NewProc("MsiGetSummaryInformationW")
	set := dll.NewProc("MsiSummaryInfoSetPropertyW")
	persist := dll.NewProc("MsiSummaryInfoPersist")
	close := dll.NewProc("MsiCloseHandle")
	data, err := os.ReadFile(original)
	require.NoError(t, err)
	for _, cp := range []uintptr{1252, 1200, 65001} {
		target := filepath.Join(t.TempDir(), "native.msi")
		require.NoError(t, os.WriteFile(target, data, 0600))
		path, err := syscall.UTF16PtrFromString(target)
		require.NoError(t, err)
		var handle uint32
		rc, _, _ := open.Call(0, uintptr(unsafe.Pointer(path)), 20, uintptr(unsafe.Pointer(&handle)))
		if rc != 0 {
			t.Logf("native open cp %d rc %d", cp, rc)
			continue
		}
		rc, _, _ = set.Call(uintptr(handle), 1, 2, cp, 0, 0)
		t.Logf("native set codepage %d rc %d", cp, rc)
		text, err := syscall.UTF16PtrFromString(name)
		require.NoError(t, err)
		rc, _, _ = set.Call(uintptr(handle), 3, 30, 0, 0, uintptr(unsafe.Pointer(text)))
		t.Logf("native set Subject cp %d rc %d", cp, rc)
		rc, _, _ = persist.Call(uintptr(handle))
		t.Logf("native persist cp %d rc %d", cp, rc)
		close.Call(uintptr(handle))
		f, err := os.Open(target)
		require.NoError(t, err)
		db, err := msi.Open(f)
		if err == nil {
			t.Logf("Go reader of native summary cp %d: cp=%d subject=%q", cp, db.Summary().CodePage(), db.Summary().Subject())
		} else {
			t.Logf("Go reader of native summary cp %d: %v", cp, err)
		}
		reader, err := cfb.NewReader(f)
		require.NoError(t, err)
		stream, err := reader.OpenStream("\x05SummaryInformation")
		require.NoError(t, err)
		wire, err := io.ReadAll(stream.Open())
		require.NoError(t, err)
		t.Logf("native summary cp %d bytes: %x", cp, wire)
		require.NoError(t, f.Close())
	}
}
