//go:build windows

package msi_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Use the Unicode Windows Installer API as an independent summary decoder.
func TestNativeUnicodeSummary(t *testing.T) {
	dll := syscall.NewLazyDLL("msi.dll")
	getSummary := dll.NewProc("MsiGetSummaryInformationW")
	getProperty := dll.NewProc("MsiSummaryInfoGetPropertyW")
	closeHandle := dll.NewProc("MsiCloseHandle")
	for _, name := range []string{"Müller café", "日本語 Привет", "Tools 🚀"} {
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
				assert.Equal(t, name, actual, "PID %d codepoints: %U", property, []rune(actual))
			}
		})
	}
}
