package msi

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func versionTestBlock(key string, value, children []byte) []byte {
	data := make([]byte, 6)
	for _, unit := range append(utf16.Encode([]rune(key)), 0) {
		data = binary.LittleEndian.AppendUint16(data, unit)
	}
	for len(data)%4 != 0 {
		data = append(data, 0)
	}
	data = append(data, value...)
	if len(children) > 0 {
		for len(data)%4 != 0 {
			data = append(data, 0)
		}
		data = append(data, children...)
	}
	binary.LittleEndian.PutUint16(data, uint16(len(data)))
	binary.LittleEndian.PutUint16(data[2:], uint16(len(value)))
	return data
}

func testVersionResource() []byte {
	info := make([]byte, 52)
	binary.LittleEndian.PutUint32(info, 0xfeef04bd)
	binary.LittleEndian.PutUint32(info[4:], 0x10000)
	binary.LittleEndian.PutUint32(info[8:], 1<<16|2)
	binary.LittleEndian.PutUint32(info[12:], 3<<16|4)
	// Deliberately differ from the fixed file version.
	binary.LittleEndian.PutUint32(info[16:], 9<<16|8)
	translation := versionTestBlock("Translation", []byte{9, 4, 0xb0, 4, 7, 4, 0xb0, 4}, nil)
	return versionTestBlock("VS_VERSION_INFO", info, versionTestBlock("VarFileInfo", nil, translation))
}

func testPEImage(t *testing.T, wide bool, blob []byte) []byte {
	t.Helper()
	resource := make([]byte, 88)
	for _, offset := range []int{0, 24, 48} {
		binary.LittleEndian.PutUint16(resource[offset+14:], 1)
	}
	for _, entry := range []struct {
		offset   int
		id, next uint32
	}{
		{16, 16, 0x80000018}, {40, 1, 0x80000030}, {64, 1033, 72},
	} {
		binary.LittleEndian.PutUint32(resource[entry.offset:], entry.id)
		binary.LittleEndian.PutUint32(resource[entry.offset+4:], entry.next)
	}
	binary.LittleEndian.PutUint32(resource[72:], 0x1000+88)
	binary.LittleEndian.PutUint32(resource[76:], uint32(len(blob)))
	resource = append(resource, blob...)
	data := make([]byte, 64)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[60:], 64)
	buf := bytes.NewBuffer(append(data, 'P', 'E', 0, 0))
	header := pe.FileHeader{Machine: pe.IMAGE_FILE_MACHINE_I386, NumberOfSections: 1, SizeOfOptionalHeader: uint16(binary.Size(pe.OptionalHeader32{}))}
	var optional any
	directory := pe.DataDirectory{VirtualAddress: 0x1000, Size: uint32(len(resource))}
	if wide {
		header.Machine, header.SizeOfOptionalHeader = pe.IMAGE_FILE_MACHINE_AMD64, uint16(binary.Size(pe.OptionalHeader64{}))
		o := pe.OptionalHeader64{Magic: 0x20b, NumberOfRvaAndSizes: 16, SizeOfHeaders: 512}
		o.DataDirectory[2] = directory
		optional = o
	} else {
		o := pe.OptionalHeader32{Magic: 0x10b, NumberOfRvaAndSizes: 16, SizeOfHeaders: 512}
		o.DataDirectory[2] = directory
		optional = o
	}
	require.NoError(t, binary.Write(buf, binary.LittleEndian, header))
	require.NoError(t, binary.Write(buf, binary.LittleEndian, optional))
	section := pe.SectionHeader32{VirtualAddress: 0x1000, VirtualSize: uint32(len(resource)), PointerToRawData: 512, SizeOfRawData: uint32(len(resource))}
	copy(section.Name[:], ".rsrc")
	require.NoError(t, binary.Write(buf, binary.LittleEndian, section))
	return append(append(buf.Bytes(), make([]byte, 512-buf.Len())...), resource...)
}

func TestAutomaticPEVersionAndLanguage(t *testing.T) {
	for _, wide := range []bool{false, true} {
		t.Run(map[bool]string{false: "PE32", true: "PE32+"}[wide], func(t *testing.T) {
			data := testPEImage(t, wide, testVersionResource())
			path := filepath.Join(t.TempDir(), "payload.bin") // extension is irrelevant
			require.NoError(t, os.WriteFile(path, data, 0o600))
			source, err := FileSourceFromPath(path)
			require.NoError(t, err)
			for _, src := range []FileSource{source, FileSourceFromBytes(data), FileSourceFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }, int64(len(data)))} {
				version, language, err := sourcePEVersion(src)
				require.NoError(t, err)
				assert.Equal(t, "1.2.3.4", version)
				assert.Equal(t, "1031,1033", language)
			}
			b := NewPackage().WithProductName("PE metadata").WithManufacturer("Test").WithVersion("1.0.0")
			b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("Main").WithFile("app.exe", source)
			b.Feature("Main").WithLevel(1)
			pkg, err := b.Build()
			require.NoError(t, err)
			var out bytes.Buffer
			require.NoError(t, pkg.WriteMSI(&out))
			db, err := readMSIDatabase(bytes.NewReader(out.Bytes()))
			require.NoError(t, err)
			table, err := db.GetTable("File")
			require.NoError(t, err)
			require.Len(t, table.rows(), 1)
			assert.Equal(t, "1.2.3.4", table.rows()[0].values()[4])
			assert.Equal(t, "1031,1033", table.rows()[0].values()[5])
		})
	}
}

func TestPEVersionErrorsAndOverrides(t *testing.T) {
	data := testPEImage(t, true, testVersionResource())
	missing := append([]byte(nil), data...)
	// Remove resource directory from the PE32+ optional header.
	clear(missing[64+24+112+16 : 64+24+112+24])
	_, _, err := sourcePEVersion(FileSourceFromBytes(missing))
	require.ErrorContains(t, err, "WithVersion")
	for _, override := range []string{"", "7.6.5.4"} {
		b := NewPackage().WithProductName("Override").WithManufacturer("Test").WithVersion("1.0.0")
		b.RootDirectory("INSTALLFOLDER", "App").Component("Main").AssociateToFeature("Main").WithFile("app.exe", FileSourceFromBytes(missing)).WithVersion(override)
		b.Feature("Main").WithLevel(1)
		pkg, err := b.Build()
		require.NoError(t, err)
		var out bytes.Buffer
		require.NoError(t, pkg.WriteMSI(&out))
		db, err := readMSIDatabase(bytes.NewReader(out.Bytes()))
		require.NoError(t, err)
		table, err := db.GetTable("File")
		require.NoError(t, err)
		if override == "" {
			assert.Nil(t, table.rows()[0].values()[4])
		} else {
			assert.Equal(t, override, table.rows()[0].values()[4])
		}
	}
	for _, content := range [][]byte{nil, []byte("ordinary data"), []byte("MZlegacy fake executable")} {
		version, language, err := sourcePEVersion(FileSourceFromBytes(content))
		require.NoError(t, err)
		assert.Empty(t, version)
		assert.Empty(t, language)
	}
	for _, size := range []int{1, 63, 70, len(data) - 1} {
		_, _, err := sourcePEVersion(FileSourceFromBytes(data[:size]))
		if size >= 64 {
			require.Error(t, err)
		}
	}
	broken := testPEImage(t, false, []byte{1, 2, 3})
	_, _, err = sourcePEVersion(FileSourceFromBytes(broken))
	require.ErrorContains(t, err, "truncated PE version block")
}
