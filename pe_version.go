package msi

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// sourcePEVersion inspects actual PE resources, independent of file extension.
// Sequential sources are staged to disk only after an MZ header is found.
func sourcePEVersion(src FileSource) (version, language string, err error) {
	rc, err := src.Open()
	if err != nil {
		return "", "", err
	}
	defer rc.Close()
	var header [64]byte
	n, err := io.ReadFull(rc, header[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", "", err
	}
	if n < len(header) || string(header[:2]) != "MZ" {
		return "", "", nil // ordinary data, including short MZ-prefixed payloads
	}
	reader, ok := rc.(io.ReaderAt)
	if !ok {
		temp, err := os.CreateTemp("", "go-msi-pe-*")
		if err != nil {
			return "", "", err
		}
		defer os.Remove(temp.Name())
		defer temp.Close()
		if _, err := temp.Write(header[:]); err != nil {
			return "", "", err
		}
		if src.Size() < int64(len(header)) {
			return "", "", fmt.Errorf("PE source is smaller than its header")
		}
		if _, err := io.CopyN(temp, rc, src.Size()-int64(len(header))); err != nil {
			return "", "", err
		}
		reader = temp
	}
	image, err := pe.NewFile(reader)
	if err != nil {
		return "", "", fmt.Errorf("invalid PE image: %w", err)
	}
	defer image.Close()
	var resource pe.DataDirectory
	switch optional := image.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		resource = optional.DataDirectory[2]
	case *pe.OptionalHeader64:
		resource = optional.DataDirectory[2]
	default:
		return "", "", fmt.Errorf("PE image has no optional header")
	}
	if resource.VirtualAddress == 0 || resource.Size == 0 {
		return "", "", missingPEVersion()
	}
	// Read bounded ranges from raw sections; never materialize the image.
	readRVA := func(rva, size uint32) ([]byte, error) {
		if size > 65536 {
			return nil, fmt.Errorf("PE version resource range too large: %d", size)
		}
		for _, section := range image.Sections {
			if uint64(rva) >= uint64(section.VirtualAddress) && uint64(rva)+uint64(size) <= uint64(section.VirtualAddress)+uint64(section.Size) {
				data := make([]byte, int(size))
				_, err := section.ReadAt(data, int64(rva-section.VirtualAddress))
				return data, err
			}
		}
		return nil, fmt.Errorf("PE resource RVA %#x is outside raw sections", rva)
	}
	readResource := func(offset, size uint32) ([]byte, error) {
		if uint64(offset)+uint64(size) > uint64(resource.Size) || uint64(resource.VirtualAddress)+uint64(offset)+uint64(size) > 1<<32 {
			return nil, fmt.Errorf("PE resource directory range is out of bounds")
		}
		return readRVA(resource.VirtualAddress+offset, size)
	}
	languages := make(map[uint16]bool)
	remainingEntries := 65536
	var walk func(offset uint32, depth int, lang uint16) error
	walk = func(offset uint32, depth int, lang uint16) error {
		head, err := readResource(offset, 16)
		if err != nil {
			return err
		}
		count := uint32(binary.LittleEndian.Uint16(head[12:])) + uint32(binary.LittleEndian.Uint16(head[14:]))
		for i := uint32(0); i < count; i++ {
			remainingEntries--
			if remainingEntries < 0 {
				return fmt.Errorf("PE resource directory has too many entries")
			}
			entry, err := readResource(offset+16+i*8, 8)
			if err != nil {
				return err
			}
			id, next := binary.LittleEndian.Uint32(entry), binary.LittleEndian.Uint32(entry[4:])
			if depth == 0 && id != 16 { // RT_VERSION
				continue
			}
			if depth < 2 {
				if next&0x80000000 == 0 {
					return fmt.Errorf("PE version resource is missing a directory")
				}
				if err := walk(next&0x7fffffff, depth+1, lang); err != nil {
					return err
				}
				continue
			}
			if next&0x80000000 != 0 || id > 65535 {
				return fmt.Errorf("invalid PE version language entry")
			}
			lang = uint16(id)
			leaf, err := readResource(next, 16)
			if err != nil {
				return err
			}
			blob, err := readRVA(binary.LittleEndian.Uint32(leaf), binary.LittleEndian.Uint32(leaf[4:]))
			if err != nil {
				return err
			}
			found, translations, err := parsePEVersionInfo(blob)
			if err != nil {
				return err
			}
			if version != "" && version != found {
				return fmt.Errorf("PE version resources disagree: %s and %s", version, found)
			}
			version = found
			if len(translations) == 0 {
				languages[lang] = true
			}
			for _, value := range translations {
				languages[value] = true
			}
		}
		return nil
	}
	if err := walk(0, 0, 0); err != nil {
		return "", "", err
	}
	if version == "" {
		return "", "", missingPEVersion()
	}
	ids := make([]int, 0, len(languages))
	for id := range languages {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(id)
	}
	return version, strings.Join(parts, ","), nil
}

func missingPEVersion() error {
	return fmt.Errorf("PE image has no fixed file version resource; use FileBuilder.WithVersion to supply a version, or WithVersion(\"\") to explicitly keep it unversioned")
}

func alignVersionOffset(n int) int { return (n + 3) &^ 3 }

// versionInfoBlock decodes the bounded VS_VERSIONINFO framing shared by all
// children. Binary value lengths count bytes; text value lengths count WORDs.
func versionInfoBlock(data []byte) (key string, value, children []byte, err error) {
	if len(data) < 6 {
		return "", nil, nil, fmt.Errorf("truncated PE version block")
	}
	length, valueLength := int(binary.LittleEndian.Uint16(data)), int(binary.LittleEndian.Uint16(data[2:]))
	if length < 6 || length > len(data) {
		return "", nil, nil, fmt.Errorf("invalid PE version block length")
	}
	data = data[:length]
	var units []uint16
	offset := 6
	for {
		if offset+2 > len(data) {
			return "", nil, nil, fmt.Errorf("unterminated PE version key")
		}
		unit := binary.LittleEndian.Uint16(data[offset:])
		offset += 2
		if unit == 0 {
			break
		}
		units = append(units, unit)
	}
	key = string(utf16.Decode(units))
	if binary.LittleEndian.Uint16(data[4:]) == 1 {
		valueLength *= 2
	}
	offset = alignVersionOffset(offset)
	if valueLength == 0 && offset >= len(data) {
		return key, nil, nil, nil
	}
	if offset+valueLength > len(data) {
		return "", nil, nil, fmt.Errorf("truncated PE version value")
	}
	value = data[offset : offset+valueLength]
	if next := alignVersionOffset(offset + valueLength); next < len(data) {
		children = data[next:]
	}
	return key, value, children, nil
}

func parsePEVersionInfo(data []byte) (string, []uint16, error) {
	key, value, children, err := versionInfoBlock(data)
	if err != nil {
		return "", nil, err
	}
	if key != "VS_VERSION_INFO" || len(value) != 52 || binary.LittleEndian.Uint32(value) != 0xfeef04bd {
		return "", nil, fmt.Errorf("invalid VS_FIXEDFILEINFO resource")
	}
	ms, ls := binary.LittleEndian.Uint32(value[8:]), binary.LittleEndian.Uint32(value[12:])
	version := fmt.Sprintf("%d.%d.%d.%d", ms>>16, ms&65535, ls>>16, ls&65535)
	var languages []uint16
	// Only the defined VarFileInfo/Translation nesting is relevant here.
	for len(children) > 0 {
		key, _, vars, err := versionInfoBlock(children)
		if err != nil {
			return "", nil, err
		}
		if key == "VarFileInfo" {
			for len(vars) > 0 {
				name, translations, _, err := versionInfoBlock(vars)
				if err != nil {
					return "", nil, err
				}
				if name == "Translation" {
					if len(translations)%4 != 0 {
						return "", nil, fmt.Errorf("invalid PE version Translation length")
					}
					for i := 0; i < len(translations); i += 4 {
						languages = append(languages, binary.LittleEndian.Uint16(translations[i:]))
					}
				}
				next := alignVersionOffset(int(binary.LittleEndian.Uint16(vars)))
				if next >= len(vars) {
					break
				}
				vars = vars[next:]
			}
		}
		next := alignVersionOffset(int(binary.LittleEndian.Uint16(children)))
		if next >= len(children) {
			break
		}
		children = children[next:]
	}
	return version, languages, nil
}
