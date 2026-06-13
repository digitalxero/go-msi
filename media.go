package msi

import (
	"fmt"
	"io"
	"sort"
)

// msi_media.go — P7 multi-media planning. Splits payload files across one or
// more cabinets (Media rows) either automatically (a size threshold) or
// explicitly (per-component AssignToMedia / declared Media). The default — no
// options set — yields exactly one embedded #cab1.cab with all files in
// sequence order, byte-identical to the historical single-cab output.

// MediaBuilder declares an explicit cabinet/disk (DiskId) and its properties.
type MediaBuilder interface {
	// WithCabinet sets the cabinet name. Embedded by default; call External to
	// emit it as a separate file instead.
	WithCabinet(name string) MediaBuilder
	External() MediaBuilder
	WithVolumeLabel(label string) MediaBuilder
	WithDiskPrompt(prompt string) MediaBuilder
	Done() PackageBuilder
}

type mediaEntry struct {
	diskID      int16
	cabinet     string // logical cab name (without "#"); "" -> derived #cab<disk>.cab
	external    bool
	volumeLabel string
	diskPrompt  string
}

// ----- PackageBuilder methods -----

// WithCabSplitThreshold auto-splits files into successive cabinets once a cab's
// accumulated uncompressed size would exceed maxUncompressedBytes (0 = single
// cab, the default).
func (p *msiPackage) WithCabSplitThreshold(maxUncompressedBytes int64) PackageBuilder {
	p.cabSplitThreshold = maxUncompressedBytes
	return p
}

// WithFolderThreshold starts a new CFFOLDER (independent MSZIP stream) within a
// cabinet once the current folder's accumulated uncompressed size would exceed
// maxUncompressedBytes (0 = one folder per cab, the default).
func (p *msiPackage) WithFolderThreshold(maxUncompressedBytes int64) PackageBuilder {
	p.cabFolderThreshold = maxUncompressedBytes
	return p
}

// WithExternalCabs routes cabinets to external files via the writer callback
// (Media.Cabinet emitted without the "#" prefix). Without it, all cabinets are
// embedded CFB streams.
func (p *msiPackage) WithExternalCabs(write func(name string) (io.WriteCloser, error)) PackageBuilder {
	p.externalCabWriter = write
	return p
}

// WithSpanning enables CAB-set spanning: when a single embedded cabinet's
// uncompressed payload would exceed maxBytesPerCab, its data is split across a
// chain of physical cabinets (CFHDR_PREV/NEXT + ifold CONTINUED markers). 0
// disables spanning (the default). Structurally validated; not end-to-end
// CI-verifiable — see msi_cab_span.go.
func (p *msiPackage) WithSpanning(maxBytesPerCab int64) PackageBuilder {
	p.cabSpanCap = maxBytesPerCab
	return p
}

// Media declares (or re-opens) an explicit cabinet for the given DiskId.
func (p *msiPackage) Media(diskID int16) MediaBuilder {
	for i := range p.mediaEntries {
		if p.mediaEntries[i].diskID == diskID {
			return &mediaHandle{pkg: p, idx: i}
		}
	}
	p.mediaEntries = append(p.mediaEntries, mediaEntry{diskID: diskID})
	return &mediaHandle{pkg: p, idx: len(p.mediaEntries) - 1}
}

type mediaHandle struct {
	pkg *msiPackage
	idx int
}

func (h *mediaHandle) entry() *mediaEntry { return &h.pkg.mediaEntries[h.idx] }

func (h *mediaHandle) WithCabinet(name string) MediaBuilder { h.entry().cabinet = name; return h }
func (h *mediaHandle) External() MediaBuilder               { h.entry().external = true; return h }
func (h *mediaHandle) WithVolumeLabel(label string) MediaBuilder {
	h.entry().volumeLabel = label
	return h
}
func (h *mediaHandle) WithDiskPrompt(prompt string) MediaBuilder {
	h.entry().diskPrompt = prompt
	return h
}
func (h *mediaHandle) Done() PackageBuilder { return h.pkg }

// AssignToMedia pins this component's files to an explicit DiskId.
func (c *compHandle) AssignToMedia(diskID int16) ComponentBuilder {
	if e := c.pkg.compEntries[c.id]; e != nil {
		e.mediaDisk = diskID
	}
	return c
}

// ----- planning -----

// mediaFileRef is one payload file in deterministic emission order.
type mediaFileRef struct {
	fileID    string
	size      int64
	component string
}

// plannedMedia is one resolved cabinet/disk.
type plannedMedia struct {
	diskID       int16
	cabinet      string // logical name without "#"
	external     bool
	volumeLabel  string
	diskPrompt   string
	lastSequence int16
}

// planMedia assigns each file a DiskId and a contiguous File.Sequence, and
// returns the sequence map plus the ordered Media rows. Sequences are grouped by
// ascending DiskId (each disk owns a contiguous range), preserving the default
// single-disk 1..N numbering exactly.
func planMedia(p *msiPackage, files []mediaFileRef) (map[string]int16, []plannedMedia, error) {
	seqByFile := make(map[string]int16, len(files))
	if len(files) == 0 {
		return seqByFile, nil, nil
	}

	explicitAssign := map[string]int16{} // component -> diskID
	for _, e := range p.compEntries {
		if e.mediaDisk > 0 {
			explicitAssign[e.id] = e.mediaDisk
		}
	}

	// Assign a DiskId to each file (in emission order).
	diskOf := make([]int16, len(files))
	hasExplicit := len(explicitAssign) > 0 || len(p.mediaEntries) > 0
	if p.cabSplitThreshold > 0 && !hasExplicit {
		disk := int16(1)
		var cur int64
		for i, f := range files {
			if cur > 0 && cur+f.size > p.cabSplitThreshold {
				disk++
				cur = 0
			}
			diskOf[i] = disk
			cur += f.size
		}
	} else {
		for i, f := range files {
			if d, ok := explicitAssign[f.component]; ok {
				diskOf[i] = d
			} else {
				diskOf[i] = 1
			}
		}
	}

	// Distinct disks, ascending.
	diskSet := map[int16]bool{}
	for _, d := range diskOf {
		diskSet[d] = true
	}
	disks := make([]int16, 0, len(diskSet))
	for d := range diskSet {
		disks = append(disks, d)
	}
	sort.Slice(disks, func(i, j int) bool { return disks[i] < disks[j] })

	// Assign contiguous sequences per disk, in emission order within each disk.
	mediaByDisk := map[int16]*plannedMedia{}
	seq := int32(0)
	for _, disk := range disks {
		pm := &plannedMedia{diskID: disk}
		// explicit Media() metadata, if declared
		for i := range p.mediaEntries {
			if p.mediaEntries[i].diskID == disk {
				me := p.mediaEntries[i]
				pm.cabinet = me.cabinet
				pm.external = me.external
				pm.volumeLabel = me.volumeLabel
				pm.diskPrompt = me.diskPrompt
			}
		}
		if pm.cabinet == "" {
			pm.cabinet = fmt.Sprintf("cab%d.cab", disk)
		}
		for i, f := range files {
			if diskOf[i] != disk {
				continue
			}
			seq++
			if seq > 32767 {
				return nil, nil, fmt.Errorf("msi media: File.Sequence %d exceeds the 32767 (i2) ceiling; split across more media or packages", seq)
			}
			seqByFile[f.fileID] = int16(seq)
			pm.lastSequence = int16(seq)
		}
		mediaByDisk[disk] = pm
	}

	out := make([]plannedMedia, 0, len(disks))
	for _, disk := range disks {
		out = append(out, *mediaByDisk[disk])
	}
	return seqByFile, out, nil
}
