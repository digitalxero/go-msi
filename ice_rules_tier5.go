package msi

import (
	"fmt"
	"sort"
)

// msi_ice_rules_tier5.go — P7 media/cabinet ICE rule (ICE07-family media
// coverage check). Validates that the Media table forms a consistent, contiguous
// cabinet mapping over the File.Sequence space:
//   - DiskId is unique and >= 1
//   - LastSequence is non-decreasing across DiskId order
//   - every File.Sequence (1..max) falls within exactly one media range, and no
//     File.Sequence exceeds the i2 ceiling
//   - embedded cabinet stream names ("#name") are valid MSI stream names.
//
// Microsoft validates media coverage under ICE07/ICE48-style checks; this is the
// honest media-coverage lint for the multi-cabinet output P7 can produce.

func registerTier5Rules() []iceRule {
	return []iceRule{
		{id: "ICE07", fn: runICE07Media, tables: []string{"Media"}},
	}
}

var tier5Rules = registerTier5Rules()

func runICE07Media(ctx *iceContext) []Finding {
	var findings []Finding

	type med struct {
		diskID  int16
		lastSeq int16
		cabinet string
	}
	var media []med
	for _, r := range ctx.rowsOf("Media") {
		v := r.values()
		if len(v) < 4 {
			continue
		}
		disk := iceInt16(v[0])
		last := iceInt16(v[1])
		cab, _ := v[3].(string)
		media = append(media, med{diskID: disk, lastSeq: last, cabinet: cab})
		if disk < 1 {
			findings = append(findings, &msiFinding{ice: "ICE07", sev: SeverityError, table: "Media", column: "DiskId", rowKeys: rowPKs(r), message: fmt.Sprintf("DiskId %d must be >= 1", disk)})
		}
		if last < 0 || last > 32767 {
			findings = append(findings, &msiFinding{ice: "ICE07", sev: SeverityError, table: "Media", column: "LastSequence", rowKeys: rowPKs(r), message: fmt.Sprintf("LastSequence %d is out of the 0..32767 range", last)})
		}
	}
	if len(media) == 0 {
		return findings
	}

	// Unique DiskId.
	seenDisk := map[int16]bool{}
	for _, m := range media {
		if seenDisk[m.diskID] {
			findings = append(findings, &msiFinding{ice: "ICE07", sev: SeverityError, table: "Media", column: "DiskId", message: fmt.Sprintf("duplicate DiskId %d", m.diskID)})
		}
		seenDisk[m.diskID] = true
	}

	// LastSequence non-decreasing across DiskId order.
	sort.Slice(media, func(i, j int) bool { return media[i].diskID < media[j].diskID })
	for i := 1; i < len(media); i++ {
		if media[i].lastSeq < media[i-1].lastSeq {
			findings = append(findings, &msiFinding{ice: "ICE07", sev: SeverityError, table: "Media", column: "LastSequence", message: fmt.Sprintf("LastSequence decreases from disk %d (%d) to disk %d (%d)", media[i-1].diskID, media[i-1].lastSeq, media[i].diskID, media[i].lastSeq)})
		}
	}

	// Every File.Sequence must fall in a media range (0, maxLast].
	maxLast := media[len(media)-1].lastSeq
	for _, r := range ctx.rowsOf("File") {
		v := r.values()
		if len(v) < 8 {
			continue
		}
		seq := iceInt16(v[7])
		if seq < 1 || seq > maxLast {
			fid, _ := v[0].(string)
			findings = append(findings, &msiFinding{ice: "ICE07", sev: SeverityError, table: "File", column: "Sequence", rowKeys: []string{fid}, message: fmt.Sprintf("File %q Sequence %d is not covered by any Media row (max LastSequence %d)", fid, seq, maxLast)})
		}
	}

	// Embedded cabinet stream names must be valid.
	for _, m := range media {
		if len(m.cabinet) > 1 && m.cabinet[0] == '#' {
			if err := validateMSIStreamName(false, m.cabinet[1:]); err != nil {
				findings = append(findings, &msiFinding{ice: "ICE07", sev: SeverityError, table: "Media", column: "Cabinet", message: fmt.Sprintf("embedded cabinet %q is not a valid stream name: %v", m.cabinet, err)})
			}
		}
	}

	return findings
}
