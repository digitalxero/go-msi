package msi

import (
	"strings"
	"time"
)

// msiBuildTime is the fixed timestamp used for the summary stream create/save
// times, keeping builds byte-for-byte reproducible.
var msiBuildTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// msiSequenceRow is one standard action scheduled in a sequence table.
type msiSequenceRow struct {
	action   string
	sequence int16
}

// Standard action schedules at the canonical sequence numbers from the Windows
// Installer "Suggested <table>" documentation (the numbers WiX also uses), so
// custom actions can be inserted between neighbors without renumbering.
var (
	msiInstallExecuteActions = []msiSequenceRow{
		{"ValidateProductID", 700},
		{"CostInitialize", 800},
		{"FileCost", 900},
		{"CostFinalize", 1000},
		{"InstallValidate", 1400},
		{"InstallInitialize", 1500},
		{"ProcessComponents", 1600},
		{"UnpublishFeatures", 1800},
		{"RemoveShortcuts", 3200},
		{"RemoveRegistryValues", 3400},
		{"RemoveFiles", 3500},
		{"InstallFiles", 4000},
		{"WriteRegistryValues", 4200},
		{"CreateShortcuts", 4500},
		{"RegisterUser", 6000},
		{"RegisterProduct", 6100},
		{"PublishFeatures", 6300},
		{"PublishProduct", 6400},
		{"InstallFinalize", 6600},
	}
	msiInstallUIActions = []msiSequenceRow{
		{"ValidateProductID", 700},
		{"CostInitialize", 800},
		{"FileCost", 900},
		{"CostFinalize", 1000},
		{"ExecuteAction", 1300},
	}
	msiAdminExecuteActions = []msiSequenceRow{
		{"CostInitialize", 800},
		{"FileCost", 900},
		{"CostFinalize", 1000},
		{"InstallValidate", 1400},
		{"InstallInitialize", 1500},
		{"InstallAdminPackage", 3900},
		{"InstallFiles", 4000},
		{"InstallFinalize", 6600},
	}
	msiAdminUIActions = []msiSequenceRow{
		{"CostInitialize", 800},
		{"FileCost", 900},
		{"CostFinalize", 1000},
		{"ExecuteAction", 1300},
	}
	msiAdvtExecuteActions = []msiSequenceRow{
		{"CostInitialize", 800},
		{"CostFinalize", 1000},
		{"InstallValidate", 1400},
		{"InstallInitialize", 1500},
		{"PublishFeatures", 6300},
		{"PublishProduct", 6400},
		{"InstallFinalize", 6600},
	}
)

// msiSanitizeDirName strips characters invalid in a directory name.
func msiSanitizeDirName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch r {
		case '\\', '/', ':', '*', '?', '"', '<', '>', '|':
			// drop
		default:
			b.WriteRune(r)
		}
	}
	s := strings.TrimSpace(b.String())
	if s == "" {
		s = "Product"
	}
	return s
}
