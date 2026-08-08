package msi

import (
	"fmt"
	"strconv"
	"strings"
)

// platform.go — P11 target-architecture plumbing. The SummaryInformation
// Template (PID 7) of an installation package is "<platform>;<langid>[,<langid>…]";
// lang.go owns the language half, this file owns the platform half. The platform
// also drives the minimum Windows Installer version written to PID 14
// (PageCount) and the 64-bit conventions applied at compile time.

// Platform is the target CPU architecture recorded in the SummaryInformation
// Template property (PID 7) of an installation package.
//
// Note that Platform_Intel64 means Itanium (IA-64), NOT x86-64 — despite
// Intel's modern "Intel 64" branding meaning the latter. AMD64 / EM64T packages
// use Platform_x64.
type Platform int

const (
	// platformUnset is the zero value and resolves to msiDefaultPlatform,
	// keeping the output of a package that never calls WithPlatform unchanged.
	platformUnset Platform = iota

	Platform_Intel   // x86, 32-bit
	Platform_Intel64 // Itanium / IA-64, 64-bit
	Platform_x64     // x86-64 (AMD64 / EM64T), 64-bit
	Platform_Arm     // ARM, 32-bit
	Platform_Arm64   // AArch64, 64-bit
)

// msiDefaultPlatform is the platform assumed when WithPlatform is not called.
const msiDefaultPlatform = Platform_x64

// msiSchemaVersionArm64 is the Windows Installer version (×100) required by
// Arm/Arm64 packages: 5.0, versus the msiSchemaVersion 2.0 baseline that
// Intel/Intel64/x64 packages need.
const msiSchemaVersionArm64 = 500

// String returns the canonical Template platform token. It returns "" for the
// zero value and for any Platform outside the defined set, which is what makes
// an unset or bogus platform detectable by validation.
func (p Platform) String() string {
	switch p {
	case Platform_Intel:
		return "Intel"
	case Platform_Intel64:
		return "Intel64"
	case Platform_x64:
		return "x64"
	case Platform_Arm:
		return "Arm"
	case Platform_Arm64:
		return "Arm64"
	}
	return ""
}

// valid reports whether p is one of the five tokens Windows Installer accepts.
// The zero value is not valid; call platformOrDefault first to resolve it.
func (p Platform) valid() bool { return p.String() != "" }

// isWin64 reports whether the platform is a 64-bit target. Platform_Arm is
// 32-bit ARM and is deliberately excluded.
func (p Platform) isWin64() bool {
	switch p {
	case Platform_Intel64, Platform_x64, Platform_Arm64:
		return true
	}
	return false
}

// minSchemaVersion is the minimum Windows Installer version (×100) the platform
// requires, for the SummaryInformation PageCount (PID 14). 64-bit packages need
// 2.0; Arm and Arm64 need 5.0.
func (p Platform) minSchemaVersion() int {
	switch p {
	case Platform_Arm, Platform_Arm64:
		return msiSchemaVersionArm64
	}
	return msiSchemaVersion
}

// programFilesFolder is the standard directory a package of this platform
// installs into by default: the 64-bit Program Files for 64-bit targets, the
// 32-bit one otherwise.
func (p Platform) programFilesFolder() string {
	if p.isWin64() {
		return "ProgramFiles64Folder"
	}
	return "ProgramFilesFolder"
}

// parsePlatform resolves a Template platform token. Matching is
// case-insensitive because Windows Installer accepts variant casing, but only
// the five documented tokens are accepted — notably "amd64" and "neutral" are
// not among them ("neutral" is an MSIX/APPX architecture, not an MSI one).
func parsePlatform(token string) (Platform, bool) {
	switch strings.ToLower(strings.TrimSpace(token)) {
	case "intel":
		return Platform_Intel, true
	case "intel64":
		return Platform_Intel64, true
	case "x64":
		return Platform_x64, true
	case "arm":
		return Platform_Arm, true
	case "arm64":
		return Platform_Arm64, true
	}
	return platformUnset, false
}

// templateIsProductCodeList reports whether a Template (PID 7) is a patch's
// ";"-separated target ProductCode list rather than an installation package's
// platform;language pair. The two grammars share the field separator, so the
// only way to tell them apart is that a patch's first field is a GUID.
func templateIsProductCodeList(template string) bool {
	first, _, _ := strings.Cut(template, ";")
	return msiGUIDPattern.MatchString(strings.TrimSpace(first))
}

// parseTemplate splits an installation package's Template (PID 7) into its
// platform and language halves. A blank platform is legal — it means the
// package is not architecture-restricted — and yields platformUnset with a nil
// error, so callers must distinguish "absent" from "invalid" via the returned
// Platform rather than the error alone.
//
// This does not apply to a patch's PID 7, which is a ";"-separated ProductCode
// list rather than a platform;language pair.
func parseTemplate(template string) (Platform, []int, error) {
	platformToken, langList, found := strings.Cut(template, ";")
	if !found {
		return platformUnset, nil, fmt.Errorf("Template %q has no %q separating platform from language", template, ";")
	}

	plat := platformUnset
	if strings.TrimSpace(platformToken) != "" {
		var ok bool
		if plat, ok = parsePlatform(platformToken); !ok {
			return platformUnset, nil, fmt.Errorf("Template platform %q is not one of Intel, Intel64, x64, Arm, Arm64", platformToken)
		}
	}

	var langs []int
	for _, field := range strings.Split(langList, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		lcid, err := strconv.Atoi(field)
		if err != nil {
			return plat, nil, fmt.Errorf("Template language id %q is not numeric", field)
		}
		langs = append(langs, lcid)
	}
	return plat, langs, nil
}

// WithPlatform sets the target CPU architecture written to the
// SummaryInformation Template. Defaults to Platform_x64.
func (p *msiPackage) WithPlatform(plat Platform) PackageBuilder {
	p.platform = plat
	return p
}

// platformOrDefault returns the configured platform (Platform_x64 if unset).
func (p *msiPackage) platformOrDefault() Platform {
	if p.platform == platformUnset {
		return msiDefaultPlatform
	}
	return p.platform
}
