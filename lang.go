package msi

import (
	"fmt"
	"strconv"
	"strings"
)

// msi_lang.go — P9 multi-language plumbing. WithLanguage sets the package's
// ProductLanguage and the SummaryInformation Template language id; embedded
// language transforms (P9.5) append their LCIDs to the Template. The string pool
// stays UTF-8 (65001). Default language is 1033 (US English), preserving today's
// "x64;1033" output exactly.

const msiDefaultLanguage = 1033

// msiPlatform is the Template platform token (the package targets x64 today).
const msiPlatform = "x64"

// LanguageCode is a Windows Language Identifier (LCID) used for ProductLanguage
// and the SummaryInformation Template. Named constants for the common locales
// are provided below; any LCID can still be passed as LanguageCode(n).
type LanguageCode int

// Common Windows LCIDs (decimal). This is not exhaustive — pass LanguageCode(n)
// for any locale not listed here.
const (
	LangCode_arSA LanguageCode = 1025 // Arabic (Saudi Arabia)
	LangCode_bgBG LanguageCode = 1026 // Bulgarian (Bulgaria)
	LangCode_caES LanguageCode = 1027 // Catalan (Spain)
	LangCode_zhTW LanguageCode = 1028 // Chinese (Taiwan)
	LangCode_csCZ LanguageCode = 1029 // Czech (Czech Republic)
	LangCode_daDK LanguageCode = 1030 // Danish (Denmark)
	LangCode_deDE LanguageCode = 1031 // German (Germany)
	LangCode_elGR LanguageCode = 1032 // Greek (Greece)
	LangCode_enUS LanguageCode = 1033 // English (United States)
	LangCode_esES LanguageCode = 1034 // Spanish (Spain, traditional sort)
	LangCode_fiFI LanguageCode = 1035 // Finnish (Finland)
	LangCode_frFR LanguageCode = 1036 // French (France)
	LangCode_heIL LanguageCode = 1037 // Hebrew (Israel)
	LangCode_huHU LanguageCode = 1038 // Hungarian (Hungary)
	LangCode_itIT LanguageCode = 1040 // Italian (Italy)
	LangCode_jaJP LanguageCode = 1041 // Japanese (Japan)
	LangCode_koKR LanguageCode = 1042 // Korean (Korea)
	LangCode_nlNL LanguageCode = 1043 // Dutch (Netherlands)
	LangCode_nbNO LanguageCode = 1044 // Norwegian Bokmål (Norway)
	LangCode_plPL LanguageCode = 1045 // Polish (Poland)
	LangCode_ptBR LanguageCode = 1046 // Portuguese (Brazil)
	LangCode_roRO LanguageCode = 1048 // Romanian (Romania)
	LangCode_ruRU LanguageCode = 1049 // Russian (Russia)
	LangCode_hrHR LanguageCode = 1050 // Croatian (Croatia)
	LangCode_skSK LanguageCode = 1051 // Slovak (Slovakia)
	LangCode_svSE LanguageCode = 1053 // Swedish (Sweden)
	LangCode_thTH LanguageCode = 1054 // Thai (Thailand)
	LangCode_trTR LanguageCode = 1055 // Turkish (Turkey)
	LangCode_ukUA LanguageCode = 1058 // Ukrainian (Ukraine)
	LangCode_idID LanguageCode = 1057 // Indonesian (Indonesia)
	LangCode_viVN LanguageCode = 1066 // Vietnamese (Vietnam)
	LangCode_enGB LanguageCode = 2057 // English (United Kingdom)
	LangCode_zhCN LanguageCode = 2052 // Chinese (PRC, simplified)
	LangCode_ptPT LanguageCode = 2070 // Portuguese (Portugal)
)

// languageTransform is one embedded :LCID language transform (P9.5).
type languageTransform struct {
	lcid      int
	configure func(PackageBuilder)
}

// WithLanguage sets the package's primary ProductLanguage / Template language id.
func (p *msiPackage) WithLanguage(lcid LanguageCode) PackageBuilder {
	p.language = int(lcid)
	return p
}

// WithLanguageTransform declares an embedded language transform for lcid. At
// WriteMSI time the base package is deep-cloned, its language set to lcid, and
// configure run against the clone; the base→clone diff is embedded as a
// sub-storage named after the decimal LCID (e.g. "1031"). The LCID is appended
// to the Template language list so msiexec can select it (TRANSFORMS=:1031).
func (p *msiPackage) WithLanguageTransform(lcid LanguageCode, configure func(t PackageBuilder)) PackageBuilder {
	p.languageTransforms = append(p.languageTransforms, languageTransform{lcid: int(lcid), configure: configure})
	return p
}

// languageOrDefault returns the configured primary LCID (1033 if unset).
func (p *msiPackage) languageOrDefault() int {
	if p.language == 0 {
		return msiDefaultLanguage
	}
	return p.language
}

// buildLanguageSubStorages compiles each declared language transform into an
// embedded sub-storage (named after the decimal LCID, CLSID = msiTransformCLSID)
// holding that language's base→clone diff. baseDB is the already-compiled base.
// Returns nil when no transforms are declared, keeping the default output
// byte-identical.
func (p *msiPackage) buildLanguageSubStorages(baseDB msiDatabase) ([]msiSubStorage, error) {
	if len(p.languageTransforms) == 0 {
		return nil, nil
	}
	var subs []msiSubStorage
	for _, lt := range p.languageTransforms {
		clone := p.cloneForTransform()
		clone.language = lt.lcid
		if lt.configure != nil {
			lt.configure(clone)
		}
		if _, err := clone.Build(); err != nil {
			return nil, fmt.Errorf("msi: language transform %d: %w", lt.lcid, err)
		}
		targetDB, err := compileMSIPackage(clone)
		if err != nil {
			return nil, fmt.Errorf("msi: language transform %d: compiling: %w", lt.lcid, err)
		}
		summary := (&msiTransform{base: p, target: clone, validation: TransformValidateLanguage}).summaryInfo()
		streams, err := buildMSITransformStreams(baseDB, targetDB, summary)
		if err != nil {
			return nil, fmt.Errorf("msi: language transform %d: %w", lt.lcid, err)
		}
		subs = append(subs, msiSubStorage{
			name:    strconv.Itoa(lt.lcid),
			clsid:   msiTransformCLSID,
			streams: streams,
		})
	}
	return subs, nil
}

// msiTemplateString builds the SummaryInformation Template: "x64;<lcid>" plus,
// when embedded language transforms exist, a comma-separated list of their LCIDs.
func msiTemplateString(p *msiPackage) string {
	langs := []string{strconv.Itoa(p.languageOrDefault())}
	for _, t := range p.languageTransforms {
		langs = append(langs, strconv.Itoa(t.lcid))
	}
	return msiPlatform + ";" + strings.Join(langs, ",")
}
