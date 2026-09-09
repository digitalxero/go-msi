package msi

// The documented Component.Attributes bits (Microsoft Learn). LocalOnly is the
// absence of every bit and so has no constant. They live outside the ICE rule
// files because the compiler sets some of them (the platform's 64-bit bit, the
// RegistryKeyPath bit for AsKeyPath components) and the ICE rules check them.
const (
	msidbComponentAttributesSourceOnly        int16 = 0x0001
	msidbComponentAttributesOptional          int16 = 0x0002
	msidbComponentAttributesRegistryKeyPath   int16 = 0x0004
	msidbComponentAttributesSharedDllRefCount int16 = 0x0008
	msidbComponentAttributesPermanent         int16 = 0x0010
	msidbComponentAttributesODBCDataSource    int16 = 0x0020
	msidbComponentAttributesTransitive        int16 = 0x0040
	msidbComponentAttributesNeverOverwrite    int16 = 0x0080
	// msidbComponentAttributes64bit marks a component as 64-bit: its files go to
	// the 64-bit locations and its registry rows to the 64-bit view rather than
	// through WOW6432Node redirection. Only legal in a 64-bit package.
	msidbComponentAttributes64bit int16 = 0x0100
	// msidbComponentAttributesDisableRegistryReflection is only meaningful on
	// 64-bit Windows and therefore only in a 64-bit package.
	msidbComponentAttributesDisableRegistryReflection int16 = 0x0200
	msidbComponentAttributesUninstallOnSupersedence   int16 = 0x0400
	msidbComponentAttributesShared                    int16 = 0x0800
)

// msiBuilderOwnedProperties are the Property rows the compiler emits from the
// package identity (WithProductName, WithVersion, WithManufacturer,
// WithProductCode, WithUpgradeCode, WithAllUsers). A WithProperty value with
// one of these names would duplicate the Property primary key, so the compiler
// rejects it up front instead of failing at serialization. ProductLanguage is
// deliberately absent: WithProperty("ProductLanguage", …) is an accepted
// override of the configured language.
var msiBuilderOwnedProperties = []string{
	"ProductName", "ProductVersion", "Manufacturer", "ProductCode", "UpgradeCode", "ALLUSERS",
}
