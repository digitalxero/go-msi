package msi

// msi_actions.go — P4 conditional standard actions. The five base action sets
// (msix.go) are always emitted; the actions here are injected into the sequence
// tables ONLY when their trigger table is populated, matching real WiX output
// (e.g. FindRelatedProducts/RemoveExistingProducts appear only with an Upgrade
// table; InstallServices only with a ServiceInstall table). Because injection is
// conditional, files-only packages keep the exact base action set (ICE26 and
// flat-repro parity are unaffected).

// conditionalAction is a standard action scheduled into a sequence table only
// when trigger reports the relevant model is populated.
type conditionalAction struct {
	table     string
	action    string
	condition string // formatted MSI condition; "" => no condition
	sequence  int16
	trigger   func(*msiPackage) bool
}

func hasUpgradeRows(p *msiPackage) bool        { return len(p.upgradeEntries) > 0 }
func hasServiceInstallRows(p *msiPackage) bool { return len(p.serviceInstallEntries) > 0 }
func hasServiceControlRows(p *msiPackage) bool { return len(p.serviceControlEntries) > 0 }
func hasAppSearchRows(p *msiPackage) bool      { return len(p.appSearchEntries) > 0 }
func hasLaunchConditionRows(p *msiPackage) bool {
	return len(p.launchConditions) > 0
}

// hasUpgradeRemoveRows reports whether any Upgrade row actually removes a related
// product (i.e. is not detect-only); RemoveExistingProducts is scheduled only
// then.
func hasUpgradeRemoveRows(p *msiPackage) bool {
	for _, e := range p.upgradeEntries {
		if e.attributes&int32(UpgradeOnlyDetect) == 0 {
			return true
		}
	}
	return false
}

// msiConditionalActions is the static schedule of P4 standard actions at their
// canonical WiX sequence numbers. RemoveExistingProducts is handled separately
// because its sequence is configurable via MajorUpgrade().RemoveAfter.
var msiConditionalActions = []conditionalAction{
	{msiInstallExecSeqTableName, "LaunchConditions", "", 100, hasLaunchConditionRows},
	{msiInstallUISeqTableName, "LaunchConditions", "", 100, hasLaunchConditionRows},
	{msiInstallExecSeqTableName, "FindRelatedProducts", "", 200, hasUpgradeRows},
	{msiInstallUISeqTableName, "FindRelatedProducts", "", 200, hasUpgradeRows},
	{msiInstallExecSeqTableName, "AppSearch", "", 400, hasAppSearchRows},
	{msiInstallUISeqTableName, "AppSearch", "", 400, hasAppSearchRows},
	{msiInstallExecSeqTableName, "MigrateFeatureStates", "", 1200, hasUpgradeRows},
	{msiInstallUISeqTableName, "MigrateFeatureStates", "", 1200, hasUpgradeRows},
	{msiInstallExecSeqTableName, "StopServices", "VersionNT", 1900, hasServiceControlRows},
	{msiInstallExecSeqTableName, "DeleteServices", "VersionNT", 2000, hasServiceControlRows},
	{msiInstallExecSeqTableName, "InstallServices", "VersionNT", 5800, hasServiceInstallRows},
	{msiInstallExecSeqTableName, "StartServices", "VersionNT", 5900, hasServiceControlRows},
}

// majorUpgradeRemoveSequence resolves the RemoveExistingProducts sequence from a
// configured MajorUpgrade().RemoveAfter (default: after InstallInitialize).
func majorUpgradeRemoveSequence(p *msiPackage) int16 {
	after := ""
	if p.majorUpgrade != nil {
		after = p.majorUpgrade.removeAfter
	}
	switch after {
	case "InstallValidate":
		return 1450
	case "InstallExecute":
		return 1550
	case "InstallFinalize":
		return 6700
	case "InstallInitialize", "":
		return 1525
	default:
		return 1525
	}
}

// injectConditionalActions schedules the P4 standard actions whose trigger table
// is populated. Called after the base action emission in compileMSIPackage.
func injectConditionalActions(p *msiPackage, db msiDatabaseBuilder) {
	for _, ca := range msiConditionalActions {
		if !ca.trigger(p) {
			continue
		}
		var cond any
		if ca.condition != "" {
			cond = ca.condition
		}
		db.WithSequenceAction(ca.table, ca.action, cond, ca.sequence)
	}
	if hasUpgradeRemoveRows(p) {
		db.WithSequenceAction(msiInstallExecSeqTableName, "RemoveExistingProducts", nil, majorUpgradeRemoveSequence(p))
	}
}
