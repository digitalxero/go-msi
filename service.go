package msi

import (
	"fmt"
	"strconv"
	"strings"
)

// msi_service.go — P4 Windows service support (ServiceInstall, ServiceControl,
// MsiServiceConfig, MsiServiceConfigFailureActions) exposed through the public
// interface-only Builder-IS-Implementation API.
//
// Enum types mirror the RegistryRoot pattern: a named integer type with a const
// block. The underlying width matches the catalog column (i4 for
// ServiceType/StartType/ErrorControl, i2 for the ServiceControl Event/Wait); the
// value is converted to a builtin int32/int16 at the cell boundary in
// msi_compile.go because the row validator only narrows builtin int.

// ServiceType is the Windows service type bit field (ServiceInstall.ServiceType).
type ServiceType int32

const (
	// ServiceTypeOwnProcess runs the service in its own process (SERVICE_WIN32_OWN_PROCESS).
	ServiceTypeOwnProcess ServiceType = 0x10
	// ServiceTypeShareProcess shares a process with other services (SERVICE_WIN32_SHARE_PROCESS).
	ServiceTypeShareProcess ServiceType = 0x20
	// ServiceTypeInteractive lets the service interact with the desktop (must be OR-ed with a Win32 type).
	ServiceTypeInteractive ServiceType = 0x100
)

// ServiceStartType is the service start type (ServiceInstall.StartType).
type ServiceStartType int32

const (
	// ServiceStartBoot and ServiceStartSystem are driver-only start types that
	// the Windows Installer service does not support; they are included for
	// completeness but should not be used for normal services.
	ServiceStartBoot   ServiceStartType = 0
	ServiceStartSystem ServiceStartType = 1
	// ServiceStartAuto starts the service automatically at boot.
	ServiceStartAuto ServiceStartType = 2
	// ServiceStartDemand starts the service on demand.
	ServiceStartDemand ServiceStartType = 3
	// ServiceStartDisabled installs the service disabled.
	ServiceStartDisabled ServiceStartType = 4
)

// ServiceErrorControl is the service error-control level (ServiceInstall.ErrorControl).
type ServiceErrorControl int32

const (
	// ServiceErrorIgnore logs the error and continues.
	ServiceErrorIgnore ServiceErrorControl = 0x0
	// ServiceErrorNormal logs the error and shows a message box.
	ServiceErrorNormal ServiceErrorControl = 0x1
	// ServiceErrorCritical fails the startup (or reverts to last-known-good).
	ServiceErrorCritical ServiceErrorControl = 0x3
)

// serviceErrorVitalBit is OR-ed into ErrorControl by Vital(true): a vital
// service install failure rolls back the whole installation.
const serviceErrorVitalBit int32 = 0x8000

// ServiceControlEvent is the ServiceControl.Event bit field. Install-time and
// uninstall-time variants are distinct bits; the builder ORs the correct
// variant based on the active OnInstall/OnUninstall scope.
type ServiceControlEvent int16

const (
	ServiceEventStart           ServiceControlEvent = 0x1
	ServiceEventStop            ServiceControlEvent = 0x2
	ServiceEventDelete          ServiceControlEvent = 0x8
	ServiceEventUninstallStart  ServiceControlEvent = 0x10
	ServiceEventUninstallStop   ServiceControlEvent = 0x20
	ServiceEventUninstallDelete ServiceControlEvent = 0x80
)

// FailureActionType is one SC_ACTION_TYPE in a service failure-actions sequence.
type FailureActionType int32

const (
	FailureActionNone           FailureActionType = 0
	FailureActionRestartService FailureActionType = 1
	FailureActionReboot         FailureActionType = 2
	FailureActionRunCommand     FailureActionType = 3
)

// msiServiceConfigDelayedAutoStart is the SERVICE_CONFIG_DELAYED_AUTO_START_INFO
// config type used by WithDelayedAutoStart.
const msiServiceConfigDelayedAutoStart int16 = 3

// msiServiceConfigEventInstall is the MsiServiceConfig/FailureActions Event bit
// applied at install time.
const msiServiceConfigEventInstall int16 = 1

// ServiceInstallBuilder configures one ServiceInstall row (and, optionally, an
// associated MsiServiceConfig delayed-auto-start row and a
// MsiServiceConfigFailureActions row).
type ServiceInstallBuilder interface {
	WithDisplayName(displayName string) ServiceInstallBuilder
	WithType(t ServiceType) ServiceInstallBuilder
	WithStartType(t ServiceStartType) ServiceInstallBuilder
	WithErrorControl(c ServiceErrorControl) ServiceInstallBuilder
	// Vital marks the service install as vital (failure rolls back the install).
	Vital(vital bool) ServiceInstallBuilder
	WithLoadOrderGroup(group string) ServiceInstallBuilder
	// WithDependencies sets the service dependency list (joined with the MSI
	// "[~]" separator).
	WithDependencies(deps ...string) ServiceInstallBuilder
	WithStartName(account string) ServiceInstallBuilder
	WithPassword(password string) ServiceInstallBuilder
	WithArguments(args string) ServiceInstallBuilder
	WithDescription(description string) ServiceInstallBuilder
	// WithDelayedAutoStart emits an MsiServiceConfig row enabling delayed
	// automatic start (only meaningful with WithStartType(ServiceStartAuto)).
	WithDelayedAutoStart() ServiceInstallBuilder
	// FailureActions opens a sub-builder for the service recovery configuration
	// (MsiServiceConfigFailureActions). Call Done() to return to this builder.
	FailureActions() ServiceFailureActionsBuilder
}

// ServiceFailureActionsBuilder configures the recovery actions of a service
// (MsiServiceConfigFailureActions). Restart/Reboot/RunCommand/None append one
// SC_ACTION in order.
type ServiceFailureActionsBuilder interface {
	WithResetPeriod(seconds int32) ServiceFailureActionsBuilder
	WithRebootMessage(message string) ServiceFailureActionsBuilder
	WithCommand(command string) ServiceFailureActionsBuilder
	Restart(delayMs int32) ServiceFailureActionsBuilder
	Reboot(delayMs int32) ServiceFailureActionsBuilder
	RunCommand(delayMs int32) ServiceFailureActionsBuilder
	None(delayMs int32) ServiceFailureActionsBuilder
	// Done returns to the parent ServiceInstallBuilder for further chaining.
	Done() ServiceInstallBuilder
}

// ServiceControlBuilder configures one ServiceControl row. OnInstall/OnUninstall
// select the scope for the subsequent Start/Stop/Delete calls (install scope is
// the default).
type ServiceControlBuilder interface {
	OnInstall() ServiceControlBuilder
	OnUninstall() ServiceControlBuilder
	Start() ServiceControlBuilder
	Stop() ServiceControlBuilder
	Delete() ServiceControlBuilder
	WithArguments(args string) ServiceControlBuilder
	// Wait sets whether the installer waits up to 30s for the control to
	// complete (default: unset / NULL).
	Wait(wait bool) ServiceControlBuilder
}

// ----- model -----

type serviceInstallEntry struct {
	component    string
	name         string
	displayName  string
	serviceType  int32
	startType    int32
	errorControl int32
	vital        bool

	loadOrderGroup string
	dependencies   string
	startName      string
	password       string
	arguments      string
	description    string

	delayedAutoStart bool
	failure          *serviceFailureSpec
}

type serviceFailureSpec struct {
	resetPeriod   int32
	rebootMessage string
	command       string
	actions       []int32 // SC_ACTION_TYPE values, in order
	delays        []int32 // matching delays in ms
}

type serviceControlEntry struct {
	component string
	name      string
	arguments string
	event     int16
	wait      *int16
	// uninstallScope is the current OnInstall/OnUninstall scope used by
	// Start/Stop/Delete; it is builder state only (not emitted).
	uninstallScope bool
}

// ----- ComponentBuilder service handles -----

func (c *compHandle) ServiceInstall(name string) ServiceInstallBuilder {
	c.pkg.serviceInstallEntries = append(c.pkg.serviceInstallEntries, serviceInstallEntry{
		component:    c.id,
		name:         name,
		serviceType:  int32(ServiceTypeOwnProcess),
		startType:    int32(ServiceStartAuto),
		errorControl: int32(ServiceErrorNormal),
	})
	return &serviceInstallHandle{pkg: c.pkg, idx: len(c.pkg.serviceInstallEntries) - 1}
}

func (c *compHandle) ServiceControl(name string) ServiceControlBuilder {
	c.pkg.serviceControlEntries = append(c.pkg.serviceControlEntries, serviceControlEntry{
		component: c.id,
		name:      name,
	})
	return &serviceControlHandle{pkg: c.pkg, idx: len(c.pkg.serviceControlEntries) - 1}
}

type serviceInstallHandle struct {
	pkg *msiPackage
	idx int
}

func (h *serviceInstallHandle) entry() *serviceInstallEntry {
	return &h.pkg.serviceInstallEntries[h.idx]
}

func (h *serviceInstallHandle) WithDisplayName(displayName string) ServiceInstallBuilder {
	h.entry().displayName = displayName
	return h
}

func (h *serviceInstallHandle) WithType(t ServiceType) ServiceInstallBuilder {
	h.entry().serviceType = int32(t)
	return h
}

func (h *serviceInstallHandle) WithStartType(t ServiceStartType) ServiceInstallBuilder {
	h.entry().startType = int32(t)
	return h
}

func (h *serviceInstallHandle) WithErrorControl(c ServiceErrorControl) ServiceInstallBuilder {
	// Preserve the vital bit if it was already set.
	vital := h.entry().vital
	h.entry().errorControl = int32(c)
	h.entry().vital = vital
	return h
}

func (h *serviceInstallHandle) Vital(vital bool) ServiceInstallBuilder {
	h.entry().vital = vital
	return h
}

func (h *serviceInstallHandle) WithLoadOrderGroup(group string) ServiceInstallBuilder {
	h.entry().loadOrderGroup = group
	return h
}

func (h *serviceInstallHandle) WithDependencies(deps ...string) ServiceInstallBuilder {
	h.entry().dependencies = strings.Join(deps, "[~]")
	return h
}

func (h *serviceInstallHandle) WithStartName(account string) ServiceInstallBuilder {
	h.entry().startName = account
	return h
}

func (h *serviceInstallHandle) WithPassword(password string) ServiceInstallBuilder {
	h.entry().password = password
	return h
}

func (h *serviceInstallHandle) WithArguments(args string) ServiceInstallBuilder {
	h.entry().arguments = args
	return h
}

func (h *serviceInstallHandle) WithDescription(description string) ServiceInstallBuilder {
	h.entry().description = description
	return h
}

func (h *serviceInstallHandle) WithDelayedAutoStart() ServiceInstallBuilder {
	h.entry().delayedAutoStart = true
	return h
}

func (h *serviceInstallHandle) FailureActions() ServiceFailureActionsBuilder {
	if h.entry().failure == nil {
		h.entry().failure = &serviceFailureSpec{}
	}
	return &serviceFailureHandle{parent: h}
}

type serviceFailureHandle struct {
	parent *serviceInstallHandle
}

func (h *serviceFailureHandle) spec() *serviceFailureSpec {
	return h.parent.entry().failure
}

func (h *serviceFailureHandle) WithResetPeriod(seconds int32) ServiceFailureActionsBuilder {
	h.spec().resetPeriod = seconds
	return h
}

func (h *serviceFailureHandle) WithRebootMessage(message string) ServiceFailureActionsBuilder {
	h.spec().rebootMessage = message
	return h
}

func (h *serviceFailureHandle) WithCommand(command string) ServiceFailureActionsBuilder {
	h.spec().command = command
	return h
}

func (h *serviceFailureHandle) appendAction(t FailureActionType, delayMs int32) ServiceFailureActionsBuilder {
	s := h.spec()
	s.actions = append(s.actions, int32(t))
	s.delays = append(s.delays, delayMs)
	return h
}

func (h *serviceFailureHandle) Restart(delayMs int32) ServiceFailureActionsBuilder {
	return h.appendAction(FailureActionRestartService, delayMs)
}

func (h *serviceFailureHandle) Reboot(delayMs int32) ServiceFailureActionsBuilder {
	return h.appendAction(FailureActionReboot, delayMs)
}

func (h *serviceFailureHandle) RunCommand(delayMs int32) ServiceFailureActionsBuilder {
	return h.appendAction(FailureActionRunCommand, delayMs)
}

func (h *serviceFailureHandle) None(delayMs int32) ServiceFailureActionsBuilder {
	return h.appendAction(FailureActionNone, delayMs)
}

func (h *serviceFailureHandle) Done() ServiceInstallBuilder {
	return h.parent
}

type serviceControlHandle struct {
	pkg *msiPackage
	idx int
}

func (h *serviceControlHandle) entry() *serviceControlEntry {
	return &h.pkg.serviceControlEntries[h.idx]
}

func (h *serviceControlHandle) OnInstall() ServiceControlBuilder {
	h.entry().uninstallScope = false
	return h
}

func (h *serviceControlHandle) OnUninstall() ServiceControlBuilder {
	h.entry().uninstallScope = true
	return h
}

func (h *serviceControlHandle) orEvent(install, uninstall ServiceControlEvent) ServiceControlBuilder {
	e := h.entry()
	if e.uninstallScope {
		e.event |= int16(uninstall)
	} else {
		e.event |= int16(install)
	}
	return h
}

func (h *serviceControlHandle) Start() ServiceControlBuilder {
	return h.orEvent(ServiceEventStart, ServiceEventUninstallStart)
}

func (h *serviceControlHandle) Stop() ServiceControlBuilder {
	return h.orEvent(ServiceEventStop, ServiceEventUninstallStop)
}

func (h *serviceControlHandle) Delete() ServiceControlBuilder {
	return h.orEvent(ServiceEventDelete, ServiceEventUninstallDelete)
}

func (h *serviceControlHandle) WithArguments(args string) ServiceControlBuilder {
	h.entry().arguments = args
	return h
}

func (h *serviceControlHandle) Wait(wait bool) ServiceControlBuilder {
	v := int16(0)
	if wait {
		v = 1
	}
	h.entry().wait = &v
	return h
}

// ----- emission (called from compileMSIPackage) -----

// emitMSIServiceTables emits the ServiceInstall, ServiceControl,
// MsiServiceConfig and MsiServiceConfigFailureActions tables for the package's
// service model. Enum cells are converted to plain int32/int16 at the boundary;
// nullable string cells pass through (the row validator maps "" to NULL); errors
// are propagated (never swallowed).
func emitMSIServiceTables(p *msiPackage, db msiDatabaseBuilder) error {
	if len(p.serviceInstallEntries) > 0 {
		siTbl := createMSITableFromCatalog("ServiceInstall")
		cfgTbl := createMSITableFromCatalog("MsiServiceConfig")
		failTbl := createMSITableFromCatalog("MsiServiceConfigFailureActions")
		var haveCfg, haveFail bool

		for i, e := range p.serviceInstallEntries {
			siID := fmt.Sprintf("si%02d_%s", i, sanitizeIDSegment(e.component))
			errControl := e.errorControl
			if e.vital {
				errControl |= serviceErrorVitalBit
			}
			row := newMSIRowBuilder().WithColumns(siTbl.columns()...).WithValues(
				siID, e.name, e.displayName,
				e.serviceType, e.startType, errControl,
				e.loadOrderGroup, e.dependencies, e.startName, e.password, e.arguments,
				e.component, e.description,
			).Build()
			if err := siTbl.addRow(row); err != nil {
				return fmt.Errorf("msi compile: ServiceInstall row %s: %w", siID, err)
			}

			if e.delayedAutoStart {
				cfgID := fmt.Sprintf("svccfg%02d_%s", i, sanitizeIDSegment(e.component))
				crow := newMSIRowBuilder().WithColumns(cfgTbl.columns()...).WithValues(
					cfgID, e.name, msiServiceConfigEventInstall, msiServiceConfigDelayedAutoStart, "1", e.component,
				).Build()
				if err := cfgTbl.addRow(crow); err != nil {
					return fmt.Errorf("msi compile: MsiServiceConfig row %s: %w", cfgID, err)
				}
				haveCfg = true
			}

			if e.failure != nil {
				failID := fmt.Sprintf("svcfail%02d_%s", i, sanitizeIDSegment(e.component))
				var resetPeriod any
				if e.failure.resetPeriod > 0 {
					resetPeriod = e.failure.resetPeriod
				}
				actions := joinInt32List(e.failure.actions)
				delays := joinInt32List(e.failure.delays)
				frow := newMSIRowBuilder().WithColumns(failTbl.columns()...).WithValues(
					failID, e.name, msiServiceConfigEventInstall, resetPeriod,
					e.failure.rebootMessage, e.failure.command, actions, delays, e.component,
				).Build()
				if err := failTbl.addRow(frow); err != nil {
					return fmt.Errorf("msi compile: MsiServiceConfigFailureActions row %s: %w", failID, err)
				}
				haveFail = true
			}
		}
		db.WithTable(siTbl)
		if haveCfg {
			db.WithTable(cfgTbl)
		}
		if haveFail {
			db.WithTable(failTbl)
		}
	}

	if len(p.serviceControlEntries) > 0 {
		scTbl := createMSITableFromCatalog("ServiceControl")
		for i, e := range p.serviceControlEntries {
			scID := fmt.Sprintf("svcctl%02d_%s", i, sanitizeIDSegment(e.component))
			var wait any
			if e.wait != nil {
				wait = *e.wait
			}
			row := newMSIRowBuilder().WithColumns(scTbl.columns()...).WithValues(
				scID, e.name, e.event, e.arguments, wait, e.component,
			).Build()
			if err := scTbl.addRow(row); err != nil {
				return fmt.Errorf("msi compile: ServiceControl row %s: %w", scID, err)
			}
		}
		db.WithTable(scTbl)
	}

	return nil
}

// joinInt32List renders a slice of ints as an MSI "[~]"-separated list (used for
// the failure-actions Actions/DelayActions columns). Returns "" (NULL) when empty.
func joinInt32List(vs []int32) string {
	if len(vs) == 0 {
		return ""
	}
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.FormatInt(int64(v), 10)
	}
	return strings.Join(parts, "[~]")
}
