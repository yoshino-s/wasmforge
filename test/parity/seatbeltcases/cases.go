// Package seatbeltcases exports the canonical ParityCase slice for
// Seatbelt parity tests. The list reflects the documented Seatbelt
// command surface from the GhostPack/Seatbelt README — every command
// is invoked the way an operator would run it manually.
//
// Goldens are captured from the NATIVE Seatbelt.exe (Flangvik/Sharp-
// Collection precompiled) running against the planted GOAD lab.
// Wasmforge parity tests therefore fail until every documented engine
// gap (WMI lazy P/Invoke, EventLogReader, Directory.GetFiles WASI
// path mapping, VaultCli bridge, etc.) is closed.
package seatbeltcases

import (
	"time"

	"github.com/praetorian-inc/wftest/parity/labctl"
)

// Cases returns the Seatbelt parity invocations.
func Cases() []labctl.ParityCase {
	const t = 120 * time.Second

	return []labctl.ParityCase{
		{Name: "AMSIProviders", Args: []string{"AMSIProviders"}, Timeout: t},
		{Name: "AntiVirus", Args: []string{"AntiVirus"}, Timeout: t},
		{Name: "Certificates", Args: []string{"Certificates"}, Timeout: t},
		{Name: "CertificateThumbprints", Args: []string{"CertificateThumbprints"}, Timeout: t},
		{Name: "ChromiumPresence", Args: []string{"ChromiumPresence"}, Timeout: t},
		{Name: "LocalGroups", Args: []string{"LocalGroups"}, Timeout: t},
		{Name: "LocalUsers", Args: []string{"LocalUsers"}, Timeout: t},
		{Name: "LogonEvents", Args: []string{"LogonEvents"}, Timeout: t},
		{Name: "McAfeeSiteList", Args: []string{"McAfeeSiteList"}, Timeout: t},
		{Name: "NetworkShares", Args: []string{"NetworkShares"}, Timeout: t},
		{Name: "OSInfo", Args: []string{"OSInfo"}, Timeout: t},
		{Name: "PoweredOnEvents", Args: []string{"PoweredOnEvents"}, Timeout: t},
		{Name: "PowerShellEvents", Args: []string{"PowerShellEvents"}, Timeout: t},
		{Name: "Printers", Args: []string{"Printers"}, Timeout: t},
		{Name: "ProcessCreationEvents", Args: []string{"ProcessCreationEvents"}, Timeout: t},
		{Name: "Processes", Args: []string{"Processes"}, Timeout: t},
		{Name: "RDPSessions", Args: []string{"RDPSessions"}, Timeout: t},
		{Name: "SecPackageCreds", Args: []string{"SecPackageCreds"}, Timeout: t},
		{Name: "Services", Args: []string{"Services"}, Timeout: t},
		{Name: "SysmonEvents", Args: []string{"SysmonEvents"}, Timeout: t},
		{Name: "TokenGroups", Args: []string{"TokenGroups"}, Timeout: t},
		{Name: "TokenPrivileges", Args: []string{"TokenPrivileges"}, Timeout: t},
		{Name: "UserRightAssignments", Args: []string{"UserRightAssignments"}, Timeout: t},
		{Name: "WifiProfile", Args: []string{"WifiProfile"}, Timeout: t},
		{Name: "WindowsAutoLogon", Args: []string{"WindowsAutoLogon"}, Timeout: t},
		{Name: "WindowsFirewall", Args: []string{"WindowsFirewall"}, Timeout: t},
		{Name: "WindowsVault", Args: []string{"WindowsVault"}, Timeout: t},
		{Name: "WMIEventConsumer", Args: []string{"WMIEventConsumer"}, Timeout: t},
	}
}
