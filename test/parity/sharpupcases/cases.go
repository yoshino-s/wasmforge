// Package sharpupcases exports the canonical ParityCase slice for SharpUp
// parity tests. Both the test file (sharpup_parity_test.go) and capture-
// baseline share this list.
//
// Every case is a real attacker invocation. Goldens are captured from
// the NATIVE SharpUp.exe (Flangvik/SharpCollection precompiled) running
// against the planted GOAD lab, so wasmforge parity tests fail until
// every documented engine gap is closed.
//
// Documented attacker invocation pattern (GhostPack/SharpUp README):
//
//   .\SharpUp.exe audit <CheckName>
//
// The `audit` modifier forces the check to run regardless of token
// integrity. We invoke as sevenkingdoms\domainuser so the planted
// misconfigurations are visible from a non-admin context.
package sharpupcases

import (
	"time"

	"github.com/praetorian-inc/wftest/parity/labctl"
)

// Cases returns the SharpUp parity invocations. All 15 documented
// audit checks are present and runnable. Lab artifacts for every
// check are planted by scripts/lab-setup/sharpup-plant.ps1 (and
// scripts/lab-setup/dc01-sysvol-gpp.ps1 for the SYSVOL GPP file).
func Cases() []labctl.ParityCase {
	const persona = "win11-domainuser"
	const t = 120 * time.Second

	return []labctl.ParityCase{
		{Name: "AlwaysInstallElevated", Args: []string{"audit", "AlwaysInstallElevated"}, Persona: persona, Timeout: t},
		{Name: "CachedGPPPassword", Args: []string{"audit", "CachedGPPPassword"}, Persona: persona, Timeout: t},
		{Name: "DomainGPPPassword", Args: []string{"audit", "DomainGPPPassword"}, Persona: persona, Timeout: t},
		{Name: "HijackablePaths", Args: []string{"audit", "HijackablePaths"}, Persona: persona, Timeout: t},
		{Name: "McAfeeSitelistFiles", Args: []string{"audit", "McAfeeSitelistFiles"}, Persona: persona, Timeout: t},
		{Name: "ModifiableScheduledTaskFile", Args: []string{"audit", "ModifiableScheduledTaskFile"}, Persona: persona, Timeout: t},
		{Name: "ModifiableServiceBinaries", Args: []string{"audit", "ModifiableServiceBinaries"}, Persona: persona, Timeout: t},
		{Name: "ModifiableServiceRegistryKeys", Args: []string{"audit", "ModifiableServiceRegistryKeys"}, Persona: persona, Timeout: t},
		{Name: "ModifiableServices", Args: []string{"audit", "ModifiableServices"}, Persona: persona, Timeout: t},
		{Name: "ProcessDLLHijack", Args: []string{"audit", "ProcessDLLHijack"}, Persona: persona, Timeout: t},
		{Name: "RegistryAutoLogons", Args: []string{"audit", "RegistryAutoLogons"}, Persona: persona, Timeout: t},
		{Name: "RegistryAutoruns", Args: []string{"audit", "RegistryAutoruns"}, Persona: persona, Timeout: t},
		{Name: "TokenPrivileges", Args: []string{"audit", "TokenPrivileges"}, Persona: persona, Timeout: t},
		{Name: "UnattendedInstallFiles", Args: []string{"audit", "UnattendedInstallFiles"}, Persona: persona, Timeout: t},
		{Name: "UnquotedServicePath", Args: []string{"audit", "UnquotedServicePath"}, Persona: persona, Timeout: t},
	}
}
