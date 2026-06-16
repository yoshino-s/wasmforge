// Package sharpviewcases exports the canonical ParityCase slice for
// SharpView parity tests.
//
// Every case is a real PowerView-style attacker invocation, taken from
// harmj0y's PowerView blog posts + the SharpView README. Goldens are
// captured from the NATIVE SharpView.exe (Flangvik/SharpCollection
// precompiled) running against the live GOAD domain.
package sharpviewcases

import (
	"time"

	"github.com/praetorian-inc/wftest/parity/internal/lab"
	"github.com/praetorian-inc/wftest/parity/labctl"
)

// Cases returns the SharpView parity invocations. The default persona
// is win11-domainuser — every PowerView verb works for any
// authenticated domain principal (DAs only need it for write
// operations, which SharpView does not expose).
func Cases() []labctl.ParityCase {
	const persona = "win11-domainuser"
	const t = 90 * time.Second
	dom := "/Domain:" + lab.Domain()

	return []labctl.ParityCase{
		// Domain identity / topology.
		{Name: "Get-NetDomain", Args: []string{"Get-NetDomain", dom}, Persona: persona, Timeout: t},
		{Name: "Get-DomainController", Args: []string{"Get-DomainController", dom}, Persona: persona, Timeout: t},
		{Name: "Get-DomainPolicy", Args: []string{"Get-DomainPolicy", dom}, Persona: persona, Timeout: t},

		// User / group / computer enumeration.
		{Name: "Get-NetUser", Args: []string{"Get-NetUser", dom, "/Identity:domainuser"}, Persona: persona, Timeout: t},
		{Name: "Get-NetGroup", Args: []string{"Get-NetGroup", dom, `/Identity:"Domain Admins"`}, Persona: persona, Timeout: t},
		{Name: "Get-NetComputer", Args: []string{"Get-NetComputer", dom, "/Identity:dc01"}, Persona: persona, Timeout: t},
		{Name: "Get-DomainGPO", Args: []string{"Get-DomainGPO", dom}, Persona: persona, Timeout: t},

		// Session / share / location enumeration.
		{Name: "Get-NetSession", Args: []string{"Get-NetSession", "/ComputerName:" + lab.DC()}, Persona: persona, Timeout: t},
		{Name: "Get-NetLoggedon", Args: []string{"Get-NetLoggedon", "/ComputerName:" + lab.DC()}, Persona: persona, Timeout: t},
		{Name: "Get-NetLocalGroup", Args: []string{"Get-NetLocalGroup", "/ComputerName:" + lab.DC()}, Persona: persona, Timeout: t},
		{Name: "Find-DomainShare", Args: []string{"Find-DomainShare", dom}, Persona: persona, Timeout: t},
		{Name: "Find-DomainUserLocation", Args: []string{"Find-DomainUserLocation", dom, "/UserIdentity:domainadmin"}, Persona: persona, Timeout: t},

		// Kerberos.
		{Name: "Invoke-Kerberoast", Args: []string{"Invoke-Kerberoast", dom}, Persona: persona, Timeout: t},
		{Name: "Get-DomainSPNTicket", Args: []string{"Get-DomainSPNTicket", "/UserName:domainuser", dom}, Persona: persona, Timeout: t},
	}
}
