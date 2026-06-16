// Package lab provides environment-configured constants for parity tests.
//
// Defaults match the [GOAD (Game of Active Directory)] topology stood up
// under [Ludus], which is the assumed lab for the parity harness. Every
// hardcoded name (sevenkingdoms.local, kingslanding, SEVENKINGDOMS-CA,
// domainuser, 10.3.10.10) is a GOAD default — they are public values
// straight out of the upstream playbook, not engagement-specific.
//
// If your range uses different names, override via the WASMFORGE_PARITY_*
// environment variables before running the tests (e.g. in a CI wrapper
// script or local shell profile).
//
// [Ludus]: https://gitlab.com/badsectorlabs/ludus
// [GOAD (Game of Active Directory)]: https://github.com/Orange-Cyberdefense/GOAD
package lab

import "os"

// Domain returns the NT-style domain name for the lab DC.
//
//	WASMFORGE_PARITY_DOMAIN  (default: "sevenkingdoms.local" — GOAD)
func Domain() string { return getenv("WASMFORGE_PARITY_DOMAIN", "sevenkingdoms.local") }

// DC returns the FQDN of the lab domain controller.
//
//	WASMFORGE_PARITY_DC  (default: "dc01.sevenkingdoms.local" — GOAD)
func DC() string { return getenv("WASMFORGE_PARITY_DC", "dc01.sevenkingdoms.local") }

// DCIP returns the IP address of the lab domain controller.
//
//	WASMFORGE_PARITY_DC_IP  (default: "10.3.10.10" — GOAD Ludus range default)
func DCIP() string { return getenv("WASMFORGE_PARITY_DC_IP", "10.3.10.10") }

// CA returns the CA name in "host\CA-NAME" CONFIG format used by Certify.
//
//	WASMFORGE_PARITY_CA  (default: `kingslanding.sevenkingdoms.local\SEVENKINGDOMS-CA` — GOAD)
func CA() string {
	return getenv("WASMFORGE_PARITY_CA", `kingslanding.sevenkingdoms.local\SEVENKINGDOMS-CA`)
}

// User returns the non-privileged domain test user name.
//
//	WASMFORGE_PARITY_USER  (default: "domainuser" — GOAD)
func User() string { return getenv("WASMFORGE_PARITY_USER", "domainuser") }

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
