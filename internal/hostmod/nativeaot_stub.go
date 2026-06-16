//go:build !nativeaot

package hostmod

import "github.com/tetratelabs/wazero"

// registerNativeAOTFunctions is a no-op when the nativeaot build tag is absent.
// This excludes NativeAOT-specific host functions (WMI, SDDL, LSA, RPC, filesystem)
// from standard Go WASM builds, minimizing binary size and attack surface.
func registerNativeAOTFunctions(b wazero.HostModuleBuilder) wazero.HostModuleBuilder {
	return b
}
