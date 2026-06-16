//go:build !darwin

package hostmod

import "github.com/tetratelabs/wazero"

// registerDarwinFunctions is a no-op on non-darwin platforms.
// All darwin functions return ENOSYS via their stub implementations.
// The registration code itself is excluded to minimize binary size.
func registerDarwinFunctions(b wazero.HostModuleBuilder) wazero.HostModuleBuilder {
	return b
}
