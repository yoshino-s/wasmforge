//go:build nativeaot && !windows

package hostmod

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

// win32ProcModulesEnum stub for non-Windows hosts. ENOSYS-equivalent —
// returns 0 bytes written so the C# caller falls back to the "no
// hijackable DLLs" empty enumeration.
func win32ProcModulesEnum(ctx context.Context, mod api.Module, outBufPtr, outBufLen uint32) uint32 {
	return 0
}
