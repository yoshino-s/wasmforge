//go:build nativeaot && !windows

package hostmod

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

// nativeaotDpapiBackupkey — non-Windows stub. Returns 0 (no bytes written)
// so cross-platform builds compile without dragging in DsGetDcName / LSA
// dependencies that don't exist outside Windows.
func nativeaotDpapiBackupkey(_ context.Context, _ api.Module, stack []uint64) {
	stack[0] = 0
}
