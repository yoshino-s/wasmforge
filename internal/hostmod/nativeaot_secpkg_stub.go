//go:build nativeaot && !windows

package hostmod

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

func osEnumSecPackages(_ context.Context, mod api.Module, stack []uint64) {
	countPtr := uint32(stack[2])
	writeUint32(mod, countPtr, 0)
	stack[0] = 0
}
