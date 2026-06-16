//go:build nativeaot && !windows

package hostmod

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

// nativeaotRegSearch — non-Windows stub. The Windows registry has no
// equivalent outside Windows targets; return 0 (no matches) so callers
// can fall back to whatever behaviour they want for cross-platform builds.
func nativeaotRegSearch(_ context.Context, _ api.Module, stack []uint64) {
	stack[0] = 0
}
