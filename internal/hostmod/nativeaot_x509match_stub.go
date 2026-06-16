//go:build nativeaot && !windows

package hostmod

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

// nativeaotX509Match — non-Windows stub. Returns 0 bytes written; the C#
// caller treats `written < 4` as a parse failure and falls back to the
// no-match path, so cross-platform builds compile without dragging in
// crypt32 / x509 dependencies.
func nativeaotX509Match(_ context.Context, _ api.Module, stack []uint64) {
	stack[0] = 0
}
