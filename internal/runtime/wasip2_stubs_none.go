//go:build !nativeaot

package runtime

import (
	"context"

	"github.com/tetratelabs/wazero"
)

// registerWASIP2Stubs is a no-op when the nativeaot build tag is absent.
// Standard Go WASM modules use WASI Preview 1 and don't need P2 stubs.
func registerWASIP2Stubs(ctx context.Context, rt wazero.Runtime, args []string) error {
	return nil
}
