package experimental

import (
	"context"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/internal/expctxkeys"
)

// MemoryFaultHandler is called when a WASM memory access is out-of-bounds.
// The handler receives the module, the base address of the access (as a 32-bit
// WASM address), and the total size of the access (base + operation size).
//
// If the handler returns true, execution resumes at the instruction after the
// bounds check. The handler should have grown memory and populated the
// requested region so the subsequent load/store succeeds.
//
// If the handler returns false, the runtime panics with an out-of-bounds error.
type MemoryFaultHandler func(mod api.Module, addr uint32, size uint32) bool

// WithMemoryFaultHandler registers a MemoryFaultHandler into the given context.
// The context must be passed when instantiating a module.
//
// When a compiled WASM module performs a memory access beyond the current
// linear memory bounds, instead of immediately trapping, the runtime calls
// the registered handler. This enables demand-paging patterns where host
// memory is lazily copied into WASM linear memory on first access.
func WithMemoryFaultHandler(ctx context.Context, handler MemoryFaultHandler) context.Context {
	if handler != nil {
		return context.WithValue(ctx, expctxkeys.MemoryFaultHandlerKey{},
			func(mod api.Module, addr uint32, size uint32) bool {
				return handler(mod, addr, size)
			})
	}
	return ctx
}
