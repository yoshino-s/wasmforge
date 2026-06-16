// Package hostmod implements the wasmforge host module that provides
// socket networking to WASM guests via custom host functions.
package hostmod

import (
	"encoding/binary"
	"fmt"

	"github.com/tetratelabs/wazero/api"
)

// readBytes reads n bytes from WASM linear memory at the given offset.
func readBytes(mod api.Module, offset, size uint32) ([]byte, bool) {
	mem := mod.Memory()
	if mem == nil {
		return nil, false
	}
	buf, ok := mem.Read(offset, size)
	if !ok {
		return nil, false
	}
	// Return a copy to avoid issues with memory growth.
	result := make([]byte, size)
	copy(result, buf)
	return result, true
}

// writeBytes writes bytes to WASM linear memory at the given offset.
func writeBytes(mod api.Module, offset uint32, data []byte) bool {
	mem := mod.Memory()
	if mem == nil {
		return false
	}
	return mem.Write(offset, data)
}

// readUint32 reads a uint32 from WASM memory (little-endian).
func readUint32(mod api.Module, offset uint32) (uint32, bool) {
	mem := mod.Memory()
	if mem == nil {
		return 0, false
	}
	buf, ok := mem.Read(offset, 4)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint32(buf), true
}

// writeUint32 writes a uint32 to WASM memory (little-endian).
func writeUint32(mod api.Module, offset uint32, val uint32) bool {
	mem := mod.Memory()
	if mem == nil {
		return false
	}
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, val)
	return mem.Write(offset, buf)
}

// writeInt32 writes an int32 to WASM memory (little-endian).
func writeInt32(mod api.Module, offset uint32, val int32) bool {
	return writeUint32(mod, offset, uint32(val))
}

// readInt32 reads an int32 from WASM memory (little-endian).
func readInt32(mod api.Module, offset uint32) (int32, bool) {
	v, ok := readUint32(mod, offset)
	return int32(v), ok
}

// memoryError creates a formatted error for memory access failures.
func memoryError(fn string, offset, size uint32) error {
	return fmt.Errorf("runtime: %s: memory access out of bounds at offset=%d size=%d", fn, offset, size)
}
