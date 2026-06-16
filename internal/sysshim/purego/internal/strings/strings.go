// Package strings provides C string helpers for the purego sysshim.
// On wasip1, GoString must handle host pointers (outside WASM linear memory)
// by reading through the darwin bridge.

//go:build wasip1

package strings

import (
	"github.com/praetorian-inc/wasmforge/guest/darwin"
)

// CString converts a Go string to a null-terminated *byte that can be passed
// to C code. Always copies to ensure the result is in WASM linear memory and
// safe from GC.
func CString(name string) *byte {
	b := make([]byte, len(name)+1)
	copy(b, name)
	return &b[0]
}

// GoString reads a null-terminated C string from a host memory address.
// Since the pointer is a host address (outside WASM linear memory), we use
// darwin.ReadHostMemory to read bytes in chunks until we find \0.
func GoString(c uintptr) string {
	if c == 0 {
		return ""
	}

	// Read in chunks to find the null terminator.
	const chunkSize = 256
	var result []byte
	offset := uint32(0)
	for {
		buf := make([]byte, chunkSize)
		err := darwin.ReadHostMemory(c, offset, buf)
		if err != nil {
			// If read fails, return what we have.
			break
		}
		for i, b := range buf {
			if b == 0 {
				result = append(result, buf[:i]...)
				return string(result)
			}
		}
		result = append(result, buf...)
		offset += chunkSize
		// Safety limit: 64KB max string length.
		if offset > 65536 {
			break
		}
	}
	return string(result)
}
