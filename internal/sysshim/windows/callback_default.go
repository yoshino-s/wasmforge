// Default NewCallback implementations that delegate to syscall.
// On wasip1, these are overridden by wasip1_shim.go which uses
// wasmforge's wasm-imported callback mechanism instead.

//go:build windows

package windows

import "syscall"

// NewCallback converts a Go function to a function pointer conforming to the stdcall calling convention.
func NewCallback(fn interface{}) uintptr {
	return syscall.NewCallback(fn)
}

// NewCallbackCDecl converts a Go function to a function pointer conforming to the cdecl calling convention.
func NewCallbackCDecl(fn interface{}) uintptr {
	return syscall.NewCallbackCDecl(fn)
}
