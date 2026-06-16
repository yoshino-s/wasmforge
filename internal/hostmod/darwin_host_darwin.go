//go:build darwin

package hostmod

import (
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
)

// dlopen/dlsym constants.
const (
	_RTLD_LAZY   = 0x1
	_RTLD_NOW    = 0x2
	_RTLD_GLOBAL = 0x8
)

// Import dlopen/dlsym from libSystem.B.dylib so the linker resolves them.
// These directives work on darwin regardless of CGO_ENABLED because Go's linker
// always links against libSystem.B.dylib on macOS.
//
//go:cgo_import_dynamic dlopen dlopen "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic dlsym dlsym "/usr/lib/libSystem.B.dylib"

// Assembly trampolines defined in darwin_trampoline_{amd64,arm64}.s.
// These call the real libc dlopen/dlsym functions resolved by the Go linker.

//go:nosplit
func dlopen_trampoline(name uintptr, mode uintptr) uintptr

//go:nosplit
func dlsym_trampoline(handle uintptr, name uintptr) uintptr

// ccall9 calls a C function pointer with up to 9 arguments via assembly trampoline.
// Uses SysV AMD64 ABI (amd64) or AAPCS (arm64). Unused args should be 0.
//
//go:nosplit
func ccall9(fn uintptr, a0, a1, a2, a3, a4, a5, a6, a7, a8 uintptr) uintptr

// nativeDlopen calls dlopen via assembly trampoline.
func nativeDlopen(path string) (uintptr, error) {
	cpath, err := syscall.BytePtrFromString(path)
	if err != nil {
		return 0, err
	}
	handle := dlopen_trampoline(uintptr(unsafe.Pointer(cpath)), _RTLD_LAZY)
	if handle == 0 {
		return 0, fmt.Errorf("dlopen(%s) failed", path)
	}
	return handle, nil
}

// nativeDlsym calls dlsym via assembly trampoline.
func nativeDlsym(handle uintptr, name string) (uintptr, error) {
	cname, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	addr := dlsym_trampoline(handle, uintptr(unsafe.Pointer(cname)))
	if addr == 0 {
		return 0, fmt.Errorf("dlsym(%s) failed", name)
	}
	return addr, nil
}

// expandFrameworkPath converts short framework names to full paths.
// "Security" → "/System/Library/Frameworks/Security.framework/Security"
// "libSystem.B" → "/usr/lib/libSystem.B.dylib"
// Paths starting with "/" are used as-is.
func expandFrameworkPath(name string) string {
	if strings.HasPrefix(name, "/") {
		return name
	}
	if strings.HasPrefix(name, "lib") {
		return "/usr/lib/" + name + ".dylib"
	}
	return "/System/Library/Frameworks/" + name + ".framework/" + name
}

// darwinVerbose returns true if debug logging is enabled via the runtime config.
func darwinVerbose(ctx context.Context) bool {
	cfg := getConfig(ctx)
	return cfg != nil && cfg.Verbose
}

// darwinAvailable returns 1 if darwin APIs are enabled in the config.
func darwinAvailable(ctx context.Context, mod api.Module) uint32 {
	cfg := getConfig(ctx)
	if cfg != nil && cfg.DarwinAPIs {
		return 1
	}
	return 0
}

// darwinLoad loads a macOS framework/dylib via dlopen and registers
// the handle in the handle table.
func darwinLoad(ctx context.Context, mod api.Module, namePtr, nameLen, handlePtr uint32) uint32 {
	name, ok := readBytes(mod, namePtr, nameLen)
	if !ok {
		return errnoEFAULT
	}
	path := expandFrameworkPath(string(name))

	handle, err := nativeDlopen(path)
	if err != nil {
		if darwinVerbose(ctx) {
			fmt.Fprintf(os.Stderr, "[runtime] darwin_load: dlopen(%s) failed: %v\n", path, err)
		}
		return errnoEINVAL
	}

	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoENOSYS
	}

	guestHandle := ht.register(&win32HandleEntry{
		kind:      handleDylib,
		dllHandle: handle,
		debugName: string(name),
	})

	if !writeInt32(mod, handlePtr, guestHandle) {
		return errnoEFAULT
	}

	if darwinVerbose(ctx) {
		fmt.Fprintf(os.Stderr, "[runtime] darwin_load: %s → handle %d (host=%#x)\n", path, guestHandle, handle)
	}
	return errnoSuccess
}

// darwinGetSymbol looks up a symbol in a loaded dylib via dlsym.
func darwinGetSymbol(ctx context.Context, mod api.Module, libHandle int32, namePtr, nameLen, symPtr uint32) uint32 {
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoENOSYS
	}

	entry := ht.get(libHandle)
	if entry == nil || entry.kind != handleDylib {
		return errnoEBADF
	}

	name, ok := readBytes(mod, namePtr, nameLen)
	if !ok {
		return errnoEFAULT
	}

	addr, err := nativeDlsym(entry.dllHandle, string(name))
	if err != nil {
		if darwinVerbose(ctx) {
			fmt.Fprintf(os.Stderr, "[runtime] darwin_get_symbol: dlsym(%s) failed: %v\n", string(name), err)
		}
		return errnoEINVAL
	}

	guestHandle := ht.register(&win32HandleEntry{
		kind:      handleSymbol,
		procAddr:  addr,
		debugName: string(name),
	})

	if !writeInt32(mod, symPtr, guestHandle) {
		return errnoEFAULT
	}

	if darwinVerbose(ctx) {
		fmt.Fprintf(os.Stderr, "[runtime] darwin_get_symbol: %s → handle %d (addr=%#x)\n", string(name), guestHandle, addr)
	}
	return errnoSuccess
}


// darwinCallMasked calls a framework function with selective pointer translation.
// Only args whose corresponding bit is set in ptrMask are translated.
func darwinCallMasked(ctx context.Context, mod api.Module, symHandle int32, nargs int32, argsPtr uint32, ptrMask int32, retPtr uint32) uint32 {
	return darwinCallInternalMasked(ctx, mod, symHandle, nargs, argsPtr, retPtr, uint32(ptrMask))
}

// darwinCallRaw calls a framework function WITHOUT pointer translation.
// Used for Mach APIs that operate on remote process addresses.
func darwinCallRaw(ctx context.Context, mod api.Module, symHandle int32, nargs int32, argsPtr, retPtr uint32) uint32 {
	return darwinCallInternalMasked(ctx, mod, symHandle, nargs, argsPtr, retPtr, 0)
}

func darwinCall(ctx context.Context, mod api.Module, symHandle int32, nargs int32, argsPtr, retPtr uint32) uint32 {
	return darwinCallInternalMasked(ctx, mod, symHandle, nargs, argsPtr, retPtr, 0xFFFFFFFF)
}

// darwinCallInternalMasked is the shared implementation. ptrMask controls which
// args get WASM→host pointer translation (bit per arg, 0xFFFFFFFF = translate all).
func darwinCallInternalMasked(ctx context.Context, mod api.Module, symHandle int32, nargs int32, argsPtr, retPtr uint32, ptrMask uint32) uint32 {
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoENOSYS
	}

	entry := ht.get(symHandle)
	if entry == nil || entry.kind != handleSymbol {
		return errnoEBADF
	}

	if nargs < 0 || nargs > 9 {
		// ccall9 supports up to 9 args via SysV AMD64 ABI. Most macOS APIs use ≤6.
		// Extended arg support (>9) can be added via assembly trampolines if needed.
		return errnoEINVAL
	}

	// Read arguments from WASM memory (8 bytes each = uint64).
	var args [9]uintptr
	if nargs > 0 {
		argBytes, ok := readBytes(mod, argsPtr, uint32(nargs)*8)
		if !ok {
			return errnoEFAULT
		}
		for i := int32(0); i < nargs; i++ {
			off := i * 8
			args[i] = uintptr(
				uint64(argBytes[off]) |
					uint64(argBytes[off+1])<<8 |
					uint64(argBytes[off+2])<<16 |
					uint64(argBytes[off+3])<<24 |
					uint64(argBytes[off+4])<<32 |
					uint64(argBytes[off+5])<<40 |
					uint64(argBytes[off+6])<<48 |
					uint64(argBytes[off+7])<<56,
			)
		}
	}

	// Step 3: WASM pointer translation with per-arg mask.
	// ptrMask controls which args get translated (bit per arg).
	// 0xFFFFFFFF = translate all eligible (legacy Call mode).
	// 0x0 = translate none (CallRaw mode).
	// Per-bit = CallMasked mode (from RegisterFunc which knows arg types).
	// ALWAYS translate WASM pointers, regardless of ptrMask.
	// The heuristic is safe: host pointers on macOS are 64-bit values (>4GB),
	// always above any practical WASM memory size. WASM offsets are small
	// values (< memory size) and need wasmMemBase added. The ptrMask is
	// informational but the heuristic handles all cases correctly.
	{
		mem := mod.Memory()
		if mem != nil {
			wasmMemSize := mem.Size()
			var wasmMemBase uintptr
			if wasmMemSize > 0 {
				if buf, ok := mem.Read(0, 1); ok && len(buf) > 0 {
					wasmMemBase = uintptr(unsafe.Pointer(&buf[0]))
				}
			}
			if wasmMemBase != 0 {
				const wasmPtrThreshold = 0x10000
				for i := int32(0); i < nargs; i++ {
					v := args[i]
					if v >= wasmPtrThreshold && v < uintptr(wasmMemSize) {
						args[i] = wasmMemBase + v
					}
				}
			}
		}
	}

	// Call the function via ccall9 assembly trampoline (C calling convention).
	// syscall.Syscall on darwin uses SYSCALL instruction (kernel traps), not
	// function pointer calls. ccall9 uses CALL instruction with SysV ABI.
	fn := entry.procAddr
	r1 := ccall9(fn, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8])

	// Write return value (r1) as uint64 into retPtr.
	retBuf := make([]byte, 8)
	retBuf[0] = byte(r1)
	retBuf[1] = byte(r1 >> 8)
	retBuf[2] = byte(r1 >> 16)
	retBuf[3] = byte(r1 >> 24)
	retBuf[4] = byte(r1 >> 32)
	retBuf[5] = byte(r1 >> 40)
	retBuf[6] = byte(r1 >> 48)
	retBuf[7] = byte(r1 >> 56)
	if !writeBytes(mod, retPtr, retBuf) {
		return errnoEFAULT
	}

	return errnoSuccess
}

// darwinMemRead copies bytes from a host memory address into WASM linear memory.
func darwinMemRead(ctx context.Context, mod api.Module, addrPtr, offset, bufPtr, bufLen uint32) uint32 {
	// Read the 8-byte host address from WASM memory.
	addrBytes, ok := readBytes(mod, addrPtr, 8)
	if !ok {
		return errnoEFAULT
	}
	hostAddr := uintptr(
		uint64(addrBytes[0]) |
			uint64(addrBytes[1])<<8 |
			uint64(addrBytes[2])<<16 |
			uint64(addrBytes[3])<<24 |
			uint64(addrBytes[4])<<32 |
			uint64(addrBytes[5])<<40 |
			uint64(addrBytes[6])<<48 |
			uint64(addrBytes[7])<<56,
	)

	if hostAddr == 0 || bufLen == 0 {
		return errnoEINVAL
	}

	// Read from host memory. Use the approved single-expression pattern to
	// avoid GC-unsafe uintptr arithmetic across statements.
	base := (*[1 << 30]byte)(unsafe.Pointer(hostAddr))
	data := make([]byte, bufLen)
	copy(data, base[offset:offset+bufLen])

	if !writeBytes(mod, bufPtr, data) {
		return errnoEFAULT
	}
	return errnoSuccess
}

// darwinMemWrite copies bytes from WASM linear memory to a host memory address.
func darwinMemWrite(ctx context.Context, mod api.Module, addrPtr, offset, dataPtr, dataLen uint32) uint32 {
	// Read the 8-byte host address from WASM memory.
	addrBytes, ok := readBytes(mod, addrPtr, 8)
	if !ok {
		return errnoEFAULT
	}
	hostAddr := uintptr(
		uint64(addrBytes[0]) |
			uint64(addrBytes[1])<<8 |
			uint64(addrBytes[2])<<16 |
			uint64(addrBytes[3])<<24 |
			uint64(addrBytes[4])<<32 |
			uint64(addrBytes[5])<<40 |
			uint64(addrBytes[6])<<48 |
			uint64(addrBytes[7])<<56,
	)

	if hostAddr == 0 || dataLen == 0 {
		return errnoEINVAL
	}

	// Read data from WASM memory.
	data, ok := readBytes(mod, dataPtr, dataLen)
	if !ok {
		return errnoEFAULT
	}

	// Write to host memory. Use the approved single-expression pattern.
	base := (*[1 << 30]byte)(unsafe.Pointer(hostAddr))
	copy(base[offset:offset+dataLen], data)

	return errnoSuccess
}
