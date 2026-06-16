//go:build wasip1

package win32

import (
	"encoding/binary"
	"fmt"
	"runtime"
)

const errnoYield = 255

// Handle represents a guest-side Win32 handle.
type Handle int32

// Proc represents a guest-side procedure address.
type Proc int32

// ENOSYS is the errno returned when Win32 APIs are not available.
const ENOSYS = 52

// ErrNotAvailable is returned when Win32 APIs are not available (non-Windows host).
var ErrNotAvailable = fmt.Errorf("win32: not available (ENOSYS)")

// errFromErrno converts a WASI errno to an error.
func errFromErrno(errno int32) error {
	if errno == 0 {
		return nil
	}
	if errno == ENOSYS {
		return ErrNotAvailable
	}
	return fmt.Errorf("win32: errno %d", errno)
}

// Available returns true if Win32 APIs are available on the host.
func Available() bool {
	return _win32_available() == 1
}

// LoadLibrary loads a DLL by name and returns a handle.
func LoadLibrary(name string) (Handle, error) {
	if len(name) == 0 {
		return 0, fmt.Errorf("win32: LoadLibrary: empty name")
	}
	b := []byte(name)
	var h int32
	errno := _win32_load_library(&b[0], int32(len(b)), &h)
	if err := errFromErrno(errno); err != nil {
		return 0, err
	}
	return Handle(h), nil
}

// GetProcAddress returns the address of a function in a loaded DLL.
func (h Handle) GetProcAddress(name string) (Proc, error) {
	if len(name) == 0 {
		return 0, fmt.Errorf("win32: GetProcAddress: empty name")
	}
	b := []byte(name)
	var p int32
	errno := _win32_get_proc_address(int32(h), &b[0], int32(len(b)), &p)
	if err := errFromErrno(errno); err != nil {
		return 0, err
	}
	return Proc(p), nil
}

// Call calls a procedure with up to 6 uint32 arguments.
// Cooperatively yields if the host reports the call is blocking (errnoYield),
// so blocking APIs called through this path don't stall the WASM scheduler.
func (p Proc) Call(args ...uint32) (uint32, error) {
	var ret uint32
	var argsPtr *uint32
	if len(args) > 0 {
		argsPtr = &args[0]
	}
	for {
		errno := _win32_call(int32(p), int32(len(args)), argsPtr, &ret)
		if errno == errnoYield {
			runtime.Gosched()
			continue
		}
		if err := errFromErrno(errno); err != nil {
			return 0, err
		}
		return ret, nil
	}
}

// Free releases the DLL handle.
func (h Handle) Free() error {
	return errFromErrno(_win32_free_library(int32(h)))
}

// CloseHandle closes a generic Win32 handle.
func CloseHandle(h Handle) error {
	return errFromErrno(_win32_close_handle(int32(h)))
}

// SyscallN calls a procedure with up to 15 uintptr-width arguments.
// Returns (r1, r2, lastErr) matching the Windows SyscallN convention.
// This is the wide variant used by x/sys/windows compatibility.
// NOTE: On WASM, uintptr is 32 bits. Use SyscallN64 when passing 64-bit host addresses.
func SyscallN(proc Proc, args ...uintptr) (r1, r2 uintptr, lastErr uint32) {
	var argBuf [15 * 8]byte // max 15 args * 8 bytes each
	for i, a := range args {
		if i >= 15 {
			break
		}
		binary.LittleEndian.PutUint64(argBuf[i*8:], uint64(a))
	}

	var ret1Buf, ret2Buf, errBuf [8]byte
	var argsPtr *byte
	if len(args) > 0 {
		argsPtr = &argBuf[0]
	}

	for {
		errno := _win32_syscalln(int32(proc), int32(len(args)), argsPtr, &ret1Buf[0], &ret2Buf[0], &errBuf[0])
		if errno == errnoYield {
			runtime.Gosched()
			continue
		}
		if errno != 0 {
			return 0, 0, uint32(errno)
		}
		break
	}

	r1 = uintptr(binary.LittleEndian.Uint64(ret1Buf[:]))
	r2 = uintptr(binary.LittleEndian.Uint64(ret2Buf[:]))
	lastErr = uint32(binary.LittleEndian.Uint64(errBuf[:]))
	return r1, r2, lastErr
}

// SyscallN64 calls a procedure with up to 15 uint64 arguments, preserving full
// 64-bit values. Use this instead of SyscallN when passing host memory addresses
// (from HostMem.Addr) or other 64-bit values that don't fit in WASM's 32-bit uintptr.
func SyscallN64(proc Proc, args ...uint64) (r1, r2 uint64, lastErr uint32) {
	var argBuf [15 * 8]byte
	for i, a := range args {
		if i >= 15 {
			break
		}
		binary.LittleEndian.PutUint64(argBuf[i*8:], a)
	}

	var ret1Buf, ret2Buf, errBuf [8]byte
	var argsPtr *byte
	if len(args) > 0 {
		argsPtr = &argBuf[0]
	}

	for {
		errno := _win32_syscalln(int32(proc), int32(len(args)), argsPtr, &ret1Buf[0], &ret2Buf[0], &errBuf[0])
		if errno == errnoYield {
			runtime.Gosched()
			continue
		}
		if errno != 0 {
			return 0, 0, uint32(errno)
		}
		break
	}

	r1 = binary.LittleEndian.Uint64(ret1Buf[:])
	r2 = binary.LittleEndian.Uint64(ret2Buf[:])
	lastErr = uint32(binary.LittleEndian.Uint64(errBuf[:]))
	return r1, r2, lastErr
}

// ProcAddr returns the real host address of a proc handle as a uint64.
// This is needed for writing resolved function addresses into PE import tables
// in host memory.
func ProcAddr(p Proc) (uint64, error) {
	var buf [8]byte
	errno := _win32_proc_addr(int32(p), &buf[0])
	if err := errFromErrno(errno); err != nil {
		return 0, fmt.Errorf("win32: ProcAddr: %w", err)
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}
