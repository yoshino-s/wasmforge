//go:build wasip1

package darwin

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unsafe"
)

// Framework represents a loaded macOS framework or dylib.
type Framework int32

// Symbol represents a resolved function symbol in a loaded framework.
type Symbol int32

// ENOSYS is the errno returned when Darwin APIs are not available.
const ENOSYS = 52

// ErrNotAvailable is returned when Darwin APIs are not available (non-macOS host).
var ErrNotAvailable = fmt.Errorf("darwin: not available (ENOSYS)")

// errFromErrno converts a WASI errno to an error.
func errFromErrno(errno int32) error {
	if errno == 0 {
		return nil
	}
	if errno == ENOSYS {
		return ErrNotAvailable
	}
	return fmt.Errorf("darwin: errno %d", errno)
}

// Available returns true if Darwin APIs are available on the host.
func Available() bool {
	return _darwin_available() == 1
}

// LoadFramework loads a macOS framework or dylib.
// Short names are expanded:
//
//	"Security"      → /System/Library/Frameworks/Security.framework/Security
//	"libSystem.B"   → /usr/lib/libSystem.B.dylib
//	"/full/path"    → used as-is
func LoadFramework(name string) (Framework, error) {
	if len(name) == 0 {
		return 0, fmt.Errorf("darwin: LoadFramework: empty name")
	}
	b := []byte(name)
	var h int32
	errno := _darwin_load(&b[0], int32(len(b)), &h)
	if err := errFromErrno(errno); err != nil {
		return 0, fmt.Errorf("darwin: LoadFramework(%s): %w", name, err)
	}
	return Framework(h), nil
}

// GetSymbol looks up a function symbol in the framework.
func (f Framework) GetSymbol(name string) (Symbol, error) {
	if len(name) == 0 {
		return 0, fmt.Errorf("darwin: GetSymbol: empty name")
	}
	b := []byte(name)
	var s int32
	errno := _darwin_get_symbol(int32(f), &b[0], int32(len(b)), &s)
	if err := errFromErrno(errno); err != nil {
		return 0, fmt.Errorf("darwin: GetSymbol(%s): %w", name, err)
	}
	return Symbol(s), nil
}

// Call calls the symbol with the given arguments. Arguments are passed as
// uintptr values (8 bytes each). WASM pointers are automatically translated
// to host addresses by the host module.
// Returns the function's return value (r1) and any error.
func (s Symbol) Call(args ...uintptr) (uintptr, error) {
	var retBuf [8]byte
	nargs := int32(len(args))

	var argsPtr *byte
	var argBytes []byte
	if nargs > 0 {
		argBytes = make([]byte, nargs*8)
		for i, arg := range args {
			binary.LittleEndian.PutUint64(argBytes[i*8:], uint64(arg))
		}
		argsPtr = &argBytes[0]
	}

	errno := _darwin_call(int32(s), nargs, argsPtr, &retBuf[0])
	r1 := uintptr(binary.LittleEndian.Uint64(retBuf[:]))

	if err := errFromErrno(errno); err != nil {
		return r1, err
	}
	return r1, nil
}

// CallMasked calls the symbol with selective WASM pointer translation.
// Only args whose corresponding bit is set in ptrMask are translated.
// Bit 0 = arg 0, bit 1 = arg 1, etc.
func (s Symbol) CallMasked(ptrMask uint32, args ...uintptr) (uintptr, error) {
	var retBuf [8]byte
	nargs := int32(len(args))

	var argsPtr *byte
	var argBytes []byte
	if nargs > 0 {
		argBytes = make([]byte, nargs*8)
		for i, arg := range args {
			binary.LittleEndian.PutUint64(argBytes[i*8:], uint64(arg))
		}
		argsPtr = &argBytes[0]
	}

	errno := _darwin_call_masked(int32(s), nargs, argsPtr, int32(ptrMask), &retBuf[0])
	r1 := uintptr(binary.LittleEndian.Uint64(retBuf[:]))

	if err := errFromErrno(errno); err != nil {
		return r1, err
	}
	return r1, nil
}

// CallRaw calls the symbol WITHOUT WASM pointer translation.
// Use this for APIs that operate on remote process memory (Mach VM APIs)
// where arguments contain addresses in another process's address space.
func (s Symbol) CallRaw(args ...uintptr) (uintptr, error) {
	var retBuf [8]byte
	nargs := int32(len(args))

	var argsPtr *byte
	var argBytes []byte
	if nargs > 0 {
		argBytes = make([]byte, nargs*8)
		for i, arg := range args {
			binary.LittleEndian.PutUint64(argBytes[i*8:], uint64(arg))
		}
		argsPtr = &argBytes[0]
	}

	errno := _darwin_call_raw(int32(s), nargs, argsPtr, &retBuf[0])
	r1 := uintptr(binary.LittleEndian.Uint64(retBuf[:]))

	if err := errFromErrno(errno); err != nil {
		return r1, err
	}
	return r1, nil
}

// ReadHostMemory reads bytes from a host memory address into a byte slice.
// addr is a host pointer returned from a framework call.
func ReadHostMemory(addr uintptr, offset uint32, buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	addrBuf := (*[8]byte)(unsafe.Pointer(&addr))
	errno := _darwin_mem_read(&addrBuf[0], offset, &buf[0], uint32(len(buf)))
	return errFromErrno(errno)
}

// WriteHostMemory writes bytes from a byte slice to a host memory address.
// addr is a host pointer returned from a framework call or mmap.
func WriteHostMemory(addr uintptr, offset uint32, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	addrBuf := (*[8]byte)(unsafe.Pointer(&addr))
	errno := _darwin_mem_write(&addrBuf[0], offset, &data[0], uint32(len(data)))
	return errFromErrno(errno)
}

// ExpandFrameworkPath expands a short framework name to its full path.
// This is the same logic used by the host, provided for informational purposes.
func ExpandFrameworkPath(name string) string {
	if strings.HasPrefix(name, "/") {
		return name
	}
	if strings.HasPrefix(name, "lib") {
		return "/usr/lib/" + name + ".dylib"
	}
	return "/System/Library/Frameworks/" + name + ".framework/" + name
}

// ---------- Callback API ----------

// CreateCallback allocates a callback slot on the host with the given number
// of arguments. Returns the slot ID.
func CreateCallback(nargs int) (int32, error) {
	var id int32
	errno := _darwin_callback_create(int32(nargs), &id)
	if err := errFromErrno(errno); err != nil {
		return 0, fmt.Errorf("darwin: CreateCallback: %w", err)
	}
	return id, nil
}

// CallbackAddr returns the native function pointer for a callback slot.
// This address can be passed to ObjC APIs (e.g., class_addMethod).
func CallbackAddr(id int32) (uintptr, error) {
	var addrBuf [8]byte
	errno := _darwin_callback_addr(id, &addrBuf[0])
	if err := errFromErrno(errno); err != nil {
		return 0, fmt.Errorf("darwin: CallbackAddr: %w", err)
	}
	addr := uintptr(binary.LittleEndian.Uint64(addrBuf[:]))
	return addr, nil
}

// errnoYIELD is the special errno returned by non-blocking host functions
// that need the guest to yield and retry.
const errnoYIELD = 255

// WaitCallback blocks (with yield protocol) until the callback is invoked.
// Returns the arguments passed by the native caller.
func WaitCallback(id int32) ([]uintptr, error) {
	const maxArgs = 9
	argsBuf := make([]byte, maxArgs*8)
	var nargs int32

	for {
		errno := _darwin_callback_wait(id, &argsBuf[0], maxArgs, &nargs)
		if errno == int32(errnoYIELD) {
			// Yield: create a scheduling point via channel.
			c := make(chan struct{}, 1)
			go func() { c <- struct{}{} }()
			<-c
			continue
		}
		if err := errFromErrno(errno); err != nil {
			return nil, fmt.Errorf("darwin: WaitCallback: %w", err)
		}
		break
	}

	args := make([]uintptr, nargs)
	for i := int32(0); i < nargs; i++ {
		off := i * 8
		args[i] = uintptr(binary.LittleEndian.Uint64(argsBuf[off : off+8]))
	}
	return args, nil
}

// ReturnCallback sends the return value back to the native caller.
func ReturnCallback(id int32, result uintptr) error {
	errno := _darwin_callback_return(id, int64(result))
	return errFromErrno(errno)
}

// FreeCallback releases a callback slot.
func FreeCallback(id int32) error {
	errno := _darwin_callback_free(id)
	return errFromErrno(errno)
}

// ReadCString reads a null-terminated C string from a host memory address.
func ReadCString(addr uintptr, maxLen int) (string, error) {
	if addr == 0 {
		return "", nil
	}
	if maxLen <= 0 {
		maxLen = 4096
	}
	addrBuf := (*[8]byte)(unsafe.Pointer(&addr))
	buf := make([]byte, maxLen)
	var actualLen int32
	errno := _darwin_read_cstring(&addrBuf[0], &buf[0], uint32(maxLen), &actualLen)
	if err := errFromErrno(errno); err != nil {
		return "", fmt.Errorf("darwin: ReadCString: %w", err)
	}
	return string(buf[:actualLen]), nil
}

// ---------- Block API ----------

// CreateBlock constructs an ObjC block on the host side using the given
// callback slot and type signature. Returns a block handle.
func CreateBlock(cbID int32, signature []byte) (int32, error) {
	var blockID int32
	var sigPtr *byte
	var sigLen int32
	if len(signature) > 0 {
		sigPtr = &signature[0]
		sigLen = int32(len(signature))
	}
	errno := _darwin_block_create(cbID, sigPtr, sigLen, &blockID)
	if err := errFromErrno(errno); err != nil {
		return 0, fmt.Errorf("darwin: CreateBlock: %w", err)
	}
	return blockID, nil
}

// BlockAddr returns the host pointer to the ObjC block object.
func BlockAddr(blockID int32) (uintptr, error) {
	var addrBuf [8]byte
	errno := _darwin_block_addr(blockID, &addrBuf[0])
	if err := errFromErrno(errno); err != nil {
		return 0, fmt.Errorf("darwin: BlockAddr: %w", err)
	}
	return uintptr(binary.LittleEndian.Uint64(addrBuf[:])), nil
}

// ReleaseBlock releases an ObjC block.
func ReleaseBlock(blockID int32) error {
	errno := _darwin_block_release(blockID)
	return errFromErrno(errno)
}
