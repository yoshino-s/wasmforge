//go:build darwin

package hostmod

import (
	"context"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/tetratelabs/wazero/api"
)

// ---------- Callback slot infrastructure ----------
//
// 8 callback slots, each backed by a real native C function pointer created
// via the host's real purego.NewCallback. When ObjC invokes the trampoline,
// it captures args into the slot's channel and blocks until the guest sends
// back a return value.

const maxCallbackSlots = 8

type callbackSlot struct {
	mu         sync.Mutex
	active     bool
	nargs      int
	invoked    chan []uintptr // native trampoline sends args here
	result     chan uintptr   // guest sends return value here
	nativeAddr uintptr       // real C function pointer from purego.NewCallback
}

var callbackSlots [maxCallbackSlots]callbackSlot

// createNativeTrampoline creates a real C function pointer for the given slot
// using the host's real purego.NewCallback. The trampoline captures up to 9
// args, sends them on slot.invoked, and blocks on slot.result.
func createNativeTrampoline(slotID int) uintptr {
	slot := &callbackSlots[slotID]
	fn := func(a0, a1, a2, a3, a4, a5, a6, a7, a8 uintptr) uintptr {
		all := [9]uintptr{a0, a1, a2, a3, a4, a5, a6, a7, a8}
		slot.mu.Lock()
		n := slot.nargs
		ch := slot.invoked
		slot.mu.Unlock()
		if ch == nil {
			return 0
		}
		args := make([]uintptr, n)
		copy(args, all[:n])
		ch <- args
		return <-slot.result
	}
	return purego.NewCallback(fn)
}

// ---------- Host function implementations ----------

// darwinCallbackCreate allocates a callback slot and returns its ID.
func darwinCallbackCreate(ctx context.Context, mod api.Module, nargs uint32, idPtr uint32) uint32 {
	if nargs > 9 {
		return errnoEINVAL
	}

	for i := 0; i < maxCallbackSlots; i++ {
		slot := &callbackSlots[i]
		slot.mu.Lock()
		if !slot.active {
			slot.active = true
			slot.nargs = int(nargs)
			slot.invoked = make(chan []uintptr, 1)
			slot.result = make(chan uintptr, 1)
			slot.nativeAddr = createNativeTrampoline(i)
			slot.mu.Unlock()

			if !writeInt32(mod, idPtr, int32(i)) {
				return errnoEFAULT
			}
			if darwinVerbose(ctx) {
				fmt.Fprintf(os.Stderr, "[runtime] darwin_callback_create: slot=%d nargs=%d addr=%#x\n",
					i, nargs, slot.nativeAddr)
			}
			return errnoSuccess
		}
		slot.mu.Unlock()
	}
	return errnoERANGE // all callback slots in use
}

// darwinCallbackAddr returns the native function pointer for a callback slot.
func darwinCallbackAddr(ctx context.Context, mod api.Module, id uint32, addrPtr uint32) uint32 {
	if int(id) >= maxCallbackSlots {
		return errnoEINVAL
	}
	slot := &callbackSlots[id]
	slot.mu.Lock()
	if !slot.active {
		slot.mu.Unlock()
		return errnoEINVAL
	}
	addr := slot.nativeAddr
	slot.mu.Unlock()

	addrBuf := make([]byte, 8)
	addrBuf[0] = byte(addr)
	addrBuf[1] = byte(addr >> 8)
	addrBuf[2] = byte(addr >> 16)
	addrBuf[3] = byte(addr >> 24)
	addrBuf[4] = byte(addr >> 32)
	addrBuf[5] = byte(addr >> 40)
	addrBuf[6] = byte(addr >> 48)
	addrBuf[7] = byte(addr >> 56)
	if !writeBytes(mod, addrPtr, addrBuf) {
		return errnoEFAULT
	}
	return errnoSuccess
}

// darwinCallbackWait checks if a callback has been invoked. Non-blocking:
// returns errnoYIELD (255) if not yet invoked.
func darwinCallbackWait(ctx context.Context, mod api.Module, id, argsPtr, argsCap, nargsPtr uint32) uint32 {
	if int(id) >= maxCallbackSlots {
		return errnoEINVAL
	}
	slot := &callbackSlots[id]
	slot.mu.Lock()
	if !slot.active {
		slot.mu.Unlock()
		return errnoEINVAL
	}
	// Copy channel ref while holding lock to avoid race with FreeCallback.
	ch := slot.invoked
	slot.mu.Unlock()

	if ch == nil {
		return errnoEINVAL
	}

	select {
	case args := <-ch:
		nargs := len(args)
		if !writeInt32(mod, nargsPtr, int32(nargs)) {
			return errnoEFAULT
		}
		if nargs > 0 && argsCap > 0 {
			n := nargs
			if n > int(argsCap) {
				n = int(argsCap)
			}
			argsBuf := make([]byte, n*8)
			for i := 0; i < n; i++ {
				v := args[i]
				off := i * 8
				argsBuf[off] = byte(v)
				argsBuf[off+1] = byte(v >> 8)
				argsBuf[off+2] = byte(v >> 16)
				argsBuf[off+3] = byte(v >> 24)
				argsBuf[off+4] = byte(v >> 32)
				argsBuf[off+5] = byte(v >> 40)
				argsBuf[off+6] = byte(v >> 48)
				argsBuf[off+7] = byte(v >> 56)
			}
			if !writeBytes(mod, argsPtr, argsBuf) {
				return errnoEFAULT
			}
		}
		return errnoSuccess
	default:
		return errnoYIELD
	}
}

// darwinCallbackReturn sends the return value back to the native trampoline.
func darwinCallbackReturn(ctx context.Context, mod api.Module, id uint32, result uint64) uint32 {
	if int(id) >= maxCallbackSlots {
		return errnoEINVAL
	}
	slot := &callbackSlots[id]
	slot.mu.Lock()
	if !slot.active {
		slot.mu.Unlock()
		return errnoEINVAL
	}
	ch := slot.result
	slot.mu.Unlock()

	if ch == nil {
		return errnoEINVAL
	}
	ch <- uintptr(result)
	return errnoSuccess
}

// darwinCallbackFree releases a callback slot and drains its channels.
func darwinCallbackFree(ctx context.Context, mod api.Module, id uint32) uint32 {
	if int(id) >= maxCallbackSlots {
		return errnoEINVAL
	}
	slot := &callbackSlots[id]
	slot.mu.Lock()
	slot.active = false
	slot.nativeAddr = 0
	// Drain channels to unblock any waiting trampoline goroutine.
	inv := slot.invoked
	res := slot.result
	slot.invoked = nil
	slot.result = nil
	slot.mu.Unlock()

	if inv != nil {
		select {
		case <-inv:
		default:
		}
	}
	if res != nil {
		select {
		case res <- 0: // unblock trampoline waiting for result
		default:
		}
	}
	return errnoSuccess
}

// darwinReadCString reads a null-terminated C string from host memory.
func darwinReadCString(ctx context.Context, mod api.Module, hostAddrPtr, bufPtr, bufLen, actualLenPtr uint32) uint32 {
	addrBytes, ok := readBytes(mod, hostAddrPtr, 8)
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

	if hostAddr == 0 {
		if !writeInt32(mod, actualLenPtr, 0) {
			return errnoEFAULT
		}
		return errnoSuccess
	}

	// Read from host memory using the approved single-expression pattern.
	base := (*[1 << 30]byte)(unsafe.Pointer(hostAddr))
	maxLen := int(bufLen)
	if maxLen > 65536 {
		maxLen = 65536
	}
	var length int
	for length = 0; length < maxLen; length++ {
		if base[length] == 0 {
			break
		}
	}

	if !writeInt32(mod, actualLenPtr, int32(length)) {
		return errnoEFAULT
	}

	if length > 0 && bufLen > 0 {
		n := length
		if n > int(bufLen) {
			n = int(bufLen)
		}
		data := make([]byte, n)
		copy(data, base[:n])
		if !writeBytes(mod, bufPtr, data) {
			return errnoEFAULT
		}
	}

	return errnoSuccess
}

// ---------- ObjC Block construction (host-side) ----------
//
// Blocks must be constructed in HOST memory because ObjC's _Block_copy
// dereferences pointers inside the layout struct (isa, descriptor).
// If the layout lives in WASM memory, the translated top-level pointer works
// but embedded pointers (descriptor) remain WASM addresses → crash.

type hostBlockLayout struct {
	isa        uintptr
	flags      uint32
	_          uint32
	invoke     uintptr
	descriptor *hostBlockDescriptor
}

type hostBlockDescriptor struct {
	_         uintptr
	size      uintptr
	_copy     uintptr
	dispose   uintptr
	signature *byte
}

var blockHandles struct {
	mu      sync.Mutex
	next    int32
	entries map[int32]uintptr
}

func init() {
	blockHandles.next = 1
	blockHandles.entries = make(map[int32]uintptr)
}

var (
	objcGetClassFn uintptr
	blockCopyFn    uintptr
	blockReleaseFn uintptr
	blockFnsOnce   sync.Once
)

func resolveBlockFns() {
	blockFnsOnce.Do(func() {
		libobjc, err := nativeDlopen("/usr/lib/libobjc.A.dylib")
		if err != nil {
			return
		}
		objcGetClassFn, _ = nativeDlsym(libobjc, "objc_getClass")
		blockCopyFn, _ = nativeDlsym(libobjc, "_Block_copy")
		blockReleaseFn, _ = nativeDlsym(libobjc, "_Block_release")
	})
}

// darwinBlockCreate constructs an ObjC block entirely on the HOST side.
func darwinBlockCreate(ctx context.Context, mod api.Module, cbID uint32, sigPtr, sigLen, blockIDPtr uint32) uint32 {
	resolveBlockFns()
	if objcGetClassFn == 0 || blockCopyFn == 0 {
		return errnoENOSYS
	}

	if int(cbID) >= maxCallbackSlots {
		return errnoEINVAL
	}
	slot := &callbackSlots[cbID]
	slot.mu.Lock()
	if !slot.active {
		slot.mu.Unlock()
		return errnoEINVAL
	}
	invokeAddr := slot.nativeAddr
	slot.mu.Unlock()

	var sigBytes []byte
	if sigLen > 0 {
		var ok bool
		sigBytes, ok = readBytes(mod, sigPtr, sigLen)
		if !ok {
			return errnoEFAULT
		}
		if len(sigBytes) == 0 || sigBytes[len(sigBytes)-1] != 0 {
			sigBytes = append(sigBytes, 0)
		}
	}

	className := []byte("__NSMallocBlock__\x00")
	isaClass := ccall9(objcGetClassFn, uintptr(unsafe.Pointer(&className[0])), 0, 0, 0, 0, 0, 0, 0, 0)
	if isaClass == 0 {
		return errnoEINVAL
	}

	desc := &hostBlockDescriptor{
		size: unsafe.Sizeof(hostBlockLayout{}),
	}
	if len(sigBytes) > 0 {
		desc.signature = &sigBytes[0]
	}

	const blockHasCopyDispose = 1 << 25
	const blockHasSignature = 1 << 30
	layout := &hostBlockLayout{
		isa:        isaClass,
		flags:      blockHasCopyDispose | blockHasSignature,
		invoke:     invokeAddr,
		descriptor: desc,
	}

	blockPtr := ccall9(blockCopyFn, uintptr(unsafe.Pointer(layout)), 0, 0, 0, 0, 0, 0, 0, 0)
	if blockPtr == 0 {
		return errnoEINVAL
	}

	blockHandles.mu.Lock()
	id := blockHandles.next
	blockHandles.next++
	blockHandles.entries[id] = blockPtr
	blockHandles.mu.Unlock()

	if !writeInt32(mod, blockIDPtr, id) {
		return errnoEFAULT
	}

	if darwinVerbose(ctx) {
		fmt.Fprintf(os.Stderr, "[runtime] darwin_block_create: cb=%d block_id=%d ptr=%#x\n", cbID, id, blockPtr)
	}
	return errnoSuccess
}

// darwinBlockRelease releases an ObjC block.
func darwinBlockRelease(ctx context.Context, mod api.Module, blockID uint32) uint32 {
	resolveBlockFns()
	if blockReleaseFn == 0 {
		return errnoENOSYS
	}

	blockHandles.mu.Lock()
	ptr, ok := blockHandles.entries[int32(blockID)]
	if !ok {
		blockHandles.mu.Unlock()
		return errnoEINVAL
	}
	delete(blockHandles.entries, int32(blockID))
	blockHandles.mu.Unlock()

	ccall9(blockReleaseFn, ptr, 0, 0, 0, 0, 0, 0, 0, 0)
	return errnoSuccess
}

// darwinBlockAddr returns the host pointer for a block.
func darwinBlockAddr(ctx context.Context, mod api.Module, blockID uint32, addrPtr uint32) uint32 {
	blockHandles.mu.Lock()
	ptr, ok := blockHandles.entries[int32(blockID)]
	blockHandles.mu.Unlock()
	if !ok {
		return errnoEINVAL
	}

	addrBuf := make([]byte, 8)
	addrBuf[0] = byte(ptr)
	addrBuf[1] = byte(ptr >> 8)
	addrBuf[2] = byte(ptr >> 16)
	addrBuf[3] = byte(ptr >> 24)
	addrBuf[4] = byte(ptr >> 32)
	addrBuf[5] = byte(ptr >> 40)
	addrBuf[6] = byte(ptr >> 48)
	addrBuf[7] = byte(ptr >> 56)
	if !writeBytes(mod, addrPtr, addrBuf) {
		return errnoEFAULT
	}
	return errnoSuccess
}
