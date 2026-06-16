//go:build nativeaot && windows

package hostmod

import (
	"context"
	"syscall"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
)

// osEnumPrinters enumerates installed printers via winspool.EnumPrintersW
// from the host side and writes printer names NUL-separated into a WASM
// buffer.
//
// Guest ABI:
//
//	stack[0] in/out: buf_ptr in, bytes_written out
//	stack[1] in:     buf_cap
//	stack[2] in:     count_ptr — WASM ptr to uint32 receiving entry count
//
// Replaces PrintersCommand's EnumPrinters P/Invoke path that crashed
// the bridge on the PRINTER_INFO struct marshaling.
func osEnumPrinters(_ context.Context, mod api.Module, stack []uint64) {
	bufPtr := uint32(stack[0])
	bufCap := uint32(stack[1])
	countPtr := uint32(stack[2])

	winspool, err := syscall.LoadDLL("winspool.drv")
	if err != nil {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}
	defer winspool.Release()
	enum, err := winspool.FindProc("EnumPrintersW")
	if err != nil {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}

	// First call: sizing. dwFlags=PRINTER_ENUM_LOCAL|PRINTER_ENUM_CONNECTIONS,
	// Level=4 (returns minimal PRINTER_INFO_4: pPrinterName, pServerName, attrs).
	const dwFlags = uintptr(0x02 | 0x04) // LOCAL|CONNECTIONS
	const level = uintptr(4)
	var needed, returned uint32
	enum.Call(dwFlags, 0, level, 0, 0,
		uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&returned)))
	if needed == 0 {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}

	heap := make([]byte, needed)
	heapPtr := unsafe.Pointer(&heap[0])
	r1, _, _ := enum.Call(dwFlags, 0, level,
		uintptr(heapPtr), uintptr(needed),
		uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&returned)))
	if r1 == 0 || returned == 0 {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}

	// PRINTER_INFO_4 = { pPrinterName, pServerName, Attributes } — 24 bytes on x64.
	const piSize = 24
	var buf []byte
	count := uint32(0)
	for i := uint32(0); i < returned; i++ {
		off := uintptr(i) * piSize
		pName := *(**uint16)(unsafe.Pointer(uintptr(heapPtr) + off))
		if pName == nil {
			continue
		}
		name := utf16PtrToString(pName)
		entry := []byte(name)
		if uint32(len(buf)+len(entry)+1) > bufCap {
			break
		}
		buf = append(buf, entry...)
		buf = append(buf, 0)
		count++
	}

	if len(buf) > 0 {
		writeBytes(mod, bufPtr, buf)
	}
	writeUint32(mod, countPtr, count)
	stack[0] = uint64(len(buf))
}

// utf16PtrToString reads a null-terminated UTF-16 string from a host
// pointer and returns its UTF-8 representation.
func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	n := 0
	for {
		c := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(n)*2))
		if c == 0 {
			break
		}
		n++
		if n > 4096 {
			break
		}
	}
	u16 := unsafe.Slice(p, n)
	return string(utf16Decode(u16))
}
