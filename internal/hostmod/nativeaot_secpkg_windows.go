//go:build nativeaot && windows

package hostmod

import (
	"context"
	"syscall"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
)

func osEnumSecPackages(_ context.Context, mod api.Module, stack []uint64) {
	bufPtr := uint32(stack[0])
	bufCap := uint32(stack[1])
	countPtr := uint32(stack[2])

	secur32, err := syscall.LoadDLL("secur32.dll")
	if err != nil {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}
	defer secur32.Release()

	enumProc, err := secur32.FindProc("EnumerateSecurityPackagesW")
	if err != nil {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}
	freeProc, err := secur32.FindProc("FreeContextBuffer")
	if err != nil {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}

	var pkgCount uint32
	var pkgInfo uintptr
	r1, _, _ := enumProc.Call(
		uintptr(unsafe.Pointer(&pkgCount)),
		uintptr(unsafe.Pointer(&pkgInfo)),
	)
	if r1 != 0 || pkgInfo == 0 {
		writeUint32(mod, countPtr, 0)
		stack[0] = 0
		return
	}
	defer freeProc.Call(pkgInfo)

	// SecPkgInfoW x64 layout (32 bytes per entry):
	//   offset  0: fCapabilities uint32
	//   offset  4: wVersion      uint16
	//   offset  6: wRPCID        uint16
	//   offset  8: cbMaxToken    uint32
	//   offset 12: padding       [4]byte
	//   offset 16: pName         *uint16  (LPWSTR)
	//   offset 24: pComment      *uint16  (LPWSTR)
	const secPkgInfoWSize = 32

	var buf []byte
	count := uint32(0)
	for i := uint32(0); i < pkgCount; i++ {
		entry := pkgInfo + uintptr(i)*secPkgInfoWSize
		pName := *(**uint16)(unsafe.Pointer(entry + 16))
		if pName == nil {
			continue
		}
		// Decode UTF-16 LE NUL-terminated string.
		n := 0
		for {
			c := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(pName)) + uintptr(n)*2))
			if c == 0 {
				break
			}
			n++
			if n > 256 {
				break
			}
		}
		u16 := unsafe.Slice(pName, n)
		name := string(utf16Decode(u16))
		if name == "" {
			continue
		}
		nameBytes := []byte(name)
		if uint32(len(buf)+len(nameBytes)+1) > bufCap {
			break
		}
		buf = append(buf, nameBytes...)
		buf = append(buf, 0)
		count++
	}

	if len(buf) > 0 {
		writeBytes(mod, bufPtr, buf)
	}
	writeUint32(mod, countPtr, count)
	stack[0] = uint64(len(buf))
}
