// Functions extracted from zsyscall.go to avoid redeclaration
// with memory_wasip1.go shadow implementations.

//go:build windows

package windows

import (
	"syscall"
	"unsafe"
)

func VirtualAlloc(address uintptr, size uintptr, alloctype uint32, protect uint32) (value uintptr, err error) {
	r0, _, e1 := syscall.SyscallN(procVirtualAlloc.Addr(), uintptr(address), uintptr(size), uintptr(alloctype), uintptr(protect))
	value = uintptr(r0)
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

func VirtualFree(address uintptr, size uintptr, freetype uint32) (err error) {
	r1, _, e1 := syscall.SyscallN(procVirtualFree.Addr(), uintptr(address), uintptr(size), uintptr(freetype))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func VirtualProtect(address uintptr, size uintptr, newprotect uint32, oldprotect *uint32) (err error) {
	r1, _, e1 := syscall.SyscallN(procVirtualProtect.Addr(), uintptr(address), uintptr(size), uintptr(newprotect), uintptr(unsafe.Pointer(oldprotect)))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

func VirtualQuery(address uintptr, buffer *MemoryBasicInformation, length uintptr) (err error) {
	r1, _, e1 := syscall.SyscallN(procVirtualQuery.Addr(), uintptr(address), uintptr(unsafe.Pointer(buffer)), uintptr(length))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}
