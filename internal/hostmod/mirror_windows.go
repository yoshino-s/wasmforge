//go:build windows

package hostmod

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// mirrorReadHost reads size bytes from a host memory address.
// Returns nil if the memory is not accessible.
func mirrorReadHost(addr uintptr, size uint32) []byte {
	if addr == 0 || size == 0 {
		return nil
	}

	// Verify the ENTIRE range [addr, addr+size) is committed.
	// VirtualQuery only reports on the region containing the queried address,
	// so we must check both the start and end of the read range.
	var mbi windows.MemoryBasicInformation
	if err := windows.VirtualQuery(addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
		return nil
	}
	if mbi.State != windows.MEM_COMMIT {
		return nil
	}
	// Reject guard pages and no-access pages — reading would fault.
	const pageGuard = 0x100
	const pageNoAccess = 0x01
	if mbi.Protect&pageGuard != 0 || mbi.Protect == pageNoAccess {
		return nil
	}
	// Clamp size to the committed region to avoid reading past its end.
	regionEnd := mbi.BaseAddress + uintptr(mbi.RegionSize)
	if addr+uintptr(size) > regionEnd {
		size = uint32(regionEnd - addr)
		if size == 0 {
			return nil
		}
	}

	// Copy the data.
	src := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)
	dst := make([]byte, size)
	copy(dst, src)
	return dst
}

// mirrorWriteHost writes data to a host memory address.
func mirrorWriteHost(addr uintptr, data []byte) {
	if addr == 0 || len(data) == 0 {
		return
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))
	copy(dst, data)
}

// Memory type constant from Windows API (not exported by golang.org/x/sys/windows).
const memImage = 0x1000000 // MEM_IMAGE: loaded DLL/EXE region

// mirrorShouldMirror returns true if the host address points to committed
// non-image memory that should be mirrored into WASM. Returns false for
// loaded DLL/EXE regions (MEM_IMAGE), uncommitted memory, and invalid addresses.
func mirrorShouldMirror(addr uintptr) bool {
	var mbi windows.MemoryBasicInformation
	if err := windows.VirtualQuery(addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
		return false
	}
	if mbi.State != windows.MEM_COMMIT {
		return false
	}
	// MEM_IMAGE = loaded DLL/EXE. These are opaque module handles (HMODULE),
	// not data the guest should dereference. Mirroring them corrupts handles.
	if mbi.Type == memImage {
		return false
	}
	return true
}

// mirrorIsCodeRegion returns true if the host address is in executable memory
// (PAGE_EXECUTE*). Executable code regions should be mirrored (for reverse
// translation of function pointers in Step 0) but NOT recursively scanned
// for more host pointers — x86 instructions contain address-like values
// that cause exponential scanning blowup.
//
// This uses page protection rather than MEM_IMAGE type because MEM_IMAGE
// covers the entire DLL including read-only data sections (.rdata) where
// COM vtables live. Vtable data (PAGE_READONLY) must be recursed into to
// replace function pointers with mirror addresses. Function code
// (PAGE_EXECUTE_READ) must not.
func mirrorIsCodeRegion(addr uintptr) bool {
	if addr == 0 {
		return false
	}
	var mbi windows.MemoryBasicInformation
	if err := windows.VirtualQuery(addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
		return false
	}
	// PAGE_EXECUTE flags:
	//   0x10 = PAGE_EXECUTE
	//   0x20 = PAGE_EXECUTE_READ
	//   0x40 = PAGE_EXECUTE_READWRITE
	//   0x80 = PAGE_EXECUTE_WRITECOPY
	return mbi.Protect&0xF0 != 0
}

// mirrorRegionSize returns the size of the committed memory region at addr
// using VirtualQuery. Returns 0 if the query fails.
func mirrorRegionSize(addr uintptr) uint32 {
	if addr == 0 {
		return 0
	}

	var mbi windows.MemoryBasicInformation
	if err := windows.VirtualQuery(addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
		return 0
	}

	if mbi.State != windows.MEM_COMMIT {
		return 0
	}

	// The region size is from addr to the end of the committed region.
	regionEnd := mbi.BaseAddress + uintptr(mbi.RegionSize)
	if addr >= regionEnd {
		return 0
	}
	size := uint32(regionEnd - addr)

	// Cap at a reasonable size for mirroring.
	if size > 65536 {
		size = 65536
	}
	return size
}
