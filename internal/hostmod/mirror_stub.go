//go:build !windows

package hostmod

// mirrorReadHost is a no-op on non-Windows platforms.
// Host pointer mirroring is only needed for Win32 API interop.
func mirrorReadHost(addr uintptr, size uint32) []byte {
	return nil
}

// mirrorWriteHost is a no-op on non-Windows platforms.
func mirrorWriteHost(addr uintptr, data []byte) {}

// mirrorRegionSize returns 0 on non-Windows platforms.
func mirrorRegionSize(addr uintptr) uint32 {
	return 0
}

// mirrorShouldMirror returns false on non-Windows platforms.
// Host pointer mirroring classification requires VirtualQuery.
func mirrorShouldMirror(addr uintptr) bool {
	return false
}

// mirrorIsCodeRegion returns false on non-Windows platforms.
func mirrorIsCodeRegion(addr uintptr) bool {
	return false
}
