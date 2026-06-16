//go:build !windows

package hostmod

// PatchAMSI is a no-op on non-Windows platforms.
func PatchAMSI() {}
