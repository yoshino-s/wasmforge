// Package win32 provides Win32 API access for Go programs compiled with wasmforge.
//
// This package uses go:wasmimport to call wasmforge host functions for Win32
// operations. Win32 APIs require the --win32-apis flag when building with wasmforge
// and are only available when running on a Windows host.
//
// On non-Windows hosts, Available() returns false and all API calls return ErrNotAvailable.
//
// Example usage:
//
//	if !win32.Available() {
//	    log.Fatal("Win32 APIs not available")
//	}
//
//	key, err := win32.RegOpenKey(win32.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion`, win32.KEY_READ)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer win32.RegCloseKey(key)
//
//	val, err := win32.RegQueryString(key, "ProgramFilesDir")
package win32
