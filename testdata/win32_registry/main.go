package main

import (
	"fmt"
	"os"

	"github.com/praetorian-inc/wasmforge/guest/win32"
)

func main() {
	if !win32.Available() {
		// On Linux: verify registry functions return ENOSYS
		_, err := win32.RegOpenKey(win32.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion`, win32.KEY_READ)
		if err == nil {
			fmt.Println("FAIL: RegOpenKey should fail on non-Windows")
			os.Exit(1)
		}
		fmt.Printf("PASS: RegOpenKey returned expected error: %v\n", err)
		fmt.Println("PASS: Win32 registry mechanism works (ENOSYS on non-Windows)")
		return
	}

	// On Windows: test real registry access
	key, err := win32.RegOpenKey(win32.HKEY_LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion`, win32.KEY_READ)
	if err != nil {
		fmt.Printf("FAIL: RegOpenKey: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: RegOpenKey succeeded")

	val, err := win32.RegQueryString(key, "ProgramFilesDir")
	if err != nil {
		fmt.Printf("FAIL: RegQueryString(ProgramFilesDir): %v\n", err)
		os.Exit(1)
	}
	if val == "" {
		fmt.Println("FAIL: ProgramFilesDir is empty")
		os.Exit(1)
	}
	fmt.Printf("PASS: ProgramFilesDir = %q\n", val)

	keys, err := win32.RegEnumKeys(key)
	if err != nil {
		fmt.Printf("FAIL: RegEnumKeys: %v\n", err)
		os.Exit(1)
	}
	if len(keys) == 0 {
		fmt.Println("FAIL: RegEnumKeys returned 0 subkeys")
		os.Exit(1)
	}
	fmt.Printf("PASS: RegEnumKeys returned %d subkeys\n", len(keys))

	if err := win32.RegCloseKey(key); err != nil {
		fmt.Printf("FAIL: RegCloseKey: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: RegCloseKey succeeded")
}
