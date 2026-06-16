package main

import (
	"fmt"
	"os"

	"github.com/praetorian-inc/wasmforge/guest/win32"
)

func main() {
	avail := win32.Available()
	fmt.Printf("PASS: win32.Available() = %v\n", avail)

	if !avail {
		// On Linux: verify mechanism exists and returns ENOSYS
		_, err := win32.LoadLibrary("kernel32.dll")
		if err == nil {
			fmt.Println("FAIL: LoadLibrary should fail on non-Windows")
			os.Exit(1)
		}
		fmt.Printf("PASS: LoadLibrary returned expected error: %v\n", err)
		fmt.Println("PASS: Win32 interop mechanism works (ENOSYS on non-Windows)")
		return
	}

	// On Windows: test real DLL loading
	lib, err := win32.LoadLibrary("kernel32.dll")
	if err != nil {
		fmt.Printf("FAIL: LoadLibrary(kernel32.dll): %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: LoadLibrary(kernel32.dll) succeeded")

	proc, err := lib.GetProcAddress("GetCurrentProcessId")
	if err != nil {
		fmt.Printf("FAIL: GetProcAddress(GetCurrentProcessId): %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: GetProcAddress(GetCurrentProcessId) succeeded")

	pid, err := proc.Call()
	if err != nil {
		fmt.Printf("FAIL: Call(): %v\n", err)
		os.Exit(1)
	}
	if pid == 0 {
		fmt.Println("FAIL: GetCurrentProcessId returned 0")
		os.Exit(1)
	}
	fmt.Printf("PASS: GetCurrentProcessId() = %d\n", pid)

	if err := lib.Free(); err != nil {
		fmt.Printf("FAIL: FreeLibrary: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: FreeLibrary succeeded")
}
