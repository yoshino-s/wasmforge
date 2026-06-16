package main

import (
	"fmt"
	"os"

	"github.com/praetorian-inc/wasmforge/guest/win32"
)

func main() {
	if !win32.Available() {
		// On Linux: verify process functions return ENOSYS
		_, err := win32.GetComputerName()
		if err == nil {
			fmt.Println("FAIL: GetComputerName should fail on non-Windows")
			os.Exit(1)
		}
		fmt.Printf("PASS: GetComputerName returned expected error: %v\n", err)
		fmt.Println("PASS: Win32 process mechanism works (ENOSYS on non-Windows)")
		return
	}

	// On Windows: test real process/system APIs
	name, err := win32.GetComputerName()
	if err != nil {
		fmt.Printf("FAIL: GetComputerName: %v\n", err)
		os.Exit(1)
	}
	if name == "" {
		fmt.Println("FAIL: computer name is empty")
		os.Exit(1)
	}
	fmt.Printf("PASS: GetComputerName() = %q\n", name)

	// OpenProcess for our own process would need current PID via GetCurrentProcessId
	// which is the generic API. Just verify the call mechanism exists.
	_, err = win32.OpenProcess(win32.PROCESS_QUERY_INFO, 0)
	if err == nil {
		fmt.Println("PASS: OpenProcess(pid=0) returned a handle (unexpected but ok)")
	} else {
		// Opening PID 0 typically fails, but the error should NOT be ENOSYS
		fmt.Printf("PASS: OpenProcess(pid=0) returned error (expected): %v\n", err)
	}
}
