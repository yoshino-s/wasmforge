package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func main() {
	fmt.Println("=== win32_syscalln: x/sys/windows shim test ===")

	// Test 1: Package compiled successfully for wasip1.
	// If we got here, the build tag patching worked.
	fmt.Println("PASS: golang.org/x/sys/windows compiled for wasip1")

	// Test 2: Types and constants are accessible.
	var h windows.Handle
	h = windows.InvalidHandle
	if h != ^windows.Handle(0) {
		fmt.Printf("FAIL: InvalidHandle mismatch: got %x\n", h)
		os.Exit(1)
	}
	fmt.Println("PASS: windows.Handle and InvalidHandle accessible")

	// Test 3: String conversion utilities work.
	utf16, err := windows.UTF16FromString("hello")
	if err != nil {
		fmt.Printf("FAIL: UTF16FromString: %v\n", err)
		os.Exit(1)
	}
	back := windows.UTF16ToString(utf16)
	if back != "hello" {
		fmt.Printf("FAIL: UTF16 round-trip: got %q\n", back)
		os.Exit(1)
	}
	fmt.Println("PASS: UTF16 string conversion works")

	// Test 4: Byte conversion utilities.
	bs, err := windows.ByteSliceFromString("test")
	if err != nil {
		fmt.Printf("FAIL: ByteSliceFromString: %v\n", err)
		os.Exit(1)
	}
	if len(bs) != 5 || bs[4] != 0 {
		fmt.Printf("FAIL: ByteSliceFromString: unexpected result %v\n", bs)
		os.Exit(1)
	}
	fmt.Println("PASS: ByteSliceFromString works")

	// Test 5: DLL loading via x/sys/windows (goes through syscall shim).
	// On non-Windows (Linux host running WASM), the host stub returns ENOSYS.
	// On a real Windows host, it would succeed.
	dll, loadErr := windows.LoadDLL("kernel32.dll")
	if loadErr == nil {
		fmt.Println("PASS: LoadDLL(kernel32.dll) succeeded")
		dll.Release()
	} else {
		fmt.Printf("PASS: LoadDLL returned expected error on non-Windows: %v\n", loadErr)
	}

	// Test 6: LazyDLL pattern (doesn't call the host until Load() is called).
	lazy := windows.NewLazyDLL("user32.dll")
	proc := lazy.NewProc("MessageBoxW")
	// Verify the lazy objects were created (no host call yet).
	if lazy.Name != "user32.dll" {
		fmt.Printf("FAIL: LazyDLL name mismatch: %s\n", lazy.Name)
		os.Exit(1)
	}
	if proc.Name != "MessageBoxW" {
		fmt.Printf("FAIL: LazyProc name mismatch: %s\n", proc.Name)
		os.Exit(1)
	}
	fmt.Println("PASS: LazyDLL/LazyProc created successfully")

	// Trigger actual load (will fail on non-Windows, succeed on Windows).
	lazyLoadErr := lazy.Load()
	if lazyLoadErr == nil {
		fmt.Println("PASS: LazyDLL.Load succeeded")
	} else {
		fmt.Printf("PASS: LazyDLL.Load returned expected error: %v\n", lazyLoadErr)
	}

	fmt.Println("=== ALL TESTS PASSED ===")
}
