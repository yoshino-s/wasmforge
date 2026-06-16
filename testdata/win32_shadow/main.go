// Shadow memory end-to-end test.
// Verifies that VirtualAlloc returns a usable uintptr within WASM linear memory,
// that direct unsafe.Pointer reads/writes work, and that VirtualProtect/Free sync correctly.

package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	testBasicAllocAndPointer()
	testMultipleAllocs()
	testVirtualProtect()
	testVirtualFree()

	fmt.Println("PASS: All shadow memory tests passed")
}

// testBasicAllocAndPointer verifies that VirtualAlloc returns a usable uintptr
// and that unsafe.Pointer reads/writes work on the WASM-side copy.
func testBasicAllocAndPointer() {
	addr, err := windows.VirtualAlloc(0, 4096,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		fmt.Printf("FAIL: VirtualAlloc: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PASS: VirtualAlloc returned addr=0x%X\n", addr)

	if addr == 0 {
		fmt.Println("FAIL: VirtualAlloc returned nil address")
		os.Exit(1)
	}

	// Write via unsafe.Pointer (direct WASM memory access).
	ptr := unsafe.Pointer(addr)
	*(*uint32)(ptr) = 0xDEADBEEF
	fmt.Println("PASS: Wrote 0xDEADBEEF via unsafe.Pointer")

	// Read back via unsafe.Pointer.
	got := *(*uint32)(ptr)
	if got != 0xDEADBEEF {
		fmt.Printf("FAIL: Read back 0x%08X, want 0xDEADBEEF\n", got)
		os.Exit(1)
	}
	fmt.Println("PASS: Read back 0xDEADBEEF via unsafe.Pointer")

	// Write a byte pattern.
	slice := unsafe.Slice((*byte)(ptr), 4096)
	for i := 0; i < 256; i++ {
		slice[i] = byte(i)
	}
	fmt.Println("PASS: Wrote 256-byte pattern via unsafe.Slice")

	// Verify the pattern.
	for i := 0; i < 256; i++ {
		if slice[i] != byte(i) {
			fmt.Printf("FAIL: slice[%d] = %d, want %d\n", i, slice[i], i)
			os.Exit(1)
		}
	}
	fmt.Println("PASS: Verified 256-byte pattern")

	// Write at an offset.
	*(*uint64)(unsafe.Pointer(addr + 512)) = 0x0123456789ABCDEF
	got64 := *(*uint64)(unsafe.Pointer(addr + 512))
	if got64 != 0x0123456789ABCDEF {
		fmt.Printf("FAIL: uint64 at offset 512: got 0x%016X, want 0x0123456789ABCDEF\n", got64)
		os.Exit(1)
	}
	fmt.Println("PASS: uint64 write/read at offset 512")

	if err := windows.VirtualFree(addr, 0, windows.MEM_RELEASE); err != nil {
		fmt.Printf("FAIL: VirtualFree: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: VirtualFree succeeded")
}

// testMultipleAllocs verifies that multiple shadow allocations coexist.
func testMultipleAllocs() {
	addr1, err := windows.VirtualAlloc(0, 4096,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		fmt.Printf("FAIL: VirtualAlloc #1: %v\n", err)
		os.Exit(1)
	}

	addr2, err := windows.VirtualAlloc(0, 8192,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		fmt.Printf("FAIL: VirtualAlloc #2: %v\n", err)
		os.Exit(1)
	}

	if addr1 == addr2 {
		fmt.Println("FAIL: Two allocations returned same address")
		os.Exit(1)
	}

	// Write different values to each.
	*(*uint32)(unsafe.Pointer(addr1)) = 0xAAAAAAAA
	*(*uint32)(unsafe.Pointer(addr2)) = 0xBBBBBBBB

	// Verify they don't interfere.
	if *(*uint32)(unsafe.Pointer(addr1)) != 0xAAAAAAAA {
		fmt.Println("FAIL: Alloc #1 corrupted by alloc #2")
		os.Exit(1)
	}
	if *(*uint32)(unsafe.Pointer(addr2)) != 0xBBBBBBBB {
		fmt.Println("FAIL: Alloc #2 corrupted by alloc #1")
		os.Exit(1)
	}
	fmt.Println("PASS: Multiple allocations are independent")

	if err := windows.VirtualFree(addr1, 0, windows.MEM_RELEASE); err != nil {
		fmt.Printf("FAIL: VirtualFree #1: %v\n", err)
		os.Exit(1)
	}
	if err := windows.VirtualFree(addr2, 0, windows.MEM_RELEASE); err != nil {
		fmt.Printf("FAIL: VirtualFree #2: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: Freed multiple allocations")
}

// testVirtualProtect verifies that VirtualProtect syncs data between copies.
func testVirtualProtect() {
	addr, err := windows.VirtualAlloc(0, 4096,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		fmt.Printf("FAIL: VirtualAlloc for protect test: %v\n", err)
		os.Exit(1)
	}
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)

	// Write data via unsafe.Pointer.
	*(*uint32)(unsafe.Pointer(addr)) = 0xCAFEBABE
	*(*uint32)(unsafe.Pointer(addr + 4)) = 0x12345678

	// VirtualProtect should sync WASM→Host, change protection, then sync Host→WASM.
	var oldProtect uint32
	err = windows.VirtualProtect(addr, 4096, windows.PAGE_READONLY, &oldProtect)
	if err != nil {
		fmt.Printf("FAIL: VirtualProtect(READONLY): %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PASS: VirtualProtect returned old protect=0x%X\n", oldProtect)

	// After VirtualProtect, data should still be readable in WASM memory.
	got1 := *(*uint32)(unsafe.Pointer(addr))
	got2 := *(*uint32)(unsafe.Pointer(addr + 4))
	if got1 != 0xCAFEBABE {
		fmt.Printf("FAIL: After VirtualProtect, got 0x%08X want 0xCAFEBABE\n", got1)
		os.Exit(1)
	}
	if got2 != 0x12345678 {
		fmt.Printf("FAIL: After VirtualProtect, got 0x%08X want 0x12345678\n", got2)
		os.Exit(1)
	}
	fmt.Println("PASS: Data preserved after VirtualProtect")

	// Restore to RW.
	err = windows.VirtualProtect(addr, 4096, windows.PAGE_READWRITE, &oldProtect)
	if err != nil {
		fmt.Printf("FAIL: VirtualProtect(READWRITE): %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: VirtualProtect restore succeeded")
}

// testVirtualFree verifies that VirtualFree works correctly.
func testVirtualFree() {
	addr, err := windows.VirtualAlloc(0, 4096,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		fmt.Printf("FAIL: VirtualAlloc for free test: %v\n", err)
		os.Exit(1)
	}

	// Write some data.
	*(*uint32)(unsafe.Pointer(addr)) = 0x11111111

	// Free it.
	err = windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	if err != nil {
		fmt.Printf("FAIL: VirtualFree: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: VirtualFree succeeded")
}
