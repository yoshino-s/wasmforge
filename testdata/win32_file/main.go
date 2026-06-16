package main

import (
	"fmt"
	"os"

	"github.com/praetorian-inc/wasmforge/guest/win32"
)

func main() {
	if !win32.Available() {
		// On Linux: verify file functions return ENOSYS
		_, err := win32.CreateFile(`C:\test.tmp`, win32.GENERIC_WRITE, 0, win32.CREATE_ALWAYS, win32.FILE_ATTRIBUTE_NORMAL)
		if err == nil {
			fmt.Println("FAIL: CreateFile should fail on non-Windows")
			os.Exit(1)
		}
		fmt.Printf("PASS: CreateFile returned expected error: %v\n", err)

		_, err = win32.GetFileAttributes(`C:\Windows`)
		if err == nil {
			fmt.Println("FAIL: GetFileAttributes should fail on non-Windows")
			os.Exit(1)
		}
		fmt.Printf("PASS: GetFileAttributes returned expected error: %v\n", err)

		fmt.Println("PASS: Win32 file mechanism works (ENOSYS on non-Windows)")
		return
	}

	// On Windows: test real file operations.
	// Use C:\Temp directly — os.Getenv("TEMP") returns "/tmp" under WASI
	// (runtime override), which is not a valid Windows path for Win32 APIs.
	testPath := `C:\Temp\wasmforge-test.tmp`
	testData := []byte("Hello from WasmForge!")

	// Create and write
	fh, err := win32.CreateFile(testPath, win32.GENERIC_WRITE, 0, win32.CREATE_ALWAYS, win32.FILE_ATTRIBUTE_NORMAL)
	if err != nil {
		fmt.Printf("FAIL: CreateFile(write): %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: CreateFile(write) succeeded")

	n, err := win32.WriteFile(fh, testData)
	if err != nil {
		fmt.Printf("FAIL: WriteFile: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PASS: WriteFile wrote %d bytes\n", n)

	if err := win32.CloseHandle(fh); err != nil {
		fmt.Printf("FAIL: CloseHandle(write): %v\n", err)
		os.Exit(1)
	}

	// Read back
	fh, err = win32.CreateFile(testPath, win32.GENERIC_READ, win32.FILE_SHARE_READ, win32.OPEN_EXISTING, win32.FILE_ATTRIBUTE_NORMAL)
	if err != nil {
		fmt.Printf("FAIL: CreateFile(read): %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: CreateFile(read) succeeded")

	buf := make([]byte, 256)
	n, err = win32.ReadFile(fh, buf)
	if err != nil {
		fmt.Printf("FAIL: ReadFile: %v\n", err)
		os.Exit(1)
	}
	if string(buf[:n]) != string(testData) {
		fmt.Printf("FAIL: ReadFile data mismatch: got %q, want %q\n", string(buf[:n]), string(testData))
		os.Exit(1)
	}
	fmt.Printf("PASS: ReadFile got %d bytes: %q\n", n, string(buf[:n]))

	if err := win32.CloseHandle(fh); err != nil {
		fmt.Printf("FAIL: CloseHandle(read): %v\n", err)
		os.Exit(1)
	}

	// Check attributes
	attrs, err := win32.GetFileAttributes(testPath)
	if err != nil {
		fmt.Printf("FAIL: GetFileAttributes: %v\n", err)
		os.Exit(1)
	}
	if attrs == win32.INVALID_FILE_ATTRIBUTES {
		fmt.Println("FAIL: GetFileAttributes returned INVALID")
		os.Exit(1)
	}
	fmt.Printf("PASS: GetFileAttributes = 0x%X\n", attrs)
}
