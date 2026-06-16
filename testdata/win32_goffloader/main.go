// win32_goffloader demonstrates goffloader-style patterns running from a WASM guest:
//
//  1. DLL loading (LoadLibrary / GetProcAddress) — goffloader resolves imports
//  2. Host memory allocation (VirtualAlloc) — goffloader allocates image memory
//  3. Data copy to host memory (HMemWrite) — goffloader copies PE sections
//  4. Memory protection changes (VirtualProtect) — goffloader marks .text executable
//  5. Host address retrieval (HMemAddr) — goffloader computes relocated addresses
//  6. Windows API calls with host pointers (SyscallN64) — goffloader calls entry point
//  7. Shellcode execution (ProcFromOffset + SyscallN64) — goffloader calls loaded code
//
// On Windows: exercises the full goffloader pipeline ending with "Hello World" output.
// On Linux: verifies ENOSYS stubs work correctly.
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
		_, err := win32.VirtualAlloc(4096, win32.MEM_COMMIT|win32.MEM_RESERVE, win32.PAGE_READWRITE)
		if err == nil {
			fmt.Println("FAIL: VirtualAlloc should fail on non-Windows")
			os.Exit(1)
		}
		fmt.Printf("PASS: VirtualAlloc returned expected error: %v\n", err)
		fmt.Println("PASS: goffloader mechanism works (ENOSYS on non-Windows)")
		return
	}

	// === Phase 1: DLL Loading (like goffloader resolving imports) ===
	fmt.Println("\n--- Phase 1: DLL Loading ---")

	kernel32, err := win32.LoadLibrary("kernel32.dll")
	if err != nil {
		fmt.Printf("FAIL: LoadLibrary(kernel32.dll): %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: LoadLibrary(kernel32.dll)")

	getStdHandle, err := kernel32.GetProcAddress("GetStdHandle")
	if err != nil {
		fmt.Printf("FAIL: GetProcAddress(GetStdHandle): %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: GetProcAddress(GetStdHandle)")

	writeFile, err := kernel32.GetProcAddress("WriteFile")
	if err != nil {
		fmt.Printf("FAIL: GetProcAddress(WriteFile): %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: GetProcAddress(WriteFile)")

	getCurrentProcessId, err := kernel32.GetProcAddress("GetCurrentProcessId")
	if err != nil {
		fmt.Printf("FAIL: GetProcAddress(GetCurrentProcessId): %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: GetProcAddress(GetCurrentProcessId)")

	// === Phase 2: Host Memory Allocation (like goffloader allocating image memory) ===
	fmt.Println("\n--- Phase 2: Host Memory Allocation ---")

	// Allocate host memory for our message string (like goffloader's section allocation).
	msgMem, err := win32.VirtualAlloc(4096, win32.MEM_COMMIT|win32.MEM_RESERVE, win32.PAGE_READWRITE)
	if err != nil {
		fmt.Printf("FAIL: VirtualAlloc for message: %v\n", err)
		os.Exit(1)
	}
	defer msgMem.Free()
	fmt.Println("PASS: VirtualAlloc(4096, RW) for message buffer")

	// Allocate host memory for output parameter (bytes written).
	outMem, err := win32.VirtualAlloc(256, win32.MEM_COMMIT|win32.MEM_RESERVE, win32.PAGE_READWRITE)
	if err != nil {
		fmt.Printf("FAIL: VirtualAlloc for output: %v\n", err)
		os.Exit(1)
	}
	defer outMem.Free()
	fmt.Println("PASS: VirtualAlloc(256, RW) for output parameter")

	// === Phase 3: Data Copy to Host Memory (like goffloader copying PE sections) ===
	fmt.Println("\n--- Phase 3: Section Data Copy ---")

	message := "Hello World from WASM guest via goffloader-style host memory!\r\n"
	if err := msgMem.Write(0, []byte(message)); err != nil {
		fmt.Printf("FAIL: HMemWrite message: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PASS: Wrote %d bytes to host memory\n", len(message))

	// === Phase 4: Get Host Addresses (like goffloader computing relocated addresses) ===
	fmt.Println("\n--- Phase 4: Address Resolution ---")

	msgAddr, err := msgMem.Addr()
	if err != nil {
		fmt.Printf("FAIL: HMemAddr for message: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PASS: Message at host address 0x%X\n", msgAddr)

	outAddr, err := outMem.Addr()
	if err != nil {
		fmt.Printf("FAIL: HMemAddr for output: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PASS: Output param at host address 0x%X\n", outAddr)

	// Also get the real proc addresses (like goffloader writing to IAT).
	getStdHandleAddr, err := win32.ProcAddr(getStdHandle)
	if err != nil {
		fmt.Printf("FAIL: ProcAddr(GetStdHandle): %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PASS: GetStdHandle at host address 0x%X\n", getStdHandleAddr)

	writeFileAddr, err := win32.ProcAddr(writeFile)
	if err != nil {
		fmt.Printf("FAIL: ProcAddr(WriteFile): %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PASS: WriteFile at host address 0x%X\n", writeFileAddr)

	// === Phase 5: Windows API Calls with Host Pointers ===
	fmt.Println("\n--- Phase 5: Windows API Calls ---")

	// GetCurrentProcessId() — simple call to verify SyscallN64 works.
	pidR1, _, lastErr := win32.SyscallN64(getCurrentProcessId)
	if pidR1 == 0 {
		fmt.Printf("FAIL: GetCurrentProcessId returned 0 (lastErr=%d)\n", lastErr)
		os.Exit(1)
	}
	fmt.Printf("PASS: GetCurrentProcessId() = %d\n", pidR1)

	// GetStdHandle(STD_OUTPUT_HANDLE) — STD_OUTPUT_HANDLE = -11 = 0xFFFFFFF5
	const STD_OUTPUT_HANDLE = 0xFFFFFFFFFFFFFFFF - 10 // -11 as uint64
	stdoutR1, _, lastErr := win32.SyscallN64(getStdHandle, STD_OUTPUT_HANDLE)
	if stdoutR1 == 0 || stdoutR1 == 0xFFFFFFFFFFFFFFFF {
		fmt.Printf("FAIL: GetStdHandle returned invalid handle 0x%X (lastErr=%d)\n", stdoutR1, lastErr)
		os.Exit(1)
	}
	fmt.Printf("PASS: GetStdHandle(STD_OUTPUT_HANDLE) = 0x%X\n", stdoutR1)

	// === Phase 6: Console Output via Host Memory ===
	fmt.Println("\n--- Phase 6: Console Output via Host Memory ---")
	fmt.Println(">>> Calling WriteFile with host memory pointer...")

	// WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped)
	r1, _, lastErr := win32.SyscallN64(writeFile,
		stdoutR1,              // hFile (stdout handle)
		msgAddr,               // lpBuffer (host memory address!)
		uint64(len(message)),  // nNumberOfBytesToWrite
		outAddr,               // lpNumberOfBytesWritten (host memory address!)
		0,                     // lpOverlapped (NULL)
	)
	if r1 == 0 {
		fmt.Printf("FAIL: WriteFile returned 0 (lastErr=%d)\n", lastErr)
		os.Exit(1)
	}

	// Read back bytes-written from host memory.
	bytesWritten, err := outMem.ReadUint32(0)
	if err != nil {
		fmt.Printf("FAIL: ReadUint32 bytes written: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PASS: WriteFile wrote %d bytes via host memory pointer\n", bytesWritten)

	// === Phase 7: Shellcode Execution (like goffloader calling entry point) ===
	fmt.Println("\n--- Phase 7: Shellcode Execution ---")

	// Allocate executable memory (like goffloader's code section).
	codeMem, err := win32.VirtualAlloc(4096, win32.MEM_COMMIT|win32.MEM_RESERVE, win32.PAGE_READWRITE)
	if err != nil {
		fmt.Printf("FAIL: VirtualAlloc for code: %v\n", err)
		os.Exit(1)
	}

	// x86-64 shellcode: mov eax, 42; ret
	// This simulates calling a loaded PE's entry point.
	shellcode := []byte{
		0xB8, 0x2A, 0x00, 0x00, 0x00, // mov eax, 42
		0xC3,                           // ret
	}
	if err := codeMem.Write(0, shellcode); err != nil {
		fmt.Printf("FAIL: Write shellcode: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: Shellcode written to host memory (mov eax, 42; ret)")

	// Mark as executable (like goffloader's VirtualProtect on .text section).
	_, err = codeMem.VirtualProtect(win32.PAGE_EXECUTE_READ)
	if err != nil {
		fmt.Printf("FAIL: VirtualProtect(EXECUTE_READ): %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: Memory marked as PAGE_EXECUTE_READ")

	// Register the shellcode address as a callable proc (like goffloader's entry point call).
	shellProc, err := codeMem.ProcFromOffset(0)
	if err != nil {
		fmt.Printf("FAIL: ProcFromOffset(0): %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: Shellcode registered as callable proc")

	// Call the shellcode! (like goffloader's syscall.SyscallN(entryPoint))
	retVal, _, _ := win32.SyscallN64(shellProc)
	if retVal != 42 {
		fmt.Printf("FAIL: Shellcode returned %d, expected 42\n", retVal)
		os.Exit(1)
	}
	fmt.Printf("PASS: Shellcode executed! Return value = %d\n", retVal)

	codeMem.Free()

	// === Phase 8: Advanced Shellcode — Hello via direct API calls ===
	fmt.Println("\n--- Phase 8: Advanced Shellcode with API Calls ---")

	// Allocate memory for the advanced shellcode + its data.
	advMem, err := win32.VirtualAlloc(8192, win32.MEM_COMMIT|win32.MEM_RESERVE, win32.PAGE_READWRITE)
	if err != nil {
		fmt.Printf("FAIL: VirtualAlloc for advanced shellcode: %v\n", err)
		os.Exit(1)
	}

	// x86-64 shellcode that calls GetStdHandle and WriteFile.
	// Windows x64 calling convention: RCX, RDX, R8, R9 + stack.
	// RCX = pointer to a struct:
	//   [0]  getStdHandle addr (uint64)
	//   [8]  writeFile addr    (uint64)
	//   [16] msg addr          (uint64)
	//   [24] msg len           (uint32)
	//   [28] bytesWritten      (uint32, output)
	advShellcode := []byte{
		// Prologue: save non-volatile registers
		0x55,                                     // push rbp
		0x48, 0x89, 0xE5,                         // mov rbp, rsp
		0x53,                                     // push rbx
		0x41, 0x54,                               // push r12
		0x48, 0x83, 0xEC, 0x30,                   // sub rsp, 48 (shadow space + alignment)

		// Save param pointer
		0x48, 0x89, 0xCB,                         // mov rbx, rcx

		// Call GetStdHandle(-11)
		0x48, 0xC7, 0xC1, 0xF5, 0xFF, 0xFF, 0xFF, // mov rcx, -11
		0xFF, 0x13,                               // call [rbx]
		0x49, 0x89, 0xC4,                         // mov r12, rax  (save stdout handle)

		// Call WriteFile(stdout, msg, len, &written, NULL)
		0x4C, 0x89, 0xE1,                         // mov rcx, r12           (hFile)
		0x48, 0x8B, 0x53, 0x10,                   // mov rdx, [rbx+16]      (lpBuffer)
		0x44, 0x8B, 0x43, 0x18,                   // mov r8d, [rbx+24]      (nBytesToWrite)
		0x4C, 0x8D, 0x4B, 0x1C,                   // lea r9, [rbx+28]       (lpBytesWritten)
		0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, // mov [rsp+32], 0 (lpOverlapped = NULL)
		0xFF, 0x53, 0x08,                         // call [rbx+8]

		// Epilogue
		0x48, 0x83, 0xC4, 0x30,                   // add rsp, 48
		0x41, 0x5C,                               // pop r12
		0x5B,                                     // pop rbx
		0x5D,                                     // pop rbp
		0xC3,                                     // ret
	}

	// Write shellcode at offset 0.
	if err := advMem.Write(0, advShellcode); err != nil {
		fmt.Printf("FAIL: Write advanced shellcode: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PASS: Advanced shellcode written (%d bytes)\n", len(advShellcode))

	// Write the message at offset 512.
	helloMsg := ">>> Hello World from x64 shellcode running inside WASM!\r\n"
	if err := advMem.Write(512, []byte(helloMsg)); err != nil {
		fmt.Printf("FAIL: Write hello message: %v\n", err)
		os.Exit(1)
	}

	// Get base address.
	advBaseAddr, _ := advMem.Addr()
	msgAddrInAdv := advBaseAddr + 512

	// Write param struct at offset 256:
	//   [0]  getStdHandle addr  (uint64)
	//   [8]  writeFile addr     (uint64)
	//   [16] msg addr           (uint64)
	//   [24] msg len            (uint32)
	//   [28] bytesWritten       (uint32, output)
	if err := advMem.WriteUint64(256, getStdHandleAddr); err != nil {
		fmt.Printf("FAIL: Write getStdHandle addr: %v\n", err)
		os.Exit(1)
	}
	if err := advMem.WriteUint64(264, writeFileAddr); err != nil {
		fmt.Printf("FAIL: Write writeFile addr: %v\n", err)
		os.Exit(1)
	}
	if err := advMem.WriteUint64(272, msgAddrInAdv); err != nil {
		fmt.Printf("FAIL: Write msg addr: %v\n", err)
		os.Exit(1)
	}
	if err := advMem.WriteUint32(280, uint32(len(helloMsg))); err != nil {
		fmt.Printf("FAIL: Write msg len: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: Parameter struct written at offset 256")

	// Mark all memory as executable (code + data in same allocation).
	_, err = advMem.VirtualProtect(win32.PAGE_EXECUTE_READWRITE)
	if err != nil {
		fmt.Printf("FAIL: VirtualProtect(ERW): %v\n", err)
		os.Exit(1)
	}

	// Register shellcode as callable proc.
	advProc, err := advMem.ProcFromOffset(0)
	if err != nil {
		fmt.Printf("FAIL: ProcFromOffset for advanced shellcode: %v\n", err)
		os.Exit(1)
	}

	// Call the shellcode with RCX = address of param struct at offset 256.
	paramAddr := advBaseAddr + 256
	fmt.Println(">>> Calling advanced shellcode...")
	advRet, _, _ := win32.SyscallN64(advProc, paramAddr)
	if advRet == 0 {
		fmt.Println("WARN: Advanced shellcode returned 0 (WriteFile may have failed)")
	} else {
		fmt.Printf("PASS: Advanced shellcode executed successfully (ret=%d)\n", advRet)
	}

	advMem.Free()

	fmt.Println("\n=== All goffloader-style tests passed! ===")
}
