// win32_clr tests CLR hosting via COM interfaces: CLRCreateInstance →
// ICLRMetaHost::EnumerateInstalledRuntimes → IEnumUnknown::Next →
// ICLRRuntimeInfo::GetVersionString. This exercises the mirror table's
// COM vtable mirroring, recursive scanning, and reverse translation.
//
// Build: GOOS=windows GOARCH=amd64 wasmforge build --win32-apis -v -o clr_test.exe ./testdata/win32_clr
// Run on Windows with .NET Framework installed.
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var (
	ole32    = syscall.NewLazyDLL("ole32.dll")
	mscoree  = syscall.NewLazyDLL("mscoree.dll")

	procCoInitializeEx    = ole32.NewProc("CoInitializeEx")
	procCLRCreateInstance = mscoree.NewProc("CLRCreateInstance")
)

// GUIDs for CLR hosting
var (
	CLSID_CLRMetaHost = GUID{
		Data1: 0x9280188d,
		Data2: 0xe8e,
		Data3: 0x4867,
		Data4: [8]byte{0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde},
	}
	IID_ICLRMetaHost = GUID{
		Data1: 0xD332DB9E,
		Data2: 0xB9B3,
		Data3: 0x4125,
		Data4: [8]byte{0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16},
	}
)

// utf16ToString converts a null-terminated uint16 buffer to a Go string.
func utf16ToString(buf []uint16) string {
	for i, v := range buf {
		if v == 0 {
			return string(utf16Decode(buf[:i]))
		}
	}
	return string(utf16Decode(buf))
}

func utf16Decode(s []uint16) []byte {
	out := make([]byte, 0, len(s)*3)
	for _, v := range s {
		if v < 0x80 {
			out = append(out, byte(v))
		} else if v < 0x800 {
			out = append(out, byte(0xC0|(v>>6)), byte(0x80|(v&0x3F)))
		} else {
			out = append(out, byte(0xE0|(v>>12)), byte(0x80|((v>>6)&0x3F)), byte(0x80|(v&0x3F)))
		}
	}
	return out
}

func main() {
	fmt.Println("=== CLR Hosting Test ===")

	// Step 1: CoInitializeEx
	// WasmForge's COM worker already initializes COM (STA). CoInitializeEx
	// may return S_OK (0), S_FALSE (1), or RPC_E_CHANGED_MODE (0x80010106).
	// All are acceptable — we just need COM to be initialized.
	fmt.Print("CoInitializeEx... ")
	hr, _, _ := procCoInitializeEx.Call(0, 0) // COINIT_MULTITHREADED
	if hr == 0 || hr == 1 || hr == 0x80010106 {
		fmt.Printf("OK (hr=0x%x)\n", hr)
	} else {
		fmt.Printf("FAIL: hr=0x%x\n", hr)
		os.Exit(1)
	}

	// Step 2: CLRCreateInstance → ICLRMetaHost
	fmt.Print("CLRCreateInstance... ")
	var pMetaHost uintptr
	hr, _, _ = procCLRCreateInstance.Call(
		uintptr(unsafe.Pointer(&CLSID_CLRMetaHost)),
		uintptr(unsafe.Pointer(&IID_ICLRMetaHost)),
		uintptr(unsafe.Pointer(&pMetaHost)),
	)
	if hr != 0 {
		fmt.Printf("FAIL: hr=0x%x\n", hr)
		os.Exit(1)
	}
	fmt.Printf("OK pMetaHost=0x%x\n", pMetaHost)

	// Step 3: ICLRMetaHost::EnumerateInstalledRuntimes (vtable index 5)
	// ICLRMetaHost vtable:
	//   [0] QueryInterface
	//   [1] AddRef
	//   [2] Release
	//   [3] GetRuntime
	//   [4] GetVersionFromFile
	//   [5] EnumerateInstalledRuntimes
	fmt.Print("EnumerateInstalledRuntimes... ")
	vtable := *(*uintptr)(unsafe.Pointer(pMetaHost))
	enumSlot := *(*uintptr)(unsafe.Pointer(vtable + 5*unsafe.Sizeof(uintptr(0))))
	var pEnum uintptr
	hr, _, _ = syscall.SyscallN(enumSlot, pMetaHost, uintptr(unsafe.Pointer(&pEnum)))
	if hr != 0 {
		fmt.Printf("FAIL: hr=0x%x\n", hr)
		os.Exit(1)
	}
	fmt.Printf("OK pEnum=0x%x\n", pEnum)

	// Step 4: IEnumUnknown::Next (vtable index 3)
	// IEnumUnknown vtable:
	//   [0] QueryInterface
	//   [1] AddRef
	//   [2] Release
	//   [3] Next
	fmt.Print("IEnumUnknown::Next... ")
	enumVtable := *(*uintptr)(unsafe.Pointer(pEnum))
	nextSlot := *(*uintptr)(unsafe.Pointer(enumVtable + 3*unsafe.Sizeof(uintptr(0))))
	var pRuntimeInfo uintptr
	var fetched uint32
	hr, _, _ = syscall.SyscallN(nextSlot, pEnum, 1,
		uintptr(unsafe.Pointer(&pRuntimeInfo)),
		uintptr(unsafe.Pointer(&fetched)))
	if hr != 0 {
		fmt.Printf("FAIL: hr=0x%x fetched=%d\n", hr, fetched)
		os.Exit(1)
	}
	fmt.Printf("OK pRuntimeInfo=0x%x fetched=%d\n", pRuntimeInfo, fetched)

	// Step 5: ICLRRuntimeInfo::GetVersionString (vtable index 3)
	// ICLRRuntimeInfo vtable:
	//   [0] QueryInterface
	//   [1] AddRef
	//   [2] Release
	//   [3] GetVersionString
	fmt.Print("GetVersionString... ")
	riVtable := *(*uintptr)(unsafe.Pointer(pRuntimeInfo))
	getVerSlot := *(*uintptr)(unsafe.Pointer(riVtable + 3*unsafe.Sizeof(uintptr(0))))
	var verBuf [256]uint16
	verLen := uint32(256)
	hr, _, _ = syscall.SyscallN(getVerSlot, pRuntimeInfo,
		uintptr(unsafe.Pointer(&verBuf[0])),
		uintptr(unsafe.Pointer(&verLen)))
	if hr != 0 {
		fmt.Printf("FAIL: hr=0x%x\n", hr)
		os.Exit(1)
	}
	version := utf16ToString(verBuf[:verLen])
	fmt.Printf("OK version=%s\n", version)

	fmt.Println("\nPASS: CLR hosting via COM interfaces works")
}
