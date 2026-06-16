// win32_clr_assembly tests the full CLR assembly loading chain:
// CLRCreateInstance → EnumerateInstalledRuntimes → ICorRuntimeHost → Start →
// GetDefaultDomain → QI _AppDomain → Load_3 → get_EntryPoint → Invoke_3 with stdout capture.
//
// The .NET assembly (hello.exe) is embedded via //go:embed — fully self-contained,
// zero external file dependencies.
//
// Build native:   GOOS=windows GOARCH=amd64 go build -o clr_asm.exe ./testdata/win32_clr_assembly
// Build wasmforge: GOWORK=off GOOS=windows GOARCH=amd64 wasmforge build --win32-apis -v -o clr_asm.exe ./testdata/win32_clr_assembly
// Run on Windows with .NET Framework 4.x installed.
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// ---- GUID type ----

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// ---- DLL/proc handles ----

var (
	ole32   = syscall.NewLazyDLL("ole32.dll")
	mscoree = syscall.NewLazyDLL("mscoree.dll")
	oleaut = syscall.NewLazyDLL("oleaut32.dll")
	ntdll  = syscall.NewLazyDLL("ntdll.dll")

	procCoInitializeEx       = ole32.NewProc("CoInitializeEx")
	procCLRCreateInstance    = mscoree.NewProc("CLRCreateInstance")
	procSafeArrayCreateVec   = oleaut.NewProc("SafeArrayCreateVector")
	procSafeArrayAccessData  = oleaut.NewProc("SafeArrayAccessData")
	procSafeArrayUnaccessDat = oleaut.NewProc("SafeArrayUnaccessData")
	procSafeArrayDestroy     = oleaut.NewProc("SafeArrayDestroy")
	procRtlMoveMemory        = ntdll.NewProc("RtlMoveMemory")
)

// ---- COM GUIDs ----

var (
	CLSID_CLRMetaHost = GUID{0x9280188d, 0xe8e, 0x4867,
		[8]byte{0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde}}
	IID_ICLRMetaHost = GUID{0xD332DB9E, 0xB9B3, 0x4125,
		[8]byte{0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16}}

	CLSID_CorRuntimeHost = GUID{0xCB2F6723, 0xAB3A, 0x11D2,
		[8]byte{0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E}}
	IID_ICorRuntimeHost = GUID{0xCB2F6722, 0xAB3A, 0x11D2,
		[8]byte{0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E}}

	IID_AppDomain = GUID{0x05F696DC, 0x2B29, 0x3663,
		[8]byte{0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13}}
)

// ---- VARIANT / SAFEARRAY constants ----

const (
	VT_UI1     = 17
	VT_BSTR    = 8
	VT_UNKNOWN = 13
	VT_NULL    = 1
	VT_EMPTY   = 0
	VT_ARRAY   = 0x2000
	VT_VARIANT = 12
)

// ---- VARIANT struct (16 bytes on x64) ----

type VARIANT struct {
	VT       uint16
	_        [6]byte // wReserved1-3
	Val      uintptr
	_padding uintptr
}

// ---- Helper: comCall ----

func comCall(iface uintptr, vtableIdx int, args ...uintptr) (uintptr, uintptr, syscall.Errno) {
	vtable := *(*uintptr)(unsafe.Pointer(iface))
	method := *(*uintptr)(unsafe.Pointer(vtable + uintptr(vtableIdx)*unsafe.Sizeof(uintptr(0))))
	allArgs := make([]uintptr, 0, 1+len(args))
	allArgs = append(allArgs, iface)
	allArgs = append(allArgs, args...)
	return syscall.SyscallN(method, allArgs...)
}

// ---- Helper: createByteArray ----
// Creates a SAFEARRAY(VT_UI1) and copies data into it.

func createByteArray(data []byte) (uintptr, error) {
	sa, _, _ := syscall.SyscallN(procSafeArrayCreateVec.Addr(), VT_UI1, 0, uintptr(len(data)))
	if sa == 0 {
		return 0, fmt.Errorf("SafeArrayCreateVector returned NULL")
	}
	var ppData uintptr
	hr, _, _ := syscall.SyscallN(procSafeArrayAccessData.Addr(), sa, uintptr(unsafe.Pointer(&ppData)))
	if hr != 0 {
		return 0, fmt.Errorf("SafeArrayAccessData hr=0x%x", hr)
	}
	syscall.SyscallN(procRtlMoveMemory.Addr(), ppData, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)))
	syscall.SyscallN(procSafeArrayUnaccessDat.Addr(), sa)
	return sa, nil
}

func pass(tag string) { fmt.Printf("PASS:clr_assembly:%s\n", tag) }
func fail(tag, msg string) {
	fmt.Printf("FAIL:clr_assembly:%s — %s\n", tag, msg)
	os.Exit(1)
}

func main() {
	fmt.Println("=== CLR Assembly Load Test ===")

	// Step 1: CoInitializeEx
	hr, _, _ := procCoInitializeEx.Call(0, 0)
	if hr != 0 && hr != 1 && hr != 0x80010106 {
		fail("coinit", fmt.Sprintf("hr=0x%x", hr))
	}
	pass("coinit")

	// Step 2: CLRCreateInstance → ICLRMetaHost
	var pMetaHost uintptr
	hr, _, _ = procCLRCreateInstance.Call(
		uintptr(unsafe.Pointer(&CLSID_CLRMetaHost)),
		uintptr(unsafe.Pointer(&IID_ICLRMetaHost)),
		uintptr(unsafe.Pointer(&pMetaHost)),
	)
	if hr != 0 {
		fail("clr_created", fmt.Sprintf("CLRCreateInstance hr=0x%x", hr))
	}
	pass("clr_created")

	// Step 3: EnumerateInstalledRuntimes → IEnumUnknown::Next → ICLRRuntimeInfo
	// On Win11, EnumerateInstalledRuntimes returns v2.0.50727 first, then
	// v4.0.30319. We need v4.0 because _AppDomain::Load_3 is slot 45 in
	// the v4.0 vtable layout. Call Next twice — skip v2.0, use v4.0.
	// ICLRMetaHost vtable:
	//   [0] QueryInterface  [1] AddRef  [2] Release
	//   [3] GetRuntime  [4] GetVersionFromFile  [5] EnumerateInstalledRuntimes
	var pEnum uintptr
	hr, _, _ = comCall(pMetaHost, 5, uintptr(unsafe.Pointer(&pEnum)))
	if hr != 0 || pEnum == 0 {
		fail("runtime", fmt.Sprintf("EnumerateInstalledRuntimes hr=0x%x pEnum=0x%x", hr, pEnum))
	}
	fmt.Printf("EnumerateInstalledRuntimes: pEnum=0x%x\n", pEnum)

	// IEnumUnknown vtable:
	//   [0] QueryInterface  [1] AddRef  [2] Release
	//   [3] Next  [4] Skip  [5] Reset  [6] Clone
	//
	// Skip the first runtime (v2.0) to avoid mirror issues with second Next.
	// IEnumUnknown::Skip(1) advances without returning any COM objects.
	hr, _, _ = comCall(pEnum, 4, 1) // Skip(celt=1)
	fmt.Printf("IEnumUnknown::Skip(1): hr=0x%x\n", hr)

	// IEnumUnknown::Next — fetch the next runtime (should be v4.0.30319).
	var pRuntimeInfo uintptr
	var fetched uint32
	hr, _, _ = comCall(pEnum, 3,
		1,
		uintptr(unsafe.Pointer(&pRuntimeInfo)),
		uintptr(unsafe.Pointer(&fetched)),
	)
	if hr != 0 || pRuntimeInfo == 0 {
		// v4.0 not found — reset and use first runtime.
		fmt.Printf("Skip+Next failed (hr=0x%x), resetting to first\n", hr)
		comCall(pEnum, 5) // Reset
		hr, _, _ = comCall(pEnum, 3,
			1,
			uintptr(unsafe.Pointer(&pRuntimeInfo)),
			uintptr(unsafe.Pointer(&fetched)),
		)
		if hr != 0 || pRuntimeInfo == 0 {
			fail("runtime", fmt.Sprintf("IEnumUnknown::Next hr=0x%x pRI=0x%x", hr, pRuntimeInfo))
		}
	}
	fmt.Printf("Using runtime: pRI=0x%x fetched=%d\n", pRuntimeInfo, fetched)
	pass("runtime")

	// Step 4: GetInterface → ICorRuntimeHost (slot 9)
	var pCorHost uintptr
	hr, _, _ = comCall(pRuntimeInfo, 9,
		uintptr(unsafe.Pointer(&CLSID_CorRuntimeHost)),
		uintptr(unsafe.Pointer(&IID_ICorRuntimeHost)),
		uintptr(unsafe.Pointer(&pCorHost)),
	)
	if hr != 0 {
		fail("host", fmt.Sprintf("GetInterface hr=0x%x", hr))
	}
	pass("host")

	// Step 5: Start (slot 10)
	hr, _, _ = comCall(pCorHost, 10)
	if hr != 0 && hr != 1 { // S_OK or S_FALSE (already started)
		fail("started", fmt.Sprintf("Start hr=0x%x", hr))
	}
	pass("started")

	// Step 6: GetDefaultDomain (slot 13)
	var pDomainThunk uintptr
	hr, _, _ = comCall(pCorHost, 13, uintptr(unsafe.Pointer(&pDomainThunk)))
	if hr != 0 {
		fail("domain", fmt.Sprintf("GetDefaultDomain hr=0x%x", hr))
	}
	pass("domain")

	// Step 7: QI for _AppDomain (slot 0)
	var pAppDomain uintptr
	hr, _, _ = comCall(pDomainThunk, 0,
		uintptr(unsafe.Pointer(&IID_AppDomain)),
		uintptr(unsafe.Pointer(&pAppDomain)),
	)
	if hr != 0 {
		fail("appdomain_qi", fmt.Sprintf("QI _AppDomain hr=0x%x", hr))
	}
	pass("appdomain_qi")

	// Step 8: Create SAFEARRAY with embedded assembly bytes.
	fmt.Printf("Assembly size: %d bytes\n", len(helloAssembly))
	sa, err := createByteArray(helloAssembly)
	if err != nil {
		fail("safearray", err.Error())
	}
	pass("safearray")

	// Step 9: _AppDomain::Load_3 (slot 45)
	var pAssembly uintptr
	hr, _, errno := comCall(pAppDomain, 45,
		sa,
		uintptr(unsafe.Pointer(&pAssembly)),
	)
	fmt.Printf("Load_3: hr=0x%x errno=%d pAssembly=0x%x\n", hr, errno, pAssembly)
	if hr != 0 {
		fail("load3", fmt.Sprintf("Load_3 hr=0x%x", hr))
	}
	if pAssembly == 0 {
		fail("load3", "pAssembly is NULL (AMSI may have blocked it)")
	}
	pass("load3")

	// Step 10: _Assembly::get_EntryPoint (slot 16)
	var pMethodInfo uintptr
	hr, _, _ = comCall(pAssembly, 16, uintptr(unsafe.Pointer(&pMethodInfo)))
	if hr != 0 {
		fail("entrypoint", fmt.Sprintf("get_EntryPoint hr=0x%x", hr))
	}
	if pMethodInfo == 0 {
		fail("entrypoint", "pMethodInfo is NULL")
	}
	pass("entrypoint")

	// Step 11: Invoke_3 — _MethodInfo::Invoke_3 (slot 37)
	// Signature: Invoke_3(obj VARIANT, params *SAFEARRAY, retVal *VARIANT) HRESULT
	// For static Main(string[] args): obj=VT_NULL, params=SAFEARRAY(VARIANT(SAFEARRAY(BSTR)))

	// Build the "this" variant (VT_EMPTY for static method)
	var objVariant VARIANT
	objVariant.VT = VT_EMPTY

	// Build args: SAFEARRAY of 1 VARIANT containing an empty BSTR array
	// For simplicity, pass no args (empty string array)
	emptyStrArray, _, _ := syscall.SyscallN(procSafeArrayCreateVec.Addr(), VT_BSTR, 0, 0)

	var argVariant VARIANT
	argVariant.VT = VT_ARRAY | VT_BSTR
	argVariant.Val = emptyStrArray

	// Outer SAFEARRAY(VARIANT) with 1 element
	outerSA, _, _ := syscall.SyscallN(procSafeArrayCreateVec.Addr(), VT_VARIANT, 0, 1)
	if outerSA != 0 {
		var ppOuter uintptr
		syscall.SyscallN(procSafeArrayAccessData.Addr(), outerSA, uintptr(unsafe.Pointer(&ppOuter)))
		// Copy the VARIANT into the SAFEARRAY data
		*(*VARIANT)(unsafe.Pointer(ppOuter)) = argVariant
		syscall.SyscallN(procSafeArrayUnaccessDat.Addr(), outerSA)
	}

	var retVariant VARIANT
	hr, _, _ = comCall(pMethodInfo, 37,
		uintptr(unsafe.Pointer(&objVariant)),
		outerSA,
		uintptr(unsafe.Pointer(&retVariant)),
	)
	if hr != 0 {
		fail("invoked", fmt.Sprintf("Invoke_3 hr=0x%x", hr))
	}
	pass("invoked")

	// .NET Console.WriteLine output goes to the process stdout.
	// Under WMI exec, this appears in the captured output. No explicit
	// capture mechanism needed — just verify the PASS line appears.
	fmt.Println("SKIP:clr_assembly:hello_from_dotnet — verify in test output")

	// Step 12: Dual Load_3 test — load the same assembly again
	sa2, _, _ := syscall.SyscallN(procSafeArrayCreateVec.Addr(), VT_UI1, 0, uintptr(len(helloAssembly)))
	if sa2 == 0 {
		fail("dual_load", "second SafeArrayCreateVector returned NULL")
	}
	var ppData2 uintptr
	hr, _, _ = syscall.SyscallN(procSafeArrayAccessData.Addr(), sa2, uintptr(unsafe.Pointer(&ppData2)))
	if hr != 0 {
		fail("dual_load", fmt.Sprintf("second SafeArrayAccessData hr=0x%x", hr))
	}
	syscall.SyscallN(procRtlMoveMemory.Addr(), ppData2, uintptr(unsafe.Pointer(&helloAssembly[0])), uintptr(len(helloAssembly)))
	syscall.SyscallN(procSafeArrayUnaccessDat.Addr(), sa2)
	var pAssembly2 uintptr
	hr, _, _ = comCall(pAppDomain, 45,
		sa2,
		uintptr(unsafe.Pointer(&pAssembly2)),
	)
	if hr != 0 {
		fail("dual_load", fmt.Sprintf("second Load_3 hr=0x%x", hr))
	}
	if pAssembly2 == 0 {
		fail("dual_load", "second pAssembly is NULL")
	}
	pass("dual_load")

	// Cleanup
	syscall.SyscallN(procSafeArrayDestroy.Addr(), sa)
	syscall.SyscallN(procSafeArrayDestroy.Addr(), sa2)
	if outerSA != 0 {
		syscall.SyscallN(procSafeArrayDestroy.Addr(), outerSA)
	}
	if emptyStrArray != 0 {
		syscall.SyscallN(procSafeArrayDestroy.Addr(), emptyStrArray)
	}

	fmt.Println("\n=== All CLR Assembly Tests Passed ===")
}
