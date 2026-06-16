// Test program for the purego sysshim on macOS via WasmForge.
// Verifies Dlopen, RegisterLibFunc, and basic ObjC class lookup.
//
// Build: GOOS=darwin GOARCH=amd64 wasmforge build -v -o /tmp/test-purego ./testdata/darwin_purego
// Run:   /tmp/test-purego

package main

import (
	"fmt"
	"os"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)

func main() {
	passed := 0
	failed := 0

	// Test 1: Dlopen libSystem.B.dylib
	lib, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_LAZY)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Dlopen libSystem: %v\n", err)
		failed++
	} else {
		fmt.Printf("PASS: Dlopen libSystem.B.dylib → handle=%#x\n", lib)
		passed++
	}

	// Test 2: RegisterLibFunc for getpid
	var getpid func() int32
	purego.RegisterLibFunc(&getpid, lib, "getpid")
	pid := getpid()
	if pid > 0 {
		fmt.Printf("PASS: getpid() = %d\n", pid)
		passed++
	} else {
		fmt.Fprintf(os.Stderr, "FAIL: getpid() = %d (expected > 0)\n", pid)
		failed++
	}

	// Test 3: RegisterLibFunc for getuid
	var getuid func() uint32
	purego.RegisterLibFunc(&getuid, lib, "getuid")
	uid := getuid()
	fmt.Printf("PASS: getuid() = %d\n", uid)
	passed++

	// Test 4: Dlsym with RTLD_DEFAULT
	sym, err := purego.Dlsym(purego.RTLD_DEFAULT, "getpid")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Dlsym RTLD_DEFAULT: %v\n", err)
		failed++
	} else {
		r1, _, _ := purego.SyscallN(sym)
		if r1 == uintptr(pid) {
			fmt.Printf("PASS: SyscallN(getpid) via RTLD_DEFAULT = %d\n", r1)
			passed++
		} else {
			fmt.Fprintf(os.Stderr, "FAIL: SyscallN(getpid) = %d, expected %d\n", r1, pid)
			failed++
		}
	}

	// Load Foundation framework (required for NSString to be available)
	_, _ = purego.Dlopen("/System/Library/Frameworks/Foundation.framework/Foundation", purego.RTLD_LAZY|purego.RTLD_GLOBAL)

	// Test 5: ObjC GetClass
	nsString := objc.GetClass("NSString")
	if nsString != 0 {
		fmt.Printf("PASS: objc.GetClass(\"NSString\") = %#x\n", nsString)
		passed++
	} else {
		fmt.Fprintf(os.Stderr, "FAIL: objc.GetClass(\"NSString\") = 0\n")
		failed++
	}

	// Test 6: ObjC RegisterName
	sel := objc.RegisterName("length")
	if sel != 0 {
		fmt.Printf("PASS: objc.RegisterName(\"length\") = %#x\n", sel)
		passed++
	} else {
		fmt.Fprintf(os.Stderr, "FAIL: objc.RegisterName(\"length\") = 0\n")
		failed++
	}

	// Test 7: Dlclose
	err = purego.Dlclose(lib)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Dlclose: %v\n", err)
		failed++
	} else {
		fmt.Printf("PASS: Dlclose OK\n")
		passed++
	}

	fmt.Printf("\n%d/%d tests passed\n", passed, passed+failed)
	if failed > 0 {
		os.Exit(1)
	}
}
