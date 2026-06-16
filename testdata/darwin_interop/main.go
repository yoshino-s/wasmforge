// darwin_interop tests basic macOS framework loading and function calling.
// It loads libSystem, resolves getpid, calls it, and verifies the result.
package main

import (
	"fmt"
	"os"

	"github.com/praetorian-inc/wasmforge/guest/darwin"
)

func main() {
	if !darwin.Available() {
		fmt.Println("SKIP: darwin APIs not available")
		os.Exit(0)
	}
	fmt.Println("PASS: darwin APIs available")

	// Load libSystem.B (always present on macOS).
	fw, err := darwin.LoadFramework("libSystem.B")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: LoadFramework(libSystem.B): %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: loaded libSystem.B")

	// Resolve getpid.
	sym, err := fw.GetSymbol("getpid")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: GetSymbol(getpid): %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: resolved getpid symbol")

	// Call getpid() — no arguments.
	pid, err := sym.Call()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Call(getpid): %v\n", err)
		os.Exit(1)
	}
	if pid == 0 {
		fmt.Fprintf(os.Stderr, "FAIL: getpid returned 0\n")
		os.Exit(1)
	}
	fmt.Printf("PASS: getpid() = %d\n", pid)

	// Resolve getuid.
	uidSym, err := fw.GetSymbol("getuid")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: GetSymbol(getuid): %v\n", err)
		os.Exit(1)
	}

	uid, err := uidSym.Call()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Call(getuid): %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PASS: getuid() = %d\n", uid)

	// Test framework path expansion.
	secPath := darwin.ExpandFrameworkPath("Security")
	if secPath != "/System/Library/Frameworks/Security.framework/Security" {
		fmt.Fprintf(os.Stderr, "FAIL: ExpandFrameworkPath(Security) = %q\n", secPath)
		os.Exit(1)
	}
	fmt.Printf("PASS: ExpandFrameworkPath(Security) = %s\n", secPath)

	libPath := darwin.ExpandFrameworkPath("libSystem.B")
	if libPath != "/usr/lib/libSystem.B.dylib" {
		fmt.Fprintf(os.Stderr, "FAIL: ExpandFrameworkPath(libSystem.B) = %q\n", libPath)
		os.Exit(1)
	}
	fmt.Printf("PASS: ExpandFrameworkPath(libSystem.B) = %s\n", libPath)

	fmt.Println("PASS: all darwin_interop tests passed")
}
