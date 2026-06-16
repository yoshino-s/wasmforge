package build

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// CheckCSharpPrereqs validates that all tools needed for C# NativeAOT-WASI
// compilation are available. Returns a combined error listing ALL missing
// prerequisites, not just the first one.
func CheckCSharpPrereqs(verbose bool) error {
	var missing []string

	// 1. dotnet SDK
	if _, err := exec.LookPath("dotnet"); err != nil {
		missing = append(missing, "dotnet SDK not found in PATH\n    Install .NET 10 SDK: https://dot.net/download\n    Then: dotnet workload install wasi-experimental")
	} else if verbose {
		if out, err := exec.Command("dotnet", "--version").Output(); err == nil {
			fmt.Fprintf(os.Stderr, "wasmforge: dotnet SDK: %s\n", strings.TrimSpace(string(out)))
		}
	}

	// 2. WASI SDK clang
	if clang := FindWASIClang(); clang == "" {
		missing = append(missing, "WASI SDK clang not found (needed for C bridge compilation)\n    Set WASI_SDK_PATH to your WASI SDK installation, e.g.:\n      export WASI_SDK_PATH=$HOME/.wasi-sdk/wasi-sdk-24.0\n    Or install: https://github.com/WebAssembly/wasi-sdk/releases")
	} else if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: clang: %s\n", clang)
	}

	// 3. wasm-ld
	if wasmld := FindWASMLD(); wasmld == "" {
		missing = append(missing, "wasm-ld not found (needed for bridge object linking)\n    wasm-ld is included in WASI SDK ($WASI_SDK_PATH/bin/wasm-ld)\n    Or install LLVM with wasm target support")
	} else if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: wasm-ld: %s\n", wasmld)
	}

	if len(missing) > 0 {
		return fmt.Errorf("C# build prerequisites not met:\n  - %s", strings.Join(missing, "\n  - "))
	}
	return nil
}

// FindWASIClang locates the WASI SDK clang binary.
// Checks in order: $WASI_SDK_PATH/bin/clang, $WASI_CLANG, PATH.
func FindWASIClang() string {
	if sdk := os.Getenv("WASI_SDK_PATH"); sdk != "" {
		path := filepath.Join(sdk, "bin", "clang")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	if c := os.Getenv("WASI_CLANG"); c != "" {
		if _, err := exec.LookPath(c); err == nil {
			return c
		}
	}
	if p, err := exec.LookPath("clang"); err == nil {
		return p
	}
	return ""
}

// FindWASMLD locates the wasm-ld linker binary.
// Checks in order: $WASI_SDK_PATH/bin/wasm-ld, PATH.
func FindWASMLD() string {
	if sdk := os.Getenv("WASI_SDK_PATH"); sdk != "" {
		path := filepath.Join(sdk, "bin", "wasm-ld")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	if p, err := exec.LookPath("wasm-ld"); err == nil {
		return p
	}
	return ""
}
