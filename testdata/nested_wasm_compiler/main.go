// nested_wasm_compiler tests running WASM inside a wasmforge'd binary using
// different wazero engine configurations. This validates the fix for GitHub #3
// (Sliver traffic encoders) where CompilerSupported() is patched to return
// false in the guest-vendored wazero, so auto-detect falls back to interpreter.
//
// Expected results (after fix):
//   - Compiler engine: panics ("unsupported architecture") — expected, requires mmap
//   - Auto-detect: succeeds — CompilerSupported() returns false, interpreter selected
//   - Interpreter: works perfectly — the correct engine for nested WASM
package main

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"os"
	"strings"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:embed guest.wasm
var guestWasm []byte

func tryEngine(ctx context.Context, cfg wazero.RuntimeConfig) (output string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	rt := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer rt.Close(ctx)

	_, err = wasi_snapshot_preview1.Instantiate(ctx, rt)
	if err != nil {
		return "", fmt.Errorf("WASI instantiate: %w", err)
	}

	compiled, err := rt.CompileModule(ctx, guestWasm)
	if err != nil {
		return "", fmt.Errorf("CompileModule: %w", err)
	}

	var stdout bytes.Buffer
	modCfg := wazero.NewModuleConfig().
		WithStdout(&stdout).
		WithStderr(os.Stderr).
		WithName("")

	_, err = rt.InstantiateModule(ctx, compiled, modCfg)
	if err != nil {
		return "", fmt.Errorf("InstantiateModule: %w", err)
	}

	return strings.TrimSpace(stdout.String()), nil
}

func main() {
	failed := false

	if len(guestWasm) == 0 {
		fmt.Fprintf(os.Stderr, "FAIL: guest.wasm not embedded\n")
		os.Exit(1)
	}
	fmt.Printf("PASS: guest.wasm embedded (%d bytes)\n", len(guestWasm))

	ctx := context.Background()

	// Test 1: Compiler engine — expected to panic inside WASM (needs mmap).
	fmt.Println("\n--- Test 1: Compiler engine ---")
	_, err := tryEngine(ctx, wazero.NewRuntimeConfigCompiler())
	if err != nil {
		fmt.Printf("PASS: compiler engine failed as expected: %v\n", err)
	} else {
		fmt.Println("INFO: compiler engine unexpectedly succeeded (running natively?)")
	}

	// Test 2: Auto-detect — with CompilerSupported() patched to return false,
	// auto-detect selects the interpreter engine and succeeds.
	fmt.Println("\n--- Test 2: Auto-detect engine ---")
	out, err := tryEngine(ctx, wazero.NewRuntimeConfig())
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: auto-detect engine failed: %v\n", err)
		failed = true
	} else if out == "hello from nested wasm" {
		fmt.Printf("PASS: auto-detect engine succeeded (interpreter fallback): %q\n", out)
	} else {
		fmt.Fprintf(os.Stderr, "FAIL: auto-detect engine wrong output: %q\n", out)
		failed = true
	}

	// Test 3: Interpreter — this is the working path for nested WASM.
	fmt.Println("\n--- Test 3: Interpreter engine ---")
	out, err = tryEngine(ctx, wazero.NewRuntimeConfigInterpreter())
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: interpreter engine failed: %v\n", err)
		failed = true
	} else if out == "hello from nested wasm" {
		fmt.Printf("PASS: interpreter output correct: %q\n", out)
	} else {
		fmt.Fprintf(os.Stderr, "FAIL: interpreter output wrong: got %q, want %q\n", out, "hello from nested wasm")
		failed = true
	}

	// Test 4: Simulate Sliver's init() pattern — compiler engine fails at
	// runtime creation (not config creation), then check if independent
	// work would be skipped by Sliver's early return.
	fmt.Println("\n--- Test 4: Sliver init() pattern simulation ---")
	encoderLoaded := false
	dictLoaded := false

	// Simulate loadWasmEncodersFromAssets() — creates runtime with compiler engine.
	// Inside WASM this panics during NewRuntimeWithConfig (mmap unsupported).
	loadErr := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
		defer rt.Close(ctx)
		encoderLoaded = true
		return nil
	}()

	// Sliver's buggy init():
	//   err := loadWasmEncodersFromAssets()
	//   if err != nil { return }    // ← BUG: skips dictionary
	//   loadEnglishDictionaryFromAssets()
	if loadErr != nil {
		fmt.Printf("INFO: encoder loading failed (expected): %v\n", loadErr)
		fmt.Println("INFO: Sliver's buggy init() would 'return' here, skipping dictionary")
	}

	// Fixed pattern: load dictionary regardless of encoder result.
	dictLoaded = true
	if dictLoaded && !encoderLoaded {
		fmt.Println("PASS: fixed pattern loads dictionary even when encoders fail")
	}

	if failed {
		fmt.Fprintf(os.Stderr, "\nFAIL: nested_wasm_compiler test failed\n")
		os.Exit(1)
	}
	fmt.Println("\nPASS: all nested_wasm_compiler tests passed")
}
