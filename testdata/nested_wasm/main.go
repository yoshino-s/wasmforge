// nested_wasm tests running a WASM module inside a wasmforge'd binary.
// This reproduces the Sliver encoders issue (GitHub #3): when a wasmforge'd
// binary tries to use wazero internally to load and run WASM modules, does
// nested WASM execution work?
//
// The test embeds a pre-compiled "hello world" wasip1 WASM blob and uses
// wazero's interpreter engine to run it, capturing stdout.
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

func main() {
	failed := false

	// Verify the embedded WASM blob is present.
	if len(guestWasm) == 0 {
		fmt.Fprintf(os.Stderr, "FAIL: guest.wasm not embedded\n")
		os.Exit(1)
	}
	fmt.Printf("PASS: guest.wasm embedded (%d bytes)\n", len(guestWasm))

	ctx := context.Background()

	// Create a wazero runtime using the interpreter engine explicitly.
	// The compiler engine requires mmap/native code which won't work inside WASM.
	cfg := wazero.NewRuntimeConfigInterpreter()
	rt := wazero.NewRuntimeWithConfig(ctx, cfg)
	defer rt.Close(ctx)

	fmt.Println("PASS: wazero runtime created (interpreter)")

	// Instantiate WASI (the guest uses fmt.Println which needs WASI fd_write).
	_, err := wasi_snapshot_preview1.Instantiate(ctx, rt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: WASI instantiation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: WASI snapshot instantiated")

	// Compile the guest module.
	compiled, err := rt.CompileModule(ctx, guestWasm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: CompileModule failed: %v\n", err)
		failed = true
	} else {
		fmt.Println("PASS: guest module compiled")

		// Capture stdout from the guest.
		var stdout bytes.Buffer
		modCfg := wazero.NewModuleConfig().
			WithStdout(&stdout).
			WithStderr(os.Stderr).
			WithName("")

		// Run the guest module.
		_, err = rt.InstantiateModule(ctx, compiled, modCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: InstantiateModule failed: %v\n", err)
			failed = true
		} else {
			output := strings.TrimSpace(stdout.String())
			if output == "hello from nested wasm" {
				fmt.Printf("PASS: guest output correct: %q\n", output)
			} else {
				fmt.Fprintf(os.Stderr, "FAIL: guest output wrong: got %q, want %q\n", output, "hello from nested wasm")
				failed = true
			}
		}
	}

	if failed {
		fmt.Fprintf(os.Stderr, "\nFAIL: nested wasm test failed\n")
		os.Exit(1)
	}
	fmt.Println("\nPASS: all nested_wasm tests passed")
}
