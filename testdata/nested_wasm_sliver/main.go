// nested_wasm_sliver replicates Sliver's actual traffic encoder loading pattern:
//   1. Create wazero runtime with INTERPRETER engine (as build tags select)
//   2. Register custom host functions (rand, time, log — matching Sliver's ABI)
//   3. Instantiate WASI
//   4. Compile and instantiate an encoder WASM module
//   5. Call encode/decode via exported functions
//
// This tests whether the full Sliver encoder flow works inside wasmforge,
// not just basic nested WASM.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:embed encoder.wasm
var encoderWasm []byte

func main() {
	failed := false

	if len(encoderWasm) == 0 {
		fmt.Fprintf(os.Stderr, "FAIL: encoder.wasm not embedded\n")
		os.Exit(1)
	}
	fmt.Printf("PASS: encoder.wasm embedded (%d bytes)\n", len(encoderWasm))

	ctx := context.Background()

	// Step 1: Create runtime with interpreter (matches Sliver's interpreter.go path).
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter())
	defer rt.Close(ctx)
	fmt.Println("PASS: wazero interpreter runtime created")

	// Step 2: Register host functions matching Sliver's encoder host module.
	// Sliver exports: rand() uint64, time() int64, log(offset, byteCount uint32)
	_, err := rt.NewHostModuleBuilder("env").
		NewFunctionBuilder().
		WithFunc(func() uint64 { return rand.Uint64() }).
		Export("rand").
		NewFunctionBuilder().
		WithFunc(func() int64 { return time.Now().UnixNano() }).
		Export("time").
		NewFunctionBuilder().
		WithFunc(func(_ context.Context, m api.Module, offset, byteCount uint32) {
			// log callback — read from WASM memory and print
			if buf, ok := m.Memory().Read(offset, byteCount); ok {
				fmt.Fprintf(os.Stderr, "[encoder] %s\n", string(buf))
			}
		}).
		Export("log").
		Instantiate(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: host module creation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: host module registered (rand, time, log)")

	// Step 3: Instantiate WASI.
	_, err = wasi_snapshot_preview1.Instantiate(ctx, rt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: WASI instantiation failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: WASI instantiated")

	// Step 4: Compile and instantiate the encoder module.
	compiled, err := rt.CompileModule(ctx, encoderWasm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: CompileModule failed: %v\n", err)
		os.Exit(1)
	}

	mod, err := rt.InstantiateModule(ctx, compiled, wazero.NewModuleConfig())
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: InstantiateModule failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: encoder module instantiated")

	// Step 5: Get exported functions (matching Sliver's TrafficEncoder).
	encodeFn := mod.ExportedFunction("encode")
	decodeFn := mod.ExportedFunction("decode")
	mallocFn := mod.ExportedFunction("malloc")
	freeFn := mod.ExportedFunction("free")

	if encodeFn == nil || decodeFn == nil || mallocFn == nil || freeFn == nil {
		fmt.Fprintf(os.Stderr, "FAIL: missing exported functions\n")
		os.Exit(1)
	}
	fmt.Println("PASS: encode/decode/malloc/free exports found")

	// Step 6: Encode/decode round-trip test.
	testData := []byte("hello from sliver encoder test!")

	// Allocate WASM memory for input.
	results, err := mallocFn.Call(ctx, uint64(len(testData)))
	if err != nil || len(results) == 0 || results[0] == 0 {
		fmt.Fprintf(os.Stderr, "FAIL: malloc failed: %v\n", err)
		os.Exit(1)
	}
	inputPtr := uint32(results[0])

	// Write test data to WASM memory.
	if !mod.Memory().Write(inputPtr, testData) {
		fmt.Fprintf(os.Stderr, "FAIL: memory write failed\n")
		os.Exit(1)
	}

	// Call encode.
	results, err = encodeFn.Call(ctx, uint64(inputPtr), uint64(len(testData)))
	if err != nil || len(results) == 0 || results[0] == 0 {
		fmt.Fprintf(os.Stderr, "FAIL: encode failed: %v\n", err)
		failed = true
	} else {
		// Parse result: ptr in upper 32 bits, size in lower 32 bits.
		packed := results[0]
		outPtr := uint32(packed >> 32)
		outSize := uint32(packed & 0xFFFFFFFF)

		encoded, ok := mod.Memory().Read(outPtr, outSize)
		if !ok {
			fmt.Fprintf(os.Stderr, "FAIL: read encoded output failed\n")
			failed = true
		} else {
			// Verify encoding changed the data.
			different := false
			for i := range testData {
				if encoded[i] != testData[i] {
					different = true
					break
				}
			}
			if !different {
				fmt.Fprintf(os.Stderr, "FAIL: encoded output identical to input\n")
				failed = true
			} else {
				fmt.Printf("PASS: encode produced %d bytes (different from input)\n", outSize)
			}

			// Call decode on the encoded output.
			results2, err := mallocFn.Call(ctx, uint64(outSize))
			if err != nil || len(results2) == 0 || results2[0] == 0 {
				fmt.Fprintf(os.Stderr, "FAIL: malloc for decode failed: %v\n", err)
				failed = true
			} else {
				decInputPtr := uint32(results2[0])
				mod.Memory().Write(decInputPtr, encoded)

				results3, err := decodeFn.Call(ctx, uint64(decInputPtr), uint64(outSize))
				if err != nil || len(results3) == 0 || results3[0] == 0 {
					fmt.Fprintf(os.Stderr, "FAIL: decode failed: %v\n", err)
					failed = true
				} else {
					decPacked := results3[0]
					decPtr := uint32(decPacked >> 32)
					decSize := uint32(decPacked & 0xFFFFFFFF)

					decoded, ok := mod.Memory().Read(decPtr, decSize)
					if !ok {
						fmt.Fprintf(os.Stderr, "FAIL: read decoded output failed\n")
						failed = true
					} else if string(decoded) != string(testData) {
						fmt.Fprintf(os.Stderr, "FAIL: decode mismatch: got %q, want %q\n", decoded, testData)
						failed = true
					} else {
						fmt.Printf("PASS: decode round-trip correct: %q\n", decoded)
					}
				}
			}

			// Free allocated memory.
			freeFn.Call(ctx, uint64(inputPtr))
			freeFn.Call(ctx, uint64(outPtr))
		}
	}

	// Step 7: Simulate Sliver's init() — encoder loaded, now check dictionary.
	fmt.Println("\n--- Sliver init() simulation ---")
	if !failed {
		fmt.Println("PASS: encoder loading succeeded — Sliver init() would proceed to dictionary")
	} else {
		fmt.Println("INFO: encoder loading failed — Sliver init() would skip dictionary (BUG)")
	}

	fmt.Printf("\nEncoder WASM size: %d bytes\n", len(encoderWasm))

	if failed {
		fmt.Fprintf(os.Stderr, "\nFAIL: nested_wasm_sliver test failed\n")
		os.Exit(1)
	}
	fmt.Println("\nPASS: all nested_wasm_sliver tests passed")
}
