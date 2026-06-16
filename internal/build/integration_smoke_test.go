//go:build integration

package build

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestHelloWorldRoundtrip_20Iterations builds testdata/baseline_controls/hello_world
// 20 times via the wasmforge binary and asserts each execution prints
// "Hello, World!". This test is gated by the "integration" build tag so the
// default go test ./... run stays fast.
//
// Prerequisites:
//   - wasmforge binary at /tmp/wasmforge or accessible via PATH
//   - testdata/baseline_controls/hello_world/main.go present
//
// Run with:
//
//	GOWORK=off go test -tags integration ./internal/build/ -run TestHelloWorldRoundtrip_20Iterations
func TestHelloWorldRoundtrip_20Iterations(t *testing.T) {
	// Locate the wasmforge binary.
	wasmforgeBin := "/tmp/wasmforge"
	if _, err := os.Stat(wasmforgeBin); err != nil {
		// Fall back to PATH lookup.
		found, lookErr := exec.LookPath("wasmforge")
		if lookErr != nil {
			t.Skip("wasmforge binary not found at /tmp/wasmforge and not in PATH; build it first: GOWORK=off go build -o /tmp/wasmforge ./cmd/wasmforge")
		}
		wasmforgeBin = found
	}

	// Locate hello_world testdata.
	helloSrc := filepath.Join("..", "..", "testdata", "baseline_controls", "hello_world")
	if _, err := os.Stat(filepath.Join(helloSrc, "main.go")); err != nil {
		t.Skipf("testdata/baseline_controls/hello_world/main.go not found: %v", err)
	}

	const iterations = 20
	for i := 0; i < iterations; i++ {
		t.Run(fmt.Sprintf("iter_%02d", i), func(t *testing.T) {
			outDir := t.TempDir()
			outBin := filepath.Join(outDir, "hello_world")

			// Build hello_world through the full wasmforge pipeline.
			buildCmd := exec.Command(wasmforgeBin, "build", "-o", outBin, ".")
			buildCmd.Dir = helloSrc
			if output, err := buildCmd.CombinedOutput(); err != nil {
				t.Fatalf("wasmforge build failed (iter %d): %v\n%s", i, err, output)
			}

			// Execute the produced binary and check output.
			runOutput, err := exec.Command(outBin).Output()
			if err != nil {
				t.Fatalf("binary execution failed (iter %d): %v", i, err)
			}
			if !strings.Contains(string(runOutput), "Hello, World!") {
				t.Errorf("iter %d: unexpected output: %q (want string containing \"Hello, World!\")", i, string(runOutput))
			}
		})
	}
}
