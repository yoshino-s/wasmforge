package build

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// forbiddenStrings are substrings that MUST NOT appear in the output binary.
// These are OPSEC-critical strings that directly identify the technology or
// organization. Generic Go patterns (compiler, opcode, compress, etc.) are
// intentionally ALLOWED — they help ML classifiers recognize the binary as
// legitimate software. See vt-batch-2026-03-19 memory for evidence.
var forbiddenStrings = []string{
	// WASM engine identity — directly identifies the technology
	"wasm",
	"wasi",
	"wazero",
	"wazevo",

	// WASM-specific encoding (unique to WASM, not generic Go)
	"leb128",

	// WASM ecosystems (identifies WASM toolchain)
	"emscripten",
	"assemblyscript",

	// Praetorian identity
	"praetorian",
	"wasmforge",
}

// TestForbiddenStrings_OutputBinary builds a real Windows PE binary via the
// full WasmForge pipeline and scans it for forbidden strings. The test is
// skipped unless WASMFORGE_FORBIDDEN_TEST=1 is set (requires full build ~30s).
//
// Run with:
//
//	WASMFORGE_FORBIDDEN_TEST=1 GOWORK=off go test ./internal/build/ -run TestForbiddenStrings -v -timeout 120s
func TestForbiddenStrings_OutputBinary(t *testing.T) {
	if os.Getenv("WASMFORGE_FORBIDDEN_TEST") != "1" {
		t.Skip("set WASMFORGE_FORBIDDEN_TEST=1 to enable (requires full build, ~30s)")
	}

	// Build wasmforge binary.
	wasmforgeBin := t.TempDir() + "/wasmforge"
	buildWF := exec.Command("go", "build", "-o", wasmforgeBin, "./cmd/wasmforge")
	buildWF.Dir = findModuleRoot()
	buildWF.Env = append(os.Environ(), "GOWORK=off")
	if out, err := buildWF.CombinedOutput(); err != nil {
		t.Fatalf("building wasmforge: %v\n%s", err, out)
	}

	// Build a test Windows PE binary.
	outputBin := t.TempDir() + "/test-forbidden.exe"
	moduleRoot := findModuleRoot()
	buildTest := exec.Command(wasmforgeBin, "build",
		"--win32-apis", "--no-sign",
		"-o", outputBin,
		moduleRoot+"/testdata/win32_registry")
	buildTest.Env = append(os.Environ(),
		"GOWORK=off",
		"GOOS=windows",
		"GOARCH=amd64",
	)
	if out, err := buildTest.CombinedOutput(); err != nil {
		t.Fatalf("building test binary: %v\n%s", err, out)
	}

	binData, err := os.ReadFile(outputBin)
	if err != nil {
		t.Fatalf("reading output binary: %v", err)
	}
	t.Logf("Output binary: %s (%d bytes)", outputBin, len(binData))

	// Phase 1: strings output — every printable string in the binary.
	stringsCmd := exec.Command("strings", outputBin)
	stringsOut, err := stringsCmd.Output()
	if err != nil {
		t.Fatalf("running strings: %v", err)
	}

	t.Run("strings", func(t *testing.T) {
		for _, forbidden := range forbiddenStrings {
			lower := strings.ToLower(forbidden)
			for _, line := range strings.Split(string(stringsOut), "\n") {
				if strings.Contains(strings.ToLower(line), lower) {
					t.Errorf("FORBIDDEN %q found: %s", forbidden, strings.TrimSpace(line))
				}
			}
		}
	})

	// Phase 2: gopclntab — function names, source paths, type names.
	t.Run("gopclntab", func(t *testing.T) {
		objdumpCmd := exec.Command("go", "tool", "objdump", outputBin)
		objdumpOut, err := objdumpCmd.Output()
		if err != nil {
			t.Skipf("go tool objdump failed: %v", err)
		}

		for _, forbidden := range forbiddenStrings {
			lower := strings.ToLower(forbidden)
			for _, line := range strings.Split(string(objdumpOut), "\n") {
				if strings.HasPrefix(line, "TEXT ") && strings.Contains(strings.ToLower(line), lower) {
					t.Errorf("FORBIDDEN in gopclntab %q: %s", forbidden, strings.TrimSpace(line))
				}
			}
		}
	})

	// Phase 3: raw binary scan — catches strings shorter than 4 chars
	// that `strings` might miss, and encoded/concatenated values.
	t.Run("raw_bytes", func(t *testing.T) {
		critical := []string{
			"wasmforge",
			"praetorian",
			"wazero",
			"wasi_snapshot_preview1",
		}
		binLower := bytes.ToLower(binData)
		for _, pat := range critical {
			if bytes.Contains(binLower, []byte(strings.ToLower(pat))) {
				t.Errorf("FORBIDDEN byte pattern %q in raw binary", pat)
			}
		}
	})
}
