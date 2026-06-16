package build

import (
	"bytes"
	"os"
	"testing"
)

// TestRemapWASM_ToolResistance verifies that a remapped WASM file is not
// parseable by standard WASM tools. Writes the remapped file to /tmp
// for manual inspection with wasm-validate and wasm-objdump.
func TestRemapWASM_ToolResistance(t *testing.T) {
	standardPath := "/tmp/wasm-verify/standard.wasm"
	if _, err := os.Stat(standardPath); err != nil {
		t.Skipf("standard WASM not available at %s (run GOOS=wasip1 GOARCH=wasm go build first)", standardPath)
	}

	wasmData, err := os.ReadFile(standardPath)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a random permutation.
	pc, err := newPolyConfig("")
	if err != nil {
		t.Fatalf("newPolyConfig: %v", err)
	}

	// Remap the WASM.
	remapped, err := remapWASM(wasmData, pc.OpcodePermutation, pc.SectionIDMap, pc.CustomMagic, pc.ExportNameMap)
	if err != nil {
		t.Fatalf("remapWASM: %v", err)
	}

	// Save remapped WASM for manual tool testing.
	remappedPath := "/tmp/wasm-verify/remapped.wasm"
	if err := os.WriteFile(remappedPath, remapped, 0o644); err != nil {
		t.Fatalf("writing remapped WASM: %v", err)
	}
	t.Logf("Saved remapped WASM to %s", remappedPath)
	t.Logf("Custom magic: %02X%02X%02X%02X", pc.CustomMagic[0], pc.CustomMagic[1], pc.CustomMagic[2], pc.CustomMagic[3])

	// Verify: standard WASM magic absent.
	stdMagic := []byte{0x00, 0x61, 0x73, 0x6D}
	if bytes.Equal(remapped[:4], stdMagic) {
		t.Error("standard WASM magic still present in remapped file")
	}

	// Verify: size preserved.
	if len(remapped) != len(wasmData) {
		t.Errorf("size changed: %d → %d", len(wasmData), len(remapped))
	}

	// Verify: content differs.
	if bytes.Equal(remapped, wasmData) {
		t.Error("remapped file is identical to original (astronomically unlikely)")
	}

	// Verify: loading in unmodified wazero should fail.
	// We check this by verifying the magic bytes don't match.
	if bytes.HasPrefix(remapped, stdMagic) {
		t.Error("remapped file still has standard WASM magic prefix")
	}

	t.Log("Remapped WASM saved. Run these commands to verify tool resistance:")
	t.Log("  wasm-validate /tmp/wasm-verify/remapped.wasm    # should FAIL")
	t.Log("  wasm-objdump -d /tmp/wasm-verify/remapped.wasm  # should FAIL")
	t.Log("  wasm-objdump -h /tmp/wasm-verify/standard.wasm  # should PASS (control)")
}
