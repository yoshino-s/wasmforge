package build

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRewriteOpcodeConstants(t *testing.T) {
	// Create a temp file with sample instruction.go content.
	dir := t.TempDir()
	path := filepath.Join(dir, "instruction.go")

	content := `package wasm

type Opcode = byte

const (
	OpcodeUnreachable Opcode = 0x00
	OpcodeNop Opcode = 0x01
	OpcodeBlock Opcode = 0x02
	OpcodeI32Add Opcode = 0x6a
	// Bare constants (no Opcode type annotation) — must also be remapped.
	OpcodeRefNull = 0xd0
	OpcodeRefIsNull = 0xd1
	OpcodeRefFunc = 0xd2
	OpcodeMiscPrefix Opcode = 0xfc
)

type OpcodeTailCall = byte

const (
	OpcodeTailCallReturnCall         OpcodeTailCall = 0x12
	OpcodeTailCallReturnCallIndirect OpcodeTailCall = 0x13
)

type OpcodeMisc = byte

const (
	OpcodeMiscI32TruncSatF32S OpcodeMisc = 0x00
	OpcodeMiscI32TruncSatF32U OpcodeMisc = 0x01
)
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create a permutation that shifts everything by +1 (mod 256).
	var perm [256]byte
	for i := range perm {
		perm[i] = byte((i + 1) % 256)
	}

	if err := rewriteOpcodeConstants(path, perm); err != nil {
		t.Fatalf("rewriteOpcodeConstants: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	result := string(data)

	// Main opcodes should be shifted.
	if !strings.Contains(result, "OpcodeUnreachable Opcode = 0x01") {
		t.Error("OpcodeUnreachable not remapped to 0x01")
	}
	if !strings.Contains(result, "OpcodeNop Opcode = 0x02") {
		t.Error("OpcodeNop not remapped to 0x02")
	}
	if !strings.Contains(result, "OpcodeI32Add Opcode = 0x6B") {
		t.Error("OpcodeI32Add not remapped to 0x6B")
	}
	if !strings.Contains(result, "OpcodeMiscPrefix Opcode = 0xFD") {
		t.Error("OpcodeMiscPrefix not remapped to 0xFD")
	}

	// Bare constants (no type annotation) should also be remapped and gain the Opcode type.
	if !strings.Contains(result, "OpcodeRefNull Opcode = 0xD1") {
		t.Errorf("OpcodeRefNull not remapped to 0xD1; result:\n%s", result)
	}
	if !strings.Contains(result, "OpcodeRefIsNull Opcode = 0xD2") {
		t.Errorf("OpcodeRefIsNull not remapped to 0xD2; result:\n%s", result)
	}
	if !strings.Contains(result, "OpcodeRefFunc Opcode = 0xD3") {
		t.Errorf("OpcodeRefFunc not remapped to 0xD3; result:\n%s", result)
	}

	// OpcodeTailCall constants (main opcode namespace) should be remapped.
	// 0x12 → +1 → 0x13, 0x13 → +1 → 0x14
	if !strings.Contains(result, "OpcodeTailCallReturnCall Opcode = 0x13") {
		t.Errorf("OpcodeTailCallReturnCall not remapped to 0x13; result:\n%s", result)
	}
	if !strings.Contains(result, "OpcodeTailCallReturnCallIndirect Opcode = 0x14") {
		t.Errorf("OpcodeTailCallReturnCallIndirect not remapped to 0x14; result:\n%s", result)
	}

	// Sub-opcodes should NOT be changed.
	if !strings.Contains(result, "OpcodeMiscI32TruncSatF32S OpcodeMisc = 0x00") {
		t.Error("OpcodeMisc sub-opcode was incorrectly remapped")
	}
}

func TestRewriteMagicBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "header.go")

	content := `package binary

var Magic = []byte{0x00, 0x61, 0x73, 0x6D}
var version = []byte{0x01, 0x00, 0x00, 0x00}
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	magic := [4]byte{0xDE, 0xAD, 0xBE, 0xEF}
	if err := rewriteMagicBytes(path, magic); err != nil {
		t.Fatalf("rewriteMagicBytes: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	result := string(data)

	if !strings.Contains(result, "var Magic = []byte{0xDE, 0xAD, 0xBE, 0xEF}") {
		t.Error("Magic not rewritten")
	}
	// Version should be unchanged.
	if !strings.Contains(result, "var version = []byte{0x01, 0x00, 0x00, 0x00}") {
		t.Error("version was modified")
	}
}

func TestRewriteSectionIDs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "module.go")

	content := `package wasm

type SectionID = byte

const (
	// SectionIDCustom includes the standard defined NameSection.
	SectionIDCustom SectionID = iota // don't add anything not in spec
	SectionIDType
	SectionIDImport
	SectionIDFunction
	SectionIDTable
	SectionIDMemory
	SectionIDGlobal
	SectionIDExport
	SectionIDStart
	SectionIDElement
	SectionIDCode
	SectionIDData

	// SectionIDDataCount may exist in WebAssembly 2.0.
	//
	// See https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/binary/modules.html#data-count-section
	// See https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/appendix/changes.html#bulk-memory-and-table-instructions
	SectionIDDataCount
)

func SectionIDName(sectionID SectionID) string {
	switch sectionID {
	case SectionIDCustom:
		return "custom"
	}
	return ""
}
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// Order-preserving map: values ascending.
	sectionMap := [13]byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0}

	if err := rewriteSectionIDs(path, sectionMap); err != nil {
		t.Fatalf("rewriteSectionIDs: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	result := string(data)

	// Verify each section ID has explicit value.
	if !strings.Contains(result, "SectionIDCustom SectionID = 0x10") {
		t.Error("SectionIDCustom not rewritten")
	}
	if !strings.Contains(result, "SectionIDType SectionID = 0x20") {
		t.Error("SectionIDType not rewritten")
	}
	if !strings.Contains(result, "SectionIDCode SectionID = 0xB0") {
		t.Error("SectionIDCode not rewritten")
	}
	if !strings.Contains(result, "SectionIDDataCount SectionID = 0xD0") {
		t.Error("SectionIDDataCount not rewritten")
	}

	// Verify iota is gone.
	if strings.Contains(result, "iota") {
		t.Error("iota still present after rewrite")
	}

	// Verify the switch statement still compiles (uses named constants).
	if !strings.Contains(result, "case SectionIDCustom:") {
		t.Error("switch statement damaged")
	}
}

func TestFixOpcodeCollisions(t *testing.T) {
	// The mixed switch statements in module.go and store.go contain:
	//   case OpcodeI32Const:      (0x41, permuted)
	//   case OpcodeI64Const:      (0x42, permuted)
	//   case OpcodeF32Const:      (0x43, permuted)
	//   case OpcodeF64Const:      (0x44, permuted)
	//   case OpcodeGlobalGet:     (0x23, permuted)
	//   case OpcodeRefNull:       (0xD0, permuted)
	//   case OpcodeRefFunc:       (0xD2, permuted)
	//   case OpcodeVecV128Const:  (0x0C, NOT permuted)
	//
	// If any permuted main opcode maps to 0x0C, the Go compiler rejects
	// the duplicate case. fixOpcodeCollisions must prevent this.

	mixedOpcodes := []byte{0x23, 0x41, 0x42, 0x43, 0x44, 0xD0, 0xD2}

	t.Run("forced_collision", func(t *testing.T) {
		// Create a permutation that maps OpcodeF64Const (0x44) to 0x0C.
		var perm [256]byte
		for i := range perm {
			perm[i] = byte(i) // identity
		}
		// Swap so perm[0x44] = 0x0C and perm[0x0C] = 0x44.
		perm[0x44], perm[0x0C] = perm[0x0C], perm[0x44]

		fixOpcodeCollisions(&perm)

		// After fix, no mixed opcode should map to 0x0C.
		for _, orig := range mixedOpcodes {
			if perm[orig] == 0x0C {
				t.Errorf("perm[0x%02X] = 0x0C after fixOpcodeCollisions", orig)
			}
		}
		// Permutation must still be bijective.
		var seen [256]bool
		for _, v := range perm {
			if seen[v] {
				t.Fatalf("permutation not bijective: duplicate value 0x%02X", v)
			}
			seen[v] = true
		}
	})

	t.Run("1000_random_permutations", func(t *testing.T) {
		for trial := 0; trial < 1000; trial++ {
			pc, err := newPolyConfig("")
			if err != nil {
				t.Fatalf("trial %d: newPolyConfig: %v", trial, err)
			}
			for _, orig := range mixedOpcodes {
				if pc.OpcodePermutation[orig] == 0x0C {
					t.Fatalf("trial %d: perm[0x%02X] = 0x0C — collision not fixed",
						trial, orig)
				}
			}
		}
	})
}

func TestCopyWazeroFork_Integration(t *testing.T) {
	// This test copies the actual wazero fork and rewrites it.
	// Skip if wazero fork doesn't exist.
	wazeroSrc := filepath.Join("..", "..", "..", "wazero")
	if _, err := os.Stat(filepath.Join(wazeroSrc, "go.mod")); err != nil {
		t.Skipf("wazero fork not found at %s: %v", wazeroSrc, err)
	}

	pc, err := newPolyConfig("")
	if err != nil {
		t.Fatalf("newPolyConfig: %v", err)
	}

	dstDir := t.TempDir()
	if err := copyWazeroFork(wazeroSrc, dstDir, pc); err != nil {
		t.Fatalf("copyWazeroFork: %v", err)
	}

	// Verify instruction.go was rewritten (no standard 0x00 for OpcodeUnreachable
	// unless the permutation happens to map 0→0, which is 1/256 chance).
	instrFile := filepath.Join(dstDir, "internal", "wasm", "instruction.go")
	instrData, err := os.ReadFile(instrFile)
	if err != nil {
		t.Fatalf("reading rewritten instruction.go: %v", err)
	}
	instrContent := string(instrData)
	if !strings.Contains(instrContent, "Opcode = 0x") {
		t.Error("instruction.go: no rewritten opcode constants found")
	}

	// Verify header.go was rewritten.
	headerFile := filepath.Join(dstDir, "internal", "wasm", "binary", "header.go")
	headerData, err := os.ReadFile(headerFile)
	if err != nil {
		t.Fatalf("reading rewritten header.go: %v", err)
	}
	if strings.Contains(string(headerData), "0x00, 0x61, 0x73, 0x6D") {
		t.Error("header.go: standard magic bytes still present")
	}

	// Verify module.go was rewritten.
	moduleFile := filepath.Join(dstDir, "internal", "wasm", "module.go")
	moduleData, err := os.ReadFile(moduleFile)
	if err != nil {
		t.Fatalf("reading rewritten module.go: %v", err)
	}
	if strings.Contains(string(moduleData), "iota") {
		t.Error("module.go: iota still present")
	}

	// Verify go.mod was copied.
	if _, err := os.Stat(filepath.Join(dstDir, "go.mod")); err != nil {
		t.Error("go.mod not copied")
	}
}
