package build

import (
	"bytes"
	"testing"
)

// buildMiniWASM constructs a minimal valid WASM binary with a code section
// containing a single function: (func (result i32) i32.const 42 end).
func buildMiniWASM() []byte {
	var buf bytes.Buffer

	// Magic + version.
	buf.Write([]byte{0x00, 0x61, 0x73, 0x6D}) // \0asm
	buf.Write([]byte{0x01, 0x00, 0x00, 0x00}) // version 1

	// Type section (ID=1): one type entry: () -> (i32)
	buf.WriteByte(0x01)                                     // section ID
	buf.Write([]byte{0x05})                                 // section size = 5
	buf.WriteByte(0x01)                                     // num types = 1
	buf.Write([]byte{0x60, 0x00, 0x01, 0x7F})              // func () -> (i32)

	// Function section (ID=3): one function using type 0
	buf.WriteByte(0x03) // section ID
	buf.Write([]byte{0x02}) // section size = 2
	buf.WriteByte(0x01) // num functions = 1
	buf.WriteByte(0x00) // type index 0

	// Code section (ID=10): one function body
	// Body: 0 locals, i32.const 42, end
	// Body bytes: [0x00, 0x41, 0x2A, 0x0B] = 4 bytes
	buf.WriteByte(0x0A) // section ID = code
	buf.Write([]byte{0x06}) // section size = 6
	buf.WriteByte(0x01) // num functions = 1
	buf.Write([]byte{0x04}) // body size = 4
	buf.WriteByte(0x00) // 0 local declarations
	buf.WriteByte(0x41) // i32.const
	buf.WriteByte(0x2A) // 42 (LEB128)
	buf.WriteByte(0x0B) // end

	return buf.Bytes()
}

func TestRemapWASM_MagicReplaced(t *testing.T) {
	wasm := buildMiniWASM()
	perm := identityPermutation()
	sectionMap := identitySectionMap()
	magic := [4]byte{0xDE, 0xAD, 0xBE, 0xEF}

	out, err := remapWASM(wasm, perm, sectionMap, magic, nil)
	if err != nil {
		t.Fatalf("remapWASM: %v", err)
	}

	// Magic bytes replaced.
	if !bytes.Equal(out[:4], magic[:]) {
		t.Errorf("magic: got %x, want %x", out[:4], magic[:])
	}

	// Version unchanged.
	if !bytes.Equal(out[4:8], []byte{0x01, 0x00, 0x00, 0x00}) {
		t.Errorf("version: got %x, want 01000000", out[4:8])
	}
}

func TestRemapWASM_SectionIDsRemapped(t *testing.T) {
	wasm := buildMiniWASM()
	perm := identityPermutation()
	magic := [4]byte{0x00, 0x61, 0x73, 0x6D} // keep original magic

	// Custom section ID map: shift each by +0x80 while preserving order.
	sectionMap := [13]byte{0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C}

	out, err := remapWASM(wasm, perm, sectionMap, magic, nil)
	if err != nil {
		t.Fatalf("remapWASM: %v", err)
	}

	// Section IDs should be remapped.
	// Type section: original ID=1 → 0x81
	if out[8] != 0x81 {
		t.Errorf("type section ID: got 0x%02X, want 0x81", out[8])
	}
}

func TestRemapWASM_OpcodesRemapped(t *testing.T) {
	wasm := buildMiniWASM()
	sectionMap := identitySectionMap()
	magic := [4]byte{0x00, 0x61, 0x73, 0x6D}

	// Create a non-identity permutation: swap 0x41 (i32.const) and 0xFF.
	perm := identityPermutation()
	perm[0x41], perm[0xFF] = perm[0xFF], perm[0x41]
	// Also remap 0x0B (end) to 0xAA.
	perm[0x0B], perm[0xAA] = perm[0xAA], perm[0x0B]

	out, err := remapWASM(wasm, perm, sectionMap, magic, nil)
	if err != nil {
		t.Fatalf("remapWASM: %v", err)
	}

	// Find the code section body in output.
	// Structure: magic(4) + version(4) + type_section(7) + func_section(4) + code_section_header(3) + body
	// Type section: ID(1) + size(1) + payload(5) = 7 bytes at offset 8
	// Func section: ID(1) + size(1) + payload(2) = 4 bytes at offset 15
	// Code section: ID(1) + size(1) + num_funcs(1) + body_size(1) + locals(1) + instructions...
	// Code section starts at offset 19: ID=0x0A, size=0x06, num=0x01, bodysize=0x04, locals=0x00
	// Instructions start at offset 24: i32.const, 42, end

	codeBodyStart := 24 // instruction start within the code section body
	i32constByte := out[codeBodyStart]
	immediateByte := out[codeBodyStart+1]
	endByte := out[codeBodyStart+2]

	// i32.const (0x41) should be remapped to 0xFF.
	if i32constByte != 0xFF {
		t.Errorf("i32.const opcode: got 0x%02X, want 0xFF", i32constByte)
	}

	// The immediate value 42 (0x2A) must NOT be remapped.
	if immediateByte != 0x2A {
		t.Errorf("i32.const immediate: got 0x%02X, want 0x2A (42)", immediateByte)
	}

	// end (0x0B) should be remapped to 0xAA.
	if endByte != 0xAA {
		t.Errorf("end opcode: got 0x%02X, want 0xAA", endByte)
	}
}

func TestRemapWASM_SizePreserved(t *testing.T) {
	wasm := buildMiniWASM()
	perm := identityPermutation()
	sectionMap := identitySectionMap()
	magic := [4]byte{0xDE, 0xAD, 0xBE, 0xEF}

	out, err := remapWASM(wasm, perm, sectionMap, magic, nil)
	if err != nil {
		t.Fatalf("remapWASM: %v", err)
	}

	if len(out) != len(wasm) {
		t.Errorf("output size %d != input size %d", len(out), len(wasm))
	}
}

func TestRemapWASM_IdentityPermutation(t *testing.T) {
	wasm := buildMiniWASM()
	perm := identityPermutation()
	sectionMap := identitySectionMap()
	magic := [4]byte{0x00, 0x61, 0x73, 0x6D} // standard magic

	out, err := remapWASM(wasm, perm, sectionMap, magic, nil)
	if err != nil {
		t.Fatalf("remapWASM: %v", err)
	}

	// With identity permutation and standard magic, output == input.
	if !bytes.Equal(out, wasm) {
		t.Errorf("identity permutation should produce identical output")
		for i := range out {
			if out[i] != wasm[i] {
				t.Errorf("  byte %d: got 0x%02X, want 0x%02X", i, out[i], wasm[i])
			}
		}
	}
}

func TestRemapWASM_LoadStoreImmediatesPreserved(t *testing.T) {
	// Build a WASM with a function that does: i32.load offset=100 align=2
	var buf bytes.Buffer

	// Magic + version.
	buf.Write([]byte{0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00})

	// Type section: (func (param i32) (result i32))
	buf.WriteByte(0x01)
	buf.Write([]byte{0x06})
	buf.WriteByte(0x01)
	buf.Write([]byte{0x60, 0x01, 0x7F, 0x01, 0x7F})

	// Function section
	buf.WriteByte(0x03)
	buf.Write([]byte{0x02})
	buf.WriteByte(0x01)
	buf.WriteByte(0x00)

	// Memory section (ID=5): 1 memory with min=1 page
	buf.WriteByte(0x05)
	buf.Write([]byte{0x03})
	buf.WriteByte(0x01)        // 1 memory
	buf.Write([]byte{0x00, 0x01}) // limits: no max, min=1

	// Code section: (func (param i32) (result i32) local.get 0 i32.load align=2 offset=100 end)
	// i32.load (0x28) takes two LEB128 immediates: align, offset.
	// align=2 → LEB128 [0x02], offset=100 → LEB128 [0x64]
	bodyBytes := []byte{
		0x00,       // 0 local declarations
		0x20, 0x00, // local.get 0
		0x28, 0x02, 0x64, // i32.load align=2 offset=100
		0x0B, // end
	}

	buf.WriteByte(0x0A) // code section ID
	sectionPayload := []byte{0x01}                 // 1 function
	sectionPayload = append(sectionPayload, byte(len(bodyBytes))) // body size
	sectionPayload = append(sectionPayload, bodyBytes...)
	buf.WriteByte(byte(len(sectionPayload))) // section size
	buf.Write(sectionPayload)

	wasm := buf.Bytes()

	// Create a permutation that swaps i32.load (0x28) with 0xF0.
	perm := identityPermutation()
	perm[0x28], perm[0xF0] = perm[0xF0], perm[0x28]

	out, err := remapWASM(wasm, perm, identitySectionMap(), [4]byte{0x00, 0x61, 0x73, 0x6D}, nil)
	if err != nil {
		t.Fatalf("remapWASM: %v", err)
	}

	// Find the i32.load instruction in output.
	// The opcode should be remapped but the align and offset immediates must be preserved.
	found := false
	for i := 0; i < len(out)-2; i++ {
		if out[i] == 0xF0 && out[i+1] == 0x02 && out[i+2] == 0x64 {
			found = true
			break
		}
	}
	if !found {
		t.Error("i32.load opcode not remapped to 0xF0, or align/offset immediates corrupted")
	}
}

func TestRemapWASM_RandomPermutation(t *testing.T) {
	wasm := buildMiniWASM()

	// Generate a real random permutation.
	pc, err := newPolyConfig("")
	if err != nil {
		t.Fatalf("newPolyConfig: %v", err)
	}

	out, err := remapWASM(wasm, pc.OpcodePermutation, pc.SectionIDMap, pc.CustomMagic, nil)
	if err != nil {
		t.Fatalf("remapWASM: %v", err)
	}

	// Output should differ from input (overwhelmingly likely with random perm).
	if bytes.Equal(out, wasm) {
		t.Error("random permutation produced identical output (astronomically unlikely)")
	}

	// Standard magic should be absent.
	if bytes.Contains(out[:4], []byte{0x00, 0x61, 0x73, 0x6D}) {
		t.Error("standard WASM magic still present after remapping")
	}

	// Size must be preserved.
	if len(out) != len(wasm) {
		t.Errorf("output size %d != input size %d", len(out), len(wasm))
	}
}

// ──────────────────────────────────────────────────────────────────────
// Export name randomization tests
// ──────────────────────────────────────────────────────────────────────

// buildWASMWithImport constructs a minimal WASM binary with one import
// from the given module/field as a function import (type 0).
func buildWASMWithImport(module, field string) []byte {
	var buf bytes.Buffer

	// Magic + version.
	buf.Write([]byte{0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00})

	// Type section (ID=1): one type entry: () -> ()
	typeSec := []byte{0x01, 0x60, 0x00, 0x00} // 1 type, func, 0 params, 0 results
	buf.WriteByte(0x01)
	buf.WriteByte(byte(len(typeSec)))
	buf.Write(typeSec)

	// Import section (ID=2): one import.
	modBytes := []byte(module)
	fieldBytes := []byte(field)
	var impBuf bytes.Buffer
	impBuf.WriteByte(0x01) // 1 import
	impBuf.Write(encodeLEB128u(uint64(len(modBytes))))
	impBuf.Write(modBytes)
	impBuf.Write(encodeLEB128u(uint64(len(fieldBytes))))
	impBuf.Write(fieldBytes)
	impBuf.WriteByte(0x00) // kind: function
	impBuf.WriteByte(0x00) // type index 0

	buf.WriteByte(0x02)
	buf.Write(encodeLEB128u(uint64(impBuf.Len())))
	buf.Write(impBuf.Bytes())

	return buf.Bytes()
}

// extractImportField scans a remapped WASM binary's import section and
// returns the field name of the first import found.
func extractImportField(data []byte) (string, bool) {
	if len(data) < 8 {
		return "", false
	}
	pos := 8 // skip magic + version
	for pos < len(data) {
		sectionID := data[pos]
		pos++
		size, n, err := readLEB128u(data, pos)
		if err != nil {
			return "", false
		}
		pos += n
		end := pos + int(size)

		if sectionID == 2 { // import section
			count, n, err := readLEB128u(data, pos)
			if err != nil || count == 0 {
				return "", false
			}
			pos += n
			// Read module string.
			modLen, n, err := readLEB128u(data, pos)
			if err != nil {
				return "", false
			}
			pos += n + int(modLen)
			// Read field string.
			fieldLen, n, err := readLEB128u(data, pos)
			if err != nil {
				return "", false
			}
			pos += n
			field := string(data[pos : pos+int(fieldLen)])
			return field, true
		}
		pos = end
	}
	return "", false
}

func TestGenerateExportNameMap_AllNamesUnique(t *testing.T) {
	m, err := generateExportNameMap(nil, make(map[string]bool))
	if err != nil {
		t.Fatalf("generateExportNameMap: %v", err)
	}

	// All values must be unique.
	seen := make(map[string]string)
	for old, new_ := range m {
		if prev, ok := seen[new_]; ok {
			t.Errorf("duplicate random name %q assigned to both %q and %q", new_, prev, old)
		}
		seen[new_] = old
	}

	// Must cover all known export names.
	if len(m) != len(exportedAnonymizedNames) {
		t.Errorf("got %d mappings, want %d", len(m), len(exportedAnonymizedNames))
	}

	// Each key must be a known export name.
	knownSet := make(map[string]bool, len(exportedAnonymizedNames))
	for _, n := range exportedAnonymizedNames {
		knownSet[n] = true
	}
	for old := range m {
		if !knownSet[old] {
			t.Errorf("unexpected key in ExportNameMap: %q", old)
		}
	}
}

func TestGenerateExportNameMap_DifferentBuilds(t *testing.T) {
	m1, err := generateExportNameMap(nil, make(map[string]bool))
	if err != nil {
		t.Fatalf("first generateExportNameMap: %v", err)
	}
	m2, err := generateExportNameMap(nil, make(map[string]bool))
	if err != nil {
		t.Fatalf("second generateExportNameMap: %v", err)
	}

	// With crypto/rand, two independent calls must produce different mappings
	// (probability of identical mapping is astronomically low).
	identical := true
	for k, v1 := range m1 {
		if v2, ok := m2[k]; !ok || v1 != v2 {
			identical = false
			break
		}
	}
	if identical {
		t.Error("two calls to generateExportNameMap produced identical mappings (astronomically unlikely)")
	}
}

func TestRemapWASM_ImportSectionFieldRenamed(t *testing.T) {
	// Build a WASM with one import from env/fd_read2.
	wasm := buildWASMWithImport("env", "fd_read2")
	perm := identityPermutation()
	sectionMap := identitySectionMap()
	magic := [4]byte{0x00, 0x61, 0x73, 0x6D}

	exportNames := map[string]string{
		"fd_read2": "a7_bx3",
	}

	out, err := remapWASM(wasm, perm, sectionMap, magic, exportNames)
	if err != nil {
		t.Fatalf("remapWASM: %v", err)
	}

	field, ok := extractImportField(out)
	if !ok {
		t.Fatal("could not extract import field from remapped WASM")
	}
	if field != "a7_bx3" {
		t.Errorf("import field: got %q, want %q", field, "a7_bx3")
	}
}

func TestRemapWASM_ImportSectionNilMapPassthrough(t *testing.T) {
	// nil exportNames must leave field names unchanged.
	wasm := buildWASMWithImport("env", "fd_read2")
	perm := identityPermutation()
	sectionMap := identitySectionMap()
	magic := [4]byte{0x00, 0x61, 0x73, 0x6D}

	out, err := remapWASM(wasm, perm, sectionMap, magic, nil)
	if err != nil {
		t.Fatalf("remapWASM: %v", err)
	}

	field, ok := extractImportField(out)
	if !ok {
		t.Fatal("could not extract import field from remapped WASM")
	}
	if field != "fd_read2" {
		t.Errorf("import field: got %q, want %q", field, "fd_read2")
	}
}

func TestRemapWASM_NonEnvImportNotRenamed(t *testing.T) {
	// Imports from non-"env" modules must NOT be renamed.
	wasm := buildWASMWithImport("wasi_snapshot_preview1", "fd_read2")
	perm := identityPermutation()
	sectionMap := identitySectionMap()
	magic := [4]byte{0x00, 0x61, 0x73, 0x6D}

	exportNames := map[string]string{
		"fd_read2": "a7_bx3",
	}

	out, err := remapWASM(wasm, perm, sectionMap, magic, exportNames)
	if err != nil {
		t.Fatalf("remapWASM: %v", err)
	}

	field, ok := extractImportField(out)
	if !ok {
		t.Fatal("could not extract import field from remapped WASM")
	}
	if field != "fd_read2" {
		t.Errorf("non-env import field should not be renamed: got %q, want %q", field, "fd_read2")
	}
}

func TestRemapWASM_ModuleNameEnvPreserved(t *testing.T) {
	// The module name "env" itself must not change — only field names change.
	wasm := buildWASMWithImport("env", "fd_read2")
	perm := identityPermutation()
	sectionMap := identitySectionMap()
	magic := [4]byte{0x00, 0x61, 0x73, 0x6D}

	exportNames := map[string]string{"fd_read2": "q9_xyz"}

	out, err := remapWASM(wasm, perm, sectionMap, magic, exportNames)
	if err != nil {
		t.Fatalf("remapWASM: %v", err)
	}

	// "env" must still be present somewhere in the import section.
	if !bytes.Contains(out, []byte("env")) {
		t.Error("module name 'env' missing from remapped WASM")
	}
}

func TestGenerateExportNameMap_WordList(t *testing.T) {
	m, err := generateExportNameMap(nil, make(map[string]bool))
	if err != nil {
		t.Fatalf("generateExportNameMap: %v", err)
	}

	// Verify all anonymized names get mapped.
	if len(m) != len(exportedAnonymizedNames) {
		t.Errorf("expected %d entries, got %d", len(exportedAnonymizedNames), len(m))
	}

	// Verify uniqueness of generated names.
	seen := make(map[string]bool)
	for orig, newName := range m {
		if newName == "" {
			t.Errorf("empty name for %q", orig)
		}
		if seen[newName] {
			t.Errorf("duplicate generated name %q", newName)
		}
		seen[newName] = true
		// Names from wordList should be camelCase (start with lowercase letter).
		if newName[0] < 'a' || newName[0] > 'z' {
			t.Errorf("name %q: should start with lowercase letter", newName)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────
// Test helpers
// ──────────────────────────────────────────────────────────────────────

func identityPermutation() [256]byte {
	var perm [256]byte
	for i := range perm {
		perm[i] = byte(i)
	}
	return perm
}

func identitySectionMap() [13]byte {
	var m [13]byte
	for i := range m {
		m[i] = byte(i)
	}
	return m
}
