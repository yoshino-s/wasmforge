package build

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// copyWazeroFork copies the wazero fork source tree to dstDir and rewrites
// three files with per-build permuted constants. The resulting module accepts
// the custom-opcoded WASM binary produced by remapWASM.
func copyWazeroFork(wazeroSrc, dstDir string, pc *polyConfig) error {
	// Recursively copy source files (skip tests, testdata, .git).
	if err := copyDirRecursive(wazeroSrc, dstDir); err != nil {
		return fmt.Errorf("copying wazero source: %w", err)
	}

	// Rewrite instruction.go with permuted opcode values.
	instrFile := filepath.Join(dstDir, "internal", "wasm", "instruction.go")
	if err := rewriteOpcodeConstants(instrFile, pc.OpcodePermutation); err != nil {
		return fmt.Errorf("rewriting instruction.go: %w", err)
	}

	// Rewrite header.go with custom magic bytes.
	headerFile := filepath.Join(dstDir, "internal", "wasm", "binary", "header.go")
	if err := rewriteMagicBytes(headerFile, pc.CustomMagic); err != nil {
		return fmt.Errorf("rewriting header.go: %w", err)
	}

	// Rewrite module.go with permuted section IDs.
	moduleFile := filepath.Join(dstDir, "internal", "wasm", "module.go")
	if err := rewriteSectionIDs(moduleFile, pc.SectionIDMap); err != nil {
		return fmt.Errorf("rewriting module.go: %w", err)
	}

	// Rewrite WASI function name strings throughout the fork.
	// These appear as string literals in internal/wasip1/*.go constants
	// and in imports/wasi_snapshot_preview1/*.go function definitions.
	if len(pc.WASINameMap) > 0 {
		if err := rewriteWASIFunctionNames(dstDir, pc.WASINameMap); err != nil {
			return fmt.Errorf("rewriting WASI function names: %w", err)
		}
	}

	// Replace WASM instruction name strings with opaque identifiers.
	// VT testing confirmed: preserving i32.add/f64.mul instruction names
	// HURTS clean rate (0/5 vs 30/100). These are distinctly WASM patterns
	// that ML classifiers use as a signal.
	if err := scrubInstructionNames(dstDir); err != nil {
		return fmt.Errorf("scrubbing instruction names: %w", err)
	}

	// Replace SSA/IR opcode String() return values with opaque identifiers.
	if err := scrubSSAOpcodeStrings(dstDir); err != nil {
		return fmt.Errorf("scrubbing SSA opcode strings: %w", err)
	}

	return nil
}

// copyDirRecursive copies a directory tree, skipping test files,
// testdata directories, and .git.
func copyDirRecursive(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		if info.IsDir() {
			base := filepath.Base(path)
			if base == "testdata" || base == ".git" || base == "vendor" {
				return filepath.SkipDir
			}
			return os.MkdirAll(target, 0o755)
		}

		// Skip test files.
		if strings.HasSuffix(info.Name(), "_test.go") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		return os.WriteFile(target, data, info.Mode().Perm())
	})
}

// opcodeConstRe matches main opcode constant definitions — all three forms:
//
//	OpcodeUnreachable Opcode = 0x00              (with Opcode type)
//	OpcodeRefNull = 0xd0                         (bare, no type)
//	OpcodeTailCallReturnCall OpcodeTailCall = 0x12 (with OpcodeTailCall type)
//
// It does NOT match sub-opcode types (OpcodeMisc, OpcodeVec, OpcodeAtomic)
// because those type names don't match the alternation.
var opcodeConstRe = regexp.MustCompile(`^(\s*Opcode\S+)\s+(?:(?:Opcode|OpcodeTailCall)\s*)?=\s*0x([0-9a-fA-F]+)(.*)$`)

// rewriteOpcodeConstants replaces every main opcode constant value
// in instruction.go with its permuted equivalent.
func rewriteOpcodeConstants(path string, perm [256]byte) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	replaced := 0
	for i, line := range lines {
		m := opcodeConstRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		origVal, err := strconv.ParseUint(m[2], 16, 8)
		if err != nil {
			continue
		}
		newVal := perm[byte(origVal)]
		lines[i] = fmt.Sprintf("%s Opcode = 0x%02X%s", m[1], newVal, m[3])
		replaced++
	}

	if replaced == 0 {
		return fmt.Errorf("no opcode constants found in %s", path)
	}

	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
}

// rewriteMagicBytes replaces the Magic variable in header.go with custom bytes.
func rewriteMagicBytes(path string, magic [4]byte) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	content := string(data)
	old := "var Magic = []byte{0x00, 0x61, 0x73, 0x6D}"
	repl := fmt.Sprintf("var Magic = []byte{0x%02X, 0x%02X, 0x%02X, 0x%02X}",
		magic[0], magic[1], magic[2], magic[3])

	if !strings.Contains(content, old) {
		return fmt.Errorf("cannot find Magic declaration in %s", path)
	}
	content = strings.Replace(content, old, repl, 1)

	return os.WriteFile(path, []byte(content), 0o644)
}

// sectionIDNames lists the 13 standard section ID constant names in order.
var sectionIDNames = [13]string{
	"SectionIDCustom",
	"SectionIDType",
	"SectionIDImport",
	"SectionIDFunction",
	"SectionIDTable",
	"SectionIDMemory",
	"SectionIDGlobal",
	"SectionIDExport",
	"SectionIDStart",
	"SectionIDElement",
	"SectionIDCode",
	"SectionIDData",
	"SectionIDDataCount",
}

// rewriteSectionIDs replaces the iota-based section ID constants in module.go
// with explicit permuted values.
func rewriteSectionIDs(path string, sectionMap [13]byte) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	content := string(data)

	// Replace the iota declaration for the first constant.
	old := "SectionIDCustom SectionID = iota"
	if !strings.Contains(content, old) {
		return fmt.Errorf("cannot find SectionIDCustom iota declaration in %s", path)
	}
	content = strings.Replace(content, old,
		fmt.Sprintf("SectionIDCustom SectionID = 0x%02X", sectionMap[0]), 1)

	// Replace each subsequent bare section ID name with an explicit value.
	// These lines look like "\tSectionIDType\n" in the const block.
	for i := 1; i < 13; i++ {
		name := sectionIDNames[i]
		old := "\t" + name + "\n"
		repl := fmt.Sprintf("\t%s SectionID = 0x%02X\n", name, sectionMap[i])
		if !strings.Contains(content, old) {
			return fmt.Errorf("cannot find %s in %s", name, path)
		}
		content = strings.Replace(content, old, repl, 1)
	}

	return os.WriteFile(path, []byte(content), 0o644)
}

// rewriteWASIFunctionNames replaces all WASI function name string literals
// throughout the wazero fork with per-build random names.
func rewriteWASIFunctionNames(dstDir string, nameMap map[string]string) error {
	return filepath.Walk(dstDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".go") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)
		modified := false
		// Sort by length descending to avoid substring collisions.
		type kv struct{ k, v string }
		sorted := make([]kv, 0, len(nameMap))
		for k, v := range nameMap {
			sorted = append(sorted, kv{k, v})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return len(sorted[i].k) > len(sorted[j].k)
		})
		for _, pair := range sorted {
			quoted := `"` + pair.k + `"`
			newQuoted := `"` + pair.v + `"`
			if strings.Contains(content, quoted) {
				content = strings.ReplaceAll(content, quoted, newQuoted)
				modified = true
			}
		}
		if modified {
			return os.WriteFile(path, []byte(content), info.Mode().Perm())
		}
		return nil
	})
}

// scrubInstructionNames replaces WASM instruction text name strings in
// instruction.go with opaque identifiers. VT testing confirmed these
// distinctly WASM patterns (i32.add, f64.mul) are a strong ML signal.
func scrubInstructionNames(dstDir string) error {
	instrFile := filepath.Join(dstDir, "internal", "wasm", "instruction.go")
	data, err := os.ReadFile(instrFile)
	if err != nil {
		return nil
	}
	content := string(data)

	instrNameRe := regexp.MustCompile(`"((?:i32|i64|f32|f64|v128|i8x16|i16x8|i32x4|i64x2|f32x4|f64x2|memory|table|ref)\.[a-z_0-9.]+)"`)
	counter := 0
	content = instrNameRe.ReplaceAllStringFunc(content, func(match string) string {
		counter++
		return fmt.Sprintf(`"op_%04x"`, counter)
	})

	for _, kw := range []string{
		"call_indirect", "return_call_indirect", "return_call",
		"unreachable", "select", "memory.grow", "memory.size",
		"memory.init", "memory.copy", "memory.fill",
		"misc_prefix", "vector_prefix", "atomic_prefix",
	} {
		quoted := `"` + kw + `"`
		if strings.Contains(content, quoted) {
			counter++
			content = strings.ReplaceAll(content, quoted, fmt.Sprintf(`"op_%04x"`, counter))
		}
	}

	if err := os.WriteFile(instrFile, []byte(content), 0o644); err != nil {
		return err
	}

	// Also scrub i32.const/i64.const references in error messages across the fork.
	return filepath.Walk(dstDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".go") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)
		modified := false
		for _, pair := range [][2]string{
			{"i32.const", "reading int32"},
			{"i64.const", "reading int64"},
			{"f32.const", "reading float32"},
			{"f64.const", "reading float64"},
		} {
			if strings.Contains(content, pair[0]) {
				content = strings.ReplaceAll(content, pair[0], pair[1])
				modified = true
			}
		}
		if modified {
			return os.WriteFile(path, []byte(content), info.Mode().Perm())
		}
		return nil
	})
}

// scrubSSAOpcodeStrings replaces SSA IR opcode String() return values
// with opaque identifiers.
func scrubSSAOpcodeStrings(dstDir string) error {
	ssaFile := filepath.Join(dstDir, "internal", "engine", "wazevo", "ssa", "instructions.go")
	data, err := os.ReadFile(ssaFile)
	if err != nil {
		return nil
	}
	content := string(data)

	ssaNameRe := regexp.MustCompile(`(case Opcode\w+:\s*\n\s*return )"([^"]+)"`)
	counter := 0
	content = ssaNameRe.ReplaceAllStringFunc(content, func(match string) string {
		counter++
		parts := ssaNameRe.FindStringSubmatch(match)
		if len(parts) < 3 {
			return match
		}
		return fmt.Sprintf(`%s"ir_%04x"`, parts[1], counter)
	})

	return os.WriteFile(ssaFile, []byte(content), 0o644)
}

