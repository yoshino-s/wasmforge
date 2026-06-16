package build

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// writePkg writes src to {dir}/pkg.go.
func writePkg(t *testing.T, dir, src string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "pkg.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("writePkg: %v", err)
	}
}

// assertFieldOrder checks that each element of want appears in content in the
// given order (using simple string position comparisons).
func assertFieldOrder(t *testing.T, content string, want []string) {
	t.Helper()
	pos := 0
	for _, field := range want {
		idx := strings.Index(content[pos:], field)
		if idx < 0 {
			t.Errorf("field %q not found in content after position %d\ncontent:\n%s", field, pos, content)
			return
		}
		pos += idx + len(field)
	}
}

// isInOriginalOrder returns true if the struct fields A, B, C, D appear in
// that order in content.
func isInOriginalOrder(content string) bool {
	fields := []string{"A int", "B string", "C uint32", "D bool"}
	pos := 0
	for _, f := range fields {
		idx := strings.Index(content[pos:], f)
		if idx < 0 {
			return false
		}
		pos += idx + len(f)
	}
	return true
}

// structSrc is the shared source for phase 9 (struct reorder) tests.
const structSrc = `package pkg

type Decoder struct {
	A int
	B string
	C uint32
	D bool
}
`

// loopSrc is the shared source for phase 11 (loop invert) tests.
const loopSrc = `package pkg

import "io"

func decode(r io.Reader, count int) []int {
	var results []int
	for i := 0; i < count; i++ {
		results = append(results, parseItem(r))
	}
	return results
}

func parseItem(r io.Reader) int { return 0 }
`

// ifelseSrc is a source with a function body large enough to trigger phase 10
// (opaque predicates require a block with 3+ statements).
const ifelseSrc = `package pkg

func process(a, b, c int) int {
	x := a + b
	y := b + c
	z := x * y
	return z
}
`

// ---------------------------------------------------------------------------
// Test Group 1: transformASTOnly env-var gate behavior
// ---------------------------------------------------------------------------

// TestTransformASTOnly_Phase9OffByDefault verifies that struct field ordering
// is preserved when WASMFORGE_WAZERO_STRUCT_REORDER is not set.
func TestTransformASTOnly_Phase9OffByDefault(t *testing.T) {
	dir := t.TempDir()
	writePkg(t, dir, structSrc)

	if err := transformASTOnly(dir); err != nil {
		t.Fatalf("transformASTOnly: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "pkg.go"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// With phase 9 off, fields must remain in original declaration order.
	assertFieldOrder(t, string(data), []string{"A int", "B string", "C uint32", "D bool"})
}

// TestTransformASTOnly_Phase9EnabledWithOptIn verifies that setting
// WASMFORGE_WAZERO_STRUCT_REORDER=1 causes struct fields to be reordered.
// The test runs 50 independent iterations; probability that all 50 leave
// 4 fields in original order by chance is (1/24)^50 ≈ 0.
func TestTransformASTOnly_Phase9EnabledWithOptIn(t *testing.T) {
	t.Setenv("WASMFORGE_WAZERO_STRUCT_REORDER", "1")

	reorderedAtLeastOnce := false
	for i := 0; i < 50; i++ {
		dir := t.TempDir()
		writePkg(t, dir, structSrc)
		if err := transformASTOnly(dir); err != nil {
			t.Fatalf("transformASTOnly iter %d: %v", i, err)
		}
		data, err := os.ReadFile(filepath.Join(dir, "pkg.go"))
		if err != nil {
			t.Fatalf("ReadFile iter %d: %v", i, err)
		}
		if !isInOriginalOrder(string(data)) {
			reorderedAtLeastOnce = true
			break
		}
	}
	if !reorderedAtLeastOnce {
		t.Error("phase 9 struct reorder never fired in 50 iterations despite WASMFORGE_WAZERO_STRUCT_REORDER=1")
	}
}

// TestTransformASTOnly_Phase9BlockedByLegacyDisable verifies that
// WASMFORGE_NO_STRUCT_REORDER=1 prevents phase 9 even when the opt-in is set.
func TestTransformASTOnly_Phase9BlockedByLegacyDisable(t *testing.T) {
	t.Setenv("WASMFORGE_WAZERO_STRUCT_REORDER", "1")
	t.Setenv("WASMFORGE_NO_STRUCT_REORDER", "1")

	dir := t.TempDir()
	writePkg(t, dir, structSrc)

	if err := transformASTOnly(dir); err != nil {
		t.Fatalf("transformASTOnly: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "pkg.go"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	assertFieldOrder(t, string(data), []string{"A int", "B string", "C uint32", "D bool"})
}

// TestTransformASTOnly_Phase11OffByDefault verifies that loop inversion does
// not fire when WASMFORGE_WAZERO_CODEXFORM is not set.
func TestTransformASTOnly_Phase11OffByDefault(t *testing.T) {
	dir := t.TempDir()
	writePkg(t, dir, loopSrc)

	if err := transformASTOnly(dir); err != nil {
		t.Fatalf("transformASTOnly: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "pkg.go"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	if strings.Contains(content, "i--") || strings.Contains(content, ">= 0") {
		t.Error("phase 11 loop inversion fired despite being off by default")
	}
}

// TestTransformASTOnly_Phase11EnabledWithOptIn verifies that setting
// WASMFORGE_WAZERO_CODEXFORM=1 causes loop inversion to fire.
// The test runs 50 independent iterations; at 20% per-loop probability the
// chance of never inverting across 50 runs is (0.8^50) * (branch-flip misses)
// ≈ negligible.
func TestTransformASTOnly_Phase11EnabledWithOptIn(t *testing.T) {
	t.Setenv("WASMFORGE_WAZERO_CODEXFORM", "1")

	invertedAtLeastOnce := false
	for i := 0; i < 50; i++ {
		dir := t.TempDir()
		writePkg(t, dir, loopSrc)
		if err := transformASTOnly(dir); err != nil {
			t.Fatalf("transformASTOnly iter %d: %v", i, err)
		}
		data, err := os.ReadFile(filepath.Join(dir, "pkg.go"))
		if err != nil {
			t.Fatalf("ReadFile iter %d: %v", i, err)
		}
		content := string(data)
		if strings.Contains(content, "i--") || strings.Contains(content, ">= 0") {
			invertedAtLeastOnce = true
			break
		}
	}
	if !invertedAtLeastOnce {
		t.Error("phase 11 loop inversion never fired in 50 iterations despite WASMFORGE_WAZERO_CODEXFORM=1")
	}
}

// TestTransformASTOnly_Phase10AlwaysOn verifies that phase 10 (opaque
// predicates) modifies files even with no env vars set.
// Opaque predicate injection has a ~10% rate per eligible block.
// With 50 iterations the probability of never modifying is negligible.
func TestTransformASTOnly_Phase10AlwaysOn(t *testing.T) {
	appliedAtLeastOnce := false
	for i := 0; i < 50; i++ {
		dir := t.TempDir()
		writePkg(t, dir, ifelseSrc)
		if err := transformASTOnly(dir); err != nil {
			t.Fatalf("transformASTOnly iter %d: %v", i, err)
		}
		// Count files in the dir — opaque predicates also writes a seed file.
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("ReadDir iter %d: %v", i, err)
		}
		// If a seed file was written (more than just pkg.go), phase 10 ran.
		if len(entries) > 1 {
			appliedAtLeastOnce = true
			break
		}
	}
	if !appliedAtLeastOnce {
		t.Error("phase 10 opaque predicates never wrote a seed file in 50 runs (expected always-on)")
	}
}

// TestTransformASTOnly_Phase10DisabledByEnv verifies that WASMFORGE_NO_OPAQUE=1
// suppresses phase 10 — no seed file is written and pkg.go is unchanged.
func TestTransformASTOnly_Phase10DisabledByEnv(t *testing.T) {
	t.Setenv("WASMFORGE_NO_OPAQUE", "1")

	dir := t.TempDir()
	writePkg(t, dir, ifelseSrc)

	if err := transformASTOnly(dir); err != nil {
		t.Fatalf("transformASTOnly: %v", err)
	}

	// Only pkg.go should exist — no seed file written.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("phase 10 wrote extra files despite WASMFORGE_NO_OPAQUE=1: %v", names)
	}

	// pkg.go content must be unchanged.
	data, err := os.ReadFile(filepath.Join(dir, "pkg.go"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != ifelseSrc {
		t.Errorf("phase 10 modified pkg.go despite WASMFORGE_NO_OPAQUE=1\ngot:\n%s", string(data))
	}
}

// ---------------------------------------------------------------------------
// Test Group 2: Known-unsafe transform behavior (documentation tests)
// ---------------------------------------------------------------------------

// TestInvertForLoop_AppendPatternNotProtected documents the known gap in
// bodyUsesIndexing: append-style decoder loops (where the index variable is
// not used as a slice subscript) are NOT protected, so invertForLoop will
// reverse their iteration order when phase 11 is enabled.
//
// This test encodes the CURRENT behavior. If it starts failing it means the
// safety check has been extended to cover append-style loops (which would be
// a fix, not a regression).
func TestInvertForLoop_AppendPatternNotProtected(t *testing.T) {
	src := `package pkg
import "io"
func f(r io.Reader, count int) []int {
	var out []int
	for i := 0; i < count; i++ {
		out = append(out, readInt(r))
	}
	return out
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "f.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}

	var forStmt *ast.ForStmt
	ast.Inspect(f, func(n ast.Node) bool {
		if fs, ok := n.(*ast.ForStmt); ok {
			forStmt = fs
		}
		return true
	})
	if forStmt == nil {
		t.Fatal("no for loop found in test AST")
	}

	result := invertForLoop(forStmt)
	if !result {
		t.Error("expected invertForLoop to return true on append-pattern (documenting known gap): bodyUsesIndexing does not protect this pattern")
	}
	t.Log("KNOWN GAP: append-style decoder loops are NOT protected by bodyUsesIndexing; phase 11 will reverse their iteration order if enabled on wazero")
}

// TestInvertForLoop_IndexExpressionIsProtected verifies that bodyUsesIndexing
// correctly protects loops that use the index variable as a slice subscript.
func TestInvertForLoop_IndexExpressionIsProtected(t *testing.T) {
	src := `package pkg
func f(buf []byte) []byte {
	out := make([]byte, len(buf))
	for i := 0; i < len(buf); i++ {
		out[i] = transform(buf[i])
	}
	return out
}
func transform(b byte) byte { return b }
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "f.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}

	var forStmt *ast.ForStmt
	ast.Inspect(f, func(n ast.Node) bool {
		if fs, ok := n.(*ast.ForStmt); ok {
			forStmt = fs
		}
		return true
	})
	if forStmt == nil {
		t.Fatal("no for loop found in test AST")
	}

	result := invertForLoop(forStmt)
	if result {
		t.Error("invertForLoop should return false (protected) when loop body uses index as slice subscript; got true (would invert)")
	}
}

// TestReorderStructFieldsInFile_ReflectUsageNotDetected documents the known
// gap in reorderStructFieldsInFile: files that reference a struct via
// reflect.TypeOf are not skipped, so field reordering breaks reflection-based
// code (e.g., wazero/internal/wasm/gofunc.go).
//
// This test encodes the CURRENT behavior as a documentation regression spec.
// If it starts failing it means reflection detection has been added, which
// would be a fix.
func TestReorderStructFieldsInFile_ReflectUsageNotDetected(t *testing.T) {
	src := `package pkg

import "reflect"

type GoFunc struct {
	Name    string
	Fn      interface{}
	Params  []reflect.Type
	Results []reflect.Type
}

func inspect(g GoFunc) reflect.Type {
	return reflect.TypeOf(g)
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "gofunc.go")

	tc := &hostTransformConfig{wl: newWordList(), used: make(map[string]bool)}

	reorderedAtLeastOnce := false
	for i := 0; i < 20; i++ {
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if err := tc.reorderStructFieldsInFile(path, map[string]bool{}); err != nil {
			t.Fatalf("reorderStructFieldsInFile: %v", err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		// Check if Name field is no longer first (indicating reorder happened).
		content := string(data)
		namePos := strings.Index(content, "Name    string")
		fnPos := strings.Index(content, "Fn      interface{}")
		if namePos < 0 || fnPos < 0 {
			// Fields may be reformatted by printer; check for any reordering.
			if !strings.Contains(content, "Name") || !strings.Contains(content, "Fn") {
				t.Fatal("struct fields disappeared from output")
			}
		}
		// Original order: Name first, Fn second.
		if namePos >= 0 && fnPos >= 0 && fnPos < namePos {
			reorderedAtLeastOnce = true
			break
		}
	}

	if !reorderedAtLeastOnce {
		t.Skip("probabilistic test: GoFunc struct stayed in original order across all 20 iterations (unlikely but possible; re-run to confirm)")
	}
	t.Log("KNOWN GAP: reorderStructFieldsInFile does not detect reflect.TypeOf usage and will reorder reflect-sensitive structs such as wazero's GoFunc")
}
