// csharp_ast_patcher.go — AST-based C# source patcher (Phase 3).
//
// The legacy csharp_patcher.go contains 250+ text-substitution rules
// (CSharpPatch.Old → CSharpPatch.New) which are fragile to upstream
// formatting changes in the .NET source code we're patching. A whitespace
// change to a single Seatbelt method body breaks the matching rule
// silently — we then ship a broken binary that "patcher applied N rules"
// without realizing the affected rule did nothing.
//
// This file introduces an AST-based replacement using tree-sitter-c-sharp:
//
//   - Parse each .cs file into a syntax tree once
//   - Rules walk the tree and match by structural patterns
//     (e.g. "find class X method Y" or "find DllImport on library Z")
//   - Edits are byte-range replacements applied bottom-up to preserve offsets
//   - Coverage report: each registered rule emits a target descriptor;
//     after applying, we know which targets were not matched and warn
//     about possible upstream drift instead of silently shipping a
//     broken binary
//
// Per the plan in ~/.claude/plans/scalable-dancing-papert.md Phase 3,
// this file initially provides:
//   - ASTRule interface (Visit signature)
//   - EditList collector (sorts edits bottom-up)
//   - applyEditsBottomUp helper
//   - ParseCSharp helper for grammar instantiation
//
// Task 3.2 (POC with 3 rules) and 3.3 (migrate 250 rules) come next.

package patch

import (
	"errors"
	"fmt"
	"os"
	"sort"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_csharp "github.com/tree-sitter/tree-sitter-c-sharp/bindings/go"
)

// ASTRule is implemented by rule types that walk a parsed tree and append
// edits to the provided EditList. Each rule should be safe to apply
// multiple times to the same tree (idempotent) — re-running a build that
// already has the patch applied should be a no-op.
//
// Description is shown in --verbose output and in the coverage report
// when a rule is registered but no target found.
type ASTRule interface {
	Description() string
	// Files returns file glob patterns (same syntax as CSharpPatch.FileGlob,
	// e.g. "**/Util/RegistryUtil.cs") that this rule applies to. An empty
	// slice means the rule applies to all .cs files.
	Files() []string
	Visit(root *tree_sitter.Node, source []byte, edits *EditList)
}

// EditList collects byte-range replacements to be applied to source bytes.
// Edits are sorted by descending start offset before application so that
// each edit's offsets remain valid through the whole replacement chain.
type EditList struct {
	edits []edit
}

type edit struct {
	start, end uint
	repl       []byte
}

// Add appends a replacement spanning [start, end) → repl.
func (l *EditList) Add(start, end uint, repl []byte) {
	l.edits = append(l.edits, edit{start: start, end: end, repl: append([]byte(nil), repl...)})
}

// Len returns the number of pending edits.
func (l *EditList) Len() int { return len(l.edits) }

// ApplyBottomUp returns a new byte slice with all edits applied. Edits
// are sorted by descending start; overlapping edits are detected and
// rejected (returns the second edit's bounds in the error).
func (l *EditList) ApplyBottomUp(src []byte) ([]byte, error) {
	if len(l.edits) == 0 {
		return src, nil
	}
	// Sort descending by start so earlier (higher-offset) edits don't
	// shift later (lower-offset) edits' positions.
	sorted := make([]edit, len(l.edits))
	copy(sorted, l.edits)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].start > sorted[j].start
	})

	// Overlap check.
	for i := 1; i < len(sorted); i++ {
		// sorted[i-1] starts AFTER sorted[i] (descending order). Overlap
		// happens when sorted[i].end > sorted[i-1].start.
		if sorted[i].end > sorted[i-1].start {
			return nil, fmt.Errorf("overlapping edits: [%d,%d) and [%d,%d)",
				sorted[i].start, sorted[i].end,
				sorted[i-1].start, sorted[i-1].end)
		}
	}

	out := append([]byte(nil), src...)
	for _, e := range sorted {
		if e.end > uint(len(out)) {
			return nil, fmt.Errorf("edit end %d exceeds source length %d", e.end, len(out))
		}
		tail := append([]byte(nil), out[e.end:]...)
		out = append(out[:e.start], e.repl...)
		out = append(out, tail...)
	}
	return out, nil
}

// ParseCSharp parses a single C# source byte slice into a tree-sitter
// tree using the tree-sitter-c-sharp grammar. Caller owns the tree and
// must Close() it.
func ParseCSharp(src []byte) (*tree_sitter.Tree, error) {
	parser := tree_sitter.NewParser()
	defer parser.Close()

	lang := tree_sitter.NewLanguage(tree_sitter_csharp.Language())
	if err := parser.SetLanguage(lang); err != nil {
		return nil, fmt.Errorf("set language: %w", err)
	}

	tree := parser.Parse(src, nil)
	if tree == nil {
		return nil, errors.New("parse returned nil tree")
	}
	return tree, nil
}

// ParseCSharpFile is a convenience wrapper that reads a file and parses
// its contents. Returns both the source bytes and the tree (caller must
// Close the tree).
func ParseCSharpFile(path string) ([]byte, *tree_sitter.Tree, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}
	tree, err := ParseCSharp(src)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return src, tree, nil
}

// CountNodes walks the tree and returns counts per node kind. Used by
// the smoke test to confirm the C# grammar is loaded correctly.
func CountNodes(root *tree_sitter.Node) map[string]int {
	counts := make(map[string]int)
	var walk func(n *tree_sitter.Node)
	walk = func(n *tree_sitter.Node) {
		if n == nil {
			return
		}
		counts[n.Kind()]++
		cursor := n.Walk()
		defer cursor.Close()
		for i := uint(0); i < n.ChildCount(); i++ {
			child := n.Child(i)
			walk(child)
		}
	}
	walk(root)
	return counts
}
