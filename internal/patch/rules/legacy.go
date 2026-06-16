// Package rules collects AST rules for the NativeAOT-WASI C# patcher.
// LegacyTextRule wraps the existing CSharpPatch text-substitution
// semantics behind the ASTRule interface so the entire patcher runs
// through one code path. Future selective true-AST rewrites can replace
// individual LegacyTextRule entries without touching the runner.
package rules

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/praetorian-inc/wasmforge/internal/patch"
)

// LegacyTextRule is an AST rule that performs strings.ReplaceAll on
// matched source. It bridges the legacy CSharpPatch model and the
// ASTRule interface without changing patcher semantics.
//
// The source bytes passed to Visit have already had CRLF normalised to
// LF by the runner (matching what applyPatchToFile does), so string
// matching is byte-level on the normalised slice.
type LegacyTextRule struct {
	Glob     string   // file glob, matches CSharpPatch.FileGlob semantics
	Excludes []string // optional file globs to exclude from Glob's match
	Old      string   // exact text to replace
	New      string   // replacement text
	Desc     string   // shown in --verbose and coverage report
}

func (r *LegacyTextRule) Description() string    { return r.Desc }
func (r *LegacyTextRule) Files() []string        { return []string{r.Glob} }
func (r *LegacyTextRule) ExcludeFiles() []string { return r.Excludes }

// Visit performs the text replacement. The tree_sitter.Node arg is
// accepted to satisfy the ASTRule interface but unused — string
// matching is byte-level on the source slice.
//
// Idempotency: if New is already present in source, the rule is skipped
// entirely (matching legacy applyPatchToFile behaviour).  If Old is not
// found, the rule is a no-op.  All non-overlapping occurrences of Old
// are replaced (matching strings.ReplaceAll semantics).
func (r *LegacyTextRule) Visit(_ *tree_sitter.Node, source []byte, edits *patch.EditList) {
	src := string(source)

	// Idempotency guard — same check as legacy applyPatchToFile.
	if strings.Contains(src, r.New) {
		return
	}

	// Find and replace all non-overlapping occurrences.
	oldLen := len(r.Old)
	newBytes := []byte(r.New)
	search := src
	base := 0
	for {
		idx := strings.Index(search, r.Old)
		if idx < 0 {
			break
		}
		abs := base + idx
		edits.Add(uint(abs), uint(abs+oldLen), newBytes)
		// Advance past this match.
		advance := idx + oldLen
		base += advance
		search = search[advance:]
	}
}
