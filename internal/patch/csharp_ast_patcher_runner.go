// csharp_ast_patcher_runner.go — Runner and equivalence verifier for AST-based C# patches.

package patch

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CoverageReport summarises which AST rules actually matched during the most
// recent Apply pass.
type CoverageReport struct {
	TotalRules   int
	MatchedRules int
	Unmatched    []string // descriptions of rules that matched a file but emitted 0 edits
}

// String returns a human-readable one-line summary printed by dotnet-patch
// --verbose. When all rules matched, the summary says "(full coverage)". When
// some rules emitted no edits, it lists them as potential upstream drift.
func (r *CoverageReport) String() string {
	if len(r.Unmatched) == 0 {
		return fmt.Sprintf("AST patcher: applied %d/%d rules (full coverage)", r.MatchedRules, r.TotalRules)
	}
	return fmt.Sprintf("AST patcher: applied %d/%d rules (%d unmatched — possible upstream drift)",
		r.MatchedRules, r.TotalRules, len(r.Unmatched))
}

// walkMatchingFiles walks srcDir and calls fn for every file whose path
// matches one of the provided globs. Glob syntax is the same as
// CSharpPatch.FileGlob: a leading "**/" means recursive; anything else is an
// exact relative-path match from srcDir.
//
// fn receives the absolute path of each matching file.
func walkMatchingFiles(srcDir string, globs []string, fn func(path string) error) error {
	return filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".cs" {
			return nil
		}
		rel, relErr := filepath.Rel(srcDir, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)

		for _, glob := range globs {
			if matchGlob(glob, rel) {
				return fn(path)
			}
		}
		return nil
	})
}

// matchGlob returns true if the slash-separated relative path rel matches
// the pattern glob. Supports leading "**/" for recursive matching.
func matchGlob(glob, rel string) bool {
	if strings.Contains(glob, "**") {
		parts := strings.SplitN(glob, "**", 2)
		suffix := strings.TrimPrefix(parts[1], "/")
		if suffix == "" || strings.HasPrefix(suffix, "*") {
			// "**/*.cs" → match any .cs file
			ext := filepath.Ext(glob)
			return ext == "" || strings.HasSuffix(rel, ext)
		}
		// "**/Util/RegistryUtil.cs" → rel must end with "Util/RegistryUtil.cs"
		return strings.HasSuffix(rel, suffix)
	}
	// Exact relative path match.
	return rel == glob
}

// ApplyCSharpASTPatches runs each AST rule against every .cs file under srcDir
// whose path matches the rule's Files() globs. Each file is parsed once;
// edits from all matching rules are accumulated then applied bottom-up.
//
// Returns the count of files modified, a CoverageReport describing which rules
// matched, and any error. Re-running on already-patched source produces zero
// changes if the rules are idempotent.
func ApplyCSharpASTPatches(srcDir string, rules []ASTRule, verbose bool) (int, *CoverageReport, error) {
	report := &CoverageReport{TotalRules: len(rules)}
	if len(rules) == 0 {
		return 0, report, nil
	}

	// Build per-file rule sets. Walk all .cs files; for each, collect rules
	// whose Files() globs match.
	type fileEntry struct {
		path  string
		rules []ASTRule
	}
	var entries []fileEntry

	err := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(srcDir, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)

		isCS := filepath.Ext(path) == ".cs"

		var matching []ASTRule
		for _, r := range rules {
			globs := r.Files()
			if len(globs) == 0 {
				// Empty Files() → applies to all .cs files only.
				// True AST rules without an explicit glob target
				// the C# parse tree and aren't meaningful on
				// non-.cs files.
				if !isCS {
					continue
				}
				// Honour ExcludeFiles even with empty Files(): "default
				// everywhere except <site>" is a legitimate pattern when
				// a sibling targeted rule handles that site differently.
				if exr, ok := r.(interface{ ExcludeFiles() []string }); ok {
					excluded := false
					for _, eg := range exr.ExcludeFiles() {
						if matchGlob(eg, rel) {
							excluded = true
							break
						}
					}
					if excluded {
						continue
					}
				}
				matching = append(matching, r)
				continue
			}
			matchedInclude := false
			for _, g := range globs {
				if matchGlob(g, rel) {
					matchedInclude = true
					break
				}
			}
			if !matchedInclude {
				continue
			}
			// Honour optional exclude globs (ExcludeFiles is duck-typed
			// so true-AST rules without exclusions don't have to
			// implement it).
			if exr, ok := r.(interface{ ExcludeFiles() []string }); ok {
				excluded := false
				for _, eg := range exr.ExcludeFiles() {
					if matchGlob(eg, rel) {
						excluded = true
						break
					}
				}
				if excluded {
					continue
				}
			}
			matching = append(matching, r)
		}
		if len(matching) > 0 {
			entries = append(entries, fileEntry{path: path, rules: matching})
		}
		return nil
	})
	if err != nil {
		return 0, report, fmt.Errorf("walking %s: %w", srcDir, err)
	}

	// Track which rules emitted at least one edit.
	hitRules := make(map[ASTRule]bool)

	modified := 0
	for _, entry := range entries {
		isCS := filepath.Ext(entry.path) == ".cs"
		var changed bool
		var hit []ASTRule
		var err error
		if isCS {
			changed, hit, err = applyASTRulesToFile(entry.path, entry.rules, verbose)
		} else {
			// Non-.cs files (csproj, xml, json, etc.) cannot be
			// fed to the C# tree-sitter parser. LegacyTextRule
			// ignores the AST node anyway and operates purely on
			// the byte stream, so route those rules through a
			// dedicated path that skips parsing. True structural
			// AST rules SHOULD use explicit .cs globs.
			changed, hit, err = applyLegacyRulesToNonCSFile(entry.path, entry.rules, verbose)
		}
		if err != nil {
			return modified, report, err
		}
		if changed {
			modified++
		}
		for _, r := range hit {
			hitRules[r] = true
		}
	}

	// Build coverage report.
	for _, r := range rules {
		if hitRules[r] {
			report.MatchedRules++
		} else {
			report.Unmatched = append(report.Unmatched, r.Description())
		}
	}

	return modified, report, nil
}

// applyASTRulesToFile parses path once, runs all rules, applies accumulated
// edits bottom-up, and writes the file back if changed.
//
// Returns (changed, hitRules, error). hitRules contains every rule that
// emitted at least one edit; callers use this to build CoverageReport.
//
// CRLF normalisation: the file is read and immediately normalised (\r\n → \n)
// before parsing and before rules run. This matches the legacy applyPatchToFile
// behaviour so that LegacyTextRule adapters see the same byte stream the legacy
// patcher saw.
func applyASTRulesToFile(path string, rules []ASTRule, verbose bool) (bool, []ASTRule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, nil, fmt.Errorf("read %s: %w", path, err)
	}

	// Normalise CRLF → LF, matching legacy applyPatchToFile.
	src := []byte(strings.ReplaceAll(string(raw), "\r\n", "\n"))

	tree, err := ParseCSharp(src)
	if err != nil {
		return false, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	defer tree.Close()

	root := tree.RootNode()
	var hitRules []ASTRule
	var edits EditList
	for _, r := range rules {
		before := edits.Len()
		r.Visit(root, src, &edits)
		if edits.Len() > before {
			hitRules = append(hitRules, r)
		}
		if verbose {
			fmt.Printf("  [AST] %s: %s\n", filepath.Base(path), r.Description())
		}
	}

	result, err := edits.ApplyBottomUp(src)
	if err != nil {
		return false, hitRules, fmt.Errorf("apply edits to %s: %w", path, err)
	}

	if string(result) == string(src) {
		return false, hitRules, nil
	}

	if err := os.WriteFile(path, result, 0o644); err != nil {
		return false, hitRules, fmt.Errorf("write %s: %w", path, err)
	}
	return true, hitRules, nil
}

// applyLegacyRulesToNonCSFile applies rules to a non-.cs file (csproj, xml,
// json, etc.) by skipping AST parsing and feeding a nil root node to each
// rule's Visit method. This works for LegacyTextRule (which ignores the
// node and operates purely on the byte stream); true structural AST rules
// MUST scope themselves to .cs via their Files() glob to avoid being routed
// here with a nil node.
//
// Behaves like applyASTRulesToFile in every other respect: CRLF
// normalisation, edits accumulated then applied bottom-up, hitRules
// reported for coverage tracking.
func applyLegacyRulesToNonCSFile(path string, rules []ASTRule, verbose bool) (bool, []ASTRule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, nil, fmt.Errorf("read %s: %w", path, err)
	}
	src := []byte(strings.ReplaceAll(string(raw), "\r\n", "\n"))

	var hitRules []ASTRule
	var edits EditList
	for _, r := range rules {
		before := edits.Len()
		// nil root: LegacyTextRule discards the node anyway.
		r.Visit(nil, src, &edits)
		if edits.Len() > before {
			hitRules = append(hitRules, r)
		}
		if verbose {
			fmt.Printf("  [legacy] %s: %s\n", filepath.Base(path), r.Description())
		}
	}

	result, err := edits.ApplyBottomUp(src)
	if err != nil {
		return false, hitRules, fmt.Errorf("apply edits to %s: %w", path, err)
	}
	if string(result) == string(src) {
		return false, hitRules, nil
	}
	if err := os.WriteFile(path, result, 0o644); err != nil {
		return false, hitRules, fmt.Errorf("write %s: %w", path, err)
	}
	return true, hitRules, nil
}

// VerifyEquivalence snapshots srcDir to two temp directories, runs the legacy
// text patcher on one and the AST patcher on the other, then byte-diffs every
// .cs file. Returns nil when all outputs match.
//
// With zero AST rules registered, the function prints a summary of how many
// files the legacy patcher would touch and exits without error — this is the
// gating signal for incremental B.2+ migration.
func VerifyEquivalence(srcDir string, astRules []ASTRule, verbose bool) error {
	ts := time.Now().UnixNano()
	tmpLegacy := filepath.Join(os.TempDir(), fmt.Sprintf("wasmforge-verify-legacy-%d", ts))
	tmpAST := filepath.Join(os.TempDir(), fmt.Sprintf("wasmforge-verify-ast-%d", ts))

	if err := copyDir(srcDir, tmpLegacy); err != nil {
		return fmt.Errorf("copy to legacy dir: %w", err)
	}
	defer os.RemoveAll(tmpLegacy)

	if err := copyDir(srcDir, tmpAST); err != nil {
		return fmt.Errorf("copy to AST dir: %w", err)
	}
	defer os.RemoveAll(tmpAST)

	// Apply legacy patcher to tmpLegacy.
	legacyCount, err := ApplyCSharpPatches(tmpLegacy, verbose)
	if err != nil {
		return fmt.Errorf("legacy patcher: %w", err)
	}

	if len(astRules) == 0 {
		fmt.Printf("VerifyEquivalence: 0 AST rules registered, %d expected differences (legacy patcher touched %d files)\n",
			legacyCount, legacyCount)
		return nil
	}

	// Apply AST patcher to tmpAST.
	if _, _, err := ApplyCSharpASTPatches(tmpAST, astRules, verbose); err != nil {
		return fmt.Errorf("AST patcher: %w", err)
	}

	// Diff every .cs file under both trees.
	return diffTrees(tmpLegacy, tmpAST)
}

// diffTrees compares .cs files under dirA and dirB. Returns the first mismatch
// as a descriptive error containing the relative path and up to 10 differing
// bytes of context.
func diffTrees(dirA, dirB string) error {
	return filepath.WalkDir(dirA, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".cs" {
			return nil
		}
		rel, _ := filepath.Rel(dirA, path)
		pathB := filepath.Join(dirB, rel)

		aBytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", rel, err)
		}
		bBytes, err := os.ReadFile(pathB)
		if err != nil {
			return fmt.Errorf("read AST output for %s: %w", rel, err)
		}

		if string(aBytes) == string(bBytes) {
			return nil
		}

		// Find first differing offset for context.
		offset := firstDiff(aBytes, bBytes)
		ctxA := truncate(aBytes, offset, 10)
		ctxB := truncate(bBytes, offset, 10)
		return fmt.Errorf("mismatch in %s at offset %d: legacy=%q ast=%q",
			rel, offset, ctxA, ctxB)
	})
}

func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

func truncate(b []byte, offset, maxBytes int) []byte {
	if offset >= len(b) {
		return nil
	}
	end := offset + maxBytes
	if end > len(b) {
		end = len(b)
	}
	return b[offset:end]
}

// copyDir recursively copies srcDir to dstDir, creating dstDir if needed.
func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(src, path)
		if relErr != nil {
			return relErr
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if mkErr := os.MkdirAll(filepath.Dir(target), 0o755); mkErr != nil {
			return mkErr
		}
		return os.WriteFile(target, data, 0o644)
	})
}
