# AST Patcher

The AST patcher (`internal/patch/csharp_ast_patcher.go` +
`internal/patch/csharp_ast_patcher_runner.go`) is the production code
path for applying NativeAOT-WASI source patches to .NET projects
(Seatbelt, Rubeus, Certify, SharpDPAPI, etc.). It replaces the legacy
text patcher (`csharp_patcher.go:ApplyCSharpPatches`) as the default
runner; the legacy path is retained as a `--legacy` CLI fallback only.

## Overview

```
.cs file ──parse──▶ tree-sitter AST ──visit──▶ EditList ──apply bottom-up──▶ new bytes
                                       ▲
                                       │
                                  []ASTRule
                                  (filtered by Files() glob)
```

For each file under `srcDir`:

1. The runner walks every `.cs` file matching at least one rule's `Files()` glob.
2. For each match, parses the file into a tree-sitter C# AST once.
3. For every rule whose glob matches that file, runs `Visit(root, source, edits)` which appends byte-range edits.
4. Calls `EditList.ApplyBottomUp(source)` to apply all collected edits in descending offset order (so earlier edits don't shift later offsets).
5. If the file changed, writes it back.

Coverage tracking: the runner records which rules emitted at least one
edit. `--verbose` mode reports unmatched rules; persistent unmatches on
files that *should* be touched are the canary for upstream-source drift.

## Rule Types

Two flavors of rule live in `internal/patch/rules/`:

### `LegacyTextRule` (`legacy.go`)

Wraps the existing `CSharpPatch{Old, New, Description, FileGlob}` data
shape behind the `ASTRule` interface. Inside `Visit`, it does
`strings.Index` lookup and emits one edit per match, mirroring the
legacy `strings.ReplaceAll` semantics. Idempotency check
(`strings.Contains(src, New)`) matches the legacy code path.

This is what 241 / 241 currently-registered rules use. New rules SHOULD
prefer real AST patterns (below); use `LegacyTextRule` only for surgical
patches that depend on exact text shapes.

### True AST rules (future)

A real AST rule walks the tree-sitter parse tree to find structural
matches (attribute on method, identifier in class, etc.) and emits
edits against the matched node's byte range. These survive whitespace
and ordering changes in the source they patch, so they're more robust
than `LegacyTextRule` against upstream code drift.

Stub example (not yet registered; pattern only):

```go
// MemberAccessRewriteRule rewrites every "X.Foo" → "Y.Foo" in matching files.
type MemberAccessRewriteRule struct {
    From string  // "X.Foo"
    To   string  // "Y.Foo"
    Glob string
    Desc string
}

func (r *MemberAccessRewriteRule) Description() string { return r.Desc }
func (r *MemberAccessRewriteRule) Files() []string     { return []string{r.Glob} }

func (r *MemberAccessRewriteRule) Visit(root *tree_sitter.Node, src []byte, edits *patch.EditList) {
    // walk member_access_expression nodes, match the text against r.From,
    // emit edit spanning the node's byte range
    walk(root, "member_access_expression", func(n *tree_sitter.Node) {
        text := string(src[n.StartByte():n.EndByte()])
        if text == r.From {
            edits.Add(n.StartByte(), n.EndByte(), []byte(r.To))
        }
    })
}
```

## Adding a New Rule

1. Decide whether the rule fits an AST pattern (preferred) or needs
   `LegacyTextRule` (for surgical text matches that are awkward to
   express structurally).
2. Add the rule to `internal/patch/rules/`. For `LegacyTextRule`,
   append an entry to `csharp_patcher.go:NativeAOTCSharpPatches` —
   `AllNativeAOTASTRules` picks it up automatically.
3. Write a unit test under `internal/patch/rules/<rule_name>_test.go`
   asserting: rule applies on matching input; rule is idempotent
   (re-applying is a no-op); rule does NOT apply to obviously
   non-matching input.
4. Run `make verify-ast-equivalence SRC=/tmp/seatbelt-fresh` to confirm
   the equivalence verifier still passes (or documents the new
   divergence).
5. Run `make test-parity-seatbelt` (and `test-parity-rubeus` if the
   rule targets Rubeus) — both must still pass.

## Debugging a Rule That Doesn't Match

`wasmforge dotnet-patch --verbose <src>` prints the coverage summary:

```
AST patcher: applied 41/241 rules (200 unmatched — possible upstream drift)
```

The 200 unmatched rules either:

- Target files not present in `<src>` (e.g., Rubeus rules in a Seatbelt build — expected).
- Match files but the `Old` text isn't found (real drift — investigate).

For the second case, the typical workflow:

1. Grep `csharp_patcher.go` for the rule's `Description` to find its definition.
2. Compare the rule's `Old` text against the current source in `<src>`. Whitespace, line endings, or upstream rephrasing are common breaks.
3. Either update `Old` to match new upstream text OR rewrite as a true AST rule that's invariant to the formatting drift.

## Equivalence Verifier

```bash
make verify-ast-equivalence SRC=/tmp/seatbelt-fresh
```

This snapshots `SRC` to two temp dirs, runs the legacy patcher on one
and the AST patcher on the other, then byte-diffs every `.cs` file
under both trees. Any non-zero diff is reported with the file path and
the first ~10 differing bytes from each side.

**Known residual:** 1 cosmetic comment diff in
`Commands/Windows/ExplorerMRUsCommand.cs` — two rules touch the same
span; sequential application (legacy) and single-pass application
(AST) produce different orderings of an informational comment. The
null guard that matters is identical in both outputs.

## Coverage Report

`wasmforge dotnet-patch <src>` (no verbose) prints the summary:

```
AST patcher: applied N/M rules
```

`<src>` outputs from a Seatbelt build look like:

```
AST patcher: applied 42/241 rules (199 unmatched — possible upstream drift)
```

199 unmatched is correct: those rules target Rubeus/Certify/SharpDPAPI
files not present in a Seatbelt source tree. Per-rule coverage tracking
exists so future audits can quickly identify which specific rules drifted
without skimming all 241.

## Migration Strategy

The original plan called for category-by-category migration of all 241
text rules to true AST patterns. After auditing the actual rule shapes,
that approach was abandoned — most rules are bespoke per-file surgical
patches that don't fit 6 clean parameterized categories.

Current state: all 241 rules use `LegacyTextRule`. Future selective
upgrades to true AST rules are tracked per-rule and can happen
incrementally — each upgrade keeps the equivalence verifier green and
the parity sweep PASSing.

## Files

| File | Purpose |
|---|---|
| `internal/patch/csharp_ast_patcher.go` | `ASTRule` interface, `EditList`, parse helpers |
| `internal/patch/csharp_ast_patcher_runner.go` | `ApplyCSharpASTPatches`, `VerifyEquivalence`, `CoverageReport` |
| `internal/patch/rules/legacy.go` | `LegacyTextRule` adapter |
| `internal/patch/rules/rules.go` | `AllNativeAOTASTRules()` aggregator |
| `internal/patch/csharp_patcher.go` | Legacy data (the 241 `CSharpPatch` entries); legacy `ApplyCSharpPatches` retained as `--legacy` fallback |
| `docs/internals/PARITY-HARNESS.md` | How the parity sweep validates patcher output end-to-end |
