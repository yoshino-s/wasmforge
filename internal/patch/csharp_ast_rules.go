// csharp_ast_rules.go — high-level structural ASTRule implementations.
//
// These rules walk the tree-sitter C# AST and match on node shape, not
// on textual whitespace. They replace whole expression nodes by their
// (start, end) byte spans, so reformatted upstream code, multi-line
// breaks, comments embedded in the expression, and intermediate
// variable bindings don't break the patch.

package patch

import (
	"strings"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

// MemberChainRewrite matches a leading sequence of identifiers in a
// member-access expression and rewrites that prefix.
//
// Example: Chain = []string{"TimeZone", "CurrentTimeZone"}
//
//   "TimeZone.CurrentTimeZone"               → "<Repl>"
//   "TimeZone.CurrentTimeZone.StandardName"  → "<Repl>.StandardName"
//   "TimeZone.CurrentTimeZone.GetUtcOffset(...)" → "<Repl>.GetUtcOffset(...)"
//
// Only the matched prefix is replaced; suffixes (further member access,
// invocations, indexers) are preserved.
//
// Match is on raw identifier names — no namespace resolution, so a
// local variable named "TimeZone" would also match. Combine with
// FileGlobs to narrow scope when needed.
type MemberChainRewrite struct {
	Chain     []string
	Repl      string
	FileGlobs []string
	Excludes  []string
	Desc      string
}

func (r *MemberChainRewrite) Description() string  { return r.Desc }
func (r *MemberChainRewrite) Files() []string      { return r.FileGlobs }
func (r *MemberChainRewrite) ExcludeFiles() []string { return r.Excludes }

func (r *MemberChainRewrite) Visit(root *tree_sitter.Node, source []byte, edits *EditList) {
	if len(r.Chain) == 0 {
		return
	}
	walkNodes(root, func(n *tree_sitter.Node) bool {
		if n.Kind() != "member_access_expression" {
			return true
		}
		// We only want to fire on the OUTERMOST member_access_expression
		// whose innermost identifier chain matches r.Chain. Walking will
		// visit nested member_access_expressions too; reject any node
		// whose parent is also a member_access_expression that would
		// match our chain — but a simpler rule is: only match nodes
		// where the LHS chain length is exactly len(r.Chain)-1 (so the
		// outer node is at chain depth len(r.Chain)).
		chain, ok := collectMemberChain(n, source)
		if !ok {
			return true
		}
		// Match: the chain must START with r.Chain.
		if len(chain) < len(r.Chain) {
			return true
		}
		for i, want := range r.Chain {
			if chain[i] != want {
				return true
			}
		}
		// Compute the byte span of the matched PREFIX. If chain has
		// exactly len(r.Chain) parts, replace the whole node. Otherwise
		// replace just the prefix subtree.
		prefixNode := n
		// Walk down the LHS chain until we're at depth len(r.Chain).
		// Each member_access_expression has expression on LHS, name on
		// RHS. The PREFIX subtree is the node whose chain depth equals
		// len(r.Chain) — i.e. walk in from the outermost node by
		// (len(chain) - len(r.Chain)) hops, each hop taking LHS.
		for i := len(chain); i > len(r.Chain); i-- {
			lhs := prefixNode.ChildByFieldName("expression")
			if lhs == nil {
				return true
			}
			prefixNode = lhs
		}
		start := prefixNode.StartByte()
		end := prefixNode.EndByte()
		edits.Add(start, end, []byte(r.Repl))
		// Don't descend into the matched node — avoids double matches
		// when nested chains overlap.
		return false
	})
}

// InvocationRewrite matches an invocation_expression where the function
// is either a bare identifier (Method, free-call form) or a
// member_access_expression whose receiver chain matches Receiver.
//
// Example: Receiver=["Dns"], Method="GetHostName" matches:
//
//   Dns.GetHostName()           → "<Repl>()"               (KeepArgs=true)
//   Dns.GetHostName()           → "<Repl>"                 (KeepArgs=false)
//
// ArgCount < 0 matches any arity. ArgCount = 0 requires exactly 0
// arguments.
type InvocationRewrite struct {
	Receiver  []string // empty for bare-identifier calls
	Method    string
	Repl      string // expression text without args (args appended if KeepArgs)
	KeepArgs  bool
	ArgCount  int // -1 = any
	FileGlobs []string
	Desc      string
}

func (r *InvocationRewrite) Description() string { return r.Desc }
func (r *InvocationRewrite) Files() []string     { return r.FileGlobs }

func (r *InvocationRewrite) Visit(root *tree_sitter.Node, source []byte, edits *EditList) {
	walkNodes(root, func(n *tree_sitter.Node) bool {
		if n.Kind() != "invocation_expression" {
			return true
		}
		fn := n.ChildByFieldName("function")
		if fn == nil {
			return true
		}
		var receiver []string
		var methodName string
		switch fn.Kind() {
		case "identifier":
			methodName = string(source[fn.StartByte():fn.EndByte()])
		case "member_access_expression":
			chain, ok := collectMemberChain(fn, source)
			if !ok || len(chain) == 0 {
				return true
			}
			methodName = chain[len(chain)-1]
			receiver = chain[:len(chain)-1]
		default:
			return true
		}
		if methodName != r.Method {
			return true
		}
		if !sliceEq(receiver, r.Receiver) {
			return true
		}
		// Arity check.
		if r.ArgCount >= 0 {
			args := n.ChildByFieldName("arguments")
			n := 0
			if args != nil {
				for i := uint(0); i < args.ChildCount(); i++ {
					c := args.Child(i)
					if c != nil && c.Kind() == "argument" {
						n++
					}
				}
			}
			if n != r.ArgCount {
				return true
			}
		}
		// Apply the rewrite.
		//
		// When KeepArgs=true we replace ONLY the function span (`fn`),
		// leaving the argument list and its sub-tree untouched. This is
		// nested-call safe: an outer Path.GetFileName(Path.GetDirectoryName(...))
		// rewrite only edits the outer 'Path.GetFileName' bytes, and the inner
		// invocation_expression is visited independently in its own walk and
		// edits the inner 'Path.GetDirectoryName' bytes — no overlap.
		//
		// When KeepArgs=false we replace the entire invocation (function +
		// argument list) so the caller can substitute a completely different
		// expression. This matches the prior behaviour for value-style
		// substitutions (e.g., `Dns.GetHostName() → WfOsInfo.MachineName`).
		if r.KeepArgs {
			edits.Add(fn.StartByte(), fn.EndByte(), []byte(r.Repl))
		} else {
			edits.Add(n.StartByte(), n.EndByte(), []byte(r.Repl))
		}
		return false
	})
}

// MethodResultMemberRewrite matches a member access expression whose
// LHS is a parameterless invocation of a specific static method, and
// rewrites the whole expression in place.
//
// Example: Receiver=["WindowsIdentity"], Method="GetCurrent", Member="Name"
// matches "WindowsIdentity.GetCurrent().Name" and rewrites the whole
// thing to Repl.
//
// Tree shape:
//   member_access_expression
//     ├── expression: invocation_expression
//     │     ├── function: member_access_expression { Receiver, Method }
//     │     └── arguments: argument_list ()
//     └── name: identifier(Member)
type MethodResultMemberRewrite struct {
	Receiver  []string
	Method    string
	Member    string
	Repl      string
	FileGlobs []string
	Desc      string
}

func (r *MethodResultMemberRewrite) Description() string { return r.Desc }
func (r *MethodResultMemberRewrite) Files() []string     { return r.FileGlobs }

func (r *MethodResultMemberRewrite) Visit(root *tree_sitter.Node, source []byte, edits *EditList) {
	walkNodes(root, func(n *tree_sitter.Node) bool {
		if n.Kind() != "member_access_expression" {
			return true
		}
		name := n.ChildByFieldName("name")
		if name == nil || name.Kind() != "identifier" {
			return true
		}
		if string(source[name.StartByte():name.EndByte()]) != r.Member {
			return true
		}
		// LHS must be an invocation_expression with empty args whose
		// function is the receiver.method member chain.
		inv := n.ChildByFieldName("expression")
		if inv == nil || inv.Kind() != "invocation_expression" {
			return true
		}
		fn := inv.ChildByFieldName("function")
		if fn == nil || fn.Kind() != "member_access_expression" {
			return true
		}
		chain, ok := collectMemberChain(fn, source)
		if !ok || len(chain) < 1 {
			return true
		}
		if chain[len(chain)-1] != r.Method {
			return true
		}
		if !sliceEq(chain[:len(chain)-1], r.Receiver) {
			return true
		}
		// Args must be empty.
		args := inv.ChildByFieldName("arguments")
		if args != nil {
			for i := uint(0); i < args.ChildCount(); i++ {
				c := args.Child(i)
				if c != nil && c.Kind() == "argument" {
					return true
				}
			}
		}
		edits.Add(n.StartByte(), n.EndByte(), []byte(r.Repl))
		return false
	})
}

// collectMemberChain walks a member_access_expression's LHS spine and
// returns the dot-separated identifier path, leftmost first. Returns
// ok=false if the chain has anything other than identifiers and
// member_access_expression nodes (e.g. an indexer or a parenthesized
// expression as the leftmost element).
//
// For "TimeZone.CurrentTimeZone.StandardName" the returned chain is
// []string{"TimeZone", "CurrentTimeZone", "StandardName"}.
func collectMemberChain(n *tree_sitter.Node, source []byte) ([]string, bool) {
	var parts []string
	cur := n
	for {
		switch cur.Kind() {
		case "member_access_expression":
			name := cur.ChildByFieldName("name")
			if name == nil || name.Kind() != "identifier" {
				return nil, false
			}
			parts = append([]string{string(source[name.StartByte():name.EndByte()])}, parts...)
			lhs := cur.ChildByFieldName("expression")
			if lhs == nil {
				return nil, false
			}
			cur = lhs
		case "identifier":
			parts = append([]string{string(source[cur.StartByte():cur.EndByte()])}, parts...)
			return parts, true
		default:
			return nil, false
		}
	}
}

// walkNodes does a pre-order traversal of the subtree rooted at root,
// invoking visit on every node. If visit returns false, the subtree at
// that node is skipped (children are not visited).
func walkNodes(root *tree_sitter.Node, visit func(*tree_sitter.Node) bool) {
	if root == nil {
		return
	}
	descend := visit(root)
	if !descend {
		return
	}
	for i := uint(0); i < root.ChildCount(); i++ {
		c := root.Child(i)
		if c == nil {
			continue
		}
		walkNodes(c, visit)
	}
}

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// trim is exposed so test code can normalise rule output without
// importing strings just for one call.
func trim(s string) string { return strings.TrimSpace(s) }
