// csharp_ast_patcher_test.go — Phase 3 Task 3.1 smoke test.

package patch

import (
	"strings"
	"testing"
)

// TestTreeSitterCSharpSmoke confirms the tree-sitter-c-sharp grammar is
// loaded correctly and produces a sensible AST for a representative
// snippet of Seatbelt-style C# (a class with a DllImport attribute on a
// static extern method).
func TestTreeSitterCSharpSmoke(t *testing.T) {
	src := []byte(`using System.Runtime.InteropServices;

namespace Seatbelt.Interop
{
    public class Netapi32
    {
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        public static extern uint NetLocalGroupEnum(
            string serverName,
            uint level,
            out IntPtr bufptr,
            uint prefmaxlen,
            out uint entriesread,
            out uint totalentries,
            ref uint resumehandle);
    }
}`)

	tree, err := ParseCSharp(src)
	if err != nil {
		t.Fatalf("ParseCSharp: %v", err)
	}
	defer tree.Close()

	root := tree.RootNode()
	if root == nil {
		t.Fatal("tree.RootNode() returned nil")
	}

	// Grammar sanity: the root is a compilation_unit.
	if root.Kind() != "compilation_unit" {
		t.Errorf("root kind = %q, want compilation_unit", root.Kind())
	}

	counts := CountNodes(root)

	// Expect at least one of each structural construct we'll match in
	// real patcher rules. If any of these are 0, the grammar isn't
	// recognizing standard C# and rule authoring will be impossible.
	required := []string{
		"compilation_unit",
		"using_directive",
		"namespace_declaration",
		"class_declaration",
		"attribute",         // [DllImport(...)]
		"method_declaration", // public static extern uint NetLocalGroupEnum(...)
		"parameter",         // method parameters
	}
	for _, kind := range required {
		if counts[kind] == 0 {
			t.Errorf("expected at least 1 %q node, got 0", kind)
		}
	}

	t.Logf("Parsed %d-byte source into tree with %d distinct node kinds, %d nodes total",
		len(src), len(counts), nodeTotal(counts))
}

// TestEditListBottomUp validates the EditList ApplyBottomUp helper.
// Multiple overlapping-safe edits applied in descending order should
// produce the expected result without any byte-offset corruption.
func TestEditListBottomUp(t *testing.T) {
	src := []byte("HELLO WORLD AND GOODBYE")

	var edits EditList
	// Replace "WORLD" → "EARTH" (offsets 6..11)
	edits.Add(6, 11, []byte("EARTH"))
	// Replace "GOODBYE" → "FAREWELL" (offsets 16..23)
	edits.Add(16, 23, []byte("FAREWELL"))

	out, err := edits.ApplyBottomUp(src)
	if err != nil {
		t.Fatalf("ApplyBottomUp: %v", err)
	}
	want := "HELLO EARTH AND FAREWELL"
	if string(out) != want {
		t.Errorf("got %q, want %q", string(out), want)
	}
}

// TestEditListOverlapDetected ensures that two edits that overlap each
// other are rejected with a clear error (rather than silently producing
// garbage).
func TestEditListOverlapDetected(t *testing.T) {
	src := []byte("AAAA BBBB CCCC")

	var edits EditList
	edits.Add(0, 6, []byte("xxx"))  // covers "AAAA B"
	edits.Add(4, 9, []byte("yyy"))  // covers " BBBB"

	_, err := edits.ApplyBottomUp(src)
	if err == nil {
		t.Fatal("expected overlapping-edit error, got nil")
	}
	if !strings.Contains(err.Error(), "overlapping edits") {
		t.Errorf("error %v doesn't mention overlapping edits", err)
	}
}

func nodeTotal(counts map[string]int) int {
	n := 0
	for _, c := range counts {
		n += c
	}
	return n
}
