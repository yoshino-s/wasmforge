package patch_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/wasmforge/internal/patch"
	"github.com/praetorian-inc/wasmforge/internal/patch/rules"
)

// TestWfPathRewrites verifies the Path.* → WfPath.* AST rewrites fire on
// realistic call-site patterns. Under NativeAOT-WASI the runtime sets
// DirectorySeparatorChar='/' so BCL Path.GetFileName cannot split on
// backslash; verified empirically with a minimal harness. The patcher
// must redirect all such calls to WfPath which splits on both '\' and '/'.
func TestWfPathRewrites(t *testing.T) {
	src := []byte(`namespace Seatbelt.Commands {
    using System.IO;
    class T {
        void M(string credFilePath) {
            var fileName = Path.GetFileName(credFilePath);
            var dir = System.IO.Path.GetDirectoryName(credFilePath);
            var ext = Path.GetExtension(credFilePath);
            var stem = Path.GetFileNameWithoutExtension(credFilePath);
            var name2 = System.IO.Path.GetFileName(credFilePath);
        }
    }
}`)

	dir := t.TempDir()
	subdir := filepath.Join(dir, "Commands")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	csPath := filepath.Join(subdir, "T.cs")
	if err := os.WriteFile(csPath, src, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, _, err := patch.ApplyCSharpASTPatches(dir, rules.AllNativeAOTASTRules(), false); err != nil {
		t.Fatalf("ApplyCSharpASTPatches: %v", err)
	}

	out, err := os.ReadFile(csPath)
	if err != nil {
		t.Fatal(err)
	}
	outStr := string(out)

	wants := []string{
		"WasmForge.Helpers.WfPath.GetFileName(credFilePath)",
		"WasmForge.Helpers.WfPath.GetDirectoryName(credFilePath)",
		"WasmForge.Helpers.WfPath.GetExtension(credFilePath)",
		"WasmForge.Helpers.WfPath.GetFileNameWithoutExtension(credFilePath)",
	}
	for _, want := range wants {
		if !strings.Contains(outStr, want) {
			t.Errorf("missing rewrite %q in patched output:\n%s", want, outStr)
		}
	}

	// Verify the pre-patched Path.X calls are gone — but the FQ form
	// "System.IO.Path." prefix may survive on namespace-qualified calls
	// because the rewrite replaces "System.IO.Path.GetFileName" with
	// the full WfPath path; the "System.IO.Path." string fragment must
	// no longer appear before a method call.
	for _, leftover := range []string{
		"Path.GetFileName(",
		"Path.GetDirectoryName(",
		"Path.GetExtension(",
		"Path.GetFileNameWithoutExtension(",
	} {
		// Strip out the WfPath substrings before checking — "WfPath.GetFileName(" trivially
		// contains "Path.GetFileName(" as a substring.
		cleaned := strings.ReplaceAll(outStr, "WfPath."+strings.TrimPrefix(leftover, "Path."), "")
		if strings.Contains(cleaned, leftover) {
			t.Errorf("call site %q survived rewrite:\n%s", leftover, outStr)
		}
	}
}

// TestWfPathRewritesNested guards the nested-call case that motivated
// the InvocationRewrite KeepArgs change: under the old semantics, the
// outer Path.GetFileName rewrite would replace the entire invocation
// span (including the inner Path.GetDirectoryName) — overlapping with
// the inner rule's edit and producing an overlapping-edit error in
// EditList.ApplyBottomUp (SharpDPAPI's Dpapi.cs hit this exact case).
// Under the new semantics each rule rewrites only the function span,
// leaving the argument list intact, so both rules can fire safely.
func TestWfPathRewritesNested(t *testing.T) {
	src := []byte(`namespace Seatbelt.Commands {
    using System.IO;
    class T {
        void M(string masterKeyPath) {
            var sid = Path.GetFileName(Path.GetDirectoryName(masterKeyPath));
        }
    }
}`)
	dir := t.TempDir()
	subdir := filepath.Join(dir, "Commands")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	csPath := filepath.Join(subdir, "T.cs")
	if err := os.WriteFile(csPath, src, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := patch.ApplyCSharpASTPatches(dir, rules.AllNativeAOTASTRules(), false); err != nil {
		t.Fatalf("ApplyCSharpASTPatches: %v", err)
	}
	out, err := os.ReadFile(csPath)
	if err != nil {
		t.Fatal(err)
	}
	outStr := string(out)
	// Both rewrites must fire.
	if !strings.Contains(outStr, "WasmForge.Helpers.WfPath.GetFileName(WasmForge.Helpers.WfPath.GetDirectoryName(masterKeyPath))") {
		t.Errorf("nested rewrite missing or wrong shape:\n%s", outStr)
	}
}
