package patch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEmitDirectPInvokeProps covers the scanner end-to-end:
//   - finds multi-line [DllImport] declarations spread across attribute + signature
//   - dedupes the same DLL referenced from multiple files
//   - emits both "user32" and "user32.dll" forms so NativeAOT-LLVM matches
//     either DllImport spelling
//   - skips bin/, obj/, node_modules/ to avoid scanning generated artifacts
func TestEmitDirectPInvokeProps(t *testing.T) {
	dir := t.TempDir()

	mustWrite(t, filepath.Join(dir, "Interop", "User32.cs"), `
namespace App.Interop {
    internal class User32 {
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool GetLastInputInfo(ref LASTINPUTINFO lpii);

        [DllImport("user32.dll")]
        public static extern IntPtr GetForegroundWindow();
    }
}
`)

	mustWrite(t, filepath.Join(dir, "Interop", "Shell32.cs"), `
namespace App.Interop {
    internal class Shell32 {
        [DllImport("shell32", CharSet = CharSet.Unicode)]
        private static extern IntPtr CommandLineToArgvW(string lpCmdLine, out int pNumArgs);
    }
}
`)

	// Duplicate user32 reference — should not produce duplicate entries.
	mustWrite(t, filepath.Join(dir, "Util", "MoreUser32.cs"), `
[DllImport("user32.dll")] private static extern int OtherFn();
`)

	// File inside bin/ — must be skipped.
	mustWrite(t, filepath.Join(dir, "bin", "Release", "GeneratedInteropStuff.cs"), `
[DllImport("kernel32.dll")] private static extern void IgnoredFn();
`)

	rel, dlls, err := EmitDirectPInvokeProps(dir, false)
	if err != nil {
		t.Fatalf("EmitDirectPInvokeProps: %v", err)
	}
	if rel != filepath.Join("Properties", "WfDirectPInvoke.props") {
		t.Errorf("unexpected props path: %s", rel)
	}

	props, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatalf("reading props: %v", err)
	}
	body := string(props)

	mustContain(t, body, `<DirectPInvoke Include="user32" />`)
	mustContain(t, body, `<DirectPInvoke Include="user32.dll" />`)
	mustContain(t, body, `<DirectPInvoke Include="shell32" />`)

	// bin/ entry must NOT appear.
	if strings.Contains(body, "kernel32") {
		t.Errorf("scanner walked into bin/ — kernel32 should not appear in props:\n%s", body)
	}

	// Dlls list must include the normalized forms.
	have := map[string]bool{}
	for _, d := range dlls {
		have[d] = true
	}
	for _, want := range []string{"user32", "user32.dll", "shell32"} {
		if !have[want] {
			t.Errorf("expected DLL %q in returned slice, got %v", want, dlls)
		}
	}
}

// TestScanDllImports_Multiline ensures we catch DllImport declarations where
// the attribute parameters and the extern signature are on separate lines —
// a common style in GhostPack source.
func TestScanDllImports_Multiline(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "x.cs"), `
[DllImport("advapi32.dll",
    SetLastError = true,
    CharSet = CharSet.Unicode)]
[SuppressUnmanagedCodeSecurity]
private static extern int
    RegOpenKeyExW(IntPtr hKey, string subKey, int options, int sam, out IntPtr phkResult);
`)

	got, err := scanDllImports(dir)
	if err != nil {
		t.Fatalf("scanDllImports: %v", err)
	}

	foundFn := false
	for _, d := range got {
		if d.DLL == "advapi32.dll" && d.Function == "RegOpenKeyExW" {
			foundFn = true
			break
		}
	}
	if !foundFn {
		t.Errorf("expected to capture advapi32.dll:RegOpenKeyExW, got %+v", got)
	}
}
