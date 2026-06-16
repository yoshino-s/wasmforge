package patch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOSInfoUsernameRoutedToWindowsIdentityName guards the OSInfo
// Username field's emission. Pristine seatbelt-fresh sources contain
//
//	yield return new OSInfoDTO(
//	    strHostName,
//	    dnsDomain,
//	    (Environment.UserName ?? "unknown"),
//	    ...);
//
// The generic Environment.UserName → WfOsInfo.UserName() AST rule then
// rewrites that arg slot to return the bare username ("localuser"). But
// the native Seatbelt baseline (built from a Seatbelt revision that
// used WindowsIdentity.GetCurrent().Name) emits the DOMAIN\username
// form ("GOADF97252-GOAD\\localuser"). To produce byte-identical
// goldens we need a targeted rewrite at this one OSInfo call site only,
// not a global Environment.UserName change.
//
// Verifying the fix: after running the patcher on the pristine line, the
// arg slot must reference WfOsInfo.WindowsIdentityName, not UserName.
func TestOSInfoUsernameRoutedToWindowsIdentityName(t *testing.T) {
	// Synthetic source that mirrors OSInfoCommand.cs after the generic
	// Environment.UserName → WfOsInfo.UserName() AST rule has run. The
	// OSInfo-specific text rule should fire AFTER the AST rule (to avoid
	// overlapping-edit conflicts in the patcher engine) and flip the
	// post-AST form to WindowsIdentityName.
	pristine := []byte(`namespace Seatbelt.Commands {
    class T {
        void Execute() {
            yield return new OSInfoDTO(
                strHostName,
                dnsDomain,
                (Environment.UserName ?? "unknown"),
                ProductName);
        }
    }
}`)

	dir := t.TempDir()
	subdir := filepath.Join(dir, "Commands", "Windows")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	csPath := filepath.Join(subdir, "OSInfoCommand.cs")
	if err := os.WriteFile(csPath, pristine, 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := ApplyCSharpPatches(dir, false); err != nil {
		t.Fatalf("ApplyCSharpPatches: %v", err)
	}

	out, err := os.ReadFile(csPath)
	if err != nil {
		t.Fatal(err)
	}
	outStr := string(out)

	if !strings.Contains(outStr, "WasmForge.Helpers.WfOsInfo.WindowsIdentityName()") {
		t.Errorf("OSInfo Username rule did NOT fire — WfOsInfo.WindowsIdentityName not present.\n"+
			"Patched output:\n%s", outStr)
	}
	// After the targeted text rule runs, WfOsInfo.UserName() at the OSInfo
	// DTO ctor's third arg slot must be gone — replaced by WindowsIdentityName.
	if strings.Contains(outStr, "WasmForge.Helpers.WfOsInfo.UserName()") {
		t.Errorf("OSInfo Username slot still has WfOsInfo.UserName() (bare username) — text rule didn't flip it to WindowsIdentityName (DOMAIN\\user)")
	}
}
