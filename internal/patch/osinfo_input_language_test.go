package patch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOSInfoInputLanguageRoutedToLayoutName guards the OSInfo
// InputLanguage field. Pristine sources contain
//
//	var inputLanguage = System.Globalization.CultureInfo.CurrentCulture.DisplayName /*WF-InputLang*/;
//
// where CultureInfo.CurrentCulture.DisplayName on WASI returns
// "Invariant Language (Invariant Country)". Native Seatbelt baseline
// emits the short layout name "US" (from
// HKLM\System\CurrentControlSet\Control\Keyboard Layouts\<KLID>\Layout Text).
//
// WfOsInfo.InputLanguageLayoutName() already implements that read
// via user32!GetKeyboardLayoutNameW + WfRegistry lookup. We just need
// a patcher fixup that flips the pre-patched form to it.
func TestOSInfoInputLanguageRoutedToLayoutName(t *testing.T) {
	preModified := []byte(`namespace Seatbelt.Commands {
    class T {
        void Execute() {
            var inputLanguage = System.Globalization.CultureInfo.CurrentCulture.DisplayName /*WF-InputLang*/;
        }
    }
}`)

	dir := t.TempDir()
	subdir := filepath.Join(dir, "Commands", "Windows")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	csPath := filepath.Join(subdir, "OSInfoCommand.cs")
	if err := os.WriteFile(csPath, preModified, 0644); err != nil {
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

	if !strings.Contains(outStr, "WasmForge.Helpers.WfOsInfo.InputLanguageLayoutName()") {
		t.Errorf("InputLanguage fixup did NOT fire — should route to WfOsInfo.InputLanguageLayoutName.\n"+
			"Patched output:\n%s", outStr)
	}
	if strings.Contains(outStr, "CultureInfo.CurrentCulture.DisplayName") {
		t.Errorf("CultureInfo.CurrentCulture.DisplayName survives — InputLanguage will render 'Invariant Language' instead of the real layout name ('US')")
	}
}
