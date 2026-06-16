package patch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstalledInputLanguagesEmptyArray locks in the OSInfo
// InstalledInputLanguages contract: the rewritten foreach must iterate
// over an EMPTY CultureInfo array, not a single-element array containing
// CurrentCulture. Otherwise the rendered list shows
// "Invariant Language (Invariant Country)" on WASI instead of the empty
// list the native baseline emits.
//
// Coverage gap: an older patcher version inserted the wrong array form
// (`new[] { CultureInfo.CurrentCulture }`) and the source-on-disk on
// every existing seatbelt-fresh tree carries that broken pattern. This
// test reproduces that pre-modified form, runs the patcher, and asserts
// the empty array survives.
func TestInstalledInputLanguagesEmptyArray(t *testing.T) {
	// Synthetic source representing the pre-modified state we keep
	// finding on seatbelt-fresh trees.
	preModified := []byte(`namespace Seatbelt.Commands {
    class T {
        void Execute() {
            var installedInputLanguages = new System.Collections.Generic.List<string>();
            foreach (var l in new[] { System.Globalization.CultureInfo.CurrentCulture }) /*WF-InputLang-foreach*/
                installedInputLanguages.Add(l.DisplayName); /*WF-InputLang-LayoutName*/
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

	// SUCCESS: foreach iterates over empty CultureInfo[] — list stays empty.
	if !strings.Contains(outStr, "new System.Globalization.CultureInfo[0]") {
		t.Errorf("InstalledInputLanguages fixup rule did NOT fire — output still iterates a non-empty array.\n"+
			"Patched output:\n%s", outStr)
	}
	// FAILURE: the broken non-empty array form is still present.
	if strings.Contains(outStr, "new[] { System.Globalization.CultureInfo.CurrentCulture }") {
		t.Errorf("Broken non-empty array form survives — InstalledInputLanguages will render 'Invariant Language' instead of blank")
	}
}
