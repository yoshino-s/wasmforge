package patch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCertificatesRuleFires verifies that the Certificates.cs patcher rule
// matches the upstream Seatbelt source and replaces X509Store with WfX509Store.
// This is a regression test for the trailing-space mismatch bug where the Old:
// text had "if (extUsages.Count == 0)" but upstream has a trailing space after "0".
//
// The test reads the actual pristine source from /tmp/seatbelt-pristine (which is
// the canonical upstream Seatbelt source used by the docker build pipeline) so it
// will catch any future upstream drift as well.
func TestCertificatesRuleFires(t *testing.T) {
	const pristinePath = "/tmp/seatbelt-fresh/Commands/Windows/Certificates.cs"
	if _, err := os.Stat(pristinePath); os.IsNotExist(err) {
		t.Skip("pristine Seatbelt source not present at " + pristinePath + "; set up a local copy if you want to run this test")
	}
	src, err := os.ReadFile(pristinePath)
	if err != nil {
		t.Skipf("pristine Seatbelt source not available at %s (run docker build pipeline first): %v", pristinePath, err)
	}

	dir := t.TempDir()
	subdir := filepath.Join(dir, "Commands", "Windows")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	csPath := filepath.Join(subdir, "Certificates.cs")
	if err := os.WriteFile(csPath, src, 0644); err != nil {
		t.Fatal(err)
	}

	applied, err := ApplyCSharpPatches(dir, false)
	if err != nil {
		t.Fatalf("ApplyCSharpPatches error: %v", err)
	}
	t.Logf("patcher applied %d rules total", applied)

	out, err := os.ReadFile(csPath)
	if err != nil {
		t.Fatal(err)
	}
	outStr := string(out)

	if !strings.Contains(outStr, "WfX509Store.EnumerateCerts") {
		t.Errorf("Certificates rule did NOT fire: WfX509Store.EnumerateCerts not found in patched output")
		// Show context to help diagnose
		idx := strings.Index(outStr, "Execute(string[] args)")
		if idx >= 0 && idx+600 < len(outStr) {
			t.Logf("Execute body after patching:\n%s", outStr[idx:idx+600])
		} else {
			t.Logf("Full patched output:\n%s", outStr)
		}
	}

	if strings.Contains(outStr, "store.Open(OpenFlags.ReadOnly)") {
		t.Errorf("old X509Store.Open code still present in patched output — rule did not replace Execute body")
	}

	if strings.Contains(outStr, "certificate.PrivateKey.ToXmlString") {
		t.Errorf("old PrivateKey.ToXmlString still present — stub replacement failed")
	}
}

// TestCertificatesRuleFiresOnPrePatchedSource guards against the regression
// observed on Ludus 2026-06-05: an older patcher version wrapped the
// "var store = new X509Store(...)" assignment in a
// "X509Store store = null; try { ... } catch (PlatformNotSupportedException)
// { continue; }" block before the WfX509Store rewrite landed. When fresh
// builds re-applied the patcher on the same source tree, the rewrite's
// `Old:` text no longer matched and the rule silently fell through —
// Certificates and CertificateThumbprints went from 0/2 to 0/2 with
// empty output because the BCL X509Store path stayed live.
//
// The fix is a defensive sibling rule whose `Old:` matches the modified
// form. This test asserts the rule fires on a synthetic input that
// mimics the corrupted Ludus source.
func TestCertificatesRuleFiresOnPrePatchedSource(t *testing.T) {
	// Use the same pristine path as TestCertificatesRuleFires; skip if missing.
	const pristinePath = "/tmp/seatbelt-pristine/Seatbelt/Commands/Windows/Certificates.cs"
	src, err := os.ReadFile(pristinePath)
	if err != nil {
		t.Skipf("pristine Seatbelt source not available at %s: %v", pristinePath, err)
	}

	// Apply the modification that an older patcher version did, in-memory:
	pristineLine := `var store = new X509Store(StoreName.My, (StoreLocation)storeLocation);`
	modifiedLine := `X509Store store = null; try { store = new X509Store(StoreName.My, (StoreLocation)storeLocation); } catch (PlatformNotSupportedException) { continue; }`
	preModified := strings.Replace(string(src), pristineLine, modifiedLine, 1)
	if preModified == string(src) {
		t.Fatalf("pristine source did not contain expected line %q", pristineLine)
	}

	dir := t.TempDir()
	subdir := filepath.Join(dir, "Commands", "Windows")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	csPath := filepath.Join(subdir, "Certificates.cs")
	if err := os.WriteFile(csPath, []byte(preModified), 0644); err != nil {
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

	if !strings.Contains(outStr, "WfX509Store.EnumerateCerts") {
		t.Errorf("Defensive Certificates rule did NOT fire on pre-modified source.\n"+
			"The pre-fixup rule should unwrap the try/catch, then the whole-body rule should rewrite to WfX509Store.\n"+
			"Patched output (truncated):\n%s",
			truncateForLog(outStr, 1500))
	}
	if strings.Contains(outStr, "store.Open(OpenFlags.ReadOnly)") {
		t.Errorf("old store.Open chain survived on pre-modified source")
	}
}

func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "... [truncated]"
}
