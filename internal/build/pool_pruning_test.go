package build

import (
	"testing"
)

// TestSelectDiverseImports_ReducedPool verifies SelectDiverseImports works
// correctly with the pruned 4-entry importDiversityPool (crypt32 + 2 of 3).
func TestSelectDiverseImports_ReducedPool(t *testing.T) {
	// Verify pool size is exactly 4.
	if got := len(importDiversityPool); got != 4 {
		t.Fatalf("importDiversityPool: expected 4 entries, got %d", got)
	}

	// Verify crypt32.dll is always the first selected DLL.
	for iter := 0; iter < 20; iter++ {
		r := SelectDiverseImports()
		if r[0].DLL != "crypt32.dll" {
			t.Fatalf("iteration %d: first DLL should be crypt32.dll, got %s", iter, r[0].DLL)
		}
	}

	// Run multiple iterations to exercise randomness paths.
	for i := 0; i < 50; i++ {
		result := SelectDiverseImports()
		if len(result) != 3 {
			t.Fatalf("iteration %d: SelectDiverseImports returned %d entries, want 3", i, len(result))
		}

		// Each entry must have at least 1 function.
		for _, entry := range result {
			if entry.DLL == "" {
				t.Errorf("iteration %d: empty DLL name in result", i)
			}
			if len(entry.Funcs) < 1 || len(entry.Funcs) > 3 {
				t.Errorf("iteration %d: DLL %s has %d funcs, want 1-3", i, entry.DLL, len(entry.Funcs))
			}
		}

		// All 3 selected DLLs must be distinct.
		seen := make(map[string]bool)
		for _, entry := range result {
			if seen[entry.DLL] {
				t.Errorf("iteration %d: duplicate DLL %s in selection", i, entry.DLL)
			}
			seen[entry.DLL] = true
		}
	}
}

// TestImportDiversityPool_NoShell32 verifies shell32.dll was removed from the pool.
func TestImportDiversityPool_NoShell32(t *testing.T) {
	for _, entry := range importDiversityPool {
		if entry.DLL == "shell32.dll" {
			t.Errorf("shell32.dll should have been removed from importDiversityPool (VT correlation: 64%% both-detected)")
		}
	}
}

// TestImportDiversityPool_NoRemovedDLLs checks that all previously-removed DLLs stay out.
func TestImportDiversityPool_NoRemovedDLLs(t *testing.T) {
	removed := []string{
		"shell32.dll",  // 2026-04-08: 0/3 clean, 64% both-detected
		"version.dll",  // 2026-05-14: crypt32+iphlpapi+version = 83% MS detection
		"user32.dll",   // 2026-04-08: 0/3 clean, 53% detected
		"ws2_32.dll",   // 2026-04-08: 0/3 clean, 41% detected
		"wtsapi32.dll", // 2026-04-07: 0/5 clean
		"netapi32.dll", // 2026-03-18: 0% clean
		"ole32.dll",    // 2026-03-18: 0% clean
		"winhttp.dll",  // 2026-03-18: 0% clean
	}

	for _, entry := range importDiversityPool {
		for _, bad := range removed {
			if entry.DLL == bad {
				t.Errorf("%s should not be in importDiversityPool (previously removed for high detection)", bad)
			}
		}
	}
}

// TestPEProductPool_ReducedSize verifies the product pool has exactly 3 entries.
func TestPEProductPool_ReducedSize(t *testing.T) {
	if got := len(peProductPool); got != 5 {
		t.Fatalf("peProductPool: expected 5 entries, got %d", got)
	}
}

// TestPEProductPool_NoRemovedProducts verifies risky products were removed.
func TestPEProductPool_NoRemovedProducts(t *testing.T) {
	removed := []string{
		"Storage Optimizer Service",      // 2026-04-08: 0/5 clean, 100% both-detected
		"Windows Resource Monitor",       // 2026-04-08: 0/3 clean, 67% both-detected
		"Infrastructure Health Monitor",  // 2026-04-09: 3/6 clean, all 3 AVG detections in noopt batch
		"Disk Cleanup Manager",       // 2026-04-07: 0/5 clean
		"Windows Memory Diagnostic",  // 2026-04-07: 0/5 clean
		"Deployment Imaging Service", // 2026-04-07: 0/5 clean
		"Group Policy Service",       // 2026-04-07: 0/5 clean
	}

	for _, entry := range peProductPool {
		for _, bad := range removed {
			if entry.Product == bad {
				t.Errorf("product %q should not be in peProductPool (previously removed for high detection)", bad)
			}
		}
	}
}

// TestPEProductPool_EntriesCoherent verifies each product entry has all required fields.
func TestPEProductPool_EntriesCoherent(t *testing.T) {
	for i, entry := range peProductPool {
		if entry.Product == "" {
			t.Errorf("peProductPool[%d]: empty Product", i)
		}
		if entry.Filename == "" {
			t.Errorf("peProductPool[%d]: empty Filename", i)
		}
		if entry.Description == "" {
			t.Errorf("peProductPool[%d]: empty Description", i)
		}
	}
}

// TestPEFileVersionPool_ReducedSize verifies the version pool has exactly 2 entries.
func TestPEFileVersionPool_ReducedSize(t *testing.T) {
	if got := len(peFileVersionPool); got != 2 {
		t.Fatalf("peFileVersionPool: expected 2 entries, got %d", got)
	}
}

// TestPEFileVersionPool_NoRemovedVersions verifies risky versions were removed.
func TestPEFileVersionPool_NoRemovedVersions(t *testing.T) {
	removed := []string{
		"10.0.1.0",     // 2026-04-08: 0/6 clean, 83% both-detected
		"1.0.0.1",      // 2026-04-08: 0/4 clean, 50% both
		"12.0.0.1",     // 2026-04-08: 0/4 clean, 50% both
		"10.0.22621.1", // 2026-04-08: risky
		"10.0.22631.1", // 2026-04-08: risky
		"11.0.0.1",     // 2026-04-08: risky
		"2.1.0.0",      // 2026-04-08: risky
		"5.0.0.0",      // 2026-04-08: risky
	}

	for _, ver := range peFileVersionPool {
		for _, bad := range removed {
			if ver == bad {
				t.Errorf("version %q should not be in peFileVersionPool (previously removed for high detection)", bad)
			}
		}
	}
}

// TestPEFileVersionPool_RandChoice verifies randChoice works with the 2-entry pool.
func TestPEFileVersionPool_RandChoice(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		v, err := randChoice(peFileVersionPool)
		if err != nil {
			t.Fatalf("iteration %d: randChoice(peFileVersionPool) error: %v", i, err)
		}
		if v == "" {
			t.Fatalf("iteration %d: randChoice returned empty string", i)
		}
		seen[v] = true
	}
	// With 50 iterations and 2 entries, both should appear.
	if len(seen) != 2 {
		t.Errorf("expected both peFileVersionPool entries to be selected over 50 iterations, got %d unique: %v", len(seen), seen)
	}
}

// TestPEProductPool_RandInt verifies randInt works with the 5-entry pool.
func TestPEProductPool_RandInt(t *testing.T) {
	seen := make(map[int]bool)
	for i := 0; i < 100; i++ {
		idx, err := randInt(len(peProductPool))
		if err != nil {
			t.Fatalf("iteration %d: randInt(%d) error: %v", i, len(peProductPool), err)
		}
		if idx < 0 || idx >= len(peProductPool) {
			t.Fatalf("iteration %d: randInt returned %d, out of bounds [0,%d)", i, idx, len(peProductPool))
		}
		seen[idx] = true
	}
	// With 100 iterations and 5 entries, all should appear.
	if len(seen) != 5 {
		t.Errorf("expected all 5 peProductPool indices to be selected over 100 iterations, got %d unique", len(seen))
	}
}

// TestSignDescriptionPool_RandChoice verifies signDescriptionPool has 9 entries
// and randSignDescription() covers all of them over 50 calls.
func TestSignDescriptionPool_RandChoice(t *testing.T) {
	if got := len(signDescriptionPool); got != 9 {
		t.Fatalf("signDescriptionPool: expected 9 entries, got %d", got)
	}
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		v := randSignDescription()
		if v == "" {
			t.Fatalf("iteration %d: randSignDescription returned empty string", i)
		}
		seen[v] = true
	}
	if len(seen) != 9 {
		t.Errorf("expected all 9 signDescriptionPool entries to be selected over 50 iterations, got %d unique: %v", len(seen), seen)
	}
}

// TestSignURLPool_RandChoice verifies signURLPool has 7 entries, that
// randSignURL() never returns "", and that every returned value starts with "https://".
func TestSignURLPool_RandChoice(t *testing.T) {
	if got := len(signURLPool); got != 7 {
		t.Fatalf("signURLPool: expected 7 entries, got %d", got)
	}
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		v := randSignURL()
		if v == "" {
			t.Fatalf("iteration %d: randSignURL returned empty string", i)
		}
		if len(v) < 8 || v[:8] != "https://" {
			t.Fatalf("iteration %d: randSignURL returned %q, expected value starting with \"https://\"", i, v)
		}
		seen[v] = true
	}
	if len(seen) != 7 {
		t.Errorf("expected all 7 signURLPool entries to be selected over 50 iterations, got %d unique: %v", len(seen), seen)
	}
}

// TestSignIssuerSuffixPool_RandChoice verifies signIssuerSuffixPool has 6 entries,
// that the empty-string entry at index 0 is load-bearing (regression anchor), and
// that randIssuerSuffix() covers all 6 entries over 50 calls.
func TestSignIssuerSuffixPool_RandChoice(t *testing.T) {
	if got := len(signIssuerSuffixPool); got != 6 {
		t.Fatalf("signIssuerSuffixPool: expected 6 entries, got %d", got)
	}
	// Regression anchor: the empty-string entry must remain at index 0.
	if signIssuerSuffixPool[0] != "" {
		t.Fatalf("signIssuerSuffixPool[0]: expected empty string (load-bearing), got %q", signIssuerSuffixPool[0])
	}
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		v := randIssuerSuffix()
		seen[v] = true
	}
	if len(seen) != 6 {
		t.Errorf("expected all 6 signIssuerSuffixPool entries to be selected over 50 iterations, got %d unique: %v", len(seen), seen)
	}
}

// TestSignHelpers_EmptyPoolFallback verifies that each helper returns its
// documented fallback value when its pool is empty. This is the only test
// that exercises the err != nil branch inside each helper.
func TestSignHelpers_EmptyPoolFallback(t *testing.T) {
	// Save originals and restore via t.Cleanup.
	origDesc := signDescriptionPool
	origURL := signURLPool
	origSuffix := signIssuerSuffixPool
	t.Cleanup(func() {
		signDescriptionPool = origDesc
		signURLPool = origURL
		signIssuerSuffixPool = origSuffix
	})

	signDescriptionPool = []string{}
	signURLPool = []string{}
	signIssuerSuffixPool = []string{}

	if got := randSignDescription(); got != "Tool" {
		t.Errorf("randSignDescription() with empty pool: got %q, want %q", got, "Tool")
	}
	if got := randSignURL(); got != "https://example.org" {
		t.Errorf("randSignURL() with empty pool: got %q, want %q", got, "https://example.org")
	}
	if got := randIssuerSuffix(); got != "" {
		t.Errorf("randIssuerSuffix() with empty pool: got %q, want %q (empty string)", got, "")
	}
}

// TestCompanyPool_ExpandedAndPruned verifies companyPool has exactly 5 entries
// containing the expected new names and does not contain any Wacatac-triggering
// legacy entry (e.g. "HashiCorp, Inc."). Mirrors TestPEFileVersionPool_NoRemovedVersions.
func TestCompanyPool_ExpandedAndPruned(t *testing.T) {
	if got := len(companyPool); got != 5 {
		t.Fatalf("companyPool: expected 5 entries, got %d: %v", got, companyPool)
	}

	want := []string{
		"GitLab Inc.",
		"JFrog Ltd.",
		"Canonical Ltd.",
		"Cloudflare, Inc.",
		"Network Component Authors",
	}
	poolSet := make(map[string]bool, len(companyPool))
	for _, v := range companyPool {
		poolSet[v] = true
	}
	for _, name := range want {
		if !poolSet[name] {
			t.Errorf("companyPool missing expected entry %q", name)
		}
	}

	// Regression: burned names must not reappear.
	burned := []string{"HashiCorp, Inc."}
	for _, name := range burned {
		if poolSet[name] {
			t.Errorf("companyPool contains removed entry %q (Wacatac trigger)", name)
		}
	}
}
