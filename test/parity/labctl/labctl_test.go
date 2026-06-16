package labctl

import (
	"strings"
	"testing"
)

// TestStripBanner verifies the Seatbelt banner block is removed but
// trailing data is preserved.
func TestStripBanner(t *testing.T) {
	in := strings.Join([]string{
		"some leading line",
		"%&&@@@&& Seatbelt fancy banner top",
		"banner middle line 1",
		"banner middle line 2",
		"#%%%%## banner bottom",
		"after banner: real data",
		"more real data",
	}, "\n")
	got := StripBanner(in)
	if strings.Contains(got, "banner middle line") {
		t.Errorf("expected banner middle lines to be stripped; got %q", got)
	}
	if !strings.Contains(got, "some leading line") {
		t.Errorf("expected pre-banner content to be preserved; got %q", got)
	}
	if !strings.Contains(got, "after banner: real data") {
		t.Errorf("expected post-banner content to be preserved; got %q", got)
	}
}

// TestStripBannerNoBanner is a no-op when no banner is present.
func TestStripBannerNoBanner(t *testing.T) {
	in := "line one\nline two\nline three"
	if got := StripBanner(in); got != in {
		t.Errorf("StripBanner without banner should be identity; got %q", got)
	}
}

// TestRunOnWin11 is the end-to-end smoke test of the labctl wrapper.
// It SKIPs cleanly when the lab is unreachable.
func TestRunOnWin11(t *testing.T) {
	SkipIfLabDown(t)

	pushed, err := Push("/tmp/wf-out/seatbelt.exe", "seatbelt-labctl-test.exe")
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	out, err := pushed.Run("WindowsVault")
	if err != nil {
		t.Fatalf("Run WindowsVault: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "Completed collection") {
		t.Errorf("expected output to contain 'Completed collection'; got first 500 chars:\n%s",
			head(out, 500))
	}
}

func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
