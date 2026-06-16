package normalize

import "testing"

// TestNormalize_ChromeVersionLine asserts that Seatbelt
// ChromiumPresenceCommand's per-row "Chrome Version : N.N.N.N" field
// normalizes to <VERSION> so parity isn't broken by auto-updates.
// The same <VERSION> tag is already used for the GhostPack tool banner;
// reusing it keeps the contract narrow (no new placeholder for every
// vendor that ships dotted version numbers).
func TestNormalize_ChromeVersionLine(t *testing.T) {
	in := "             Chrome Version                       :  148.0.7778.217"
	want := "             Chrome Version                       :  <VERSION>"
	got := Normalize(in, Default())
	if got != want {
		t.Errorf("Chrome Version\n  in:   %q\n  got:  %q\n  want: %q", in, got, want)
	}
}

// TestNormalize_ChromeVersionDriftPreservesContext checks the
// surrounding lines stay intact — we are only collapsing the
// version number, not the whole row.
func TestNormalize_ChromeVersionDriftPreservesContext(t *testing.T) {
	in := `  C:\Users\localuser\AppData\Local\Google\Chrome\User Data\Default\

    'History'     (<TIMESTAMP>)  :  Run the 'ChromiumHistory' command
     Chrome Version                       :  149.0.7827.53`
	want := `  C:\Users\localuser\AppData\Local\Google\Chrome\User Data\Default\

    'History'     (<TIMESTAMP>)  :  Run the 'ChromiumHistory' command
     Chrome Version                       :  <VERSION>`
	got := Normalize(in, Default())
	if got != want {
		t.Errorf("Chrome Version (context)\n  in:\n%s\n  got:\n%s\n  want:\n%s", in, got, want)
	}
}

// TestNormalize_GhostPackBannerVersionStillWorks regression-guards the
// existing reToolVersion behavior: extending the regex must not break
// the original banner-line match. The banner uses the 3-part form
// "  v2.3.2" right-padded; Chrome uses 4-part "148.0.7778.217" inline.
func TestNormalize_GhostPackBannerVersionStillWorks(t *testing.T) {
	in := "  v2.3.2 "
	want := "  <VERSION>"
	got := Normalize(in, Default())
	if got != want {
		t.Errorf("Tool banner version\n  in:   %q\n  got:  %q\n  want: %q", in, got, want)
	}
}

// TestNormalize_TwoPartVersionUnchanged guards against the over-eager
// regex that previously normalized "CurrentVersion : 6.3" (2-part
// dotted number) to "<VERSION>", breaking OSInfo parity. The
// CurrentVersion field is the Windows kernel version label which is
// always emitted as the literal "6.3" — never with build number.
// Only 3+ part dotted-quad versions (typical "marketing" versions
// like Chrome 149.0.7827.53 or .NET 6.0.32.41033) should normalize.
func TestNormalize_TwoPartVersionUnchanged(t *testing.T) {
	in := "  CurrentVersion                 :  6.3"
	want := "  CurrentVersion                 :  6.3"
	got := Normalize(in, Default())
	if got != want {
		t.Errorf("CurrentVersion 2-part\n  in:   %q\n  got:  %q\n  want: %q", in, got, want)
	}
}

// TestNormalize_ThreePartVersionNormalized confirms the 3-part case
// (e.g., .NET 6.0.32) still matches — Chrome's 4-part case already
// covered by TestNormalize_ChromeVersionLine.
func TestNormalize_ThreePartVersionNormalized(t *testing.T) {
	in := "Build Version : 6.0.32"
	want := "Build Version : <VERSION>"
	got := Normalize(in, Default())
	if got != want {
		t.Errorf(".NET 3-part\n  in:   %q\n  got:  %q\n  want: %q", in, got, want)
	}
}
