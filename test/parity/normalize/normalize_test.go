package normalize

import (
	"strings"
	"testing"
)

func TestNormalize_Timestamp(t *testing.T) {
	in := "BootTimeUtc (approx)          :  05/26/2026 21:42:50"
	want := "BootTimeUtc (approx)          :  <TIMESTAMP>"
	got := Normalize(in, Default())
	if got != want {
		t.Errorf("timestamp\n  in:   %q\n  got:  %q\n  want: %q", in, got, want)
	}
}

func TestNormalize_GUID(t *testing.T) {
	in := "MachineGuid                   :  61243150-82d5-409c-ad19-370d263f7b78"
	want := "MachineGuid                   :  <GUID>"
	got := Normalize(in, Default())
	if got != want {
		t.Errorf("guid\n  in:   %q\n  got:  %q\n  want: %q", in, got, want)
	}
}

func TestNormalize_SecondsDuration(t *testing.T) {
	in := "[*] Completed collection in 22.89 seconds"
	want := "[*] Completed collection in <DURATION>"
	got := Normalize(in, Default())
	if got != want {
		t.Errorf("seconds\n  in:   %q\n  got:  %q\n  want: %q", in, got, want)
	}
}

func TestNormalize_SecondsDurationInteger(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"integer plural", "Completed in 4 seconds", "Completed in <DURATION>"},
		{"integer zero", "Completed in 0 seconds", "Completed in <DURATION>"},
		{"integer singular", "Completed in 1 second", "Completed in <DURATION>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Normalize(tc.in, Default())
			if got != tc.want {
				t.Errorf("in:   %q\ngot:  %q\nwant: %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalize_UptimeMillis(t *testing.T) {
	// Two duration shapes side-by-side: DD:HH:MM:SS handled by
	// reUptimeDD, H+:MM:SS:NNNms handled by reUptimeMillis. Both
	// substrings must be replaced.
	in := "Total uptime: 00:20:49:44 (123:45:67:890ms)"
	got := Normalize(in, Default())
	if strings.Contains(got, "00:20:49:44") {
		t.Errorf("expected DD:HH:MM:SS to be stripped; got %q", got)
	}
	if strings.Contains(got, "123:45:67:890ms") {
		t.Errorf("expected H+:MM:SS:NNNms to be stripped; got %q", got)
	}
}

// TestNormalize_UptimeDDFormat isolates the DD:HH:MM:SS regex (per
// reviewer Finding 2 — exercise it directly with no other duration
// shape in the input).
func TestNormalize_UptimeDDFormat(t *testing.T) {
	in := "Total uptime: 03:21:14:07"
	got := Normalize(in, Default())
	if strings.Contains(got, "03:21:14:07") {
		t.Errorf("expected DD:HH:MM:SS to be stripped; got %q", got)
	}
}

func TestNormalize_SessionIDUnchanged(t *testing.T) {
	in := "SessionID 1"
	if got := Normalize(in, Default()); got != in {
		t.Errorf("SessionID should be unchanged\n  in:  %q\n  got: %q", in, got)
	}
}

func TestNormalize_PIDsOptIn(t *testing.T) {
	in := "  12345 explorer.exe\n     6 System"
	opts := Default()
	opts.StripPIDs = true
	got := Normalize(in, opts)
	if !strings.Contains(got, "<PID>") {
		t.Errorf("expected <PID> token; got %q", got)
	}
	if strings.Contains(got, "12345") {
		t.Errorf("expected 12345 to be stripped; got %q", got)
	}
	// Single-digit PIDs (kernel-managed) are intentionally left alone.
	if !strings.Contains(got, "6 System") {
		t.Errorf("expected single-digit kernel PID to be preserved; got %q", got)
	}
}

func TestNormalize_PIDsDefaultOff(t *testing.T) {
	in := "  12345 explorer.exe"
	got := Normalize(in, Default())
	if got != in {
		t.Errorf("PIDs should not strip by default\n  in:  %q\n  got: %q", in, got)
	}
}

func TestNormalize_StripsLabctlPrefix(t *testing.T) {
	// Baseline and parity runs push the binary under different names
	// ("seatbelt-baseline.exe" vs "seatbelt-parity.exe"), so the
	// labctl prefix MUST be stripped before diffing.
	in := "[labctl] win11-winrm> C:\\Users\\localuser\\seatbelt-x.exe LocalGroups\n\n====== LocalGroups ======\n"
	got := Normalize(in, NormalizeOpts{})
	if strings.Contains(got, "[labctl]") {
		t.Errorf("expected labctl prefix to be stripped; got %q", got)
	}
	if !strings.Contains(got, "====== LocalGroups ======") {
		t.Errorf("expected real output to be preserved; got %q", got)
	}
}

func TestNormalize_CRLFToLF(t *testing.T) {
	in := "line one\r\nline two\r\n"
	want := "line one\nline two\n"
	got := Normalize(in, NormalizeOpts{}) // No transforms, just CRLF normalization
	if got != want {
		t.Errorf("CRLF normalization failed\n  got:  %q\n  want: %q", got, want)
	}
}

// TestNormalize_Idempotent verifies that Normalize(Normalize(x)) == Normalize(x).
// Important for parity tests where the same baseline may be re-normalized.
func TestNormalize_Idempotent(t *testing.T) {
	in := "BootTime: 05/26/2026 21:42:50, MachineGuid: 61243150-82d5-409c-ad19-370d263f7b78, took 1.23 seconds"
	once := Normalize(in, Default())
	twice := Normalize(once, Default())
	if once != twice {
		t.Errorf("Normalize not idempotent\n  once:  %q\n  twice: %q", once, twice)
	}
}

func TestNormalize_KirbiLine(t *testing.T) {
	in := "  [*] base64(ticket.kirbi):\n\n        doIGqDCCBqSgAwIBBaEDAgEWooIF3jCCBdphggXWMIIF0qADAgEFoRIbEFNFVkVOS0lOR0RPTVM\n        uTE9DQUyiJTAjoAMCAQKhHDAaGwZrcmJ0Z3QbEHNldmVua2luZ2RvbXMubG9jYWyjggWVMIIF\n        kqADAgEXoQMCAQKiggWDBIIFf/r9Gma3H"
	got := Normalize(in, Default())
	if strings.Contains(got, "doIGqDCC") {
		t.Errorf("expected kirbi base64 to be stripped; got:\n%s", got)
	}
	if !strings.Contains(got, "<KIRBI>") {
		t.Errorf("expected <KIRBI> placeholder; got:\n%s", got)
	}
}

func TestNormalize_KirbiInline(t *testing.T) {
	// /nowrap produces a single very long base64 line
	longBase64 := strings.Repeat("A", 250) + "=="
	in := "[*] base64(ticket.kirbi):\n\n        " + longBase64
	got := Normalize(in, Default())
	if strings.Contains(got, longBase64) {
		t.Errorf("expected long inline kirbi to be stripped")
	}
}

func TestNormalize_KerberosKeyField(t *testing.T) {
	in := "  ServiceKey         : 4a8b3f2e1c9d7a0b5e2f8c6d3a1b4e7f"
	got := Normalize(in, Default())
	if strings.Contains(got, "4a8b3f2e1c9d7a0b5e2f8c6d3a1b4e7f") {
		t.Errorf("expected hex key to be stripped; got: %q", got)
	}
	if !strings.Contains(got, "<KEY>") {
		t.Errorf("expected <KEY> placeholder; got: %q", got)
	}
}

func TestNormalize_HashOutput(t *testing.T) {
	// Rubeus hash output contains named fields with hex values
	in := "  rc4_hmac             : 8846F7EAEE8FB117AD06BDD830B7586C\n  aes256_cts_hmac_sha1 : F5638C76350A2CB813F386AFBBE602D1571EAA207E3622E4E5668464326FDE20"
	got := Normalize(in, Default())
	if strings.Contains(got, "8846F7EAEE8FB117AD06BDD830B7586C") {
		t.Errorf("expected RC4 hash to be stripped; got: %q", got)
	}
}

func TestNormalize_LUID(t *testing.T) {
	in := "[*] Current LogonID (LUID) : 0x3e7 (999)"
	got := Normalize(in, Default())
	if strings.Contains(got, "0x3e7") {
		t.Errorf("expected LUID to be stripped; got: %q", got)
	}
	if !strings.Contains(got, "<LUID>") {
		t.Errorf("expected <LUID> placeholder; got: %q", got)
	}
}

func TestNormalize_CertSerial(t *testing.T) {
	in := "Serial Number  : 610000000A1234ABCD5678EF"
	got := Normalize(in, Default())
	if strings.Contains(got, "610000000A1234ABCD5678EF") {
		t.Errorf("expected serial to be stripped; got: %q", got)
	}
	if !strings.Contains(got, "<SERIAL>") {
		t.Errorf("expected <SERIAL> placeholder; got: %q", got)
	}
}

func TestNormalize_KirbiDisabled(t *testing.T) {
	opts := NormalizeOpts{} // all false
	longBase64 := strings.Repeat("B", 250) + "=="
	in := "  " + longBase64
	got := Normalize(in, opts)
	if got != in {
		t.Errorf("kirbi stripping should be off when StripKirbiBlobs=false\n  got: %q", got)
	}
}

func TestNormalize_ToolVersion(t *testing.T) {
	// Version lines like "  v2.3.2 " and "  v2.3.3 " should both become "  <VERSION>"
	for _, ver := range []string{"  v2.3.2 ", "  v2.3.3 ", "  v1.0.0 "} {
		got := Normalize(ver, Default())
		if got != "  <VERSION>" {
			t.Errorf("version %q not normalized: got %q", ver, got)
		}
	}
}

func TestNormalize_CertifyRequestID(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "request ID field line",
			in:   "[*] Request ID              : 14",
			want: "[*] Request ID              : <REQUEST_ID>",
		},
		{
			name: "request ID field line different value",
			in:   "[*] Request ID              : 15",
			want: "[*] Request ID              : <REQUEST_ID>",
		},
		{
			name: "GetRequestId trace line",
			in:   "[trace] GetRequestId hr=0x0 id=15",
			want: "[trace] GetRequestId hr=<HRESULT> id=<REQUEST_ID>",
		},
		{
			name: "GetRequestId trace line different value",
			in:   "[trace] GetRequestId hr=0x0 id=14",
			want: "[trace] GetRequestId hr=<HRESULT> id=<REQUEST_ID>",
		},
		{
			name: "multiple sequential lines",
			in:   "[trace] GetRequestId hr=0x0 id=14\n[*] Request ID              : 14",
			want: "[trace] GetRequestId hr=<HRESULT> id=<REQUEST_ID>\n[*] Request ID              : <REQUEST_ID>",
		},
		{
			name: "idempotent request ID field",
			in:   "[*] Request ID              : <REQUEST_ID>",
			want: "[*] Request ID              : <REQUEST_ID>",
		},
		{
			name: "idempotent trace line",
			in:   "[trace] GetRequestId hr=<HRESULT> id=<REQUEST_ID>",
			want: "[trace] GetRequestId hr=<HRESULT> id=<REQUEST_ID>",
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			got := Normalize(c.in, Default())
			if got != c.want {
				t.Errorf("input %q\n  want: %q\n  got:  %q", c.in, c.want, got)
			}
		})
	}
}

func TestNormalize_Base64Key(t *testing.T) {
	// Base64(key) and ASREP (key) lines should have their values replaced.
	cases := []struct {
		in   string
		want string
	}{
		{
			in:   "  Base64(key)              :  cM3frJFe9lNMIx/NFcyIdQ==",
			want: "  Base64(key)              :  <KEY>",
		},
		{
			in:   "  ASREP (key)              :  8846F7EAEE8FB117AD06BDD830B7586C",
			want: "  ASREP (key)              :  <KEY>",
		},
	}
	for _, c := range cases {
		got := Normalize(c.in, Default())
		if got != c.want {
			t.Errorf("input %q\n  want: %q\n  got:  %q", c.in, c.want, got)
		}
	}
}
