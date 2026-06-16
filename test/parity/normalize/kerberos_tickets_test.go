package normalize

import (
	"strings"
	"testing"
)

// TestCanonicalizeKerberosTickets locks in the SecPackageCreds parity
// contract: when the WfLsa Kerberos-ticket-cache bridge enumerates the
// lab's cache, the multiset of tickets drifts between captures
// (background re-auths to GOAD services produce extra cifs/krbtgt
// renewals). The bag of unique (client, server, etype) triples is
// stable; only per-service multiplicities vary. To compare those
// outputs reproducibly we canonicalize each "[*] ... -> ... [etype:N]"
// block (the header + the indented Version/Hash lines that follow)
// into a sorted, deduplicated stream — set semantics, not multiset.
//
// Set rather than multiset because the observed drift is in counts of
// already-present entries, not in which entries exist. Multiset
// comparison would still fail when one capture has 2 cifs entries and
// the other has 1.
func TestCanonicalizeKerberosTickets_DedupAndSort(t *testing.T) {
	input := `
====== SecPackageCreds ======

[*] alice @ EXAMPLE.COM -> krbtgt/EXAMPLE.COM @ EXAMPLE.COM  [etype:18]
  Version                        : 18
  Hash                           : krbtgt/EXAMPLE.COM@EXAMPLE.COM

[*] alice @ EXAMPLE.COM -> cifs/host.example.com @ EXAMPLE.COM  [etype:18]
  Version                        : 18
  Hash                           : cifs/host.example.com@EXAMPLE.COM

[*] alice @ EXAMPLE.COM -> krbtgt/EXAMPLE.COM @ EXAMPLE.COM  [etype:18]
  Version                        : 18
  Hash                           : krbtgt/EXAMPLE.COM@EXAMPLE.COM

[*] Completed collection in <DURATION>
`

	got := CanonicalizeKerberosTickets(input)

	// cifs entry should appear (it's lexicographically before krbtgt).
	cifsCount := strings.Count(got, "cifs/host.example.com")
	if cifsCount == 0 {
		t.Fatalf("cifs entry missing after canonicalize:\n%s", got)
	}

	// The duplicate krbtgt block should appear ONCE, not twice.
	krbtgtHeaders := strings.Count(got, "-> krbtgt/EXAMPLE.COM @")
	if krbtgtHeaders != 1 {
		t.Errorf("expected exactly 1 krbtgt block after dedup, got %d:\n%s", krbtgtHeaders, got)
	}

	// Sorted: cifs ('c') should precede krbtgt ('k').
	cifsPos := strings.Index(got, "cifs/host")
	krbtgtPos := strings.Index(got, "krbtgt/EXAMPLE")
	if cifsPos < 0 || krbtgtPos < 0 || cifsPos > krbtgtPos {
		t.Errorf("blocks not sorted lexicographically; cifsPos=%d krbtgtPos=%d\n%s",
			cifsPos, krbtgtPos, got)
	}

	// Non-ticket lines (banner, completion footer) must be preserved verbatim
	// and in original position relative to the ticket region.
	if !strings.Contains(got, "====== SecPackageCreds ======") {
		t.Errorf("section banner stripped:\n%s", got)
	}
	if !strings.Contains(got, "[*] Completed collection in <DURATION>") {
		t.Errorf("completion footer stripped:\n%s", got)
	}
}

// TestCanonicalizeKerberosTickets_NoTicketsNoOp guards against the
// function munging output that has no ticket blocks at all.
func TestCanonicalizeKerberosTickets_NoTicketsNoOp(t *testing.T) {
	input := `====== SomeOtherCommand ======

  Field1                         : value1
  Field2                         : value2

[*] Completed collection in <DURATION>
`
	got := CanonicalizeKerberosTickets(input)
	if got != input {
		t.Errorf("non-ticket output was modified:\n--- want ---\n%s\n--- got ---\n%s", input, got)
	}
}

// TestCanonicalizeKerberosTickets_TwoDisjointSpans guards the outer
// scan-forward loop: ticket regions separated by non-ticket scaffolding
// (e.g., two SecPackageCreds-style sections in one output) must each
// be canonicalized independently while preserving the scaffolding
// between them in original position.
func TestCanonicalizeKerberosTickets_TwoDisjointSpans(t *testing.T) {
	input := `====== FirstSection ======

[*] alice @ EX -> krbtgt/EX @ EX  [etype:18]
  Version                        : 18
  Hash                           : krbtgt/EX@EX

[*] alice @ EX -> krbtgt/EX @ EX  [etype:18]
  Version                        : 18
  Hash                           : krbtgt/EX@EX

------ INTERLUDE ------

====== SecondSection ======

[*] bob @ EX -> ldap/dc.EX @ EX  [etype:18]
  Version                        : 18
  Hash                           : ldap/dc.EX@EX

[*] Completed collection in <DURATION>
`
	got := CanonicalizeKerberosTickets(input)

	if !strings.Contains(got, "------ INTERLUDE ------") {
		t.Errorf("interlude scaffolding between spans was dropped:\n%s", got)
	}
	if !strings.Contains(got, "====== SecondSection ======") {
		t.Errorf("second section banner was dropped:\n%s", got)
	}
	krbtgtHeaders := strings.Count(got, "-> krbtgt/EX @")
	if krbtgtHeaders != 1 {
		t.Errorf("first span: expected dedup to 1 krbtgt block, got %d:\n%s", krbtgtHeaders, got)
	}
	ldapHeaders := strings.Count(got, "-> ldap/dc.EX @")
	if ldapHeaders != 1 {
		t.Errorf("second span: expected 1 ldap block, got %d:\n%s", ldapHeaders, got)
	}
	// First-section block must precede the interlude, which must precede
	// the second section.
	krbPos := strings.Index(got, "krbtgt/EX@EX")
	interludePos := strings.Index(got, "INTERLUDE")
	ldapPos := strings.Index(got, "ldap/dc.EX@EX")
	if !(krbPos < interludePos && interludePos < ldapPos) {
		t.Errorf("region order broken: krb=%d interlude=%d ldap=%d", krbPos, interludePos, ldapPos)
	}
}

// TestCanonicalizeKerberosTickets_HeaderOnlyBlock covers the edge case
// where a ticket header has zero indented sub-lines (followed
// immediately by another header or a blank/EOF). The header alone is
// still a valid block that should be dedupped against identical
// header-only blocks.
func TestCanonicalizeKerberosTickets_HeaderOnlyBlock(t *testing.T) {
	input := `====== SecPackageCreds ======

[*] alice @ EX -> svc/x @ EX  [etype:18]
[*] alice @ EX -> svc/x @ EX  [etype:18]
[*] alice @ EX -> svc/y @ EX  [etype:18]

[*] Completed collection in <DURATION>
`
	got := CanonicalizeKerberosTickets(input)
	svcXCount := strings.Count(got, "-> svc/x @")
	svcYCount := strings.Count(got, "-> svc/y @")
	if svcXCount != 1 {
		t.Errorf("header-only dedup failed: expected 1 svc/x, got %d:\n%s", svcXCount, got)
	}
	if svcYCount != 1 {
		t.Errorf("header-only block lost: expected 1 svc/y, got %d:\n%s", svcYCount, got)
	}
}

// TestCanonicalizeKerberosTickets_PreservesHeaderFormat ensures we
// don't drop the Version/Hash sub-lines that follow each "[*]" header.
func TestCanonicalizeKerberosTickets_PreservesHeaderFormat(t *testing.T) {
	input := `====== SecPackageCreds ======

[*] alice @ EXAMPLE.COM -> ldap/dc.example.com @ EXAMPLE.COM  [etype:18]
  Version                        : 18
  Hash                           : ldap/dc.example.com@EXAMPLE.COM

[*] Completed collection in <DURATION>
`
	got := CanonicalizeKerberosTickets(input)
	if !strings.Contains(got, "Version                        : 18") {
		t.Errorf("Version sub-line lost:\n%s", got)
	}
	if !strings.Contains(got, "Hash                           : ldap/dc.example.com@EXAMPLE.COM") {
		t.Errorf("Hash sub-line lost:\n%s", got)
	}
}
