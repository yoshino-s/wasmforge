package normalize

import (
	"sort"
	"strings"
)

// CanonicalizeKerberosTickets normalizes runs of "[*] <client> @ <realm> ->
// <server> @ <realm>  [etype:N]\n  Version ...\n  Hash ..." blocks emitted by
// the wasmforge WfLsa Kerberos-ticket-cache bridge (Seatbelt SecPackageCreds
// + similar consumers) into a deterministic form.
//
// Why this exists: the lab's Kerberos ticket cache drifts between captures as
// the Win11 host re-authenticates to GOAD services (krbtgt renewals, repeated
// cifs/ldap accesses, etc.). The bag of UNIQUE (client, server, etype)
// triples is stable; only per-service ticket multiplicities vary. Pure
// multiset comparison still fails when one capture has 2 cifs entries and
// another has 1, so we go further: sort the blocks lexicographically and
// deduplicate identical blocks (set semantics). After canonicalization a
// baseline captured at time T and a run at time T+N should yield the same
// stream as long as the lab continues to authenticate the same services.
//
// Trade-off: a hypothetical bridge bug that emits the same ticket twice
// would be masked. That risk is judged acceptable in exchange for test
// stability — the bridge format and ticket content are still validated.
//
// The function is a no-op on outputs containing no "[*]" ticket blocks.
// Non-ticket lines (section banners, the "Completed collection" footer,
// blank lines outside the ticket region) are preserved verbatim and in
// original position.
func CanonicalizeKerberosTickets(s string) string {
	lines := strings.Split(s, "\n")

	// A ticket block is identified by a line beginning with "[*] " and
	// containing the " -> " arrow + "[etype:" tag (distinguishes ticket
	// headers from other "[*] " lines such as the completion footer).
	// The block extends through subsequent indented lines ("  ") until
	// a blank line or another non-indented line.
	isTicketHeader := func(line string) bool {
		return strings.HasPrefix(line, "[*] ") &&
			strings.Contains(line, " -> ") &&
			strings.Contains(line, "[etype:")
	}

	// Two passes: collect tickets + the non-ticket scaffolding around
	// them. We replace the contiguous ticket region with a single
	// canonicalized stream, preserving the position of the scaffolding.
	type span struct {
		start, end int // [start, end) over lines slice
		blocks     []string
	}

	var spans []span
	i := 0
	for i < len(lines) {
		if !isTicketHeader(lines[i]) {
			i++
			continue
		}
		// Start of a ticket region. Collect contiguous blocks.
		regionStart := i
		var blocks []string
		for i < len(lines) {
			if !isTicketHeader(lines[i]) {
				// A blank line between blocks is part of the region;
				// any other non-header line ends the region.
				if strings.TrimSpace(lines[i]) == "" {
					i++
					continue
				}
				break
			}
			// Capture this header + all immediately-following indented
			// lines (the Version/Hash sub-fields).
			// Block-continuation delimiter is the two-space prefix —
			// any future ticket format that adds non-indented
			// continuation lines (e.g., a bare "Flags : ..." flush
			// against the margin) would silently terminate the block
			// mid-way. Update this guard if the emission format changes.
			block := []string{lines[i]}
			i++
			for i < len(lines) && strings.HasPrefix(lines[i], "  ") {
				block = append(block, lines[i])
				i++
			}
			blocks = append(blocks, strings.Join(block, "\n"))
		}
		spans = append(spans, span{start: regionStart, end: i, blocks: blocks})
	}

	if len(spans) == 0 {
		return s
	}

	// Sort + dedup each region's blocks.
	for si := range spans {
		sort.Strings(spans[si].blocks)
		spans[si].blocks = dedupSortedStrings(spans[si].blocks)
	}

	// Rebuild: walk lines, replacing each region with its canonical form.
	var out []string
	cursor := 0
	for _, sp := range spans {
		out = append(out, lines[cursor:sp.start]...)
		for bi, block := range sp.blocks {
			out = append(out, strings.Split(block, "\n")...)
			// Preserve the blank-line separator between blocks that the
			// original format uses (matches WriteHost emission style).
			if bi < len(sp.blocks)-1 {
				out = append(out, "")
			}
		}
		// Trailing blank line after the last block, matching the
		// original Seatbelt formatter convention.
		out = append(out, "")
		cursor = sp.end
	}
	out = append(out, lines[cursor:]...)

	return strings.Join(out, "\n")
}

// dedupSortedStrings collapses consecutive equal entries in a sorted slice.
func dedupSortedStrings(in []string) []string {
	if len(in) <= 1 {
		return in
	}
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}
