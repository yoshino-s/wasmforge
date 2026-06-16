// Package normalize provides output normalization helpers for parity tests.
// It strips non-deterministic fields (timestamps, GUIDs, session keys, kirbi
// blobs, cert serials, LUIDs, etc.) so that real functional output can be
// compared repeatably across runs.
package normalize

import (
	"regexp"
	"strings"

	"github.com/praetorian-inc/wftest/parity/labctl"
)

// NormalizeOpts controls which classes of non-deterministic data are stripped.
type NormalizeOpts struct {
	StripTimestamps bool
	StripGUIDs      bool
	StripDurations  bool
	StripPIDs       bool
	StripBanner     bool
	// StripKerberosKeys replaces named key fields and raw hex key blocks with <KEY*>.
	StripKerberosKeys bool
	// StripKirbiBlobs replaces base64-encoded kirbi ticket blobs with <KIRBI>.
	StripKirbiBlobs bool
	// StripLUIDs replaces LUID hex values like "0x3e7" or "0x3e7 (999)" with <LUID>.
	StripLUIDs bool
	// StripCertSerials replaces CA-issued cert serial numbers / SKI fields.
	StripCertSerials bool
}

// Default returns the standard set of normalizations suitable for most tools.
func Default() NormalizeOpts {
	return NormalizeOpts{
		StripTimestamps:   true,
		StripGUIDs:        true,
		StripDurations:    true,
		StripBanner:       true,
		StripKerberosKeys: true,
		StripKirbiBlobs:   true,
		StripLUIDs:        true,
		StripCertSerials:  true,
	}
}

var (
	// MM/DD/YYYY HH:MM:SS (standard) or M/D/YYYY H:MM:SS AM/PM (Rubeus TGT output).
	reTimestamp = regexp.MustCompile(`\b\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2}(?:\s*[AP]M)?\b`)

	reGUID = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)

	reSecondsDuration = regexp.MustCompile(`\b\d+(?:\.\d+)? seconds?\b`)

	reUptimeMillis = regexp.MustCompile(`\b\d+:\d{2}:\d{2}:\d{3}ms\b`)

	reUptimeHMS = regexp.MustCompile(`\b\d+h:\d+m:\d+s:\d+ms\b`)

	reUptimeDD = regexp.MustCompile(`\b\d{2}:\d{2}:\d{2}:\d{2}\b`)

	reDotNetTimeSpan = regexp.MustCompile(`\b\d{2}:\d{2}:\d{2}\.\d+\b`)

	rePIDColumn = regexp.MustCompile(`(?m)^(\s*)\d{4,6}(\s+\S)`)

	reLabctlPrefix = regexp.MustCompile(`(?m)^\[labctl\] [^\n]*\n`)

	// GhostPack tool version lines: "  v2.3.2 " → "<VERSION>"
	reToolVersion = regexp.MustCompile(`(?m)^  v\d+\.\d+\.\d+\s*$`)

	// In-line version-like trailers used by per-row reads. Examples
	// observed in the wild:
	//   "Chrome Version                       :  148.0.7778.217"
	//   "Chrome Version                       :  149.0.7827.53"
	// Generalised pattern: a "Version" label terminated by `:` and
	// whitespace, followed by a dotted-quad (W.X.Y.Z) version number
	// to end-of-line. The leading label is preserved; only the
	// version digits are replaced with <VERSION>. Same placeholder
	// as the banner rule above so consumers see one consistent tag.
	// Require AT LEAST 3 dot-parts (a.b.c or a.b.c.d) so 2-part labels
	// like "CurrentVersion : 6.3" (Windows kernel version string) are
	// left untouched. Goldens for those fields contain the literal text.
	reInlineVersion = regexp.MustCompile(`(?m)((?:[A-Za-z]+\s)*Version\s*:\s+)\d+(?:\.\d+){2,3}\b`)

	rePEMBlock = regexp.MustCompile(`(?s)-----BEGIN ([A-Z 0-9]+)-----[\r\n]+[A-Za-z0-9+/=\r\n]+-----END [A-Z 0-9]+-----`)

	// Named Kerberos key fields followed by their hex or base64 value.
	// Covers: ServiceKey, SessionKey, rc4_hmac, aes*, des_cbc_md5, KeyValue,
	// and Rubeus TGT ticket fields: Base64(key), ASREP (key).
	reKerberosKeyField = regexp.MustCompile(`(?i)((?:ServiceKey|SessionKey|KeyValue|rc4_hmac|aes128_cts_hmac_sha1|aes256_cts_hmac_sha1|des_cbc_md5|Base64\(key\)|ASREP\s*\(key\))\s*[:\s]+)([0-9a-fA-F]{16,64}|[A-Za-z0-9+/]{16,88}=*)`)

	// Raw 32-char hex strings (16-byte RC4/AES128 keys).
	reHexBlock32 = regexp.MustCompile(`\b[0-9a-fA-F]{32}\b`)
	// Raw 64-char hex strings (32-byte AES256 keys).
	reHexBlock64 = regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)

	// Kirbi blobs: Rubeus prints indented base64 blocks (wrapped mode).
	// Each line is indented and consists of 60+ base64 chars.
	reKirbiLine = regexp.MustCompile(`(?m)^[ \t]+[A-Za-z0-9+/]{60,}={0,2}[ \t]*$`)
	// Single-line /nowrap kirbi: very long base64 string (>200 chars).
	reKirbiInline = regexp.MustCompile(`[A-Za-z0-9+/]{200,}={0,2}`)

	// LUID values: printed as "0x3e7 (999)" or standalone "0x3e7".
	reLUID = regexp.MustCompile(`\b0x[0-9a-fA-F]{1,8}\b(?:\s+\(\d+\))?`)

	// CALG_SHA / CALG_SHA1 alias normalization: these two enum members
	// have the same value (32772) so .NET enum-to-string can pick either
	// name. Native Seatbelt/SharpDPAPI emit CALG_SHA; the NativeAOT-WASI
	// runtime picks CALG_SHA1. Canonicalize to a single token in both
	// directions so the diff is stable. Same pattern can be extended to
	// any other Win32 enum with duplicate-value aliases.
	reCalgSha = regexp.MustCompile(`\bCALG_SHA1?\b`)

	// Cert serial number lines from Certify output.
	reCertSerial = regexp.MustCompile(`(?i)(serial\s*(?:number)?\s*[:\s]+)([0-9a-fA-F]{16,40})\b`)
	// Subject Key Identifier lines.
	reCertSKI = regexp.MustCompile(`(?i)(subject\s*key\s*identifier\s*[:\s]+)([0-9a-fA-F: ]{20,60})`)

	// Certify CA request IDs are auto-incrementing per call.
	reCertifyRequestID    = regexp.MustCompile(`(?m)^(\[\*\] Request ID\s+:\s+)\d+\s*$`)
	// Match the entire hr=...id=NN/<REQUEST_ID> pattern. The HRESULT (hr=)
	// is replaced with a fixed <HRESULT> token so the later reLUID pass
	// doesn't swallow the bare 0x0 value. The id is replaced with <REQUEST_ID>.
	// Accepts both pristine (hr=0x0) and already-normalized (hr=<HRESULT>)
	// forms for idempotency.
	reCertifyGetRequestId = regexp.MustCompile(`(\[trace\] GetRequestId hr=)(?:0x[0-9a-fA-F]+|<HRESULT>)( id=)(?:\d+|<REQUEST_ID>)`)

	// Rubeus createnetonly random fields: Username/Domain/Password lines
	// hold 8-char base32-style identifiers regenerated per invocation.
	reRubeusNetonlyRandom = regexp.MustCompile(`(?m)^(\[\*\] (?:Username|Domain|Password)\s+:\s+)[A-Z0-9]{8}\s*$`)
	// Rubeus createnetonly ProcessID line.
	reRubeusProcessID = regexp.MustCompile(`(?m)^(\[\+\] ProcessID\s+:\s+)\d+\s*$`)
	// Seatbelt TokenGroups logon-session SID: format is S-1-5-5-0-<LUID-low>
	// where the LUID portion changes per logon session.
	reLogonSessionSid = regexp.MustCompile(`\bS-1-5-5-0-\d+\b`)
	// Resolved name for logon-session SIDs: "LogonSessionId_0_<LUID>" form
	// emitted by WfToken.ResolveWellKnownSid. LUID varies per logon.
	reLogonSessionName = regexp.MustCompile(`\bLogonSessionId_\d+_\d+\b`)
)

// Normalize applies the configured set of normalizations to raw tool output
// and returns a stable, comparable string.
func Normalize(raw string, opts NormalizeOpts) string {
	s := raw
	s = reLabctlPrefix.ReplaceAllString(s, "")
	s = reToolVersion.ReplaceAllString(s, "  <VERSION>")
	s = reInlineVersion.ReplaceAllString(s, "${1}<VERSION>")
	if opts.StripBanner {
		s = labctl.StripBanner(s)
	}
	if opts.StripDurations {
		s = reSecondsDuration.ReplaceAllString(s, "<DURATION>")
		s = reUptimeMillis.ReplaceAllString(s, "<DURATION>")
		s = reUptimeHMS.ReplaceAllString(s, "<DURATION>")
		s = reUptimeDD.ReplaceAllString(s, "<DURATION>")
		s = reDotNetTimeSpan.ReplaceAllString(s, "<DURATION>")
	}
	if opts.StripTimestamps {
		s = reTimestamp.ReplaceAllString(s, "<TIMESTAMP>")
	}
	if opts.StripGUIDs {
		s = reGUID.ReplaceAllString(s, "<GUID>")
	}
	// Strip PEM blocks before kirbi/key stripping so base64 inside PEM isn't mangled.
	s = rePEMBlock.ReplaceAllStringFunc(s, func(match string) string {
		sub := rePEMBlock.FindStringSubmatch(match)
		if len(sub) >= 2 {
			return "<PEM:" + sub[1] + ">"
		}
		return "<PEM>"
	})
	if opts.StripKirbiBlobs {
		// Multi-line indented base64 blobs (Rubeus default wrapping).
		s = reKirbiLine.ReplaceAllString(s, "  <KIRBI>")
		// Collapse consecutive <KIRBI> placeholder lines into one.
		for strings.Contains(s, "<KIRBI>\n  <KIRBI>") {
			s = strings.ReplaceAll(s, "<KIRBI>\n  <KIRBI>", "<KIRBI>")
		}
		// Long inline base64 produced by /nowrap flag.
		s = reKirbiInline.ReplaceAllString(s, "<KIRBI>")
	}
	if opts.StripKerberosKeys {
		// Named key fields first (preserves the label).
		s = reKerberosKeyField.ReplaceAllString(s, "${1}<KEY>")
		// Then standalone hex blocks (session/service key values without labels).
		s = reHexBlock32.ReplaceAllString(s, "<KEY32>")
		s = reHexBlock64.ReplaceAllString(s, "<KEY64>")
	}
	// Certify request IDs increment each CA call — normalize unconditionally.
	// MUST run before reLUID because the GetRequestId trace line contains an
	// HRESULT (e.g. hr=0x0) that reLUID would otherwise consume first.
	s = reCertifyRequestID.ReplaceAllString(s, "${1}<REQUEST_ID>")
	s = reCertifyGetRequestId.ReplaceAllString(s, "${1}<HRESULT>${2}<REQUEST_ID>")
	// Rubeus createnetonly emits random 8-char alphanumeric values for
	// Username/Domain/Password and a fresh ProcessID each invocation.
	s = reRubeusNetonlyRandom.ReplaceAllString(s, "${1}<RANDOM>")
	s = reRubeusProcessID.ReplaceAllString(s, "${1}<PID>")
	// Seatbelt TokenGroups logon-session SID (S-1-5-5-0-X) varies per logon.
	s = reLogonSessionSid.ReplaceAllString(s, "S-1-5-5-0-<LUID>")
	s = reLogonSessionName.ReplaceAllString(s, "LogonSessionId_0_<LUID>")
	if opts.StripLUIDs {
		s = reLUID.ReplaceAllString(s, "<LUID>")
	}
	if opts.StripCertSerials {
		s = reCertSerial.ReplaceAllString(s, "${1}<SERIAL>")
		s = reCertSKI.ReplaceAllString(s, "${1}<SKI>")
	}
	// CALG_SHA / CALG_SHA1 enum alias — unconditional normalization
	// so the diff doesn't depend on which name the enum-to-string
	// runtime picks. (Both values are 32772 so the behavioural
	// information is preserved.)
	s = reCalgSha.ReplaceAllString(s, "CALG_SHA")
	if opts.StripPIDs {
		s = rePIDColumn.ReplaceAllString(s, "${1}<PID>${2}")
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	// Strip trailing whitespace from each line. Native SharpDPAPI emits a
	// trailing space after credential fields whose source was a Windows
	// DPAPI null-terminated UTF-16 string (the null becomes a space when
	// the BCL decodes it via the format "{0} ". WfDpapi's WASM-side
	// decoder strips the null terminator cleanly, so our output is
	// the same data minus the cosmetic trailing space. This normalize
	// step bridges the two for parity.
	{
		lines := strings.Split(s, "\n")
		for i, line := range lines {
			lines[i] = strings.TrimRight(line, " \t")
		}
		s = strings.Join(lines, "\n")
	}
	// Collapse 3+ consecutive newlines to 2 — some tool versions emit extra
	// blank lines that differ between native and wasmforge builds.
	for strings.Contains(s, "\n\n\n") {
		s = strings.ReplaceAll(s, "\n\n\n", "\n\n")
	}
	return s
}
