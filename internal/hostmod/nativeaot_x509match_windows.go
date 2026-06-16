//go:build nativeaot && windows

// NativeAOT host-side X.509 store walker + RSA modulus matcher for
// SharpDPAPI's machinetriage cert-file path.
//
// SharpDPAPI's native DescribeCertificate decrypts a CAPI/CNG private-key
// file via DPAPI, extracts the RSA private key, derives a PublicXML
// (containing the modulus), then walks `CurrentUser\MY` and
// `LocalMachine\MY` X509 stores asking each cert for its
// `cert.PublicKey.Key.ToXmlString(false)` and substring-comparing against
// the private key's PublicXML. On a match, the cert metadata + base64 DER
// is printed.
//
// On wasm32 every step of that chain hits System.Security.Cryptography
// (PlatformNotSupportedException) or a host-pointer P/Invoke that traps
// the host. This bridge takes the raw modulus bytes from the C# side
// (extracted by manual byte slicing of the decrypted blob — no crypto
// calls on the C# side), walks both X509 stores natively via
// `golang.org/x/sys/windows`'s CertOpenSystemStore family, parses each
// cert's SubjectPublicKeyInfo via `crypto/x509`, compares the moduli,
// and on match returns a packed binary reply matching the format the
// patched DescribeCertificate expects.
//
// Wire format (output buffer):
//
//	u32 status                       — 0 = match found, 1 = no match
//	When status == 0:
//	  u32 thumbprint_len + bytes     — hex-encoded SHA-1 (uppercase, no separators)
//	  u32 issuer_len     + bytes     — distinguished name string
//	  u32 subject_len    + bytes     — distinguished name string
//	  u32 not_before_len + bytes     — RFC3339 timestamp text
//	  u32 not_after_len  + bytes     — RFC3339 timestamp text
//	  u32 eku_blob_len   + bytes     — semicolon-separated "<friendly>|<oid>" pairs
//	  u32 cert_der_len   + bytes     — raw DER (caller base64-wraps for PEM)

package hostmod

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"strings"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
	"golang.org/x/sys/windows"
)

// X.509 store names + locations exercised by SharpDPAPI's TriageSystemCerts.
// MY = personal store; native opens both CurrentUser and LocalMachine.
var x509MatchStores = []struct {
	name        string
	storeFlag   uint32
	displayName string // appears in the OID-friendly EKU label table
}{
	{"MY", windows.CERT_SYSTEM_STORE_CURRENT_USER, "CurrentUser"},
	{"MY", windows.CERT_SYSTEM_STORE_LOCAL_MACHINE, "LocalMachine"},
}

// Friendly-name table for the Enhanced Key Usage OIDs SharpDPAPI's native
// run emits. .NET's X509EnhancedKeyUsageExtension.EnhancedKeyUsages returns
// `Oid.FriendlyName` which we replicate via a small lookup; unknown OIDs
// fall back to the OID itself (matches native when FriendlyName is empty).
var ekuFriendlyNames = map[string]string{
	"1.3.6.1.5.5.7.3.1": "Server Authentication",
	"1.3.6.1.5.5.7.3.2": "Client Authentication",
	"1.3.6.1.5.5.7.3.3": "Code Signing",
	"1.3.6.1.5.5.7.3.4": "Secure Email",
	"1.3.6.1.5.5.7.3.5": "IP security end system",
	"1.3.6.1.5.5.7.3.6": "IP security tunnel termination",
	"1.3.6.1.5.5.7.3.7": "IP security user",
	"1.3.6.1.5.5.7.3.8": "Time Stamping",
	"1.3.6.1.5.5.7.3.9": "OCSP Signing",
	"1.3.6.1.4.1.311.10.3.4":  "Encrypting File System",
	"1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
	"1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
	"1.3.6.1.4.1.311.21.5":  "Private Key Archival",
	"1.3.6.1.4.1.311.21.6":  "Key Recovery Agent",
	"1.3.6.1.4.1.311.21.19": "Directory Service Email Replication",
}

// nativeaotX509Match — see file header for wire format. Stack ABI:
//
//	stack[0] = modulus_ptr (raw big-endian RSA modulus bytes)
//	stack[1] = modulus_len
//	stack[2] = out_buf_ptr
//	stack[3] = out_buf_cap
//	stack[0] (return) = bytes written, 0 if buffer too small / read failure
func nativeaotX509Match(_ context.Context, mod api.Module, stack []uint64) {
	modulusPtr := uint32(stack[0])
	modulusLen := uint32(stack[1])
	outPtr := uint32(stack[2])
	outCap := uint32(stack[3])

	target, ok := readBytes(mod, modulusPtr, modulusLen)
	if !ok || len(target) == 0 {
		stack[0] = writeX509MatchNoMatch(mod, outPtr, outCap)
		return
	}
	// Normalise the target modulus by stripping leading zero bytes — RSA
	// integers may have a 0x00 sign-byte prefix and we want the comparison
	// to be invariant to that.
	target = trimLeadingZeros(target)

	for _, st := range x509MatchStores {
		match, found := walkStoreForModulus(st.name, st.storeFlag, target)
		if found {
			stack[0] = writeX509MatchReply(mod, outPtr, outCap, match)
			return
		}
	}
	stack[0] = writeX509MatchNoMatch(mod, outPtr, outCap)
}

type x509MatchResult struct {
	thumbprintHex string
	issuer        string
	subject       string
	notBefore     string
	notAfter      string
	ekus          []ekuEntry // semicolon-joined into the wire format
	certDER       []byte
}

type ekuEntry struct {
	friendlyName string
	oid          string
}

func walkStoreForModulus(name string, storeFlag uint32, targetModulus []byte) (x509MatchResult, bool) {
	storeNamePtr, _ := windows.UTF16PtrFromString(name)
	hStore, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM_W,
		0,
		0,
		storeFlag|windows.CERT_STORE_READONLY_FLAG,
		uintptr(unsafe2Pointer(storeNamePtr)))
	if err != nil || hStore == 0 {
		return x509MatchResult{}, false
	}
	defer windows.CertCloseStore(hStore, 0)

	var prev *windows.CertContext
	for {
		curr, err := windows.CertEnumCertificatesInStore(hStore, prev)
		if err != nil || curr == nil {
			return x509MatchResult{}, false
		}
		prev = curr

		der := unsafeBytes(curr.EncodedCert, int(curr.Length))
		if len(der) == 0 {
			continue
		}
		// Defensive: x509.ParseCertificate is documented to handle malformed
		// DER without panicking, but cert stores in the wild include odd
		// entries (test certs, partial chains). Skip on any parse failure.
		cert, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			continue
		}
		rsaPub, isRSA := cert.PublicKey.(*rsa.PublicKey)
		if !isRSA {
			continue
		}
		certModulus := rsaPub.N.Bytes() // big-endian, no leading zero
		if bytes.Equal(certModulus, targetModulus) {
			return buildMatchResult(cert, der), true
		}
	}
}

// unsafe2Pointer returns the bare uintptr of a UTF-16 pointer, suitable for
// passing as the `pvPara` parameter of CertOpenStore (Windows treats it
// opaquely; the value just needs to point to the wide-string store name).
func unsafe2Pointer(p *uint16) uintptr {
	return uintptr(unsafe.Pointer(p))
}

// unsafeBytes returns a Go []byte view of `n` host bytes starting at `p`.
// The returned slice aliases host memory — only safe to use while the
// underlying allocation is alive. We immediately copy it before passing
// out of scope, so this is fine.
func unsafeBytes(p *byte, n int) []byte {
	if p == nil || n <= 0 {
		return nil
	}
	return unsafe.Slice(p, n)
}

// sha1Sum returns the raw SHA-1 digest of b. We keep this separate from the
// strings/hex encoding so callers can still get the bytes if needed.
func sha1Sum(b []byte) []byte {
	h := sha1.Sum(b)
	return h[:]
}

func buildMatchResult(cert *x509.Certificate, der []byte) x509MatchResult {
	res := x509MatchResult{
		thumbprintHex: strings.ToUpper(hexEncode(certThumbprint(cert))),
		issuer:        cert.Issuer.String(),
		subject:       cert.Subject.String(),
		notBefore:     cert.NotBefore.Format("1/2/2006 3:04:05 PM"),
		notAfter:      cert.NotAfter.Format("1/2/2006 3:04:05 PM"),
		certDER:       append([]byte(nil), der...),
	}
	for _, ekuOID := range cert.ExtKeyUsage {
		oid := extKeyUsageToOID(ekuOID)
		if oid == "" {
			continue
		}
		res.ekus = append(res.ekus, ekuEntry{oid: oid, friendlyName: friendlyEKU(oid)})
	}
	for _, unknownOID := range cert.UnknownExtKeyUsage {
		oid := unknownOID.String()
		res.ekus = append(res.ekus, ekuEntry{oid: oid, friendlyName: friendlyEKU(oid)})
	}
	return res
}

func friendlyEKU(oid string) string {
	if n, ok := ekuFriendlyNames[oid]; ok {
		return n
	}
	return oid // fallback when we don't know a friendly name
}

func extKeyUsageToOID(eku x509.ExtKeyUsage) string {
	switch eku {
	case x509.ExtKeyUsageServerAuth:
		return "1.3.6.1.5.5.7.3.1"
	case x509.ExtKeyUsageClientAuth:
		return "1.3.6.1.5.5.7.3.2"
	case x509.ExtKeyUsageCodeSigning:
		return "1.3.6.1.5.5.7.3.3"
	case x509.ExtKeyUsageEmailProtection:
		return "1.3.6.1.5.5.7.3.4"
	case x509.ExtKeyUsageTimeStamping:
		return "1.3.6.1.5.5.7.3.8"
	case x509.ExtKeyUsageOCSPSigning:
		return "1.3.6.1.5.5.7.3.9"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "1.3.6.1.4.1.311.10.3.3"
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return "2.16.840.1.113730.4.1"
	}
	return ""
}

func writeX509MatchReply(mod api.Module, outPtr, outCap uint32, m x509MatchResult) uint64 {
	// EKU wire format: semicolon-separated "friendly|oid" entries.
	var ekuBuf bytes.Buffer
	for i, e := range m.ekus {
		if i > 0 {
			ekuBuf.WriteByte(';')
		}
		ekuBuf.WriteString(e.friendlyName)
		ekuBuf.WriteByte('|')
		ekuBuf.WriteString(e.oid)
	}
	ekuBytes := ekuBuf.Bytes()

	size := 4 // status
	for _, b := range [][]byte{
		[]byte(m.thumbprintHex),
		[]byte(m.issuer),
		[]byte(m.subject),
		[]byte(m.notBefore),
		[]byte(m.notAfter),
		ekuBytes,
		m.certDER,
	} {
		size += 4 + len(b)
	}
	if uint32(size) > outCap {
		return 0
	}

	buf := make([]byte, size)
	off := 0
	binary.LittleEndian.PutUint32(buf[off:], 0) // status = 0 (match)
	off += 4
	for _, b := range [][]byte{
		[]byte(m.thumbprintHex),
		[]byte(m.issuer),
		[]byte(m.subject),
		[]byte(m.notBefore),
		[]byte(m.notAfter),
		ekuBytes,
		m.certDER,
	} {
		binary.LittleEndian.PutUint32(buf[off:], uint32(len(b)))
		off += 4
		copy(buf[off:], b)
		off += len(b)
	}
	if !mod.Memory().Write(outPtr, buf) {
		return 0
	}
	return uint64(off)
}

func writeX509MatchNoMatch(mod api.Module, outPtr, outCap uint32) uint64 {
	const size = 4
	if outCap < size {
		return 0
	}
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], 1) // status = 1 (no match)
	if !mod.Memory().Write(outPtr, buf[:]) {
		return 0
	}
	return size
}

func trimLeadingZeros(b []byte) []byte {
	i := 0
	for i < len(b) && b[i] == 0 {
		i++
	}
	return b[i:]
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0xF]
	}
	return string(out)
}

// certThumbprint returns the SHA-1 hash of the cert's raw DER — matching
// Win32 `CertGetCertificateContextProperty(CERT_HASH_PROP_ID)` /
// X509Certificate2.Thumbprint.
func certThumbprint(cert *x509.Certificate) []byte {
	return sha1Sum(cert.Raw)
}
