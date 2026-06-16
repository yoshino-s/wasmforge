//go:build parity

package seatbelt_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/wftest/parity/labctl"
	"github.com/praetorian-inc/wftest/parity/normalize"
	"github.com/praetorian-inc/wftest/parity/seatbeltcases"
)

var baselineDir = filepath.Join("..", "..", "..", "testdata", "parity-baselines", "seatbelt")

// TestSeatbeltParity validates wasmforge Seatbelt against captured baselines.
//
// Lab prerequisites:
//   - run scripts/lab-setup/seatbelt-plant.ps1 on win11-ssh as
//     Administrator before capturing or running tests; the script is
//     idempotent (cmdkey vault entries, SMB share, RDP enabled).
//
// Every case runs as localuser against the planted lab. Goldens are
// captured from native Seatbelt.exe; wasmforge tests fail wherever
// the engine output diverges from native.
func TestSeatbeltParity(t *testing.T) {
	labctl.SkipIfLabDown(t)

	binary := os.Getenv("WASMFORGE_TEST_BINARY")
	if binary == "" {
		binary = "/tmp/wf-out/seatbelt.exe"
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("binary not found at %s (set WASMFORGE_TEST_BINARY to override): %v",
			binary, err)
	}

	if _, err := labctl.PushTo("win11-ssh", binary, "seatbelt-parity.exe"); err != nil {
		t.Fatalf("labctl push: %v", err)
	}
	relocate := exec.Command("labctl", "exec", "win11-ssh",
		`powershell -NoProfile -Command "Get-Process | Where-Object {$_.Name -like '*-parity'} | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 500; New-Item -ItemType Directory -Force -Path C:\WfBin | Out-Null; icacls C:\WfBin /grant 'Everyone:(OI)(CI)RX' | Out-Null; Copy-Item -Force C:\Users\localuser\seatbelt-parity.exe C:\WfBin\seatbelt-parity.exe"`)
	if out, err := relocate.CombinedOutput(); err != nil {
		t.Fatalf("relocate binary to C:\\WfBin: %v\n%s", err, out)
	}
	pushed := &labctl.PushedBinary{LabPath: `C:\WfBin\seatbelt-parity.exe`}

	for _, c := range seatbeltcases.Cases() {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			goldPath := filepath.Join(baselineDir, c.Name+".golden")

			actual, runErr := pushed.RunOn(c.PersonaOrDefault(), c.Args...)
			actual = normalize.Normalize(actual, normalize.Default())

			// SecPackageCreds is repurposed in wasmforge to enumerate the
			// Kerberos ticket cache via WfLsa.EnumerateKerberosTickets
			// (the native NTLM/AcquireCredentialsHandle path crashes
			// under the WASM bridge). Cache contents drift between
			// captures as the Win11 host re-authenticates to GOAD
			// services in the background; the bag of unique ticket
			// triples is stable but per-service multiplicities vary.
			// Canonicalize both sides (sort + dedup) so the test
			// compares the *set* of tickets, not the multiset.
			if c.Name == "SecPackageCreds" {
				actual = normalize.CanonicalizeKerberosTickets(actual)
			}

			expectedRaw, readErr := os.ReadFile(goldPath)
			if readErr != nil {
				t.Fatalf("read baseline %s: %v", goldPath, readErr)
			}
			// Apply the same normalize to the baseline. Native Seatbelt
			// emits trailing whitespace after a number of header/empty-value
			// lines (e.g. "Comment                        : " when the
			// comment is empty); our binary doesn't. Normalize both sides
			// so the test compares semantic content, not cosmetic-whitespace
			// drift — matches the SharpDPAPI test behaviour after commit
			// 5b4577a refreshed those goldens.
			expected := normalize.Normalize(string(expectedRaw), normalize.Default())
			if c.Name == "SecPackageCreds" {
				expected = normalize.CanonicalizeKerberosTickets(expected)
			}

			if actual != expected {
				if runErr != nil {
					t.Logf("run reported error: %v", runErr)
				}
				t.Errorf("output mismatch for %s\n--- baseline (%d bytes) ---\n%s\n--- actual (%d bytes) ---\n%s",
					c.Name, len(expected), expected, len(actual), actual)
			}
		})
	}
}
