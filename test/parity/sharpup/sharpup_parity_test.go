//go:build parity

package sharpup_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/wftest/parity/labctl"
	"github.com/praetorian-inc/wftest/parity/normalize"
	"github.com/praetorian-inc/wftest/parity/sharpupcases"
)

var baselineDir = filepath.Join("..", "..", "..", "testdata", "parity-baselines", "sharpup")

// TestSharpUpParity validates wasmforge SharpUp against captured baselines.
//
// Lab prerequisites:
//   - run scripts/lab-setup/sharpup-plant.ps1 on win11-ssh (as
//     Administrator) before capturing or running tests; the script is
//     idempotent and plants the misconfigurations that the active
//     check cases below detect.
//   - run scripts/lab-setup/dc01-sysvol-gpp.ps1 on dc01-ssh (as DA)
//     to plant SYSVOL Groups.xml for the DomainGPPPassword check (the
//     check itself is currently excluded — see cases.go).
//
// Each case runs as sevenkingdoms\domainuser with `audit <CheckName>`
// args so SharpUp executes the check regardless of integrity level.
func TestSharpUpParity(t *testing.T) {
	labctl.SkipIfLabDown(t)

	binary := os.Getenv("WASMFORGE_TEST_BINARY")
	if binary == "" {
		binary = "/tmp/wf-out/sharpup.exe"
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("binary not found at %s (set WASMFORGE_TEST_BINARY to override): %v",
			binary, err)
	}

	// Push to localuser's home (default upload destination), then copy
	// to C:\WfBin\ so the world-readable location is reachable from the
	// non-admin domainuser SSH session.
	if _, err := labctl.PushTo("win11-ssh", binary, "sharpup-parity.exe"); err != nil {
		t.Fatalf("labctl push: %v", err)
	}
	relocate := exec.Command("labctl", "exec", "win11-ssh",
		`powershell -NoProfile -Command "Get-Process | Where-Object {$_.Name -like '*-parity'} | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 500; New-Item -ItemType Directory -Force -Path C:\WfBin | Out-Null; icacls C:\WfBin /grant 'Everyone:(OI)(CI)RX' | Out-Null; Copy-Item -Force C:\Users\localuser\sharpup-parity.exe C:\WfBin\sharpup-parity.exe"`)
	if out, err := relocate.CombinedOutput(); err != nil {
		t.Fatalf("relocate binary to C:\\WfBin: %v\n%s", err, out)
	}
	worldReadable := &labctl.PushedBinary{LabPath: `C:\WfBin\sharpup-parity.exe`}

	for _, c := range sharpupcases.Cases() {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			goldPath := filepath.Join(baselineDir, c.Name+".golden")

			actual, runErr := worldReadable.RunOn(c.PersonaOrDefault(), c.Args...)
			actual = normalize.Normalize(actual, normalize.Default())

			expected, readErr := os.ReadFile(goldPath)
			if readErr != nil {
				t.Fatalf("read baseline %s: %v", goldPath, readErr)
			}

			if actual != string(expected) {
				if runErr != nil {
					t.Logf("run reported error: %v", runErr)
				}
				t.Errorf("output mismatch for %s\n--- baseline (%d bytes) ---\n%s\n--- actual (%d bytes) ---\n%s",
					c.Name, len(expected), expected, len(actual), actual)
			}
		})
	}
}
