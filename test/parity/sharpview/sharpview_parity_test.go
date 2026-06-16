//go:build parity

package sharpview_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/wftest/parity/labctl"
	"github.com/praetorian-inc/wftest/parity/normalize"
	"github.com/praetorian-inc/wftest/parity/sharpviewcases"
)

var baselineDir = filepath.Join("..", "..", "..", "testdata", "parity-baselines", "sharpview")

// TestSharpViewParity validates wasmforge SharpView against native
// SharpView baselines captured from Flangvik/SharpCollection.
func TestSharpViewParity(t *testing.T) {
	labctl.SkipIfLabDown(t)

	binary := os.Getenv("WASMFORGE_TEST_BINARY")
	if binary == "" {
		binary = "/tmp/wf-out/sharpview.exe"
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("binary not found at %s (set WASMFORGE_TEST_BINARY to override): %v",
			binary, err)
	}

	if _, err := labctl.PushTo("win11-ssh", binary, "sharpview-parity.exe"); err != nil {
		t.Fatalf("labctl push: %v", err)
	}
	relocate := exec.Command("labctl", "exec", "win11-ssh",
		`powershell -NoProfile -Command "Get-Process | Where-Object {$_.Name -like '*-parity'} | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 500; New-Item -ItemType Directory -Force -Path C:\WfBin | Out-Null; icacls C:\WfBin /grant 'Everyone:(OI)(CI)RX' | Out-Null; Copy-Item -Force C:\Users\localuser\sharpview-parity.exe C:\WfBin\sharpview-parity.exe"`)
	if out, err := relocate.CombinedOutput(); err != nil {
		t.Fatalf("relocate binary to C:\\WfBin: %v\n%s", err, out)
	}
	pushed := &labctl.PushedBinary{LabPath: `C:\WfBin\sharpview-parity.exe`}

	for _, c := range sharpviewcases.Cases() {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			actual, runErr := pushed.RunOn(c.PersonaOrDefault(), c.Args...)
			actual = normalize.Normalize(actual, normalize.Default())

			goldPath := filepath.Join(baselineDir, c.Name+".golden")
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
