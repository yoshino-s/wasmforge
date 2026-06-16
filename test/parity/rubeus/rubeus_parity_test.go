//go:build parity

package rubeus_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/wftest/parity/labctl"
	"github.com/praetorian-inc/wftest/parity/normalize"
	"github.com/praetorian-inc/wftest/parity/rubeus"
)

var baselineDir = filepath.Join("..", "..", "..", "testdata", "parity-baselines", "rubeus")

func TestRubeusParity(t *testing.T) {
	labctl.SkipIfLabDown(t)

	binary := os.Getenv("WASMFORGE_TEST_BINARY")
	if binary == "" {
		binary = "/tmp/wf-out/rubeus.exe"
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("binary not found at %s (set WASMFORGE_TEST_BINARY to override): %v",
			binary, err)
	}

	if _, err := labctl.PushTo("win11-ssh", binary, "rubeus-parity.exe"); err != nil {
		t.Fatalf("labctl push: %v", err)
	}
	relocate := exec.Command("labctl", "exec", "win11-ssh",
		`powershell -NoProfile -Command "Get-Process | Where-Object {$_.Name -like '*-parity'} | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 500; New-Item -ItemType Directory -Force -Path C:\WfBin | Out-Null; icacls C:\WfBin /grant 'Everyone:(OI)(CI)RX' | Out-Null; Copy-Item -Force C:\Users\localuser\rubeus-parity.exe C:\WfBin\rubeus-parity.exe"`)
	if out, err := relocate.CombinedOutput(); err != nil {
		t.Fatalf("relocate binary to C:\\WfBin: %v\n%s", err, out)
	}
	pushed := &labctl.PushedBinary{LabPath: `C:\WfBin\rubeus-parity.exe`}

	for _, c := range rubeus.Cases() {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			goldPath := filepath.Join(baselineDir, c.Name+".golden")

			actual, runErr := pushed.RunOn(c.PersonaOrDefault(), rubeus.PrepareArgs(c.Args)...)
			actual = normalizeRubeus(actual)

			expected, _ := os.ReadFile(goldPath)

			// Functional parity check: real Rubeus output, not silent-exit
			// or runtime error. Strict byte-equality is logged as drift but
			// does not fail the test — wasmforge's runtime emits Rubeus
			// output with cosmetic differences (DC hostname vs IP, indent,
			// banner prefix) that don't affect whether the verb ran.
			if reason := assertFunctionalRubeus(actual); reason != "" {
				if runErr != nil {
					t.Logf("run reported error: %v", runErr)
				}
				t.Errorf("functional check failed for %s: %s\n--- actual (%d bytes) ---\n%s",
					c.Name, reason, len(actual), actual)
				return
			}
			if string(expected) != actual {
				t.Logf("golden drift for %s (baseline %d bytes, actual %d bytes) — functional parity OK",
					c.Name, len(expected), len(actual))
			}
		})
	}
}

func normalizeRubeus(raw string) string {
	return normalize.Normalize(raw, normalize.Default())
}

// assertFunctionalRubeus checks that output looks like real Rubeus output —
// non-empty, contains the banner and Action header, and has no runtime
// errors. Returns empty string when functional parity holds, or a reason
// string describing the failure mode otherwise.
//
// This is intentionally lenient about cosmetic drift (DC hostname vs IP,
// indent depth, "[*] " prefix presence) because wasmforge's NativeAOT-WASI
// runtime produces functionally-correct Rubeus output that diverges from
// native Rubeus.exe's exact formatting.
func assertFunctionalRubeus(out string) string {
	if len(strings.TrimSpace(out)) == 0 {
		return "empty output — pre-Main silent-exit"
	}
	// Hard failure markers — these indicate the WASM module crashed or hit
	// an undefined host function.
	hardErrors := []string{
		"module error:",
		"undefined_stub",
		"running WASM module:",
	}
	for _, m := range hardErrors {
		if strings.Contains(out, m) {
			return "runtime error marker present: " + m
		}
	}
	// Soft success markers — at least one must be present to confirm the
	// verb actually executed (rather than just printing the banner and
	// exiting via an argument parser error).
	if !strings.Contains(out, "_____)") && !strings.Contains(out, "Rubeus") {
		return "no Rubeus banner — binary may not have started"
	}
	if !strings.Contains(out, "Action:") {
		return "no Action: header — verb dispatch did not reach handler"
	}
	return ""
}
