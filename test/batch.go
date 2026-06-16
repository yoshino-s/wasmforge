package test

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// BatchResult holds parsed results from a batch Windows test run.
type BatchResult struct {
	Tests map[string]BatchTestResult // keyed by test name (exe basename without .exe)
}

// BatchTestResult holds results for a single test in a batch.
type BatchTestResult struct {
	Output   string
	ExitCode int
}

const batchRunnerPS1 = `$ErrorActionPreference = 'SilentlyContinue'
$resultsFile = '%s\results.txt'
$exeDir = '%s'

'' | Out-File $resultsFile -Encoding UTF8

Get-ChildItem "$exeDir\*.exe" | Sort-Object Name | ForEach-Object {
    $name = $_.BaseName
    "--- TEST $name ---" | Out-File $resultsFile -Append -Encoding UTF8

    $proc = Start-Process -FilePath $_.FullName -NoNewWindow -PassThru -RedirectStandardOutput "$exeDir\$name.stdout" -RedirectStandardError "$exeDir\$name.stderr" -Wait
    $exitCode = $proc.ExitCode

    if (Test-Path "$exeDir\$name.stdout") {
        Get-Content "$exeDir\$name.stdout" | Out-File $resultsFile -Append -Encoding UTF8
    }
    if (Test-Path "$exeDir\$name.stderr") {
        Get-Content "$exeDir\$name.stderr" | Out-File $resultsFile -Append -Encoding UTF8
    }

    "EXIT_CODE=$exitCode" | Out-File $resultsFile -Append -Encoding UTF8
    "--- END $name ---" | Out-File $resultsFile -Append -Encoding UTF8
}

'BATCH_COMPLETE' | Out-File $resultsFile -Append -Encoding UTF8
`

// createTestZip creates a ZIP file containing all the provided binary files.
func createTestZip(t *testing.T, binaries map[string]string) string {
	t.Helper()

	f, err := os.CreateTemp("", "wftest-batch-*.zip")
	if err != nil {
		t.Fatalf("creating zip temp file: %v", err)
	}
	defer f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	w := zip.NewWriter(f)
	for name, path := range binaries {
		src, err := os.Open(path)
		if err != nil {
			t.Fatalf("opening %s: %v", path, err)
		}
		dst, err := w.Create(name)
		if err != nil {
			src.Close()
			t.Fatalf("adding %s to zip: %v", name, err)
		}
		if _, err := io.Copy(dst, src); err != nil {
			src.Close()
			t.Fatalf("copying %s to zip: %v", name, err)
		}
		src.Close()
	}

	if err := w.Close(); err != nil {
		t.Fatalf("closing zip: %v", err)
	}
	return f.Name()
}

// createBatchRunner generates the PowerShell script for running all tests.
func createBatchRunner(t *testing.T, workDir string) string {
	t.Helper()

	content := fmt.Sprintf(batchRunnerPS1, workDir, workDir)
	f, err := os.CreateTemp("", "wftest-runner-*.ps1")
	if err != nil {
		t.Fatalf("creating runner temp file: %v", err)
	}
	defer f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writing runner: %v", err)
	}
	return f.Name()
}

// runBatchWindows executes a batch of test binaries on a remote Windows machine.
// Steps:
//  1. Push ZIP of all binaries
//  2. Push PowerShell runner script
//  3. Execute runner (unzips + runs each exe sequentially)
//  4. Pull results
//  5. Parse per-test results
func runBatchWindows(t *testing.T, cfg *Config, binaries map[string]string) BatchResult {
	t.Helper()

	machine := cfg.Remote.Win11.Machine
	workDir := cfg.Remote.Win11.WorkDir

	// Create work dir on remote.
	labctlExec(t, machine, fmt.Sprintf("mkdir %s 2>nul & echo ok", workDir), 30*time.Second)

	// Create and push ZIP.
	zipPath := createTestZip(t, binaries)
	remoteZip := workDir + `\tests.zip`
	labctlPush(t, zipPath, machine, remoteZip, true)

	// Create and push runner script.
	runnerPath := createBatchRunner(t, workDir)
	remoteRunner := workDir + `\runner.ps1`
	labctlPush(t, runnerPath, machine, remoteRunner, true)

	// Extract ZIP and run tests.
	expandCmd := fmt.Sprintf(`powershell -ExecutionPolicy Bypass -Command "Expand-Archive -Path '%s' -DestinationPath '%s' -Force"`, remoteZip, workDir)
	labctlExec(t, machine, expandCmd, 1*time.Minute)

	runCmd := fmt.Sprintf(`powershell -ExecutionPolicy Bypass -File %s`, remoteRunner)
	labctlExec(t, machine, runCmd, 5*time.Minute)

	// Pull results.
	resultsLocal, err := os.CreateTemp("", "wftest-results-*.txt")
	if err != nil {
		t.Fatalf("creating results temp file: %v", err)
	}
	resultsLocal.Close()
	t.Cleanup(func() { os.Remove(resultsLocal.Name()) })

	remoteResults := workDir + `\results.txt`
	labctlPull(t, machine, remoteResults, resultsLocal.Name())

	data, err := os.ReadFile(resultsLocal.Name())
	if err != nil {
		t.Fatalf("reading results: %v", err)
	}

	return parseBatchResults(t, string(data))
}

// parseBatchResults parses the output format:
//
//	--- TEST name ---
//	output lines...
//	EXIT_CODE=N
//	--- END name ---
func parseBatchResults(t *testing.T, data string) BatchResult {
	t.Helper()

	result := BatchResult{Tests: make(map[string]BatchTestResult)}
	lines := strings.Split(data, "\n")

	var currentTest string
	var outputLines []string

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")

		if strings.HasPrefix(line, "--- TEST ") && strings.HasSuffix(line, " ---") {
			currentTest = strings.TrimSuffix(strings.TrimPrefix(line, "--- TEST "), " ---")
			outputLines = nil
			continue
		}

		if strings.HasPrefix(line, "--- END ") && strings.HasSuffix(line, " ---") {
			if currentTest != "" {
				tr := BatchTestResult{
					Output:   strings.Join(outputLines, "\n"),
					ExitCode: -1,
				}
				// Extract exit code from output.
				for _, ol := range outputLines {
					if strings.HasPrefix(ol, "EXIT_CODE=") {
						fmt.Sscanf(ol, "EXIT_CODE=%d", &tr.ExitCode)
					}
				}
				result.Tests[currentTest] = tr
			}
			currentTest = ""
			outputLines = nil
			continue
		}

		if currentTest != "" {
			outputLines = append(outputLines, line)
		}
	}

	if !strings.Contains(data, "BATCH_COMPLETE") {
		t.Error("batch results missing BATCH_COMPLETE marker — runner may have crashed")
	}

	return result
}

// verifyBatchTest checks a single test from batch results.
func verifyBatchTest(t *testing.T, batch BatchResult, testName string) {
	t.Helper()

	tr, ok := batch.Tests[testName]
	if !ok {
		names := make([]string, 0, len(batch.Tests))
		for k := range batch.Tests {
			names = append(names, k)
		}
		t.Fatalf("test %q not found in batch results (have: %s)", testName, strings.Join(names, ", "))
	}

	if tr.ExitCode != 0 {
		t.Errorf("%s: exit code %d (expected 0)\noutput:\n%s", testName, tr.ExitCode, tr.Output)
		return
	}

	if strings.Contains(tr.Output, "FAIL:") {
		t.Errorf("%s: output contains FAIL:\n%s", testName, tr.Output)
		return
	}

	if !strings.Contains(tr.Output, "PASS:") {
		t.Errorf("%s: no PASS: lines in output\n%s", testName, tr.Output)
		return
	}

	passCount := strings.Count(tr.Output, "PASS:")
	t.Logf("%s: %d PASS assertions", testName, passCount)
}
