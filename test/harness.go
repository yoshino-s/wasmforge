package test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// BuildOpts configures a WasmForge build invocation.
type BuildOpts struct {
	GOOS      string // Target GOOS (default: runtime.GOOS).
	GOARCH    string // Target GOARCH (default: "amd64").
	Win32APIs bool   // Pass --win32-apis.
	Tags      string // Extra build tags (comma-separated).
	Verbose   bool   // Pass -v.
	NoSign    bool   // Pass --no-sign.
	Output    string // Explicit output path; empty = auto temp file.
}

// BuildResult holds the output of a successful WasmForge build.
type BuildResult struct {
	Path     string        // Path to the built binary.
	Duration time.Duration // How long the build took.
}

// RunResult holds the output of running a built binary.
type RunResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

var (
	wasmforgeBin     string
	wasmforgeBinOnce sync.Once
	wasmforgeBinErr  error

	// buildMu serializes WasmForge build invocations.
	// The GOROOT cache uses symlinks that aren't safe for concurrent creation.
	buildMu sync.Mutex

	// sourceRoot caches the resolved absolute path to the wasmforge source.
	sourceRoot     string
	sourceRootOnce sync.Once
)

// resolveSourceRoot returns the absolute path to the wasmforge source root.
func resolveSourceRoot(cfg *Config) string {
	sourceRootOnce.Do(func() {
		src := cfg.WasmForge.Source
		if !filepath.IsAbs(src) {
			wd, _ := os.Getwd()
			src = filepath.Join(wd, src)
		}
		sourceRoot = filepath.Clean(src)
	})
	return sourceRoot
}

// wasmforgeBinary returns the path to the wasmforge binary, building it if needed.
func wasmforgeBinary(t *testing.T, cfg *Config) string {
	t.Helper()
	wasmforgeBinOnce.Do(func() {
		if cfg.WasmForge.Binary != "" {
			if _, err := os.Stat(cfg.WasmForge.Binary); err == nil {
				wasmforgeBin = cfg.WasmForge.Binary
				return
			}
		}

		src := resolveSourceRoot(cfg)
		tmpBin := filepath.Join(os.TempDir(), "wasmforge-test-bin")
		if runtime.GOOS == "windows" {
			tmpBin += ".exe"
		}

		t.Logf("Building wasmforge binary from %s ...", src)
		cmd := exec.Command("go", "build", "-o", tmpBin, "./cmd/wasmforge")
		cmd.Dir = src
		cmd.Env = append(os.Environ(), "GOWORK=off")
		out, err := cmd.CombinedOutput()
		if err != nil {
			wasmforgeBinErr = fmt.Errorf("building wasmforge: %v\n%s", err, out)
			return
		}
		wasmforgeBin = tmpBin
		t.Logf("Built wasmforge binary: %s", tmpBin)
	})

	if wasmforgeBinErr != nil {
		t.Fatalf("wasmforge binary unavailable: %v", wasmforgeBinErr)
	}
	return wasmforgeBin
}

// WasmForgeBuild compiles a Go package using wasmforge.
// Builds are serialized because the GOROOT cache doesn't support concurrent creation.
func WasmForgeBuild(t *testing.T, cfg *Config, pkg string, opts BuildOpts) BuildResult {
	t.Helper()
	bin := wasmforgeBinary(t, cfg)
	src := resolveSourceRoot(cfg)

	output := opts.Output
	if output == "" {
		name := filepath.Base(pkg)
		f, err := os.CreateTemp("", "wftest-"+name+"-*")
		if err != nil {
			t.Fatalf("creating temp file: %v", err)
		}
		output = f.Name()
		f.Close()
		t.Cleanup(func() { os.Remove(output) })
	}

	// Make output path absolute (wasmforge resolves relative to its CWD).
	if !filepath.IsAbs(output) {
		wd, _ := os.Getwd()
		output = filepath.Join(wd, output)
	}

	// Resolve package path relative to wasmforge source root.
	pkgArg := pkg
	if !filepath.IsAbs(pkg) {
		pkgArg = filepath.Join(src, pkg)
	}

	args := []string{"build", "-o", output}
	if opts.Win32APIs {
		args = append(args, "--win32-apis")
	}
	if opts.Tags != "" {
		args = append(args, "--tags", opts.Tags)
	}
	if opts.Verbose {
		args = append(args, "-v")
	}
	if opts.NoSign {
		args = append(args, "--no-sign")
	}
	args = append(args, pkgArg)

	cmd := exec.Command(bin, args...)
	// Set CWD to wasmforge source root so findModuleRoot() works.
	cmd.Dir = src
	env := os.Environ()
	env = append(env, "GOWORK=off")
	if opts.GOOS != "" {
		env = append(env, "GOOS="+opts.GOOS)
	}
	if opts.GOARCH != "" {
		env = append(env, "GOARCH="+opts.GOARCH)
	} else {
		env = append(env, "GOARCH=amd64")
	}
	cmd.Env = env

	// Serialize builds — GOROOT cache doesn't support concurrent creation.
	buildMu.Lock()
	start := time.Now()
	out, err := cmd.CombinedOutput()
	dur := time.Since(start)
	buildMu.Unlock()

	if err != nil {
		t.Fatalf("wasmforge build %s failed (%v):\n%s", pkg, err, out)
	}

	return BuildResult{Path: output, Duration: dur}
}

// LocalRun executes a built binary locally and captures output.
func LocalRun(t *testing.T, binaryPath string, args []string, timeout time.Duration) RunResult {
	t.Helper()

	cmd := exec.Command(binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s: %v", binaryPath, err)
	}
	go func() { done <- cmd.Wait() }()

	var exitCode int
	select {
	case err := <-done:
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				t.Fatalf("running %s: %v", binaryPath, err)
			}
		}
	case <-time.After(timeout):
		cmd.Process.Kill()
		t.Fatalf("timeout running %s after %v", binaryPath, timeout)
	}

	return RunResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Duration: time.Since(start),
	}
}

// VerifyPASS checks that the run result contains at least one PASS: line,
// no FAIL: lines, and exited with code 0.
func VerifyPASS(t *testing.T, result RunResult) {
	t.Helper()

	combined := result.Stdout + result.Stderr

	if result.ExitCode != 0 {
		t.Errorf("exit code %d (expected 0)\nstdout:\n%s\nstderr:\n%s",
			result.ExitCode, result.Stdout, result.Stderr)
		return
	}

	if strings.Contains(combined, "FAIL:") {
		t.Errorf("output contains FAIL:\nstdout:\n%s\nstderr:\n%s",
			result.Stdout, result.Stderr)
		return
	}

	if !strings.Contains(result.Stdout, "PASS:") {
		t.Errorf("no PASS: lines in output\nstdout:\n%s\nstderr:\n%s",
			result.Stdout, result.Stderr)
		return
	}

	passCount := strings.Count(result.Stdout, "PASS:")
	t.Logf("%d PASS assertions in %v", passCount, result.Duration)
}

// VerifyContains checks that the combined output contains all expected substrings.
func VerifyContains(t *testing.T, result RunResult, expected ...string) {
	t.Helper()
	combined := result.Stdout + result.Stderr
	for _, s := range expected {
		if !strings.Contains(combined, s) {
			t.Errorf("output missing %q\nstdout:\n%s\nstderr:\n%s",
				s, result.Stdout, result.Stderr)
		}
	}
}

// VerifyExitCode checks the exit code matches expected.
func VerifyExitCode(t *testing.T, result RunResult, expected int) {
	t.Helper()
	if result.ExitCode != expected {
		t.Errorf("exit code %d (expected %d)\nstdout:\n%s\nstderr:\n%s",
			result.ExitCode, expected, result.Stdout, result.Stderr)
	}
}
