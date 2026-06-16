//go:build integration && windows_remote

package test

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// win32Tests lists testdata programs that require a real Windows host.
var win32Tests = []struct {
	name string
	pkg  string
}{
	{"win32_interop", "./testdata/win32_interop"},
	{"win32_syscalln", "./testdata/win32_syscalln"},
	{"win32_registry", "./testdata/win32_registry"},
	{"win32_process", "./testdata/win32_process"},
	{"win32_file", "./testdata/win32_file"},
	{"win32_hostmem", "./testdata/win32_hostmem"},
	{"win32_shadow", "./testdata/win32_shadow"},
	{"win32_goffloader", "./testdata/win32_goffloader"},
	{"win32_clr", "./testdata/win32_clr"},
	{"win32_clr_assembly", "./testdata/win32_clr_assembly"},
	{"win32_clr_load", "./testdata/win32_clr_load"},
	{"async_yield", "./testdata/async_yield"},
}

func TestWin32Remote(t *testing.T) {
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	if !cfg.Remote.Enabled {
		t.Skip("remote testing disabled in config")
	}
	if !labctlAvailable() {
		t.Skip("labctl not in PATH")
	}

	// Create temp dir for binaries — cleaned up by parent test, not subtests.
	// This prevents the subtest t.Cleanup in WasmForgeBuild from deleting
	// binaries before runBatchWindows can open them.
	buildDir, err := os.MkdirTemp("", "wftest-win32builds-*")
	if err != nil {
		t.Fatalf("creating build dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(buildDir) })

	// Phase 1: Build all binaries in parallel.
	t.Log("building Win32 test binaries...")
	type buildEntry struct {
		name string
		path string
	}
	builds := make(chan buildEntry, len(win32Tests))

	t.Run("build", func(t *testing.T) {
		for _, tt := range win32Tests {
			tt := tt
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				outPath := filepath.Join(buildDir, tt.name+".exe")
				bin := WasmForgeBuild(t, cfg, tt.pkg, BuildOpts{
					GOOS:      "windows",
					GOARCH:    "amd64",
					Win32APIs: true,
					NoSign:    true, // Skip signing for test builds.
					Output:    outPath,
				})
				t.Logf("built %s in %v", tt.name, bin.Duration)
				builds <- buildEntry{name: tt.name + ".exe", path: bin.Path}
			})
		}
	})
	close(builds)

	// Collect built binaries.
	binaries := make(map[string]string)
	for b := range builds {
		binaries[b.name] = b.path
	}

	if len(binaries) == 0 {
		t.Fatal("no binaries built successfully")
	}

	// Phase 2: Batch execute on Windows.
	t.Logf("running %d binaries on remote Windows...", len(binaries))
	startBatch := time.Now()
	batch := runBatchWindows(t, cfg, binaries)
	t.Logf("batch execution completed in %v", time.Since(startBatch))

	// Phase 3: Report per-test results.
	for _, tt := range win32Tests {
		t.Run(tt.name, func(t *testing.T) {
			verifyBatchTest(t, batch, tt.name)
		})
	}
}
