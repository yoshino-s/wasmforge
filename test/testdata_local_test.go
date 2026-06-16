//go:build integration

package test

import (
	"testing"
	"time"
)

// localTests lists testdata programs that run on any platform (no Win32, no Darwin frameworks).
var localTests = []struct {
	name    string
	pkg     string
	timeout time.Duration
}{
	{"echo_tcp", "./testdata/echo_tcp", 30 * time.Second},
	{"udp_echo", "./testdata/udp_echo", 30 * time.Second},
	{"http_client", "./testdata/http_client", 30 * time.Second},
	{"dns_lookup", "./testdata/dns_lookup", 30 * time.Second},
	{"time_clock", "./testdata/time_clock", 15 * time.Second},
	{"crypto_rand", "./testdata/crypto_rand", 15 * time.Second},
	{"env_args", "./testdata/env_args", 15 * time.Second},
	{"fs_readwrite", "./testdata/fs_readwrite", 15 * time.Second},
	{"fs_tempfile", "./testdata/fs_tempfile", 15 * time.Second},
	{"path_ops", "./testdata/path_ops", 15 * time.Second},
	{"goroutine_sync", "./testdata/goroutine_sync", 30 * time.Second},
	{"stdio_pipe", "./testdata/stdio_pipe", 15 * time.Second},
	{"port_scanner", "./testdata/port_scanner", 60 * time.Second},
	{"os_host", "./testdata/os_host", 15 * time.Second},
}

func TestLocal(t *testing.T) {
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	for _, tt := range localTests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			bin := WasmForgeBuild(t, cfg, tt.pkg, BuildOpts{})
			t.Logf("built %s in %v (%s)", tt.name, bin.Duration, bin.Path)
			result := LocalRun(t, bin.Path, nil, tt.timeout)
			VerifyPASS(t, result)
		})
	}
}

func TestLocalShort(t *testing.T) {
	if !testing.Short() {
		t.Skip("only runs with -short flag (quick regression subset)")
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	// Quick subset — no network dependencies.
	quickTests := []struct {
		name    string
		pkg     string
		timeout time.Duration
	}{
		{"crypto_rand", "./testdata/crypto_rand", 15 * time.Second},
		{"goroutine_sync", "./testdata/goroutine_sync", 30 * time.Second},
		{"time_clock", "./testdata/time_clock", 15 * time.Second},
		{"env_args", "./testdata/env_args", 15 * time.Second},
		{"path_ops", "./testdata/path_ops", 15 * time.Second},
	}

	for _, tt := range quickTests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			bin := WasmForgeBuild(t, cfg, tt.pkg, BuildOpts{})
			result := LocalRun(t, bin.Path, nil, tt.timeout)
			VerifyPASS(t, result)
		})
	}
}
