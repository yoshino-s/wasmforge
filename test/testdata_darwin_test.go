//go:build integration && darwin

package test

import (
	"testing"
	"time"
)

func TestDarwinInterop(t *testing.T) {
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	bin := WasmForgeBuild(t, cfg, "./testdata/darwin_interop", BuildOpts{
		GOOS:   "darwin",
		GOARCH: "amd64",
	})
	t.Logf("built darwin_interop in %v (%s)", bin.Duration, bin.Path)
	result := LocalRun(t, bin.Path, nil, 30*time.Second)
	VerifyPASS(t, result)
}
