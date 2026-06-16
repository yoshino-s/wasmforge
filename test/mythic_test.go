//go:build integration && mythic

package test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/wftest/c2"
)

func TestMythic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping C2 test in short mode")
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	if !cfg.Mythic.Enabled {
		t.Skip("mythic tests disabled in config")
	}
	if cfg.Mythic.TribunusSource == "" {
		t.Skip("mythic tribunus_source not configured")
	}
	if !cfg.Remote.Enabled || !labctlAvailable() {
		t.Skip("remote testing not available (labctl or remote.enabled)")
	}

	// Connect to Mythic.
	mythicClient, err := c2.NewMythicClient(cfg.Mythic.APIURL, cfg.Mythic.Username, cfg.Mythic.PasswordEnv)
	if err != nil {
		t.Fatalf("connecting to Mythic: %v", err)
	}

	// Copy source to temp dir for config patching.
	tmpDir, err := os.MkdirTemp("", "wftest-tribunus-*")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	if err := copyDir(cfg.Mythic.TribunusSource, tmpDir); err != nil {
		t.Fatalf("copying tribunus source: %v", err)
	}

	// Build with WasmForge.
	t.Log("building Tribunus agent...")
	bin := WasmForgeBuild(t, cfg, tmpDir, BuildOpts{
		GOOS:      "windows",
		GOARCH:    "amd64",
		Win32APIs: true,
		Tags:      "shell,ps,netstat,execute_assembly,execute_coff,execute_pe,injection,token,portscan,ldapsearch,socks",
	})
	t.Logf("built Tribunus agent in %v (%s)", bin.Duration, bin.Path)

	// Deploy to Win11.
	machine := cfg.Remote.Win11.Machine
	remotePath := cfg.Remote.Win11.WorkDir + `\tribunus-test.exe`

	labctlKill(t, machine, "tribunus-test.exe")
	labctlPush(t, bin.Path, machine, remotePath, true)
	labctlExecBackground(t, machine, remotePath)

	// Wait for callback.
	t.Log("waiting for Mythic callback...")
	// Use empty UUID to match any callback (the payload UUID is compiled into the binary).
	callback, err := mythicClient.WaitForCallback("", 90*time.Second)
	if err != nil {
		t.Fatalf("no Mythic callback: %v", err)
	}
	t.Logf("got callback: %s (host=%s, user=%s, pid=%d)",
		callback.ID, callback.Hostname, callback.Username, callback.PID)

	callbackID := 0
	fmt.Sscanf(callback.ID, "%d", &callbackID)
	if callbackID == 0 {
		t.Fatalf("invalid callback ID: %s", callback.ID)
	}

	// Cleanup on exit.
	t.Cleanup(func() {
		labctlKill(t, machine, "tribunus-test.exe")
		labctlCleanup(t, "kali")
	})

	// Run command battery.
	mythicCommands := []struct {
		name    string
		command string
		params  string
		check   func(t *testing.T, output string)
	}{
		{
			name:    "shell/whoami",
			command: "shell",
			params:  "whoami",
			check: func(t *testing.T, output string) {
				if output == "" {
					t.Fatal("whoami returned empty")
				}
				t.Logf("whoami: %s", strings.TrimSpace(output))
			},
		},
		{
			name:    "shell/hostname",
			command: "shell",
			params:  "hostname",
			check: func(t *testing.T, output string) {
				if output == "" {
					t.Fatal("hostname returned empty")
				}
				t.Logf("hostname: %s", strings.TrimSpace(output))
			},
		},
		{
			name:    "ps",
			command: "ps",
			params:  "",
			check: func(t *testing.T, output string) {
				if output == "" {
					t.Fatal("ps returned empty")
				}
				t.Logf("ps output: %d bytes", len(output))
			},
		},
		{
			name:    "netstat",
			command: "netstat",
			params:  "",
			check: func(t *testing.T, output string) {
				if output == "" {
					t.Fatal("netstat returned empty")
				}
				t.Logf("netstat output: %d bytes", len(output))
			},
		},
	}

	for _, mc := range mythicCommands {
		mc := mc
		t.Run(mc.name, func(t *testing.T) {
			taskID, err := mythicClient.CreateTask(callbackID, mc.command, mc.params)
			if err != nil {
				t.Fatalf("creating task %q: %v", mc.command, err)
			}

			output, err := mythicClient.WaitForTaskResult(taskID, 60*time.Second)
			if err != nil {
				t.Fatalf("waiting for task %d: %v", taskID, err)
			}

			mc.check(t, output)
		})
	}
}

// copyDir recursively copies src to dst.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
}
