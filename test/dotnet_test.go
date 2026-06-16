//go:build integration && dotnet

package test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDotnetMigrate tests the `wasmforge dotnet-migrate` command against real
// GhostPack repos. This test runs locally — no remote access required.
func TestDotnetMigrate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping dotnet tests in short mode")
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	if !cfg.Dotnet.Enabled {
		t.Skip("dotnet tests disabled in config")
	}

	t.Run("seatbelt", func(t *testing.T) {
		// Clone or reuse cached Seatbelt source.
		sourceDir := dotnetCloneOrReuse(t, cfg.Dotnet.SeatbeltRepo, cfg.Dotnet.SeatbeltSource)

		// Copy to temp dir so we don't mutate the cached source.
		workDir := t.TempDir()
		cmd := exec.Command("cp", "-r", sourceDir+"/.", workDir)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("cp source to workDir: %v\n%s", err, out)
		}

		// Run dotnet-migrate.
		dotnetMigrateLocal(t, cfg, workDir)

		// Verify .csproj.framework-backup exists (original .csproj was backed up).
		csprojBackups, err := filepath.Glob(filepath.Join(workDir, "**", "*.csproj.framework-backup"))
		if err != nil {
			t.Fatalf("globbing for .csproj.framework-backup: %v", err)
		}
		if len(csprojBackups) == 0 {
			// Try top-level too (some repos have flat structure).
			csprojBackups, _ = filepath.Glob(filepath.Join(workDir, "*.csproj.framework-backup"))
		}
		if len(csprojBackups) == 0 {
			t.Error("no .csproj.framework-backup files found — migrate did not back up original csproj")
		}

		// Verify the new .csproj contains net10.0 and PublishAot.
		csprojFiles, _ := filepath.Glob(filepath.Join(workDir, "**", "*.csproj"))
		if len(csprojFiles) == 0 {
			csprojFiles, _ = filepath.Glob(filepath.Join(workDir, "*.csproj"))
		}
		if len(csprojFiles) == 0 {
			t.Fatal("no .csproj files found after migration")
		}
		for _, f := range csprojFiles {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Errorf("reading %s: %v", f, err)
				continue
			}
			content := string(data)
			if !strings.Contains(content, "net10.0") {
				t.Errorf("%s: missing net10.0 target framework", f)
			}
			if !strings.Contains(content, "PublishAot") {
				t.Errorf("%s: missing PublishAot property", f)
			}
		}

		// Verify WasmForge/ helpers directory exists with 4 files.
		helpersDir := filepath.Join(workDir, "WasmForge")
		entries, err := os.ReadDir(helpersDir)
		if err != nil {
			t.Fatalf("WasmForge/ helpers dir not found: %v", err)
		}
		if len(entries) != 4 {
			t.Errorf("WasmForge/ dir has %d files, expected 4", len(entries))
		}

		// Verify stubs/ directory exists with 4 subdirectories.
		stubsDir := filepath.Join(workDir, "stubs")
		stubEntries, err := os.ReadDir(stubsDir)
		if err != nil {
			t.Fatalf("stubs/ dir not found: %v", err)
		}
		subdirCount := 0
		for _, e := range stubEntries {
			if e.IsDir() {
				subdirCount++
			}
		}
		if subdirCount != 4 {
			t.Errorf("stubs/ has %d subdirectories, expected 4", subdirCount)
		}
	})

	t.Run("rubeus", func(t *testing.T) {
		// Clone or reuse cached Rubeus source.
		sourceDir := dotnetCloneOrReuse(t, cfg.Dotnet.RubeusRepo, cfg.Dotnet.RubeusSource)

		// Copy to temp dir so we don't mutate the cached source.
		workDir := t.TempDir()
		cmd := exec.Command("cp", "-r", sourceDir+"/.", workDir)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("cp source to workDir: %v\n%s", err, out)
		}

		// Run dotnet-migrate.
		dotnetMigrateLocal(t, cfg, workDir)

		// Verify .csproj.framework-backup exists.
		csprojBackups, _ := filepath.Glob(filepath.Join(workDir, "**", "*.csproj.framework-backup"))
		if len(csprojBackups) == 0 {
			csprojBackups, _ = filepath.Glob(filepath.Join(workDir, "*.csproj.framework-backup"))
		}
		if len(csprojBackups) == 0 {
			t.Error("no .csproj.framework-backup files found — migrate did not back up original csproj")
		}

		// Verify the new .csproj contains net10.0 and PublishAot.
		csprojFiles, _ := filepath.Glob(filepath.Join(workDir, "**", "*.csproj"))
		if len(csprojFiles) == 0 {
			csprojFiles, _ = filepath.Glob(filepath.Join(workDir, "*.csproj"))
		}
		if len(csprojFiles) == 0 {
			t.Fatal("no .csproj files found after migration")
		}
		for _, f := range csprojFiles {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Errorf("reading %s: %v", f, err)
				continue
			}
			content := string(data)
			if !strings.Contains(content, "net10.0") {
				t.Errorf("%s: missing net10.0 target framework", f)
			}
			if !strings.Contains(content, "PublishAot") {
				t.Errorf("%s: missing PublishAot property", f)
			}
		}

		// Verify WasmForge/ helpers directory exists with 4 files.
		helpersDir := filepath.Join(workDir, "WasmForge")
		entries, err := os.ReadDir(helpersDir)
		if err != nil {
			t.Fatalf("WasmForge/ helpers dir not found: %v", err)
		}
		if len(entries) != 4 {
			t.Errorf("WasmForge/ dir has %d files, expected 4", len(entries))
		}

		// Verify stubs/ directory exists with 4 subdirectories.
		stubsDir := filepath.Join(workDir, "stubs")
		stubEntries, err := os.ReadDir(stubsDir)
		if err != nil {
			t.Fatalf("stubs/ dir not found: %v", err)
		}
		subdirCount := 0
		for _, e := range stubEntries {
			if e.IsDir() {
				subdirCount++
			}
		}
		if subdirCount != 4 {
			t.Errorf("stubs/ has %d subdirectories, expected 4", subdirCount)
		}
	})
}

// TestDotnetSeatbelt tests the full .NET NativeAOT-WASI pipeline for Seatbelt:
// clone → migrate → build on Ludus → deploy to Win11 → verify output.
func TestDotnetSeatbelt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping dotnet tests in short mode")
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	if !cfg.Dotnet.Enabled {
		t.Skip("dotnet tests disabled in config")
	}
	if !cfg.Remote.Enabled || !labctlAvailable() {
		t.Skip("remote testing not available (labctl or remote.enabled)")
	}

	// Phase 1: Prepare — clone/reuse source and migrate.
	sourceDir := dotnetCloneOrReuse(t, cfg.Dotnet.SeatbeltRepo, cfg.Dotnet.SeatbeltSource)
	workDir := t.TempDir()
	cmd := exec.Command("cp", "-r", sourceDir+"/.", workDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cp source to workDir: %v\n%s", err, out)
	}
	dotnetMigrateLocal(t, cfg, workDir)

	// Phase 2: Build on Ludus.
	pePath := dotnetBuildOnLudus(t, cfg, workDir, "Seatbelt")

	// Cleanup on exit.
	t.Cleanup(func() {
		labctlKill(t, cfg.Remote.Win11.Machine, "Seatbelt.exe")
		labctlCleanup(t, "kali")
	})

	// Phase 3: Standalone tests on Win11.
	t.Run("standalone", func(t *testing.T) {
		t.Run("runs_without_crash", func(t *testing.T) {
			result := dotnetRunOnWin11(t, cfg, pePath, "EnvironmentVariables", 2*time.Minute)
			VerifyExitCode(t, result, 0)
		})

		t.Run("has_section_markers", func(t *testing.T) {
			result := dotnetRunOnWin11(t, cfg, pePath, "EnvironmentVariables OSInfo", 2*time.Minute)
			VerifyContains(t, result, "====== EnvironmentVariables ======", "====== OSInfo ======")
		})

		t.Run("os_info", func(t *testing.T) {
			result := dotnetRunOnWin11(t, cfg, pePath, "OSInfo", 2*time.Minute)
			VerifyContains(t, result, "Hostname", "ProductName", "Build")
		})

		t.Run("token_privileges", func(t *testing.T) {
			result := dotnetRunOnWin11(t, cfg, pePath, "TokenPrivileges", 2*time.Minute)
			VerifyContains(t, result, "SeDebugPrivilege")
		})
	})

	// Phase 4: Execute-assembly via Sliver (skipped — full C2 testing is in TestSliver).
	t.Run("execute_assembly", func(t *testing.T) {
		if !cfg.Sliver.Enabled {
			t.Skip("sliver not enabled")
		}
		if cfg.Sliver.SeatbeltPath == "" {
			t.Skip("seatbelt_path not configured for execute-assembly")
		}
		// Full execute-assembly requires an active Sliver beacon — run TestSliver for
		// complete C2 validation including execute-assembly/seatbelt.
		t.Skip("execute-assembly requires active Sliver beacon — run TestSliver for full C2 validation")
	})
}

// TestDotnetRubeus tests the full .NET NativeAOT-WASI pipeline for Rubeus:
// clone → migrate → build on Ludus → deploy to Win11 → verify output.
func TestDotnetRubeus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping dotnet tests in short mode")
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	if !cfg.Dotnet.Enabled {
		t.Skip("dotnet tests disabled in config")
	}
	if !cfg.Remote.Enabled || !labctlAvailable() {
		t.Skip("remote testing not available (labctl or remote.enabled)")
	}

	// Phase 1: Prepare — clone/reuse source and migrate.
	sourceDir := dotnetCloneOrReuse(t, cfg.Dotnet.RubeusRepo, cfg.Dotnet.RubeusSource)
	workDir := t.TempDir()
	cmd := exec.Command("cp", "-r", sourceDir+"/.", workDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cp source to workDir: %v\n%s", err, out)
	}
	dotnetMigrateLocal(t, cfg, workDir)

	// Phase 2: Build on Ludus.
	pePath := dotnetBuildOnLudus(t, cfg, workDir, "Rubeus")

	// Cleanup on exit.
	t.Cleanup(func() {
		labctlKill(t, cfg.Remote.Win11.Machine, "Rubeus.exe")
		labctlCleanup(t, "kali")
	})

	// Phase 3: Standalone tests on Win11.
	t.Run("standalone", func(t *testing.T) {
		t.Run("currentluid", func(t *testing.T) {
			result := dotnetRunOnWin11(t, cfg, pePath, "currentluid", 2*time.Minute)
			VerifyContains(t, result, "Current LogonID", "LUID")
		})

		t.Run("klist", func(t *testing.T) {
			result := dotnetRunOnWin11(t, cfg, pePath, "klist", 2*time.Minute)
			VerifyContains(t, result, "Action: List Kerberos Tickets")
		})

		t.Run("hash", func(t *testing.T) {
			// RC4 hash of "Password123" is always 58A478135A93AC3BF058A5EA0E8FDB71.
			result := dotnetRunOnWin11(t, cfg, pePath, "hash /password:Password123", 2*time.Minute)
			VerifyContains(t, result, "58A478135A93AC3BF058A5EA0E8FDB71")
		})
	})
}

