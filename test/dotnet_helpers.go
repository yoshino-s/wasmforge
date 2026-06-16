//go:build integration && dotnet

package test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// dotnetCloneOrReuse clones a git repo to a temp dir, or reuses a cached path.
// If cachedPath is non-empty and exists, returns it directly.
// Otherwise clones repoURL into a new temp dir and returns the path.
func dotnetCloneOrReuse(t *testing.T, repoURL, cachedPath string) string {
	t.Helper()
	if cachedPath != "" {
		if _, err := os.Stat(cachedPath); err == nil {
			t.Logf("reusing cached source: %s", cachedPath)
			return cachedPath
		}
	}

	tmpDir := t.TempDir()
	t.Logf("cloning %s...", repoURL)
	cmd := exec.Command("git", "clone", "--depth=1", repoURL, tmpDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git clone %s: %v\n%s", repoURL, err, out)
	}
	t.Logf("cloned to %s", tmpDir)
	return tmpDir
}

// dotnetMigrateLocal runs `wasmforge dotnet-migrate` on a source directory.
// Uses the wasmforge binary from the test config (auto-builds if needed).
func dotnetMigrateLocal(t *testing.T, cfg *Config, sourceDir string) {
	t.Helper()
	bin := wasmforgeBinary(t, cfg)

	cmd := exec.Command(bin, "dotnet-migrate", sourceDir, "-v")
	cmd.Dir = resolveSourceRoot(cfg) // So it can find dotnet/helpers and dotnet/stubs
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dotnet-migrate %s: %v\n%s", sourceDir, err, out)
	}
	t.Logf("migration output:\n%s", out)
}

// dotnetBuildOnLudus transfers a migrated project to Ludus, builds it there,
// and pulls the resulting PE back. Returns the local path to the built PE.
//
// Steps:
//  1. Copy the bridge/ directory from wasmforge dotnet/ into the project
//  2. Tar the project directory
//  3. Push tarball + ludus_build.sh to Ludus
//  4. Execute ludus_build.sh on Ludus
//  5. Pull the resulting PE back
func dotnetBuildOnLudus(t *testing.T, cfg *Config, sourceDir, projectName string) string {
	t.Helper()

	if !labctlAvailable() {
		t.Skip("labctl not available")
	}

	src := resolveSourceRoot(cfg)
	workDir := cfg.Dotnet.LudusWorkDir

	// Copy bridge directory into project (needed for C compilation on Ludus)
	bridgeSrc := filepath.Join(src, "dotnet", "bridge")
	bridgeDst := filepath.Join(sourceDir, "bridge")
	copyDir(t, bridgeSrc, bridgeDst)

	// Create tarball of the project
	tarPath := filepath.Join(os.TempDir(), "wftest-dotnet-"+projectName+".tar.gz")
	t.Cleanup(func() { os.Remove(tarPath) })

	tarCmd := exec.Command("tar", "czf", tarPath, "-C", filepath.Dir(sourceDir), filepath.Base(sourceDir))
	if out, err := tarCmd.CombinedOutput(); err != nil {
		t.Fatalf("tar: %v\n%s", err, out)
	}

	// Push tarball and build script to Ludus
	ludusTar := workDir + "/" + projectName + ".tar.gz"
	ludusScript := workDir + "/ludus_build.sh"
	ludusProject := workDir + "/" + projectName
	ludusOutput := workDir + "/" + projectName + ".exe"
	buildScript := filepath.Join(src, "dotnet", "ludus_build.sh")

	labctlExec(t, "ludus", "mkdir -p "+workDir, 10*time.Second)
	labctlPush(t, tarPath, "ludus", ludusTar, true)
	labctlPush(t, buildScript, "ludus", ludusScript, true)

	// Extract on Ludus
	labctlExec(t, "ludus", "cd "+workDir+" && rm -rf "+projectName+" && tar xzf "+projectName+".tar.gz", 30*time.Second)

	// Make build script executable and run it
	labctlExec(t, "ludus", "chmod +x "+ludusScript, 5*time.Second)
	result := labctlExec(t, "ludus", ludusScript+" "+ludusProject+" "+ludusOutput, 5*time.Minute)
	t.Logf("ludus build output:\n%s", result.Stdout)

	// Pull the PE back
	localPE := filepath.Join(os.TempDir(), "wftest-"+projectName+".exe")
	t.Cleanup(func() { os.Remove(localPE) })
	labctlPull(t, "ludus", ludusOutput, localPE)

	info, err := os.Stat(localPE)
	if err != nil {
		t.Fatalf("PE not found after pull: %v", err)
	}
	t.Logf("built PE: %s (%d bytes)", localPE, info.Size())
	return localPE
}

// dotnetRunOnWin11 deploys a PE to Win11 via labctl, executes it with args,
// and returns the captured output.
func dotnetRunOnWin11(t *testing.T, cfg *Config, pePath, args string, timeout time.Duration) RunResult {
	t.Helper()

	if !labctlAvailable() {
		t.Skip("labctl not available")
	}

	machine := cfg.Remote.Win11.Machine
	exeName := filepath.Base(pePath)
	remotePath := cfg.Remote.Win11.WorkDir + `\` + exeName

	// Add Defender exclusion
	labctlExec(t, machine, `powershell -c "Add-MpPreference -ExclusionProcess `+exeName+`"`, 30*time.Second)

	// Kill previous instance
	labctlKill(t, machine, exeName)

	// Push PE
	labctlPush(t, pePath, machine, remotePath, true)

	// Execute and capture output
	cmd := remotePath
	if args != "" {
		cmd += " " + args
	}
	return labctlExec(t, machine, cmd, timeout)
}

// copyDir recursively copies src directory to dst.
func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	cmd := exec.Command("cp", "-r", src, dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cp -r %s %s: %v\n%s", src, dst, err, out)
	}
}
