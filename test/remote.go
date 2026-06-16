package test

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// labctlExec runs a command on a remote machine via labctl.
func labctlExec(t *testing.T, machine, command string, timeout time.Duration) RunResult {
	t.Helper()
	args := []string{"exec"}
	if timeout > 0 {
		args = append(args, "-t", timeout.String())
	}
	args = append(args, machine, command)
	return runLabctl(t, args, timeout+30*time.Second)
}

// labctlPush uploads a local file to a remote machine.
// Syntax: labctl push <local> <machine>:<remotePath>
func labctlPush(t *testing.T, localPath, machine, remotePath string, force bool) {
	t.Helper()
	args := []string{"push"}
	if force {
		args = append(args, "-f")
	}
	dest := fmt.Sprintf("%s:%s", machine, remotePath)
	args = append(args, localPath, dest)

	result := runLabctl(t, args, 2*time.Minute)
	if result.ExitCode != 0 {
		t.Fatalf("labctl push failed: %s%s", result.Stdout, result.Stderr)
	}
}

// labctlPull downloads a file from a remote machine.
// Syntax: labctl pull <machine>:<remotePath> <local>
func labctlPull(t *testing.T, machine, remotePath, localPath string) {
	t.Helper()
	src := fmt.Sprintf("%s:%s", machine, remotePath)
	args := []string{"pull", src, localPath}

	result := runLabctl(t, args, 2*time.Minute)
	if result.ExitCode != 0 {
		t.Fatalf("labctl pull failed: %s%s", result.Stdout, result.Stderr)
	}
}

// labctlRead reads a remote file to stdout.
// Syntax: labctl read <machine> <remotePath>
func labctlRead(t *testing.T, machine, remotePath string) string {
	t.Helper()
	args := []string{"read", machine, remotePath}
	result := runLabctl(t, args, 1*time.Minute)
	if result.ExitCode != 0 {
		t.Fatalf("labctl read failed: %s%s", result.Stdout, result.Stderr)
	}
	return result.Stdout
}

// labctlKill kills a process on a remote machine.
// Syntax: labctl kill <machine> <processName>
func labctlKill(t *testing.T, machine, processName string) {
	t.Helper()
	args := []string{"kill", machine, processName}
	// Ignore errors — process may not be running.
	runLabctl(t, args, 30*time.Second)
}

// labctlExecBackground runs a command on a remote machine without waiting.
// Uses labctl exec with a short timeout — the process continues on the remote host.
func labctlExecBackground(t *testing.T, machine, command string) {
	t.Helper()
	args := []string{"exec", "-t", "5s", machine, command}
	// Don't fail on timeout — we expect the command to outlive the exec session.
	runLabctl(t, args, 10*time.Second)
}

// labctlCleanup kills stuck processes on a machine.
func labctlCleanup(t *testing.T, machine string) {
	t.Helper()
	args := []string{"cleanup", machine}
	runLabctl(t, args, 30*time.Second)
}

// labctlAvailable checks if labctl is in PATH.
func labctlAvailable() bool {
	_, err := exec.LookPath("labctl")
	return err == nil
}

func runLabctl(t *testing.T, args []string, timeout time.Duration) RunResult {
	t.Helper()
	cmd := exec.Command("labctl", args...)

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return RunResult{ExitCode: -1, Stderr: err.Error()}
	}
	go func() { done <- cmd.Wait() }()

	var exitCode int
	select {
	case err := <-done:
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = -1
			}
		}
	case <-time.After(timeout):
		cmd.Process.Kill()
		return RunResult{
			Stdout:   stdout.String(),
			Stderr:   "labctl timeout after " + timeout.String(),
			ExitCode: -1,
			Duration: time.Since(start),
		}
	}

	return RunResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Duration: time.Since(start),
	}
}
