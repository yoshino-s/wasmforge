// Package labctl wraps the host `labctl` CLI for use from Go-based parity
// tests. It provides Push, RunOn (persona-aware), and the ParityCase struct
// that bundles a verb's name, args, and persona into a single test descriptor.
package labctl

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ParityCase describes a single parity test: the args to pass to the binary
// on the remote lab host, under which persona, and other metadata.
type ParityCase struct {
	// Name is the golden filename basename (without .golden extension).
	Name string
	// Args are the verb name and all arguments to pass to the binary.
	// An empty or nil Args slice invokes the binary with no arguments (noargs case).
	Args []string
	// Persona is the labctl machine name: "win11-ssh", "win11-domainuser",
	// "win11-domainadmin", or "dc01-ssh". Defaults to "win11-ssh" if empty.
	Persona string
	// Timeout overrides the default per-command timeout. Zero uses the default.
	Timeout time.Duration
	// ExcludeReason, if non-empty, marks this case as excluded from live runs.
	// Capture-baseline writes only the reason string into the golden file.
	ExcludeReason string
}

// PersonaOrDefault returns the effective persona for this case.
func (c ParityCase) PersonaOrDefault() string {
	if c.Persona != "" {
		return c.Persona
	}
	return "win11-ssh"
}

func machineName() string {
	if m := os.Getenv("LABCTL_WIN11_MACHINE"); m != "" {
		return m
	}
	return "win11-ssh"
}

// PushedBinary represents a binary that has been pushed to the lab.
type PushedBinary struct {
	LabPath string // e.g. "C:\\Users\\localuser\\rubeus-parity.exe"
}

// Push copies localPath to the default win11-ssh machine under remoteName.
func Push(localPath, remoteName string) (*PushedBinary, error) {
	remotePath := `C:\Users\localuser\` + remoteName
	cmd := exec.Command("labctl", "push", "--force", localPath,
		machineName()+":"+remotePath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("labctl push: %w: %s", err, out)
	}
	return &PushedBinary{LabPath: remotePath}, nil
}

// PushTo copies localPath to the specified persona machine under remoteName.
func PushTo(persona, localPath, remoteName string) (*PushedBinary, error) {
	remotePath := `C:\Users\localuser\` + remoteName
	cmd := exec.Command("labctl", "push", "--force", localPath,
		persona+":"+remotePath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("labctl push to %s: %w: %s", persona, err, out)
	}
	return &PushedBinary{LabPath: remotePath}, nil
}

// Run invokes the pushed binary on the default machine with the given args.
func (b *PushedBinary) Run(args ...string) (string, error) {
	cmdline := b.LabPath
	for _, a := range args {
		cmdline += " " + a
	}
	cmd := exec.Command("labctl", "exec", machineName(), cmdline)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("labctl exec: %w", err)
	}
	return string(out), nil
}

// RunOn invokes the pushed binary on the specified persona with the given args.
// The persona is typically "win11-ssh", "win11-domainuser", or "win11-domainadmin".
// An empty persona falls back to the default machine.
func (b *PushedBinary) RunOn(persona string, args ...string) (string, error) {
	if persona == "" {
		persona = machineName()
	}
	cmdline := b.LabPath
	for _, a := range args {
		cmdline += " " + a
	}
	// Hard-cap the per-case run at 90s so a hung binary (slow Directory.GetFiles
	// over a deep tree, blocked LDAP bind, etc.) doesn't stall the whole suite.
	// 90s comfortably exceeds the average ~5s per-case wall time while keeping
	// worst-case suite duration bounded.
	cmd := exec.Command("labctl", "exec", "-t", "90s", persona, cmdline)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("labctl exec %s: %w", persona, err)
	}
	return string(out), nil
}

// IsReachable returns nil if the default lab machine responds to a test command.
func IsReachable() error {
	cmd := exec.Command("labctl", "exec", machineName(), "echo", "ok")
	_, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("lab unreachable: %w", err)
	}
	return nil
}

type labSkipper interface {
	Skipf(format string, args ...interface{})
}

// SkipIfLabDown skips the current test if the lab is unreachable.
func SkipIfLabDown(t labSkipper) {
	if err := IsReachable(); err != nil {
		t.Skipf("Win11 lab unreachable, skipping parity test: %v", err)
	}
}

// StripBanner removes the GhostPack ASCII-art banner block.
// The banner is delimited by lines containing "%&&@@@&&" (start) and
// "#%%%%##" (end).
func StripBanner(s string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	inBanner := false
	for _, line := range lines {
		if !inBanner && strings.Contains(line, "%&&@@@&&") {
			inBanner = true
			continue
		}
		if inBanner {
			if strings.Contains(line, "#%%%%##") {
				inBanner = false
			}
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
