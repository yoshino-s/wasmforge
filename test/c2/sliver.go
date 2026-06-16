//go:build sliver

package c2

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ansiRE strips ANSI CSI escape sequences (color codes, cursor movement,
// private-mode toggles). Includes '?' in the parameter class so DEC private
// modes like ESC[?25h (hide cursor) are stripped.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]`)

// oscRE strips OSC sequences. OSC = ESC ] ... terminated by BEL (\x07) or
// ST (ESC \). Newer terminals/sliver-client builds emit either form.
var oscRE = regexp.MustCompile(`\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)`)

// boxDrawingRE matches Unicode box-drawing characters (U+2500–U+257F) and
// common table border characters. Sliver v1.7.x renders ps/sessions/beacons
// via lipgloss tables; replacing borders with whitespace lets strings.Fields
// parse the rows.
var boxDrawingRE = regexp.MustCompile(`[\x{2500}-\x{257F}│┃|]`)

// SliverClient wraps the Sliver client CLI for test automation.
// Uses the `sliver-client console --rc <rc-file>` approach under a macOS
// script(1) PTY wrapper so the client starts up and processes commands from
// a pre-written rc file.
type SliverClient struct {
	clientBin  string // Path to sliver-client binary.
	configPath string // Path to operator .cfg file (sanity-checked, not passed to console).
}

// NewSliverClient creates a new Sliver console client.
//
// clientBin is the path to the sliver-client binary (auto-detected from PATH
// if empty). operatorConfigPath is the path to the operator .cfg file; it is
// sanity-checked for existence and valid JSON with lhost/lport/token fields,
// but is NOT passed to `console` (v1.7.3 removed --config from that sub-command).
// The console auto-selects the single config present in ~/.sliver-client/configs/.
// NewSliverClient validates that exactly one config exists there so failures are
// caught early with a clear message.
func NewSliverClient(clientBin, operatorConfigPath string) (*SliverClient, error) {
	if clientBin == "" {
		p, err := exec.LookPath("sliver-client")
		if err != nil {
			p, err = exec.LookPath("sliver")
			if err != nil {
				return nil, fmt.Errorf("sliver-client not found in PATH")
			}
		}
		clientBin = p
	}

	// Sanity-check the operator config file.
	if _, err := os.Stat(operatorConfigPath); err != nil {
		return nil, fmt.Errorf("operator config not found: %w", err)
	}
	if err := validateOperatorConfig(operatorConfigPath); err != nil {
		return nil, fmt.Errorf("operator config invalid: %w", err)
	}

	// Ensure exactly one config lives in ~/.sliver-client/configs/ so that
	// `sliver-client console` auto-selects it without ambiguity.
	if err := validateSingleConfig(); err != nil {
		return nil, err
	}

	return &SliverClient{
		clientBin:  clientBin,
		configPath: operatorConfigPath,
	}, nil
}

// Close is a no-op; there is no persistent connection to tear down.
func (c *SliverClient) Close() error { return nil }

// WaitForBeacon polls for a beacon matching the given hostname.
// It polls every 5 seconds until timeout is reached.
func (c *SliverClient) WaitForBeacon(hostname string, timeout time.Duration) (*Beacon, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := c.execScript(15*time.Second, []string{"beacons"})
		if err == nil {
			if id := parseIDFromTable(out, hostname); id != "" {
				return &Beacon{ID: id, Hostname: hostname}, nil
			}
		}
		time.Sleep(5 * time.Second)
	}
	return nil, fmt.Errorf("no beacon from %q within %v", hostname, timeout)
}

// WaitForSession polls for a session matching the given hostname.
// It polls every 5 seconds until timeout is reached.
func (c *SliverClient) WaitForSession(hostname string, timeout time.Duration) (*Beacon, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := c.execScript(15*time.Second, []string{"sessions"})
		if err == nil {
			if id := parseIDFromTable(out, hostname); id != "" {
				return &Beacon{ID: id, Hostname: hostname}, nil
			}
		}
		time.Sleep(5 * time.Second)
	}
	return nil, fmt.Errorf("no session from %q within %v", hostname, timeout)
}

// Whoami returns the current user identity on the target.
func (c *SliverClient) Whoami(sessionID string) (string, error) {
	out, err := c.runInSession(sessionID, "whoami", 15*time.Second)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(stripSliverMarkers(out)), nil
}

// Execute runs an executable on the target and returns its output.
func (c *SliverClient) Execute(sessionID, exe string, args []string) (string, error) {
	cmd := "execute " + exe
	if len(args) > 0 {
		cmd += " " + strings.Join(args, " ")
	}
	out, err := c.runInSession(sessionID, cmd, 30*time.Second)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(stripSliverMarkers(out)), nil
}

// Ps lists processes running on the target.
//
// Passes "--overflow" so sliver-client emits the entire table at once instead
// of blocking on an interactive "Continue? Yes/No" lipgloss paginator. Without
// it, the --rc-driven console sits forever waiting for a key on the prompt
// dialog while the implant's reply is already buffered. With it, ps returns
// in a few seconds and the 30s timeout is comfortable.
func (c *SliverClient) Ps(sessionID string) ([]Process, error) {
	out, err := c.runInSession(sessionID, "ps --overflow", 30*time.Second)
	if err != nil {
		return nil, err
	}
	return parsePsOutput(out), nil
}

// Netstat returns network connection information from the target.
func (c *SliverClient) Netstat(sessionID string) (string, error) {
	out, err := c.runInSession(sessionID, "netstat", 15*time.Second)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(stripSliverMarkers(out)), nil
}

// ExecuteAssembly loads and runs a .NET assembly on the target via
// execute-assembly using Sliver's defaults (sacrificial process, AMSI/ETW
// bypass enabled). NOTE: Sliver v1.7.x rejects --amsi-bypass=false /
// --etw-bypass=false unless --in-process is also set ("can only be used with
// the --in-process flag"), and --in-process corrupts the WasmForge implant's
// host memory pages. So we pass no flags and rely on Sliver's default
// sacrificial-process injection. Uses a 90-second timeout to cover slower
// tools like Rubeus dump and Seatbelt -group=system.
func (c *SliverClient) ExecuteAssembly(sessionID, assemblyPath, args string) (string, error) {
	return c.ExecuteAssemblyWithFlags(sessionID, "", assemblyPath, args, 90*time.Second)
}

// ExecuteAssemblyWithFlags is the lower-level form that lets callers customise
// the flag string passed between "execute-assembly" and the assembly path,
// and override the per-command timeout. Pass "" for flags to invoke
// execute-assembly with its defaults.
//
// Assembly arguments are separated from sliver's own flags by " -- " so that
// dash-prefixed args (e.g. Seatbelt's "-group=system") are not parsed as
// sliver flags. cobra reports "unknown flag: --group" without the separator.
func (c *SliverClient) ExecuteAssemblyWithFlags(sessionID, flags, assemblyPath, args string, timeout time.Duration) (string, error) {
	cmd := "execute-assembly"
	if flags != "" {
		cmd += " " + flags
	}
	cmd += " " + assemblyPath
	if args != "" {
		cmd += " -- " + args
	}
	out, err := c.runInSession(sessionID, cmd, timeout)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(stripSliverMarkers(out)), nil
}

// Sysinfo runs the `info` builtin and returns the cleaned output. This
// exercises the implant's syscall bridge for environment + identity queries
// without depending on a .NET assembly.
func (c *SliverClient) Sysinfo(sessionID string) (string, error) {
	out, err := c.runInSession(sessionID, "info", 15*time.Second)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(stripSliverMarkers(out)), nil
}

// GetPID runs the `getpid` builtin and returns the implant's host process ID
// as text.
func (c *SliverClient) GetPID(sessionID string) (string, error) {
	out, err := c.runInSession(sessionID, "getpid", 15*time.Second)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(stripSliverMarkers(out)), nil
}

// Ifconfig lists network interfaces on the target. Exercises the implant's
// net.Interfaces() proxy.
func (c *SliverClient) Ifconfig(sessionID string) (string, error) {
	out, err := c.runInSession(sessionID, "ifconfig", 20*time.Second)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(stripSliverMarkers(out)), nil
}

// Pwd returns the implant's current working directory.
func (c *SliverClient) Pwd(sessionID string) (string, error) {
	out, err := c.runInSession(sessionID, "pwd", 15*time.Second)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(stripSliverMarkers(out)), nil
}

// Ls lists directory entries at the given path on the target.
func (c *SliverClient) Ls(sessionID, path string) (string, error) {
	cmd := "ls"
	if path != "" {
		cmd += " " + path
	}
	out, err := c.runInSession(sessionID, cmd, 20*time.Second)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(stripSliverMarkers(out)), nil
}

// Kill terminates the active session.
func (c *SliverClient) Kill(sessionID string) error {
	_, err := c.runInSession(sessionID, "kill", 15*time.Second)
	return err
}

// ── internal helpers ───────────────────────────────────────────────────────────

// runInSession executes a single Sliver command within a session context.
// It issues `use <sessionID>` followed by cmd, then exits the console.
func (c *SliverClient) runInSession(sessionID, cmd string, timeout time.Duration) (string, error) {
	cmds := []string{
		"use " + sessionID,
		cmd,
	}
	raw, err := c.execScript(timeout, cmds)
	if err != nil {
		return "", err
	}
	return extractCommandOutput(raw, cmd), nil
}

// execScript drives `sliver-client console --rc <tmpfile>` under a macOS
// script(1) PTY wrapper, waits up to timeout for the process to exit, then
// returns the cleaned log output.
//
// The rc file contains one Sliver command per line; "exit" is appended
// automatically so the console closes cleanly after executing all commands.
func (c *SliverClient) execScript(timeout time.Duration, cmds []string) (string, error) {
	// Write rc file.
	rcFile, err := os.CreateTemp("", "sliver-rc-*.txt")
	if err != nil {
		return "", fmt.Errorf("creating rc file: %w", err)
	}
	defer os.Remove(rcFile.Name())

	for _, line := range cmds {
		fmt.Fprintln(rcFile, line)
	}
	fmt.Fprintln(rcFile, "exit")
	rcFile.Close()

	// Write log file.
	logFile, err := os.CreateTemp("", "sliver-log-*.txt")
	if err != nil {
		return "", fmt.Errorf("creating log file: %w", err)
	}
	logPath := logFile.Name()
	logFile.Close()
	defer os.Remove(logPath)

	// Build the script(1) invocation:
	//   script -q <logfile> <clientBin> console --rc <rcfile>
	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx,
		"script", "-q", logPath,
		c.clientBin, "console", "--rc", rcFile.Name(),
	)
	// Run script + sliver-client in their own process group so a timeout
	// kill takes both down together. Without this, cmd.Process.Kill only
	// sends SIGKILL to script(1); its sliver-client child is reparented
	// to launchd and leaks until the next manual pkill.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("starting sliver-client: %w", err)
	}

	// Wait up to timeout for the process, then kill.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-time.After(timeout):
		// Negative PID = signal the whole process group.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done // reap
	case <-done:
		// process exited cleanly
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		return "", fmt.Errorf("reading log: %w", err)
	}

	return stripANSI(string(raw)), nil
}

// stripANSI removes ANSI escape codes from s.
func stripANSI(s string) string {
	// Order: OSC first (it contains ESC sequences that look like CSI),
	// then CSI/ANSI, finally box-drawing → whitespace so tables parse.
	s = oscRE.ReplaceAllString(s, "")
	s = ansiRE.ReplaceAllString(s, "")
	s = boxDrawingRE.ReplaceAllString(s, " ")
	return s
}

// activeSessionRE matches the "[*] Active session NAME (UUID)" line that
// Sliver emits after a successful `use SESSION_ID` command. We anchor on this
// line because Sliver's `console --rc` mode does NOT print interactive prompts
// or echo commands, so there is no per-command delimiter — only the use
// marker that separates the connect banner from the command's output.
var activeSessionRE = regexp.MustCompile(`Active session\s+\S+\s+\([0-9a-fA-F-]+\)`)

// executeAssemblySpinnerRE matches the rendered execute-assembly progress
// spinner (e.g. " ⠋  Executing assembly ... ⠙  Executing assembly ... "). The
// spinner rewrites a single line via carriage returns, so after ANSI/CR
// stripping we end up with a long sequence of braille + repeated phrases that
// drown out the actual assembly output.
var executeAssemblySpinnerRE = regexp.MustCompile(`(?:\s*[\x{2800}-\x{28FF}]\s*Executing assembly\s*\.\.\.\s*)+`)

// extractCommandOutput pulls the actual command result out of the cleaned
// sliver-client console log. Each execScript call issues "use SESSION; CMD;
// exit" against a fresh console, so the log layout is:
//
//	^D...Connecting to 127.0.0.1:31337 ...        (connect banner)
//	[*] Active session NAME (UUID)                (use's response)
//	<command output>                              (what we want)
//
// We anchor on the "Active session" line because Sliver --rc mode does not
// print prompts. The cmd argument is unused — kept for future extensibility
// and to make the call site self-documenting.
func extractCommandOutput(log, _ string) string {
	lines := strings.Split(log, "\n")

	start := -1
	for i, line := range lines {
		if activeSessionRE.MatchString(line) {
			start = i + 1
			break
		}
	}
	if start < 0 {
		// Use command didn't take effect (no session marker). Return the
		// log as-is so callers can see the error in the failure message.
		return log
	}

	// Strip the execute-assembly spinner so substring checks against the
	// assembly's real output aren't drowned out by repeated spinner text.
	out := strings.Join(lines[start:], "\n")
	out = executeAssemblySpinnerRE.ReplaceAllString(out, "\n")
	return out
}

// parseIDFromTable scans the cleaned console output of a `beacons` or
// `sessions` listing for a row containing hostname (case-insensitive) and
// returns the 8-character hex ID in the first column.
//
// Sliver table rows look like (after ANSI stripping):
//
//	abc12345  HOSTNAME  ...
//
// The ID may be prefixed by a UTF-8 emoji icon; we strip leading non-ASCII
// rune runs to find the hex token.
func parseIDFromTable(out, hostname string) string {
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(strings.ToLower(line), strings.ToLower(hostname)) {
			continue
		}
		fields := strings.Fields(line)
		for _, f := range fields {
			// Strip leading non-ASCII characters (emoji prefixes).
			clean := strings.TrimLeftFunc(f, func(r rune) bool { return r > 127 })
			if len(clean) >= 8 && isHexString(clean[:8]) {
				return clean[:8]
			}
		}
	}
	return ""
}

// parsePsOutput parses the table produced by Sliver's `ps` command.
//
// Sliver v1.7.x renders ps via a lipgloss TUI table; after stripANSI replaces
// box-drawing borders with whitespace, each data row starts with two integers
// (PID, PPID). We skip lines that don't begin with two parseable integers so
// header and decorative rows fall out naturally — no separator detection.
func parsePsOutput(out string) []Process {
	var procs []Process
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid < 0 {
			continue
		}
		ppid, err := strconv.Atoi(fields[1])
		if err != nil || ppid < 0 {
			continue
		}
		name := ""
		user := ""
		switch len(fields) {
		case 2:
			// PID PPID only – unlikely but safe.
		case 3:
			name = fields[2]
		default:
			// PID PPID Owner... Executable [Arch] [Session]
			// Prefer the first field that looks like an executable; fall back
			// to the last field if none matches. This survives multi-word
			// owners like "NT AUTHORITY\SYSTEM" splitting on whitespace.
			user = fields[2]
			name = fields[len(fields)-1]
			for i := 2; i < len(fields); i++ {
				lc := strings.ToLower(fields[i])
				if strings.HasSuffix(lc, ".exe") || strings.HasSuffix(lc, ".dll") {
					name = fields[i]
					break
				}
			}
		}
		procs = append(procs, Process{
			PID:  pid,
			PPID: ppid,
			Name: name,
			User: user,
		})
	}
	return procs
}

// stripSliverMarkers removes leading Sliver status prefixes ([*], [+], [!]).
func stripSliverMarkers(s string) string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, prefix := range []string{"[*] ", "[+] ", "[!] "} {
			trimmed = strings.TrimPrefix(trimmed, prefix)
		}
		lines = append(lines, trimmed)
	}
	return strings.Join(lines, "\n")
}

// isHexString reports whether s consists entirely of hex digits.
func isHexString(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

// validateOperatorConfig does a lightweight sanity check that the file is
// valid JSON containing lhost, lport, and token fields.
func validateOperatorConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("not valid JSON: %w", err)
	}
	for _, key := range []string{"lhost", "lport", "token"} {
		if _, ok := m[key]; !ok {
			return fmt.Errorf("missing field %q", key)
		}
	}
	return nil
}

// validateSingleConfig checks that ~/.sliver-client/configs/ contains exactly
// one config file so that `sliver-client console` auto-selects it without
// prompting.
func validateSingleConfig() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}
	cfgDir := filepath.Join(home, ".sliver-client", "configs")
	entries, err := os.ReadDir(cfgDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("~/.sliver-client/configs/ does not exist; copy your operator .cfg there first")
		}
		return fmt.Errorf("reading configs dir: %w", err)
	}
	var cfgs []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".cfg") {
			cfgs = append(cfgs, e.Name())
		}
	}
	switch len(cfgs) {
	case 0:
		return fmt.Errorf("no .cfg files in ~/.sliver-client/configs/; copy your operator config there first")
	case 1:
		return nil
	default:
		return fmt.Errorf("multiple .cfg files in ~/.sliver-client/configs/ (%v); leave only one so console auto-selects it", cfgs)
	}
}
