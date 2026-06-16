// capture-baseline pushes a .exe to the Win11 lab and captures normalized
// output for each verb/case defined in the per-tool ParityCase slices.
// It writes <name>.golden files into -output dir.
//
// Usage:
//
//	capture-baseline -binary /path/tool.exe -tool rubeus \
//	    -output testdata/parity-baselines/rubeus
//
// The -commands flag (comma-separated verb names) is still supported for quick
// ad-hoc captures, but the primary workflow is -all which reads the tool's
// cases slice automatically.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/wftest/parity/certifycases"
	"github.com/praetorian-inc/wftest/parity/labctl"
	"github.com/praetorian-inc/wftest/parity/normalize"
	"github.com/praetorian-inc/wftest/parity/rubeus"
	"github.com/praetorian-inc/wftest/parity/seatbeltcases"
	"github.com/praetorian-inc/wftest/parity/sharpdpapicases"
	"github.com/praetorian-inc/wftest/parity/sharpupcases"
	"github.com/praetorian-inc/wftest/parity/sharpviewcases"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "capture-baseline: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		binary      = flag.String("binary", "", "absolute path to the local .exe to push to Win11 (omit if -remote-path is set)")
		remotePath  = flag.String("remote-path", "", "use a pre-existing remote binary path; skips push (e.g. C:\\\\Users\\\\localuser\\\\Desktop\\\\Rubeus-native.exe)")
		tool        = flag.String("tool", "", "tool name: rubeus | certify | sharpup | seatbelt | sharpdpapi | sharpview (selects built-in case list); or use -commands")
		commandsCSV = flag.String("commands", "", "comma-separated verb names for simple arg-less invocation (legacy)")
		outputDir   = flag.String("output", "", "directory to write <name>.golden files into")
		allowErrors = flag.Bool("allow-errors", false, "do not fail on non-zero exit from individual commands")
	)
	flag.Parse()

	switch {
	case *binary == "" && *remotePath == "":
		return fmt.Errorf("-binary or -remote-path is required")
	case *binary != "" && *remotePath != "":
		return fmt.Errorf("-binary and -remote-path are mutually exclusive")
	case *outputDir == "":
		return fmt.Errorf("-output is required")
	case *tool == "" && *commandsCSV == "":
		return fmt.Errorf("supply -tool <rubeus|certify> or -commands <csv>")
	}

	if err := labctl.IsReachable(); err != nil {
		return fmt.Errorf("lab unreachable: %w", err)
	}

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", *outputDir, err)
	}

	// Build the case list.
	var cases []labctl.ParityCase
	switch *tool {
	case "rubeus":
		cases = rubeus.Cases()
	case "certify":
		cases = certifycases.Cases()
	case "sharpup":
		cases = sharpupcases.Cases()
	case "seatbelt":
		cases = seatbeltcases.Cases()
	case "sharpdpapi":
		cases = sharpdpapicases.Cases()
	case "sharpview":
		cases = sharpviewcases.Cases()
	case "":
		// Legacy -commands mode: produce arg-less cases with default persona.
		for _, v := range splitCSV(*commandsCSV) {
			cases = append(cases, labctl.ParityCase{Name: v, Args: []string{v}})
		}
	default:
		return fmt.Errorf("unknown tool %q; expected rubeus, certify, sharpup, seatbelt, sharpdpapi, or sharpview", *tool)
	}
	if len(cases) == 0 {
		return fmt.Errorf("empty case list")
	}

	var pushed *labctl.PushedBinary
	if *remotePath != "" {
		// Use pre-existing remote binary — no push needed.
		fmt.Printf("Using pre-existing remote binary: %s\n", *remotePath)
		pushed = &labctl.PushedBinary{LabPath: *remotePath}
	} else {
		remoteName := strings.TrimSuffix(filepath.Base(*binary), ".exe") + "-baseline.exe"
		if *tool != "" {
			remoteName = *tool + "-baseline.exe"
		}
		fmt.Printf("Pushing %s → win11:C:\\Users\\localuser\\%s\n", *binary, remoteName)
		var err error
		pushed, err = labctl.Push(*binary, remoteName)
		if err != nil {
			return fmt.Errorf("push: %w", err)
		}
	}

	isLabConnectionError := func(s string) (string, bool) {
		switch {
		case strings.Contains(s, "winrm error: HTTPConnectionPool"):
			return "WinRM connection failure", true
		case strings.Contains(s, "ERROR: connecting to via host"):
			return "SSH chain to lab failed", true
		case strings.Contains(s, "No route to host"):
			return "lab unreachable", true
		case strings.Contains(s, "labctl push: exit status"):
			return "labctl push failure", true
		}
		return "", false
	}

	fmt.Printf("Running %d cases…\n", len(cases))
	var firstErr error
	var totalBytes int
	var skipped int

	for _, c := range cases {
		path := filepath.Join(*outputDir, c.Name+".golden")

		if c.ExcludeReason != "" {
			if err := os.WriteFile(path, []byte(c.ExcludeReason), 0o644); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}
			fmt.Printf("  %-30s EXCLUDED (%s)\n", c.Name, c.ExcludeReason)
			continue
		}

		runArgs := c.Args
		if *tool == "rubeus" {
			runArgs = rubeus.PrepareArgs(runArgs)
		}
		raw, runErr := pushed.RunOn(c.PersonaOrDefault(), runArgs...)
		clean := normalize.Normalize(raw, normalize.Default())

		if reason, isLabErr := isLabConnectionError(clean); isLabErr {
			fmt.Printf("  %-30s SKIPPED: %s\n", c.Name, reason)
			skipped++
			if firstErr == nil {
				firstErr = fmt.Errorf("lab connection error during %s: %s", c.Name, reason)
			}
			continue
		}

		if err := os.WriteFile(path, []byte(clean), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		totalBytes += len(clean)
		switch {
		case runErr != nil && *allowErrors:
			fmt.Printf("  %-30s ⚠ %d bytes (run error tolerated: %v)\n", c.Name, len(clean), runErr)
		case runErr != nil:
			fmt.Printf("  %-30s ✗ %d bytes (run error: %v)\n", c.Name, len(clean), runErr)
			if firstErr == nil {
				firstErr = fmt.Errorf("case %s failed: %w", c.Name, runErr)
			}
		default:
			fmt.Printf("  %-30s ✓ %d bytes\n", c.Name, len(clean))
		}
	}

	captured := len(cases) - skipped
	if skipped > 0 {
		fmt.Printf("Captured %d cases, %d skipped (lab error), %d total bytes → %s\n",
			captured, skipped, totalBytes, *outputDir)
	} else {
		fmt.Printf("Captured %d cases, %d total bytes → %s\n",
			captured, totalBytes, *outputDir)
	}
	return firstErr
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
