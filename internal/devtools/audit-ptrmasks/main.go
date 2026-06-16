// audit-ptrmasks reports which Win32 APIs observed in a verbose runtime log
// have explicit pointer masks vs. falling through to the heuristic classifier.
//
// Usage:
//
//	go run ./internal/devtools/audit-ptrmasks -log /tmp/wasmforge-verbose.log
//
// The log file should be captured from a wasmforge run with verbose mode
// enabled (Config.Verbose = true in the runtime). Each SyscallN call produces
// a line like:
//
//	[wasmforge] SyscallN: GetUserDefaultLocaleName (proc=0x7ffd..., nargs=2, ...)
//
// The tool reads generated_ptrmasks.go and win32_windows_dll.go as text to
// extract known API names, then compares them against the observed proc names.
// This avoids importing internal/hostmod (which has //go:build windows tags).
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
)

func main() {
	logPath := flag.String("log", "", "Path to verbose wasmforge runtime log (required)")
	generatedPath := flag.String("generated", "internal/hostmod/generated_ptrmasks.go", "Path to generated_ptrmasks.go")
	semanticPath := flag.String("semantic", "internal/hostmod/win32_windows_dll.go", "Path to win32_windows_dll.go (for semanticOverrides)")
	ntapiPath := flag.String("ntapi", "internal/hostmod/ntapi_overrides.go", "Path to ntapi_overrides.go")
	flag.Parse()

	if *logPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Step 1: Build the set of all APIs that have explicit masks.
	knownMasks := make(map[string]bool)

	if err := extractMapKeys(*generatedPath, knownMasks); err != nil {
		log.Printf("WARNING: could not read generated_ptrmasks.go: %v", err)
	}
	if err := extractMapKeys(*semanticPath, knownMasks); err != nil {
		log.Printf("WARNING: could not read win32_windows_dll.go: %v", err)
	}
	if err := extractMapKeys(*ntapiPath, knownMasks); err != nil {
		log.Printf("WARNING: could not read ntapi_overrides.go: %v", err)
	}

	fmt.Printf("Known explicit masks: %d APIs\n\n", len(knownMasks))

	// Step 2: Parse the log for SyscallN proc names.
	observed, err := parseSyscallNLog(*logPath)
	if err != nil {
		log.Fatalf("Failed to parse log: %v", err)
	}

	if len(observed) == 0 {
		fmt.Println("No SyscallN entries found in log.")
		fmt.Println("Make sure the binary was run with verbose mode (Config.Verbose = true).")
		return
	}

	fmt.Printf("Observed %d unique API calls in log\n\n", len(observed))

	// Step 3: Classify each observed API.
	var withMask, heuristic []string
	for api := range observed {
		if knownMasks[api] {
			withMask = append(withMask, api)
		} else {
			heuristic = append(heuristic, api)
		}
	}

	sort.Strings(withMask)
	sort.Strings(heuristic)

	// Report APIs that fell through to heuristic.
	if len(heuristic) > 0 {
		fmt.Printf("APIs using heuristic fallback (%d/%d observed):\n", len(heuristic), len(observed))
		for _, api := range heuristic {
			fmt.Printf("  - %s\n", api)
		}
	} else {
		fmt.Println("All observed APIs have explicit pointer masks.")
	}

	fmt.Println()
	fmt.Printf("Summary: %d with explicit mask, %d heuristic, %d total observed\n",
		len(withMask), len(heuristic), len(observed))
}

// mapKeyRE matches quoted map keys like `"SomeName":` inside Go source.
var mapKeyRE = regexp.MustCompile(`"([A-Za-z][A-Za-z0-9_]*)"\s*:`)

// extractMapKeys reads a Go source file and collects all map keys that look
// like Win32 API names (starts with a letter, alphanumeric + underscore).
func extractMapKeys(path string, out map[string]bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		matches := mapKeyRE.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			if len(m) >= 2 {
				out[m[1]] = true
			}
		}
	}
	return scanner.Err()
}

// syscallNRE matches log lines emitted by the verbose SyscallN tracer.
// Example: [wasmforge] SyscallN: GetUserDefaultLocaleName (proc=0x7ffd...)
var syscallNRE = regexp.MustCompile(`SyscallN:\s+(\w+)`)

// parseSyscallNLog reads a runtime log file and returns the unique set of
// proc names seen in SyscallN trace lines.
func parseSyscallNLog(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "SyscallN") {
			continue
		}
		m := syscallNRE.FindStringSubmatch(line)
		if len(m) >= 2 {
			result[m[1]] = true
		}
	}
	return result, scanner.Err()
}
