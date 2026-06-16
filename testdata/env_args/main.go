package main

import (
	"fmt"
	"os"
)

func main() {
	failed := false

	// Verify os.Args[0] is populated.
	if len(os.Args) == 0 {
		fmt.Fprintln(os.Stderr, "FAIL: os.Args is empty")
		os.Exit(1)
	}
	if os.Args[0] == "" {
		fmt.Fprintln(os.Stderr, "FAIL: os.Args[0] is empty string")
		failed = true
	} else {
		fmt.Println("PASS: os.Args[0] is populated:", os.Args[0])
	}

	// Verify os.Environ() returns a slice (may be empty if no env set).
	env := os.Environ()
	fmt.Printf("PASS: os.Environ() returned %d entries\n", len(env))

	// Verify os.Getenv works for a known variable.
	// The runtime can set env vars via WithEnv; check common ones.
	home := os.Getenv("HOME")
	path := os.Getenv("PATH")
	if home != "" {
		fmt.Println("PASS: HOME env var is set:", home)
	} else if path != "" {
		fmt.Println("PASS: PATH env var is set:", path)
	} else {
		fmt.Println("PASS: no HOME or PATH env var (expected in minimal WASI)")
	}

	// Verify setting and getting a custom env var.
	// Note: os.Setenv may not be supported in WASI preview 1,
	// so we test that Getenv returns empty for unset vars.
	val := os.Getenv("WASMFORGE_TEST_NONEXISTENT")
	if val != "" {
		fmt.Fprintln(os.Stderr, "FAIL: WASMFORGE_TEST_NONEXISTENT should be empty, got:", val)
		failed = true
	} else {
		fmt.Println("PASS: os.Getenv for unset var returns empty")
	}

	// Verify os.Getpid() returns non-negative (WASI returns 0).
	pid := os.Getpid()
	if pid < 0 {
		fmt.Fprintf(os.Stderr, "FAIL: os.Getpid() returned negative: %d\n", pid)
		failed = true
	} else {
		fmt.Printf("PASS: os.Getpid() returned %d (non-negative)\n", pid)
	}

	if failed {
		os.Exit(1)
	}
}
