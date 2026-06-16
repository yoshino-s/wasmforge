package main

import (
	"fmt"
	"os"
)

func main() {
	failed := false

	// Verify stdout and stderr are not nil.
	if os.Stdout == nil {
		fmt.Fprintln(os.Stderr, "FAIL: os.Stdout is nil")
		os.Exit(1)
	}
	if os.Stderr == nil {
		// Can't print to stderr if it's nil, so use stdout.
		fmt.Println("FAIL: os.Stderr is nil")
		os.Exit(1)
	}
	fmt.Println("PASS: os.Stdout is not nil")
	fmt.Println("PASS: os.Stderr is not nil")

	// Test fmt.Println to stdout.
	fmt.Println("PASS: fmt.Println to stdout works")

	// Test fmt.Fprintln to stderr.
	fmt.Fprintln(os.Stderr, "INFO: writing to stderr (this is expected)")
	fmt.Println("PASS: fmt.Fprintln to os.Stderr works")

	// Write 64KB to stdout to test buffering.
	bigBuf := make([]byte, 64*1024)
	for i := range bigBuf {
		bigBuf[i] = byte('A' + (i % 26))
	}
	n, err := os.Stdout.Write(bigBuf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: writing 64KB to stdout: %v\n", err)
		failed = true
	} else if n != len(bigBuf) {
		fmt.Fprintf(os.Stderr, "FAIL: wrote %d bytes, expected %d\n", n, len(bigBuf))
		failed = true
	} else {
		fmt.Printf("\nPASS: wrote %d bytes (64KB) to stdout\n", n)
	}

	if failed {
		os.Exit(1)
	}
}
