package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

func main() {
	failed := false

	// Test os.CreateTemp.
	f, err := os.CreateTemp("", "wasmforge-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: CreateTemp: %v\n", err)
		os.Exit(1)
	}
	tmpName := f.Name()
	fmt.Printf("PASS: CreateTemp created %s\n", tmpName)

	// Write data, seek to start, read back, compare.
	data := []byte("seek test data for wasmforge")
	if _, err := f.Write(data); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Write to temp file: %v\n", err)
		os.Exit(1)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Seek to start: %v\n", err)
		os.Exit(1)
	}
	readBack, err := io.ReadAll(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: ReadAll after seek: %v\n", err)
		os.Exit(1)
	}
	if !bytes.Equal(data, readBack) {
		fmt.Fprintf(os.Stderr, "FAIL: Seek read-back mismatch: %q vs %q\n", data, readBack)
		failed = true
	} else {
		fmt.Println("PASS: Write/Seek/Read round-trip matches")
	}

	// Test Truncate.
	truncLen := int64(10)
	if err := f.Truncate(truncLen); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Truncate: %v\n", err)
		failed = true
	} else {
		// Seek to start and read.
		f.Seek(0, io.SeekStart)
		truncData, _ := io.ReadAll(f)
		if int64(len(truncData)) != truncLen {
			fmt.Fprintf(os.Stderr, "FAIL: after Truncate(%d), read %d bytes\n", truncLen, len(truncData))
			failed = true
		} else {
			fmt.Printf("PASS: Truncate(%d) produced %d bytes\n", truncLen, len(truncData))
		}
	}

	f.Close()

	// Clean up temp file.
	os.Remove(tmpName)

	// Test os.MkdirTemp.
	tmpDir, err := os.MkdirTemp("", "wasmforge-dir-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: MkdirTemp: %v\n", err)
		os.Exit(1)
	}
	info, err := os.Stat(tmpDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Stat temp dir: %v\n", err)
		os.Exit(1)
	}
	if !info.IsDir() {
		fmt.Fprintln(os.Stderr, "FAIL: MkdirTemp result is not a directory")
		failed = true
	} else {
		fmt.Printf("PASS: MkdirTemp created directory %s\n", tmpDir)
	}

	// Clean up temp dir.
	os.RemoveAll(tmpDir)

	if failed {
		os.Exit(1)
	}
}
