package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	failed := false

	// Use /tmp as our writable workspace (auto-mounted by runtime).
	base := "/tmp/wasmforge_fs_test"

	// Clean up from any previous run.
	os.RemoveAll(base)

	// Test os.MkdirAll to create nested directories.
	nested := filepath.Join(base, "a", "b", "c")
	if err := os.MkdirAll(nested, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: MkdirAll(%q): %v\n", nested, err)
		os.Exit(1)
	}
	fmt.Println("PASS: MkdirAll created nested directories")

	// Test os.WriteFile + os.ReadFile round-trip.
	testFile := filepath.Join(base, "hello.txt")
	data := []byte("hello wasmforge filesystem")
	if err := os.WriteFile(testFile, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: WriteFile: %v\n", err)
		os.Exit(1)
	}
	readBack, err := os.ReadFile(testFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: ReadFile: %v\n", err)
		os.Exit(1)
	}
	if !bytes.Equal(data, readBack) {
		fmt.Fprintf(os.Stderr, "FAIL: ReadFile mismatch: wrote %q, read %q\n", data, readBack)
		failed = true
	} else {
		fmt.Println("PASS: WriteFile/ReadFile round-trip matches")
	}

	// Test os.Stat.
	info, err := os.Stat(testFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Stat: %v\n", err)
		os.Exit(1)
	}
	if info.Size() != int64(len(data)) {
		fmt.Fprintf(os.Stderr, "FAIL: Stat size %d != expected %d\n", info.Size(), len(data))
		failed = true
	} else {
		fmt.Printf("PASS: Stat size is correct (%d bytes)\n", info.Size())
	}
	if info.IsDir() {
		fmt.Fprintln(os.Stderr, "FAIL: Stat says file is a directory")
		failed = true
	} else {
		fmt.Println("PASS: Stat IsDir() is false for file")
	}

	// Verify directory stat.
	dirInfo, err := os.Stat(nested)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Stat directory: %v\n", err)
		os.Exit(1)
	}
	if !dirInfo.IsDir() {
		fmt.Fprintln(os.Stderr, "FAIL: Stat says directory is not a directory")
		failed = true
	} else {
		fmt.Println("PASS: Stat IsDir() is true for directory")
	}

	// Test os.ReadDir.
	// Create a few files in the base directory.
	for i := 0; i < 3; i++ {
		p := filepath.Join(base, fmt.Sprintf("file%d.txt", i))
		os.WriteFile(p, []byte(fmt.Sprintf("content %d", i)), 0644)
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: ReadDir: %v\n", err)
		os.Exit(1)
	}
	// Expect at least 4 entries: a/, hello.txt, file0.txt, file1.txt, file2.txt
	if len(entries) < 4 {
		fmt.Fprintf(os.Stderr, "FAIL: ReadDir returned %d entries, expected >= 4\n", len(entries))
		failed = true
	} else {
		fmt.Printf("PASS: ReadDir returned %d entries\n", len(entries))
	}

	// Test os.Remove file.
	if err := os.Remove(testFile); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Remove file: %v\n", err)
		failed = true
	} else {
		_, err := os.Stat(testFile)
		if err == nil {
			fmt.Fprintln(os.Stderr, "FAIL: file still exists after Remove")
			failed = true
		} else {
			fmt.Println("PASS: Remove file succeeded, Stat confirms gone")
		}
	}

	// Test os.RemoveAll directory tree.
	if err := os.RemoveAll(base); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: RemoveAll: %v\n", err)
		failed = true
	} else {
		_, err := os.Stat(base)
		if err == nil {
			fmt.Fprintln(os.Stderr, "FAIL: directory still exists after RemoveAll")
			failed = true
		} else {
			fmt.Println("PASS: RemoveAll succeeded, directory tree gone")
		}
	}

	if failed {
		os.Exit(1)
	}
}
