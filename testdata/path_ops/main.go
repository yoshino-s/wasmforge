package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	failed := false

	// filepath.Join uses "/" on wasip1 (even when host is Windows).
	joined := filepath.Join("a", "b", "c")
	if joined != "a/b/c" {
		fmt.Fprintf(os.Stderr, "FAIL: filepath.Join(\"a\",\"b\",\"c\") = %q, expected \"a/b/c\"\n", joined)
		failed = true
	} else {
		fmt.Printf("PASS: filepath.Join(\"a\",\"b\",\"c\") = %q\n", joined)
	}

	// filepath.Dir and filepath.Base.
	dir := filepath.Dir("/foo/bar/baz.txt")
	base := filepath.Base("/foo/bar/baz.txt")
	if dir != "/foo/bar" {
		fmt.Fprintf(os.Stderr, "FAIL: filepath.Dir = %q, expected \"/foo/bar\"\n", dir)
		failed = true
	} else {
		fmt.Printf("PASS: filepath.Dir(\"/foo/bar/baz.txt\") = %q\n", dir)
	}
	if base != "baz.txt" {
		fmt.Fprintf(os.Stderr, "FAIL: filepath.Base = %q, expected \"baz.txt\"\n", base)
		failed = true
	} else {
		fmt.Printf("PASS: filepath.Base(\"/foo/bar/baz.txt\") = %q\n", base)
	}

	// filepath.Ext.
	ext := filepath.Ext("archive.tar.gz")
	if ext != ".gz" {
		fmt.Fprintf(os.Stderr, "FAIL: filepath.Ext(\"archive.tar.gz\") = %q, expected \".gz\"\n", ext)
		failed = true
	} else {
		fmt.Printf("PASS: filepath.Ext(\"archive.tar.gz\") = %q\n", ext)
	}

	// filepath.Clean normalizes paths.
	clean := filepath.Clean("a//b/./c")
	if clean != "a/b/c" {
		fmt.Fprintf(os.Stderr, "FAIL: filepath.Clean(\"a//b/./c\") = %q, expected \"a/b/c\"\n", clean)
		failed = true
	} else {
		fmt.Printf("PASS: filepath.Clean(\"a//b/./c\") = %q\n", clean)
	}

	// os.PathSeparator should be '/' in WASI.
	if os.PathSeparator != '/' {
		fmt.Fprintf(os.Stderr, "FAIL: os.PathSeparator = %q, expected '/'\n", string(os.PathSeparator))
		failed = true
	} else {
		fmt.Println("PASS: os.PathSeparator is '/'")
	}

	// filepath.IsAbs.
	if !filepath.IsAbs("/foo") {
		fmt.Fprintln(os.Stderr, "FAIL: filepath.IsAbs(\"/foo\") returned false")
		failed = true
	} else {
		fmt.Println("PASS: filepath.IsAbs(\"/foo\") is true")
	}
	if filepath.IsAbs("relative/path") {
		fmt.Fprintln(os.Stderr, "FAIL: filepath.IsAbs(\"relative/path\") returned true")
		failed = true
	} else {
		fmt.Println("PASS: filepath.IsAbs(\"relative/path\") is false")
	}

	// filepath.Abs should return a rooted path.
	// Note: filepath.Abs calls os.Getwd(), which may fail in WASI without a mounted CWD.
	abs, err := filepath.Abs("relative")
	if err != nil {
		// This is expected in WASI when no CWD is mounted.
		fmt.Printf("PASS: filepath.Abs(\"relative\") returned error (expected in WASI): %v\n", err)
	} else if !filepath.IsAbs(abs) {
		fmt.Fprintf(os.Stderr, "FAIL: filepath.Abs returned non-absolute path: %q\n", abs)
		failed = true
	} else {
		fmt.Printf("PASS: filepath.Abs(\"relative\") = %q (rooted)\n", abs)
	}

	if failed {
		os.Exit(1)
	}
}
