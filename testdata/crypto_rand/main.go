package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
)

func main() {
	failed := false

	// Test crypto/rand.Read for 32 bytes.
	buf := make([]byte, 32)
	n, err := rand.Read(buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: crypto/rand.Read: %v\n", err)
		os.Exit(1)
	}
	if n != 32 {
		fmt.Fprintf(os.Stderr, "FAIL: crypto/rand.Read returned %d bytes, expected 32\n", n)
		os.Exit(1)
	}
	fmt.Println("PASS: crypto/rand.Read returned 32 bytes")

	// Verify not all zeros.
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		fmt.Fprintln(os.Stderr, "FAIL: crypto/rand.Read returned all zeros")
		failed = true
	} else {
		fmt.Println("PASS: crypto/rand.Read data is not all zeros")
	}

	// Two successive reads should differ.
	buf2 := make([]byte, 32)
	if _, err := rand.Read(buf2); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: second crypto/rand.Read: %v\n", err)
		os.Exit(1)
	}
	same := true
	for i := range buf {
		if buf[i] != buf2[i] {
			same = false
			break
		}
	}
	if same {
		fmt.Fprintln(os.Stderr, "FAIL: two crypto/rand.Read calls returned identical data")
		failed = true
	} else {
		fmt.Println("PASS: two successive crypto/rand.Read calls differ")
	}

	// Test rand.Int for a random number in range [0, 100).
	// Using crypto/rand.Int instead of math/rand/v2 for broader compatibility.
	val, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: rand.Int: %v\n", err)
		failed = true
	} else if val.Int64() < 0 || val.Int64() >= 100 {
		fmt.Fprintf(os.Stderr, "FAIL: rand.Int returned %d, expected [0, 100)\n", val.Int64())
		failed = true
	} else {
		fmt.Printf("PASS: rand.Int returned %d (in range [0, 100))\n", val.Int64())
	}

	if failed {
		os.Exit(1)
	}
}
