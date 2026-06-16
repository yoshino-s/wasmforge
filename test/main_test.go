//go:build integration

package test

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	start := time.Now()

	// Run tests.
	code := m.Run()

	// Summary.
	elapsed := time.Since(start)
	if code == 0 {
		fmt.Printf("\n=== SUITE PASSED in %v ===\n", elapsed.Round(time.Second))
	} else {
		fmt.Printf("\n=== SUITE FAILED in %v ===\n", elapsed.Round(time.Second))
	}

	os.Exit(code)
}
