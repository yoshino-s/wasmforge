package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	failed := false

	// Test wall clock: year should be > 1970 (WASI clock may not reflect host time exactly).
	now := time.Now()
	if now.Year() <= 1970 {
		fmt.Fprintf(os.Stderr, "FAIL: time.Now() year is %d, expected > 1970\n", now.Year())
		failed = true
	} else {
		fmt.Printf("PASS: time.Now() year is %d (> 1970, wall clock working)\n", now.Year())
	}

	// Test time.Sleep with measurement.
	start := time.Now()
	time.Sleep(100 * time.Millisecond)
	elapsed := time.Since(start)
	if elapsed < 100*time.Millisecond {
		fmt.Fprintf(os.Stderr, "FAIL: Sleep(100ms) elapsed only %v\n", elapsed)
		failed = true
	} else if elapsed > 5*time.Second {
		fmt.Fprintf(os.Stderr, "FAIL: Sleep(100ms) took too long: %v\n", elapsed)
		failed = true
	} else {
		fmt.Printf("PASS: Sleep(100ms) elapsed %v (reasonable)\n", elapsed)
	}

	// Test monotonic ordering: two successive time.Now() calls are ordered.
	t1 := time.Now()
	t2 := time.Now()
	if t2.Before(t1) {
		fmt.Fprintf(os.Stderr, "FAIL: t2 (%v) is before t1 (%v)\n", t2, t1)
		failed = true
	} else {
		fmt.Println("PASS: successive time.Now() calls are monotonically ordered")
	}

	// Test time.After channel.
	start = time.Now()
	select {
	case <-time.After(50 * time.Millisecond):
		afterElapsed := time.Since(start)
		if afterElapsed < 50*time.Millisecond {
			fmt.Fprintf(os.Stderr, "FAIL: time.After(50ms) fired too early: %v\n", afterElapsed)
			failed = true
		} else {
			fmt.Printf("PASS: time.After(50ms) received after %v\n", afterElapsed)
		}
	case <-time.After(5 * time.Second):
		fmt.Fprintln(os.Stderr, "FAIL: time.After(50ms) did not fire within 5s")
		failed = true
	}

	// Test Unix timestamp round-trip.
	nowUnix := now.Unix()
	roundTrip := time.Unix(nowUnix, 0)
	diff := now.Sub(roundTrip)
	if diff < 0 {
		diff = -diff
	}
	if diff > time.Second {
		fmt.Fprintf(os.Stderr, "FAIL: Unix round-trip diff is %v (> 1s)\n", diff)
		failed = true
	} else {
		fmt.Printf("PASS: Unix round-trip within %v\n", diff)
	}

	if failed {
		os.Exit(1)
	}
}
