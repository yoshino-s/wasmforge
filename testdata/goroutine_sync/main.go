package main

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	failed := false

	// Test atomic increment from 100 goroutines.
	var counter atomic.Int64
	var wg sync.WaitGroup
	const numGoroutines = 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			counter.Add(1)
		}()
	}
	wg.Wait()

	if counter.Load() != numGoroutines {
		fmt.Fprintf(os.Stderr, "FAIL: atomic counter is %d, expected %d\n", counter.Load(), numGoroutines)
		failed = true
	} else {
		fmt.Printf("PASS: atomic counter reached %d from %d goroutines\n", counter.Load(), numGoroutines)
	}

	// Test buffered channel.
	const chanSize = 50
	ch := make(chan int, chanSize)
	for i := 0; i < chanSize; i++ {
		ch <- i
	}
	sum := 0
	for i := 0; i < chanSize; i++ {
		sum += <-ch
	}
	expectedSum := (chanSize - 1) * chanSize / 2
	if sum != expectedSum {
		fmt.Fprintf(os.Stderr, "FAIL: channel sum is %d, expected %d\n", sum, expectedSum)
		failed = true
	} else {
		fmt.Printf("PASS: buffered channel sent/received %d values (sum=%d)\n", chanSize, sum)
	}

	// Test sync.Mutex protecting a map from 50 concurrent writers.
	var mu sync.Mutex
	m := make(map[int]bool)
	const numWriters = 50

	var wg2 sync.WaitGroup
	for i := 0; i < numWriters; i++ {
		wg2.Add(1)
		go func(id int) {
			defer wg2.Done()
			mu.Lock()
			m[id] = true
			mu.Unlock()
		}(i)
	}
	wg2.Wait()

	if len(m) != numWriters {
		fmt.Fprintf(os.Stderr, "FAIL: map has %d entries, expected %d\n", len(m), numWriters)
		failed = true
	} else {
		fmt.Printf("PASS: sync.Mutex protected map has %d entries from %d writers\n", len(m), numWriters)
	}

	// Test select with time.After timeout.
	start := time.Now()
	select {
	case <-time.After(100 * time.Millisecond):
		elapsed := time.Since(start)
		if elapsed < 100*time.Millisecond {
			fmt.Fprintf(os.Stderr, "FAIL: select timeout fired too early: %v\n", elapsed)
			failed = true
		} else {
			fmt.Printf("PASS: select with time.After(100ms) completed after %v\n", elapsed)
		}
	case <-time.After(5 * time.Second):
		fmt.Fprintln(os.Stderr, "FAIL: select timeout did not fire within 5s")
		failed = true
	}

	if failed {
		os.Exit(1)
	}
}
