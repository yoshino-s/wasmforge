// Tests that blocking Win32 APIs don't freeze other goroutines.
// Spawns a goroutine that calls Sleep(2000) via SyscallN, while the main
// goroutine prints periodic ticks. If ticks continue during Sleep, the
// cooperative yield protocol is working.
//
// Uses SyscallN (not Call) because the yield protocol is in the
// win32SyscallN host path, which is the path golang.org/x/sys/windows uses.
package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/praetorian-inc/wasmforge/guest/win32"
)

func main() {
	if !win32.Available() {
		fmt.Println("SKIP: Win32 APIs not available")
		return
	}

	lib, err := win32.LoadLibrary("kernel32.dll")
	if err != nil {
		fmt.Printf("FAIL: LoadLibrary(kernel32.dll): %v\n", err)
		os.Exit(1)
	}
	defer lib.Free()

	sleepProc, err := lib.GetProcAddress("Sleep")
	if err != nil {
		fmt.Printf("FAIL: GetProcAddress(Sleep): %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Cooperative Yield Test ===")

	// Test 1: Sleep(2000) in background, ticks in foreground.
	// Uses SyscallN (the path with yield protocol), not Call.
	fmt.Println("\nTest 1: Sleep(2000ms) via SyscallN with concurrent ticks")
	var wg sync.WaitGroup
	sleepDone := make(chan time.Duration, 1)
	tickCount := 0
	tickStop := make(chan struct{})

	// Background: blocking Sleep via SyscallN.
	wg.Add(1)
	go func() {
		defer wg.Done()
		start := time.Now()
		fmt.Printf("  [sleep] calling SyscallN(Sleep, 2000)...\n")
		win32.SyscallN(sleepProc, 2000) // Sleep(2000ms)
		elapsed := time.Since(start)
		fmt.Printf("  [sleep] returned after %v\n", elapsed)
		sleepDone <- elapsed
	}()

	// Foreground: tick every 200ms.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				tickCount++
				fmt.Printf("  [tick] #%d at %v\n", tickCount, time.Now().Format("15:04:05.000"))
			case <-tickStop:
				return
			}
		}
	}()

	// Wait for sleep to complete.
	elapsed := <-sleepDone
	close(tickStop)
	wg.Wait()

	if elapsed < 1500*time.Millisecond {
		fmt.Printf("FAIL: Sleep returned too early (%v < 1500ms)\n", elapsed)
		os.Exit(1)
	}
	if elapsed > 10*time.Second {
		fmt.Printf("FAIL: Sleep took too long (%v > 10s)\n", elapsed)
		os.Exit(1)
	}
	fmt.Printf("PASS: Sleep(2000) took %v\n", elapsed)

	if tickCount < 3 {
		fmt.Printf("FAIL: only %d ticks during Sleep (expected >= 3, yield not working)\n", tickCount)
		os.Exit(1)
	}
	fmt.Printf("PASS: %d ticks fired during Sleep (cooperative yield working)\n", tickCount)

	// Test 2: WaitForSingleObject with a manual-reset event.
	fmt.Println("\nTest 2: WaitForSingleObject with event signaled after 1s")
	createEventProc, err := lib.GetProcAddress("CreateEventW")
	if err != nil {
		fmt.Printf("SKIP: CreateEventW not available: %v\n", err)
	} else {
		setEventProc, _ := lib.GetProcAddress("SetEvent")
		waitProc, _ := lib.GetProcAddress("WaitForSingleObject")
		closeHandleProc, _ := lib.GetProcAddress("CloseHandle")

		// CreateEventW(nil, TRUE, FALSE, nil) — manual reset, initially non-signaled.
		eventHandle, _, lastErr := win32.SyscallN(createEventProc, 0, 1, 0, 0)
		if eventHandle == 0 {
			fmt.Printf("FAIL: CreateEventW failed: lastErr=%d\n", lastErr)
			os.Exit(1)
		}
		defer win32.SyscallN(closeHandleProc, eventHandle)

		waitDone := make(chan time.Duration, 1)
		tickCount2 := 0
		tickStop2 := make(chan struct{})

		// Background: wait for event.
		go func() {
			start := time.Now()
			fmt.Printf("  [wait] calling WaitForSingleObject(event, 5000)...\n")
			r1, _, _ := win32.SyscallN(waitProc, eventHandle, 5000)
			elapsed := time.Since(start)
			fmt.Printf("  [wait] returned %d after %v\n", r1, elapsed)
			waitDone <- elapsed
		}()

		// Foreground: ticks.
		go func() {
			ticker := time.NewTicker(200 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					tickCount2++
					fmt.Printf("  [tick2] #%d\n", tickCount2)
				case <-tickStop2:
					return
				}
			}
		}()

		// Signal the event after 1 second.
		time.Sleep(1 * time.Second)
		fmt.Println("  [main] signaling event")
		win32.SyscallN(setEventProc, eventHandle)

		elapsed2 := <-waitDone
		close(tickStop2)

		if elapsed2 < 800*time.Millisecond || elapsed2 > 5*time.Second {
			fmt.Printf("FAIL: WaitForSingleObject took %v (expected ~1s)\n", elapsed2)
			os.Exit(1)
		}
		fmt.Printf("PASS: WaitForSingleObject took %v\n", elapsed2)

		if tickCount2 < 2 {
			fmt.Printf("FAIL: only %d ticks during wait (expected >= 2)\n", tickCount2)
			os.Exit(1)
		}
		fmt.Printf("PASS: %d ticks during WaitForSingleObject\n", tickCount2)
	}

	fmt.Println("\n=== All cooperative yield tests passed ===")
}
