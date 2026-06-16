package main

import (
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	target := "127.0.0.1"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}

	// Start 10 listeners
	var listeners []net.Listener
	for i := 0; i < 10; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Listen failed: %v\n", err)
			os.Exit(1)
		}
		listeners = append(listeners, ln)
		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}(ln)
	}
	defer func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}()

	// Scan all listener ports concurrently
	var wg sync.WaitGroup
	var open atomic.Int32

	for _, ln := range listeners {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err == nil {
				conn.Close()
				open.Add(1)
			}
		}(ln.Addr().String())
	}

	wg.Wait()

	openCount := open.Load()
	fmt.Printf("Scanned %d ports, %d open\n", len(listeners), openCount)

	if openCount == int32(len(listeners)) {
		fmt.Println("PASS: All concurrent connections successful")
	} else {
		fmt.Fprintf(os.Stderr, "FAIL: expected %d open, got %d\n", len(listeners), openCount)
		os.Exit(1)
	}

	_ = target
}
