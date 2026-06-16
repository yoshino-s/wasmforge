package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	// Start echo server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Listen failed: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()
	fmt.Printf("Echo server on %s\n", ln.Addr())

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	// Client test
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Dial failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	msg := "hello wasmforge"
	_, err = conn.Write([]byte(msg))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Write failed: %v\n", err)
		os.Exit(1)
	}

	buf := make([]byte, len(msg))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read failed: %v\n", err)
		os.Exit(1)
	}

	if string(buf) == msg {
		fmt.Println("PASS: TCP echo round-trip successful")
	} else {
		fmt.Fprintf(os.Stderr, "FAIL: expected %q, got %q\n", msg, string(buf))
		os.Exit(1)
	}
}
