package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	// Start UDP echo server
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ListenPacket failed: %v\n", err)
		os.Exit(1)
	}
	defer pc.Close()
	fmt.Printf("UDP echo server on %s\n", pc.LocalAddr())

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], addr)
		}
	}()

	// Client test
	conn, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Dial failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	msg := "hello udp wasmforge"
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.Write([]byte(msg))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Write failed: %v\n", err)
		os.Exit(1)
	}

	buf := make([]byte, len(msg))
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read failed: %v\n", err)
		os.Exit(1)
	}

	if string(buf[:n]) == msg {
		fmt.Println("PASS: UDP echo round-trip successful")
	} else {
		fmt.Fprintf(os.Stderr, "FAIL: expected %q, got %q\n", msg, string(buf[:n]))
		os.Exit(1)
	}
}
