// Baseline control: TCP client. Exercises net.Dial, raw TCP I/O.
// Build: GOOS=windows GOARCH=amd64 go build -trimpath -o tcp_client.exe .
package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	conn, err := net.DialTimeout("tcp", "example.com:80", 5*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	fmt.Printf("Received %d bytes\n", n)
}
