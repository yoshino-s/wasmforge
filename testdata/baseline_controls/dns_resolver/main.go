// Baseline control: DNS resolver. Exercises net.LookupHost.
// Build: GOOS=windows GOARCH=amd64 go build -trimpath -o dns_resolver.exe .
package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: resolve <hostname>")
		os.Exit(1)
	}
	addrs, err := net.LookupHost(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, addr := range addrs {
		fmt.Println(addr)
	}
}
