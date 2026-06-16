package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	host := "example.com"
	if len(os.Args) > 1 {
		host = os.Args[1]
	}

	fmt.Printf("Looking up %s...\n", host)

	addrs, err := net.LookupHost(host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DNS lookup failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Resolved %d addresses:\n", len(addrs))
	for _, addr := range addrs {
		fmt.Printf("  %s\n", addr)
	}

	if len(addrs) > 0 {
		fmt.Println("PASS: DNS lookup successful")
	} else {
		fmt.Fprintln(os.Stderr, "FAIL: no addresses resolved")
		os.Exit(1)
	}
}
