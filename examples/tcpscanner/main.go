package main

import (
	"flag"
	"fmt"
	"net"
	"sync"
	"time"
)

func main() {
	target := flag.String("target", "scanme.nmap.org", "Target host")
	ports := flag.String("ports", "22,80,443", "Comma-separated ports")
	timeout := flag.Duration("timeout", 2*time.Second, "Connection timeout")
	flag.Parse()

	portList := parsePorts(*ports)
	fmt.Printf("Scanning %s (%d ports)...\n", *target, len(portList))

	var wg sync.WaitGroup
	results := make(chan string, len(portList))

	for _, port := range portList {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			addr := net.JoinHostPort(*target, fmt.Sprint(p))
			conn, err := net.DialTimeout("tcp", addr, *timeout)
			if err != nil {
				results <- fmt.Sprintf("  %d/tcp closed", p)
				return
			}
			conn.Close()
			results <- fmt.Sprintf("  %d/tcp open", p)
		}(port)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		fmt.Println(r)
	}
	fmt.Println("Scan complete.")
}

func parsePorts(s string) []int {
	var ports []int
	current := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			if current > 0 {
				ports = append(ports, current)
			}
			current = 0
		} else if s[i] >= '0' && s[i] <= '9' {
			current = current*10 + int(s[i]-'0')
		}
	}
	if current > 0 {
		ports = append(ports, current)
	}
	return ports
}
