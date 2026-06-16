//go:build wasip1

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/praetorian-inc/wasmforge/guest/rawnet"
)

func main() {
	target := "8.8.8.8"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}

	ip := parseIPv4(target)
	if ip == [4]byte{} {
		fmt.Fprintf(os.Stderr, "Invalid IPv4 address: %s\n", target)
		os.Exit(1)
	}

	conn, err := rawnet.Open(rawnet.AF_INET, rawnet.IPPROTO_ICMP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open raw socket: %v\n", err)
		fmt.Fprintf(os.Stderr, "Hint: use --raw-sockets flag and run with appropriate privileges\n")
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("PING %s\n", target)

	for seq := 0; seq < 4; seq++ {
		pkt := makeICMPEchoRequest(uint16(os.Getpid()&0xffff), uint16(seq))
		start := time.Now()

		_, err := conn.SendTo(pkt, &rawnet.Addr4{IP: ip})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Send failed: %v\n", err)
			continue
		}

		buf := make([]byte, 1500)
		n, _, err := conn.RecvFrom(buf)
		elapsed := time.Since(start)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Recv failed: %v\n", err)
			continue
		}

		fmt.Printf("%d bytes from %s: seq=%d time=%v\n", n, target, seq, elapsed.Round(time.Microsecond))
		time.Sleep(time.Second)
	}
}

func parseIPv4(s string) [4]byte {
	var ip [4]byte
	part := 0
	idx := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if idx > 3 {
				return [4]byte{}
			}
			ip[idx] = byte(part)
			idx++
			part = 0
		} else if s[i] >= '0' && s[i] <= '9' {
			part = part*10 + int(s[i]-'0')
			if part > 255 {
				return [4]byte{}
			}
		} else {
			return [4]byte{}
		}
	}
	if idx != 4 {
		return [4]byte{}
	}
	return ip
}

func makeICMPEchoRequest(id, seq uint16) []byte {
	pkt := make([]byte, 8)
	pkt[0] = 8 // Echo Request
	pkt[1] = 0 // Code
	// Checksum at [2:4], filled below
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], seq)

	// Compute checksum.
	var sum uint32
	for i := 0; i < len(pkt); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	binary.BigEndian.PutUint16(pkt[2:4], ^uint16(sum))

	return pkt
}
