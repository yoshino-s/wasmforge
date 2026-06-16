//go:build windows

package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// synthResolvConf creates a temporary directory containing a synthetic
// resolv.conf with the system's DNS server addresses. On Windows, Go's
// pure-Go DNS resolver reads /etc/resolv.conf which doesn't exist natively.
// This function queries Windows adapter info to discover DNS servers and
// creates a temporary /etc directory the WASM guest can read.
//
// Returns the temp dir path and a cleanup function, or ("", nil) on failure.
func synthResolvConf() (tmpDir string, cleanup func()) {
	servers := getWindowsDNSServers()
	if len(servers) == 0 {
		// Fallback to well-known public DNS servers.
		servers = []string{"8.8.8.8", "8.8.4.4"}
	}

	dir, err := os.MkdirTemp("", "wasmforge-etc-")
	if err != nil {
		return "", nil
	}

	var content string
	for _, s := range servers {
		content += "nameserver " + s + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "resolv.conf"), []byte(content), 0o644); err != nil {
		os.RemoveAll(dir)
		return "", nil
	}

	return dir, func() { os.RemoveAll(dir) }
}

// getWindowsDNSServers queries the Windows network adapter configuration
// to find DNS server addresses. Prefers IPv4 addresses for maximum
// compatibility; IPv6 addresses are only used if no IPv4 servers are found.
func getWindowsDNSServers() []string {
	// GetAdaptersAddresses returns linked list of adapter info.
	var size uint32
	// First call to get buffer size.
	err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX, 0, nil, &size)
	if err != windows.ERROR_BUFFER_OVERFLOW {
		return nil
	}

	buf := make([]byte, size)
	addr := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	err = windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX, 0, addr, &size)
	if err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var ipv4Servers, ipv6Servers []string

	for ; addr != nil; addr = addr.Next {
		// Skip adapters that are not up.
		if addr.OperStatus != windows.IfOperStatusUp {
			continue
		}

		for dns := addr.FirstDnsServerAddress; dns != nil; dns = dns.Next {
			ip := sockaddrToIP(&dns.Address)
			if ip == "" || seen[ip] {
				continue
			}
			seen[ip] = true
			if strings.Contains(ip, ":") {
				ipv6Servers = append(ipv6Servers, ip)
			} else {
				ipv4Servers = append(ipv4Servers, ip)
			}
		}
	}

	// Prefer IPv4 DNS servers for compatibility. IPv6 socket creation
	// in WASM guests can fail on some Windows configurations, and
	// Hyper-V virtual DNS addresses (fec0::) are unreliable.
	if len(ipv4Servers) > 0 {
		return ipv4Servers
	}
	return ipv6Servers
}

// sockaddrToIP extracts an IP string from a windows.SocketAddress.
func sockaddrToIP(sa *windows.SocketAddress) string {
	if sa.Sockaddr == nil || sa.SockaddrLength == 0 {
		return ""
	}
	raw := sa.Sockaddr // *syscall.RawSockaddrAny
	switch raw.Addr.Family {
	case syscall.AF_INET:
		addr := (*syscall.RawSockaddrInet4)(unsafe.Pointer(raw))
		return fmt.Sprintf("%d.%d.%d.%d",
			addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	case syscall.AF_INET6:
		addr := (*syscall.RawSockaddrInet6)(unsafe.Pointer(raw))
		// Skip link-local IPv6 for DNS (fe80::)
		if addr.Addr[0] == 0xfe && addr.Addr[1] == 0x80 {
			return ""
		}
		ip := fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
			uint16(addr.Addr[0])<<8|uint16(addr.Addr[1]),
			uint16(addr.Addr[2])<<8|uint16(addr.Addr[3]),
			uint16(addr.Addr[4])<<8|uint16(addr.Addr[5]),
			uint16(addr.Addr[6])<<8|uint16(addr.Addr[7]),
			uint16(addr.Addr[8])<<8|uint16(addr.Addr[9]),
			uint16(addr.Addr[10])<<8|uint16(addr.Addr[11]),
			uint16(addr.Addr[12])<<8|uint16(addr.Addr[13]),
			uint16(addr.Addr[14])<<8|uint16(addr.Addr[15]))
		return ip
	}
	return ""
}
