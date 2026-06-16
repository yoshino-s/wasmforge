package hostmod

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

// Address ABI (Guest-Host Wire Format):
// IPv4 (8 bytes):  [family:u16 LE] [port:u16 BE] [addr:4 bytes]
// IPv6 (28 bytes): [family:u16 LE] [port:u16 BE] [flowinfo:u32] [addr:16 bytes] [scope:u32]

const (
	addrFamilyIPv4 = 2
	addrFamilyIPv6 = 10
	addrSizeIPv4   = 8
	addrSizeIPv6   = 28
)

// bytesToSockaddr deserializes a wire-format address from WASM memory
// into a Go syscall.Sockaddr.
func bytesToSockaddr(buf []byte) (syscall.Sockaddr, error) {
	if len(buf) < 2 {
		return nil, fmt.Errorf("address too short: %d bytes", len(buf))
	}
	family := binary.LittleEndian.Uint16(buf[0:2])

	switch family {
	case addrFamilyIPv4:
		if len(buf) < addrSizeIPv4 {
			return nil, fmt.Errorf("IPv4 address too short: %d bytes", len(buf))
		}
		sa := &syscall.SockaddrInet4{
			Port: int(binary.BigEndian.Uint16(buf[2:4])),
		}
		copy(sa.Addr[:], buf[4:8])
		return sa, nil

	case addrFamilyIPv6:
		if len(buf) < addrSizeIPv6 {
			return nil, fmt.Errorf("IPv6 address too short: %d bytes", len(buf))
		}
		sa := &syscall.SockaddrInet6{
			Port: int(binary.BigEndian.Uint16(buf[2:4])),
		}
		// flowinfo at buf[4:8] — not commonly used, skip.
		copy(sa.Addr[:], buf[8:24])
		sa.ZoneId = binary.LittleEndian.Uint32(buf[24:28])
		return sa, nil

	default:
		return nil, fmt.Errorf("unsupported address family: %d", family)
	}
}

// sockaddrToBytes serializes a syscall.Sockaddr into wire-format bytes.
func sockaddrToBytes(sa syscall.Sockaddr) ([]byte, error) {
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		buf := make([]byte, addrSizeIPv4)
		binary.LittleEndian.PutUint16(buf[0:2], addrFamilyIPv4)
		binary.BigEndian.PutUint16(buf[2:4], uint16(sa.Port))
		copy(buf[4:8], sa.Addr[:])
		return buf, nil

	case *syscall.SockaddrInet6:
		buf := make([]byte, addrSizeIPv6)
		binary.LittleEndian.PutUint16(buf[0:2], addrFamilyIPv6)
		binary.BigEndian.PutUint16(buf[2:4], uint16(sa.Port))
		// flowinfo at buf[4:8] = 0
		copy(buf[8:24], sa.Addr[:])
		binary.LittleEndian.PutUint32(buf[24:28], sa.ZoneId)
		return buf, nil

	default:
		return nil, fmt.Errorf("unsupported sockaddr type: %T", sa)
	}
}

// sockaddrToNetAddr converts a syscall.Sockaddr to a net.Addr.
func sockaddrToNetAddr(sa syscall.Sockaddr, sockType int) net.Addr {
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		ip := net.IP(sa.Addr[:])
		if sockType == syscall.SOCK_DGRAM {
			return &net.UDPAddr{IP: ip, Port: sa.Port}
		}
		return &net.TCPAddr{IP: ip, Port: sa.Port}
	case *syscall.SockaddrInet6:
		ip := net.IP(sa.Addr[:])
		if sockType == syscall.SOCK_DGRAM {
			return &net.UDPAddr{IP: ip, Port: sa.Port}
		}
		return &net.TCPAddr{IP: ip, Port: sa.Port}
	default:
		return nil
	}
}
