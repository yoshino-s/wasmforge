//go:build wasip1

package rawnet

import (
	"errors"
	"fmt"
	"runtime"
)

const (
	AF_INET  = 2
	AF_INET6 = 10

	IPPROTO_ICMP   = 1
	IPPROTO_ICMPv6 = 58
	IPPROTO_RAW    = 255
)

// Addr4 is an IPv4 raw socket address.
type Addr4 struct {
	IP [4]byte
}

// Addr6 is an IPv6 raw socket address.
type Addr6 struct {
	IP     [16]byte
	ZoneID uint32
}

// RawConn is a raw socket connection.
type RawConn struct {
	fd     int32
	family int32
	closed bool
}

// Open creates a new raw socket.
// family: AF_INET or AF_INET6
// protocol: IPPROTO_ICMP, IPPROTO_ICMPv6, etc.
func Open(family, protocol int) (*RawConn, error) {
	var fd int32
	errno := raw_sock_open(int32(family), int32(protocol), &fd)
	if errno != 0 {
		return nil, fmt.Errorf("rawnet: open failed with errno %d", errno)
	}
	return &RawConn{fd: fd, family: int32(family)}, nil
}

// SendTo sends raw data to the specified address.
func (c *RawConn) SendTo(buf []byte, addr interface{}) (int, error) {
	if c.closed {
		return 0, errors.New("rawnet: connection closed")
	}
	if len(buf) == 0 {
		return 0, nil
	}

	addrBytes := marshalAddr(c.family, addr)
	if addrBytes == nil {
		return 0, errors.New("rawnet: invalid address")
	}

	var nsent int32
	for {
		errno := raw_sock_send(c.fd, &buf[0], int32(len(buf)), 0, &addrBytes[0], int32(len(addrBytes)), &nsent)
		if errno == 0 {
			return int(nsent), nil
		}
		if errno == 6 { // EAGAIN
			runtime.Gosched()
			continue
		}
		return 0, fmt.Errorf("rawnet: send failed with errno %d", errno)
	}
}

// RecvFrom receives raw data and returns the sender address.
func (c *RawConn) RecvFrom(buf []byte) (int, interface{}, error) {
	if c.closed {
		return 0, nil, errors.New("rawnet: connection closed")
	}
	if len(buf) == 0 {
		return 0, nil, nil
	}

	var addrBuf [28]byte // max size for IPv6
	var addrLen int32 = int32(len(addrBuf))
	var nrecv int32

	for {
		errno := raw_sock_recv(c.fd, &buf[0], int32(len(buf)), 0, &addrBuf[0], int32(len(addrBuf)), &addrLen, &nrecv)
		if errno == 0 {
			addr := unmarshalAddr(addrBuf[:addrLen])
			return int(nrecv), addr, nil
		}
		if errno == 6 { // EAGAIN
			runtime.Gosched()
			continue
		}
		return 0, nil, fmt.Errorf("rawnet: recv failed with errno %d", errno)
	}
}

// Close closes the raw socket.
func (c *RawConn) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	errno := raw_sock_close(c.fd)
	if errno != 0 {
		return fmt.Errorf("rawnet: close failed with errno %d", errno)
	}
	return nil
}

func marshalAddr(family int32, addr interface{}) []byte {
	switch family {
	case AF_INET:
		a, ok := addr.(*Addr4)
		if !ok {
			return nil
		}
		buf := make([]byte, 8)
		buf[0] = 2 // AF_INET LE
		buf[1] = 0
		buf[2] = 0 // port = 0 for raw
		buf[3] = 0
		copy(buf[4:8], a.IP[:])
		return buf
	case AF_INET6:
		a, ok := addr.(*Addr6)
		if !ok {
			return nil
		}
		buf := make([]byte, 28)
		buf[0] = 10 // AF_INET6 LE
		buf[1] = 0
		// port = 0
		copy(buf[8:24], a.IP[:])
		buf[24] = byte(a.ZoneID)
		buf[25] = byte(a.ZoneID >> 8)
		buf[26] = byte(a.ZoneID >> 16)
		buf[27] = byte(a.ZoneID >> 24)
		return buf
	}
	return nil
}

func unmarshalAddr(buf []byte) interface{} {
	if len(buf) < 2 {
		return nil
	}
	family := uint16(buf[0]) | uint16(buf[1])<<8
	switch family {
	case 2:
		if len(buf) < 8 {
			return nil
		}
		a := &Addr4{}
		copy(a.IP[:], buf[4:8])
		return a
	case 10:
		if len(buf) < 28 {
			return nil
		}
		a := &Addr6{}
		copy(a.IP[:], buf[8:24])
		a.ZoneID = uint32(buf[24]) | uint32(buf[25])<<8 | uint32(buf[26])<<16 | uint32(buf[27])<<24
		return a
	}
	return nil
}
