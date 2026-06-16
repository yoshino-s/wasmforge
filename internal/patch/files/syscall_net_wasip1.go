// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// WasmForge replacement for syscall/net_wasip1.go
// Provides real socket operations via wasmforge host functions.

//go:build wasip1

package syscall

const (
	SHUT_RD   = 0x1
	SHUT_WR   = 0x2
	SHUT_RDWR = SHUT_RD | SHUT_WR
)

type sdflags = uint32

// WASI errno constants used by our host functions.
const (
	_ERRNO_SUCCESS     = 0
	_ERRNO_EAGAIN      = 6
	_ERRNO_EINPROGRESS = 26
)

// Socket option constants needed by the patched net package.
// These use standard Linux values which the host maps appropriately.
const (
	SOL_SOCKET   = 1
	SO_REUSEADDR = 2
	SO_KEEPALIVE = 9
	SO_RCVBUF    = 8
	SO_SNDBUF    = 7
)

// Address ABI constants.
const (
	_ADDR_SIZE_IPV4 = 8
	_ADDR_SIZE_IPV6 = 28
)

//go:wasmimport wasi_snapshot_preview1 sock_accept
//go:noescape
func sock_accept(fd int32, flags fdflags, newfd *int32) Errno

//go:wasmimport wasi_snapshot_preview1 sock_shutdown
//go:noescape
func sock_shutdown(fd int32, flags sdflags) Errno

// wasmforge host function imports for socket operations.

//go:wasmimport env fd_open
//go:noescape
func wasmforge_sock_open(domain, socktype, protocol int32, fd *int32) int32

//go:wasmimport env fd_bind
//go:noescape
func wasmforge_sock_bind(fd int32, addr *byte, addrLen int32) int32

//go:wasmimport env fd_listen
//go:noescape
func wasmforge_sock_listen(fd int32, backlog int32) int32

//go:wasmimport env fd_connect
//go:noescape
func wasmforge_sock_connect(fd int32, addr *byte, addrLen int32) int32

//go:wasmimport env fd_accept
//go:noescape
func wasmforge_sock_accept(fd int32, flags int32, newfd *int32, addr *byte, addrLen *int32) int32

//go:wasmimport env fd_read2
//go:noescape
func wasmforge_sock_read(fd int32, buf *byte, bufLen int32, nread *int32) int32

//go:wasmimport env fd_write2
//go:noescape
func wasmforge_sock_write(fd int32, buf *byte, bufLen int32, nwritten *int32) int32

//go:wasmimport env fd_close2
//go:noescape
func wasmforge_sock_close(fd int32) int32

//go:wasmimport env fd_sendto
//go:noescape
func wasmforge_sock_sendto(fd int32, buf *byte, bufLen int32, flags int32, addr *byte, addrLen int32, nsent *int32) int32

//go:wasmimport env fd_recvfrom
//go:noescape
func wasmforge_sock_recvfrom(fd int32, buf *byte, bufLen int32, flags int32, addr *byte, addrCap int32, addrLen *int32, nrecv *int32) int32

//go:wasmimport env fd_shutdown
//go:noescape
func wasmforge_sock_shutdown(fd int32, how int32) int32

//go:wasmimport env fd_setsockopt
//go:noescape
func wasmforge_sock_setsockopt(fd int32, level int32, opt int32, val *byte, valLen int32) int32

//go:wasmimport env fd_getsockopt
//go:noescape
func wasmforge_sock_getsockopt(fd int32, level int32, opt int32, val *byte, valLen *int32) int32

//go:wasmimport env fd_getpeername
//go:noescape
func wasmforge_sock_getpeername(fd int32, addr *byte, addrLen *int32) int32

//go:wasmimport env fd_getsockname
//go:noescape
func wasmforge_sock_getsockname(fd int32, addr *byte, addrLen *int32) int32

func Socket(proto, sotype, unused int) (fd int, err error) {
	var newfd int32
	errno := wasmforge_sock_open(int32(proto), int32(sotype), int32(unused), &newfd)
	if errno != 0 {
		return 0, Errno(errno)
	}
	return int(newfd), nil
}

func Bind(fd int, sa Sockaddr) error {
	buf := sockaddrToBytes(sa)
	if buf == nil {
		return EINVAL
	}
	errno := wasmforge_sock_bind(int32(fd), &buf[0], int32(len(buf)))
	if errno != 0 {
		return Errno(errno)
	}
	return nil
}

func StopIO(fd int) error {
	return ENOSYS
}

func Listen(fd int, backlog int) error {
	errno := wasmforge_sock_listen(int32(fd), int32(backlog))
	if errno != 0 {
		return Errno(errno)
	}
	return nil
}

func Accept(fd int) (int, Sockaddr, error) {
	// First try the wasmforge accept (for our sockets >= 10000).
	if fd >= 10000 {
		var newfd int32
		var addrBuf [_ADDR_SIZE_IPV6]byte
		var addrLen int32 = _ADDR_SIZE_IPV6
		errno := wasmforge_sock_accept(int32(fd), 0, &newfd, &addrBuf[0], &addrLen)
		if errno != 0 {
			return 0, nil, Errno(errno)
		}
		sa := bytesToSockaddr(addrBuf[:addrLen])
		return int(newfd), sa, nil
	}
	// Fall back to WASI accept for pre-opened sockets.
	var newfd int32
	errno := sock_accept(int32(fd), 0, &newfd)
	return int(newfd), nil, errnoErr(errno)
}

func Connect(fd int, sa Sockaddr) error {
	buf := sockaddrToBytes(sa)
	if buf == nil {
		return EINVAL
	}
	errno := wasmforge_sock_connect(int32(fd), &buf[0], int32(len(buf)))
	if errno != 0 {
		e := Errno(errno)
		// EINPROGRESS means the connect is in progress (non-blocking).
		if e == Errno(_ERRNO_EINPROGRESS) {
			return EINPROGRESS
		}
		return e
	}
	return nil
}

func Recvfrom(fd int, p []byte, flags int) (n int, from Sockaddr, err error) {
	if len(p) == 0 {
		return 0, nil, nil
	}
	var addrBuf [_ADDR_SIZE_IPV6]byte
	var addrLen int32 = _ADDR_SIZE_IPV6
	var nrecv int32
	errno := wasmforge_sock_recvfrom(int32(fd), &p[0], int32(len(p)), int32(flags), &addrBuf[0], _ADDR_SIZE_IPV6, &addrLen, &nrecv)
	if errno != 0 {
		return 0, nil, Errno(errno)
	}
	var sa Sockaddr
	if addrLen > 0 {
		sa = bytesToSockaddr(addrBuf[:addrLen])
	}
	return int(nrecv), sa, nil
}

func Sendto(fd int, p []byte, flags int, to Sockaddr) error {
	if len(p) == 0 {
		return nil
	}
	buf := sockaddrToBytes(to)
	if buf == nil {
		return EINVAL
	}
	var nsent int32
	errno := wasmforge_sock_sendto(int32(fd), &p[0], int32(len(p)), int32(flags), &buf[0], int32(len(buf)), &nsent)
	if errno != 0 {
		return Errno(errno)
	}
	return nil
}

func Recvmsg(fd int, p, oob []byte, flags int) (n, oobn, recvflags int, from Sockaddr, err error) {
	n, from, err = Recvfrom(fd, p, flags)
	return n, 0, 0, from, err
}

func SendmsgN(fd int, p, oob []byte, to Sockaddr, flags int) (n int, err error) {
	err = Sendto(fd, p, flags, to)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func GetsockoptInt(fd, level, opt int) (value int, err error) {
	var buf [4]byte
	var valLen int32 = 4
	errno := wasmforge_sock_getsockopt(int32(fd), int32(level), int32(opt), &buf[0], &valLen)
	if errno != 0 {
		return 0, Errno(errno)
	}
	return int(uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24), nil
}

func SetsockoptInt(fd, level, opt int, value int) error {
	buf := [4]byte{
		byte(value),
		byte(value >> 8),
		byte(value >> 16),
		byte(value >> 24),
	}
	errno := wasmforge_sock_setsockopt(int32(fd), int32(level), int32(opt), &buf[0], 4)
	if errno != 0 {
		return Errno(errno)
	}
	return nil
}

func SetReadDeadline(fd int, t int64) error {
	return ENOSYS
}

func SetWriteDeadline(fd int, t int64) error {
	return ENOSYS
}

func Shutdown(fd int, how int) error {
	if fd >= 10000 {
		errno := wasmforge_sock_shutdown(int32(fd), int32(how))
		if errno != 0 {
			return Errno(errno)
		}
		return nil
	}
	errno := sock_shutdown(int32(fd), sdflags(how))
	return errnoErr(errno)
}

// WasmForgeRead performs a non-blocking read on a wasmforge socket.
// Returns (n, errno). Errno is _ERRNO_EAGAIN if no data available.
func WasmForgeRead(fd int32, p []byte) (int, int32) {
	if len(p) == 0 {
		return 0, 0
	}
	var nread int32
	errno := wasmforge_sock_read(fd, &p[0], int32(len(p)), &nread)
	return int(nread), errno
}

// WasmForgeWrite performs a non-blocking write on a wasmforge socket.
// Returns (n, errno). Errno is _ERRNO_EAGAIN if buffer full.
func WasmForgeWrite(fd int32, p []byte) (int, int32) {
	if len(p) == 0 {
		return 0, 0
	}
	var nwritten int32
	errno := wasmforge_sock_write(fd, &p[0], int32(len(p)), &nwritten)
	return int(nwritten), errno
}

// WasmForgeClose closes a wasmforge socket.
func WasmForgeClose(fd int32) error {
	errno := wasmforge_sock_close(fd)
	if errno != 0 {
		return Errno(errno)
	}
	return nil
}

// WasmForgeGetpeername returns the peer address for a wasmforge socket.
func WasmForgeGetpeername(fd int32) Sockaddr {
	var addrBuf [_ADDR_SIZE_IPV6]byte
	var addrLen int32 = _ADDR_SIZE_IPV6
	errno := wasmforge_sock_getpeername(fd, &addrBuf[0], &addrLen)
	if errno != 0 {
		return nil
	}
	return bytesToSockaddr(addrBuf[:addrLen])
}

// WasmForgeGetsockname returns the local address for a wasmforge socket.
func WasmForgeGetsockname(fd int32) Sockaddr {
	var addrBuf [_ADDR_SIZE_IPV6]byte
	var addrLen int32 = _ADDR_SIZE_IPV6
	errno := wasmforge_sock_getsockname(fd, &addrBuf[0], &addrLen)
	if errno != 0 {
		return nil
	}
	return bytesToSockaddr(addrBuf[:addrLen])
}

// Address serialization helpers.

func sockaddrToBytes(sa Sockaddr) []byte {
	switch sa := sa.(type) {
	case *SockaddrInet4:
		buf := make([]byte, _ADDR_SIZE_IPV4)
		buf[0] = 2 // AF_INET, little-endian u16
		buf[1] = 0
		buf[2] = byte(sa.Port >> 8) // port big-endian
		buf[3] = byte(sa.Port)
		copy(buf[4:8], sa.Addr[:])
		return buf
	case *SockaddrInet6:
		buf := make([]byte, _ADDR_SIZE_IPV6)
		buf[0] = 10 // AF_INET6, little-endian u16
		buf[1] = 0
		buf[2] = byte(sa.Port >> 8) // port big-endian
		buf[3] = byte(sa.Port)
		// flowinfo at [4:8] = 0
		copy(buf[8:24], sa.Addr[:])
		buf[24] = byte(sa.ZoneId)
		buf[25] = byte(sa.ZoneId >> 8)
		buf[26] = byte(sa.ZoneId >> 16)
		buf[27] = byte(sa.ZoneId >> 24)
		return buf
	default:
		return nil
	}
}

func bytesToSockaddr(buf []byte) Sockaddr {
	if len(buf) < 2 {
		return nil
	}
	family := uint16(buf[0]) | uint16(buf[1])<<8

	switch family {
	case 2: // AF_INET
		if len(buf) < _ADDR_SIZE_IPV4 {
			return nil
		}
		sa := &SockaddrInet4{
			Port: int(buf[2])<<8 | int(buf[3]),
		}
		copy(sa.Addr[:], buf[4:8])
		return sa
	case 10: // AF_INET6
		if len(buf) < _ADDR_SIZE_IPV6 {
			return nil
		}
		sa := &SockaddrInet6{
			Port: int(buf[2])<<8 | int(buf[3]),
		}
		copy(sa.Addr[:], buf[8:24])
		sa.ZoneId = uint32(buf[24]) | uint32(buf[25])<<8 | uint32(buf[26])<<16 | uint32(buf[27])<<24
		return sa
	default:
		return nil
	}
}
