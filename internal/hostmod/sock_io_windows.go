//go:build windows

package hostmod

import (
	"syscall"
	"unsafe"
)

// Winsock error codes — raw values from WSAGetLastError().
// Go's syscall.EAGAIN etc. on Windows are synthetic (0x20000000+offset)
// and don't match raw Winsock errors. We map raw errors to Go's synthetic
// errnos so comparisons like err == syscall.EAGAIN work correctly.
const (
	wsaeInval         = 10022
	wsaeWouldBlock    = 10035
	wsaeInProgress    = 10036
	wsaeAlready       = 10037
	wsaeNotSock       = 10038
	wsaeMsgSize       = 10040
	wsaeAfNoSupport   = 10047
	wsaeAddrInUse     = 10048
	wsaeAddrNotAvail  = 10049
	wsaeNetUnreach    = 10051
	wsaeConnAborted   = 10053
	wsaeConnReset     = 10054
	wsaeNotConn       = 10057
	wsaeTimedOut      = 10060
	wsaeConnRefused   = 10061
)

// winsockErrno converts a raw Windows error code to a Go syscall.Errno.
func winsockErrno(e syscall.Errno) error {
	if e == 0 {
		return nil
	}
	switch uintptr(e) {
	case wsaeWouldBlock:
		return syscall.EWOULDBLOCK
	case wsaeInProgress:
		return syscall.EINPROGRESS
	case wsaeAlready:
		return syscall.EALREADY
	case wsaeConnAborted:
		return syscall.ECONNABORTED
	case wsaeConnReset:
		return syscall.ECONNRESET
	case wsaeNotConn:
		return syscall.ENOTCONN
	case wsaeTimedOut:
		return syscall.ETIMEDOUT
	case wsaeConnRefused:
		return syscall.ECONNREFUSED
	default:
		return e
	}
}

// FIONBIO is the ioctl command to set non-blocking mode on a Winsock socket.
const fionbio = 0x8004667E

var (
	modws2_32       = syscall.NewLazyDLL("ws2_32.dll")
	procSendto      = modws2_32.NewProc("sendto")
	procRecvfromRaw = modws2_32.NewProc("recvfrom")
	procIoctlsocket = modws2_32.NewProc("ioctlsocket")
	procAccept      = modws2_32.NewProc("accept")
	procSelect      = modws2_32.NewProc("select")
)

// setSocketNonblock sets a Winsock socket to non-blocking mode using ioctlsocket.
// syscall.SetNonblock on Windows does NOT work for Winsock handles — it only affects
// file handles via SetFileInformationByHandle. Sockets require ioctlsocket(FIONBIO).
func setSocketNonblock(fd osFDType) error {
	var mode uint32 = 1
	r1, _, e1 := syscall.SyscallN(
		procIoctlsocket.Addr(),
		uintptr(fd),
		uintptr(fionbio),
		uintptr(unsafe.Pointer(&mode)),
	)
	if int32(r1) == -1 { // SOCKET_ERROR
		return winsockErrno(e1)
	}
	return nil
}

// socketRecv reads from a socket using WSARecv.
// syscall.Read on Windows calls ReadFile which does not work on Winsock handles.
func socketRecv(fd osFDType, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var recvd uint32
	var flags uint32
	wsaBuf := syscall.WSABuf{
		Len: uint32(len(buf)),
		Buf: &buf[0],
	}
	err := syscall.WSARecv(fd, &wsaBuf, 1, &recvd, &flags, nil, nil)
	if err != nil {
		return int(recvd), err
	}
	return int(recvd), nil
}

// socketSend writes to a socket using WSASend.
// syscall.Write on Windows calls WriteFile which does not work on Winsock handles.
func socketSend(fd osFDType, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var sent uint32
	wsaBuf := syscall.WSABuf{
		Len: uint32(len(buf)),
		Buf: &buf[0],
	}
	err := syscall.WSASend(fd, &wsaBuf, 1, &sent, 0, nil, nil)
	if err != nil {
		return int(sent), err
	}
	return int(sent), nil
}

// socketSendTo sends data to a specific address using ws2_32.sendto directly.
// Go's syscall.Sendto on Windows returns EWINDOWS ("not supported by windows").
func socketSendTo(fd osFDType, buf []byte, flags int, sa syscall.Sockaddr) error {
	rawSA, rawLen, err := sockaddrToRaw(sa)
	if err != nil {
		return err
	}
	var bufPtr unsafe.Pointer
	if len(buf) > 0 {
		bufPtr = unsafe.Pointer(&buf[0])
	}
	r1, _, e1 := syscall.SyscallN(
		procSendto.Addr(),
		uintptr(fd),
		uintptr(bufPtr),
		uintptr(len(buf)),
		uintptr(flags),
		uintptr(rawSA),
		uintptr(rawLen),
	)
	if int32(r1) == -1 { // SOCKET_ERROR
		return winsockErrno(e1)
	}
	return nil
}

// socketRecvFrom receives data and returns the sender's address using
// ws2_32.recvfrom directly. Go's syscall.Recvfrom on Windows returns
// EWINDOWS ("not supported by windows").
func socketRecvFrom(fd osFDType, buf []byte, flags int) (int, syscall.Sockaddr, error) {
	var rsa syscall.RawSockaddrAny
	rsaLen := int32(unsafe.Sizeof(rsa))

	var bufPtr unsafe.Pointer
	if len(buf) > 0 {
		bufPtr = unsafe.Pointer(&buf[0])
	}
	r1, _, e1 := syscall.SyscallN(
		procRecvfromRaw.Addr(),
		uintptr(fd),
		uintptr(bufPtr),
		uintptr(len(buf)),
		uintptr(flags),
		uintptr(unsafe.Pointer(&rsa)),
		uintptr(unsafe.Pointer(&rsaLen)),
	)
	n := int32(r1)
	if n == -1 { // SOCKET_ERROR
		return 0, nil, winsockErrno(e1)
	}
	sa, _ := rsa.Sockaddr()
	return int(n), sa, nil
}

// socketAccept accepts a connection on a listening socket.
// Go's syscall.Accept on Windows returns EWINDOWS ("not supported by windows"),
// so we call ws2_32.dll's accept() directly.
func socketAccept(fd osFDType) (osFDType, syscall.Sockaddr, error) {
	var rsa syscall.RawSockaddrAny
	rsaLen := int32(unsafe.Sizeof(rsa))

	r1, _, e1 := syscall.SyscallN(
		procAccept.Addr(),
		uintptr(fd),
		uintptr(unsafe.Pointer(&rsa)),
		uintptr(unsafe.Pointer(&rsaLen)),
	)

	newFD := syscall.Handle(r1)
	if newFD == syscall.InvalidHandle {
		return 0, nil, winsockErrno(e1)
	}
	sa, _ := rsa.Sockaddr()
	return newFD, sa, nil
}

// socketClose closes a Winsock socket. On Windows, syscall.Close calls CloseHandle
// which is not the correct way to close a socket; closesocket must be used.
func socketClose(fd osFDType) error {
	return syscall.Closesocket(fd)
}

// waitConnectComplete waits for a non-blocking connect to actually complete.
// On Windows, getsockopt(SO_ERROR) returns 0 while the TCP handshake is still
// in progress, so the guest-side polling loop (which checks SO_ERROR==0 to mean
// "connected") breaks out too early. This function uses Winsock select() to
// reliably wait for write-readiness, which indicates true connect completion.
func waitConnectComplete(fd osFDType) error {
	// Winsock fd_set: count + socket array. We only need 1 socket.
	type fdSet struct {
		Count uint32
		Fd    [1]uintptr
	}
	type timeVal struct {
		Sec  int32
		Usec int32
	}

	writeSet := fdSet{Count: 1}
	writeSet.Fd[0] = uintptr(fd)
	exceptSet := fdSet{Count: 1}
	exceptSet.Fd[0] = uintptr(fd)

	// 30 second timeout for connection establishment.
	tv := timeVal{Sec: 30}

	r1, _, e1 := syscall.SyscallN(
		procSelect.Addr(),
		0, // nfds (ignored on Windows)
		0, // readfds
		uintptr(unsafe.Pointer(&writeSet)),
		uintptr(unsafe.Pointer(&exceptSet)),
		uintptr(unsafe.Pointer(&tv)),
	)
	n := int32(r1)
	if n < 0 { // SOCKET_ERROR
		return winsockErrno(e1)
	}
	if n == 0 { // timeout
		return syscall.ETIMEDOUT
	}

	// Exception set means connect failed — retrieve the actual error.
	if exceptSet.Count > 0 {
		val, err := syscall.GetsockoptInt(fd, 0xFFFF, 0x1007) // SOL_SOCKET, SO_ERROR
		if err != nil {
			return err
		}
		if val != 0 {
			return winsockErrno(syscall.Errno(val))
		}
		return syscall.ECONNREFUSED
	}

	// Write set ready means connected.
	return nil
}

// connectNeedsPolling reports whether the guest must poll SO_ERROR after
// a non-blocking connect. On Windows, SO_ERROR returns 0 while the TCP
// handshake is still in progress, so waitConnectComplete handles the wait
// via select() instead.
func connectNeedsPolling() bool { return false }

// sockaddrToRaw converts a Go syscall.Sockaddr to a raw pointer and length
// for use with low-level Winsock calls.
func sockaddrToRaw(sa syscall.Sockaddr) (unsafe.Pointer, int32, error) {
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		var raw syscall.RawSockaddrInet4
		raw.Family = syscall.AF_INET
		p := (*[2]byte)(unsafe.Pointer(&raw.Port))
		p[0] = byte(sa.Port >> 8)
		p[1] = byte(sa.Port)
		copy(raw.Addr[:], sa.Addr[:])
		return unsafe.Pointer(&raw), int32(unsafe.Sizeof(raw)), nil
	case *syscall.SockaddrInet6:
		var raw syscall.RawSockaddrInet6
		raw.Family = syscall.AF_INET6
		p := (*[2]byte)(unsafe.Pointer(&raw.Port))
		p[0] = byte(sa.Port >> 8)
		p[1] = byte(sa.Port)
		copy(raw.Addr[:], sa.Addr[:])
		raw.Scope_id = sa.ZoneId
		return unsafe.Pointer(&raw), int32(unsafe.Sizeof(raw)), nil
	default:
		return nil, 0, syscall.EINVAL
	}
}
