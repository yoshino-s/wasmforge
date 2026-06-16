//go:build darwin

package hostmod

import "syscall"

// socketRecv reads from a socket. On Darwin, syscall.Read works on socket FDs.
func socketRecv(fd osFDType, buf []byte) (int, error) {
	return syscall.Read(fd, buf)
}

// socketSend writes to a socket. On Darwin, syscall.Write works on socket FDs.
func socketSend(fd osFDType, buf []byte) (int, error) {
	return syscall.Write(fd, buf)
}

// setSocketNonblock sets a socket to non-blocking mode.
func setSocketNonblock(fd osFDType) error {
	return syscall.SetNonblock(fd, true)
}

// socketSendTo sends data to a specific address.
func socketSendTo(fd osFDType, buf []byte, flags int, sa syscall.Sockaddr) error {
	return syscall.Sendto(fd, buf, flags, sa)
}

// socketRecvFrom receives data and returns the sender's address.
func socketRecvFrom(fd osFDType, buf []byte, flags int) (int, syscall.Sockaddr, error) {
	return syscall.Recvfrom(fd, buf, flags)
}

// socketAccept accepts a connection on a listening socket.
func socketAccept(fd osFDType) (osFDType, syscall.Sockaddr, error) {
	return syscall.Accept(fd)
}

// socketClose closes a socket.
func socketClose(fd osFDType) error {
	return syscall.Close(fd)
}

// waitConnectComplete waits for a non-blocking connect to complete using
// select(). On macOS/BSD, getsockopt(SO_ERROR) returns 0 immediately after
// a non-blocking connect that returned EINPROGRESS — meaning "no error yet",
// NOT "connected". The guest-side SO_ERROR polling loop would falsely detect
// completion and attempt writes on an unconnected socket. Instead, we use
// select() to wait for true write-readiness, then check SO_ERROR for the
// actual connection result.
func waitConnectComplete(fd osFDType) error {
	// FD_SETSIZE on macOS is 1024. FDs >= 1024 cause out-of-bounds
	// array access in FdSet.Bits and are rejected by select(2) anyway.
	if fd >= 1024 {
		return syscall.EINVAL
	}

	// 30-second timeout matching the Windows implementation.
	tv := syscall.Timeval{Sec: 30}

	var writeSet, exceptSet syscall.FdSet
	fdSet(&writeSet, fd)
	fdSet(&exceptSet, fd)

	// On macOS, syscall.Select returns only error (not count).
	// Timeout is detected by checking if neither fd_set has our fd.
	if err := syscall.Select(fd+1, nil, &writeSet, &exceptSet, &tv); err != nil {
		return err
	}

	if !fdIsSet(&writeSet, fd) && !fdIsSet(&exceptSet, fd) {
		return syscall.ETIMEDOUT
	}

	// Exception means connect failed — retrieve the actual error.
	if fdIsSet(&exceptSet, fd) {
		val, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
		if err != nil {
			return err
		}
		if val != 0 {
			return syscall.Errno(val)
		}
		return syscall.ECONNREFUSED
	}

	// Write-ready — check SO_ERROR to confirm connection succeeded.
	// After select() reports write-readiness, SO_ERROR now reflects the
	// actual connection result (0 = success, nonzero = error).
	val, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
	if err != nil {
		return err
	}
	if val != 0 {
		return syscall.Errno(val)
	}

	return nil
}

// connectNeedsPolling reports whether the guest must poll SO_ERROR after
// a non-blocking connect. On macOS/BSD, SO_ERROR returns 0 immediately
// (meaning "no error yet", not "connected"), so waitConnectComplete handles
// the wait via select() instead. The guest skips polling entirely.
func connectNeedsPolling() bool { return false }

// fdSet sets fd in the fd_set. macOS FdSet.Bits is [32]int32.
func fdSet(set *syscall.FdSet, fd int) {
	set.Bits[fd/32] |= 1 << (uint(fd) % 32)
}

// fdIsSet checks if fd is set in the fd_set.
func fdIsSet(set *syscall.FdSet, fd int) bool {
	return set.Bits[fd/32]&(1<<(uint(fd)%32)) != 0
}
