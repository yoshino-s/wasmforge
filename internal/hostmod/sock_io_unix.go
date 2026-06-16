//go:build !windows && !darwin

package hostmod

import "syscall"

// socketRecv reads from a socket. On Unix, syscall.Read works on socket FDs.
func socketRecv(fd osFDType, buf []byte) (int, error) {
	return syscall.Read(fd, buf)
}

// socketSend writes to a socket. On Unix, syscall.Write works on socket FDs.
func socketSend(fd osFDType, buf []byte) (int, error) {
	return syscall.Write(fd, buf)
}

// setSocketNonblock sets a socket to non-blocking mode. On Unix, syscall.SetNonblock works directly.
func setSocketNonblock(fd osFDType) error {
	return syscall.SetNonblock(fd, true)
}

// socketSendTo sends data to a specific address. On Unix, syscall.Sendto works directly.
func socketSendTo(fd osFDType, buf []byte, flags int, sa syscall.Sockaddr) error {
	return syscall.Sendto(fd, buf, flags, sa)
}

// socketRecvFrom receives data and returns the sender's address. On Unix, syscall.Recvfrom works directly.
func socketRecvFrom(fd osFDType, buf []byte, flags int) (int, syscall.Sockaddr, error) {
	return syscall.Recvfrom(fd, buf, flags)
}

// socketAccept accepts a connection on a listening socket. On Unix, syscall.Accept works directly.
func socketAccept(fd osFDType) (osFDType, syscall.Sockaddr, error) {
	return syscall.Accept(fd)
}

// socketClose closes a socket. On Unix, syscall.Close works for all FD types.
func socketClose(fd osFDType) error {
	return syscall.Close(fd)
}

// waitConnectComplete waits for a non-blocking connect to finish.
// On Unix, the guest-side polling loop (SO_ERROR check) works correctly,
// so this is a no-op.
func waitConnectComplete(fd osFDType) error {
	return nil
}

// connectNeedsPolling reports whether the guest must poll SO_ERROR after
// a non-blocking connect. On Unix, SO_ERROR correctly reflects in-progress
// state, so the guest can poll. On Windows, SO_ERROR returns 0 prematurely,
// so waitConnectComplete handles it instead.
func connectNeedsPolling() bool { return true }
