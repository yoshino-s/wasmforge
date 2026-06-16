//go:build darwin

package platform

import "syscall"

// SetSocketNonblock sets a socket to non-blocking mode on macOS.
func SetSocketNonblock(fd int) error {
	return syscall.SetNonblock(fd, true)
}

// SetReuseAddr sets SO_REUSEADDR on macOS.
func SetReuseAddr(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}

// SO_NOSIGPIPE prevents SIGPIPE on macOS.
const SO_NOSIGPIPE = 0x1022

// SetNoSigPipe sets SO_NOSIGPIPE on macOS to prevent SIGPIPE.
func SetNoSigPipe(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, SO_NOSIGPIPE, 1)
}
