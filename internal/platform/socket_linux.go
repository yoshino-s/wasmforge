//go:build linux

package platform

import "syscall"

// SetSocketNonblock sets a socket to non-blocking mode on Linux.
func SetSocketNonblock(fd int) error {
	return syscall.SetNonblock(fd, true)
}

// SetReuseAddr sets SO_REUSEADDR on Linux.
func SetReuseAddr(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
}
