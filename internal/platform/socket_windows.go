//go:build windows

package platform

// SetSocketNonblock is a no-op on Windows (winsock handles non-blocking differently).
func SetSocketNonblock(fd int) error {
	// Windows sockets use ioctlsocket for non-blocking mode.
	// This is handled by the host module at a higher level.
	return nil
}

// SetReuseAddr is a no-op placeholder on Windows.
func SetReuseAddr(fd int) error {
	return nil
}
