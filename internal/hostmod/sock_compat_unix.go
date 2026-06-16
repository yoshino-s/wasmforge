//go:build !windows && !darwin

package hostmod

import "syscall"

// translateDomain converts a guest (Linux/WASI) address family to the host value.
// On Unix, these are identical.
func translateDomain(domain int) int { return domain }

// translateSockoptLevel converts a guest (Linux) SOL_* to the host value.
// On Unix, these are identical.
func translateSockoptLevel(level int) int { return level }

// translateSockoptName converts a guest (Linux) SO_* to the host value.
// On Unix, these are identical.
func translateSockoptName(level, name int) int { return name }

// isErrWouldBlock returns true if err indicates the operation would block.
// On Unix, EAGAIN and EWOULDBLOCK are the same value.
func isErrWouldBlock(err error) bool {
	return err == syscall.EAGAIN || err == syscall.EWOULDBLOCK
}

// isErrConnectInProgress returns true if err indicates a non-blocking
// connect is in progress.
func isErrConnectInProgress(err error) bool {
	return err == syscall.EINPROGRESS || err == syscall.EALREADY || err == syscall.EWOULDBLOCK
}

// classifyWinsockError maps raw Winsock error codes to WASI errno values.
// On Unix, there are no Winsock errors. Always returns (0, false).
func classifyWinsockError(_ syscall.Errno) (uint32, bool) {
	return 0, false
}
