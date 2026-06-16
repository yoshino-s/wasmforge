//go:build darwin

package hostmod

import "syscall"

// Guest (wasip1) uses Linux-like socket constants that differ from macOS/BSD values.
// These must be translated before passing to macOS syscalls.
const (
	guestAF_INET6 = 10 // Linux AF_INET6 (macOS is 30)

	guestSOL_SOCKET   = 1  // Linux SOL_SOCKET (macOS is 0xFFFF)
	guestSOL_TCP      = 6  // same on both
	guestIPPROTO_IPV6 = 41 // same on both

	guestSO_REUSEADDR = 2  // Linux SO_REUSEADDR (macOS is 0x0004)
	guestSO_ERROR     = 4  // Linux SO_ERROR (macOS is 0x1007)
	guestSO_KEEPALIVE = 9  // Linux SO_KEEPALIVE (macOS is 0x0008)
	guestSO_BROADCAST = 6  // Linux SO_BROADCAST (macOS is 0x0020)
	guestSO_RCVBUF    = 8  // Linux SO_RCVBUF (macOS is 0x1002)
	guestSO_SNDBUF    = 7  // Linux SO_SNDBUF (macOS is 0x1001)
	guestSO_LINGER    = 13 // Linux SO_LINGER (macOS is 0x0080)
)

// translateDomain converts a guest (Linux/WASI) address family to the host value.
// AF_INET=2, AF_UNIX=1 match between Linux and macOS. AF_INET6 differs.
func translateDomain(domain int) int {
	if domain == guestAF_INET6 {
		return int(syscall.AF_INET6) // 30 on macOS
	}
	return domain
}

// translateSockoptLevel converts a guest (Linux) SOL_* to the host value.
func translateSockoptLevel(level int) int {
	switch level {
	case guestSOL_SOCKET:
		return int(syscall.SOL_SOCKET) // 0xFFFF on macOS
	case guestSOL_TCP:
		return int(syscall.IPPROTO_TCP) // 6 on both
	case guestIPPROTO_IPV6:
		return int(syscall.IPPROTO_IPV6) // 41 on both
	default:
		return level
	}
}

// translateSockoptName converts a guest (Linux) SO_* option name to the host value.
func translateSockoptName(level, name int) int {
	// Only SOL_SOCKET options differ between Linux and macOS.
	if level == guestSOL_SOCKET {
		switch name {
		case guestSO_REUSEADDR:
			return int(syscall.SO_REUSEADDR) // 0x0004 on macOS
		case guestSO_ERROR:
			return int(syscall.SO_ERROR) // 0x1007 on macOS
		case guestSO_KEEPALIVE:
			return int(syscall.SO_KEEPALIVE) // 0x0008 on macOS
		case guestSO_BROADCAST:
			return int(syscall.SO_BROADCAST) // 0x0020 on macOS
		case guestSO_RCVBUF:
			return int(syscall.SO_RCVBUF) // 0x1002 on macOS
		case guestSO_SNDBUF:
			return int(syscall.SO_SNDBUF) // 0x1001 on macOS
		case guestSO_LINGER:
			return int(syscall.SO_LINGER) // 0x0080 on macOS
		}
	}
	return name
}

// isErrWouldBlock returns true if err indicates the operation would block.
// On macOS, EAGAIN and EWOULDBLOCK are the same value.
func isErrWouldBlock(err error) bool {
	return err == syscall.EAGAIN || err == syscall.EWOULDBLOCK
}

// isErrConnectInProgress returns true if err indicates a non-blocking
// connect is in progress.
func isErrConnectInProgress(err error) bool {
	return err == syscall.EINPROGRESS || err == syscall.EALREADY || err == syscall.EWOULDBLOCK
}

// classifyWinsockError maps raw Winsock error codes to WASI errno values.
// On macOS, there are no Winsock errors. Always returns (0, false).
func classifyWinsockError(_ syscall.Errno) (uint32, bool) {
	return 0, false
}
