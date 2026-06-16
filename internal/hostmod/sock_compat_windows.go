//go:build windows

package hostmod

import "syscall"

// Guest constants use Linux/WASI values. These differ from Windows.
const (
	// Address families: Linux vs Windows
	linuxAF_INET6 = 10 // Guest uses this
	// Windows AF_INET6 = 23, available as syscall.AF_INET6

	// Socket option levels
	linuxSOL_SOCKET   = 1
	linuxSOL_TCP      = 6
	linuxIPPROTO_TCP  = 6
	linuxIPPROTO_IPV6 = 41

	// Common SO_* options (Linux values)
	linuxSO_REUSEADDR = 2
	linuxSO_ERROR     = 4
	linuxSO_KEEPALIVE = 9
	linuxSO_BROADCAST = 6
	linuxSO_RCVBUF    = 8
	linuxSO_SNDBUF    = 7
	linuxSO_RCVTIMEO  = 20
	linuxSO_SNDTIMEO  = 21
	linuxSO_LINGER    = 13
	linuxTCP_NODELAY  = 1
	linuxIPV6_V6ONLY  = 26
)

// translateDomain converts a guest (Linux/WASI) address family to the host value.
// AF_INET=2 is the same. AF_INET6=10 (Linux) must become 23 (Windows).
func translateDomain(domain int) int {
	if domain == linuxAF_INET6 {
		return int(syscall.AF_INET6)
	}
	return domain
}

// translateSockoptLevel converts a guest (Linux) SOL_* to the host value.
func translateSockoptLevel(level int) int {
	switch level {
	case linuxSOL_SOCKET:
		return int(syscall.SOL_SOCKET) // 0xFFFF on Windows
	case linuxSOL_TCP:
		return int(syscall.IPPROTO_TCP) // 6 on both
	case linuxIPPROTO_IPV6:
		return int(syscall.IPPROTO_IPV6) // 41 on both
	default:
		return level
	}
}

// translateSockoptName converts a guest (Linux) SO_* option name to the host value.
func translateSockoptName(level, name int) int {
	// Only SOL_SOCKET options differ between Linux and Windows.
	if level == linuxSOL_SOCKET {
		switch name {
		case linuxSO_REUSEADDR:
			return int(syscall.SO_REUSEADDR) // 4 on Windows
		case linuxSO_ERROR:
			return 0x1007 // SO_ERROR on Windows
		case linuxSO_KEEPALIVE:
			return int(syscall.SO_KEEPALIVE) // 8 on Windows
		case linuxSO_BROADCAST:
			return int(syscall.SO_BROADCAST) // 0x20 on Windows
		case linuxSO_RCVBUF:
			return int(syscall.SO_RCVBUF) // 0x1002 on Windows
		case linuxSO_SNDBUF:
			return int(syscall.SO_SNDBUF) // 0x1001 on Windows
		case linuxSO_LINGER:
			return int(syscall.SO_LINGER) // 0x80 on Windows
		}
	}
	// TCP_NODELAY=1 and IPV6_V6ONLY=27 are the same on both.
	return name
}

// isErrWouldBlock returns true if err indicates the operation would block.
// On Windows, Go's syscall functions return raw Winsock error codes (e.g., 10035)
// while syscall.EWOULDBLOCK is a synthetic POSIX value (0x2000007F). We must
// check both the synthetic constants AND the raw Winsock codes.
func isErrWouldBlock(err error) bool {
	if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
		return true
	}
	if errno, ok := err.(syscall.Errno); ok {
		return uintptr(errno) == wsaeWouldBlock
	}
	return false
}

// isErrConnectInProgress returns true if err indicates a non-blocking
// connect is in progress. On Windows, non-blocking connect returns
// WSAEWOULDBLOCK (10035) instead of EINPROGRESS.
func isErrConnectInProgress(err error) bool {
	if err == syscall.EINPROGRESS || err == syscall.EALREADY || err == syscall.EWOULDBLOCK {
		return true
	}
	if errno, ok := err.(syscall.Errno); ok {
		switch uintptr(errno) {
		case wsaeWouldBlock, wsaeInProgress, wsaeAlready:
			return true
		}
	}
	return false
}

// classifyWinsockError maps raw Winsock error codes to WASI errno values.
// Go's standard syscall functions on Windows return raw Winsock codes (e.g.,
// 10035 for WSAEWOULDBLOCK) that don't match Go's synthetic POSIX constants
// (e.g., syscall.EWOULDBLOCK = 0x2000007F). This function bridges the gap
// for errnoFromError.
func classifyWinsockError(errno syscall.Errno) (uint32, bool) {
	switch uintptr(errno) {
	case wsaeInval:
		return errnoEINVAL, true
	case wsaeWouldBlock:
		return errnoEAGAIN, true
	case wsaeInProgress:
		return errnoEINPROGRESS, true
	case wsaeAlready:
		return 5, true // WASI EALREADY
	case wsaeNotSock:
		return errnoEBADF, true
	case wsaeAfNoSupport:
		return 57, true // WASI ENOTSUP (closest match)
	case wsaeAddrInUse:
		return 3, true // WASI EADDRINUSE
	case wsaeAddrNotAvail:
		return 4, true // WASI EADDRNOTAVAIL
	case wsaeNetUnreach:
		return 40, true // WASI ENETUNREACH
	case wsaeConnAborted:
		return 13, true // WASI ECONNABORTED
	case wsaeConnReset:
		return 15, true // WASI ECONNRESET
	case wsaeNotConn:
		return 53, true // WASI ENOTCONN
	case wsaeTimedOut:
		return 73, true // WASI ETIMEDOUT
	case wsaeConnRefused:
		return 61, true // WASI ECONNREFUSED
	}
	return 0, false
}
