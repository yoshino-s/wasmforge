// Types and constants that are defined in syscallwin.go (windows-only)
// but referenced by types.go (windows || wasip1). This file provides
// the missing definitions for wasip1 builds.

//go:build wasip1

package windows

import (
	"syscall"
	"unsafe"
)

// Signal is defined in syscallwin.go on Windows.
type Signal int

func (s Signal) Signal() {}

func (s Signal) String() string {
	if 0 <= s && int(s) < len(signals) {
		str := signals[s]
		if str != "" {
			return str
		}
	}
	return "signal " + itoa(int(s))
}

// Socket address types from syscallwin.go.

type RawSockaddrInet4 struct {
	Family uint16
	Port   uint16
	Addr   [4]byte /* in_addr */
	Zero   [8]uint8
}

type RawSockaddrInet6 struct {
	Family   uint16
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte /* in6_addr */
	Scope_id uint32
}

type RawSockaddrInet struct {
	Family uint16
	Port   uint16
	Data   [6]uint32
}

type RawSockaddr struct {
	Family uint16
	Data   [14]int8
}

type RawSockaddrAny struct {
	Addr RawSockaddr
	Pad  [100]int8
}

type Sockaddr interface {
	sockaddr() (ptr unsafe.Pointer, len int32, err error)
}

// Job object types — WASM is 32-bit, matching types_32bit.go.

type WSAData struct {
	Version      uint16
	HighVersion  uint16
	Description  [WSADESCRIPTION_LEN + 1]byte
	SystemStatus [WSASYS_STATUS_LEN + 1]byte
	MaxSockets   uint16
	MaxUdpDg     uint16
	VendorInfo   *byte
}

type Servent struct {
	Name    *byte
	Aliases **byte
	Port    uint16
	Proto   *byte
}

type JOBOBJECT_BASIC_LIMIT_INFORMATION struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
	_                       uint32 // pad to 8 byte boundary
}

// socket_error sentinel for Winsock functions (from syscallwin.go).
const socket_error = uintptr(^uint32(0))

// --- NTStatus error interface (from syscallwin.go) ---

func (s NTStatus) Error() string {
	b := make([]uint16, 300)
	n, err := FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_FROM_HMODULE|FORMAT_MESSAGE_ARGUMENT_ARRAY, modntdll.Handle(), uint32(s), langID(LANG_ENGLISH, SUBLANG_ENGLISH_US), b, nil)
	if err != nil {
		return "NTSTATUS 0x" + ntstatusHex(uint32(s))
	}
	for ; n > 0 && (b[n-1] == '\n' || b[n-1] == '\r'); n-- {
	}
	return UTF16ToString(b[:n])
}

func (s NTStatus) Errno() syscall.Errno {
	return rtlNtStatusToDosErrorNoTeb(s)
}

func langID(pri, sub uint16) uint32 { return uint32(sub)<<10 | uint32(pri) }

func ntstatusHex(v uint32) string {
	const digits = "0123456789abcdef"
	var buf [8]byte
	for i := 7; i >= 0; i-- {
		buf[i] = digits[v&0xf]
		v >>= 4
	}
	return string(buf[:])
}

// --- UTF16 string functions (from syscallwin.go) ---

// StringToUTF16 is deprecated. Use UTF16FromString instead.
func StringToUTF16(s string) []uint16 {
	a, err := UTF16FromString(s)
	if err != nil {
		panic("windows: string with NUL passed to StringToUTF16")
	}
	return a
}

// UTF16FromString returns the UTF-16 encoding of the UTF-8 string
// s, with a terminating NUL added.
func UTF16FromString(s string) ([]uint16, error) {
	return syscall.UTF16FromString(s)
}

// UTF16ToString returns the UTF-8 encoding of the UTF-16 sequence s,
// with a terminating NUL and any bytes after the NUL removed.
func UTF16ToString(s []uint16) string {
	return syscall.UTF16ToString(s)
}

// StringToUTF16Ptr is deprecated. Use UTF16PtrFromString instead.
func StringToUTF16Ptr(s string) *uint16 { return &StringToUTF16(s)[0] }

// UTF16PtrFromString returns pointer to the UTF-16 encoding of
// the UTF-8 string s, with a terminating NUL added.
func UTF16PtrFromString(s string) (*uint16, error) {
	a, err := UTF16FromString(s)
	if err != nil {
		return nil, err
	}
	return &a[0], nil
}

// UTF16PtrToString takes a pointer to a UTF-16 sequence and returns
// the corresponding UTF-8 encoded string.
func UTF16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	if *p == 0 {
		return ""
	}
	n := 0
	ptr := p
	for *ptr != 0 {
		n++
		ptr = (*uint16)(unsafe.Add(unsafe.Pointer(ptr), 2))
	}
	s := unsafe.Slice(p, n)
	return syscall.UTF16ToString(s)
}

// --- Additional types from syscallwin.go ---

// Getuid/Getgid stubs (from syscallwin.go).
func Getuid() (uid int)                  { return -1 }
func Getgid() (gid int)                  { return -1 }
func Geteuid() (euid int)                { return -1 }
func Getegid() (egid int)                { return -1 }
func Getgroups() (gids []int, err error) { return nil, syscall.ENOSYS }

// --- NTUnicodeString methods (from syscallwin.go) ---

// Slice returns a uint16 slice that aliases the data in the NTUnicodeString.
func (s *NTUnicodeString) Slice() []uint16 {
	return unsafe.Slice(s.Buffer, s.MaximumLength/2)[:s.Length/2]
}

func (s *NTUnicodeString) String() string {
	return UTF16ToString(s.Slice())
}

// NewNTUnicodeString returns a new NTUnicodeString structure for use with native
// NT APIs that work over the NTUnicodeString type.
func NewNTUnicodeString(s string) (*NTUnicodeString, error) {
	var u NTUnicodeString
	s16, err := UTF16FromString(s)
	if err != nil {
		return nil, err
	}
	u.Buffer = &s16[0]
	u.Length = uint16(2 * len(s))
	u.MaximumLength = uint16(2 * len(s16))
	return &u, nil
}

// For testing: clients can set this flag to force
// creation of IPv6 sockets to return EAFNOSUPPORT.
var SocketDisableIPv6 bool

// GetProcAddressByOrdinal retrieves the address of an exported function
// by ordinal rather than by name. Uses procGetProcAddress from zsyscall.go.
func GetProcAddressByOrdinal(module Handle, ordinal uintptr) (proc uintptr, err error) {
	r0, _, e1 := syscall.SyscallN(procGetProcAddress.Addr(), uintptr(module), ordinal)
	proc = uintptr(r0)
	if proc == 0 {
		err = errnoErr(e1)
	}
	return
}

// GetCurrentThread returns the pseudo-handle for the current thread.
// From syscallwin.go — needed by priv code for token operations.
func GetCurrentThread() (Handle, error) {
	return CurrentThread(), nil
}

// CurrentThread returns the handle for the current thread.
// It is a pseudo handle that does not need to be closed.
func CurrentThread() Handle {
	return ^Handle(1)
}
