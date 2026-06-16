//go:build wasip1

package win32

import "fmt"

// Process access rights.
const (
	PROCESS_ALL_ACCESS = uint32(0x001FFFFF)
	PROCESS_TERMINATE  = uint32(0x0001)
	PROCESS_QUERY_INFO = uint32(0x0400)
)

// Process creation flags.
const (
	CREATE_NEW_CONSOLE = uint32(0x00000010)
	CREATE_NO_WINDOW   = uint32(0x08000000)
)

// GetComputerName returns the NetBIOS name of the local computer.
// The host writes the name as UTF-8.
func GetComputerName() (string, error) {
	var buf [256]byte
	bufLen := uint32(len(buf))
	errno := _win32_get_computer_name(&buf[0], &bufLen)
	if err := errFromErrno(errno); err != nil {
		return "", fmt.Errorf("win32: GetComputerName: %w", err)
	}
	return string(buf[:bufLen]), nil
}

// CreateProcess starts a new process with the given command line and creation flags.
// It returns the PID and a process handle on success.
func CreateProcess(cmdline string, flags uint32) (pid uint32, handle Handle, err error) {
	if len(cmdline) == 0 {
		return 0, 0, fmt.Errorf("win32: CreateProcess: empty cmdline")
	}
	b := []byte(cmdline)
	var h int32
	errno := _win32_create_process(&b[0], int32(len(b)), flags, &pid, &h)
	if e := errFromErrno(errno); e != nil {
		return 0, 0, fmt.Errorf("win32: CreateProcess: %w", e)
	}
	return pid, Handle(h), nil
}

// OpenProcess opens an existing process by PID with the requested access rights.
func OpenProcess(access, pid uint32) (Handle, error) {
	var h int32
	errno := _win32_open_process(access, pid, &h)
	if err := errFromErrno(errno); err != nil {
		return 0, fmt.Errorf("win32: OpenProcess pid=%d: %w", pid, err)
	}
	return Handle(h), nil
}

// TerminateProcess terminates the process associated with the given handle.
func TerminateProcess(handle Handle, exitCode uint32) error {
	errno := _win32_terminate_process(int32(handle), exitCode)
	if err := errFromErrno(errno); err != nil {
		return fmt.Errorf("win32: TerminateProcess: %w", err)
	}
	return nil
}
