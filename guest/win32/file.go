//go:build wasip1

package win32

import "fmt"

// File access rights.
const (
	GENERIC_READ    = uint32(0x80000000)
	GENERIC_WRITE   = uint32(0x40000000)
	GENERIC_EXECUTE = uint32(0x20000000)
	GENERIC_ALL     = uint32(0x10000000)
)

// Share mode flags.
const (
	FILE_SHARE_READ   = uint32(0x1)
	FILE_SHARE_WRITE  = uint32(0x2)
	FILE_SHARE_DELETE = uint32(0x4)
)

// File creation disposition values.
const (
	CREATE_NEW        = uint32(1)
	CREATE_ALWAYS     = uint32(2)
	OPEN_EXISTING     = uint32(3)
	OPEN_ALWAYS       = uint32(4)
	TRUNCATE_EXISTING = uint32(5)
)

// File attribute flags.
const (
	FILE_ATTRIBUTE_READONLY  = uint32(0x1)
	FILE_ATTRIBUTE_HIDDEN    = uint32(0x2)
	FILE_ATTRIBUTE_SYSTEM    = uint32(0x4)
	FILE_ATTRIBUTE_DIRECTORY = uint32(0x10)
	FILE_ATTRIBUTE_ARCHIVE   = uint32(0x20)
	FILE_ATTRIBUTE_NORMAL    = uint32(0x80)
	INVALID_FILE_ATTRIBUTES  = uint32(0xFFFFFFFF)
)

// CreateFile opens or creates a file with the specified access, share, creation,
// and attribute flags.
func CreateFile(path string, access, shareMode, creation, flags uint32) (Handle, error) {
	if len(path) == 0 {
		return 0, fmt.Errorf("win32: CreateFile: empty path")
	}
	b := []byte(path)
	var h int32
	errno := _win32_create_file(&b[0], int32(len(b)), access, shareMode, creation, flags, &h)
	if err := errFromErrno(errno); err != nil {
		return 0, fmt.Errorf("win32: CreateFile %q: %w", path, err)
	}
	return Handle(h), nil
}

// ReadFile reads data from an open file handle into buf.
// It returns the number of bytes actually read.
func ReadFile(h Handle, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var nread uint32
	errno := _win32_read_file(int32(h), &buf[0], uint32(len(buf)), &nread)
	if err := errFromErrno(errno); err != nil {
		return 0, fmt.Errorf("win32: ReadFile: %w", err)
	}
	return int(nread), nil
}

// WriteFile writes buf to an open file handle.
// It returns the number of bytes actually written.
func WriteFile(h Handle, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var nwritten uint32
	errno := _win32_write_file(int32(h), &buf[0], uint32(len(buf)), &nwritten)
	if err := errFromErrno(errno); err != nil {
		return 0, fmt.Errorf("win32: WriteFile: %w", err)
	}
	return int(nwritten), nil
}

// GetFileAttributes returns the file attribute flags for the given path.
// Returns INVALID_FILE_ATTRIBUTES on error.
func GetFileAttributes(path string) (uint32, error) {
	if len(path) == 0 {
		return INVALID_FILE_ATTRIBUTES, fmt.Errorf("win32: GetFileAttributes: empty path")
	}
	b := []byte(path)
	var attrs uint32
	errno := _win32_get_file_attrs(&b[0], int32(len(b)), &attrs)
	if err := errFromErrno(errno); err != nil {
		return INVALID_FILE_ATTRIBUTES, fmt.Errorf("win32: GetFileAttributes %q: %w", path, err)
	}
	return attrs, nil
}

// SetFileAttributes sets the file attribute flags for the given path.
func SetFileAttributes(path string, attrs uint32) error {
	if len(path) == 0 {
		return fmt.Errorf("win32: SetFileAttributes: empty path")
	}
	b := []byte(path)
	errno := _win32_set_file_attrs(&b[0], int32(len(b)), attrs)
	if err := errFromErrno(errno); err != nil {
		return fmt.Errorf("win32: SetFileAttributes %q: %w", path, err)
	}
	return nil
}
