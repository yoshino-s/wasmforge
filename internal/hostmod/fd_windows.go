//go:build windows

package hostmod

import "syscall"

// osFDType is the OS-level file descriptor type.
// On Windows, handles are syscall.Handle (uintptr).
type osFDType = syscall.Handle
