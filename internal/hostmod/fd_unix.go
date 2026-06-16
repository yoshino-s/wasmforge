//go:build !windows

package hostmod

// osFDType is the OS-level file descriptor type.
// On Unix-like systems, file descriptors are ints.
type osFDType = int
