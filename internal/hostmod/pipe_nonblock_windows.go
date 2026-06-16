//go:build windows

package hostmod

import (
	"os"
	"syscall"
	"time"
	"unsafe"
)

var (
	modkernel32      = syscall.NewLazyDLL("kernel32.dll")
	procPeekNamedPipe = modkernel32.NewProc("PeekNamedPipe")
)

// peekNamedPipe checks if data is available on a pipe without blocking.
// Returns the number of bytes available.
func peekNamedPipe(f *os.File) (uint32, error) {
	h := syscall.Handle(f.Fd())
	var avail uint32
	r, _, err := procPeekNamedPipe.Call(
		uintptr(h),
		0,    // no buffer (just peek)
		0,    // buffer size
		0,    // bytes read (not needed)
		uintptr(unsafe.Pointer(&avail)),
		0,    // bytes left this message
	)
	if r == 0 {
		return 0, err
	}
	return avail, nil
}

// nonBlockingPipeRead reads from a pipe without blocking. If no data is
// available, it returns (0, errnoEAGAIN) instead of blocking the caller.
// This is critical for single-threaded WASM runtimes where a blocking
// host function deadlocks the entire execution.
func nonBlockingPipeRead(f *os.File, buf []byte) (int, uint32) {
	avail, err := peekNamedPipe(f)
	if err != nil {
		// PeekNamedPipe failed — pipe might be broken.
		return 0, errnoEBADF
	}
	if avail == 0 {
		// No data available — sleep briefly to prevent guest busy-spin,
		// then return EAGAIN. The guest retries with runtime.Gosched()
		// between attempts, allowing other goroutines to run.
		time.Sleep(1 * time.Millisecond)
		return 0, errnoEAGAIN
	}

	// Read up to len(buf) bytes (but no more than available to avoid blocking).
	readSize := len(buf)
	if int(avail) < readSize {
		readSize = int(avail)
	}
	n, readErr := f.Read(buf[:readSize])
	if readErr != nil && n == 0 {
		return 0, errnoFromError(readErr)
	}
	return n, errnoSuccess
}
