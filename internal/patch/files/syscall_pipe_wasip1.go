// WasmForge pipe support for wasip1.
// Provides os.Pipe() via host functions and routes pipe FD I/O
// through host functions transparently.

//go:build wasip1

package syscall

import "runtime"

//go:wasmimport env fd_pipe
//go:noescape
func wasmforge_os_pipe(readFDPtr *int32, writeFDPtr *int32) int32

//go:wasmimport env fd_pread
//go:noescape
func wasmforge_pipe_read(fd int32, bufPtr *byte, bufLen uint32, nreadPtr *uint32) int32

//go:wasmimport env fd_pwrite
//go:noescape
func wasmforge_pipe_write(fd int32, bufPtr *byte, bufLen uint32, nwrittenPtr *uint32) int32

//go:wasmimport env fd_pclose
//go:noescape
func wasmforge_pipe_close(fd int32) int32

// wasmforgePipeFDBase is the base FD for WasmForge pipe descriptors.
// Must match basePipeFD in internal/hostmod/pipe.go.
const wasmforgePipeFDBase = 15000

// IsWasmForgePipeFD reports whether fd is a WasmForge pipe FD.
func IsWasmForgePipeFD(fd int) bool {
	return fd >= wasmforgePipeFDBase
}

// WasmForgePipe creates an OS pipe via the host and returns two FDs.
func WasmForgePipe(fd []int) error {
	if len(fd) < 2 {
		return EINVAL
	}
	var rfd, wfd int32
	if errno := wasmforge_os_pipe(&rfd, &wfd); errno != 0 {
		return Errno(errno)
	}
	fd[0] = int(rfd)
	fd[1] = int(wfd)
	return nil
}

// WasmForgePipeRead reads from a WasmForge pipe FD.
// On Windows hosts, pipe reads are non-blocking (returning EAGAIN when empty)
// to prevent deadlocking the single-threaded WASM runtime. This function
// retries on EAGAIN, yielding to the Go scheduler between attempts so other
// goroutines can run. From the caller's perspective, this behaves like a
// blocking read.
func WasmForgePipeRead(fd int, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	var nread uint32
	for {
		errno := wasmforge_pipe_read(int32(fd), &p[0], uint32(len(p)), &nread)
		if errno == 0 {
			return int(nread), nil
		}
		if errno == 6 { // WASI EAGAIN — pipe empty, retry after yielding
			runtime.Gosched()
			continue
		}
		return int(nread), Errno(errno)
	}
}

// WasmForgePipeWrite writes to a WasmForge pipe FD.
func WasmForgePipeWrite(fd int, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	var nwritten uint32
	errno := wasmforge_pipe_write(int32(fd), &p[0], uint32(len(p)), &nwritten)
	if errno != 0 {
		return int(nwritten), Errno(errno)
	}
	return int(nwritten), nil
}

// WasmForgePipeClose closes a WasmForge pipe FD.
func WasmForgePipeClose(fd int) error {
	if errno := wasmforge_pipe_close(int32(fd)); errno != 0 {
		return Errno(errno)
	}
	return nil
}
