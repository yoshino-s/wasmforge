package hostmod

import (
	"context"
	"os"
	"sync"

	"github.com/tetratelabs/wazero/api"
)

const basePipeFD = 15000

// pipeTable manages the mapping from guest pipe FDs (>= 15000) to host *os.File.
type pipeTable struct {
	mu      sync.Mutex
	entries map[int32]*os.File
	nextFD  int32
}

// newPipeTable creates a new pipe FD table.
func newPipeTable() *pipeTable {
	return &pipeTable{
		entries: make(map[int32]*os.File),
		nextFD:  basePipeFD,
	}
}

// insert adds an os.File to the table and returns a guest FD.
func (t *pipeTable) insert(f *os.File) int32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	fd := t.nextFD
	t.nextFD++
	t.entries[fd] = f
	return fd
}

// get returns the os.File for a guest FD, or nil if not found.
func (t *pipeTable) get(fd int32) *os.File {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.entries[fd]
}

// nativeHandle returns the OS-level file handle for a guest FD.
// On Windows this is a HANDLE suitable for Win32 APIs like SetStdHandle.
// Returns 0 if the FD is not found.
func (t *pipeTable) nativeHandle(fd int32) uintptr {
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.entries[fd]
	if f == nil {
		return 0
	}
	return f.Fd()
}

// isPipeFD reports whether val falls in the WasmForge pipe FD range.
func isPipeFD(val uint32) bool {
	return val >= basePipeFD && val < basePipeFD+1000
}

// remove closes and removes the file for a guest FD. Returns false if not found.
func (t *pipeTable) remove(fd int32) bool {
	t.mu.Lock()
	f, ok := t.entries[fd]
	if ok {
		delete(t.entries, fd)
	}
	t.mu.Unlock()
	if !ok {
		return false
	}
	f.Close()
	return true
}

// Context key for pipe table.
const ctxKeyPipeTable contextKey = 10

// WithPipeTable stores the pipe table in the context.
func WithPipeTable(ctx context.Context, pt *pipeTable) context.Context {
	return context.WithValue(ctx, ctxKeyPipeTable, pt)
}

// getPipeTable retrieves the pipe table from the context.
func getPipeTable(ctx context.Context) *pipeTable {
	pt, _ := ctx.Value(ctxKeyPipeTable).(*pipeTable)
	return pt
}

// NewPipeTable creates a new pipe FD table for external use.
func NewPipeTable() *pipeTable {
	return newPipeTable()
}

// osPipe implements the wasmforge.os_pipe host function.
// Creates an OS pipe and returns two guest FDs (read end, write end).
//
// Guest ABI:
//
//	read_fd_ptr:  pointer to write read-end FD (int32)
//	write_fd_ptr: pointer to write write-end FD (int32)
//
// Returns WASI errno (0 = success).
func osPipe(ctx context.Context, mod api.Module, stack []uint64) {
	readFDPtr := uint32(stack[0])
	writeFDPtr := uint32(stack[1])

	pt := getPipeTable(ctx)
	if pt == nil {
		stack[0] = uint64(errnoENOSYS)
		return
	}

	r, w, err := os.Pipe()
	if err != nil {
		stack[0] = uint64(errnoFromError(err))
		return
	}

	rfd := pt.insert(r)
	wfd := pt.insert(w)

	if !writeInt32(mod, readFDPtr, rfd) {
		pt.remove(rfd)
		pt.remove(wfd)
		stack[0] = uint64(errnoEFAULT)
		return
	}
	if !writeInt32(mod, writeFDPtr, wfd) {
		pt.remove(rfd)
		pt.remove(wfd)
		stack[0] = uint64(errnoEFAULT)
		return
	}

	stack[0] = uint64(errnoSuccess)
}

// pipeRead implements the wasmforge.pipe_read host function.
// Reads from a pipe FD into a WASM buffer.
//
// Guest ABI:
//
//	fd:        pipe FD
//	buf_ptr:   pointer to destination buffer
//	buf_len:   buffer capacity
//	nread_ptr: pointer to write actual bytes read (uint32)
//
// Returns WASI errno (0 = success).
func pipeRead(ctx context.Context, mod api.Module, stack []uint64) {
	fd := int32(stack[0])
	bufPtr := uint32(stack[1])
	bufLen := uint32(stack[2])
	nreadPtr := uint32(stack[3])

	pt := getPipeTable(ctx)
	if pt == nil {
		stack[0] = uint64(errnoENOSYS)
		return
	}

	f := pt.get(fd)
	if f == nil {
		stack[0] = uint64(errnoEBADF)
		return
	}

	buf := make([]byte, bufLen)
	n, errno := nonBlockingPipeRead(f, buf)
	if n > 0 {
		if !writeBytes(mod, bufPtr, buf[:n]) {
			stack[0] = uint64(errnoEFAULT)
			return
		}
	}
	if !writeUint32(mod, nreadPtr, uint32(n)) {
		stack[0] = uint64(errnoEFAULT)
		return
	}

	if errno != errnoSuccess {
		stack[0] = uint64(errno)
		return
	}

	stack[0] = uint64(errnoSuccess)
}

// pipeWrite implements the wasmforge.pipe_write host function.
// Writes from a WASM buffer to a pipe FD.
//
// Guest ABI:
//
//	fd:           pipe FD
//	buf_ptr:      pointer to source buffer
//	buf_len:      bytes to write
//	nwritten_ptr: pointer to write actual bytes written (uint32)
//
// Returns WASI errno (0 = success).
func pipeWrite(ctx context.Context, mod api.Module, stack []uint64) {
	fd := int32(stack[0])
	bufPtr := uint32(stack[1])
	bufLen := uint32(stack[2])
	nwrittenPtr := uint32(stack[3])

	pt := getPipeTable(ctx)
	if pt == nil {
		stack[0] = uint64(errnoENOSYS)
		return
	}

	f := pt.get(fd)
	if f == nil {
		stack[0] = uint64(errnoEBADF)
		return
	}

	data, ok := readBytes(mod, bufPtr, bufLen)
	if !ok {
		stack[0] = uint64(errnoEFAULT)
		return
	}

	n, err := f.Write(data)
	if !writeUint32(mod, nwrittenPtr, uint32(n)) {
		stack[0] = uint64(errnoEFAULT)
		return
	}

	if err != nil {
		stack[0] = uint64(errnoFromError(err))
		return
	}

	stack[0] = uint64(errnoSuccess)
}

// pipeClose implements the wasmforge.pipe_close host function.
// Closes a pipe FD.
//
// Guest ABI:
//
//	fd: pipe FD to close
//
// Returns WASI errno (0 = success).
func pipeClose(ctx context.Context, mod api.Module, stack []uint64) {
	fd := int32(stack[0])

	pt := getPipeTable(ctx)
	if pt == nil {
		stack[0] = uint64(errnoENOSYS)
		return
	}

	if !pt.remove(fd) {
		stack[0] = uint64(errnoEBADF)
		return
	}

	stack[0] = uint64(errnoSuccess)
}
