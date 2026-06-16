package hostmod

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/tetratelabs/wazero/api"
)

var debugNet = os.Getenv("WASMFORGE_DEBUG") != ""

// eagainBackoff is the duration to sleep when a non-blocking socket
// operation returns EAGAIN. This yield is critical: wazero's compiled
// WASM execution runs as a tight native loop that starves the Go runtime
// scheduler. Without this pause the kernel never delivers incoming
// packets to socket receive buffers.
const eagainBackoff = 100 * time.Microsecond

// yieldOnEAGAIN sleeps for eagainBackoff to let the OS scheduler run.
func yieldOnEAGAIN() { time.Sleep(eagainBackoff) }

// sockRead implements non-blocking read from a socket.
// Returns number of bytes read or EAGAIN if no data available.
func sockRead(ctx context.Context, mod api.Module, fd int32, bufPtr, bufLen, nreadPtr uint32) uint32 {
	ft := getFDTable(ctx)
	entry := ft.get(fd)
	if entry == nil {
		return errnoEBADF
	}

	buf := make([]byte, bufLen)
	n, err := socketRecv(entry.osFD, buf)
	if debugNet {
		if err == nil {
			fmt.Fprintf(os.Stderr, "[runtime-debug] sockRead: guestFD=%d osFD=%d n=%d\n",
				fd, entry.osFD, n)
		} else if !isErrWouldBlock(err) {
			fmt.Fprintf(os.Stderr, "[runtime-debug] sockRead: guestFD=%d err=%v\n", fd, err)
		}
	}
	if err != nil {
		if isErrWouldBlock(err) {
			// Yield to the OS scheduler. Without this sleep, wazero's
			// compiled WASM execution starves the Go runtime scheduler
			// and the kernel never delivers incoming packets to the
			// socket receive buffer.
			yieldOnEAGAIN()
			writeUint32(mod, nreadPtr, 0)
			return errnoEAGAIN
		}
		return errnoFromError(err)
	}

	if n == 0 {
		// EOF
		writeUint32(mod, nreadPtr, 0)
		return 0
	}

	if !writeBytes(mod, bufPtr, buf[:n]) {
		return errnoEFAULT
	}
	if !writeUint32(mod, nreadPtr, uint32(n)) {
		return errnoEFAULT
	}
	return 0
}

// sockWrite implements non-blocking write to a socket.
// Returns number of bytes written or EAGAIN if buffer is full.
func sockWrite(ctx context.Context, mod api.Module, fd int32, bufPtr, bufLen, nwrittenPtr uint32) uint32 {
	ft := getFDTable(ctx)
	entry := ft.get(fd)
	if entry == nil {
		return errnoEBADF
	}

	buf, ok := readBytes(mod, bufPtr, bufLen)
	if !ok {
		return errnoEFAULT
	}
	n, err := socketSend(entry.osFD, buf)
	if debugNet {
		if err == nil {
			fmt.Fprintf(os.Stderr, "[runtime-debug] sockWrite: guestFD=%d n=%d\n", fd, n)
		} else {
			fmt.Fprintf(os.Stderr, "[runtime-debug] sockWrite: FAILED guestFD=%d err=%v\n", fd, err)
		}
	}
	if err != nil {
		if isErrWouldBlock(err) {
			yieldOnEAGAIN()
			writeUint32(mod, nwrittenPtr, 0)
			return errnoEAGAIN
		}
		return errnoFromError(err)
	}

	if !writeUint32(mod, nwrittenPtr, uint32(n)) {
		return errnoEFAULT
	}
	return 0
}

// sockClose implements the wasmforge.sock_close host function.
func sockClose(ctx context.Context, mod api.Module, fd int32) uint32 {
	ft := getFDTable(ctx)
	if err := ft.remove(fd); err != nil {
		return errnoFromError(err)
	}
	return 0
}
