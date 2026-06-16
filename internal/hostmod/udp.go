package hostmod

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

// sockSendto implements the wasmforge.sock_sendto host function.
// Sends data to a specific address (used for UDP).
func sockSendto(ctx context.Context, mod api.Module, fd int32, bufPtr, bufLen uint32, flags int32, addrPtr, addrLen uint32, nsentPtr uint32) uint32 {
	ft := getFDTable(ctx)
	entry := ft.get(fd)
	if entry == nil {
		return errnoEBADF
	}

	buf, ok := readBytes(mod, bufPtr, bufLen)
	if !ok {
		return errnoEFAULT
	}

	addrBuf, ok := readBytes(mod, addrPtr, addrLen)
	if !ok {
		return errnoEFAULT
	}

	sa, err := bytesToSockaddr(addrBuf)
	if err != nil {
		return errnoEINVAL
	}

	if err := socketSendTo(entry.osFD, buf, int(flags), sa); err != nil {
		if isErrWouldBlock(err) {
			yieldOnEAGAIN()
			writeUint32(mod, nsentPtr, 0)
			return errnoEAGAIN
		}
		return errnoFromError(err)
	}

	if !writeUint32(mod, nsentPtr, bufLen) {
		return errnoEFAULT
	}
	return 0
}

// sockRecvfrom implements the wasmforge.sock_recvfrom host function.
// Receives data and returns the sender's address (used for UDP).
func sockRecvfrom(ctx context.Context, mod api.Module, fd int32, bufPtr, bufLen uint32, flags int32, addrPtr, addrCap, addrLenPtr, nrecvPtr uint32) uint32 {
	ft := getFDTable(ctx)
	entry := ft.get(fd)
	if entry == nil {
		return errnoEBADF
	}

	buf := make([]byte, bufLen)
	n, from, err := socketRecvFrom(entry.osFD, buf, int(flags))
	if err != nil {
		if isErrWouldBlock(err) {
			yieldOnEAGAIN()
			writeUint32(mod, nrecvPtr, 0)
			return errnoEAGAIN
		}
		return errnoFromError(err)
	}

	if n > 0 {
		if !writeBytes(mod, bufPtr, buf[:n]) {
			return errnoEFAULT
		}
	}
	if !writeUint32(mod, nrecvPtr, uint32(n)) {
		return errnoEFAULT
	}

	// Write sender address if requested.
	if addrPtr != 0 && addrLenPtr != 0 && from != nil {
		addrBuf, err := sockaddrToBytes(from)
		if err == nil && uint32(len(addrBuf)) <= addrCap {
			writeBytes(mod, addrPtr, addrBuf)
			writeUint32(mod, addrLenPtr, uint32(len(addrBuf)))
		}
	}

	return 0
}
