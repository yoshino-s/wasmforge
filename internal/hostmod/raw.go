package hostmod

import (
	"context"
	"syscall"

	"github.com/tetratelabs/wazero/api"
)

// rawSockOpen implements the wasmforge.raw_sock_open host function.
// Creates a raw socket (SOCK_RAW). Requires CAP_NET_RAW or root on Linux.
func rawSockOpen(ctx context.Context, mod api.Module, domain, protocol int32, fdPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg != nil && !cfg.RawSockets {
		return errnoEPERM
	}

	ft := getFDTable(ctx)

	osFD, err := syscall.Socket(int(domain), syscall.SOCK_RAW, int(protocol))
	if err != nil {
		return errnoFromError(err)
	}

	if err := setSocketNonblock(osFD); err != nil {
		socketClose(osFD)
		return errnoFromError(err)
	}

	guestFD := ft.register(osFD, int(domain), syscall.SOCK_RAW, int(protocol))
	if !writeInt32(mod, fdPtr, guestFD) {
		ft.remove(guestFD)
		return errnoEFAULT
	}
	return 0
}

// rawSockSend implements the wasmforge.raw_sock_send host function.
func rawSockSend(ctx context.Context, mod api.Module, fd int32, bufPtr, bufLen uint32, flags int32, destPtr, destLen uint32, nsentPtr uint32) uint32 {
	ft := getFDTable(ctx)
	entry := ft.get(fd)
	if entry == nil {
		return errnoEBADF
	}

	buf, ok := readBytes(mod, bufPtr, bufLen)
	if !ok {
		return errnoEFAULT
	}

	destBuf, ok := readBytes(mod, destPtr, destLen)
	if !ok {
		return errnoEFAULT
	}

	sa, err := bytesToSockaddr(destBuf)
	if err != nil {
		return errnoEINVAL
	}

	if err := syscall.Sendto(entry.osFD, buf, int(flags), sa); err != nil {
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

// rawSockRecv implements the wasmforge.raw_sock_recv host function.
func rawSockRecv(ctx context.Context, mod api.Module, fd int32, bufPtr, bufLen uint32, flags int32, srcPtr, srcCap, srcLenPtr, nrecvPtr uint32) uint32 {
	ft := getFDTable(ctx)
	entry := ft.get(fd)
	if entry == nil {
		return errnoEBADF
	}

	buf := make([]byte, bufLen)
	n, from, err := syscall.Recvfrom(entry.osFD, buf, int(flags))
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

	if srcPtr != 0 && srcLenPtr != 0 && from != nil {
		addrBuf, err := sockaddrToBytes(from)
		if err == nil && uint32(len(addrBuf)) <= srcCap {
			writeBytes(mod, srcPtr, addrBuf)
			writeUint32(mod, srcLenPtr, uint32(len(addrBuf)))
		}
	}

	return 0
}
