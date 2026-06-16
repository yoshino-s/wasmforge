package hostmod

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"

	"github.com/tetratelabs/wazero/api"
)

// sockSetsockopt implements the wasmforge.sock_setsockopt host function.
func sockSetsockopt(ctx context.Context, mod api.Module, fd, level, opt int32, valPtr, valLen uint32) uint32 {
	ft := getFDTable(ctx)
	entry := ft.get(fd)
	if entry == nil {
		return errnoEBADF
	}

	valBuf, ok := readBytes(mod, valPtr, valLen)
	if !ok {
		return errnoEFAULT
	}

	// We support integer socket options (4 bytes).
	if valLen != 4 {
		return errnoEINVAL
	}
	val := int(binary.LittleEndian.Uint32(valBuf))

	hostLevel := translateSockoptLevel(int(level))
	hostOpt := translateSockoptName(int(level), int(opt))
	if err := syscall.SetsockoptInt(entry.osFD, hostLevel, hostOpt, val); err != nil {
		return errnoFromError(err)
	}
	return 0
}

// sockGetsockopt implements the wasmforge.sock_getsockopt host function.
func sockGetsockopt(ctx context.Context, mod api.Module, fd, level, opt int32, valPtr, valLenPtr uint32) uint32 {
	ft := getFDTable(ctx)
	entry := ft.get(fd)
	if entry == nil {
		return errnoEBADF
	}

	hostLevel := translateSockoptLevel(int(level))
	hostOpt := translateSockoptName(int(level), int(opt))
	val, err := syscall.GetsockoptInt(entry.osFD, hostLevel, hostOpt)
	if debugNet {
		fmt.Fprintf(os.Stderr, "[runtime-debug] getsockopt: guestFD=%d level=%d→%d opt=%d→%d val=%d err=%v\n",
			fd, level, hostLevel, opt, hostOpt, val, err)
	}
	if err != nil {
		return errnoFromError(err)
	}

	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(val))
	if !writeBytes(mod, valPtr, buf) {
		return errnoEFAULT
	}
	if !writeUint32(mod, valLenPtr, 4) {
		return errnoEFAULT
	}
	return 0
}

// sockGetpeername implements the wasmforge.sock_getpeername host function.
func sockGetpeername(ctx context.Context, mod api.Module, fd int32, addrPtr, addrLenPtr uint32) uint32 {
	ft := getFDTable(ctx)
	entry := ft.get(fd)
	if entry == nil {
		return errnoEBADF
	}

	sa, err := syscall.Getpeername(entry.osFD)
	if err != nil {
		return errnoFromError(err)
	}

	addrBuf, err := sockaddrToBytes(sa)
	if err != nil {
		return errnoEINVAL
	}

	capVal, ok := readUint32(mod, addrLenPtr)
	if !ok {
		return errnoEFAULT
	}
	if uint32(len(addrBuf)) > capVal {
		return errnoEINVAL
	}

	if !writeBytes(mod, addrPtr, addrBuf) {
		return errnoEFAULT
	}
	if !writeUint32(mod, addrLenPtr, uint32(len(addrBuf))) {
		return errnoEFAULT
	}
	return 0
}

// sockGetsockname implements the wasmforge.sock_getsockname host function.
func sockGetsockname(ctx context.Context, mod api.Module, fd int32, addrPtr, addrLenPtr uint32) uint32 {
	ft := getFDTable(ctx)
	entry := ft.get(fd)
	if entry == nil {
		return errnoEBADF
	}

	sa, err := syscall.Getsockname(entry.osFD)
	if err != nil {
		return errnoFromError(err)
	}

	addrBuf, err := sockaddrToBytes(sa)
	if err != nil {
		return errnoEINVAL
	}

	capVal, ok := readUint32(mod, addrLenPtr)
	if !ok {
		return errnoEFAULT
	}
	if uint32(len(addrBuf)) > capVal {
		return errnoEINVAL
	}

	if !writeBytes(mod, addrPtr, addrBuf) {
		return errnoEFAULT
	}
	if !writeUint32(mod, addrLenPtr, uint32(len(addrBuf))) {
		return errnoEFAULT
	}
	return 0
}
