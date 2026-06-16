package hostmod

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"github.com/tetratelabs/wazero/api"
)

// sockOpen implements the wasmforge.sock_open host function.
// Creates a new socket and registers it in the FD table.
func sockOpen(ctx context.Context, mod api.Module, domain, socktype, protocol int32, fdPtr uint32) uint32 {
	ft := getFDTable(ctx)

	osFD, err := syscall.Socket(translateDomain(int(domain)), int(socktype), int(protocol))
	if err != nil {
		return errnoFromError(err)
	}

	// Set non-blocking.
	if err := setSocketNonblock(osFD); err != nil {
		socketClose(osFD)
		return errnoFromError(err)
	}

	guestFD := ft.register(osFD, int(domain), int(socktype), int(protocol))
	if debugNet {
		fmt.Fprintf(os.Stderr, "[runtime-debug] sockOpen: domain=%d type=%d proto=%d osFD=%d guestFD=%d\n",
			domain, socktype, protocol, osFD, guestFD)
	}
	if !writeInt32(mod, fdPtr, guestFD) {
		ft.remove(guestFD)
		return errnoEFAULT
	}
	return 0
}

// sockBind implements the wasmforge.sock_bind host function.
func sockBind(ctx context.Context, mod api.Module, fd int32, addrPtr, addrLen uint32) uint32 {
	ft := getFDTable(ctx)
	entry := ft.get(fd)
	if entry == nil {
		return errnoEBADF
	}

	addrBuf, ok := readBytes(mod, addrPtr, addrLen)
	if !ok {
		return errnoEFAULT
	}

	sa, err := bytesToSockaddr(addrBuf)
	if err != nil {
		return errnoEINVAL
	}

	if err := syscall.Bind(entry.osFD, sa); err != nil {
		return errnoFromError(err)
	}

	entry.localAddr = sockaddrToNetAddr(sa, entry.sockType)
	return 0
}

// sockListen implements the wasmforge.sock_listen host function.
func sockListen(ctx context.Context, mod api.Module, fd, backlog int32) uint32 {
	ft := getFDTable(ctx)
	entry := ft.get(fd)
	if entry == nil {
		return errnoEBADF
	}

	if err := syscall.Listen(entry.osFD, int(backlog)); err != nil {
		return errnoFromError(err)
	}
	return 0
}

// sockConnect implements the wasmforge.sock_connect host function.
// Returns 0 on success, EINPROGRESS if non-blocking connect is in progress.
func sockConnect(ctx context.Context, mod api.Module, fd int32, addrPtr, addrLen uint32) uint32 {
	ft := getFDTable(ctx)
	entry := ft.get(fd)
	if entry == nil {
		return errnoEBADF
	}

	addrBuf, ok := readBytes(mod, addrPtr, addrLen)
	if !ok {
		return errnoEFAULT
	}

	sa, err := bytesToSockaddr(addrBuf)
	if err != nil {
		return errnoEINVAL
	}

	err = syscall.Connect(entry.osFD, sa)
	if debugNet {
		fmt.Fprintf(os.Stderr, "[runtime-debug] sockConnect: guestFD=%d osFD=%d err=%v\n",
			fd, entry.osFD, err)
	}
	if err != nil {
		// EINPROGRESS is expected for non-blocking connect.
		// On Windows, raw Winsock returns WSAEWOULDBLOCK (10035) instead
		// of EINPROGRESS, and Go's synthetic constants don't match raw
		// values. isErrConnectInProgress handles both.
		if isErrConnectInProgress(err) {
			// Wait for the connection to actually complete. On Windows,
			// getsockopt(SO_ERROR) returns 0 while connecting (unlike
			// Linux), so the guest-side polling detects "connected" too
			// early. waitConnectComplete uses select() to reliably wait
			// for write-readiness. On Unix, this is a no-op.
			if waitErr := waitConnectComplete(entry.osFD); waitErr != nil {
				return errnoFromError(waitErr)
			}
			entry.remoteAddr = sockaddrToNetAddr(sa, entry.sockType)
			// On Unix, SO_ERROR polling works correctly so the guest
			// must still poll. On Windows, select() already confirmed
			// the connection is established.
			if connectNeedsPolling() {
				return errnoEINPROGRESS
			}
			return 0
		}
		return errnoFromError(err)
	}

	entry.remoteAddr = sockaddrToNetAddr(sa, entry.sockType)
	return 0
}

// sockAccept implements the wasmforge.sock_accept host function.
func sockAccept(ctx context.Context, mod api.Module, fd, flags int32, newFDPtr, addrPtr, addrLenPtr uint32) uint32 {
	ft := getFDTable(ctx)
	entry := ft.get(fd)
	if entry == nil {
		return errnoEBADF
	}

	nfd, sa, err := socketAccept(entry.osFD)
	if err != nil {
		if isErrWouldBlock(err) {
			yieldOnEAGAIN()
		} else if debugNet {
			fmt.Fprintf(os.Stderr, "[runtime-debug] sockAccept: guestFD=%d err=%v\n", fd, err)
		}
		return errnoFromError(err)
	}
	if debugNet {
		fmt.Fprintf(os.Stderr, "[runtime-debug] sockAccept: guestFD=%d newOsFD=%d\n", fd, nfd)
	}

	// Set the new socket to non-blocking.
	if err := setSocketNonblock(nfd); err != nil {
		socketClose(nfd)
		return errnoFromError(err)
	}

	guestFD := ft.register(nfd, entry.family, entry.sockType, entry.protocol)

	// Update the new entry's addresses.
	newEntry := ft.get(guestFD)
	if newEntry != nil {
		newEntry.localAddr = entry.localAddr
		newEntry.remoteAddr = sockaddrToNetAddr(sa, entry.sockType)
	}

	if !writeInt32(mod, newFDPtr, guestFD) {
		ft.remove(guestFD)
		return errnoEFAULT
	}

	// Write peer address if requested.
	if addrPtr != 0 && addrLenPtr != 0 {
		addrBuf, err := sockaddrToBytes(sa)
		if err == nil {
			capVal, ok := readUint32(mod, addrLenPtr)
			if ok && uint32(len(addrBuf)) <= capVal {
				writeBytes(mod, addrPtr, addrBuf)
				writeUint32(mod, addrLenPtr, uint32(len(addrBuf)))
			}
		}
	}

	return 0
}

// sockShutdown implements the wasmforge.sock_shutdown host function.
func sockShutdown(ctx context.Context, mod api.Module, fd, how int32) uint32 {
	ft := getFDTable(ctx)
	entry := ft.get(fd)
	if entry == nil {
		return errnoEBADF
	}

	if err := syscall.Shutdown(entry.osFD, int(how)); err != nil {
		return errnoFromError(err)
	}
	return 0
}
