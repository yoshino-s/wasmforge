// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// WasmForge replacement for net/net_fake.go
// Replaces fake in-memory networking with real host-proxied networking
// via wasmforge host functions.

//go:build js || wasip1

package net

import (
	"context"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const defaultBuffer = 65535

// socket creates a real network socket via wasmforge host functions.
func socket(ctx context.Context, net string, family, sotype, proto int, ipv6only bool, laddr, raddr sockaddr, ctrlCtxFn func(context.Context, string, string, syscall.RawConn) error) (*netFD, error) {
	if raddr != nil && ctrlCtxFn != nil {
		return nil, os.NewSyscallError("socket", syscall.ENOTSUP)
	}
	switch sotype {
	case syscall.SOCK_STREAM, syscall.SOCK_SEQPACKET, syscall.SOCK_DGRAM:
	default:
		return nil, os.NewSyscallError("socket", syscall.ENOTSUP)
	}

	// Create a real socket via the host.
	sfd, err := syscall.Socket(family, sotype, proto)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}

	fd := &netFD{
		family: family,
		sotype: sotype,
		net:    net,
	}
	ffd := newFakeNetFD(fd, int32(sfd))
	fd.fakeNetFD = ffd

	if raddr == nil {
		// Listener or PacketConn.
		if err := ffd.listen(laddr); err != nil {
			ffd.Close()
			return nil, err
		}
		return fd, nil
	}

	// Dialer.
	if err := ffd.connect(ctx, laddr, raddr); err != nil {
		ffd.Close()
		return nil, err
	}
	return fd, nil
}

func validateResolvedAddr(net string, family int, sa sockaddr) error {
	validateIP := func(ip IP) error {
		switch family {
		case syscall.AF_INET:
			if len(ip) != 4 {
				return &AddrError{
					Err:  "non-IPv4 address",
					Addr: ip.String(),
				}
			}
		case syscall.AF_INET6:
			if len(ip) != 16 {
				return &AddrError{
					Err:  "non-IPv6 address",
					Addr: ip.String(),
				}
			}
		default:
			panic("net: unexpected address family in validateResolvedAddr")
		}
		return nil
	}

	switch net {
	case "tcp", "tcp4", "tcp6":
		sa, ok := sa.(*TCPAddr)
		if !ok {
			return &AddrError{
				Err:  "non-TCP address for " + net + " network",
				Addr: sa.String(),
			}
		}
		if err := validateIP(sa.IP); err != nil {
			return err
		}
		if sa.Port <= 0 || sa.Port >= 1<<16 {
			return &AddrError{
				Err:  "port out of range",
				Addr: sa.String(),
			}
		}
		return nil

	case "udp", "udp4", "udp6":
		sa, ok := sa.(*UDPAddr)
		if !ok {
			return &AddrError{
				Err:  "non-UDP address for " + net + " network",
				Addr: sa.String(),
			}
		}
		if err := validateIP(sa.IP); err != nil {
			return err
		}
		if sa.Port <= 0 || sa.Port >= 1<<16 {
			return &AddrError{
				Err:  "port out of range",
				Addr: sa.String(),
			}
		}
		return nil

	case "unix", "unixgram", "unixpacket":
		sa, ok := sa.(*UnixAddr)
		if !ok {
			return &AddrError{
				Err:  "non-Unix address for " + net + " network",
				Addr: sa.String(),
			}
		}
		if sa.Name != "" {
			i := len(sa.Name) - 1
			for i > 0 && !os.IsPathSeparator(sa.Name[i]) {
				i--
			}
			for i > 0 && os.IsPathSeparator(sa.Name[i]) {
				i--
			}
			if i <= 0 {
				return &AddrError{
					Err:  "unix socket name missing path component",
					Addr: sa.Name,
				}
			}
			if _, err := os.Stat(sa.Name[:i+1]); err != nil {
				return &AddrError{
					Err:  err.Error(),
					Addr: sa.Name,
				}
			}
		}
		return nil

	default:
		return &AddrError{
			Err:  syscall.EAFNOSUPPORT.Error(),
			Addr: sa.String(),
		}
	}
}

func matchIPFamily(family int, addr sockaddr) sockaddr {
	convertIP := func(ip IP) IP {
		switch family {
		case syscall.AF_INET:
			return ip.To4()
		case syscall.AF_INET6:
			return ip.To16()
		default:
			return ip
		}
	}

	switch addr := addr.(type) {
	case *TCPAddr:
		ip := convertIP(addr.IP)
		if ip == nil || len(ip) == len(addr.IP) {
			return addr
		}
		return &TCPAddr{IP: ip, Port: addr.Port, Zone: addr.Zone}
	case *UDPAddr:
		ip := convertIP(addr.IP)
		if ip == nil || len(ip) == len(addr.IP) {
			return addr
		}
		return &UDPAddr{IP: ip, Port: addr.Port, Zone: addr.Zone}
	default:
		return addr
	}
}

// fakeNetFD wraps a real host socket FD with non-blocking I/O
// and cooperative scheduling.
type fakeNetFD struct {
	fd       *netFD
	socketFD int32 // host socket FD (>= 10000)

	readDeadline  atomic.Pointer[deadlineTimer]
	writeDeadline atomic.Pointer[deadlineTimer]

	// For listeners: incoming connections.
	incoming   chan *netFD
	listenOnce sync.Once

	closed atomic.Bool
}

func newFakeNetFD(fd *netFD, socketFD int32) *fakeNetFD {
	ffd := &fakeNetFD{
		fd:       fd,
		socketFD: socketFD,
	}
	ffd.readDeadline.Store(newDeadlineTimer(noDeadline))
	ffd.writeDeadline.Store(newDeadlineTimer(noDeadline))
	return ffd
}

// Read performs a non-blocking read with cooperative scheduling.
func (ffd *fakeNetFD) Read(p []byte) (n int, err error) {
	if ffd.closed.Load() {
		return 0, ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	deadline := ffd.readDeadline.Load()
	for {
		n, errno := syscall.WasmForgeRead(ffd.socketFD, p)
		if errno == 0 {
			if n == 0 {
				return 0, io.EOF
			}
			return n, nil
		}
		if errno != 6 { // not EAGAIN
			return 0, os.NewSyscallError("read", syscall.Errno(errno))
		}
		// EAGAIN: yield and retry.
		select {
		case <-deadline.expired:
			return 0, os.ErrDeadlineExceeded
		default:
			runtime.Gosched()
		}
	}
}

// Write performs a non-blocking write with cooperative scheduling.
func (ffd *fakeNetFD) Write(p []byte) (nn int, err error) {
	if ffd.closed.Load() {
		return 0, ErrClosed
	}
	deadline := ffd.writeDeadline.Load()
	for len(p) > 0 {
		n, errno := syscall.WasmForgeWrite(ffd.socketFD, p)
		if errno == 0 {
			nn += n
			p = p[n:]
			continue
		}
		if errno != 6 { // not EAGAIN
			return nn, os.NewSyscallError("write", syscall.Errno(errno))
		}
		// EAGAIN: yield and retry.
		select {
		case <-deadline.expired:
			return nn, os.ErrDeadlineExceeded
		default:
			runtime.Gosched()
		}
	}
	return nn, nil
}

func (ffd *fakeNetFD) Close() error {
	if ffd.closed.Swap(true) {
		return ErrClosed
	}
	ffd.readDeadline.Load().Reset(noDeadline)
	ffd.writeDeadline.Load().Reset(noDeadline)

	if ffd.incoming != nil {
		close(ffd.incoming)
		// Drain and close any pending connections.
		for peer := range ffd.incoming {
			if peer != nil && peer.fakeNetFD != nil {
				peer.fakeNetFD.Close()
			}
		}
	}

	return syscall.WasmForgeClose(ffd.socketFD)
}

func (ffd *fakeNetFD) closeRead() error {
	return syscall.Shutdown(int(ffd.socketFD), syscall.SHUT_RD)
}

func (ffd *fakeNetFD) closeWrite() error {
	return syscall.Shutdown(int(ffd.socketFD), syscall.SHUT_WR)
}

func (ffd *fakeNetFD) accept(laddr Addr) (*netFD, error) {
	if ffd.incoming == nil {
		return nil, os.NewSyscallError("accept", syscall.EINVAL)
	}
	deadline := ffd.readDeadline.Load()
	for {
		select {
		case <-deadline.expired:
			return nil, os.ErrDeadlineExceeded
		case peer, ok := <-ffd.incoming:
			if !ok {
				return nil, ErrClosed
			}
			return peer, nil
		default:
		}

		// Try non-blocking accept.
		newfd, sa, err := syscall.Accept(int(ffd.socketFD))
		if err != nil {
			if err == syscall.EAGAIN {
				select {
				case <-deadline.expired:
					return nil, os.ErrDeadlineExceeded
				default:
					runtime.Gosched()
					continue
				}
			}
			return nil, os.NewSyscallError("accept", err)
		}

		peer := &netFD{
			family:      ffd.fd.family,
			sotype:      ffd.fd.sotype,
			net:         ffd.fd.net,
			isConnected: true,
		}
		peerFFD := newFakeNetFD(peer, int32(newfd))
		peer.fakeNetFD = peerFFD

		peer.laddr = laddr
		if sa != nil {
			peer.raddr = sockaddrToAddr(ffd.fd.net, sa)
		}

		return peer, nil
	}
}

func (ffd *fakeNetFD) SetDeadline(t time.Time) error {
	err1 := ffd.SetReadDeadline(t)
	err2 := ffd.SetWriteDeadline(t)
	if err1 != nil {
		return err1
	}
	return err2
}

func (ffd *fakeNetFD) SetReadDeadline(t time.Time) error {
	dt := ffd.readDeadline.Load()
	if !dt.Reset(t) {
		ffd.readDeadline.Store(newDeadlineTimer(t))
	}
	return nil
}

func (ffd *fakeNetFD) SetWriteDeadline(t time.Time) error {
	dt := ffd.writeDeadline.Load()
	if !dt.Reset(t) {
		ffd.writeDeadline.Store(newDeadlineTimer(t))
	}
	return nil
}

// listen binds and listens on the socket.
func (ffd *fakeNetFD) listen(laddr sockaddr) error {
	if laddr != nil {
		laddr = matchIPFamily(ffd.fd.family, laddr)
		sa, err := laddr.sockaddr(ffd.fd.family)
		if err != nil {
			return &AddrError{Err: err.Error(), Addr: laddr.String()}
		}
		if sa != nil {
			if err := syscall.Bind(int(ffd.socketFD), sa); err != nil {
				return os.NewSyscallError("bind", err)
			}
		}
	}

	// For stream sockets, set up listening.
	switch ffd.fd.sotype {
	case syscall.SOCK_STREAM, syscall.SOCK_SEQPACKET:
		if err := syscall.Listen(int(ffd.socketFD), syscall.SOMAXCONN); err != nil {
			return os.NewSyscallError("listen", err)
		}
		ffd.incoming = make(chan *netFD, syscall.SOMAXCONN)
	case syscall.SOCK_DGRAM:
		// UDP: no listen needed, just bound.
	}

	// Set local address from the OS.
	localSA := syscall.WasmForgeGetsockname(ffd.socketFD)
	if localSA != nil {
		ffd.fd.laddr = sockaddrToAddr(ffd.fd.net, localSA)
	} else if laddr != nil {
		ffd.fd.laddr = laddr
	} else {
		ffd.fd.laddr = defaultAddr(ffd.fd.net)
	}

	return nil
}

// connect performs a non-blocking connect with polling.
func (ffd *fakeNetFD) connect(ctx context.Context, laddr, raddr sockaddr) error {
	raddr = matchIPFamily(ffd.fd.family, raddr)

	if laddr != nil {
		sa, err := laddr.sockaddr(ffd.fd.family)
		if err != nil {
			return &AddrError{Err: err.Error(), Addr: laddr.String()}
		}
		if sa != nil {
			if err := syscall.Bind(int(ffd.socketFD), sa); err != nil {
				return os.NewSyscallError("bind", err)
			}
		}
	}

	remoteSA, err := raddr.sockaddr(ffd.fd.family)
	if err != nil {
		return &AddrError{Err: err.Error(), Addr: raddr.String()}
	}

	err = syscall.Connect(int(ffd.socketFD), remoteSA)
	if err != nil && err != syscall.EINPROGRESS && err != syscall.EALREADY {
		return os.NewSyscallError("connect", err)
	}

	// If EINPROGRESS, poll until connected.
	if err == syscall.EINPROGRESS || err == syscall.EALREADY {
		for {
			if ctx.Err() != nil {
				return os.NewSyscallError("connect", syscall.ETIMEDOUT)
			}
			// Check SO_ERROR to see if connect completed.
			val, gerr := syscall.GetsockoptInt(int(ffd.socketFD), syscall.SOL_SOCKET, syscall.SO_ERROR)
			if gerr != nil {
				runtime.Gosched()
				continue
			}
			if val == 0 {
				break // Connected!
			}
			if syscall.Errno(val) != syscall.EINPROGRESS {
				return os.NewSyscallError("connect", syscall.Errno(val))
			}
			runtime.Gosched()
		}
	}

	ffd.fd.isConnected = true
	ffd.fd.raddr = raddr

	// Set local address.
	localSA := syscall.WasmForgeGetsockname(ffd.socketFD)
	if localSA != nil {
		ffd.fd.laddr = sockaddrToAddr(ffd.fd.net, localSA)
	} else if laddr != nil {
		ffd.fd.laddr = laddr
	} else {
		ffd.fd.laddr = defaultAddr(ffd.fd.net)
	}

	return nil
}

// Datagram (UDP) methods.

func (ffd *fakeNetFD) readFrom(p []byte) (n int, sa syscall.Sockaddr, err error) {
	deadline := ffd.readDeadline.Load()
	for {
		n, from, err := syscall.Recvfrom(int(ffd.socketFD), p, 0)
		if err == nil {
			return n, from, nil
		}
		if err != syscall.EAGAIN {
			return 0, nil, os.NewSyscallError("recvfrom", err)
		}
		select {
		case <-deadline.expired:
			return 0, nil, os.ErrDeadlineExceeded
		default:
			runtime.Gosched()
		}
	}
}

func (ffd *fakeNetFD) readFromInet4(p []byte, sa *syscall.SockaddrInet4) (n int, err error) {
	n, from, err := ffd.readFrom(p)
	if err != nil {
		return n, err
	}
	if from != nil {
		if sa4, ok := from.(*syscall.SockaddrInet4); ok {
			*sa = *sa4
		}
	}
	return n, nil
}

func (ffd *fakeNetFD) readFromInet6(p []byte, sa *syscall.SockaddrInet6) (n int, err error) {
	n, from, err := ffd.readFrom(p)
	if err != nil {
		return n, err
	}
	if from != nil {
		if sa6, ok := from.(*syscall.SockaddrInet6); ok {
			*sa = *sa6
		}
	}
	return n, nil
}

func (ffd *fakeNetFD) readMsg(p []byte, oob []byte, flags int) (n, oobn, retflags int, sa syscall.Sockaddr, err error) {
	if flags != 0 {
		return 0, 0, 0, nil, os.NewSyscallError("readMsg", syscall.ENOTSUP)
	}
	n, sa, err = ffd.readFrom(p)
	return n, 0, 0, sa, err
}

func (ffd *fakeNetFD) readMsgInet4(p []byte, oob []byte, flags int, sa *syscall.SockaddrInet4) (n, oobn, retflags int, err error) {
	if flags != 0 {
		return 0, 0, 0, os.NewSyscallError("readMsgInet4", syscall.ENOTSUP)
	}
	n, err = ffd.readFromInet4(p, sa)
	return n, 0, 0, err
}

func (ffd *fakeNetFD) readMsgInet6(p []byte, oob []byte, flags int, sa *syscall.SockaddrInet6) (n, oobn, retflags int, err error) {
	if flags != 0 {
		return 0, 0, 0, os.NewSyscallError("readMsgInet6", syscall.ENOTSUP)
	}
	n, err = ffd.readFromInet6(p, sa)
	return n, 0, 0, err
}

func (ffd *fakeNetFD) writeTo(p []byte, sa syscall.Sockaddr) (n int, err error) {
	deadline := ffd.writeDeadline.Load()
	for {
		err := syscall.Sendto(int(ffd.socketFD), p, 0, sa)
		if err == nil {
			return len(p), nil
		}
		if err != syscall.EAGAIN {
			return 0, os.NewSyscallError("sendto", err)
		}
		select {
		case <-deadline.expired:
			return 0, os.ErrDeadlineExceeded
		default:
			runtime.Gosched()
		}
	}
}

func (ffd *fakeNetFD) writeToInet4(p []byte, sa *syscall.SockaddrInet4) (n int, err error) {
	return ffd.writeTo(p, sa)
}

func (ffd *fakeNetFD) writeToInet6(p []byte, sa *syscall.SockaddrInet6) (n int, err error) {
	return ffd.writeTo(p, sa)
}

func (ffd *fakeNetFD) writeMsg(p []byte, oob []byte, sa syscall.Sockaddr) (n int, oobn int, err error) {
	if len(oob) > 0 {
		return 0, 0, os.NewSyscallError("writeMsg", syscall.ENOTSUP)
	}
	n, err = ffd.writeTo(p, sa)
	return n, 0, err
}

func (ffd *fakeNetFD) writeMsgInet4(p []byte, oob []byte, sa *syscall.SockaddrInet4) (n int, oobn int, err error) {
	return ffd.writeMsg(p, oob, sa)
}

func (ffd *fakeNetFD) writeMsgInet6(p []byte, oob []byte, sa *syscall.SockaddrInet6) (n int, oobn int, err error) {
	return ffd.writeMsg(p, oob, sa)
}

func (ffd *fakeNetFD) dup() (f *os.File, err error) {
	return nil, os.NewSyscallError("dup", syscall.ENOSYS)
}

func (ffd *fakeNetFD) setReadBuffer(bytes int) error {
	return syscall.SetsockoptInt(int(ffd.socketFD), syscall.SOL_SOCKET, syscall.SO_RCVBUF, bytes)
}

func (ffd *fakeNetFD) setWriteBuffer(bytes int) error {
	return syscall.SetsockoptInt(int(ffd.socketFD), syscall.SOL_SOCKET, syscall.SO_SNDBUF, bytes)
}

func (ffd *fakeNetFD) setLinger(sec int) error {
	// Linger not directly supported via simple int option, ignore gracefully.
	return nil
}

// Helper functions.

func sysSocket(family, sotype, proto int) (int, error) {
	return 0, os.NewSyscallError("sysSocket", syscall.ENOSYS)
}

func defaultAddr(net string) Addr {
	switch {
	case len(net) >= 3 && net[:3] == "tcp":
		return &TCPAddr{}
	case len(net) >= 3 && net[:3] == "udp":
		return &UDPAddr{}
	default:
		return unknownAddr{}
	}
}

func sockaddrToAddr(net string, sa syscall.Sockaddr) Addr {
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		ip := IP(sa.Addr[:])
		switch {
		case len(net) >= 3 && net[:3] == "tcp":
			return &TCPAddr{IP: ip, Port: sa.Port}
		case len(net) >= 3 && net[:3] == "udp":
			return &UDPAddr{IP: ip, Port: sa.Port}
		}
	case *syscall.SockaddrInet6:
		ip := IP(sa.Addr[:])
		switch {
		case len(net) >= 3 && net[:3] == "tcp":
			return &TCPAddr{IP: ip, Port: sa.Port}
		case len(net) >= 3 && net[:3] == "udp":
			return &UDPAddr{IP: ip, Port: sa.Port}
		}
	}
	return unknownAddr{}
}

// deadlineTimer provides a timer-based deadline mechanism.
type deadlineTimer struct {
	timer   chan *time.Timer
	expired chan struct{}
}

func newDeadlineTimer(deadline time.Time) *deadlineTimer {
	dt := &deadlineTimer{
		timer:   make(chan *time.Timer, 1),
		expired: make(chan struct{}),
	}
	dt.timer <- nil
	dt.Reset(deadline)
	return dt
}

func (dt *deadlineTimer) Reset(deadline time.Time) bool {
	timer := <-dt.timer
	defer func() { dt.timer <- timer }()

	if deadline.Equal(noDeadline) {
		if timer != nil && timer.Stop() {
			timer = nil
		}
		return timer == nil
	}

	d := time.Until(deadline)
	if d < 0 {
		defer func() { <-dt.expired }()
	}

	if timer == nil {
		timer = time.AfterFunc(d, func() { close(dt.expired) })
		return true
	}
	if !timer.Stop() {
		return false
	}
	timer.Reset(d)
	return true
}
