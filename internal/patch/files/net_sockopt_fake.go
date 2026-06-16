// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// WasmForge replacement for net/sockopt_fake.go
// Provides real socket option support via wasmforge host functions.

//go:build js || wasip1

package net

import "syscall"

func setDefaultSockopts(s, family, sotype int, ipv6only bool) error {
	if family == syscall.AF_INET6 && sotype != syscall.SOCK_RAW {
		// Set IPV6_V6ONLY for IPv6 sockets.
		v := 0
		if ipv6only {
			v = 1
		}
		syscall.SetsockoptInt(s, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, v)
	}
	return nil
}

func setDefaultListenerSockopts(s int) error {
	// Set SO_REUSEADDR for listener sockets.
	syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	return nil
}

func setDefaultMulticastSockopts(s int) error {
	return nil
}

func setReadBuffer(fd *netFD, bytes int) error {
	if fd.fakeNetFD != nil {
		return fd.fakeNetFD.setReadBuffer(bytes)
	}
	return syscall.ENOPROTOOPT
}

func setWriteBuffer(fd *netFD, bytes int) error {
	if fd.fakeNetFD != nil {
		return fd.fakeNetFD.setWriteBuffer(bytes)
	}
	return syscall.ENOPROTOOPT
}

func setKeepAlive(fd *netFD, keepalive bool) error {
	if fd.fakeNetFD == nil {
		return syscall.ENOPROTOOPT
	}
	v := 0
	if keepalive {
		v = 1
	}
	return syscall.SetsockoptInt(int(fd.fakeNetFD.socketFD), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, v)
}

func setLinger(fd *netFD, sec int) error {
	if fd.fakeNetFD != nil {
		return fd.fakeNetFD.setLinger(sec)
	}
	return syscall.ENOPROTOOPT
}
