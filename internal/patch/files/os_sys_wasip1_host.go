// WasmForge replacement for os/sys_bsd.go on wasip1.
// Provides os.hostname() via wasmforge host function instead of
// the broken sysctl("kern.hostname") call.

//go:build wasip1

package os

import "syscall"

//go:wasmimport env sys_hostname
//go:noescape
func wasmforge_os_hostname(bufPtr *byte, bufCap uint32, resultLenPtr *uint32) uint32

func hostname() (name string, err error) {
	var buf [256]byte
	var resultLen uint32
	errno := wasmforge_os_hostname(&buf[0], uint32(len(buf)), &resultLen)
	if errno != 0 {
		return "", syscall.Errno(errno)
	}
	return string(buf[:resultLen]), nil
}
