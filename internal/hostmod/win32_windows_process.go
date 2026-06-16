//go:build windows

package hostmod

import (
	"context"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
	"golang.org/x/sys/windows"
)

// win32GetComputerName retrieves the NetBIOS name of the local computer.
func win32GetComputerName(ctx context.Context, mod api.Module, bufPtr, bufLenPtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}

	bufLen, ok := readUint32(mod, bufLenPtr)
	if !ok {
		return errnoEFAULT
	}
	if bufLen == 0 {
		return errnoEINVAL
	}

	nameBuf := make([]uint16, bufLen)
	size := bufLen

	if err := windows.GetComputerName(&nameBuf[0], &size); err != nil {
		return win32Errno(err)
	}

	name := windows.UTF16ToString(nameBuf[:size])
	nameBytes := []byte(name)

	if !writeUint32(mod, bufLenPtr, uint32(len(nameBytes))) {
		return errnoEFAULT
	}
	if !writeBytes(mod, bufPtr, nameBytes) {
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32CreateProcess creates a new process.
func win32CreateProcess(ctx context.Context, mod api.Module, cmdlinePtr, cmdlineLen, flags, pidPtr, handlePtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	cmdlineBytes, ok := readBytes(mod, cmdlinePtr, cmdlineLen)
	if !ok {
		return errnoEFAULT
	}
	cmdline, err := windows.UTF16PtrFromString(string(cmdlineBytes))
	if err != nil {
		return errnoEINVAL
	}

	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	if err := windows.CreateProcess(
		nil,
		cmdline,
		nil,
		nil,
		false,
		flags,
		nil,
		nil,
		&si,
		&pi,
	); err != nil {
		return win32Errno(err)
	}

	if !writeUint32(mod, pidPtr, pi.ProcessId) {
		windows.CloseHandle(pi.Process)
		windows.CloseHandle(pi.Thread)
		return errnoEFAULT
	}

	// Store the process handle; close the thread handle immediately.
	windows.CloseHandle(pi.Thread)

	id := ht.register(&win32HandleEntry{
		kind:      handleWin32,
		winHandle: uintptr(pi.Process),
	})

	if !writeInt32(mod, handlePtr, id) {
		windows.CloseHandle(pi.Process)
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32OpenProcess opens a handle to an existing process.
func win32OpenProcess(ctx context.Context, mod api.Module, access, pid, handlePtr uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	handle, err := windows.OpenProcess(access, false, pid)
	if err != nil {
		return win32Errno(err)
	}

	id := ht.register(&win32HandleEntry{
		kind:      handleWin32,
		winHandle: uintptr(handle),
	})

	if !writeInt32(mod, handlePtr, id) {
		windows.CloseHandle(handle)
		return errnoEFAULT
	}
	return errnoSuccess
}

// win32TerminateProcess terminates a process.
func win32TerminateProcess(ctx context.Context, mod api.Module, handle int32, exitCode uint32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.get(handle)
	if entry == nil {
		return errnoEBADF
	}

	if err := windows.TerminateProcess(windows.Handle(entry.winHandle), exitCode); err != nil {
		return win32Errno(err)
	}
	return errnoSuccess
}

// win32CloseHandle closes a generic Win32 handle stored in the handle table.
func win32CloseHandle(ctx context.Context, mod api.Module, handle int32) uint32 {
	cfg := getConfig(ctx)
	if cfg == nil || !cfg.Win32APIs {
		return errnoENOSYS
	}
	ht := getWin32Handles(ctx)
	if ht == nil {
		return errnoEINVAL
	}

	entry := ht.remove(handle)
	if entry == nil {
		return errnoEBADF
	}

	switch entry.kind {
	case handleDLL:
		if err := windows.FreeLibrary(windows.Handle(entry.dllHandle)); err != nil {
			return win32Errno(err)
		}
	case handleWin32:
		if err := windows.CloseHandle(windows.Handle(entry.winHandle)); err != nil {
			return win32Errno(err)
		}
	case handleProc:
		// Proc addresses don't need OS cleanup.
	}
	return errnoSuccess
}
